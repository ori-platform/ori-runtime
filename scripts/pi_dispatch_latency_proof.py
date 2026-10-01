# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Measure Tier D latency on a device under CPU, disk and evidence-store pressure.

Runs against the installed runtime package: the shipped energy-anomaly-detector
and battery-lifecycle-observer skills are loaded through the real loader and
registered on a real event bus, with the real state store, evidence attestor
and inbound evidence route. While every core is busy, a writer fsyncs to the
state store's filesystem, the state and evidence stores are locked by another
connection, the inbound route is flooded and each skill's hook is held, it
publishes dangerous readings and times each from publication on the bus to the
trigger's first act.

    <install root>/current/venv/bin/python pi_dispatch_latency_proof.py \\
        --data-dir /var/tmp/ori-latency-proof --readings 50

It writes a JSON report to stdout and exits 1 when any reading exceeds the
bound. Nothing outside ``--data-dir`` is written, no MQTT broker is needed (the
route's client is replaced at the transport edge), and no relay is driven.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import multiprocessing
import os
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ori.gateway.evidence_inbound import (
    ARTIFACT_RECEIPT,
    EvidenceInboundRouter,
    MqttEvidenceInboundSubscriber,
)
from ori.integration.rule_evaluation import bundled_skill_path
from ori.network.event_bus import EventBus
from ori.network.events import OriEvent, SensorReading
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.dispatch_coordinator import DispatchCoordinator
from ori.reasoning.elevator import IntelligenceElevator
from ori.reasoning.resource_gate import ResourceGate
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.skills.loader import SkillLoader
from ori.state.store import StateStore

DEVICE = "latency-proof"
BOUND_S = 0.25
#: The skill, its Tier D trigger, and a reading that meets it.
CASES = {
    "energy-anomaly-detector": ("dangerous_overcurrent", "current_clamp", 30.0),
    "battery-lifecycle-observer": (
        "battery_emergency_cutoff",
        "growatt_battery_soc",
        3.0,
    ),
}


def _busy(stop: Any) -> None:
    while not stop.is_set():
        pass


def _disk(directory: Path, stop: threading.Event) -> None:
    chunk = os.urandom(4 * 1024 * 1024)
    path = directory / "pressure.bin"
    while not stop.is_set():
        with open(path, "wb") as handle:
            for _ in range(16):
                handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
                if stop.is_set():
                    break
    path.unlink(missing_ok=True)


class _Client:
    """The inbound route's MQTT client, replaced at the transport edge."""

    on_connect: Any = None
    on_subscribe: Any = None
    on_disconnect: Any = None
    on_message: Any = None

    def username_pw_set(self, *_a: Any) -> None:
        pass

    def connect(self, *_a: Any) -> None:
        pass

    def loop_start(self) -> None:
        self.on_connect(self, None, None, 0)

    def subscribe(self, *_a: Any, **_k: Any) -> tuple[int, int]:
        self.on_subscribe(self, None, 1, [1], None)
        return (0, 1)

    def publish(self, *_a: Any, **_k: Any) -> None:
        pass

    def loop_stop(self) -> None:
        pass

    def disconnect(self) -> None:
        pass


async def _prove(data: Path, readings: int) -> dict[str, Any]:
    store = StateStore(db_path=str(data / "state.db"))
    await store.open()
    attestor = FirstPartyEvidenceAttestor(
        db_path=str(data / "evidence.db"),
        key_path=str(data / "evidence.key"),
        device_secret="latency-proof-install-secret",
        device_id=DEVICE,
    )
    if not await attestor.start():
        raise SystemExit("the evidence attestor could not start")
    acts: dict[str, list[float]] = {}

    def executor(name: str) -> Any:
        async def run(_action: str, context: Any, *_a: Any, **_k: Any) -> bool:
            acts.setdefault(str(getattr(context, "trigger_name", "")), []).append(
                time.monotonic()
            )
            return True

        return run

    dispatcher = ActionDispatcher(
        state_store=store, evidence_attestor=attestor, config={}
    )
    for action in ("alert_whatsapp", "log_to_dashboard"):
        dispatcher.register_executor(action, executor(action))
    gate = ResourceGate()
    dispatcher.bind_resource_gate(gate, None)
    coordinator = DispatchCoordinator(
        elevator=IntelligenceElevator(),
        dispatcher=dispatcher,
        state_store=store,
        gate=gate,
    )
    loader = SkillLoader(
        elevator=coordinator._elevator,
        state_store=store,
        dispatcher=dispatcher,
        coordinator=coordinator,
    )
    bus = EventBus()
    root = bundled_skill_path("energy-anomaly-detector").parent
    held = asyncio.Event()
    for skill in loader.load_all(str(root)):
        if skill.name in CASES:

            async def blocked(_context: Any) -> None:
                await held.wait()

            skill.hooks.pre_trigger_eval = blocked
            loader.register(skill, bus)

    client = _Client()
    ingest = attestor.ingest
    assert ingest is not None
    subscriber = MqttEvidenceInboundSubscriber(
        broker_url="mqtt://127.0.0.1:1883",
        router=EvidenceInboundRouter(device_id=DEVICE, ingest=ingest),
        device_id=DEVICE,
        client_factory=lambda **_k: client,
    )
    shutdown = asyncio.Event()
    serving = asyncio.create_task(subscriber.serve_until(shutdown))
    await asyncio.sleep(0.2)

    lockers = []
    for name in ("state.db", "evidence.db"):
        locker = sqlite3.connect(str(data / name), isolation_level=None)
        locker.execute("BEGIN EXCLUSIVE")
        lockers.append(locker)
    flooding = threading.Event()
    malformed = json.dumps(
        {"device_id": DEVICE, "artifact_type": ARTIFACT_RECEIPT, "artifact": {"v": 1}}
    ).encode()

    def flood() -> None:
        n = 0
        while not flooding.is_set():
            n += 1
            client.on_message(
                client, None, SimpleNamespace(payload=malformed, mid=n, qos=1)
            )
            time.sleep(0.001)

    flooder = threading.Thread(target=flood, daemon=True)
    flooder.start()

    latencies: dict[str, list[float]] = {name: [] for name in CASES}
    try:
        for i in range(readings):
            for name, (trigger, sensor_type, value) in CASES.items():
                fired = acts.setdefault(trigger, [])
                before = len(fired)
                event = OriEvent.from_reading(
                    SensorReading(
                        sensor_id=f"proof-{name}",
                        sensor_type=sensor_type,
                        value=value,
                        unit="x",
                        timestamp=int(time.time() * 1000),
                        quality=1.0,
                    ),
                    DEVICE,
                )
                started = time.monotonic()
                await bus.publish(event)
                deadline = started + 10.0
                while len(fired) <= before and time.monotonic() < deadline:
                    await asyncio.sleep(0.001)
                latencies[name].append(
                    fired[before] - started if len(fired) > before else float("inf")
                )
            await asyncio.sleep(0.1)
    finally:
        flooding.set()
        held.set()
        for locker in lockers:
            locker.execute("COMMIT")
            locker.close()
        shutdown.set()
        await asyncio.wait({serving}, timeout=10.0)
        await coordinator.drain(timeout=10.0)
        await dispatcher.drain_records(timeout=10.0)
        await store.close()
        attestor.close()

    report: dict[str, Any] = {"bound_ms": BOUND_S * 1000, "shed": subscriber.shed_count}
    for name, values in latencies.items():
        finite = [v for v in values if v != float("inf")]
        report[name] = {
            "readings": len(values),
            "missed": len(values) - len(finite),
            "p50_ms": round(statistics.median(finite) * 1000, 2) if finite else None,
            "p95_ms": round(sorted(finite)[int(len(finite) * 0.95) - 1] * 1000, 2)
            if finite
            else None,
            "max_ms": round(max(values) * 1000, 2) if finite else None,
        }
    report["pass"] = all(
        v != float("inf") and v < BOUND_S
        for values in latencies.values()
        for v in values
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("--data-dir", default=tempfile.gettempdir())
    parser.add_argument("--readings", type=int, default=50)
    parser.add_argument("--cpu-workers", type=int, default=os.cpu_count() or 1)
    args = parser.parse_args()
    base = Path(args.data_dir)
    base.mkdir(parents=True, exist_ok=True)
    stop_cpu = multiprocessing.Event()
    workers = [
        multiprocessing.Process(target=_busy, args=(stop_cpu,), daemon=True)
        for _ in range(args.cpu_workers)
    ]
    for worker in workers:
        worker.start()
    with tempfile.TemporaryDirectory(dir=base, prefix="ori-latency-") as scratch:
        data = Path(scratch)
        stop_disk = threading.Event()
        writer = threading.Thread(target=_disk, args=(data, stop_disk), daemon=True)
        writer.start()
        try:
            report = asyncio.run(_prove(data, args.readings))
        finally:
            stop_disk.set()
            stop_cpu.set()
            writer.join(30)
            for worker in workers:
                worker.join(10)
    report["cpu_workers"] = args.cpu_workers
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
