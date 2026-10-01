# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Measure Tier D and approved Tier C latency on a device under pressure.

Runs against the installed runtime package. The shipped
energy-anomaly-detector and battery-lifecycle-observer skills, hooks included,
are loaded through the real loader and registered on a real event bus, with
the real state store, evidence attestor and inbound evidence route. Every core
is kept busy, a writer fsyncs to the state store's filesystem, the evidence
store is locked by another connection and the inbound route is flooded.

* Tier D: with the state store locked too, a sensor thread publishes a normal
  reading and then a dangerous one, and each dangerous reading is timed from
  that thread's clock to every act its trigger reaches. The bundled Tier D
  triggers carry notifications only, so the first act is a notification.
* Tier C: with the state store free (an approval is committed to it before
  anything acts), a governed approval is raised on a commissioned zone, the
  operator answers YES, and the act is timed from the reply to its executor.

    <install root>/current/venv/bin/python pi_dispatch_latency_proof.py \\
        --data-dir /var/tmp/ori-latency-proof --readings 200

scripts/ is not in the wheel, so copy this file to the device. It writes a
JSON report to stdout and exits 1 when any first act misses the bound. Nothing
outside --data-dir is written, no MQTT broker is needed (the route's client
is replaced at the transport edge), and no relay is driven.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import multiprocessing
import os
import sqlite3
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
from ori.reasoning.dispatch_plan import (
    CLOSE_PROTECTED_CIRCUIT,
    OPEN_PROTECTED_CIRCUIT,
    BindingView,
)
from ori.reasoning.elevator import IntelligenceElevator
from ori.reasoning.resource_gate import ResourceGate
from ori.reasoning.tier_c_admission import TierCAuthorityFacts
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.skills.loader import SkillLoader, Trigger
from ori.state.store import StateStore

DEVICE = "latency-proof"
BOUND_S = 0.25
#: How long the whole notice set of a dangerous reading is waited for.
NOTICE_WINDOW_S = 8.0
#: How long one approval round may take, the proposal's own lifetime.
APPROVAL_WINDOW_S = 30.0
#: The skill, its Tier D trigger, a normal reading and a dangerous one.
CASES = {
    "energy-anomaly-detector": ("dangerous_overcurrent", "current_clamp", 5.0, 30.0),
    "battery-lifecycle-observer": (
        "battery_emergency_cutoff",
        "growatt_battery_soc",
        60.0,
        3.0,
    ),
}
_ZONE = BindingView(
    zone_identity_key=("local_gpio", "pin:26"),
    binding_revision="1",
    consequence_by_outcome={
        OPEN_PROTECTED_CIRCUIT: "hard",
        CLOSE_PROTECTED_CIRCUIT: "hard",
    },
)


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


def _count(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def _summary(values: list[float]) -> dict[str, Any]:
    finite = sorted(v for v in values if v != math.inf)
    if not finite:
        return {"n": len(values), "missed": len(values)}

    def rank(p: float) -> float:
        return finite[max(0, math.ceil(p * len(finite)) - 1)]

    return {
        "n": len(values),
        "missed": len(values) - len(finite),
        "p50_ms": round(rank(0.50) * 1000, 2),
        "p95_ms": round(rank(0.95) * 1000, 2),
        "max_ms": round(finite[-1] * 1000, 2),
    }


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

    def ack(self, *_a: Any) -> int:
        return 0

    def loop_stop(self) -> None:
        pass

    def disconnect(self) -> None:
        pass


class _Phone:
    """The operator: answers every proposal YES, and notes when."""

    def __init__(self) -> None:
        self.proposals: list[str] = []
        self.replied_at: list[float] = []

    async def send(self, *, alert: Any, to_number: str) -> bool:
        if alert.intent.value == "tier_c_approval":
            self.proposals.append(str(alert.template_variables[3]))
        return True

    async def listen_for_response(
        self, *, from_number: str, timeout_seconds: int
    ) -> str | None:
        while not self.proposals:
            await asyncio.sleep(0.001)
        self.replied_at.append(time.monotonic())
        # Oldest first: each proposal is answered, never one skipped for a
        # newer one.
        return f"YES-{self.proposals.pop(0)}"


class _Isolator:
    """An operator-approved isolation of the commissioned zone."""

    name = "latency-proof-isolator"
    version = "1.0.0"
    first_party = True
    hooks = None
    config: dict[str, Any] = {}
    sensors_required = [{"type": "isolation_request"}]
    triggers = [
        Trigger(
            name="isolate",
            condition="value > 0",
            action_tier="C",
            escalate_to="rule",
            cooldown_seconds=0,
            approval_timeout_seconds=30,
            safe_default_action="log_to_dashboard",
        )
    ]
    actions = {
        "available": [
            {"name": "trip_relay", "tier": "C"},
            {"name": "log_to_dashboard", "tier": "A"},
        ],
        "defaults": {"isolate": ["trip_relay"]},
    }

    def get_default_actions(self, _sensor_type: str) -> list[str]:
        return []


def _event(sensor_id: str, sensor_type: str, value: float) -> OriEvent:
    return OriEvent.from_reading(
        SensorReading(
            sensor_id=sensor_id,
            sensor_type=sensor_type,
            value=value,
            unit="x",
            timestamp=int(time.time() * 1000),
            quality=1.0,
        ),
        DEVICE,
    )


def _authority_facts(zone_id: str | None = None) -> TierCAuthorityFacts:
    return TierCAuthorityFacts(
        zone_id="zone-a",
        zone_document={"zone_id": "zone-a", "identity": {"gpio_pin": 26}},
        binding_digest="sha256:" + "b" * 64,
        safety_profile_digest="",
        resource_for={
            OPEN_PROTECTED_CIRCUIT: "relay-gpio-26",
            CLOSE_PROTECTED_CIRCUIT: "relay-gpio-26",
        },
        deployment_inputs={},
    )


async def _prove(data: Path, readings: int, notice_readings: int = 3) -> dict[str, Any]:
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
    acts: dict[str, list[tuple[str, float]]] = {}

    def executor(name: str) -> Any:
        async def run(_action: str, context: Any, *_a: Any, **_k: Any) -> bool:
            trigger = str(getattr(context, "trigger_name", ""))
            acts.setdefault(trigger, []).append((name, time.monotonic()))
            return True

        return run

    phone = _Phone()
    dispatcher = ActionDispatcher(
        state_store=store,
        alert_sender=phone,
        evidence_attestor=attestor,
        config={"operator_contact": "+10000000000", "relay_enabled": True},
        authority_facts=_authority_facts,
    )
    for action in ("alert_whatsapp", "log_to_dashboard", "trip_relay"):
        dispatcher.register_executor(action, executor(action))
    gate = ResourceGate()
    dispatcher.bind_resource_gate(gate, _ZONE)
    coordinator = DispatchCoordinator(
        elevator=IntelligenceElevator(),
        dispatcher=dispatcher,
        state_store=store,
        gate=gate,
    )
    coordinator.set_binding(_ZONE)
    loader = SkillLoader(
        elevator=coordinator._elevator,
        state_store=store,
        dispatcher=dispatcher,
        coordinator=coordinator,
    )
    bus = EventBus()
    root = bundled_skill_path("energy-anomaly-detector").parent
    notices: dict[str, int] = {}
    for skill in loader.load_all(str(root)):
        if skill.name in CASES:
            loader.register(skill, bus)
            trigger = CASES[skill.name][0]
            notices[skill.name] = len(
                skill.actions.get("defaults", {}).get(trigger, [])
            )
    coordinator.add_skill(_Isolator())
    bus.subscribe("isolation_request", coordinator.handle_event)

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
    for n in range(6):
        await store.append_history(_event("proof-energy", "current_clamp", 5.0 + n))

    evidence_lock = sqlite3.connect(str(data / "evidence.db"), isolation_level=None)
    evidence_lock.execute("BEGIN EXCLUSIVE")
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
    loop = asyncio.get_running_loop()

    def publish(event: OriEvent) -> float:
        produced = time.monotonic()
        asyncio.run_coroutine_threadsafe(bus.publish(event), loop)
        return produced

    def skill_actions(name: str) -> list[str]:
        skill = next(s for s in coordinator._skills if s.name == name)
        return list(skill.actions.get("defaults", {}).get(CASES[name][0], []))

    first: dict[str, list[float]] = {name: [] for name in CASES}
    every: dict[str, dict[str, list[float]]] = {name: {} for name in CASES}
    approvals: list[float] = []
    decisions: list[dict[str, Any]] = []
    try:
        # Tier D, both stores locked: a normal reading, then a dangerous one.
        state_lock = sqlite3.connect(str(data / "state.db"), isolation_level=None)
        state_lock.execute("BEGIN EXCLUSIVE")
        try:
            for i in range(readings):
                for name, (trigger, sensor_type, normal, danger) in CASES.items():
                    fired = acts.setdefault(trigger, [])
                    before = len(fired)
                    sensor = f"proof-{name}"
                    await asyncio.to_thread(
                        publish, _event(sensor, sensor_type, normal)
                    )
                    await asyncio.sleep(0.05)
                    produced = await asyncio.to_thread(
                        publish, _event(sensor, sensor_type, danger)
                    )
                    deadline = time.monotonic() + 10.0
                    while len(fired) <= before and time.monotonic() < deadline:
                        await asyncio.sleep(0.001)
                    first[name].append(
                        fired[before][1] - produced if len(fired) > before else math.inf
                    )
                    # The whole notice set, for the first few readings: a later
                    # notice can wait on the locked state store.
                    window = NOTICE_WINDOW_S if i < notice_readings else 0.3
                    want = before + notices[name]
                    deadline = time.monotonic() + window
                    while len(fired) < want and time.monotonic() < deadline:
                        await asyncio.sleep(0.01)
                    if i < notice_readings:
                        reached = {a: at for a, at in fired[before:want]}
                        for action in skill_actions(name):
                            every[name].setdefault(action, []).append(
                                reached[action] - produced
                                if action in reached
                                else math.inf
                            )
        finally:
            state_lock.execute("COMMIT")
            state_lock.close()
        # Tier C, the state store free: from the operator's YES to the act.
        # Each round is one proposal: it waits for the previous one's event to
        # settle, so an isolation request never joins a proposal still open.
        # The phase starts straight after the unlock, with whatever the locked
        # phase left queued for the store.
        for _ in range(max(1, readings // 4)):
            fired = acts.setdefault("isolate", [])
            before = len(fired)
            replies = len(phone.replied_at)
            await asyncio.to_thread(
                publish, _event("proof-isolation", "isolation_request", 1.0)
            )
            deadline = time.monotonic() + APPROVAL_WINDOW_S
            while len(fired) <= before and time.monotonic() < deadline:
                await asyncio.sleep(0.001)
            approvals.append(
                fired[before][1] - phone.replied_at[replies]
                if len(fired) > before and len(phone.replied_at) > replies
                else math.inf
            )
            await coordinator.drain(timeout=APPROVAL_WINDOW_S)
        decisions = await store.get_tier_c_proposals()
    finally:
        flooding.set()
        evidence_lock.execute("COMMIT")
        evidence_lock.close()
        shutdown.set()
        await asyncio.wait({serving}, timeout=10.0)
        await coordinator.drain(timeout=10.0)
        await dispatcher.drain_records(timeout=10.0)
        await store.close()
        attestor.close()

    report: dict[str, Any] = {
        "bound_ms": BOUND_S * 1000,
        "inbound_messages_left_with_broker": subscriber.shed_count,
        "tier_d": {
            name: {
                "trigger": CASES[name][0],
                "first_act": "the first notification the trigger reached",
                "first_act_latency": _summary(first[name]),
                "every_act": {a: _summary(v) for a, v in every[name].items()},
            }
            for name in CASES
        },
        "approved_tier_c_reply_to_act": _summary(approvals),
        "tier_c_decisions": _count(str(d.get("decision_state", "")) for d in decisions),
    }
    report["pass"] = (
        all(v < BOUND_S for values in first.values() for v in values)
        and all(v < BOUND_S for v in approvals)
        and all(str(d.get("decision_state", "")) == "executed" for d in decisions)
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument(
        "--data-dir",
        default="/var/tmp",
        help="a directory on the filesystem the state store lives on",
    )
    parser.add_argument("--readings", type=int, default=200)
    parser.add_argument(
        "--notice-readings",
        type=int,
        default=3,
        help="dangerous readings whose whole notice set is waited for",
    )
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
            report = asyncio.run(_prove(data, args.readings, args.notice_readings))
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
