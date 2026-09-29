# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The poll interval holds when the deduplicator suppresses a reading."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from ori.hal.mqtt_adapter import MqttAdapter
from ori.network.deduplicator import EventDeduplicator
from ori.network.event_bus import EventBus
from ori.network.events import SensorReading
from ori.runtime import OriRuntime
from ori.state.store import StateStore
from tests.test_mqtt_adapter import _config, _FakeClient

POLL_MS = 100
RUN_S = 0.6
SENSOR = "chiller-temp-01"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[StateStore]:
    s = StateStore(str(tmp_path / "state.db"))
    await s.open()
    yield s
    await s.close()


def _runtime(store: StateStore) -> Any:
    runtime: Any = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._shutdown_event = asyncio.Event()
    runtime._measurement_refusals = {}
    runtime._measurement_valid_streak = {}
    runtime._measurement_refusal_reason = {}
    runtime._measurement_degraded = set()
    runtime._measurement_unnotified = set()
    runtime._measurement_notify_attempts = {}
    return runtime


class _Observed:
    """Stands in for the safety registry; records when each value arrives."""

    def __init__(self) -> None:
        self.first_seen: dict[float, float] = {}

    async def observe_reading(self, _sensor: str, value: Any, *_: Any) -> list[Any]:
        self.first_seen.setdefault(float(value), time.monotonic())
        return []


class _Counted:
    def __init__(self, adapter: Any) -> None:
        self._adapter = adapter
        self.reads = 0

    async def read(self, sensor_id: str) -> SensorReading:
        self.reads += 1
        return await self._adapter.read(sensor_id)


async def _run(
    runtime: Any, adapter: Any, *side: Any, bus: EventBus | None = None
) -> tuple[float, float]:
    """Poll for RUN_S beside a 10 ms ticker; return (elapsed, worst tick overshoot)."""
    overshoot: list[float] = []

    async def ticker() -> None:
        while not runtime._shutdown_event.is_set():
            start = time.monotonic()
            await asyncio.sleep(0.01)
            overshoot.append(time.monotonic() - start - 0.01)

    async def stop() -> None:
        await asyncio.sleep(RUN_S)
        runtime._shutdown_event.set()

    started = time.monotonic()
    await asyncio.gather(
        runtime._poll_sensor(
            adapter,
            SimpleNamespace(id=SENSOR, poll_interval_ms=POLL_MS),
            bus or EventBus(),
            "dev-01",
            deduplicator=EventDeduplicator(),
        ),
        ticker(),
        stop(),
        *side,
    )
    return time.monotonic() - started, max(overshoot)


def _bounded(reads: int, elapsed: float) -> None:
    ceiling = int(elapsed * 1000 / POLL_MS) + 2
    assert reads >= 3, f"only {reads} reads: the poll never ran"
    assert reads <= ceiling, (
        f"{reads} reads in {elapsed:.2f}s at {POLL_MS} ms: a suppressed duplicate "
        "skipped the poll interval"
    )


async def test_a_cached_duplicate_neither_spins_the_poll_nor_starves_the_loop(
    store: StateStore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.CRITICAL)
    runtime = _runtime(store)
    observed = _Observed()
    runtime._safety_registry = observed
    mqtt = MqttAdapter()
    with (
        patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
        patch("ori.hal.mqtt_base._aiomqtt", SimpleNamespace(Client=_FakeClient)),
    ):
        cfg = _config()
        await mqtt.connect(cfg)
        client: Any = mqtt._client
        await client.emit(cfg["topic"], b'{"reading":{"value":27.4,"quality":1.0}}')
        await asyncio.sleep(0.05)
        adapter = _Counted(mqtt)
        changed_at: list[float] = []
        published: list[float] = []
        bus = EventBus()

        async def on_reading(event: Any) -> None:
            published.append(event.reading.value)

        bus.subscribe("temperature", on_reading)

        async def change() -> None:
            await asyncio.sleep(RUN_S / 2)
            changed_at.append(time.monotonic())
            await client.emit(cfg["topic"], b'{"reading":{"value":99.9,"quality":1.0}}')

        try:
            elapsed, worst = await _run(runtime, adapter, change(), bus=bus)
        finally:
            await mqtt.close()

    _bounded(adapter.reads, elapsed)
    assert worst < 0.05, f"a concurrent task waited {worst * 1000:.0f} ms"
    assert 99.9 in observed.first_seen, "a changed value never reached the registry"
    lag = observed.first_seen[99.9] - changed_at[0]
    assert lag < 2 * POLL_MS / 1000, f"a changed value waited {lag * 1000:.0f} ms"
    assert store.history_admission.lost == 0
    assert published == [27.4, 99.9], "a suppressed duplicate reached the bus"


async def test_a_duplicate_from_a_yielding_adapter_waits_the_poll_interval(
    store: StateStore,
) -> None:
    runtime = _runtime(store)

    class _Stable:
        reads = 0

        async def read(self, sensor_id: str) -> SensorReading:
            self.reads += 1
            await asyncio.sleep(0)
            return SensorReading(
                sensor_id=sensor_id,
                sensor_type="voltage",
                value=230.0,
                unit="volt",
                timestamp=int(time.time() * 1000),
                quality=1.0,
                metadata={"source": "i2c"},
            )

    adapter = _Stable()
    elapsed, _ = await _run(runtime, adapter)

    _bounded(adapter.reads, elapsed)
