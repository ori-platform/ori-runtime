# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A sensor poll waits its interval on every path, and stops promptly.

Every poll here runs behind a read-count trip-wire: a loop that stops yielding
cannot be stopped by a timeout, so the adapter itself sets shutdown after too
many reads and the test fails on that instead of hanging.
"""

from __future__ import annotations

import asyncio
import logging
import statistics
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from ori import runtime as runtime_module
from ori.hal.base import AdapterReadError
from ori.hal.mqtt_adapter import MqttAdapter
from ori.network.deduplicator import EventDeduplicator
from ori.network.event_bus import EventBus
from ori.network.events import SensorReading
from ori.runtime import OriRuntime
from ori.state.store import StateStore
from tests.test_mqtt_adapter import _config, _FakeClient

POLL_MS = 100
RUN_S = 0.6
HARD_CEILING_S = 10.0
TRIP_READS = 50
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


def _reading(
    sensor_id: str, value: float = 230.0, sensor_type: str = "voltage"
) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit="volt",
        timestamp=int(time.time() * 1000),
        quality=1.0,
        metadata={"source": "i2c"},
    )


class _Observed:
    """Stands in for the safety registry; records when each value arrives."""

    def __init__(self) -> None:
        self.first_seen: dict[float, float] = {}

    async def observe_reading(self, _sensor: str, value: Any, *_: Any) -> list[Any]:
        self.first_seen.setdefault(float(value), time.monotonic())
        return []


class _Paced:
    """Records each read's time; past TRIP_READS it sets shutdown instead of hanging."""

    def __init__(
        self, runtime: Any, read: Callable[[str], Awaitable[SensorReading]]
    ) -> None:
        self._runtime = runtime
        self._read = read
        self.times: list[float] = []
        self.tripped = False

    @property
    def reads(self) -> int:
        return len(self.times)

    async def read(self, sensor_id: str) -> SensorReading:
        self.times.append(time.monotonic())
        if len(self.times) >= TRIP_READS:
            self.tripped = True
            self._runtime._shutdown_event.set()
        return await self._read(sensor_id)


async def _run(
    runtime: Any, adapter: _Paced, *side: Any, bus: EventBus | None = None
) -> tuple[float, float]:
    """Poll for RUN_S beside a 10 ms ticker; return (elapsed, worst tick overshoot)."""
    overshoot: list[float] = [0.0]

    async def ticker() -> None:
        while not runtime._shutdown_event.is_set():
            start = time.monotonic()
            await asyncio.sleep(0.01)
            overshoot.append(time.monotonic() - start - 0.01)

    async def stop() -> None:
        await asyncio.sleep(RUN_S)
        runtime._shutdown_event.set()

    started = time.monotonic()
    await asyncio.wait_for(
        asyncio.gather(
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
        ),
        HARD_CEILING_S,
    )
    return time.monotonic() - started, max(overshoot)


def _paced(adapter: _Paced, elapsed: float) -> None:
    """The poll read once per interval: not faster, and not slower."""
    assert not adapter.tripped, (
        f"{TRIP_READS} reads before shutdown: the poll skipped its interval"
    )
    expected = elapsed * 1000 / POLL_MS
    assert adapter.reads >= 3, f"only {adapter.reads} reads: the poll never ran"
    assert adapter.reads <= int(expected) + 2, (
        f"{adapter.reads} reads in {elapsed:.2f}s at {POLL_MS} ms: the poll "
        "skipped its interval"
    )
    assert adapter.reads >= int(expected * 0.6), (
        f"{adapter.reads} reads in {elapsed:.2f}s at {POLL_MS} ms: the poll "
        "waited more than its interval"
    )
    gaps = [b - a for a, b in zip(adapter.times, adapter.times[1:])]
    median = statistics.median(gaps) * 1000
    assert 0.8 * POLL_MS <= median <= 1.6 * POLL_MS, (
        f"median gap between reads {median:.0f} ms at a {POLL_MS} ms interval"
    )


@pytest.mark.latency_bound
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
        adapter = _Paced(runtime, mqtt.read)
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

    _paced(adapter, elapsed)
    assert worst < 0.05, f"a concurrent task waited {worst * 1000:.0f} ms"
    assert 99.9 in observed.first_seen, "a changed value never reached the registry"
    lag = observed.first_seen[99.9] - changed_at[0]
    assert lag < 2 * POLL_MS / 1000, f"a changed value waited {lag * 1000:.0f} ms"
    assert store.history_admission.lost == 0
    assert published == [27.4, 99.9], "a suppressed duplicate reached the bus"


@pytest.mark.latency_bound
async def test_a_duplicate_from_a_yielding_adapter_waits_the_poll_interval(
    store: StateStore,
) -> None:
    runtime = _runtime(store)

    async def stable(sensor_id: str) -> SensorReading:
        await asyncio.sleep(0)
        return _reading(sensor_id)

    adapter = _Paced(runtime, stable)
    elapsed, _ = await _run(runtime, adapter)

    _paced(adapter, elapsed)


@pytest.mark.latency_bound
async def test_the_status_indicator_syncs_only_on_a_published_reading(
    store: StateStore,
) -> None:
    runtime = _runtime(store)
    synced: list[Any] = []
    runtime._status_indicator = SimpleNamespace(
        set_power_state=synced.append, set_hardware_fault=lambda _on: None
    )
    published: list[float] = []
    bus = EventBus()

    async def on_reading(event: Any) -> None:
        published.append(event.reading.value)

    bus.subscribe("battery_percent", on_reading)

    async def repeating(sensor_id: str) -> SensorReading:
        return _reading(sensor_id, value=50.0, sensor_type="battery_percent")

    adapter = _Paced(runtime, repeating)
    elapsed, _ = await _run(runtime, adapter, bus=bus)

    _paced(adapter, elapsed)
    assert published == [50.0]
    assert len(synced) == len(published), (
        f"{len(synced)} status syncs for {len(published)} published readings: "
        "a suppressed duplicate reached the indicator"
    )


@pytest.mark.latency_bound
@pytest.mark.parametrize(
    "failure",
    [AdapterReadError("bus timeout"), RuntimeError("adapter bug")],
    ids=["adapter_read_error", "unexpected_error"],
)
async def test_a_failed_read_still_waits_the_poll_interval(
    store: StateStore, caplog: pytest.LogCaptureFixture, failure: Exception
) -> None:
    caplog.set_level(logging.CRITICAL)
    runtime = _runtime(store)

    async def failing(_sensor_id: str) -> SensorReading:
        raise failure

    adapter = _Paced(runtime, failing)
    elapsed, _ = await _run(runtime, adapter)

    _paced(adapter, elapsed)


async def test_each_suppressed_duplicate_sleeps_once_and_cancels_promptly_in_the_sleep(
    store: StateStore,
) -> None:
    """Observe the poll's own sleeps: one per read, and cancellable while asleep.

    The runtime's sleeps are told apart from any other caller's by the
    interval they wait. The task is cancelled inside the sleep that follows
    the second suppressed duplicate, after the sleep following the first has
    been counted, so both a skipped and a doubled sleep are visible here.
    """
    runtime = _runtime(store)
    interval = 0.317
    real_sleep = asyncio.sleep
    published: list[float] = []
    sleeps: list[tuple[int, int]] = []
    in_sleep_after_third_read = asyncio.Event()
    bus = EventBus()

    async def on_reading(event: Any) -> None:
        published.append(event.reading.value)

    bus.subscribe("voltage", on_reading)

    async def stable(sensor_id: str) -> SensorReading:
        return _reading(sensor_id)

    adapter = _Paced(runtime, stable)

    async def observed_sleep(delay: float, result: Any = None) -> Any:
        if delay == interval:
            sleeps.append((adapter.reads, len(published)))
            if adapter.reads == 3:
                in_sleep_after_third_read.set()
        return await real_sleep(delay, result)

    with patch.object(runtime_module.asyncio, "sleep", observed_sleep):
        task = asyncio.create_task(
            runtime._poll_sensor(
                adapter,
                SimpleNamespace(id=SENSOR, poll_interval_ms=interval * 1000),
                bus,
                "dev-01",
                deduplicator=EventDeduplicator(),
            )
        )
        try:
            waiter = asyncio.create_task(in_sleep_after_third_read.wait())
            done, _ = await asyncio.wait(
                {waiter, task},
                timeout=HARD_CEILING_S,
                return_when=asyncio.FIRST_COMPLETED,
            )
            waiter.cancel()
            assert done, f"neither a third read nor the poll's end in {HARD_CEILING_S}s"
            assert in_sleep_after_third_read.is_set(), (
                f"no poll-interval sleep after the third read ({adapter.reads} "
                f"reads, sleeps at {sleeps}): a suppressed duplicate skipped it"
            )
            cancelled_at = time.monotonic()
            task.cancel()
            await asyncio.wait_for(
                asyncio.gather(task, return_exceptions=True), HARD_CEILING_S
            )
            took = time.monotonic() - cancelled_at
        finally:
            runtime._shutdown_event.set()
            task.cancel()

    assert not adapter.tripped
    assert published == [230.0], "the second and third reads were not suppressed"
    assert sleeps == [(1, 1), (2, 1), (3, 1)], (
        f"sleeps (reads, published) {sleeps}: each read must be followed by "
        "exactly one poll-interval sleep"
    )
    assert task.cancelled()
    assert took < interval / 3, (
        f"cancellation inside the sleep took {took * 1000:.0f} ms at a "
        f"{interval * 1000:.0f} ms interval"
    )
    assert adapter.reads == 3, "a read happened after the poll was cancelled"


async def test_cancelling_the_poll_during_a_read_is_not_delayed_by_the_interval(
    store: StateStore,
) -> None:
    """A cancel delivered inside the read ends the poll without a last sleep.

    This is what a sleep moved into ``finally`` breaks: the cancellation raised
    by the read would run the full interval before it propagated.
    """
    runtime = _runtime(store)
    poll_ms = 300
    blocked = asyncio.Event()

    async def then_block(sensor_id: str) -> SensorReading:
        if adapter.reads == 1:
            return _reading(sensor_id)
        blocked.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    adapter = _Paced(runtime, then_block)
    task = asyncio.create_task(
        runtime._poll_sensor(
            adapter,
            SimpleNamespace(id=SENSOR, poll_interval_ms=poll_ms),
            EventBus(),
            "dev-01",
            deduplicator=EventDeduplicator(),
        )
    )
    try:
        await asyncio.wait_for(blocked.wait(), HARD_CEILING_S)
        cancelled_at = time.monotonic()
        task.cancel()
        await asyncio.wait_for(
            asyncio.gather(task, return_exceptions=True), HARD_CEILING_S
        )
        took = time.monotonic() - cancelled_at
    finally:
        runtime._shutdown_event.set()
        task.cancel()

    assert not adapter.tripped
    assert task.cancelled()
    assert took < poll_ms / 1000 / 3, (
        f"cancellation during a read took {took * 1000:.0f} ms at a "
        f"{poll_ms} ms interval"
    )
