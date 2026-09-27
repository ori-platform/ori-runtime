# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A reading is never part of its own history, and a busy store never holds it.

Evaluation-time history is the rows the store had committed when the reading
was admitted, bounded by insertion identity rather than by value or clock. The
reading's history row is queued beside it: a store that is locked or full can
delay the row or lose it, never the reading's evaluation.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from ori.gateway.reasoning import _history_points
from ori.network.event_bus import EventBus
from ori.network.events import OriEvent, SensorReading, history_as_of
from ori.reasoning.elevator import IntelligenceElevator
from ori.reasoning.rule_engine import RuleEngine
from ori.runtime import OriRuntime
from ori.skills.hooks_api import HookContext
from ori.skills.loader import SkillLoader
from ori.state.store import StateStore

SENSOR = "load-current-01"
T0 = int(time.time() * 1000) - 600_000  # inside every age window


def _reading(
    value: float,
    *,
    timestamp: int,
    sensor_id: str = SENSOR,
    sensor_type: str = "current_clamp",
    unit: str = "ampere",
) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp=timestamp,
        quality=1.0,
        metadata={"source": "i2c"},
    )


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


class _Sequence:
    """Serves readings in order; the store has taken each earlier row first."""

    def __init__(self, runtime: Any, store: StateStore, readings: list[Any]):
        self._runtime = runtime
        self._store = store
        self._readings = list(readings)

    async def read(self, sensor_id: str) -> SensorReading:
        await self._store.history_admission.drain(5.0)
        reading = self._readings.pop(0)
        if not self._readings:
            self._runtime._shutdown_event.set()
        return reading


async def _poll(
    store: StateStore, readings: list[SensorReading], handler: Any, sensor_type: str
) -> Any:
    runtime = _runtime(store)
    bus = EventBus()
    bus.subscribe(sensor_type, handler)
    sensor_cfg: Any = SimpleNamespace(id=readings[0].sensor_id, poll_interval_ms=1)
    await runtime._poll_sensor(
        cast(Any, _Sequence(runtime, store, readings)), sensor_cfg, bus, "dev-01"
    )
    return runtime


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


async def test_every_evaluation_time_reader_excludes_the_reading_being_evaluated(
    store: StateStore,
) -> None:
    """Each reader sees the earlier reading only, even once this one's row has landed."""
    seen: dict[str, Any] = {}

    async def handler(event: OriEvent) -> None:
        assert event.reading is not None
        if event.reading.value != 20.0:
            return
        # The row lands before any reader runs: exclusion is by identity, so a
        # row committed after the frontier is still not this reading's history.
        await store.history_admission.drain(5.0)
        persisted = await store.get_history(SENSOR, 10)
        seen["persisted"] = [row.value for row in persisted]
        seen["get_history"] = [
            row.value
            for row in await store.get_history(SENSOR, 10, **history_as_of(event))
        ]
        seen["avg_last_hours"] = await store.avg_last_hours(
            SENSOR, 24, **history_as_of(event)
        )
        hook = HookContext.build(event, store, "probe").history
        seen["hook_last_value"] = hook.last_value(SENSOR)
        seen["hook_last_timestamp"] = hook.last_timestamp(SENSOR)
        seen["hook_fetch"] = [row["value"] for row in hook.fetch_history(SENSOR, 10)]
        seen["hook_avg_last_n"] = hook.avg_last_n(SENSOR, 10)
        seen["hook_avg_hours"] = hook.avg_hours(SENSOR, 24)
        await IntelligenceElevator._attach_decision_history_window(
            cast(Any, None), event, store
        )
        seen["decision_window"] = [
            point["value"] for point in event.context["history_window"]
        ]
        event.context.pop("history_window")
        seen["gateway_points"] = [
            point["value"] for point in await _history_points(event, store)
        ]
        result = await RuleEngine().evaluate(
            event,
            [
                {
                    "name": "earlier_only",
                    "condition": f"history.avg_24h('{SENSOR}') == 10.0",
                    "action_tier": "A",
                    "escalate_to": "rule",
                }
            ],
            state_store=store,
        )
        seen["rule_matched"] = result.matched

    await _poll(
        store,
        [_reading(10.0, timestamp=T0), _reading(20.0, timestamp=T0 + 60_000)],
        handler,
        "current_clamp",
    )

    assert seen["persisted"] == [20.0, 10.0], "the evaluated row had not landed"
    assert seen["get_history"] == [10.0]
    assert seen["avg_last_hours"] == 10.0
    assert seen["hook_last_value"] == 10.0
    assert seen["hook_last_timestamp"] == T0
    assert seen["hook_fetch"] == [10.0]
    assert seen["hook_avg_last_n"] == 10.0
    assert seen["hook_avg_hours"] == 10.0
    assert seen["decision_window"] == [10.0]
    assert seen["gateway_points"] == [10.0]
    assert seen["rule_matched"] is True


async def test_the_first_reading_has_no_history(store: StateStore) -> None:
    seen: list[Any] = []

    async def handler(event: OriEvent) -> None:
        await store.history_admission.drain(5.0)
        seen.append(HookContext.build(event, store, "probe").history.last_value(SENSOR))

    await _poll(store, [_reading(10.0, timestamp=T0)], handler, "current_clamp")

    assert seen == [None]


async def test_the_registry_observes_a_reading_before_its_history_is_admitted(
    store: StateStore,
) -> None:
    order: list[tuple[int, int]] = []

    class _Registry:
        async def observe_reading(self, *_: Any) -> list[Any]:
            rows = len(await store.get_history(SENSOR, 10))
            order.append((rows, store.history_admission.pending))
            return []

    runtime = _runtime(store)
    runtime._safety_registry = _Registry()
    bus = EventBus()
    sensor_cfg: Any = SimpleNamespace(id=SENSOR, poll_interval_ms=1)
    await runtime._poll_sensor(
        cast(Any, _Sequence(runtime, store, [_reading(10.0, timestamp=T0)])),
        sensor_cfg,
        bus,
        "dev-01",
    )

    assert order == [(0, 0)]


def _lock(path: str) -> sqlite3.Connection:
    holder = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    holder.execute("BEGIN EXCLUSIVE")
    return holder


async def test_a_locked_store_neither_delays_nor_drops_a_polled_reading(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "state.db")
    store = StateStore(path)
    await store.open()
    delivered: list[float] = []

    async def handler(event: OriEvent) -> None:
        delivered.append(time.monotonic())

    holder = _lock(path)
    try:
        runtime = _runtime(store)
        bus = EventBus()
        bus.subscribe("current_clamp", handler)
        sensor_cfg: Any = SimpleNamespace(id=SENSOR, poll_interval_ms=1)

        class _Once:
            async def read(self, sensor_id: str) -> SensorReading:
                runtime._shutdown_event.set()
                return _reading(10.0, timestamp=T0)

        started = time.monotonic()
        await runtime._poll_sensor(cast(Any, _Once()), sensor_cfg, bus, "dev-01")
        assert len(delivered) == 1
        assert delivered[0] - started < 1.0, "the locked store delayed evaluation"
    finally:
        holder.execute("ROLLBACK")
        holder.close()

    await store.history_admission.drain(10.0)
    assert [row.value for row in await store.get_history(SENSOR, 10)] == [10.0]
    assert store.history_admission.lost == 0
    await store.close()


async def test_a_row_past_the_admission_ceiling_is_counted_lost_and_named(
    store: StateStore, caplog: pytest.LogCaptureFixture
) -> None:
    store.history_admission.ceiling = 0
    delivered: list[OriEvent] = []

    async def handler(event: OriEvent) -> None:
        delivered.append(event)

    with caplog.at_level(logging.WARNING):
        await _poll(store, [_reading(10.0, timestamp=T0)], handler, "current_clamp")

    assert len(delivered) == 1, "a full admission queue dropped the reading"
    assert store.history_admission.lost == 1
    assert any(
        f"sensor={SENSOR}" in record.getMessage() for record in caplog.records
    ), "the lost row does not name its reading"


async def test_a_locked_store_neither_delays_nor_drops_a_firmware_reading(
    tmp_path: Path,
) -> None:
    from tests.firmware.test_mqtt import _FakeFirmwareGate, _subscriber

    path = str(tmp_path / "state.db")
    store = StateStore(path)
    await store.open()
    bus = EventBus()
    delivered: list[OriEvent] = []

    async def handler(event: OriEvent) -> None:
        delivered.append(event)

    bus.subscribe("current", handler)
    subscriber, _client = _subscriber(gate=_FakeFirmwareGate(), store=store, bus=bus)
    holder = _lock(path)
    try:
        started = time.monotonic()
        await subscriber._ingest_telemetry({"envelope": {}, "signature": "x"})
        elapsed = time.monotonic() - started
        assert len(delivered) == 1
        assert elapsed < 1.0, "the locked store delayed evaluation"
        assert delivered[0].history_frontier == 0
    finally:
        holder.execute("ROLLBACK")
        holder.close()

    await store.history_admission.drain(10.0)
    rows = await store.get_history("ori-fw-7c9f2b3a:ch0", 10)
    assert [row.value for row in rows] == [8.21]
    await store.close()


async def test_the_energy_spike_ratio_compares_with_the_previous_reading(
    store: StateStore,
) -> None:
    skill = SkillLoader().load_one(
        Path(__file__).resolve().parents[1] / "skills" / "energy-anomaly-detector"
    )
    ratios: list[float] = []

    async def handler(event: OriEvent) -> None:
        await store.history_admission.drain(5.0)
        ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
        skill.hooks.pre_trigger_eval(ctx)
        ratios.append(ctx.derived["spike_ratio"])

    await _poll(
        store,
        [_reading(10.0, timestamp=T0), _reading(20.0, timestamp=T0 + 60_000)],
        handler,
        "current_clamp",
    )

    # With the reading in its own history the ratio was always 1.0.
    assert ratios == [0.0, 2.0]


async def test_the_disk_write_rate_is_measured_against_the_previous_reading(
    store: StateStore,
) -> None:
    skill = SkillLoader().load_one(
        Path(__file__).resolve().parents[1] / "skills" / "pc-system-health"
    )
    rates: list[Any] = []

    async def handler(event: OriEvent) -> None:
        await store.history_admission.drain(5.0)
        ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
        skill.hooks.pre_trigger_eval(ctx)
        rates.append(ctx.derived.get("write_rate_mb_per_min"))

    def disk(value: float, timestamp: int) -> SensorReading:
        return _reading(
            value,
            timestamp=timestamp,
            sensor_id="disk_write_mb",
            sensor_type="disk_write_mb",
            unit="megabyte",
        )

    await _poll(
        store,
        [disk(100.0, T0), disk(160.0, T0 + 60_000)],
        handler,
        "disk_write_mb",
    )

    # With the reading in its own history no time had elapsed, so no rate.
    assert rates == [None, 60.0]


async def test_a_reopened_store_resumes_the_frontier_past_removed_rows(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "state.db")
    store = StateStore(path)
    await store.open()
    for value in (1.0, 2.0, 3.0):
        event = OriEvent.from_reading(_reading(value, timestamp=T0), "dev-01")
        store.admit_history(event)
    await store.close()

    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM sensor_history")

    reopened = StateStore(path)
    await reopened.open()
    try:
        assert reopened.history_frontier == 3
        event = OriEvent.from_reading(_reading(4.0, timestamp=T0), "dev-01")
        reopened.admit_history(event)
        assert event.history_frontier == 3
        await reopened.history_admission.drain(5.0)
        assert await reopened.get_history(SENSOR, 10, **history_as_of(event)) == []
    finally:
        await reopened.close()


_HISTORY_READS = {
    "get_history",
    "avg_last_hours",
    "avg_last_n",
    "hooks_get_history",
    "hooks_avg_last_hours",
    "hooks_avg_last_n",
}


class _Recording:
    """The real store, noting the frontier every history read was bounded by."""

    def __init__(self, store: StateStore) -> None:
        self._store = store
        self.calls: list[tuple[str, Any]] = []

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._store, name)
        if name not in _HISTORY_READS:
            return attr

        def recorded(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((name, kwargs.get("frontier")))
            return attr(*args, **kwargs)

        return recorded


async def test_tier_selection_prompts_and_the_sandbox_read_to_the_frontier(
    store: StateStore, tmp_path: Path
) -> None:
    from ori.reasoning.rule_engine import RuleResult
    from ori.skills.os_sandbox import OSSandboxHookRunner

    battery = _reading(
        90.0,
        timestamp=T0,
        sensor_id="battery",
        sensor_type="battery_percent",
        unit="percent",
    )
    for reading in (battery, _reading(10.0, timestamp=T0)):
        store.admit_history(OriEvent.from_reading(reading, "dev-01"))
    await store.history_admission.drain(5.0)
    event = OriEvent.from_reading(_reading(20.0, timestamp=T0 + 60_000), "dev-01")
    store.admit_history(event)
    await store.history_admission.drain(5.0)
    assert event.history_frontier == 2
    recording = _Recording(store)

    elevator = IntelligenceElevator(
        config={
            "energy_aware_reasoning": {
                "enabled": True,
                "battery_sensor_id": "battery",
            }
        }
    )
    await elevator._select_tier_from_rule_result(
        event,
        SimpleNamespace(name="probe"),
        recording,
        RuleResult(matched=False, action_tier="A"),
    )
    await elevator._resolve_history_expression(
        expression=f"history.last_n('{SENSOR}', 5)", event=event, state_store=recording
    )
    runner = OSSandboxHookRunner(
        hooks_path=tmp_path / "hooks.py",
        state_store=recording,
        skill_name="probe",
        os_sandbox_config={},
    )
    for method, params in (
        ("history.avg_hours", {"sensor_id": SENSOR, "hours": 24}),
        ("history.avg_last_n", {"sensor_id": SENSOR, "n": 5}),
        ("history.last_value", {"sensor_id": SENSOR, "limit": 1}),
    ):
        runner._handle_rpc_request(
            {"method": method, "params": params}, history_as_of(event)
        )

    reads = {name for name, _ in recording.calls}
    assert {"get_history", "avg_last_hours", "hooks_get_history"} <= reads
    assert {"hooks_avg_last_hours", "hooks_avg_last_n"} <= reads
    unbounded = [name for name, frontier in recording.calls if frontier != 2]
    assert unbounded == [], f"history read past the frontier: {unbounded}"


async def _energy_derived(store: StateStore, values: list[float]) -> dict[str, Any]:
    skill = SkillLoader().load_one(
        Path(__file__).resolve().parents[1] / "skills" / "energy-anomaly-detector"
    )
    derived: dict[str, Any] = {}

    async def handler(event: OriEvent) -> None:
        await store.history_admission.drain(5.0)
        ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
        skill.hooks.pre_trigger_eval(ctx)
        derived.clear()
        derived.update(ctx.derived)

    readings = [
        _reading(value, timestamp=T0 + index * 60_000)
        for index, value in enumerate(values)
    ]
    await _poll(store, readings, handler, "current_clamp")
    return derived


async def test_the_volatility_window_is_this_reading_and_the_nine_before_it(
    store: StateStore,
) -> None:
    # Ten earlier readings, the oldest an outlier just outside the window.
    derived = await _energy_derived(store, [100.0] + [10.0] * 9 + [20.0])

    window = [20.0] + [10.0] * 9
    mean = sum(window) / len(window)
    stddev = (sum((v - mean) ** 2 for v in window) / len(window)) ** 0.5
    baseline = (100.0 + 10.0 * 9) / 10
    assert derived["baseline_24h"] == pytest.approx(baseline)
    assert derived["recent_volatility_percent"] == pytest.approx(
        stddev / baseline * 100.0
    )


async def test_the_sustained_window_counts_this_reading(store: StateStore) -> None:
    derived = await _energy_derived(store, [10.0] * 6 + [30.0])

    assert derived["sustained_high_count"] == 1
    assert derived["sustained_high_ratio"] == pytest.approx(1 / 6)
