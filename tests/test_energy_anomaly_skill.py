# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

from ori.network.events import OriEvent, ReasoningResult, SensorReading, StoredReading
from ori.reasoning.rule_engine import RuleEngine
from ori.skills.hooks_api import HookContext
from ori.skills.loader import SkillLoader


class _Store:
    def __init__(self) -> None:
        self._history: dict[str, list[SensorReading]] = {}
        self.time_of_week_baseline: dict | None = None

    def add_history(self, sensor_id: str, reading: SensorReading) -> None:
        self._history.setdefault(sensor_id, []).insert(0, reading)

    def _get_history_sync(self, sensor_id: str, limit: int) -> list[SensorReading]:
        return self._history.get(sensor_id, [])[:limit]

    def _avg_last_hours_sync(self, sensor_id: str, _hours: int) -> float | None:
        rows = self._history.get(sensor_id, [])
        if not rows:
            return None
        return sum(r.value for r in rows) / len(rows)

    def hooks_get_history(self, sensor_id: str, limit: int = 1) -> list[StoredReading]:
        # The store hands hooks stored readings, each with its receipt; this
        # double received every reading the moment it was measured.
        return [
            StoredReading(**{**vars(reading), "received_at_ms": reading.timestamp})
            for reading in self._get_history_sync(sensor_id, limit)
        ]

    def hooks_avg_last_hours(self, sensor_id: str, hours: int) -> float | None:
        return self._avg_last_hours_sync(sensor_id, hours)

    def hooks_avg_last_n(self, sensor_id: str, n: int) -> float | None:
        rows = self._get_history_sync(sensor_id, n)
        if not rows:
            return None
        return sum(r.value for r in rows) / len(rows)

    def hooks_time_of_week_baseline(
        self,
        sensor_id: str,
        reference_timestamp_ms: int,
        timezone: str,
        lookback_weeks: int,
        min_weeks: int,
    ) -> dict:
        assert sensor_id
        assert reference_timestamp_ms > 0
        assert timezone
        assert lookback_weeks >= min_weeks
        return self.time_of_week_baseline or {}


def _skill_dir() -> Path:
    return Path(__file__).parent.parent / "skills" / "energy-anomaly-detector"


def _load_skill():
    return SkillLoader().load_one(_skill_dir())


def _event(
    *,
    sensor_id: str = "load-current-01",
    sensor_type: str = "current_clamp",
    value: float,
    unit: str = "ampere",
    source: str = "i2c",
    quality: float = 1.0,
    timestamp: int = 1_710_000_000_123,
) -> OriEvent:
    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp=timestamp,
        quality=quality,
        metadata={"source": source},
    )
    event = OriEvent.from_reading(reading, "energy-site-01")
    event.received_at_ms = reading.timestamp  # received when measured
    return event


def _ctx(skill, event, store):
    hook_ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
    skill.hooks.pre_trigger_eval(hook_ctx)
    context = dict(skill.config)
    context.update(hook_ctx.derived)
    return hook_ctx, context


def _history_reading(
    sensor_id: str,
    value: float,
    ts: int,
    *,
    sensor_type: str = "current_clamp",
    unit: str = "ampere",
    source: str = "i2c",
) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp=ts,
        quality=1.0,
        metadata={"source": source},
    )


def _seed_history(
    store: _Store,
    sensor_id: str,
    values: list[float],
    *,
    sensor_type: str = "current_clamp",
    unit: str = "ampere",
    source: str = "i2c",
) -> None:
    base_ts = 1_709_999_000_000
    for idx, value in enumerate(reversed(values)):
        store.add_history(
            sensor_id,
            _history_reading(
                sensor_id,
                value,
                base_ts + idx,
                sensor_type=sensor_type,
                unit=unit,
                source=source,
            ),
        )


@pytest.mark.asyncio
async def test_skill_loads_with_v2_triggers():
    skill = _load_skill()
    assert skill.name == "energy-anomaly-detector"
    assert len(skill.triggers) == 8
    assert {trigger.action_tier for trigger in skill.triggers} == {"A", "D", "B"}


def test_hook_computes_baseline_and_deviation():
    skill = _load_skill()
    store = _Store()
    sensor_id = "load-current-01"
    _seed_history(store, sensor_id, [10.0, 10.0, 10.0, 10.0, 10.0, 10.0])

    event = _event(sensor_id=sensor_id, value=14.0)
    hook_ctx, _ = _ctx(skill, event, store)

    assert hook_ctx.derived["baseline_valid"] == 1
    assert hook_ctx.derived["baseline_24h"] == pytest.approx(10.0)
    assert hook_ctx.derived["deviation_percent"] == pytest.approx(40.0)


def test_hook_marks_contextually_normal_time_of_week_draw():
    skill = _load_skill()
    store = _Store()
    store.time_of_week_baseline = {
        "avg_value": 12.0,
        "covered_weeks": 4,
        "sample_count": 48,
        "usable": True,
        "reason": "ok",
        "tier": "hourly",
    }

    event = _event(value=12.8, timestamp=1_717_925_400_000)
    event.context = {"device_timezone": "Africa/Lagos"}
    hook_ctx, _ = _ctx(skill, event, store)

    assert hook_ctx.derived["time_of_week_baseline_usable"] == 1
    assert hook_ctx.derived["time_of_week_baseline"] == pytest.approx(12.0)
    assert hook_ctx.derived["time_of_week_covered_weeks"] == 4
    assert hook_ctx.derived["time_of_week_deviation_percent"] == pytest.approx(
        ((12.8 - 12.0) / 12.0) * 100.0
    )
    assert hook_ctx.derived["context_aware_suppression"] == 1


@pytest.mark.asyncio
async def test_contextual_suppression_does_not_suppress_tier_d():
    skill = _load_skill()
    store = _Store()
    store.time_of_week_baseline = {
        "avg_value": 30.0,
        "covered_weeks": 4,
        "sample_count": 48,
        "usable": True,
        "reason": "ok",
        "tier": "hourly",
    }
    event = _event(value=30.5, quality=0.95)
    event.context = {"device_timezone": "Africa/Lagos"}
    _, context = _ctx(skill, event, store)
    trigger = next(t for t in skill.triggers if t.name == "dangerous_overcurrent")

    result = await RuleEngine().evaluate(event, [trigger], context=context)

    assert context["context_aware_suppression"] == 1
    assert result.matched is True
    assert trigger.action_tier == "D"


@pytest.mark.asyncio
async def test_rule_matches_sustained_overdraw():
    skill = _load_skill()
    skill.config["overdraw_threshold_percent"] = 7.0
    skill.config["sustained_ratio_threshold"] = 0.6
    store = _Store()
    sensor_id = "load-current-01"
    _seed_history(store, sensor_id, [14.0, 13.5, 14.2, 14.1, 13.7, 13.9, 10.0, 10.1])

    event = _event(sensor_id=sensor_id, value=14.4, quality=0.95)
    _, context = _ctx(skill, event, store)
    trigger = next(t for t in skill.triggers if t.name == "sustained_overdraw")

    result = await RuleEngine().evaluate(event, [trigger], context=context)
    assert result.matched is True
    assert result.rule_name == "sustained_overdraw"


@pytest.mark.asyncio
async def test_usb_power_matches_sustained_overdraw_and_uses_watts_for_cost():
    skill = _load_skill()
    skill.config["overdraw_threshold_percent"] = 10.0
    skill.config["sustained_ratio_threshold"] = 0.6
    skill.config["tariff_per_kwh"] = 100.0
    store = _Store()
    sensor_id = "phone-main-power"
    _seed_history(
        store,
        sensor_id,
        [1_700.0, 1_650.0, 1_720.0, 1_680.0, 1_710.0, 1_690.0, 1_000.0, 1_000.0],
        sensor_type="usb_power",
        unit="watt",
        source="usb_serial",
    )

    event = _event(
        sensor_id=sensor_id,
        sensor_type="usb_power",
        value=1_750.0,
        unit="watt",
        source="usb_serial",
        quality=0.95,
    )
    hook_ctx, context = _ctx(skill, event, store)
    trigger = next(t for t in skill.triggers if t.name == "sustained_overdraw")

    result = await RuleEngine().evaluate(event, [trigger], context=context)

    assert result.matched is True
    assert hook_ctx.derived["measurement_kind"] == "power"
    assert hook_ctx.derived["delta_amps"] == 0.0
    assert hook_ctx.derived["delta_watts"] == pytest.approx(
        1_750.0 - hook_ctx.derived["baseline_24h"]
    )
    assert hook_ctx.derived["estimated_kw_delta"] == pytest.approx(
        hook_ctx.derived["delta_watts"] / 1000.0
    )
    assert hook_ctx.derived["cost_confidence"] == "exact"


@pytest.mark.asyncio
async def test_contextual_suppression_blocks_sustained_overdraw_tier_a():
    skill = _load_skill()
    skill.config["overdraw_threshold_percent"] = 7.0
    skill.config["sustained_ratio_threshold"] = 0.6
    store = _Store()
    store.time_of_week_baseline = {
        "avg_value": 14.0,
        "covered_weeks": 5,
        "sample_count": 60,
        "usable": True,
        "reason": "ok",
        "tier": "hourly",
    }
    sensor_id = "load-current-01"
    _seed_history(store, sensor_id, [14.0, 13.5, 14.2, 14.1, 13.7, 13.9, 10.0, 10.1])

    event = _event(sensor_id=sensor_id, value=14.4, quality=0.95)
    event.context = {"device_timezone": "Africa/Lagos"}
    _, context = _ctx(skill, event, store)
    trigger = next(t for t in skill.triggers if t.name == "sustained_overdraw")

    result = await RuleEngine().evaluate(event, [trigger], context=context)

    assert context["baseline_valid"] == 1
    assert context["deviation_percent"] >= skill.config["overdraw_threshold_percent"]
    assert context["sustained_high_ratio"] >= skill.config["sustained_ratio_threshold"]
    assert context["context_aware_suppression"] == 1
    assert result.matched is False


@pytest.mark.asyncio
async def test_rule_matches_sudden_load_spike():
    skill = _load_skill()
    skill.config["overdraw_threshold_percent"] = 20.0
    store = _Store()
    sensor_id = "load-current-01"
    _seed_history(store, sensor_id, [8.0, 10.0, 10.0, 10.0, 10.0, 10.0])

    event = _event(sensor_id=sensor_id, value=14.0, quality=0.95)
    _, context = _ctx(skill, event, store)
    trigger = next(t for t in skill.triggers if t.name == "sudden_load_spike")

    result = await RuleEngine().evaluate(event, [trigger], context=context)
    assert result.matched is True
    assert result.rule_name == "sudden_load_spike"


@pytest.mark.asyncio
async def test_rule_matches_unstable_power_draw():
    skill = _load_skill()
    store = _Store()
    sensor_id = "load-current-01"
    _seed_history(store, sensor_id, [15.0, 8.0, 14.0, 7.0, 13.5, 8.5, 10.0, 10.0])

    event = _event(sensor_id=sensor_id, value=13.6, quality=0.95)
    _, context = _ctx(skill, event, store)
    trigger = next(t for t in skill.triggers if t.name == "unstable_power_draw")

    result = await RuleEngine().evaluate(event, [trigger], context=context)
    assert result.matched is True
    assert result.rule_name == "unstable_power_draw"


@pytest.mark.asyncio
async def test_low_quality_does_not_match_v2_alerts():
    skill = _load_skill()
    store = _Store()
    sensor_id = "load-current-01"
    _seed_history(store, sensor_id, [14.0, 13.0, 13.5, 14.1, 13.8, 13.9, 10.0, 10.0])

    event = _event(sensor_id=sensor_id, value=14.5, quality=0.5)
    _, context = _ctx(skill, event, store)
    trigger = next(t for t in skill.triggers if t.name == "sustained_overdraw")

    result = await RuleEngine().evaluate(event, [trigger], context=context)
    assert result.matched is False


@pytest.mark.asyncio
async def test_dangerous_overcurrent_threshold_is_configurable():
    skill = _load_skill()
    skill.config["dangerous_overcurrent_threshold"] = 25.0
    trigger = next(t for t in skill.triggers if t.name == "dangerous_overcurrent")

    event = _event(value=22.0)
    _, context = _ctx(skill, event, _Store())
    result = await RuleEngine().evaluate(event, [trigger], context=context)
    assert result.matched is False


def test_post_reasoning_appends_baseline_summary():
    skill = _load_skill()
    event = _event(value=14.0, timestamp=1_710_000_000_000)
    hook_ctx = HookContext.build(event, _Store(), skill.name, skill_config=skill.config)
    hook_ctx.trigger_name = "sustained_overdraw"

    result = ReasoningResult(
        text="Current reading crossed baseline threshold due to anomaly.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
    )
    updated = skill.hooks.post_reasoning(result, hook_ctx)
    assert updated.text.startswith("At ")
    assert "I noticed power stayed high for too long." in updated.text
    assert len(updated.text) <= 160
    banned = [
        "threshold",
        "anomaly",
        "baseline",
        "deviation",
        "sensor",
        "reading",
        "value",
        " current ",
        "voltage",
    ]
    lower = f" {updated.text.lower()} "
    for token in banned:
        assert token not in lower


def test_post_reasoning_uses_configured_timezone_when_provided():
    skill = _load_skill()
    # 2024-03-09 10:40:00 UTC => 11:40 WAT
    event = _event(value=14.0, timestamp=1_709_980_800_000)
    hook_ctx = HookContext.build(
        event, _Store(), skill.name, skill_config={"timezone": "Africa/Lagos"}
    )
    hook_ctx.trigger_name = "sudden_load_spike"

    result = ReasoningResult(
        text="Power changed quickly.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
    )
    updated = skill.hooks.post_reasoning(result, hook_ctx)
    assert updated.text.startswith("At 11:40,")


def test_post_reasoning_uses_global_safe_fallback_timezone():
    skill = _load_skill()
    event = _event(value=14.0, timestamp=1_709_980_800_000)
    hook_ctx = HookContext.build(event, _Store(), skill.name, skill_config={})
    hook_ctx.trigger_name = "sudden_load_spike"

    result = ReasoningResult(
        text="Power changed quickly.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
    )
    updated = skill.hooks.post_reasoning(result, hook_ctx)
    assert updated.text.startswith("At ")


def test_cost_projection_infers_country_voltage_and_currency():
    skill = _load_skill()
    skill.config["tariff_per_kwh"] = 100.0
    skill.config.pop("line_voltage", None)
    skill.config.pop("currency_symbol", None)
    skill.config.pop("currency_code", None)

    store = _Store()
    sensor_id = "load-current-01"
    _seed_history(store, sensor_id, [10.0, 10.0, 10.0, 10.0, 10.0, 10.0])
    event = _event(sensor_id=sensor_id, value=14.0, quality=0.95)
    event.context["device_country_code"] = "US"
    hook_ctx, _ = _ctx(skill, event, store)

    assert hook_ctx.derived["line_voltage_used"] == pytest.approx(120.0)
    assert hook_ctx.derived["cost_currency_symbol"] == "$"
    assert hook_ctx.derived["cost_confidence"] == "estimated"
    assert hook_ctx.derived["delta_amps"] == pytest.approx(4.0)
    assert hook_ctx.derived["projected_extra_cost_daily"] > 0.0


def test_cost_projection_uses_explicit_voltage_and_exact_confidence():
    skill = _load_skill()
    skill.config["tariff_per_kwh"] = 120.0
    skill.config["line_voltage"] = 230.0
    skill.config["currency_symbol"] = "€"
    skill.config["power_factor"] = 1.0

    store = _Store()
    sensor_id = "load-current-01"
    _seed_history(store, sensor_id, [10.0, 10.0, 10.0, 10.0, 10.0, 10.0])
    event = _event(sensor_id=sensor_id, value=13.0, quality=0.95)
    hook_ctx, _ = _ctx(skill, event, store)

    assert hook_ctx.derived["line_voltage_used"] == pytest.approx(230.0)
    assert hook_ctx.derived["cost_currency_symbol"] == "€"
    assert hook_ctx.derived["cost_confidence"] == "exact"
    assert hook_ctx.derived["projected_extra_cost_daily"] > 0.0


def test_post_reasoning_includes_projected_daily_risk_anchor():
    skill = _load_skill()
    skill.config["tariff_per_kwh"] = 150.0
    skill.config["currency_symbol"] = "₦"
    skill.config["line_voltage"] = 230.0

    store = _Store()
    sensor_id = "load-current-01"
    _seed_history(store, sensor_id, [10.0, 10.0, 10.0, 10.0, 10.0, 10.0])
    event = _event(sensor_id=sensor_id, value=14.0, quality=0.95)
    hook_ctx, _ = _ctx(skill, event, store)
    hook_ctx.trigger_name = "sustained_overdraw"

    result = ReasoningResult(
        text="Power remained elevated due to delayed generator stop.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
    )
    updated = skill.hooks.post_reasoning(result, hook_ctx)
    assert "/day projected extra cost risk" in updated.text
    assert "prevented" not in updated.text.lower()


def test_observed_window_is_the_span_of_receipts_not_of_device_clocks():
    """Ten hours on the readings' own clocks, one hour of observation."""
    skill = _load_skill()
    store = _Store()
    sensor_id = "load-current-01"
    _seed_history(store, sensor_id, [10.0, 10.0, 10.0, 10.0, 10.0, 10.0])
    base = 1_710_000_000_000
    rows = [
        StoredReading(
            sensor_id=sensor_id,
            sensor_type="current_clamp",
            value=10.0,
            unit="ampere",
            timestamp=base + index * 2 * 3_600_000,
            quality=1.0,
            received_at_ms=base + index * 12 * 60_000,
        )
        for index in range(6)
    ]
    store.hooks_get_history = lambda _sensor_id, limit=1: rows[:limit]  # type: ignore[method-assign]

    # Received after every row in its history, as an event always is.
    event = _event(sensor_id=sensor_id, value=14.0, timestamp=base + 3_600_000)
    hook_ctx, _ = _ctx(skill, event, store)

    assert hook_ctx.derived["observed_window_hours"] == pytest.approx(1.0)


def _receipt_rows(sensor_id: str, receipts: list[int]) -> list[dict]:
    return [
        {
            "sensor_id": sensor_id,
            "sensor_type": "current_clamp",
            "value": 10.0,
            "unit": "ampere",
            "timestamp": received,
            "quality": 1.0,
            "metadata": {},
            "received_at_ms": received,
        }
        for received in receipts
    ]


def _observed_hours(receipts: list[int], event_received_at_ms: int) -> float:
    skill = _load_skill()
    store = _Store()
    sensor_id = "load-current-01"
    _seed_history(store, sensor_id, [10.0, 10.0, 10.0, 10.0, 10.0, 10.0])
    rows = _receipt_rows(sensor_id, receipts)
    event = _event(sensor_id=sensor_id, value=14.0, timestamp=event_received_at_ms)
    hook_ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
    hook_ctx.history.fetch_history = lambda _sensor_id, limit=1: rows[:limit]  # type: ignore[method-assign]
    skill.hooks.pre_trigger_eval(hook_ctx)
    return hook_ctx.derived["observed_window_hours"]


def test_a_receipt_after_the_event_does_not_stretch_the_observed_window():
    """Only a clock that ran ahead writes a receipt later than the event itself."""
    base = 1_710_000_000_000
    now = base + 5 * 60_000
    ahead = now + 365 * 86_400_000
    receipts = [ahead] + [base + index * 60_000 for index in range(5)]

    assert _observed_hours(receipts, now) == pytest.approx(4 / 60)


def test_the_observed_window_never_exceeds_raw_retention():
    """Raw history is kept for 48 hours; no span of it can honestly be longer."""
    base = 1_710_000_000_000
    now = base + 400 * 86_400_000
    receipts = [base] + [now - index * 60_000 for index in range(5)]

    assert _observed_hours(receipts, now) == pytest.approx(48.0)


def test_a_history_row_without_a_receipt_does_not_stretch_the_observed_window():
    """A zero receipt would span to the epoch; the row is left out instead."""
    skill = _load_skill()
    store = _Store()
    sensor_id = "load-current-01"
    _seed_history(store, sensor_id, [10.0, 10.0, 10.0, 10.0, 10.0, 10.0])
    base = 1_710_000_000_000
    rows = [
        {
            "sensor_id": sensor_id,
            "sensor_type": "current_clamp",
            "value": 10.0,
            "unit": "ampere",
            "timestamp": base + index * 60_000,
            "quality": 1.0,
            "metadata": {},
            "received_at_ms": 0 if index == 0 else base + index * 60_000,
        }
        for index in range(6)
    ]
    event = _event(sensor_id=sensor_id, value=14.0, timestamp=base + 5 * 60_000)
    hook_ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
    hook_ctx.history.fetch_history = lambda _sensor_id, limit=1: rows[:limit]  # type: ignore[method-assign]

    skill.hooks.pre_trigger_eval(hook_ctx)

    assert hook_ctx.derived["observed_window_hours"] == pytest.approx(4 / 60)


async def test_the_events_own_row_counts_though_the_store_stamped_it_later(
    tmp_path, monkeypatch
):
    """The store receives a reading just after the event that carries it."""
    from ori.state.store import StateStore

    skill = _load_skill()
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    sensor_id = "load-current-01"
    base = 1_710_000_000_000
    clock = {"now": base}
    monkeypatch.setattr("ori.state.store.now_ms", lambda: clock["now"])
    try:
        for index in range(5):
            clock["now"] = base + index * 60_000
            await store.append_history(
                _event(sensor_id=sensor_id, value=10.0, timestamp=clock["now"])
            )
        event = _event(sensor_id=sensor_id, value=14.0, timestamp=base + 4 * 60_000)

        # The row for this event was stamped 50 ms after the event itself.
        def _lag() -> None:
            assert store._conn is not None
            store._conn.execute(
                "UPDATE sensor_history SET received_at_ms = received_at_ms + 50 "
                "WHERE id = (SELECT MAX(id) FROM sensor_history)"
            )
            store._conn.commit()

        await store._run_write(_lag)
        hook_ctx = HookContext.build(
            event, store, skill.name, skill_config=skill.config
        )
        skill.hooks.pre_trigger_eval(hook_ctx)
    finally:
        await store.close()

    assert hook_ctx.derived["observed_window_hours"] == pytest.approx(
        (4 * 60_000 + 50) / 3_600_000
    )
