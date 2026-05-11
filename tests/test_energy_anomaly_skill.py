# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning.rule_engine import RuleEngine
from ori.skills.hooks_api import HookContext
from ori.skills.loader import SkillLoader


class _Store:
    def __init__(self) -> None:
        self._history: dict[str, list[SensorReading]] = {}

    def add_history(self, sensor_id: str, reading: SensorReading) -> None:
        self._history.setdefault(sensor_id, []).insert(0, reading)

    def _get_history_sync(self, sensor_id: str, limit: int) -> list[SensorReading]:
        return self._history.get(sensor_id, [])[:limit]

    def _avg_last_hours_sync(self, sensor_id: str, _hours: int) -> float | None:
        rows = self._history.get(sensor_id, [])
        if not rows:
            return None
        return sum(r.value for r in rows) / len(rows)

    def hooks_get_history(self, sensor_id: str, limit: int = 1) -> list[SensorReading]:
        return self._get_history_sync(sensor_id, limit)

    def hooks_avg_last_hours(self, sensor_id: str, hours: int) -> float | None:
        return self._avg_last_hours_sync(sensor_id, hours)

    def hooks_avg_last_n(self, sensor_id: str, n: int) -> float | None:
        rows = self._get_history_sync(sensor_id, n)
        if not rows:
            return None
        return sum(r.value for r in rows) / len(rows)


def _skill_dir() -> Path:
    return Path(__file__).parent.parent / "skills" / "energy-anomaly-detector"


def _load_skill():
    return SkillLoader().load_one(_skill_dir())


def _event(
    *,
    sensor_id: str = "load-current-01",
    sensor_type: str = "current_clamp",
    value: float,
    quality: float = 1.0,
    timestamp: int = 1_710_000_000_123,
) -> OriEvent:
    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit="ampere",
        timestamp=timestamp,
        quality=quality,
        metadata={"source": "i2c"},
    )
    return OriEvent.from_reading(reading, "energy-site-01")


def _ctx(skill, event, store):
    hook_ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
    skill.hooks.pre_trigger_eval(hook_ctx)
    context = dict(skill.config)
    context.update(hook_ctx.derived)
    return hook_ctx, context


def _history_reading(sensor_id: str, value: float, ts: int) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type="current_clamp",
        value=value,
        unit="ampere",
        timestamp=ts,
        quality=1.0,
        metadata={"source": "i2c"},
    )


def _seed_history(store: _Store, sensor_id: str, values: list[float]) -> None:
    base_ts = 1_709_999_000_000
    for idx, value in enumerate(reversed(values)):
        store.add_history(sensor_id, _history_reading(sensor_id, value, base_ts + idx))


@pytest.mark.asyncio
async def test_skill_loads_with_v2_triggers():
    skill = _load_skill()
    assert skill.name == "energy-anomaly-detector"
    assert len(skill.triggers) == 4
    assert {trigger.action_tier for trigger in skill.triggers} == {"A", "D"}


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
