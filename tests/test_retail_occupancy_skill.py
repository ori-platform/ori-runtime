# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning.rule_engine import RuleEngine
from ori.skills.hooks_api import HookContext
from ori.skills.loader import SkillLoader, SkillValidationError


class _Store:
    def __init__(self) -> None:
        self._history: dict[str, list[SensorReading]] = {}
        self._state: dict[tuple[str, str], str] = {}

    def add_history(self, sensor_id: str, reading: SensorReading) -> None:
        self._history.setdefault(sensor_id, []).insert(0, reading)

    def hooks_get_history(self, sensor_id: str, limit: int = 1) -> list[SensorReading]:
        return self._history.get(sensor_id, [])[:limit]

    def hooks_avg_last_hours(self, sensor_id: str, _hours: int) -> float | None:
        rows = self._history.get(sensor_id, [])
        if not rows:
            return None
        return sum(r.value for r in rows) / len(rows)

    def hooks_avg_last_n(self, sensor_id: str, n: int) -> float | None:
        rows = self.hooks_get_history(sensor_id, n)
        if not rows:
            return None
        return sum(r.value for r in rows) / len(rows)

    def hooks_get_skill_state(self, skill_name: str, key: str) -> str | None:
        return self._state.get((skill_name, key))

    def hooks_set_skill_state(self, skill_name: str, key: str, value: str) -> None:
        self._state[(skill_name, key)] = value


def _skill_dir() -> Path:
    return Path(__file__).parent.parent / "skills" / "retail-occupancy-optimizer"


def _load_skill(path: Path | None = None):
    return SkillLoader().load_one(path or _skill_dir())


def _ts_utc(year: int, month: int, day: int, hour: int, minute: int = 0) -> int:
    return int(
        datetime(year, month, day, hour, minute, tzinfo=timezone.utc).timestamp() * 1000
    )


def _event(
    *,
    sensor_id: str,
    sensor_type: str,
    value: float,
    timestamp: int,
    quality: float = 1.0,
) -> OriEvent:
    unit = "count" if sensor_type == "occupancy_count" else "watt"
    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp=timestamp,
        quality=quality,
        metadata={"source": "mqtt"},
    )
    event = OriEvent.from_reading(reading, "retail-site-01")
    event.context = {"device_timezone": "Africa/Lagos"}
    return event


def _ctx(skill, event, store):
    hook_ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
    skill.hooks.pre_trigger_eval(hook_ctx)
    context = dict(skill.config)
    context.update(hook_ctx.derived)
    return hook_ctx, context


def _seed_power_baseline(store: _Store, sensor_id: str, values: list[float]) -> None:
    base_ts = _ts_utc(2024, 3, 1, 12)
    for idx, value in enumerate(values):
        reading = SensorReading(
            sensor_id=sensor_id,
            sensor_type="total_power_watts",
            value=value,
            unit="watt",
            timestamp=base_ts + idx,
            quality=1.0,
            metadata={"source": "mqtt"},
        )
        store.add_history(sensor_id, reading)


def _prime_empty_occupancy(skill, store: _Store, *, timestamp: int) -> None:
    occupancy_event = _event(
        sensor_id="front-door-counter",
        sensor_type="occupancy_count",
        value=0.0,
        timestamp=timestamp,
    )
    _ctx(skill, occupancy_event, store)


@pytest.mark.asyncio
async def test_skill_loads_with_expected_tiers_and_policies():
    skill = _load_skill()

    assert skill.name == "retail-occupancy-optimizer"
    assert {trigger.name for trigger in skill.triggers} == {
        "empty_business_hours_high_power",
        "empty_off_hours_load_shed",
    }
    tier_c = next(
        t for t in skill.triggers if t.name == "empty_business_hours_high_power"
    )
    tier_b = next(t for t in skill.triggers if t.name == "empty_off_hours_load_shed")
    assert tier_c.action_tier == "C"
    assert tier_c.requires_approval is True
    assert tier_c.safe_default_action == "log_to_dashboard"
    assert tier_b.action_tier == "B"
    assert tier_b.reasoning_policy == "post_action"
    assert "alert_whatsapp" in skill.get_default_actions_for_trigger(tier_b.name)


@pytest.mark.asyncio
async def test_business_hours_empty_high_power_requests_tier_c_approval():
    skill = _load_skill()
    skill.config["timezone"] = "Africa/Lagos"
    skill.config["high_power_threshold_watts"] = 3000.0
    skill.config["high_power_baseline_multiplier"] = 1.2
    store = _Store()
    _seed_power_baseline(store, "site-total-power", [2000.0, 2100.0, 1900.0, 2000.0])
    _prime_empty_occupancy(skill, store, timestamp=_ts_utc(2024, 3, 11, 8, 0))

    power_event = _event(
        sensor_id="site-total-power",
        sensor_type="total_power_watts",
        value=3600.0,
        timestamp=_ts_utc(2024, 3, 11, 8, 50),  # 09:50 Africa/Lagos business hours
        quality=0.95,
    )
    _, context = _ctx(skill, power_event, store)
    trigger = next(
        t for t in skill.triggers if t.name == "empty_business_hours_high_power"
    )

    result = await RuleEngine().evaluate(power_event, [trigger], context=context)

    assert context["facility_empty"] == 1
    assert context["business_hours"] == 1
    assert context["empty_duration_minutes"] >= 45
    assert context["power_waste_detected"] == 1
    assert result.matched is True
    assert result.action_tier == "C"
    assert result.requires_approval is True


@pytest.mark.asyncio
async def test_off_hours_empty_high_power_uses_tier_b_post_action():
    skill = _load_skill()
    skill.config["timezone"] = "Africa/Lagos"
    skill.config["high_power_threshold_watts"] = 3000.0
    store = _Store()
    _seed_power_baseline(store, "site-total-power", [1800.0, 2000.0, 1900.0, 2000.0])
    _prime_empty_occupancy(skill, store, timestamp=_ts_utc(2024, 3, 11, 20, 30))

    power_event = _event(
        sensor_id="site-total-power",
        sensor_type="total_power_watts",
        value=3800.0,
        timestamp=_ts_utc(2024, 3, 11, 21, 30),  # 22:30 Africa/Lagos off-hours
        quality=0.95,
    )
    _, context = _ctx(skill, power_event, store)
    trigger = next(t for t in skill.triggers if t.name == "empty_off_hours_load_shed")

    result = await RuleEngine().evaluate(power_event, [trigger], context=context)

    assert context["off_hours"] == 1
    assert context["power_waste_detected"] == 1
    assert result.matched is True
    assert result.action_tier == "B"
    assert result.reasoning_policy == "post_action"


@pytest.mark.asyncio
async def test_occupancy_present_suppresses_energy_reduction_triggers():
    skill = _load_skill()
    skill.config["timezone"] = "Africa/Lagos"
    skill.config["high_power_threshold_watts"] = 3000.0
    store = _Store()
    _seed_power_baseline(store, "site-total-power", [1800.0, 2000.0, 1900.0, 2000.0])

    occupied_event = _event(
        sensor_id="front-door-counter",
        sensor_type="occupancy_count",
        value=4.0,
        timestamp=_ts_utc(2024, 3, 11, 8, 0),
    )
    _ctx(skill, occupied_event, store)

    power_event = _event(
        sensor_id="site-total-power",
        sensor_type="total_power_watts",
        value=3800.0,
        timestamp=_ts_utc(2024, 3, 11, 8, 50),
        quality=0.95,
    )
    _, context = _ctx(skill, power_event, store)
    trigger = next(
        t for t in skill.triggers if t.name == "empty_business_hours_high_power"
    )

    result = await RuleEngine().evaluate(power_event, [trigger], context=context)

    assert context["facility_empty"] == 0
    assert context["power_waste_detected"] == 1
    assert result.matched is False


@pytest.mark.asyncio
async def test_missing_power_baseline_fails_closed():
    skill = _load_skill()
    skill.config["timezone"] = "Africa/Lagos"
    skill.config["high_power_threshold_watts"] = 3000.0
    store = _Store()
    _prime_empty_occupancy(skill, store, timestamp=_ts_utc(2024, 3, 11, 8, 0))

    power_event = _event(
        sensor_id="site-total-power",
        sensor_type="total_power_watts",
        value=5000.0,
        timestamp=_ts_utc(2024, 3, 11, 8, 50),
        quality=0.95,
    )
    _, context = _ctx(skill, power_event, store)
    trigger = next(
        t for t in skill.triggers if t.name == "empty_business_hours_high_power"
    )

    result = await RuleEngine().evaluate(power_event, [trigger], context=context)

    assert context["power_baseline_valid"] == 0
    assert context["power_waste_detected"] == 0
    assert result.matched is False


def test_post_reasoning_returns_plain_operator_message():
    skill = _load_skill()
    store = _Store()
    event = _event(
        sensor_id="site-total-power",
        sensor_type="total_power_watts",
        value=3800.0,
        timestamp=_ts_utc(2024, 3, 11, 21, 30),
    )
    hook_ctx, _ = _ctx(skill, event, store)
    hook_ctx.trigger_name = "empty_off_hours_load_shed"
    hook_ctx.derived["projected_waste_cost_daily"] = 5400.0

    result = ReasoningResult(
        text="The empty building is above baseline because HVAC and lighting stayed active.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
    )
    updated = skill.hooks.post_reasoning(result, hook_ctx)

    assert updated.text.startswith("At 22:30,")
    assert "shed non-critical load" in updated.text
    assert len(updated.text) <= 160
    assert "baseline" not in updated.text.lower()


@pytest.mark.asyncio
async def test_occupancy_present_suppresses_off_hours_trigger():
    skill = _load_skill()
    skill.config["timezone"] = "Africa/Lagos"
    skill.config["high_power_threshold_watts"] = 3000.0
    store = _Store()
    _seed_power_baseline(store, "site-total-power", [1800.0, 2000.0, 1900.0, 2000.0])

    occupied_event = _event(
        sensor_id="front-door-counter",
        sensor_type="occupancy_count",
        value=2.0,
        timestamp=_ts_utc(2024, 3, 11, 20, 30),
    )
    _ctx(skill, occupied_event, store)

    power_event = _event(
        sensor_id="site-total-power",
        sensor_type="total_power_watts",
        value=3800.0,
        timestamp=_ts_utc(2024, 3, 11, 21, 30),  # 22:30 WAT — off-hours
        quality=0.95,
    )
    _, context = _ctx(skill, power_event, store)
    trigger = next(t for t in skill.triggers if t.name == "empty_off_hours_load_shed")

    result = await RuleEngine().evaluate(power_event, [trigger], context=context)

    assert context["off_hours"] == 1
    assert context["facility_empty"] == 0
    assert result.matched is False


@pytest.mark.asyncio
async def test_off_hours_wraps_past_midnight():
    skill = _load_skill()
    skill.config["timezone"] = "Africa/Lagos"
    skill.config["high_power_threshold_watts"] = 2000.0
    skill.config["high_power_baseline_multiplier"] = 1.2
    store = _Store()
    _seed_power_baseline(store, "site-total-power", [1500.0, 1600.0, 1500.0, 1600.0])
    # Prime empty occupancy well before midnight UTC (so duration >> 45 min by 1 AM WAT)
    _prime_empty_occupancy(skill, store, timestamp=_ts_utc(2024, 3, 11, 20, 0))

    # 00:30 UTC = 01:30 WAT — well past midnight; off_hours must still be 1
    power_event = _event(
        sensor_id="site-total-power",
        sensor_type="total_power_watts",
        value=3000.0,
        timestamp=_ts_utc(2024, 3, 12, 0, 30),
        quality=0.95,
    )
    _, context = _ctx(skill, power_event, store)
    trigger = next(t for t in skill.triggers if t.name == "empty_off_hours_load_shed")

    result = await RuleEngine().evaluate(power_event, [trigger], context=context)

    assert context["local_hour"] == 1  # 01:30 WAT
    assert context["off_hours"] == 1
    assert context["facility_empty"] == 1
    assert result.matched is True


def test_tier_c_safe_default_is_informational_not_physical():
    skill = _load_skill()
    tier_c = next(
        t for t in skill.triggers if t.name == "empty_business_hours_high_power"
    )
    available_by_name = {a["name"]: a for a in skill.actions.get("available", [])}
    safe_default = tier_c.safe_default_action
    assert safe_default == "log_to_dashboard"
    assert available_by_name[safe_default]["tier"] == "A"


def test_post_action_trigger_requires_tier_a_followup(tmp_path):
    skill_copy = tmp_path / "retail-occupancy-optimizer"
    shutil.copytree(_skill_dir(), skill_copy)
    yaml_path = skill_copy / "skill.yaml"
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    raw["actions"]["defaults"]["empty_off_hours_load_shed"] = ["shed_noncritical_loads"]
    yaml_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    with pytest.raises(SkillValidationError, match="no Tier A default action"):
        _load_skill(skill_copy)
