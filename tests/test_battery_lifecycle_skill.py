# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
from pathlib import Path

import pytest

from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning.rule_engine import RuleEngine
from ori.skills.hooks_api import HookContext
from ori.skills.loader import SkillLoader


class _Store:
    def __init__(self) -> None:
        self._state: dict[tuple[str, str], str] = {}

    def _get_history_sync(self, _sensor_id: str, _limit: int):
        return []

    def _avg_last_hours_sync(self, _sensor_id: str, _hours: int):
        return None

    def _get_skill_state_sync(self, skill_name: str, key: str) -> str | None:
        return self._state.get((skill_name, key))

    def _set_skill_state_sync(self, skill_name: str, key: str, value: str) -> None:
        self._state[(skill_name, key)] = value

    def hooks_get_history(self, sensor_id: str, limit: int = 1):
        return self._get_history_sync(sensor_id, limit)

    def hooks_avg_last_hours(self, sensor_id: str, hours: int):
        return self._avg_last_hours_sync(sensor_id, hours)

    def hooks_avg_last_n(self, sensor_id: str, n: int):
        rows = self._get_history_sync(sensor_id, n)
        if not rows:
            return None
        return sum(r.value for r in rows) / len(rows)

    def hooks_get_skill_state(self, skill_name: str, key: str) -> str | None:
        return self._get_skill_state_sync(skill_name, key)

    def hooks_set_skill_state(self, skill_name: str, key: str, value: str) -> None:
        self._set_skill_state_sync(skill_name, key, value)


def _skill_dir() -> Path:
    return Path(__file__).parent.parent / "skills" / "battery-lifecycle-observer"


def _load_skill():
    return SkillLoader().load_one(_skill_dir())


def _ts_utc(year: int, month: int, day: int, hour: int, minute: int = 0) -> int:
    return int(
        datetime(year, month, day, hour, minute, tzinfo=timezone.utc).timestamp() * 1000
    )


def _event(
    *,
    sensor_id: str,
    sensor_type: str,
    value: float,
    quality: float = 1.0,
    timestamp: int,
) -> OriEvent:
    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit="percent",
        timestamp=timestamp,
        quality=quality,
        metadata={},
    )
    return OriEvent.from_reading(reading, "battery-site-01")


def _ctx(skill, event, store):
    hook_ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
    skill.hooks.pre_trigger_eval(hook_ctx)
    context = dict(skill.config)
    context.update(hook_ctx.derived)
    return hook_ctx, context


@pytest.mark.asyncio
async def test_skill_loads_with_expected_triggers():
    skill = _load_skill()
    assert skill.name == "battery-lifecycle-observer"
    assert len(skill.triggers) == 3
    assert {t.action_tier for t in skill.triggers} == {"A"}


@pytest.mark.asyncio
async def test_deep_discharge_risk_matches_after_persistence_window():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    skill.config["low_soc_persistence_minutes"] = 1
    store = _Store()

    first = _event(
        sensor_id="bat-soc-1",
        sensor_type="growatt_battery_soc",
        value=18.0,
        timestamp=_ts_utc(2024, 3, 9, 12, 0),
    )
    _ctx(skill, first, store)

    second = _event(
        sensor_id="bat-soc-1",
        sensor_type="growatt_battery_soc",
        value=17.5,
        timestamp=_ts_utc(2024, 3, 9, 12, 2),
    )
    _, context = _ctx(skill, second, store)
    trigger = next(t for t in skill.triggers if t.name == "battery_deep_discharge_risk")
    result = await RuleEngine().evaluate(second, [trigger], context=context)
    assert result.matched is True


@pytest.mark.asyncio
async def test_cycle_stress_matches_when_weekly_efc_crosses_threshold():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    skill.config["efc_warning_threshold_weekly"] = 0.2
    store = _Store()

    points = [
        ("growatt_battery_soc", 90.0, _ts_utc(2024, 3, 9, 12, 0)),
        ("growatt_battery_soc", 60.0, _ts_utc(2024, 3, 9, 12, 10)),
        ("growatt_battery_soc", 80.0, _ts_utc(2024, 3, 9, 12, 20)),
    ]
    event = None
    context = {}
    for sensor_type, value, ts in points:
        event = _event(
            sensor_id="bat-soc-1",
            sensor_type=sensor_type,
            value=value,
            timestamp=ts,
        )
        _, context = _ctx(skill, event, store)
    assert event is not None
    trigger = next(t for t in skill.triggers if t.name == "battery_cycle_stress")
    result = await RuleEngine().evaluate(event, [trigger], context=context)
    assert result.matched is True
    assert context["weekly_efc"] >= 0.2


@pytest.mark.asyncio
async def test_olax_voltage_decay_matches_during_outage():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    skill.config["olax_min_outage_minutes"] = 5
    skill.config["olax_decay_threshold_v_per_hour"] = 1.0
    store = _Store()

    grid_drop = _event(
        sensor_id="grid-voltage",
        sensor_type="ads1115_voltage",
        value=150.0,
        timestamp=_ts_utc(2024, 3, 9, 12, 0),
    )
    _ctx(skill, grid_drop, store)

    first_batt = _event(
        sensor_id="olax-battery-voltage",
        sensor_type="ads1115_voltage",
        value=12.4,
        timestamp=_ts_utc(2024, 3, 9, 12, 1),
    )
    _ctx(skill, first_batt, store)

    second_batt = _event(
        sensor_id="olax-battery-voltage",
        sensor_type="ads1115_voltage",
        value=12.1,
        timestamp=_ts_utc(2024, 3, 9, 12, 11),
    )
    _, context = _ctx(skill, second_batt, store)

    trigger = next(t for t in skill.triggers if t.name == "olax_voltage_decay_degraded")
    result = await RuleEngine().evaluate(second_batt, [trigger], context=context)
    assert result.matched is True
    assert context["outage_active"] == 1
    assert context["voltage_decay_v_per_hour"] >= 1.0


@pytest.mark.asyncio
async def test_grid_power_fallback_clears_outage_on_recovery():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    skill.config["grid_voltage_sensor_ids"] = []
    store = _Store()

    outage = _event(
        sensor_id="growatt-grid-power-1",
        sensor_type="growatt_grid_power",
        value=0.0,
        timestamp=_ts_utc(2024, 3, 9, 12, 0),
    )
    _ctx(skill, outage, store)

    recovered = _event(
        sensor_id="growatt-grid-power-1",
        sensor_type="growatt_grid_power",
        value=450.0,
        timestamp=_ts_utc(2024, 3, 9, 12, 1),
    )
    _, context = _ctx(skill, recovered, store)
    assert context["outage_active"] == 0
    assert context["outage_duration_minutes"] == 0.0


def test_post_reasoning_uses_plain_language_sms_bounded_text():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()
    event = _event(
        sensor_id="bat-soc-1",
        sensor_type="growatt_battery_soc",
        value=18.0,
        timestamp=_ts_utc(2024, 3, 9, 12, 0),
    )
    hook_ctx, _ = _ctx(skill, event, store)
    hook_ctx.trigger_name = "battery_deep_discharge_risk"

    result = ReasoningResult(
        text="Battery anomaly threshold crossed with voltage concern.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
    )
    updated = skill.hooks.post_reasoning(result, hook_ctx)
    assert updated.text.startswith("At ")
    assert len(updated.text) <= 160
    lower = updated.text.lower()
    for token in ("anomaly", "threshold", "voltage"):
        assert token not in lower
