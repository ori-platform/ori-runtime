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
        self._history: dict[str, list[SensorReading]] = {}
        self._state: dict[tuple[str, str], str] = {}

    def _get_history_sync(self, sensor_id: str, limit: int) -> list[SensorReading]:
        return self._history.get(sensor_id, [])[:limit]

    def _avg_last_hours_sync(self, sensor_id: str, _hours: int) -> float | None:
        rows = self._history.get(sensor_id, [])
        if not rows:
            return None
        return sum(r.value for r in rows) / len(rows)

    def _get_skill_state_sync(self, skill_name: str, key: str) -> str | None:
        return self._state.get((skill_name, key))

    def _set_skill_state_sync(self, skill_name: str, key: str, value: str) -> None:
        self._state[(skill_name, key)] = value


def _skill_dir() -> Path:
    return Path(__file__).parent.parent / "skills" / "solar-performance-monitor"


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
    metadata: dict | None = None,
) -> OriEvent:
    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit="watt" if "power" in sensor_type else "percent",
        timestamp=timestamp,
        quality=quality,
        metadata=metadata or {},
    )
    return OriEvent.from_reading(reading, "solar-site-01")


def _ctx(skill, event, store):
    hook_ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
    skill.hooks.pre_trigger_eval(hook_ctx)
    context = dict(skill.config)
    context.update(hook_ctx.derived)
    return hook_ctx, context


@pytest.mark.asyncio
async def test_skill_loads_with_expected_triggers():
    skill = _load_skill()
    assert skill.name == "solar-performance-monitor"
    assert len(skill.triggers) == 3
    assert {t.action_tier for t in skill.triggers} == {"A"}


@pytest.mark.asyncio
async def test_underperforming_daytime_matches_with_low_pv_ratio():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()

    event = _event(
        sensor_id="pv-1",
        sensor_type="growatt_pv_power",
        value=300.0,
        quality=0.95,
        timestamp=_ts_utc(2024, 3, 9, 12),
    )
    _, context = _ctx(skill, event, store)
    trigger = next(
        t for t in skill.triggers if t.name == "solar_underperforming_daytime"
    )
    result = await RuleEngine().evaluate(event, [trigger], context=context)
    assert result.matched is True


@pytest.mark.asyncio
async def test_daytime_gate_blocks_alert_outside_window():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()

    event = _event(
        sensor_id="pv-1",
        sensor_type="growatt_pv_power",
        value=300.0,
        quality=0.95,
        timestamp=_ts_utc(2024, 3, 9, 2),
    )
    _, context = _ctx(skill, event, store)
    trigger = next(
        t for t in skill.triggers if t.name == "solar_underperforming_daytime"
    )
    result = await RuleEngine().evaluate(event, [trigger], context=context)
    assert context["is_daytime"] == 0
    assert result.matched is False


@pytest.mark.asyncio
async def test_required_capacity_config_is_enforced_via_guard():
    skill = _load_skill()
    skill.config["installed_pv_capacity_watts"] = 0.0
    store = _Store()

    event = _event(
        sensor_id="pv-1",
        sensor_type="growatt_pv_power",
        value=300.0,
        quality=0.95,
        timestamp=_ts_utc(2024, 3, 9, 12),
    )
    _, context = _ctx(skill, event, store)
    trigger = next(
        t for t in skill.triggers if t.name == "solar_underperforming_daytime"
    )
    result = await RuleEngine().evaluate(event, [trigger], context=context)
    assert context["config_valid"] == 0
    assert result.matched is False


@pytest.mark.asyncio
async def test_battery_not_charging_matches_when_pv_ratio_is_high():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()

    # Seed PV ratio snapshot at good sun.
    pv_event = _event(
        sensor_id="pv-1",
        sensor_type="growatt_pv_power",
        value=3500.0,
        quality=0.95,
        timestamp=_ts_utc(2024, 3, 9, 12),
    )
    _ctx(skill, pv_event, store)

    # Seed prior battery SOC.
    first_soc = _event(
        sensor_id="bat-1",
        sensor_type="growatt_battery_soc",
        value=80.0,
        quality=0.95,
        timestamp=_ts_utc(2024, 3, 9, 12, 5),
    )
    _ctx(skill, first_soc, store)

    # SOC drops despite good sun.
    second_soc = _event(
        sensor_id="bat-1",
        sensor_type="growatt_battery_soc",
        value=79.5,
        quality=0.95,
        timestamp=_ts_utc(2024, 3, 9, 12, 10),
    )
    _, context = _ctx(skill, second_soc, store)
    trigger = next(
        t for t in skill.triggers if t.name == "battery_not_charging_when_pv_available"
    )
    result = await RuleEngine().evaluate(second_soc, [trigger], context=context)
    assert result.matched is True


@pytest.mark.asyncio
async def test_battery_not_charging_does_not_match_when_soc_is_already_high():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    skill.config["battery_not_full_soc_threshold"] = 95.0
    store = _Store()

    pv_event = _event(
        sensor_id="pv-1",
        sensor_type="growatt_pv_power",
        value=3500.0,
        quality=0.95,
        timestamp=_ts_utc(2024, 3, 9, 12),
    )
    _ctx(skill, pv_event, store)

    first_soc = _event(
        sensor_id="bat-1",
        sensor_type="growatt_battery_soc",
        value=98.0,
        quality=0.95,
        timestamp=_ts_utc(2024, 3, 9, 12, 5),
    )
    _ctx(skill, first_soc, store)

    second_soc = _event(
        sensor_id="bat-1",
        sensor_type="growatt_battery_soc",
        value=98.0,
        quality=0.95,
        timestamp=_ts_utc(2024, 3, 9, 12, 10),
    )
    _, context = _ctx(skill, second_soc, store)
    trigger = next(
        t for t in skill.triggers if t.name == "battery_not_charging_when_pv_available"
    )
    result = await RuleEngine().evaluate(second_soc, [trigger], context=context)
    assert result.matched is False


@pytest.mark.asyncio
async def test_unexpected_grid_draw_matches_when_sun_is_good():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()

    pv_event = _event(
        sensor_id="pv-1",
        sensor_type="victron_pv_power",
        value=3000.0,
        quality=0.95,
        timestamp=_ts_utc(2024, 3, 9, 12),
    )
    _ctx(skill, pv_event, store)

    grid_event = _event(
        sensor_id="grid-1",
        sensor_type="victron_grid_power",
        value=900.0,
        quality=0.95,
        timestamp=_ts_utc(2024, 3, 9, 12, 5),
    )
    _, context = _ctx(skill, grid_event, store)
    trigger = next(
        t for t in skill.triggers if t.name == "unexpected_grid_draw_with_good_sun"
    )
    result = await RuleEngine().evaluate(grid_event, [trigger], context=context)
    assert result.matched is True


def test_post_reasoning_uses_plain_language_sms_bounded_text():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()
    event = _event(
        sensor_id="pv-1",
        sensor_type="growatt_pv_power",
        value=400.0,
        quality=0.95,
        timestamp=_ts_utc(2024, 3, 9, 12),
    )
    hook_ctx, _ = _ctx(skill, event, store)
    hook_ctx.trigger_name = "solar_underperforming_daytime"
    result = ReasoningResult(
        text="PV anomaly threshold crossed with low voltage reading.",
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
