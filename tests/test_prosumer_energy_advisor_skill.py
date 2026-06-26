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
    return Path(__file__).parent.parent / "skills" / "prosumer-energy-advisor"


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
    unit = "percent" if sensor_type.endswith("_soc") else "watt"
    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp=timestamp,
        quality=quality,
        metadata={},
    )
    return OriEvent.from_reading(reading, "prosumer-site-01")


def _ctx(skill, event, store):
    hook_ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
    skill.hooks.pre_trigger_eval(hook_ctx)
    context = dict(skill.config)
    context.update(hook_ctx.derived)
    return hook_ctx, context


async def _matches(skill, event, store, trigger_name: str) -> tuple[bool, dict]:
    _, context = _ctx(skill, event, store)
    trigger = next(t for t in skill.triggers if t.name == trigger_name)
    result = await RuleEngine().evaluate(event, [trigger], context=context)
    return result.matched, context


@pytest.mark.asyncio
async def test_skill_loads_as_tier_a_only():
    skill = _load_skill()

    assert skill.name == "prosumer-energy-advisor"
    assert len(skill.triggers) == 3
    assert {trigger.action_tier for trigger in skill.triggers} == {"A"}
    assert {action["tier"] for action in skill.actions["available"]} == {"A"}


@pytest.mark.asyncio
async def test_self_consume_or_store_surplus_matches_when_export_credit_is_low():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 12)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="growatt_battery_soc",
            value=55.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="growatt_load_power",
            value=1200.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="pv",
        sensor_type="growatt_pv_power",
        value=2600.0,
        timestamp=ts,
    )

    matched, context = await _matches(
        skill, event, store, "self_consume_or_store_surplus"
    )

    assert matched is True
    assert context["surplus_watts"] == 1400.0
    assert context["export_credit_discounted"] == 1


@pytest.mark.asyncio
async def test_self_consume_or_store_surplus_blocks_when_export_credit_is_not_discounted():
    skill = _load_skill()
    skill.config["export_credit_naira_per_kwh"] = 250.0
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 12)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="growatt_battery_soc",
            value=55.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="growatt_load_power",
            value=1200.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="pv",
        sensor_type="growatt_pv_power",
        value=2600.0,
        timestamp=ts,
    )

    matched, context = await _matches(
        skill, event, store, "self_consume_or_store_surplus"
    )

    assert matched is False
    assert context["export_credit_discounted"] == 0


@pytest.mark.asyncio
async def test_export_cap_approaching_matches_on_signed_export_power():
    skill = _load_skill()
    skill.config["export_cap_watts"] = 1000.0
    skill.config["export_cap_warning_ratio"] = 0.8
    store = _Store()
    event = _event(
        sensor_id="grid",
        sensor_type="deye_grid_power",
        value=-850.0,
        timestamp=_ts_utc(2026, 6, 26, 12),
    )

    matched, context = await _matches(skill, event, store, "export_cap_approaching")

    assert matched is True
    assert context["grid_export_watts"] == 850.0
    assert context["export_cap_warning_watts"] == 800.0


@pytest.mark.asyncio
async def test_defer_deferrable_load_matches_when_import_high_and_reserve_low():
    skill = _load_skill()
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 19)

    _ctx(
        skill,
        _event(
            sensor_id="pv",
            sensor_type="deye_pv1_power",
            value=120.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="deye_battery_soc",
            value=32.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="grid",
        sensor_type="deye_grid_power",
        value=1500.0,
        timestamp=ts,
    )

    matched, context = await _matches(skill, event, store, "defer_deferrable_load")

    assert matched is True
    assert context["grid_import_watts"] == 1500.0
    assert context["battery_soc_snapshot"] == 32.0
    assert context["pv_watts_snapshot"] == 120.0


def test_post_reasoning_is_bounded_tier_a_advisory_text():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()
    event = _event(
        sensor_id="grid",
        sensor_type="deye_grid_power",
        value=-850.0,
        timestamp=_ts_utc(2026, 6, 26, 12),
    )
    hook_ctx, _ = _ctx(skill, event, store)
    hook_ctx.trigger_name = "export_cap_approaching"
    result = ReasoningResult(
        text="The threshold anomaly indicates a command should be issued to the inverter.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
        action_tier="B",
        proposed_action="change_inverter_export_limit",
    )

    updated = skill.hooks.post_reasoning(result, hook_ctx)

    assert updated.action_tier == "A"
    assert updated.proposed_action is None
    assert len(updated.text) <= 160
    assert "Ori changed" not in updated.text
    assert "command" not in updated.text.lower()
