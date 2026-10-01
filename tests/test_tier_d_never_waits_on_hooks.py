# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A Tier D condition is decided before any skill hook runs, and a hook cannot hold it.

The shipped skills are loaded through the real loader and registered on a real
event bus, and latency is measured from the reading's publication on that bus.
Each bundled Tier D trigger here carries notifications only; what is timed is
the first act its plan reaches.
"""

from __future__ import annotations

import asyncio
import shutil
import time
from pathlib import Path
from typing import Any

import pytest

from ori.network.event_bus import EventBus
from ori.network.events import OriEvent, SensorReading
from ori.reasoning.rule_engine import RULES_ALL, RuleEngine, evaluate_condition_safely
from ori.skills.loader import (
    SkillLoader,
    SkillValidationError,
    _hook_supplied_names,
)
from tests.test_dispatch_never_waits_on_delivery import (
    _MALFORMED_RECEIPT,
    _TRIP_BOUND_S,
    DEVICE,
    _pi_sized_default_executor,
    _Site,
    _site,
    _until,
)

_SKILLS = Path(__file__).resolve().parent.parent / "skills"
_READING_NAMES = {"value", "sensor_id", "sensor_type", "unit", "quality"}

#: A bundled skill, the reading that meets its Tier D condition, and the trigger.
_TIER_D_READINGS = {
    "energy-anomaly-detector": ("dangerous_overcurrent", "current_clamp", 30.0),
    "battery-lifecycle-observer": (
        "battery_emergency_cutoff",
        "growatt_battery_soc",
        3.0,
    ),
}


def _reading(sensor_type: str, value: float) -> OriEvent:
    return OriEvent.from_reading(
        SensorReading(
            sensor_id="sensor-1",
            sensor_type=sensor_type,
            value=value,
            unit="x",
            timestamp=int(time.time() * 1000),
            quality=1.0,
        ),
        DEVICE,
    )


def _register(site: _Site, names: list[str]) -> tuple[EventBus, list[Any]]:
    """Load *names* from the shipped skills and register them as the runtime does."""
    site.coordinator._skills = []
    site.dispatcher.register_executor(
        "alert_whatsapp", site.acts.executor("alert_whatsapp")
    )
    loader = SkillLoader(
        elevator=site.coordinator._elevator,
        state_store=site.store,
        dispatcher=site.dispatcher,
        coordinator=site.coordinator,
    )
    bus = EventBus()
    skills = [s for s in loader.load_all(str(_SKILLS)) if s.name in names]
    assert sorted(s.name for s in skills) == sorted(names)
    for skill in skills:
        loader.register(skill, bus)
    return bus, skills


async def _first_act(
    site: _Site, bus: EventBus, trigger: str, event: OriEvent
) -> float:
    """Seconds from publication on the bus to the trigger's first act."""
    fired = site.acts.by_trigger.setdefault(trigger, [])
    before = len(fired)
    started = time.monotonic()
    await bus.publish(event)
    await _until(lambda: len(fired) > before)
    assert len(fired) > before, f"{trigger} did not fire: {site.acts.by_trigger}"
    return fired[before][1] - started


class TestAHookCannotHoldATrip:
    @pytest.mark.parametrize("name", sorted(_TIER_D_READINGS))
    async def test_a_hook_that_never_returns(self, name: str, tmp_path: Path) -> None:
        """The hook awaits forever; the trip runs regardless, on every reading."""
        trigger, sensor_type, value = _TIER_D_READINGS[name]
        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, [name])
            never = asyncio.Event()
            called: list[float] = []

            async def blocked(_context: Any) -> None:
                called.append(time.monotonic())
                await never.wait()

            skill.hooks.pre_trigger_eval = blocked
            try:
                for _ in range(2):
                    latency = await _first_act(
                        site, bus, trigger, _reading(sensor_type, value)
                    )
                    assert latency < _TRIP_BOUND_S, latency
                await _until(lambda: bool(called))
                assert called, "the hook was never reached"
            finally:
                never.set()

    @pytest.mark.parametrize("name", sorted(_TIER_D_READINGS))
    async def test_a_hook_that_blocks_the_loop_runs_after_the_trip(
        self, name: str, tmp_path: Path
    ) -> None:
        trigger, sensor_type, value = _TIER_D_READINGS[name]
        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, [name])
            called: list[float] = []

            def blocking(_context: Any) -> None:
                called.append(time.monotonic())
                time.sleep(0.5)

            skill.hooks.pre_trigger_eval = blocking
            latency = await _first_act(site, bus, trigger, _reading(sensor_type, value))
            assert latency < _TRIP_BOUND_S, latency
            fired = site.acts.by_trigger[trigger]
            await _until(lambda: bool(called))
            assert called and called[0] >= fired[0][1], "the hook ran before the trip"

    @pytest.mark.parametrize("name", sorted(_TIER_D_READINGS))
    async def test_flood_and_both_stores_locked_with_the_hook_held(
        self, name: str, tmp_path: Path
    ) -> None:
        trigger, sensor_type, value = _TIER_D_READINGS[name]
        _pi_sized_default_executor()
        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, [name])
            never = asyncio.Event()

            async def blocked(_context: Any) -> None:
                await never.wait()

            skill.hooks.pre_trigger_eval = blocked
            await site.start_routes()
            site.lock("state.db")
            site.lock("evidence.db")
            site.flood_inbound(_MALFORMED_RECEIPT)
            await asyncio.sleep(0.2)
            try:
                latency = await _first_act(
                    site, bus, trigger, _reading(sensor_type, value)
                )
                assert latency < _TRIP_BOUND_S, latency
            finally:
                never.set()
                site.release()


class TestTheRuntimeDecidesTierDWithoutAHook:
    async def test_the_tier_d_context_carries_no_hook_output(
        self, tmp_path: Path
    ) -> None:
        """A Tier D condition naming a hook-only name is refused when evaluated."""
        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, ["energy-anomaly-detector"])
            target = next(
                t for t in skill.triggers if t.name == "dangerous_overcurrent"
            )
            original = target.condition
            target.condition = "value > 1 and only_a_hook_sets_this == 1"

            def supplies(context: Any) -> None:
                context.derived["only_a_hook_sets_this"] = 1

            skill.hooks.pre_trigger_eval = supplies
            try:
                await bus.publish(_reading("current_clamp", 30.0))
                await site._finish_dispatches()
                await site.coordinator.drain(timeout=2.0)
                assert "dangerous_overcurrent" not in site.acts.by_trigger
            finally:
                target.condition = original


class TestTheLoaderRefusesATierDConditionAHookDecides:
    def test_a_hook_only_name_is_refused(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "battery-lifecycle-observer"
        shutil.copytree(_SKILLS / "battery-lifecycle-observer", skill_dir)
        manifest = skill_dir / "skill.yaml"
        manifest.write_text(
            manifest.read_text().replace(
                "sensor_type == 'battery_percent') and value",
                "is_soc_sensor == 1) and value",
            )
        )
        loader = SkillLoader()
        loader._is_core_bundled_skill = lambda _path: True  # type: ignore[method-assign]
        with pytest.raises(SkillValidationError, match="only a hook supplies"):
            loader.load_one(skill_dir)

    def test_a_configured_name_the_hook_also_copies_is_allowed(self) -> None:
        names = _hook_supplied_names(_SKILLS / "energy-anomaly-detector" / "hooks.py")
        assert "dangerous_overcurrent_threshold" in names
        loaded = {s.name for s in SkillLoader().load_all(str(_SKILLS))}
        assert {"energy-anomaly-detector", "battery-lifecycle-observer"} <= loaded

    def test_every_hook_write_form_is_seen(self, tmp_path: Path) -> None:
        hooks = tmp_path / "hooks.py"
        hooks.write_text(
            "def pre_trigger_eval(context):\n"
            "    context.derived['a'] = 1\n"
            "    context.derived.update({'b': 2}, c=3)\n"
            "    context.derived.setdefault('d', 4)\n"
        )
        assert _hook_supplied_names(hooks) == {"a", "b", "c", "d"}

    def test_every_shipped_tier_d_condition_names_only_the_reading_or_config(
        self,
    ) -> None:
        import ast

        skills = SkillLoader().load_all(str(_SKILLS))
        assert len(skills) == len(
            [p for p in _SKILLS.iterdir() if (p / "skill.yaml").is_file()]
        ) - int((_SKILLS / "template" / "skill.yaml").is_file()), (
            "a shipped skill no longer loads"
        )
        for skill in skills:
            for trigger in skill.triggers:
                if trigger.action_tier != "D":
                    continue
                named = {
                    n.id
                    for n in ast.walk(ast.parse(trigger.condition, mode="eval"))
                    if isinstance(n, ast.Name)
                }
                unknown = named - _READING_NAMES - set(skill.config)
                assert not unknown, f"{skill.name}.{trigger.name}: {sorted(unknown)}"

    def test_a_name_nothing_supplies_is_refused(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "hvac-refrigerant-monitor"
        shutil.copytree(_SKILLS / "hvac-refrigerant-monitor", skill_dir)
        manifest = skill_dir / "skill.yaml"
        text = manifest.read_text()
        assert "value > 400" in text
        manifest.write_text(
            text.replace("value > 400", "value > gas_limit_nobody_sets")
        )
        loader = SkillLoader()
        loader._is_core_bundled_skill = lambda _path: True  # type: ignore[method-assign]
        with pytest.raises(SkillValidationError, match="nothing supplies them"):
            loader.load_one(skill_dir)

    def test_only_the_skills_own_configuration_is_allowed(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "hvac-refrigerant-monitor"
        shutil.copytree(_SKILLS / "hvac-refrigerant-monitor", skill_dir)
        manifest = skill_dir / "skill.yaml"
        text = manifest.read_text().replace("value > 400", "value > gas_limit")
        loader = SkillLoader()
        loader._is_core_bundled_skill = lambda _path: True  # type: ignore[method-assign]
        manifest.write_text(text)
        with pytest.raises(SkillValidationError):
            loader.load_one(skill_dir)
        manifest.write_text(text.replace("config:\n", "config:\n  gas_limit: 400\n", 1))
        skill = loader.load_one(skill_dir)
        assert skill.config["gas_limit"] == 400


class TestCpuOverheatingIsANotice:
    async def test_it_fires_on_a_hot_reading_only(self) -> None:
        skill = next(
            s
            for s in SkillLoader().load_all(str(_SKILLS))
            if s.name == "pc-system-health"
        )
        (trigger,) = [t for t in skill.triggers if t.name == "cpu_overheating"]
        assert trigger.action_tier == "A" and not trigger.bypass_llm
        engine = RuleEngine()

        def reading(value: float, quality: float) -> OriEvent:
            return OriEvent.from_reading(
                SensorReading(
                    sensor_id="cpu-temp",
                    sensor_type="cpu_temp",
                    value=value,
                    unit="celsius",
                    timestamp=int(time.time() * 1000),
                    quality=quality,
                ),
                DEVICE,
            )

        async def fires(event: OriEvent) -> bool:
            matches = await engine.evaluate_all(event, [trigger], dict(skill.config))
            return [m.rule_name for m in matches] == ["cpu_overheating"]

        assert await fires(reading(95.0, 1.0))
        assert not await fires(reading(60.0, 1.0))
        assert not await fires(reading(95.0, 0.0))


def test_set_threshold_cannot_raise_the_shipped_overcurrent_threshold() -> None:
    from ori.security.threshold_guard import check_tier_d_startup_sensitivity

    skill = next(
        s
        for s in SkillLoader().load_all(str(_SKILLS))
        if s.name == "energy-anomaly-detector"
    )
    startup = skill.config["dangerous_overcurrent_threshold"]
    ok, detail = check_tier_d_startup_sensitivity(
        skill,
        threshold_key="dangerous_overcurrent_threshold",
        new_value=startup + 5.0,
        startup_value=startup,
    )
    assert not ok and "less sensitive" in detail
    ok, _ = check_tier_d_startup_sensitivity(
        skill,
        threshold_key="dangerous_overcurrent_threshold",
        new_value=startup - 5.0,
        startup_value=startup,
    )
    assert ok


class TestTheRewrittenBatteryConditionTripsAsBefore:
    def test_every_eligible_reading_matches_as_the_hook_derived_form_did(
        self,
    ) -> None:
        """The old form read the hook's is_soc_sensor; the new one reads the type."""
        skill = next(
            s
            for s in SkillLoader().load_all(str(_SKILLS))
            if s.name == "battery-lifecycle-observer"
        )
        (trigger,) = [t for t in skill.triggers if t.action_tier == "D"]
        old = trigger.condition.replace(
            "sensor_type == 'battery_percent') and value",
            "is_soc_sensor == 1) and value",
        )
        assert old != trigger.condition
        soc_types = {"growatt_battery_soc", "victron_battery_soc", "battery_percent"}
        types = {str(s["type"]) for s in skill.sensors_required} | soc_types
        for sensor_type in sorted(types):
            for value in (0.0, 4.9, 5.0, 5.1, 50.0):
                base = {
                    **skill.config,
                    "value": value,
                    "sensor_type": sensor_type,
                }
                with_hook = {**base, "is_soc_sensor": int(sensor_type in soc_types)}
                assert evaluate_condition_safely(
                    trigger.condition, base
                ) == evaluate_condition_safely(old, with_hook), (sensor_type, value)


class TestTheOvercurrentThresholdIsTheConfiguredOne:
    async def test_the_tier_d_match_is_the_same_with_or_without_the_hook(
        self, tmp_path: Path
    ) -> None:
        skill = next(
            s
            for s in SkillLoader().load_all(str(_SKILLS))
            if s.name == "energy-anomaly-detector"
        )
        engine = RuleEngine()
        tier_d = [t for t in skill.triggers if t.name == "dangerous_overcurrent"]
        hooked: dict[str, Any] = {}

        class _Ctx:
            config = skill.config
            derived = hooked
            event = None

        skill.hooks.pre_trigger_eval(_Ctx())
        for value in (19.9, 20.0, 20.1, 40.0):
            event = _reading("current_clamp", value)
            plain = await engine.evaluate_all(event, tier_d, dict(skill.config))
            with_hook = await engine.evaluate_all(
                event, tier_d, {**skill.config, **hooked}, select=RULES_ALL
            )
            assert [r.rule_name for r in plain] == [r.rule_name for r in with_hook]
        assert (
            hooked["dangerous_overcurrent_threshold"]
            == skill.config["dangerous_overcurrent_threshold"]
        )
