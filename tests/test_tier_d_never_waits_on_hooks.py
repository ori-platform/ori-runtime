# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A Tier D condition is decided before any skill hook runs, and a hook cannot hold it.

The shipped skills are loaded through the real loader and registered on a real
event bus, and latency is measured from the reading's publication on that bus.
Each bundled Tier D trigger here is an unbound safety incident: it carries
notifications only, no protective outcome. What is timed is the first act its
plan reaches, a notification, never a proven physical trip.
"""

from __future__ import annotations

import asyncio
import shutil
import threading
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
)
from tests.test_dispatch_never_waits_on_delivery import (
    _MALFORMED_RECEIPT,
    _TRIP_BOUND_S,
    DEVICE,
    _pi_sized_default_executor,
    _Site,
    _site,
)
from tests.waiting import wait_until

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
    await wait_until(lambda: len(fired) > before, what="len(fired) > before")
    assert len(fired) > before, f"{trigger} did not fire: {site.acts.by_trigger}"
    return fired[before][1] - started


class TestAHookCannotHoldATierDIncident:
    @pytest.mark.parametrize("name", sorted(_TIER_D_READINGS))
    async def test_a_hook_that_never_returns(self, name: str, tmp_path: Path) -> None:
        """The hook awaits forever; the incident acts regardless, on every reading."""
        trigger, sensor_type, value = _TIER_D_READINGS[name]
        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, [name])
            never = threading.Event()
            called: list[float] = []

            def blocked(_context: Any) -> None:
                called.append(time.monotonic())
                never.wait(3.0)

            skill.hooks.pre_trigger_eval = blocked
            try:
                for _ in range(2):
                    latency = await _first_act(
                        site, bus, trigger, _reading(sensor_type, value)
                    )
                    assert latency < _TRIP_BOUND_S, latency
                await wait_until(lambda: bool(called), what="bool(called)")
                assert called, "the hook was never reached"
            finally:
                never.set()

    @pytest.mark.parametrize("name", sorted(_TIER_D_READINGS))
    async def test_a_hook_that_blocks_runs_after_the_incident_acts(
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
            await wait_until(lambda: bool(called), what="bool(called)")
            assert called and called[0] >= fired[0][1], (
                "the hook ran before the incident acted"
            )

    @pytest.mark.parametrize("name", sorted(_TIER_D_READINGS))
    async def test_flood_and_both_stores_locked_with_the_hook_held(
        self, name: str, tmp_path: Path
    ) -> None:
        trigger, sensor_type, value = _TIER_D_READINGS[name]
        _pi_sized_default_executor()
        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, [name])
            never = threading.Event()

            def blocked(_context: Any) -> None:
                never.wait(3.0)

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


def _publish_from_sensor_thread(
    bus: EventBus, loop: asyncio.AbstractEventLoop, event: OriEvent
) -> float:
    """Publish as a sensor does: from its own thread, timed on its own clock."""
    produced = time.monotonic()
    asyncio.run_coroutine_threadsafe(bus.publish(event), loop)
    return produced


#: A normal reading, then a critical one: the skill whose hook the first
#: reading runs, and the Tier D trigger the second must reach.
_FOLLOWED_BY_CRITICAL = {
    "battery-lifecycle-observer": (
        ("battery-lifecycle-observer", "growatt_battery_soc", 60.0),
        ("battery_emergency_cutoff", "growatt_battery_soc", 3.0),
    ),
    "energy-anomaly-detector": (
        ("energy-anomaly-detector", "current_clamp", 5.0),
        ("dangerous_overcurrent", "current_clamp", 30.0),
    ),
    "prosumer-then-overcurrent": (
        ("prosumer-energy-advisor", "power", 900.0),
        ("dangerous_overcurrent", "current_clamp", 30.0),
    ),
}


class TestAShippedHookCannotHoldTheNextIncident:
    @pytest.mark.parametrize("case", sorted(_FOLLOWED_BY_CRITICAL))
    async def test_a_critical_reading_after_a_normal_one_with_the_store_locked(
        self, case: str, tmp_path: Path
    ) -> None:
        """The shipped hooks, not stubs, run for the first reading with the
        state store held; the critical reading that follows from the sensor's
        own thread reaches its first act within the bound of that thread's clock."""
        (first_skill, first_type, first_value), (trigger, crit_type, crit_value) = (
            _FOLLOWED_BY_CRITICAL[case]
        )
        names = sorted(
            {first_skill, "battery-lifecycle-observer", "energy-anomaly-detector"}
        )
        async with _site(tmp_path) as site:
            bus, _skills = _register(site, names)
            for n in range(3):
                await site.store.append_history(_reading(crit_type, 5.0 + n))
            site.lock("state.db")
            loop = asyncio.get_running_loop()
            fired = site.acts.by_trigger.setdefault(trigger, [])
            produced: list[float] = []

            def sensor() -> None:
                _publish_from_sensor_thread(
                    bus, loop, _reading(first_type, first_value)
                )
                time.sleep(0.3)
                produced.append(
                    _publish_from_sensor_thread(
                        bus, loop, _reading(crit_type, crit_value)
                    )
                )

            thread = threading.Thread(target=sensor)
            thread.start()
            await asyncio.to_thread(thread.join, 5.0)
            await wait_until(lambda: bool(fired), what="bool(fired)")
            assert fired, f"{trigger} did not fire: {site.acts.by_trigger}"
            latency = fired[0][1] - produced[0]
            assert latency < _TRIP_BOUND_S, latency
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
        with pytest.raises(SkillValidationError, match="is_soc_sensor"):
            loader.load_one(skill_dir)

    def test_a_configured_name_the_hook_also_copies_is_allowed(self) -> None:
        loaded = {s.name for s in SkillLoader().load_all(str(_SKILLS))}
        assert {"energy-anomaly-detector", "battery-lifecycle-observer"} <= loaded

    @pytest.mark.parametrize("value", ["20", "true", ".nan", ".inf", "[1]"])
    def test_a_configured_tier_d_input_must_be_a_finite_number(
        self, value: str, tmp_path: Path
    ) -> None:
        skill_dir = tmp_path / "energy-anomaly-detector"
        shutil.copytree(_SKILLS / "energy-anomaly-detector", skill_dir)
        manifest = skill_dir / "skill.yaml"
        text = manifest.read_text()
        assert "  dangerous_overcurrent_threshold: 20.0\n" in text
        manifest.write_text(
            text.replace(
                "  dangerous_overcurrent_threshold: 20.0\n",
                f"  dangerous_overcurrent_threshold: {value if value != '20' else repr('20')}\n",
            )
        )
        loader = SkillLoader()
        loader._is_core_bundled_skill = lambda _path: True  # type: ignore[method-assign]
        with pytest.raises(SkillValidationError, match="not a finite number"):
            loader.load_one(skill_dir)

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
        with pytest.raises(SkillValidationError, match="gas_limit_nobody_sets"):
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


class TestTheRewrittenBatteryConditionMatchesAsBefore:
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
        # The hook strips the type before comparing; the condition does not.
        # A padded or recased type is not one the skill subscribes to, so it
        # never reaches either form.
        from ori.reasoning.dispatch_coordinator import DispatchCoordinator

        for sensor_type in sorted(types):
            for variant in (f" {sensor_type}", f"{sensor_type} ", sensor_type.upper()):
                assert not DispatchCoordinator._eligible(
                    skill, _reading(variant, 3.0)
                ), variant
        for sensor_type in sorted(types):
            for value in (0.0, 4.9, 5.0, 5.1, 50.0):
                base = {
                    **skill.config,
                    "value": value,
                    "sensor_type": sensor_type,
                }
                with_hook = {
                    **base,
                    "is_soc_sensor": int(sensor_type.strip() in soc_types),
                }
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


class TestAHookWriteNeverJoinsTheWritersTransaction:
    async def test_a_hook_commit_cannot_land_inside_a_writer_transaction(
        self, tmp_path: Path
    ) -> None:
        """A writer transaction, as an approval commit is, that rolls back.

        A hook writing skill state while it is open must neither commit the
        writer's half-done work nor wait out the store's busy timeout.
        """
        import sqlite3

        from ori.state.store import HOOK_BUSY_TIMEOUT_S, StateStore

        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        opened = threading.Event()
        finish = threading.Event()

        def half_done(_value: str) -> None:
            conn = store._conn
            assert conn is not None
            conn.execute(
                "INSERT INTO skill_state (skill_name, key, value, updated_at) "
                "VALUES ('writer', 'approval', 'half-done', 0)"
            )
            opened.set()
            finish.wait(5.0)
            conn.rollback()

        try:
            writer = asyncio.create_task(store._run_write(half_done, "x"))
            await asyncio.to_thread(opened.wait, 5.0)
            started = time.monotonic()
            with pytest.raises(sqlite3.OperationalError):
                store.hooks_set_skill_state("battery-lifecycle-observer", "k", "v")
            assert time.monotonic() - started < HOOK_BUSY_TIMEOUT_S + 0.2
            finish.set()
            await asyncio.wait_for(writer, 5.0)
            with sqlite3.connect(str(tmp_path / "state.db")) as reader:
                left = reader.execute(
                    "SELECT value FROM skill_state WHERE skill_name = 'writer'"
                ).fetchall()
            assert left == [], "a hook commit landed inside the writer's transaction"
        finally:
            finish.set()
            await store.close()


# ── Hooks run off the event loop ─────────────────────────────────────────────


def _stall(kind: str, release: threading.Event) -> Any:
    """A synchronous hook that stalls the way a real one could."""

    def hook(_context: Any) -> None:
        if kind == "event":
            release.wait(3.0)
        elif kind == "sleep":
            deadline = time.monotonic() + 3.0
            while not release.is_set() and time.monotonic() < deadline:
                time.sleep(0.05)
        else:  # cpu
            deadline = time.monotonic() + 30.0
            while not release.is_set() and time.monotonic() < deadline:
                sum(range(1000))

    return hook


class TestAStalledHookRunsOffTheLoop:
    @pytest.mark.latency_bound
    def test_a_cpu_bound_hook_in_a_fresh_interpreter(self) -> None:
        """The CPU-bound case, in an interpreter of its own.

        A pure-Python CPU-bound hook on the hook thread hands the interpreter
        lock back to the loop every switch interval; inside a long test session
        other threads contend for it too, so the case runs where only one
        runtime's own threads exist. It asserts the bound on the maximum over
        every reading and prints p50, p95 and max.
        """
        import os
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-s",
                "-p",
                "no:cacheprovider",
                __file__,
                "-k",
                "test_cpu_bound_hook_latency_over_many_readings",
            ],
            env={**os.environ, "ORI_CPU_HOOK_CASE": "1"},
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        report = [
            line for line in result.stdout.splitlines() if "cpu-bound hook" in line
        ]
        print("\n".join(report))
        assert result.returncode == 0, result.stdout[-3000:]
        assert "2 passed" in result.stdout, result.stdout[-1000:]

    @pytest.mark.parametrize("name", sorted(_TIER_D_READINGS))
    async def test_cpu_bound_hook_latency_over_many_readings(
        self, name: str, tmp_path: Path
    ) -> None:
        import os
        import statistics

        if os.environ.get("ORI_CPU_HOOK_CASE") != "1":
            pytest.skip("runs in a fresh interpreter, see the test above")
        readings = 20
        trigger, sensor_type, value = _TIER_D_READINGS[name]
        release = threading.Event()
        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, [name])
            skill.hooks.pre_trigger_eval = _stall("cpu", release)
            loop = asyncio.get_running_loop()
            fired = site.acts.by_trigger.setdefault(trigger, [])
            produced: list[float] = []

            def sensor() -> None:
                for _ in range(readings):
                    produced.append(
                        _publish_from_sensor_thread(
                            bus, loop, _reading(sensor_type, value)
                        )
                    )
                    time.sleep(0.1)

            thread = threading.Thread(target=sensor)
            thread.start()
            try:
                await asyncio.to_thread(thread.join, 10.0)
                await wait_until(
                    lambda: len(fired) >= 2 * readings,
                    what="len(fired) >= 2 * readings",
                )
                firsts = [at for action, at in fired if action == "alert_whatsapp"]
                latencies = sorted(a - p for a, p in zip(firsts, produced))
            finally:
                release.set()
        assert len(latencies) == readings, (len(latencies), readings)
        p95 = latencies[max(0, -(-95 * len(latencies) // 100) - 1)]
        print(
            f"cpu-bound hook {name}: n={len(latencies)} "
            f"p50={statistics.median(latencies) * 1000:.1f}ms "
            f"p95={p95 * 1000:.1f}ms max={latencies[-1] * 1000:.1f}ms"
        )
        assert latencies[-1] < _TRIP_BOUND_S, latencies[-1]

    @pytest.mark.parametrize("kind", ["event", "sleep"])
    @pytest.mark.parametrize("name", sorted(_TIER_D_READINGS))
    async def test_the_next_incident_acts_while_the_hook_is_stuck(
        self, name: str, kind: str, tmp_path: Path
    ) -> None:
        trigger, sensor_type, value = _TIER_D_READINGS[name]
        normal = 5.0 if name == "energy-anomaly-detector" else 60.0
        release = threading.Event()
        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, [name])
            skill.hooks.pre_trigger_eval = _stall(kind, release)
            loop = asyncio.get_running_loop()
            fired = site.acts.by_trigger.setdefault(trigger, [])
            produced: list[float] = []

            def sensor() -> None:
                _publish_from_sensor_thread(bus, loop, _reading(sensor_type, normal))
                time.sleep(0.3)
                produced.append(
                    _publish_from_sensor_thread(bus, loop, _reading(sensor_type, value))
                )

            thread = threading.Thread(target=sensor)
            thread.start()
            try:
                await asyncio.to_thread(thread.join, 5.0)
                await wait_until(lambda: bool(fired), what="bool(fired)")
                assert fired, f"{trigger} did not act behind a stuck hook"
                assert fired[0][1] - produced[0] < _TRIP_BOUND_S
            finally:
                release.set()

    async def test_readings_past_a_stuck_hook_are_skipped_not_queued(
        self, tmp_path: Path
    ) -> None:
        from ori.skills.hook_runner import HOOK_QUEUE_CAPACITY

        release = threading.Event()
        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, ["energy-anomaly-detector"])
            skill.hooks.pre_trigger_eval = _stall("event", release)
            runner = site.coordinator._elevator._hooks
            try:
                for _ in range(HOOK_QUEUE_CAPACITY + 6):
                    await bus.publish(_reading("current_clamp", 5.0))
                await wait_until(
                    lambda: runner.skipped_saturated >= 5,
                    what="runner.skipped_saturated >= 5",
                )
                assert runner.pending <= HOOK_QUEUE_CAPACITY
                assert runner.skipped_saturated >= 5
            finally:
                release.set()

    async def test_a_hook_past_its_timeout_is_skipped_for_its_reading(
        self, tmp_path: Path
    ) -> None:
        release = threading.Event()
        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, ["energy-anomaly-detector"])
            runner = site.coordinator._elevator._hooks
            runner._timeout_s = 0.2
            real = skill.hooks.pre_trigger_eval
            calls: list[int] = []

            def slow(context: Any) -> None:
                calls.append(1)
                real(context)
                release.wait(2.0)

            skill.hooks.pre_trigger_eval = slow
            for n in range(3):
                await site.store.append_history(_reading("current_clamp", 5.0 + n))
            try:
                await bus.publish(_reading("current_clamp", 30.0))
                await wait_until(
                    lambda: runner.timed_out >= 1,
                    what="runner.timed_out >= 1",
                )
                assert runner.timed_out == 1
                # Tier D was decided without it; the notices that need the
                # hook's baseline were not evaluated for this reading.
                assert "dangerous_overcurrent" in site.acts.by_trigger
                await site._finish_dispatches()
                assert "sudden_load_spike" not in site.acts.by_trigger
            finally:
                release.set()

    async def test_stop_abandons_a_stuck_hook_within_its_bound(
        self, tmp_path: Path
    ) -> None:
        release = threading.Event()
        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, ["energy-anomaly-detector"])
            skill.hooks.pre_trigger_eval = _stall("event", release)
            await bus.publish(_reading("current_clamp", 5.0))
            await bus.publish(_reading("current_clamp", 5.0))
            runner = site.coordinator._elevator._hooks
            await wait_until(lambda: runner.pending >= 1, what="runner.pending >= 1")
            started = time.monotonic()
            lost = await asyncio.wait_for(runner.close(timeout_s=0.3), 2.0)
            assert time.monotonic() - started < 1.0
            assert lost >= 2, lost
            assert runner.lost_at_shutdown == lost
            release.set()

    async def test_hooks_run_with_the_default_executor_full(
        self, tmp_path: Path
    ) -> None:
        from concurrent.futures import ThreadPoolExecutor

        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, ["energy-anomaly-detector"])
            loop = asyncio.get_running_loop()
            loop.set_default_executor(ThreadPoolExecutor(max_workers=2))
            hold = threading.Event()
            held = [loop.run_in_executor(None, hold.wait) for _ in range(2)]
            ran: list[float] = []
            real = skill.hooks.pre_trigger_eval

            def recorded(context: Any) -> None:
                ran.append(time.monotonic())
                real(context)

            skill.hooks.pre_trigger_eval = recorded
            try:
                await bus.publish(_reading("current_clamp", 5.0))
                await wait_until(lambda: bool(ran), what="bool(ran)")
                assert ran, "the hook waited on the loop's default executor"
            finally:
                hold.set()
                await asyncio.gather(*held)

    def test_the_hook_connection_belongs_to_the_thread_that_opened_it(
        self, tmp_path: Path
    ) -> None:
        import sqlite3

        from ori.state.store import StateStore

        async def scenario() -> None:
            store = StateStore(db_path=str(tmp_path / "state.db"))
            await store.open()
            try:
                store.hooks_set_skill_state("s", "k", "1")
                mine = store._hook_local.conn
                other: list[Any] = []

                def elsewhere() -> None:
                    store.hooks_set_skill_state("s", "k", "2")
                    other.append(store._hook_local.conn)
                    try:
                        mine.execute("SELECT 1")
                    except sqlite3.ProgrammingError as exc:
                        other.append(exc)

                thread = threading.Thread(target=elsewhere)
                thread.start()
                thread.join(5.0)
                assert other[0] is not mine and other[0] is not store._conn
                assert isinstance(other[1], sqlite3.ProgrammingError)
            finally:
                await store.close()

        asyncio.run(scenario())


class TestASkippedHookLeavesNothingBehind:
    async def test_a_queued_hook_past_its_deadline_never_starts(self) -> None:
        from ori.skills.hook_runner import HookRunner, HookSkippedError

        runner = HookRunner(timeout_s=0.2)
        release = threading.Event()
        started: list[str] = []

        def first() -> None:
            started.append("first")
            release.wait(1.0)

        def second() -> None:
            started.append("second")

        try:
            with pytest.raises(HookSkippedError):
                await asyncio.gather(runner.run(first), runner.run(second))
            release.set()
            await wait_until(
                lambda: runner.expired_unstarted == 1,
                what="runner.expired_unstarted == 1",
            )
            assert started == ["first"]
            assert runner.expired_unstarted == 1
        finally:
            release.set()
            await runner.close(0.5)

    async def test_a_hook_that_runs_past_its_deadline_persists_nothing(
        self, tmp_path: Path
    ) -> None:
        from ori.skills.hook_runner import HookRunner, HookSkippedError
        from ori.skills.hooks_api import BufferedHookState, HookStateAdapter
        from ori.state.store import StateStore

        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        runner = HookRunner(timeout_s=0.2)
        state = BufferedHookState(HookStateAdapter(store, "battery-lifecycle-observer"))
        returned = threading.Event()

        def late(_state: Any) -> None:
            _state.set("outage_active", "1")
            time.sleep(0.5)
            returned.set()

        try:
            with pytest.raises(HookSkippedError):
                await runner.run(late, state, commit=state.commit)
            await asyncio.to_thread(returned.wait, 3.0)
            await wait_until(
                lambda: runner.discarded == 1,
                what="runner.discarded == 1",
            )
            assert runner.discarded == 1
            assert (
                store.hooks_get_skill_state(
                    "battery-lifecycle-observer", "outage_active"
                )
                is None
            )
        finally:
            await runner.close(0.5)
            await store.close()

    async def test_a_hook_abandoned_at_stop_persists_nothing(
        self, tmp_path: Path
    ) -> None:
        from ori.skills.hook_runner import HookRunner
        from ori.skills.hooks_api import BufferedHookState, HookStateAdapter
        from ori.state.store import StateStore

        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        runner = HookRunner(timeout_s=10.0)
        state = BufferedHookState(HookStateAdapter(store, "battery-lifecycle-observer"))
        release = threading.Event()
        returned = threading.Event()

        def stuck(_state: Any) -> None:
            _state.set("outage_active", "1")
            release.wait(3.0)
            returned.set()

        pending = asyncio.ensure_future(runner.run(stuck, state, commit=state.commit))
        try:
            await asyncio.sleep(0.1)
            lost = await asyncio.wait_for(runner.close(timeout_s=0.2), 2.0)
            assert lost == 1
            release.set()
            await asyncio.to_thread(returned.wait, 3.0)
            await asyncio.sleep(0.1)
            assert (
                store.hooks_get_skill_state(
                    "battery-lifecycle-observer", "outage_active"
                )
                is None
            )
        finally:
            release.set()
            pending.cancel()
            await store.close()


class TestAnAsynchronousHookNeverRunsOnTheLoop:
    def test_an_asynchronous_hook_is_refused_at_load(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "energy-anomaly-detector"
        shutil.copytree(_SKILLS / "energy-anomaly-detector", skill_dir)
        hooks = skill_dir / "hooks.py"
        hooks.write_text(
            hooks.read_text().replace(
                "def pre_trigger_eval(context):", "async def pre_trigger_eval(context):"
            )
        )
        loader = SkillLoader()
        loader._is_core_bundled_skill = lambda _path: True  # type: ignore[method-assign]
        with pytest.raises(SkillValidationError, match="asynchronous"):
            loader.load_one(skill_dir)

    def test_no_shipped_hook_is_asynchronous(self) -> None:
        import inspect

        for skill in SkillLoader().load_all(str(_SKILLS)):
            for name in ("pre_trigger_eval", "post_reasoning"):
                fn = getattr(skill.hooks, name, None)
                assert fn is None or not inspect.iscoroutinefunction(fn), (
                    skill.name,
                    name,
                )

    @pytest.mark.parametrize("name", sorted(_TIER_D_READINGS))
    async def test_an_async_hook_that_sleeps_cannot_hold_the_next_incident(
        self, name: str, tmp_path: Path
    ) -> None:
        trigger, sensor_type, value = _TIER_D_READINGS[name]
        normal = 5.0 if name == "energy-anomaly-detector" else 60.0
        async with _site(tmp_path) as site:
            bus, (skill,) = _register(site, [name])
            ran: list[float] = []

            async def sleeps(_context: Any) -> None:
                ran.append(time.monotonic())
                time.sleep(2.0)

            skill.hooks.pre_trigger_eval = sleeps
            loop = asyncio.get_running_loop()
            fired = site.acts.by_trigger.setdefault(trigger, [])
            produced: list[float] = []

            def sensor() -> None:
                _publish_from_sensor_thread(bus, loop, _reading(sensor_type, normal))
                time.sleep(0.3)
                produced.append(
                    _publish_from_sensor_thread(bus, loop, _reading(sensor_type, value))
                )

            thread = threading.Thread(target=sensor)
            thread.start()
            await asyncio.to_thread(thread.join, 5.0)
            await wait_until(lambda: bool(fired), what="bool(fired)")
            assert fired and fired[0][1] - produced[0] < _TRIP_BOUND_S
            assert ran == [], "the asynchronous hook's body ran"
