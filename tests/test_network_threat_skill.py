# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

from ori.network.events import OriEvent, SensorReading
from ori.reasoning.rule_engine import RuleEngine
from ori.skills.hooks_api import HookContext
from ori.skills.loader import SkillLoader


class _Store:
    def __init__(self) -> None:
        self._history: dict[str, list[SensorReading]] = {}
        self._state: dict[tuple[str, str], str] = {}

    def add_history(self, sensor_id: str, reading: SensorReading) -> None:
        self._history.setdefault(sensor_id, []).insert(0, reading)

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
    return Path(__file__).parent.parent / "skills" / "pc-network-threat-monitor"


def _load_skill():
    return SkillLoader().load_one(_skill_dir())


def _event(
    *,
    sensor_id: str,
    sensor_type: str,
    value: float,
    quality: float = 1.0,
    metadata: dict | None = None,
    timestamp: int = 1_710_000_000_123,
) -> OriEvent:
    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit="count",
        timestamp=timestamp,
        quality=quality,
        metadata=metadata or {},
    )
    return OriEvent.from_reading(reading, "pc-cyber-01")


def _prepare_context(skill, event, store: _Store):
    hook_ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
    skill.hooks.pre_trigger_eval(hook_ctx)
    context = dict(skill.config)
    context.update(hook_ctx.derived)
    return hook_ctx, context


@pytest.mark.asyncio
async def test_skill_loads_with_valid_tiers():
    skill = _load_skill()
    assert skill.name == "pc-network-threat-monitor"
    assert len(skill.triggers) == 4
    assert {t.action_tier for t in skill.triggers} == {"A", "C"}


@pytest.mark.asyncio
async def test_tier_c_trigger_has_safe_default_action():
    skill = _load_skill()
    trigger = next(
        t for t in skill.triggers if t.name == "probable_c2_or_shell_foothold"
    )
    assert trigger.action_tier == "C"
    assert trigger.safe_default_action == "log_to_dashboard"
    defaults = skill.actions.get("defaults", {})
    assert defaults["probable_c2_or_shell_foothold"] == [
        "alert_whatsapp",
        "log_to_dashboard",
    ]


@pytest.mark.asyncio
async def test_warmup_polls_suppress_delta_triggers():
    skill = _load_skill()
    trigger = next(t for t in skill.triggers if t.name == "suspicious_new_listener")
    store = _Store()

    for idx in range(5):
        event = _event(
            sensor_id="net-listeners-01",
            sensor_type="net_listening_sockets",
            value=2.0,
            metadata={"listener_ports": [22, 5432]},
            timestamp=1_710_000_000_123 + idx,
        )
        _, ctx = _prepare_context(skill, event, store)
        result = await RuleEngine().evaluate(event, [trigger], context=ctx)
        assert result.matched is False
        assert ctx["warmup_complete"] == 0


@pytest.mark.asyncio
async def test_hooks_compute_listener_delta_after_warmup():
    skill = _load_skill()
    store = _Store()
    store._set_skill_state_sync(skill.name, "poll_count", "6")
    store._set_skill_state_sync(skill.name, "last_net_listening_sockets", "1")

    event = _event(
        sensor_id="net-listeners-01",
        sensor_type="net_listening_sockets",
        value=3.0,
        metadata={"listener_ports": [22, 5432, 31337]},
    )
    _, ctx = _prepare_context(skill, event, store)
    assert ctx["warmup_complete"] == 1
    assert ctx["net_listening_sockets"] == pytest.approx(2.0)
    assert ctx["listener_delta"] == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_hooks_apply_known_listener_allowlist():
    skill = _load_skill()
    store = _Store()
    store._set_skill_state_sync(skill.name, "poll_count", "6")

    event = _event(
        sensor_id="net-listeners-01",
        sensor_type="net_listening_sockets",
        value=3.0,
        metadata={"listener_ports": [5432, 8080, 9001]},
    )
    _, ctx = _prepare_context(skill, event, store)
    assert ctx["net_listening_sockets"] == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_hooks_apply_known_terminal_users_allowlist():
    skill = _load_skill()
    store = _Store()
    store._set_skill_state_sync(skill.name, "poll_count", "6")

    event = _event(
        sensor_id="active-users-01",
        sensor_type="active_terminal_users",
        value=3.0,
        metadata={
            "sessions": [
                {"name": "admin", "terminal": "pts/0"},
                {"name": "deploy", "terminal": "pts/1"},
                {"name": "analyst", "terminal": "pts/2"},
            ]
        },
    )
    _, ctx = _prepare_context(skill, event, store)
    assert ctx["active_terminal_users"] == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_rule_matches_suspicious_new_listener():
    skill = _load_skill()
    store = _Store()
    trigger = next(t for t in skill.triggers if t.name == "suspicious_new_listener")

    store._set_skill_state_sync(skill.name, "poll_count", "6")
    store._set_skill_state_sync(skill.name, "last_net_listening_sockets", "1")

    event = _event(
        sensor_id="net-listeners-01",
        sensor_type="net_listening_sockets",
        value=3.0,
        metadata={"listener_ports": [22, 5432, 31337]},
        quality=0.95,
    )
    _, ctx = _prepare_context(skill, event, store)
    result = await RuleEngine().evaluate(event, [trigger], context=ctx)
    assert result.matched is True


@pytest.mark.asyncio
async def test_rule_matches_probable_c2_or_shell_foothold_when_correlated():
    skill = _load_skill()
    store = _Store()
    trigger = next(
        t for t in skill.triggers if t.name == "probable_c2_or_shell_foothold"
    )

    store._set_skill_state_sync(skill.name, "poll_count", "6")
    store._set_skill_state_sync(skill.name, "last_net_established_connections", "10")
    store._set_skill_state_sync(skill.name, "last_listener_spike_ts", "1710000000000")

    baseline_sensor_id = "net-established-01"
    store.add_history(
        baseline_sensor_id,
        SensorReading(
            sensor_id=baseline_sensor_id,
            sensor_type="net_established_connections",
            value=10.0,
            unit="count",
            timestamp=1_709_999_900_000,
            quality=1.0,
        ),
    )

    event = _event(
        sensor_id=baseline_sensor_id,
        sensor_type="net_established_connections",
        value=60.0,
        quality=0.95,
        timestamp=1_710_000_000_123,
    )
    _, ctx = _prepare_context(skill, event, store)
    result = await RuleEngine().evaluate(event, [trigger], context=ctx)
    assert result.matched is True


@pytest.mark.asyncio
async def test_low_quality_readings_do_not_trigger_alerts():
    skill = _load_skill()
    store = _Store()
    trigger = next(t for t in skill.triggers if t.name == "suspicious_new_listener")

    store._set_skill_state_sync(skill.name, "poll_count", "6")
    store._set_skill_state_sync(skill.name, "last_net_listening_sockets", "1")

    event = _event(
        sensor_id="net-listeners-01",
        sensor_type="net_listening_sockets",
        value=3.0,
        metadata={"listener_ports": [22, 5432, 31337]},
        quality=0.3,
    )
    _, ctx = _prepare_context(skill, event, store)
    result = await RuleEngine().evaluate(event, [trigger], context=ctx)
    assert result.matched is False


@pytest.mark.asyncio
async def test_no_correlation_does_not_fire_tier_c():
    skill = _load_skill()
    store = _Store()
    trigger = next(
        t for t in skill.triggers if t.name == "probable_c2_or_shell_foothold"
    )

    store._set_skill_state_sync(skill.name, "poll_count", "6")
    store._set_skill_state_sync(skill.name, "last_net_established_connections", "10")
    # Explicitly absent listener spike
    store._set_skill_state_sync(skill.name, "last_listener_spike_ts", "0")

    baseline_sensor_id = "net-established-01"
    store.add_history(
        baseline_sensor_id,
        SensorReading(
            sensor_id=baseline_sensor_id,
            sensor_type="net_established_connections",
            value=10.0,
            unit="count",
            timestamp=1_709_999_900_000,
            quality=1.0,
        ),
    )

    event = _event(
        sensor_id=baseline_sensor_id,
        sensor_type="net_established_connections",
        value=60.0,
        quality=0.95,
        timestamp=1_710_000_000_123,
    )
    _, ctx = _prepare_context(skill, event, store)
    result = await RuleEngine().evaluate(event, [trigger], context=ctx)
    assert result.matched is False
