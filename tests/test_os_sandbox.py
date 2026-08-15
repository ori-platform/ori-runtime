# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import textwrap
from pathlib import Path

import pytest

from ori.network.events import OriEvent, SensorReading
from ori.reasoning.elevator import IntelligenceElevator
from ori.skills.loader import Trigger
from ori.skills.os_sandbox import (
    OSSandboxSupport,
    _RPCHistoryProxy,
    load_community_hooks,
)
from ori.skills.sandbox import SkillSecurityError


def _write_hooks(path: Path, source: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


def _event(value: float = 10.0) -> OriEvent:
    reading = SensorReading(
        sensor_id="s-1",
        sensor_type="current",
        value=value,
        unit="ampere",
        timestamp=1_700_000_000_000,
        quality=1.0,
        metadata={},
    )
    return OriEvent.from_reading(reading, "dev-01")


@pytest.mark.parametrize(
    "support",
    [
        OSSandboxSupport(True, "ok"),
        OSSandboxSupport(False, "kernel_not_linux"),
    ],
    ids=["landlock_available", "landlock_unavailable"],
)
@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.parametrize("require_for_community", [True, False])
def test_community_hooks_never_execute_in_this_release(
    monkeypatch, tmp_path, support, enabled, require_for_community
):
    """No configuration or host capability produces a hook runner.

    Two behaviours are pinned here. The first is that an unsupported OS sandbox
    no longer degrades to the in-process loader — it used to, unless the
    operator had opted into requiring isolation, which made the permissive
    default the dangerous one.

    The second is the case this matters most for: a host where Landlock *is*
    available. Returning a working runner there would leave community hook
    execution enabled on precisely the modern Linux systems Ori targets, under
    a runner that predates the isolation contract still being specified. The
    refusal is unconditional so the shipped posture matches the documented one.
    """
    hooks = _write_hooks(
        tmp_path / "community-skill" / "hooks.py",
        """
        def pre_trigger_eval(context):
            context.derived["x"] = 1
        """,
    )
    monkeypatch.setattr(
        "ori.skills.os_sandbox.probe_os_sandbox_support",
        lambda: support,
    )
    with pytest.raises(SkillSecurityError, match="disabled in this release"):
        load_community_hooks(
            hooks_path=hooks,
            state_store=None,
            skill_name="community-skill",
            os_sandbox_config={
                "enabled": enabled,
                "require_for_community": require_for_community,
            },
        )


def test_supported_host_is_not_probed_into_an_execution_path(monkeypatch, tmp_path):
    """The refusal does not depend on the probe answering unfavourably."""
    hooks = _write_hooks(
        tmp_path / "community-skill" / "hooks.py",
        "def pre_trigger_eval(context):\n    pass\n",
    )

    def _must_not_matter():  # pragma: no cover - result is irrelevant
        raise AssertionError("probe result must not gate the refusal")

    monkeypatch.setattr(
        "ori.skills.os_sandbox.probe_os_sandbox_support", _must_not_matter
    )
    with pytest.raises(SkillSecurityError, match="disabled in this release"):
        load_community_hooks(
            hooks_path=hooks,
            state_store=None,
            skill_name="community-skill",
            os_sandbox_config={"enabled": True, "require_for_community": False},
        )


def test_rpc_history_proxy_exposes_time_of_week_baseline():
    calls: list[tuple[str, dict]] = []

    def _rpc(method: str, params: dict):
        calls.append((method, params))
        return {"usable": True, "avg_value": 12.0}

    history = _RPCHistoryProxy(
        _rpc,
        reference_timestamp_ms=1_717_925_400_000,
        timezone="Africa/Lagos",
    )

    result = history.same_weekday_hour_baseline(
        "load-current",
        lookback_weeks=8,
        min_weeks=3,
    )

    assert result == {"usable": True, "avg_value": 12.0}
    assert calls == [
        (
            "history.same_weekday_hour_baseline",
            {
                "sensor_id": "load-current",
                "reference_timestamp_ms": 1_717_925_400_000,
                "timezone": "Africa/Lagos",
                "lookback_weeks": 8,
                "min_weeks": 3,
            },
        )
    ]


@pytest.mark.asyncio
async def test_elevator_awaits_async_hook_methods():
    called = {"pre": False, "post": False}

    class _AsyncHooks:
        async def pre_trigger_eval(self, context):
            called["pre"] = True
            context.derived["min_quality"] = 0.5

        async def post_reasoning(self, result, _context):
            called["post"] = True
            result.text = "post hook updated"

    class _Skill:
        name = "async-hook-skill"
        config = {}
        hooks = _AsyncHooks()
        triggers = [
            Trigger(
                name="t1",
                condition="value > 5",
                action_tier="A",
                cooldown_seconds=0,
            )
        ]
        actions = {
            "available": [{"name": "log_to_dashboard", "tier": "A"}],
            "defaults": {"t1": ["log_to_dashboard"]},
        }

        def get_default_actions_for_trigger(self, trigger_name: str):
            return list(self.actions["defaults"].get(trigger_name, []))

    dispatched: list[tuple[str, str, str]] = []

    class _Dispatcher:
        async def dispatch(self, action, tier, context, result, approval_timeout=300):
            dispatched.append((action, tier, result.text))

    elevator = IntelligenceElevator(local_llm=None)
    await elevator.reason_and_dispatch(
        event=_event(9.0),
        skill=_Skill(),
        state_store=None,
        dispatcher=_Dispatcher(),
    )
    assert called["pre"] is True
    assert called["post"] is True
    assert dispatched
    assert dispatched[0][2] == "post hook updated"
