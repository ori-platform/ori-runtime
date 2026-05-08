# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import textwrap
from pathlib import Path

import pytest

from ori.network.events import OriEvent, SensorReading
from ori.reasoning.elevator import IntelligenceElevator
from ori.skills.loader import Trigger
from ori.skills.os_sandbox import OSSandboxSupport, load_community_hooks
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


def test_load_community_hooks_falls_back_to_python_sandbox(monkeypatch, tmp_path):
    hooks = _write_hooks(
        tmp_path / "community-skill" / "hooks.py",
        """
        def pre_trigger_eval(context):
            context.derived["x"] = 1
        """,
    )
    monkeypatch.setattr(
        "ori.skills.os_sandbox.probe_os_sandbox_support",
        lambda: OSSandboxSupport(False, "kernel_not_linux"),
    )
    module = load_community_hooks(
        hooks_path=hooks,
        state_store=None,
        skill_name="community-skill",
        os_sandbox_config={"enabled": True, "require_for_community": False},
    )
    assert module is not None
    assert callable(getattr(module, "pre_trigger_eval", None))


def test_load_community_hooks_strict_mode_rejects_when_unsupported(
    monkeypatch, tmp_path
):
    hooks = _write_hooks(
        tmp_path / "community-skill" / "hooks.py",
        "def pre_trigger_eval(context):\n    pass\n",
    )
    monkeypatch.setattr(
        "ori.skills.os_sandbox.probe_os_sandbox_support",
        lambda: OSSandboxSupport(False, "kernel_not_linux"),
    )
    with pytest.raises(SkillSecurityError, match="os sandbox required"):
        load_community_hooks(
            hooks_path=hooks,
            state_store=None,
            skill_name="community-skill",
            os_sandbox_config={"enabled": True, "require_for_community": True},
        )


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
