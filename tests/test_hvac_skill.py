# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from types import SimpleNamespace

from ori.network.events import ReasoningResult
from ori.skills.loader import SkillLoader


def _skill_dir() -> Path:
    return Path(__file__).parent.parent / "skills" / "hvac-refrigerant-monitor"


def _load_skill():
    return SkillLoader().load_one(_skill_dir())


def test_skill_loads():
    skill = _load_skill()
    assert skill.name == "hvac-refrigerant-monitor"
    assert len(skill.triggers) == 4


def test_gas_leak_trigger_is_tier_d():
    skill = _load_skill()
    trigger = next(t for t in skill.triggers if t.name == "gas_leak_detected")
    assert trigger.action_tier == "D"
    assert trigger.bypass_llm is True


def test_elevated_trigger_is_tier_a():
    skill = _load_skill()
    trigger = next(t for t in skill.triggers if t.name == "gas_concentration_elevated")
    assert trigger.action_tier == "A"


def test_compressor_anomaly_is_tier_a():
    skill = _load_skill()
    trigger = next(t for t in skill.triggers if t.name == "compressor_current_anomaly")
    assert trigger.action_tier == "A"


def test_tier_d_has_valve_action():
    skill = _load_skill()
    defaults = skill.actions.get("defaults", {})
    assert "close_gas_valve" in defaults.get("gas_leak_detected", [])


def test_hooks_add_joint_label():
    skill = _load_skill()
    assert skill.hooks is not None

    result = ReasoningResult(
        text="Potential refrigerant leak detected.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
    )
    ctx = SimpleNamespace(readings={"joint_label": "Pipe-Joint-3"})

    updated = skill.hooks.post_reasoning(result, ctx)
    assert updated.text.startswith("[Joint: Pipe-Joint-3] ")
