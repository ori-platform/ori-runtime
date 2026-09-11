# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A shipped skill may not declare a state-changing action the registry lacks.

This proves governed membership, not executability. A registry entry means the
runtime knows the action and assigns it a floor; whether an executor is bound is
a separate condition, and three entries currently have none.

A trigger's default actions are read as what the device does when the condition
holds. Naming an action with no registry entry reads as protection while being
incapable of it, and for a Tier D trigger the failure surfaces when the trigger
fires — the worst possible moment to learn that the only protective action in
the list was never something the runtime could perform.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ori.reasoning.action_registry import ACTION_REGISTRY, tier_rank
from ori.skills.loader import SkillLoader, SkillValidationError

_SKILLS_ROOT = Path(__file__).parent.parent / "skills"


def _shipped_manifests() -> list[tuple[str, dict]]:
    return [
        (path.parent.name, yaml.safe_load(path.read_text(encoding="utf-8")))
        for path in sorted(_SKILLS_ROOT.glob("*/skill.yaml"))
    ]


def _manifest_ids() -> list[str]:
    return [name for name, _ in _shipped_manifests()]


@pytest.mark.parametrize(
    ("skill_name", "manifest"), _shipped_manifests(), ids=_manifest_ids()
)
def test_every_default_action_resolves_in_the_registry(skill_name, manifest):
    defaults = (manifest.get("actions") or {}).get("defaults") or {}
    unresolved = sorted(
        {
            action
            for actions in defaults.values()
            for action in actions
            if action not in ACTION_REGISTRY
        }
    )
    assert not unresolved, (
        f"{skill_name} defaults to actions the runtime has no capability for, "
        f"which can never gain an executor because `register_executor` refuses "
        f"an unregistered name: {unresolved}"
    )


@pytest.mark.parametrize(
    ("skill_name", "manifest"), _shipped_manifests(), ids=_manifest_ids()
)
def test_no_declared_action_above_tier_a_is_ungoverned(skill_name, manifest):
    available = (manifest.get("actions") or {}).get("available") or []
    offenders = sorted(
        {
            entry["name"]
            for entry in available
            if isinstance(entry, dict)
            and entry.get("name") not in ACTION_REGISTRY
            and tier_rank(str(entry.get("tier") or "A")) > tier_rank("A")
        }
    )
    assert not offenders, (
        f"{skill_name} declares state-changing actions the registry does not "
        f"hold: {offenders}"
    )


def _write_skill(root: Path, *, action: str, tier: str) -> Path:
    skill_dir = root / "capability-probe"
    skill_dir.mkdir()
    skill_dir.joinpath("skill.yaml").write_text(
        f"""
name: capability-probe
version: 0.1.0
author: test
signature: bundled
sensors_required:
  - type: current_clamp
triggers:
  - name: probe
    condition: "value > 1.0"
    action_tier: A
prompts:
  probe: Probe.
actions:
  available:
    - name: {action}
      tier: {tier}
  defaults:
    probe: [{action}]
config:
  threshold: 1.0
""",
        encoding="utf-8",
    )
    return skill_dir


def _load(skill_dir: Path):
    loader = SkillLoader()
    loader._is_core_bundled_skill = lambda _d: True  # type: ignore[method-assign]
    return loader.load_one(skill_dir)


@pytest.mark.parametrize("tier", ["B", "C", "D"])
def test_ungoverned_state_changing_action_is_refused_at_load(tmp_path, tier):
    """Registry membership is decidable, so it is answered before the trigger fires."""
    skill_dir = _write_skill(tmp_path, action="switch_to_grid", tier=tier)

    with pytest.raises(SkillValidationError, match="can never execute"):
        _load(skill_dir)


def test_ungoverned_informational_action_still_loads(tmp_path):
    """A skill may name its own notice; dispatch records the intent.

    Refusing every ungoverned name would take custom informational actions with
    it, which actuate nothing. The boundary is the claim to change the world,
    not the absence of a registry entry.
    """
    skill_dir = _write_skill(tmp_path, action="post_to_site_noticeboard", tier="A")

    skill = _load(skill_dir)

    assert skill.get_default_actions_for_trigger("probe") == [
        "post_to_site_noticeboard"
    ]


def test_a_governed_action_above_tier_a_still_loads(tmp_path):
    """The mutation that would make the refusal above vacuous."""
    skill_dir = _write_skill(tmp_path, action="switch_power_source", tier="B")

    skill = _load(skill_dir)

    assert skill.get_default_actions_for_trigger("probe") == ["switch_power_source"]
