# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""`approval_timeout_seconds` is bounded at load, in ori.yaml and in skill.yaml.

A deployment may shorten a Tier C proposal's lifetime and never extend it past
the release maximum; a fraction, zero and a string are refused rather than
rounded or clamped.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ori.config import ConfigValidationError, _parse_skills
from ori.reasoning.approval_bounds import MAX_PROPOSAL_LIFETIME_S
from ori.skills.loader import SkillLoader, SkillValidationError


def _first_party_loader() -> SkillLoader:
    """The scratch directory stands in for a packaged skill; provenance is not under test."""
    loader = SkillLoader()
    loader._is_core_bundled_skill = lambda skill_dir: True  # type: ignore[method-assign]
    return loader


@pytest.mark.parametrize("value", [1, 120, MAX_PROPOSAL_LIFETIME_S])
def test_ori_yaml_accepts_a_lifetime_within_the_release_bound(value: int) -> None:
    skills = _parse_skills(
        [{"name": "s", "version": "1", "config": {"approval_timeout_seconds": value}}]
    )
    assert skills[0].config["approval_timeout_seconds"] == value


@pytest.mark.parametrize(
    "value", [0, MAX_PROPOSAL_LIFETIME_S + 1, 86400, 30.5, "300", True, None]
)
def test_ori_yaml_refuses_a_lifetime_outside_the_release_bound(value: Any) -> None:
    with pytest.raises(ConfigValidationError, match="approval_timeout_seconds"):
        _parse_skills(
            [
                {
                    "name": "s",
                    "version": "1",
                    "config": {"approval_timeout_seconds": value},
                }
            ]
        )


def _skill_yaml(timeout: str) -> str:
    return f"""
name: bounded
version: 0.1.0
author: test
license: MIT
sensors_required:
  - type: cpu_percent
triggers:
  - name: t
    condition: "cpu_percent > 90"
    action_tier: C
    approval_timeout_seconds: {timeout}
    safe_default_action: log_to_dashboard
actions:
  available:
    - name: terminate_process
      tier: C
    - name: log_to_dashboard
      tier: A
  defaults:
    t: [terminate_process]
"""


@pytest.mark.parametrize("timeout", ["0", "3601", "30.5", '"300"'])
def test_skill_yaml_refuses_a_lifetime_outside_the_release_bound(
    tmp_path: Path, timeout: str
) -> None:
    skill_dir = tmp_path / "bounded"
    skill_dir.mkdir()
    (skill_dir / "skill.yaml").write_text(_skill_yaml(timeout))
    loader = _first_party_loader()
    with pytest.raises(SkillValidationError, match="approval_timeout_seconds"):
        loader.load_one(skill_dir)


def test_skill_yaml_accepts_the_release_maximum(tmp_path: Path) -> None:
    skill_dir = tmp_path / "bounded"
    skill_dir.mkdir()
    (skill_dir / "skill.yaml").write_text(_skill_yaml(str(MAX_PROPOSAL_LIFETIME_S)))
    skill = _first_party_loader().load_one(skill_dir)
    assert skill.triggers[0].approval_timeout_seconds == MAX_PROPOSAL_LIFETIME_S
