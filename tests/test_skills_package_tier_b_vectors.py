# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The skill loader against the skills-package/v3 Tier B execution-policy corpus."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from ori.reasoning.action_registry import minimum_tier
from ori.skills.loader import SkillLoader, SkillValidationError

VECTOR_DIR = Path(__file__).parent / "vectors" / "skills_package"
CORPUS = json.loads((VECTOR_DIR / "tier-b-policy.json").read_text())
MANIFEST = json.loads((VECTOR_DIR / "MANIFEST.json").read_text())
CASES: list[dict[str, Any]] = CORPUS["cases"]

#: Published case count at the pinned revision. A re-vendor that drops or adds
#: cases fails here until the change is reviewed.
EXPECTED_CASES = 14
RULES = {"one_policy", "trigger_only", "boolean"}


def _first_party_loader() -> SkillLoader:
    """A loader that treats the scratch skill directory as a packaged skill."""
    loader = SkillLoader()
    loader._is_core_bundled_skill = lambda skill_dir: True  # type: ignore[method-assign]
    return loader


def test_corpus_is_the_published_artifact_at_the_pinned_revision() -> None:
    assert MANIFEST["source_repository"] == "ori-platform/ori-specs"
    assert MANIFEST["source_path"] == "skills-package/vectors"
    assert MANIFEST["source_commit"]
    assert set(MANIFEST["files"]) == {
        path.name for path in VECTOR_DIR.glob("*.json") if path.name != "MANIFEST.json"
    }
    for name, recorded in MANIFEST["files"].items():
        assert (
            hashlib.sha256((VECTOR_DIR / name).read_bytes()).hexdigest() == recorded
        ), f"the vendored {name} has been edited locally; re-vendor it"


def test_corpus_declares_the_contract_the_manifest_claims() -> None:
    claimed = f"skills-package/{MANIFEST['contract_version']}"
    declared = CORPUS["contract"]
    assert declared == claimed or declared.startswith(claimed + " "), (
        f"the corpus declares {declared!r}, not the claimed {claimed}"
    )


def test_every_case_is_driven_and_every_rule_is_exercised() -> None:
    names = [case["name"] for case in CASES]
    assert len(names) == EXPECTED_CASES
    assert len(set(names)) == len(names), "case names are not unique"
    refused = [case for case in CASES if case["expect"] == "refused"]
    assert {case["rule"] for case in refused} == RULES
    assert {case["expect"] for case in CASES} == {"accepted", "refused"}


def test_the_fixture_registry_agrees_with_the_runtime_registry() -> None:
    """The loader reads the runtime registry, so the fixture must not differ from it."""
    for action, tier in CORPUS["action_registry"].items():
        assert minimum_tier(action) == tier, action
    for case in CASES:
        assert case["registry"] == "action_registry", case["name"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_tier_b_policy_case(case: dict[str, Any], tmp_path: Path) -> None:
    skill_dir = tmp_path / case["manifest"]["name"]
    skill_dir.mkdir()
    (skill_dir / "skill.yaml").write_text(yaml.safe_dump(case["manifest"]))
    loader = _first_party_loader()

    if case["expect"] == "accepted":
        skill = loader.load_one(skill_dir, load_hooks=False)
        assert skill.name == case["manifest"]["name"]
        declared = case["manifest"]["triggers"]
        assert [t.name for t in skill.triggers] == [t["name"] for t in declared]
        for trigger, raw in zip(skill.triggers, declared, strict=True):
            assert trigger.action_tier == raw["action_tier"]
            assert trigger.requires_approval is raw.get("requires_approval", False)
            assert trigger.reasoning_policy == raw.get("reasoning_policy", "")
        return

    assert case["expect"] == "refused"
    assert case["error"] == SkillValidationError.__name__
    with pytest.raises(SkillValidationError) as refusal:
        loader.load_one(skill_dir, load_hooks=False)
    assert type(refusal.value) is SkillValidationError
    message = str(refusal.value)
    missing = [name for name in case["must_name"] if name not in message]
    assert not missing, f"refusal does not name {missing}: {message}"
