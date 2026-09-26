# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime against the tier-c-approval/v1 case corpora.

The authority snapshot's closed canonical form and digests, which actions may
stand as a Tier C safe default, which proposals the contract governs, and the
release bound on `approval_timeout_seconds`, each driven through the runtime
module that decides it. The sequence corpus is replayed through the real
dispatcher in `tests/test_tier_c_approval_sequences.py`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from ori.reasoning import tier_c_admission as admission
from ori.reasoning.action_registry import ACTION_REGISTRY, ActionCapability

VECTOR_DIR = Path(__file__).parent / "vectors" / "tier_c_approval"
VECTORS = json.loads((VECTOR_DIR / "admission.json").read_text())


def test_corpus_is_the_published_artifact_at_the_pinned_revision() -> None:
    manifest = json.loads((VECTOR_DIR / "MANIFEST.json").read_text())
    assert manifest["source_repository"] == "ori-platform/ori-specs"
    assert manifest["source_commit"]
    assert set(manifest["files"]) == {
        path.name for path in VECTOR_DIR.glob("*.json") if path.name != "MANIFEST.json"
    }
    for name, recorded in manifest["files"].items():
        assert (
            hashlib.sha256((VECTOR_DIR / name).read_bytes()).hexdigest() == recorded
        ), f"the vendored {name} has been edited locally; re-vendor it"


@pytest.mark.parametrize(
    "case", VECTORS["authority_snapshot_cases"], ids=lambda c: c["name"]
)
def test_authority_snapshots(case: dict[str, Any]) -> None:
    """Every valid snapshot reproduces its digest; every malformed one refuses."""
    if "snapshot_text" in case:
        source: Any = case["snapshot_text"]

        def build() -> bytes:
            return admission.snapshot_bytes(admission.parse_snapshot_text(source))

    else:
        source = case["snapshot"]

        def build() -> bytes:
            return admission.snapshot_bytes(source)

    if case["expected"] == "valid":
        assert admission.sha256_digest(build()) == case["canonical_sha256"]
    else:
        assert case["expected"] == "malformed"
        with pytest.raises(admission.MalformedSnapshotError):
            build()


def _entry(registry: dict[str, Any] | None) -> ActionCapability | None:
    """The corpus's registry entry as a capability, or None for no entry.

    An entry the registry could not hold — a consequence class it does not
    define, a physical eligible fallback — is one the runtime refuses to
    construct, and a fallback with no constructible entry is refused.
    """
    if registry is None:
        return None
    try:
        return ActionCapability(
            minimum_tier=str(registry["minimum_tier"]),
            physical=bool(registry["physical"]),
            safe_default_eligible=bool(registry["safe_default_eligible"]),
            summary="corpus",
            consequence_class=str(registry.get("consequence_class", "")),
        )
    except ValueError:
        return None


@pytest.mark.parametrize(
    "case",
    VECTORS["safe_default_cases"],
    ids=lambda c: f"{c['safe_default_action']}-{c['capability']}",
)
def test_safe_default_cases(case: dict[str, Any]) -> None:
    """Only an informational, eligible, registered, non-physical action stands.

    The physicality the corpus states is what the runtime's own pinned table
    must say for an action it names; a hypothetical action outside the table is
    unclassified and refused whatever entry it claims.
    """
    action = case["safe_default_action"]
    if action in admission.PHYSICALITY:
        assert admission.physicality(action) == case["capability"]
    else:
        assert admission.physicality(action) == "unclassified"
    entry = _entry(case["registry"])
    admitted = admission.safe_default_admitted(action, entry=entry)
    assert admitted is (case["expected"] == "admitted"), case


@pytest.mark.parametrize(
    "case", VECTORS["safe_default_cases"], ids=lambda c: c["safe_default_action"]
)
def test_the_registry_matches_the_corpus_for_the_actions_it_names(
    case: dict[str, Any],
) -> None:
    """The corpus pins the runtime registry's entries for the named actions."""
    action = case["safe_default_action"]
    entry = ACTION_REGISTRY.get(action)
    pinned = case["registry"]
    if action not in admission.PHYSICALITY:
        return  # a hypothetical action
    if pinned is None:
        assert entry is None, f"{action} has a registry entry the corpus says it lacks"
        return
    assert entry is not None, f"{action} is missing from the registry"
    assert {
        "minimum_tier": entry.minimum_tier,
        "physical": entry.physical,
        "consequence_class": entry.consequence_class,
        "safe_default_eligible": entry.safe_default_eligible,
    } == pinned


def test_every_registry_entry_is_classified_and_agrees_with_the_table() -> None:
    assert admission.registry_disagreements() == []
    assert admission.unclassified_executors(ACTION_REGISTRY) == []


def test_a_new_executor_must_be_classified_before_it_can_be_a_safe_default() -> None:
    assert admission.unclassified_executors({"brand_new_action": object()}) == [
        "brand_new_action"
    ]
    assert (
        admission.safe_default_admitted(
            "brand_new_action",
            entry=ActionCapability(
                "A", False, True, "x", consequence_class="informational"
            ),
        )
        is False
    )


@pytest.mark.parametrize(
    "case", VECTORS["proposal_scope_cases"], ids=lambda c: c["name"]
)
def test_proposal_scope_cases(case: dict[str, Any]) -> None:
    action = case["action"]
    if action not in admission.PHYSICALITY:
        # A hypothetical physical Tier B action the runtime has no executor for.
        assert case["expected"] == admission.OUTSIDE_CONTRACT
        assert case["tier"] != "C"
        return
    assert admission.physicality(action) == case["capability"]
    assert (
        admission.proposal_scope(
            action,
            case["tier"],
            zone_id=case["zone"],
            commissioned_outcome_name=case["commissioned_outcome"],
            requires_approval=bool(case.get("requires_approval", False)),
        )
        == case["expected"]
    )


@pytest.mark.parametrize("case", VECTORS["config_cases"], ids=lambda c: c["name"])
def test_approval_timeout_bound(case: dict[str, Any]) -> None:
    accepted = admission.approval_timeout_accepted(
        case["approval_timeout_seconds"],
        release_maximum_s=case["release_maximum_seconds"],
    )
    assert accepted is (case["expected"] == "accept")


def test_the_release_maximum_is_a_release_constant_within_the_corpus_bound() -> None:
    """The runtime's own maximum: a bounded release duration, never a setting."""
    assert 1 <= admission.MAX_PROPOSAL_LIFETIME_S <= 3600
    assert admission.approval_timeout_accepted(admission.MAX_PROPOSAL_LIFETIME_S)
    assert not admission.approval_timeout_accepted(
        admission.MAX_PROPOSAL_LIFETIME_S + 1
    )
    assert not admission.approval_timeout_accepted(True)


def test_decision_states_are_the_contracts_closed_set() -> None:
    expected = {
        step["expect"]["state"]
        for sequence in VECTORS["sequences"]
        for step in sequence["steps"]
        if "state" in step.get("expect", {})
    }
    assert expected <= admission.DECISION_STATES
    assert admission.BLOCKING_STATES <= admission.DECISION_STATES
    assert admission.UNCERTAIN_STATES <= admission.BLOCKING_STATES
    assert admission.ADMITTED_STATES <= admission.DECISION_STATES
