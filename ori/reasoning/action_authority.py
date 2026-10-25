# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The licence an attested action ran under, as the action row records it."""

from __future__ import annotations

import json
from typing import Any

from ori.network.events import ActionResult, ActionTier
from ori.reasoning.elevator import SkillContext
from ori.security.evidence.policy import tier_requires_attestation


def authority_snapshot_json(
    action_result: ActionResult,
    context: SkillContext,
    *,
    trigger_name: str,
) -> str | None:
    """The licence this dispatch acted under, as canonical JSON, or None.

    Built by the dispatcher because it alone holds all of it at once: the skill
    that declared the trigger, the trigger that matched, and the proposal an
    operator answered. It is persisted with the action row so reconciliation
    after a restart replays this decision rather than rebuilding one from
    whatever is loaded then. A binding sequence is recorded on the row, never
    here: no defined kind pairs one with a skill declaration.

    Only Tier C and Tier D rows reach the evidence chain, so only they carry a
    snapshot. Returning None for the rest is not an omission: an action that
    produces no `runtime_action` evidence has no authority object to carry.
    """
    tier = str(action_result.tier or "").upper()
    if not tier_requires_attestation(tier):
        return None

    if tier == ActionTier.HARD_PHYSICAL:
        proposal_id = str(action_result.proposal_id or "")
        # Only an approval licenses a Tier C action. A refused, unanswered or
        # undelivered proposal has no licence kind, and the attestor refuses it.
        if not proposal_id or action_result.approved is not True:
            return None
        authority: dict[str, Any] = {
            "kind": "tier_c_approval",
            "proposal_id": proposal_id,
        }
    else:
        skill = getattr(context, "skill", None)
        skill_name = str(getattr(skill, "name", "") or "")
        skill_version = str(getattr(skill, "version", "") or "")
        if not (skill_name and skill_version and trigger_name):
            return None
        # `tier_d_legacy_skill` is the truthful kind while a packaged skill's
        # declaration is what licenses the trip. It is not a protection claim,
        # and a verifier is required not to read it as one; the profile and
        # qualification kinds become emittable when the safety registry is the
        # Tier D path.
        authority = {
            "kind": "tier_d_legacy_skill",
            "skill_name": skill_name,
            "skill_version": skill_version,
            "trigger_name": trigger_name,
        }
    return json.dumps(authority, sort_keys=True, separators=(",", ":"))
