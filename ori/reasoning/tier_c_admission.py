# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""What a Tier C proposal binds and what admits an operator's reply to it.

The decision states, the authority snapshot a proposal is created under and an
approval is byte-matched against, the release bound on a proposal's lifetime,
which proposals the admission contract governs, and which actions may stand as
a proposal's non-actuating safe default. Pure functions over runtime-owned
facts; the store and the dispatcher hold the state.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Final

from ori.reasoning.action_registry import ACTION_REGISTRY, ActionCapability, capability
from ori.reasoning.dispatch_plan import commissioned_outcome

# ── Decision states ───────────────────────────────────────────────────────────
# The closed set. A proposal is in exactly one; every transition is forward.
PROPOSED: Final = "proposed"
PROPOSAL_EXPIRED: Final = "proposal_expired"
REJECTED: Final = "rejected"
APPROVED_PENDING_DISPATCH: Final = "approved_pending_dispatch"
DISPATCH_STARTED: Final = "dispatch_started"
EXECUTED: Final = "executed"
APPROVAL_EXPIRED_UNDISPATCHED: Final = "approval_expired_undispatched"
APPROVAL_ABORTED_UNDISPATCHED: Final = "approval_aborted_undispatched"
PROPOSAL_ABORTED_RESTART: Final = "proposal_aborted_restart"
APPROVAL_BINDING_CHANGED: Final = "approval_binding_changed"
PROPOSAL_BLOCKED_UNCERTAIN_OUTCOME: Final = "proposal_blocked_uncertain_outcome"
DISPATCH_REFUSED_CONTENTION: Final = "dispatch_refused_contention"
DISPATCH_FAILED: Final = "dispatch_failed"
DISPATCH_OUTCOME_UNKNOWN: Final = "dispatch_outcome_unknown"
DISPATCH_NOT_PROVEN: Final = "dispatch_not_proven"
RECONCILED_EXECUTED: Final = "reconciled_executed"
RECONCILED_NOT_EXECUTED: Final = "reconciled_not_executed"

DECISION_STATES: Final[frozenset[str]] = frozenset(
    {
        PROPOSED,
        PROPOSAL_EXPIRED,
        REJECTED,
        APPROVED_PENDING_DISPATCH,
        DISPATCH_STARTED,
        EXECUTED,
        APPROVAL_EXPIRED_UNDISPATCHED,
        APPROVAL_ABORTED_UNDISPATCHED,
        PROPOSAL_ABORTED_RESTART,
        APPROVAL_BINDING_CHANGED,
        PROPOSAL_BLOCKED_UNCERTAIN_OUTCOME,
        DISPATCH_REFUSED_CONTENTION,
        DISPATCH_FAILED,
        DISPATCH_OUTCOME_UNKNOWN,
        DISPATCH_NOT_PROVEN,
        RECONCILED_EXECUTED,
        RECONCILED_NOT_EXECUTED,
    }
)

#: An approval in one of these holds, or may still hold, execution authority
#: over its outcome on its zone, so a later proposal for the same outcome on
#: the same zone is blocked while it stands.
BLOCKING_STATES: Final[frozenset[str]] = frozenset(
    {
        APPROVED_PENDING_DISPATCH,
        DISPATCH_STARTED,
        DISPATCH_OUTCOME_UNKNOWN,
        DISPATCH_NOT_PROVEN,
    }
)

#: The two states reconciliation moves.
UNCERTAIN_STATES: Final[frozenset[str]] = frozenset(
    {DISPATCH_OUTCOME_UNKNOWN, DISPATCH_NOT_PROVEN}
)

#: States in which the approval was admitted; the operator's affirmative reply
#: became a durable decision, whatever became of the act.
ADMITTED_STATES: Final[frozenset[str]] = frozenset(
    {
        APPROVED_PENDING_DISPATCH,
        DISPATCH_STARTED,
        EXECUTED,
        APPROVAL_EXPIRED_UNDISPATCHED,
        APPROVAL_ABORTED_UNDISPATCHED,
        DISPATCH_REFUSED_CONTENTION,
        DISPATCH_FAILED,
        DISPATCH_OUTCOME_UNKNOWN,
        DISPATCH_NOT_PROVEN,
        RECONCILED_EXECUTED,
        RECONCILED_NOT_EXECUTED,
    }
)

#: The reasons `evidence reconcile-tier-c` accepts; the observation method.
RECONCILE_REASONS: Final[frozenset[str]] = frozenset(
    {"site_inspection", "instrument_measurement", "actuator_position_observed"}
)

# ── The proposal's lifetime ───────────────────────────────────────────────────
#: The release-defined maximum Tier C proposal lifetime. A deployment may
#: shorten it through `approval_timeout_seconds` and never extend it. Physical
#: authority left open longer than this is stale against the conditions that
#: produced it.
MAX_PROPOSAL_LIFETIME_S: Final = 3600


def approval_timeout_accepted(
    value: Any, *, release_maximum_s: int = MAX_PROPOSAL_LIFETIME_S
) -> bool:
    """Whether *value* is an `approval_timeout_seconds` a deployment may set.

    An integer from 1 to the release maximum. A fraction, a Boolean, a string
    and anything outside the bound are refused, never rounded or clamped.
    """
    return type(value) is int and 1 <= value <= int(release_maximum_s)


# ── The authority snapshot ────────────────────────────────────────────────────
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SNAPSHOT_MEMBERS: Final[tuple[str, ...]] = (
    "action",
    "action_capability",
    "binding_digest",
    "outcome",
    "policy_digest",
    "resource",
    "safety_profile",
    "v",
    "zone_digest",
    "zone_id",
)


class MalformedSnapshotError(ValueError):
    """An authority snapshot that cannot bind a proposal."""


def canonical_bytes(value: Any) -> bytes:
    """Profile 2 canonical form: sorted keys, no whitespace, UTF-8, no NaN."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _refuse_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise MalformedSnapshotError(f"member {key!r} is named twice")
        seen[key] = value
    return seen


def parse_snapshot_text(text: str) -> dict[str, Any]:
    """Decode snapshot JSON, refusing a member named twice at any depth."""
    try:
        decoded = json.loads(text, object_pairs_hook=_refuse_duplicate_members)
    except MalformedSnapshotError:
        raise
    except (ValueError, RecursionError) as exc:
        raise MalformedSnapshotError(f"not JSON ({exc})") from exc
    if not isinstance(decoded, dict):
        raise MalformedSnapshotError("not an object")
    return decoded


def validate_snapshot(snapshot: Any) -> dict[str, Any]:
    """Return *snapshot* when it is a well-formed authority snapshot.

    Exactly the ten members; `v` the integer 1; every digest `sha256:` and 64
    lowercase hex characters, except `safety_profile`, which may be empty when
    no profile is in force; every other member a string.
    """
    if not isinstance(snapshot, dict):
        raise MalformedSnapshotError("not an object")
    keys = tuple(sorted(snapshot))
    if keys != SNAPSHOT_MEMBERS:
        missing = sorted(set(SNAPSHOT_MEMBERS) - set(keys))
        extra = sorted(set(keys) - set(SNAPSHOT_MEMBERS))
        raise MalformedSnapshotError(f"members missing {missing}, unexpected {extra}")
    version = snapshot["v"]
    if type(version) is not int or version != 1:
        raise MalformedSnapshotError("v must be the integer 1")
    for member in (
        "action_capability",
        "binding_digest",
        "policy_digest",
        "zone_digest",
    ):
        value = snapshot[member]
        if not isinstance(value, str) or not _DIGEST.match(value):
            raise MalformedSnapshotError(f"{member} is not a sha256 digest")
    profile = snapshot["safety_profile"]
    if not isinstance(profile, str) or (profile and not _DIGEST.match(profile)):
        raise MalformedSnapshotError("safety_profile is not a sha256 digest or empty")
    for member in ("action", "outcome", "resource", "zone_id"):
        if not isinstance(snapshot[member], str):
            raise MalformedSnapshotError(f"{member} is not a string")
    return snapshot


def snapshot_bytes(snapshot: dict[str, Any]) -> bytes:
    """The exact bytes a proposal binds and an approval is matched against."""
    return canonical_bytes(validate_snapshot(snapshot))


def capability_digest(entry: ActionCapability) -> str:
    """The digest of a registry capability, as the snapshot names it."""
    return sha256_digest(
        canonical_bytes(
            {
                "consequence_class": entry.consequence_class,
                "minimum_tier": entry.minimum_tier,
                "physical": entry.physical,
                "safe_default_eligible": entry.safe_default_eligible,
            }
        )
    )


@dataclass(frozen=True)
class AuthorityInputs:
    """Everything the snapshot is computed from, held by the runtime."""

    action: str
    outcome: str
    resource: str
    zone_id: str
    zone_document: Any
    binding_canonical_hash: str
    safety_profile_digest: str
    policy_inputs: Any


def build_snapshot(inputs: AuthorityInputs) -> dict[str, Any]:
    """The authority snapshot for a proposal, or a MalformedSnapshotError."""
    entry = capability(inputs.action)
    if entry is None:
        raise MalformedSnapshotError(f"{inputs.action!r} has no registry capability")
    binding = str(inputs.binding_canonical_hash or "")
    if not binding.startswith("sha256:"):
        binding = sha256_digest(binding.encode("utf-8")) if binding else ""
    snapshot = {
        "action": inputs.action,
        "action_capability": capability_digest(entry),
        "binding_digest": binding,
        "outcome": inputs.outcome,
        "policy_digest": sha256_digest(canonical_bytes(inputs.policy_inputs)),
        "resource": inputs.resource,
        "safety_profile": str(inputs.safety_profile_digest or ""),
        "v": 1,
        "zone_digest": sha256_digest(canonical_bytes(inputs.zone_document)),
        "zone_id": inputs.zone_id,
    }
    return validate_snapshot(snapshot)


# ── Which proposals the contract governs ──────────────────────────────────────
GOVERNED: Final = "governed"
REFUSED: Final = "refused"
OUTSIDE_CONTRACT: Final = "outside_contract"

#: Every action the runtime can execute, by what it can do to the world. Pinned
#: here, independent of the registry it checks: a physical action whose
#: registry entry disagreed would still be refused as a safe default. A new
#: executor has to be classified here before a proposal can name it.
PHYSICALITY: Final[dict[str, str]] = {
    "alert_whatsapp": "informational",
    "alert_sms": "informational",
    "log_to_dashboard": "informational",
    "terminate_process": "host_state",
    "reset_kernel_subsystem": "host_state",
    "coap_command": "physical",
    "trip_relay": "physical",
    "release_relay": "physical",
    "close_gas_valve": "physical",
    "open_protected_circuit": "physical",
    "close_protected_circuit": "physical",
}


def physicality(action: str) -> str:
    """`informational`, `host_state`, `physical`, or `unclassified`."""
    return PHYSICALITY.get(str(action), "unclassified")


def proposal_scope(
    action: str,
    tier: str,
    *,
    zone_id: str | None,
    commissioned_outcome_name: str | None,
    requires_approval: bool = False,
) -> str:
    """Whether tier-c-approval/v1 governs, refuses or does not reach a proposal.

    Governed: a physical action proposed at Tier C through a commissioned zone
    and outcome. Refused: a physical action at Tier C with no zone, or the
    generic `coap_command` however it is named. Outside: a host-state action,
    and any Tier B action requiring approval, which stay on the existing
    workflow.
    """
    kind = physicality(action)
    if str(tier).upper() != "C":
        return OUTSIDE_CONTRACT
    if kind != "physical":
        return OUTSIDE_CONTRACT
    if action == "coap_command":
        return REFUSED
    if not zone_id or not commissioned_outcome_name:
        return REFUSED
    return GOVERNED


def governed_outcome(action: str) -> str | None:
    """The commissioned outcome a governed action commands, or None."""
    if action in ("open_protected_circuit", "close_protected_circuit"):
        return action
    return commissioned_outcome(action)


# ── Safe defaults ─────────────────────────────────────────────────────────────
def safe_default_admitted(
    action: str, *, entry: ActionCapability | None = None
) -> bool:
    """Whether *action* may stand as a Tier C proposal's safe default.

    Three independent refusals, each sufficient: the physicality table above
    does not classify it `informational`; it has no registry entry, or that
    entry is not `informational` and `safe_default_eligible` and non-physical.
    """
    if physicality(action) != "informational":
        return False
    registry = entry if entry is not None else capability(action)
    if registry is None:
        return False
    return (
        registry.consequence_class == "informational"
        and registry.safe_default_eligible
        and not registry.physical
    )


def unclassified_executors(executors: Any) -> list[str]:
    """Registered executors the physicality table does not classify."""
    return sorted(name for name in executors if name not in PHYSICALITY)


def registry_disagreements() -> list[str]:
    """Registry entries whose physical flag contradicts the physicality table."""
    wrong = []
    for name, entry in ACTION_REGISTRY.items():
        kind = PHYSICALITY.get(name)
        if kind is None or entry.physical != (kind == "physical"):
            wrong.append(name)
    return sorted(wrong)
