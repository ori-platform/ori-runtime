#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Generate the shared cross-store device-lifecycle vectors.

The contract is ori-specs/device-provisioning/v1.md, which requires
"shared cross-repo lifecycle vectors ... agreed byte-for-byte by every
implementing repository" before an implementation may claim it.

Two things are being pinned, and they are pinned differently.

**Epoch identifiers** are *derived* here. ``key_epoch_id`` and
``anchor_epoch_id`` exist so two stores that never talk to each other
compute the same value for the same anchor; that is what makes "both
accepted the same epoch" checkable rather than asserted. The canonical
pre-image bytes are emitted alongside each identifier so a mismatch in
another language localises to canonicalisation or to hashing, instead of
presenting as an opaque hash difference.

**Scenario expectations are hand-authored from the spec**, not recorded
from this store. That distinction is the whole point. A corpus generated
by running the implementation cannot detect that the implementation is
wrong -- it certifies whatever the code does today, and a bug becomes the
contract the moment it ships. Every ``expect`` and ``final_state`` below
was written by reading the section named in ``contract_ref``, so a
runtime that deviates from the spec fails its verifier rather than
quietly rewriting the corpus.

The keys are fixed test values. Nothing here needs a private key: the
lifecycle operates on an anchor's *identity*, and signature verification
happens a layer above, in the gate.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from ori.security.firmware.telemetry import (
    anchor_epoch_id,
    canonical_json_bytes,
    key_epoch_id,
)

CONTRACT = "ori-specs/device-provisioning/v1.md"
VERSION = 1

DEVICE_ID = "ori-edge-lifecycle-01"

# Fixed 32-byte test keys. Distinct, deterministic, and obviously
# synthetic so no one mistakes one for a fleet key.
KEYS = {
    "K1": base64.b64encode(bytes([0x11] * 32)).decode(),
    "K2": base64.b64encode(bytes([0x22] * 32)).decode(),
    "K3": base64.b64encode(bytes([0x33] * 32)).decode(),
}

CAPS = {
    "C1": "sha256:" + hashlib.sha256(b"ori-lifecycle-capability-1").hexdigest(),
    "C2": "sha256:" + hashlib.sha256(b"ori-lifecycle-capability-2").hexdigest(),
    "C3": "sha256:" + hashlib.sha256(b"ori-lifecycle-capability-3").hexdigest(),
}

# Named anchors, referenced by scenarios. An anchor is the triple the
# lifecycle actually turns on: key, posture, capability hash.
ANCHORS: dict[str, dict[str, str]] = {
    # baseline
    "A1": {"key": "K1", "posture": "development", "cap": "C1"},
    # same key, new manifest -> same key epoch, new anchor epoch
    "A2": {"key": "K1", "posture": "development", "cap": "C2"},
    # a second manifest change, to exercise pending replacement
    "A3": {"key": "K1", "posture": "development", "cap": "C3"},
    # new key -> new key epoch
    "A4": {"key": "K2", "posture": "development", "cap": "C1"},
    # a third key, for the reuse case
    "A5": {"key": "K3", "posture": "development", "cap": "C1"},
    # same key and manifest, different posture: a different trust
    # proposition, so a different anchor epoch under the same key epoch
    "A6": {"key": "K1", "posture": "sealed_flash", "cap": "C1"},
}


def anchor_fields(name: str) -> dict[str, str]:
    a = ANCHORS[name]
    return {
        "device_id": DEVICE_ID,
        "public_key_b64": KEYS[a["key"]],
        "posture": a["posture"],
        "capability_hash": CAPS[a["cap"]],
    }


def epoch_ids(name: str) -> tuple[str, str]:
    f = anchor_fields(name)
    return (
        key_epoch_id(device_id=f["device_id"], public_key_b64=f["public_key_b64"]),
        anchor_epoch_id(**f),
    )


# ── Scenarios ────────────────────────────────────────────────────────
#
# Authored from the spec. `contract_ref` names the section each
# expectation comes from, so a reviewer can check the corpus against the
# contract without reading any implementation.
#
# `ops`:
#   register     ordinary device-initiated registration
#   promote      the operator act that makes a pending anchor active
#   revoke       take the identity out of service
#   reinstate    return a revoked identity to service
#   reprovision  explicit, audited key replacement
#   advance_freshness / allocate_cmd_seq   freshness bookkeeping
#
# `final_state.anchor_states` is the COMPLETE set of anchors the identity
# has ever held, keyed by name. Requiring completeness is deliberate: an
# implementation that silently deletes a superseded anchor would satisfy
# a subset check while destroying the history evidence depends on.

SCENARIOS: list[dict[str, Any]] = [
    {
        "name": "first_registration_is_pending",
        "contract_ref": "Registration Lifecycle / Anchor States",
        "why": (
            "A device that has just published its manifest has proved "
            "internal consistency and nothing else. It grants nothing "
            "until an operator promotes it."
        ),
        "steps": [{"op": "register", "anchor": "A1", "expect": "registered"}],
        "final_state": {
            "approved": False,
            "revoked": False,
            "active": None,
            "pending": "A1",
            "anchor_states": {"A1": "pending"},
            "activation_counts": {},
            "transitions": [],
        },
    },
    {
        "name": "duplicate_registration_is_idempotent",
        "contract_ref": "Registration Lifecycle -- anchor matches active exactly",
        "why": (
            "A device reconnecting and re-publishing an unchanged "
            "manifest is the common case, not an event. Re-registration "
            "must not re-open approval or disturb freshness."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "advance_freshness", "boot_id": 7, "seq": 42, "expect": True},
            {"op": "register", "anchor": "A1", "expect": "unchanged"},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A1",
            "pending": None,
            "anchor_states": {"A1": "active"},
            "activation_counts": {"A1": 1},
            "last_boot_id": 7,
            "last_seq": 42,
            "transitions": ["promoted"],
        },
    },
    {
        "name": "pending_registration_republished_is_idempotent",
        "contract_ref": "Registration Lifecycle -- anchor matches pending exactly",
        "why": "Re-publishing does not promote. Only an operator promotes.",
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "register", "anchor": "A1", "expect": "unchanged"},
        ],
        "final_state": {
            "approved": False,
            "revoked": False,
            "active": None,
            "pending": "A1",
            "anchor_states": {"A1": "pending"},
            "activation_counts": {},
            "transitions": [],
        },
    },
    {
        "name": "manifest_change_becomes_pending_candidate",
        "contract_ref": "Registration Lifecycle -- same key, new capability_hash",
        "why": (
            "A device must not be able to grant itself a new capability "
            "surface by publishing. The new manifest waits beside the "
            "active anchor, which keeps operating untouched."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "advance_freshness", "boot_id": 3, "seq": 9, "expect": True},
            {"op": "register", "anchor": "A2", "expect": "pending_manifest_epoch"},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A1",
            "pending": "A2",
            "anchor_states": {"A1": "active", "A2": "pending"},
            "activation_counts": {"A1": 1},
            # Freshness is scoped to the KEY epoch, which did not change.
            "last_boot_id": 3,
            "last_seq": 9,
            "transitions": ["promoted"],
        },
    },
    {
        "name": "posture_change_is_a_new_anchor_epoch",
        "contract_ref": "Epoch Identity / anchor_epoch_id",
        "why": (
            "The same device in sealed_flash is a materially different "
            "trust proposition from the same device in development, even "
            "with an unchanged key and manifest, so it needs approving."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "register", "anchor": "A6", "expect": "pending_manifest_epoch"},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A1",
            "pending": "A6",
            "anchor_states": {"A1": "active", "A6": "pending"},
            "activation_counts": {"A1": 1},
            "transitions": ["promoted"],
        },
    },
    {
        "name": "replaced_pending_candidate_is_discarded",
        "contract_ref": "Replacing a pending candidate",
        "why": (
            "Refusing instead would strand a device whose unpromoted "
            "manifest was wrong. Discarding costs nothing because a "
            "pending anchor never granted anything -- which is exactly "
            "why it is recorded as discarded rather than superseded."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "register", "anchor": "A2", "expect": "pending_manifest_epoch"},
            {"op": "register", "anchor": "A3", "expect": "pending_manifest_epoch"},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A1",
            "pending": "A3",
            "anchor_states": {"A1": "active", "A2": "discarded", "A3": "pending"},
            "activation_counts": {"A1": 1},
            "transitions": ["promoted"],
        },
    },
    {
        "name": "promotion_supersedes_the_previous_anchor",
        "contract_ref": "Anchor States / Promotion",
        "why": (
            "The previous anchor is retained, never deleted: evidence "
            "outlives the anchor that authorised it."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "register", "anchor": "A2", "expect": "pending_manifest_epoch"},
            {"op": "advance_freshness", "boot_id": 4, "seq": 11, "expect": True},
            {"op": "promote", "expect": True},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A2",
            "pending": None,
            "anchor_states": {"A1": "superseded", "A2": "active"},
            "activation_counts": {"A1": 1, "A2": 1},
            # Same key epoch throughout, so the replay window stays closed.
            "last_boot_id": 4,
            "last_seq": 11,
            "transitions": ["promoted", "promoted"],
        },
    },
    {
        "name": "superseded_anchor_re_registered_stays_ever_active",
        "contract_ref": (
            "Anchor History / Re-registering an anchor the identity has held before"
        ),
        "why": (
            "An anchor epoch has one record whose state is its CURRENT "
            "state, so re-registering a superseded anchor returns it to "
            "pending and the state field stops showing it was ever "
            "active. Evidence produced while it WAS active is still "
            "attributed to it. An implementation that answered "
            "'was this authorised' from current state would read "
            "correctly signed history as never authorised, so the "
            "active intervals must survive the re-registration."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "register", "anchor": "A2", "expect": "pending_manifest_epoch"},
            {"op": "promote", "expect": True},
            # A1 is superseded here; registering it again returns it to
            # pending, which is what erases "was active" from the state.
            {"op": "register", "anchor": "A1", "expect": "pending_manifest_epoch"},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A2",
            "pending": "A1",
            "anchor_states": {"A1": "pending", "A2": "active"},
            # The point of the scenario: A1 reads pending, and is still
            # identifiable as having been active.
            "activation_counts": {"A1": 1, "A2": 1},
            "transitions": ["promoted", "promoted"],
        },
    },
    {
        "name": "discarded_anchor_re_registered_returns_to_pending",
        "contract_ref": ("Re-registering an anchor the identity has held before"),
        "why": (
            "A discarded candidate was never active, so returning it to "
            "pending attributes no evidence and grants nothing. It is "
            "still not neutral: it displaces whatever candidate was "
            "pending, which is recorded discarded in its place. The "
            "judgement belongs at promotion, which has not happened."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "register", "anchor": "A2", "expect": "pending_manifest_epoch"},
            {"op": "register", "anchor": "A3", "expect": "pending_manifest_epoch"},
            # A2 is discarded here; registering it again brings it back
            # and displaces A3 in turn.
            {"op": "register", "anchor": "A2", "expect": "pending_manifest_epoch"},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A1",
            "pending": "A2",
            "anchor_states": {
                "A1": "active",
                "A2": "pending",
                "A3": "discarded",
            },
            "activation_counts": {"A1": 1},
            "transitions": ["promoted"],
        },
    },
    {
        "name": "key_change_refused_through_registration",
        "contract_ref": "Why a changed key cannot arrive through ordinary registration",
        "why": (
            "A self-signed manifest proves internal consistency, never "
            "provenance. Accepting a new key on that basis would let "
            "anyone able to publish take over the identity."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "register", "anchor": "A4", "expect": "refused_key_change"},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A1",
            "pending": None,
            "anchor_states": {"A1": "active"},
            "activation_counts": {"A1": 1},
            "transitions": ["promoted"],
        },
    },
    {
        "name": "revocation_retains_active_and_discards_pending",
        "contract_ref": "Revocation",
        "why": (
            "The formerly active anchor is retained so reinstatement has "
            "something to return to. A pending candidate is discarded, so "
            "revocation cannot leave a promotable anchor behind."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "register", "anchor": "A2", "expect": "pending_manifest_epoch"},
            {"op": "revoke", "expect": True},
        ],
        "final_state": {
            "approved": False,
            "revoked": True,
            "active": None,
            "pending": None,
            "anchor_states": {"A1": "revoked", "A2": "discarded"},
            "activation_counts": {"A1": 1},
            "transitions": ["promoted", "revoked"],
        },
    },
    {
        "name": "revocation_survives_registration",
        "contract_ref": "Identity And Revocation",
        "why": (
            "Revocation belongs to the identity, not to an anchor. If "
            "re-publishing a manifest cleared it, revocation would be "
            "durable only until the device next reconnected."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "revoke", "expect": True},
            {"op": "register", "anchor": "A1", "expect": "refused_revoked"},
            {"op": "register", "anchor": "A2", "expect": "refused_revoked"},
        ],
        "final_state": {
            "approved": False,
            "revoked": True,
            "active": None,
            "pending": None,
            "anchor_states": {"A1": "revoked"},
            "activation_counts": {"A1": 1},
            "transitions": ["promoted", "revoked"],
        },
    },
    {
        "name": "revocation_survives_reprovision",
        "contract_ref": "Identity And Revocation / Re-provisioning",
        "why": (
            "Key replacement is not a way around revocation. Returning a "
            "revoked identity to service is reinstatement, which is "
            "separately audited."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "revoke", "expect": True},
            {"op": "reprovision", "anchor": "A4", "expect": "revoked"},
        ],
        "final_state": {
            "approved": False,
            "revoked": True,
            "active": None,
            "pending": None,
            "anchor_states": {"A1": "revoked"},
            "activation_counts": {"A1": 1},
            "transitions": ["promoted", "revoked"],
        },
    },
    {
        "name": "reinstatement_returns_to_pending_never_active",
        "contract_ref": "Reinstatement",
        "why": (
            "Promotion is the only path to active. Reinstatement undoes "
            "the revocation; it does not re-grant trust, so the operator "
            "must still promote, and that promotion is audited on its own."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "revoke", "expect": True},
            {"op": "reinstate", "expect": True},
        ],
        "final_state": {
            "approved": False,
            "revoked": False,
            "active": None,
            "pending": "A1",
            "anchor_states": {"A1": "pending"},
            "activation_counts": {"A1": 1},
            "transitions": ["promoted", "revoked", "reinstated"],
        },
    },
    {
        "name": "revocation_before_first_promotion_retains_nothing",
        "contract_ref": "Revocation / Reinstatement",
        "why": (
            "Revoking an identity that was never promoted discards its "
            "pending candidate and retains no anchor, because there was "
            "never an active one. Reinstatement therefore has nothing to "
            "return to pending: it clears the revocation and grants "
            "nothing, and the device must register again before there is "
            "anything to promote. This is a materially different "
            "reinstatement state from the promoted case, and the one "
            "where an implementation is most likely to resurrect a "
            "discarded candidate."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "revoke", "expect": True},
            {"op": "reinstate", "expect": True},
        ],
        "final_state": {
            "approved": False,
            "revoked": False,
            "active": None,
            "pending": None,
            "anchor_states": {"A1": "discarded"},
            "activation_counts": {},
            "transitions": ["revoked", "reinstated"],
        },
    },
    {
        "name": "reinstated_unpromoted_identity_must_register_again",
        "contract_ref": "Revocation / Reinstatement / Promotion",
        "why": (
            "The return path for a never-promoted identity runs through "
            "registration, not promotion. The discarded candidate stays "
            "discarded; the re-registered anchor is a new pending one."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "revoke", "expect": True},
            {"op": "reinstate", "expect": True},
            {"op": "register", "anchor": "A2", "expect": "pending_manifest_epoch"},
            {"op": "promote", "expect": True},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A2",
            "pending": None,
            # A1 stays discarded. The history proves the candidate that was
            # discarded at revocation was retained and never resurrected.
            "anchor_states": {"A1": "discarded", "A2": "active"},
            "activation_counts": {"A2": 1},
            "transitions": ["revoked", "reinstated", "promoted"],
        },
    },
    {
        "name": "reinstated_identity_is_promotable_again",
        "contract_ref": "Reinstatement / Promotion",
        "why": "Reinstatement plus promotion is the full return to service.",
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "revoke", "expect": True},
            {"op": "reinstate", "expect": True},
            {"op": "promote", "expect": True},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A1",
            "pending": None,
            "anchor_states": {"A1": "active"},
            "activation_counts": {"A1": 2},
            "transitions": ["promoted", "revoked", "reinstated", "promoted"],
        },
    },
    {
        "name": "reprovision_leaves_the_previous_anchor_active",
        "contract_ref": "Re-provisioning (key replacement)",
        "why": (
            "Re-provisioning stores the new key as PENDING and leaves the "
            "current anchor active until an operator promotes. The device "
            "keeps working under its existing key throughout. This "
            "scenario deliberately ENDS at the re-provisioning: every "
            "other rotation case promotes afterwards, which would close "
            "the old anchor's active interval anyway and hide an "
            "implementation that ended it too early."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "reprovision", "anchor": "A4", "expect": "reprovisioned"},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A1",
            "pending": "A4",
            "anchor_states": {"A1": "active", "A4": "pending"},
            # A1's interval is still OPEN here: it is active now.
            "activation_counts": {"A1": 1},
            "transitions": ["promoted", "reprovisioned"],
        },
    },
    {
        "name": "key_rotation_via_reprovision",
        "contract_ref": "Re-provisioning (key replacement) / Freshness Across Epochs",
        "why": (
            "The new key lands pending, so the device keeps operating "
            "under the old anchor until an operator promotes. Promoting a "
            "new KEY epoch resets telemetry freshness -- a re-keyed device "
            "restarts its counters and would otherwise be refused as a "
            "replay against its predecessor's high-water mark. cmd_seq is "
            "per device, not per key, so it survives."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "advance_freshness", "boot_id": 5, "seq": 77, "expect": True},
            {"op": "allocate_cmd_seq", "expect": 1},
            {"op": "allocate_cmd_seq", "expect": 2},
            {"op": "reprovision", "anchor": "A4", "expect": "reprovisioned"},
            # The active anchor is untouched while the new key waits.
            {"op": "assert_active", "anchor": "A1"},
            {"op": "promote", "expect": True},
            # The command mark continues from 2 rather than restarting.
            # Asserting the next allocation proves continuation; reading
            # the stored column would also pass if the counter had been
            # reset and coincidentally rewritten.
            {"op": "allocate_cmd_seq", "expect": 3},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A4",
            "pending": None,
            "anchor_states": {"A1": "superseded", "A4": "active"},
            "activation_counts": {"A1": 1, "A4": 1},
            "last_boot_id": 0,
            "last_seq": 0,
            "transitions": ["promoted", "reprovisioned", "promoted"],
        },
    },
    {
        "name": "reprovision_with_the_current_key_refused",
        "contract_ref": "Re-provisioning (key replacement)",
        "why": (
            "Nothing is being replaced. Accepting it would put a pending "
            "anchor over an active one for the same key, leaving the "
            "registry and the anchor history disagreeing about which "
            "anchor is trusted."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "reprovision", "anchor": "A2", "expect": "refused_same_key"},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A1",
            "pending": None,
            "anchor_states": {"A1": "active"},
            "activation_counts": {"A1": 1},
            "transitions": ["promoted"],
        },
    },
    {
        "name": "reprovision_to_a_previously_used_key_refused",
        "contract_ref": "Re-provisioning (key replacement)",
        "why": (
            "An old key may be exactly the one rotated away from because "
            "it was compromised. Returning to it would make rotation "
            "reversible by whoever still holds it."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "reprovision", "anchor": "A4", "expect": "reprovisioned"},
            {"op": "promote", "expect": True},
            # Back to K1 -- the key just rotated away from.
            {"op": "reprovision", "anchor": "A2", "expect": "refused_key_reuse"},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A4",
            "pending": None,
            "anchor_states": {"A1": "superseded", "A4": "active"},
            "activation_counts": {"A1": 1, "A4": 1},
            "transitions": ["promoted", "reprovisioned", "promoted"],
        },
    },
    {
        "name": "second_rotation_to_a_fresh_key_accepted",
        "contract_ref": "Re-provisioning (key replacement) / Anchor History",
        "why": (
            "Refusing key reuse must not refuse rotation itself. A "
            "genuinely new key is still accepted after a previous "
            "rotation, and every anchor stays in history."
        ),
        "steps": [
            {"op": "register", "anchor": "A1", "expect": "registered"},
            {"op": "promote", "expect": True},
            {"op": "reprovision", "anchor": "A4", "expect": "reprovisioned"},
            {"op": "promote", "expect": True},
            {"op": "reprovision", "anchor": "A5", "expect": "reprovisioned"},
            {"op": "promote", "expect": True},
        ],
        "final_state": {
            "approved": True,
            "revoked": False,
            "active": "A5",
            "pending": None,
            "anchor_states": {
                "A1": "superseded",
                "A4": "superseded",
                "A5": "active",
            },
            "activation_counts": {"A1": 1, "A4": 1, "A5": 1},
            "transitions": [
                "promoted",
                "reprovisioned",
                "promoted",
                "reprovisioned",
                "promoted",
            ],
        },
    },
]


def build() -> dict[str, Any]:
    epoch_vectors = []
    for name in sorted(ANCHORS):
        f = anchor_fields(name)
        key_pre = canonical_json_bytes(
            {
                "device_id": f["device_id"],
                "public_key_b64": f["public_key_b64"],
                "v": 1,
            }
        )
        anchor_pre = canonical_json_bytes(
            {
                "capability_hash": f["capability_hash"],
                "device_id": f["device_id"],
                "posture": f["posture"],
                "public_key_b64": f["public_key_b64"],
                "v": 1,
            }
        )
        kid, aid = epoch_ids(name)
        epoch_vectors.append(
            {
                "anchor": name,
                "input": f,
                "key_epoch_canonical_hex": key_pre.hex(),
                "key_epoch_id": kid,
                "anchor_epoch_canonical_hex": anchor_pre.hex(),
                "anchor_epoch_id": aid,
            }
        )

    scenarios = []
    for s in SCENARIOS:
        entry = dict(s)
        used = sorted(
            {st["anchor"] for st in s["steps"] if "anchor" in st}
            | set(s["final_state"]["anchor_states"])
        )
        entry["anchors_used"] = used
        scenarios.append(entry)

    return {
        "contract": CONTRACT,
        "version": VERSION,
        "comment": (
            "Shared cross-store device-lifecycle vectors. Epoch identifiers "
            "are derived; scenario expectations are hand-authored from the "
            "contract sections named in each contract_ref, so an "
            "implementation that deviates fails rather than redefining the "
            "corpus. Keys are fixed test values and are never used in "
            "production."
        ),
        "device_id": DEVICE_ID,
        "keys": KEYS,
        "capability_hashes": CAPS,
        "anchors": {
            name: {
                "public_key_b64": KEYS[a["key"]],
                "posture": a["posture"],
                "capability_hash": CAPS[a["cap"]],
                "key_ref": a["key"],
            }
            for name, a in ANCHORS.items()
        },
        "epoch_vectors": epoch_vectors,
        "scenarios": scenarios,
    }


def main() -> None:
    out = Path(__file__).resolve().parents[1] / (
        "tests/fixtures/device_lifecycle_vectors.json"
    )
    out.write_text(json.dumps(build(), indent=2, sort_keys=False) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
