# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The licence an action was dispatched under is replayed, never rebuilt.

`evidence/v2` requires an `authority` object on every `runtime_action` payload,
naming what permitted the action. The value cannot be derived at sealing time:
reconciliation runs after a restart, and the skill, profile or binding loaded
then may not be the one that licensed the action. So it is captured when the
action row is first written and replayed verbatim.

What that buys is the case these tests exist for — a device that crashed between
acting and attesting seals the decision it actually made, not the one its
current configuration would imply.
"""

from __future__ import annotations

import json

import pytest

from ori.security.evidence.first_party import (
    AuthorityUnavailableError,
    _action_payload,
)

LEGACY_SKILL = {
    "kind": "tier_d_legacy_skill",
    "skill_name": "energy-anomaly-detector",
    "skill_version": "0.2.1",
    "trigger_name": "dangerous_overcurrent",
}
TIER_C = {"kind": "tier_c_approval", "proposal_id": "AB12CD34"}
PROFILE = {
    "kind": "tier_d_profile",
    "profile_id": "electrical.overcurrent.v1",
    "zone_id": "zone-main-incomer",
    "binding_seq": 4,
}
QUALIFICATION = {
    **PROFILE,
    "kind": "tier_d_qualification",
    "fixture_hash": "sha256:" + "b" * 64,
}


def _row(**overrides) -> dict:
    row = {
        "id": 7,
        "action_name": "emergency_cutoff",
        "tier": "D",
        "executed": True,
        "approved": None,
        "action_taken": "emergency_cutoff",
        "trigger_name": "dangerous_overcurrent",
        "sensor_id": "load-current",
        "timestamp": 1787000000000,
        "authority_json": json.dumps(
            LEGACY_SKILL, sort_keys=True, separators=(",", ":")
        ),
    }
    row.update(overrides)
    return row


def test_at_emission_sealing_uses_the_stored_snapshot():
    payload = _action_payload(_row(), reconciled=False)

    assert payload["authority"] == LEGACY_SKILL
    assert payload["attestation"] == "at_emission"


def test_reconciliation_needs_no_loaded_skill():
    """The crash path: nothing is in scope but the stored row."""
    payload = _action_payload(_row(), reconciled=True)

    assert payload["authority"] == LEGACY_SKILL
    assert payload["attestation"] == "reconciled_late"


def test_a_changed_skill_version_does_not_change_the_sealed_authority():
    """The reason the snapshot exists at all.

    Reconstructing from the installed package would attribute an action to
    whatever is installed when the device recovers, which is a different claim
    wearing the same field name.
    """
    row = _row()

    sealed = _action_payload(row, reconciled=True)["authority"]

    assert sealed["skill_version"] == "0.2.1"
    assert sealed == json.loads(row["authority_json"])


@pytest.mark.parametrize("absent", [None, ""])
def test_a_row_with_no_snapshot_is_refused_not_invented(absent):
    """A migrated legacy row. Its licence was never recorded and cannot be."""
    with pytest.raises(AuthorityUnavailableError, match="cannot be recovered"):
        _action_payload(_row(authority_json=absent), reconciled=True)


def test_a_snapshot_disagreeing_with_a_query_column_is_refused():
    """One of the two was written from something other than this decision."""
    row = _row(
        tier="C",
        authority_json=json.dumps(TIER_C, sort_keys=True, separators=(",", ":")),
        proposal_id="ZZ99ZZ99",
    )

    with pytest.raises(AuthorityUnavailableError, match="disagrees"):
        _action_payload(row, reconciled=False)


def test_a_trigger_name_disagreeing_with_the_column_is_refused():
    row = _row(trigger_name="some_other_trigger")

    with pytest.raises(AuthorityUnavailableError, match="trigger_name"):
        _action_payload(row, reconciled=False)


@pytest.mark.parametrize(
    ("kind", "authority", "columns"),
    [
        ("tier_c_approval", TIER_C, {"tier": "C", "proposal_id": "AB12CD34"}),
        ("tier_d_legacy_skill", LEGACY_SKILL, {}),
        ("tier_d_profile", PROFILE, {"binding_seq": 4}),
        ("tier_d_qualification", QUALIFICATION, {"binding_seq": 4}),
    ],
)
def test_every_authority_kind_round_trips(kind, authority, columns):
    row = _row(
        authority_json=json.dumps(authority, sort_keys=True, separators=(",", ":")),
        trigger_name=authority.get("trigger_name", "dangerous_overcurrent"),
        **columns,
    )

    payload = _action_payload(row, reconciled=True)

    assert payload["authority"] == authority
    assert payload["authority"]["kind"] == kind


@pytest.mark.parametrize(
    "snapshot",
    [
        "not json at all",
        "[]",
        '"a string"',
        "{}",
        '{"proposal_id":"AB12CD34"}',
        '{"kind":7}',
    ],
)
def test_a_malformed_snapshot_never_reaches_signing(snapshot):
    with pytest.raises(AuthorityUnavailableError):
        _action_payload(_row(authority_json=snapshot), reconciled=False)


class TestRefusalIsTerminal:
    """A row that can never be attested must stop being retried.

    `failed` means "try again": the reconciliation loop selects it on every
    pass. A row whose licence was never recorded will never succeed, so leaving
    it `failed` retries a certainty forever and logs once per pass, burying the
    transient failures the loop exists to repair.
    """

    async def test_a_refused_row_leaves_the_reconciliation_set(self, tmp_path):
        from ori.state.store import StateStore

        store = StateStore(db_path=str(tmp_path / "terminal.db"))
        await store.open()
        try:
            from ori.network.events import ActionResult

            row_id = await store.log_action_for_event(
                ActionResult(
                    action_name="emergency_cutoff",
                    tier="D",
                    executed=True,
                    approved=None,
                    action_taken="emergency_cutoff",
                    timestamp=1787000000000,
                ),
                trigger_name="dangerous_overcurrent",
                attestation_pending=True,
            )
            assert [r["id"] for r in await store.get_actions_needing_attestation()] == [
                row_id
            ]

            await store.set_action_attestation(
                row_id,
                status="refused",
                attestation_seq=None,
                reason="authority_unavailable_for_reconciliation",
            )

            assert await store.get_actions_needing_attestation() == []
        finally:
            await store.close()

    async def test_a_transiently_failed_row_is_still_retried(self, tmp_path):
        """The control: `refused` must not swallow repairable failures."""
        from ori.network.events import ActionResult
        from ori.state.store import StateStore

        store = StateStore(db_path=str(tmp_path / "retry.db"))
        await store.open()
        try:
            row_id = await store.log_action_for_event(
                ActionResult(
                    action_name="emergency_cutoff",
                    tier="D",
                    executed=True,
                    approved=None,
                    action_taken="emergency_cutoff",
                    timestamp=1787000000000,
                ),
                trigger_name="dangerous_overcurrent",
                attestation_pending=True,
            )
            await store.set_action_attestation(
                row_id, status="failed", attestation_seq=None
            )

            assert [r["id"] for r in await store.get_actions_needing_attestation()] == [
                row_id
            ]
        finally:
            await store.close()
