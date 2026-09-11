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
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ori.security.evidence.first_party import (
    AUTHORITY_UNAVAILABLE_REASON,
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


async def _attestation_of(store, row_id: int) -> tuple[str, str]:
    """The persisted attestation state, read from the row itself."""

    def read(conn):
        row = conn.execute(
            "SELECT attestation_status, attestation_reason FROM action_log "
            "WHERE id = ?",
            (row_id,),
        ).fetchone()
        return (row[0], row[1])

    return await store._run_read(lambda conn: read(conn))


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
                reason=AUTHORITY_UNAVAILABLE_REASON,
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


class TestGrammarIsEnforcedBeforeSigning:
    """Presence is not enough, and a non-conforming snapshot must not be signed.

    A snapshot naming the right fields with a null, an empty list and a string
    where an integer belongs satisfies a presence check and is refused by any
    conforming verifier. Signing it would publish a row that reads as evidence
    and is discounted on arrival.
    """

    @pytest.mark.parametrize(
        ("label", "snapshot"),
        [
            ("unknown kind", {"kind": "invented"}),
            ("missing required field", {"kind": "tier_c_approval"}),
            (
                "invalid field value",
                {"kind": "tier_c_approval", "proposal_id": "wrong"},
            ),
            (
                "typed garbage",
                {
                    "kind": "tier_d_profile",
                    "profile_id": None,
                    "zone_id": [],
                    "binding_seq": "three",
                },
            ),
            (
                "a field the kind does not permit",
                {"kind": "tier_c_approval", "proposal_id": "AB12CD34", "extra": True},
            ),
            (
                "a field belonging to another kind",
                {
                    "kind": "tier_c_approval",
                    "proposal_id": "AB12CD34",
                    "zone_id": "zone-a",
                },
            ),
            (
                "binding_seq below its range",
                {
                    "kind": "tier_d_profile",
                    "profile_id": "electrical.overcurrent.v1",
                    "zone_id": "zone-a",
                    "binding_seq": 0,
                },
            ),
        ],
    )
    def test_a_non_conforming_snapshot_is_refused(self, label, snapshot):
        row = _row(
            authority_json=json.dumps(snapshot),
            tier="C" if snapshot.get("kind") == "tier_c_approval" else "D",
            proposal_id="",
        )

        with pytest.raises(AuthorityUnavailableError, match="non-conforming"):
            _action_payload(row, reconciled=False)

    async def test_no_chain_row_is_allocated_for_an_invalid_snapshot(self, tmp_path):
        """Driven through `attest_action`, not the payload builder.

        A refusal that still consumed a sequence number would leave a gap a
        verifier reads as a missing row.
        """
        from ori.security.evidence.first_party import FirstPartyEvidenceAttestor

        attestor = FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "evidence.db"),
            key_path=str(tmp_path / "device.key"),
            device_secret="a" * 64,
            device_id="test-device",
        )
        assert await attestor.start()
        try:
            head_before = await attestor.chain_head_hash()

            with pytest.raises(AuthorityUnavailableError):
                await attestor.attest_action(_row(authority_json='{"kind":"invented"}'))

            assert await attestor.chain_head_hash() == head_before
        finally:
            attestor.close()


class TestTheProductionCallersRefuse:
    """The transition must happen where it really happens.

    Setting `refused` by hand proves the query excludes such a row. It does not
    prove either caller catches the refusal and performs that transition, which
    is the join that decides whether a device retries a certainty forever.
    """

    async def test_reconciliation_refuses_a_legacy_row_and_stops_retrying(
        self, tmp_path, monkeypatch
    ):
        from ori.network.events import ActionResult
        from ori.runtime import OriRuntime
        from ori.security.evidence.first_party import (
            AUTHORITY_UNAVAILABLE_REASON,
            FirstPartyEvidenceAttestor,
        )
        from ori.state.store import StateStore

        store = StateStore(db_path=str(tmp_path / "recon.db"))
        await store.open()
        attestor = FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "evidence.db"),
            key_path=str(tmp_path / "device.key"),
            device_secret="a" * 64,
            device_id="test-device",
        )
        assert await attestor.start()
        try:
            # A row written before the column existed: pending, no snapshot.
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

            calls: list[int] = []
            real = attestor.attest_action

            async def counting(action_row, *, reconciled=False):
                calls.append(int(action_row.get("id", 0)))
                return await real(action_row, reconciled=reconciled)

            monkeypatch.setattr(attestor, "attest_action", counting)

            # The real production method, bound to a stand-in carrying only the
            # collaborators it uses. Nothing about the transition is reimplemented
            # here; a stand-in for the method itself would test the test.
            runtime = SimpleNamespace(
                _evidence_attestor=attestor,
                _state_store=store,
                _firmware_source_confirmed=AsyncMock(return_value=True),
            )
            reconcile = OriRuntime._reconcile_pending_attestations

            await reconcile(runtime)

            assert await _attestation_of(store, row_id) == (
                "refused",
                AUTHORITY_UNAVAILABLE_REASON,
            )

            # The point of a terminal state: a second pass does not re-attempt.
            before = len(calls)
            await reconcile(runtime)
            assert len(calls) == before
        finally:
            attestor.close()
            await store.close()


class TestTierAndLicenceMustAgree:
    """A well-formed licence is not thereby the right licence.

    Tier C is an operator's scoped approval. Tier D is a release-owned safety
    condition. Sealing a Tier D action under a `tier_c_approval` would attest
    that a human approved a trip nobody was asked about — a falsified
    attribution inside the record that exists to be trustworthy about it.
    """

    @pytest.mark.parametrize(
        ("tier", "authority"),
        [
            ("D", TIER_C),
            ("C", LEGACY_SKILL),
            ("C", PROFILE),
            ("D", {**TIER_C}),
        ],
    )
    def test_a_licence_from_the_wrong_tier_is_refused(self, tier, authority):
        row = _row(
            tier=tier,
            authority_json=json.dumps(authority),
            proposal_id=authority.get("proposal_id", ""),
            trigger_name=authority.get("trigger_name", "dangerous_overcurrent"),
            binding_seq=authority.get("binding_seq"),
        )

        with pytest.raises(AuthorityUnavailableError, match="cannot be licensed by"):
            _action_payload(row, reconciled=False)

    @pytest.mark.parametrize("tier", ["A", "B", ""])
    def test_a_tier_off_the_evidence_path_carries_no_licence(self, tier):
        row = _row(tier=tier, authority_json=json.dumps(TIER_C), proposal_id="AB12CD34")

        with pytest.raises(AuthorityUnavailableError, match="no authority"):
            _action_payload(row, reconciled=False)

    async def test_no_sequence_is_allocated_for_a_cross_tier_licence(self, tmp_path):
        from ori.security.evidence.first_party import FirstPartyEvidenceAttestor

        attestor = FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "evidence.db"),
            key_path=str(tmp_path / "device.key"),
            device_secret="a" * 64,
            device_id="test-device",
        )
        assert await attestor.start()
        try:
            head_before = await attestor.chain_head_hash()

            with pytest.raises(AuthorityUnavailableError):
                await attestor.attest_action(
                    _row(
                        tier="D",
                        authority_json=json.dumps(TIER_C),
                        proposal_id="AB12CD34",
                    )
                )

            assert await attestor.chain_head_hash() == head_before
        finally:
            attestor.close()


class TestTheEmissionCallerRefuses:
    """The dispatcher's own attestation path, not only reconciliation.

    Existing dispatcher tests cover a generic exception becoming `failed` and a
    `None` return becoming `failed`. Neither reaches this typed refusal, which
    must be terminal rather than retried forever.
    """

    async def test_the_dispatcher_marks_a_bad_licence_terminally_refused(
        self, tmp_path
    ):
        from ori.network.events import ActionResult
        from ori.reasoning.action_dispatcher import ActionDispatcher
        from ori.security.evidence.first_party import (
            AUTHORITY_UNAVAILABLE_REASON,
            FirstPartyEvidenceAttestor,
        )
        from ori.state.store import StateStore

        store = StateStore(db_path=str(tmp_path / "emit.db"))
        await store.open()
        attestor = FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "evidence.db"),
            key_path=str(tmp_path / "device.key"),
            device_secret="a" * 64,
            device_id="test-device",
        )
        assert await attestor.start()
        try:
            result = ActionResult(
                action_name="emergency_cutoff",
                tier="D",
                executed=True,
                approved=None,
                action_taken="emergency_cutoff",
                timestamp=1787000000000,
            )
            # A Tier D row licensed by an operator approval: well formed, and
            # the wrong licence for this tier.
            row_id = await store.log_action_for_event(
                result,
                trigger_name="dangerous_overcurrent",
                attestation_pending=True,
                authority_json=json.dumps(TIER_C),
            )

            dispatcher = ActionDispatcher(evidence_attestor=attestor)
            await dispatcher._attest_action(
                store,
                row_id,
                result,
                "dangerous_overcurrent",
                "load-current",
                "unattested",
                "",
                "",
                0,
                0,
            )

            assert await _attestation_of(store, row_id) == (
                "refused",
                AUTHORITY_UNAVAILABLE_REASON,
            )
        finally:
            attestor.close()
            await store.close()


class TestAMissingTriggerNeverBecomesAnAuthority:
    """The sensor id is not the trigger, and must not be recorded as one.

    The evidence path once took `event.sensor_id` when no trigger name reached
    dispatch. Persisting that as a Tier D licence's `trigger_name` invents
    provenance from a different field, which is worse than having none: a
    reader cannot tell an attributed trip from an unattributed one.
    """

    async def test_the_action_runs_but_claims_no_licence(self, tmp_path):
        from unittest.mock import AsyncMock

        from ori.network.events import OriEvent, SensorReading
        from ori.reasoning.action_dispatcher import ActionDispatcher, ActionTier
        from ori.reasoning.elevator import SkillContext
        from ori.state.store import StateStore

        store = StateStore(db_path=str(tmp_path / "notrigger.db"))
        await store.open()
        try:
            reading = SensorReading(
                sensor_id="load-current",
                sensor_type="current",
                value=99.0,
                unit="ampere",
                timestamp=1787000000000,
                quality=1.0,
            )
            event = OriEvent.from_reading(reading, "dev-01")
            # A first-party skill, so Tier D authority is genuinely held and the
            # dispatch is not lowered for provenance — the missing trigger name
            # is the only thing under test. `SkillContext.trigger_name` is
            # absent, which is what the sensor fallback used to fill.
            skill = SimpleNamespace(
                name="energy-anomaly-detector",
                version="0.2.1",
                first_party=True,
                config={},
            )
            context = SkillContext(skill=skill, event=event, state_store=store)

            executed = AsyncMock(return_value=True)
            dispatcher = ActionDispatcher(config={"relay_enabled": True})
            dispatcher.register_executor("trip_relay", executed)

            result = await dispatcher.dispatch(
                "trip_relay",
                ActionTier.SAFETY_CRITICAL,
                context,
                _reasoning_result(),
            )

            # The physical action is not withheld for want of provenance.
            assert result.executed is True
            executed.assert_awaited_once()

            rows = await store._run_read(
                lambda conn: conn.execute(
                    "SELECT trigger_name, authority_json FROM action_log"
                ).fetchall()
            )
            assert rows, "the action was not logged"
            trigger_column, authority_json = rows[0]
            # The legacy display column keeps its historical fallback ...
            assert trigger_column == "load-current"
            # ... and the licence claims nothing rather than claiming a sensor.
            assert authority_json is None
        finally:
            await store.close()


def _reasoning_result():
    from ori.network.events import ReasoningResult

    return ReasoningResult(
        text="overcurrent",
        tier="rule",
        model="rule_engine",
        tokens_used=0,
        latency_ms=0,
        action_tier="D",
    )
