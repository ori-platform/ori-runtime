# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Behaviour of the first-party attestor that replaces the private loader."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from ori.security.evidence.anchor import derive_runtime_anchor
from ori.security.evidence.chain import (
    EVENT_ID_NAMESPACE,
    SCHEMA_VERSION,
    attestation_event_id,
)
from ori.security.evidence.first_party import (
    ACTION_EVENT_TYPE,
    FirstPartyEvidenceAttestor,
    PendingAuthorisationRegistrar,
)
from ori.security.evidence.registrar import (
    AnchorRegistrationRequest,
    RegistrationStatus,
)


def _text(value) -> str:
    """canonical_json is the signed byte string; read it as text either way."""
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


DEVICE = "energy-monitor-ikeja-01"
SECRET = "install-secret-for-tests"


def _action_row(action_log_id: int = 42, **overrides) -> dict:  # noqa: D401
    row = {
        "id": action_log_id,
        "action_name": "emergency_cutoff",
        "tier": "D",
        "executed": True,
        "approved": None,
        "action_taken": "emergency_cutoff",
        "trigger_name": "dangerous_overcurrent",
        "sensor_id": "load-current",
        "timestamp": 1787000000000,
    }
    row.update(overrides)
    return row


@pytest.fixture()
async def attestor(tmp_path):
    a = FirstPartyEvidenceAttestor(
        db_path=str(tmp_path / "evidence.db"),
        key_path=str(tmp_path / "device.key"),
        device_secret=SECRET,
        device_id=DEVICE,
    )
    assert await a.start() is True
    try:
        yield a
    finally:
        a.close()


class TestEventIdentity:
    def test_event_id_uses_the_v2_derivation(self, tmp_path) -> None:
        """The contract binds the device into the identity."""
        a = FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "e.db"),
            key_path=str(tmp_path / "k"),
            device_secret=SECRET,
            device_id=DEVICE,
        )
        assert a.attestation_event_id(42) == attestation_event_id(DEVICE, 42)

    def test_event_id_is_device_bound(self, tmp_path) -> None:
        """Two devices must not derive the same identity for the same row id."""
        ids = set()
        for device in (DEVICE, "another-device-02"):
            a = FirstPartyEvidenceAttestor(
                db_path=str(tmp_path / f"{device}.db"),
                key_path=str(tmp_path / f"{device}.key"),
                device_secret=SECRET,
                device_id=device,
            )
            ids.add(a.attestation_event_id(42))
        assert len(ids) == 2

    def test_event_id_is_not_the_v1_identity(self, tmp_path) -> None:
        """v1 identifiers must not be reproduced by a v2 producer.

        The v1 namespace encodes a private product name in its own bytes, so
        reproducing it would reintroduce an encoded identifier as well as
        writing a v1 identity into a v2 chain. v1 rows stay as they are.
        """
        # v1 used the same name string as v2 and differed only in its
        # namespace, so the namespace is the whole of the difference -- and
        # v1's encodes a private product name in its own bytes.
        legacy_namespace = uuid.UUID("6f726920-7665-5269-7479-2065766e7431")
        legacy = str(uuid.uuid5(legacy_namespace, f"{DEVICE}:action_log:42"))
        a = FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "e.db"),
            key_path=str(tmp_path / "k"),
            device_secret=SECRET,
            device_id=DEVICE,
        )
        assert a.attestation_event_id(42) != legacy
        assert EVENT_ID_NAMESPACE != legacy_namespace


class TestAppendAndSeal:
    async def test_attesting_seals_a_delivery_envelope(self, attestor) -> None:
        """A signed row that never becomes an envelope is undeliverable.

        Without the seal the runtime would report an action as attested while
        advancing no delivery high-water mark and giving the courier nothing to
        carry.
        """
        seq = await attestor.attest_action(_action_row())
        assert seq is not None

        ledger = attestor._ledger
        assert ledger is not None
        high_water = attestor._executor.run(ledger.high_water_seq)
        assert high_water >= 1, "the action was signed but never sealed"

    async def test_attestation_is_idempotent_across_retry(self, attestor) -> None:
        """A retry after a lost status update must not attest twice."""
        row = _action_row()
        first = await attestor.attest_action(row)
        second = await attestor.attest_action(row)
        assert first == second

        ledger = attestor._ledger
        assert ledger is not None
        assert attestor._executor.run(ledger.high_water_seq) == 1

    async def test_distinct_actions_get_distinct_envelopes(self, attestor) -> None:
        await attestor.attest_action(_action_row(1))
        await attestor.attest_action(_action_row(2))
        ledger = attestor._ledger
        assert ledger is not None
        assert attestor._executor.run(ledger.high_water_seq) == 2

    async def test_the_chain_verifies_after_attesting(self, attestor) -> None:
        await attestor.attest_action(_action_row(1))
        await attestor.attest_action(_action_row(2))
        chain = attestor._chain
        assert chain is not None
        assert attestor._executor.run(chain.verify_chain) == []

    async def test_signed_payload_carries_the_action_and_its_tier(
        self, attestor
    ) -> None:
        seq = await attestor.attest_action(_action_row())
        chain = attestor._chain
        assert chain is not None
        row = attestor._executor.run(
            chain.find_by_event_id, attestor.attestation_event_id(42)
        )
        assert row is not None and int(row["seq"]) == seq
        assert row["event_type"] == ACTION_EVENT_TYPE
        assert '"action_tier":"D"' in _text(row["canonical_json"])


class TestHonestClaims:
    async def test_freshness_is_not_claimed_as_verified(self, attestor) -> None:
        """Signing supplied coordinates is not verifying freshness.

        Reporting True here would let the runtime describe an unverified
        reading as freshness-bound evidence.
        """
        assert attestor.atomic_freshness_available is False

    async def test_freshness_coordinates_are_still_signed(self, attestor) -> None:
        """Not claiming verification is not the same as discarding the values."""
        await attestor.attest_action(
            _action_row(
                7,
                input_firmware_device_id="fw-01",
                input_firmware_boot_id=3,
                input_firmware_seq=99,
            )
        )
        chain = attestor._chain
        assert chain is not None
        row = attestor._executor.run(
            chain.find_by_event_id, attestor.attestation_event_id(7)
        )
        assert '"input_firmware_seq":99' in _text(row["canonical_json"])

    async def test_protocol_version_is_the_v2_schema(self, attestor) -> None:
        assert attestor.protocol_version == SCHEMA_VERSION

    async def test_unavailable_attestor_reports_nothing(self, tmp_path) -> None:
        """A failed open must not report a usable evidence path."""
        a = FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "e.db"),
            key_path=str(tmp_path / "k"),
            device_secret="",  # an empty secret seals nothing, so open fails
            device_id=DEVICE,
        )
        assert await a.start() is False
        assert a.available is False
        assert a.protocol_version == ""
        assert a.public_key_hex == ""
        assert await a.attest_action(_action_row()) is None
        a.close()


class TestRegistrationRemainsPending:
    def test_no_authorisation_produces_no_registration(self) -> None:
        outcome = PendingAuthorisationRegistrar().register(
            AnchorRegistrationRequest(
                device_id=DEVICE,
                public_key_hex="ab" * 32,
                anchor_epoch_id="epoch-1",
                posture="sealed_flash",
            )
        )
        assert outcome.status is RegistrationStatus.PENDING_AUTHORISATION
        assert outcome.registration is None
        assert not outcome.authoritative

    async def test_epoch_is_not_active_merely_because_it_was_requested(
        self, attestor
    ) -> None:
        """Authority arrives only as a signed confirmation through ingest."""
        backend = attestor.confirmation_backend()
        assert backend is not None
        backend.register_anchor(
            AnchorRegistrationRequest(
                device_id=DEVICE,
                public_key_hex=attestor.public_key_hex,
                anchor_epoch_id=attestor.anchor.anchor_epoch_id,
                posture=attestor.anchor.posture,
            )
        )
        assert backend.active_anchor_epoch_id(DEVICE) is None


class TestHealthReadingSurface:
    """The health payload reads these; a missing one crashes the whole report.

    `runtime.py` calls both without a guard, so an absent method raises
    `AttributeError` while building health — taking down the parts that were
    fine along with the part that was not. The full suite passed while both
    methods were missing, because nothing exercised the health path with an
    available attestor. That gap is why this class exists.
    """

    async def test_chain_head_hash_is_a_sha256_hex_digest(self, attestor) -> None:
        head = await attestor.chain_head_hash()
        assert head is not None
        assert len(head) == 64, "a chain head is a SHA-256 digest in hex"
        int(head, 16)  # raises if it is not hex

    async def test_chain_head_advances_when_an_action_is_attested(
        self, attestor
    ) -> None:
        before = await attestor.chain_head_hash()
        await attestor.attest_action(_action_row(1))
        after = await attestor.chain_head_hash()
        assert after != before, "the head did not move after a signed action"
        assert len(after) == 64

    async def test_pending_export_count_starts_at_zero(self, attestor) -> None:
        assert await attestor.pending_export_count() == 0

    async def test_pending_export_count_advances_by_one_per_signed_action(
        self, attestor
    ) -> None:
        """A rising count is the visible signal that delivery has stalled."""
        await attestor.attest_action(_action_row(1))
        assert await attestor.pending_export_count() == 1
        await attestor.attest_action(_action_row(2))
        assert await attestor.pending_export_count() == 2

    async def test_a_retry_does_not_inflate_the_pending_count(self, attestor) -> None:
        """Idempotent re-attestation must not look like new undelivered evidence."""
        await attestor.attest_action(_action_row(1))
        await attestor.attest_action(_action_row(1))
        assert await attestor.pending_export_count() == 1

    async def test_an_unavailable_attestor_reports_none_rather_than_raising(
        self, tmp_path
    ) -> None:
        """Health reports state; a health call that raises reports nothing at all."""
        a = FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "e.db"),
            key_path=str(tmp_path / "k"),
            device_secret="",
            device_id=DEVICE,
        )
        assert await a.start() is False
        assert await a.chain_head_hash() is None
        assert await a.pending_export_count() is None
        a.close()

    async def test_pending_count_measures_envelopes_not_chain_rows(
        self, attestor
    ) -> None:
        """The two diverge exactly between append and seal, so test there.

        Attesting an action does both, which makes chain rows, ledger rows and
        the health count all equal -- and a count implemented against the chain
        table would pass just as happily. The distinguishing state is a row that
        has been appended and not yet sealed.
        """
        chain = attestor._chain
        ledger = attestor._ledger
        assert chain is not None and ledger is not None

        def _append_only():
            return chain.append(
                event_id=attestor.attestation_event_id(41),
                event_type=ACTION_EVENT_TYPE,
                emitted_at_ms=1787000000000,
                payload={"kind": "runtime_action", "action_log_id": 41},
                created_at_ms=1787000000040,
            )

        row = attestor._executor.run(_append_only)

        chain_rows = attestor._executor.run(
            lambda: chain._connection.execute(
                "SELECT COUNT(*) AS n FROM evidence_chain"
            ).fetchone()["n"]
        )
        assert chain_rows == 1, "the row was not appended"
        assert attestor._executor.run(ledger.awaiting_custody_count) == 0, (
            "an unsealed row was counted as awaiting a courier"
        )
        assert await attestor.pending_export_count() == 0

        attestor._executor.run(lambda: ledger.seal(row, sealed_at_ms=1787000000500))

        assert attestor._executor.run(ledger.awaiting_custody_count) == 1
        assert await attestor.pending_export_count() == 1, (
            "sealing did not make the envelope visible as awaiting a courier"
        )

    async def test_custody_and_receipt_counts_move_independently(
        self, attestor
    ) -> None:
        """Only the transitions prove the two are distinct.

        Asserting the initial (none, none) state would pass against a receipt
        count hard-coded to zero. Custody and receipt are separate hops with
        separate remedies, so each must move on its own event.
        """
        await attestor.attest_action(_action_row(1))
        ledger = attestor._ledger
        assert ledger is not None
        run = attestor._executor.run

        assert run(ledger.awaiting_custody_count) == 1
        assert run(ledger.awaiting_receipt_count) == 0

        # A courier takes custody. The envelope leaves the custody queue and
        # enters the receipt queue -- it is held, but nothing has accepted it.
        run(
            lambda: ledger._apply_verified_custody(
                1, custody_at_ms=1787000000900, key_id="gw-secret-1"
            )
        )
        assert run(ledger.awaiting_custody_count) == 0
        assert run(ledger.awaiting_receipt_count) == 1, (
            "custody did not move the envelope into the receipt queue"
        )

        # The authority accepts it. Only now is the envelope out of both queues.
        run(
            lambda: ledger._apply_verified_receipt(
                1, receipt_at_ms=1787000001000, key_id="auth-receipt-1"
            )
        )
        assert run(ledger.awaiting_custody_count) == 0
        assert run(ledger.awaiting_receipt_count) == 0


class TestProvisioningAndIdentity:
    """Key provisioning and the identity it produces.

    A fixture that starts successfully proves the fixture works. It cannot fail
    with a diagnosis about provisioning, and asserts nothing about the anchor's
    shape or whether it survives a restart -- which is the whole point of a
    sealed key.
    """

    async def test_first_start_provisions_a_key_and_exposes_its_anchor(
        self, tmp_path
    ) -> None:
        key_path = tmp_path / "device.key"
        assert not key_path.exists()

        a = FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "e.db"),
            key_path=str(key_path),
            device_secret=SECRET,
            device_id=DEVICE,
        )
        try:
            assert await a.start() is True
            assert a.available is True
            assert key_path.exists(), "first start did not provision a key"
            anchor = a.public_key_hex
            assert len(anchor) == 64, "an Ed25519 anchor is 32 bytes in hex"
            int(anchor, 16)
            assert anchor == anchor.lower()
        finally:
            a.close()

    async def test_the_anchor_derives_from_this_device_and_this_key(
        self, tmp_path
    ) -> None:
        """Stability is not enough: a hard-coded identity is also stable.

        The anchor must follow the device it is bound to, or two devices would
        seal evidence under one identity and the authority could not tell them
        apart.
        """
        anchors = {}
        for device_id in (DEVICE, "energy-monitor-ikeja-02"):
            a = FirstPartyEvidenceAttestor(
                db_path=str(tmp_path / f"{device_id}.db"),
                key_path=str(tmp_path / f"{device_id}.key"),
                device_secret=SECRET,
                device_id=device_id,
            )
            assert await a.start() is True
            assert a.anchor is not None
            anchors[device_id] = (a.anchor.anchor_epoch_id, a.anchor.key_id)
            # The derivation must be the contract's, over this device's own key.
            assert (
                a.anchor.anchor_epoch_id
                == derive_runtime_anchor(
                    device_id=device_id, pubkey_hex=a.public_key_hex
                ).anchor_epoch_id
            )
            a.close()
        assert len(set(anchors.values())) == 2, (
            "two devices derived the same evidence identity"
        )

    async def test_identity_is_stable_across_a_restart(self, tmp_path) -> None:
        """A key that changed on restart would orphan every prior signature."""
        paths: dict[str, Any] = {
            "db_path": str(tmp_path / "e.db"),
            "key_path": str(tmp_path / "device.key"),
            "device_secret": SECRET,
            "device_id": DEVICE,
        }
        first = FirstPartyEvidenceAttestor(**paths)
        assert await first.start() is True
        anchor = first.public_key_hex
        epoch = first.anchor.anchor_epoch_id if first.anchor else None
        key_id = first.anchor.key_id if first.anchor else None
        first.close()

        second = FirstPartyEvidenceAttestor(**paths)
        try:
            assert await second.start() is True
            assert second.public_key_hex == anchor, "the device key changed"
            assert second.anchor is not None
            assert second.anchor.anchor_epoch_id == epoch, "the epoch moved"
            assert second.anchor.key_id == key_id, "the selector moved"
        finally:
            second.close()

    async def test_a_wrong_secret_leaves_the_attestor_unavailable(
        self, tmp_path
    ) -> None:
        """Fail closed: a key that cannot be unsealed must not degrade to unsigned.

        The key layer refuses the wrong secret. This asserts the consequence at
        the attestor -- that it reports unavailable and signs nothing, rather
        than starting with no key and quietly producing no evidence.
        """
        paths: dict[str, Any] = {
            "db_path": str(tmp_path / "e.db"),
            "key_path": str(tmp_path / "device.key"),
            "device_id": DEVICE,
        }
        first = FirstPartyEvidenceAttestor(device_secret=SECRET, **paths)
        assert await first.start() is True
        first.close()

        wrong = FirstPartyEvidenceAttestor(device_secret="a-different-secret", **paths)
        try:
            assert await wrong.start() is False
            assert wrong.available is False
            assert wrong.public_key_hex == ""
            assert await wrong.attest_action(_action_row()) is None
        finally:
            wrong.close()


class TestSignedPayloadFidelity:
    async def test_the_payload_preserves_the_action_identity_and_time(
        self, attestor
    ) -> None:
        """A verifier reads these. A rewritten timestamp is a different claim."""
        row = _action_row(42, timestamp=1787000000123)
        await attestor.attest_action(row)
        chain = attestor._chain
        assert chain is not None
        stored = attestor._executor.run(
            chain.find_by_event_id, attestor.attestation_event_id(42)
        )
        assert stored is not None
        assert int(stored["emitted_at_ms"]) == 1787000000123, (
            "the signed row does not carry the action's own timestamp"
        )
        assert stored["device_id"] == DEVICE
        body = _text(stored["canonical_json"])
        assert '"action_log_id":42' in body
        assert '"action_name":"emergency_cutoff"' in body

    async def test_emission_evidence_is_marked_at_emission(self, attestor) -> None:
        await attestor.attest_action(_action_row(1))
        assert '"attestation":"at_emission"' in _text(
            self._stored(attestor, 1)["canonical_json"]
        )

    async def test_reconciled_evidence_is_explicitly_marked_late(
        self, attestor
    ) -> None:
        """Late evidence must never be presentable as emission-time evidence.

        The distinction is the whole value of reconciliation: a reader has to be
        able to tell that this signature was produced after the fact, because
        the gap between the action and the signature is itself a fact about the
        device.
        """
        await attestor.attest_action(_action_row(2), reconciled=True)
        body = _text(self._stored(attestor, 2)["canonical_json"])
        assert '"attestation":"reconciled_late"' in body
        assert '"attestation":"at_emission"' not in body

    @staticmethod
    def _stored(attestor, action_log_id: int):
        chain = attestor._chain
        assert chain is not None
        row = attestor._executor.run(
            chain.find_by_event_id, attestor.attestation_event_id(action_log_id)
        )
        assert row is not None
        return row


class TestFailureContainment:
    async def test_an_append_failure_returns_none_rather_than_raising(
        self, tmp_path
    ) -> None:
        """The caller marks the row failed and continues; it must not crash.

        The action has already happened by the time signing runs, so a raised
        exception here would turn a recording problem into an action-path
        problem.
        """
        a = FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "e.db"),
            key_path=str(tmp_path / "device.key"),
            device_secret=SECRET,
            device_id=DEVICE,
        )
        assert await a.start() is True
        # Close the underlying handles while leaving the attestor believing it
        # is available, which is what a mid-flight failure looks like.
        chain = a._chain
        assert chain is not None
        a._executor.run(chain.close)

        assert await a.attest_action(_action_row(1)) is None
        a.close()

    async def test_the_chain_is_durable_across_close_and_reopen(self, tmp_path) -> None:
        """Evidence that does not survive a restart evidences nothing."""
        paths: dict[str, Any] = {
            "db_path": str(tmp_path / "e.db"),
            "key_path": str(tmp_path / "device.key"),
            "device_secret": SECRET,
            "device_id": DEVICE,
        }
        first = FirstPartyEvidenceAttestor(**paths)
        assert await first.start() is True
        seq = await first.attest_action(_action_row(7))
        head = await first.chain_head_hash()
        first.close()

        second = FirstPartyEvidenceAttestor(**paths)
        try:
            assert await second.start() is True
            assert await second.chain_head_hash() == head, "the head did not persist"
            chain = second._chain
            assert chain is not None
            row = second._executor.run(
                chain.find_by_event_id, second.attestation_event_id(7)
            )
            assert row is not None and int(row["seq"]) == seq
            assert second._executor.run(chain.verify_chain) == [], (
                "the reopened chain does not verify"
            )
            # And a retry after the restart still must not double-attest.
            assert await second.attest_action(_action_row(7)) == seq
        finally:
            second.close()


class TestOutboundRetention:
    async def test_sealing_and_checkpointing_notify_the_listener(self, attestor):
        calls: list[str] = []
        attestor.set_sealed_listener(lambda: calls.append("sealed"))
        assert await attestor.attest_action(_action_row(1)) is not None
        assert calls == ["sealed"]
        assert await attestor.issue_checkpoint() is not None
        assert calls == ["sealed", "sealed"]
        attestor.set_sealed_listener(None)
        await attestor.attest_action(_action_row(2))
        assert calls == ["sealed", "sealed"]

    async def test_a_checkpoint_is_retained_for_the_courier(self, attestor):
        await attestor.attest_action(_action_row(1))
        queued = await attestor.issue_checkpoint()
        assert queued is not None and queued["artifact_type"] == "checkpoint"
        outbound = attestor.outbound
        assert outbound is not None
        pending = await outbound.pending_artifacts()
        assert [p["artifact_digest"] for p in pending] == [queued["artifact_digest"]]
        assert [e["chain_seq"] for e in await outbound.awaiting_custody()] == [1]

    async def test_a_failing_listener_does_not_undo_the_seal(self, attestor):
        def boom() -> None:
            raise RuntimeError("listener broke")

        attestor.set_sealed_listener(boom)
        assert await attestor.attest_action(_action_row(1)) == 1
        outbound = attestor.outbound
        assert outbound is not None
        assert len(await outbound.awaiting_custody()) == 1

    def test_outbound_is_absent_until_started(self, tmp_path):
        a = FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "e.db"),
            key_path=str(tmp_path / "k"),
            device_secret=SECRET,
            device_id=DEVICE,
        )
        assert a.outbound is None
