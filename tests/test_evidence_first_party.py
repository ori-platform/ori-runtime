# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Behaviour of the first-party attestor that replaces the private loader."""

from __future__ import annotations

import uuid

import pytest

from ori.security.evidence_chain import (
    EVENT_ID_NAMESPACE,
    SCHEMA_VERSION,
    attestation_event_id,
)
from ori.security.evidence_first_party import (
    ACTION_EVENT_TYPE,
    FirstPartyEvidenceAttestor,
    PendingAuthorisationRegistrar,
)
from ori.security.evidence_registrar import (
    AnchorRegistrationRequest,
    RegistrationStatus,
)


def _text(value) -> str:
    """canonical_json is the signed byte string; read it as text either way."""
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


DEVICE = "energy-monitor-ikeja-01"
SECRET = "install-secret-for-tests"


def _action_row(action_log_id: int = 42, **overrides) -> dict:
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
        anchor_epoch_id="epoch-1",
        key_id="dev-key-1",
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
            anchor_epoch_id="epoch-1",
            key_id="dev-key-1",
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
                anchor_epoch_id="epoch-1",
                key_id="dev-key-1",
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
            anchor_epoch_id="epoch-1",
            key_id="dev-key-1",
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
            anchor_epoch_id="epoch-1",
            key_id="dev-key-1",
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
                anchor_epoch_id="epoch-1",
                posture="sealed_flash",
            )
        )
        assert backend.active_anchor_epoch_id(DEVICE) is None
