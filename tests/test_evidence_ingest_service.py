# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The production path from an arriving artifact to a change in evidence state.

Verification alone proves an artifact is genuine. These prove the genuine ones
reach state and the rest do not — which is a different claim, and the one that
matters once anything acts on the result.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.custody_keys import (
    CustodyKeyRegistry,
    derive_custody_key_id,
)
from ori.security.evidence_authority_keys import (
    PURPOSE_EPOCH,
    PURPOSE_RECEIPT,
    REGISTRY_SCHEMA,
    load_authority_key_registry,
)
from ori.security.evidence_canonical import canonical_json
from ori.security.evidence_chain import EvidenceChain, attestation_event_id
from ori.security.evidence_device_key import EvidenceDeviceKey
from ori.security.evidence_ingest import (
    REJECT_BAD_AUTHENTICATOR,
    REJECT_BINDING_MISMATCH,
    REJECT_UNKNOWN_KEY,
    REJECT_UNKNOWN_SEQUENCE,
    REJECT_WRONG_PURPOSE,
)
from ori.security.evidence_ingest_service import (
    ConfirmedEpochReader,
    EvidenceIngestService,
)
from ori.security.evidence_ledger import (
    CUSTODY_HELD,
    RECEIPT_ACCEPTED,
    RECEIPT_NONE,
    EvidenceDeliveryLedger,
)

DEVICE = "energy-monitor-ikeja-01"
EPOCH = "epoch-0002"
KEY_ID = "anchor-key-2"
CUSTODY_SECRET = "site-custody-secret"
PREVIOUS_CUSTODY_SECRET = "site-custody-secret-previous"

RECEIPT_SEED = bytes([0x7A] * 32)
EPOCH_SEED = bytes([0x6B] * 32)
IMPOSTOR_SEED = bytes([0x5C] * 32)

RECEIPT_DOMAIN = b"ori.evidence_delivery_receipt.v1\x00"
EPOCH_DOMAIN = b"ori.evidence_epoch_confirmation.v1\x00"
CUSTODY_DOMAIN = b"ori.evidence_custody_ack.v1\x00"


def _pub(seed: bytes) -> str:
    return (
        Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw().hex()
    )


def _sign(artifact: dict, domain: bytes, seed: bytes) -> dict:
    body = {k: v for k, v in artifact.items() if k != "signature"}
    key = Ed25519PrivateKey.from_private_bytes(seed)
    artifact["signature"] = (
        "ed25519:" + base64.b64encode(key.sign(domain + canonical_json(body))).decode()
    )
    return artifact


def _mac(artifact: dict, secret: str) -> dict:
    import hmac

    body = {k: v for k, v in artifact.items() if k != "mac"}
    artifact["mac"] = (
        "hmac-sha256:"
        + hmac.new(
            secret.encode(), CUSTODY_DOMAIN + canonical_json(body), hashlib.sha256
        ).hexdigest()
    )
    return artifact


@pytest.fixture
def rig(tmp_path):
    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "install-secret")
    chain = EvidenceChain(tmp_path / "chain.db", key, DEVICE)
    ledger = EvidenceDeliveryLedger(
        tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id=EPOCH, key_id=KEY_ID
    )
    registry_path = tmp_path / "authority.json"
    registry_path.write_text(
        json.dumps(
            {
                "schema": REGISTRY_SCHEMA,
                "keys": [
                    {
                        "key_id": "auth-receipt-1",
                        "public_key_hex": _pub(RECEIPT_SEED),
                        "purpose": PURPOSE_RECEIPT,
                        "status": "active",
                    },
                    {
                        "key_id": "auth-epoch-1",
                        "public_key_hex": _pub(EPOCH_SEED),
                        "purpose": PURPOSE_EPOCH,
                        "status": "active",
                    },
                ],
            }
        )
    )
    service = EvidenceIngestService(
        ledger=ledger,
        registry=load_authority_key_registry(registry_path),
        device_id=DEVICE,
        device_pubkey_hex=key.public_key_hex,
        custody_keys=CustodyKeyRegistry(
            active_secret=CUSTODY_SECRET,
            previous_secret=PREVIOUS_CUSTODY_SECRET,
        ),
    )
    yield key, chain, ledger, service
    chain.close()
    ledger.close()


def _seal(chain, ledger, n: int):
    row = chain.append(
        event_id=attestation_event_id(DEVICE, n),
        event_type="SAFETY_ACTION_EXECUTED",
        emitted_at_ms=1751500800000 + n * 1000,
        payload={
            "kind": "runtime_action",
            "attestation": "at_emission",
            "action_log_id": n,
        },
        created_at_ms=1751500800040 + n * 1000,
    )
    return ledger.seal(row, sealed_at_ms=1000 + n)


def _receipt(
    ledger, from_seq: int, to_seq: int, seed=RECEIPT_SEED, key_id="auth-receipt-1"
):
    digests = ledger.envelope_digests(from_seq, to_seq)
    raw = b"".join(
        bytes.fromhex(digests[s].split("sha256:")[1])
        for s in range(from_seq, to_seq + 1)
    )
    return _sign(
        {
            "v": 1,
            "device_id": DEVICE,
            "from_seq": from_seq,
            "to_seq": to_seq,
            "range_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "accepted_at_ms": 1787000001000,
            "key_id": key_id,
        },
        RECEIPT_DOMAIN,
        seed,
    )


def _confirmation(
    pubkey_hex: str, seed=EPOCH_SEED, key_id="auth-epoch-1", device=DEVICE
):
    return _sign(
        {
            "v": 1,
            "device_id": device,
            "anchor_epoch_id": EPOCH,
            "pubkey_hex": pubkey_hex,
            "actor": "commissioning-operator",
            "confirmed_at_ms": 1787000002000,
            "key_id": key_id,
        },
        EPOCH_DOMAIN,
        seed,
    )


def _custody(ledger, local_seq: int, secret=CUSTODY_SECRET, key_id=None):
    """Build an acknowledgement, naming the generation it was actually signed with.

    `key_id` defaults to the identifier derived from *secret*, so a caller that
    changes the secret gets a coherent artifact rather than the mismatch case.
    Pass `key_id` explicitly only to build that mismatch deliberately.
    """
    sealed = ledger.find_by_local_seq(local_seq)
    return _mac(
        {
            "v": 1,
            "device_id": DEVICE,
            "local_seq": local_seq,
            "envelope_digest": str(sealed["envelope_digest"]),
            "custody_at_ms": 1787000000900,
            "key_id": key_id or derive_custody_key_id(secret),
        },
        secret,
    )


# --------------------------------------------------------------------------
# Only verified artifacts reach state
# --------------------------------------------------------------------------


def test_a_verified_receipt_marks_its_range_delivered(rig):
    _, chain, ledger, service = rig
    for n in (1, 2, 3):
        _seal(chain, ledger, n)

    outcome = service.accept_receipt(_receipt(ledger, 1, 2))
    assert outcome.accepted
    assert outcome.applied_sequences == (1, 2)
    assert [r["local_seq"] for r in ledger.undelivered()] == [3]


# Each case is re-signed after being corrupted, except the one whose defect
# *is* the signature. Mutating a signed artifact without re-signing makes every
# case fail as `bad_authenticator`, and the semantic rule it was written for is
# never reached — the same trap that flattened the contract's own rejection
# vectors.
@pytest.mark.parametrize(
    "corrupt,expected,resign",
    [
        (
            lambda a: a.__setitem__(
                "signature", "ed25519:" + base64.b64encode(b"\x00" * 64).decode()
            ),
            REJECT_BAD_AUTHENTICATOR,
            False,
        ),
        (
            lambda a: a.__setitem__("device_id", "some-other-device"),
            REJECT_BINDING_MISMATCH,
            True,
        ),
        (
            lambda a: a.__setitem__("range_digest", "sha256:" + "0" * 64),
            REJECT_BINDING_MISMATCH,
            True,
        ),
        (lambda a: a.__setitem__("to_seq", 99), REJECT_UNKNOWN_SEQUENCE, True),
        (lambda a: a.__setitem__("key_id", "auth-epoch-1"), REJECT_WRONG_PURPOSE, True),
    ],
)
def test_an_unverified_receipt_changes_nothing(rig, corrupt, expected, resign):
    """Every binding must survive into application, not merely verification."""
    _, chain, ledger, service = rig
    for n in (1, 2):
        _seal(chain, ledger, n)
    artifact = _receipt(ledger, 1, 2)
    corrupt(artifact)
    if resign:
        _sign(artifact, RECEIPT_DOMAIN, RECEIPT_SEED)

    outcome = service.accept_receipt(artifact)
    assert not outcome.accepted
    assert outcome.reason == expected
    assert [r["local_seq"] for r in ledger.undelivered()] == [1, 2], "state changed"
    assert service.rejections[-1].reason == expected


@pytest.mark.parametrize(
    ("name", "build", "expected"),
    [
        (
            "invented_secret",
            lambda ledger: _custody(ledger, 1, secret="not-the-custody-secret"),
            REJECT_UNKNOWN_KEY,
        ),
        (
            "replayed_key_id",
            lambda ledger: _custody(
                ledger,
                1,
                secret="not-the-custody-secret",
                key_id=derive_custody_key_id(CUSTODY_SECRET),
            ),
            REJECT_BAD_AUTHENTICATOR,
        ),
    ],
)
def test_a_forged_custody_changes_nothing(rig, name, build, expected):
    """Both forgery shapes are refused, and they are refused differently.

    A forger without any held secret can invent one, and its derived key_id
    then names nothing the registry holds. Or it can copy a key_id off the
    wire -- they travel in clear -- and forge a MAC under a secret it does not
    have. The second is the more realistic attack, and asserting only the
    first would leave it uncovered.

    The reasons differ because the operator remedies differ: an unknown key
    says a party is presenting a secret this runtime never shared, while a bad
    authenticator says something is claiming a generation it cannot
    authenticate under.
    """
    _, chain, ledger, service = rig
    _seal(chain, ledger, 1)
    artifact = build(ledger)

    outcome = service.accept_custody(artifact)
    assert not outcome.accepted
    assert outcome.reason == expected
    assert ledger.find_by_local_seq(1)["custody_state"] == "none"


def test_custody_for_an_envelope_never_sealed_changes_nothing(rig):
    _, chain, ledger, service = rig
    _seal(chain, ledger, 1)
    artifact = _custody(ledger, 1)
    artifact["local_seq"] = 99
    _mac(artifact, CUSTODY_SECRET)  # re-authenticated, so the sequence rule is reached

    outcome = service.accept_custody(artifact)
    assert not outcome.accepted
    assert outcome.reason == REJECT_UNKNOWN_SEQUENCE


# --------------------------------------------------------------------------
# Custody and receipt stay distinct through application
# --------------------------------------------------------------------------


def test_custody_does_not_deliver_and_receipt_does(rig):
    _, chain, ledger, service = rig
    _seal(chain, ledger, 1)

    assert service.accept_custody(_custody(ledger, 1)).accepted
    held = ledger.find_by_local_seq(1)
    assert held["custody_state"] == CUSTODY_HELD
    assert held["receipt_state"] == RECEIPT_NONE
    assert [r["local_seq"] for r in ledger.undelivered()] == [1]

    assert service.accept_receipt(_receipt(ledger, 1, 1)).accepted
    delivered = ledger.find_by_local_seq(1)
    assert delivered["custody_state"] == CUSTODY_HELD
    assert delivered["receipt_state"] == RECEIPT_ACCEPTED
    assert ledger.undelivered() == []


# --------------------------------------------------------------------------
# Replay
# --------------------------------------------------------------------------


def test_replaying_the_same_receipt_is_idempotent(rig):
    """A courier that redelivers must not produce different state."""
    _, chain, ledger, service = rig
    _seal(chain, ledger, 1)
    artifact = _receipt(ledger, 1, 1)

    first = service.accept_receipt(artifact)
    before = dict(ledger.find_by_local_seq(1))
    second = service.accept_receipt(json.loads(json.dumps(artifact)))
    after = dict(ledger.find_by_local_seq(1))

    assert first.accepted and second.accepted
    assert before == after


def test_a_conflicting_receipt_over_the_same_range_is_rejected(rig):
    """Two authorities cannot both be right about one range.

    The final-state triggers refuse a rewrite, so a second receipt claiming a
    different acceptance time or key for an already-delivered range cannot
    quietly replace what the first one established.
    """
    import sqlite3

    _, chain, ledger, service = rig
    _seal(chain, ledger, 1)
    assert service.accept_receipt(_receipt(ledger, 1, 1)).accepted

    conflicting = _receipt(ledger, 1, 1)
    conflicting["accepted_at_ms"] = 1787000009999
    _sign(conflicting, RECEIPT_DOMAIN, RECEIPT_SEED)

    with pytest.raises(sqlite3.IntegrityError, match="receipt"):
        service.accept_receipt(conflicting)
    assert ledger.find_by_local_seq(1)["receipt_at_ms"] == 1787000001000


def test_replaying_custody_is_idempotent(rig):
    _, chain, ledger, service = rig
    _seal(chain, ledger, 1)
    artifact = _custody(ledger, 1)
    assert service.accept_custody(artifact).accepted
    before = dict(ledger.find_by_local_seq(1))
    assert service.accept_custody(json.loads(json.dumps(artifact))).accepted
    assert dict(ledger.find_by_local_seq(1)) == before


# --------------------------------------------------------------------------
# Epoch state, and what the coordinator reads
# --------------------------------------------------------------------------


def test_a_verified_confirmation_is_what_the_coordinator_reads(rig):
    """The whole point of the wiring: proven state reaches the consumer.

    The coordinator asks `active_anchor_epoch_id`, which under the off-device
    topology is answered from confirmations this device has verified rather
    than from an artifact in this process.
    """
    key, _, ledger, service = rig
    reader = ConfirmedEpochReader(ledger)
    assert reader.active_anchor_epoch_id(DEVICE) is None, "authority by default"

    assert service.accept_epoch_confirmation(_confirmation(key.public_key_hex)).accepted
    assert reader.active_anchor_epoch_id(DEVICE) == EPOCH


@pytest.mark.parametrize(
    "corrupt,expected",
    [
        (
            lambda a, k: a.__setitem__("device_id", "some-other-device"),
            REJECT_BINDING_MISMATCH,
        ),
        (lambda a, k: a.__setitem__("pubkey_hex", "11" * 32), REJECT_BINDING_MISMATCH),
        (lambda a, k: a.__setitem__("key_id", "auth-receipt-1"), REJECT_WRONG_PURPOSE),
    ],
)
def test_an_unverified_confirmation_leaves_the_epoch_unset(rig, corrupt, expected):
    """A statement about another device's anchor must not advance this one's."""
    key, _, ledger, service = rig
    artifact = _confirmation(key.public_key_hex)
    corrupt(artifact, key)
    # Re-signed so the artifact is cryptographically sound and the binding rule
    # is what refuses it.
    _sign(artifact, EPOCH_DOMAIN, EPOCH_SEED)

    outcome = service.accept_epoch_confirmation(artifact)
    assert not outcome.accepted
    assert outcome.reason == expected
    assert ConfirmedEpochReader(ledger).active_anchor_epoch_id(DEVICE) is None


def test_a_confirmation_signed_by_an_impostor_leaves_the_epoch_unset(rig):
    key, _, ledger, service = rig
    artifact = _confirmation(key.public_key_hex, seed=IMPOSTOR_SEED)
    outcome = service.accept_epoch_confirmation(artifact)
    assert outcome.reason == REJECT_BAD_AUTHENTICATOR
    assert ConfirmedEpochReader(ledger).active_anchor_epoch_id(DEVICE) is None


def test_a_later_confirmation_supersedes_an_earlier_one(rig):
    """The authority is the sole source of epoch truth; a device does not adjudicate."""
    key, _, ledger, service = rig
    assert service.accept_epoch_confirmation(_confirmation(key.public_key_hex)).accepted

    later = _confirmation(key.public_key_hex)
    later["anchor_epoch_id"] = "epoch-0003"
    later["confirmed_at_ms"] = 1787000009000
    _sign(later, EPOCH_DOMAIN, EPOCH_SEED)
    assert service.accept_epoch_confirmation(later).accepted

    assert ConfirmedEpochReader(ledger).active_anchor_epoch_id(DEVICE) == "epoch-0003"


# --------------------------------------------------------------------------
# A crash between verification and application
# --------------------------------------------------------------------------


def test_an_artifact_lost_between_verification_and_application_is_safely_replayable(
    rig,
):
    """Verification is pure, so a crash before application leaves no trace.

    The defined outcome is that nothing was applied and the artifact can be
    presented again — which is safe because application is idempotent. That is
    why the two are separable at all: a partially applied verification would
    have no such recovery.
    """
    key, chain, ledger, service = rig
    _seal(chain, ledger, 1)
    artifact = _receipt(ledger, 1, 1)

    # Verification alone, as though the process died before applying.
    from ori.security.evidence_ingest import verify_delivery_receipt

    verify_delivery_receipt(
        artifact,
        device_id=DEVICE,
        registry=service._registry,
        envelope_digests=ledger.envelope_digests(1, 1),
    )
    assert ledger.find_by_local_seq(1)["receipt_state"] == RECEIPT_NONE, (
        "verification must not mutate state on its own"
    )

    # The courier re-presents it after the restart.
    assert service.accept_receipt(artifact).accepted
    assert ledger.find_by_local_seq(1)["receipt_state"] == RECEIPT_ACCEPTED


def test_epoch_state_survives_a_restart(rig, tmp_path):
    key, _, ledger, service = rig
    assert service.accept_epoch_confirmation(_confirmation(key.public_key_hex)).accepted
    ledger.close()

    reopened = EvidenceDeliveryLedger(
        tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id=EPOCH, key_id=KEY_ID
    )
    try:
        assert ConfirmedEpochReader(reopened).active_anchor_epoch_id(DEVICE) == EPOCH
    finally:
        reopened.close()


def test_rejections_are_retained_for_diagnosis(rig):
    """A device that drops them cannot explain why its evidence never arrived."""
    _, chain, ledger, service = rig
    _seal(chain, ledger, 1)

    bad = _receipt(ledger, 1, 1)
    bad["device_id"] = "elsewhere"
    service.accept_receipt(bad)
    service.accept_custody(_custody(ledger, 1, secret="wrong"))

    assert [r.artifact for r in service.rejections] == [
        "delivery_receipt",
        "custody_acknowledgement",
    ]
    assert all(r.reason for r in service.rejections)
