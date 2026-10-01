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
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.evidence.authority_keys import (
    PURPOSE_EPOCH,
    PURPOSE_RECEIPT,
    REGISTRY_SCHEMA,
    derive_key_id,
    load_authority_key_registry,
)
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.chain import EvidenceChain, attestation_event_id
from ori.security.evidence.custody_keys import (
    CustodyKeyRegistry,
    derive_custody_key_id,
)
from ori.security.evidence.device_key import EvidenceDeviceKey
from ori.security.evidence.ingest import (
    REJECT_BAD_AUTHENTICATOR,
    REJECT_BINDING_MISMATCH,
    REJECT_MALFORMED,
    REJECT_UNKNOWN_KEY,
    REJECT_UNKNOWN_SEQUENCE,
    REJECT_WRONG_PURPOSE,
)
from ori.security.evidence.ingest_service import (
    ConfirmedEpochReader,
    EvidenceIngestService,
)
from ori.security.evidence.ledger import (
    CUSTODY_HELD,
    RECEIPT_ACCEPTED,
    RECEIPT_NONE,
    EvidenceDeliveryLedger,
)

DEVICE = "energy-monitor-ikeja-01"
EPOCH = "sha256:" + "2" * 64
EARLIER_EPOCH = "sha256:" + "3" * 64
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


RECEIPT_KEY_ID = derive_key_id(bytes.fromhex(_pub(RECEIPT_SEED)))
EPOCH_KEY_ID = derive_key_id(bytes.fromhex(_pub(EPOCH_SEED)))


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
                        "key_id": RECEIPT_KEY_ID,
                        "public_key_hex": _pub(RECEIPT_SEED),
                        "purpose": PURPOSE_RECEIPT,
                        "status": "active",
                    },
                    {
                        "key_id": EPOCH_KEY_ID,
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


def _wire_digests(ledger, from_seq: int, to_seq: int, field: str) -> list[str]:
    """A field of each sealed envelope as the authority receives it, in order.

    Read from the envelope's wire bytes and never from the ledger's own range
    query, so a ledger that answered the wrong column could not agree with
    itself here.
    """
    out = []
    for seq in range(from_seq, to_seq + 1):
        sealed = ledger.find_by_local_seq(seq)
        wire = str(sealed["envelope_json"]).encode()
        if field == "envelope_digest":
            out.append("sha256:" + hashlib.sha256(wire).hexdigest())
        else:
            out.append(json.loads(wire)[field])
    return out


def _range_digest(digests: list[str]) -> str:
    raw = b"".join(bytes.fromhex(d.removeprefix("sha256:")) for d in digests)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _receipt(
    ledger,
    from_seq: int,
    to_seq: int,
    seed=RECEIPT_SEED,
    key_id=RECEIPT_KEY_ID,
    *,
    over: str = "chain_row_digest",
):
    """A receipt per evidence-exchange: the range over raw chain row digests."""
    return _sign(
        {
            "v": 1,
            "device_id": DEVICE,
            "from_seq": from_seq,
            "to_seq": to_seq,
            "range_digest": _range_digest(
                _wire_digests(ledger, from_seq, to_seq, over)
            ),
            "accepted_at_ms": 1787000001000,
            "key_id": key_id,
        },
        RECEIPT_DOMAIN,
        seed,
    )


def _confirmation(pubkey_hex: str, seed=EPOCH_SEED, key_id=EPOCH_KEY_ID, device=DEVICE):
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


def _register(ledger, key, epoch: str = EPOCH) -> None:
    """Seal a registration for *epoch*, which is what a confirmation answers."""
    ledger.seal_registration(
        {
            "v": 1,
            "device_id": DEVICE,
            "pubkey_hex": key.public_key_hex,
            "anchor_epoch_id": epoch,
            "commissioning_digest": "sha256:" + "a" * 64,
        },
        sealed_at_ms=1787000001000,
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


def test_the_ledger_supplies_each_chain_row_digest_it_sealed(rig):
    """The range is over chain row digests, which are not envelope digests."""
    _, chain, ledger, _ = rig
    for n in (1, 2, 3):
        _seal(chain, ledger, n)

    held = ledger.chain_row_digests(1, 3)
    assert [held[s] for s in (1, 2, 3)] == _wire_digests(
        ledger, 1, 3, "chain_row_digest"
    )
    assert set(held.values()).isdisjoint(_wire_digests(ledger, 1, 3, "envelope_digest"))
    assert ledger.chain_row_digests(2, 9).keys() == {2, 3}


def test_a_receipt_over_envelope_digests_is_refused(rig):
    """Envelope digests cover the wire bytes; the contract's range does not."""
    _, chain, ledger, service = rig
    for n in (1, 2):
        _seal(chain, ledger, n)

    outcome = service.accept_receipt(_receipt(ledger, 1, 2, over="envelope_digest"))
    assert not outcome.accepted
    assert outcome.reason == REJECT_BINDING_MISMATCH
    assert [r["local_seq"] for r in ledger.undelivered()] == [1, 2], "state changed"


def test_a_single_envelope_receipt_is_accepted(rig):
    """The shape the authority issues: one receipt per accepted envelope."""
    _, chain, ledger, service = rig
    _seal(chain, ledger, 1)

    outcome = service.accept_receipt(_receipt(ledger, 1, 1))
    assert outcome.accepted
    assert outcome.applied_sequences == (1,)
    assert ledger.find_by_local_seq(1)["receipt_state"] == RECEIPT_ACCEPTED


def test_a_range_digest_in_descending_order_is_refused(rig):
    """Ascending `local_seq` order is part of what the digest commits to."""
    _, chain, ledger, service = rig
    for n in (1, 2, 3):
        _seal(chain, ledger, n)
    artifact = _receipt(ledger, 1, 3)
    artifact["range_digest"] = _range_digest(
        list(reversed(_wire_digests(ledger, 1, 3, "chain_row_digest")))
    )
    _sign(artifact, RECEIPT_DOMAIN, RECEIPT_SEED)

    outcome = service.accept_receipt(artifact)
    assert not outcome.accepted
    assert outcome.reason == REJECT_BINDING_MISMATCH
    assert [r["local_seq"] for r in ledger.undelivered()] == [1, 2, 3]

    assert service.accept_receipt(_receipt(ledger, 1, 3)).applied_sequences == (
        1,
        2,
        3,
    )


def test_an_unreadable_sealed_chain_row_digest_refuses_rather_than_raises(rig):
    """A damaged stored digest cannot be checked, so nothing is applied."""
    _, chain, ledger, service = rig
    for n in (1, 2):
        _seal(chain, ledger, n)
    artifact = _receipt(ledger, 1, 2)
    ledger._connection.execute("DROP TRIGGER evidence_ledger_no_sealed_update")
    ledger._connection.execute(
        "UPDATE evidence_delivery_ledger SET chain_row_digest = 'sha256:zz'"
        " WHERE local_seq = 2"
    )

    outcome = service.accept_receipt(artifact)
    assert outcome.reason == REJECT_BINDING_MISMATCH
    assert [r["local_seq"] for r in ledger.undelivered()] == [1, 2]


def test_a_receipt_reaching_past_the_sealed_head_is_unknown_sequence(rig):
    _, chain, ledger, service = rig
    for n in (1, 2):
        _seal(chain, ledger, n)
    artifact = _receipt(ledger, 1, 2)
    artifact["to_seq"] = 3
    _sign(artifact, RECEIPT_DOMAIN, RECEIPT_SEED)

    outcome = service.accept_receipt(artifact)
    assert outcome.reason == REJECT_UNKNOWN_SEQUENCE
    assert [r["local_seq"] for r in ledger.undelivered()] == [1, 2]


def test_a_receipt_at_the_largest_json_integer_is_refused_promptly(rig):
    """The signed interval's width is counted, never enumerated."""
    import time

    _, chain, ledger, service = rig
    for n in (1, 2):
        _seal(chain, ledger, n)
    for from_seq in (1, 3):
        artifact = _receipt(ledger, 1, 2)
        artifact["from_seq"], artifact["to_seq"] = from_seq, 9007199254740991
        _sign(artifact, RECEIPT_DOMAIN, RECEIPT_SEED)

        started = time.monotonic()
        outcome = service.accept_receipt(artifact)
        assert time.monotonic() - started < 0.5
        assert outcome.reason == REJECT_UNKNOWN_SEQUENCE
        assert [r["local_seq"] for r in ledger.undelivered()] == [1, 2]


NOT_INTEGERS = (True, False, 1.0, "1")


@pytest.mark.parametrize("bad", NOT_INTEGERS, ids=repr)
@pytest.mark.parametrize("field", ["v", "from_seq", "to_seq", "accepted_at_ms"])
def test_a_receipt_integer_of_another_json_type_is_malformed(rig, field, bad):
    """Re-signed, so the refusal can only come from the type."""
    _, chain, ledger, service = rig
    _seal(chain, ledger, 1)
    artifact = _receipt(ledger, 1, 1)
    artifact[field] = bad
    _sign(artifact, RECEIPT_DOMAIN, RECEIPT_SEED)

    outcome = service.accept_receipt(artifact)
    assert outcome.reason == REJECT_MALFORMED
    assert ledger.find_by_local_seq(1)["receipt_state"] == RECEIPT_NONE


@pytest.mark.parametrize("bad", NOT_INTEGERS, ids=repr)
@pytest.mark.parametrize("field", ["v", "local_seq", "custody_at_ms"])
def test_a_custody_integer_of_another_json_type_is_malformed(rig, field, bad):
    _, chain, ledger, service = rig
    _seal(chain, ledger, 1)
    artifact = _custody(ledger, 1)
    artifact[field] = bad
    _mac(artifact, CUSTODY_SECRET)

    outcome = service.accept_custody(artifact)
    assert outcome.reason == REJECT_MALFORMED
    assert ledger.find_by_local_seq(1)["custody_state"] != CUSTODY_HELD


@pytest.mark.parametrize("bad", NOT_INTEGERS, ids=repr)
@pytest.mark.parametrize("field", ["v", "confirmed_at_ms"])
def test_an_epoch_integer_of_another_json_type_is_malformed(rig, field, bad):
    key, _, ledger, service = rig
    _register(ledger, key)
    artifact = _confirmation(key.public_key_hex)
    artifact[field] = bad
    _sign(artifact, EPOCH_DOMAIN, EPOCH_SEED)

    outcome = service.accept_epoch_confirmation(artifact)
    assert outcome.reason == REJECT_MALFORMED
    assert ledger.confirmed_epoch(DEVICE) is None


def test_the_valid_artifacts_still_pass_the_integer_check(rig):
    """The negative cases above differ from accepted ones only in the field."""
    key, chain, ledger, service = rig
    _seal(chain, ledger, 1)
    _register(ledger, key)
    assert service.accept_custody(_custody(ledger, 1)).accepted
    assert service.accept_receipt(_receipt(ledger, 1, 1)).accepted
    assert service.accept_epoch_confirmation(_confirmation(key.public_key_hex)).accepted


# --------------------------------------------------------------------------
# The contract's receipt corpus, through a real ledger
# --------------------------------------------------------------------------

EXCHANGE_VECTORS = (
    pathlib.Path(__file__).parent.parent / "vectors" / "evidence_exchange"
)


def _exchange(name: str) -> dict:
    return json.loads((EXCHANGE_VECTORS / name).read_text())


@pytest.fixture
def vector_rig(tmp_path):
    """A ledger holding the envelope corpus's chain row at its published `local_seq`.

    The corpus publishes the device seed and the chain row, so the envelope the
    authority receipted is reached by sealing, not by feeding the verifier a
    digest table: the range digest is then checked against whatever the ledger
    actually stored.
    """
    envelopes = _exchange("delivery-envelope.json")
    receipts = _exchange("delivery-receipt-v2.json")
    published = next(c for c in envelopes["cases"] if c["name"] == "valid")["artifact"]
    assert published["device_id"] == DEVICE

    key = EvidenceDeviceKey.load_or_create(tmp_path / "vector.key", "vector-secret")
    key._private = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(envelopes["signing_key_seed_hex"])
    )
    key._public = key._private.public_key()
    chain = EvidenceChain(tmp_path / "chain.db", key, DEVICE)
    ledger = EvidenceDeliveryLedger(
        tmp_path / "ledger.db",
        key,
        DEVICE,
        anchor_epoch_id=published["anchor_epoch_id"],
        key_id=published["key_id"],
    )
    for n in range(1, int(published["local_seq"])):
        _seal(chain, ledger, n)
    sealed = ledger.seal(dict(published["chain_row"]), sealed_at_ms=1787000000512)
    assert int(sealed["local_seq"]) == int(published["local_seq"])
    assert sealed["chain_row_digest"] == published["chain_row_digest"]

    registry_path = tmp_path / "authority.json"
    registry_path.write_text(json.dumps(receipts["authority_key_registry"]))
    service = EvidenceIngestService(
        ledger=ledger,
        registry=load_authority_key_registry(registry_path),
        device_id=DEVICE,
        device_pubkey_hex=key.public_key_hex,
        custody_keys=CustodyKeyRegistry(active_secret=CUSTODY_SECRET),
    )
    yield ledger, service, receipts
    chain.close()
    ledger.close()


@pytest.mark.parametrize(
    ("case_name", "reason"),
    [
        ("valid", None),
        ("signed_with_epoch_key", REJECT_BAD_AUTHENTICATOR),
        # Every sequence in 9..12 is sealed here, so what refuses it is the
        # range digest covering 12 alone.
        ("non_contiguous_range", REJECT_BINDING_MISMATCH),
    ],
)
def test_every_receipt_vector_reaches_its_outcome_through_the_ledger(
    vector_rig, case_name, reason
):
    ledger, service, receipts = vector_rig
    published = next(c for c in receipts["cases"] if c["name"] == case_name)
    assert [c["name"] for c in receipts["cases"]] == [
        "valid",
        "signed_with_epoch_key",
        "non_contiguous_range",
    ], "a receipt case was added; give it an outcome here"
    assert receipts["valid_range_chain_row_digests"] == [
        ledger.find_by_local_seq(12)["chain_row_digest"]
    ]

    outcome = service.accept_receipt(published["artifact"])
    if published["expected"] == "accept":
        assert reason is None
        assert outcome.accepted
        assert outcome.applied_sequences == (12,)
        assert ledger.find_by_local_seq(12)["receipt_state"] == RECEIPT_ACCEPTED
        return
    assert not outcome.accepted
    assert outcome.reason == reason
    assert ledger.find_by_local_seq(12)["receipt_state"] == RECEIPT_NONE


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
        (lambda a: a.__setitem__("key_id", EPOCH_KEY_ID), REJECT_WRONG_PURPOSE, True),
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

    _register(ledger, key)
    assert service.accept_epoch_confirmation(_confirmation(key.public_key_hex)).accepted
    assert reader.active_anchor_epoch_id(DEVICE) == EPOCH


def test_a_confirmation_for_the_current_epoch_with_nothing_sealed_is_refused(rig):
    """A confirmation answers a registration; one this device never sealed is refused."""
    key, _, ledger, service = rig
    outcome = service.accept_epoch_confirmation(_confirmation(key.public_key_hex))
    assert not outcome.accepted
    assert outcome.reason == REJECT_BINDING_MISMATCH
    assert ConfirmedEpochReader(ledger).active_anchor_epoch_id(DEVICE) is None
    assert not ledger.registration_confirmed(EPOCH, key.public_key_hex)


@pytest.mark.parametrize(
    "corrupt,expected",
    [
        (
            lambda a, k: a.__setitem__("device_id", "some-other-device"),
            REJECT_BINDING_MISMATCH,
        ),
        (lambda a, k: a.__setitem__("pubkey_hex", "11" * 32), REJECT_BINDING_MISMATCH),
        (lambda a, k: a.__setitem__("key_id", RECEIPT_KEY_ID), REJECT_WRONG_PURPOSE),
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


def test_a_late_confirmation_for_an_earlier_epoch_does_not_roll_back(rig):
    """It closes that epoch's obligation, and the active epoch stays current."""
    key, _, ledger, service = rig
    _register(ledger, key)
    _register(ledger, key, EARLIER_EPOCH)
    assert service.accept_epoch_confirmation(_confirmation(key.public_key_hex)).accepted

    late = _confirmation(key.public_key_hex)
    late["anchor_epoch_id"] = EARLIER_EPOCH
    late["confirmed_at_ms"] = 1787000000500
    _sign(late, EPOCH_DOMAIN, EPOCH_SEED)
    assert service.accept_epoch_confirmation(late).accepted

    assert ConfirmedEpochReader(ledger).active_anchor_epoch_id(DEVICE) == EPOCH
    assert ledger.registration_confirmed(EARLIER_EPOCH, key.public_key_hex)
    assert ledger.open_registration_obligation(EARLIER_EPOCH) is None


def test_a_confirmation_for_an_epoch_under_another_key_is_refused(rig):
    """Sealed under this device, but not under the key the confirmation names."""
    key, _, ledger, service = rig
    _register(ledger, key)
    other = _confirmation("11" * 32)
    service_other = EvidenceIngestService(
        ledger=ledger,
        registry=service._registry,
        device_id=DEVICE,
        device_pubkey_hex="11" * 32,
    )
    outcome = service_other.accept_epoch_confirmation(other)
    assert not outcome.accepted and outcome.reason == REJECT_BINDING_MISMATCH
    assert ConfirmedEpochReader(ledger).active_anchor_epoch_id(DEVICE) is None


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
    from ori.security.evidence.ingest import verify_delivery_receipt

    verify_delivery_receipt(
        artifact,
        device_id=DEVICE,
        registry=service._registry,
        chain_row_digests=ledger.chain_row_digests(1, 1),
    )
    assert ledger.find_by_local_seq(1)["receipt_state"] == RECEIPT_NONE, (
        "verification must not mutate state on its own"
    )

    # The courier re-presents it after the restart.
    assert service.accept_receipt(artifact).accepted
    assert ledger.find_by_local_seq(1)["receipt_state"] == RECEIPT_ACCEPTED


def test_epoch_state_survives_a_restart(rig, tmp_path):
    key, _, ledger, service = rig
    _register(ledger, key)
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
