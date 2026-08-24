# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Verifying what arrives back, per `ori-specs/evidence-exchange/v1`.

Driven from the contract's own vectors, including the cases it publishes as
rejections. The two cross-purpose cases matter most: a receipt signed with the
epoch key, and a confirmation signed with the receipt key. Both verify
cryptographically and both must be refused, which is exactly the kind of
failure a signature check alone reports as success.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.custody_keys import (
    CustodyKeyRegistry,
    CustodyKeyRegistryError,
    derive_custody_key_id,
)
from ori.security.evidence_authority_keys import (
    PURPOSE_EPOCH,
    PURPOSE_RECEIPT,
    REGISTRY_SCHEMA,
    STATUS_REVOKED,
    STATUS_VERIFY_ONLY,
    AuthorityKeyError,
    load_authority_key_registry,
    select_verifying_key,
)
from ori.security.evidence_ingest import (
    REJECT_BAD_AUTHENTICATOR,
    REJECT_BINDING_MISMATCH,
    REJECT_MALFORMED,
    REJECT_NON_CONTIGUOUS,
    REJECT_REASONS,
    REJECT_RETIRED_KEY,
    REJECT_UNKNOWN_KEY,
    REJECT_UNKNOWN_SEQUENCE,
    REJECT_UNRECOGNISED_VERSION,
    REJECT_WRONG_PURPOSE,
    IngestRejectedError,
    verify_custody_acknowledgement,
    verify_delivery_receipt,
    verify_epoch_confirmation,
)

# Every rejection reason, by the name the verifiers use for it. Written out
# rather than gathered from `globals()`: a dynamically resolved import looks
# unused to a linter and gets stripped, which silently shrinks the scan below
# to whatever happened to survive.
REASON_CONSTANTS = {
    "REJECT_BAD_AUTHENTICATOR": REJECT_BAD_AUTHENTICATOR,
    "REJECT_BINDING_MISMATCH": REJECT_BINDING_MISMATCH,
    "REJECT_MALFORMED": REJECT_MALFORMED,
    "REJECT_NON_CONTIGUOUS": REJECT_NON_CONTIGUOUS,
    "REJECT_RETIRED_KEY": REJECT_RETIRED_KEY,
    "REJECT_UNKNOWN_KEY": REJECT_UNKNOWN_KEY,
    "REJECT_UNKNOWN_SEQUENCE": REJECT_UNKNOWN_SEQUENCE,
    "REJECT_UNRECOGNISED_VERSION": REJECT_UNRECOGNISED_VERSION,
    "REJECT_WRONG_PURPOSE": REJECT_WRONG_PURPOSE,
}


def test_this_module_knows_every_published_reason():
    """The map above is the scan's vocabulary; a gap in it shrinks the scan."""
    assert set(REASON_CONSTANTS.values()) == REJECT_REASONS


VECTORS = pathlib.Path(__file__).parent / "vectors" / "evidence_exchange"
DEVICE = "energy-monitor-ikeja-01"


def vector(name: str) -> dict:
    return json.loads((VECTORS / f"{name}.json").read_text())


def case(name: str, case_name: str) -> dict:
    return next(c for c in vector(name)["cases"] if c["name"] == case_name)


def public_hex(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


@pytest.fixture
def registry(tmp_path):
    """A release-shipped registry holding both authority purposes."""
    receipt_seed = vector("delivery-receipt")["authority_receipt_seed_hex"]
    epoch_seed = vector("epoch-confirmation")["signing_key_seed_hex"]
    path = tmp_path / "authority-keys.json"
    path.write_text(
        json.dumps(
            {
                "schema": REGISTRY_SCHEMA,
                "keys": [
                    {
                        "key_id": case("delivery-receipt", "valid")["artifact"][
                            "key_id"
                        ],
                        "public_key_hex": public_hex(receipt_seed),
                        "purpose": PURPOSE_RECEIPT,
                        "status": "active",
                    },
                    {
                        "key_id": case("epoch-confirmation", "valid")["artifact"][
                            "key_id"
                        ],
                        "public_key_hex": public_hex(epoch_seed),
                        "purpose": PURPOSE_EPOCH,
                        "status": "active",
                    },
                ],
            }
        )
    )
    return load_authority_key_registry(path)


# --------------------------------------------------------------------------
# The registry is a trust root, and where it comes from decides everything
# --------------------------------------------------------------------------


def test_a_key_held_for_another_purpose_does_not_verify(registry):
    """Purposes are disjoint, and the failure says which is which.

    "Unknown" and "held for something else" are different findings: one is a
    missing key, the other is the shape of a cross-purpose substitution.
    """
    receipt_key_id = case("delivery-receipt", "valid")["artifact"]["key_id"]
    with pytest.raises(AuthorityKeyError, match="is held for"):
        select_verifying_key(registry, PURPOSE_EPOCH, receipt_key_id)


def test_an_unknown_key_is_distinguished_from_a_misplaced_one(registry):
    with pytest.raises(AuthorityKeyError, match="no key"):
        select_verifying_key(registry, PURPOSE_RECEIPT, "never-issued")


@pytest.mark.parametrize("status", [STATUS_REVOKED])
def test_a_revoked_key_verifies_nothing(tmp_path, status):
    """A retired key that still verified would make rotation cosmetic."""
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {
                "schema": REGISTRY_SCHEMA,
                "keys": [
                    {
                        "key_id": "old",
                        "public_key_hex": "aa" * 32,
                        "purpose": PURPOSE_RECEIPT,
                        "status": status,
                    }
                ],
            }
        )
    )
    loaded = load_authority_key_registry(path)
    with pytest.raises(AuthorityKeyError, match="verifies nothing"):
        select_verifying_key(loaded, PURPOSE_RECEIPT, "old")


def test_a_verify_only_key_still_verifies(tmp_path):
    """Rotation keeps artifacts signed before it verifiable."""
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {
                "schema": REGISTRY_SCHEMA,
                "keys": [
                    {
                        "key_id": "outgoing",
                        "public_key_hex": "bb" * 32,
                        "purpose": PURPOSE_RECEIPT,
                        "status": STATUS_VERIFY_ONLY,
                    }
                ],
            }
        )
    )
    assert select_verifying_key(
        load_authority_key_registry(path), PURPOSE_RECEIPT, "outgoing"
    )


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (lambda r: r.__setitem__("schema", "something.else"), "schema"),
        (lambda r: r.__setitem__("keys", []), "must contain keys"),
        (
            lambda r: r["keys"][0].__setitem__("purpose", "evidence_device"),
            "does not govern",
        ),
        (lambda r: r["keys"][0].__setitem__("status", "probationary"), "status"),
        (lambda r: r["keys"][0].__setitem__("public_key_hex", "aa"), "32"),
        (lambda r: r.__setitem__("extra", True), "fields are wrong"),
    ],
)
def test_a_malformed_registry_is_refused(tmp_path, mutate, expected):
    raw = {
        "schema": REGISTRY_SCHEMA,
        "keys": [
            {
                "key_id": "k1",
                "public_key_hex": "cc" * 32,
                "purpose": PURPOSE_RECEIPT,
                "status": "active",
            }
        ],
    }
    mutate(raw)
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(AuthorityKeyError, match=expected):
        load_authority_key_registry(path)


# --------------------------------------------------------------------------
# Delivery receipts
# --------------------------------------------------------------------------


def _digests_for(
    from_seq: int, to_seq: int, expected_range_digest: str
) -> dict[int, str]:
    """Envelope digests that reproduce the vector's published range digest."""
    published = vector("delivery-envelope")
    valid = next(c for c in published["cases"] if c["name"] == "valid")["artifact"]
    reordered = next(c for c in published["cases"] if c["name"] == "reordered_batch")[
        "artifact"
    ]
    digests = {
        int(valid["local_seq"]): "sha256:"
        + hashlib.sha256(valid["chain_row"]["canonical_json"].encode()).hexdigest(),
        int(reordered["local_seq"]): "sha256:"
        + hashlib.sha256(reordered["chain_row"]["canonical_json"].encode()).hexdigest(),
    }
    concatenated = b"".join(
        bytes.fromhex(digests[seq].split("sha256:")[1])
        for seq in range(from_seq, to_seq + 1)
    )
    assert (
        "sha256:" + hashlib.sha256(concatenated).hexdigest() == expected_range_digest
    ), "the fixture does not reproduce the vector's range digest"
    return digests


def test_the_valid_receipt_verifies(registry):
    artifact = case("delivery-receipt", "valid")["artifact"]
    digests = _digests_for(
        artifact["from_seq"], artifact["to_seq"], artifact["range_digest"]
    )
    verified = verify_delivery_receipt(
        artifact, device_id=DEVICE, registry=registry, envelope_digests=digests
    )
    assert verified.from_seq == artifact["from_seq"]
    assert verified.to_seq == artifact["to_seq"]


def test_a_receipt_signed_with_the_epoch_key_is_refused(registry):
    """Purpose separation is what refuses this, and it shows up as a bad signature.

    The artifact names the correct receipt key id and is signed with the epoch
    private key — cryptographically sound, and asserting something a receipt
    key is not held to say. Selecting by `(purpose, key_id)` forces
    verification against the *receipt* key, under which that signature does not
    verify. So the mechanism is purpose separation and the observable outcome
    is a signature failure; a verifier that trial-verified against every key it
    holds would accept this.
    """
    artifact = case("delivery-receipt", "signed_with_epoch_key")["artifact"]
    assert (
        artifact["key_id"] == case("delivery-receipt", "valid")["artifact"]["key_id"]
    ), "this case is only meaningful while it names the correct key id"
    with pytest.raises(IngestRejectedError) as raised:
        verify_delivery_receipt(
            artifact, device_id=DEVICE, registry=registry, envelope_digests={}
        )
    assert raised.value.reason == REJECT_BAD_AUTHENTICATOR


def test_a_non_contiguous_receipt_is_refused(registry):
    artifact = case("delivery-receipt", "non_contiguous_range")["artifact"]
    with pytest.raises(IngestRejectedError) as raised:
        verify_delivery_receipt(
            artifact, device_id=DEVICE, registry=registry, envelope_digests={}
        )
    assert raised.value.reason in {REJECT_NON_CONTIGUOUS, REJECT_UNKNOWN_SEQUENCE}


def test_a_receipt_for_another_device_is_refused(registry):
    artifact = dict(case("delivery-receipt", "valid")["artifact"])
    with pytest.raises(IngestRejectedError) as raised:
        verify_delivery_receipt(
            artifact,
            device_id="some-other-device",
            registry=registry,
            envelope_digests=_digests_for(
                artifact["from_seq"], artifact["to_seq"], artifact["range_digest"]
            ),
        )
    assert raised.value.reason == REJECT_BINDING_MISMATCH


def test_a_receipt_covering_unsealed_sequences_is_refused(registry):
    """A receipt cannot assert a range this device never produced."""
    artifact = case("delivery-receipt", "valid")["artifact"]
    with pytest.raises(IngestRejectedError) as raised:
        verify_delivery_receipt(
            artifact, device_id=DEVICE, registry=registry, envelope_digests={}
        )
    assert raised.value.reason == REJECT_UNKNOWN_SEQUENCE


def test_a_receipt_whose_range_digest_disagrees_is_refused(registry):
    """Recomputing the digest is what makes the prefix claim checkable."""
    artifact = dict(case("delivery-receipt", "valid")["artifact"])
    digests = _digests_for(
        artifact["from_seq"], artifact["to_seq"], artifact["range_digest"]
    )
    digests[artifact["to_seq"]] = "sha256:" + "0" * 64
    with pytest.raises(IngestRejectedError) as raised:
        verify_delivery_receipt(
            artifact, device_id=DEVICE, registry=registry, envelope_digests=digests
        )
    assert raised.value.reason == REJECT_BINDING_MISMATCH


# --------------------------------------------------------------------------
# Epoch confirmations
# --------------------------------------------------------------------------


def test_the_valid_epoch_confirmation_verifies(registry):
    artifact = case("epoch-confirmation", "valid")["artifact"]
    verified = verify_epoch_confirmation(
        artifact,
        device_id=DEVICE,
        registry=registry,
        expected_pubkey_hex=artifact["pubkey_hex"],
    )
    assert verified.anchor_epoch_id == artifact["anchor_epoch_id"]


def test_a_confirmation_signed_with_the_receipt_key_is_refused(registry):
    """A receipt key cannot assert that an epoch became effective."""
    artifact = case("epoch-confirmation", "signed_with_receipt_key")["artifact"]
    assert (
        artifact["key_id"] == case("epoch-confirmation", "valid")["artifact"]["key_id"]
    )
    with pytest.raises(IngestRejectedError) as raised:
        verify_epoch_confirmation(
            artifact, device_id=DEVICE, registry=registry, expected_pubkey_hex="00" * 32
        )
    assert raised.value.reason == REJECT_BAD_AUTHENTICATOR


def test_an_artifact_naming_a_key_held_for_another_purpose_is_refused(registry):
    """The other shape of the same attack, and it fails at selection instead.

    Here the artifact names a key id this device holds — but under a different
    purpose. Selection refuses it before any signature is checked, which is why
    both shapes need covering: one fails at the lookup, the other at the
    signature, and a verifier could easily catch one and not the other.
    """
    artifact = dict(case("delivery-receipt", "valid")["artifact"])
    artifact["key_id"] = case("epoch-confirmation", "valid")["artifact"]["key_id"]
    with pytest.raises(IngestRejectedError) as raised:
        verify_delivery_receipt(
            artifact, device_id=DEVICE, registry=registry, envelope_digests={}
        )
    assert raised.value.reason == REJECT_WRONG_PURPOSE


def test_a_confirmation_naming_another_key_is_refused(registry):
    """Without this binding, a statement about another device's anchor would advance this one's."""
    artifact = case("epoch-confirmation", "valid")["artifact"]
    with pytest.raises(IngestRejectedError) as raised:
        verify_epoch_confirmation(
            artifact, device_id=DEVICE, registry=registry, expected_pubkey_hex="11" * 32
        )
    assert raised.value.reason == REJECT_BINDING_MISMATCH


def test_a_confirmation_for_another_device_is_refused(registry):
    artifact = case("epoch-confirmation", "valid")["artifact"]
    with pytest.raises(IngestRejectedError) as raised:
        verify_epoch_confirmation(
            artifact,
            device_id="some-other-device",
            registry=registry,
            expected_pubkey_hex=artifact["pubkey_hex"],
        )
    assert raised.value.reason == REJECT_BINDING_MISMATCH


# --------------------------------------------------------------------------
# Custody acknowledgements
# --------------------------------------------------------------------------


def _custody_secret(which: str = "gateway_secret_hex") -> str:
    published = vector("custody-acknowledgement")
    return bytes.fromhex(published[which]).decode("utf-8")


def _custody_registry() -> CustodyKeyRegistry:
    """The registry the published vectors describe.

    Built from the file's own `registry_state`, so the fixture cannot drift
    from the cases it is meant to verify. The retired generation is a
    tombstone: its secret is published as generator material, and a conforming
    receiver never holds it.
    """
    published = vector("custody-acknowledgement")
    return CustodyKeyRegistry(
        active_secret=_custody_secret("gateway_secret_hex"),
        previous_secret=_custody_secret("previous_gateway_secret_hex"),
        retired_key_ids=(published["registry_state"]["retired"]["key_id"],),
    )


def _custody_case(name: str):
    return case("custody-acknowledgement", name)


def _verify_custody(artifact, **overrides):
    kwargs = {
        "device_id": DEVICE,
        "custody_keys": _custody_registry(),
        "expected_digest": artifact["envelope_digest"],
        "expected_local_seq": artifact["local_seq"],
    }
    kwargs.update(overrides)
    return verify_custody_acknowledgement(artifact, **kwargs)


def test_the_registry_the_vectors_describe_reproduces_from_the_secrets():
    """Every published identifier derives from its own secret.

    If this drifts, every case below is verifying against a registry the
    vector file does not describe, and the outcomes would prove nothing.
    """
    published = vector("custody-acknowledgement")
    state = published["registry_state"]
    assert (
        derive_custody_key_id(_custody_secret("gateway_secret_hex"))
        == (state["active"]["key_id"])
    )
    assert (
        derive_custody_key_id(_custody_secret("previous_gateway_secret_hex"))
        == (state["verify_only"]["key_id"])
    )
    assert (
        derive_custody_key_id(_custody_secret("retired_gateway_secret_hex"))
        == (state["retired"]["key_id"])
    )
    assert state["retired"]["secret"] is None, "a tombstone must hold no secret"


@pytest.mark.parametrize("name", ["valid", "valid_previous_generation"])
def test_both_live_generations_verify(name):
    """Selection is by key_id, so a rotation window keeps verifying.

    The previous generation is `verify_only` rather than removed, which is what
    stops acknowledgements already in the courier's hands from failing the
    moment a secret is rotated.
    """
    artifact = _custody_case(name)["artifact"]
    verified = _verify_custody(artifact)
    assert verified.local_seq == artifact["local_seq"]
    assert verified.key_id == artifact["key_id"]


@pytest.mark.parametrize(
    "name",
    [
        "invalid_mac",
        "unknown_key_id",
        "retired_key_id",
        "malformed_key_id",
        "malformed_mac_too_short",
        "malformed_mac_too_long",
        "malformed_mac_non_hex",
        "malformed_mac_uppercase",
        "key_id_not_derived_from_signing_secret",
    ],
)
def test_each_published_refusal_carries_the_reason_the_vector_names(name):
    """The vector names the outcome; this asserts the implementation agrees.

    Mapping case names to reasons here instead would be a second copy of the
    contract, and the copy would be the one that drifted.
    """
    published = _custody_case(name)
    artifact = published["artifact"]
    with pytest.raises(IngestRejectedError) as raised:
        _verify_custody(artifact)
    assert raised.value.reason == published["reject_reason"]


def test_a_key_id_naming_another_generation_is_refused_without_trial_verification():
    """The case that separates selection from trial verification.

    Its MAC verifies under the ACTIVE secret while its key_id derives from the
    PREVIOUS one. A verifier that selects by key_id checks the previous secret
    and refuses. A verifier that tries every secret it holds finds the active
    one and wrongly accepts, which would make "which key authenticated this"
    unanswerable and would silently accept under the wrong generation during a
    rotation.
    """
    published = vector("custody-acknowledgement")
    artifact = _custody_case("key_id_not_derived_from_signing_secret")["artifact"]

    # The premise, established independently: the artifact really does verify
    # under a secret the registry holds -- just not the one it names. Without
    # this the test would pass for the wrong reason, since any refusal at all
    # satisfies the assertion below.
    body = {k: v for k, v in artifact.items() if k != "mac"}
    signed = b"ori.evidence_custody_ack.v1\x00" + json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    under_active = (
        "hmac-sha256:"
        + hmac.new(
            _custody_secret("gateway_secret_hex").encode("utf-8"),
            signed,
            hashlib.sha256,
        ).hexdigest()
    )
    assert artifact["mac"] == under_active, "premise: it verifies under the active key"
    assert artifact["key_id"] == published["registry_state"]["verify_only"]["key_id"], (
        "premise: but names the previous generation"
    )

    with pytest.raises(IngestRejectedError) as raised:
        _verify_custody(artifact)
    assert raised.value.reason == REJECT_BAD_AUTHENTICATOR


RECEIVER_STATE = (
    pathlib.Path(__file__).parent / "vectors" / "evidence_exchange_receiver_state"
)


def receiver_state_vector(name: str) -> dict:
    return json.loads((RECEIVER_STATE / f"{name}.json").read_text())


#: Parties a receiver-state vector may be owned by, named as roles.
#:
#: An allowlist rather than a check against forbidden names. Banning a specific
#: implementation would mean writing that implementation's name here, which is
#: the disclosure the check exists to prevent -- and it would still admit every
#: other name. Requiring one of these admits only a role.
RECEIVER_STATE_OWNERS = frozenset(
    {
        "the evidence authority",
        "the site gateway",
    }
)

#: Statuses an unexercised vector may carry. Ownership and proof are separate
#: facts, and collapsing them is how "someone else owns this" becomes "someone
#: else has done this". Only `proven_elsewhere` asserts that a proof exists.
RECEIVER_STATE_STATUSES = {
    "proof_pending": "owned by another repository; not proven anywhere yet",
    "proven_elsewhere": "a conforming implementation exercises it in the owning repository",
}

#: Receiver-state vectors this runtime cannot exercise.
#:
#: Vendoring a vector proves nothing on its own. The set is drift-checked, which
#: is worth having, but a file nothing reads is a file whose invariant is
#: unproven -- and one that reads as covered because it sits beside files that
#: are. Each entry therefore records three separate things: who is responsible,
#: whether a proof actually exists yet, and where that is tracked.
RECEIVER_STATE_NOT_EXERCISED_HERE = {
    "anchor-quarantine": {
        # A role, not an implementation. The authority's identity is not
        # disclosed in this repository, and an accounting note is not an
        # exception to that.
        "owner": "the evidence authority",
        "status": "proof_pending",
        "tracking": "ori-runtime#372",
        "reason": (
            "Authority-side. Its receiver_state is `held_anchors`, the registry "
            "an evidence authority keeps of other devices' anchors, and the "
            "outcome is that authority refusing to rebind one. This runtime "
            "produces its own registration and never holds another device's "
            "anchor, so there is no code path here to drive."
        ),
    },
}


def test_every_vendored_receiver_state_vector_is_exercised_or_accounted_for():
    """A vendored vector is either consumed here or accounted for precisely.

    This is the failure mode the vendoring work was filed against: files
    arriving in the tree, passing the drift check, and quietly implying a
    coverage that does not exist. Adding a receiver-state vector forces a
    decision rather than allowing silent accumulation.

    The accounting separates ownership from proof deliberately. An entry naming
    a repository says who is responsible, not that the work is done, and an
    earlier revision of this list conflated the two by asserting only that a
    repository was named.
    """
    vendored = {p.stem for p in RECEIVER_STATE.glob("*.json") if p.stem != "MANIFEST"}
    assert vendored, "no receiver-state vectors are vendored"

    exercised = {"custody-key-purpose"}
    accounted = exercised | set(RECEIVER_STATE_NOT_EXERCISED_HERE)

    assert vendored <= accounted, (
        "vendored receiver-state vectors that nothing consumes and nothing "
        f"explains: {sorted(vendored - accounted)}"
    )
    assert set(RECEIVER_STATE_NOT_EXERCISED_HERE) <= vendored, (
        "an exemption names a vector that is not vendored: "
        f"{sorted(set(RECEIVER_STATE_NOT_EXERCISED_HERE) - vendored)}"
    )
    assert not (exercised & set(RECEIVER_STATE_NOT_EXERCISED_HERE)), (
        "a vector cannot be both exercised here and exempted from being so"
    )

    for name, entry in RECEIVER_STATE_NOT_EXERCISED_HERE.items():
        assert set(entry) == {"owner", "status", "tracking", "reason"}, (
            f"{name} must record owner, status, tracking and reason"
        )
        assert entry["status"] in RECEIVER_STATE_STATUSES, (
            f"{name} carries an unrecognised status {entry['status']!r}"
        )
        assert entry["owner"] in RECEIVER_STATE_OWNERS, (
            f"{name} must name a responsible role, one of "
            f"{sorted(RECEIVER_STATE_OWNERS)}, rather than an implementation"
        )
        assert "#" in entry["tracking"], (
            f"{name} must cite a tracking issue, not just a repository"
        )


def test_an_unproven_vector_is_not_recorded_as_proven():
    """`proof_pending` means no proof exists, and must not read as ownership alone.

    ori-runtime#372 states that the anchor quarantine invariant is unproven
    anywhere today. If this list said `proven_elsewhere`, the two would
    contradict each other and the more comfortable one would be the one people
    read.
    """
    entry = RECEIVER_STATE_NOT_EXERCISED_HERE["anchor-quarantine"]
    assert entry["status"] == "proof_pending"
    assert "proven" not in entry["reason"].lower(), (
        "the reason must explain why it cannot be exercised here, not assert a "
        "proof elsewhere"
    )


def test_a_key_id_held_for_another_purpose_is_refused_as_such():
    """Purpose separation, from the vector that describes the receiver's state.

    The artifact is byte-identical to a conforming one -- `key_id` is derived,
    so an identifier held under another purpose cannot differ in the bytes.
    The defect is entirely in what the receiver holds, which is why this case
    lives in the receiver-state set and why it cannot be found by inspecting
    the acknowledgement.

    Answering `unknown_key` here would hide a key being used across purposes,
    which is the thing purpose separation exists to prevent.
    """
    published = receiver_state_vector("custody-key-purpose")
    case_ = published["cases"][0]
    artifact = case_["artifact"]
    held = case_["receiver_state"]["held_keys"][0]

    # The registry holds no custody generation deriving to this identifier...
    registry = CustodyKeyRegistry(active_secret="a-different-custody-secret")
    assert registry.lookup(artifact["key_id"]) is None
    # ...but an authority key is registered under another purpose for it.
    authority_keys = {(held["key_purpose"], held["key_id"]): object()}
    assert held["key_purpose"] != "gateway_custody"

    with pytest.raises(IngestRejectedError) as raised:
        verify_custody_acknowledgement(
            artifact,
            device_id=DEVICE,
            custody_keys=registry,
            authority_keys=authority_keys,
            expected_digest=artifact["envelope_digest"],
            expected_local_seq=artifact["local_seq"],
        )
    assert raised.value.reason == case_["reject_reason"]


def test_the_same_artifact_is_unknown_key_when_no_purpose_holds_it():
    """The contrast that gives the previous test meaning.

    Identical bytes, identical custody registry -- only the purpose-aware state
    differs. If both produced the same reason, the distinction would be
    decorative.
    """
    published = receiver_state_vector("custody-key-purpose")
    artifact = published["cases"][0]["artifact"]

    with pytest.raises(IngestRejectedError) as raised:
        verify_custody_acknowledgement(
            artifact,
            device_id=DEVICE,
            custody_keys=CustodyKeyRegistry(active_secret="a-different-custody-secret"),
            authority_keys={},
            expected_digest=artifact["envelope_digest"],
            expected_local_seq=artifact["local_seq"],
        )
    assert raised.value.reason == REJECT_UNKNOWN_KEY


def test_custody_key_material_may_not_be_an_envelope_secret():
    """Separation is enforced on the bytes, not on the variable names.

    Two environment variables can hold one value, so an operator who points
    both at the same secret has reused the envelope secret for custody. A check
    on the names an operator wrote would call that configuration correct.
    """
    with pytest.raises(CustodyKeyRegistryError, match="envelope secret"):
        CustodyKeyRegistry(
            active_secret="one-secret-for-both",
            forbidden_secrets=("one-secret-for-both",),
        )
    with pytest.raises(CustodyKeyRegistryError, match="envelope secret"):
        CustodyKeyRegistry(
            active_secret="custody-secret",
            previous_secret="one-secret-for-both",
            forbidden_secrets=("one-secret-for-both",),
        )


def test_custody_for_an_envelope_this_device_did_not_seal_is_refused():
    artifact = _custody_case("valid")["artifact"]
    with pytest.raises(IngestRejectedError) as raised:
        _verify_custody(artifact, expected_local_seq=int(artifact["local_seq"]) + 1)
    assert raised.value.reason == REJECT_UNKNOWN_SEQUENCE


def test_custody_over_different_bytes_is_refused():
    """Custody commits to the artifact the gateway actually holds."""
    artifact = _custody_case("valid")["artifact"]
    with pytest.raises(IngestRejectedError) as raised:
        _verify_custody(artifact, expected_digest="sha256:" + "0" * 64)
    assert raised.value.reason == REJECT_BINDING_MISMATCH


def test_a_registry_cannot_hold_one_secret_as_two_generations():
    """An operator error that would silently collapse the rotation window."""
    secret = _custody_secret("gateway_secret_hex")
    with pytest.raises(CustodyKeyRegistryError, match="distinct secrets"):
        CustodyKeyRegistry(active_secret=secret, previous_secret=secret)


def test_a_tombstone_cannot_name_a_generation_that_still_holds_a_secret():
    """The tombstone asserts the secret was destroyed; here it demonstrably was not."""
    secret = _custody_secret("gateway_secret_hex")
    with pytest.raises(CustodyKeyRegistryError, match="still holds"):
        CustodyKeyRegistry(
            active_secret=secret, retired_key_ids=(derive_custody_key_id(secret),)
        )


# --------------------------------------------------------------------------
# Shape and version
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "verifier,name,kwargs",
    [
        (verify_delivery_receipt, "delivery-receipt", {"envelope_digests": {}}),
        (
            verify_epoch_confirmation,
            "epoch-confirmation",
            {"expected_pubkey_hex": "00" * 32},
        ),
    ],
)
def test_an_unrecognised_version_is_rejected_before_anything_is_trusted(
    registry, verifier, name, kwargs
):
    """A version this contract does not define means the rest is not ours to read.

    Checked before the signature, because interpreting fields from an unknown
    version is how a future meaning gets silently assigned an old one.
    """
    artifact = dict(case(name, "valid")["artifact"])
    artifact["v"] = 2
    with pytest.raises(IngestRejectedError) as raised:
        verifier(artifact, device_id=DEVICE, registry=registry, **kwargs)
    assert raised.value.reason == REJECT_UNRECOGNISED_VERSION


@pytest.mark.parametrize("name", ["delivery-receipt", "epoch-confirmation"])
def test_an_undefined_field_is_rejected(registry, name):
    artifact = dict(case(name, "valid")["artifact"])
    artifact["unexpected"] = True
    kwargs = (
        {"envelope_digests": {}}
        if name == "delivery-receipt"
        else {"expected_pubkey_hex": "00" * 32}
    )
    verifier = (
        verify_delivery_receipt
        if name == "delivery-receipt"
        else verify_epoch_confirmation
    )
    with pytest.raises(IngestRejectedError):
        verifier(artifact, device_id=DEVICE, registry=registry, **kwargs)


def test_a_free_text_rejection_reason_cannot_be_constructed():
    """Construction is the action under test: the reason is validated in `__init__`.

    That placement is the point. A free-text reason cannot be created at all,
    rather than being created and filtered somewhere downstream where a caller
    might forget — and the text here is the shape of what would leak, an
    endpoint reaching a diagnostic an operator reads.
    """

    def construct(reason: str) -> IngestRejectedError:
        return IngestRejectedError(reason, "detail")

    with pytest.raises(ValueError, match="not a recognised rejection reason"):
        construct("connection to private.host failed")


@pytest.mark.parametrize("reason", sorted(REJECT_REASONS))
def test_every_published_reason_can_be_constructed(reason):
    """The closed set must not reject the reasons the verifiers actually use."""
    assert IngestRejectedError(reason, "detail").reason == reason


def test_the_verifiers_only_use_published_reasons():
    """A verifier raising an unpublished reason would fail at the point of failure.

    Asserted structurally rather than by exercising every path: the constructor
    refuses an unknown reason, so any such call site raises `ValueError` instead
    of the rejection it meant to report — losing the finding it was trying to
    make.
    """
    import ast
    import pathlib as _pathlib

    source = (
        _pathlib.Path(__file__).parent.parent
        / "ori"
        / "security"
        / "evidence_ingest.py"
    ).read_text()
    used: set[str] = set()
    unresolved: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "IngestRejectedError"
            and node.args
        ):
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            used.add(first.value)
        elif isinstance(first, ast.Name):
            # Call sites name the constants rather than repeating the strings.
            # A scan that resolved only literals would report full coverage of
            # nothing, so an unresolvable name is collected and reported.
            resolved = REASON_CONSTANTS.get(first.id)
            if isinstance(resolved, str):
                used.add(resolved)
            else:
                unresolved.append(first.id)
        else:
            unresolved.append(ast.dump(first)[:40])

    assert not unresolved, f"rejection reasons the scan could not resolve: {unresolved}"
    assert len(used) >= 6, (
        f"only {len(used)} reasons found in use; the scan is not working"
    )
    assert used <= REJECT_REASONS, (
        f"unpublished reasons in use: {sorted(used - REJECT_REASONS)}"
    )
