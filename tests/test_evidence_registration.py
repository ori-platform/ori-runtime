# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Anchor registration, per `ori-specs/evidence-exchange/v1`.

Driven against the contract's vector. Reproducing its bytes is the whole
acceptance criterion: a registration this device signs differently from what
the authority expects is a registration the authority cannot use, and the
device's evidence stays unattributable.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ori.security.evidence_canonical import canonical_json
from ori.security.evidence_device_key import EvidenceDeviceKey
from ori.security.evidence_registration import (
    REGISTRATION_DOMAIN,
    REGISTRATION_FIELDS,
    RegistrationError,
    build_anchor_registration,
    commissioning_digest,
)

VECTORS = pathlib.Path(__file__).parent / "vectors" / "evidence_exchange"


def vector(name: str) -> dict:
    return json.loads((VECTORS / f"{name}.json").read_text())


def case(name: str, case_name: str) -> dict:
    return next(c for c in vector(name)["cases"] if c["name"] == case_name)


@pytest.fixture
def device_key(tmp_path):
    """A key holding the seed the registration vector was signed with."""
    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "secret")
    seed = bytes.fromhex(vector("anchor-registration")["signing_key_seed_hex"])
    key._private = Ed25519PrivateKey.from_private_bytes(seed)
    key._public = key._private.public_key()
    return key


@pytest.fixture
def authorisation():
    return case("commissioning-authorization", "valid")["artifact"]


# --------------------------------------------------------------------------
# Agreement with the contract
# --------------------------------------------------------------------------


def test_the_registration_reproduces_the_contract_vector_byte_for_byte(
    device_key, authorisation
):
    published = case("anchor-registration", "valid")["artifact"]
    built = build_anchor_registration(
        device_key=device_key,
        device_id=published["device_id"],
        anchor_epoch_id=published["anchor_epoch_id"],
        posture=published["posture"],
        key_id=published["key_id"],
        registered_at_ms=published["registered_at_ms"],
        authorisation=authorisation,
    )
    assert built == published, "the registration differs from the contract's artifact"


def test_the_registration_carries_exactly_the_contract_field_set(
    device_key, authorisation
):
    built = build_anchor_registration(
        device_key=device_key,
        device_id="energy-monitor-ikeja-01",
        anchor_epoch_id="epoch-0002",
        posture="hardware_key",
        key_id="dev-key-2",
        registered_at_ms=1787000000000,
        authorisation=authorisation,
    )
    assert set(built) == set(REGISTRATION_FIELDS)


def test_it_is_signed_by_the_key_it_registers(device_key, authorisation):
    """Self-signed by construction: it proves control of the key, and only that."""
    built = build_anchor_registration(
        device_key=device_key,
        device_id="energy-monitor-ikeja-01",
        anchor_epoch_id="epoch-0002",
        posture="hardware_key",
        key_id="dev-key-2",
        registered_at_ms=1787000000000,
        authorisation=authorisation,
    )
    body = {k: v for k, v in built.items() if k != "signature"}
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(built["pubkey_hex"])).verify(
        base64.b64decode(built["signature"].split("ed25519:")[1]),
        REGISTRATION_DOMAIN + canonical_json(body),
    )


# --------------------------------------------------------------------------
# The commissioning binding
# --------------------------------------------------------------------------


def test_the_digest_covers_the_complete_authorisation(authorisation):
    """Including its signature.

    A digest over the unsigned body would let the same body travel with a
    different signature, so the registration would bind a claim rather than the
    signed artifact making it.
    """
    complete = commissioning_digest(authorisation)
    body_only = (
        "sha256:"
        + hashlib.sha256(
            canonical_json({k: v for k, v in authorisation.items() if k != "signature"})
        ).hexdigest()
    )

    assert (
        complete
        == case("anchor-registration", "valid")["artifact"]["commissioning_digest"]
    )
    assert complete != body_only, "the digest excludes the signature"


def test_a_different_signature_changes_the_digest(authorisation):
    """The substitution the binding exists to prevent."""
    swapped = dict(authorisation)
    swapped["signature"] = "ed25519:" + base64.b64encode(b"\x00" * 64).decode()
    assert commissioning_digest(swapped) != commissioning_digest(authorisation)


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("device_id", "some-other-device", "names device_id"),
        ("anchor_epoch_id", "epoch-9999", "names anchor_epoch_id"),
        ("pubkey_hex", "11" * 32, "authorises a different key"),
    ],
)
def test_an_authorisation_that_does_not_describe_this_registration_is_refused(
    device_key, authorisation, field, value, expected
):
    """A structural check, not a cryptographic one.

    The evidence authority verifies the authorisation, because it holds the
    commissioning trust root and this device does not. Agreement on device, key
    and epoch needs no trust root, and catching a mismatch here is the
    difference between producing something obviously wrong and producing
    something the authority must quarantine — which is an incident, not a retry.
    """
    mismatched = dict(authorisation)
    mismatched[field] = value
    with pytest.raises(RegistrationError, match=expected):
        build_anchor_registration(
            device_key=device_key,
            device_id="energy-monitor-ikeja-01",
            anchor_epoch_id="epoch-0002",
            posture="hardware_key",
            key_id="dev-key-2",
            registered_at_ms=1787000000000,
            authorisation=mismatched,
        )


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (lambda a: a.pop("actor"), "missing"),
        (lambda a: a.__setitem__("unexpected", True), "carries"),
        (lambda a: a.__setitem__("v", 2), "version"),
    ],
)
def test_a_malformed_authorisation_is_refused(
    device_key, authorisation, mutate, expected
):
    malformed = dict(authorisation)
    mutate(malformed)
    with pytest.raises(RegistrationError, match=expected):
        build_anchor_registration(
            device_key=device_key,
            device_id="energy-monitor-ikeja-01",
            anchor_epoch_id="epoch-0002",
            posture="hardware_key",
            key_id="dev-key-2",
            registered_at_ms=1787000000000,
            authorisation=malformed,
        )


# --------------------------------------------------------------------------
# Idempotency
# --------------------------------------------------------------------------


def test_the_same_inputs_produce_the_same_bytes(device_key, authorisation):
    """`(device_id, anchor_epoch_id)` is what a receiver deduplicates on.

    Idempotent by construction rather than by bookkeeping: every input is fixed
    or supplied, so re-presenting an identical binding is genuinely identical
    rather than merely equivalent.
    """
    kwargs = dict(
        device_key=device_key,
        device_id="energy-monitor-ikeja-01",
        anchor_epoch_id="epoch-0002",
        posture="hardware_key",
        key_id="dev-key-2",
        registered_at_ms=1787000000000,
        authorisation=authorisation,
    )
    assert build_anchor_registration(**kwargs) == build_anchor_registration(**kwargs)


def test_a_different_epoch_produces_a_different_registration(device_key, authorisation):
    """One registration per epoch; the epoch is half the identity."""
    other = dict(authorisation)
    other["anchor_epoch_id"] = "epoch-0003"
    first = build_anchor_registration(
        device_key=device_key,
        device_id="energy-monitor-ikeja-01",
        anchor_epoch_id="epoch-0002",
        posture="hardware_key",
        key_id="dev-key-2",
        registered_at_ms=1787000000000,
        authorisation=authorisation,
    )
    second = build_anchor_registration(
        device_key=device_key,
        device_id="energy-monitor-ikeja-01",
        anchor_epoch_id="epoch-0003",
        posture="hardware_key",
        key_id="dev-key-2",
        registered_at_ms=1787000000000,
        authorisation=other,
    )
    assert first["anchor_epoch_id"] != second["anchor_epoch_id"]
    assert first["signature"] != second["signature"]


@pytest.mark.parametrize("missing", ["device_id", "anchor_epoch_id", "key_id"])
def test_the_identity_fields_are_required(device_key, authorisation, missing):
    kwargs = dict(
        device_key=device_key,
        device_id="energy-monitor-ikeja-01",
        anchor_epoch_id="epoch-0002",
        posture="hardware_key",
        key_id="dev-key-2",
        registered_at_ms=1787000000000,
        authorisation=authorisation,
    )
    kwargs[missing] = ""
    with pytest.raises(RegistrationError, match="must name"):
        build_anchor_registration(**kwargs)
