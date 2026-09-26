# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Anchor registration, per `ori-specs/evidence-exchange/v1`.

Driven against the contract's vector. Reproducing its bytes is the whole
acceptance criterion: a registration this device signs differently from what
the authority expects is a registration the authority cannot use.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ori.security.evidence.anchor import derive_runtime_anchor
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.device_key import EvidenceDeviceKey
from ori.security.evidence.registration import (
    REGISTRATION_DOMAIN,
    REGISTRATION_FIELDS,
    RegistrationError,
    build_anchor_registration,
)

VECTORS = pathlib.Path(__file__).parent.parent / "vectors" / "evidence_exchange"
ANCHOR_VECTORS = (
    pathlib.Path(__file__).parent.parent / "vectors" / "runtime_evidence_anchor"
)


def vector(name: str) -> dict:
    return json.loads((VECTORS / f"{name}.json").read_text())


def case(name: str, case_name: str) -> dict:
    return next(c for c in vector(name)["cases"] if c["name"] == case_name)


DEVICE_ID = "energy-monitor-ikeja-01"


@pytest.fixture
def device_key(tmp_path):
    """A key holding the seed the registration vector was signed with."""
    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "secret")
    seed = bytes.fromhex(vector("anchor-registration-v2")["signing_key_seed_hex"])
    key._private = Ed25519PrivateKey.from_private_bytes(seed)
    key._public = key._private.public_key()
    return key


@pytest.fixture
def anchor(device_key):
    return derive_runtime_anchor(
        device_id=DEVICE_ID, pubkey_hex=device_key.public_key_hex
    )


@pytest.fixture
def reference() -> str:
    """The commissioning reference the published registration carries."""
    return str(
        case("anchor-registration-v2", "valid")["artifact"]["commissioning_digest"]
    )


def _kwargs(device_key, anchor, reference: str) -> dict[str, Any]:
    return dict(
        device_key=device_key,
        device_id=DEVICE_ID,
        anchor_epoch_id=anchor.anchor_epoch_id,
        posture=anchor.posture,
        key_id=anchor.key_id,
        registered_at_ms=1787000000000,
        commissioning_reference=reference,
        capability_profile=anchor.profile.as_document(),
    )


# --------------------------------------------------------------------------
# Agreement with the contract
# --------------------------------------------------------------------------


def test_the_registration_reproduces_the_contract_vector_byte_for_byte(
    device_key, anchor, reference
):
    published = case("anchor-registration-v2", "valid")
    built = build_anchor_registration(
        device_key=device_key,
        device_id=published["artifact"]["device_id"],
        anchor_epoch_id=published["artifact"]["anchor_epoch_id"],
        posture=published["artifact"]["posture"],
        key_id=published["artifact"]["key_id"],
        registered_at_ms=published["artifact"]["registered_at_ms"],
        commissioning_reference=reference,
        capability_profile=anchor.profile.as_document(),
    )
    assert built == published["artifact"]
    unsigned = {k: v for k, v in built.items() if k != "signature"}
    assert canonical_json(unsigned).hex() == published["canonical_hex"]


def test_the_producer_default_anchor_is_the_contract_baseline():
    """The attestor seals under `derive_runtime_anchor`'s defaults; they are the baseline."""
    cases = json.loads((ANCHOR_VECTORS / "runtime-anchor-v2.json").read_text())["cases"]
    baseline = next(c for c in cases if c["name"] == "baseline")
    inputs = baseline["inputs"]
    derived = derive_runtime_anchor(
        device_id=inputs["device_id"],
        pubkey_hex=base64.b64decode(inputs["public_key_b64"]).hex(),
    )
    assert derived.posture == inputs["posture"]
    assert derived.profile.as_document() == inputs["capability_profile"]
    assert derived.key_id == baseline["key_id"]
    assert derived.anchor_epoch_id == baseline["anchor_epoch_id"]


def test_the_registration_carries_the_document_its_epoch_derives_from(
    device_key, anchor, reference
):
    """A member the derivation ignores is refused, never signed in.

    The authority recomputes the epoch from the carried profile, so a document
    that derives one epoch and carries another member would be refused there
    as a mismatch; it is refused here instead.
    """
    supplied = dict(anchor.profile.as_document())
    built = build_anchor_registration(**_kwargs(device_key, anchor, reference))
    assert built["capability_profile"] == supplied
    supplied["ignored"] = "x"
    with pytest.raises(RegistrationError):
        build_anchor_registration(
            **dict(_kwargs(device_key, anchor, reference), capability_profile=supplied)
        )


def test_the_published_registration_identifiers_are_derived(anchor):
    published = case("anchor-registration-v2", "valid")["artifact"]
    assert published["key_id"] == anchor.key_id
    assert published["anchor_epoch_id"] == anchor.anchor_epoch_id


def test_the_vector_reference_is_the_digest_of_the_complete_authorisation(
    reference,
):
    """What the device carries is the authority's resolution key, signature included."""
    authorisation = case("commissioning-authorization", "valid")["artifact"]
    complete = "sha256:" + hashlib.sha256(canonical_json(authorisation)).hexdigest()
    body = {k: v for k, v in authorisation.items() if k != "signature"}
    unsigned = "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()
    assert reference == complete
    assert reference != unsigned


def test_the_registration_carries_exactly_the_contract_field_set(
    device_key, anchor, reference
):
    built = build_anchor_registration(**_kwargs(device_key, anchor, reference))
    assert set(built) == set(REGISTRATION_FIELDS)
    assert built["commissioning_digest"] == reference


def test_it_is_signed_by_the_key_it_registers(device_key, anchor, reference):
    built = build_anchor_registration(**_kwargs(device_key, anchor, reference))
    body = {k: v for k, v in built.items() if k != "signature"}
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(built["pubkey_hex"])).verify(
        base64.b64decode(built["signature"].split("ed25519:")[1]),
        REGISTRATION_DOMAIN + canonical_json(body),
    )


# --------------------------------------------------------------------------
# The reference
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "sha256:",
        "sha256:" + "a" * 63,
        "sha256:" + "a" * 65,
        "sha256:" + "A" * 64,
        "SHA256:" + "a" * 64,
        "sha512:" + "a" * 64,
        "sha256:" + "g" * 64,
        " sha256:" + "a" * 64,
        "sha256:" + "a" * 64 + "\n",
        "sha256:" + "a" * 63 + "\x00",
        "a" * 64,
    ],
)
def test_a_malformed_reference_is_refused(device_key, anchor, bad):
    with pytest.raises(RegistrationError, match="commissioning reference"):
        build_anchor_registration(**_kwargs(device_key, anchor, bad))


def test_the_same_inputs_produce_the_same_bytes(device_key, anchor, reference):
    kwargs = _kwargs(device_key, anchor, reference)
    assert canonical_json(build_anchor_registration(**kwargs)) == canonical_json(
        build_anchor_registration(**kwargs)
    )


def test_a_different_reference_is_a_different_registration(
    device_key, anchor, reference
):
    first = build_anchor_registration(**_kwargs(device_key, anchor, reference))
    second = build_anchor_registration(
        **_kwargs(device_key, anchor, "sha256:" + "1" * 64)
    )
    assert first["signature"] != second["signature"]


def test_a_claimed_epoch_its_inputs_do_not_produce_is_refused(
    device_key, anchor, reference
):
    foreign = derive_runtime_anchor(
        device_id="some-other-device", pubkey_hex=device_key.public_key_hex
    )
    kwargs = _kwargs(device_key, anchor, reference)
    kwargs["anchor_epoch_id"] = foreign.anchor_epoch_id
    with pytest.raises(RegistrationError, match="anchor_epoch_id"):
        build_anchor_registration(**kwargs)


def test_a_claimed_key_id_its_inputs_do_not_produce_is_refused(
    device_key, anchor, reference
):
    foreign = derive_runtime_anchor(
        device_id="some-other-device", pubkey_hex=device_key.public_key_hex
    )
    kwargs = _kwargs(device_key, anchor, reference)
    kwargs["key_id"] = foreign.key_id
    with pytest.raises(RegistrationError, match="key_id"):
        build_anchor_registration(**kwargs)


@pytest.mark.parametrize("missing", ["device_id", "anchor_epoch_id", "key_id"])
def test_the_identity_fields_are_required(device_key, anchor, reference, missing):
    kwargs = _kwargs(device_key, anchor, reference)
    kwargs[missing] = ""
    with pytest.raises(RegistrationError, match="must name"):
        build_anchor_registration(**kwargs)
