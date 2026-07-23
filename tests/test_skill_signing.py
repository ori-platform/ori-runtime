# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.skills.sandbox import SkillSecurityError
from ori.skills.signing import canonical_signed_payload, verify_signed_payload

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "skill_signing_vectors.json"
FIXTURE_SHA256 = "13832babac98468ddd368aafd04c5140bba771f568500c50d4bac60c8588fddc"


def _signature_bytes(value: str) -> bytes:
    scheme, encoded = value.split(":", 1)
    assert scheme == "ed25519"
    return base64.b64decode(encoded, validate=True)


def test_shared_skill_signing_fixture_digest_and_profiles() -> None:
    raw_fixture = FIXTURE_PATH.read_bytes()
    assert hashlib.sha256(raw_fixture).hexdigest() == FIXTURE_SHA256
    fixture = json.loads(raw_fixture)

    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(fixture["public_key_b64"], validate=True)
    )
    private_key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(fixture["private_seed_b64"], validate=True)
    )
    assert (
        base64.b64encode(
            private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii")
        == fixture["public_key_b64"]
    )
    manifest = fixture["manifest_profile"]
    artifact = fixture["artifact_profile"]

    canonical_manifest = canonical_signed_payload(manifest["parsed_skill"])
    expected_manifest = base64.b64decode(
        manifest["canonical_unsigned_b64"], validate=True
    )
    assert canonical_manifest == expected_manifest
    assert (
        hashlib.sha256(canonical_manifest).hexdigest()
        == manifest["canonical_unsigned_sha256"]
    )

    artifact_bytes = base64.b64decode(artifact["artifact_bytes_b64"], validate=True)
    assert (
        "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
        == artifact["artifact_sha256"]
    )
    assert (
        artifact["detached_metadata"]["artifact_sha256"] == artifact["artifact_sha256"]
    )
    assert artifact["detached_metadata"]["signature"] == artifact["signature"]

    manifest_signature = _signature_bytes(manifest["signature"])
    artifact_signature = _signature_bytes(artifact["signature"])
    assert private_key.sign(canonical_manifest) == manifest_signature
    assert private_key.sign(artifact_bytes) == artifact_signature
    public_key.verify(manifest_signature, canonical_manifest)
    public_key.verify(artifact_signature, artifact_bytes)

    with pytest.raises(InvalidSignature):
        public_key.verify(manifest_signature, artifact_bytes)
    with pytest.raises(InvalidSignature):
        public_key.verify(artifact_signature, canonical_manifest)
    with pytest.raises(InvalidSignature):
        public_key.verify(manifest_signature, canonical_manifest + b" ")
    with pytest.raises(InvalidSignature):
        public_key.verify(artifact_signature, artifact_bytes + b" ")


@pytest.mark.parametrize(
    "payload, message",
    [
        ({"value": float("nan")}, "non-finite number"),
        ({"value": float("inf")}, "non-finite number"),
        ({1: "not-a-string-key"}, "non-string object key"),
        ({"value": object()}, "non-JSON value"),
    ],
)
def test_canonical_signed_payload_rejects_non_json_values(
    payload: dict[object, object],
    message: str,
) -> None:
    with pytest.raises(SkillSecurityError, match=message):
        canonical_signed_payload(payload)  # type: ignore[arg-type]


def test_canonical_signed_payload_rejects_cycles() -> None:
    payload: dict[str, object] = {}
    payload["cycle"] = payload

    with pytest.raises(SkillSecurityError, match="contains a cycle"):
        canonical_signed_payload(payload)


@pytest.mark.parametrize(
    "signature",
    [
        "ED25519:"
        "mbOGxjLsq0V9uC/dDy7zYi9OqZlcx/OXmPMs9euY6DTuydpSAxFQA17RBpzkoep4"
        "IFOcoT715yO3HymxC3VUDg==",
        "ed25519:"
        "mbOGxjLsq0V9uC/dDy7zYi9OqZlcx/OXmPMs9euY6DTuydpSAxFQA17RBpzkoep4"
        "IFOcoT715yO3HymxC3VUDh==",
    ],
)
def test_verifier_rejects_noncanonical_signature_encoding(signature: str) -> None:
    with pytest.raises(SkillSecurityError):
        verify_signed_payload(
            {"name": "ori-signing-vector", "signature": signature},
            "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
        )


def test_verifier_rejects_noncanonical_public_key_encoding() -> None:
    fixture = json.loads(FIXTURE_PATH.read_bytes())
    manifest = fixture["manifest_profile"]
    signed_manifest = dict(manifest["parsed_skill"])
    signed_manifest["signature"] = manifest["signature"]

    with pytest.raises(SkillSecurityError, match="non-canonical base64"):
        verify_signed_payload(
            signed_manifest,
            "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbh=",
        )


def test_verifier_rejects_wrong_signature_and_public_key_lengths() -> None:
    fixture = json.loads(FIXTURE_PATH.read_bytes())
    manifest = fixture["manifest_profile"]
    signed_manifest = dict(manifest["parsed_skill"])
    signed_manifest["signature"] = manifest["signature"]

    with pytest.raises(SkillSecurityError, match="exactly 64 bytes"):
        verify_signed_payload(
            {"name": "short-signature", "signature": "ed25519:AA=="},
            fixture["public_key_b64"],
        )
    with pytest.raises(SkillSecurityError, match="exactly 32 bytes"):
        verify_signed_payload(
            signed_manifest,
            "AA==",
        )
