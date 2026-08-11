# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import base64
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.security.aws_kms_release_signer import AwsKmsReleaseSigner
from ori.security.release_bundles import ReleaseBundleError, ReleaseKey

ARN = "arn:aws:kms:eu-west-1:111122223333:key/12345678-1234-1234-1234-1234567890ab"


def _fixture() -> tuple[Ed25519PrivateKey, ReleaseKey, str]:
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = private.public_key()
    raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    der = public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return (
        private,
        ReleaseKey("ori-runtime-release-test", base64.b64encode(raw).decode()),
        base64.b64encode(der).decode(),
    )


def test_signer_validates_immutable_identity_and_signs_raw_message() -> None:
    private, release_key, public_der = _fixture()
    commands: list[Sequence[str]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if "get-public-key" in command:
            output = {"PublicKey": public_der, "SigningAlgorithms": ["ED25519_SHA_512"]}
        else:
            message_arg = command[command.index("--message") + 1]
            message = Path(message_arg.removeprefix("fileb://")).read_bytes()
            output = {"Signature": base64.b64encode(private.sign(message)).decode()}
        return subprocess.CompletedProcess(command, 0, json.dumps(output), "")

    signer = AwsKmsReleaseSigner(
        key_arn=ARN, region="eu-west-1", release_key=release_key, runner=runner
    )
    signer.validate_identity()
    message = b"ori.runtime_release_bundle_signature.v1\0test"
    signature = signer.sign(message)
    private.public_key().verify(signature, message)
    assert "RAW" in commands[1]
    assert "ED25519_SHA_512" in commands[1]


def test_signer_rejects_alias_region_mismatch_and_unvalidated_use() -> None:
    _, release_key, _ = _fixture()
    with pytest.raises(ReleaseBundleError, match="ARN"):
        AwsKmsReleaseSigner(
            key_arn="alias/example-release-key",
            region="eu-west-1",
            release_key=release_key,
        )
    with pytest.raises(ReleaseBundleError, match="region"):
        AwsKmsReleaseSigner(key_arn=ARN, region="us-east-1", release_key=release_key)
    signer = AwsKmsReleaseSigner(
        key_arn=ARN, region="eu-west-1", release_key=release_key
    )
    with pytest.raises(ReleaseBundleError, match="validated"):
        signer.sign(b"message")


def test_signer_rejects_kms_public_key_mismatch() -> None:
    _, release_key, _ = _fixture()
    other = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        output = {
            "PublicKey": base64.b64encode(other).decode(),
            "SigningAlgorithms": ["ED25519_SHA_512"],
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(output), "")

    signer = AwsKmsReleaseSigner(
        key_arn=ARN, region="eu-west-1", release_key=release_key, runner=runner
    )
    with pytest.raises(ReleaseBundleError, match="pinned registry"):
        signer.validate_identity()


def test_signer_wraps_missing_aws_cli() -> None:
    _, release_key, _ = _fixture()

    def runner(_command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("aws")

    signer = AwsKmsReleaseSigner(
        key_arn=ARN, region="eu-west-1", release_key=release_key, runner=runner
    )
    with pytest.raises(ReleaseBundleError, match="could not run"):
        signer.validate_identity()
