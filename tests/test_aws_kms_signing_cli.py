# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import json
import runpy
from pathlib import Path
from typing import Any

from ori.security.release_bundles import (
    KEY_REGISTRY_SCHEMA,
    RELEASE_KEY_PURPOSE,
    ReleaseBundleError,
)

VERSION = "2.3.0"
TARGET = "linux-x86_64-python3.12"
KEY_ID = "ori-runtime-release-test"
ARN = "arn:aws:kms:eu-west-1:111122223333:key/12345678-1234-1234-1234-1234567890ab"
ARTIFACT_NAME = f"ori-runtime-{VERSION}-{TARGET}.tar.gz"


def _registry(path: Path, *, status: str = "active") -> None:
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": KEY_ID,
                        "public_key_b64": base64.b64encode(bytes(32)).decode(),
                        "purpose": RELEASE_KEY_PURPOSE,
                        "status": status,
                    }
                ],
                "schema": KEY_REGISTRY_SCHEMA,
            }
        ),
        encoding="utf-8",
    )


def _arguments(tmp_path: Path, registry: Path) -> list[str]:
    return [
        "--artifact",
        str(tmp_path / ARTIFACT_NAME),
        "--runtime-version",
        VERSION,
        "--target",
        TARGET,
        "--key-id",
        KEY_ID,
        "--key-registry",
        str(registry),
        "--kms-key-arn",
        ARN,
        "--aws-region",
        "eu-west-1",
        "--output",
        str(tmp_path / "signature.json"),
    ]


def test_kms_cli_validates_identity_before_signing_and_writes_envelope(
    tmp_path: Path,
) -> None:
    script = runpy.run_path("scripts/sign-release-bundle-aws-kms.py")
    registry = tmp_path / "registry.json"
    _registry(registry)
    (tmp_path / ARTIFACT_NAME).write_bytes(b"artifact")
    calls: list[str] = []

    class FakeSigner:
        def __init__(self, **kwargs: Any) -> None:
            assert kwargs["key_arn"] == ARN
            assert kwargs["region"] == "eu-west-1"

        def validate_identity(self) -> None:
            calls.append("validate")

        def sign(self, _message: bytes) -> bytes:
            calls.append("sign")
            return bytes(64)

    main = script["main"]
    main.__globals__["AwsKmsReleaseSigner"] = FakeSigner
    assert main(_arguments(tmp_path, registry)) == 0
    assert calls == ["validate", "sign"]
    envelope = json.loads((tmp_path / "signature.json").read_text())
    assert envelope["key_id"] == KEY_ID
    assert envelope["runtime_version"] == VERSION
    assert envelope["target"] == TARGET


def test_kms_cli_rejects_non_active_registry_key_before_signer_creation(
    tmp_path: Path,
) -> None:
    script = runpy.run_path("scripts/sign-release-bundle-aws-kms.py")
    registry = tmp_path / "registry.json"
    _registry(registry, status="verify_only")
    (tmp_path / ARTIFACT_NAME).write_bytes(b"artifact")

    class UnexpectedSigner:
        def __init__(self, **_kwargs: Any) -> None:
            raise AssertionError("signer must not be created")

    main = script["main"]
    main.__globals__["AwsKmsReleaseSigner"] = UnexpectedSigner
    assert main(_arguments(tmp_path, registry)) == 2
    assert not (tmp_path / "signature.json").exists()


def test_kms_cli_maps_identity_failure_to_exit_two(tmp_path: Path) -> None:
    script = runpy.run_path("scripts/sign-release-bundle-aws-kms.py")
    registry = tmp_path / "registry.json"
    _registry(registry)
    (tmp_path / ARTIFACT_NAME).write_bytes(b"artifact")

    class FailingSigner:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def validate_identity(self) -> None:
            raise ReleaseBundleError("signing_failed", "identity mismatch")

    main = script["main"]
    main.__globals__["AwsKmsReleaseSigner"] = FailingSigner
    assert main(_arguments(tmp_path, registry)) == 2
    assert not (tmp_path / "signature.json").exists()
