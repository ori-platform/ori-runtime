# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""AWS KMS adapter for the external Runtime release-signing boundary."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

from ori.security.release_bundles import ReleaseBundleError, ReleaseKey

_ARN_RE = re.compile(
    r"^arn:aws:kms:(?P<region>[a-z0-9-]+):[0-9]{12}:key/[0-9a-f-]{36}$"
)
_ALGORITHM = "ED25519_SHA_512"

CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class AwsKmsReleaseSigner:
    """Purpose-bound signer that proves KMS identity before first use."""

    def __init__(
        self,
        *,
        key_arn: str,
        region: str,
        release_key: ReleaseKey,
        runner: CommandRunner | None = None,
    ) -> None:
        match = _ARN_RE.fullmatch(key_arn)
        if match is None or match.group("region") != region:
            raise ReleaseBundleError(
                "signing_failed", "KMS key ARN is malformed or region-mismatched"
            )
        if release_key.status != "active":
            raise ReleaseBundleError("signing_failed", "release key must be active")
        self._key_arn = key_arn
        self._region = region
        self._release_key = release_key
        self._runner = runner or _run_aws
        self._validated = False

    def validate_identity(self) -> None:
        """Require KMS public bytes to equal the reviewed registry entry."""
        payload = self._invoke("get-public-key")
        try:
            encoded_public = payload["PublicKey"]
            if not isinstance(encoded_public, str):
                raise TypeError("public key is not a string")
            der = base64.b64decode(encoded_public, validate=True)
            key = load_der_public_key(der)
            if not isinstance(key, Ed25519PublicKey):
                raise TypeError("not Ed25519")
            raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            expected = base64.b64decode(self._release_key.public_key_b64, validate=True)
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise ReleaseBundleError(
                "signing_failed", "KMS returned a malformed public key"
            ) from exc
        if raw != expected:
            raise ReleaseBundleError(
                "signing_failed", "KMS public key does not match pinned registry"
            )
        algorithms = payload.get("SigningAlgorithms")
        if not isinstance(algorithms, list) or _ALGORITHM not in algorithms:
            raise ReleaseBundleError(
                "signing_failed", "KMS key does not permit the required algorithm"
            )
        self._validated = True

    def sign(self, message: bytes) -> bytes:
        """Sign exact domain-separated bytes with standard Ed25519."""
        if not self._validated:
            raise ReleaseBundleError(
                "signing_failed", "KMS identity must be validated before signing"
            )
        with tempfile.TemporaryDirectory(prefix="ori-release-sign-") as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            message_path = directory / "message.bin"
            message_path.write_bytes(message)
            message_path.chmod(0o600)
            payload = self._invoke("sign", message_path=message_path)
        try:
            encoded_signature = payload["Signature"]
            if not isinstance(encoded_signature, str):
                raise TypeError("signature is not a string")
            signature = base64.b64decode(encoded_signature, validate=True)
        except (KeyError, TypeError, binascii.Error) as exc:
            raise ReleaseBundleError(
                "signing_failed", "KMS returned a malformed signature"
            ) from exc
        if len(signature) != 64:
            raise ReleaseBundleError(
                "signing_failed", "KMS returned a non-Ed25519 signature"
            )
        return signature

    def _invoke(
        self, operation: str, *, message_path: Path | None = None
    ) -> dict[str, object]:
        command = [
            "aws",
            "kms",
            operation,
            "--region",
            self._region,
            "--key-id",
            self._key_arn,
        ]
        if operation == "sign":
            if message_path is None:
                raise AssertionError("sign requires message path")
            command.extend(
                [
                    "--signing-algorithm",
                    _ALGORITHM,
                    "--message-type",
                    "RAW",
                    "--message",
                    f"fileb://{message_path}",
                ]
            )
        command.extend(["--output", "json", "--no-cli-pager"])
        try:
            result = self._runner(command)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ReleaseBundleError(
                "signing_failed", "AWS KMS operation could not run"
            ) from exc
        if result.returncode != 0:
            raise ReleaseBundleError("signing_failed", "AWS KMS operation failed")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ReleaseBundleError(
                "signing_failed", "AWS KMS returned invalid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise ReleaseBundleError(
                "signing_failed", "AWS KMS response must be an object"
            )
        return payload


def _run_aws(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "AWS_PAGER": ""}
    return subprocess.run(
        command, capture_output=True, text=True, check=False, env=env, timeout=30
    )
