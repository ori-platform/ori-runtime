#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Sign every Android runtime payload of a release through a purpose-bound KMS key.

The KMS transport is the release-bundle one; the protocol is not. The envelope,
domain separator and registry are `runtime-mobile/v2`'s, so a payload signature
cannot verify as a bundle signature.

The directory must hold each v2 target's payload under its published name with
the `.sha256` staged beside it. The expected set comes from the contract's
target list, never from what the directory happens to hold, so a payload that
failed to build cannot be left quietly unsigned. Each payload must be stripped,
as measured from its bytes, and must record the target's API level. Every
envelope is verified offline against the pinned registry before any is written,
so a run either writes the complete set or none of it.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from ori.security.android_payloads import (
    TARGETS,
    AndroidPayloadError,
    create_payload_envelope,
    encode_signature_envelope,
    load_payload_key_registry,
    payload_artifact_name,
    read_staged_payload,
    verify_payload,
)
from ori.security.aws_kms_release_signer import AwsKmsReleaseSigner
from ori.security.release_bundles import ReleaseBundleError


def _write_atomically(path: Path, content: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sign every Android runtime payload of a release through KMS."
    )
    parser.add_argument("--payload-dir", required=True)
    parser.add_argument("--runtime-version", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--key-registry", required=True)
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--aws-region", required=True)
    args = parser.parse_args(argv)

    directory = Path(args.payload_dir)
    try:
        registry = load_payload_key_registry(Path(args.key_registry))
        key = registry.get(args.key_id)
        if key is None or key.status != "active":
            print(
                "signing key must be active in the pinned payload registry",
                file=sys.stderr,
            )
            return 2
        names = {
            target: payload_artifact_name(args.runtime_version, target)
            for target in TARGETS
        }
        staged = {
            target: read_staged_payload(directory, name)
            for target, name in names.items()
        }
        signer = AwsKmsReleaseSigner(
            key_arn=args.kms_key_arn,
            region=args.aws_region,
            release_key=key,
        )
        signer.validate_identity()
        envelopes: dict[str, bytes] = {}
        for target, data in staged.items():
            envelope = create_payload_envelope(
                artifact=data,
                artifact_name=names[target],
                runtime_version=args.runtime_version,
                target=target,
                key_id=args.key_id,
                signer=signer.sign,
                require_stripped=True,
            )
            encoded = encode_signature_envelope(envelope)
            verify_payload(
                envelope_text=encoded,
                registry=registry,
                artifact=data,
                downloaded_basename=names[target],
                runtime_version=args.runtime_version,
                target=target,
            )
            envelopes[target] = encoded
    except (AndroidPayloadError, ReleaseBundleError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        for target, encoded in envelopes.items():
            _write_atomically(directory / f"{names[target]}.signature.json", encoded)
            print(f"signed {names[target]}")
    except OSError as exc:
        print(f"could not write signature envelopes: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
