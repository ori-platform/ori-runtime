#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Sign an Ori Runtime release bundle through a purpose-bound AWS KMS key."""

from __future__ import annotations

import argparse
import sys

from ori.security.aws_kms_release_signer import AwsKmsReleaseSigner
from ori.security.release_bundles import (
    ReleaseBundleError,
    create_signature_envelope,
    load_release_key_registry,
    write_signature_envelope,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sign an Ori Runtime release bundle with an immutable AWS KMS key."
    )
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--runtime-version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--key-registry", required=True)
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--aws-region", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    try:
        registry = load_release_key_registry(args.key_registry)
        release_key = registry.get(args.key_id)
        if release_key is None or release_key.status != "active":
            raise ReleaseBundleError(
                "signing_failed", "signing key must be active in the pinned registry"
            )
        signer = AwsKmsReleaseSigner(
            key_arn=args.kms_key_arn,
            region=args.aws_region,
            release_key=release_key,
        )
        signer.validate_identity()
        envelope = create_signature_envelope(
            artifact_path=args.artifact,
            runtime_version=args.runtime_version,
            target=args.target,
            key_id=args.key_id,
            signer=signer.sign,
        )
        write_signature_envelope(args.output, envelope)
    except ReleaseBundleError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
