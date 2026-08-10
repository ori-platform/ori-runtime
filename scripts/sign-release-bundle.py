#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Sign an exact Runtime release bundle in an isolated signing environment."""

from __future__ import annotations

import argparse
import base64
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)

from ori.security.release_bundles import (
    ReleaseBundleError,
    create_signature_envelope,
    load_release_key_registry,
    write_signature_envelope,
)


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    fd = -1
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(path, flags)
        file_stat = os.fstat(fd)
    except OSError as exc:
        raise ReleaseBundleError("signing_failed", "cannot inspect private key") from exc
    try:
        if not stat.S_ISREG(file_stat.st_mode):
            raise ReleaseBundleError(
                "signing_failed", "private key must be a regular file"
            )
        if file_stat.st_mode & 0o077:
            raise ReleaseBundleError(
                "signing_failed",
                "private key permissions must not grant group or other access",
            )
        if file_stat.st_size <= 0 or file_stat.st_size > 64 * 1024:
            raise ReleaseBundleError(
                "signing_failed", "private key file size is outside bounds"
            )
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            key_bytes = handle.read(64 * 1024 + 1)
        key = load_pem_private_key(key_bytes, password=None)
    except ReleaseBundleError:
        raise
    except Exception as exc:
        raise ReleaseBundleError(
            "signing_failed", "private key is not an unencrypted PEM key"
        ) from exc
    finally:
        if fd != -1:
            os.close(fd)
    if not isinstance(key, Ed25519PrivateKey):
        raise ReleaseBundleError(
            "signing_failed", "private key must be a dedicated Ed25519 key"
        )
    return key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sign an Ori Runtime release bundle with a dedicated Ed25519 key."
    )
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--runtime-version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--key-registry", required=True)
    parser.add_argument("--private-key-file", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(
            "signing_failed: local private-key signing is forbidden in GitHub Actions; "
            "use the approved external signing system",
            file=sys.stderr,
        )
        return 2

    try:
        registry = load_release_key_registry(args.key_registry)
        release_key = registry.get(args.key_id)
        if release_key is None or release_key.status != "active":
            raise ReleaseBundleError(
                "signing_failed", "signing key must be active in the pinned registry"
            )
        private_key = _load_private_key(Path(args.private_key_file))
        public_key_b64 = base64.b64encode(
            private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii")
        if public_key_b64 != release_key.public_key_b64:
            raise ReleaseBundleError(
                "signing_failed", "private key does not match the pinned active key"
            )
        envelope = create_signature_envelope(
            artifact_path=args.artifact,
            runtime_version=args.runtime_version,
            target=args.target,
            key_id=args.key_id,
            signer=private_key.sign,
        )
        write_signature_envelope(args.output, envelope)
    except ReleaseBundleError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
