#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Verify an Android runtime payload on disk before packaging it.

Runs the nine `runtime-mobile/v2` consumer checks against a payload and its
envelope, for the runtime release the caller selected and the ABI slot it is
filling. Neither is read from the envelope; they are what it is checked against.

Exits 0 when the payload may be packaged. Every refusal exits 2 and prints the
stage and reason, including an input that cannot be read, and nothing is
packaged: absence and failure are refusals, never a reason to fall back to a
stub. To fetch payloads from a tagged release and verify them in one step, use
`scripts/verify_published_release.py --android-target`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ori.security.android_payloads import (
    AndroidPayloadError,
    load_payload_key_registry,
    verify_payload,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an Android runtime payload before packaging it."
    )
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--signature", required=True)
    parser.add_argument("--runtime-version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--key-registry", required=True)
    args = parser.parse_args(argv)

    artifact_path = Path(args.artifact)
    try:
        registry = load_payload_key_registry(Path(args.key_registry))
        envelope = Path(args.signature).read_bytes()
        try:
            artifact: bytes | None = artifact_path.read_bytes()
        except FileNotFoundError:
            artifact = None
        verified = verify_payload(
            envelope_text=envelope,
            registry=registry,
            artifact=artifact,
            downloaded_basename=artifact_path.name,
            runtime_version=args.runtime_version,
            target=args.target,
        )
    except AndroidPayloadError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"refused: input could not be read: {exc}", file=sys.stderr)
        return 2

    print(
        f"verified {verified.artifact} {verified.artifact_sha256} "
        f"size={verified.artifact_size} key={verified.key_id} stripped={verified.stripped}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
