#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Hold a staged set of built Android payloads to what a release requires.

Every v2 target must be staged under its published name with its checksum, and
each is signed with a throwaway key through the release's own producer --
refused unless stripped and built at the target's API level -- and then held to
all nine consumer checks. Nothing here is a release signature and the key is
discarded.

Prints each payload's size and digest so a build on one host can be compared
with a build on another, and, per payload, its sections and whatever its
`.comment` section records about the toolchain. Where two hosts disagree on a
digest, that is what distinguishes a different linker or compiler from a
different section layout or a difference inside one section.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.android_payloads import (
    TARGETS,
    AndroidPayloadError,
    create_payload_envelope,
    encode_signature_envelope,
    inspect_payload_build,
    payload_artifact_name,
    payload_sections,
    read_staged_payload,
    verify_payload,
)
from ori.security.release_bundles import ReleaseKey

_KEY_ID = "ori-throwaway-build-check"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Hold a staged set of built Android payloads to what a release requires."
    )
    parser.add_argument("--payload-dir", required=True, type=Path)
    parser.add_argument("--runtime-version", required=True)
    args = parser.parse_args(argv)

    key = Ed25519PrivateKey.generate()
    registry = {
        _KEY_ID: ReleaseKey(
            key_id=_KEY_ID,
            public_key_b64=base64.b64encode(
                key.public_key().public_bytes_raw()
            ).decode(),
            purpose="android_runtime_payload",
            status="active",
        )
    }
    rows = []
    details: list[tuple[str, list[str], list[str]]] = []
    try:
        for target in TARGETS:
            name = payload_artifact_name(args.runtime_version, target)
            data = read_staged_payload(args.payload_dir, name)
            envelope = create_payload_envelope(
                artifact=data,
                artifact_name=name,
                runtime_version=args.runtime_version,
                target=target,
                key_id=_KEY_ID,
                signer=key.sign,
                require_stripped=True,
            )
            verify_payload(
                envelope_text=encode_signature_envelope(envelope),
                registry=registry,
                artifact=data,
                downloaded_basename=name,
                runtime_version=args.runtime_version,
                target=target,
            )
            build = inspect_payload_build(data)
            sections = payload_sections(data)
            comment = next(
                (
                    data[offset : offset + size]
                    for name, offset, size in sections
                    if name == ".comment"
                ),
                b"",
            )
            details.append(
                (
                    target,
                    [f"{name}:{size}" for name, _, size in sections if name],
                    sorted(
                        piece.decode("ascii", "replace")
                        for piece in comment.split(b"\0")
                        if piece
                    ),
                )
            )
            rows.append(
                f"| `{target}` | {len(data):,} | `{hashlib.sha256(data).hexdigest()}` "
                f"| {build.api_level} | {build.stripped} |"
            )
    except (AndroidPayloadError, OSError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    print("| target | bytes | sha256 | API level | stripped |")
    print("|---|---:|---|---:|---|")
    print("\n".join(rows))
    for target, sections, comment in details:
        print(f"\n<details><summary>{target}: sections and toolchain</summary>\n")
        print(f"- toolchain: {'; '.join(comment) or 'no .comment section'}")
        print(f"- sections: `{' '.join(sections)}`")
        print("\n</details>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
