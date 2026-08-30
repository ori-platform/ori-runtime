# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Drive the runtime's binding verifier over the golden corpus, standalone.

The verifier itself lives in ``ori.security.commissioning.binding``: it is the
runtime's consumer of the contract, written from the contract text and sharing
no code with the generator beside this file. This module keeps the corpus
shapes — a ``verifier_context`` dict per case — and the command-line entry
point, and it exists so the corpus can be checked without pytest.

    python tests/golden/verify_commissioned_binding_vectors.py CORPUS
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from typing import Any

from ori.security.commissioning.binding import (
    ORDER,
    PROFILE_ORDER,
    BindingRefusedError,
    ProfileContext,
    VerifierContext,
    canonical_bytes,
    parse_document,
    parse_envelope,
    verify_binding,
    verify_firmware_profile,
)

RefusedError = BindingRefusedError
cbytes = canonical_bytes

__all__ = [
    "PROFILE_ORDER",
    "RefusedError",
    "cbytes",
    "run",
    "run_raw",
    "run_envelope",
    "run_profile",
    "run_profile_envelope",
]


def run(b: Any, ctx: dict[str, Any], sig_b64: str) -> None:
    verify_binding(b, VerifierContext.from_corpus(ctx), sig_b64)


def run_profile(pr: Any, ctx: dict[str, Any], sig_b64: str) -> None:
    verify_firmware_profile(pr, ProfileContext.from_corpus(ctx), sig_b64)


def run_envelope(envelope: Any, ctx: dict[str, Any]) -> None:
    binding, sig_b64 = parse_envelope(envelope, "binding")
    run(binding, ctx, sig_b64)


def run_profile_envelope(envelope: Any, ctx: dict[str, Any]) -> None:
    profile, sig_b64 = parse_envelope(envelope, "firmware_profile")
    run_profile(profile, ctx, sig_b64)


def run_raw(envelope_bytes: bytes, ctx: dict[str, Any]) -> None:
    """The bytes entry point, which is the one a device uses.

    A raw case says nothing when fed through a decoded-object entry point: the
    decode is the step under test.
    """
    document = parse_document(envelope_bytes.decode("utf-8"))
    run_envelope(document, ctx)


def main(path: str) -> int:
    corpus = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    failures: list[str] = []

    for c in corpus["cases"] + corpus["reject_cases"]:
        b, name = c["binding"], c["name"]
        if cbytes(b).hex() != c["canonical_hex"]:
            failures.append(f"{name}: canonical_hex does not reproduce")
        if "sha256:" + hashlib.sha256(cbytes(b)).hexdigest() != c["canonical_sha256"]:
            failures.append(f"{name}: canonical_sha256 wrong")
        env = {"binding": b, "signature": "ed25519:" + c["signature_b64"]}
        if cbytes(env).hex() != c["message_hex"]:
            failures.append(f"{name}: message_hex does not reproduce")

    for c in corpus["cases"]:
        try:
            run(c["binding"], c["verifier_context"], c["signature_b64"])
        except RefusedError as r:
            failures.append(
                f"{c['name']}: accept case refused at {r.stage} ({r.reason})"
            )

    for c in corpus["reject_cases"]:
        name = c["name"]
        try:
            run(c["binding"], c["verifier_context"], c["signature_b64"])
        except RefusedError as r:
            if r.reason != c["reason"] or r.stage != c.get("stage"):
                failures.append(
                    f"{name}: refused {r.reason!r}@{r.stage}, declared "
                    f"{c['reason']!r}@{c.get('stage')}"
                )
            decided_after_sig = ORDER.index(r.stage) > ORDER.index("signature")
            if c["signature_valid"] and r.stage == "signature":
                failures.append(
                    f"{name}: signature_valid true but refused at signature"
                )
            if not c["signature_valid"] and decided_after_sig:
                failures.append(
                    f"{name}: signature_valid false but refused after signature"
                )
        else:
            failures.append(f"{name}: reject case was ACCEPTED")

    for c in corpus.get("firmware_profile_cases", []):
        pr = c["firmware_profile"]
        if cbytes(pr).hex() != c["canonical_hex"]:
            failures.append(f"{c['name']}: profile canonical_hex does not reproduce")
        try:
            run_profile(pr, c["verifier_context"], c["signature_b64"])
        except RefusedError as r:
            failures.append(
                f"{c['name']}: accept profile refused at {r.stage} ({r.reason})"
            )

    for c in corpus.get("firmware_profile_reject_cases", []):
        pr = c["firmware_profile"]
        if cbytes(pr).hex() != c["canonical_hex"]:
            failures.append(f"{c['name']}: profile canonical_hex does not reproduce")
        try:
            run_profile(pr, c["verifier_context"], c["signature_b64"])
        except RefusedError as r:
            if r.reason != c["reason"] or r.stage != c.get("stage"):
                failures.append(
                    f"{c['name']}: refused {r.reason!r}@{r.stage}, declared "
                    f"{c['reason']!r}@{c.get('stage')}"
                )
            decided_after_sig = PROFILE_ORDER.index(r.stage) > PROFILE_ORDER.index(
                "signature"
            )
            if "signature_valid" not in c:
                failures.append(f"{c['name']}: reject profile has no signature_valid")
            elif c["signature_valid"] and r.stage == "signature":
                failures.append(
                    f"{c['name']}: signature_valid true but refused at signature"
                )
            elif not c["signature_valid"] and decided_after_sig:
                failures.append(
                    f"{c['name']}: signature_valid false but refused after signature"
                )
        else:
            failures.append(f"{c['name']}: reject profile was ACCEPTED")

    for c in corpus.get("envelope_reject_cases", []):
        runner = run_envelope if "binding" in c["envelope"] else run_profile_envelope
        try:
            runner(c["envelope"], c["verifier_context"])
        except RefusedError as r:
            if r.reason != c["reason"] or r.stage != c["stage"]:
                failures.append(
                    f"{c['name']}: refused {r.reason!r}@{r.stage}, declared "
                    f"{c['reason']!r}@{c['stage']}"
                )
        except Exception as exc:  # noqa: BLE001 - the property under test
            failures.append(
                f"{c['name']}: raised {type(exc).__name__} instead of a verdict"
            )
        else:
            failures.append(f"{c['name']}: envelope reject case was ACCEPTED")

    for c in corpus.get("raw_reject_cases", []):
        try:
            run_raw(bytes.fromhex(c["envelope_hex"]), c["verifier_context"])
        except RefusedError as r:
            if r.reason != c["reason"] or r.stage != c["stage"]:
                failures.append(
                    f"{c['name']}: refused {r.reason!r}@{r.stage}, declared "
                    f"{c['reason']!r}@{c['stage']}"
                )
        except Exception as exc:  # noqa: BLE001 - the property under test
            failures.append(
                f"{c['name']}: raised {type(exc).__name__} instead of a verdict"
            )
        else:
            failures.append(f"{c['name']}: raw reject case was ACCEPTED")

    for failure in failures:
        print("FAIL", failure)
    print(
        f"\n{len(corpus['cases'])} accept, {len(corpus['reject_cases'])} reject, "
        f"{len(corpus.get('firmware_profile_cases', []))} profile accept, "
        f"{len(corpus.get('firmware_profile_reject_cases', []))} profile reject, "
        f"{len(corpus.get('envelope_reject_cases', []))} envelope reject, "
        f"{len(corpus.get('raw_reject_cases', []))} raw reject, "
        f"{len(failures)} failures"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
