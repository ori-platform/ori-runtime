# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime's Ed25519 verification reaches every verdict of ed25519-verification/v1.

Every public key the runtime verifies under passes `admit_public_key`, and the
key it returns is the one whose `verify` each consumer calls, so a case driven
through those two calls is driven through the verifier every consumer uses.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ori.security.ed25519_keys import RefusedPublicKeyError, admit_public_key

CORPUS = (
    Path(__file__).resolve().parent
    / "vectors"
    / "ed25519_verification"
    / "vectors-v1.json"
)
#: The corpus this test was written for; a change in size is a change to review.
CASES = 295


def _cases() -> list[tuple[str, dict[str, Any]]]:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    return [
        (section, case)
        for section, cases in corpus.items()
        if isinstance(cases, list)
        for case in cases
    ]


def _accepted_by_the_runtime(case: dict[str, Any]) -> bool:
    try:
        key = admit_public_key(bytes.fromhex(case["public_key_hex"]))
    except RefusedPublicKeyError:
        return False
    try:
        key.verify(
            bytes.fromhex(case["signature_hex"]), bytes.fromhex(case["message_hex"])
        )
    except InvalidSignature:
        return False
    return True


def _accepted_without_admission(case: dict[str, Any]) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(case["public_key_hex"]))
        key.verify(
            bytes.fromhex(case["signature_hex"]), bytes.fromhex(case["message_hex"])
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def test_the_corpus_is_the_one_this_test_was_written_for() -> None:
    assert len(_cases()) == CASES


@pytest.mark.parametrize(
    ("section", "case"),
    _cases(),
    ids=[f"{section}-{index}" for index, (section, _) in enumerate(_cases())],
)
def test_the_runtime_reaches_the_contract_verdict(
    section: str, case: dict[str, Any]
) -> None:
    accepted = _accepted_by_the_runtime(case)
    assert accepted is (case["expected"] == "accepted"), (section, case["why"])


def test_admission_is_what_refuses_the_refused_keys() -> None:
    # OpenSSL alone accepts a signature under a key admission refuses; the
    # runtime's verdict on those cases rests on admission running first.
    refused_keys = [case for section, case in _cases() if section == "refused_keys"]
    accepted_alone = [
        case for case in refused_keys if _accepted_without_admission(case)
    ]
    assert accepted_alone, "no refused-key case separates admission from OpenSSL"
    assert not any(_accepted_by_the_runtime(case) for case in accepted_alone)
