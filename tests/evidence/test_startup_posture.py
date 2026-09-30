# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""What a runtime can establish locally about evidence trust, and reports."""

from __future__ import annotations

from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.runtime import (
    EVIDENCE_POSTURE_AUTHORITY_KEYS_INCOMPLETE,
    EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING,
    EVIDENCE_POSTURE_AUTHORITY_KEYS_REFUSED,
    EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED,
    EVIDENCE_POSTURE_SIGNING_UNAVAILABLE,
    _evidence_posture_problems,
)
from ori.security.evidence.authority_keys import (
    PURPOSE_DISPOSITION,
    PURPOSE_EPOCH,
    PURPOSE_RECEIPT,
    VERIFIED_PURPOSES,
    AuthorityKey,
    derive_key_id,
    parse_authority_key_registry,
)
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor


class _Gateway:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled


class _Cfg:
    def __init__(self, *, gateway_enabled: bool = True) -> None:
        self.gateway = _Gateway(gateway_enabled)


def _registry(*purposes: str) -> dict[tuple[str, str], AuthorityKey]:
    """A registry the contract accepts, one active key per purpose."""
    if not purposes:
        return {}
    keys = []
    for purpose in purposes:
        raw = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        keys.append(
            {
                "key_id": derive_key_id(raw),
                "public_key_hex": raw.hex(),
                "purpose": purpose,
                "status": "active",
            }
        )
    return parse_authority_key_registry(
        {"schema": "ori.evidence_authority_keys.v1", "keys": keys}
    )


class _Attestor:
    """The posture surface of the attestor, driven by the real purpose coverage."""

    def __init__(
        self,
        *,
        available: bool = True,
        purposes: tuple[str, ...] = (PURPOSE_RECEIPT, PURPOSE_EPOCH),
        refused: bool = False,
        custody: bool = True,
    ) -> None:
        real = FirstPartyEvidenceAttestor(
            db_path=":memory:",
            key_path="unused.key",
            device_secret="unused",
            device_id="dev",
            authority_keys=_registry(*purposes),
            authority_keys_refused=refused,
        )
        self.available = available
        self.verifying_authority_purposes = real.verifying_authority_purposes
        self.authority_keys_refused = real.authority_keys_refused
        self.custody_configured = custody


def _problems(cfg: _Cfg, attestor: _Attestor) -> list[str]:
    return _evidence_posture_problems(cast(Any, cfg), cast(Any, attestor))


def test_an_established_posture_reports_nothing():
    assert _problems(_Cfg(), _Attestor()) == []


def test_the_release_requires_receipt_and_epoch_and_not_disposition():
    assert VERIFIED_PURPOSES == {PURPOSE_RECEIPT, PURPOSE_EPOCH}


@pytest.mark.parametrize("missing", [PURPOSE_RECEIPT, PURPOSE_EPOCH])
def test_each_missing_required_purpose_is_incomplete(missing):
    held = tuple(p for p in (PURPOSE_RECEIPT, PURPOSE_EPOCH) if p != missing)
    assert _problems(_Cfg(), _Attestor(purposes=held)) == [
        EVIDENCE_POSTURE_AUTHORITY_KEYS_INCOMPLETE
    ]
    # A disposition key does not stand in for a purpose the release verifies.
    held_with_disposition = (*held, PURPOSE_DISPOSITION)
    assert _problems(_Cfg(), _Attestor(purposes=held_with_disposition)) == [
        EVIDENCE_POSTURE_AUTHORITY_KEYS_INCOMPLETE
    ]


def test_a_disposition_only_registry_is_incomplete():
    assert _problems(_Cfg(), _Attestor(purposes=(PURPOSE_DISPOSITION,))) == [
        EVIDENCE_POSTURE_AUTHORITY_KEYS_INCOMPLETE
    ]


def test_disposition_is_not_required_while_no_verifier_is_installed():
    all_three = (PURPOSE_RECEIPT, PURPOSE_EPOCH, PURPOSE_DISPOSITION)
    assert _problems(_Cfg(), _Attestor(purposes=all_three)) == []
    assert _problems(_Cfg(), _Attestor(purposes=(PURPOSE_RECEIPT, PURPOSE_EPOCH))) == []


def test_a_revoked_key_does_not_count_as_coverage():
    registry = _registry(PURPOSE_RECEIPT, PURPOSE_EPOCH)
    epoch_id = next(key_id for purpose, key_id in registry if purpose == PURPOSE_EPOCH)
    registry[(PURPOSE_EPOCH, epoch_id)] = AuthorityKey(
        key_id=epoch_id,
        public_key_hex=registry[(PURPOSE_EPOCH, epoch_id)].public_key_hex,
        purpose=PURPOSE_EPOCH,
        status="revoked",
    )
    attestor = FirstPartyEvidenceAttestor(
        db_path=":memory:",
        key_path="unused.key",
        device_secret="unused",
        device_id="dev",
        authority_keys=registry,
    )
    assert attestor.verifying_authority_purposes == {PURPOSE_RECEIPT}


def test_absent_refused_and_incomplete_are_distinct():
    assert _problems(_Cfg(), _Attestor(purposes=())) == [
        EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING
    ]
    assert _problems(_Cfg(), _Attestor(purposes=(), refused=True)) == [
        EVIDENCE_POSTURE_AUTHORITY_KEYS_REFUSED
    ]


def test_each_missing_piece_is_named():
    assert _problems(_Cfg(), _Attestor(available=False)) == [
        EVIDENCE_POSTURE_SIGNING_UNAVAILABLE
    ]
    assert _problems(_Cfg(), _Attestor(custody=False)) == [
        EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED
    ]


def test_every_problem_is_reported_not_only_the_first():
    assert _problems(
        _Cfg(), _Attestor(available=False, purposes=(), custody=False)
    ) == [
        EVIDENCE_POSTURE_SIGNING_UNAVAILABLE,
        EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING,
        EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED,
    ]


def test_custody_is_not_required_without_a_gateway():
    assert _problems(_Cfg(gateway_enabled=False), _Attestor(custody=False)) == []
