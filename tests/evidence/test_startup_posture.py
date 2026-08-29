# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""What a runtime can establish locally about evidence trust, and reports."""

from __future__ import annotations

from typing import Any, cast

from ori.runtime import (
    EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING,
    EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED,
    EVIDENCE_POSTURE_SIGNING_UNAVAILABLE,
    _evidence_posture_problems,
)


class _Gateway:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled


class _Cfg:
    def __init__(self, *, gateway_enabled: bool = True) -> None:
        self.gateway = _Gateway(gateway_enabled)


class _Attestor:
    def __init__(
        self, *, available: bool = True, keys: int = 2, custody: bool = True
    ) -> None:
        self.available = available
        self.authority_key_count = keys
        self.custody_configured = custody


def _problems(cfg: _Cfg, attestor: _Attestor) -> list[str]:
    return _evidence_posture_problems(cast(Any, cfg), cast(Any, attestor))


def test_an_established_posture_reports_nothing():
    assert _problems(_Cfg(), _Attestor()) == []


def test_each_missing_piece_is_named():
    assert _problems(_Cfg(), _Attestor(available=False)) == [
        EVIDENCE_POSTURE_SIGNING_UNAVAILABLE
    ]
    assert _problems(_Cfg(), _Attestor(keys=0)) == [
        EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING
    ]
    assert _problems(_Cfg(), _Attestor(custody=False)) == [
        EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED
    ]


def test_every_problem_is_reported_not_only_the_first():
    assert _problems(_Cfg(), _Attestor(available=False, keys=0, custody=False)) == [
        EVIDENCE_POSTURE_SIGNING_UNAVAILABLE,
        EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING,
        EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED,
    ]


def test_custody_is_not_required_without_a_gateway():
    assert _problems(_Cfg(gateway_enabled=False), _Attestor(custody=False)) == []
