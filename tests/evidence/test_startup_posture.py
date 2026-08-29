# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""What a hardened runtime must be able to establish locally before it starts.

Only local, knowable facts: the ledger and key opened, the signed release
shipped authority keys, and custody can be verified when a gateway carries
evidence. Nothing here reaches off the device.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from ori.config import ConfigValidationError
from ori.runtime import _require_evidence_posture


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


def test_an_established_posture_passes():
    _require_evidence_posture(cast(Any, _Cfg()), cast(Any, _Attestor()))


def test_signing_that_did_not_open_refuses_startup():
    with pytest.raises(ConfigValidationError, match="signing is unavailable"):
        _require_evidence_posture(
            cast(Any, _Cfg()), cast(Any, _Attestor(available=False))
        )


def test_a_release_without_authority_keys_refuses_startup():
    with pytest.raises(ConfigValidationError, match="authority-key registry"):
        _require_evidence_posture(cast(Any, _Cfg()), cast(Any, _Attestor(keys=0)))


def test_a_gateway_without_custody_refuses_startup():
    with pytest.raises(ConfigValidationError, match="gateway.custody.secret_env"):
        _require_evidence_posture(
            cast(Any, _Cfg()), cast(Any, _Attestor(custody=False))
        )


def test_custody_is_not_required_without_a_gateway():
    _require_evidence_posture(
        cast(Any, _Cfg(gateway_enabled=False)), cast(Any, _Attestor(custody=False))
    )


def test_the_checks_are_ordered_from_the_inside_out():
    """An unopened ledger is reported before anything that depends on it."""
    with pytest.raises(ConfigValidationError, match="signing is unavailable"):
        _require_evidence_posture(
            cast(Any, _Cfg()),
            cast(Any, _Attestor(available=False, keys=0, custody=False)),
        )
