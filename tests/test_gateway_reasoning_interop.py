# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Gateway-signed reasoning responses verified by this runtime's own verifier.

The fixture is what `ori-gateway`'s dispatcher emitted for a fixed clock and a
published test secret, including confidences on either side of the `1e-4`
boundary where Go and CPython spell a float differently. Verifying each one
here proves the bytes the gateway signs are the bytes this runtime
re-serialises — the inverse of the runtime-signed request fixture the gateway
carries.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
    GatewayMessageAuthError,
)

FIXTURE = (
    pathlib.Path(__file__).parent
    / "fixtures"
    / "gateway_signed_reasoning_responses.json"
)


@pytest.fixture(scope="module")
def corpus() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _verifier(corpus: dict) -> GatewayMessageAuthenticator:
    return GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret=corpus["secret"])
    )


def test_every_gateway_signed_response_verifies_here(corpus):
    names = []
    for case in corpus["cases"]:
        verified = _verifier(corpus).verify(
            case["response"],
            message_type="reasoning_response",
            expected_device_id=corpus["device_id"],
            expected_request_id=case["request_id"],
            now_ms_value=corpus["signed_at_ms"] + 1,
        )
        assert verified["device_id"] == corpus["device_id"]
        assert verified["confidence"] == case["emitted_confidence"], case["name"]
        if case.get("provider_error"):
            assert verified["error"]
        names.append(case["name"])
    assert {
        "below_agreement_zone_rounds_to_zero",
        "half_unit_rounds_up",
        "five_decimals_round_to_four",
        "error_response",
    } <= set(names)


def test_confidence_arrives_in_the_agreement_zone(corpus):
    """Every emitted confidence is exactly 0 or at least 1e-4, so CPython's
    repr and Go's formatting agree and the signature survives re-serialisation."""
    for case in corpus["cases"]:
        emitted = case["response"]["confidence"]
        assert emitted == 0 or emitted >= 1e-4, case["name"]
        assert emitted == round(case["provider_confidence"], 4), case["name"]


@pytest.mark.parametrize(
    "field, value, reason",
    [
        ("text", "forged", "invalid_signature"),
        ("action_tier", "D", "invalid_signature"),
        ("confidence", 0.9999, "invalid_signature"),
        ("device_id", "site-b", "device_mismatch"),
    ],
)
def test_a_forged_field_is_refused(corpus, field, value, reason):
    case = corpus["cases"][2]
    forged = dict(case["response"])
    forged[field] = value
    with pytest.raises(GatewayMessageAuthError, match=reason):
        _verifier(corpus).verify(
            forged,
            message_type="reasoning_response",
            expected_device_id=corpus["device_id"],
            expected_request_id=case["request_id"],
            now_ms_value=corpus["signed_at_ms"] + 1,
        )
