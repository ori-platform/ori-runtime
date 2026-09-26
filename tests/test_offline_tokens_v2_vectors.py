# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime's token verifiers against the offline-tokens/v2 signing-domain corpus.

Every case carries a real Ed25519 signature under the corpus's published test
key. A v1 verifier verifies over the unprefixed preimage and reads no version;
a v2 verifier reads the exact `token_version` first and verifies in its domain
only then. The binding sequences are replayed with the admission sequences in
`tests/test_tier_c_approval_sequences.py`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from ori.security import offline_tokens as tokens

VECTOR_DIR = Path(__file__).parent / "vectors" / "offline_tokens"
DOMAIN = json.loads((VECTOR_DIR / "signing-domain-v2.json").read_text())
KEY = DOMAIN["public_key_b64"]


def test_corpus_is_the_published_artifact_at_the_pinned_revision() -> None:
    manifest = json.loads((VECTOR_DIR / "MANIFEST.json").read_text())
    assert manifest["source_repository"] == "ori-platform/ori-specs"
    assert set(manifest["files"]) == {
        path.name for path in VECTOR_DIR.glob("*.json") if path.name != "MANIFEST.json"
    }
    for name, recorded in manifest["files"].items():
        assert (
            hashlib.sha256((VECTOR_DIR / name).read_bytes()).hexdigest() == recorded
        ), f"the vendored {name} has been edited locally; re-vendor it"


def test_the_corpus_key_is_refused_as_a_trust_anchor() -> None:
    """The seed is published, so a device configured with it approves nothing."""
    verifier = tokens.OfflineTierCTokenVerifier(public_key_b64=KEY)
    case = DOMAIN["cases"][0]
    result = verifier.verify_tier_c_token(
        json.dumps(case["token"]),
        proposal=tokens.ProposalClaims(
            proposal_id="AB12CD34",
            device_id="energy-monitor-ikeja-01",
            action="trip_relay",
            target="relay-gpio-26",
            zone_id="zone-feeder-a",
        ),
    )
    assert result.approved is False
    assert result.reason == "trust_anchor_published"


def _raw(case: dict[str, Any]) -> str:
    if "token_text" in case:
        return str(case["token_text"])
    return json.dumps(case["token"], ensure_ascii=False)


@pytest.mark.parametrize("case", DOMAIN["cases"], ids=lambda c: c["name"])
def test_signing_domain(case: dict[str, Any]) -> None:
    raw = _raw(case)
    expected = case["expected"]

    assert tokens.v2_verdict(raw, KEY) == expected["v2"]

    try:
        payload = tokens.decode_token_text(raw)
    except tokens.DuplicateMemberError:
        payload = None
    if payload is None:
        # A v1 verifier decodes with the last occurrence and verifies over it;
        # the corpus records only that its signature does not hold.
        assert expected["v1"] == "refuse:signature"
        return
    v1 = "accept" if tokens.v1_signature_valid(payload, KEY) else "refuse:signature"
    assert v1 == expected["v1"]
    domain = "valid" if tokens.v2_domain_signature_valid(payload, KEY) else "invalid"
    assert domain == expected["v2_domain_signature"]


@pytest.mark.parametrize(
    ("text", "version"),
    [
        ('{"token_version": 2}', 2),
        ('{"token_version": 2.0}', None),
        ('{"token_version": 2e0}', None),
        ('{"token_version": "2"}', None),
        ('{"token_version": true}', None),
        ('{"token_version": 3}', None),
        ("{}", 1),
    ],
)
def test_the_version_is_read_from_the_number_token(
    text: str, version: int | None
) -> None:
    payload = tokens.decode_token_text(text)
    assert payload is not None
    assert tokens.token_version(payload) == version


def test_a_member_named_twice_at_any_depth_is_refused() -> None:
    with pytest.raises(tokens.DuplicateMemberError):
        tokens.decode_token_text('{"a": {"b": 1, "b": 2}}')


def _fresh_key() -> tuple[Any, str]:
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode("ascii")
    return key, public


def _signed(key: Any, claims: dict[str, Any]) -> str:
    import base64

    from ori.skills.signing import canonical_signed_payload

    payload = dict(claims)
    signature = key.sign(
        tokens.V2_SIGNATURE_DOMAIN + b"\x00" + canonical_signed_payload(payload)
    )
    payload["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return json.dumps(payload)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"token_id": "tok\x00-1"}, "malformed_token_id"),
        ({"token_id": "tok\x7f"}, "malformed_token_id"),
        (
            {"issued_at": 1_787_000_400, "expires_at": 1_787_000_300},
            "invalid_timestamp",
        ),
    ],
)
def test_a_malformed_identifier_or_an_inverted_window_is_refused(
    change: dict[str, Any], reason: str, monkeypatch: Any
) -> None:
    monkeypatch.setattr(tokens, "now_ms", lambda: 1_787_000_100_000)
    key, public = _fresh_key()
    claims = {
        "token_version": 2,
        "token_id": "tok-1",
        "device_id": "energy-monitor-ikeja-01",
        "proposal_id": "AB12CD34",
        "action_scope": "trip_relay",
        "target": "relay-gpio-26",
        "zone_id": "zone-feeder-a",
        "issued_at": 1_787_000_000,
        "expires_at": 1_787_000_300,
        "nonce": "n-1",
        **change,
    }
    verifier = tokens.OfflineTierCTokenVerifier(public_key_b64=public)
    proposal = tokens.ProposalClaims(
        proposal_id="AB12CD34",
        device_id="energy-monitor-ikeja-01",
        action="trip_relay",
        target="relay-gpio-26",
        zone_id="zone-feeder-a",
    )
    assert (
        verifier.verify_tier_c_token(_signed(key, claims), proposal=proposal).reason
        == reason
    )
    sound = {
        **claims,
        "token_id": "tok-1",
        "issued_at": 1_787_000_000,
        "expires_at": 1_787_000_300,
    }
    assert (
        verifier.verify_tier_c_token(_signed(key, sound), proposal=proposal).approved
        is True
    )
