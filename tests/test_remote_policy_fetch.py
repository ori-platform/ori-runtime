# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import base64
import time

import pytest

from ori.policy.remote_fetch import (
    RemotePolicyFetchError,
    fetch_remote_device_policy,
)
from ori.skills.signing import canonical_signed_payload

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except Exception:  # pragma: no cover - environment without cryptography support
    Ed25519PrivateKey = None
    Encoding = None
    PublicFormat = None


def _base_config(public_key_b64: str) -> dict:
    return {
        "enabled": True,
        "url": "https://example.com/device-policy",
        "auth_token": "test-token",
        "public_key_b64": public_key_b64,
        "request_timeout_ms": 3000,
        "max_clock_skew_s": 300,
    }


def _signed_payload(private_key, **overrides) -> dict:
    payload = {
        "tier": "cloud",
        "relay_b_enabled": True,
        "relay_c_enabled": True,
        "cloud_llm_enabled": True,
        "valid_until": int(time.time()) + 3600,
        "policy_version": 2,
        "issued_at": int(time.time()) - 10,
        "timestamp": int(time.time()),
    }
    payload.update(overrides)
    sig = private_key.sign(canonical_signed_payload(payload))
    payload["signature"] = "ed25519:" + base64.b64encode(sig).decode("ascii")
    return payload


@pytest.mark.skipif(
    Ed25519PrivateKey is None,
    reason="cryptography ed25519 is unavailable",
)
@pytest.mark.asyncio
async def test_fetch_remote_policy_accepts_valid_signed_payload(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
    ).decode("ascii")
    payload = _signed_payload(private_key)

    monkeypatch.setattr("ori.policy.remote_fetch._http_get_json", lambda _cfg: payload)
    policy = await fetch_remote_device_policy(_base_config(public_key_b64))
    assert policy.policy_version == 2
    assert policy.relay_b_enabled is True
    assert policy.signature.startswith("ed25519:")


@pytest.mark.skipif(
    Ed25519PrivateKey is None,
    reason="cryptography ed25519 is unavailable",
)
@pytest.mark.asyncio
async def test_fetch_remote_policy_rejects_stale_timestamp(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
    ).decode("ascii")
    payload = _signed_payload(private_key, timestamp=int(time.time()) - 1000)

    monkeypatch.setattr("ori.policy.remote_fetch._http_get_json", lambda _cfg: payload)
    with pytest.raises(RemotePolicyFetchError, match="skew window") as exc:
        await fetch_remote_device_policy(
            {**_base_config(public_key_b64), "max_clock_skew_s": 5}
        )
    assert exc.value.code == "stale_timestamp"


@pytest.mark.skipif(
    Ed25519PrivateKey is None,
    reason="cryptography ed25519 is unavailable",
)
@pytest.mark.asyncio
async def test_fetch_remote_policy_rejects_version_downgrade(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
    ).decode("ascii")
    payload = _signed_payload(private_key, policy_version=1)

    monkeypatch.setattr("ori.policy.remote_fetch._http_get_json", lambda _cfg: payload)
    with pytest.raises(RemotePolicyFetchError, match="lower than current") as exc:
        await fetch_remote_device_policy(
            _base_config(public_key_b64),
            current_policy_version=3,
        )
    assert exc.value.code == "version_downgrade"


@pytest.mark.skipif(
    Ed25519PrivateKey is None,
    reason="cryptography ed25519 is unavailable",
)
@pytest.mark.asyncio
async def test_fetch_remote_policy_rejects_invalid_signature(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    another_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(
        another_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
    ).decode("ascii")
    payload = _signed_payload(private_key)

    monkeypatch.setattr("ori.policy.remote_fetch._http_get_json", lambda _cfg: payload)
    with pytest.raises(
        RemotePolicyFetchError,
        match="signature verification failed",
    ) as exc:
        await fetch_remote_device_policy(_base_config(public_key_b64))
    assert exc.value.code == "invalid_signature"


@pytest.mark.asyncio
async def test_fetch_remote_policy_rejects_non_https_url():
    with pytest.raises(RemotePolicyFetchError, match="https://") as exc:
        await fetch_remote_device_policy(
            {
                "enabled": True,
                "url": "http://example.com/device-policy",
                "auth_token": "token",
                "public_key_b64": "abc",
            }
        )
    assert exc.value.code == "invalid_config"
