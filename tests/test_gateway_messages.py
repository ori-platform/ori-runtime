# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
    GatewayMessageAuthError,
    GatewayMessageEncryptionConfig,
    GatewayMessageEncryptionError,
    GatewayMessageEncryptor,
    GatewayReplayCache,
)


def _auth(secret: str = "site-local-secret") -> GatewayMessageAuthenticator:
    return GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret=secret,
            max_skew_ms=1_000,
            replay_ttl_ms=1_000,
        )
    )


def _payload() -> dict:
    return {
        "request_id": "req-001",
        "device_id": "dev-01",
        "export_type": "health",
        "items": [],
    }


def test_sign_and_verify_returns_payload_without_auth():
    auth = _auth()
    signed = auth.sign(_payload(), message_type="export_response", signed_at_ms=10_000)

    assert "auth" in signed
    verified = auth.verify(
        signed,
        message_type="export_response",
        expected_device_id="dev-01",
        expected_request_id="req-001",
        now_ms_value=10_000,
    )

    assert verified == _payload()


def test_verify_rejects_tampered_payload():
    signed = _auth().sign(
        _payload(), message_type="export_response", signed_at_ms=10_000
    )
    signed["device_id"] = "attacker"

    with pytest.raises(GatewayMessageAuthError, match="device_mismatch"):
        _auth().verify(
            signed,
            message_type="export_response",
            expected_device_id="dev-01",
            expected_request_id="req-001",
            now_ms_value=10_000,
        )


def test_verify_rejects_stale_and_future_timestamps():
    auth = _auth()
    stale = auth.sign(_payload(), message_type="export_response", signed_at_ms=10_000)
    future = auth.sign(
        _payload(), message_type="reasoning_response", signed_at_ms=20_000
    )

    with pytest.raises(GatewayMessageAuthError, match="stale_timestamp"):
        auth.verify(
            stale,
            message_type="export_response",
            expected_device_id="dev-01",
            now_ms_value=11_001,
        )
    with pytest.raises(GatewayMessageAuthError, match="future_timestamp"):
        auth.verify(
            future,
            message_type="reasoning_response",
            expected_device_id="dev-01",
            now_ms_value=18_999,
        )


def test_verify_rejects_replay_within_ttl_but_allows_after_expiry():
    cache = GatewayReplayCache(ttl_ms=100)
    auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="secret", replay_ttl_ms=100),
        replay_cache=cache,
    )
    signed = auth.sign(_payload(), message_type="export_request", signed_at_ms=10_000)

    auth.verify(
        signed,
        message_type="export_request",
        expected_device_id="dev-01",
        expected_request_id="req-001",
        now_ms_value=10_000,
    )
    with pytest.raises(GatewayMessageAuthError, match="replay_detected"):
        auth.verify(
            signed,
            message_type="export_request",
            expected_device_id="dev-01",
            expected_request_id="req-001",
            now_ms_value=10_050,
        )

    auth.verify(
        signed,
        message_type="export_request",
        expected_device_id="dev-01",
        expected_request_id="req-001",
        now_ms_value=10_101,
    )


def test_verify_rejects_missing_auth_when_authenticator_is_configured():
    with pytest.raises(GatewayMessageAuthError, match="missing_auth"):
        _auth().verify(
            _payload(),
            message_type="export_request",
            expected_device_id="dev-01",
        )


def test_signature_is_bound_to_message_type():
    auth = _auth()
    signed = auth.sign(_payload(), message_type="export_request", signed_at_ms=10_000)

    with pytest.raises(GatewayMessageAuthError, match="invalid_signature"):
        auth.verify(
            signed,
            message_type="export_response",
            expected_device_id="dev-01",
            expected_request_id="req-001",
            now_ms_value=10_000,
        )


def test_encrypt_and_decrypt_returns_original_payload():
    encryptor = GatewayMessageEncryptor(
        GatewayMessageEncryptionConfig(shared_secret="site-local-secret")
    )

    encrypted = encryptor.encrypt(
        _payload() | {"items": [{"value": 42.0}]},
        message_type="export_response",
        nonce=b"0" * 12,
    )

    assert encrypted["encrypted"] is True
    assert encrypted["request_id"] == "req-001"
    assert encrypted["device_id"] == "dev-01"
    assert encrypted["export_type"] == "health"
    assert "items" not in encrypted

    decrypted = encryptor.decrypt(
        encrypted,
        message_type="export_response",
        expected_device_id="dev-01",
        expected_request_id="req-001",
    )
    assert decrypted == _payload() | {"items": [{"value": 42.0}]}


def test_decrypt_rejects_wrong_secret():
    encrypted = GatewayMessageEncryptor(
        GatewayMessageEncryptionConfig(shared_secret="right-secret")
    ).encrypt(
        _payload() | {"items": [{"value": 42.0}]},
        message_type="export_response",
        nonce=b"1" * 12,
    )

    with pytest.raises(GatewayMessageEncryptionError, match="decryption_failed"):
        GatewayMessageEncryptor(
            GatewayMessageEncryptionConfig(shared_secret="wrong-secret")
        ).decrypt(
            encrypted,
            message_type="export_response",
            expected_device_id="dev-01",
            expected_request_id="req-001",
        )


def test_decrypt_rejects_tampered_ciphertext():
    encryptor = GatewayMessageEncryptor(
        GatewayMessageEncryptionConfig(shared_secret="site-local-secret")
    )
    encrypted = encryptor.encrypt(
        _payload() | {"items": [{"value": 42.0}]},
        message_type="export_response",
        nonce=b"2" * 12,
    )
    ciphertext = encrypted["encryption"]["ciphertext"]
    replacement = "A" if ciphertext[-1] != "A" else "B"
    encrypted["encryption"]["ciphertext"] = ciphertext[:-1] + replacement

    with pytest.raises(GatewayMessageEncryptionError, match="decryption_failed"):
        encryptor.decrypt(
            encrypted,
            message_type="export_response",
            expected_device_id="dev-01",
            expected_request_id="req-001",
        )


# ── verify_broadcast tests ────────────────────────────────────────────────────


def _broadcast_payload() -> dict:
    return {
        "status": "healthy",
        "uptime_s": 12.5,
        "provider": "echo",
        "sim_available": False,
        "timestamp_ms": 1_000_000,
    }


def test_verify_broadcast_accepts_valid_signed_payload():
    auth = _auth()
    signed = auth.sign(
        _broadcast_payload(), message_type="gateway.heartbeat", signed_at_ms=10_000
    )

    verified = auth.verify_broadcast(
        signed, message_type="gateway.heartbeat", now_ms_value=10_000
    )

    assert verified == _broadcast_payload()


def test_verify_broadcast_rejects_missing_auth():
    with pytest.raises(GatewayMessageAuthError, match="missing_auth"):
        _auth().verify_broadcast(_broadcast_payload(), message_type="gateway.heartbeat")


def test_verify_broadcast_rejects_tampered_payload():
    auth = _auth()
    signed = auth.sign(
        _broadcast_payload(), message_type="gateway.heartbeat", signed_at_ms=10_000
    )
    signed["uptime_s"] = 9999.0

    with pytest.raises(GatewayMessageAuthError, match="invalid_signature"):
        auth.verify_broadcast(
            signed, message_type="gateway.heartbeat", now_ms_value=10_000
        )


def test_verify_broadcast_rejects_stale_timestamp():
    auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="s", max_skew_ms=1_000, replay_ttl_ms=5_000
        )
    )
    signed = auth.sign(
        _broadcast_payload(), message_type="gateway.heartbeat", signed_at_ms=0
    )

    with pytest.raises(GatewayMessageAuthError, match="stale_timestamp"):
        auth.verify_broadcast(
            signed, message_type="gateway.heartbeat", now_ms_value=10_000
        )


def test_verify_broadcast_rejects_replay():
    auth = _auth()
    signed = auth.sign(
        _broadcast_payload(), message_type="gateway.heartbeat", signed_at_ms=10_000
    )

    auth.verify_broadcast(signed, message_type="gateway.heartbeat", now_ms_value=10_000)

    with pytest.raises(GatewayMessageAuthError, match="replay_detected"):
        auth.verify_broadcast(
            signed, message_type="gateway.heartbeat", now_ms_value=10_001
        )


def test_verify_broadcast_replay_key_is_independent_of_device_id():
    """Broadcast replay key must not include device_id — two runtimes with different
    device_ids must each be able to accept the same site heartbeat once."""
    auth1 = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="s", max_skew_ms=5_000, replay_ttl_ms=5_000
        )
    )
    auth2 = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="s", max_skew_ms=5_000, replay_ttl_ms=5_000
        )
    )
    signed = auth1.sign(
        _broadcast_payload(), message_type="gateway.heartbeat", signed_at_ms=10_000
    )

    # Each authenticator has its own replay cache — both accept the same heartbeat.
    r1 = auth1.verify_broadcast(
        signed, message_type="gateway.heartbeat", now_ms_value=10_000
    )
    r2 = auth2.verify_broadcast(
        signed, message_type="gateway.heartbeat", now_ms_value=10_000
    )

    assert r1 == _broadcast_payload()
    assert r2 == _broadcast_payload()


def test_verify_broadcast_signature_bound_to_message_type():
    auth = _auth()
    signed = auth.sign(
        _broadcast_payload(), message_type="gateway.heartbeat", signed_at_ms=10_000
    )

    with pytest.raises(GatewayMessageAuthError, match="invalid_signature"):
        auth.verify_broadcast(
            signed, message_type="gateway.other_type", now_ms_value=10_000
        )
