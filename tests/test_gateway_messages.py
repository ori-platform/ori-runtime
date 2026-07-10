# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import logging

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


def test_sign_uses_current_secret_when_previous_secret_is_configured():
    auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="current-secret",
            previous_shared_secret="previous-secret",
            max_skew_ms=1_000,
            replay_ttl_ms=1_000,
        )
    )
    signed = auth.sign(_payload(), message_type="export_response", signed_at_ms=10_000)

    verified = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="current-secret",
            max_skew_ms=1_000,
            replay_ttl_ms=1_000,
        )
    ).verify(
        signed,
        message_type="export_response",
        expected_device_id="dev-01",
        expected_request_id="req-001",
        now_ms_value=10_000,
    )

    assert verified == _payload()


def test_verify_accepts_previous_secret_during_rotation(caplog):
    previous_auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="previous-secret",
            max_skew_ms=1_000,
            replay_ttl_ms=1_000,
        )
    )
    rotated_auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="current-secret",
            previous_shared_secret="previous-secret",
            max_skew_ms=1_000,
            replay_ttl_ms=1_000,
        )
    )
    signed = previous_auth.sign(
        _payload(), message_type="export_response", signed_at_ms=10_000
    )

    with caplog.at_level(logging.WARNING, logger="ori.security.gateway_messages"):
        verified = rotated_auth.verify(
            signed,
            message_type="export_response",
            expected_device_id="dev-01",
            expected_request_id="req-001",
            now_ms_value=10_000,
        )

    assert verified == _payload()
    assert "previous HMAC secret" in caplog.text
    assert "device_id=dev-01" in caplog.text
    assert "request_id=req-001" in caplog.text


def test_verify_broadcast_accepts_previous_secret_during_rotation(caplog):
    previous_auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="previous-secret",
            max_skew_ms=1_000,
            replay_ttl_ms=1_000,
        )
    )
    rotated_auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="current-secret",
            previous_shared_secret="previous-secret",
            max_skew_ms=1_000,
            replay_ttl_ms=1_000,
        )
    )
    payload = {"gateway_id": "gw-01", "status": "healthy"}
    signed = previous_auth.sign(
        payload, message_type="gateway.heartbeat", signed_at_ms=10_000
    )

    with caplog.at_level(logging.WARNING, logger="ori.security.gateway_messages"):
        verified = rotated_auth.verify_broadcast(
            signed,
            message_type="gateway.heartbeat",
            now_ms_value=10_000,
        )

    assert verified == payload
    assert "broadcast accepted with previous HMAC secret" in caplog.text
    assert "message_type=gateway.heartbeat" in caplog.text


def test_auth_config_rejects_same_current_and_previous_secret():
    with pytest.raises(ValueError, match="previous_shared_secret"):
        GatewayMessageAuthenticator(
            GatewayMessageAuthConfig(
                shared_secret="same-secret",
                previous_shared_secret="same-secret",
            )
        )


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


def test_gateway_replay_cache_fails_closed_when_full_of_live_entries():
    cache = GatewayReplayCache(ttl_ms=10_000, max_entries=1)

    assert cache.mark_seen("nonce-1", now_ms_value=1_000) is True
    assert cache.mark_seen("nonce-2", now_ms_value=1_001) is False
    assert cache.mark_seen("nonce-1", now_ms_value=1_002) is False


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


def test_persistent_replay_cache_survives_restart(tmp_path):
    db_path = str(tmp_path / "replay.db")
    cache = GatewayReplayCache(ttl_ms=60_000, db_path=db_path)
    assert cache.persistent is True
    assert cache.mark_seen("envelope-key-1", now_ms_value=10_000) is True
    assert cache.mark_seen("envelope-key-1", now_ms_value=10_500) is False

    restarted = GatewayReplayCache(ttl_ms=60_000, db_path=db_path)
    assert restarted.persistent is True
    assert restarted.mark_seen("envelope-key-1", now_ms_value=11_000) is False
    assert restarted.mark_seen("envelope-key-2", now_ms_value=11_000) is True


def test_persistent_replay_cache_expires_keys_across_restart(tmp_path):
    db_path = str(tmp_path / "replay.db")
    cache = GatewayReplayCache(ttl_ms=1_000, db_path=db_path)
    assert cache.mark_seen("short-lived", now_ms_value=10_000) is True
    # Force expired rows to be pruned from the persistent table too.
    assert cache.mark_seen("another", now_ms_value=12_000) is True

    restarted = GatewayReplayCache(ttl_ms=1_000, db_path=db_path)
    assert restarted.mark_seen("short-lived", now_ms_value=12_500) is True


def test_persistent_replay_cache_falls_back_when_db_unavailable(tmp_path, caplog):
    unwritable = tmp_path / "missing-dir" / "replay.db"
    with caplog.at_level(logging.WARNING):
        cache = GatewayReplayCache(ttl_ms=60_000, db_path=str(unwritable))

    assert cache.persistent is False
    assert any("in-memory replay protection" in r.message for r in caplog.records)
    # In-memory protection still works.
    assert cache.mark_seen("key", now_ms_value=10_000) is True
    assert cache.mark_seen("key", now_ms_value=10_500) is False


def test_authenticator_rejects_replay_across_cache_restart(tmp_path):
    db_path = str(tmp_path / "replay.db")
    config = GatewayMessageAuthConfig(
        shared_secret="site-local-secret", max_skew_ms=60_000, replay_ttl_ms=60_000
    )
    first = GatewayMessageAuthenticator(
        config, replay_cache=GatewayReplayCache(ttl_ms=60_000, db_path=db_path)
    )
    signed = first.sign(_payload(), message_type="export_response", signed_at_ms=10_000)
    first.verify(
        signed,
        message_type="export_response",
        expected_device_id="dev-01",
        expected_request_id="req-001",
        now_ms_value=10_000,
    )

    restarted = GatewayMessageAuthenticator(
        config, replay_cache=GatewayReplayCache(ttl_ms=60_000, db_path=db_path)
    )
    with pytest.raises(GatewayMessageAuthError, match="replay_detected"):
        restarted.verify(
            signed,
            message_type="export_response",
            expected_device_id="dev-01",
            expected_request_id="req-001",
            now_ms_value=11_000,
        )
