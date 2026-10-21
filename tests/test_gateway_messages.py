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
    _canonical_json,
)


def _cache(
    *, ttl_ms: int = 1_000, max_skew_ms: int = 1_000, **kwargs
) -> GatewayReplayCache:
    """A cache started at clock 0, for tests on a synthetic clock."""
    kwargs.setdefault("start_ms", 0)
    return GatewayReplayCache(ttl_ms=ttl_ms, max_skew_ms=max_skew_ms, **kwargs)


def _auth(
    secret: str = "site-local-secret", *, previous: str = ""
) -> GatewayMessageAuthenticator:
    return GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret=secret,
            previous_shared_secret=previous,
            max_skew_ms=1_000,
            replay_ttl_ms=1_000,
        ),
        replay_cache=_cache(),
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
        ),
        replay_cache=_cache(max_skew_ms=1_000, ttl_ms=1_000),
    )
    signed = auth.sign(_payload(), message_type="export_response", signed_at_ms=10_000)

    verified = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="current-secret",
            max_skew_ms=1_000,
            replay_ttl_ms=1_000,
        ),
        replay_cache=_cache(max_skew_ms=1_000, ttl_ms=1_000),
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
        ),
        replay_cache=_cache(max_skew_ms=1_000, ttl_ms=1_000),
    )
    rotated_auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="current-secret",
            previous_shared_secret="previous-secret",
            max_skew_ms=1_000,
            replay_ttl_ms=1_000,
        ),
        replay_cache=_cache(max_skew_ms=1_000, ttl_ms=1_000),
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
        ),
        replay_cache=_cache(max_skew_ms=1_000, ttl_ms=1_000),
    )
    rotated_auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="current-secret",
            previous_shared_secret="previous-secret",
            max_skew_ms=1_000,
            replay_ttl_ms=1_000,
        ),
        replay_cache=_cache(max_skew_ms=1_000, ttl_ms=1_000),
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
            ),
            replay_cache=_cache(max_skew_ms=300_000, ttl_ms=300_000),
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


def test_a_replay_is_refused_while_held_and_at_the_floor_once_dropped():
    cache = _cache(ttl_ms=100, max_skew_ms=300)
    auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="secret", max_skew_ms=300, replay_ttl_ms=100
        ),
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

    # Still within the skew once the key is dropped: the floor refuses it.
    cache.prune(10_301)
    assert cache.floor_ms() == 10_001
    with pytest.raises(GatewayMessageAuthError, match="before_replay_floor"):
        auth.verify(
            signed,
            message_type="export_request",
            expected_device_id="dev-01",
            expected_request_id="req-001",
            now_ms_value=10_250,
        )


def test_a_full_cache_evicts_the_smallest_signing_time_and_raises_the_floor():
    cache = _cache(ttl_ms=10_000, max_skew_ms=10_000, max_entries=2)

    assert (
        cache.admit(
            "late", signed_at_ms=1_500, received_at_ms=1_000, now_ms_value=1_000
        )
        is None
    )
    assert (
        cache.admit("early", signed_at_ms=900, received_at_ms=1_000, now_ms_value=1_000)
        is None
    )
    assert (
        cache.admit(
            "next", signed_at_ms=1_001, received_at_ms=1_001, now_ms_value=1_001
        )
        is None
    )
    assert sorted(cache._held) == ["late", "next"]
    assert cache.floor_ms() == 901
    assert cache.admit(
        "early", signed_at_ms=900, received_at_ms=1_002, now_ms_value=1_002
    ) == ("before_replay_floor")
    assert cache.admit(
        "late", signed_at_ms=1_500, received_at_ms=1_002, now_ms_value=1_002
    ) == ("replay_detected")


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
        ),
        replay_cache=_cache(max_skew_ms=1_000, ttl_ms=5_000),
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
        ),
        replay_cache=_cache(max_skew_ms=5_000, ttl_ms=5_000),
    )
    auth2 = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="s", max_skew_ms=5_000, replay_ttl_ms=5_000
        ),
        replay_cache=_cache(max_skew_ms=5_000, ttl_ms=5_000),
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


def _admit(cache: GatewayReplayCache, key: str, at_ms: int) -> str | None:
    return cache.admit(
        key, signed_at_ms=at_ms, received_at_ms=at_ms, now_ms_value=at_ms
    )


def test_persistent_replay_cache_survives_restart(tmp_path):
    db_path = str(tmp_path / "replay.db")
    cache = _cache(ttl_ms=60_000, max_skew_ms=60_000, db_path=db_path)
    assert cache.persistent is True
    assert _admit(cache, "envelope-key-1", 10_000) is None
    assert cache.check("envelope-key-1", signed_at_ms=10_000) == "replay_detected"
    cache.close()

    restarted = _cache(ttl_ms=60_000, max_skew_ms=60_000, db_path=db_path)
    assert restarted.persistent is True
    assert restarted.check("envelope-key-1", signed_at_ms=10_000) == ("replay_detected")
    assert _admit(restarted, "envelope-key-2", 11_000) is None


def test_a_dropped_key_stores_the_floor_across_restart(tmp_path):
    db_path = str(tmp_path / "replay.db")
    cache = _cache(ttl_ms=1_000, max_skew_ms=1_000, db_path=db_path)
    assert _admit(cache, "short-lived", 10_000) is None
    # Dropped by the next write, which stores the floor past it.
    assert _admit(cache, "another", 12_000) is None
    cache.close()

    restarted = _cache(ttl_ms=1_000, max_skew_ms=1_000, db_path=db_path, start_ms=0)
    assert sorted(restarted._held) == ["another"]
    assert restarted.floor_ms() == 10_001
    assert restarted.check("short-lived", signed_at_ms=10_000) == (
        "before_replay_floor"
    )


def test_persistent_replay_cache_falls_back_when_db_unavailable(tmp_path, caplog):
    unwritable = tmp_path / "missing-dir" / "replay.db"
    with caplog.at_level(logging.WARNING):
        cache = _cache(ttl_ms=60_000, max_skew_ms=60_000, db_path=str(unwritable))

    assert cache.persistent is False
    assert any("in-memory replay protection" in r.message for r in caplog.records)
    # In-memory protection still works.
    assert _admit(cache, "key", 10_000) is None
    assert _admit(cache, "key", 10_500) == "replay_detected"


def test_authenticator_rejects_replay_across_cache_restart(tmp_path):
    db_path = str(tmp_path / "replay.db")
    config = GatewayMessageAuthConfig(
        shared_secret="site-local-secret", max_skew_ms=60_000, replay_ttl_ms=60_000
    )
    first = GatewayMessageAuthenticator(
        config,
        replay_cache=_cache(ttl_ms=60_000, max_skew_ms=60_000, db_path=db_path),
    )
    signed = first.sign(_payload(), message_type="export_response", signed_at_ms=10_000)
    first.verify(
        signed,
        message_type="export_response",
        expected_device_id="dev-01",
        expected_request_id="req-001",
        now_ms_value=10_000,
    )
    first._replay_cache.close()

    restarted = GatewayMessageAuthenticator(
        config,
        replay_cache=_cache(ttl_ms=60_000, max_skew_ms=60_000, db_path=db_path),
    )
    with pytest.raises(GatewayMessageAuthError, match="replay_detected"):
        restarted.verify(
            signed,
            message_type="export_response",
            expected_device_id="dev-01",
            expected_request_id="req-001",
            now_ms_value=11_000,
        )


def test_canonical_json_refuses_non_finite_numbers() -> None:
    """NaN and Infinity are not valid JSON and must never reach the wire.

    ``json.dumps`` emits them as bare ``NaN``/``Infinity`` tokens by default. No
    conforming parser accepts those, so the Go gateway rejects the payload and the
    message becomes unverifiable rather than merely odd.
    """
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            _canonical_json({"reading": value})


def test_canonical_json_keeps_operational_telemetry_range() -> None:
    """Gateway MQTT is not evidence/v2 and must not impose the D-011 zone.

    A small leakage-current reading is ordinary telemetry. Constraining this
    serializer to the evidence agreement zone would turn it into an authentication
    failure.
    """
    assert _canonical_json({"value": 5e-05}) == '{"value":5e-05}'
    assert _canonical_json({"value": 1e-05}) == '{"value":1e-05}'
    assert _canonical_json({"value": 1e300}) == '{"value":1e+300}'


@pytest.mark.parametrize(
    "value", ["1000", 1000.0, True, None], ids=["str", "float", "bool", "none"]
)
def test_both_verifiers_refuse_a_signed_time_that_is_not_an_integer(value):
    from ori.security.gateway_messages import (
        GatewayMessageAuthConfig,
        GatewayMessageAuthenticator,
        GatewayMessageAuthError,
    )

    auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="s"),
        replay_cache=_cache(max_skew_ms=300_000, ttl_ms=300_000),
    )
    signed = auth.sign(
        {"device_id": "d", "request_id": "r"}, message_type="m", signed_at_ms=1000
    )
    signed["auth"]["signed_at_ms"] = value
    with pytest.raises(GatewayMessageAuthError, match="invalid_signed_at_ms"):
        auth.verify(signed, message_type="m", expected_device_id="d", now_ms_value=1000)
    broadcast = auth.sign({"site": "x"}, message_type="m", signed_at_ms=1000)
    broadcast["auth"]["signed_at_ms"] = value
    with pytest.raises(GatewayMessageAuthError, match="invalid_signed_at_ms"):
        auth.verify_broadcast(broadcast, message_type="m", now_ms_value=1000)


def _hostile(shape: str) -> dict:
    """A correctly shaped, unauthenticated envelope a sender controls fully."""
    from ori.utils.time_utils import now_ms

    payload: dict = {
        "device_id": "dev-01",
        "body": {"value": 1},
        "auth": {
            "scheme": "hmac-sha256",
            "signed_at_ms": now_ms(),
            "signature": "hmac-sha256:" + "0" * 64,
        },
    }
    if shape == "non_ascii_signature":
        payload["auth"]["signature"] = "hmac-sha256:é"
    elif shape == "surrogate":
        payload["body"]["value"] = "\ud800"
    elif shape == "non_finite":
        payload["body"]["value"] = float("nan")
    elif shape == "deep":
        # Deep enough that encoding it raises RecursionError on every
        # supported interpreter; a parser may admit it on a later one.
        nested: object = 0
        for _ in range(200_000):
            nested = [nested]
        payload["body"]["value"] = nested
    elif shape == "signature_shape":
        payload["auth"]["signature"] = "hmac-sha256:" + "Z" * 64
    return payload


HOSTILE_SHAPES = [
    "non_ascii_signature",
    "surrogate",
    "non_finite",
    "deep",
    "signature_shape",
]


@pytest.mark.parametrize("shape", HOSTILE_SHAPES)
def test_verify_raises_only_an_auth_error_for_anything_on_the_wire(shape):
    """Every caller catches GatewayMessageAuthError alone, so nothing else may escape."""
    with pytest.raises(GatewayMessageAuthError):
        _auth().verify(
            _hostile(shape),
            message_type="evidence_inbound",
            expected_device_id="dev-01",
        )


@pytest.mark.parametrize("shape", HOSTILE_SHAPES)
def test_verify_broadcast_raises_only_an_auth_error_for_anything_on_the_wire(shape):
    with pytest.raises(GatewayMessageAuthError):
        _auth().verify_broadcast(_hostile(shape), message_type="gateway_heartbeat")


@pytest.mark.parametrize("shape", ["non_ascii_signature", "signature_shape"])
def test_a_signature_of_another_shape_is_malformed_before_any_comparison(shape):
    with pytest.raises(GatewayMessageAuthError, match="malformed_signature"):
        _auth().verify(
            _hostile(shape),
            message_type="evidence_inbound",
            expected_device_id="dev-01",
        )


def _signed(auth: GatewayMessageAuthenticator, request_id: str, at_ms: int) -> dict:
    return auth.sign(
        {"device_id": "dev-01", "request_id": request_id},
        message_type="export_request",
        signed_at_ms=at_ms,
    )


def test_authenticate_makes_the_floor_and_held_key_checks_before_any_commit():
    auth = _auth()
    held = _signed(auth, "held", 10_000)
    auth.verify(
        held,
        message_type="export_request",
        expected_device_id="dev-01",
        now_ms_value=10_000,
    )
    with pytest.raises(GatewayMessageAuthError, match="replay_detected"):
        auth.authenticate(
            held,
            message_type="export_request",
            expected_device_id="dev-01",
            now_ms_value=10_001,
        )
    auth._replay_cache.prune(11_001)
    assert auth._replay_cache.floor_ms() == 10_001
    with pytest.raises(GatewayMessageAuthError, match="before_replay_floor"):
        auth.authenticate(
            _signed(auth, "below", 10_000),
            message_type="export_request",
            expected_device_id="dev-01",
            now_ms_value=10_500,
        )


def test_a_floor_refusal_warns_naming_the_floor_and_the_clock(caplog):
    skew, t = 1_000, 50_000
    auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="s", max_skew_ms=skew, replay_ttl_ms=1),
        replay_cache=_cache(ttl_ms=1, max_skew_ms=skew, start_ms=t - skew + 1),
    )
    with caplog.at_level(logging.WARNING, logger="ori.security.gateway_messages"):
        with pytest.raises(GatewayMessageAuthError, match="before_replay_floor"):
            auth.verify(
                _signed(auth, "r", t - skew),
                message_type="export_request",
                expected_device_id="dev-01",
                now_ms_value=t,
            )
    assert f"below the replay floor {t - skew + 1} at clock {t}" in caplog.text


def test_a_cache_built_for_another_skew_is_refused():
    with pytest.raises(ValueError, match="skew"):
        GatewayMessageAuthenticator(
            GatewayMessageAuthConfig(shared_secret="s", max_skew_ms=1_000),
            replay_cache=_cache(max_skew_ms=999),
        )


def test_sign_takes_its_time_from_the_signing_clock():
    from ori.security.signing_clock import SigningClock

    clock = SigningClock(clock=lambda: 42)
    auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="s", max_skew_ms=1_000),
        replay_cache=_cache(),
        signing_clock=clock,
    )
    times = [
        auth.sign({"device_id": "d"}, message_type="m")["auth"]["signed_at_ms"]
        for _ in range(3)
    ]
    assert times == [42, 43, 44]


def test_a_full_table_loaded_past_its_capacity_evicts_with_a_floor_raise(tmp_path):
    db = str(tmp_path / "replay.db")
    wide = _cache(ttl_ms=10**9, max_skew_ms=10**9, db_path=db)
    for index in range(5):
        assert _admit(wide, f"k{index}", 1_000 + index) is None
    wide.close()
    narrow = _cache(ttl_ms=10**9, max_skew_ms=10**9, db_path=db, max_entries=3)
    assert sorted(narrow._held) == ["k2", "k3", "k4"]
    assert narrow.floor_ms() == 1_002
    narrow.close()
    again = _cache(ttl_ms=10**9, max_skew_ms=10**9, db_path=db, max_entries=3)
    assert sorted(again._held) == ["k2", "k3", "k4"] and again.floor_ms() == 1_002


def test_no_rotation_lowers_the_stored_floor_or_drops_a_held_key(tmp_path):
    """Not even one that keeps no earlier secret: a secret brought back would
    otherwise readmit what it signed."""
    db = str(tmp_path / "replay.db")

    def build(secret: str, previous: str = "") -> GatewayMessageAuthenticator:
        return GatewayMessageAuthenticator(
            GatewayMessageAuthConfig(
                shared_secret=secret, previous_shared_secret=previous, max_skew_ms=1_000
            ),
            replay_cache=_cache(db_path=db),
        )

    first = build("one")
    first._replay_cache.admit(
        "k", signed_at_ms=5_000, received_at_ms=5_000, now_ms_value=5_000
    )
    first._replay_cache.prune(10**6)
    first._replay_cache.admit(
        "held", signed_at_ms=10**6, received_at_ms=10**6, now_ms_value=10**6
    )
    first._replay_cache.close()
    for secret, previous in (("two", "one"), ("three", ""), ("one", "")):
        rotated = build(secret, previous)
        assert rotated._replay_cache.floor_ms() == 5_001
        assert list(rotated._replay_cache._held) == ["held"]
        rotated._replay_cache.close()


def test_a_store_has_one_owner_in_this_process_and_any_other(tmp_path):
    import subprocess
    import sys

    from ori.security.gateway_messages import ReplayStoreOwnedError

    db = str(tmp_path / "replay.db")
    owner = _cache(db_path=db)
    with pytest.raises(ReplayStoreOwnedError):
        _cache(db_path=db)
    probe = (
        "import sys\n"
        "from ori.security.gateway_messages import GatewayReplayCache, "
        "ReplayStoreOwnedError\n"
        "try:\n"
        "    GatewayReplayCache(max_skew_ms=1000, db_path=sys.argv[1], start_ms=0)\n"
        "except ReplayStoreOwnedError:\n"
        "    sys.exit(3)\n"
    )
    other = subprocess.run([sys.executable, "-c", probe, db], check=False)
    assert other.returncode == 3
    owner.close()
    _cache(db_path=db).close()


def test_a_secret_brought_back_readmits_nothing_it_signed(tmp_path):
    """B staged as previous, A alone, then B again: B's envelope stays a
    replay. The signer keeps its own store, so no step registers B early."""
    db = str(tmp_path / "replay.db")

    def build(secret: str, previous: str = "") -> GatewayMessageAuthenticator:
        return GatewayMessageAuthenticator(
            GatewayMessageAuthConfig(
                shared_secret=secret,
                previous_shared_secret=previous,
                max_skew_ms=300_000,
            ),
            replay_cache=_cache(max_skew_ms=300_000, db_path=db),
        )

    signer = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="B", max_skew_ms=300_000),
        replay_cache=_cache(max_skew_ms=300_000),
    )
    envelope = _signed(signer, "r1", 60_000)
    staged = build("A", previous="B")
    staged.verify(
        envelope,
        message_type="export_request",
        expected_device_id="dev-01",
        now_ms_value=1_000,
    )
    staged._replay_cache.close()
    build("A")._replay_cache.close()
    for at_ms in (2_000, 3_000):
        returned = build("B")
        with pytest.raises(GatewayMessageAuthError, match="replay_detected"):
            returned.verify(
                envelope,
                message_type="export_request",
                expected_device_id="dev-01",
                now_ms_value=at_ms,
            )
        returned._replay_cache.close()


@pytest.mark.parametrize("entry", ["verify", "authenticate_commit", "broadcast"])
def test_a_locked_store_still_refuses_what_the_cache_holds(tmp_path, entry):
    """A store that cannot be written mid-run: the cache owns it alone, so its
    own memory is the whole history, and nothing it holds is readmitted."""
    import sqlite3

    db = str(tmp_path / "replay.db")
    cache = _cache(ttl_ms=60_000, max_skew_ms=60_000, db_path=db)
    auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="s", max_skew_ms=60_000),
        replay_cache=cache,
    )
    if entry == "broadcast":
        envelope = auth.sign(
            {"gateway_id": "gw"}, message_type="gateway.heartbeat", signed_at_ms=10_000
        )

        def receive(at_ms: int) -> None:
            auth.verify_broadcast(
                envelope, message_type="gateway.heartbeat", now_ms_value=at_ms
            )
    else:
        envelope = _signed(auth, "r1", 10_000)

        def receive(at_ms: int) -> None:
            if entry == "verify":
                auth.verify(
                    envelope,
                    message_type="export_request",
                    expected_device_id="dev-01",
                    now_ms_value=at_ms,
                )
                return
            claim = auth.authenticate(
                envelope,
                message_type="export_request",
                expected_device_id="dev-01",
                now_ms_value=at_ms,
            )
            auth.commit(claim, now_ms_value=at_ms)

    receive(10_000)
    assert cache._conn is not None
    cache._conn.execute("PRAGMA busy_timeout = 50")
    holder = sqlite3.connect(db, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(GatewayMessageAuthError, match="replay_detected"):
            receive(10_001)
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    with pytest.raises(GatewayMessageAuthError, match="replay_detected"):
        receive(10_002)
    cache.close()


def test_closing_the_envelope_state_releases_the_store_whatever_the_clock_does(
    tmp_path,
):
    from ori.security.gateway_messages import GatewayEnvelopeState
    from ori.security.signing_clock import SigningClock

    class _Stuck(SigningClock):
        def stop(self, timeout_s: float = 2.0) -> None:
            raise RuntimeError("stuck")

    db = str(tmp_path / "replay.db")
    state = GatewayEnvelopeState(
        replay_cache=_cache(db_path=db), signing_clock=_Stuck()
    )
    state.close()
    # The store's ownership was released, so the next start can take it.
    _cache(db_path=db).close()


@pytest.mark.parametrize("alias", ["symlink", "directory_symlink"])
def test_an_alias_of_an_owned_store_reaches_the_same_owner(tmp_path, alias):
    import os

    from ori.security.gateway_messages import ReplayStoreOwnedError

    real_dir = tmp_path / "real"
    real_dir.mkdir()
    db = real_dir / "replay.db"
    owner = _cache(db_path=str(db))
    if alias == "symlink":
        aliased = tmp_path / "alias.db"
        os.symlink(db, aliased)
    else:
        os.symlink(real_dir, tmp_path / "linked")
        aliased = tmp_path / "linked" / "replay.db"
    with pytest.raises(ReplayStoreOwnedError):
        _cache(db_path=str(aliased))
    owner.close()


def test_a_hard_linked_store_is_refused_rather_than_shared(tmp_path):
    import os

    from ori.security.gateway_messages import ReplayStoreOwnedError

    db = tmp_path / "replay.db"
    _cache(db_path=str(db)).close()
    os.link(db, tmp_path / "other.db")
    with pytest.raises(ReplayStoreOwnedError, match="hard-linked"):
        _cache(db_path=str(db))
    with pytest.raises(ReplayStoreOwnedError, match="hard-linked"):
        _cache(db_path=str(tmp_path / "other.db"))
    # Refused without leaving its lock held.
    os.unlink(tmp_path / "other.db")
    _cache(db_path=str(db)).close()


def test_ownership_that_cannot_be_taken_raises_rather_than_running_alone(tmp_path):
    import os

    from ori.security.gateway_messages import ReplayStoreOwnedError

    db = tmp_path / "replay.db"
    db.touch()
    identity = os.stat(db)
    lock = tmp_path / f".ori-gateway-replay-{identity.st_dev}-{identity.st_ino}.lock"
    lock.mkdir()  # The lock's name is taken by something no one can open.
    with pytest.raises(ReplayStoreOwnedError, match="cannot take ownership"):
        _cache(db_path=str(db))
    os.rmdir(lock)


def test_an_in_memory_database_is_no_store_and_takes_no_lock(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cache = _cache(db_path=":memory:")
    assert cache.persistent is False and cache._ownership is None
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("entry", ["verify", "authenticate_commit", "broadcast"])
def test_a_fresh_envelope_admitted_while_the_store_fails_stays_a_replay(
    tmp_path, entry
):
    """Forces the transaction to fail on a fresh envelope, so the cache falls
    back to its memory, then replays it: as sole owner, its memory refuses."""
    import sqlite3

    db = str(tmp_path / "replay.db")
    cache = _cache(ttl_ms=60_000, max_skew_ms=60_000, db_path=db)
    auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="s", max_skew_ms=60_000),
        replay_cache=cache,
    )
    if entry == "broadcast":
        envelope = auth.sign(
            {"gateway_id": "gw"}, message_type="gateway.heartbeat", signed_at_ms=10_000
        )

        def receive(at_ms: int) -> None:
            auth.verify_broadcast(
                envelope, message_type="gateway.heartbeat", now_ms_value=at_ms
            )
    else:
        envelope = _signed(auth, "fresh", 10_000)

        def receive(at_ms: int) -> None:
            if entry == "verify":
                auth.verify(
                    envelope,
                    message_type="export_request",
                    expected_device_id="dev-01",
                    now_ms_value=at_ms,
                )
                return
            claim = auth.authenticate(
                envelope,
                message_type="export_request",
                expected_device_id="dev-01",
                now_ms_value=at_ms,
            )
            auth.commit(claim, now_ms_value=at_ms)

    assert cache._conn is not None
    cache._conn.execute("PRAGMA busy_timeout = 50")
    holder = sqlite3.connect(db, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        receive(10_000)  # Admitted in memory; the store write failed.
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert cache.persistent is False
    with pytest.raises(GatewayMessageAuthError, match="replay_detected"):
        receive(10_001)
    cache.close()


def test_a_case_variant_name_reaches_the_same_owner(tmp_path):
    """On a case-insensitive filesystem two spellings name one database."""
    import os

    from ori.security.gateway_messages import ReplayStoreOwnedError

    db = tmp_path / "replay.db"
    owner = _cache(db_path=str(db))
    variant = tmp_path / "REPLAY.db"
    if not os.path.exists(variant) or not os.path.samefile(db, variant):
        owner.close()
        pytest.skip("this filesystem is case-sensitive")
    with pytest.raises(ReplayStoreOwnedError):
        _cache(db_path=str(variant))
    owner.close()


def test_the_lock_is_named_by_the_database_not_its_path(tmp_path):
    import os

    db = tmp_path / "replay.db"
    cache = _cache(db_path=str(db))
    identity = os.stat(db)
    assert (
        tmp_path / f".ori-gateway-replay-{identity.st_dev}-{identity.st_ino}.lock"
    ).exists()
    cache.close()
