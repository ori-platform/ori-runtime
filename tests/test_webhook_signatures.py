# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from ori.security.webhook_signatures import (
    WebhookReplayCache,
    WebhookSignatureConfig,
    WebhookSignatureVerifier,
    sign_webhook_body,
)
from ori.state.store import StateStore


@pytest.mark.asyncio
async def test_webhook_signature_accepts_valid_raw_body() -> None:
    body = b"from=%2B2348000000000&text=YES-AB12CD34"
    signature = sign_webhook_body(
        body, shared_secret="secret", signed_at_ms=1_000, nonce="nonce-1"
    )
    verifier = WebhookSignatureVerifier(
        WebhookSignatureConfig(
            mode="hmac_required",
            shared_secret="secret",
            max_skew_ms=500,
            replay_ttl_ms=500,
        )
    )

    result = await verifier.verify(
        headers={
            "x-ori-webhook-signature": signature,
            "x-ori-webhook-timestamp": "1000",
            "x-ori-webhook-nonce": "nonce-1",
        },
        body=body,
        now_ms_value=1_100,
    )

    assert result.accepted is True
    assert result.reason == "accepted"


@pytest.mark.asyncio
async def test_webhook_signature_accepts_previous_secret_during_rotation() -> None:
    body = b"from=%2B2348000000000&text=YES-AB12CD34"
    signature = sign_webhook_body(
        body,
        shared_secret="previous-secret",
        signed_at_ms=1_000,
        nonce="nonce-rotation",
    )
    verifier = WebhookSignatureVerifier(
        WebhookSignatureConfig(
            mode="hmac_required",
            shared_secret="current-secret",
            previous_shared_secret="previous-secret",
            max_skew_ms=500,
            replay_ttl_ms=500,
        )
    )

    result = await verifier.verify(
        headers={
            "x-ori-webhook-signature": signature,
            "x-ori-webhook-timestamp": "1000",
            "x-ori-webhook-nonce": "nonce-rotation",
        },
        body=body,
        now_ms_value=1_100,
    )

    assert result.accepted is True
    assert result.reason == "accepted_previous_secret"


def test_webhook_signature_rejects_same_current_and_previous_secret() -> None:
    with pytest.raises(ValueError, match="previous_shared_secret"):
        WebhookSignatureVerifier(
            WebhookSignatureConfig(
                mode="hmac_required",
                shared_secret="same-secret",
                previous_shared_secret="same-secret",
            )
        )


@pytest.mark.asyncio
async def test_webhook_signature_rejects_tampered_body() -> None:
    signed_body = b"from=%2B2348000000000&text=YES-AB12CD34"
    tampered_body = b"from=%2B2348000000000&text=YES-WRONG999"
    signature = sign_webhook_body(
        signed_body, shared_secret="secret", signed_at_ms=1_000, nonce="nonce-2"
    )
    verifier = WebhookSignatureVerifier(
        WebhookSignatureConfig(mode="hmac_required", shared_secret="secret")
    )

    result = await verifier.verify(
        headers={
            "x-ori-webhook-signature": signature,
            "x-ori-webhook-timestamp": "1000",
            "x-ori-webhook-nonce": "nonce-2",
        },
        body=tampered_body,
        now_ms_value=1_000,
    )

    assert result.accepted is False
    assert result.reason == "invalid_signature"


@pytest.mark.asyncio
async def test_webhook_signature_rejects_replayed_nonce_with_state_store(
    tmp_path,
) -> None:
    store = StateStore(str(tmp_path / "webhook-replay.db"))
    await store.open()
    try:
        body = b"from=%2B2348000000000&text=YES-AB12CD34"
        signature = sign_webhook_body(
            body, shared_secret="secret", signed_at_ms=1_000, nonce="nonce-3"
        )
        verifier = WebhookSignatureVerifier(
            WebhookSignatureConfig(mode="hmac_required", shared_secret="secret")
        )
        headers = {
            "x-ori-webhook-signature": signature,
            "x-ori-webhook-timestamp": "1000",
            "x-ori-webhook-nonce": "nonce-3",
        }

        first = await verifier.verify(
            headers=headers,
            body=body,
            state_store=store,
            now_ms_value=1_000,
        )
        second = await verifier.verify(
            headers=headers,
            body=body,
            state_store=store,
            now_ms_value=1_001,
        )

        assert first.accepted is True
        assert second.accepted is False
        assert second.reason == "replay_detected"
    finally:
        await store.close()


def test_webhook_replay_cache_fails_closed_when_full_of_live_entries() -> None:
    cache = WebhookReplayCache(ttl_ms=10_000, max_entries=1)

    assert cache.mark_seen("nonce-1", now_ms_value=1_000) is True
    assert cache.mark_seen("nonce-2", now_ms_value=1_001) is False
    assert cache.mark_seen("nonce-1", now_ms_value=1_002) is False


def test_webhook_replay_cache_accepts_new_nonce_after_expiry() -> None:
    cache = WebhookReplayCache(ttl_ms=10, max_entries=1)

    assert cache.mark_seen("nonce-1", now_ms_value=1_000) is True
    assert cache.mark_seen("nonce-2", now_ms_value=1_011) is True
