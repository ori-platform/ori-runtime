# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""HMAC verification for public webhook ingress.

Webhook signatures protect public SMS/WhatsApp ingress before Ori parses the
provider payload. This is intentionally separate from remote command HMACs:
webhook signing authenticates the HTTP transport envelope, while remote-command
verification authenticates state-mutating commands inside approved channels.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Mapping

from ori.utils.time_utils import now_ms

SIGNATURE_PREFIX = "hmac-sha256:"
DEFAULT_WEBHOOK_SKEW_MS = 300_000
DEFAULT_WEBHOOK_REPLAY_TTL_MS = 300_000
_MAX_MEMORY_REPLAY_ENTRIES = 4096


class WebhookSignatureError(ValueError):
    """Raised when a webhook HTTP envelope fails signature verification."""


@dataclass(frozen=True)
class WebhookSignatureConfig:
    """Configuration for webhook HMAC verification."""

    mode: str = "token_only"
    shared_secret: str = ""
    signature_header: str = "x-ori-webhook-signature"
    timestamp_header: str = "x-ori-webhook-timestamp"
    nonce_header: str = "x-ori-webhook-nonce"
    max_skew_ms: int = DEFAULT_WEBHOOK_SKEW_MS
    replay_ttl_ms: int = DEFAULT_WEBHOOK_REPLAY_TTL_MS
    require_nonce: bool = True


@dataclass(frozen=True)
class WebhookVerificationResult:
    accepted: bool
    reason: str


class WebhookReplayCache:
    """Small in-memory fallback for webhook replay checks."""

    def __init__(
        self,
        *,
        ttl_ms: int = DEFAULT_WEBHOOK_REPLAY_TTL_MS,
        max_entries: int = _MAX_MEMORY_REPLAY_ENTRIES,
    ) -> None:
        self._ttl_ms = max(1, int(ttl_ms))
        self._max_entries = max(1, int(max_entries))
        self._seen_until_ms: dict[str, int] = {}

    def mark_seen(self, key: str, *, now_ms_value: int | None = None) -> bool:
        current_ms = int(now_ms_value if now_ms_value is not None else now_ms())
        self._prune(current_ms)
        if key in self._seen_until_ms:
            return False
        if len(self._seen_until_ms) >= self._max_entries:
            return False
        self._seen_until_ms[key] = current_ms + self._ttl_ms
        return True

    def _prune(self, current_ms: int) -> None:
        expired = [
            key
            for key, expires_ms in self._seen_until_ms.items()
            if expires_ms <= current_ms
        ]
        for key in expired:
            self._seen_until_ms.pop(key, None)


class WebhookSignatureVerifier:
    """Verify raw HTTP webhook bodies before provider payload parsing."""

    def __init__(
        self,
        config: WebhookSignatureConfig,
        *,
        replay_cache: WebhookReplayCache | None = None,
    ) -> None:
        self._mode = str(config.mode or "token_only").strip().lower()
        if self._mode not in {"token_only", "hmac_required", "token_and_hmac"}:
            raise ValueError("unsupported webhook signature mode")
        self._secret = str(config.shared_secret or "").strip()
        if self._mode != "token_only" and not self._secret:
            raise ValueError("webhook HMAC shared_secret must not be empty")
        self._signature_header = _normalize_header(config.signature_header)
        self._timestamp_header = _normalize_header(config.timestamp_header)
        self._nonce_header = _normalize_header(config.nonce_header)
        self._max_skew_ms = max(0, int(config.max_skew_ms))
        self._replay_ttl_ms = max(1, int(config.replay_ttl_ms))
        self._require_nonce = bool(config.require_nonce)
        self._replay_cache = replay_cache or WebhookReplayCache(
            ttl_ms=self._replay_ttl_ms
        )

    @property
    def mode(self) -> str:
        return self._mode

    async def verify(
        self,
        *,
        headers: Mapping[str, str],
        body: bytes,
        state_store: Any = None,
        source: str = "sms_webhook",
        now_ms_value: int | None = None,
    ) -> WebhookVerificationResult:
        if self._mode == "token_only":
            return WebhookVerificationResult(True, "token_only")

        normalized_headers = {
            _normalize_header(key): str(value or "") for key, value in headers.items()
        }
        signature = normalized_headers.get(self._signature_header, "").strip()
        if not signature.startswith(SIGNATURE_PREFIX):
            return WebhookVerificationResult(False, "missing_signature")

        timestamp_text = normalized_headers.get(self._timestamp_header, "").strip()
        try:
            signed_at_ms = int(timestamp_text)
        except (TypeError, ValueError):
            return WebhookVerificationResult(False, "invalid_timestamp")

        current_ms = int(now_ms_value if now_ms_value is not None else now_ms())
        if signed_at_ms < current_ms - self._max_skew_ms:
            return WebhookVerificationResult(False, "stale_timestamp")
        if signed_at_ms > current_ms + self._max_skew_ms:
            return WebhookVerificationResult(False, "future_timestamp")

        nonce = normalized_headers.get(self._nonce_header, "").strip()
        if self._require_nonce and not nonce:
            return WebhookVerificationResult(False, "missing_nonce")

        expected = sign_webhook_body(
            body,
            shared_secret=self._secret,
            signed_at_ms=signed_at_ms,
            nonce=nonce,
        )
        if not hmac.compare_digest(signature, expected):
            return WebhookVerificationResult(False, "invalid_signature")

        if nonce:
            replay_key = f"{source}\n{nonce}"
            expires_at_ms = current_ms + self._replay_ttl_ms
            if state_store is not None and hasattr(state_store, "record_webhook_nonce"):
                recorded = await state_store.record_webhook_nonce(
                    source=source,
                    nonce=nonce,
                    received_at_ms=current_ms,
                    expires_at_ms=expires_at_ms,
                )
                if not recorded:
                    return WebhookVerificationResult(False, "replay_detected")
            elif not self._replay_cache.mark_seen(replay_key, now_ms_value=current_ms):
                return WebhookVerificationResult(False, "replay_detected")

        return WebhookVerificationResult(True, "accepted")


def sign_webhook_body(
    body: bytes,
    *,
    shared_secret: str,
    signed_at_ms: int,
    nonce: str = "",
) -> str:
    """Return ``hmac-sha256:<hex>`` for a raw webhook body."""
    signed = b"\n".join(
        [str(int(signed_at_ms)).encode("utf-8"), str(nonce or "").encode("utf-8"), body]
    )
    digest = hmac.new(str(shared_secret).encode("utf-8"), signed, sha256).hexdigest()
    return f"{SIGNATURE_PREFIX}{digest}"


def _normalize_header(value: str) -> str:
    return str(value or "").strip().lower()
