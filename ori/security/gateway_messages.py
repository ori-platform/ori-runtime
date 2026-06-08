# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""HMAC authentication for site-local runtime-gateway MQTT envelopes.

Gateway messages have a different trust model from remote commands:

* remote commands are rare, state-mutating, and durably audited in SQLite;
* gateway MQTT messages are site-local, short-lived, and higher frequency.

This module therefore uses the same HMAC/canonical-JSON idea as remote
commands, but keeps replay protection in memory with a bounded TTL cache.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Mapping

from ori.utils.time_utils import now_ms

AUTH_FIELD = "auth"
AUTH_SCHEME = "hmac-sha256"
SIGNATURE_PREFIX = "hmac-sha256:"
DEFAULT_GATEWAY_AUTH_SKEW_MS = 300_000
DEFAULT_GATEWAY_AUTH_REPLAY_TTL_MS = 300_000
_MAX_REPLAY_ENTRIES = 4096


class GatewayMessageAuthError(ValueError):
    """Raised when a runtime-gateway MQTT envelope fails authentication."""


@dataclass(frozen=True)
class GatewayMessageAuthConfig:
    shared_secret: str
    max_skew_ms: int = DEFAULT_GATEWAY_AUTH_SKEW_MS
    replay_ttl_ms: int = DEFAULT_GATEWAY_AUTH_REPLAY_TTL_MS


class GatewayReplayCache:
    """In-memory TTL replay cache for short-lived gateway MQTT messages."""

    def __init__(
        self,
        *,
        ttl_ms: int = DEFAULT_GATEWAY_AUTH_REPLAY_TTL_MS,
        max_entries: int = _MAX_REPLAY_ENTRIES,
    ) -> None:
        self._ttl_ms = max(1, int(ttl_ms))
        self._max_entries = max(1, int(max_entries))
        self._seen_until_ms: dict[str, int] = {}

    def mark_seen(self, key: str, *, now_ms_value: int | None = None) -> bool:
        """Return False when *key* is already present and unexpired."""
        current_ms = int(now_ms_value if now_ms_value is not None else now_ms())
        self._prune(current_ms)
        if key in self._seen_until_ms:
            return False
        if len(self._seen_until_ms) >= self._max_entries:
            # Oldest expiry is the cheapest deterministic eviction strategy.
            oldest = min(self._seen_until_ms, key=self._seen_until_ms.get)
            self._seen_until_ms.pop(oldest, None)
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


class GatewayMessageAuthenticator:
    """Sign and verify runtime-gateway MQTT JSON payloads."""

    def __init__(
        self,
        config: GatewayMessageAuthConfig,
        *,
        replay_cache: GatewayReplayCache | None = None,
    ) -> None:
        secret = str(config.shared_secret or "").strip()
        if not secret:
            raise ValueError("gateway message shared_secret must not be empty")
        self._secret = secret
        self._max_skew_ms = max(0, int(config.max_skew_ms))
        self._replay_cache = replay_cache or GatewayReplayCache(
            ttl_ms=config.replay_ttl_ms
        )

    def sign(
        self,
        payload: Mapping[str, Any],
        *,
        message_type: str,
        signed_at_ms: int | None = None,
    ) -> dict[str, Any]:
        """Return a copy of *payload* with an HMAC auth block attached."""
        signed_payload = _payload_without_auth(payload)
        issued_ms = int(signed_at_ms if signed_at_ms is not None else now_ms())
        signature = self._signature(
            payload=signed_payload,
            message_type=message_type,
            signed_at_ms=issued_ms,
        )
        signed_payload[AUTH_FIELD] = {
            "scheme": AUTH_SCHEME,
            "signed_at_ms": issued_ms,
            "signature": signature,
        }
        return signed_payload

    def verify(
        self,
        payload: Mapping[str, Any],
        *,
        message_type: str,
        expected_device_id: str,
        expected_request_id: str | None = None,
        now_ms_value: int | None = None,
    ) -> dict[str, Any]:
        """Verify *payload* and return a copy without the auth block."""
        auth = payload.get(AUTH_FIELD)
        if not isinstance(auth, Mapping):
            raise GatewayMessageAuthError("missing_auth")
        scheme = str(auth.get("scheme", "") or "")
        if scheme != AUTH_SCHEME:
            raise GatewayMessageAuthError("unsupported_auth_scheme")
        signature = str(auth.get("signature", "") or "")
        if not signature.startswith(SIGNATURE_PREFIX):
            raise GatewayMessageAuthError("missing_signature")
        try:
            signed_at_ms = int(auth.get("signed_at_ms", 0) or 0)
        except (TypeError, ValueError) as exc:
            raise GatewayMessageAuthError("invalid_signed_at_ms") from exc

        current_ms = int(now_ms_value if now_ms_value is not None else now_ms())
        if signed_at_ms < current_ms - self._max_skew_ms:
            raise GatewayMessageAuthError("stale_timestamp")
        if signed_at_ms > current_ms + self._max_skew_ms:
            raise GatewayMessageAuthError("future_timestamp")

        unsigned_payload = _payload_without_auth(payload)
        device_id = str(unsigned_payload.get("device_id", "") or "")
        if device_id != str(expected_device_id):
            raise GatewayMessageAuthError("device_mismatch")
        request_id = str(unsigned_payload.get("request_id", "") or "")
        if expected_request_id is not None and request_id != str(expected_request_id):
            raise GatewayMessageAuthError("request_id_mismatch")

        expected = self._signature(
            payload=unsigned_payload,
            message_type=message_type,
            signed_at_ms=signed_at_ms,
        )
        if not hmac.compare_digest(signature, expected):
            raise GatewayMessageAuthError("invalid_signature")

        replay_key = "\n".join(
            [message_type, device_id, request_id, str(signed_at_ms), signature]
        )
        if not self._replay_cache.mark_seen(replay_key, now_ms_value=current_ms):
            raise GatewayMessageAuthError("replay_detected")
        return unsigned_payload

    def _signature(
        self,
        *,
        payload: Mapping[str, Any],
        message_type: str,
        signed_at_ms: int,
    ) -> str:
        device_id = str(payload.get("device_id", "") or "")
        request_id = str(payload.get("request_id", "") or "")
        signed = "\n".join(
            [
                str(message_type),
                device_id,
                request_id,
                str(int(signed_at_ms)),
                _canonical_json(payload),
            ]
        )
        digest = hmac.new(
            self._secret.encode("utf-8"),
            signed.encode("utf-8"),
            sha256,
        ).hexdigest()
        return f"{SIGNATURE_PREFIX}{digest}"


def _payload_without_auth(payload: Mapping[str, Any]) -> dict[str, Any]:
    clean = dict(payload)
    clean.pop(AUTH_FIELD, None)
    return clean


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
