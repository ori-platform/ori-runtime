# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Offline Tier C token verification with replay protection."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from ori.skills.sandbox import SkillSecurityError
from ori.skills.signing import verify_signed_payload
from ori.utils.time_utils import now_ms


@dataclass
class TokenVerificationResult:
    approved: bool
    reason: str
    token_id: str = ""


class OfflineTierCTokenVerifier:
    """Verify offline token payloads signed with Ed25519.

    Token string format:
    - base64url encoded JSON payload (preferred), or
    - raw JSON payload string.
    """

    def __init__(self, *, public_key_b64: str, max_clock_skew_s: int = 300) -> None:
        self._public_key_b64 = str(public_key_b64 or "").strip()
        self._max_clock_skew_s = max(0, int(max_clock_skew_s))

    async def verify_token(
        self,
        token: str,
        *,
        expected_device_id: str,
        expected_action: str,
        state_store: Any,
    ) -> TokenVerificationResult:
        payload = self._decode_token_payload(token)
        if payload is None:
            return await self._audit(
                state_store=state_store,
                token_id="",
                device_id=expected_device_id,
                action=expected_action,
                approved=False,
                reason="decode_failed",
            )

        token_id = str(payload.get("token_id", "")).strip()
        if not token_id:
            return await self._audit(
                state_store=state_store,
                token_id="",
                device_id=expected_device_id,
                action=expected_action,
                approved=False,
                reason="missing_token_id",
            )

        try:
            verify_signed_payload(
                payload,
                self._public_key_b64,
                context_label="offline tier c token",
            )
        except SkillSecurityError:
            return await self._audit(
                state_store=state_store,
                token_id=token_id,
                device_id=expected_device_id,
                action=expected_action,
                approved=False,
                reason="invalid_signature",
            )

        device_id = str(payload.get("device_id", "")).strip()
        if device_id != expected_device_id:
            return await self._audit(
                state_store=state_store,
                token_id=token_id,
                device_id=expected_device_id,
                action=expected_action,
                approved=False,
                reason="device_mismatch",
            )

        token_action = str(payload.get("action_scope", "")).strip()
        if token_action not in {expected_action, "*"}:
            return await self._audit(
                state_store=state_store,
                token_id=token_id,
                device_id=expected_device_id,
                action=expected_action,
                approved=False,
                reason="action_scope_mismatch",
            )

        try:
            issued_at = int(payload.get("issued_at", 0))
            expires_at = int(payload.get("expires_at", 0))
        except (TypeError, ValueError):
            return await self._audit(
                state_store=state_store,
                token_id=token_id,
                device_id=expected_device_id,
                action=expected_action,
                approved=False,
                reason="invalid_timestamp",
            )

        now_s = now_ms() // 1000
        if issued_at > now_s + self._max_clock_skew_s:
            return await self._audit(
                state_store=state_store,
                token_id=token_id,
                device_id=expected_device_id,
                action=expected_action,
                approved=False,
                reason="issued_in_future",
            )
        if expires_at < now_s - self._max_clock_skew_s:
            return await self._audit(
                state_store=state_store,
                token_id=token_id,
                device_id=expected_device_id,
                action=expected_action,
                approved=False,
                reason="expired",
            )

        nonce = str(payload.get("nonce", "")).strip()
        if not nonce:
            return await self._audit(
                state_store=state_store,
                token_id=token_id,
                device_id=expected_device_id,
                action=expected_action,
                approved=False,
                reason="missing_nonce",
            )

        if state_store is None or not hasattr(state_store, "claim_offline_token"):
            return await self._audit(
                state_store=state_store,
                token_id=token_id,
                device_id=expected_device_id,
                action=expected_action,
                approved=False,
                reason="state_store_unavailable",
            )

        claimed = await state_store.claim_offline_token(
            token_id=token_id,
            device_id=expected_device_id,
            action=expected_action,
        )
        if not claimed:
            return await self._audit(
                state_store=state_store,
                token_id=token_id,
                device_id=expected_device_id,
                action=expected_action,
                approved=False,
                reason="replay_detected",
            )

        return await self._audit(
            state_store=state_store,
            token_id=token_id,
            device_id=expected_device_id,
            action=expected_action,
            approved=True,
            reason="approved",
        )

    def _decode_token_payload(self, token: str) -> dict[str, Any] | None:
        raw = str(token or "").strip()
        if not raw:
            return None
        # Prefer base64url compact tokens; fallback to direct JSON.
        payload_txt = ""
        try:
            padded = raw + "=" * (-len(raw) % 4)
            payload_txt = base64.urlsafe_b64decode(padded.encode("ascii")).decode(
                "utf-8"
            )
        except Exception:
            payload_txt = raw
        try:
            decoded = json.loads(payload_txt)
        except json.JSONDecodeError:
            return None
        if not isinstance(decoded, dict):
            return None
        return decoded

    async def _audit(
        self,
        *,
        state_store: Any,
        token_id: str,
        device_id: str,
        action: str,
        approved: bool,
        reason: str,
    ) -> TokenVerificationResult:
        if state_store is not None and hasattr(
            state_store, "log_offline_token_attempt"
        ):
            await state_store.log_offline_token_attempt(
                token_id=token_id,
                device_id=device_id,
                action=action,
                approved=approved,
                reason=reason,
            )
        return TokenVerificationResult(
            approved=approved,
            reason=reason,
            token_id=token_id,
        )
