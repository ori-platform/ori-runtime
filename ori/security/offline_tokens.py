# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Offline Tier C token verification with replay protection.

Two token formats. A v1 token names a device and an action scope and approves
any request in that scope; it is never Tier C approval. A v2 token binds one
open proposal: its identifier, device, exact action, target and commissioned
zone, and is signed in its own domain, so a v1 verifier rejects it and a v2
verifier rejects a v1 token before verifying anything.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Final

from ori.security.ed25519_keys import admit_public_key
from ori.security.published_test_keys import PUBLISHED_TEST_KEYS
from ori.skills.sandbox import SkillSecurityError
from ori.skills.signing import canonical_signed_payload, verify_signed_payload
from ori.utils.time_utils import now_ms

#: The v2 signature domain: these bytes, a NUL, then the canonical payload.
V2_SIGNATURE_DOMAIN: Final = b"ori.offline_token.v2"

V2_CLAIMS: Final[tuple[str, ...]] = (
    "token_version",
    "token_id",
    "device_id",
    "proposal_id",
    "action_scope",
    "target",
    "zone_id",
    "issued_at",
    "expires_at",
    "nonce",
    "signature",
)


@dataclass
class TokenVerificationResult:
    approved: bool
    reason: str
    token_id: str = ""


@dataclass(frozen=True)
class ProposalClaims:
    """What an open proposal binds, for a v2 token to match exactly."""

    proposal_id: str
    device_id: str
    action: str
    target: str
    zone_id: str


class DuplicateMemberError(ValueError):
    """A JSON object naming a member twice, at any depth."""


def _refuse_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise DuplicateMemberError(key)
        seen[key] = value
    return seen


def decode_token_text(raw: str) -> dict[str, Any] | None:
    """The token's payload object, or None when there is nothing to judge.

    Accepts the base64url compact form or the raw JSON text. Keeps each number
    as written: a fraction or an exponent stays a float, so `2.0` is not the
    integer 2. A member named twice at any depth raises DuplicateMemberError;
    a lone surrogate, which UTF-8 cannot carry, is nothing to verify.
    """
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        padded = text + "=" * (-len(text) % 4)
        payload_txt = base64.b64decode(
            padded.encode("ascii"), altchars=b"-_", validate=True
        ).decode("utf-8")
    except Exception:
        payload_txt = text
    try:
        decoded = json.loads(payload_txt, object_pairs_hook=_refuse_duplicates)
    except DuplicateMemberError:
        raise
    except (ValueError, RecursionError):
        return None
    if not isinstance(decoded, dict):
        return None
    try:
        json.dumps(decoded, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        return None
    return decoded


def token_version(payload: dict[str, Any]) -> int | None:
    """1 for a payload with no version, 2 for the integer 2, None otherwise.

    Decided from the type the decoder kept for the number token, so a Boolean,
    a string, `2.0` and `2e0` are all malformed rather than v2.
    """
    if "token_version" not in payload:
        return 1
    version = payload["token_version"]
    if type(version) is int and version == 2:
        return 2
    return None


def _public_key_bytes(public_key_b64: str) -> bytes | None:
    try:
        key = base64.b64decode(str(public_key_b64 or "").strip(), validate=True)
    except Exception:
        return None
    return key if len(key) == 32 else None


def _signature_bytes(payload: dict[str, Any]) -> bytes | None:
    field = str(payload.get("signature") or "").strip()
    if not field.startswith("ed25519:"):
        return None
    try:
        signature = base64.b64decode(field.split(":", 1)[1], validate=True)
    except Exception:
        return None
    return signature if len(signature) == 64 else None


def v2_domain_signature_valid(payload: dict[str, Any], public_key_b64: str) -> bool:
    """Whether the signature verifies over the v2 preimage of *payload* as given.

    The domain check alone: it reads no version and refuses nothing else, so a
    caller decides the version first and this only after.
    """
    key = _public_key_bytes(public_key_b64)
    signature = _signature_bytes(payload)
    if key is None or signature is None:
        return False
    unsigned = {k: v for k, v in payload.items() if k != "signature"}
    try:
        preimage = V2_SIGNATURE_DOMAIN + b"\x00" + canonical_signed_payload(unsigned)
    except SkillSecurityError:
        return False
    try:
        admit_public_key(key).verify(signature, preimage)
    except Exception:
        return False
    return True


def v1_signature_valid(payload: dict[str, Any], public_key_b64: str) -> bool:
    """Whether a v1 verifier, over the unprefixed preimage, accepts the signature."""
    key = _public_key_bytes(public_key_b64)
    signature = _signature_bytes(payload)
    if key is None or signature is None:
        return False
    unsigned = {k: v for k, v in payload.items() if k != "signature"}
    try:
        preimage = canonical_signed_payload(unsigned)
    except SkillSecurityError:
        return False
    try:
        admit_public_key(key).verify(signature, preimage)
    except Exception:
        return False
    return True


def v2_verdict(raw: str, public_key_b64: str) -> str:
    """A v2 verifier's verdict on *raw*: the version first, the domain second.

    `accept`, `refuse:duplicate_member`, `refuse:decode`, `refuse:version` or
    `refuse:signature`. Nothing is verified before the version is read.
    """
    try:
        payload = decode_token_text(raw)
    except DuplicateMemberError:
        return "refuse:duplicate_member"
    if payload is None:
        return "refuse:decode"
    if token_version(payload) != 2:
        return "refuse:version"
    if not v2_domain_signature_valid(payload, public_key_b64):
        return "refuse:signature"
    return "accept"


class OfflineTierCTokenVerifier:
    """Verify offline token payloads signed with Ed25519.

    Token string format:
    - base64url encoded JSON payload (preferred), or
    - raw JSON payload string.
    """

    def __init__(self, *, public_key_b64: str, max_clock_skew_s: int = 300) -> None:
        self._public_key_b64 = str(public_key_b64 or "").strip()
        self._max_clock_skew_s = max(0, int(max_clock_skew_s))

    def _anchor_is_published(self) -> bool:
        key = _public_key_bytes(self._public_key_b64)
        return key is not None and key in PUBLISHED_TEST_KEYS

    def verify_tier_c_token(
        self, token: str, *, proposal: ProposalClaims
    ) -> TokenVerificationResult:
        """Judge a v2 token against the open proposal it must name.

        Nothing is claimed here: the caller claims `token_id` inside the same
        transaction that admits the approval, so a spent token and a durable
        approval never exist apart. A v1 token is refused before any signature
        is read, and a wildcard scope approves nothing.
        """
        try:
            payload = decode_token_text(token)
        except DuplicateMemberError:
            return TokenVerificationResult(False, "duplicate_member")
        if payload is None:
            return TokenVerificationResult(False, "decode_failed")
        token_id = str(payload.get("token_id", "") or "").strip()
        version = token_version(payload)
        if version != 2:
            return TokenVerificationResult(
                False,
                "v1_token_is_not_tier_c_approval"
                if version == 1
                else "malformed_version",
                token_id,
            )
        if not token_id:
            return TokenVerificationResult(False, "missing_token_id")
        if any(ord(ch) < 0x20 or ch == "\x7f" for ch in token_id):
            return TokenVerificationResult(False, "malformed_token_id")
        if set(payload) - set(V2_CLAIMS):
            return TokenVerificationResult(False, "unknown_claim", token_id)
        if self._anchor_is_published():
            return TokenVerificationResult(False, "trust_anchor_published", token_id)
        if not v2_domain_signature_valid(payload, self._public_key_b64):
            return TokenVerificationResult(False, "invalid_signature", token_id)
        scope = str(payload.get("action_scope", "") or "")
        if scope == "*":
            return TokenVerificationResult(False, "wildcard_scope", token_id)
        bound = (
            ("proposal_id", proposal.proposal_id, "proposal_mismatch"),
            ("device_id", proposal.device_id, "device_mismatch"),
            ("action_scope", proposal.action, "action_scope_mismatch"),
            ("target", proposal.target, "target_mismatch"),
            ("zone_id", proposal.zone_id, "zone_mismatch"),
        )
        for claim, expected, reason in bound:
            value = payload.get(claim)
            if not isinstance(value, str) or value != expected:
                return TokenVerificationResult(False, reason, token_id)
        issued_at = payload.get("issued_at")
        expires_at = payload.get("expires_at")
        if (
            type(issued_at) is not int
            or type(expires_at) is not int
            or expires_at < issued_at
        ):
            return TokenVerificationResult(False, "invalid_timestamp", token_id)
        now_s = now_ms() // 1000
        if issued_at > now_s + self._max_clock_skew_s:
            return TokenVerificationResult(False, "issued_in_future", token_id)
        if expires_at < now_s - self._max_clock_skew_s:
            return TokenVerificationResult(False, "expired", token_id)
        if not str(payload.get("nonce", "") or "").strip():
            return TokenVerificationResult(False, "missing_nonce", token_id)
        return TokenVerificationResult(True, "verified", token_id)

    async def verify_token(
        self,
        token: str,
        *,
        expected_device_id: str,
        expected_action: str,
        state_store: Any,
    ) -> TokenVerificationResult:
        """Verify and claim a v1 token for the existing approval workflow.

        The workflow admits this only for a host-state action that requires
        approval; a physical action at any tier and a Tier C action never take
        a v1 token, and the dispatcher refuses them before this is reached.
        """
        try:
            payload = decode_token_text(token)
        except DuplicateMemberError:
            payload = None
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
        try:
            return decode_token_text(token)
        except DuplicateMemberError:
            return None

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
