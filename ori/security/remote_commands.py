# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Authenticated remote runtime command verification.

Remote commands are not Tier C approval replies.  Approval replies answer an
already-created proposal; remote commands attempt to change runtime state.  This
module verifies those commands before any channel-specific ingress can dispatch
or persist them as executable instructions.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from ori.time_utils import now_ms

_ALLOWED_COMMANDS = {
    "UPDATE_CONFIG",
    "UPDATE_SKILL",
    "APPLY_POLICY",
    "REFRESH_POLICY",
    "RESTART_RUNTIME",
    "SET_THRESHOLD",
    "SET_RELAY_MODE",
    "TRIGGER_SYNC",
}

_FORBIDDEN_COMMANDS = {
    "DISABLE_TIER_D",
    "DISABLE_SAFETY",
    "DISABLE_SENSOR_VALIDATION",
    "BYPASS_DEVICE_POLICY_FOR_TIER_B_OR_C",
    "EXECUTE_RELAY",
    "FORCE_ACTUATOR",
}

_COMMAND_FIELDS = {"command_id", "device_id", "issued_at_ms", "command", "args"}


@dataclass(frozen=True)
class RemoteCommand:
    command_id: str
    channel: str
    device_id: str
    issued_at_ms: int
    command: str
    args: dict[str, Any]
    signature: str | None = None
    from_number: str = ""


@dataclass(frozen=True)
class CommandVerificationResult:
    accepted: bool
    reason: str
    command: RemoteCommand | None = None


class RemoteCommandVerifier:
    """Verify HMAC-authenticated remote commands with replay protection."""

    def __init__(
        self,
        *,
        device_id: str,
        shared_secret: str | None,
        max_skew_ms: int = 300_000,
    ) -> None:
        self._device_id = str(device_id or "").strip()
        self._shared_secret = str(shared_secret or "").strip()
        self._max_skew_ms = max(0, int(max_skew_ms))

    async def verify(
        self,
        payload: dict[str, Any],
        *,
        state_store: Any,
    ) -> CommandVerificationResult:
        parsed, parse_reason = _parse_command(payload)
        if parsed is None:
            return await self._audit(
                state_store=state_store,
                command_id=str(payload.get("command_id", "") or ""),
                channel=str(payload.get("channel", "") or ""),
                from_number=str(payload.get("from_number", "") or ""),
                command=str(payload.get("command", "") or ""),
                accepted=False,
                reason=parse_reason,
                issued_at_ms=_safe_int_or_none(payload.get("issued_at_ms")),
            )

        if parsed.device_id != self._device_id:
            return await self._reject(state_store, parsed, "device_mismatch")

        if not self._shared_secret:
            return await self._reject(state_store, parsed, "missing_shared_secret")

        now = now_ms()
        if parsed.issued_at_ms < now - self._max_skew_ms:
            return await self._reject(state_store, parsed, "stale_timestamp")
        if parsed.issued_at_ms > now + self._max_skew_ms:
            return await self._reject(state_store, parsed, "future_timestamp")

        if parsed.command in _FORBIDDEN_COMMANDS:
            return await self._reject(state_store, parsed, "forbidden_command")
        if parsed.command not in _ALLOWED_COMMANDS:
            return await self._reject(state_store, parsed, "unknown_command")
        if _contains_forbidden_safety_disable(parsed.args):
            return await self._reject(state_store, parsed, "forbidden_safety_mutation")

        if not parsed.signature:
            return await self._reject(state_store, parsed, "missing_signature")
        if not parsed.signature.startswith("hmac-sha256:"):
            return await self._reject(state_store, parsed, "unsupported_signature")

        expected = sign_remote_command(parsed, self._shared_secret)
        if not hmac.compare_digest(parsed.signature, expected):
            return await self._reject(state_store, parsed, "invalid_signature")

        if state_store is None or not hasattr(state_store, "has_remote_command"):
            return await self._reject(state_store, parsed, "state_store_unavailable")
        if await state_store.has_remote_command(parsed.command_id):
            return await self._reject(state_store, parsed, "replay_detected")

        return await self._audit(
            state_store=state_store,
            command_id=parsed.command_id,
            channel=parsed.channel,
            from_number=parsed.from_number,
            command=parsed.command,
            accepted=True,
            reason="accepted",
            issued_at_ms=parsed.issued_at_ms,
            command_obj=parsed,
        )

    async def _reject(
        self,
        state_store: Any,
        command: RemoteCommand,
        reason: str,
    ) -> CommandVerificationResult:
        return await self._audit(
            state_store=state_store,
            command_id=command.command_id,
            channel=command.channel,
            from_number=command.from_number,
            command=command.command,
            accepted=False,
            reason=reason,
            issued_at_ms=command.issued_at_ms,
            command_obj=command,
        )

    async def _audit(
        self,
        *,
        state_store: Any,
        command_id: str,
        channel: str,
        from_number: str = "",
        command: str,
        accepted: bool,
        reason: str,
        issued_at_ms: int | None,
        command_obj: RemoteCommand | None = None,
    ) -> CommandVerificationResult:
        if state_store is not None and hasattr(
            state_store, "log_remote_command_attempt"
        ):
            await state_store.log_remote_command_attempt(
                command_id=command_id,
                channel=channel,
                from_number=from_number,
                command=command,
                accepted=accepted,
                reason=reason,
                issued_at_ms=issued_at_ms,
            )
        return CommandVerificationResult(
            accepted=accepted,
            reason=reason,
            command=command_obj,
        )


async def handle_remote_command(
    payload: dict[str, Any],
    *,
    channel: str,
    state_store: Any,
    verifier: RemoteCommandVerifier,
) -> CommandVerificationResult:
    """Verify a remote command before any runtime state mutation is allowed."""
    candidate = dict(payload)
    candidate["channel"] = channel
    return await verifier.verify(candidate, state_store=state_store)


async def verify_inbound_remote_command(
    payload: dict[str, Any],
    *,
    channel: str,
    from_number: str = "",
    state_store: Any,
    verifier: RemoteCommandVerifier | None,
) -> CommandVerificationResult | None:
    """Extract and verify an inbound remote command for any transport channel.

    Returns:
        ``None`` when the inbound message is not a structured remote command.
        A :class:`CommandVerificationResult` when a command was found and either
        accepted or rejected. Callers must not treat either result as a Tier C
        approval reply.
    """
    command_payload = extract_remote_command_payload(
        payload,
        channel=channel,
        from_number=from_number,
    )
    if command_payload is None:
        return None

    return await verify_extracted_remote_command(
        command_payload,
        channel=channel,
        state_store=state_store,
        verifier=verifier,
    )


async def verify_extracted_remote_command(
    command_payload: dict[str, Any],
    *,
    channel: str,
    state_store: Any,
    verifier: RemoteCommandVerifier | None,
) -> CommandVerificationResult:
    """Verify an already-extracted remote command payload.

    This lets pull-based transports deduplicate repeated provider results
    before invoking verification and audit writes.
    """
    if verifier is None:
        await _audit_without_verifier(
            command_payload,
            channel=channel,
            state_store=state_store,
        )
        return CommandVerificationResult(
            accepted=False,
            reason="remote_command_verifier_disabled",
        )

    return await handle_remote_command(
        command_payload,
        channel=channel,
        state_store=state_store,
        verifier=verifier,
    )


def extract_remote_command_payload(
    payload: dict[str, Any],
    *,
    channel: str,
    from_number: str = "",
) -> dict[str, Any] | None:
    """Extract a structured remote command from webhook payloads.

    Supported SMS text forms:
    - ``ORI_COMMAND {json}``
    - raw JSON object containing command fields

    Plain Tier C replies like ``YES`` or ``NO`` return ``None``.
    """
    direct = {key: payload.get(key) for key in _COMMAND_FIELDS if key in payload}
    if _COMMAND_FIELDS <= set(direct):
        result = dict(payload)
        result["channel"] = channel
        result["from_number"] = from_number
        return result

    raw = str(payload.get("text") or payload.get("message") or "").strip()
    if not raw:
        return None

    body = raw
    if raw.upper().startswith("ORI_COMMAND "):
        body = raw[len("ORI_COMMAND ") :].strip()
    elif not raw.startswith("{"):
        return None

    try:
        decoded = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(decoded, dict):
        return None
    if not _COMMAND_FIELDS <= set(decoded):
        return None

    decoded["channel"] = channel
    decoded["from_number"] = from_number
    return decoded


def sign_remote_command(
    command: RemoteCommand | dict[str, Any], shared_secret: str
) -> str:
    """Return ``hmac-sha256:<hex>`` for a remote command payload."""
    if isinstance(command, RemoteCommand):
        device_id = command.device_id
        command_id = command.command_id
        issued_at_ms = command.issued_at_ms
        command_name = command.command
        args = command.args
    else:
        device_id = str(command.get("device_id", "") or "")
        command_id = str(command.get("command_id", "") or "")
        issued_at_ms = int(command.get("issued_at_ms", 0) or 0)
        command_name = str(command.get("command", "") or "").strip().upper()
        args = command.get("args") if isinstance(command.get("args"), dict) else {}

    signed = "\n".join(
        [
            device_id,
            command_id,
            str(issued_at_ms),
            command_name,
            _canonical_json(args),
        ]
    )
    digest = hmac.new(
        str(shared_secret).encode("utf-8"),
        signed.encode("utf-8"),
        sha256,
    ).hexdigest()
    return f"hmac-sha256:{digest}"


def _parse_command(payload: dict[str, Any]) -> tuple[RemoteCommand | None, str]:
    command_id = str(payload.get("command_id", "") or "").strip()
    if not command_id:
        return None, "missing_command_id"

    device_id = str(payload.get("device_id", "") or "").strip()
    if not device_id:
        return None, "missing_device_id"

    issued_at_ms = _safe_int_or_none(payload.get("issued_at_ms"))
    if issued_at_ms is None:
        return None, "invalid_timestamp"

    command = str(payload.get("command", "") or "").strip().upper()
    if not command:
        return None, "missing_command"

    args = payload.get("args")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return None, "invalid_args"

    return (
        RemoteCommand(
            command_id=command_id,
            channel=str(payload.get("channel", "") or ""),
            device_id=device_id,
            issued_at_ms=issued_at_ms,
            command=command,
            args=args,
            signature=str(payload.get("signature") or "") or None,
            from_number=str(payload.get("from_number", "") or ""),
        ),
        "ok",
    )


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _safe_int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


async def _audit_without_verifier(
    payload: dict[str, Any],
    *,
    channel: str,
    state_store: Any,
) -> None:
    if state_store is None or not hasattr(state_store, "log_remote_command_attempt"):
        return
    await state_store.log_remote_command_attempt(
        command_id=str(payload.get("command_id", "") or ""),
        channel=channel,
        from_number=str(payload.get("from_number", "") or ""),
        command=str(payload.get("command", "") or ""),
        accepted=False,
        reason="remote_command_verifier_disabled",
        issued_at_ms=_safe_int_or_none(payload.get("issued_at_ms")),
    )


def _contains_forbidden_safety_disable(value: Any) -> bool:
    if isinstance(value, dict):
        normalized = {_normalize_key(k): v for k, v in value.items()}
        tier_value = str(
            normalized.get("actiontier") or normalized.get("tier") or ""
        ).upper()
        if tier_value == "D" and (
            _is_false_like(normalized.get("enabled"))
            or _is_false_like(normalized.get("bypassllm"))
        ):
            return True

        for key, item in normalized.items():
            if key in {"disabletierd", "disablesafety", "disablesensorvalidation"}:
                return True
            if key in {"tierdenabled", "safetyenabled", "sensorvalidationenabled"}:
                if _is_false_like(item):
                    return True
            if _contains_forbidden_safety_disable(item):
                return True
        return False

    if isinstance(value, list):
        return any(_contains_forbidden_safety_disable(item) for item in value)
    return False


def _normalize_key(value: Any) -> str:
    return str(value).lower().replace("_", "").replace("-", "").replace(".", "")


def _is_false_like(value: Any) -> bool:
    if value is False:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"false", "0", "no", "off", "disabled"}
    if isinstance(value, int | float):
        return value == 0
    return False
