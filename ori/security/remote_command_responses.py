# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Operator-facing responses for authenticated remote commands."""

from __future__ import annotations

from ori.security.remote_command_policy import (
    STATUS_AUDIT_ONLY,
    STATUS_DRY_RUN,
    STATUS_EXECUTED,
    STATUS_FAILED,
    STATUS_PRECONDITION_FAILED,
    STATUS_UNSUPPORTED,
    RemoteCommandExecutionResult,
)

_DEFAULT_MAX_CHARS = 160


def _clip(value: str, max_chars: int) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= max_chars:
        return text
    if max_chars <= 1:
        return text[:max_chars]
    return text[: max_chars - 1].rstrip() + "…"


def format_remote_command_execution_response(
    result: RemoteCommandExecutionResult,
    *,
    max_chars: int = _DEFAULT_MAX_CHARS,
) -> str:
    """Return a concise SMS/WhatsApp-safe execution outcome message."""
    if not isinstance(result, RemoteCommandExecutionResult):
        return _clip("Ori command accepted; execution result unavailable.", max_chars)

    command = str(result.command or "command")
    command_id = str(result.command_id or "")

    if result.status == STATUS_DRY_RUN:
        message = f"Ori command DRY RUN: {command} ({command_id}). {result.detail}"
    elif result.status == STATUS_EXECUTED and result.executed:
        message = f"Ori command executed: {command} ({command_id})."
    elif result.status == STATUS_AUDIT_ONLY:
        message = f"Ori command accepted but not executed: {command} is audit-only ({command_id})."
    elif result.status == STATUS_PRECONDITION_FAILED:
        message = f"Ori command not executed: precondition failed for {command} ({command_id}). {result.detail}"
    elif result.status == STATUS_UNSUPPORTED:
        message = f"Ori command not executed: {command} is unsupported ({command_id})."
    elif result.status == STATUS_FAILED:
        message = f"Ori command failed: {command} ({command_id}). {result.detail}"
    else:
        message = f"Ori command not executed: {command} ({command_id}). {result.detail}"

    return _clip(message, max_chars)


def format_remote_command_rejection_response(
    *,
    max_chars: int = _DEFAULT_MAX_CHARS,
) -> str:
    """Return a generic rejection response for unauthenticated commands."""
    return _clip(
        "Ori command rejected: authentication or safety verification failed.",
        max_chars,
    )
