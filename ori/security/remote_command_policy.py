# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Execution policy for authenticated remote runtime commands.

Verification only proves that a command came from an authenticated source.
Execution policy decides whether the runtime is currently allowed to act on
that command. Keep this boundary explicit: adding a command to the verifier's
allowlist must not automatically make it executable.
"""

from __future__ import annotations

from dataclasses import dataclass

from ori.security.remote_commands import RemoteCommand
from ori.time_utils import now_ms

STATUS_EXECUTED = "executed"
STATUS_AUDIT_ONLY = "audit_only"
STATUS_UNSUPPORTED = "unsupported"
STATUS_FAILED = "failed"
STATUS_PRECONDITION_FAILED = "precondition_failed"

EXECUTABLE_COMMANDS = frozenset({"APPLY_POLICY", "REFRESH_POLICY"})

AUDIT_ONLY_COMMANDS = frozenset(
    {
        "UPDATE_CONFIG",
        "UPDATE_SKILL",
        "RESTART_RUNTIME",
        "SET_THRESHOLD",
        "SET_RELAY_MODE",
        "TRIGGER_SYNC",
    }
)


@dataclass(frozen=True)
class RemoteCommandExecutionResult:
    command_id: str
    channel: str
    command: str
    status: str
    detail: str
    executed: bool = False
    executed_at_ms: int = 0


def classify_remote_command(command: RemoteCommand) -> str:
    """Return the default execution status for an authenticated command."""
    command_name = str(command.command or "").strip().upper()
    if command_name in EXECUTABLE_COMMANDS:
        return STATUS_EXECUTED
    if command_name in AUDIT_ONLY_COMMANDS:
        return STATUS_AUDIT_ONLY
    return STATUS_UNSUPPORTED


def command_result(
    command: RemoteCommand,
    *,
    status: str,
    detail: str,
    executed: bool = False,
) -> RemoteCommandExecutionResult:
    return RemoteCommandExecutionResult(
        command_id=command.command_id,
        channel=command.channel,
        command=command.command,
        status=status,
        detail=detail,
        executed=executed,
        executed_at_ms=now_ms(),
    )
