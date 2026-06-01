# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Advisory lockout policy for remote command senders.

This module deliberately separates risk calculation from enforcement.  The
runtime can expose high-risk senders for operator visibility without blocking
valid signed recovery commands until a safe recovery/override policy exists.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ori.time_utils import now_ms

LOCKOUT_RISK_NORMAL = "normal"
LOCKOUT_RISK_ELEVATED = "elevated"
LOCKOUT_RISK_CRITICAL = "critical"

DEFAULT_LOCKOUT_RISK_WINDOW_MS = 60 * 60 * 1000
ELEVATED_INCIDENT_THRESHOLD = 1
CRITICAL_INCIDENT_THRESHOLD = 3
ELEVATED_REJECTION_THRESHOLD = 5
CRITICAL_REJECTION_THRESHOLD = 15


@dataclass(frozen=True)
class RemoteCommandLockoutState:
    channel: str
    from_number: str
    risk_level: str
    locked_out: bool
    enforcement_enabled: bool
    incident_count: int
    rejection_count: int
    window_ms: int
    checked_at_ms: int
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


async def evaluate_remote_command_lockout(
    *,
    state_store: Any,
    channel: str,
    from_number: str,
    window_ms: int = DEFAULT_LOCKOUT_RISK_WINDOW_MS,
    enforcement_enabled: bool = False,
    now_ms_value: int | None = None,
) -> RemoteCommandLockoutState:
    """Evaluate sender risk without enforcing lockout by default."""
    normalized_channel = str(channel or "")
    normalized_sender = str(from_number or "")
    window = max(0, int(window_ms))
    checked_at = int(now_ms_value if now_ms_value is not None else now_ms())
    since_ms = checked_at - window

    incident_count = 0
    rejection_count = 0
    if state_store is not None:
        if hasattr(state_store, "count_recent_remote_command_security_incidents"):
            incident_count = (
                await state_store.count_recent_remote_command_security_incidents(
                    channel=normalized_channel,
                    from_number=normalized_sender,
                    since_ms=since_ms,
                )
            )
        if hasattr(state_store, "count_recent_remote_command_rejections"):
            rejection_count = await state_store.count_recent_remote_command_rejections(
                channel=normalized_channel,
                from_number=normalized_sender,
                since_ms=since_ms,
            )

    risk_level, reason = classify_remote_command_lockout_risk(
        incident_count=incident_count,
        rejection_count=rejection_count,
    )
    return RemoteCommandLockoutState(
        channel=normalized_channel,
        from_number=normalized_sender,
        risk_level=risk_level,
        locked_out=bool(enforcement_enabled and risk_level == LOCKOUT_RISK_CRITICAL),
        enforcement_enabled=bool(enforcement_enabled),
        incident_count=incident_count,
        rejection_count=rejection_count,
        window_ms=window,
        checked_at_ms=checked_at,
        reason=reason,
    )


def classify_remote_command_lockout_risk(
    *,
    incident_count: int,
    rejection_count: int,
) -> tuple[str, str]:
    incidents = max(0, int(incident_count))
    rejections = max(0, int(rejection_count))
    if incidents >= CRITICAL_INCIDENT_THRESHOLD:
        return LOCKOUT_RISK_CRITICAL, "critical_incident_volume"
    if rejections >= CRITICAL_REJECTION_THRESHOLD:
        return LOCKOUT_RISK_CRITICAL, "critical_rejection_volume"
    if incidents >= ELEVATED_INCIDENT_THRESHOLD:
        return LOCKOUT_RISK_ELEVATED, "recent_security_incident"
    if rejections >= ELEVATED_REJECTION_THRESHOLD:
        return LOCKOUT_RISK_ELEVATED, "elevated_rejection_volume"
    return LOCKOUT_RISK_NORMAL, "below_threshold"


def remote_command_sender_key(*, channel: str, from_number: str) -> str:
    return f"{str(channel or '')}:{str(from_number or '')}"
