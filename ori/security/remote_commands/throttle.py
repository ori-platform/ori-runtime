# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Abuse throttling for remote command rejection feedback.

The verifier and audit trail remain authoritative.  This module only decides
whether a channel should send another generic rejection message to a sender that
is repeatedly submitting rejected remote commands.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any

from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

DEFAULT_REJECTION_FEEDBACK_LIMIT = 5
DEFAULT_REJECTION_FEEDBACK_WINDOW_MS = 10 * 60 * 1000


@dataclass(frozen=True)
class RemoteCommandThrottleDecision:
    send_feedback: bool
    incident_logged: bool = False
    incident_id: str = ""
    channel: str = ""
    from_number: str = ""
    rejection_count: int = 0
    threshold: int = DEFAULT_REJECTION_FEEDBACK_LIMIT
    window_ms: int = DEFAULT_REJECTION_FEEDBACK_WINDOW_MS


async def should_send_rejection_feedback(
    *,
    state_store: Any,
    channel: str,
    from_number: str,
    max_rejections: int = DEFAULT_REJECTION_FEEDBACK_LIMIT,
    window_ms: int = DEFAULT_REJECTION_FEEDBACK_WINDOW_MS,
    now_ms_value: int | None = None,
) -> bool:
    decision = await evaluate_rejection_feedback(
        state_store=state_store,
        channel=channel,
        from_number=from_number,
        max_rejections=max_rejections,
        window_ms=window_ms,
        now_ms_value=now_ms_value,
    )
    return decision.send_feedback


async def evaluate_rejection_feedback(
    *,
    state_store: Any,
    channel: str,
    from_number: str,
    max_rejections: int = DEFAULT_REJECTION_FEEDBACK_LIMIT,
    window_ms: int = DEFAULT_REJECTION_FEEDBACK_WINDOW_MS,
    now_ms_value: int | None = None,
) -> RemoteCommandThrottleDecision:
    """Return whether a generic rejection response should be sent.

    The current rejected command is expected to have already been audited before
    this helper is called, so a count above ``max_rejections`` means feedback is
    suppressed for this attempt while the audit record remains intact.
    """
    normalized_channel = str(channel or "")
    normalized_sender = str(from_number or "")
    threshold = max(0, int(max_rejections))
    window = max(0, int(window_ms))
    now_value = int(now_ms_value if now_ms_value is not None else now_ms())

    if state_store is None or not hasattr(
        state_store, "count_recent_remote_command_rejections"
    ):
        return RemoteCommandThrottleDecision(
            send_feedback=True,
            channel=normalized_channel,
            from_number=normalized_sender,
            threshold=threshold,
            window_ms=window,
        )

    if not normalized_channel or not normalized_sender:
        return RemoteCommandThrottleDecision(
            send_feedback=True,
            channel=normalized_channel,
            from_number=normalized_sender,
            threshold=threshold,
            window_ms=window,
        )

    since_ms = now_value - window
    try:
        count = await state_store.count_recent_remote_command_rejections(
            channel=normalized_channel,
            from_number=normalized_sender,
            since_ms=since_ms,
        )
    except Exception:
        logger.exception(
            "Remote command rejection throttle lookup failed for channel=%s sender=%r",
            normalized_channel,
            normalized_sender,
        )
        return RemoteCommandThrottleDecision(
            send_feedback=True,
            channel=normalized_channel,
            from_number=normalized_sender,
            threshold=threshold,
            window_ms=window,
        )

    if count > threshold:
        incident_id = _incident_id(
            channel=normalized_channel,
            from_number=normalized_sender,
            now_value=now_value,
            window_ms=window,
        )
        incident_logged = False
        if hasattr(state_store, "log_remote_command_security_incident"):
            try:
                incident_logged = (
                    await state_store.log_remote_command_security_incident(
                        incident_id=incident_id,
                        channel=normalized_channel,
                        from_number=normalized_sender,
                        reason="remote_command_rejection_feedback_suppressed",
                        rejection_count=count,
                        threshold=threshold,
                        window_ms=window,
                        created_at_ms=now_value,
                    )
                )
            except Exception:
                logger.exception(
                    "Remote command security incident logging failed for channel=%s sender=%r",
                    normalized_channel,
                    normalized_sender,
                )
        if incident_logged:
            logger.warning(
                "Suppressing remote command rejection feedback for channel=%s sender=%r after %d rejected attempts",
                normalized_channel,
                normalized_sender,
                count,
            )
        return RemoteCommandThrottleDecision(
            send_feedback=False,
            incident_logged=incident_logged,
            incident_id=incident_id,
            channel=normalized_channel,
            from_number=normalized_sender,
            rejection_count=count,
            threshold=threshold,
            window_ms=window,
        )

    return RemoteCommandThrottleDecision(
        send_feedback=True,
        channel=normalized_channel,
        from_number=normalized_sender,
        rejection_count=count,
        threshold=threshold,
        window_ms=window,
    )


def _incident_id(
    *,
    channel: str,
    from_number: str,
    now_value: int,
    window_ms: int,
) -> str:
    bucket = now_value // max(1, int(window_ms))
    sender_hash = hashlib.sha256(str(from_number or "").encode("utf-8")).hexdigest()
    return f"remote-command-abuse:{channel}:{sender_hash[:16]}:{bucket}"
