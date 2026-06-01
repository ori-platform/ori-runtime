# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Abuse throttling for remote command rejection feedback.

The verifier and audit trail remain authoritative.  This module only decides
whether a channel should send another generic rejection message to a sender that
is repeatedly submitting rejected remote commands.
"""

from __future__ import annotations

import logging
from typing import Any

from ori.time_utils import now_ms

logger = logging.getLogger(__name__)

DEFAULT_REJECTION_FEEDBACK_LIMIT = 5
DEFAULT_REJECTION_FEEDBACK_WINDOW_MS = 10 * 60 * 1000


async def should_send_rejection_feedback(
    *,
    state_store: Any,
    channel: str,
    from_number: str,
    max_rejections: int = DEFAULT_REJECTION_FEEDBACK_LIMIT,
    window_ms: int = DEFAULT_REJECTION_FEEDBACK_WINDOW_MS,
    now_ms_value: int | None = None,
) -> bool:
    """Return whether a generic rejection response should be sent.

    The current rejected command is expected to have already been audited before
    this helper is called, so a count above ``max_rejections`` means feedback is
    suppressed for this attempt while the audit record remains intact.
    """
    if state_store is None or not hasattr(
        state_store, "count_recent_remote_command_rejections"
    ):
        return True

    normalized_channel = str(channel or "")
    normalized_sender = str(from_number or "")
    if not normalized_channel or not normalized_sender:
        return True

    now_value = now_ms_value if now_ms_value is not None else now_ms()
    since_ms = int(now_value) - max(0, int(window_ms))
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
        return True

    if count > max_rejections:
        if count == max_rejections + 1:
            logger.warning(
                "Suppressing remote command rejection feedback for channel=%s sender=%r after %d rejected attempts",
                normalized_channel,
                normalized_sender,
                count,
            )
        return False

    return True
