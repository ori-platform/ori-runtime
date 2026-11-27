# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The last-resort notice that a Tier D act failed: one SMS, straight through
SMSAction, independent of any configured alert channel or capability posture."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

#: The trigger name of a failure notice's outbox row starts with this, so its
#: retries keep the direct SMS as their last resort.
FAILURE_NOTICE_TRIGGER = "tier_d_failure:"


def failure_notice_text(action: str, device_id: str) -> str:
    return (
        f"CRITICAL: Ori safety action '{action}' FAILED to execute "
        f"on device {device_id}. Manual intervention required immediately."
    )


async def direct_failure_notice(
    sms: Any, contact: str, action: str, device_id: str
) -> bool:
    """Send the notice to *contact* through *sms* (an SMSAction when None).

    True when the provider accepted it. Never raises; a failure is logged.
    """
    if not contact:
        logger.critical(
            "no operator_contact configured: cannot send the notice that Tier D "
            "action=%r failed",
            action,
        )
        return False
    try:
        if sms is None:
            from ori.actions.sms import SMSAction

            sms = SMSAction()
        return bool(
            await sms.send(failure_notice_text(action, device_id), to_number=contact)
        )
    except Exception:
        logger.exception(
            "the direct notice that Tier D action=%r failed was not sent", action
        )
        return False
