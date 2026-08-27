# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Typed contracts for outbound operator alerts and provider receipts.

Business-initiated WhatsApp messages are deliberately represented as semantic
intents rather than free-form strings.  The provider adapter resolves an intent
to an approved template and receives only the bounded variables that template
declares.  SMS still carries the full operator text.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import Enum

from ori.utils.time_utils import now_ms


class AlertIntent(str, Enum):
    """Closed set of business-initiated operator-message purposes."""

    STARTUP = "startup"
    TIER_A_ALERT = "tier_a_alert"
    TIER_C_APPROVAL = "tier_c_approval"
    TIER_C_ESCALATION = "tier_c_escalation"


# Variable order is part of the provider contract.  Each tuple position has an
# independent ceiling so an approved template cannot become a free-form-message
# tunnel by placing arbitrary model output in one variable.
_VARIABLE_LIMITS: dict[AlertIntent, tuple[int, ...]] = {
    AlertIntent.STARTUP: (80, 4, 4),
    AlertIntent.TIER_A_ALERT: (64, 80, 32),
    AlertIntent.TIER_C_APPROVAL: (64, 80, 32, 16, 8),
    AlertIntent.TIER_C_ESCALATION: (16, 80, 32, 16),
}


@dataclass(frozen=True)
class OutboundAlert:
    """One operator alert with channel-specific, semantically equal forms.

    ``sms_body`` is the detailed text used by SMS and the audit trail.
    ``template_variables`` is the ordered, bounded data used by WhatsApp.
    """

    intent: AlertIntent
    sms_body: str
    template_variables: tuple[str, ...]

    def __post_init__(self) -> None:
        limits = _VARIABLE_LIMITS[self.intent]
        if len(self.template_variables) != len(limits):
            raise ValueError(
                f"{self.intent.value} requires {len(limits)} template variables"
            )
        if not self.sms_body:
            raise ValueError("sms_body must not be empty")
        for value, limit in zip(self.template_variables, limits, strict=True):
            if not value:
                raise ValueError("template variables must not be empty")
            if len(value) > limit:
                raise ValueError(
                    f"{self.intent.value} template variable exceeds {limit} characters"
                )
            if _contains_unsafe_text(value):
                raise ValueError("template variables must not contain control text")


def build_outbound_alert(
    *,
    intent: AlertIntent,
    sms_body: str,
    template_variables: tuple[object, ...],
) -> OutboundAlert:
    """Build an alert after compacting and bounding each template field."""

    limits = _VARIABLE_LIMITS[intent]
    if len(template_variables) != len(limits):
        raise ValueError(f"{intent.value} requires {len(limits)} template variables")
    bounded = tuple(
        _bound_template_value(value, limit)
        for value, limit in zip(template_variables, limits, strict=True)
    )
    return OutboundAlert(
        intent=intent,
        sms_body=str(sms_body or "").strip(),
        template_variables=bounded,
    )


@dataclass(frozen=True)
class AlertSendReceipt:
    """Provider acknowledgement for one outbound submission.

    Acceptance says that a provider or modem accepted custody of the message.
    It does not say that the recipient's handset received it.
    """

    accepted: bool
    channel: str
    provider_message_id: str = ""
    provider_status: str = ""
    accepted_at_ms: int | None = None
    delivered_at_ms: int | None = None
    error: str = ""

    @classmethod
    def refused(cls, *, channel: str, error: str = "") -> AlertSendReceipt:
        return cls(
            accepted=False,
            channel=channel,
            provider_status="failed",
            error=error,
        )

    @classmethod
    def accepted_without_provider_receipt(
        cls,
        *,
        channel: str,
        provider_status: str = "accepted",
    ) -> AlertSendReceipt:
        return cls(
            accepted=True,
            channel=channel,
            provider_status=provider_status,
            accepted_at_ms=now_ms(),
        )


@dataclass(frozen=True)
class AlertDeliveryReceipt:
    """A later provider observation for an already accepted message."""

    provider_message_id: str
    provider_status: str
    observed_at_ms: int
    delivered_at_ms: int | None = None
    terminal_failure: bool = False


@dataclass(frozen=True)
class InboundWhatsAppMessage:
    """Provider-backed inbound message that can open a reply window."""

    provider_message_id: str
    from_number: str
    body: str
    received_at_ms: int


@dataclass(frozen=True)
class WhatsAppSessionReply:
    """Free-form reply bound to one recorded inbound WhatsApp message."""

    body: str
    in_reply_to: InboundWhatsAppMessage


def _bound_template_value(value: object, limit: int) -> str:
    compact = " ".join(str(value or "").split())
    safe = "".join(ch for ch in compact if not _unsafe_character(ch)).strip()
    if not safe:
        safe = "unknown"
    if len(safe) <= limit:
        return safe
    if limit <= 3:
        return safe[:limit]
    return safe[: limit - 3].rstrip() + "..."


def _contains_unsafe_text(value: str) -> bool:
    return any(_unsafe_character(ch) for ch in value)


def _unsafe_character(character: str) -> bool:
    category = unicodedata.category(character)
    return category in {"Cc", "Cf", "Cs", "Zl", "Zp"}
