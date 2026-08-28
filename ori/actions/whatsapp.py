# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""WhatsApp action executor and approval-response listener.

Provider abstraction
--------------------
All Twilio-specific code lives in :class:`TwilioProvider`, which implements
:class:`WhatsAppProvider`.  :class:`WhatsAppAction` holds a reference to a
provider instance and never calls Twilio directly.  Migrating to another
backend (e.g. Meta Cloud API) in Phase 2 requires only:

    action = WhatsAppAction(provider=MetaCloudProvider())

Nothing in the approval workflow logic changes.

Business-initiated messages are accepted only as typed alerts and are sent
through pre-approved provider templates.  Free-form text is restricted to a
reply that is bound to a recorded inbound message inside the 24-hour session
window.
"""

import asyncio
import datetime
import json
import logging
import os
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Protocol, runtime_checkable

from ori.actions.alert_delivery import (
    AlertDeliveryReceipt,
    AlertIntent,
    AlertSendReceipt,
    InboundWhatsAppMessage,
    OutboundAlert,
    WhatsAppSessionReply,
    build_outbound_alert,
)
from ori.network.events import ReasoningResult
from ori.security.remote_command_responses import (
    format_remote_command_execution_response,
    format_remote_command_rejection_response,
)
from ori.security.remote_command_throttle import (
    RemoteCommandThrottleDecision,
    evaluate_rejection_feedback,
)
from ori.security.remote_commands import (
    RemoteCommand,
    RemoteCommandVerifier,
    extract_remote_command_payload,
    verify_extracted_remote_command,
)
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

# ── Approval message template (canonical form from CLAUDE.md) ────────────────

_APPROVAL_TEMPLATE = """\
ORI ALERT — Action Required
Device: {device_id}
Proposal ID: {proposal_id}
Time: {timestamp}

OBSERVATION:
{observation}

PROPOSED ACTION:
{action_description}

CONFIDENCE: {confidence}

Reply YES-{proposal_id} to approve  |  Reply NO-{proposal_id} to cancel
Auto-cancel in {timeout} seconds if no response."""

_WHATSAPP_REPLY_WINDOW_MS = 24 * 60 * 60 * 1000
_DELIVERED_STATUSES = frozenset({"delivered", "read"})
_TERMINAL_FAILURE_STATUSES = frozenset({"failed", "undelivered", "canceled"})


# ── Provider protocol ─────────────────────────────────────────────────────────


@runtime_checkable
class WhatsAppProvider(Protocol):
    """Interface every WhatsApp backend must satisfy."""

    async def send_template(
        self,
        to: str,
        template_id: str,
        variables: tuple[str, ...],
    ) -> AlertSendReceipt:
        """Submit one approved business template."""
        raise NotImplementedError

    async def send_session_reply(
        self,
        to: str,
        message: str,
    ) -> AlertSendReceipt:
        """Submit free-form text inside a caller-proven reply window."""
        raise NotImplementedError

    async def get_incoming(
        self,
        from_number: str,
        since_ms: int,
    ) -> list[InboundWhatsAppMessage]:
        """Return provider-backed messages received after *since_ms*.

        *since_ms* is a Unix timestamp in milliseconds (UTC).
        Returns an empty list when there are no matching messages.
        """
        raise NotImplementedError

    async def get_delivery_receipt(
        self,
        provider_message_id: str,
    ) -> AlertDeliveryReceipt | None:
        """Return the provider's latest status for an accepted message."""
        raise NotImplementedError


# ── Twilio provider ───────────────────────────────────────────────────────────


class TwilioProvider:
    """Concrete :class:`WhatsAppProvider` backed by the Twilio REST API.

    Credentials are read from environment variables at construction time:

    - ``TWILIO_ACCOUNT_SID``
    - ``TWILIO_AUTH_TOKEN``
    - ``TWILIO_WHATSAPP_FROM``  (e.g. ``whatsapp:+14155238886``)

    If any credential is missing the provider enters *degraded mode*: all
    calls log a warning and return safe empty/False values without raising.
    """

    def __init__(self) -> None:
        self._sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
        self._token = os.environ.get("TWILIO_AUTH_TOKEN", "")
        self._from = os.environ.get("TWILIO_WHATSAPP_FROM", "")
        self._request_timeout_s = max(
            1.0, float(os.environ.get("TWILIO_REQUEST_TIMEOUT_S", "5.0"))
        )
        self._min_incoming_poll_interval_s = max(
            1.0, float(os.environ.get("TWILIO_INCOMING_MIN_POLL_INTERVAL_S", "5.0"))
        )
        self._rate_limit_cooldown_s = max(
            5.0, float(os.environ.get("TWILIO_RATE_LIMIT_COOLDOWN_S", "30.0"))
        )
        self._last_incoming_poll_monotonic = 0.0
        self._next_incoming_poll_monotonic = 0.0
        self._ready = bool(self._sid and self._token and self._from)
        if self._ready and not self._from.lower().startswith("whatsapp:+"):
            logger.error(
                "TwilioProvider: TWILIO_WHATSAPP_FROM must start with 'whatsapp:+'; got %r",
                self._from,
            )
            self._ready = False
        if not self._ready:
            logger.warning(
                "TwilioProvider: TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / "
                "TWILIO_WHATSAPP_FROM are not set — WhatsApp delivery disabled."
            )

    # ------------------------------------------------------------------
    # WhatsAppProvider interface
    # ------------------------------------------------------------------

    async def send_template(
        self,
        to: str,
        template_id: str,
        variables: tuple[str, ...],
    ) -> AlertSendReceipt:
        return await self._send(
            to=to,
            content_sid=template_id,
            content_variables=json.dumps(
                {str(index): value for index, value in enumerate(variables, start=1)},
                separators=(",", ":"),
            ),
        )

    async def send_session_reply(
        self,
        to: str,
        message: str,
    ) -> AlertSendReceipt:
        return await self._send(to=to, body=message)

    async def _send(self, *, to: str, **message_fields: str) -> AlertSendReceipt:
        if not self._ready:
            logger.warning(
                "TwilioProvider: skipped send (credentials not configured). to=%r", to
            )
            return AlertSendReceipt.refused(
                channel="whatsapp", error="credentials_not_configured"
            )
        if not str(to).lower().startswith("whatsapp:+"):
            logger.error(
                "TwilioProvider: destination must start with 'whatsapp:+'; got %r",
                to,
            )
            return AlertSendReceipt.refused(
                channel="whatsapp", error="invalid_destination"
            )

        try:
            from twilio.rest import Client

            client = Client(self._sid, self._token)
            # Twilio's Python SDK is synchronous — run in executor to avoid
            # blocking the event loop.
            provider_message = await asyncio.wait_for(
                asyncio.to_thread(
                    client.messages.create,
                    from_=self._from,
                    to=to,
                    **message_fields,
                ),
                timeout=self._request_timeout_s,
            )
            provider_message_id = str(getattr(provider_message, "sid", "") or "")
            provider_status = str(
                getattr(provider_message, "status", "accepted") or "accepted"
            ).lower()
            accepted_at_ms = now_ms()
            delivered_at_ms = None
            if provider_status in _DELIVERED_STATUSES:
                delivered_at_ms = (
                    _provider_datetime_ms(
                        getattr(provider_message, "date_updated", None)
                    )
                    or accepted_at_ms
                )
            logger.info(
                "TwilioProvider: message accepted to=%r sid=%s status=%s",
                to,
                provider_message_id,
                provider_status,
            )
            return AlertSendReceipt(
                accepted=True,
                channel="whatsapp",
                provider_message_id=provider_message_id,
                provider_status=provider_status,
                accepted_at_ms=accepted_at_ms,
                delivered_at_ms=delivered_at_ms,
            )
        except Exception:
            logger.exception("TwilioProvider: message submission failed to %r", to)
            return AlertSendReceipt.refused(
                channel="whatsapp", error="provider_submission_failed"
            )

    async def get_incoming(
        self,
        from_number: str,
        since_ms: int,
    ) -> list[InboundWhatsAppMessage]:
        """Poll Twilio for inbound messages from *from_number* after *since_ms*.

        Returns typed provider records in chronological order.
        """
        if not self._ready:
            return []
        if not str(from_number).lower().startswith("whatsapp:+"):
            logger.error(
                "TwilioProvider.get_incoming: source number must start with 'whatsapp:+'; got %r",
                from_number,
            )
            return []

        now_mono = time.monotonic()
        if now_mono < self._next_incoming_poll_monotonic:
            return []
        if (
            now_mono - self._last_incoming_poll_monotonic
            < self._min_incoming_poll_interval_s
        ):
            return []
        self._last_incoming_poll_monotonic = now_mono

        try:
            import datetime

            from twilio.rest import Client

            # Convert ms timestamp to a datetime for the Twilio filter
            since_dt = datetime.datetime.fromtimestamp(
                since_ms / 1000.0, tz=datetime.timezone.utc
            )
            client = Client(self._sid, self._token)
            messages = await asyncio.wait_for(
                asyncio.to_thread(
                    client.messages.list,
                    from_=from_number,
                    to=self._from,
                    date_sent_after=since_dt,
                ),
                timeout=self._request_timeout_s,
            )
            inbound: list[InboundWhatsAppMessage] = []
            for message in messages:
                body = getattr(message, "body", None)
                provider_message_id = str(getattr(message, "sid", "") or "")
                received_at_ms = _provider_datetime_ms(
                    getattr(message, "date_sent", None)
                    or getattr(message, "date_created", None)
                )
                if body is None or not provider_message_id or received_at_ms is None:
                    continue
                inbound.append(
                    InboundWhatsAppMessage(
                        provider_message_id=provider_message_id,
                        from_number=str(
                            getattr(message, "from_", from_number) or from_number
                        ),
                        body=str(body),
                        received_at_ms=received_at_ms,
                    )
                )
            inbound.sort(
                key=lambda item: (item.received_at_ms, item.provider_message_id)
            )
            return inbound
        except Exception as exc:
            status = getattr(exc, "status", None)
            code = getattr(exc, "code", None)
            if status == 429 or code == 20429:
                self._next_incoming_poll_monotonic = (
                    time.monotonic() + self._rate_limit_cooldown_s
                )
                logger.warning(
                    "TwilioProvider.get_incoming: rate-limited; backing off for %.1fs",
                    self._rate_limit_cooldown_s,
                )
            logger.exception(
                "TwilioProvider.get_incoming: failed to fetch messages from %r",
                from_number,
            )
            return []

    async def get_delivery_receipt(
        self,
        provider_message_id: str,
    ) -> AlertDeliveryReceipt | None:
        if not self._ready or not provider_message_id:
            return None
        try:
            from twilio.rest import Client

            client = Client(self._sid, self._token)
            provider_message = await asyncio.wait_for(
                asyncio.to_thread(client.messages(provider_message_id).fetch),
                timeout=self._request_timeout_s,
            )
            status = str(getattr(provider_message, "status", "") or "").lower()
            if not status:
                return None
            observed_at_ms = now_ms()
            delivered_at_ms = None
            if status in _DELIVERED_STATUSES:
                delivered_at_ms = (
                    _provider_datetime_ms(
                        getattr(provider_message, "date_updated", None)
                    )
                    or observed_at_ms
                )
            return AlertDeliveryReceipt(
                provider_message_id=provider_message_id,
                provider_status=status,
                observed_at_ms=observed_at_ms,
                delivered_at_ms=delivered_at_ms,
                terminal_failure=status in _TERMINAL_FAILURE_STATUSES,
            )
        except Exception:
            logger.exception(
                "TwilioProvider.get_delivery_receipt: failed for sid=%s",
                provider_message_id,
            )
            return None


# ── WhatsAppAction ────────────────────────────────────────────────────────────


class WhatsAppAction:
    """Sends WhatsApp messages and listens for operator approval responses.

    Args:
        provider: A :class:`WhatsAppProvider` implementation.  Defaults to a
            :class:`TwilioProvider` instance constructed from environment
            variables.

    Tier C approval orchestration lives in ``ActionDispatcher`` via
    ``AlertFailoverSender``. This class provides the transport primitives
    used there (``send`` and ``listen_for_response``).

    ``send_approval_request`` is retained for standalone integrations and tests,
    but is not used by the runtime's built-in approval workflow.
    """

    _POLL_INTERVAL_SECONDS: int = 5

    def __init__(
        self,
        provider: WhatsAppProvider | None = None,
        *,
        templates: Mapping[str, str] | None = None,
        state_store: Any = None,
        remote_command_verifier: RemoteCommandVerifier | None = None,
        remote_command_handler: Callable[[RemoteCommand], Awaitable[Any]] | None = None,
        remote_command_incident_handler: Callable[
            [RemoteCommandThrottleDecision], Awaitable[Any]
        ]
        | None = None,
    ) -> None:
        self._provider: WhatsAppProvider = provider or TwilioProvider()
        self._templates = {
            str(key).strip(): str(value).strip()
            for key, value in (templates or {}).items()
        }
        self._state_store = state_store
        self._remote_command_verifier = remote_command_verifier
        self._remote_command_handler = remote_command_handler
        self._remote_command_incident_handler = remote_command_incident_handler

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def submit(
        self,
        alert: OutboundAlert,
        to_number: str,
    ) -> AlertSendReceipt:
        """Submit a business-initiated alert through an approved template."""

        template_id = self._templates.get(alert.intent.value, "")
        if not template_id:
            logger.error(
                "WhatsAppAction.submit: no template configured for intent=%s",
                alert.intent.value,
            )
            return AlertSendReceipt.refused(
                channel="whatsapp", error="template_not_configured"
            )
        try:
            return await self._provider.send_template(
                to_number,
                template_id,
                alert.template_variables,
            )
        except Exception:
            logger.exception(
                "WhatsAppAction.submit: provider raised unexpectedly for to=%r",
                to_number,
            )
            return AlertSendReceipt.refused(channel="whatsapp", error="provider_raised")

    async def send_reply(
        self,
        reply: WhatsAppSessionReply,
        to_number: str,
    ) -> bool:
        """Send a free-form reply only when bound to a fresh inbound message."""

        inbound = reply.in_reply_to
        age_ms = now_ms() - int(inbound.received_at_ms)
        if not inbound.provider_message_id:
            logger.warning("WhatsAppAction.send_reply: inbound provider SID is missing")
            return False
        if _normalize_address(inbound.from_number) != _normalize_address(to_number):
            logger.warning(
                "WhatsAppAction.send_reply: destination is not the inbound sender"
            )
            return False
        if age_ms < 0 or age_ms >= _WHATSAPP_REPLY_WINDOW_MS:
            logger.warning(
                "WhatsAppAction.send_reply: inbound reply window is not open sid=%s",
                inbound.provider_message_id,
            )
            return False
        try:
            receipt = await self._provider.send_session_reply(to_number, reply.body)
        except Exception:
            logger.exception(
                "WhatsAppAction.send_reply: provider raised unexpectedly for to=%r",
                to_number,
            )
            return False
        return bool(receipt.accepted)

    async def get_delivery_receipt(
        self,
        provider_message_id: str,
    ) -> AlertDeliveryReceipt | None:
        try:
            return await self._provider.get_delivery_receipt(provider_message_id)
        except Exception:
            logger.exception(
                "WhatsAppAction.get_delivery_receipt: provider raised for sid=%s",
                provider_message_id,
            )
            return None

    async def send_approval_request(
        self,
        result: ReasoningResult,
        action: str,
        timeout_seconds: int,
        to_number: str,
        device_id: str = "ori-device",
        proposal_id: str | None = None,
    ) -> tuple[str, bool]:
        """Format and send the canonical Tier C approval request.

        Args:
            result: The :class:`~ori.network.events.ReasoningResult` from the
                Intelligence Elevator.
            action: Human-readable description of the proposed action
                (e.g. ``"open_safety_circuit"``).
            timeout_seconds: Seconds before the request auto-cancels.
            to_number: Destination WhatsApp number
                (e.g. ``"whatsapp:+234XXXXXXXXXX"``).
            device_id: Device identifier shown in the alert header.

        Returns:
            ``(message, accepted)`` where ``message`` is the detailed SMS/audit
            form and ``accepted`` reports provider submission only.
        """
        timestamp = datetime.datetime.now(tz=datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        resolved_proposal_id = (
            str(proposal_id or "").strip().upper() or uuid.uuid4().hex[:8].upper()
        )
        message = _APPROVAL_TEMPLATE.format(
            device_id=device_id,
            proposal_id=resolved_proposal_id,
            timestamp=timestamp,
            observation=result.text,
            action_description=action,
            confidence=f"{result.confidence:.0%}",
            timeout=timeout_seconds,
        )
        alert = build_outbound_alert(
            intent=AlertIntent.TIER_C_APPROVAL,
            sms_body=message,
            template_variables=(
                action,
                device_id,
                timestamp,
                resolved_proposal_id,
                timeout_seconds,
            ),
        )
        receipt = await self.submit(alert, to_number)
        return message, bool(receipt.accepted)

    async def listen_for_response(
        self,
        from_number: str,
        timeout_seconds: int,
        since_ms: int | None = None,
    ) -> str | None:
        """Poll for an inbound WhatsApp reply from *from_number*.

        Polls every :attr:`_POLL_INTERVAL_SECONDS` seconds until a message
        arrives or *timeout_seconds* elapses.

        Args:
            from_number: The operator's WhatsApp number to listen for
                (e.g. ``"whatsapp:+234XXXXXXXXXX"``).
            timeout_seconds: Maximum seconds to wait before returning None.
            since_ms: Only consider messages received at or after this Unix
                timestamp (milliseconds, UTC).  Defaults to the current time
                at the moment the method is called.  Pass a timestamp captured
                *before* the approval request was sent to catch replies that
                arrive in the window between sending and starting to listen.

        Returns:
            The first message body received, or None on timeout.
        """
        since_ms = since_ms if since_ms is not None else now_ms()
        deadline = time.monotonic() + timeout_seconds
        seen_remote_command_ids: set[str] = set()

        while time.monotonic() < deadline:
            messages = await self._provider.get_incoming(from_number, since_ms)
            for inbound in messages:
                reply = inbound.body
                command_payload = {"text": reply}
                extracted_command = extract_remote_command_payload(
                    command_payload,
                    channel="whatsapp",
                    from_number=from_number,
                )
                if extracted_command is not None:
                    command_id = str(extracted_command.get("command_id", "") or "")
                    if command_id and command_id in seen_remote_command_ids:
                        continue
                    if command_id:
                        seen_remote_command_ids.add(command_id)
                    command_result = await verify_extracted_remote_command(
                        extracted_command,
                        channel="whatsapp",
                        state_store=self._state_store,
                        verifier=self._remote_command_verifier,
                    )
                    if command_result.accepted:
                        logger.info(
                            "WhatsAppAction.listen_for_response: accepted remote command command_id=%s command=%s",
                            command_result.command.command_id
                            if command_result.command
                            else "",
                            command_result.command.command
                            if command_result.command
                            else "",
                        )
                        if (
                            self._remote_command_handler is not None
                            and command_result.command
                        ):
                            execution_result = await self._remote_command_handler(
                                command_result.command
                            )
                            await self._send_remote_command_feedback(
                                to_number=from_number,
                                message=format_remote_command_execution_response(
                                    execution_result
                                ),
                                inbound=inbound,
                            )
                    else:
                        logger.warning(
                            "WhatsAppAction.listen_for_response: rejected remote command reason=%s",
                            command_result.reason,
                        )
                        throttle_decision = await evaluate_rejection_feedback(
                            state_store=self._state_store,
                            channel="whatsapp",
                            from_number=from_number,
                        )
                        if throttle_decision.incident_logged:
                            await self._notify_remote_command_incident(
                                throttle_decision
                            )
                        if throttle_decision.send_feedback:
                            await self._send_remote_command_feedback(
                                to_number=from_number,
                                message=format_remote_command_rejection_response(),
                                inbound=inbound,
                            )
                    continue

                logger.info(
                    "WhatsAppAction.listen_for_response: received reply from %r: %r",
                    from_number,
                    reply,
                )
                return reply

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            await asyncio.sleep(min(self._POLL_INTERVAL_SECONDS, remaining))

        logger.warning(
            "WhatsAppAction.listen_for_response: timed out after %ds waiting "
            "for reply from %r",
            timeout_seconds,
            from_number,
        )
        return None

    async def _send_remote_command_feedback(
        self,
        *,
        to_number: str,
        message: str,
        inbound: InboundWhatsAppMessage,
    ) -> bool:
        try:
            sent = await self.send_reply(
                WhatsAppSessionReply(body=message, in_reply_to=inbound),
                to_number,
            )
        except Exception:
            logger.exception(
                "WhatsAppAction: remote command feedback send raised for to=%r",
                to_number,
            )
            return False
        if not sent:
            logger.warning(
                "WhatsAppAction: failed to send remote command feedback to %r",
                to_number,
            )
        return bool(sent)

    async def _notify_remote_command_incident(
        self,
        decision: RemoteCommandThrottleDecision,
    ) -> None:
        if self._remote_command_incident_handler is None:
            return
        try:
            await self._remote_command_incident_handler(decision)
        except Exception:
            logger.exception("WhatsAppAction: remote command incident handler failed")


def _provider_datetime_ms(value: object) -> int | None:
    if not isinstance(value, datetime.datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=datetime.timezone.utc)
    return int(value.timestamp() * 1000)


def _normalize_address(value: str) -> str:
    return str(value or "").strip().lower()
