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

Usage
-----
    provider = TwilioProvider()          # reads env vars at construction time
    action   = WhatsAppAction(provider)

    ok = await action.send("Hello", to_number="whatsapp:+234XXXXXXXXXX")

    msg = await action.send_approval_request(result, "trip_main_breaker",
                                             timeout_seconds=300,
                                             to_number="whatsapp:+234XXXXXXXXXX")

    reply = await action.listen_for_response("whatsapp:+234XXXXXXXXXX",
                                             timeout_seconds=300)
"""

import asyncio
import logging
import os
import time
from typing import Protocol, runtime_checkable

from ori.network.events import ReasoningResult
from ori.time_utils import now_ms

logger = logging.getLogger(__name__)

# ── Approval message template (canonical form from CLAUDE.md) ────────────────

_APPROVAL_TEMPLATE = """\
ORI ALERT — Action Required
Device: {device_id}
Time: {timestamp}

OBSERVATION:
{observation}

PROPOSED ACTION:
{action_description}

CONFIDENCE: {confidence}

Reply YES to approve  |  Reply NO to cancel
Auto-cancel in {timeout} seconds if no response."""


# ── Provider protocol ─────────────────────────────────────────────────────────


@runtime_checkable
class WhatsAppProvider(Protocol):
    """Interface every WhatsApp backend must satisfy."""

    async def send(self, to: str, message: str) -> bool:
        """Send *message* to *to*.  Returns True on success."""
        ...

    async def get_incoming(self, from_number: str, since_ms: int) -> list[str]:
        """Return message bodies received from *from_number* after *since_ms*.

        *since_ms* is a Unix timestamp in milliseconds (UTC).
        Returns an empty list when there are no matching messages.
        """
        ...


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
        self._ready = bool(self._sid and self._token and self._from)
        if not self._ready:
            logger.warning(
                "TwilioProvider: TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / "
                "TWILIO_WHATSAPP_FROM are not set — WhatsApp delivery disabled."
            )

    # ------------------------------------------------------------------
    # WhatsAppProvider interface
    # ------------------------------------------------------------------

    async def send(self, to: str, message: str) -> bool:
        if not self._ready:
            logger.warning(
                "TwilioProvider.send: skipped (credentials not configured). to=%r", to
            )
            return False

        try:
            from twilio.rest import Client  # type: ignore[import-untyped]

            client = Client(self._sid, self._token)
            # Twilio's Python SDK is synchronous — run in executor to avoid
            # blocking the event loop.
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: client.messages.create(
                    body=message,
                    from_=self._from,
                    to=to,
                ),
            )
            logger.info("TwilioProvider.send: message delivered to %r", to)
            return True
        except Exception:
            logger.exception("TwilioProvider.send: delivery failed to %r", to)
            return False

    async def get_incoming(self, from_number: str, since_ms: int) -> list[str]:
        """Poll Twilio for inbound messages from *from_number* after *since_ms*.

        Returns message body strings in chronological order.
        """
        if not self._ready:
            return []

        try:
            import datetime

            from twilio.rest import Client  # type: ignore[import-untyped]

            # Convert ms timestamp to a datetime for the Twilio filter
            since_dt = datetime.datetime.fromtimestamp(
                since_ms / 1000.0, tz=datetime.timezone.utc
            )
            client = Client(self._sid, self._token)
            loop = asyncio.get_running_loop()

            messages = await loop.run_in_executor(
                None,
                lambda: client.messages.list(
                    from_=from_number,
                    to=self._from,
                    date_sent_after=since_dt,
                ),
            )
            return [m.body for m in messages]
        except Exception:
            logger.exception(
                "TwilioProvider.get_incoming: failed to fetch messages from %r",
                from_number,
            )
            return []


# ── WhatsAppAction ────────────────────────────────────────────────────────────


class WhatsAppAction:
    """Sends WhatsApp messages and listens for operator approval responses.

    Args:
        provider: A :class:`WhatsAppProvider` implementation.  Defaults to a
            :class:`TwilioProvider` instance constructed from environment
            variables.

    The approval workflow (used for Tier C hard-physical actions):

    1. Call :meth:`send_approval_request` — formats and sends the canonical
       approval message template, returns the formatted string for logging.
    2. Call :meth:`listen_for_response` — polls for an inbound YES/NO reply
       every 5 seconds until *timeout_seconds* elapses.
    3. Pass the returned string to
       :func:`~ori.reasoning.action_dispatcher.parse_approval_response` to
       decide whether to execute or fall back to ``safe_default_action``.
    """

    _POLL_INTERVAL_SECONDS: int = 5

    def __init__(self, provider: WhatsAppProvider | None = None) -> None:
        self._provider: WhatsAppProvider = provider or TwilioProvider()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def send(self, message: str, to_number: str) -> bool:
        """Send *message* to *to_number*.

        Returns True on success, False on any failure.  Never raises.
        """
        try:
            return await self._provider.send(to_number, message)
        except Exception:
            logger.exception(
                "WhatsAppAction.send: provider raised unexpectedly for to=%r", to_number
            )
            return False

    async def send_approval_request(
        self,
        result: ReasoningResult,
        action: str,
        timeout_seconds: int,
        to_number: str,
        device_id: str = "ori-device",
    ) -> str:
        """Format and send the canonical Tier C approval request.

        Args:
            result: The :class:`~ori.network.events.ReasoningResult` from the
                Intelligence Elevator.
            action: Human-readable description of the proposed action
                (e.g. ``"trip_main_breaker"``).
            timeout_seconds: Seconds before the request auto-cancels.
            to_number: Destination WhatsApp number
                (e.g. ``"whatsapp:+234XXXXXXXXXX"``).
            device_id: Device identifier shown in the alert header.

        Returns:
            The formatted message string (useful for logging / audit trail).
        """
        import datetime

        timestamp = datetime.datetime.now(tz=datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        message = _APPROVAL_TEMPLATE.format(
            device_id=device_id,
            timestamp=timestamp,
            observation=result.text,
            action_description=action,
            confidence=f"{result.confidence:.0%}",
            timeout=timeout_seconds,
        )
        await self._provider.send(to_number, message)
        return message

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

        while time.monotonic() < deadline:
            messages = await self._provider.get_incoming(from_number, since_ms)
            if messages:
                reply = messages[0]
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
