# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Africa's Talking SMS action — PRIMARY alert channel for Nigeria.

Works across all major Nigerian networks: MTN, Airtel, Glo, 9mobile.

SMS is the primary alert channel because:
- WhatsApp requires internet; SMS works on 2G/EDGE everywhere in Nigeria.
- Africa's Talking has direct carrier integrations, reducing delivery
  latency and failure rates compared to international aggregators.

Approval workflow note
----------------------
Africa's Talking delivers inbound SMS via webhook. This class supports
Tier C approval listening when a webhook process stores inbound SMS into
StateStore via :meth:`ingest_incoming_webhook`.

Usage
-----
    action = SMSAction()                 # reads env vars at construction time
    ok = await action.send("Alert: overcurrent detected.", "+234XXXXXXXXXX")
"""

import asyncio
import logging
import os
import time
from typing import Any

from ori.time_utils import now_ms

logger = logging.getLogger(__name__)


class SMSAction:
    """Africa's Talking SMS sender — fire-and-forget alert delivery.

    Credentials are read from environment variables at construction time:

    - ``AT_API_KEY``    — Africa's Talking API key (required)
    - ``AT_USERNAME``   — Africa's Talking username (default: ``"sandbox"``)
    - ``AT_SENDER_ID``  — Alphanumeric sender ID shown to the recipient
                          (default: ``"ORI"``).  **Must be pre-registered with
                          Africa's Talking before production use** — unregistered
                          sender IDs are silently replaced by a short code.

    If ``AT_API_KEY`` is not set the action enters *degraded mode*: calls log a
    warning and return ``False`` without raising.
    """

    _POLL_INTERVAL_SECONDS: int = 5

    def __init__(
        self,
        state_store: Any = None,
        poll_interval_seconds: int = _POLL_INTERVAL_SECONDS,
    ) -> None:
        self._api_key = os.environ.get("AT_API_KEY", "")
        self._username = os.environ.get("AT_USERNAME", "sandbox")
        self._sender_id = os.environ.get("AT_SENDER_ID", "ORI")
        self._state_store = state_store
        self._poll_interval_seconds = max(1, int(poll_interval_seconds))
        self._ready = bool(self._api_key)
        if not self._ready:
            logger.warning("SMSAction: AT_API_KEY is not set — SMS delivery disabled.")
        if self._ready:
            try:
                import africastalking  # type: ignore[import-untyped]

                africastalking.initialize(self._username, self._api_key)
            except Exception:
                logger.exception("SMSAction: failed to initialise AT SDK")
                self._ready = False

    async def send(self, message: str, to_number: str) -> bool:
        """Send *message* to *to_number* via Africa's Talking.

        Args:
            message: Plain-text message body (max 160 chars per SMS segment).
            to_number: Recipient phone number in international format
                (e.g. ``"+234XXXXXXXXXX"``).

        Returns:
            ``True`` if Africa's Talking accepted the message, ``False``
            on any failure.  Never raises.
        """
        if not self._ready:
            logger.warning(
                "SMSAction.send: skipped (AT_API_KEY not configured). to=%r",
                to_number,
            )
            return False

        try:
            import africastalking  # type: ignore[import-untyped]

            # Africa's Talking SDK is synchronous — push to executor so the
            # event loop is not blocked during the HTTP round-trip.
            def _send_sync() -> dict:
                sms = africastalking.SMS
                return sms.send(message, [to_number], self._sender_id)

            response = await asyncio.to_thread(_send_sync)

            # AT returns a dict with a "SMSMessageData" key containing
            # a "Recipients" list.  Each recipient has a "status" field.
            recipients = response.get("SMSMessageData", {}).get("Recipients") or []
            if recipients:
                status = recipients[0].get("status", "")
                if status == "Success":
                    logger.info(
                        "SMSAction.send: message delivered to %r (status=%r)",
                        to_number,
                        status,
                    )
                    return True
                logger.warning(
                    "SMSAction.send: delivery not confirmed for %r (status=%r)",
                    to_number,
                    status,
                )
                return False

            logger.warning(
                "SMSAction.send: empty recipients list in AT response for %r",
                to_number,
            )
            return False

        except Exception:
            logger.exception(
                "SMSAction.send: unexpected error sending to %r", to_number
            )
            return False

    async def ingest_incoming_webhook(self, payload: dict[str, Any]) -> bool:
        """Store one inbound Africa's Talking webhook message in StateStore.

        Expected payload keys:
            - ``from`` (or ``from_number``)
            - ``text`` (or ``message``)

        Returns ``True`` when the message is persisted, otherwise ``False``.
        """
        if self._state_store is None:
            logger.warning(
                "SMSAction.ingest_incoming_webhook: no StateStore configured"
            )
            return False

        raw_from = str(payload.get("from") or payload.get("from_number") or "")
        raw_text = str(payload.get("text") or payload.get("message") or "")
        from_number = _normalize_phone(raw_from)
        message = raw_text.strip()
        if not from_number or not message:
            logger.warning(
                "SMSAction.ingest_incoming_webhook: invalid payload (from=%r text=%r)",
                raw_from,
                raw_text,
            )
            return False

        try:
            await self._state_store.store_incoming_message(
                channel="sms",
                from_number=from_number,
                message=message,
            )
            return True
        except Exception:
            logger.exception(
                "SMSAction.ingest_incoming_webhook: failed to store inbound SMS"
            )
            return False

    async def listen_for_response(
        self,
        from_number: str,
        timeout_seconds: int,
    ) -> str | None:
        """Poll StateStore for inbound SMS approval responses.

        Returns:
            The first matching SMS body, or ``None`` on timeout / misconfig.
        """
        if self._state_store is None:
            logger.info(
                "SMSAction.listen_for_response: no StateStore configured; "
                "cannot listen for SMS replies"
            )
            return None

        normalized_from = _normalize_phone(from_number)
        if not normalized_from:
            return None

        since_ms = now_ms()
        deadline = time.monotonic() + timeout_seconds

        while time.monotonic() < deadline:
            try:
                message = await self._state_store.consume_incoming_message(
                    channel="sms",
                    from_number=normalized_from,
                    since_ms=since_ms,
                )
            except Exception:
                logger.exception(
                    "SMSAction.listen_for_response: StateStore lookup failed"
                )
                return None

            if message:
                return message

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            await asyncio.sleep(min(self._poll_interval_seconds, remaining))

        return None


def _normalize_phone(value: str) -> str:
    """Normalize a phone number for stable matching."""
    return "".join(ch for ch in value if ch.isdigit() or ch == "+")
