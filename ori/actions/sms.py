# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""SMS action transport with IP (Africa's Talking) and GSM modem support.

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
    action = SMSAction()                 # reads env vars / config at construction time
    ok = await action.send("Alert: overcurrent detected.", "+234XXXXXXXXXX")
"""

import asyncio
import logging
import os
import time
from collections.abc import Awaitable, Callable
from typing import Any

from ori.bool_utils import is_truthy
from ori.security.remote_command_responses import (
    format_remote_command_execution_response,
    format_remote_command_rejection_response,
)
from ori.security.remote_command_throttle import should_send_rejection_feedback
from ori.security.remote_commands import (
    RemoteCommand,
    RemoteCommandVerifier,
    verify_inbound_remote_command,
)
from ori.time_utils import now_ms

logger = logging.getLogger(__name__)

try:
    import serial as _serial_module  # type: ignore[import-untyped]

    _PYSERIAL_AVAILABLE = True
except Exception:
    _serial_module = None
    _PYSERIAL_AVAILABLE = False


class SMSAction:
    """SMS sender with pluggable transport: ``ip`` | ``gsm`` | ``hybrid``.

    IP transport credentials are read from config first, then environment:

    - ``AT_API_KEY``    — Africa's Talking API key (required)
    - ``AT_USERNAME``   — Africa's Talking username (default: ``"sandbox"``)
    - ``AT_SENDER_ID``  — Alphanumeric sender ID shown to the recipient
                          (default: ``"ORI"``).  **Must be pre-registered with
                          Africa's Talking before production use** — unregistered
                          sender IDs are silently replaced by a short code.

    GSM transport config is read from ``actions.sms.gsm``:

    - ``enabled`` (bool)
    - ``port`` (e.g. ``/dev/ttyUSB0``)
    - ``baud`` (default: ``115200``)
    - ``sim_pin`` (optional)
    - ``timeout_s`` (default: ``5.0``)
    """

    _POLL_INTERVAL_SECONDS: int = 5
    _DEFAULT_GSM_BAUD: int = 115200
    _DEFAULT_GSM_TIMEOUT_S: float = 5.0
    _DEFAULT_GSM_COMMAND_TIMEOUT_S: float = 3.0
    _DEFAULT_GSM_WRITE_TIMEOUT_S: float = 3.0

    def __init__(
        self,
        state_store: Any = None,
        poll_interval_seconds: int = _POLL_INTERVAL_SECONDS,
        config: dict[str, Any] | None = None,
        remote_command_verifier: RemoteCommandVerifier | None = None,
        remote_command_handler: Callable[[RemoteCommand], Awaitable[Any]] | None = None,
    ) -> None:
        sms_cfg = config if isinstance(config, dict) else {}

        self._transport = str(sms_cfg.get("transport", "hybrid")).strip().lower()
        if self._transport not in {"ip", "gsm", "hybrid"}:
            logger.warning(
                "SMSAction: unknown transport=%r; disabling SMS transport (fail-closed).",
                self._transport,
            )
            self._transport = "invalid"

        self._hybrid_order = (
            str(sms_cfg.get("hybrid_order", "gsm_first")).strip().lower()
        )
        if self._hybrid_order not in {"ip_first", "gsm_first"}:
            logger.warning(
                "SMSAction: unknown hybrid_order=%r; defaulting to 'gsm_first'",
                self._hybrid_order,
            )
            self._hybrid_order = "gsm_first"

        self._api_key = str(
            sms_cfg.get("AT_API_KEY") or os.environ.get("AT_API_KEY", "")
        )
        self._username = str(
            sms_cfg.get("AT_USERNAME") or os.environ.get("AT_USERNAME", "sandbox")
        )
        self._sender_id = str(
            sms_cfg.get("AT_SENDER_ID") or os.environ.get("AT_SENDER_ID", "ORI")
        )
        self._state_store = state_store
        self._remote_command_verifier = remote_command_verifier
        self._remote_command_handler = remote_command_handler
        self._poll_interval_seconds = max(1, int(poll_interval_seconds))
        self._ip_ready = bool(self._api_key)

        gsm_cfg = sms_cfg.get("gsm") if isinstance(sms_cfg.get("gsm"), dict) else {}
        self._gsm_enabled = is_truthy(gsm_cfg.get("enabled", False))
        self._gsm_port = str(gsm_cfg.get("port", "")).strip()
        self._gsm_baud = int(gsm_cfg.get("baud", self._DEFAULT_GSM_BAUD))
        self._gsm_sim_pin = str(gsm_cfg.get("sim_pin", "")).strip()
        self._gsm_timeout_s = max(
            0.2, float(gsm_cfg.get("timeout_s", self._DEFAULT_GSM_TIMEOUT_S))
        )
        self._gsm_command_timeout_s = max(
            0.2,
            float(
                gsm_cfg.get(
                    "command_timeout_s",
                    self._DEFAULT_GSM_COMMAND_TIMEOUT_S,
                )
            ),
        )
        self._gsm_write_timeout_s = max(
            0.2,
            float(
                gsm_cfg.get(
                    "write_timeout_s",
                    self._DEFAULT_GSM_WRITE_TIMEOUT_S,
                )
            ),
        )
        self._gsm_ready = bool(
            self._gsm_enabled and self._gsm_port and _PYSERIAL_AVAILABLE
        )

        if self._ip_ready and self._transport in {"ip", "hybrid"}:
            try:
                import africastalking  # type: ignore[import-untyped]

                africastalking.initialize(self._username, self._api_key)
            except Exception:
                logger.exception("SMSAction: failed to initialise AT SDK")
                self._ip_ready = False

        if self._transport in {"ip", "hybrid"} and not self._ip_ready:
            logger.warning(
                "SMSAction: IP transport unavailable (AT_API_KEY missing or SDK init failed)."
            )
        if self._transport in {"gsm", "hybrid"}:
            if not self._gsm_enabled:
                logger.warning("SMSAction: GSM transport is not enabled in config.")
            elif not self._gsm_port:
                logger.warning(
                    "SMSAction: GSM transport enabled but no serial port configured."
                )
            elif not _PYSERIAL_AVAILABLE:
                logger.warning(
                    "SMSAction: pyserial not available — GSM modem transport disabled."
                )

    async def send(self, message: str, to_number: str) -> bool:
        """Send *message* to *to_number* via configured SMS transport.

        Args:
            message: Plain-text message body (max 160 chars per SMS segment).
            to_number: Recipient phone number in international format
                (e.g. ``"+234XXXXXXXXXX"``).

        Returns:
            ``True`` if Africa's Talking accepted the message, ``False``
            on any failure.  Never raises.
        """
        transport_order = self._resolve_transport_order()
        if not transport_order:
            logger.warning(
                "SMSAction.send: skipped (no available SMS transport). to=%r",
                to_number,
            )
            return False

        for transport in transport_order:
            if transport == "ip":
                if await self._send_ip(message=message, to_number=to_number):
                    return True
                continue
            if transport == "gsm":
                if await self._send_gsm(message=message, to_number=to_number):
                    return True
                continue

        return False

    def _resolve_transport_order(self) -> list[str]:
        if self._transport == "invalid":
            return []
        if self._transport == "ip":
            return ["ip"] if self._ip_ready else []
        if self._transport == "gsm":
            return ["gsm"] if self._gsm_ready else []

        if self._hybrid_order == "gsm_first":
            order = ["gsm", "ip"]
        else:
            order = ["ip", "gsm"]

        resolved: list[str] = []
        for candidate in order:
            if candidate == "ip" and self._ip_ready:
                resolved.append("ip")
            if candidate == "gsm" and self._gsm_ready:
                resolved.append("gsm")
        return resolved

    async def _send_ip(self, message: str, to_number: str) -> bool:
        """Send through Africa's Talking (synchronous SDK offloaded to thread)."""
        if not self._ip_ready:
            return False

        try:
            import africastalking  # type: ignore[import-untyped]

            # Africa's Talking SDK is synchronous — offload to thread.
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
                        "SMSAction._send_ip: message delivered to %r (status=%r)",
                        to_number,
                        status,
                    )
                    return True
                logger.warning(
                    "SMSAction._send_ip: delivery not confirmed for %r (status=%r)",
                    to_number,
                    status,
                )
                return False

            logger.warning(
                "SMSAction._send_ip: empty recipients list in AT response for %r",
                to_number,
            )
            return False

        except Exception:
            logger.exception(
                "SMSAction._send_ip: unexpected error sending to %r", to_number
            )
            return False

    async def _send_gsm(self, message: str, to_number: str) -> bool:
        """Send through GSM modem AT commands (all serial I/O offloaded)."""
        if not self._gsm_ready:
            return False
        return await asyncio.to_thread(self._send_gsm_sync, message, to_number)

    def _send_gsm_sync(self, message: str, to_number: str) -> bool:
        if not _PYSERIAL_AVAILABLE or _serial_module is None:
            return False

        number = _normalize_phone(to_number)
        if not number:
            logger.warning("SMSAction._send_gsm_sync: invalid recipient %r", to_number)
            return False

        try:
            modem = _serial_module.Serial(
                port=self._gsm_port,
                baudrate=self._gsm_baud,
                timeout=self._gsm_timeout_s,
                write_timeout=self._gsm_write_timeout_s,
            )
        except Exception:
            logger.exception(
                "SMSAction._send_gsm_sync: failed to open modem port=%r",
                self._gsm_port,
            )
            return False

        try:
            if not self._gsm_command(modem, "AT", expect="OK"):
                return False
            if not self._gsm_command(modem, "ATE0", expect="OK"):
                return False
            if not self._gsm_command(modem, "AT+CMGF=1", expect="OK"):
                return False

            # Unlock SIM only when required.
            cpin = self._gsm_command(
                modem, "AT+CPIN?", expect="OK", timeout_s=self._gsm_command_timeout_s
            )
            if cpin and "SIM PIN" in cpin and self._gsm_sim_pin:
                if not self._gsm_command(
                    modem,
                    f'AT+CPIN="{self._gsm_sim_pin}"',
                    expect="OK",
                    timeout_s=self._gsm_command_timeout_s,
                ):
                    return False

            prompt = self._gsm_command(
                modem,
                f'AT+CMGS="{number}"',
                expect=">",
                timeout_s=self._gsm_command_timeout_s,
            )
            if prompt is None:
                return False

            modem.write(message.encode("utf-8", errors="ignore") + bytes([26]))
            modem.flush()
            response = self._gsm_read_until(
                modem,
                expect="OK",
                timeout_s=max(5.0, self._gsm_command_timeout_s),
            )
            if response is None or "+CMGS" not in response:
                logger.warning(
                    "SMSAction._send_gsm_sync: modem did not confirm send to %r",
                    number,
                )
                return False
            logger.info(
                "SMSAction._send_gsm_sync: message handed off to modem for %r",
                number,
            )
            return True
        except Exception:
            logger.exception("SMSAction._send_gsm_sync: send failed")
            return False
        finally:
            try:
                modem.close()
            except Exception:
                logger.warning("SMSAction._send_gsm_sync: modem close failed")

    def _gsm_command(
        self,
        modem: Any,
        command: str,
        *,
        expect: str,
        timeout_s: float | None = None,
    ) -> str | None:
        modem.reset_input_buffer()
        modem.write((command + "\r").encode("ascii", errors="ignore"))
        modem.flush()
        return self._gsm_read_until(
            modem,
            expect=expect,
            timeout_s=self._gsm_command_timeout_s if timeout_s is None else timeout_s,
        )

    def _gsm_read_until(
        self, modem: Any, *, expect: str, timeout_s: float
    ) -> str | None:
        deadline = time.monotonic() + max(0.2, timeout_s)
        output = ""
        expected = expect.upper()
        while time.monotonic() < deadline:
            chunk = modem.read(modem.in_waiting or 1)
            if chunk:
                text = chunk.decode("utf-8", errors="ignore")
                output += text
                upper = output.upper()
                if expected in upper:
                    return output
                if "ERROR" in upper or "+CMS ERROR" in upper:
                    logger.warning("SMSAction._gsm_read_until: modem error: %s", output)
                    return None
            else:
                time.sleep(0.05)

        logger.warning(
            "SMSAction._gsm_read_until: timeout waiting for %r (buffer=%r)",
            expect,
            output,
        )
        return None

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
            command_result = await verify_inbound_remote_command(
                payload,
                channel="sms",
                from_number=from_number,
                state_store=self._state_store,
                verifier=self._remote_command_verifier,
            )
            if command_result is not None:
                if not command_result.accepted:
                    logger.warning(
                        "SMSAction.ingest_incoming_webhook: rejected remote command reason=%s",
                        command_result.reason,
                    )
                    if await should_send_rejection_feedback(
                        state_store=self._state_store,
                        channel="sms",
                        from_number=from_number,
                    ):
                        await self._send_remote_command_feedback(
                            to_number=from_number,
                            message=format_remote_command_rejection_response(),
                        )
                    return False
                logger.info(
                    "SMSAction.ingest_incoming_webhook: accepted remote command command_id=%s command=%s",
                    command_result.command.command_id if command_result.command else "",
                    command_result.command.command if command_result.command else "",
                )
                if self._remote_command_handler is not None and command_result.command:
                    execution_result = await self._remote_command_handler(
                        command_result.command
                    )
                    await self._send_remote_command_feedback(
                        to_number=from_number,
                        message=format_remote_command_execution_response(
                            execution_result
                        ),
                    )
                return True

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

    async def _send_remote_command_feedback(
        self,
        *,
        to_number: str,
        message: str,
    ) -> bool:
        try:
            sent = await self.send(message, to_number)
        except Exception:
            logger.exception(
                "SMSAction: remote command feedback send raised for to=%r",
                to_number,
            )
            return False
        if not sent:
            logger.warning(
                "SMSAction: failed to send remote command feedback to %r",
                to_number,
            )
        return bool(sent)


def _normalize_phone(value: str) -> str:
    """Normalize a phone number for stable matching."""
    return "".join(ch for ch in value if ch.isdigit() or ch == "+")
