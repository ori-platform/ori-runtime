# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Failover alert transport wrapper used by approval workflows.

Primary usage:
- send Tier C approval requests via preferred channel
- fall back to the secondary channel on transport failure
- listen for operator responses on both channels concurrently
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class AlertFailoverSender:
    """Wraps SMS and WhatsApp senders with primary/secondary failover."""

    def __init__(
        self,
        *,
        primary_channel: str,
        sms_sender: Any,
        whatsapp_sender: Any,
    ) -> None:
        self._primary_channel = str(primary_channel or "sms").strip().lower()
        self._sms_sender = sms_sender
        self._whatsapp_sender = whatsapp_sender

        if self._primary_channel not in {"sms", "whatsapp"}:
            logger.warning(
                "AlertFailoverSender: unknown primary channel %r; defaulting to sms",
                self._primary_channel,
            )
            self._primary_channel = "sms"

    @property
    def _ordered_senders(self) -> list[tuple[str, Any]]:
        primary = (
            ("sms", self._sms_sender)
            if self._primary_channel == "sms"
            else ("whatsapp", self._whatsapp_sender)
        )
        secondary = (
            ("whatsapp", self._whatsapp_sender)
            if primary[0] == "sms"
            else ("sms", self._sms_sender)
        )
        return [primary, secondary]

    async def send(self, message: str, to_number: str) -> bool:
        """Send via primary transport; fall back to secondary on failure."""
        for channel_name, sender in self._ordered_senders:
            if sender is None:
                continue
            try:
                ok = await sender.send(message=message, to_number=to_number)
            except Exception:
                logger.exception(
                    "AlertFailoverSender: send failed on channel=%s",
                    channel_name,
                )
                ok = False
            if ok:
                return True
        return False

    async def listen_for_response(
        self,
        from_number: str,
        timeout_seconds: int,
    ) -> str | None:
        """Wait for first response from either transport listener."""
        listeners: list[tuple[str, Any]] = []
        for channel_name, sender in self._ordered_senders:
            if sender is None:
                continue
            listener = getattr(sender, "listen_for_response", None)
            if callable(listener):
                listeners.append((channel_name, listener))

        if not listeners:
            return None

        deadline = time.monotonic() + max(1, int(timeout_seconds))
        pending: set[asyncio.Task[str | None]] = set()
        for channel_name, listener in listeners:
            pending.add(
                asyncio.create_task(
                    self._listen_safe(
                        channel_name=channel_name,
                        listener=listener,
                        from_number=from_number,
                        timeout_seconds=timeout_seconds,
                    ),
                    name=f"approval-listen:{channel_name}",
                )
            )

        try:
            while pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break

                done, pending = await asyncio.wait(
                    pending,
                    timeout=remaining,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not done:
                    break

                for task in done:
                    response = task.result()
                    if response is not None:
                        for other in pending:
                            other.cancel()
                        await asyncio.gather(*pending, return_exceptions=True)
                        return response
        finally:
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

        return None

    async def _listen_safe(
        self,
        *,
        channel_name: str,
        listener: Any,
        from_number: str,
        timeout_seconds: int,
    ) -> str | None:
        try:
            return await listener(
                from_number=from_number,
                timeout_seconds=timeout_seconds,
            )
        except TypeError:
            try:
                return await listener(from_number, timeout_seconds)
            except Exception:
                logger.exception(
                    "AlertFailoverSender: %s listener failed",
                    channel_name,
                )
                return None
        except Exception:
            logger.exception(
                "AlertFailoverSender: %s listener failed",
                channel_name,
            )
            return None
