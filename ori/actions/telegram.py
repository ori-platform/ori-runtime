# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx
from httpx import Timeout

logger = logging.getLogger(__name__)

_TELEGRAM_MAX_MESSAGE_LEN = 4096
_DEFAULT_TIMEOUT_S = 3.0
# ``getUpdates`` long-poll can block up to the per-request ``timeout`` param (we use up to 5s);
# httpx read timeout must exceed that or the client raises ReadTimeout before Telegram responds.
_LISTEN_HTTP_READ_TIMEOUT_S = 65.0
_DRAIN_MAX_BATCHES = 100


class TelegramBotAction:
    """Send plain-text messages via ``sendMessage``."""

    def __init__(self, bot_token: str | None = None) -> None:
        self._token = (bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")).strip()
        self._updates_offset = 0

    async def send(self, message: str, to_number: str) -> bool:
        """Send *message* to Telegram chat *to_number* (numeric chat id).

        ``to_number`` is the operator chat id from ``actions.operator_contact``.
        """
        chat_id = (to_number or "").strip()
        if not chat_id:
            logger.warning("TelegramBotAction.send: empty chat_id (operator_contact)")
            return False
        if not self._token:
            logger.warning(
                "TelegramBotAction.send: missing bot token — set actions.telegram.bot_token "
                "or TELEGRAM_BOT_TOKEN"
            )
            return False

        text = (
            message
            if len(message) <= _TELEGRAM_MAX_MESSAGE_LEN
            else message[: _TELEGRAM_MAX_MESSAGE_LEN - 20] + "\n…(truncated)"
        )
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text}

        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_S) as client:
                resp = await client.post(url, json=payload)
        except Exception:
            logger.exception("TelegramBotAction.send: HTTP request failed")
            return False

        if resp.status_code != 200:
            logger.warning(
                "TelegramBotAction.send: API error status=%s body=%r",
                resp.status_code,
                resp.text[:500],
            )
            return False
        try:
            data = resp.json()
        except Exception:
            logger.warning("TelegramBotAction.send: invalid JSON in response")
            return False
        if not data.get("ok"):
            logger.warning("TelegramBotAction.send: ok=false result=%r", data)
            return False
        return True

    def _advance_offset_for_updates(self, updates: list[Any]) -> None:
        for update in updates:
            update_id = int(update.get("update_id", 0))
            if update_id >= self._updates_offset:
                self._updates_offset = update_id + 1

    async def _drain_pending_updates(self, client: httpx.AsyncClient, url: str) -> None:
        """Acknowledge queued ``getUpdates`` so stale messages are not mistaken for a new reply."""
        for _ in range(_DRAIN_MAX_BATCHES):
            resp = await client.get(
                url, params={"offset": self._updates_offset, "timeout": 0}
            )
            if resp.status_code != 200:
                return
            try:
                data = resp.json()
            except Exception:
                return
            if not data.get("ok"):
                return
            updates = data.get("result") or []
            if not updates:
                return
            max_id = max(int(u.get("update_id", 0)) for u in updates)
            if max_id < self._updates_offset:
                return
            self._updates_offset = max_id + 1

    async def listen_for_response(
        self, from_number: str, timeout_seconds: int
    ) -> str | None:
        chat_id = (from_number or "").strip()
        if not chat_id or not self._token:
            return None

        url = f"https://api.telegram.org/bot{self._token}/getUpdates"
        deadline = time.monotonic() + max(1, int(timeout_seconds))

        try:
            listen_timeout = Timeout(
                connect=_DEFAULT_TIMEOUT_S,
                read=_LISTEN_HTTP_READ_TIMEOUT_S,
                write=_DEFAULT_TIMEOUT_S,
                pool=_DEFAULT_TIMEOUT_S,
            )
            async with httpx.AsyncClient(timeout=listen_timeout) as client:
                await self._drain_pending_updates(client, url)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    poll_timeout = max(1, min(5, int(remaining)))
                    resp = await client.get(
                        url,
                        params={"offset": self._updates_offset, "timeout": poll_timeout},
                    )
                    if resp.status_code != 200:
                        return None
                    data = resp.json()
                    if not data.get("ok"):
                        return None
                    updates = data.get("result") or []
                    for update in updates:
                        self._advance_offset_for_updates([update])
                        message = update.get("message") or {}
                        chat = message.get("chat") or {}
                        if str(chat.get("id", "")).strip() != chat_id:
                            continue
                        text = str(message.get("text", "")).strip()
                        if text:
                            return text
        except Exception:
            logger.exception("TelegramBotAction.listen_for_response: polling failed")
            return None
