# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

try:
    import httpx as _httpx  # type: ignore[import-untyped]

    _HTTPX_AVAILABLE = True
except ImportError:
    _httpx = None
    _HTTPX_AVAILABLE = False

_TELEGRAM_MAX_MESSAGE_LEN = 4096
_DEFAULT_TIMEOUT_S = 15.0


class TelegramBotAction:
    """Send plain-text messages via ``sendMessage``."""

    def __init__(self, bot_token: str | None = None) -> None:
        self._token = (bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")).strip()

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
        if not _HTTPX_AVAILABLE or _httpx is None:
            logger.error("TelegramBotAction.send: httpx is not installed")
            return False

        text = message if len(message) <= _TELEGRAM_MAX_MESSAGE_LEN else (
            message[: _TELEGRAM_MAX_MESSAGE_LEN - 20] + "\n…(truncated)"
        )
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text}

        try:
            async with _httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_S) as client:
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
