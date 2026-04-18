# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for ori/actions/telegram.py — TelegramBotAction."""

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from ori.actions.telegram import (
    _DEFAULT_TIMEOUT_S,
    _TELEGRAM_MAX_MESSAGE_LEN,
    TelegramBotAction,
)


@pytest.mark.asyncio
async def test_send_returns_false_without_token():
    act = TelegramBotAction(bot_token="")
    assert await act.send("hello", "123") is False


@pytest.mark.asyncio
async def test_send_returns_false_without_chat_id():
    act = TelegramBotAction(bot_token="x:y")
    assert await act.send("hello", "") is False


@pytest.mark.asyncio
async def test_send_success_uses_httpx():
    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {"ok": True, "result": {"message_id": 1}}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def post(self, _url, json=None):
            return _Resp()

    fake_httpx = SimpleNamespace(AsyncClient=lambda **kwargs: _Client())

    act = TelegramBotAction(bot_token="123:secret")
    with patch("ori.actions.telegram.httpx", fake_httpx):
        assert await act.send("hello world", "999001") is True


@pytest.mark.asyncio
async def test_send_false_when_api_not_ok():
    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {"ok": False, "description": "bad"}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def post(self, _url, json=None):
            return _Resp()

    fake_httpx = SimpleNamespace(AsyncClient=lambda **kwargs: _Client())
    act = TelegramBotAction(bot_token="123:secret")
    with patch("ori.actions.telegram.httpx", fake_httpx):
        assert await act.send("x", "1") is False


@pytest.mark.asyncio
async def test_send_false_on_non_200_status():
    class _Resp:
        status_code = 429
        text = "rate limited"

        def json(self):
            return {}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def post(self, _url, json=None):
            return _Resp()

    fake_httpx = SimpleNamespace(AsyncClient=lambda **kwargs: _Client())
    act = TelegramBotAction(bot_token="123:secret")
    with patch("ori.actions.telegram.httpx", fake_httpx):
        assert await act.send("x", "1") is False


@pytest.mark.asyncio
async def test_send_false_on_invalid_json():
    class _Resp:
        status_code = 200
        text = "not json"

        def json(self):
            raise ValueError("no json")

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def post(self, _url, json=None):
            return _Resp()

    fake_httpx = SimpleNamespace(AsyncClient=lambda **kwargs: _Client())
    act = TelegramBotAction(bot_token="123:secret")
    with patch("ori.actions.telegram.httpx", fake_httpx):
        assert await act.send("x", "1") is False


@pytest.mark.asyncio
async def test_send_false_on_http_exception():
    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def post(self, _url, json=None):
            raise OSError("network down")

    fake_httpx = SimpleNamespace(AsyncClient=lambda **kwargs: _Client())
    act = TelegramBotAction(bot_token="123:secret")
    with patch("ori.actions.telegram.httpx", fake_httpx):
        assert await act.send("x", "1") is False


@pytest.mark.asyncio
async def test_send_truncates_long_message():
    captured: dict[str, Any] = {}

    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {"ok": True, "result": {}}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def post(self, _url, json=None):
            captured["payload"] = json
            return _Resp()

    fake_httpx = SimpleNamespace(AsyncClient=lambda **kwargs: _Client())
    long_msg = "a" * (_TELEGRAM_MAX_MESSAGE_LEN + 500)
    act = TelegramBotAction(bot_token="123:secret")
    with patch("ori.actions.telegram.httpx", fake_httpx):
        assert await act.send(long_msg, "1") is True
    text = captured["payload"]["text"]
    assert len(text) <= _TELEGRAM_MAX_MESSAGE_LEN
    assert text.endswith("\n…(truncated)")


@pytest.mark.asyncio
async def test_send_passes_short_timeout_to_httpx_client():
    """Outbound Telegram calls use a 2–3s timeout (IoT-friendly)."""
    captured: dict[str, Any] = {}

    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {"ok": True, "result": {}}

    class _Client:
        def __init__(self, **kwargs: Any) -> None:
            captured["timeout"] = kwargs.get("timeout")

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_exc: Any) -> None:
            return None

        async def post(self, *_a: Any, **_k: Any) -> _Resp:
            return _Resp()

    with patch("ori.actions.telegram.httpx.AsyncClient", _Client):
        act = TelegramBotAction(bot_token="123:secret")
        assert await act.send("hi", "1") is True

    assert captured.get("timeout") == _DEFAULT_TIMEOUT_S
    assert _DEFAULT_TIMEOUT_S <= 3.0


@pytest.mark.asyncio
async def test_listen_for_response_returns_text_from_matching_chat():
    """Drain calls ``getUpdates`` first; first response must be empty, then the reply batch."""
    bodies = [
        {"ok": True, "result": []},
        {
            "ok": True,
            "result": [
                {"update_id": 10, "message": {"chat": {"id": 111}, "text": "YES"}},
            ],
        },
    ]

    class _Resp:
        status_code = 200
        text = ""

        def __init__(self, body: dict[str, Any]) -> None:
            self._body = body

        def json(self):
            return self._body

    class _Client:
        def __init__(self) -> None:
            self._n = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def get(self, *_a, **_k):
            body = bodies[min(self._n, len(bodies) - 1)]
            self._n += 1
            return _Resp(body)

    fake_httpx = SimpleNamespace(AsyncClient=lambda **kwargs: _Client())
    act = TelegramBotAction(bot_token="123:secret")
    with patch("ori.actions.telegram.httpx", fake_httpx):
        assert await act.listen_for_response("111", timeout_seconds=1) == "YES"


@pytest.mark.asyncio
async def test_listen_for_response_drains_backlog_then_accepts_new_message():
    bodies = [
        {
            "ok": True,
            "result": [
                {
                    "update_id": 1,
                    "message": {"chat": {"id": 111}, "text": "/start"},
                },
            ],
        },
        {"ok": True, "result": []},
        {
            "ok": True,
            "result": [
                {
                    "update_id": 2,
                    "message": {"chat": {"id": 111}, "text": "YES"},
                },
            ],
        },
    ]

    class _Resp:
        status_code = 200
        text = ""

        def __init__(self, body: dict[str, Any]) -> None:
            self._body = body

        def json(self):
            return self._body

    class _Client:
        def __init__(self) -> None:
            self._n = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def get(self, *_a, **_k):
            body = bodies[min(self._n, len(bodies) - 1)]
            self._n += 1
            return _Resp(body)

    fake_httpx = SimpleNamespace(AsyncClient=lambda **kwargs: _Client())
    act = TelegramBotAction(bot_token="123:secret")
    with patch("ori.actions.telegram.httpx", fake_httpx):
        assert await act.listen_for_response("111", timeout_seconds=5) == "YES"


@pytest.mark.asyncio
async def test_listen_for_response_ignores_other_chats_and_times_out():
    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {
                "ok": True,
                "result": [
                    {"update_id": 10, "message": {"chat": {"id": 222}, "text": "NO"}},
                ],
            }

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def get(self, *_a, **_k):
            return _Resp()

    fake_httpx = SimpleNamespace(AsyncClient=lambda **kwargs: _Client())
    act = TelegramBotAction(bot_token="123:secret")
    with patch("ori.actions.telegram.httpx", fake_httpx):
        assert await act.listen_for_response("111", timeout_seconds=1) is None
