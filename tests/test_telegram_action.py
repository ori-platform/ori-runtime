# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ori.actions.telegram import TelegramBotAction


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
    import ori.actions.telegram as tg_mod

    with (
        patch.object(tg_mod, "_HTTPX_AVAILABLE", True),
        patch.object(tg_mod, "_httpx", fake_httpx),
    ):
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
    import ori.actions.telegram as tg_mod

    with (
        patch.object(tg_mod, "_HTTPX_AVAILABLE", True),
        patch.object(tg_mod, "_httpx", fake_httpx),
    ):
        assert await act.send("x", "1") is False
