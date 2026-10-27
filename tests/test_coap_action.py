# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ori.actions.coap import CoAPAction


def _config() -> dict:
    return {
        "enabled": True,
        "timeout_s": 0.5,
        "retries": 1,
        "allowed_hosts": ["192.168.1.70"],
        "commands": {
            "open_bypass_valve": {
                "uri": "coap://192.168.1.70/actuators/bypass",
                "method": "POST",
                "payload": {"state": "open"},
            }
        },
    }


class _Code(int):
    """An int that prints as aiocoap's `Code` does, such as "2.04 Changed"."""

    _text: str

    def __new__(cls, value: int, text: str) -> "_Code":
        code = super().__new__(cls, value)
        code._text = text
        return code

    def __str__(self) -> str:
        return self._text


CHANGED = _Code(68, "2.04 Changed")
UNAUTHORIZED = _Code(129, "4.01 Unauthorized")


class _FakeResponse:
    def __init__(self, code: object):
        self.code = code


class _FakeRequester:
    def __init__(self, response):
        self.response = response


class _FakeContext:
    def __init__(self, response):
        self._response = response
        self.messages = []
        self.shutdown_called = False

    def request(self, message):
        self.messages.append(message)
        return _FakeRequester(self._response)

    async def shutdown(self):
        self.shutdown_called = True


class _FakeMessage:
    def __init__(self, code, uri, payload):
        self.code = code
        self.uri = uri
        self.payload = payload


class TestCoAPAction:
    @pytest.mark.asyncio
    async def test_disabled_returns_false(self):
        action = CoAPAction({"enabled": False})
        assert await action.execute_command("open_bypass_valve") is False

    @pytest.mark.asyncio
    async def test_missing_aiocoap_returns_false(self):
        action = CoAPAction(_config())
        with (
            patch("ori.actions.coap._AIOCOAP_AVAILABLE", False),
            patch("ori.actions.coap._aiocoap", None),
        ):
            assert await action.execute_command("open_bypass_valve") is False

    @pytest.mark.asyncio
    async def test_successful_command(self):
        action = CoAPAction(_config())
        fake_context = _FakeContext(asyncio.Future())
        fake_context._response.set_result(_FakeResponse(CHANGED))
        fake_aiocoap = SimpleNamespace(
            POST="POST",
            GET="GET",
            PUT="PUT",
            DELETE="DELETE",
            Message=_FakeMessage,
            Context=SimpleNamespace(
                create_client_context=staticmethod(
                    lambda: _completed_future(fake_context)
                )
            ),
        )

        with (
            patch("ori.actions.coap._AIOCOAP_AVAILABLE", True),
            patch("ori.actions.coap._aiocoap", fake_aiocoap),
        ):
            ok = await action.execute_command("open_bypass_valve")
            assert ok is True
            assert len(fake_context.messages) == 1
            req = fake_context.messages[0]
            assert req.uri == "coap://192.168.1.70/actuators/bypass"
            assert req.code == "POST"
            assert b'"state":"open"' in req.payload
            assert fake_context.shutdown_called is True

    @pytest.mark.asyncio
    async def test_disallowed_host_refused(self):
        cfg = _config()
        cfg["commands"]["open_bypass_valve"]["uri"] = "coap://10.0.0.8/relay"
        action = CoAPAction(cfg)
        assert await action.execute_command("open_bypass_valve") is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "code",
        [
            pytest.param(_Code(0x00, "0.00 EMPTY"), id="0.00"),
            pytest.param(_Code(0x20, "1.00 (unknown)"), id="1.00"),
            pytest.param(UNAUTHORIZED, id="4.01"),
            pytest.param(_Code(163, "5.03 Service Unavailable"), id="5.03"),
            pytest.param(_Code(255, "7.31 (unknown)"), id="unregistered-class"),
            # Read as the adapter reads it: a text code, even one that
            # prints as a success, is not one.
            pytest.param("2.04 Changed", id="text"),
            pytest.param(None, id="no-code"),
        ],
    )
    async def test_non_success_response_returns_false(self, code):
        action = CoAPAction(_config())
        fake_context = _FakeContext(asyncio.Future())
        fake_context._response.set_result(_FakeResponse(code))
        fake_aiocoap = SimpleNamespace(
            POST="POST",
            GET="GET",
            PUT="PUT",
            DELETE="DELETE",
            Message=_FakeMessage,
            Context=SimpleNamespace(
                create_client_context=staticmethod(
                    lambda: _completed_future(fake_context)
                )
            ),
        )
        with (
            patch("ori.actions.coap._AIOCOAP_AVAILABLE", True),
            patch("ori.actions.coap._aiocoap", fake_aiocoap),
        ):
            assert await action.execute_command("open_bypass_valve") is False


def _completed_future(value):
    fut = asyncio.Future()
    fut.set_result(value)
    return fut
