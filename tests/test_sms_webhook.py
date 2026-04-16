# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
from unittest.mock import AsyncMock

import pytest

from ori.network.sms_webhook import SMSWebhookServer, _HttpRequest


class _FakeWriter:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


@pytest.mark.asyncio
async def test_authorized_accepts_header_and_bearer():
    server = SMSWebhookServer(sms_action=AsyncMock(), token="secret-token")
    assert server._authorized({"x-ori-webhook-token": "secret-token"}) is True
    assert server._authorized({"authorization": "Bearer secret-token"}) is True
    assert server._authorized({}, {"token": ["secret-token"]}) is True
    assert server._authorized({"x-ori-webhook-token": "wrong"}) is False


@pytest.mark.asyncio
async def test_decode_payload_form_and_json():
    server = SMSWebhookServer(sms_action=AsyncMock(), token="secret-token")

    form = server._decode_payload(
        {"content-type": "application/x-www-form-urlencoded"},
        b"from=%2B2348000000000&text=YES",
    )
    assert form == {"from": "+2348000000000", "text": "YES"}

    js = server._decode_payload(
        {"content-type": "application/json"},
        b'{"from":"+2348000000000","text":"NO"}',
    )
    assert js == {"from": "+2348000000000", "text": "NO"}


@pytest.mark.asyncio
async def test_read_request_parses_http_message():
    server = SMSWebhookServer(sms_action=AsyncMock(), token="secret-token")
    reader = asyncio.StreamReader()
    body = b'{"text":"YES"}'
    raw = (
        b"POST /webhooks/sms/africastalking HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("utf-8")
        + b"\r\n"
        + body
    )
    reader.feed_data(raw)
    reader.feed_eof()

    request = await server._read_request(reader)
    assert request is not None
    assert request.method == "POST"
    assert request.path == "/webhooks/sms/africastalking"
    assert request.headers["content-type"] == "application/json"
    assert request.body == body


@pytest.mark.asyncio
async def test_handle_client_returns_401_when_token_invalid():
    sms_action = AsyncMock()
    sms_action.ingest_incoming_webhook.return_value = True
    server = SMSWebhookServer(sms_action=sms_action, token="secret-token")
    server._read_request = AsyncMock(
        return_value=_HttpRequest(
            method="POST",
            path="/webhooks/sms/africastalking",
            headers={"x-ori-webhook-token": "wrong"},
            body=b"from=%2B2348000000000&text=YES",
        )
    )
    reader = asyncio.StreamReader()
    writer = _FakeWriter()

    await server._handle_client(reader, writer)

    text = writer.buffer.decode("utf-8", errors="replace")
    assert "401 Unauthorized" in text
    sms_action.ingest_incoming_webhook.assert_not_called()


@pytest.mark.asyncio
async def test_handle_client_returns_200_for_valid_request():
    sms_action = AsyncMock()
    sms_action.ingest_incoming_webhook.return_value = True
    server = SMSWebhookServer(sms_action=sms_action, token="secret-token")
    server._read_request = AsyncMock(
        return_value=_HttpRequest(
            method="POST",
            path="/webhooks/sms/africastalking",
            headers={
                "x-ori-webhook-token": "secret-token",
                "content-type": "application/x-www-form-urlencoded",
            },
            body=b"from=%2B2348000000000&text=YES",
        )
    )
    reader = asyncio.StreamReader()
    writer = _FakeWriter()

    await server._handle_client(reader, writer)

    text = writer.buffer.decode("utf-8", errors="replace")
    assert "200 OK" in text
    sms_action.ingest_incoming_webhook.assert_awaited_once_with(
        {"from": "+2348000000000", "text": "YES"}
    )


@pytest.mark.asyncio
async def test_handle_client_accepts_query_token_fallback():
    sms_action = AsyncMock()
    sms_action.ingest_incoming_webhook.return_value = True
    server = SMSWebhookServer(sms_action=sms_action, token="secret-token")
    server._read_request = AsyncMock(
        return_value=_HttpRequest(
            method="POST",
            path="/webhooks/sms/africastalking?token=secret-token",
            headers={
                "content-type": "application/x-www-form-urlencoded",
            },
            body=b"from=%2B2348000000000&text=YES",
        )
    )
    reader = asyncio.StreamReader()
    writer = _FakeWriter()

    await server._handle_client(reader, writer)

    text = writer.buffer.decode("utf-8", errors="replace")
    assert "200 OK" in text
    sms_action.ingest_incoming_webhook.assert_awaited_once_with(
        {"from": "+2348000000000", "text": "YES"}
    )
