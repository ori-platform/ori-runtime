# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ori.network.sms_webhook import SMSWebhookServer, _HttpRequest
from ori.security.webhook_signatures import (
    WebhookSignatureConfig,
    WebhookSignatureVerifier,
    sign_webhook_body,
)
from ori.utils.time_utils import now_ms


class _FakeWriter:
    def __init__(self, peername: tuple[str, int] = ("127.0.0.1", 12345)) -> None:
        self.buffer = bytearray()
        self.closed = False
        self.peername = peername

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    def get_extra_info(self, name: str):
        if name == "peername":
            return self.peername
        return None

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


#: Structural double for the declared parameter type.
_fakewriter: Any = _FakeWriter


@pytest.mark.asyncio
async def test_authorized_accepts_header_and_bearer():
    server = SMSWebhookServer(sms_action=AsyncMock(), token="secret-token")
    assert server._authorized({"x-ori-webhook-token": "secret-token"}) is True
    assert server._authorized({"authorization": "Bearer secret-token"}) is True
    assert server._authorized({"x-ori-webhook-token": "wrong"}) is False
    assert server._authorized({}) is False


def test_default_host_is_loopback():
    server = SMSWebhookServer(sms_action=AsyncMock(), token="secret-token")
    assert server._host == "127.0.0.1"


def test_source_allowed_enforces_configured_cidrs():
    server = SMSWebhookServer(
        sms_action=AsyncMock(),
        token="secret-token",
        allowed_source_cidrs=["203.0.113.0/24", "2001:db8::/32"],
    )

    assert server._source_allowed("203.0.113.9") is True
    assert server._source_allowed("2001:db8::1") is True
    assert server._source_allowed("198.51.100.9") is False
    assert server._source_allowed("unknown") is False


@pytest.mark.asyncio
async def test_handle_client_rejects_disallowed_source_before_parsing():
    sms_action = AsyncMock()
    sms_action.ingest_incoming_webhook.return_value = True
    server = SMSWebhookServer(
        sms_action=sms_action,
        token="secret-token",
        allowed_source_cidrs=["203.0.113.0/24"],
    )
    server._read_request = AsyncMock()
    reader = asyncio.StreamReader()
    writer = _fakewriter(peername=("198.51.100.10", 12345))

    await server._handle_client(reader, writer)

    text = writer.buffer.decode("utf-8", errors="replace")
    assert "403 Forbidden" in text
    server._read_request.assert_not_called()
    sms_action.ingest_incoming_webhook.assert_not_called()


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


@pytest.mark.parametrize(
    "body",
    [b'{"a":' * 50_000 + b"1" + b"}" * 50_000, b'{"text":' + b"9" * 5_000 + b"}"],
    ids=["deep nesting", "5000-digit integer"],
)
def test_decode_payload_refuses_hostile_json(body):
    server = SMSWebhookServer(sms_action=AsyncMock(), token="secret-token")

    assert server._decode_payload({"content-type": "application/json"}, body) == {}


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
async def test_read_request_rejects_oversized_body():
    server = SMSWebhookServer(sms_action=AsyncMock(), token="secret-token")
    reader = asyncio.StreamReader()
    content_length = 70 * 1024
    raw = (
        b"POST /webhooks/sms/africastalking HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {content_length}\r\n".encode("utf-8")
        + b"\r\n"
    )
    reader.feed_data(raw)
    reader.feed_eof()

    request = await server._read_request(reader)
    assert request is None


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
    writer = _fakewriter()

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
    writer = _fakewriter()

    await server._handle_client(reader, writer)

    text = writer.buffer.decode("utf-8", errors="replace")
    assert "200 OK" in text
    sms_action.ingest_incoming_webhook.assert_awaited_once_with(
        {"from": "+2348000000000", "text": "YES"}
    )


@pytest.mark.asyncio
async def test_handle_client_rejects_query_token_fallback():
    """Query-string token is no longer accepted; only header tokens are valid."""
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
    writer = _fakewriter()

    await server._handle_client(reader, writer)

    text = writer.buffer.decode("utf-8", errors="replace")
    assert "401 Unauthorized" in text
    sms_action.ingest_incoming_webhook.assert_not_called()


@pytest.mark.asyncio
async def test_handle_client_rejects_unsigned_hmac_webhook_before_parsing():
    sms_action = AsyncMock()
    sms_action.ingest_incoming_webhook.return_value = True
    server = SMSWebhookServer(
        sms_action=sms_action,
        token="secret-token",
        signature_verifier=WebhookSignatureVerifier(
            WebhookSignatureConfig(mode="hmac_required", shared_secret="hmac-secret")
        ),
    )
    server._read_request = AsyncMock(
        return_value=_HttpRequest(
            method="POST",
            path="/webhooks/sms/africastalking",
            headers={
                "x-ori-webhook-token": "secret-token",
                "content-type": "application/json",
            },
            body=b'{"from":"+2348000000000","text":"YES-AB12CD34"}',
        )
    )
    reader = asyncio.StreamReader()
    writer = _fakewriter()

    await server._handle_client(reader, writer)

    text = writer.buffer.decode("utf-8", errors="replace")
    assert "401 Unauthorized" in text
    sms_action.ingest_incoming_webhook.assert_not_called()


@pytest.mark.asyncio
async def test_handle_client_accepts_signed_hmac_webhook():
    sms_action = AsyncMock()
    sms_action.ingest_incoming_webhook.return_value = True
    body = b"from=%2B2348000000000&text=YES-AB12CD34"
    signed_at_ms = now_ms()
    signature = sign_webhook_body(
        body, shared_secret="hmac-secret", signed_at_ms=signed_at_ms, nonce="nonce-1"
    )
    server = SMSWebhookServer(
        sms_action=sms_action,
        token="secret-token",
        signature_verifier=WebhookSignatureVerifier(
            WebhookSignatureConfig(
                mode="token_and_hmac",
                shared_secret="hmac-secret",
                max_skew_ms=10_000_000_000,
            )
        ),
    )
    server._read_request = AsyncMock(
        return_value=_HttpRequest(
            method="POST",
            path="/webhooks/sms/africastalking",
            headers={
                "x-ori-webhook-token": "secret-token",
                "x-ori-webhook-signature": signature,
                "x-ori-webhook-timestamp": str(signed_at_ms),
                "x-ori-webhook-nonce": "nonce-1",
                "content-type": "application/x-www-form-urlencoded",
            },
            body=body,
        )
    )
    reader = asyncio.StreamReader()
    writer = _fakewriter()

    await server._handle_client(reader, writer)

    text = writer.buffer.decode("utf-8", errors="replace")
    assert "200 OK" in text
    sms_action.ingest_incoming_webhook.assert_awaited_once_with(
        {"from": "+2348000000000", "text": "YES-AB12CD34"}
    )


@pytest.mark.asyncio
async def test_the_per_peer_limit_is_a_cpu_backstop_not_an_approval_budget(
    monkeypatch,
):
    """Through `_handle_client`: every request from a bridge shares one
    address, so this limit sits far above any sender's and is the only one
    answered 429 before anything is read."""
    from ori.network import sms_webhook

    clock = [1_000.0]
    monkeypatch.setattr(sms_webhook.time, "monotonic", lambda: clock[0])
    sms_action = AsyncMock()
    sms_action.ingest_incoming_webhook.return_value = True
    server = SMSWebhookServer(sms_action=sms_action, token="secret-token")
    server._read_request = AsyncMock(return_value=None)

    async def answer(peer: str) -> str:
        writer = _fakewriter(peername=(peer, 12345))
        await server._handle_client(asyncio.StreamReader(), writer)
        return writer.buffer.decode("utf-8", errors="replace")

    for _ in range(600):
        assert "429" not in await answer("10.0.0.1")
    refused = await answer("10.0.0.1")
    assert "429 Too Many Requests" in refused
    assert server._read_request.await_count == 600, "refused before reading"
    assert "429" not in await answer("10.0.0.2"), "another peer has its own window"
    clock[0] += 60.001
    assert "429" not in await answer("10.0.0.1")


async def _served(monkeypatch: pytest.MonkeyPatch) -> tuple[SMSWebhookServer, Any]:
    from ori.network import sms_webhook

    monkeypatch.setattr(sms_webhook, "_REQUEST_TIMEOUT_SECONDS", 0.5)
    sms_action = AsyncMock()
    sms_action.ingest_incoming_webhook.return_value = True
    server = SMSWebhookServer(sms_action=sms_action, port=0, token="secret-token")
    await server.start()
    return server, sms_action


async def test_a_peer_that_sends_nothing_is_answered_408_and_releases_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, sms_action = await _served(monkeypatch)
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    try:
        answer = await asyncio.wait_for(reader.read(), timeout=5)
        assert answer.startswith(b"HTTP/1.1 408 ")
        await asyncio.wait_for(server.stop(), timeout=5)
    finally:
        writer.transport.abort()
    sms_action.ingest_incoming_webhook.assert_not_called()


async def test_bytes_that_trickle_in_do_not_extend_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, sms_action = await _served(monkeypatch)
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    try:

        async def trickle() -> None:
            for byte in b"POST /webhooks/sms/africastalking HTTP/1.1\r\nX-A: " * 4:
                writer.write(bytes([byte]))
                await writer.drain()
                await asyncio.sleep(0.05)

        sending = asyncio.create_task(trickle())
        answer = await asyncio.wait_for(reader.read(), timeout=5)
        # Answered while bytes were still arriving: the trickle, about 10 s of
        # them, did not extend the 0.5 s deadline.
        assert not sending.done()
        sending.cancel()
        assert answer.startswith(b"HTTP/1.1 408 ")
    finally:
        writer.transport.abort()
        await server.stop()
    sms_action.ingest_incoming_webhook.assert_not_called()


async def test_a_request_that_arrives_in_time_is_served(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, sms_action = await _served(monkeypatch)
    body = b"from=%2B2348000000000&text=YES"
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    try:
        writer.write(
            b"POST /webhooks/sms/africastalking HTTP/1.1\r\n"
            b"X-Ori-Webhook-Token: secret-token\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        answer = await asyncio.wait_for(reader.read(), timeout=5)
        assert answer.startswith(b"HTTP/1.1 200 ")
    finally:
        writer.transport.abort()
        await server.stop()
    sms_action.ingest_incoming_webhook.assert_awaited_once()


async def test_stop_waits_for_a_request_being_processed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On every supported interpreter: Python 3.11's wait_closed() would not."""
    server, sms_action = await _served(monkeypatch)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def slow_ingest(_payload: Any) -> bool:
        entered.set()
        await release.wait()
        return True

    sms_action.ingest_incoming_webhook.side_effect = slow_ingest
    body = b"from=%2B2348000000000&text=YES"
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    stopping: asyncio.Task[None] | None = None
    try:
        writer.write(
            b"POST /webhooks/sms/africastalking HTTP/1.1\r\n"
            b"X-Ori-Webhook-Token: secret-token\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        await asyncio.wait_for(entered.wait(), timeout=5)
        stopping = asyncio.create_task(server.stop())
        await asyncio.sleep(0.2)
        assert not stopping.done(), "stop() returned while the request was processed"
        release.set()
        await asyncio.wait_for(stopping, timeout=5)
        answer = await asyncio.wait_for(reader.read(), timeout=5)
        assert answer.startswith(b"HTTP/1.1 200 ")
    finally:
        release.set()
        writer.transport.abort()
        if stopping is not None and not stopping.done():
            stopping.cancel()


async def test_a_handler_starting_after_stop_is_not_served(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, sms_action = await _served(monkeypatch)
    await server.stop()
    writer = _fakewriter()
    reader = asyncio.StreamReader()
    reader.feed_data(b"POST /webhooks/sms/africastalking HTTP/1.1\r\n\r\n")
    reader.feed_eof()
    await server._tracked_client(reader, writer)  # type: ignore[arg-type]
    sms_action.ingest_incoming_webhook.assert_not_called()
    assert writer.buffer == b""


async def _mid_ingest(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    SMSWebhookServer, asyncio.StreamReader, asyncio.Event, asyncio.StreamWriter, Any
]:
    """A server with one complete request whose ingest is held."""
    server, sms_action = await _served(monkeypatch)
    entered, release = asyncio.Event(), asyncio.Event()

    async def slow_ingest(_payload: Any) -> bool:
        entered.set()
        await release.wait()
        return True

    sms_action.ingest_incoming_webhook.side_effect = slow_ingest
    body = b"from=%2B2348000000000&text=YES"
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    writer.write(
        b"POST /webhooks/sms/africastalking HTTP/1.1\r\n"
        b"X-Ori-Webhook-Token: secret-token\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
        + body
    )
    await writer.drain()
    await asyncio.wait_for(entered.wait(), timeout=5)
    return server, reader, release, writer, sms_action


async def test_a_second_stop_waits_for_the_first_drain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, reader, release, writer, _ = await _mid_ingest(monkeypatch)
    try:
        first = asyncio.create_task(server.stop())
        second = asyncio.create_task(server.stop())
        await asyncio.sleep(0.2)
        assert not first.done() and not second.done()
        release.set()
        await asyncio.wait_for(asyncio.gather(first, second), timeout=5)
    finally:
        release.set()
        writer.transport.abort()


async def test_a_cancelled_stop_still_lets_the_request_finish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shutdown cancels its tasks; the cancel must not reach a handler."""
    server, reader, release, writer, sms_action = await _mid_ingest(monkeypatch)
    try:
        stopping = asyncio.create_task(server.stop())
        await asyncio.sleep(0.1)
        stopping.cancel()
        await asyncio.sleep(0.2)
        assert not stopping.done(), "a cancelled stop() returned while a request ran"
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(stopping, timeout=5)
        answer = await asyncio.wait_for(reader.read(), timeout=5)
        assert answer.startswith(b"HTTP/1.1 200 ")
        sms_action.ingest_incoming_webhook.assert_awaited_once()
    finally:
        release.set()
        writer.transport.abort()
