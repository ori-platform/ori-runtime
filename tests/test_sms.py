# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for ori/actions/sms.py.

The Africa's Talking SDK is never imported in these tests — it is stubbed
at the module level via monkeypatch so no live credentials are required.
"""

import sys
import types
from unittest.mock import AsyncMock

import pytest

from ori.actions.sms import SMSAction

# ── AT SDK stub ───────────────────────────────────────────────────────────────


def _make_at_stub(status: str = "Success") -> types.ModuleType:
    """Build a minimal africastalking module stub that returns *status*."""
    stub = types.ModuleType("africastalking")

    class _SMS:
        @staticmethod
        def send(message, recipients, sender_id):
            return {
                "SMSMessageData": {
                    "Recipients": [{"status": status, "number": recipients[0]}]
                }
            }

    stub.SMS = _SMS
    stub.initialize = lambda username, api_key: None
    return stub


def _make_at_stub_empty_recipients() -> types.ModuleType:
    stub = types.ModuleType("africastalking")
    stub.SMS = type(
        "_SMS",
        (),
        {
            "send": staticmethod(
                lambda msg, recip, sid: {"SMSMessageData": {"Recipients": []}}
            )
        },
    )
    stub.initialize = lambda username, api_key: None
    return stub


def _make_at_stub_raises() -> types.ModuleType:
    stub = types.ModuleType("africastalking")

    class _SMS:
        @staticmethod
        def send(message, recipients, sender_id):
            raise RuntimeError("AT network error")

    stub.SMS = _SMS
    stub.initialize = lambda username, api_key: None
    return stub


# ── Degraded mode (no credentials) ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_returns_false_without_api_key(monkeypatch):
    monkeypatch.delenv("AT_API_KEY", raising=False)
    action = SMSAction()
    ok = await action.send("Alert", "+2340000000000")
    assert ok is False


@pytest.mark.asyncio
async def test_listen_returns_none_without_api_key(monkeypatch):
    monkeypatch.delenv("AT_API_KEY", raising=False)
    action = SMSAction()
    result = await action.listen_for_response("+2340000000000", timeout_seconds=10)
    assert result is None


# ── Successful send ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_returns_true_on_success(monkeypatch):
    monkeypatch.setenv("AT_API_KEY", "test-key")
    monkeypatch.setitem(sys.modules, "africastalking", _make_at_stub("Success"))
    action = SMSAction()
    ok = await action.send("Alert: overcurrent.", "+2341234567890")
    assert ok is True


@pytest.mark.asyncio
async def test_send_passes_message_and_number_to_sdk(monkeypatch):
    """initialize() is called exactly once at construction, not on every send."""
    monkeypatch.setenv("AT_API_KEY", "test-key")
    send_calls: list[tuple] = []
    init_calls: list[tuple] = []

    stub = types.ModuleType("africastalking")

    class _SMS:
        @staticmethod
        def send(message, recipients, sender_id):
            send_calls.append((message, recipients, sender_id))
            return {"SMSMessageData": {"Recipients": [{"status": "Success"}]}}

    stub.SMS = _SMS
    stub.initialize = lambda u, k: init_calls.append((u, k))
    monkeypatch.setitem(sys.modules, "africastalking", stub)

    action = SMSAction()
    # initialize() must have fired exactly once at construction time
    assert len(init_calls) == 1, "initialize() must be called once in __init__"

    await action.send("hello from ori", "+2341111111111")
    await action.send("second alert", "+2341111111111")

    # Still exactly one init call after two sends
    assert len(init_calls) == 1, "initialize() must not be called again on send()"

    assert len(send_calls) == 2
    message, recipients, sender_id = send_calls[0]
    assert message == "hello from ori"
    assert "+2341111111111" in recipients
    assert sender_id == "ORI"


@pytest.mark.asyncio
async def test_send_uses_at_sender_id_env_var(monkeypatch):
    monkeypatch.setenv("AT_API_KEY", "key")
    monkeypatch.setenv("AT_SENDER_ID", "MYAPP")
    calls: list[str] = []

    stub = types.ModuleType("africastalking")

    class _SMS:
        @staticmethod
        def send(message, recipients, sender_id):
            calls.append(sender_id)
            return {"SMSMessageData": {"Recipients": [{"status": "Success"}]}}

    stub.SMS = _SMS
    stub.initialize = lambda u, k: None
    monkeypatch.setitem(sys.modules, "africastalking", stub)

    action = SMSAction()
    await action.send("test", "+234000")
    assert calls[0] == "MYAPP"


# ── Failed send paths ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_returns_false_on_non_success_status(monkeypatch):
    monkeypatch.setenv("AT_API_KEY", "test-key")
    monkeypatch.setitem(
        sys.modules, "africastalking", _make_at_stub("InvalidPhoneNumber")
    )
    action = SMSAction()
    ok = await action.send("Alert", "+000")
    assert ok is False


@pytest.mark.asyncio
async def test_send_returns_false_on_empty_recipients(monkeypatch):
    monkeypatch.setenv("AT_API_KEY", "test-key")
    monkeypatch.setitem(sys.modules, "africastalking", _make_at_stub_empty_recipients())
    action = SMSAction()
    ok = await action.send("Alert", "+000")
    assert ok is False


@pytest.mark.asyncio
async def test_send_returns_false_on_sdk_exception(monkeypatch):
    monkeypatch.setenv("AT_API_KEY", "test-key")
    monkeypatch.setitem(sys.modules, "africastalking", _make_at_stub_raises())
    action = SMSAction()
    ok = await action.send("Alert", "+234000")
    assert ok is False


@pytest.mark.asyncio
async def test_send_never_raises(monkeypatch):
    """send() must never propagate any exception — always returns bool."""
    monkeypatch.setenv("AT_API_KEY", "test-key")
    monkeypatch.setitem(sys.modules, "africastalking", _make_at_stub_raises())
    action = SMSAction()
    result = await action.send("Alert", "+234000")
    assert isinstance(result, bool)


# ── listen_for_response stub ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_listen_for_response_returns_none(monkeypatch):
    monkeypatch.setenv("AT_API_KEY", "key")
    monkeypatch.setitem(sys.modules, "africastalking", _make_at_stub())
    action = SMSAction()
    result = await action.listen_for_response("+2340000000000", timeout_seconds=30)
    assert result is None


@pytest.mark.asyncio
async def test_listen_for_response_does_not_block(monkeypatch):
    """Stub must return immediately — no sleeping or polling."""
    import time

    monkeypatch.setenv("AT_API_KEY", "key")
    monkeypatch.setitem(sys.modules, "africastalking", _make_at_stub())
    action = SMSAction()
    start = time.monotonic()
    await action.listen_for_response("+234000", timeout_seconds=300)
    elapsed = time.monotonic() - start
    assert elapsed < 0.5, f"listen_for_response blocked for {elapsed:.2f}s"


# ── webhook ingest + StateStore-backed listener ──────────────────────────────


@pytest.mark.asyncio
async def test_ingest_incoming_webhook_persists_message(monkeypatch):
    monkeypatch.delenv("AT_API_KEY", raising=False)
    store = types.SimpleNamespace(store_incoming_message=AsyncMock(return_value=None))
    action = SMSAction(state_store=store)

    ok = await action.ingest_incoming_webhook(
        {"from": "+234 800 000 0000", "text": " YES "}
    )

    assert ok is True
    store.store_incoming_message.assert_awaited_once()
    kwargs = store.store_incoming_message.await_args.kwargs
    assert kwargs["channel"] == "sms"
    assert kwargs["from_number"] == "+2348000000000"
    assert kwargs["message"] == "YES"


@pytest.mark.asyncio
async def test_ingest_incoming_webhook_rejects_invalid_payload(monkeypatch):
    monkeypatch.delenv("AT_API_KEY", raising=False)
    store = types.SimpleNamespace(store_incoming_message=AsyncMock(return_value=None))
    action = SMSAction(state_store=store)
    ok = await action.ingest_incoming_webhook({"from": "", "text": ""})
    assert ok is False
    assert not store.store_incoming_message.called


@pytest.mark.asyncio
async def test_listen_for_response_reads_from_state_store(monkeypatch):
    monkeypatch.delenv("AT_API_KEY", raising=False)
    store = types.SimpleNamespace(
        consume_incoming_message=AsyncMock(return_value="YES")
    )
    action = SMSAction(state_store=store)

    reply = await action.listen_for_response("+234 800 000 0000", timeout_seconds=1)

    assert reply == "YES"
    store.consume_incoming_message.assert_awaited_once()
    kwargs = store.consume_incoming_message.await_args.kwargs
    assert kwargs["channel"] == "sms"
    assert kwargs["from_number"] == "+2348000000000"


@pytest.mark.asyncio
async def test_listen_for_response_returns_none_when_store_missing(monkeypatch):
    monkeypatch.delenv("AT_API_KEY", raising=False)
    action = SMSAction(state_store=None)
    reply = await action.listen_for_response("+2348000000000", timeout_seconds=1)
    assert reply is None
