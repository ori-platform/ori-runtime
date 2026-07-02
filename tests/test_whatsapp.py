# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for ori/actions/whatsapp.py.

All tests use a fake in-process provider — no Twilio credentials required.
"""

import sys
import types

import pytest

from ori.actions.whatsapp import (
    TwilioProvider,
    WhatsAppAction,
    WhatsAppProvider,
)
from ori.network.events import ReasoningResult

# ── Helpers ───────────────────────────────────────────────────────────────────


def _result(
    text: str = "Overcurrent detected.", confidence: float = 0.95
) -> ReasoningResult:
    return ReasoningResult(
        text=text,
        tier="rule",
        model="rule_engine",
        tokens_used=0,
        latency_ms=1,
        confidence=confidence,
        action_tier="C",
        proposed_action="open_safety_circuit",
    )


class _OKProvider:
    """Always succeeds; stores sent messages for inspection."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []  # (to, message)
        self.inbox: list[str] = []  # pre-loaded replies

    async def send(self, to: str, message: str) -> bool:
        self.sent.append((to, message))
        return True

    async def get_incoming(self, from_number: str, since_ms: int) -> list[str]:
        msgs, self.inbox = self.inbox[:], []
        return msgs


class _FailProvider:
    """Always fails on send."""

    async def send(self, to: str, message: str) -> bool:
        return False

    async def get_incoming(self, from_number: str, since_ms: int) -> list[str]:
        return []


# ── Protocol conformance ──────────────────────────────────────────────────────


def test_ok_provider_satisfies_protocol():
    assert isinstance(_OKProvider(), WhatsAppProvider)


def test_fail_provider_satisfies_protocol():
    assert isinstance(_FailProvider(), WhatsAppProvider)


# ── WhatsAppAction.send ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_returns_true_on_success():
    action = WhatsAppAction(provider=_OKProvider())
    ok = await action.send("Hello", to_number="whatsapp:+2340000000000")
    assert ok is True


@pytest.mark.asyncio
async def test_send_returns_false_on_failure():
    action = WhatsAppAction(provider=_FailProvider())
    ok = await action.send("Hello", to_number="whatsapp:+2340000000000")
    assert ok is False


@pytest.mark.asyncio
async def test_send_delegates_to_provider():
    provider = _OKProvider()
    action = WhatsAppAction(provider=provider)
    await action.send("ping", to_number="whatsapp:+111")
    assert provider.sent == [("whatsapp:+111", "ping")]


@pytest.mark.asyncio
async def test_send_never_raises_even_on_exception():
    """send() must return False, not propagate, even if the provider raises."""

    class _ExplodingProvider:
        async def send(self, to: str, message: str) -> bool:
            raise RuntimeError("network down")

        async def get_incoming(self, from_number: str, since_ms: int) -> list[str]:
            return []

    action = WhatsAppAction(provider=_ExplodingProvider())
    result = await action.send("msg", "whatsapp:+0")
    assert result is False


# ── WhatsAppAction.send_approval_request ─────────────────────────────────────


@pytest.mark.asyncio
async def test_send_approval_request_returns_formatted_string():
    provider = _OKProvider()
    action = WhatsAppAction(provider=provider)
    msg, delivered = await action.send_approval_request(
        result=_result("AC draws 40% above baseline."),
        action="open_safety_circuit",
        timeout_seconds=300,
        to_number="whatsapp:+234111",
        device_id="energy-monitor-ikeja-01",
    )
    assert delivered is True
    assert "energy-monitor-ikeja-01" in msg
    assert "AC draws 40% above baseline." in msg
    assert "open_safety_circuit" in msg
    assert "300" in msg
    assert "95%" in msg  # confidence formatted as percentage


@pytest.mark.asyncio
async def test_send_approval_request_sends_via_provider():
    provider = _OKProvider()
    action = WhatsAppAction(provider=provider)
    _, delivered = await action.send_approval_request(
        result=_result(),
        action="open_safety_circuit",
        timeout_seconds=300,
        to_number="whatsapp:+234111",
    )
    assert delivered is True
    assert len(provider.sent) == 1
    to, body = provider.sent[0]
    assert to == "whatsapp:+234111"
    assert "YES" in body
    assert "NO" in body


@pytest.mark.asyncio
async def test_send_approval_request_contains_all_template_fields():
    """Every placeholder in the canonical template must be filled."""
    provider = _OKProvider()
    action = WhatsAppAction(provider=provider)
    msg, delivered = await action.send_approval_request(
        result=_result("High temperature."),
        action="shutdown_heater",
        timeout_seconds=120,
        to_number="whatsapp:+1",
        device_id="device-x",
    )
    assert delivered is True
    # No un-expanded {placeholder} should remain
    assert "{" not in msg and "}" not in msg


@pytest.mark.asyncio
async def test_send_approval_request_returns_false_when_provider_fails():
    action = WhatsAppAction(provider=_FailProvider())
    _msg, delivered = await action.send_approval_request(
        result=_result("High temperature."),
        action="shutdown_heater",
        timeout_seconds=120,
        to_number="whatsapp:+1",
        device_id="device-x",
    )
    assert delivered is False


# ── WhatsAppAction.listen_for_response ────────────────────────────────────────


@pytest.mark.asyncio
async def test_listen_returns_reply_when_available():
    provider = _OKProvider()
    provider.inbox = ["YES"]
    action = WhatsAppAction(provider=provider)
    reply = await action.listen_for_response(
        from_number="whatsapp:+234111", timeout_seconds=30
    )
    assert reply == "YES"


@pytest.mark.asyncio
async def test_listen_returns_none_on_timeout():
    # _FailProvider never produces inbox messages
    action = WhatsAppAction(provider=_FailProvider())
    action._POLL_INTERVAL_SECONDS = 0  # make the test instant
    reply = await action.listen_for_response(
        from_number="whatsapp:+234111", timeout_seconds=0
    )
    assert reply is None


@pytest.mark.asyncio
async def test_listen_returns_first_message():
    """When multiple messages arrive, only the first is returned."""
    provider = _OKProvider()
    provider.inbox = ["maybe", "YES", "NO"]
    action = WhatsAppAction(provider=provider)
    reply = await action.listen_for_response(
        from_number="whatsapp:+234111", timeout_seconds=30
    )
    assert reply == "maybe"


@pytest.mark.asyncio
async def test_listen_polls_until_reply_arrives():
    """Provider returns empty list on first call, then a reply on the second."""
    call_count = 0

    class _DelayedProvider:
        async def send(self, to: str, message: str) -> bool:
            return True

        async def get_incoming(self, from_number: str, since_ms: int) -> list[str]:
            nonlocal call_count
            call_count += 1
            return ["NO"] if call_count >= 2 else []

    action = WhatsAppAction(provider=_DelayedProvider())
    action._POLL_INTERVAL_SECONDS = 0  # no real sleeping in tests
    reply = await action.listen_for_response(
        from_number="whatsapp:+234111", timeout_seconds=60
    )
    assert reply == "NO"
    assert call_count >= 2


# ── TwilioProvider degraded mode (no credentials) ────────────────────────────


@pytest.mark.asyncio
async def test_twilio_provider_send_returns_false_without_credentials(monkeypatch):
    monkeypatch.delenv("TWILIO_ACCOUNT_SID", raising=False)
    monkeypatch.delenv("TWILIO_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("TWILIO_WHATSAPP_FROM", raising=False)
    provider = TwilioProvider()
    assert await provider.send("whatsapp:+1", "hello") is False


@pytest.mark.asyncio
async def test_twilio_provider_get_incoming_returns_empty_without_credentials(
    monkeypatch,
):
    monkeypatch.delenv("TWILIO_ACCOUNT_SID", raising=False)
    monkeypatch.delenv("TWILIO_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("TWILIO_WHATSAPP_FROM", raising=False)
    provider = TwilioProvider()
    msgs = await provider.get_incoming("whatsapp:+1", since_ms=0)
    assert msgs == []


@pytest.mark.asyncio
async def test_twilio_provider_disables_on_invalid_from_prefix(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "sid")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "token")
    monkeypatch.setenv("TWILIO_WHATSAPP_FROM", "+14155238886")
    provider = TwilioProvider()
    assert await provider.send("whatsapp:+1", "hello") is False


@pytest.mark.asyncio
async def test_twilio_provider_rate_limit_backoff_skips_immediate_repoll(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "sid")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "token")
    monkeypatch.setenv("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")
    monkeypatch.setenv("TWILIO_INCOMING_MIN_POLL_INTERVAL_S", "1")
    monkeypatch.setenv("TWILIO_RATE_LIMIT_COOLDOWN_S", "30")

    # Stub twilio.rest.Client import path.
    twilio_mod = types.ModuleType("twilio")
    twilio_rest_mod = types.ModuleType("twilio.rest")

    class _FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        class messages:  # noqa: N801
            @staticmethod
            def list(**_kwargs):
                return []

    twilio_rest_mod.Client = _FakeClient
    monkeypatch.setitem(sys.modules, "twilio", twilio_mod)
    monkeypatch.setitem(sys.modules, "twilio.rest", twilio_rest_mod)

    class _RateLimitError(Exception):
        status = 429
        code = 20429

    async def _raise_rate_limit(*_args, **_kwargs):
        raise _RateLimitError()

    provider = TwilioProvider()
    monkeypatch.setattr("ori.actions.whatsapp.asyncio.to_thread", _raise_rate_limit)
    first = await provider.get_incoming("whatsapp:+234111", since_ms=0)
    assert first == []

    called = {"count": 0}

    async def _count_calls(*_args, **_kwargs):
        called["count"] += 1
        return []

    monkeypatch.setattr("ori.actions.whatsapp.asyncio.to_thread", _count_calls)
    second = await provider.get_incoming("whatsapp:+234111", since_ms=0)
    assert second == []
    assert called["count"] == 0


# ── Provider swappability ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_custom_provider_is_used_exclusively():
    """WhatsAppAction.send contains no Twilio-specific code — provider is the sole I/O path."""

    class _RecordingProvider:
        called_with: tuple | None = None

        async def send(self, to: str, message: str) -> bool:
            _RecordingProvider.called_with = (to, message)
            return True

        async def get_incoming(self, from_number: str, since_ms: int) -> list[str]:
            return []

    action = WhatsAppAction(provider=_RecordingProvider())
    await action.send("test", to_number="whatsapp:+999")
    assert _RecordingProvider.called_with == ("whatsapp:+999", "test")


# ── since_ms parameter ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_since_ms_catches_reply_sent_before_listen_starts():
    """A reply that arrives between sending the request and calling
    listen_for_response is found when since_ms is set before the send,
    but missed when since_ms defaults to the current time at listen time.

    Timeline:
        t0  since_ms captured
        t1  approval request sent  (reply already in inbox at t1)
        t2  listen_for_response called
            - with since_ms=t0  → reply is at t1 > t0  → FOUND
            - with since_ms=None → defaults to t2, reply is at t1 < t2 → MISSED
    """
    import time as _time

    REPLY = "YES"  # noqa: N806
    REPLY_MS = (  # noqa: N806
        int(_time.time() * 1000) - 2000
    )  # reply "arrived" 2 seconds ago  # noqa: N806

    class _TimestampAwareProvider:
        """Returns REPLY only for queries with since_ms earlier than REPLY_MS."""

        async def send(self, to: str, message: str) -> bool:
            return True

        async def get_incoming(self, from_number: str, since_ms: int) -> list[str]:
            # Simulate: message exists at REPLY_MS; only visible if since_ms <= REPLY_MS
            return [REPLY] if since_ms <= REPLY_MS else []

    action = WhatsAppAction(provider=_TimestampAwareProvider())
    action._POLL_INTERVAL_SECONDS = 0

    # With since_ms set before the reply arrived: reply is found
    t0 = REPLY_MS - 1000  # 1 second before the reply
    reply_found = await action.listen_for_response(
        from_number="whatsapp:+234111",
        timeout_seconds=1,
        since_ms=t0,
    )
    assert reply_found == REPLY, "Expected reply to be found when since_ms precedes it"

    # Without since_ms (defaults to now, which is after the reply): reply is missed
    reply_missed = await action.listen_for_response(
        from_number="whatsapp:+234111",
        timeout_seconds=0,  # instant timeout — since_ms > REPLY_MS, so no match
    )
    assert reply_missed is None, (
        "Expected reply to be missed when since_ms defaults to now"
    )
