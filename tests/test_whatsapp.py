# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for ori/actions/whatsapp.py.

All tests use a fake in-process provider — no Twilio credentials required.
"""

import json
import sys
import types
from datetime import UTC, datetime

import pytest

from ori.actions.alert_delivery import (
    AlertDeliveryReceipt,
    AlertIntent,
    AlertSendReceipt,
    InboundWhatsAppMessage,
    WhatsAppSessionReply,
    build_outbound_alert,
)
from ori.actions.whatsapp import (
    TwilioProvider,
    WhatsAppAction,
    WhatsAppProvider,
)
from ori.network.events import ReasoningResult
from ori.utils.time_utils import now_ms

_TEMPLATES = {
    intent.value: "HX" + f"{index:x}" * 32
    for index, intent in enumerate(AlertIntent, start=1)
}


def _alert(intent: AlertIntent = AlertIntent.TIER_A_ALERT):
    variables: dict[AlertIntent, tuple[object, ...]] = {
        AlertIntent.STARTUP: ("Abuja", 2, 4),
        AlertIntent.TIER_A_ALERT: ("overcurrent", "Abuja", "2026-08-26 23:00 WAT"),
        AlertIntent.TIER_C_APPROVAL: (
            "open_safety_circuit",
            "Abuja",
            "Wednesday 23:00",
            "AB12CD34",
            300,
        ),
        AlertIntent.TIER_C_ESCALATION: (
            "AB12CD34",
            "Abuja",
            "Wednesday 23:05",
            "completed",
        ),
    }
    return build_outbound_alert(
        intent=intent,
        sms_body="Detailed SMS reasoning.",
        template_variables=variables[intent],
    )


def _inbound(body: str = "YES", *, received_at_ms: int | None = None):
    return InboundWhatsAppMessage(
        provider_message_id="SM" + "a" * 32,
        from_number="whatsapp:+234111",
        body=body,
        received_at_ms=received_at_ms if received_at_ms is not None else now_ms(),
    )


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
        self.sent_templates: list[tuple[str, str, tuple[str, ...]]] = []
        self.session_replies: list[tuple[str, str]] = []
        self.inbox: list[InboundWhatsAppMessage] = []

    async def send_template(self, to, template_id, variables):
        self.sent_templates.append((to, template_id, variables))
        return AlertSendReceipt(
            accepted=True,
            channel="whatsapp",
            provider_message_id="SM" + "b" * 32,
            provider_status="queued",
            accepted_at_ms=now_ms(),
        )

    async def send_session_reply(self, to, message):
        self.session_replies.append((to, message))
        return AlertSendReceipt.accepted_without_provider_receipt(channel="whatsapp")

    async def get_incoming(self, from_number, since_ms):
        msgs, self.inbox = self.inbox[:], []
        return msgs

    async def get_delivery_receipt(self, provider_message_id):
        return AlertDeliveryReceipt(
            provider_message_id=provider_message_id,
            provider_status="delivered",
            observed_at_ms=now_ms(),
            delivered_at_ms=now_ms(),
        )


class _FailProvider:
    """Always fails on send."""

    async def send_template(self, to, template_id, variables):
        return AlertSendReceipt.refused(channel="whatsapp")

    async def send_session_reply(self, to, message):
        return AlertSendReceipt.refused(channel="whatsapp")

    async def get_incoming(self, from_number, since_ms):
        return []

    async def get_delivery_receipt(self, provider_message_id):
        return None


# ── Protocol conformance ──────────────────────────────────────────────────────


def test_ok_provider_satisfies_protocol():
    assert isinstance(_OKProvider(), WhatsAppProvider)


def test_fail_provider_satisfies_protocol():
    assert isinstance(_FailProvider(), WhatsAppProvider)


# ── WhatsAppAction.submit / send_reply ───────────────────────────────────────


@pytest.mark.asyncio
async def test_submit_returns_provider_acceptance():
    action = WhatsAppAction(provider=_OKProvider(), templates=_TEMPLATES)
    receipt = await action.submit(_alert(), to_number="whatsapp:+2340000000000")
    assert receipt.accepted is True
    assert receipt.delivered_at_ms is None


@pytest.mark.asyncio
async def test_submit_returns_refusal_on_failure():
    action = WhatsAppAction(provider=_FailProvider(), templates=_TEMPLATES)
    receipt = await action.submit(_alert(), to_number="whatsapp:+2340000000000")
    assert receipt.accepted is False


@pytest.mark.asyncio
async def test_submit_delegates_template_identity_and_ordered_variables():
    provider = _OKProvider()
    action = WhatsAppAction(provider=provider, templates=_TEMPLATES)
    alert = _alert()
    await action.submit(alert, to_number="whatsapp:+111")
    assert provider.sent_templates == [
        (
            "whatsapp:+111",
            _TEMPLATES[AlertIntent.TIER_A_ALERT.value],
            alert.template_variables,
        )
    ]


@pytest.mark.asyncio
async def test_submit_never_raises_even_on_exception():
    """submit() returns a refusal rather than propagating provider failure."""

    class _ExplodingProvider:
        async def send_template(self, to, template_id, variables):
            raise RuntimeError("network down")

        async def send_session_reply(self, to, message):
            raise RuntimeError("network down")

        async def get_incoming(self, from_number, since_ms):
            return []

        async def get_delivery_receipt(self, provider_message_id):
            return None

    action = WhatsAppAction(provider=_ExplodingProvider(), templates=_TEMPLATES)
    receipt = await action.submit(_alert(), "whatsapp:+0")
    assert receipt.accepted is False


@pytest.mark.asyncio
async def test_free_form_reply_requires_fresh_recorded_inbound_message():
    provider = _OKProvider()
    action = WhatsAppAction(provider=provider, templates=_TEMPLATES)
    inbound = _inbound("ORI_COMMAND {...}")

    sent = await action.send_reply(
        WhatsAppSessionReply(body="Command rejected.", in_reply_to=inbound),
        "whatsapp:+234111",
    )

    assert sent is True
    assert provider.session_replies == [("whatsapp:+234111", "Command rejected.")]


@pytest.mark.asyncio
async def test_free_form_reply_refuses_expired_inbound_window():
    provider = _OKProvider()
    action = WhatsAppAction(provider=provider, templates=_TEMPLATES)
    inbound = _inbound(received_at_ms=now_ms() - (24 * 60 * 60 * 1000))

    sent = await action.send_reply(
        WhatsAppSessionReply(body="late", in_reply_to=inbound),
        "whatsapp:+234111",
    )

    assert sent is False
    assert provider.session_replies == []


# ── WhatsAppAction.send_approval_request ─────────────────────────────────────


@pytest.mark.asyncio
async def test_send_approval_request_returns_formatted_string():
    provider = _OKProvider()
    action = WhatsAppAction(provider=provider, templates=_TEMPLATES)
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
    action = WhatsAppAction(provider=provider, templates=_TEMPLATES)
    _, delivered = await action.send_approval_request(
        result=_result(),
        action="open_safety_circuit",
        timeout_seconds=300,
        to_number="whatsapp:+234111",
    )
    assert delivered is True
    assert len(provider.sent_templates) == 1
    to, template_id, variables = provider.sent_templates[0]
    assert to == "whatsapp:+234111"
    assert template_id == _TEMPLATES[AlertIntent.TIER_C_APPROVAL.value]
    assert variables[0] == "open_safety_circuit"
    assert all("Overcurrent detected" not in value for value in variables)


@pytest.mark.asyncio
async def test_send_approval_request_contains_all_template_fields():
    """Every placeholder in the canonical template must be filled."""
    provider = _OKProvider()
    action = WhatsAppAction(provider=provider, templates=_TEMPLATES)
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
    action = WhatsAppAction(provider=_FailProvider(), templates=_TEMPLATES)
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
    provider.inbox = [_inbound("YES")]
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
    provider.inbox = [_inbound("maybe"), _inbound("YES"), _inbound("NO")]
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
        async def send_template(self, to, template_id, variables):
            return AlertSendReceipt.accepted_without_provider_receipt(
                channel="whatsapp"
            )

        async def send_session_reply(self, to, message):
            return AlertSendReceipt.accepted_without_provider_receipt(
                channel="whatsapp"
            )

        async def get_incoming(self, from_number, since_ms):
            nonlocal call_count
            call_count += 1
            return [_inbound("NO")] if call_count >= 2 else []

        async def get_delivery_receipt(self, provider_message_id):
            return None

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
    receipt = await provider.send_template("whatsapp:+1", "HX" + "1" * 32, ("hello",))
    assert receipt.accepted is False


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
    receipt = await provider.send_template("whatsapp:+1", "HX" + "1" * 32, ("hello",))
    assert receipt.accepted is False


@pytest.mark.asyncio
async def test_twilio_business_send_uses_content_sid_and_never_body(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "sid")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "token")
    monkeypatch.setenv("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")
    calls: list[dict] = []
    twilio_mod = types.ModuleType("twilio")
    twilio_rest_mod = types.ModuleType("twilio.rest")

    class _Messages:
        def create(self, **kwargs):
            calls.append(kwargs)
            return types.SimpleNamespace(
                sid="SM" + "d" * 32,
                status="queued",
                date_updated=datetime.now(UTC),
            )

    class _FakeClient:
        def __init__(self, *_args, **_kwargs):
            self.messages = _Messages()

    twilio_rest_mod.Client = _FakeClient
    monkeypatch.setitem(sys.modules, "twilio", twilio_mod)
    monkeypatch.setitem(sys.modules, "twilio.rest", twilio_rest_mod)

    async def _run_inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr("ori.actions.whatsapp.asyncio.to_thread", _run_inline)

    provider = TwilioProvider()
    receipt = await provider.send_template(
        "whatsapp:+234111",
        "HX" + "1" * 32,
        ("risk", "Abuja", "Wednesday 23:00"),
    )

    assert receipt.accepted is True
    assert receipt.provider_message_id == "SM" + "d" * 32
    assert calls == [
        {
            "from_": "whatsapp:+14155238886",
            "to": "whatsapp:+234111",
            "content_sid": "HX" + "1" * 32,
            "content_variables": json.dumps(
                {"1": "risk", "2": "Abuja", "3": "Wednesday 23:00"},
                separators=(",", ":"),
            ),
        }
    ]
    assert "body" not in calls[0]


@pytest.mark.asyncio
async def test_twilio_delivery_receipt_retains_provider_status(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "sid")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "token")
    monkeypatch.setenv("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")
    twilio_mod = types.ModuleType("twilio")
    twilio_rest_mod = types.ModuleType("twilio.rest")

    class _MessageResource:
        def fetch(self):
            return types.SimpleNamespace(
                status="delivered",
                date_updated=datetime.now(UTC),
            )

    class _Messages:
        def __call__(self, provider_message_id):
            assert provider_message_id == "SM" + "d" * 32
            return _MessageResource()

    class _FakeClient:
        def __init__(self, *_args, **_kwargs):
            self.messages = _Messages()

    twilio_rest_mod.Client = _FakeClient
    monkeypatch.setitem(sys.modules, "twilio", twilio_mod)
    monkeypatch.setitem(sys.modules, "twilio.rest", twilio_rest_mod)

    async def _run_inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr("ori.actions.whatsapp.asyncio.to_thread", _run_inline)
    provider = TwilioProvider()

    receipt = await provider.get_delivery_receipt("SM" + "d" * 32)

    assert receipt is not None
    assert receipt.provider_status == "delivered"
    assert receipt.delivered_at_ms is not None
    assert receipt.terminal_failure is False


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
    """WhatsAppAction contains no Twilio-specific template I/O."""

    class _RecordingProvider:
        called_with: tuple | None = None

        async def send_template(self, to, template_id, variables):
            _RecordingProvider.called_with = (to, template_id, variables)
            return AlertSendReceipt.accepted_without_provider_receipt(
                channel="whatsapp"
            )

        async def send_session_reply(self, to, message):
            raise AssertionError("business alerts must not use body=")

        async def get_incoming(self, from_number, since_ms):
            return []

        async def get_delivery_receipt(self, provider_message_id):
            return None

    action = WhatsAppAction(provider=_RecordingProvider(), templates=_TEMPLATES)
    alert = _alert()
    await action.submit(alert, to_number="whatsapp:+999")
    assert _RecordingProvider.called_with == (
        "whatsapp:+999",
        _TEMPLATES[AlertIntent.TIER_A_ALERT.value],
        alert.template_variables,
    )


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

        async def send_template(self, to, template_id, variables):
            return AlertSendReceipt.accepted_without_provider_receipt(
                channel="whatsapp"
            )

        async def send_session_reply(self, to, message):
            return AlertSendReceipt.accepted_without_provider_receipt(
                channel="whatsapp"
            )

        async def get_incoming(self, from_number, since_ms):
            # Simulate: message exists at REPLY_MS; only visible if since_ms <= REPLY_MS
            return (
                [
                    InboundWhatsAppMessage(
                        provider_message_id="SM" + "c" * 32,
                        from_number=from_number,
                        body=REPLY,
                        received_at_ms=REPLY_MS,
                    )
                ]
                if since_ms <= REPLY_MS
                else []
            )

        async def get_delivery_receipt(self, provider_message_id):
            return None

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
