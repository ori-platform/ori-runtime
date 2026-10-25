# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""An authenticated input binds exactly what was received.

Nothing on the inbound-authentication path strips, case-maps or coerces a
value before it is verified or compared: one tag, token or reply binds one
input. Driven through the real verifier, webhook server, signature verifier
and approval classifier.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ori.network.sms_webhook import SMSWebhookServer
from ori.reasoning.action_dispatcher import _classify_approval_response
from ori.security.remote_commands.commands import (
    RemoteCommand,
    normalize_remote_command_sender,
    sign_remote_command,
)
from ori.security.remote_commands.policy import (
    STATUS_EXECUTED,
    STATUS_UNSUPPORTED,
    classify_remote_command,
)
from ori.security.webhook_signatures import (
    WebhookSignatureConfig,
    WebhookSignatureVerifier,
    sign_webhook_body,
)
from ori.state.store import StateStore
from tests.remote_commands.test_commands import _payload, _verifier

SECRET = "shared-secret"


@pytest.fixture
async def store(tmp_path: Any) -> Any:
    s = StateStore(db_path=str(tmp_path / "commands.db"))
    await s.open()
    yield s
    await s.close()


@pytest.fixture
def fixed_now(monkeypatch: pytest.MonkeyPatch) -> int:
    now = 1_780_000_000_000
    monkeypatch.setattr("ori.security.remote_commands.commands.now_ms", lambda: now)
    monkeypatch.setattr("ori.security.remote_commands.throttle.now_ms", lambda: now)
    return now


def _signed_as(fields: dict[str, Any], wire: dict[str, Any]) -> dict[str, Any]:
    """*wire* carrying the tag computed over *fields*."""
    return {**wire, "signature": sign_remote_command(fields, SECRET)}


# --- Remote commands ---------------------------------------------------------


async def test_the_issue_reproduction_is_refused(store, fixed_now) -> None:
    fields = {**_payload(now=fixed_now), "command_id": "c1", "command": "SET_THRESHOLD"}
    wire = {**fields, "command_id": "\x85c1"}
    result = await _verifier().verify(_signed_as(fields, wire), state_store=store)
    assert (result.accepted, result.reason) == (False, "invalid_command_id")

    wire = {**fields, "device_id": " dev-01\xa0"}
    result = await _verifier().verify(_signed_as(fields, wire), state_store=store)
    assert (result.accepted, result.reason) == (False, "device_mismatch")

    wire = {**fields, "command": "ſet_threshold\n"}
    result = await _verifier().verify(_signed_as(fields, wire), state_store=store)
    assert (result.accepted, result.reason) == (False, "invalid_command")


async def test_the_exact_payload_still_verifies(store, fixed_now) -> None:
    fields = {**_payload(now=fixed_now), "command": "SET_THRESHOLD"}
    result = await _verifier().verify(_signed_as(fields, fields), state_store=store)
    assert (result.accepted, result.reason) == (True, "accepted")


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("command_id", 123, "invalid_command_id"),
        ("command_id", " cmd-1", "invalid_command_id"),
        ("command_id", "x" * 129, "invalid_command_id"),
        ("device_id", 1, "invalid_device_id"),
        ("command", "update_config", "invalid_command"),
        ("command", "UPDATE_CONFIG ", "invalid_command"),
        ("command", ["UPDATE_CONFIG"], "invalid_command"),
        ("issued_at_ms", "1800000000000", "invalid_timestamp"),
        ("issued_at_ms", 1.8e12, "invalid_timestamp"),
        ("issued_at_ms", True, "invalid_timestamp"),
        ("args", None, "invalid_args"),
        ("args", [], "invalid_args"),
    ],
    ids=lambda v: repr(v)[:24],
)
async def test_a_value_outside_its_grammar_is_refused_never_coerced(
    store, fixed_now, field: str, value: Any, reason: str
) -> None:
    payload = {**_payload(now=fixed_now), field: value}
    # Signed over the coerced reading the runtime used to verify against.
    coerced = {
        **payload,
        field: str(value).strip().upper() if field == "command" else value,
    }
    result = await _verifier().verify(_signed_as(coerced, payload), state_store=store)
    assert (result.accepted, result.reason) == (False, reason)


def test_classification_is_exact() -> None:
    def command(name: str) -> RemoteCommand:
        return RemoteCommand(
            command_id="c1",
            channel="sms",
            device_id="dev-01",
            issued_at_ms=0,
            command=name,
            args={},
        )

    assert classify_remote_command(command("SET_THRESHOLD")) == STATUS_EXECUTED
    assert classify_remote_command(command("set_threshold")) == STATUS_UNSUPPORTED
    assert classify_remote_command(command("SET_THRESHOLD ")) == STATUS_UNSUPPORTED


@pytest.mark.parametrize(
    ("channel", "sender", "expected"),
    [
        ("sms", "+234 801 234 5678", "+2348012345678"),
        ("sms", "+234801234567٨", ""),
        ("sms", "+234801234567³", ""),
        ("whatsapp", "WhatsApp:+2348012345678", "whatsapp:+2348012345678"),
        ("whatsapp", "whatsapp:+2348012345678K", ""),
    ],
)
def test_a_sender_identity_folds_ascii_only(
    channel: str, sender: str, expected: str
) -> None:
    assert normalize_remote_command_sender(channel, sender) == expected


async def test_a_non_ascii_sender_is_not_allowed(store, fixed_now) -> None:
    fields = {**_payload(now=fixed_now), "from_number": "+234801234567٨"}
    result = await _verifier().verify(_signed_as(fields, fields), state_store=store)
    assert (result.accepted, result.reason) == (False, "sender_not_allowed")


# --- The SMS webhook ---------------------------------------------------------


class _Writer:
    def __init__(self) -> None:
        self.buffer = bytearray()

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    def get_extra_info(self, name: str) -> Any:
        return ("127.0.0.1", 12345) if name == "peername" else None

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


async def _serve(server: SMSWebhookServer, raw: bytes) -> str:
    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()
    writer = _Writer()
    await server._handle_client(reader, writer)  # type: ignore[arg-type]
    return writer.buffer.split(b"\r\n", 1)[0].decode("ascii")


def _request(*headers: bytes, body: bytes = b"from=%2B2348000000000&text=YES") -> bytes:
    head = [b"POST /webhooks/sms/africastalking HTTP/1.1", *headers]
    if not any(h.lower().startswith(b"content-length:") for h in headers):
        head.append(b"Content-Length: " + str(len(body)).encode())
    return b"\r\n".join(head) + b"\r\n\r\n" + body


def _server() -> tuple[SMSWebhookServer, AsyncMock]:
    action = AsyncMock()
    action.ingest_incoming_webhook.return_value = True
    return SMSWebhookServer(sms_action=action, token="secret-token"), action


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ((b"X-Ori-Webhook-Token: secret-token",), "HTTP/1.1 200 OK"),
        ((b"Authorization: Bearer secret-token",), "HTTP/1.1 200 OK"),
        ((b"X-Ori-Webhook-Token: secret-token\xc2\xa0",), "HTTP/1.1 401 Unauthorized"),
        ((b"X-Ori-Webhook-Token: secret-tok\xff",), "HTTP/1.1 400 Bad Request"),
        (
            (b"X-Ori-Webhook-Token: wrong", b"X-Ori-Webhook-Token: secret-token"),
            "HTTP/1.1 400 Bad Request",
        ),
        (
            (b"X-Ori-Webhook-To\xe2\x84\xaaen: secret-token",),
            "HTTP/1.1 400 Bad Request",
        ),
        (
            (b"X-Ori-Webhook-Token: secret-token", b"Content-Length: \xd9\xa3"),
            "HTTP/1.1 400 Bad Request",
        ),
        (
            (b"X-Ori-Webhook-Token: secret-token", b"Content-Length: 3_0"),
            "HTTP/1.1 400 Bad Request",
        ),
    ],
    ids=[
        "token",
        "bearer",
        "token with nbsp",
        "header not utf-8",
        "repeated token",
        "kelvin-sign header name",
        "arabic-digit length",
        "underscore length",
    ],
)
async def test_the_webhook_takes_headers_exactly(
    headers: tuple[bytes, ...], status: str
) -> None:
    server, action = _server()
    assert await _serve(server, _request(*headers)) == status
    if not status.endswith("200 OK"):
        action.ingest_incoming_webhook.assert_not_called()


async def test_the_method_is_case_sensitive() -> None:
    server, action = _server()
    raw = _request(b"X-Ori-Webhook-Token: secret-token").replace(
        b"POST", "poſt".encode(), 1
    )
    assert await _serve(server, raw) == "HTTP/1.1 405 Method Not Allowed"
    action.ingest_incoming_webhook.assert_not_called()


# --- The webhook signature ---------------------------------------------------


def _signature_verifier() -> WebhookSignatureVerifier:
    return WebhookSignatureVerifier(
        WebhookSignatureConfig(mode="hmac_required", shared_secret="hmac-secret")
    )


async def _verify(signature: str, timestamp: str, nonce: str, now: int) -> str:
    result = await _signature_verifier().verify(
        headers={
            "x-ori-webhook-signature": signature,
            "x-ori-webhook-timestamp": timestamp,
            "x-ori-webhook-nonce": nonce,
        },
        body=b"body",
        now_ms_value=now,
    )
    return result.reason


async def test_the_signature_binds_the_timestamp_and_nonce_as_sent() -> None:
    now = 1_800_000_000_000
    tag = sign_webhook_body(
        b"body", shared_secret="hmac-secret", signed_at_ms=now, nonce="n1"
    )
    assert await _verify(tag, str(now), "n1", now) == "accepted"
    assert await _verify(tag, "0" + str(now), "n1", now) == "invalid_signature"
    assert await _verify(tag, "+" + str(now), "n1", now) == "invalid_timestamp"
    assert (
        await _verify(tag, str(now).replace("1", "١", 1), "n1", now)
        == "invalid_timestamp"
    )
    assert await _verify(tag, str(now), "n1\xa0", now) == "invalid_nonce"
    assert await _verify(tag, str(now), " n1", now) == "invalid_nonce"
    assert await _verify(tag + "é", str(now), "n1", now) == "invalid_signature"


# --- Tier C approval replies -------------------------------------------------


@pytest.mark.parametrize(
    ("reply", "kind"),
    [
        ("YES-AB12", "approve"),
        ("yes-ab12", "approve"),
        ("oK-AB12", "invalid"),
        ("YES-ﬀ", "invalid"),
        ("YEſ-AB12", "invalid"),
        (" YES-AB12", "invalid"),
    ],
    ids=["exact", "ascii case", "kelvin ok", "ligature id", "long s", "line separator"],
)
def test_an_approval_reply_folds_ascii_only(reply: str, kind: str) -> None:
    assert (
        _classify_approval_response(reply, proposal_id="AB12", require_scoped=True)
        == kind
    )


async def test_a_refused_timestamp_is_audited_as_received_not_coerced(
    store: Any, fixed_now: int
) -> None:
    payload = {
        **_payload(now=fixed_now, command_id="cmd-text-ts"),
        "issued_at_ms": str(fixed_now),
    }
    result = await _verifier().verify(payload, state_store=store)
    assert result.reason == "invalid_timestamp"
    (row,) = [
        r
        for r in await store.get_remote_command_log(limit=500)
        if r["command_id"] == "cmd-text-ts"
    ]
    assert row["issued_at_ms"] is None


# --- Configured senders ------------------------------------------------------


def test_a_configured_contact_drops_whitespace_but_not_look_alike_digits() -> None:
    from types import SimpleNamespace

    from ori.config._actions import parse_actions
    from ori.config._fields import ConfigValidationError
    from ori.runtime._remote_command_wiring import build_sms_allowed_senders

    actions = parse_actions({"operator_contact": "+234\xa08000000001"})
    config: Any = SimpleNamespace(actions=actions)
    assert build_sms_allowed_senders(config) == {"+2348000000001"}
    with pytest.raises(ConfigValidationError, match="operator_contact"):
        parse_actions({"operator_contact": "+٢٣٤8000000001"})
    with pytest.raises(ConfigValidationError, match="secondary_contact"):
        parse_actions({"secondary_contact": "+234800000000١"})


def test_a_configured_allowlist_refuses_look_alike_digits() -> None:
    from ori.config._fields import ConfigValidationError
    from ori.config._security import _parse_remote_command_allowed_senders

    parsed = _parse_remote_command_allowed_senders({"sms": ["+234 800\xa00001"]})
    assert parsed["sms"] == ["+2348000001"]
    with pytest.raises(ConfigValidationError, match="non-ASCII"):
        _parse_remote_command_allowed_senders({"sms": ["+٢٣٤800"]})


def test_the_gsm_recipient_reads_a_configured_number() -> None:
    from ori.security.remote_commands.commands import normalize_configured_sender

    assert normalize_configured_sender("sms", "+234\xa08000000001") == "+2348000000001"
    assert normalize_configured_sender("sms", "+٢٣٤800") == ""


async def test_a_reply_binding_never_matches_two_empty_identities() -> None:
    from ori.actions.alert_delivery import InboundWhatsAppMessage, WhatsAppSessionReply
    from ori.actions.whatsapp import WhatsAppAction
    from ori.utils.time_utils import now_ms
    from tests.test_whatsapp import _TEMPLATES, _OKProvider

    provider = _OKProvider()
    action = WhatsAppAction(provider=provider, templates=_TEMPLATES)
    inbound = InboundWhatsAppMessage(
        provider_message_id="SM1",
        from_number="whatsapp:+٢٣٤111",
        body="hi",
        received_at_ms=now_ms(),
    )
    sent = await action.send_reply(
        WhatsAppSessionReply(body="x", in_reply_to=inbound), "whatsapp:+٢٣٤999"
    )
    assert sent is False
    assert provider.session_replies == []


async def test_a_boolean_timestamp_is_refused_and_audited_as_null(
    store: Any, fixed_now: int
) -> None:
    payload = {
        **_payload(now=fixed_now, command_id="cmd-bool-ts"),
        "issued_at_ms": True,
    }
    result = await _verifier().verify(payload, state_store=store)
    assert result.reason == "invalid_timestamp"
    (row,) = [
        r
        for r in await store.get_remote_command_log(limit=500)
        if r["command_id"] == "cmd-bool-ts"
    ]
    assert row["issued_at_ms"] is None


def test_the_dispatcher_audits_a_local_console_timestamp_exactly() -> None:
    from ori.reasoning.action_dispatcher import _safe_int_or_none

    assert _safe_int_or_none(1700) == 1700
    assert [_safe_int_or_none(v) for v in ("1700", True, 1.9, 2**63)] == [None] * 4


def test_the_command_prefix_folds_ascii_only() -> None:
    from ori.security.remote_commands.commands import extract_remote_command_payload

    body = '{"command_id":"c","device_id":"d","issued_at_ms":1,"command":"X","args":{}}'
    assert extract_remote_command_payload(
        {"text": "ori_command " + body}, channel="sms"
    )
    assert (
        extract_remote_command_payload({"text": "orı_command " + body}, channel="sms")
        is None
    )


# --- More of the webhook -----------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        (
            (b"X-Ori-Webhook-Token: wrong", b"Authorization: Bearer secret-token"),
            "HTTP/1.1 200 OK",
        ),
        ((b"X-Ori-Webhook-Token : secret-token",), "HTTP/1.1 400 Bad Request"),
        (
            (b"X-Ori-Webhook-Token: secret-token", b" folded"),
            "HTTP/1.1 400 Bad Request",
        ),
        (
            (b"X-Ori-Webhook-Token: secret-token", b"Transfer-Encoding: chunked"),
            "HTTP/1.1 400 Bad Request",
        ),
        (
            (b"X-Ori-Webhook-Token: secret-token", b"Content-Length: 4"),
            "HTTP/1.1 400 Bad Request",
        ),
    ],
    ids=[
        "bearer after a wrong token",
        "space before colon",
        "folded line",
        "chunked",
        "bytes past length",
    ],
)
async def test_the_webhook_frames_a_request_strictly(
    headers: tuple[bytes, ...], status: str
) -> None:
    server, _ = _server()
    assert await _serve(server, _request(*headers)) == status


@pytest.mark.parametrize(
    "name",
    [b"X-Ori-Webhook-Signature", b"X-Ori-Webhook-Timestamp", b"X-Ori-Webhook-Nonce"],
)
async def test_a_repeated_signature_header_is_refused(name: bytes) -> None:
    action = AsyncMock()
    server = SMSWebhookServer(
        sms_action=action,
        token="secret-token",
        signature_verifier=_signature_verifier(),
    )
    raw = _request(b"X-Ori-Webhook-Token: secret-token", name + b": a", name + b": b")
    assert await _serve(server, raw) == "HTTP/1.1 400 Bad Request"
    action.ingest_incoming_webhook.assert_not_called()


async def test_the_signature_headers_are_bounded_in_length() -> None:
    now = 1_800_000_000_000
    tag = sign_webhook_body(
        b"body", shared_secret="hmac-secret", signed_at_ms=now, nonce="n"
    )
    assert await _verify(tag, "1" * 17, "n", now) == "invalid_timestamp"
    assert await _verify(tag, str(now), "n" * 129, now) == "invalid_nonce"


@pytest.mark.parametrize(
    ("reply", "kind"),
    [("YES-AB12 👍", "approve"), ("Yes-AB12 ", "approve"), ("no-ab-12", "reject")],
)
def test_text_after_an_ascii_reply_is_ignored(reply: str, kind: str) -> None:
    assert (
        _classify_approval_response(reply, proposal_id="AB12", require_scoped=True)
        == kind
    )


def test_a_ligature_never_folds_into_the_proposal_id() -> None:
    # `ﬀ` upper-cases to FF, so folding before selecting would match FF12.
    assert (
        _classify_approval_response("YES-ﬀ12", proposal_id="FF12", require_scoped=True)
        == "invalid"
    )
    assert (
        _classify_approval_response("YES-FF12", proposal_id="FF12", require_scoped=True)
        == "approve"
    )


async def test_listening_for_a_configured_operator_reads_the_configured_rule() -> None:
    from ori.actions.sms import SMSAction

    asked: list[str] = []

    class _Store:
        async def consume_incoming_message(self, **kwargs: Any) -> str:
            asked.append(kwargs["from_number"])
            return "YES-AB12"

    action = SMSAction(state_store=_Store())
    reply = await action.listen_for_response("+234\xa08000000001", timeout_seconds=1)
    assert (reply, asked) == ("YES-AB12", ["+2348000000001"])


def test_a_configured_gsm_recipient_reads_the_configured_rule(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging
    from types import SimpleNamespace

    from ori.actions.sms import SMSAction

    opened: list[str] = []

    def _serial(**kwargs: Any) -> Any:
        opened.append(kwargs.get("port", ""))
        raise OSError("no modem")

    monkeypatch.setattr("ori.actions.sms._PYSERIAL_AVAILABLE", True)
    monkeypatch.setattr(
        "ori.actions.sms._serial_module", SimpleNamespace(Serial=_serial)
    )
    action = SMSAction()
    with caplog.at_level(logging.WARNING):
        action._send_gsm_sync("hi", "+234\xa08000000001")
    assert "invalid recipient" not in caplog.text
    assert opened, (
        "a configured number with a non-breaking space never reached the modem"
    )


@pytest.mark.parametrize("reply", ["OK", "oK", "Yİ"])
def test_an_unscoped_look_alike_reply_is_invalid(reply: str) -> None:
    assert _classify_approval_response(reply) == "invalid"
    assert _classify_approval_response("ok") == "approve"


async def test_a_reply_binds_a_configured_contact_written_with_spaces() -> None:
    from ori.actions.alert_delivery import InboundWhatsAppMessage, WhatsAppSessionReply
    from ori.actions.whatsapp import WhatsAppAction
    from ori.utils.time_utils import now_ms
    from tests.test_whatsapp import _TEMPLATES, _OKProvider

    provider = _OKProvider()
    action = WhatsAppAction(provider=provider, templates=_TEMPLATES)
    inbound = InboundWhatsAppMessage(
        provider_message_id="SM1",
        from_number="whatsapp:+2348000000001",
        body="hi",
        received_at_ms=now_ms(),
    )
    sent = await action.send_reply(
        WhatsAppSessionReply(body="x", in_reply_to=inbound),
        "whatsapp:+234\xa08000000001",
    )
    assert sent is True


@pytest.mark.parametrize(
    ("reply", "scoped", "kind"),
    [
        ("Y\x0c", False, "approve"),
        ("\x1fY", False, "approve"),
        ("YES\n-AB12", True, "approve"),
        ("N\r-ab12", True, "reject"),
    ],
)
def test_every_ascii_space_main_trimmed_is_still_trimmed(
    reply: str, scoped: bool, kind: str
) -> None:
    assert (
        _classify_approval_response(reply, proposal_id="AB12", require_scoped=scoped)
        == kind
    )


# --- From ingress to the decision -------------------------------------------


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("\xa0YES-AB12", "invalid"),
        ("　YES-AB12", "invalid"),
        ("YES-AB12 ", "approve"),
        (" YES-AB12\n", "approve"),
    ],
    ids=["leading nbsp", "ideographic space", "trailing separator", "ascii spaces"],
)
async def test_an_sms_reply_reaches_the_decision_as_it_was_received(
    store: Any, text: str, kind: str
) -> None:
    """Ingress keeps the reply's non-ASCII characters, so the classifier judges
    what the operator's handset sent, not a cleaned-up copy."""
    from ori.actions.sms import SMSAction

    operator = "+2348000000001"
    action = SMSAction(state_store=store, allowed_senders={operator})
    assert await action.ingest_incoming_webhook({"from": operator, "text": text})
    # Read as the listener reads it; from the start of time, since a listener
    # only sees replies that arrive after it starts.
    reply = await store.consume_incoming_message(
        channel="sms", from_number=operator, since_ms=0
    )
    assert reply is not None
    assert (
        _classify_approval_response(reply, proposal_id="AB12", require_scoped=True)
        == kind
    )


async def test_a_configured_contact_reaches_the_provider_without_its_spaces() -> None:
    from ori.actions.alert_delivery import InboundWhatsAppMessage, WhatsAppSessionReply
    from ori.actions.whatsapp import WhatsAppAction
    from ori.config._actions import parse_actions
    from ori.utils.time_utils import now_ms
    from tests.test_whatsapp import _TEMPLATES, _OKProvider

    contact = parse_actions(
        {"operator_contact": "\xa0whatsapp:+234 111"}
    ).operator_contact
    assert contact == "whatsapp:+234111"

    polled: list[str] = []
    answer = InboundWhatsAppMessage(
        provider_message_id="SM0",
        from_number="whatsapp:+234111",
        body="YES-AB12",
        received_at_ms=now_ms(),
    )

    class _Provider(_OKProvider):
        async def get_incoming(self, from_number: str, since_ms: int) -> list[Any]:
            polled.append(from_number)
            return [answer]

    provider = _Provider()
    action = WhatsAppAction(provider=provider, templates=_TEMPLATES)
    reply = await action.listen_for_response(contact, timeout_seconds=5)
    assert reply == "YES-AB12"
    assert polled == ["whatsapp:+234111"]
    inbound = InboundWhatsAppMessage(
        provider_message_id="SM1",
        from_number="whatsapp:+234111",
        body="hi",
        received_at_ms=now_ms(),
    )
    assert await action.send_reply(
        WhatsAppSessionReply(body="x", in_reply_to=inbound), contact
    )
    assert provider.session_replies == [("whatsapp:+234111", "x")]


def test_a_command_is_extracted_from_the_text_as_sent() -> None:
    from ori.security.remote_commands.commands import extract_remote_command_payload

    body = '{"command_id":"c","device_id":"d","issued_at_ms":1,"command":"X","args":{}}'
    assert extract_remote_command_payload(
        {"text": " ORI_COMMAND " + body}, channel="sms"
    )
    assert (
        extract_remote_command_payload(
            {"text": "\xa0ORI_COMMAND " + body}, channel="sms"
        )
        is None
    )


async def test_a_recipient_retained_from_before_reaches_the_provider_whole(
    store: Any,
) -> None:
    """A row queued by an earlier release keeps the recipient as configured
    then; the transport boundary still sends the number without its spaces."""
    from ori.actions.alert_delivery import (
        AlertIntent,
        AlertSendReceipt,
        build_outbound_alert,
    )
    from ori.actions.alert_failover import AlertFailoverSender

    assert await store.enqueue_alert(
        alert_id="a1",
        channel="sms",
        recipient="+234\xa0111 222",
        message="hello",
        action_tier="A",
        trigger_name="t",
        original_ts=1,
    )
    (row,) = await store.get_retryable_alerts(10)
    sms = AsyncMock()
    sms.submit = AsyncMock(
        return_value=AlertSendReceipt.accepted_without_provider_receipt(channel="sms")
    )
    sender = AlertFailoverSender(
        primary_channel="sms", sms_sender=sms, whatsapp_sender=None
    )
    alert = build_outbound_alert(
        intent=AlertIntent.TIER_A_ALERT,
        sms_body="hello",
        template_variables=("risk", "Abuja", "Wednesday 23:00"),
    )
    await sender.send(alert, str(row["recipient"]), preferred_channel="sms")
    assert sms.submit.await_args.kwargs["to_number"] == "+234111222"
