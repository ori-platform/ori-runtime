# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json
from unittest.mock import AsyncMock

import pytest

from ori.actions.sms import SMSAction
from ori.actions.whatsapp import WhatsAppAction
from ori.security.remote_command_policy import (
    STATUS_AUDIT_ONLY,
    STATUS_EXECUTED,
    STATUS_PRECONDITION_FAILED,
    command_result,
)
from ori.security.remote_commands import (
    RemoteCommandVerifier,
    extract_remote_command_payload,
    sign_remote_command,
)
from ori.state.store import StateStore


@pytest.fixture
async def store(tmp_path):
    s = StateStore(db_path=str(tmp_path / "commands.db"))
    await s.open()
    yield s
    await s.close()


@pytest.fixture
def fixed_now(monkeypatch):
    now = 1_780_000_000_000
    monkeypatch.setattr("ori.security.remote_commands.now_ms", lambda: now)
    monkeypatch.setattr("ori.security.remote_command_throttle.now_ms", lambda: now)
    return now


def _payload(*, now: int, command_id: str = "cmd-1", args: dict | None = None):
    return {
        "command_id": command_id,
        "channel": "sms",
        "device_id": "dev-01",
        "issued_at_ms": now,
        "command": "UPDATE_CONFIG",
        "args": args if args is not None else {"threshold": 42, "sensor_id": "s1"},
    }


def _signed(payload: dict, secret: str = "shared-secret") -> dict:
    signed = dict(payload)
    signed["signature"] = sign_remote_command(payload, secret)
    return signed


def _verifier(secret: str = "shared-secret") -> RemoteCommandVerifier:
    return RemoteCommandVerifier(
        device_id="dev-01",
        shared_secret=secret,
        max_skew_ms=300_000,
    )


async def _seed_rejected_attempts(
    store: StateStore,
    *,
    channel: str,
    from_number: str,
    now: int,
    count: int = 5,
) -> None:
    for i in range(count):
        await store.log_remote_command_attempt(
            command_id=f"seed-reject-{channel}-{i}",
            channel=channel,
            from_number=from_number,
            command="UPDATE_CONFIG",
            accepted=False,
            reason="missing_signature",
            issued_at_ms=now - 1_000,
            received_at_ms=now - 1_000,
        )


class _InboxWhatsAppProvider:
    def __init__(self, inbox: list[str]) -> None:
        self.inbox = inbox
        self.sent: list[tuple[str, str]] = []

    async def send(self, to: str, message: str) -> bool:
        self.sent.append((to, message))
        return True

    async def get_incoming(self, from_number: str, since_ms: int) -> list[str]:
        messages, self.inbox = self.inbox[:], []
        return messages


class _RepeatingWhatsAppProvider:
    def __init__(self, repeated: str, final: str) -> None:
        self.repeated = repeated
        self.final = final
        self.calls = 0
        self.sent: list[tuple[str, str]] = []

    async def send(self, to: str, message: str) -> bool:
        self.sent.append((to, message))
        return True

    async def get_incoming(self, from_number: str, since_ms: int) -> list[str]:
        self.calls += 1
        if self.calls < 3:
            return [self.repeated]
        return [self.repeated, self.final]


async def test_accepts_valid_hmac_command(store, fixed_now):
    payload = _signed(_payload(now=fixed_now))
    payload["from_number"] = "+2348012345678"

    result = await _verifier().verify(payload, state_store=store)

    assert result.accepted is True
    assert result.reason == "accepted"
    assert result.command is not None
    assert result.command.from_number == "+2348012345678"
    assert await store.has_remote_command("cmd-1") is True
    rows = await store.get_remote_command_log()
    assert rows[0]["command_id"] == "cmd-1"
    assert rows[0]["accepted"] is True
    assert rows[0]["from_number"] == "+2348012345678"


async def test_rejects_missing_signature(store, fixed_now):
    result = await _verifier().verify(_payload(now=fixed_now), state_store=store)

    assert result.accepted is False
    assert result.reason == "missing_signature"
    rows = await store.get_remote_command_log()
    assert rows[0]["accepted"] is False
    assert rows[0]["reason"] == "missing_signature"


async def test_rejects_bad_signature(store, fixed_now):
    payload = _signed(_payload(now=fixed_now), secret="wrong-secret")

    result = await _verifier().verify(payload, state_store=store)

    assert result.accepted is False
    assert result.reason == "invalid_signature"


async def test_rejects_wrong_device_id(store, fixed_now):
    payload = _payload(now=fixed_now)
    payload["device_id"] = "other-device"
    payload = _signed(payload)

    result = await _verifier().verify(payload, state_store=store)

    assert result.accepted is False
    assert result.reason == "device_mismatch"


async def test_rejects_stale_timestamp(store, fixed_now):
    payload = _signed(_payload(now=fixed_now - 300_001))

    result = await _verifier().verify(payload, state_store=store)

    assert result.accepted is False
    assert result.reason == "stale_timestamp"


async def test_rejects_future_timestamp(store, fixed_now):
    payload = _signed(_payload(now=fixed_now + 300_001))

    result = await _verifier().verify(payload, state_store=store)

    assert result.accepted is False
    assert result.reason == "future_timestamp"


async def test_rejects_replayed_command_id(store, fixed_now):
    payload = _signed(_payload(now=fixed_now))

    first = await _verifier().verify(payload, state_store=store)
    second = await _verifier().verify(payload, state_store=store)

    assert first.accepted is True
    assert second.accepted is False
    assert second.reason == "replay_detected"


async def test_logs_rejected_command_attempt(store, fixed_now):
    payload = _payload(now=fixed_now)
    payload["args"] = []

    result = await _verifier().verify(payload, state_store=store)

    assert result.accepted is False
    rows = await store.get_remote_command_log()
    assert rows[0]["reason"] == "invalid_args"


async def test_rejects_disable_tier_d_command(store, fixed_now):
    payload = _payload(now=fixed_now)
    payload["command"] = "DISABLE_TIER_D"
    payload = _signed(payload)

    result = await _verifier().verify(payload, state_store=store)

    assert result.accepted is False
    assert result.reason == "forbidden_command"


async def test_rejects_nested_tier_d_disable_arg(store, fixed_now):
    payload = _payload(
        now=fixed_now,
        args={"skills": [{"trigger": {"action_tier": "D", "enabled": False}}]},
    )
    payload = _signed(payload)

    result = await _verifier().verify(payload, state_store=store)

    assert result.accepted is False
    assert result.reason == "forbidden_safety_mutation"


async def test_rejects_force_actuator_command(store, fixed_now):
    payload = _payload(now=fixed_now)
    payload["command"] = "FORCE_ACTUATOR"
    payload = _signed(payload)

    result = await _verifier().verify(payload, state_store=store)

    assert result.accepted is False
    assert result.reason == "forbidden_command"


def test_canonical_json_signature_is_order_independent(fixed_now):
    first = _payload(now=fixed_now, args={"b": 2, "a": 1})
    second = _payload(now=fixed_now, args={"a": 1, "b": 2})

    assert sign_remote_command(first, "shared-secret") == sign_remote_command(
        second, "shared-secret"
    )


def test_extract_remote_command_ignores_plain_approval_reply():
    payload = {"from": "+2348012345678", "text": "YES"}

    result = extract_remote_command_payload(
        payload, channel="sms", from_number="+2348012345678"
    )

    assert result is None


def test_extract_remote_command_uses_ingress_channel_not_payload_channel(fixed_now):
    command = _payload(now=fixed_now)
    command["channel"] = "sms"
    payload = {"from": "whatsapp:+2348012345678", "text": json.dumps(command)}

    result = extract_remote_command_payload(
        payload,
        channel="whatsapp",
        from_number="whatsapp:+2348012345678",
    )

    assert result is not None
    assert result["channel"] == "whatsapp"
    assert result["from_number"] == "whatsapp:+2348012345678"


async def test_sms_command_handler_rejects_unsigned_config_change(store, fixed_now):
    action = SMSAction(
        state_store=store,
        config={},
        remote_command_verifier=_verifier(),
    )
    command = _payload(now=fixed_now)
    payload = {"from": "+2348012345678", "text": f"ORI_COMMAND {json.dumps(command)}"}

    ok = await action.ingest_incoming_webhook(payload)

    assert ok is False
    rows = await store.get_remote_command_log()
    assert rows[0]["reason"] == "missing_signature"
    assert await store.consume_incoming_message("sms", "+2348012345678", 0) is None


async def test_sms_command_handler_audits_when_verifier_disabled(store, fixed_now):
    action = SMSAction(state_store=store, config={})
    command = _payload(now=fixed_now)
    payload = {"from": "+2348012345678", "text": f"ORI_COMMAND {json.dumps(command)}"}

    ok = await action.ingest_incoming_webhook(payload)

    assert ok is False
    rows = await store.get_remote_command_log()
    assert rows[0]["command_id"] == "cmd-1"
    assert rows[0]["reason"] == "remote_command_verifier_disabled"


async def test_sms_approval_yes_no_is_not_treated_as_remote_command(store):
    action = SMSAction(state_store=store, config={})

    ok = await action.ingest_incoming_webhook({"from": "+2348012345678", "text": "YES"})

    assert ok is True
    assert await store.consume_incoming_message("sms", "+2348012345678", 0) == "YES"
    assert await store.get_remote_command_log() == []


async def test_sms_handler_accepts_signed_command_without_storing_approval(
    store, fixed_now
):
    action = SMSAction(
        state_store=store,
        config={},
        remote_command_verifier=_verifier(),
    )
    command = _signed(_payload(now=fixed_now))
    payload = {"from": "+2348012345678", "text": json.dumps(command)}

    ok = await action.ingest_incoming_webhook(payload)

    assert ok is True
    rows = await store.get_remote_command_log()
    assert rows[0]["accepted"] is True
    assert await store.consume_incoming_message("sms", "+2348012345678", 0) is None


async def test_sms_handler_invokes_runtime_command_handler(store, fixed_now):
    handler = AsyncMock()
    action = SMSAction(
        state_store=store,
        config={},
        remote_command_verifier=_verifier(),
        remote_command_handler=handler,
    )
    command = _signed(_payload(now=fixed_now, command_id="sms-handler"))
    payload = {"from": "+2348012345678", "text": json.dumps(command)}

    ok = await action.ingest_incoming_webhook(payload)

    assert ok is True
    handler.assert_awaited_once()
    handled = handler.await_args.args[0]
    assert handled.command_id == "sms-handler"
    assert handled.command == "UPDATE_CONFIG"


async def test_sms_handler_sends_execution_feedback(store, fixed_now):
    async def handler(command):
        return command_result(
            command,
            status=STATUS_EXECUTED,
            detail="threshold updated",
            executed=True,
        )

    action = SMSAction(
        state_store=store,
        config={},
        remote_command_verifier=_verifier(),
        remote_command_handler=handler,
    )
    action.send = AsyncMock(return_value=True)  # type: ignore[method-assign]
    command = _signed(_payload(now=fixed_now, command_id="sms-exec"))

    ok = await action.ingest_incoming_webhook(
        {"from": "+2348012345678", "text": json.dumps(command)}
    )

    assert ok is True
    action.send.assert_awaited_once()
    message, to_number = action.send.await_args.args
    assert to_number == "+2348012345678"
    assert "executed" in message
    assert "sms-exec" in message


async def test_sms_handler_sends_precondition_feedback(store, fixed_now):
    async def handler(command):
        return command_result(
            command,
            status=STATUS_PRECONDITION_FAILED,
            detail="skill 'missing' is not loaded",
            executed=False,
        )

    action = SMSAction(
        state_store=store,
        config={},
        remote_command_verifier=_verifier(),
        remote_command_handler=handler,
    )
    action.send = AsyncMock(return_value=True)  # type: ignore[method-assign]
    command = _signed(_payload(now=fixed_now, command_id="sms-precondition"))

    ok = await action.ingest_incoming_webhook(
        {"from": "+2348012345678", "text": json.dumps(command)}
    )

    assert ok is True
    message, _to_number = action.send.await_args.args
    assert "precondition failed" in message
    assert "sms-precondition" in message


async def test_sms_handler_sends_audit_only_feedback(store, fixed_now):
    async def handler(command):
        return command_result(
            command,
            status=STATUS_AUDIT_ONLY,
            detail="handler is not enabled",
            executed=False,
        )

    action = SMSAction(
        state_store=store,
        config={},
        remote_command_verifier=_verifier(),
        remote_command_handler=handler,
    )
    action.send = AsyncMock(return_value=True)  # type: ignore[method-assign]
    command = _signed(_payload(now=fixed_now, command_id="sms-audit"))

    ok = await action.ingest_incoming_webhook(
        {"from": "+2348012345678", "text": json.dumps(command)}
    )

    assert ok is True
    message, _to_number = action.send.await_args.args
    assert "audit-only" in message


async def test_sms_handler_sends_generic_rejection_feedback(store, fixed_now):
    action = SMSAction(
        state_store=store,
        config={},
        remote_command_verifier=_verifier(),
    )
    action.send = AsyncMock(return_value=True)  # type: ignore[method-assign]
    command = _payload(now=fixed_now, command_id="sms-unsigned")

    ok = await action.ingest_incoming_webhook(
        {"from": "+2348012345678", "text": json.dumps(command)}
    )

    assert ok is False
    action.send.assert_awaited_once()
    message, to_number = action.send.await_args.args
    assert to_number == "+2348012345678"
    assert "rejected" in message
    assert "missing_signature" not in message


async def test_sms_rejection_feedback_is_throttled_after_repeated_failures(
    store, fixed_now
):
    from_number = "+2348012345678"
    incident_handler = AsyncMock()
    await _seed_rejected_attempts(
        store,
        channel="sms",
        from_number=from_number,
        now=fixed_now,
    )
    action = SMSAction(
        state_store=store,
        config={},
        remote_command_verifier=_verifier(),
        remote_command_incident_handler=incident_handler,
    )
    action.send = AsyncMock(return_value=True)  # type: ignore[method-assign]
    command = _payload(now=fixed_now, command_id="sms-throttled")

    ok = await action.ingest_incoming_webhook(
        {"from": from_number, "text": json.dumps(command)}
    )

    assert ok is False
    action.send.assert_not_awaited()
    incident_handler.assert_awaited_once()
    decision = incident_handler.await_args.args[0]
    assert decision.channel == "sms"
    assert decision.from_number == from_number
    assert decision.rejection_count == 6
    rows = await store.get_remote_command_log()
    assert rows[0]["command_id"] == "sms-throttled"
    assert rows[0]["from_number"] == from_number
    assert rows[0]["accepted"] is False
    assert (
        await store.count_recent_remote_command_rejections(
            channel="sms",
            from_number=from_number,
            since_ms=fixed_now - 600_000,
        )
        == 6
    )
    incidents = await store.get_remote_command_security_incidents()
    assert len(incidents) == 1
    assert incidents[0]["channel"] == "sms"
    assert incidents[0]["from_number"] == from_number
    assert incidents[0]["rejection_count"] == 6
    assert incidents[0]["threshold"] == 5
    assert incidents[0]["window_ms"] == 600_000


async def test_sms_rejection_incident_is_deduped_within_window(store, fixed_now):
    from_number = "+2348012345678"
    incident_handler = AsyncMock()
    await _seed_rejected_attempts(
        store,
        channel="sms",
        from_number=from_number,
        now=fixed_now,
    )
    action = SMSAction(
        state_store=store,
        config={},
        remote_command_verifier=_verifier(),
        remote_command_incident_handler=incident_handler,
    )
    action.send = AsyncMock(return_value=True)  # type: ignore[method-assign]

    for command_id in ("sms-throttled-1", "sms-throttled-2"):
        command = _payload(now=fixed_now, command_id=command_id)
        ok = await action.ingest_incoming_webhook(
            {"from": from_number, "text": json.dumps(command)}
        )
        assert ok is False

    action.send.assert_not_awaited()
    incident_handler.assert_awaited_once()
    incidents = await store.get_remote_command_security_incidents()
    assert len(incidents) == 1
    assert incidents[0]["rejection_count"] == 6


async def test_sms_rejection_feedback_still_sends_at_threshold_boundary(
    store, fixed_now
):
    from_number = "+2348012345678"
    await _seed_rejected_attempts(
        store,
        channel="sms",
        from_number=from_number,
        now=fixed_now,
        count=4,
    )
    action = SMSAction(
        state_store=store,
        config={},
        remote_command_verifier=_verifier(),
    )
    action.send = AsyncMock(return_value=True)  # type: ignore[method-assign]
    command = _payload(now=fixed_now, command_id="sms-threshold-boundary")

    ok = await action.ingest_incoming_webhook(
        {"from": from_number, "text": json.dumps(command)}
    )

    assert ok is False
    action.send.assert_awaited_once()
    assert await store.get_remote_command_security_incidents() == []
    message, to_number = action.send.await_args.args
    assert to_number == from_number
    assert "rejected" in message
    assert (
        await store.count_recent_remote_command_rejections(
            channel="sms",
            from_number=from_number,
            since_ms=fixed_now - 600_000,
        )
        == 5
    )


async def test_accepted_sms_command_feedback_is_not_rejection_throttled(
    store, fixed_now
):
    from_number = "+2348012345678"
    await _seed_rejected_attempts(
        store,
        channel="sms",
        from_number=from_number,
        now=fixed_now,
    )

    async def handler(command):
        return command_result(
            command,
            status=STATUS_EXECUTED,
            detail="policy refreshed",
            executed=True,
        )

    action = SMSAction(
        state_store=store,
        config={},
        remote_command_verifier=_verifier(),
        remote_command_handler=handler,
    )
    action.send = AsyncMock(return_value=True)  # type: ignore[method-assign]
    command = _signed(_payload(now=fixed_now, command_id="sms-accepted-throttle"))

    ok = await action.ingest_incoming_webhook(
        {"from": from_number, "text": json.dumps(command)}
    )

    assert ok is True
    action.send.assert_awaited_once()
    message, to_number = action.send.await_args.args
    assert to_number == from_number
    assert "executed" in message
    assert "sms-accepted-throttle" in message


async def test_sms_feedback_failure_does_not_affect_execution_log(store, fixed_now):
    async def handler(command):
        result = command_result(
            command,
            status=STATUS_EXECUTED,
            detail="threshold updated",
            executed=True,
        )
        await store.log_remote_command_execution(
            command_id=result.command_id,
            channel=result.channel,
            command=result.command,
            status=result.status,
            detail=result.detail,
            executed=result.executed,
            executed_at_ms=result.executed_at_ms,
        )
        return result

    action = SMSAction(
        state_store=store,
        config={},
        remote_command_verifier=_verifier(),
        remote_command_handler=handler,
    )
    action.send = AsyncMock(return_value=False)  # type: ignore[method-assign]
    command = _signed(_payload(now=fixed_now, command_id="sms-feedback-fails"))

    ok = await action.ingest_incoming_webhook(
        {"from": "+2348012345678", "text": json.dumps(command)}
    )

    assert ok is True
    action.send.assert_awaited_once()
    rows = await store.get_remote_command_execution_log()
    assert rows[0]["command_id"] == "sms-feedback-fails"
    assert rows[0]["status"] == STATUS_EXECUTED
    assert rows[0]["executed"] is True


async def test_whatsapp_approval_yes_no_is_not_treated_as_remote_command(store):
    provider = _InboxWhatsAppProvider(["YES"])
    action = WhatsAppAction(provider=provider, state_store=store)

    reply = await action.listen_for_response(
        from_number="whatsapp:+2348012345678",
        timeout_seconds=1,
    )

    assert reply == "YES"
    assert await store.get_remote_command_log() == []


async def test_whatsapp_rejects_unsigned_command_and_continues_to_approval(
    store, fixed_now
):
    command = _payload(now=fixed_now, command_id="wa-unsigned")
    provider = _InboxWhatsAppProvider([json.dumps(command), "YES"])
    action = WhatsAppAction(
        provider=provider,
        state_store=store,
        remote_command_verifier=_verifier(),
    )

    reply = await action.listen_for_response(
        from_number="whatsapp:+2348012345678",
        timeout_seconds=1,
    )

    assert reply == "YES"
    rows = await store.get_remote_command_log()
    assert rows[0]["command_id"] == "wa-unsigned"
    assert rows[0]["channel"] == "whatsapp"
    assert rows[0]["accepted"] is False
    assert rows[0]["reason"] == "missing_signature"


async def test_whatsapp_accepts_signed_command_without_returning_it_as_approval(
    store, fixed_now
):
    command = _signed(_payload(now=fixed_now, command_id="wa-signed"))
    provider = _InboxWhatsAppProvider([f"ORI_COMMAND {json.dumps(command)}", "NO"])
    action = WhatsAppAction(
        provider=provider,
        state_store=store,
        remote_command_verifier=_verifier(),
    )

    reply = await action.listen_for_response(
        from_number="whatsapp:+2348012345678",
        timeout_seconds=1,
    )

    assert reply == "NO"
    rows = await store.get_remote_command_log()
    assert rows[0]["command_id"] == "wa-signed"
    assert rows[0]["channel"] == "whatsapp"
    assert rows[0]["accepted"] is True


async def test_whatsapp_invokes_runtime_command_handler(store, fixed_now):
    handler = AsyncMock()
    command = _signed(_payload(now=fixed_now, command_id="wa-handler"))
    provider = _InboxWhatsAppProvider([json.dumps(command), "NO"])
    action = WhatsAppAction(
        provider=provider,
        state_store=store,
        remote_command_verifier=_verifier(),
        remote_command_handler=handler,
    )

    reply = await action.listen_for_response(
        from_number="whatsapp:+2348012345678",
        timeout_seconds=1,
    )

    assert reply == "NO"
    handler.assert_awaited_once()
    handled = handler.await_args.args[0]
    assert handled.command_id == "wa-handler"
    assert handled.channel == "whatsapp"


async def test_whatsapp_sends_execution_feedback(store, fixed_now):
    async def handler(command):
        return command_result(
            command,
            status=STATUS_EXECUTED,
            detail="threshold updated",
            executed=True,
        )

    command = _signed(_payload(now=fixed_now, command_id="wa-exec"))
    provider = _InboxWhatsAppProvider([json.dumps(command), "YES"])
    action = WhatsAppAction(
        provider=provider,
        state_store=store,
        remote_command_verifier=_verifier(),
        remote_command_handler=handler,
    )

    reply = await action.listen_for_response(
        from_number="whatsapp:+2348012345678",
        timeout_seconds=1,
    )

    assert reply == "YES"
    assert provider.sent
    to_number, message = provider.sent[0]
    assert to_number == "whatsapp:+2348012345678"
    assert "executed" in message
    assert "wa-exec" in message


async def test_whatsapp_sends_generic_rejection_feedback(store, fixed_now):
    command = _payload(now=fixed_now, command_id="wa-unsigned-feedback")
    provider = _InboxWhatsAppProvider([json.dumps(command), "YES"])
    action = WhatsAppAction(
        provider=provider,
        state_store=store,
        remote_command_verifier=_verifier(),
    )

    reply = await action.listen_for_response(
        from_number="whatsapp:+2348012345678",
        timeout_seconds=1,
    )

    assert reply == "YES"
    assert provider.sent
    _to_number, message = provider.sent[0]
    assert "rejected" in message
    assert "missing_signature" not in message


async def test_whatsapp_rejection_feedback_is_throttled_after_repeated_failures(
    store, fixed_now
):
    from_number = "whatsapp:+2348012345678"
    incident_handler = AsyncMock()
    await _seed_rejected_attempts(
        store,
        channel="whatsapp",
        from_number=from_number,
        now=fixed_now,
    )
    command = _payload(now=fixed_now, command_id="wa-throttled")
    provider = _InboxWhatsAppProvider([json.dumps(command), "YES"])
    action = WhatsAppAction(
        provider=provider,
        state_store=store,
        remote_command_verifier=_verifier(),
        remote_command_incident_handler=incident_handler,
    )

    reply = await action.listen_for_response(
        from_number=from_number,
        timeout_seconds=1,
    )

    assert reply == "YES"
    assert provider.sent == []
    incident_handler.assert_awaited_once()
    rows = await store.get_remote_command_log()
    assert rows[0]["command_id"] == "wa-throttled"
    assert rows[0]["channel"] == "whatsapp"
    assert rows[0]["from_number"] == from_number
    assert rows[0]["accepted"] is False
    incidents = await store.get_remote_command_security_incidents()
    assert len(incidents) == 1
    assert incidents[0]["channel"] == "whatsapp"
    assert incidents[0]["from_number"] == from_number


async def test_whatsapp_rejection_incident_is_deduped_within_window(store, fixed_now):
    from_number = "whatsapp:+2348012345678"
    incident_handler = AsyncMock()
    await _seed_rejected_attempts(
        store,
        channel="whatsapp",
        from_number=from_number,
        now=fixed_now,
    )
    provider = _InboxWhatsAppProvider(
        [
            json.dumps(_payload(now=fixed_now, command_id="wa-throttled-1")),
            json.dumps(_payload(now=fixed_now, command_id="wa-throttled-2")),
            "YES",
        ]
    )
    action = WhatsAppAction(
        provider=provider,
        state_store=store,
        remote_command_verifier=_verifier(),
        remote_command_incident_handler=incident_handler,
    )

    reply = await action.listen_for_response(
        from_number=from_number,
        timeout_seconds=1,
    )

    assert reply == "YES"
    assert provider.sent == []
    incident_handler.assert_awaited_once()
    incidents = await store.get_remote_command_security_incidents()
    assert len(incidents) == 1
    assert incidents[0]["channel"] == "whatsapp"
    assert incidents[0]["from_number"] == from_number
    assert incidents[0]["rejection_count"] == 6


async def test_accepted_whatsapp_command_feedback_is_not_rejection_throttled(
    store, fixed_now
):
    from_number = "whatsapp:+2348012345678"
    await _seed_rejected_attempts(
        store,
        channel="whatsapp",
        from_number=from_number,
        now=fixed_now,
    )

    async def handler(command):
        return command_result(
            command,
            status=STATUS_EXECUTED,
            detail="policy refreshed",
            executed=True,
        )

    command = _signed(_payload(now=fixed_now, command_id="wa-accepted-throttle"))
    provider = _InboxWhatsAppProvider([json.dumps(command), "YES"])
    action = WhatsAppAction(
        provider=provider,
        state_store=store,
        remote_command_verifier=_verifier(),
        remote_command_handler=handler,
    )

    reply = await action.listen_for_response(
        from_number=from_number,
        timeout_seconds=1,
    )

    assert reply == "YES"
    assert provider.sent
    to_number, message = provider.sent[0]
    assert to_number == from_number
    assert "executed" in message
    assert "wa-accepted-throttle" in message


async def test_whatsapp_audits_command_when_verifier_disabled(store, fixed_now):
    command = _payload(now=fixed_now, command_id="wa-disabled")
    provider = _InboxWhatsAppProvider([json.dumps(command), "YES"])
    action = WhatsAppAction(provider=provider, state_store=store)

    reply = await action.listen_for_response(
        from_number="whatsapp:+2348012345678",
        timeout_seconds=1,
    )

    assert reply == "YES"
    rows = await store.get_remote_command_log()
    assert rows[0]["command_id"] == "wa-disabled"
    assert rows[0]["channel"] == "whatsapp"
    assert rows[0]["accepted"] is False
    assert rows[0]["reason"] == "remote_command_verifier_disabled"


async def test_whatsapp_repeated_poll_result_is_audited_once(store, fixed_now):
    command = _signed(_payload(now=fixed_now, command_id="wa-repeat"))
    provider = _RepeatingWhatsAppProvider(json.dumps(command), "YES")
    action = WhatsAppAction(
        provider=provider,
        state_store=store,
        remote_command_verifier=_verifier(),
    )
    action._POLL_INTERVAL_SECONDS = 0

    reply = await action.listen_for_response(
        from_number="whatsapp:+2348012345678",
        timeout_seconds=1,
    )

    assert reply == "YES"
    rows = await store.get_remote_command_log()
    assert len([row for row in rows if row["command_id"] == "wa-repeat"]) == 1
    assert rows[0]["accepted"] is True
