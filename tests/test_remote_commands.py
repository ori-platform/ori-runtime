# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

from ori.actions.sms import SMSAction
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


async def test_accepts_valid_hmac_command(store, fixed_now):
    payload = _signed(_payload(now=fixed_now))

    result = await _verifier().verify(payload, state_store=store)

    assert result.accepted is True
    assert result.reason == "accepted"
    assert await store.has_remote_command("cmd-1") is True
    rows = await store.get_remote_command_log()
    assert rows[0]["command_id"] == "cmd-1"
    assert rows[0]["accepted"] is True


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
