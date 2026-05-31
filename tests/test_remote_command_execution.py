# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ori.network.events import ActionTier
from ori.policy.device_policy import DevicePolicy
from ori.policy.remote_fetch import FetchedRemotePolicy, RemotePolicyFetchError
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.runtime import OriRuntime
from ori.security.remote_command_policy import (
    STATUS_AUDIT_ONLY,
    STATUS_EXECUTED,
    STATUS_FAILED,
    STATUS_PRECONDITION_FAILED,
    STATUS_UNSUPPORTED,
    classify_remote_command,
)
from ori.security.remote_commands import RemoteCommand
from ori.state.store import StateStore


@pytest.fixture
async def store(tmp_path):
    s = StateStore(db_path=str(tmp_path / "commands.db"))
    await s.open()
    yield s
    await s.close()


def _command(
    command: str,
    command_id: str = "cmd-1",
    args: dict | None = None,
) -> RemoteCommand:
    return RemoteCommand(
        command_id=command_id,
        channel="sms",
        device_id="dev-01",
        issued_at_ms=1_780_000_000_000,
        command=command,
        args=args or {},
        signature="hmac-sha256:test",
    )


def test_policy_executes_only_refresh_policy():
    assert classify_remote_command(_command("REFRESH_POLICY")) == STATUS_EXECUTED
    assert classify_remote_command(_command("APPLY_POLICY")) == STATUS_EXECUTED
    assert classify_remote_command(_command("UPDATE_CONFIG")) == STATUS_AUDIT_ONLY
    assert classify_remote_command(_command("UPDATE_SKILL")) == STATUS_AUDIT_ONLY


async def test_audit_only_command_is_logged_without_execution(store):
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._config = SimpleNamespace(device_policy={"enabled": True})
    runtime._dispatcher = object()
    runtime._refresh_remote_device_policy_once = AsyncMock(return_value=True)  # type: ignore[method-assign]

    result = await runtime._handle_remote_command(_command("UPDATE_CONFIG"))

    assert result.status == STATUS_AUDIT_ONLY
    assert result.executed is False
    runtime._refresh_remote_device_policy_once.assert_not_awaited()
    rows = await store.get_remote_command_execution_log()
    assert rows[0]["command_id"] == "cmd-1"
    assert rows[0]["command"] == "UPDATE_CONFIG"
    assert rows[0]["status"] == STATUS_AUDIT_ONLY
    assert rows[0]["executed"] is False


async def test_refresh_policy_requires_enabled_device_policy(store):
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._config = SimpleNamespace(device_policy={"enabled": False})
    runtime._dispatcher = object()
    runtime._refresh_remote_device_policy_once = AsyncMock(return_value=True)  # type: ignore[method-assign]

    result = await runtime._handle_remote_command(_command("REFRESH_POLICY"))

    assert result.status == STATUS_PRECONDITION_FAILED
    assert result.executed is False
    runtime._refresh_remote_device_policy_once.assert_not_awaited()
    rows = await store.get_remote_command_execution_log()
    assert rows[0]["status"] == STATUS_PRECONDITION_FAILED


async def test_refresh_policy_executes_existing_verified_policy_path(store):
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._config = SimpleNamespace(device_policy={"enabled": True})
    runtime._dispatcher = object()
    runtime._refresh_remote_device_policy_once = AsyncMock(return_value=True)  # type: ignore[method-assign]

    result = await runtime._handle_remote_command(_command("REFRESH_POLICY"))

    assert result.status == STATUS_EXECUTED
    assert result.executed is True
    runtime._refresh_remote_device_policy_once.assert_awaited_once()
    rows = await store.get_remote_command_execution_log()
    assert rows[0]["command"] == "REFRESH_POLICY"
    assert rows[0]["status"] == STATUS_EXECUTED
    assert rows[0]["executed"] is True


async def test_unsupported_command_is_logged_without_execution(store):
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._config = SimpleNamespace(device_policy={"enabled": True})
    runtime._dispatcher = object()
    runtime._refresh_remote_device_policy_once = AsyncMock(return_value=True)  # type: ignore[method-assign]

    result = await runtime._handle_remote_command(_command("UNKNOWN_COMMAND"))

    assert result.status == STATUS_UNSUPPORTED
    assert result.executed is False
    runtime._refresh_remote_device_policy_once.assert_not_awaited()
    rows = await store.get_remote_command_execution_log()
    assert rows[0]["command"] == "UNKNOWN_COMMAND"
    assert rows[0]["status"] == STATUS_UNSUPPORTED
    assert rows[0]["executed"] is False


async def test_executable_policy_without_handler_is_logged_as_mismatch(
    store, monkeypatch
):
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._config = SimpleNamespace(device_policy={"enabled": True})
    runtime._dispatcher = object()
    runtime._refresh_remote_device_policy_once = AsyncMock(return_value=True)  # type: ignore[method-assign]
    monkeypatch.setattr(
        "ori.runtime.classify_remote_command", lambda _: STATUS_EXECUTED
    )

    result = await runtime._handle_remote_command(_command("NEW_EXECUTABLE"))

    assert result.status == STATUS_UNSUPPORTED
    assert result.executed is False
    assert "no runtime handler" in result.detail
    runtime._refresh_remote_device_policy_once.assert_not_awaited()
    rows = await store.get_remote_command_execution_log()
    assert rows[0]["command"] == "NEW_EXECUTABLE"
    assert rows[0]["status"] == STATUS_UNSUPPORTED


async def test_apply_policy_requires_reference_args(store):
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._config = SimpleNamespace(
        device=SimpleNamespace(id="dev-01"),
        device_policy={"enabled": True},
    )
    runtime._dispatcher = ActionDispatcher()

    result = await runtime._handle_remote_command(_command("APPLY_POLICY"))

    assert result.status == STATUS_PRECONDITION_FAILED
    assert result.executed is False
    rows = await store.get_remote_command_execution_log()
    assert rows[0]["command"] == "APPLY_POLICY"
    assert rows[0]["status"] == STATUS_PRECONDITION_FAILED


async def test_apply_policy_fetches_hash_verifies_and_applies(store, monkeypatch):
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._config = SimpleNamespace(
        device=SimpleNamespace(id="dev-01"),
        device_policy={
            "enabled": True,
            "auth_token": "token",
            "public_key_b64": "public-key",
        },
    )
    runtime._dispatcher = ActionDispatcher()
    fetched = FetchedRemotePolicy(
        policy=DevicePolicy(
            tier=ActionTier.HARD_PHYSICAL,
            relay_b_enabled=True,
            relay_c_enabled=False,
            cloud_llm_enabled=False,
            valid_until=1_900_000_000,
            policy_version=12,
            issued_at=1_780_000_000,
            signature="ed25519:test",
        ),
        raw_payload='{"policy_version":12}',
        payload={"timestamp": 1_780_000_000},
    )
    fetch_policy = AsyncMock(return_value=fetched)
    monkeypatch.setattr(
        "ori.runtime.fetch_remote_device_policy_bundle_by_reference",
        fetch_policy,
    )
    command = _command(
        "APPLY_POLICY",
        args={
            "url": "https://policy.example.com/dev-01.json",
            "sha256": "a" * 64,
        },
    )

    result = await runtime._handle_remote_command(command)

    assert result.status == STATUS_EXECUTED
    assert result.executed is True
    fetch_policy.assert_awaited_once_with(
        runtime._config.device_policy,
        url="https://policy.example.com/dev-01.json",
        expected_sha256="a" * 64,
        current_policy_version=0,
    )
    assert runtime._dispatcher.current_policy_version() == 12
    cached = await store.get_latest_device_policy_cache()
    assert cached is not None
    assert cached["policy_version"] == 12
    rows = await store.get_remote_command_execution_log()
    assert rows[0]["status"] == STATUS_EXECUTED
    assert rows[0]["executed"] is True


async def test_apply_policy_hash_mismatch_is_rejected_and_logged(store, monkeypatch):
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._config = SimpleNamespace(
        device=SimpleNamespace(id="dev-01"),
        device_policy={
            "enabled": True,
            "auth_token": "token",
            "public_key_b64": "public-key",
        },
    )
    runtime._dispatcher = ActionDispatcher()
    fetch_policy = AsyncMock(
        side_effect=RemotePolicyFetchError("hash_mismatch", "hash mismatch")
    )
    monkeypatch.setattr(
        "ori.runtime.fetch_remote_device_policy_bundle_by_reference",
        fetch_policy,
    )
    command = _command(
        "APPLY_POLICY",
        args={
            "url": "https://policy.example.com/dev-01.json",
            "sha256": "b" * 64,
        },
    )

    result = await runtime._handle_remote_command(command)

    assert result.status == STATUS_FAILED
    assert result.executed is False
    assert runtime._dispatcher.current_policy_version() == 0
    rows = await store.get_remote_command_execution_log()
    assert rows[0]["status"] == STATUS_FAILED
    rejection = await store._run_read(
        lambda conn: conn.execute(
            """
            SELECT override_type, reason
            FROM override_log
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    )
    assert rejection is not None
    assert rejection["override_type"] == "policy_rejection"
    assert '"code":"hash_mismatch"' in rejection["reason"]


async def test_apply_policy_requires_device_policy_enabled(store):
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._config = SimpleNamespace(
        device=SimpleNamespace(id="dev-01"),
        device_policy={"enabled": False},
    )
    runtime._dispatcher = ActionDispatcher()

    result = await runtime._handle_remote_command(
        _command(
            "APPLY_POLICY",
            args={"url": "https://policy.example.com/dev-01.json", "sha256": "a" * 64},
        )
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert result.executed is False
    rows = await store.get_remote_command_execution_log()
    assert rows[0]["command"] == "APPLY_POLICY"
    assert rows[0]["status"] == STATUS_PRECONDITION_FAILED
