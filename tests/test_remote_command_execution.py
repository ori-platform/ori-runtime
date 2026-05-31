# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ori.runtime import OriRuntime
from ori.security.remote_command_policy import (
    STATUS_AUDIT_ONLY,
    STATUS_EXECUTED,
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


def _command(command: str, command_id: str = "cmd-1") -> RemoteCommand:
    return RemoteCommand(
        command_id=command_id,
        channel="sms",
        device_id="dev-01",
        issued_at_ms=1_780_000_000_000,
        command=command,
        args={},
        signature="hmac-sha256:test",
    )


def test_policy_executes_only_refresh_policy():
    assert classify_remote_command(_command("REFRESH_POLICY")) == STATUS_EXECUTED
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
