# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ori.network.events import ActionTier, SensorReading
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
from ori.security.threshold_guard import tier_d_config_keys
from ori.skills.loader import Skill, Trigger
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


async def test_advisory_lockout_risk_does_not_block_valid_signed_command(store):
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._config = SimpleNamespace(device_policy={"enabled": True})
    runtime._dispatcher = object()
    runtime._refresh_remote_device_policy_once = AsyncMock(return_value=True)  # type: ignore[method-assign]
    runtime._remote_command_lockout_states = {
        "sms:+2348012345678": {
            "channel": "sms",
            "from_number": "+2348012345678",
            "risk_level": "critical",
            "locked_out": False,
            "enforcement_enabled": False,
            "incident_count": 3,
            "rejection_count": 18,
            "window_ms": 3_600_000,
            "checked_at_ms": 1_780_000_000_000,
            "reason": "critical_incident_volume",
        }
    }

    result = await runtime._handle_remote_command(
        _command("REFRESH_POLICY", command_id="refresh-under-risk")
    )

    assert result.status == STATUS_EXECUTED
    assert result.executed is True
    runtime._refresh_remote_device_policy_once.assert_awaited_once()


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


# ─── SET_THRESHOLD helpers ────────────────────────────────────────────────────


def _make_skill(
    name: str = "test-skill",
    config: dict | None = None,
    tier_d_condition: str | None = "value > dangerous_threshold",
    extra_triggers: list[Trigger] | None = None,
) -> Skill:
    # Always include a non-Tier-D trigger so warn_threshold is in trigger refs.
    triggers: list[Trigger] = [
        Trigger(name="warn", condition="value > warn_threshold", action_tier="A"),
        *(extra_triggers or []),
    ]
    if tier_d_condition is not None:
        triggers = [
            Trigger(
                name="danger",
                condition=tier_d_condition,
                action_tier="D",
                bypass_llm=True,
            ),
            *triggers,
        ]
    return Skill(
        name=name,
        version="0.1.0",
        author="test",
        sensors_required=[{"type": "current"}],
        triggers=triggers,
        config=config
        if config is not None
        else {"dangerous_threshold": 20.0, "warn_threshold": 15.0},
    )


def _runtime_with_skill(skill: Skill, store: StateStore) -> OriRuntime:
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._config = SimpleNamespace(
        device=SimpleNamespace(id="dev-01"),
        device_policy={"enabled": False},
        sensors=[SimpleNamespace(id="sensor-1", type="current")],
    )
    runtime._dispatcher = ActionDispatcher()
    runtime._loaded_skills = [skill]
    runtime._startup_skill_configs = {skill.name: dict(skill.config)}
    return runtime


# ─── SET_THRESHOLD tests ──────────────────────────────────────────────────────


def test_tier_d_config_keys_identifies_keys_in_tier_d_conditions():
    skill = _make_skill(tier_d_condition="value > dangerous_threshold")
    assert "dangerous_threshold" in tier_d_config_keys(skill)
    assert "warn_threshold" not in tier_d_config_keys(skill)


def test_tier_d_config_keys_empty_when_no_tier_d_triggers():
    skill = _make_skill(tier_d_condition=None)
    assert tier_d_config_keys(skill) == frozenset()


async def test_set_threshold_applies_non_tier_d_key(store):
    skill = _make_skill()
    runtime = _runtime_with_skill(skill, store)

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "warn_threshold",
                "value": 12.0,
            },
        )
    )

    assert result.status == STATUS_EXECUTED
    assert result.executed is True
    assert skill.config["warn_threshold"] == 12.0
    rows = await store.get_remote_command_execution_log()
    assert rows[0]["status"] == STATUS_EXECUTED


async def test_set_threshold_makes_upper_bound_tier_d_more_sensitive(store):
    skill = _make_skill()
    runtime = _runtime_with_skill(skill, store)

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "dangerous_threshold",
                "value": 15.0,
            },
        )
    )

    assert result.status == STATUS_EXECUTED
    assert skill.config["dangerous_threshold"] == 15.0


async def test_set_threshold_upper_bound_less_sensitive_than_startup_rejected(store):
    skill = _make_skill()
    runtime = _runtime_with_skill(skill, store)

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "dangerous_threshold",
                "value": 25.0,  # startup threshold is 20.0
            },
        )
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert result.executed is False
    assert skill.config["dangerous_threshold"] == 20.0  # unchanged
    assert "less sensitive" in result.detail
    rows = await store.get_remote_command_execution_log()
    assert rows[0]["status"] == STATUS_PRECONDITION_FAILED


async def test_set_threshold_rejects_active_suppression(store):
    skill = _make_skill()
    runtime = _runtime_with_skill(skill, store)
    # Lower threshold first so we can raise it into the active-reading window
    skill.config["dangerous_threshold"] = 15.0
    runtime._startup_skill_configs["test-skill"]["dangerous_threshold"] = 20.0
    # Seed a reading between old (15.0) and proposed new (19.0)
    await store.append_history(
        SimpleNamespace(
            reading=SensorReading(
                sensor_id="sensor-1",
                sensor_type="current",
                value=18.0,
                unit="A",
                timestamp=1_780_000_000_000,
                quality=1.0,
                metadata={},
            )
        )
    )

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "dangerous_threshold",
                "value": 19.0,  # 15 < 18.0 <= 19 → suppression
            },
        )
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert result.executed is False
    assert skill.config["dangerous_threshold"] == 15.0  # unchanged
    assert "suppress" in result.detail


async def test_set_threshold_missing_args_rejected(store):
    skill = _make_skill()
    runtime = _runtime_with_skill(skill, store)

    result = await runtime._handle_remote_command(
        _command("SET_THRESHOLD", args={"skill_name": "test-skill"})
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert result.executed is False


async def test_set_threshold_unknown_skill_rejected(store):
    skill = _make_skill()
    runtime = _runtime_with_skill(skill, store)

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "no-such-skill",
                "threshold_key": "dangerous_threshold",
                "value": 10.0,
            },
        )
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert "not loaded" in result.detail


async def test_set_threshold_unknown_key_rejected(store):
    skill = _make_skill()
    runtime = _runtime_with_skill(skill, store)

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "nonexistent_key",
                "value": 10.0,
            },
        )
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert "does not exist" in result.detail


async def test_set_threshold_non_numeric_value_rejected(store):
    skill = _make_skill()
    runtime = _runtime_with_skill(skill, store)

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "warn_threshold",
                "value": "not-a-number",
            },
        )
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert result.executed is False


def test_set_threshold_policy_classification():
    assert classify_remote_command(_command("SET_THRESHOLD")) == STATUS_EXECUTED


async def test_set_threshold_non_numeric_existing_value_rejected(store):
    # A config key whose current value is not a number must be rejected —
    # SET_THRESHOLD must not mutate string config keys like currency_code.
    skill = _make_skill(
        config={"dangerous_threshold": 20.0, "warn_threshold": 15.0, "label": "main"},
        extra_triggers=[
            Trigger(name="label_check", condition="label == label", action_tier="A")
        ],
    )
    runtime = _runtime_with_skill(skill, store)

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "label",
                "value": 1.0,
            },
        )
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert "not numeric" in result.detail
    assert skill.config["label"] == "main"  # unchanged


async def test_set_threshold_key_not_in_trigger_condition_rejected(store):
    # A numeric config key not referenced by any trigger must be rejected —
    # SET_THRESHOLD is for tuning parameters used in rule conditions only.
    skill = _make_skill(
        config={
            "dangerous_threshold": 20.0,
            "warn_threshold": 15.0,
            "history_window": 10,
        },
    )
    runtime = _runtime_with_skill(skill, store)

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "history_window",
                "value": 5.0,
            },
        )
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert "trigger condition" in result.detail
    assert skill.config["history_window"] == 10  # unchanged


async def test_set_threshold_tier_d_fails_closed_when_store_unavailable(store):
    # When StateStore is None, Tier D threshold changes must be rejected
    # rather than allowed — the runtime cannot prove no condition is active.
    skill = _make_skill()
    runtime = _runtime_with_skill(skill, store)
    runtime._state_store = None  # simulate unavailability

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "dangerous_threshold",
                "value": 15.0,  # lowering — would be fine if store were available
            },
        )
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert result.executed is False
    assert "StateStore" in result.detail


async def test_set_threshold_lower_bound_tier_d_suppression_rejected(store):
    # Lower-bound Tier D condition: value < low_voltage_threshold.
    # Lowering the threshold from 10.0 to 7.0 while a reading of 8.0 is active
    # (8.0 < 10.0 = True) suppresses the condition (8.0 < 7.0 = False).
    skill = _make_skill(
        tier_d_condition="value < low_voltage_threshold",
        config={"low_voltage_threshold": 10.0, "warn_threshold": 12.0},
    )
    runtime = _runtime_with_skill(skill, store)
    runtime._startup_skill_configs = {skill.name: dict(skill.config)}
    # Seed a reading that currently satisfies the lower-bound condition
    await store.append_history(
        SimpleNamespace(
            reading=SensorReading(
                sensor_id="sensor-1",
                sensor_type="current",
                value=8.0,  # 8.0 < 10.0 = active Tier D condition
                unit="V",
                timestamp=1_780_000_000_000,
                quality=1.0,
                metadata={},
            )
        )
    )

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "low_voltage_threshold",
                "value": 7.0,  # 8.0 < 7.0 = False → suppression
            },
        )
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert result.executed is False
    assert skill.config["low_voltage_threshold"] == 10.0  # unchanged
    assert "less sensitive" in result.detail


async def test_set_threshold_lower_bound_less_sensitive_than_startup_rejected(store):
    # No active reading is required for this rejection. Tier D remote commands
    # may not make startup safety less sensitive.
    skill = _make_skill(
        tier_d_condition="value < low_voltage_threshold",
        config={"low_voltage_threshold": 10.0, "warn_threshold": 12.0},
    )
    runtime = _runtime_with_skill(skill, store)

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "low_voltage_threshold",
                "value": 7.0,
            },
        )
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert result.executed is False
    assert skill.config["low_voltage_threshold"] == 10.0
    assert "less sensitive" in result.detail


async def test_set_threshold_lower_bound_more_sensitive_than_startup_allowed(store):
    skill = _make_skill(
        tier_d_condition="value < low_voltage_threshold",
        config={"low_voltage_threshold": 10.0, "warn_threshold": 12.0},
    )
    runtime = _runtime_with_skill(skill, store)

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "low_voltage_threshold",
                "value": 12.0,
            },
        )
    )

    assert result.status == STATUS_EXECUTED
    assert result.executed is True
    assert skill.config["low_voltage_threshold"] == 12.0


async def test_set_threshold_complex_tier_d_condition_fails_closed(store):
    skill = _make_skill(
        tier_d_condition="value > (dangerous_threshold / 2.0)",
        config={"dangerous_threshold": 20.0, "warn_threshold": 15.0},
    )
    runtime = _runtime_with_skill(skill, store)

    result = await runtime._handle_remote_command(
        _command(
            "SET_THRESHOLD",
            args={
                "skill_name": "test-skill",
                "threshold_key": "dangerous_threshold",
                "value": 15.0,
            },
        )
    )

    assert result.status == STATUS_PRECONDITION_FAILED
    assert result.executed is False
    assert "cannot prove" in result.detail
    assert skill.config["dangerous_threshold"] == 20.0


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
