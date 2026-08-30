# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""What a runtime start may claim about commissioning, on a real start.

Declared actuating hardware with no accepted binding starts degraded in
development and refuses under hardened posture; an accepted binding beside the
config licenses actuation and is reported in health by zone; colliding anchors
refuse every start before any binding is read.
"""

from __future__ import annotations

import asyncio
import base64
import json
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ori.config import Config, ConfigValidationError
from ori.runtime import OriRuntime
from ori.security.commissioning.anchors import (
    COMMISSIONING_ANCHOR_ENV,
    CommissioningAnchors,
)
from ori.security.commissioning.loader import BINDING_RELATIVE_PATH
from ori.state.store import StateStore
from tests.commissioning.signing import (
    local_gpio_binding,
    public_key_b64,
    sign_envelope,
)

SEED = "5" * 64
DEVICE = "bench-runtime-01"
SENSOR = "cpu-sensor"


def _write_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "ori.yaml"
    cfg.write_text(
        textwrap.dedent(f"""\
            device:
              id: {DEVICE}
              name: Bench
              location: Test Lab
              deployment_profile: development
            sensors:
              - id: {SENSOR}
                type: cpu_percent
                protocol: psutil
                poll_interval_ms: 100
            skills: []
            reasoning:
              default_tier: rule
            gateway:
              enabled: false
              broker_url: ""
            actions:
              primary_alert_channel: sms
              whatsapp:
                enabled: false
              sms:
                enabled: false
              relay:
                enabled: false
                gpio_pin: 26
            database:
              path: {tmp_path / "ori_state.db"}
            logging:
              file: {tmp_path / "ori.log"}
        """),
        encoding="utf-8",
    )
    return cfg


def _write_binding(tmp_path: Path, **overrides: Any) -> None:
    binding = local_gpio_binding(
        device_id=DEVICE, sensor_id=SENSOR, gpio_pin=26, active_high=False, **overrides
    )
    target = tmp_path / BINDING_RELATIVE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(sign_envelope(binding, SEED)))


def _patch_external(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "ori.actions.whatsapp.TwilioProvider.send", AsyncMock(return_value=True)
    )
    monkeypatch.setattr("ori.actions.sms.SMSAction.send", AsyncMock(return_value=True))


async def _start_expecting_refusal(runtime: OriRuntime) -> None:
    """A start that should refuse must not be allowed to come up instead."""
    task = asyncio.ensure_future(runtime.start())
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=15.0)
    except asyncio.TimeoutError:
        await runtime.stop()
        await asyncio.wait_for(task, timeout=15.0)
        raise AssertionError("the runtime started instead of refusing")


async def _started_health(runtime: OriRuntime) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + 30.0
    while runtime._dispatcher is None:
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("the runtime did not come up in time")
        await asyncio.sleep(0.05)
    health = await runtime._build_health_snapshot()
    await runtime.stop()
    return health


async def test_a_declared_relay_with_no_binding_starts_degraded_and_unlicensed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_external(monkeypatch)
    monkeypatch.delenv(COMMISSIONING_ANCHOR_ENV, raising=False)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    observed: dict[str, Any] = {}

    async def _observe() -> None:
        observed["health"] = await _started_health(runtime)

    await asyncio.gather(runtime.start(), _observe())
    health = observed["health"]
    assert health["status"] == "degraded"
    block = health["commissioning"]
    assert block["binding_seq"] == 0 and block["binding_hash"] is None
    assert block["anchors_configured"] is False
    assert block["actuation_licensed"] is False
    assert block["zones"] == []
    assert runtime._commissioning_state is not None
    assert "binding_missing" in runtime._commissioning_state.problems


async def test_an_accepted_binding_beside_the_config_licenses_and_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_external(monkeypatch)
    monkeypatch.setenv(COMMISSIONING_ANCHOR_ENV, public_key_b64(SEED))
    _write_binding(tmp_path)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    observed: dict[str, Any] = {}

    async def _observe() -> None:
        observed["health"] = await _started_health(runtime)

    await asyncio.gather(runtime.start(), _observe())
    block = observed["health"]["commissioning"]
    assert block["binding_seq"] == 1
    assert block["anchors_configured"] is True
    assert block["actuation_licensed"] is True
    assert block["last_verdict"]["reason"] == "accepted"
    (zone,) = block["zones"]
    assert zone["actuator"] == {
        "kind": "local_gpio",
        "identity": {"gpio_pin": 26, "active_high": False},
    }
    assert zone["commissioned_mapping"]["open_protected_circuit"] == "de_energised"
    assert zone["proof_method"] == "undemonstrated"
    # Not degraded: status is only stamped when something is.
    assert observed["health"].get("status", "healthy") == "healthy"
    # Retained: a second start with the file gone still holds it.
    (tmp_path / BINDING_RELATIVE_PATH).unlink()
    runtime2 = OriRuntime(config_path=str(tmp_path / "ori.yaml"))

    async def _observe2() -> None:
        observed["health2"] = await _started_health(runtime2)

    await asyncio.gather(runtime2.start(), _observe2())
    assert observed["health2"]["commissioning"]["binding_seq"] == 1
    assert observed["health2"]["commissioning"]["actuation_licensed"] is True


async def test_a_refused_binding_is_reported_by_stage_and_licenses_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_external(monkeypatch)
    # The anchor configured is not the key that signed the document.
    monkeypatch.setenv(COMMISSIONING_ANCHOR_ENV, public_key_b64("6" * 64))
    _write_binding(tmp_path)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    observed: dict[str, Any] = {}

    async def _observe() -> None:
        observed["health"] = await _started_health(runtime)

    await asyncio.gather(runtime.start(), _observe())
    block = observed["health"]["commissioning"]
    assert block["last_verdict"]["stage"] == "key_selection"
    assert block["last_verdict"]["reason"] == "unknown_signer"
    assert block["actuation_licensed"] is False
    assert observed["health"]["status"] == "degraded"


async def test_colliding_anchors_refuse_the_start_before_any_binding_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_external(monkeypatch)
    key = public_key_b64(SEED)
    monkeypatch.setenv(COMMISSIONING_ANCHOR_ENV, key)
    monkeypatch.setenv("ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64", key)
    _write_binding(tmp_path)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    with pytest.raises(ConfigValidationError, match="anchor_collision"):
        await _start_expecting_refusal(runtime)
    assert runtime._state_store is None


async def test_a_malformed_anchor_refuses_the_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_external(monkeypatch)
    monkeypatch.setenv(COMMISSIONING_ANCHOR_ENV, "not a key")
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    with pytest.raises(ConfigValidationError, match="commissioning anchors"):
        await _start_expecting_refusal(runtime)


async def test_hardened_posture_refuses_declared_hardware_without_a_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Driven at the load step: on this host a hardened start refuses at the
    relay backend first, and the binding rule has to hold on its own."""
    monkeypatch.delenv(COMMISSIONING_ANCHOR_ENV, raising=False)
    config = Config.load(str(_write_config(tmp_path)))
    config.device.deployment_profile = "production"
    runtime = OriRuntime(config_path=str(tmp_path / "ori.yaml"))
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    runtime._state_store = store
    try:
        with pytest.raises(ConfigValidationError, match="no accepted binding"):
            await runtime._load_commissioning(
                config, CommissioningAnchors(current=None, previous=None)
            )
    finally:
        await store.close()


async def test_hardened_posture_starts_with_an_accepted_demonstrated_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(COMMISSIONING_ANCHOR_ENV, public_key_b64(SEED))
    _write_binding(tmp_path, proof_method="actuate_and_observe")
    config = Config.load(str(_write_config(tmp_path)))
    config.device.deployment_profile = "production"
    runtime = OriRuntime(config_path=str(tmp_path / "ori.yaml"))
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    runtime._state_store = store
    try:
        anchors = CommissioningAnchors(
            current=base64.b64decode(public_key_b64(SEED)), previous=None
        )
        await runtime._load_commissioning(config, anchors)
        state = runtime._commissioning_state
        assert state is not None and state.actuation_licensed
        assert state.problems == []
        # An undemonstrated revision is refused at activation_posture under
        # hardened posture, and the demonstrated binding stays in force: a
        # refused document never withdraws what was accepted.
        assert state.in_force is not None
        _write_binding(
            tmp_path, binding_seq=2, supersedes=state.in_force.canonical_hash
        )
        await runtime._load_commissioning(config, anchors)
        state = runtime._commissioning_state
        assert state is not None and state.in_force is not None
        assert state.in_force.binding_seq == 1
        assert state.last_verdict is not None
        assert state.last_verdict.reason == "undemonstrated_binding"
        assert state.actuation_licensed
    finally:
        await store.close()


async def test_the_relay_is_driven_only_through_the_commissioned_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Startup commands de_energised through the zone's polarity, and the
    legacy relay names resolve to outcomes through the mapping: on a zone
    whose open outcome is de_energised, `trip_relay` releases the coil."""
    _patch_external(monkeypatch)
    monkeypatch.setenv(COMMISSIONING_ANCHOR_ENV, public_key_b64(SEED))
    _write_binding(tmp_path)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    observed: dict[str, Any] = {}

    async def _observe() -> None:
        # The dispatcher exists before the relay executors are registered on
        # it, and device policy is awaited in between; waiting for the
        # dispatcher alone can observe it with no `trip_relay` yet.
        deadline = asyncio.get_running_loop().time() + 30.0
        while (
            runtime._dispatcher is None
            or "trip_relay" not in runtime._dispatcher._executors
        ):
            if asyncio.get_running_loop().time() > deadline:
                raise AssertionError("the relay executors were not registered in time")
            await asyncio.sleep(0.05)
        actuator = runtime._commissioned_actuator
        assert actuator is not None
        observed["startup"] = actuator.health()
        executors = runtime._dispatcher._executors
        observed["registered"] = sorted(
            n
            for n in ("trip_relay", "release_relay", "close_gas_valve")
            if n in executors
        )
        await executors["trip_relay"]("trip_relay", None)
        observed["after_trip"] = actuator.health()
        await executors["release_relay"]("release_relay", None)
        observed["after_release"] = actuator.health()
        observed["health"] = await runtime._build_health_snapshot()
        await runtime.stop()

    await asyncio.gather(runtime.start(), _observe())
    startup = observed["startup"]
    assert startup["active_high"] is False and startup["gpio_pin"] == 26
    assert startup["last_command"]["outcome"] == "startup"
    assert startup["last_command"]["coil_state"] == "de_energised"
    assert startup["last_command"]["level"] == "high"
    assert startup["coil"] == "de_energised"
    assert observed["registered"] == ["close_gas_valve", "release_relay", "trip_relay"]
    after_trip = observed["after_trip"]["last_command"]
    assert after_trip == {
        "outcome": "open_protected_circuit",
        "coil_state": "de_energised",
        "level": "high",
        "executed": True,
    }
    after_release = observed["after_release"]["last_command"]
    assert (
        after_release["outcome"],
        after_release["coil_state"],
        after_release["level"],
    ) == (
        "close_protected_circuit",
        "energised",
        "low",
    )
    assert observed["health"]["commissioning"]["actuator"]["binding_seq"] == 1


async def test_without_an_accepted_zone_the_pin_is_not_driven_and_relay_actions_are_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_external(monkeypatch)
    monkeypatch.delenv(COMMISSIONING_ANCHOR_ENV, raising=False)
    connect = AsyncMock(return_value=None)
    monkeypatch.setattr("ori.actions.relay.RelayAction.connect", connect)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    observed: dict[str, Any] = {}

    async def _observe() -> None:
        observed["health"] = await _started_health(runtime)
        observed["executors"] = (
            set(runtime._dispatcher._executors) if runtime._dispatcher else set()
        )

    await asyncio.gather(runtime.start(), _observe())
    connect.assert_not_awaited()
    assert runtime._commissioned_actuator is None
    assert (
        not {"trip_relay", "release_relay", "close_gas_valve"} & observed["executors"]
    )
    assert observed["health"]["commissioning"]["actuator"] is None
