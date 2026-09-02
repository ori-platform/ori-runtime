# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The registry wired into a real runtime start, on the startup harness.

Ratified profiles enter only through monkeypatching the shipped-set loader;
the shipped candidate statuses are never overridden, and no configuration
path can reach the profile set.
"""

from __future__ import annotations

import asyncio
import json
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ori.config import ConfigValidationError
from ori.runtime import OriRuntime
from ori.security.commissioning.anchors import COMMISSIONING_ANCHOR_ENV
from ori.security.commissioning.loader import BINDING_RELATIVE_PATH
from ori.security.commissioning.profiles import load_profile_set
from tests.commissioning.signing import (
    local_gpio_binding,
    public_key_b64,
    sign_envelope,
)

SEED = "5" * 64
DEVICE = "bench-runtime-01"
SENSOR = "cpu-sensor"

RATIFIED = load_profile_set(
    [
        {
            "v": 1,
            "id": "fixture.overcurrent.v1",
            "status": "ratified",
            "observes": {"quantity": "current", "unit": "ampere"},
            "condition": {
                "kind": "upper_capacity_multiplier",
                "capacity_parameter": "rated_capacity_amps",
                "multiplier": 2.0,
            },
            "outcome": "open_protected_circuit",
        }
    ]
)


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
    overrides.setdefault("proof_method", "actuate_and_observe")
    overrides.setdefault("control_proof_method", "commanded_and_observed")
    binding = local_gpio_binding(
        device_id=DEVICE, sensor_id=SENSOR, gpio_pin=26, active_high=False, **overrides
    )
    target = tmp_path / BINDING_RELATIVE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(sign_envelope(binding, SEED)))


def _patch_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, ratified: bool
) -> None:
    monkeypatch.setattr(
        "ori.actions.whatsapp.TwilioProvider.send", AsyncMock(return_value=True)
    )
    monkeypatch.setattr("ori.actions.sms.SMSAction.send", AsyncMock(return_value=True))
    monkeypatch.setenv(COMMISSIONING_ANCHOR_ENV, public_key_b64(SEED))
    monkeypatch.chdir(tmp_path)
    if ratified:
        monkeypatch.setattr("ori.runtime.load_shipped_profile_set", lambda: RATIFIED)


async def _run_until(runtime: OriRuntime, probe) -> Any:
    result: dict[str, Any] = {}

    async def _observe() -> None:
        deadline = asyncio.get_running_loop().time() + 30.0
        while True:
            value = probe()
            if value is not None:
                result["value"] = value
                break
            if asyncio.get_running_loop().time() > deadline:
                break
            await asyncio.sleep(0.05)
        await runtime.stop()

    await asyncio.gather(runtime.start(), _observe())
    assert "value" in result, "the runtime never reached the probed state"
    return result["value"]


async def test_activation_reaches_health_on_a_real_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_binding(tmp_path)
    _patch_environment(tmp_path, monkeypatch, ratified=True)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))

    def _ready():
        return runtime._safety_registry if runtime._dispatcher is not None else None

    registry = await _run_until(runtime, _ready)
    assert registry.activation.activated[0].profile_id == "fixture.overcurrent.v1"
    health = await runtime._build_health_snapshot()
    assert health["safety"]["active"] == [
        ["local-relay", "fixture.overcurrent.v1"]
    ] or (health["safety"]["active"][0][1] == "fixture.overcurrent.v1")


async def test_shipped_set_stays_dormant_on_a_real_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_binding(tmp_path)
    _patch_environment(tmp_path, monkeypatch, ratified=False)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))

    def _ready():
        return runtime._safety_registry if runtime._dispatcher is not None else None

    registry = await _run_until(runtime, _ready)
    assert registry.activation.activated == ()
    assert [p.profile_id for p in registry.activation.pending]


async def test_registry_consumes_the_reading_before_the_event_bus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ordering invariant: for any sensor reading, the registry's
    synchronous consumption completes before the EventBus publication that
    lets any skill handler observe the same event."""
    _write_binding(tmp_path)
    _patch_environment(tmp_path, monkeypatch, ratified=True)
    order: list[str] = []

    from ori.network.event_bus import EventBus
    from ori.safety.registry import SafetyRegistry

    real_observe = SafetyRegistry.observe_reading
    real_publish = EventBus.publish

    async def spy_observe(self, sensor_id, value, unit, quality):
        result = await real_observe(self, sensor_id, value, unit, quality)
        order.append("registry")
        return result

    async def spy_publish(self, event):
        if getattr(event, "sensor_id", None) == SENSOR:
            order.append("publish")
        return await real_publish(self, event)

    monkeypatch.setattr(SafetyRegistry, "observe_reading", spy_observe)
    monkeypatch.setattr(EventBus, "publish", spy_publish)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    await _run_until(runtime, lambda: True if "publish" in order else None)
    first_publish = order.index("publish")
    assert "registry" in order[:first_publish]


async def test_refused_activation_gates_the_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runtime's hardened gate consumes the registry verdict: a refusal
    stops the start before any pin could be driven."""
    _write_binding(tmp_path)
    _patch_environment(tmp_path, monkeypatch, ratified=True)
    from ori.safety.registry import SafetyRegistry

    monkeypatch.setattr(
        SafetyRegistry, "startup_verdict", lambda self, *, hardened: "refuse"
    )
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    task = asyncio.ensure_future(runtime.start())
    try:
        with pytest.raises(ConfigValidationError):
            await asyncio.wait_for(asyncio.shield(task), timeout=15.0)
    except asyncio.TimeoutError:
        await runtime.stop()
        await asyncio.wait_for(task, timeout=15.0)
        raise AssertionError("the runtime started instead of refusing")


async def _actuator_after_start(runtime: OriRuntime) -> Any:
    def _ready():
        if runtime._dispatcher is None:
            return None
        return (runtime._commissioned_actuator,)

    (actuator,) = await _run_until(runtime, _ready)
    return actuator


async def test_registry_owns_the_startup_command_for_an_active_zone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An open-terminal zone with an active profile gets its startup
    de_energised from the registry, recorded under the safety reason."""
    _write_binding(tmp_path)
    _patch_environment(tmp_path, monkeypatch, ratified=True)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    actuator = await _actuator_after_start(runtime)
    assert actuator is not None
    assert actuator.last is not None
    assert actuator.last.outcome == "safety_startup"
    assert actuator.last.coil_state == "de_energised"


async def test_closed_terminal_active_zone_defers_the_startup_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A closed-terminal zone's coil is not commanded at startup: the
    deferred gate waits for a credible reading, and the cpu-percent
    readings this harness produces are unit-mismatched and never credible."""
    _write_binding(tmp_path, terminal_state="closed", open_outcome="energised")
    _patch_environment(tmp_path, monkeypatch, ratified=True)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    actuator = await _actuator_after_start(runtime)
    assert actuator is not None
    assert actuator.last is None


async def test_dormant_zone_keeps_the_plain_startup_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_binding(tmp_path)
    _patch_environment(tmp_path, monkeypatch, ratified=False)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    actuator = await _actuator_after_start(runtime)
    assert actuator is not None
    assert actuator.last is not None
    assert actuator.last.outcome == "startup"


async def test_no_line_is_touched_on_a_closed_terminal_active_zone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The acquisition itself drives the coil, so the proof is at the
    driver: no connect, no acquire, no trigger, no release happens before a
    credible reading — and this harness's readings are never credible."""
    _write_binding(tmp_path, terminal_state="closed", open_outcome="energised")
    _patch_environment(tmp_path, monkeypatch, ratified=True)
    calls: list[str] = []
    from ori.actions.relay import RelayAction

    for name in ("connect", "acquire_at", "trigger", "release"):

        async def _spy(self, *a, _name=name, **k):
            calls.append(_name)

        monkeypatch.setattr(RelayAction, name, _spy)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    await _actuator_after_start(runtime)
    assert calls == []


async def test_deferred_first_command_is_the_acquisition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The commander's deferred switch: the first command acquires at the
    licensed coil state as one act; the next commands normally."""
    from ori.safety.commander import ActuatorOutcomeCommander

    events: list[str] = []

    class FakeActuator:
        async def acquire_commanding(self, outcome):
            events.append(f"acquire:{outcome}")
            return True

        async def acquire_coil(self, coil_state, *, reason):
            events.append(f"acquire_coil:{coil_state}")
            return True

        async def command(self, outcome):
            events.append(f"command:{outcome}")
            return True

        async def command_coil(self, coil_state, *, reason):
            events.append(f"command_coil:{coil_state}")
            return True

    commander = ActuatorOutcomeCommander()
    commander.bind("z", FakeActuator(), defer_acquisition=True)
    assert await commander.command_outcome("z", "open_protected_circuit")
    assert await commander.command_outcome("z", "open_protected_circuit")
    assert events == [
        "acquire:open_protected_circuit",
        "command:open_protected_circuit",
    ]
    events.clear()
    commander2 = ActuatorOutcomeCommander()
    commander2.bind("z", FakeActuator(), defer_acquisition=True)
    assert await commander2.command_startup_de_energised("z")
    assert await commander2.command_startup_de_energised("z")
    assert events == ["acquire_coil:de_energised", "command_coil:de_energised"]


async def test_active_zone_without_executor_degrades_a_dev_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An active pair whose zone will bind no executor degrades a
    development start explicitly, decided before any relay connection. A
    second local-GPIO zone cannot reach this state — the binding verifier
    refuses an undeclared actuator and the config declares one pin — so the
    reachable case is a firmware-channel zone, simulated here by the zone
    resolving to no relay pin."""
    _write_binding(tmp_path)
    _patch_environment(tmp_path, monkeypatch, ratified=True)
    from ori.security.commissioning.loader import CommissioningState

    monkeypatch.setattr(
        CommissioningState, "zone_for_local_gpio", lambda self, pin: None
    )
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))

    def _ready():
        return runtime._safety_registry if runtime._dispatcher is not None else None

    with caplog.at_level("WARNING"):
        registry = await _run_until(runtime, _ready)
    (zone_id,) = registry.zones_with_active_pairs
    assert any(
        zone_id in record.getMessage()
        and "starting degraded" in record.getMessage()
        and "bound executor" in record.getMessage()
        for record in caplog.records
    ), "the pre-connect gate's own degradation warning was not emitted"


def test_unbound_active_zone_refuses_a_hardened_start() -> None:
    from ori.runtime import _refuse_unbound_active_zones

    _refuse_unbound_active_zones([], hardened=True)
    _refuse_unbound_active_zones(["zone-two"], hardened=False)
    with pytest.raises(ConfigValidationError):
        _refuse_unbound_active_zones(["zone-two"], hardened=True)


async def test_deferral_survives_a_failed_acquisition() -> None:
    """A failed or raising acquire leaves the line untaken: the next attempt
    must acquire again, never command an unheld line."""
    from ori.safety.commander import ActuatorOutcomeCommander

    events: list[str] = []

    class FlakyActuator:
        def __init__(self) -> None:
            self.fail = True

        async def acquire_commanding(self, outcome):
            events.append("acquire")
            if self.fail:
                raise OSError("no backend")
            return True

        async def command(self, outcome):
            events.append("command")
            return True

    actuator = FlakyActuator()
    commander = ActuatorOutcomeCommander()
    commander.bind("z", actuator, defer_acquisition=True)
    with pytest.raises(OSError):
        await commander.command_outcome("z", "open_protected_circuit")
    actuator.fail = False
    assert await commander.command_outcome("z", "open_protected_circuit")
    assert await commander.command_outcome("z", "open_protected_circuit")
    assert events == ["acquire", "acquire", "command"]


async def test_credible_reading_drives_the_deferred_acquisition_through_the_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The join the no-touch test stops short of: a credible clear reading
    arriving through the real poll path performs the deferred acquisition —
    one acquire_at, at de_energised, and no connect, trigger or release."""
    _write_binding(tmp_path, terminal_state="closed", open_outcome="energised")
    _patch_environment(tmp_path, monkeypatch, ratified=True)
    calls: list[tuple[str, Any]] = []
    from ori.actions.relay import RelayAction
    from ori.hal.psutil_adapter import PsutilAdapter
    from ori.network.events import SensorReading
    from ori.utils.time_utils import now_ms

    for name in ("connect", "trigger", "release"):

        async def _spy(self, *a, _name=name, **k):
            calls.append((_name, None))

        monkeypatch.setattr(RelayAction, name, _spy)

    async def _acquire_spy(self, *a, **k):
        calls.append(("acquire_at", k.get("coil_state")))

    monkeypatch.setattr(RelayAction, "acquire_at", _acquire_spy)

    async def _ampere_read(self, sensor_id):
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="current",
            value=5.0,
            unit="ampere",
            timestamp=now_ms(),
            quality=1.0,
        )

    monkeypatch.setattr(PsutilAdapter, "read", _ampere_read)
    runtime = OriRuntime(config_path=str(_write_config(tmp_path)))
    await _run_until(runtime, lambda: True if calls else None)
    assert calls == [("acquire_at", "de_energised")]


async def test_safety_notice_survives_a_denying_device_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exemption is structural: with the external-alert policy gate
    denying everything, a rejected-input safety notice still reaches the
    sender through the dedicated entrypoint, and the policy-counted
    counter never moves for it."""
    _write_binding(tmp_path)
    _patch_environment(tmp_path, monkeypatch, ratified=True)
    from ori.actions.alert_failover import AlertFailoverSender
    from ori.hal.psutil_adapter import PsutilAdapter
    from ori.network.events import SensorReading
    from ori.utils.time_utils import now_ms

    sent: list[str] = []
    counted: list[str] = []

    async def _deny(self, *, channel, action_tier):
        return False

    async def _spy_send(self, *, message, to_number, preferred_channel):
        sent.append(message)
        return True

    async def _count(self, channel, *, action_tier):
        counted.append(action_tier)

    monkeypatch.setattr(OriRuntime, "_policy_permits_external_alert", _deny)
    monkeypatch.setattr(OriRuntime, "_record_policy_counted_alert", _count)
    monkeypatch.setattr(AlertFailoverSender, "send", _spy_send)
    monkeypatch.setenv("OWNER_PHONE_NUMBER", "+2340000000000")

    async def _rejected_read(self, sensor_id):
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="current",
            value=5.0,
            unit="ampere",
            timestamp=now_ms(),
            quality=0.0,
        )

    monkeypatch.setattr(PsutilAdapter, "read", _rejected_read)
    runtime = OriRuntime(config_path=str(_write_config_with_contact(tmp_path)))
    await _run_until(
        runtime,
        lambda: True if any("SAFETY rejected_input" in m for m in sent) else None,
    )
    assert not counted


def _write_config_with_contact(tmp_path: Path) -> Path:
    cfg = _write_config(tmp_path)
    text = cfg.read_text()
    spliced = text.replace(
        "actions:\n", 'actions:\n  operator_contact: "+2340000000000"\n', 1
    )
    assert spliced != text, "the config splice found no actions block"
    cfg.write_text(spliced)
    return cfg
