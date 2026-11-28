# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""A hardened start refuses a sensor whose adapter's library is not installed.

Configuration accepted `protocol: mqtt` on a Pi install that lacked `aiomqtt`,
and the sensor could never connect. Each adapter module names the library it
lacks for a sensor, and staging and production refuse to start on one.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ori.config import ConfigValidationError, SensorConfig
from ori.hal.protocol_registry import (
    PROTOCOL_DEFINITIONS,
    connect_config,
    protocol_library_check,
)
from ori.runtime._capabilities import validate_required_runtime_capabilities

HAL = Path(__file__).resolve().parents[1] / "ori" / "hal"

# Each guarded optional import: protocol -> (module holding the flag, flag, library).
GUARDED = {
    "serial": ("ori.hal.serial_adapter", "_SERIAL_AVAILABLE", "pyserial"),
    "usb_serial": ("ori.hal.usb_serial_adapter", "_PYSERIAL_AVAILABLE", "pyserial"),
    "solarman_modbus": (
        "ori.hal.solarman_modbus_adapter",
        "_PYSOLARMAN_AVAILABLE",
        "pysolarmanv5",
    ),
    "growatt": ("ori.hal.growatt_adapter", "_PYSOLARMAN_AVAILABLE", "pysolarmanv5"),
    "http": ("ori.hal.http_adapter", "_HTTPX_AVAILABLE", "httpx"),
    "coap": ("ori.hal.coap_adapter", "_AIOCOAP_AVAILABLE", "aiocoap"),
    "opcua": ("ori.hal.opcua_adapter", "_ASYNCUA_AVAILABLE", "asyncua"),
    "mqtt": ("ori.hal.mqtt_base", "_AIOMQTT_AVAILABLE", "aiomqtt"),
    "mqtt_perception": ("ori.hal.mqtt_base", "_AIOMQTT_AVAILABLE", "aiomqtt"),
    "victron": ("ori.hal.mqtt_base", "_AIOMQTT_AVAILABLE", "aiomqtt"),
    "zigbee": ("ori.hal.mqtt_base", "_AIOMQTT_AVAILABLE", "aiomqtt"),
    "lorawan": ("ori.hal.mqtt_base", "_AIOMQTT_AVAILABLE", "aiomqtt"),
}


# Guarded imports a sensor does not need, each with the reason.
OPTIONAL = {
    ("ori.hal.smart_adapter", "_PYSMART_AVAILABLE"): (
        "pySMART wraps smartctl and reads fall back to it; missing_library checks "
        "smartctl itself"
    ),
}

# Modules whose guarded imports are checked another way: i2c loads its chip
# drivers lazily and names them per sensor type (i2c_driver_unavailable_reason).
CHECKED_OTHERWISE = {"ori.hal.i2c_adapter"}


def _sensor(protocol: str, sensor_type: str = "temperature") -> SensorConfig:
    return SensorConfig(
        id=f"{protocol}-1",
        type=sensor_type,
        protocol=protocol,
        poll_interval_ms=1000,
    )


def _check(sensor: SensorConfig) -> str | None:
    return protocol_library_check(sensor.protocol)(
        connect_config(
            sensor.metadata,
            sensor_id=sensor.id,
            sensor_type=sensor.type,
            poll_interval_ms=sensor.poll_interval_ms,
            calibration=sensor.calibration,
        )
    )


def _config(profile: str, sensors: list[SensorConfig]) -> Any:
    return SimpleNamespace(
        device=SimpleNamespace(deployment_profile=profile, deployment_type="pi"),
        security={"enforce_production_posture": False},
        actions=SimpleNamespace(relay={}, coap={}),
        sensors=sensors,
        reasoning=SimpleNamespace(default_tier="rule", local_model="", model_path=""),
        hal=SimpleNamespace(status_signaling={}),
    )


@pytest.mark.parametrize("protocol", sorted(PROTOCOL_DEFINITIONS))
def test_every_protocol_module_names_what_it_lacks(protocol: str) -> None:
    assert callable(protocol_library_check(protocol))


def test_a_module_without_the_check_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module(PROTOCOL_DEFINITIONS["http"].module)
    monkeypatch.delattr(module, "missing_library")
    with pytest.raises(ValueError, match="missing_library"):
        protocol_library_check("http")


def _guarded_flags(path: Path) -> set[str]:
    """Flags a module sets False in a top-level `except ImportError`."""
    flags: set[str] = set()
    for node in ast.parse(path.read_text()).body:
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            names = ast.unparse(handler.type) if handler.type else ""
            if "ImportError" not in names:
                continue
            for statement in handler.body:
                if (
                    isinstance(statement, ast.Assign)
                    and isinstance(statement.value, ast.Constant)
                    and statement.value.value is False
                ):
                    flags |= {
                        t.id for t in statement.targets if isinstance(t, ast.Name)
                    }
    return flags


def test_every_guarded_import_of_a_protocol_module_is_covered() -> None:
    """A new optional import in an adapter module must be named here."""
    covered = {(module, flag) for module, flag, _lib in GUARDED.values()}
    covered |= set(OPTIONAL)
    modules = {d.module for d in PROTOCOL_DEFINITIONS.values()} | {"ori.hal.mqtt_base"}
    for module in sorted(modules):
        path = HAL / f"{module.rsplit('.', 1)[1]}.py"
        for flag in _guarded_flags(path):
            assert (module, flag) in covered, f"{module}.{flag} is not covered"


def _catches_an_import_failure(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return False
    names = {
        n.id if isinstance(n, ast.Name) else getattr(n, "attr", "")
        for n in ast.walk(handler.type)
    }
    return bool(names & {"ImportError", "ModuleNotFoundError"})


def test_every_hal_module_that_guards_an_import_is_accounted_for() -> None:
    """At any depth, in any ori/hal module, helpers included: a guarded import
    is either named by its module's missing_library or listed with its reason."""
    accounted = {m for m, _f, _l in GUARDED.values()}
    accounted |= {m for m, _f in OPTIONAL} | CHECKED_OTHERWISE
    for path in sorted(HAL.glob("*.py")):
        guarded = any(
            _catches_an_import_failure(handler)
            for node in ast.walk(ast.parse(path.read_text()))
            if isinstance(node, ast.Try)
            for handler in node.handlers
        )
        module = f"ori.hal.{path.stem}"
        assert not guarded or module in accounted, f"{module} guards an import"


@pytest.mark.parametrize("protocol", sorted(GUARDED))
def test_a_missing_library_is_named(
    protocol: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, flag, library = GUARDED[protocol]
    monkeypatch.setattr(importlib.import_module(module), flag, False)
    reason = _check(_sensor(protocol))
    assert reason is not None and library in reason
    monkeypatch.setattr(importlib.import_module(module), flag, True)
    assert _check(_sensor(protocol)) is None


def test_a_smart_sensor_needs_smartctl(monkeypatch: pytest.MonkeyPatch) -> None:
    from ori.hal import smart_adapter

    monkeypatch.setattr(smart_adapter.shutil, "which", lambda name: None)
    reason = _check(_sensor("smart", "drive_temp_celsius"))
    assert reason is not None and "smartctl" in reason
    monkeypatch.setattr(smart_adapter.shutil, "which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(smart_adapter, "_PYSMART_AVAILABLE", False)
    assert _check(_sensor("smart", "drive_temp_celsius")) is None


def test_an_i2c_sensor_names_its_chip_drivers(monkeypatch: pytest.MonkeyPatch) -> None:
    from ori.hal import i2c_adapter

    monkeypatch.setattr(
        i2c_adapter, "i2c_driver_unavailable_reason", lambda kind: f"{kind} driver"
    )
    assert _check(_sensor("i2c", "bme280")) == "bme280 driver"


@pytest.mark.parametrize("profile", ["staging", "production"])
def test_a_hardened_start_refuses_a_sensor_its_install_cannot_serve(
    profile: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from ori.hal import mqtt_base

    monkeypatch.setattr(mqtt_base, "_AIOMQTT_AVAILABLE", False)
    config = _config(profile, [_sensor("psutil"), _sensor("mqtt")])
    with pytest.raises(ConfigValidationError, match=r"'mqtt-1'.*aiomqtt"):
        validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))


def test_a_hardened_start_with_every_library_present_passes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from ori.hal import mqtt_base

    monkeypatch.setattr(mqtt_base, "_AIOMQTT_AVAILABLE", True)
    config = _config("production", [_sensor("psutil"), _sensor("mqtt")])
    validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))


def test_development_keeps_a_sensor_its_install_cannot_serve(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from ori.hal import mqtt_base

    monkeypatch.setattr(mqtt_base, "_AIOMQTT_AVAILABLE", False)
    config = _config("development", [_sensor("mqtt")])
    validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))
