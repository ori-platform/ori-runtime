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


# Every guarded import in ori/hal, by module and imported package, with what
# names it to a hardened start. A new one, at any depth, must be added here.
DEPENDENCIES = {
    ("ori.hal.coap_adapter", "aiocoap"): "coap missing_library",
    ("ori.hal.growatt_adapter", "pysolarmanv5"): "growatt missing_library",
    ("ori.hal.http_adapter", "httpx"): "http missing_library",
    ("ori.hal.i2c_adapter", "smbus2"): "i2c_driver_unavailable_reason",
    ("ori.hal.i2c_adapter", "bme280"): "i2c_driver_unavailable_reason",
    ("ori.hal.i2c_adapter", "adafruit_ads1x15"): "i2c_driver_unavailable_reason",
    ("ori.hal.i2c_adapter", "board"): "i2c_driver_unavailable_reason (blinka)",
    ("ori.hal.i2c_adapter", "busio"): "i2c_driver_unavailable_reason (blinka)",
    ("ori.hal.i2c_adapter", "adafruit_scd4x"): "i2c_driver_unavailable_reason",
    ("ori.hal.mqtt_base", "aiomqtt"): "mqtt_base missing_library, re-exported",
    ("ori.hal.opcua_adapter", "asyncua"): "opcua missing_library",
    ("ori.hal.serial_adapter", "serial"): "serial missing_library",
    ("ori.hal.smart_adapter", "pySMART"): OPTIONAL[
        ("ori.hal.smart_adapter", "_PYSMART_AVAILABLE")
    ],
    ("ori.hal.solarman_modbus_adapter", "pysolarmanv5"): "solarman missing_library",
    ("ori.hal.usb_serial_adapter", "serial"): "usb_serial missing_library",
}

_IMPORT_FAILURES = {"ImportError", "ModuleNotFoundError"}


def _names(expr: ast.AST, aliases: dict[str, set[str]]) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(expr):
        if isinstance(node, ast.Name):
            found |= {node.id} | aliases.get(node.id, set())
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
    return found


def _guarded_imports(path: Path, module: str) -> set[tuple[str, str]]:
    """(module, package) for each import inside a `try` that catches an import
    failure, at any depth, by name or through a module-level tuple of them."""
    tree = ast.parse(path.read_text())
    aliases = {
        target.id: _names(statement.value, {})
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        for target in statement.targets
        if isinstance(target, ast.Name)
    }
    found: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try) or not any(
            h.type is not None and _names(h.type, aliases) & _IMPORT_FAILURES
            for h in node.handlers
        ):
            continue
        for statement in node.body:
            for child in ast.walk(statement):
                if isinstance(child, ast.Import):
                    found |= {(module, a.name.split(".")[0]) for a in child.names}
                elif (
                    isinstance(child, ast.ImportFrom)
                    and child.module
                    and not child.level
                ):
                    found.add((module, child.module.split(".")[0]))
    return found


def _hal_guarded_imports(root: Path = HAL) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for path in sorted(root.rglob("*.py")):
        module = ".".join(("ori", "hal", *path.relative_to(root).with_suffix("").parts))
        found |= _guarded_imports(path, module)
    return found


def test_every_guarded_import_in_hal_is_accounted_for() -> None:
    """Each dependency, not each module: a new import in a covered module fails."""
    assert _hal_guarded_imports() == set(DEPENDENCIES)


def test_the_guard_sees_a_nested_import_in_a_covered_module(tmp_path: Path) -> None:
    package = tmp_path / "hal" / "helpers"
    package.mkdir(parents=True)
    (tmp_path / "hal" / "http_adapter.py").write_text(
        "def connect():\n"
        "    try:\n"
        "        import newlib\n"
        "    except ModuleNotFoundError:\n"
        "        pass\n"
    )
    (package / "probe.py").write_text(
        "FAILS = (ImportError, RuntimeError)\n"
        "def load():\n"
        "    try:\n"
        "        from otherlib import thing\n"
        "    except FAILS:\n"
        "        pass\n"
    )
    assert _hal_guarded_imports(tmp_path / "hal") == {
        ("ori.hal.http_adapter", "newlib"),
        ("ori.hal.helpers.probe", "otherlib"),
    }


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


@pytest.mark.parametrize(
    ("system", "tool"), [("Linux", "systemd-inhibit"), ("Darwin", "pmset")]
)
def test_a_sleep_assertion_sensor_needs_its_platform_tool(
    system: str, tool: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ori.hal import psutil_adapter

    monkeypatch.setattr(psutil_adapter.platform, "system", lambda: system)
    monkeypatch.setattr(psutil_adapter.shutil, "which", lambda name: None)
    reason = _check(_sensor("psutil", "sleep_blocking_process"))
    assert reason is not None and tool in reason
    monkeypatch.setattr(psutil_adapter.shutil, "which", lambda name: f"/bin/{name}")
    assert _check(_sensor("psutil", "sleep_blocking_process")) is None
    monkeypatch.setattr(psutil_adapter.platform, "system", lambda: "Windows")
    assert _check(_sensor("psutil", "sleep_blocking_process")) is not None


def test_cpu_temperature_needs_a_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    from ori.hal import psutil_adapter

    monkeypatch.setattr(psutil_adapter.shutil, "which", lambda name: None)
    monkeypatch.delattr(psutil_adapter.psutil, "sensors_temperatures", raising=False)
    monkeypatch.setattr(psutil_adapter.platform, "system", lambda: "Darwin")
    reason = _check(_sensor("psutil", "cpu_temp"))
    assert reason is not None and "osx-cpu-temp" in reason
    monkeypatch.setattr(psutil_adapter.shutil, "which", lambda name: f"/bin/{name}")
    assert _check(_sensor("psutil", "cpu_temp")) is None
    monkeypatch.setattr(psutil_adapter.platform, "system", lambda: "Windows")
    assert _check(_sensor("psutil", "cpu_temp")) is not None
    monkeypatch.setattr(
        psutil_adapter.psutil, "sensors_temperatures", lambda: {}, raising=False
    )
    assert _check(_sensor("psutil", "cpu_temp")) is None
    assert _check(_sensor("psutil", "cpu_percent")) is None


async def test_the_startup_stage_refuses_before_the_store_opens(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from ori.hal import mqtt_base
    from ori.runtime import OriRuntime, _startup_foundation
    from ori.startup_stages import StartupContext

    monkeypatch.setattr(mqtt_base, "_AIOMQTT_AVAILABLE", False)
    config = _config("production", [_sensor("mqtt")])
    monkeypatch.setattr(
        _startup_foundation.Config, "load", staticmethod(lambda path: config)
    )
    runtime = OriRuntime(config_path=str(tmp_path / "ori.yaml"))
    with pytest.raises(ConfigValidationError, match=r"'mqtt-1'.*aiomqtt"):
        await runtime._stage_configuration(StartupContext())
    assert runtime._state_store is None


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
