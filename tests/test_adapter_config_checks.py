# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Config load runs each adapter's own configuration check, as connect() does.

A sensor setting connect would refuse from the configuration alone is refused
at `Config.load`, naming the sensor, before any adapter is built. A direct
caller gets the same refusal from `connect()`.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

import pytest
import yaml

from ori.config import Config, ConfigValidationError
from ori.hal import protocol_registry as registry
from ori.hal.base import AdapterConnectionError, BaseAdapter

MQTT = "broker_host: 127.0.0.1\n"

# One usable sensor per protocol. A test below holds this to the registry.
VALID: dict[str, str] = {
    "psutil": "type: cpu_percent\n",
    "i2c": "type: bme280\naddress: 0x76\n",
    "serial": "type: voltage\nport: /dev/ttyUSB0\n",
    "solarman_modbus": (
        "type: growatt_pv_power\nprofile: growatt_spf\nhost: 192.168.1.20\n"
        'serial: "123"\n'
    ),
    "growatt": 'type: growatt_grid_power\nhost: 192.168.1.20\nserial: "123"\n',
    "victron": f"type: victron_battery_soc\n{MQTT}portal_id: abc123\n",
    "zigbee": f"type: temperature\n{MQTT}topic: zigbee2mqtt/room\n",
    "lorawan": f"type: lorawan_temperature\n{MQTT}topic: v3/app/up\n",
    "mqtt": f"type: temperature\n{MQTT}topic: t/1\n",
    "mqtt_perception": f"type: ppe_hardhat_violation_score\n{MQTT}topic: p/1\n",
    "usb_serial": "type: usb_voltage\ndevice_path: /dev/ttyUSB0\n",
    "http": "type: temperature\nurl: http://192.168.1.9/x\njson_path: v\n",
    "coap": "type: temperature\nuri: coap://192.168.1.70/x\njson_path: v\n",
    "opcua": 'type: temperature\nurl: opc.tcp://192.168.1.9:4840\nnode_id: "ns=2;i=2"\n',
    "smart": "type: drive_temp_celsius\ndevice: /dev/sda\n",
}

ADS = (
    "type: ads1115_current\naddress: 0x48\ncalibration:\n"
    "  sensitivity_v_per_amp: 0.0333\n  mains_frequency_hz: 50\n"
)

# (protocol, sensor, a fragment the refusal must carry)
REFUSED: list[tuple[str, str, str]] = [
    ("opcua", 'type: t\nurl: " "\nnode_id: "ns=2;i=2"\n', "'url'"),
    ("opcua", 'type: t\nurl: opc.tcp://h:4840\nnode_id: " "\n', "'node_id'"),
    ("growatt", 'type: growatt_grid_power\nhost: " "\nserial: "123"\n', "'host'"),
    ("growatt", 'type: growatt_grid_power\nhost: h\nserial: " "\n', "'serial'"),
    ("growatt", 'type: temperature\nhost: h\nserial: "123"\n', "'temperature'"),
    (
        "solarman_modbus",
        'type: growatt_pv_power\nprofile: nonexistent\nhost: h\nserial: "1"\n',
        "'nonexistent'",
    ),
    (
        "solarman_modbus",
        'type: deye_grid_power\nprofile: growatt_spf\nhost: h\nserial: "1"\n',
        "has no metric 'deye_grid_power'",
    ),
    (
        "solarman_modbus",
        'type: growatt_pv_power\nprofile: growatt_spf\nhost: " "\nserial: "1"\n',
        "'host'",
    ),
    (
        "solarman_modbus",
        'type: growatt_pv_power\nprofile: growatt_spf\nhost: h\nserial: " "\n',
        "'serial'",
    ),
    ("smart", "type: temperature\ndevice: /dev/sda\n", "'temperature'"),
    ("smart", 'type: drive_temp_celsius\ndevice: ""\n', "'device'"),
    ("mqtt_perception", f"type: temperature\n{MQTT}topic: p/1\n", "'temperature'"),
    (
        "mqtt_perception",
        f'type: ppe_vest_violation_score\n{MQTT}topic: " "\n',
        "'topic'",
    ),
    ("victron", f"type: temperature\n{MQTT}portal_id: abc\n", "'temperature'"),
    ("victron", f'type: victron_pv_power\n{MQTT}portal_id: " "\n', "'portal_id'"),
    ("zigbee", f'type: temperature\n{MQTT}topic: z/1\nvalue_path: ""\n', "value_path"),
    ("zigbee", f"type: pressure\n{MQTT}topic: z/1\n", "value_path"),
    ("zigbee", f'type: temperature\n{MQTT}topic: " "\n', "'topic'"),
    (
        "lorawan",
        f'type: lorawan_temperature\n{MQTT}topic: v3/up\nvalue_path: ""\n',
        "value_path",
    ),
    ("lorawan", f"type: temperature\n{MQTT}topic: v3/up\n", "value_path"),
    ("mqtt", f'type: temperature\n{MQTT}topic: " "\n', "'topic'"),
    ("mqtt", 'type: temperature\nbroker_host: " "\ntopic: t/1\n', "'broker_host'"),
    (
        "victron",
        'type: victron_pv_power\nbroker_host: ""\nportal_id: a\n',
        "broker_host",
    ),
    ("http", 'type: t\nurl: " "\njson_path: v\n', "'url'"),
    ("http", 'type: t\nurl: http://h/x\njson_path: " "\n', "'json_path'"),
    ("coap", 'type: t\nuri: coap://192.168.1.70/x\njson_path: " "\n', "'json_path'"),
    ("coap", "type: t\nuri: http://192.168.1.70/x\njson_path: v\n", "coap/coaps"),
    ("coap", "type: t\nuri: file:///etc/passwd\njson_path: v\n", "coap/coaps"),
    ("coap", "type: t\nuri: coap:///x\njson_path: v\n", "uri host"),
    (
        "coap",
        "type: t\nuri: coap://192.168.1.70/x\njson_path: v\n"
        'allowed_hosts: ["192.168.1.71"]\n',
        "not in allowed_hosts",
    ),
    ("serial", "type: usb_voltage\nport: /dev/ttyUSB0\n", "'usb_voltage'"),
    ("serial", 'type: voltage\nport: ""\n', "'port'"),
    ("usb_serial", "type: voltage\ndevice_path: /dev/ttyUSB0\n", "'voltage'"),
    ("usb_serial", 'type: usb_voltage\ndevice_path: ""\n', "'device_path'"),
    ("i2c", "type: temperature\naddress: 0x76\n", "'temperature'"),
    ("i2c", ADS + "  gain: 3\n", "gain"),
    ("i2c", ADS + "  data_rate: 8\n", "data_rate"),
    ("i2c", "type: ads1115_voltage\naddress: 0x48\nbus: 0\n", "bus 1"),
    ("i2c", ADS + "bus: 0\n", "bus 1"),
    ("i2c", "type: scd40\naddress: 0x62\nbus: 0\n", "bus 1"),
    ("psutil", "type: current\n", "'current'"),
]

# Inputs beside the refused ones that connect accepts.
NEIGHBOURS: list[tuple[str, str]] = [
    ("zigbee", f"type: pressure\n{MQTT}topic: z/1\nvalue_path: pressure\n"),
    ("lorawan", f"type: custom\n{MQTT}topic: v3/up\nvalue_path: decoded.x\n"),
    (
        "usb_serial",
        'type: usb_voltage\ndevice_path: ""\nauto_detect_device_path: true\n',
    ),
    ("usb_serial", "type: usb_voltage\nauto_detect_device_path: true\n"),
    (
        "solarman_modbus",
        'type: deye_grid_power\nprofile: deye_hybrid\nhost: h\nserial: "1"\n',
    ),
    (
        "coap",
        "type: t\nuri: coap://192.168.1.71/x\njson_path: v\n"
        'allowed_hosts: ["192.168.1.71"]\n',
    ),
    ("i2c", ADS),
    ("i2c", "type: ads1115_voltage\naddress: 0x48\nbus: 1\n"),
    ("i2c", "type: scd40\naddress: 0x62\nbus: 1\n"),
    # bme280 opens its bus through smbus2, which is not limited to bus 1.
    ("i2c", "type: bme280\naddress: 0x76\nbus: 0\n"),
    ("mqtt", f"type: anything\n{MQTT}topic: t/1\n"),
    ("opcua", 'type: anything\nurl: opc.tcp://h:4840\nnode_id: "ns=2;i=2"\n'),
]


def _config_text(tmp_path: Path, sensors: list[tuple[str, str]]) -> str:
    (tmp_path / "skills").mkdir(exist_ok=True)
    entries = "".join(
        f"  - id: s{i}\n    protocol: {protocol}\n" + textwrap.indent(sensor, " " * 4)
        for i, (protocol, sensor) in enumerate(sensors)
    )
    return (
        "device:\n  id: dev-01\n  name: T\n  location: L\n"
        f"sensors:\n{entries}"
        "skills: []\n"
        "reasoning:\n  default_tier: rule\n"
        'gateway:\n  enabled: false\n  broker_url: ""\n'
        "actions:\n  primary_alert_channel: sms\n"
        '  operator_contact: "+2348000000000"\n'
        "  whatsapp: {enabled: false}\n  sms: {enabled: false}\n"
        "  relay: {enabled: false}\n"
        '  coap: {enabled: false, allowed_hosts: ["192.168.1.70", "192.168.1.71"]}\n'
        f"skills_dir: {tmp_path / 'skills'}\n"
        f"database:\n  path: {tmp_path / 'ori_state.db'}\n"
    )


def _load(tmp_path: Path, sensors: list[tuple[str, str]]) -> Config:
    path = tmp_path / "ori.yaml"
    path.write_text(_config_text(tmp_path, sensors), encoding="utf-8")
    return Config.load(str(path))


class _Forbidden:
    """A driver stand-in: any use of it means the refusal came too late.

    Attribute access records the touch and raises AttributeError, as Python
    expects; `drivers_present` fails the test on any recorded touch, so code
    that catches the AttributeError or probes with a default is still caught.
    """

    def __init__(self, touches: list[str]) -> None:
        self._touches = touches

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        self._touches.append(name)
        raise AttributeError(f"driver touched: {name}")

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._touches.append("__call__")
        raise AssertionError("driver called")


@pytest.fixture
def drivers_present(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make every optional driver look installed, so connect reaches its checks."""
    touches: list[str] = []
    for module, flag, handle in (
        ("ori.hal.opcua_adapter", "_ASYNCUA_AVAILABLE", "_AsyncUaClient"),
        ("ori.hal.http_adapter", "_HTTPX_AVAILABLE", "_httpx"),
        ("ori.hal.coap_adapter", "_AIOCOAP_AVAILABLE", "_aiocoap"),
        ("ori.hal.serial_adapter", "_SERIAL_AVAILABLE", "serial"),
        ("ori.hal.usb_serial_adapter", "_PYSERIAL_AVAILABLE", "_serial_module"),
        ("ori.hal.growatt_adapter", "_PYSOLARMAN_AVAILABLE", "_PySolarmanV5"),
        ("ori.hal.solarman_modbus_adapter", "_PYSOLARMAN_AVAILABLE", "_PySolarmanV5"),
        ("ori.hal.mqtt_base", "_AIOMQTT_AVAILABLE", "_aiomqtt"),
    ):
        target = import_module(module)
        monkeypatch.setattr(target, flag, True)
        monkeypatch.setattr(target, handle, _Forbidden(touches))
    yield
    assert not touches, f"a driver was touched before the refusal: {touches}"


def _connect_config(sensor: str) -> dict[str, Any]:
    """The mapping connect() receives for this sensor, as the runtime builds it."""
    fields = yaml.safe_load(sensor)
    sensor_type = fields.pop("type")
    calibration = fields.pop("calibration", {})
    # What config load inherits from actions.coap.allowed_hosts in _config_text.
    fields.setdefault("allowed_hosts", ["192.168.1.70", "192.168.1.71"])
    return {
        **fields,
        "sensor_id": "s0",
        "sensor_type": sensor_type,
        "poll_interval_ms": 1000,
        "calibration": calibration,
    }


def test_every_protocol_has_a_valid_sensor_here() -> None:
    assert set(VALID) == set(registry.PROTOCOL_DEFINITIONS)


def test_a_usable_sensor_of_every_protocol_loads(tmp_path: Path) -> None:
    config = _load(tmp_path, sorted(VALID.items()))
    assert sorted(sensor.protocol for sensor in config.sensors) == sorted(VALID)


@pytest.mark.parametrize(("protocol", "sensor"), NEIGHBOURS)
def test_a_neighbouring_valid_input_loads(
    tmp_path: Path, protocol: str, sensor: str
) -> None:
    assert _load(tmp_path, [(protocol, sensor)]).sensors[0].protocol == protocol


@pytest.mark.parametrize(("protocol", "sensor", "fragment"), REFUSED)
def test_a_setting_connect_refuses_is_refused_at_load(
    tmp_path: Path, protocol: str, sensor: str, fragment: str
) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        _load(tmp_path, [("psutil", VALID["psutil"]), (protocol, sensor)])
    message = str(excinfo.value)
    assert f"sensors[1] (id='s1', protocol='{protocol}')" in message
    assert fragment in message


@pytest.mark.asyncio
@pytest.mark.usefixtures("drivers_present")
@pytest.mark.parametrize(("protocol", "sensor", "fragment"), REFUSED)
async def test_connect_gives_a_direct_caller_the_same_refusal(
    tmp_path: Path, protocol: str, sensor: str, fragment: str
) -> None:
    adapter = registry.make_adapter(protocol)
    with pytest.raises(AdapterConnectionError) as at_connect:
        await adapter.connect(_connect_config(sensor))
    assert fragment in str(at_connect.value)
    with pytest.raises(ConfigValidationError) as at_load:
        _load(tmp_path, [(protocol, sensor)])
    assert str(at_load.value).endswith(str(at_connect.value))


@pytest.mark.parametrize("protocol", sorted(VALID))
def test_the_check_accepts_what_loads(protocol: str) -> None:
    registry.protocol_config_check(protocol)(_connect_config(VALID[protocol]))


def test_every_protocol_declares_its_check_without_construction() -> None:
    def forbid(self: BaseAdapter, *args: Any, **kwargs: Any) -> None:
        raise AssertionError(f"resolving the check constructed {type(self).__name__}")

    owners = {BaseAdapter}
    for definition in registry.PROTOCOL_DEFINITIONS.values():
        adapter_class = getattr(import_module(definition.module), definition.class_name)
        owners.add(next(k for k in adapter_class.__mro__ if "__init__" in vars(k)))
    with contextlib.ExitStack() as stack:
        for owner in owners:
            stack.enter_context(mock.patch.object(owner, "__init__", forbid))
        for protocol in registry.PROTOCOL_DEFINITIONS:
            assert callable(registry.protocol_config_check(protocol))


def _without_check(monkeypatch: pytest.MonkeyPatch) -> None:
    real = import_module("ori.hal.psutil_adapter")
    stub = SimpleNamespace(
        CONFIG_SCHEMA=real.CONFIG_SCHEMA,
        CALIBRATION_SCHEMAS=real.CALIBRATION_SCHEMAS,
        PsutilAdapter=real.PsutilAdapter,
    )
    monkeypatch.setattr(
        registry,
        "import_module",
        lambda name: stub if name == "ori.hal.psutil_adapter" else import_module(name),
    )


def test_a_protocol_without_a_check_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _without_check(monkeypatch)
    with pytest.raises(ValueError) as excinfo:
        registry.protocol_config_check("psutil")
    for name in ("psutil", "ori.hal.psutil_adapter", registry.CONFIG_CHECK_NAME):
        assert name in str(excinfo.value)


def test_config_load_refuses_a_protocol_without_a_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _without_check(monkeypatch)
    with pytest.raises(ConfigValidationError, match=registry.CONFIG_CHECK_NAME):
        _load(tmp_path, [("psutil", VALID["psutil"])])


_BLOCKED = (
    "aiocoap",
    "aiomqtt",
    "paho",
    "asyncua",
    "httpx",
    "serial",
    "pySMART",
    "pysolarmanv5",
    "smbus",
    "smbus2",
    "bme280",
    "board",
    "busio",
    "adafruit_ads1x15",
    "adafruit_blinka",
    "adafruit_scd4x",
)

_BLOCKED_LOAD = """
import sys

BLOCKED = set(sys.argv[2].split(","))


class Block:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in BLOCKED:
            raise ImportError(f"blocked: {name}")
        return None


sys.meta_path.insert(0, Block())
from ori.config import Config, ConfigValidationError

config = Config.load(sys.argv[1])
loaded = sorted(sensor.protocol for sensor in config.sensors)
leaked = sorted(name for name in sys.modules if name.split(".")[0] in BLOCKED)
try:
    Config.load(sys.argv[3])
except ConfigValidationError as exc:
    refused = str(exc)
else:
    refused = ""
print(loaded, leaked, refused, sep="\\n")
"""


def test_config_load_needs_no_optional_driver(tmp_path: Path) -> None:
    valid = tmp_path / "valid"
    valid.mkdir()
    (valid / "ori.yaml").write_text(
        _config_text(valid, sorted(VALID.items())), encoding="utf-8"
    )
    refused = tmp_path / "refused"
    refused.mkdir()
    (refused / "ori.yaml").write_text(
        _config_text(refused, [("opcua", REFUSED[0][1])]), encoding="utf-8"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            _BLOCKED_LOAD,
            str(valid / "ori.yaml"),
            ",".join(_BLOCKED),
            str(refused / "ori.yaml"),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert result.returncode == 0, result.stderr
    loaded, leaked, refusal = result.stdout.splitlines()[-3:]
    assert loaded == str(sorted(VALID))
    assert leaked == "[]"
    assert "'url' is required" in refusal


# Refusals the schema makes first at load, so only a direct caller reaches them.
CONNECT_ONLY: list[tuple[str, dict[str, Any], str]] = [
    ("growatt", {"port": 0}, "'port'"),
    ("solarman_modbus", {"port": -1}, "'port'"),
    ("mqtt", {"port": 0}, "'port'"),
    ("http", {"poll_interval_ms": 99}, "poll_interval_ms"),
    ("coap", {"poll_interval_ms": 99}, "poll_interval_ms"),
    ("coap", {"method": "PATCH"}, "method"),
    ("i2c", {"address": 72.0}, "address"),
    ("i2c", {"bus": True}, "bus"),
    ("i2c", {"channel": "0"}, "channel"),
]


@pytest.mark.asyncio
@pytest.mark.usefixtures("drivers_present")
@pytest.mark.parametrize(("protocol", "override", "fragment"), CONNECT_ONLY)
async def test_connect_refuses_what_the_schema_refuses_first_at_load(
    protocol: str, override: dict[str, Any], fragment: str
) -> None:
    config = {**_connect_config(VALID[protocol]), **override}
    with pytest.raises(AdapterConnectionError, match=fragment):
        registry.protocol_config_check(protocol)(config)
    with pytest.raises(AdapterConnectionError, match=fragment):
        await registry.make_adapter(protocol).connect(config)


def test_load_checks_the_mapping_the_runtime_connects_with(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ori.runtime._device_io import adapter_connect_config

    seen: dict[str, dict[str, Any]] = {}

    def spy(protocol: str) -> Any:
        return lambda config: seen.setdefault(config["sensor_id"], dict(config))

    monkeypatch.setattr("ori.config._sensors.protocol_config_check", spy)
    config = _load(tmp_path, sorted(VALID.items()))
    for sensor in config.sensors:
        connected = adapter_connect_config(sensor, config)
        connected.pop("circuit_breaker")
        assert seen[sensor.id] == connected
