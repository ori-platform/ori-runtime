# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A sensor setting connect would refuse is refused at config load.

A timeout below 1 ms, non-finite or too large for a float expires before any
exchange completes or cannot be read at all, and an ADS1115 calibration the
measurement cannot use is refused at connect. Either way the adapter would be
built and scheduled, and then fail every connect or poll.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

from ori.config import Config, ConfigValidationError
from ori.hal.base import MIN_TIMEOUT_S, AdapterConnectionError, timeout_seconds
from ori.hal.coap_adapter import CoapAdapter
from ori.hal.http_adapter import HttpAdapter
from ori.hal.mqtt_adapter import MqttAdapter
from ori.hal.protocol_registry import MQTT_FAMILY_PROTOCOLS, protocol_schemas
from ori.hal.serial_adapter import SerialAdapter
from ori.hal.usb_serial_adapter import UsbSerialAdapter

# The last is 10**400: an integer no float can hold.
REFUSED = ["0", "0.0001", "0.00099", ".nan", ".inf", "-.inf", "1" + "0" * 400]
ACCEPTED = ["0.001", "5"]

# Every spelling an operator may write, through the loader's alias precedence.
SPELLINGS = {
    "mqtt.timeout": "mqtt:\n  timeout: {v}",
    "mqtt.mqtt_timeout_s": "mqtt:\n  mqtt_timeout_s: {v}",
    "mqtt_timeout_s": "mqtt_timeout_s: {v}",
    "timeout": "timeout: {v}",
}


MQTT_SENSOR = (
    "type: temperature\nunit: celsius\nprotocol: mqtt\n"
    "broker_host: 127.0.0.1\ntopic: t/1\n"
)


def _load(tmp_path: Path, sensor_extra: str, sensor: str = MQTT_SENSOR) -> Config:
    (tmp_path / "skills").mkdir(exist_ok=True)
    body = textwrap.indent(sensor + sensor_extra, " " * 4)
    cfg = tmp_path / "ori.yaml"
    cfg.write_text(
        "device:\n  id: dev-01\n  name: T\n  location: L\n"
        "sensors:\n"
        "  - id: s1\n"
        f"{body}\n"
        "skills: []\n"
        "reasoning:\n  default_tier: rule\n"
        'gateway:\n  enabled: false\n  broker_url: ""\n'
        "actions:\n  primary_alert_channel: sms\n"
        '  operator_contact: "+2348000000000"\n'
        "  whatsapp: {enabled: false}\n  sms: {enabled: false}\n"
        "  relay: {enabled: false}\n"
        f"skills_dir: {tmp_path / 'skills'}\n"
        f"database:\n  path: {tmp_path / 'ori_state.db'}\n",
        encoding="utf-8",
    )
    return Config.load(str(cfg))


@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
@pytest.mark.parametrize("value", REFUSED)
def test_an_mqtt_timeout_below_the_floor_is_refused_at_load(
    tmp_path: Path, spelling: str, value: str
) -> None:
    with pytest.raises(ConfigValidationError, match="below the minimum|not a finite"):
        _load(tmp_path, SPELLINGS[spelling].format(v=value))


@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
@pytest.mark.parametrize("value", ACCEPTED)
def test_an_mqtt_timeout_at_or_above_the_floor_loads(
    tmp_path: Path, spelling: str, value: str
) -> None:
    config = _load(tmp_path, SPELLINGS[spelling].format(v=value))
    assert config.sensors[0].metadata["mqtt"]["timeout"] == float(value)


SERIAL_SENSOR = "type: current\nprotocol: serial\nport: /dev/ttyUSB0\n"


def test_a_serial_timeout_too_large_for_a_float_is_refused_at_load(
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigValidationError, match="not a finite"):
        _load(tmp_path, "timeout: 1" + "0" * 400, sensor=SERIAL_SENSOR)


ADS_SENSOR = (
    "type: ads1115_current\nprotocol: i2c\naddress: 0x48\n"
    "channel: 0\ncalibration:\n  sensitivity_v_per_amp: 0.0333\n"
    "  mains_frequency_hz: 50\n"
)


@pytest.mark.parametrize(
    "setting",
    [
        "sensitivity_v_per_amp: 0",
        "gain: 0",
        "gain: 3",
        "overrun_tolerance: 0",
        "clip_margin_volts: 0",
        "data_rate: 1",
        "data_rate: 8",
    ],
)
def test_a_calibration_connect_would_refuse_is_refused_at_load(
    tmp_path: Path, setting: str
) -> None:
    key = setting.split(":")[0]
    sensor = "\n".join(
        line for line in ADS_SENSOR.splitlines() if not line.strip().startswith(key)
    )
    with pytest.raises(ConfigValidationError, match=r"protocol='i2c'\): I2CAdapter"):
        _load(tmp_path, "", sensor=f"{sensor}\n  {setting}\n")


def test_a_usable_calibration_loads(tmp_path: Path) -> None:
    config = _load(tmp_path, "", sensor=ADS_SENSOR)
    assert config.sensors[0].calibration["sensitivity_v_per_amp"] == 0.0333


@pytest.mark.parametrize("protocol", sorted(MQTT_FAMILY_PROTOCOLS))
def test_every_mqtt_family_protocol_declares_the_floor(protocol: str) -> None:
    schema, _ = protocol_schemas(protocol)
    timeout = schema.fields["mqtt"]["properties"]["timeout"]
    assert timeout["minimum"] == MIN_TIMEOUT_S


@pytest.mark.parametrize(
    ("protocol", "field"),
    [
        ("http", "timeout_s"),
        ("coap", "timeout_s"),
        ("serial", "timeout"),
        ("usb_serial", "timeout_s"),
    ],
)
def test_the_request_timeout_protocols_declare_the_floor(
    protocol: str, field: str
) -> None:
    schema, _ = protocol_schemas(protocol)
    assert schema.fields[field]["minimum"] == MIN_TIMEOUT_S


def _http_config(timeout_s: float) -> dict[str, Any]:
    return {
        "sensor_id": "s1",
        "sensor_type": "temperature",
        "url": "http://example.local/metrics",
        "json_path": "main.temp",
        "timeout_s": timeout_s,
    }


def _coap_config(timeout_s: float) -> dict[str, Any]:
    return {
        "sensor_id": "s1",
        "sensor_type": "temperature",
        "uri": "coap://192.168.1.70/x",
        "json_path": "value",
        "allowed_hosts": ["192.168.1.70"],
        "timeout_s": timeout_s,
    }


@pytest.mark.parametrize(
    "value", [0.0, 0.0009, float("nan"), float("inf"), float("-inf")]
)
@pytest.mark.parametrize(
    ("adapter", "config"),
    [(HttpAdapter, _http_config), (CoapAdapter, _coap_config)],
    ids=["http", "coap"],
)
async def test_a_direct_caller_meets_the_same_floor(
    adapter: Any, config: Any, value: float, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The floor is checked before the client library is touched.
    monkeypatch.setattr("ori.hal.coap_adapter._AIOCOAP_AVAILABLE", True)
    monkeypatch.setattr("ori.hal.coap_adapter._aiocoap", object())
    with pytest.raises(AdapterConnectionError, match="at least"):
        await adapter().connect(config(value))


@pytest.mark.parametrize("value", [MIN_TIMEOUT_S, 5.0])
async def test_a_direct_caller_at_the_floor_is_accepted(
    value: float, monkeypatch: pytest.MonkeyPatch
) -> None:
    kwargs = MqttAdapter()._build_mqtt_client_kwargs({"mqtt": {"timeout": value}})
    assert kwargs["timeout"] == value
    monkeypatch.setattr("ori.hal.coap_adapter._AIOCOAP_AVAILABLE", True)
    monkeypatch.setattr("ori.hal.coap_adapter._aiocoap", object())
    for adapter, config in (
        (HttpAdapter(), _http_config),
        (CoapAdapter(), _coap_config),
    ):
        try:
            await adapter.connect(config(value))
        except AdapterConnectionError as exc:
            assert "at least" not in str(exc)
        finally:
            await adapter.close()
        assert adapter._timeout_s == value


@pytest.mark.parametrize(
    "value",
    [True, "5", "bad", None, 10**400, float("nan")],
    ids=["bool", "numeric-str", "str", "none", "huge", "nan"],
)
def test_a_direct_caller_gets_the_same_type_check(value: Any) -> None:
    with pytest.raises(AdapterConnectionError, match="at least"):
        timeout_seconds(value, "Adapter")


@pytest.mark.parametrize("value", [True, "bad", 10**400], ids=["bool", "str", "huge"])
async def test_every_direct_adapter_refuses_a_malformed_timeout(
    value: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(AdapterConnectionError, match="at least"):
        MqttAdapter()._build_mqtt_client_kwargs({"mqtt": {"timeout": value}})
    monkeypatch.setattr("ori.hal.coap_adapter._AIOCOAP_AVAILABLE", True)
    monkeypatch.setattr("ori.hal.coap_adapter._aiocoap", object())
    for adapter, config in ((HttpAdapter, _http_config), (CoapAdapter, _coap_config)):
        with pytest.raises(AdapterConnectionError, match="at least"):
            await adapter().connect(config(value))


@pytest.mark.parametrize(
    "value", [True, "bad", 10**400, 0.0005], ids=["bool", "str", "huge", "sub-ms"]
)
async def test_the_serial_adapters_refuse_a_malformed_timeout(
    value: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("ori.hal.serial_adapter._SERIAL_AVAILABLE", True)
    monkeypatch.setattr("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", True)
    monkeypatch.setattr("ori.hal.usb_serial_adapter._serial_module", object())
    with pytest.raises(AdapterConnectionError, match="at least"):
        await SerialAdapter().connect(
            {"sensor_type": "current", "port": "/dev/null", "timeout": value}
        )
    with pytest.raises(AdapterConnectionError, match="at least"):
        await UsbSerialAdapter().connect(
            {
                "sensor_type": "usb_current",
                "device_path": "/dev/null",
                "timeout_s": value,
            }
        )


@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
@pytest.mark.parametrize("value", [None, ""], ids=["null", "empty"])
def test_an_mqtt_timeout_written_null_or_empty_is_refused_directly(
    spelling: str, value: Any
) -> None:
    config: dict[str, Any] = {}
    if spelling.startswith("mqtt."):
        config["mqtt"] = {spelling.removeprefix("mqtt."): value}
    else:
        config[spelling] = value
    with pytest.raises(AdapterConnectionError, match="at least"):
        MqttAdapter()._build_mqtt_client_kwargs(config)


def test_an_mqtt_timeout_left_out_is_not_set() -> None:
    assert "timeout" not in MqttAdapter()._build_mqtt_client_kwargs({})
