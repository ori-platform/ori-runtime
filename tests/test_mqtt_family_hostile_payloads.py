# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""No single MQTT message stops a sensor, and a stopped listener is a silent one.

Every MQTT-family adapter caches what its listener delivers and serves that
cache on read. A payload that ended the listener used to freeze the sensor at
its last value: reads kept succeeding, the runtime kept recording the sensor as
seen, and a Tier D condition evaluated a value that no longer changed.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from ori.hal.base import AdapterReadError
from ori.hal.lorawan_adapter import LoraWanAdapter
from ori.hal.mqtt_adapter import MqttAdapter
from ori.hal.mqtt_perception_adapter import MqttPerceptionAdapter
from ori.hal.victron_adapter import VictronAdapter
from ori.hal.zigbee_adapter import ZigbeeAdapter
from tests.test_lorawan_adapter import _config as lorawan_config
from tests.test_mqtt_adapter import _config as mqtt_config
from tests.test_mqtt_adapter import _FakeClient
from tests.test_mqtt_perception_adapter import _config as perception_config
from tests.test_victron_adapter import _config as victron_config
from tests.test_zigbee_adapter import _config as zigbee_config

HUGE_INTEGER = "9" * 5000  # past json's integer digit limit: ValueError
OVERFLOWING = "9" * 400  # parses, then overflows float(): OverflowError
DEEP = "[" * 20000  # RecursionError


def _spec(
    name: str,
    adapter: type,
    config: dict[str, Any],
    sensor_id: str,
    valid: Any,
    value: float,
    wrap: Any,
) -> Any:
    return pytest.param(adapter, config, sensor_id, valid, value, wrap, id=name)


def _topic(adapter: Any, config: dict[str, Any]) -> str:
    if isinstance(adapter, VictronAdapter):
        return adapter._topic_for_sensor(config["sensor_type"])
    return config["topic"]


ADAPTERS = [
    _spec(
        "mqtt",
        MqttAdapter,
        mqtt_config(),
        "chiller-temp-01",
        {"reading": {"value": 27.4, "quality": 0.91}},
        27.4,
        lambda raw: '{"reading": {"value": ' + raw + ', "quality": 0.9}}',
    ),
    _spec(
        "lorawan",
        LoraWanAdapter,
        lorawan_config(sensor_type="lorawan_temperature"),
        "field-temp",
        {
            "uplink_message": {
                "decoded_payload": {"temperature": 32.4, "humidity": 77.1},
                "rx_metadata": [{"rssi": -89, "snr": 5.2}],
                "received_at": "2026-04-12T08:00:00Z",
            }
        },
        32.4,
        lambda raw: (
            '{"uplink_message": {"decoded_payload": {"temperature": ' + raw + "}}}"
        ),
    ),
    _spec(
        "zigbee",
        ZigbeeAdapter,
        zigbee_config(),
        "living-room-temp",
        {
            "temperature": 28.6,
            "humidity": 62.4,
            "last_seen": 1710001111,
            "quality": 0.93,
        },
        28.6,
        lambda raw: '{"temperature": ' + raw + "}",
    ),
    _spec(
        "mqtt_perception",
        MqttPerceptionAdapter,
        perception_config(),
        "ppe-hardhat-cam-01",
        {
            "schema": "ori.perception.v1",
            "sensor_type": "ppe_hardhat_violation_score",
            "value": 0.88,
            "confidence": 0.92,
            "timestamp_ms": 1710000000123,
            "metadata": {"zone_id": "line-3", "camera_id": "cam-01"},
        },
        0.88,
        lambda raw: (
            '{"schema": "ori.perception.v1", "sensor_type": "ppe_hardhat_violation_score", "value": '
            + raw
            + ', "confidence": 0.5}'
        ),
    ),
    _spec(
        "victron",
        VictronAdapter,
        victron_config(sensor_type="victron_battery_soc"),
        "victron-01",
        {"value": 84.5},
        84.5,
        lambda raw: '{"value": ' + raw + "}",
    ),
]


async def _connected(
    adapter_type: type, config: dict[str, Any]
) -> tuple[Any, _FakeClient, str]:
    adapter = adapter_type()
    await adapter.connect(config)
    client = adapter._client
    assert isinstance(client, _FakeClient)
    return adapter, client, _topic(adapter, config)


async def _delivered(client: _FakeClient, topic: str, payload: Any) -> None:
    body = (
        payload if isinstance(payload, (bytes, str)) else json.dumps(payload).encode()
    )
    await client.emit(topic, body)
    for _ in range(5):
        await asyncio.sleep(0)


def _patched() -> Any:
    fake = SimpleNamespace(Client=_FakeClient)
    return (
        patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
        patch("ori.hal.mqtt_base._aiomqtt", fake),
    )


@pytest.mark.parametrize(
    ("adapter_type", "config", "sensor_id", "valid", "value", "wrap"), ADAPTERS
)
async def test_a_hostile_payload_is_refused_and_the_next_one_is_read(
    adapter_type: type,
    config: dict[str, Any],
    sensor_id: str,
    valid: Any,
    value: float,
    wrap: Any,
) -> None:
    available, module = _patched()
    with available, module:
        adapter, client, topic = await _connected(adapter_type, config)
        try:
            hostile = [
                wrap(HUGE_INTEGER).encode(),
                DEEP.encode(),
                wrap(OVERFLOWING).encode(),
                b"\xff\xfe{\x00",
            ]
            for payload in hostile:
                await _delivered(client, topic, payload)
            listener = adapter._listener_task
            assert listener is not None and not listener.done(), (
                "a payload ended the listener"
            )
            await _delivered(client, topic, valid)
            reading = await adapter.read(sensor_id)
            assert reading.value == pytest.approx(value)
        finally:
            await adapter.close()


async def test_an_unexpected_handler_error_does_not_end_the_listener() -> None:
    """A payload no parser anticipated is skipped like any refused one."""
    available, module = _patched()
    with available, module:
        adapter, client, topic = await _connected(MqttAdapter, mqtt_config())
        original = adapter._handle_message
        failures = {"left": 1}

        async def once(message_topic: str, payload: Any) -> None:
            if failures["left"]:
                failures["left"] -= 1
                raise RuntimeError("a defect in a message handler")
            await original(message_topic, payload)

        adapter._handle_message = once
        try:
            await _delivered(client, topic, {"reading": {"value": 1.0, "quality": 0.9}})
            await _delivered(
                client, topic, {"reading": {"value": 27.4, "quality": 0.9}}
            )
            listener = adapter._listener_task
            assert listener is not None and not listener.done()
            reading = await adapter.read("chiller-temp-01")
            assert reading.value == pytest.approx(27.4)
        finally:
            await adapter.close()


class _LostConnection:
    """A message whose topic fails, as a dropped connection surfaces from the stream."""

    @property
    def topic(self) -> Any:
        raise RuntimeError("connection lost")

    payload = b""


@pytest.mark.parametrize(
    ("adapter_type", "config", "sensor_id", "valid", "value", "wrap"), ADAPTERS
)
async def test_a_stopped_listener_makes_the_sensor_silent(
    adapter_type: type,
    config: dict[str, Any],
    sensor_id: str,
    valid: Any,
    value: float,
    wrap: Any,
) -> None:
    """Once the listener stops, the cached value is refused rather than served."""
    available, module = _patched()
    with available, module:
        adapter, client, topic = await _connected(adapter_type, config)
        try:
            await _delivered(client, topic, valid)
            assert (await adapter.read(sensor_id)).value == pytest.approx(value)
            await client._queue.put(_LostConnection())
            for _ in range(5):
                await asyncio.sleep(0)
            listener = adapter._listener_task
            assert listener is not None and listener.done(), (
                "the listener survived its stream"
            )
            with pytest.raises(AdapterReadError, match="listener is not running"):
                await adapter.read(sensor_id)
        finally:
            await adapter.close()


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("[" + "9" * 5000 + "]", id="integer-past-the-digit-limit"),
        pytest.param("[" * 20000, id="nesting-past-the-recursion-limit"),
        pytest.param("{", id="truncated"),
    ],
)
def test_the_shared_loader_refuses_what_json_refuses(text: str) -> None:
    from ori.hal.mqtt_base import load_json_payload

    with pytest.raises(AdapterReadError, match="not valid JSON"):
        load_json_payload(text, "MQTT")


def test_a_value_float_cannot_hold_is_refused() -> None:
    from ori.hal.mqtt_base import MqttCachedAdapter

    with pytest.raises(AdapterReadError, match="not numeric"):
        MqttCachedAdapter.parse_numeric_payload('{"value": ' + "9" * 400 + "}")
