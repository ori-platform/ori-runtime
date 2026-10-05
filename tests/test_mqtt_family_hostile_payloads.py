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
import math
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from ori.hal.base import (
    AdapterReadError,
    MeasurementRefusedError,
    refuse_unusable_reading,
)
from ori.hal.lorawan_adapter import LoraWanAdapter
from ori.hal.mqtt_adapter import MqttAdapter
from ori.hal.mqtt_perception_adapter import MqttPerceptionAdapter
from ori.hal.victron_adapter import VictronAdapter
from ori.hal.zigbee_adapter import ZigbeeAdapter
from ori.network.events import SensorReading
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


NOT_JSON_NUMBERS = ["NaN", "Infinity", "-Infinity", "1e400"]


@pytest.mark.parametrize(
    ("adapter_type", "config", "sensor_id", "valid", "value", "wrap"), ADAPTERS
)
async def test_a_number_json_does_not_have_withdraws_the_cached_value(
    adapter_type: type,
    config: dict[str, Any],
    sensor_id: str,
    valid: Any,
    value: float,
    wrap: Any,
) -> None:
    """Python's json reads NaN, Infinity and 1e400; none of them is JSON.

    Each is refused, and the refusal withdraws the value it would have
    replaced: the earlier value is not served as current.
    """
    available, module = _patched()
    with available, module:
        adapter, client, topic = await _connected(adapter_type, config)
        try:
            for token in NOT_JSON_NUMBERS:
                await _delivered(client, topic, valid)
                assert (await adapter.read(sensor_id)).value == pytest.approx(value)
                await _delivered(client, topic, wrap(token).encode())
                with pytest.raises(AdapterReadError, match="was refused"):
                    await adapter.read(sensor_id)
            await _delivered(client, topic, valid)
            assert (await adapter.read(sensor_id)).value == pytest.approx(value)
        finally:
            await adapter.close()


@pytest.mark.parametrize("token", NOT_JSON_NUMBERS)
async def test_a_perception_timestamp_json_does_not_have_is_refused(token: str) -> None:
    """A cached non-finite timestamp made every read raise until the next message."""
    available, module = _patched()
    with available, module:
        config = perception_config()
        adapter, client, topic = await _connected(MqttPerceptionAdapter, config)
        try:
            body = (
                '{"schema": "ori.perception.v1", "sensor_type": '
                '"ppe_hardhat_violation_score", "value": 0.5, "confidence": 0.9, '
                '"timestamp_ms": ' + token + "}"
            )
            await _delivered(client, topic, body.encode())
            with pytest.raises(AdapterReadError, match="was refused"):
                await adapter.read("ppe-hardhat-cam-01")
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
async def test_a_lost_connection_is_silent_then_reconnects(
    adapter_type: type,
    config: dict[str, Any],
    sensor_id: str,
    valid: Any,
    value: float,
    wrap: Any,
) -> None:
    """A lost broker refuses reads and opens the breaker; the reconnect resumes.

    The cached value does not survive the connection it arrived on, so reads
    refuse after reconnecting until a new value arrives, which closes the
    breaker at once.
    """
    available, module = _patched()
    with available, module, patch("ori.hal.mqtt_base.reconnect_delay", lambda _a: 0):
        adapter, client, topic = await _connected(adapter_type, config)
        try:
            await _delivered(client, topic, valid)
            assert (await adapter.read(sensor_id)).value == pytest.approx(value)
            listener = adapter._listener_task
            gate = asyncio.Event()
            original_open = adapter._open_client

            async def held_open() -> None:
                await gate.wait()
                await original_open()

            adapter._open_client = held_open
            await client._queue.put(_LostConnection())
            for _ in range(5):
                await asyncio.sleep(0)
            threshold = adapter._breaker.failure_threshold
            for _ in range(threshold):
                with pytest.raises(AdapterReadError, match="connection is down"):
                    await adapter.read(sensor_id)
            with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
                await adapter.read(sensor_id)

            gate.set()
            for _ in range(10):
                await asyncio.sleep(0)
            assert adapter._listener_task is listener and not listener.done()
            fresh = adapter._client
            assert fresh is not client and isinstance(fresh, _FakeClient)
            assert fresh.subscriptions == client.subscriptions
            with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
                await adapter.read(sensor_id)
            await _delivered(fresh, topic, valid)
            assert (await adapter.read(sensor_id)).value == pytest.approx(value)
        finally:
            await adapter.close()


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("[" + "9" * 5000 + "]", id="integer-past-the-digit-limit"),
        pytest.param("[" * 20000, id="nesting-past-the-recursion-limit"),
        pytest.param("{", id="truncated"),
        pytest.param('{"value": NaN}', id="nan"),
        pytest.param('{"value": -Infinity}', id="infinity"),
        pytest.param('{"value": 1e400}', id="float-overflowing-to-infinity"),
    ],
)
def test_the_shared_loader_refuses_what_is_not_json(text: str) -> None:
    from ori.hal.mqtt_base import load_json_payload

    with pytest.raises(AdapterReadError, match="not valid JSON"):
        load_json_payload(text, "MQTT")


def test_a_value_float_cannot_hold_is_refused() -> None:
    from ori.hal.mqtt_base import MqttCachedAdapter

    with pytest.raises(AdapterReadError, match="not numeric"):
        MqttCachedAdapter.parse_numeric_payload('{"value": ' + "9" * 400 + "}")


@pytest.mark.parametrize("text", ["nan", "inf", "-Infinity", "1e400"])
def test_a_plain_text_value_that_is_not_finite_is_refused(text: str) -> None:
    from ori.hal.mqtt_base import MqttCachedAdapter

    with pytest.raises(AdapterReadError, match="not finite"):
        MqttCachedAdapter.parse_numeric_payload(text)


def _reading(**overrides: Any) -> SensorReading:
    fields: dict[str, Any] = {
        "sensor_id": "chiller-temp-01",
        "sensor_type": "temperature",
        "value": 27.4,
        "unit": "celsius",
        "timestamp": 1_710_000_000_123,
        "quality": 0.9,
    }
    fields.update(overrides)
    return SensorReading(**fields)


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"value": math.nan}, id="nan-value"),
        pytest.param({"value": math.inf}, id="infinite-value"),
        pytest.param({"value": True}, id="boolean-value"),
        pytest.param({"value": 2**63}, id="integer-past-sqlite-integer"),
        pytest.param({"value": "27.4"}, id="string-value"),
        pytest.param({"timestamp": 2**63}, id="timestamp-past-sqlite-integer"),
        pytest.param({"timestamp": -1}, id="negative-timestamp"),
        pytest.param({"timestamp": 1.5}, id="float-timestamp"),
        pytest.param({"quality": math.nan}, id="nan-quality"),
        pytest.param({"quality": 1.5}, id="quality-above-one"),
        pytest.param({"quality": 10**400}, id="quality-past-float-range"),
    ],
)
def test_an_unusable_reading_is_refused_as_a_measurement(
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(MeasurementRefusedError):
        refuse_unusable_reading(_reading(**overrides))


def test_a_usable_reading_passes() -> None:
    refuse_unusable_reading(_reading())
    refuse_unusable_reading(_reading(value=0, timestamp=2**63 - 1, quality=1.0))
    refuse_unusable_reading(_reading(value=-(2**63)))


@pytest.mark.parametrize(
    ("adapter_type", "config", "sensor_id", "valid", "value", "wrap"), ADAPTERS
)
async def test_no_value_survives_the_connection_it_arrived_on(
    adapter_type: type,
    config: dict[str, Any],
    sensor_id: str,
    valid: Any,
    value: float,
    wrap: Any,
) -> None:
    """After a reconnect, with the breaker never opened, the old value is gone."""
    available, module = _patched()
    with available, module, patch("ori.hal.mqtt_base.reconnect_delay", lambda _a: 0):
        adapter, client, topic = await _connected(adapter_type, config)
        try:
            await _delivered(client, topic, valid)
            await client._queue.put(_LostConnection())
            for _ in range(10):
                await asyncio.sleep(0)
            assert adapter._link_up and adapter._client is not client
            with pytest.raises(AdapterReadError, match="no .* cached yet"):
                await adapter.read(sensor_id)
        finally:
            await adapter.close()


@pytest.mark.parametrize("stable", [False, True], ids=["flapping", "stable"])
async def test_a_link_that_drops_at_once_keeps_backing_off(stable: bool) -> None:
    """A broker that accepts and drops must not be redialled at the base delay."""
    attempts: list[int] = []
    available, module = _patched()
    with (
        available,
        module,
        patch("ori.hal.mqtt_base.reconnect_delay", lambda a: attempts.append(a) or 0),
        patch("ori.hal.mqtt_base.RECONNECT_STABLE_S", 0.0 if stable else 3600.0),
    ):
        adapter, client, _topic_name = await _connected(MqttAdapter, mqtt_config())
        try:
            for _ in range(4):
                await adapter._client._queue.put(_LostConnection())
                for _ in range(10):
                    await asyncio.sleep(0)
            assert len(attempts) == 4
            assert attempts == ([0, 0, 0, 0] if stable else [0, 1, 2, 3])
        finally:
            await adapter.close()


async def test_a_broker_that_never_answers_leaves_nothing_open() -> None:
    aiomqtt = pytest.importorskip("aiomqtt")
    held: list[asyncio.StreamWriter] = []

    async def accept_and_hold(_reader: Any, writer: asyncio.StreamWriter) -> None:
        held.append(writer)

    server = await asyncio.start_server(accept_and_hold, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    built: list[Any] = []

    class Recording(aiomqtt.Client):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            built.append(self)

    adapter = MqttAdapter()
    try:
        with patch("ori.hal.mqtt_base._aiomqtt", SimpleNamespace(Client=Recording)):
            with pytest.raises(Exception):
                await adapter.connect(
                    {
                        **mqtt_config(),
                        "broker_host": "127.0.0.1",
                        "port": port,
                        "mqtt": {"timeout": 0.3},
                    }
                )
        assert built, "no client was built"
        for client in built:
            assert client._client.socket() is None, "paho's socket was left open"
            task = getattr(client, "_misc_task", None)
            if task is not None:
                for _ in range(10):
                    await asyncio.sleep(0)
                assert task.done(), "aiomqtt's misc task was left running"
    finally:
        await adapter.close()
        for writer in held:
            writer.close()
        server.close()
        await server.wait_closed()
