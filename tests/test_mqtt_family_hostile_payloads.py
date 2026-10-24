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
import contextlib
import errno
import gc
import json
import logging
import math
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
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
from tests.waiting import DEADLINE_S, HOLD_S, settle, wait_until

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


@pytest.mark.parametrize("watched", [True, False], ids=["watch", "no-watch"])
async def test_a_broker_that_never_answers_leaves_nothing_open(watched: bool) -> None:
    """With no watch installed, the failure path closes the socket itself."""
    aiomqtt = pytest.importorskip("aiomqtt")
    from ori.hal import mqtt_base

    install = mqtt_base._ConnectWatch.install if watched else (lambda *_a: None)
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
        with (
            patch("ori.hal.mqtt_base._aiomqtt", SimpleNamespace(Client=Recording)),
            patch("ori.hal.mqtt_base.reconnect_delay", lambda _a: 3600.0),
            patch.object(mqtt_base._ConnectWatch, "install", install),
        ):
            await adapter.connect(
                {
                    **mqtt_config(),
                    "broker_host": "127.0.0.1",
                    "port": port,
                    "mqtt": {"timeout": 0.3},
                }
            )
            assert adapter.connection_retrying and adapter._client is None
        await _assert_abandoned(built, aiomqtt)
    finally:
        await adapter.close()
        for writer in held:
            writer.close()
        server.close()
        await server.wait_closed()


async def test_an_abandoned_connect_schedules_nothing_on_its_closed_socket() -> None:
    """A retried silent broker must not make the loop log EBADF per attempt."""
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

    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    errors: list[str] = []
    loop.set_exception_handler(
        lambda _loop, context: errors.append(
            f"{context.get('message')} {context.get('exception')!r}"
        )
    )
    adapter = MqttAdapter()
    try:
        with (
            patch("ori.hal.mqtt_base._aiomqtt", SimpleNamespace(Client=Recording)),
            patch("ori.hal.mqtt_base.reconnect_delay", lambda _a: 0.01),
        ):
            await adapter.connect(
                {
                    **mqtt_config(),
                    "broker_host": "127.0.0.1",
                    "port": port,
                    "mqtt": {"timeout": 0.1},
                }
            )
            await wait_until(
                lambda: len(built) >= 4 and built[-1]._client.socket() is not None,
                what="three abandoned retries and a fourth awaiting CONNACK",
            )
            await adapter.close()
        await _assert_abandoned(built, aiomqtt)
        assert not errors, errors
    finally:
        loop.set_exception_handler(previous)
        await adapter.close()
        for writer in held:
            writer.close()
        server.close()
        await server.wait_closed()


async def _assert_abandoned(built: list[Any], aiomqtt: Any) -> None:
    assert built, "no client was built"
    for client in built:
        assert client._client.socket() is None, "paho's socket was left open"
        assert hasattr(client, "_misc_task"), (
            f"aiomqtt {getattr(aiomqtt, '__version__', '?')} no longer has "
            "_misc_task; _abandon_half_open must be revisited for it"
        )
        task = client._misc_task
        for _ in range(10):
            await asyncio.sleep(0)
        assert task is None or task.done(), "aiomqtt's misc task was left running"


async def test_a_connect_cancelled_mid_handshake_leaves_nothing_open() -> None:
    """close() while the broker has not answered: the cancel reaches the handshake."""
    aiomqtt = pytest.importorskip("aiomqtt")
    held: list[asyncio.StreamWriter] = []
    accepted = asyncio.Event()

    async def accept_and_hold(_reader: Any, writer: asyncio.StreamWriter) -> None:
        held.append(writer)
        accepted.set()

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
            connecting = asyncio.create_task(
                adapter.connect(
                    {
                        **mqtt_config(),
                        "broker_host": "127.0.0.1",
                        "port": port,
                        "mqtt": {"timeout": 30},
                    }
                )
            )
            await asyncio.wait_for(accepted.wait(), 5)
            await asyncio.sleep(0.05)
            connecting.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(connecting, 5)
        await _assert_abandoned(built, aiomqtt)
    finally:
        await adapter.close()
        for writer in held:
            writer.close()
        server.close()
        await server.wait_closed()


class _GatedConnect:
    """Holds paho's socket connect in aiomqtt's executor thread until released.

    The first call can fail as a broker that is down, so the held attempt is a
    retry; the socket is then opened for real, after the adapter let go.
    """

    def __init__(self, paho: Any, *, fail_first: bool) -> None:
        self._original = paho.Client._create_socket_connection
        self._fail_first = fail_first
        self.entered = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.socket: Any = None

    def method(self) -> Any:
        """A plain function, so the class attribute binds as a method."""

        def gated(client: Any) -> Any:
            return self(client)

        return gated

    def __call__(self, client: Any) -> Any:
        if self._fail_first:
            self._fail_first = False
            raise ConnectionRefusedError(61, "Connection refused")
        self.entered.set()
        self.release.wait(HOLD_S)
        try:
            self.socket = self._original(client)
            return self.socket
        finally:
            self.finished.set()


async def _closed_by_peer(reader: asyncio.StreamReader) -> bool:
    return await reader.read(4096) == b""


@pytest.mark.parametrize("where", ["connect", "retry"])
async def test_a_close_while_the_connect_thread_connects_leaves_no_socket(
    where: str,
) -> None:
    aiomqtt = pytest.importorskip("aiomqtt")
    paho = pytest.importorskip("paho.mqtt.client")
    accepted: list[asyncio.StreamReader] = []
    writers: list[asyncio.StreamWriter] = []

    async def accept_and_hold(reader: Any, writer: asyncio.StreamWriter) -> None:
        accepted.append(reader)
        writers.append(writer)

    server = await asyncio.start_server(accept_and_hold, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    gate = _GatedConnect(paho, fail_first=where == "retry")
    built: list[Any] = []

    class Recording(aiomqtt.Client):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            built.append(self)

    adapter = MqttAdapter()
    try:
        with (
            patch.object(paho.Client, "_create_socket_connection", gate.method()),
            patch("ori.hal.mqtt_base._aiomqtt", SimpleNamespace(Client=Recording)),
            patch("ori.hal.mqtt_base.reconnect_delay", lambda _a: 0.001),
        ):
            connecting = asyncio.create_task(
                adapter.connect(
                    {
                        **mqtt_config(),
                        "broker_host": "127.0.0.1",
                        "port": port,
                        "mqtt": {"timeout": 30},
                    }
                )
            )
            if where == "retry":
                await settle({connecting}, what="the connect at start to return")
                assert adapter.connection_retrying
            await wait_until(gate.entered.is_set, what="the connect thread to start")
            if where == "retry":
                stopping = asyncio.create_task(adapter.close())
            else:
                connecting.cancel()
                stopping = connecting
            await wait_until(
                lambda: adapter._abandoned_connects, what="the abandoned connect"
            )
            gate.release.set()
            await settle({stopping}, what="the close")
            assert gate.finished.is_set(), "close returned before the thread finished"
            assert built[-1]._client.socket() is None, "the late socket is open"
        await wait_until(lambda: accepted, what="the thread's late connection")
        assert len(accepted) == 1
        await wait_until(
            lambda: _closed_by_peer(accepted[0]), what="the late socket to be closed"
        )
        assert not adapter._abandoned_connects
    finally:
        gate.release.set()
        await adapter.close()
        for writer in writers:
            writer.close()
        server.close()
        await server.wait_closed()


async def test_a_connect_thread_past_the_bound_is_closed_when_it_finishes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    aiomqtt = pytest.importorskip("aiomqtt")
    paho = pytest.importorskip("paho.mqtt.client")
    accepted: list[asyncio.StreamReader] = []
    writers: list[asyncio.StreamWriter] = []

    async def accept_and_hold(reader: Any, writer: asyncio.StreamWriter) -> None:
        accepted.append(reader)
        writers.append(writer)

    server = await asyncio.start_server(accept_and_hold, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    gate = _GatedConnect(paho, fail_first=True)
    adapter = MqttAdapter()
    try:
        with (
            patch.object(paho.Client, "_create_socket_connection", gate.method()),
            patch("ori.hal.mqtt_base._aiomqtt", aiomqtt),
            patch("ori.hal.mqtt_base.reconnect_delay", lambda _a: 0.001),
            patch("ori.hal.mqtt_base.ABANDONED_CONNECT_WAIT_S", 0.01),
            caplog.at_level(logging.WARNING, logger="ori.hal.mqtt_base"),
        ):
            await adapter.connect(
                {**mqtt_config(), "broker_host": "127.0.0.1", "port": port}
            )
            await wait_until(gate.entered.is_set, what="the connect thread to start")
            await adapter.close()
            assert "still running" in caplog.text
            gate.release.set()
        await wait_until(lambda: accepted, what="the thread's late connection")
        await wait_until(
            lambda: _closed_by_peer(accepted[0]), what="the late socket to be closed"
        )
    finally:
        gate.release.set()
        for writer in writers:
            writer.close()
        server.close()
        await server.wait_closed()


async def test_the_connect_watch_installs_on_the_installed_aiomqtt() -> None:
    """A dependency bump that renames the hook must fail here, not leak silently."""
    aiomqtt = pytest.importorskip("aiomqtt")
    from ori.hal.mqtt_base import _ConnectWatch

    client = aiomqtt.Client(hostname="127.0.0.1", port=1)
    assert _ConnectWatch.install(client, "test") is not None, (
        f"aiomqtt {getattr(aiomqtt, '__version__', '?')} has no _client_connect"
    )


async def test_a_missing_connect_hook_is_warned_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from ori.hal import mqtt_base

    mqtt_base._warn_connect_watch_unavailable.cache_clear()
    try:
        with caplog.at_level(logging.WARNING, logger="ori.hal.mqtt_base"):
            assert mqtt_base._ConnectWatch.install(SimpleNamespace(), "test") is None
            assert mqtt_base._ConnectWatch.install(SimpleNamespace(), "test") is None
        warnings = [r for r in caplog.records if "_client_connect" in r.getMessage()]
        assert len(warnings) == 1
        assert "aiomqtt" in warnings[0].getMessage()
    finally:
        mqtt_base._warn_connect_watch_unavailable.cache_clear()


class _OwnLoop:
    """An adapter on a loop the test retires itself, with a held retry.

    `abandon()` leaves a reconnect held inside paho's connect, abandoned by a
    close whose settling bound has passed, and the loop stopped but open.
    """

    def __init__(self, aiomqtt: Any, paho: Any) -> None:
        self.aiomqtt = aiomqtt
        self.paho = paho
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(DEADLINE_S)
        self.gate = _GatedConnect(paho, fail_first=True)
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.loop = asyncio.new_event_loop()
        self.loop.set_default_executor(self.executor)
        self.adapter = MqttAdapter()
        self.peers: list[socket.socket] = []
        self.watches: list[Any] = []

    def patched(self, owner_wait_s: float = 60.0) -> contextlib.ExitStack:
        from ori.hal import mqtt_base

        install = mqtt_base._ConnectWatch.install

        def recording(client: Any, label: str) -> Any:
            watch = install(client, label)
            self.watches.append(watch)
            return watch

        stack = contextlib.ExitStack()
        for patcher in (
            patch.object(
                self.paho.Client, "_create_socket_connection", self.gate.method()
            ),
            patch("ori.hal.mqtt_base._aiomqtt", self.aiomqtt),
            patch("ori.hal.mqtt_base.reconnect_delay", lambda _a: 0.001),
            patch("ori.hal.mqtt_base.ABANDONED_CONNECT_WAIT_S", 0.01),
            patch("ori.hal.mqtt_base.ABANDONED_SOCKET_OWNER_WAIT_S", owner_wait_s),
            patch("ori.hal.mqtt_base.REAPER_POLL_S", 0.02),
            patch.object(mqtt_base._ConnectWatch, "install", recording),
        ):
            stack.enter_context(patcher)
        return stack

    def abandon(self) -> None:
        port = self.listener.getsockname()[1]
        self.loop.run_until_complete(
            self.adapter.connect(
                {**mqtt_config(), "broker_host": "127.0.0.1", "port": port}
            )
        )
        self.loop.run_until_complete(
            wait_until(self.gate.entered.is_set, what="the retry to reach connect")
        )
        self.loop.run_until_complete(self.adapter.close())
        assert self.adapter._abandoned_connects, "the thread settled within the bound"

    def peer_reads_eof(self) -> bool:
        peer, _ = self.listener.accept()
        self.peers.append(peer)
        peer.settimeout(DEADLINE_S)
        return peer.recv(1) == b""

    def retire(self) -> None:
        self.gate.release.set()
        if not self.loop.is_closed():
            self.loop.close()
        self.executor.shutdown(wait=True)
        if self.gate.socket is not None:
            self.gate.socket.close()
        for peer in self.peers:
            peer.close()
        self.listener.close()


@pytest.fixture
def own_loop() -> Any:
    aiomqtt = pytest.importorskip("aiomqtt")
    paho = pytest.importorskip("paho.mqtt.client")
    fixture = _OwnLoop(aiomqtt, paho)
    yield fixture
    fixture.retire()


def test_a_late_socket_is_closed_when_the_loop_closed_first(own_loop: Any) -> None:
    """The post is refused, nothing queued can run, so the thread closes it."""
    with own_loop.patched():
        own_loop.abandon()
        own_loop.loop.close()
        own_loop.gate.release.set()
        own_loop.executor.shutdown(wait=True)
    assert own_loop.gate.socket.fileno() == -1, "the late socket is open"
    assert own_loop.peer_reads_eof()


def test_a_late_socket_is_closed_once_a_stopped_loop_closes(own_loop: Any) -> None:
    """Accepted by a stopped loop, the post is discarded when the loop closes."""
    loop = own_loop.loop
    posting = threading.Event()
    let_post = threading.Event()
    real_post = loop.call_soon_threadsafe

    def held_post(callback: Any, *args: Any, **kwargs: Any) -> Any:
        # Holds only the watch's own `_settle` post, so the milestone can be
        # seen not to precede it.
        if getattr(callback, "__name__", "") == "_settle":
            posting.set()
            let_post.wait(HOLD_S)
        return real_post(callback, *args, **kwargs)

    with own_loop.patched():
        own_loop.abandon()
        # Installed only now, so the failed first attempt's post is not held.
        loop.call_soon_threadsafe = held_post  # type: ignore[method-assign]
        own_loop.gate.release.set()
        watch = own_loop.watches[-1]  # the held retry, the last attempt made
        assert posting.wait(DEADLINE_S), "the worker never posted"
        assert not watch.post_accepted.is_set(), "the milestone preceded the post"
        let_post.set()
        assert watch.post_accepted.wait(DEADLINE_S), "the loop never took the post"
        assert own_loop.gate.socket.fileno() >= 0
        own_loop.loop.close()
        own_loop.executor.shutdown(wait=True)
        # The reaper closes it once it sees the loop closed.
        _wait_sync(
            lambda: own_loop.gate.socket.fileno() == -1, what="the reaper to close it"
        )
    assert watch._posted, "the post was refused, so this took the closed-loop path"
    assert own_loop.peer_reads_eof()


def test_a_resumed_loop_closes_the_late_socket_and_touches_no_other(
    own_loop: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """The thread must not close while the loop is open: the registrations its
    attempt queued would land on whatever socket reuses the descriptor."""
    loop = own_loop.loop
    with (
        own_loop.patched(owner_wait_s=0.3),
        caplog.at_level(logging.WARNING, logger="ori.hal.mqtt_base"),
    ):
        own_loop.abandon()
        own_loop.gate.release.set()
        own_loop.executor.shutdown(wait=True)
        _wait_sync(lambda: _cap_warnings(caplog), what="the cap to pass")
        late = own_loop.gate.socket
        assert late.fileno() >= 0, "closed off the loop while the loop is open"
        old_fd = late.fileno()
        left, right = socket.socketpair()
        own_loop.peers.extend([left, right])
        left.setblocking(False)
        received: list[bytes] = []

        def on_readable() -> None:
            received.append(left.recv(64))
            loop.remove_reader(left.fileno())

        loop.add_reader(left.fileno(), on_readable)
        right.send(b"owned-by-another-reader")
        loop.run_until_complete(
            wait_until(lambda: received, what="the unrelated reader's payload")
        )
        loop.run_until_complete(
            wait_until(lambda: late.fileno() == -1, what="the loop to close it")
        )
    assert received == [b"owned-by-another-reader"]
    assert not loop.remove_reader(old_fd) and not loop.remove_writer(old_fd)
    assert own_loop.peer_reads_eof()
    assert len(_cap_warnings(caplog)) == 1
    # The loop settled it, so the reaper drops it and, with nothing left, ends.
    from ori.hal import mqtt_base

    with patch("ori.hal.mqtt_base.REAPER_POLL_S", 0.02):
        _wait_sync(
            lambda: (
                not mqtt_base._REAPER._watches and mqtt_base._REAPER._thread is None
            ),
            what="the reaper to drop the settled watch and exit",
        )


def test_the_owner_wait_cap_ends_the_connection_and_holds_the_descriptor(
    own_loop: Any, caplog: pytest.LogCaptureFixture
) -> None:
    loop = own_loop.loop
    with (
        own_loop.patched(owner_wait_s=0.2),
        caplog.at_level(logging.WARNING, logger="ori.hal.mqtt_base"),
    ):
        own_loop.abandon()
        own_loop.gate.release.set()
        own_loop.executor.shutdown(wait=True)
        late = own_loop.gate.socket
        old_fd = late.fileno()
        _wait_sync(lambda: _cap_warnings(caplog), what="the cap to pass")
        _await_reaper_passes(2)
        assert old_fd != -1 and late.fileno() != -1, (
            "the descriptor was released while the loop is open"
        )
        assert own_loop.peer_reads_eof(), "the broker connection was not ended"
        other = socket.socket()
        own_loop.peers.append(other)
        assert other.fileno() != old_fd, "the held descriptor was reused"
        warnings = _cap_warnings(caplog)
        assert len(warnings) == 1
        assert "MqttAdapter 127.0.0.1:" in warnings[0].getMessage()
        loop.run_until_complete(
            wait_until(lambda: late.fileno() == -1, what="the resumed loop to close it")
        )
    assert not loop.remove_reader(old_fd) and not loop.remove_writer(old_fd)


async def test_a_connect_cancelled_after_paho_has_its_socket_touches_no_other() -> None:
    """Cancelled once paho holds its socket and aiomqtt has posted its
    registrations, but before the loop has run them: the socket must not be
    closed ahead of them, or they land on whatever socket reuses the descriptor.

    The unrelated socket is opened at the moment the adapter closes the late
    one, which is when another component's socket would take the number.
    """
    aiomqtt = pytest.importorskip("aiomqtt")
    paho = pytest.importorskip("paho.mqtt.client")
    from ori.hal import mqtt_base

    held: list[asyncio.StreamReader] = []
    writers: list[asyncio.StreamWriter] = []

    async def accept_and_hold(reader: Any, writer: asyncio.StreamWriter) -> None:
        held.append(reader)
        writers.append(writer)

    server = await asyncio.start_server(accept_and_hold, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    entered = threading.Event()
    release = threading.Event()
    posted = threading.Event()
    original_open = paho.Client._call_socket_open
    opened: list[Any] = []

    def held_open(client: Any, sock: Any) -> None:
        opened.append(sock)
        entered.set()
        release.wait(HOLD_S)
        original_open(client, sock)
        posted.set()

    loop = asyncio.get_running_loop()
    peers: list[socket.socket] = []
    received: list[bytes] = []
    original_abandon = mqtt_base._abandon_half_open

    def abandon_then_reuse(client: Any) -> None:
        original_abandon(client)
        if peers:
            return
        left, right = socket.socketpair()
        peers.extend([left, right])
        left.setblocking(False)

        def on_readable() -> None:
            received.append(left.recv(64))
            loop.remove_reader(left.fileno())

        loop.add_reader(left.fileno(), on_readable)
        right.send(b"owned-by-another-reader")

    adapter = MqttAdapter()
    try:
        with (
            patch.object(paho.Client, "_call_socket_open", held_open),
            patch("ori.hal.mqtt_base._aiomqtt", aiomqtt),
            patch("ori.hal.mqtt_base._abandon_half_open", abandon_then_reuse),
            patch("ori.hal.mqtt_base.reconnect_delay", lambda _a: 3600.0),
        ):
            connecting = asyncio.create_task(
                adapter.connect(
                    {
                        **mqtt_config(),
                        "broker_host": "127.0.0.1",
                        "port": port,
                        "mqtt": {"timeout": 30},
                    }
                )
            )
            await wait_until(entered.is_set, what="paho to hold its new socket")
            (late,) = opened
            old_fd = late.fileno()
            # Without yielding: the cancellation is queued first, then the
            # worker posts its registrations behind it.
            connecting.cancel()
            release.set()
            assert posted.wait(DEADLINE_S), "aiomqtt never posted its registrations"
            await settle({connecting}, what="the cancelled connect")
            await wait_until(lambda: peers, what="the late socket to be closed")
            await wait_until(lambda: received, what="the unrelated reader's payload")
        assert received == [b"owned-by-another-reader"]
        assert late.fileno() == -1
        if peers[0].fileno() != old_fd:
            assert not loop.remove_reader(old_fd) and not loop.remove_writer(old_fd)
        await wait_until(lambda: held, what="the server to see the connection")
        await wait_until(lambda: _closed_by_peer(held[0]), what="the peer to read EOF")
    finally:
        release.set()
        await adapter.close()
        for peer in peers:
            peer.close()
        for writer in writers:
            writer.close()
        server.close()
        await server.wait_closed()


def test_a_held_descriptor_is_closed_when_the_loop_closes_after_the_cap(
    own_loop: Any,
) -> None:
    """Past the cap the worker has returned; the reaper closes the descriptor
    when the owner closes its loop, with no help from garbage collection."""
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        with own_loop.patched(owner_wait_s=0.2):
            own_loop.abandon()
            own_loop.gate.release.set()
            own_loop.executor.shutdown(wait=True)
            late = own_loop.gate.socket
            old_fd = late.fileno()
            assert old_fd != -1 and own_loop.peer_reads_eof()
            # The reaper keeps what it has not closed, pass after pass.
            _await_reaper_passes(2)
            assert late.fileno() != -1
            own_loop.loop.close()
            _wait_sync(lambda: late.fileno() == -1, what="the reaper to close it")
        with pytest.raises(OSError) as caught:
            os.fstat(old_fd)
        assert caught.value.errno == errno.EBADF
    finally:
        if gc_was_enabled:
            gc.enable()


def _await_reaper_passes(count: int) -> None:
    from ori.hal import mqtt_base

    target = mqtt_base._REAPER.passes + count

    async def passed() -> None:
        await wait_until(
            lambda: (
                mqtt_base._REAPER.passes >= target or mqtt_base._REAPER._thread is None
            ),
            what=f"{count} reaper passes",
        )

    asyncio.run(passed())


def _wait_sync(predicate: Any, *, what: str) -> None:
    """`wait_until` for a synchronous test whose own loop is not running."""
    asyncio.run(wait_until(predicate, what=what))


def _cap_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if "neither run nor closed" in r.getMessage()]
