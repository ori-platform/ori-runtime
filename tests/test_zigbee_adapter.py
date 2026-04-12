# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ori.hal.base import AdapterConnectionError, AdapterReadError, CircuitState
from ori.hal.zigbee_adapter import ZigbeeAdapter


def _config(
    *,
    sensor_type: str = "temperature",
    topic: str = "zigbee2mqtt/living-room",
    failure_threshold: int = 3,
    extra: dict | None = None,
) -> dict:
    base = {
        "sensor_id": "living-room-temp",
        "sensor_type": sensor_type,
        "broker_host": "192.168.1.55",
        "port": 1883,
        "topic": topic,
        "circuit_breaker": {
            "failure_threshold": failure_threshold,
            "recovery_timeout_s": 300,
            "success_threshold": 2,
        },
    }
    if extra:
        base.update(extra)
    return base


class _FakeTopic:
    def __init__(self, value: str):
        self._value = value

    def __str__(self) -> str:
        return self._value


class _FakeMessage:
    def __init__(self, topic: str, payload: bytes | str):
        self.topic = _FakeTopic(topic)
        self.payload = payload


class _FakeMessageStream:
    def __init__(self, queue: asyncio.Queue):
        self._queue = queue

    def __aiter__(self):
        return self

    async def __anext__(self):
        return await self._queue.get()


class _FakeClient:
    def __init__(self, *, hostname: str, port: int, **kwargs):
        self.hostname = hostname
        self.port = port
        self.kwargs = kwargs
        self.subscriptions: list[str] = []
        self._queue: asyncio.Queue = asyncio.Queue()
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc, _tb):
        self.closed = True

    async def subscribe(self, topic: str) -> None:
        self.subscriptions.append(topic)

    @property
    def messages(self):
        return _FakeMessageStream(self._queue)

    async def emit(self, topic: str, payload: bytes | str) -> None:
        await self._queue.put(_FakeMessage(topic, payload))


class TestZigbeeAdapter:
    @pytest.mark.asyncio
    async def test_graceful_import_failure(self):
        adapter = ZigbeeAdapter()
        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", False),
            patch("ori.hal.mqtt_base._aiomqtt", None),
        ):
            with pytest.raises(AdapterConnectionError, match="aiomqtt"):
                await adapter.connect(_config())
            assert adapter.is_connected is False

    @pytest.mark.asyncio
    async def test_read_temperature_from_json_payload(self):
        adapter = ZigbeeAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)

        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            cfg = _config(sensor_type="temperature")
            await adapter.connect(cfg)
            payload = {
                "temperature": 28.6,
                "humidity": 62.4,
                "last_seen": 1710001111,
                "quality": 0.93,
            }
            assert isinstance(adapter._client, _FakeClient)
            await adapter._client.emit(cfg["topic"], json.dumps(payload).encode())
            await asyncio.sleep(0)

            reading = await adapter.read("living-room-temp")
            assert reading.sensor_type == "temperature"
            assert reading.value == pytest.approx(28.6)
            assert reading.unit == "celsius"
            assert reading.quality == pytest.approx(1.0)
            assert reading.metadata["source"] == "zigbee"
            assert reading.metadata["topic"] == cfg["topic"]
            await adapter.close()

    @pytest.mark.asyncio
    async def test_custom_value_and_quality_paths(self):
        adapter = ZigbeeAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)
        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            cfg = _config(
                sensor_type="motion",
                extra={"value_path": "state.motion", "quality_path": "state.conf"},
            )
            await adapter.connect(cfg)
            payload = {"state": {"motion": True, "conf": 0.78}}
            assert isinstance(adapter._client, _FakeClient)
            await adapter._client.emit(cfg["topic"], json.dumps(payload).encode())
            await asyncio.sleep(0)

            reading = await adapter.read("living-room-temp")
            assert reading.value == pytest.approx(1.0)
            assert reading.quality == pytest.approx(0.78)
            await adapter.close()

    @pytest.mark.asyncio
    async def test_no_data_yet_raises(self):
        adapter = ZigbeeAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)
        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            await adapter.connect(_config())
            with pytest.raises(AdapterReadError, match="no MQTT data cached yet"):
                await adapter.read("living-room-temp")
            await adapter.close()

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        adapter = ZigbeeAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)
        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            await adapter.connect(_config(failure_threshold=2))
            with pytest.raises(AdapterReadError, match="no MQTT data cached yet"):
                await adapter.read("living-room-temp")
            assert adapter._breaker is not None
            assert adapter._breaker.state == CircuitState.CLOSED

            with pytest.raises(AdapterReadError, match="no MQTT data cached yet"):
                await adapter.read("living-room-temp")
            assert adapter._breaker.state == CircuitState.OPEN

            with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
                await adapter.read("living-room-temp")
            await adapter.close()
