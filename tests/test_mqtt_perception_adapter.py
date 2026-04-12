# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ori.hal.base import AdapterConnectionError, AdapterReadError, CircuitState
from ori.hal.mqtt_perception_adapter import MqttPerceptionAdapter


def _config(
    sensor_type: str = "ppe_hardhat_violation_score",
    topic: str = "ori/perception/site-b/cam-01",
    failure_threshold: int = 3,
) -> dict:
    return {
        "sensor_id": "ppe-hardhat-cam-01",
        "sensor_type": sensor_type,
        "broker_host": "192.168.1.20",
        "port": 1883,
        "topic": topic,
        "circuit_breaker": {
            "failure_threshold": failure_threshold,
            "recovery_timeout_s": 300,
            "success_threshold": 2,
        },
    }


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


class TestMqttPerceptionAdapter:
    @pytest.mark.asyncio
    async def test_graceful_import_failure(self):
        adapter = MqttPerceptionAdapter()
        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", False),
            patch("ori.hal.mqtt_base._aiomqtt", None),
        ):
            with pytest.raises(AdapterConnectionError, match="aiomqtt"):
                await adapter.connect(_config())
            assert adapter.is_connected is False

    @pytest.mark.asyncio
    async def test_connect_stores_config(self):
        adapter = MqttPerceptionAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)

        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            cfg = _config(topic="ori/perception/site-b/cam-07")
            await adapter.connect(cfg)
            assert adapter.is_connected is True
            assert adapter._sensor_type == "ppe_hardhat_violation_score"
            assert adapter._topic == "ori/perception/site-b/cam-07"
            assert isinstance(adapter._client, _FakeClient)
            assert adapter._client.subscriptions == ["ori/perception/site-b/cam-07"]
            await adapter.close()

    @pytest.mark.asyncio
    async def test_read_valid_payload_maps_quality_and_metadata(self):
        adapter = MqttPerceptionAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)

        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            cfg = _config()
            await adapter.connect(cfg)
            payload = {
                "schema": "ori.perception.v1",
                "sensor_type": "ppe_hardhat_violation_score",
                "value": 0.88,
                "confidence": 0.92,
                "timestamp_ms": 1710000000123,
                "metadata": {
                    "zone_id": "line-3",
                    "camera_id": "cam-01",
                    "subject_id": "worker-7",
                },
            }
            assert isinstance(adapter._client, _FakeClient)
            await adapter._client.emit(cfg["topic"], json.dumps(payload).encode())
            await asyncio.sleep(0)

            reading = await adapter.read("ppe-hardhat-cam-01")
            assert reading.sensor_type == "ppe_hardhat_violation_score"
            assert reading.value == pytest.approx(0.88)
            assert reading.quality == pytest.approx(0.92)
            assert reading.timestamp == 1710000000123
            assert reading.metadata["source"] == "mqtt_perception"
            assert reading.metadata["schema"] == "ori.perception.v1"
            assert reading.metadata["zone_id"] == "line-3"
            assert reading.metadata["camera_id"] == "cam-01"
            await adapter.close()

    @pytest.mark.asyncio
    async def test_mismatched_sensor_type_is_ignored(self):
        adapter = MqttPerceptionAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)

        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            cfg = _config(sensor_type="ppe_hardhat_violation_score")
            await adapter.connect(cfg)
            payload = {
                "schema": "ori.perception.v1",
                "sensor_type": "ppe_vest_violation_score",
                "value": 0.93,
                "confidence": 0.9,
                "metadata": {},
            }
            assert isinstance(adapter._client, _FakeClient)
            await adapter._client.emit(cfg["topic"], json.dumps(payload).encode())
            await asyncio.sleep(0)

            with pytest.raises(AdapterReadError, match="no perception message cached"):
                await adapter.read("ppe-hardhat-cam-01")
            await adapter.close()

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        adapter = MqttPerceptionAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)

        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            await adapter.connect(_config(failure_threshold=2))

            with pytest.raises(AdapterReadError, match="no perception message cached"):
                await adapter.read("ppe-hardhat-cam-01")
            assert adapter._breaker is not None
            assert adapter._breaker.state == CircuitState.CLOSED

            with pytest.raises(AdapterReadError, match="no perception message cached"):
                await adapter.read("ppe-hardhat-cam-01")
            assert adapter._breaker.state == CircuitState.OPEN

            with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
                await adapter.read("ppe-hardhat-cam-01")

            await adapter.close()
