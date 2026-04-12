# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ori.hal.base import AdapterConnectionError, AdapterReadError, CircuitState
from ori.hal.lorawan_adapter import LoraWanAdapter


def _config(
    *,
    sensor_type: str = "lorawan_temperature",
    topic: str = "v3/app@ttn/devices/device-01/up",
    failure_threshold: int = 3,
    extra: dict | None = None,
) -> dict:
    base = {
        "sensor_id": "field-temp",
        "sensor_type": sensor_type,
        "broker_host": "192.168.1.88",
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


class TestLoraWanAdapter:
    @pytest.mark.asyncio
    async def test_graceful_import_failure(self):
        adapter = LoraWanAdapter()
        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", False),
            patch("ori.hal.mqtt_base._aiomqtt", None),
        ):
            with pytest.raises(AdapterConnectionError, match="aiomqtt"):
                await adapter.connect(_config())
            assert adapter.is_connected is False

    @pytest.mark.asyncio
    async def test_read_from_ttn_uplink_shape(self):
        adapter = LoraWanAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)

        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            cfg = _config(sensor_type="lorawan_temperature")
            await adapter.connect(cfg)
            payload = {
                "uplink_message": {
                    "decoded_payload": {"temperature": 32.4, "humidity": 77.1},
                    "rx_metadata": [{"rssi": -89, "snr": 5.2}],
                    "received_at": "2026-04-12T08:00:00Z",
                }
            }
            assert isinstance(adapter._client, _FakeClient)
            await adapter._client.emit(cfg["topic"], json.dumps(payload).encode())
            await asyncio.sleep(0)

            reading = await adapter.read("field-temp")
            assert reading.sensor_type == "lorawan_temperature"
            assert reading.value == pytest.approx(32.4)
            assert reading.unit == "celsius"
            assert reading.metadata["source"] == "lorawan"
            await adapter.close()

    @pytest.mark.asyncio
    async def test_read_signal_rssi(self):
        adapter = LoraWanAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)
        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            cfg = _config(sensor_type="lorawan_signal_rssi")
            await adapter.connect(cfg)
            payload = {"rx_metadata": [{"rssi": -101.5, "snr": 2.1}]}
            assert isinstance(adapter._client, _FakeClient)
            await adapter._client.emit(cfg["topic"], json.dumps(payload).encode())
            await asyncio.sleep(0)

            reading = await adapter.read("field-temp")
            assert reading.value == pytest.approx(-101.5)
            assert reading.unit == "dbm"
            await adapter.close()

    @pytest.mark.asyncio
    async def test_custom_value_and_quality_paths(self):
        adapter = LoraWanAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)
        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            cfg = _config(
                sensor_type="lorawan_tank_level",
                extra={
                    "value_path": "object.level",
                    "quality_path": "object.quality",
                    "unit": "percent",
                },
            )
            await adapter.connect(cfg)
            payload = {"object": {"level": 66.0, "quality": 0.87}}
            assert isinstance(adapter._client, _FakeClient)
            await adapter._client.emit(cfg["topic"], json.dumps(payload).encode())
            await asyncio.sleep(0)

            reading = await adapter.read("field-temp")
            assert reading.value == pytest.approx(66.0)
            assert reading.quality == pytest.approx(0.87)
            await adapter.close()

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        adapter = LoraWanAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)
        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            await adapter.connect(_config(failure_threshold=2))
            with pytest.raises(AdapterReadError, match="no MQTT data cached yet"):
                await adapter.read("field-temp")
            assert adapter._breaker is not None
            assert adapter._breaker.state == CircuitState.CLOSED

            with pytest.raises(AdapterReadError, match="no MQTT data cached yet"):
                await adapter.read("field-temp")
            assert adapter._breaker.state == CircuitState.OPEN

            with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
                await adapter.read("field-temp")
            await adapter.close()
