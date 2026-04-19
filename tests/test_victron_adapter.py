# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ori.hal.base import AdapterConnectionError, AdapterReadError, CircuitState
from ori.hal.victron_adapter import _SENSOR_MAP, VictronAdapter


def _config(
    sensor_type: str = "victron_battery_soc",
    broker_host: str = "192.168.1.50",
    portal_id: str = "VENUS123",
    port: int = 1883,
    failure_threshold: int = 3,
) -> dict:
    return {
        "sensor_id": "victron-01",
        "sensor_type": sensor_type,
        "broker_host": broker_host,
        "portal_id": portal_id,
        "port": port,
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


class TestVictronAdapter:
    @pytest.mark.asyncio
    async def test_graceful_import_failure(self):
        adapter = VictronAdapter()
        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", False),
            patch("ori.hal.mqtt_base._aiomqtt", None),
        ):
            with pytest.raises(AdapterConnectionError, match="aiomqtt"):
                await adapter.connect(_config())
            assert adapter.is_connected is False

    def test_topic_mapping(self):
        adapter = VictronAdapter()
        adapter._portal_id = "PORTAL123"
        assert (
            adapter._topic_for_sensor("victron_battery_soc")
            == "N/PORTAL123/battery/276/Soc"
        )
        assert (
            adapter._topic_for_sensor("victron_grid_power")
            == "N/PORTAL123/system/0/Ac/Grid/L1/Power"
        )

    @pytest.mark.asyncio
    async def test_cached_read(self):
        adapter = VictronAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)

        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            await adapter.connect(_config(sensor_type="victron_battery_soc"))
            topic = adapter._topic_for_sensor("victron_battery_soc")
            assert isinstance(adapter._client, _FakeClient)
            await adapter._client.emit(topic, b'{"value": 84.5}')
            await asyncio.sleep(0)

            reading = await adapter.read("victron-01")
            assert reading.sensor_type == "victron_battery_soc"
            assert reading.value == pytest.approx(84.5)
            assert reading.unit == "percent"
            assert reading.metadata["source"] == "victron"
            assert reading.metadata["topic"] == topic

            expected_topics = {
                f"N/{adapter._portal_id}/{suffix}"
                for suffix, _unit in _SENSOR_MAP.values()
            }
            assert set(adapter._client.subscriptions) == expected_topics
            await adapter.close()

    @pytest.mark.asyncio
    async def test_no_data_yet(self):
        adapter = VictronAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)

        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            await adapter.connect(_config(sensor_type="victron_battery_voltage"))
            with pytest.raises(AdapterReadError, match="no MQTT data cached yet"):
                await adapter.read("victron-01")
            await adapter.close()

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        adapter = VictronAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)

        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            await adapter.connect(_config(failure_threshold=2))

            with pytest.raises(AdapterReadError, match="no MQTT data cached yet"):
                await adapter.read("victron-01")
            assert adapter._breaker is not None
            assert adapter._breaker.state == CircuitState.CLOSED

            with pytest.raises(AdapterReadError, match="no MQTT data cached yet"):
                await adapter.read("victron-01")
            assert adapter._breaker.state == CircuitState.OPEN

            with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
                await adapter.read("victron-01")

            await adapter.close()

    @pytest.mark.asyncio
    async def test_connect_passes_auth_and_client_options(self):
        adapter = VictronAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)

        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            cfg = _config()
            cfg.update(
                {
                    "mqtt_username": "operator",
                    "mqtt_password": "secret",
                    "mqtt_client_id": "ori-victron-01",
                    "mqtt_keepalive_s": 90,
                    "mqtt_clean_session": True,
                }
            )
            await adapter.connect(cfg)

            assert isinstance(adapter._client, _FakeClient)
            assert adapter._client.kwargs["username"] == "operator"
            assert adapter._client.kwargs["password"] == "secret"
            assert adapter._client.kwargs["identifier"] == "ori-victron-01"
            assert adapter._client.kwargs["keepalive"] == 90
            assert adapter._client.kwargs["clean_session"] is True
            await adapter.close()

    @pytest.mark.asyncio
    async def test_connect_builds_tls_context_when_enabled(self):
        adapter = VictronAdapter()
        fake_aiomqtt = SimpleNamespace(Client=_FakeClient)

        with (
            patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
            patch("ori.hal.mqtt_base._aiomqtt", fake_aiomqtt),
        ):
            cfg = _config()
            cfg.update(
                {
                    "mqtt_tls_enabled": True,
                    "mqtt_tls_insecure": True,
                }
            )
            await adapter.connect(cfg)

            assert isinstance(adapter._client, _FakeClient)
            tls_context = adapter._client.kwargs.get("tls_context")
            assert tls_context is not None
            assert tls_context.check_hostname is False
            await adapter.close()
