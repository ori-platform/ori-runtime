# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from typing import Any, cast
from unittest.mock import patch

import pytest

from ori.hal.base import AdapterConnectionError, AdapterReadError, CircuitState
from ori.hal.opcua_adapter import OpcUaAdapter


def _config(
    sensor_type: str = "temperature",
    url: str = "opc.tcp://192.168.1.100:4840",
    node_id: str = "ns=2;i=1002",
    failure_threshold: int = 3,
) -> dict:
    return {
        "sensor_id": "plc-temperature",
        "sensor_type": sensor_type,
        "url": url,
        "node_id": node_id,
        "circuit_breaker": {
            "failure_threshold": failure_threshold,
            "recovery_timeout_s": 300,
            "success_threshold": 2,
        },
    }


class _Variant:
    def __init__(self, value):
        self.Value = value


class _DataValue:
    def __init__(self, value):
        self.Value = _Variant(value)


class _FakeNode:
    def __init__(self, value):
        self._value = value

    async def read_data_value(self):
        return self._value


class _FakeClient:
    default_node_value = 0.0

    def __init__(self, url=None, **kwargs):
        self.url = url if url is not None else kwargs.get("url")
        self.connected = False
        self.disconnected = False
        self._node = _FakeNode(type(self).default_node_value)

    async def connect(self):
        self.connected = True

    async def disconnect(self):
        self.disconnected = True

    def get_node(self, _node_id: str):
        return self._node


class TestOpcUaAdapter:
    @pytest.mark.asyncio
    async def test_graceful_import_failure(self):
        adapter = OpcUaAdapter()

        with (
            patch("ori.hal.opcua_adapter._ASYNCUA_AVAILABLE", False),
            patch("ori.hal.opcua_adapter._AsyncUaClient", None),
        ):
            with pytest.raises(AdapterConnectionError, match="asyncua"):
                await adapter.connect(_config())

            assert adapter.is_connected is False
            with pytest.raises(AdapterConnectionError, match="asyncua"):
                await adapter.read("plc-temperature")

    @pytest.mark.asyncio
    async def test_connect_stores_config(self):
        adapter = OpcUaAdapter()
        cast(Any, _FakeClient).default_node_value = 12.3

        with (
            patch("ori.hal.opcua_adapter._ASYNCUA_AVAILABLE", True),
            patch("ori.hal.opcua_adapter._AsyncUaClient", _FakeClient),
        ):
            await adapter.connect(
                _config(
                    sensor_type="temperature",
                    url="opc.tcp://10.0.0.20:4840",
                    node_id="ns=3;i=9001",
                )
            )
            assert adapter.is_connected is True
            assert adapter._url == "opc.tcp://10.0.0.20:4840"
            assert adapter._node_id == "ns=3;i=9001"
            assert adapter._sensor_type == "temperature"
            assert isinstance(adapter._client, _FakeClient)
            assert adapter._client.connected is True

    @pytest.mark.asyncio
    async def test_read_float_value(self):
        adapter = OpcUaAdapter()
        cast(Any, _FakeClient).default_node_value = 42.75

        with (
            patch("ori.hal.opcua_adapter._ASYNCUA_AVAILABLE", True),
            patch("ori.hal.opcua_adapter._AsyncUaClient", _FakeClient),
        ):
            await adapter.connect(_config())
            reading = await adapter.read("plc-temperature")

        assert reading.sensor_type == "temperature"
        assert reading.value == pytest.approx(42.75)
        assert reading.metadata["source"] == "opcua"

    @pytest.mark.asyncio
    async def test_read_int_value(self):
        adapter = OpcUaAdapter()
        cast(Any, _FakeClient).default_node_value = _DataValue(123)

        with (
            patch("ori.hal.opcua_adapter._ASYNCUA_AVAILABLE", True),
            patch("ori.hal.opcua_adapter._AsyncUaClient", _FakeClient),
        ):
            await adapter.connect(_config())
            reading = await adapter.read("plc-temperature")

        assert reading.value == pytest.approx(123.0)

    @pytest.mark.asyncio
    async def test_read_boolean(self):
        adapter = OpcUaAdapter()
        cast(Any, _FakeClient).default_node_value = _DataValue(True)

        with (
            patch("ori.hal.opcua_adapter._ASYNCUA_AVAILABLE", True),
            patch("ori.hal.opcua_adapter._AsyncUaClient", _FakeClient),
        ):
            await adapter.connect(_config())
            reading = await adapter.read("plc-temperature")

        assert reading.value == pytest.approx(1.0)

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        adapter = OpcUaAdapter()
        cast(Any, _FakeClient).default_node_value = 10.0

        with (
            patch("ori.hal.opcua_adapter._ASYNCUA_AVAILABLE", True),
            patch("ori.hal.opcua_adapter._AsyncUaClient", _FakeClient),
        ):
            await adapter.connect(_config(failure_threshold=2))

            error = AdapterReadError("simulated read failure")
            with patch.object(adapter, "_read_node_value", side_effect=error):
                with pytest.raises(AdapterReadError):
                    await adapter.read("plc-temperature")
                assert adapter._breaker is not None
                assert adapter._breaker.state == CircuitState.CLOSED

                with pytest.raises(AdapterReadError):
                    await adapter.read("plc-temperature")
                assert adapter._breaker.state == CircuitState.OPEN

                with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
                    await adapter.read("plc-temperature")
