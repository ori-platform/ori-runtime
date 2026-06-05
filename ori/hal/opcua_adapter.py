# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import logging
from numbers import Real
from typing import Any

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    BaseAdapter,
    HardwareCircuitBreaker,
)
from ori.network.events import SensorReading
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

try:
    from asyncua import Client as _AsyncUaClient  # type: ignore[import-untyped]

    _ASYNCUA_AVAILABLE = True
except ImportError:
    _AsyncUaClient = None
    _ASYNCUA_AVAILABLE = False


class OpcUaAdapter(BaseAdapter):
    """OPC-UA adapter for PLC/SCADA sensor values."""

    def __init__(self) -> None:
        self._connected = False
        self._sensor_type: str = ""
        self._url: str = ""
        self._node_id: str = ""
        self._client: Any = None
        self._node: Any = None
        self._breaker: HardwareCircuitBreaker | None = None

    @property
    def is_connected(self) -> bool:
        return self._connected and _ASYNCUA_AVAILABLE

    async def connect(self, config: dict) -> None:
        if not _ASYNCUA_AVAILABLE or _AsyncUaClient is None:
            raise AdapterConnectionError(
                "OpcUaAdapter: 'asyncua' is not installed. Run: pip install asyncua"
            )

        self._sensor_type = str(config.get("sensor_type", "")).strip()
        self._url = str(config.get("url", "")).strip()
        self._node_id = str(config.get("node_id", "")).strip()
        self._breaker = HardwareCircuitBreaker(self.adapter_name, config)

        if not self._sensor_type:
            raise AdapterConnectionError("OpcUaAdapter: 'sensor_type' is required")
        if not self._url:
            raise AdapterConnectionError("OpcUaAdapter: 'url' is required")
        if not self._node_id:
            raise AdapterConnectionError("OpcUaAdapter: 'node_id' is required")

        try:
            try:
                client = _AsyncUaClient(url=self._url)
            except TypeError:
                client = _AsyncUaClient(self._url)
            await client.connect()
            self._client = client
            self._node = client.get_node(self._node_id)
            self._connected = True
        except Exception as exc:
            await self.close()
            raise AdapterConnectionError(
                f"OpcUaAdapter: failed to connect to '{self._url}' "
                f"node '{self._node_id}': {exc}"
            ) from exc

    async def read(self, sensor_id: str) -> SensorReading:
        if not _ASYNCUA_AVAILABLE:
            raise AdapterConnectionError(
                "OpcUaAdapter: 'asyncua' is not installed. Run: pip install asyncua"
            )
        if not self._connected or self._node is None:
            raise AdapterReadError("OpcUaAdapter: not connected — call connect() first")
        if self._breaker is None:
            raise AdapterReadError("OpcUaAdapter: circuit breaker is not initialized")

        async with self._breaker:
            try:
                raw_value = await self._read_node_value()
                value = self._coerce_to_float(raw_value)
            except AdapterReadError:
                raise
            except Exception as exc:
                raise AdapterReadError(
                    f"OpcUaAdapter: failed to read node '{self._node_id}': {exc}"
                ) from exc

            return SensorReading(
                sensor_id=sensor_id,
                sensor_type=self._sensor_type,
                value=value,
                unit="",
                timestamp=now_ms(),
                quality=1.0,
                metadata={
                    "source": "opcua",
                    "url": self._url,
                    "node_id": self._node_id,
                    "raw_type": type(raw_value).__name__,
                },
            )

    async def close(self) -> None:
        client = self._client
        self._client = None
        self._node = None
        self._connected = False

        if client is None:
            return

        try:
            await client.disconnect()
        except Exception:
            logger.warning("OpcUaAdapter: exception during disconnect")

    async def _read_node_value(self) -> Any:
        if self._node is None:
            raise AdapterReadError("OpcUaAdapter: node is not initialized")

        read_data_value = getattr(self._node, "read_data_value", None)
        if callable(read_data_value):
            return await read_data_value()

        read_value = getattr(self._node, "read_value", None)
        if callable(read_value):
            return await read_value()

        raise AdapterReadError("OpcUaAdapter: node has no readable value method")

    @classmethod
    def _coerce_to_float(cls, value: Any) -> float:
        unwrapped = cls._unwrap_opcua_value(value)

        if isinstance(unwrapped, bool):
            return 1.0 if unwrapped else 0.0
        if isinstance(unwrapped, Real):
            return float(unwrapped)
        if isinstance(unwrapped, str):
            try:
                return float(unwrapped)
            except ValueError as exc:
                raise AdapterReadError(
                    f"OpcUaAdapter: cannot convert string value to float: {unwrapped!r}"
                ) from exc

        raise AdapterReadError(
            f"OpcUaAdapter: unsupported OPC-UA value type {type(unwrapped).__name__}"
        )

    @classmethod
    def _unwrap_opcua_value(cls, value: Any) -> Any:
        current = value

        # asyncua DataValue -> Variant -> primitive usually lives in `.Value`.
        for _ in range(3):
            inner = getattr(current, "Value", None)
            if inner is None or inner is current:
                break
            current = inner

        # Some wrappers may use lowercase `.value`.
        inner_lower = getattr(current, "value", None)
        if (
            inner_lower is not None
            and inner_lower is not current
            and not isinstance(current, (str, bytes, bytearray))
        ):
            current = inner_lower

        return current
