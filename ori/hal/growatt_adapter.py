# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
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
    from pysolarmanv5 import (
        PySolarmanV5 as _PySolarmanV5,  # type: ignore[import-untyped]
    )

    _PYSOLARMAN_AVAILABLE = True
except ImportError:
    _PySolarmanV5 = None
    _PYSOLARMAN_AVAILABLE = False


_DEFAULT_PORT = 8899

# Mapping: sensor_type -> (register, register_count, scale, unit, signed)
_SENSOR_MAP: dict[str, tuple[int, int, float, str, bool]] = {
    "growatt_battery_soc": (1014, 1, 0.1, "percent", False),
    "growatt_pv_power": (1060, 2, 1.0, "watt", False),
    "growatt_grid_power": (1062, 2, 1.0, "watt", True),
    "growatt_load_power": (1064, 2, 1.0, "watt", False),
    "growatt_battery_voltage": (1016, 1, 0.1, "volt", False),
}

_SUPPORTED = frozenset(_SENSOR_MAP)


class GrowattAdapter(BaseAdapter):
    """Growatt/Deye SolarmanV5 adapter.

    This adapter keeps connect() lightweight and lazily initializes the
    synchronous Solarman client at first read. All sync I/O is dispatched
    through run_in_executor to avoid blocking the event loop.
    """

    def __init__(self) -> None:
        self._connected: bool = False
        self._sensor_type: str = ""
        self._host: str = ""
        self._serial: str = ""
        self._port: int = _DEFAULT_PORT
        self._client: Any = None

    async def connect(self, config: dict) -> None:
        sensor_type = str(config.get("sensor_type", ""))
        if sensor_type not in _SUPPORTED:
            raise AdapterConnectionError(
                f"GrowattAdapter: unsupported sensor_type '{sensor_type}'. "
                f"Supported: {sorted(_SUPPORTED)}"
            )

        self._sensor_type = sensor_type
        self._host = str(config.get("host", "")).strip()
        self._serial = str(config.get("serial", "")).strip()
        self._port = int(config.get("port", _DEFAULT_PORT))
        self._breaker = HardwareCircuitBreaker(
            getattr(self, "adapter_name", type(self).__name__), config
        )

        if not self._host:
            raise AdapterConnectionError(
                "GrowattAdapter: 'host' is required in sensor config."
            )
        if not self._serial:
            raise AdapterConnectionError(
                "GrowattAdapter: 'serial' is required in sensor config."
            )
        if self._port <= 0:
            raise AdapterConnectionError("GrowattAdapter: 'port' must be > 0.")

        if not _PYSOLARMAN_AVAILABLE:
            raise AdapterConnectionError(
                "GrowattAdapter: 'pysolarmanv5' is not installed. "
                "Run: pip install pysolarmanv5"
            )

        # Lazy connect on first read.
        self._connected = True

    async def close(self) -> None:
        client = self._client
        self._client = None
        self._connected = False
        if client is None:
            return

        closer = getattr(client, "disconnect", None)
        if closer is None:
            closer = getattr(client, "close", None)
        if callable(closer):
            try:
                await asyncio.to_thread(closer)
            except Exception:
                logger.warning("GrowattAdapter: exception during client close")

    @property
    def is_connected(self) -> bool:
        return self._connected and _PYSOLARMAN_AVAILABLE

    async def read(self, sensor_id: str) -> SensorReading:
        if not _PYSOLARMAN_AVAILABLE:
            raise AdapterConnectionError(
                "GrowattAdapter: 'pysolarmanv5' is not installed. "
                "Run: pip install pysolarmanv5"
            )
        if not self._connected:
            raise AdapterReadError(
                "GrowattAdapter: not connected — call connect() first"
            )

        async with self._breaker:
            try:
                return await asyncio.to_thread(self._read_sensor_value_sync, sensor_id)
            except ConnectionRefusedError as exc:
                raise AdapterReadError(
                    f"GrowattAdapter: connection refused for host={self._host}:{self._port}"
                ) from exc
            except (AdapterReadError, AdapterConnectionError):
                raise
            except Exception as exc:
                raise AdapterReadError(
                    f"GrowattAdapter: unexpected error reading '{self._sensor_type}': {exc}"
                ) from exc

    def _read_sensor_value_sync(self, sensor_id: str) -> SensorReading:
        client = self._ensure_client_sync()
        register, count, scale, unit, signed = _SENSOR_MAP[self._sensor_type]
        raw_regs = self._read_registers_sync(client, register, count)
        raw_value = self._decode_registers(raw_regs, signed=signed)
        value = float(raw_value) * scale
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type=self._sensor_type,
            value=round(value, 4),
            unit=unit,
            timestamp=now_ms(),
            quality=1.0,
            metadata={
                "source": "growatt",
                "host": self._host,
                "port": self._port,
                "register": register,
                "register_count": count,
                "raw_registers": raw_regs,
            },
        )

    def _ensure_client_sync(self) -> Any:
        if self._client is not None:
            return self._client
        self._client = self._create_client_sync()
        return self._client

    def _create_client_sync(self) -> Any:
        if _PySolarmanV5 is None:
            raise AdapterConnectionError(
                "GrowattAdapter: 'pysolarmanv5' is not installed. "
                "Run: pip install pysolarmanv5"
            )
        try:
            try:
                return _PySolarmanV5(self._host, self._serial, port=self._port)
            except TypeError:
                return _PySolarmanV5(self._host, self._serial, self._port)
        except Exception as exc:
            raise AdapterConnectionError(
                f"GrowattAdapter: failed to create Solarman client for "
                f"{self._host}:{self._port}: {exc}"
            ) from exc

    def _read_registers_sync(self, client: Any, register: int, count: int) -> list[int]:
        read_fn = getattr(client, "read_holding_registers", None)
        if read_fn is None:
            read_fn = getattr(client, "read_input_registers", None)
        if read_fn is None:
            raise AdapterConnectionError(
                "GrowattAdapter: Solarman client has no supported read method."
            )

        raw = read_fn(register, count)
        if isinstance(raw, int):
            return [raw]
        if isinstance(raw, tuple):
            raw = list(raw)
        if not isinstance(raw, list) or len(raw) < count:
            raise AdapterReadError(
                f"GrowattAdapter: invalid register response for register={register}: {raw!r}"
            )
        try:
            return [int(v) for v in raw[:count]]
        except Exception as exc:
            raise AdapterReadError(
                f"GrowattAdapter: non-numeric register values for register={register}"
            ) from exc

    @staticmethod
    def _decode_registers(registers: list[int], signed: bool) -> int:
        if not registers:
            raise AdapterReadError("GrowattAdapter: empty register payload")

        if len(registers) == 1:
            value = int(registers[0]) & 0xFFFF
            if signed and value >= 0x8000:
                value -= 0x10000
            return value

        value = 0
        for reg in registers:
            value = (value << 16) | (int(reg) & 0xFFFF)

        if signed and value >= (1 << (16 * len(registers) - 1)):
            value -= 1 << (16 * len(registers))
        return value
