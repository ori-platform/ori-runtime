# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import struct
from functools import partial
from typing import Any

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    AdapterTimeoutError,
    BaseAdapter,
    HardwareCircuitBreaker,
)
from ori.network.events import SensorReading
from ori.time_utils import now_ms

logger = logging.getLogger(__name__)

try:
    import serial as _serial_module  # type: ignore[import-untyped]

    _PYSERIAL_AVAILABLE = True
except ImportError:
    _serial_module = None
    _PYSERIAL_AVAILABLE = False

_FC_READ_HOLDING = 0x03

# PZEM-004T (Modbus RTU) register map.
# entry: (register, register_count, scale, unit)
_SENSOR_MAP: dict[str, tuple[int, int, float, str]] = {
    "usb_voltage": (0x0000, 2, 0.1, "volt"),
    "usb_current": (0x0008, 2, 0.01, "ampere"),
    "usb_power": (0x0012, 2, 0.1, "watt"),
    "usb_frequency": (0x0046, 1, 0.1, "hertz"),
    "usb_energy": (0x0100, 2, 0.01, "kilowatt_hour"),
}
_SUPPORTED = frozenset(_SENSOR_MAP)

_DEFAULT_BAUD_RATE = 9600
_DEFAULT_BYTESIZE = 8
_DEFAULT_PARITY = "N"
_DEFAULT_STOPBITS = 1
_DEFAULT_TIMEOUT_S = 1.0
_DEFAULT_SLAVE_ID = 1


def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def _build_read_request(slave_id: int, register: int, count: int) -> bytes:
    frame = struct.pack(">BBHH", slave_id, _FC_READ_HOLDING, register, count)
    return frame + struct.pack("<H", _crc16(frame))


def _parse_response(response: bytes, expected_count: int) -> int:
    min_len = 5 + expected_count * 2
    if len(response) < min_len:
        raise AdapterReadError(
            f"UsbSerialAdapter: short Modbus response ({len(response)} bytes, "
            f"expected >= {min_len})"
        )

    payload = response[:-2]
    received_crc = struct.unpack("<H", response[-2:])[0]
    computed_crc = _crc16(payload)
    if received_crc != computed_crc:
        raise AdapterReadError(
            f"UsbSerialAdapter: CRC mismatch (got 0x{received_crc:04X}, "
            f"computed 0x{computed_crc:04X})"
        )

    data = response[3:-2]
    if expected_count == 1:
        return struct.unpack(">H", data[:2])[0]
    return struct.unpack(">I", data[:4])[0]


class UsbSerialAdapter(BaseAdapter):
    """USB serial adapter for PZEM-004T energy meter readings."""

    def __init__(self) -> None:
        self._connected = False
        self._sensor_type: str = ""
        self._device_path: str = ""
        self._baud_rate: int = _DEFAULT_BAUD_RATE
        self._bytesize: int = _DEFAULT_BYTESIZE
        self._parity: str = _DEFAULT_PARITY
        self._stopbits: int = _DEFAULT_STOPBITS
        self._timeout_s: float = _DEFAULT_TIMEOUT_S
        self._slave_id: int = _DEFAULT_SLAVE_ID
        self._serial: Any = None
        self._breaker: HardwareCircuitBreaker | None = None

    async def connect(self, config: dict) -> None:
        if not _PYSERIAL_AVAILABLE or _serial_module is None:
            raise AdapterConnectionError(
                "UsbSerialAdapter: 'pyserial' is not installed. Run: pip install pyserial"
            )

        sensor_type = str(config.get("sensor_type", ""))
        if sensor_type not in _SUPPORTED:
            raise AdapterConnectionError(
                f"UsbSerialAdapter: unsupported sensor_type '{sensor_type}'. "
                f"Supported: {sorted(_SUPPORTED)}"
            )
        self._sensor_type = sensor_type

        self._device_path = str(config.get("device_path", "")).strip()
        if not self._device_path:
            raise AdapterConnectionError(
                "UsbSerialAdapter: 'device_path' is required (e.g. /dev/ttyUSB0)"
            )

        baud_from_cfg = config.get(
            "baud_rate", config.get("baudrate", _DEFAULT_BAUD_RATE)
        )
        self._baud_rate = int(baud_from_cfg)
        self._bytesize = int(config.get("bytesize", _DEFAULT_BYTESIZE))
        self._parity = str(config.get("parity", _DEFAULT_PARITY))
        self._stopbits = int(config.get("stopbits", _DEFAULT_STOPBITS))
        self._timeout_s = float(config.get("timeout_s", _DEFAULT_TIMEOUT_S))
        self._slave_id = int(config.get("slave_id", _DEFAULT_SLAVE_ID))

        self._breaker = HardwareCircuitBreaker(self.adapter_name, config)

        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._open_port_sync)
        except AdapterConnectionError:
            raise
        except Exception as exc:
            raise AdapterConnectionError(
                f"UsbSerialAdapter: failed to open '{self._device_path}': {exc}"
            ) from exc

        self._connected = True

    async def read(self, sensor_id: str) -> SensorReading:
        if not _PYSERIAL_AVAILABLE:
            raise AdapterConnectionError(
                "UsbSerialAdapter: 'pyserial' is not installed. Run: pip install pyserial"
            )
        if not self._connected or self._serial is None:
            raise AdapterReadError(
                "UsbSerialAdapter: not connected — call connect() first"
            )
        if self._breaker is None:
            raise AdapterReadError(
                "UsbSerialAdapter: circuit breaker is not initialized"
            )

        async with self._breaker:
            register, count, scale, unit = _SENSOR_MAP[self._sensor_type]
            loop = asyncio.get_running_loop()
            read_timeout = self._timeout_s + 1.0
            try:
                raw = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        partial(self._read_sync, register, count),
                    ),
                    timeout=read_timeout,
                )
            except asyncio.TimeoutError as exc:
                raise AdapterTimeoutError(
                    f"UsbSerialAdapter: read timed out on '{self._device_path}'"
                ) from exc
            except (AdapterReadError, AdapterConnectionError):
                raise
            except Exception as exc:
                raise AdapterReadError(
                    f"UsbSerialAdapter: unexpected read failure for '{self._sensor_type}': {exc}"
                ) from exc

            return SensorReading(
                sensor_id=sensor_id,
                sensor_type=self._sensor_type,
                value=round(raw * scale, 4),
                unit=unit,
                timestamp=now_ms(),
                quality=1.0,
                metadata={
                    "source": "usb_serial",
                    "device_path": self._device_path,
                    "slave_id": self._slave_id,
                    "register": register,
                    "raw": raw,
                },
            )

    async def close(self) -> None:
        try:
            if self._serial is not None and self._serial.is_open:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, self._serial.close)
        except Exception:
            logger.warning(
                "UsbSerialAdapter: exception during close on '%s'",
                self._device_path,
            )
        finally:
            self._serial = None
            self._connected = False

    def _open_port_sync(self) -> None:
        if _serial_module is None:
            raise AdapterConnectionError(
                "UsbSerialAdapter: pyserial module unavailable"
            )
        self._serial = _serial_module.Serial(
            port=self._device_path,
            baudrate=self._baud_rate,
            bytesize=self._bytesize,
            parity=self._parity,
            stopbits=self._stopbits,
            timeout=self._timeout_s,
        )

    def _read_sync(self, register: int, count: int) -> int:
        request = _build_read_request(self._slave_id, register, count)
        self._serial.reset_input_buffer()
        self._serial.write(request)
        response = self._serial.read(5 + count * 2)
        if not response:
            raise AdapterReadError(
                f"UsbSerialAdapter: no response from slave {self._slave_id} "
                f"on '{self._device_path}'"
            )
        return _parse_response(response, count)
