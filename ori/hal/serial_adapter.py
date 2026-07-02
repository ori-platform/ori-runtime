# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import struct
from typing import Any

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    AdapterTimeoutError,
    BaseAdapter,
    HardwareCircuitBreaker,
)
from ori.network.events import SensorReading
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

try:
    import serial  # type: ignore[import-untyped]

    _SERIAL_AVAILABLE = True
except ImportError:
    _SERIAL_AVAILABLE = False

# ── Modbus RTU constants ───────────────────────────────────────────────────────

_FC_READ_HOLDING = 0x03  # Function code: Read Holding Registers

# Supported sensor types and their Modbus register map + unit.
# Each entry: (start_register, register_count, scale, unit)
# scale is applied as: value = raw_int * scale
_SENSOR_MAP: dict[str, tuple[int, int, float, str]] = {
    "voltage": (0x0000, 2, 0.1, "volt"),
    "current": (0x0008, 2, 0.01, "ampere"),
    "active_power": (0x0012, 2, 0.1, "watt"),
    "apparent_power": (0x001A, 2, 0.1, "volt_ampere"),
    "reactive_power": (0x0022, 2, 0.1, "var"),
    "power_factor": (0x002A, 1, 0.001, "ratio"),
    "frequency": (0x0046, 1, 0.1, "hertz"),
    "energy_kwh": (0x0100, 2, 0.01, "kilowatt_hour"),
}

_SUPPORTED = frozenset(_SENSOR_MAP)

# Default serial parameters for PZEM-004T and similar Modbus RTU meters
_DEFAULT_BAUDRATE = 9600
_DEFAULT_BYTESIZE = 8
_DEFAULT_PARITY = "N"
_DEFAULT_STOPBITS = 1
_DEFAULT_TIMEOUT = 1.0  # seconds
_DEFAULT_SLAVE_ID = 1  # Modbus slave address


def _crc16(data: bytes) -> int:
    """Compute Modbus RTU CRC-16."""
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
    """Build a Modbus RTU Read Holding Registers (FC 0x03) request frame."""
    frame = struct.pack(">BBHH", slave_id, _FC_READ_HOLDING, register, count)
    crc = _crc16(frame)
    return frame + struct.pack("<H", crc)  # CRC appended little-endian


def _parse_response(response: bytes, expected_count: int) -> int:
    """Parse a Modbus RTU FC 0x03 response and return the raw integer value.

    For 1-register reads: returns the 16-bit unsigned integer.
    For 2-register reads: returns a 32-bit unsigned integer (high word first).

    Raises:
        AdapterReadError: Malformed response, CRC mismatch, or Modbus exception.
    """
    # Check for Modbus exception response first — these are 5 bytes and would
    # fail the length check below even though they carry valid error information.
    if len(response) >= 2 and response[1] & 0x80:
        exception_code = response[2] if len(response) > 2 else 0
        raise AdapterReadError(
            f"SerialAdapter: Modbus exception code 0x{exception_code:02X}"
        )

    # Minimum valid normal response: addr(1) + fc(1) + byte_count(1) + data + crc(2)
    min_len = 5 + expected_count * 2
    if len(response) < min_len:
        raise AdapterReadError(
            f"SerialAdapter: short Modbus response ({len(response)} bytes, "
            f"expected >= {min_len})"
        )

    # Verify CRC
    payload = response[:-2]
    received_crc = struct.unpack("<H", response[-2:])[0]
    computed_crc = _crc16(payload)
    if received_crc != computed_crc:
        raise AdapterReadError(
            f"SerialAdapter: CRC mismatch (got 0x{received_crc:04X}, "
            f"computed 0x{computed_crc:04X})"
        )

    data = response[3:-2]  # strip addr, fc, byte_count, crc
    if expected_count == 1:
        return struct.unpack(">H", data[:2])[0]
    else:
        # Two 16-bit registers → 32-bit value, high word first
        return struct.unpack(">I", data[:4])[0]


class SerialAdapter(BaseAdapter):
    """RS485/UART serial adapter for Modbus RTU energy meters.

    Communicates with devices such as the PZEM-004T, SDM120, and compatible
    Modbus RTU meters over an RS485 or UART serial port.

    Implements Modbus RTU Function Code 0x03 (Read Holding Registers).

    Supported sensor types and their default register addresses:

    .. list-table::
       :header-rows: 1

       * - ``sensor_type``
         - Unit
         - Registers
       * - ``voltage``
         - volt
         - 0x0000 (×0.1)
       * - ``current``
         - ampere
         - 0x0008 (×0.01)
       * - ``active_power``
         - watt
         - 0x0012 (×0.1)
       * - ``apparent_power``
         - volt_ampere
         - 0x001A (×0.1)
       * - ``reactive_power``
         - var
         - 0x0022 (×0.1)
       * - ``power_factor``
         - ratio
         - 0x002A (×0.001)
       * - ``frequency``
         - hertz
         - 0x0046 (×0.1)
       * - ``energy_kwh``
         - kilowatt_hour
         - 0x0100 (×0.01)

    Usage example (ori.yaml sensor entry)::

        sensors:
          - id: grid-power
            type: active_power
            protocol: serial
            port: /dev/ttyUSB0
            baudrate: 9600
            slave_id: 1
    """

    def __init__(self) -> None:
        self._connected: bool = False
        self._sensor_type: str = ""
        self._port: str = ""
        self._baudrate: int = _DEFAULT_BAUDRATE
        self._bytesize: int = _DEFAULT_BYTESIZE
        self._parity: str = _DEFAULT_PARITY
        self._stopbits: int = _DEFAULT_STOPBITS
        self._timeout: float = _DEFAULT_TIMEOUT
        self._slave_id: int = _DEFAULT_SLAVE_ID

        # Register override: callers may specify a non-default start register
        self._register: int | None = None

        self._serial: Any = None  # serial.Serial instance

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self, config: dict) -> None:
        """Open the serial port.

        Args:
            config: Sensor config dict from ``ori.yaml``.  Required keys:

                - ``sensor_type`` (str) — one of the supported types above
                - ``port`` (str) — serial device, e.g. ``/dev/ttyUSB0``

                Optional keys:

                - ``baudrate`` (int, default ``9600``)
                - ``bytesize`` (int, default ``8``)
                - ``parity`` (str, default ``'N'``)
                - ``stopbits`` (int, default ``1``)
                - ``timeout`` (float, default ``1.0``) — read timeout in seconds
                - ``slave_id`` (int, default ``1``) — Modbus slave address
                - ``register`` (int) — override the default start register

        Raises:
            :exc:`AdapterConnectionError`: Unsupported sensor type, missing
                ``pyserial``, or the serial port cannot be opened.
        """
        if not _SERIAL_AVAILABLE:
            raise AdapterConnectionError(
                "SerialAdapter: 'pyserial' is not installed. Run: pip install pyserial"
            )

        sensor_type = config.get("sensor_type", "")
        if sensor_type not in _SUPPORTED:
            raise AdapterConnectionError(
                f"SerialAdapter: unsupported sensor_type '{sensor_type}'. "
                f"Supported: {sorted(_SUPPORTED)}"
            )

        self._sensor_type = sensor_type
        self._port = config.get("port", "")
        if not self._port:
            raise AdapterConnectionError(
                "SerialAdapter: 'port' is required in sensor config (e.g. /dev/ttyUSB0)"
            )

        self._baudrate = int(config.get("baudrate", _DEFAULT_BAUDRATE))
        self._bytesize = int(config.get("bytesize", _DEFAULT_BYTESIZE))
        self._parity = str(config.get("parity", _DEFAULT_PARITY))
        self._stopbits = int(config.get("stopbits", _DEFAULT_STOPBITS))
        self._timeout = float(config.get("timeout", _DEFAULT_TIMEOUT))
        self._slave_id = int(config.get("slave_id", _DEFAULT_SLAVE_ID))
        reg = config.get("register")
        self._register = int(reg) if reg is not None else None

        try:
            await asyncio.to_thread(self._open_port)
        except AdapterConnectionError:
            raise
        except Exception as exc:
            raise AdapterConnectionError(
                f"SerialAdapter: failed to open '{self._port}': {exc}"
            ) from exc

        self._breaker = HardwareCircuitBreaker(
            getattr(self, "adapter_name", type(self).__name__), config
        )
        self._connected = True

    def _open_port(self) -> None:
        self._serial = serial.Serial(
            port=self._port,
            baudrate=self._baudrate,
            bytesize=self._bytesize,
            parity=self._parity,
            stopbits=self._stopbits,
            timeout=self._timeout,
        )

    async def close(self) -> None:
        """Close the serial port."""
        try:
            if self._serial is not None and self._serial.is_open:
                await asyncio.to_thread(self._serial.close)
        except Exception:
            logger.warning("SerialAdapter: exception during close on '%s'", self._port)
        finally:
            self._serial = None
            self._connected = False

    async def health_check(self) -> bool:
        """Return ``True`` if the serial port is open."""
        return self._connected and self._serial is not None and self._serial.is_open

    # ── Read ──────────────────────────────────────────────────────────────────

    async def read(self, sensor_id: str) -> SensorReading:
        """Sample the sensor and return a normalised :class:`~ori.network.events.SensorReading`.

        Args:
            sensor_id: Logical sensor id from ``ori.yaml``.

        Raises:
            :exc:`AdapterReadError`: Not connected, port I/O error, or Modbus
                exception / CRC failure.
            :exc:`AdapterTimeoutError`: No response within the configured
                ``timeout`` plus a 1-second guard margin.
        """
        if not self._connected or self._serial is None:
            raise AdapterReadError(
                "SerialAdapter: not connected — call connect() first"
            )

        async with self._breaker:
            reg, count, scale, unit = _SENSOR_MAP[self._sensor_type]
            if self._register is not None:
                reg = self._register

            read_timeout = self._timeout + 1.0  # asyncio guard > serial read timeout

            try:
                raw = await asyncio.wait_for(
                    asyncio.to_thread(self._read_sync, reg, count),
                    timeout=read_timeout,
                )
            except asyncio.TimeoutError as exc:
                raise AdapterTimeoutError(
                    f"SerialAdapter: read timed out on '{self._port}' "
                    f"(sensor_type={self._sensor_type})"
                ) from exc
            except AdapterReadError:
                raise
            except Exception as exc:
                raise AdapterReadError(
                    f"SerialAdapter: unexpected error reading '{self._sensor_type}': {exc}"
                ) from exc

            value = round(raw * scale, 4)
            return SensorReading(
                sensor_id=sensor_id,
                sensor_type=self._sensor_type,
                value=value,
                unit=unit,
                timestamp=now_ms(),
                quality=1.0,
                metadata={
                    "slave_id": self._slave_id,
                    "register": reg,
                    "raw": raw,
                },
            )

    def _read_sync(self, register: int, count: int) -> int:
        """Send Modbus request and return the raw integer value."""
        request = _build_read_request(self._slave_id, register, count)
        self._serial.reset_input_buffer()
        self._serial.write(request)

        # Response: addr(1) + fc(1) + byte_count(1) + data(count*2) + crc(2)
        expected_bytes = 5 + count * 2
        response = self._serial.read(expected_bytes)

        if not response:
            raise AdapterReadError(
                f"SerialAdapter: no response from slave {self._slave_id} "
                f"on '{self._port}'"
            )

        return _parse_response(response, count)
