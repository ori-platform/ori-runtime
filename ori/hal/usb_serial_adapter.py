# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import glob
import logging
import shutil
import struct
import subprocess
from typing import Any

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    AdapterTimeoutError,
    BaseAdapter,
    HardwareCircuitBreaker,
    resolve_baud_rate,
)
from ori.network.events import SensorReading
from ori.utils.termux import parse_termux_usb_output
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

CONFIG_SCHEMA = {
    "device_path": {
        "type": "string",
        "required_unless": {"auto_detect_device_path": True},
    },
    "auto_detect_device_path": {"type": "boolean", "default": False},
    "baud_rate": {"type": "integer", "default": 9600, "minimum": 1},
    "baudrate": {"type": "integer", "deprecated": True, "supersedes": "baud_rate"},
    "bytesize": {"type": "integer", "default": 8, "enum": [5, 6, 7, 8]},
    "parity": {"type": "string", "default": "N", "enum": ["N", "E", "O"]},
    "stopbits": {"type": "integer", "default": 1, "enum": [1, 2]},
    "timeout_s": {"type": "number", "default": 1.0, "minimum": 0},
    "slave_id": {"type": "integer", "default": 1, "minimum": 1, "maximum": 247},
    # Addressed to the Android agent, not to this adapter: it is how the phone
    # picks its meter out of everything on the USB bus. One signed document
    # carries both sides, so the runtime's job is to stop refusing the block,
    # not to read it.
    #
    # Shape only, deliberately. Which values make a usable binding is the
    # reading party's judgement: an absent block is accepted, so refusing an
    # empty one would draw a line this side cannot defend, and documents signed
    # before the issuing side required real identifiers carry zeroes and were
    # never recalled.
    #
    # Declared field by field because this schema admits no open object. So a
    # field added here on the issuing side is refused by every deployed
    # runtime, and the document is signed, so no operator can edit it out:
    # adding one is a coordinated release, not a server change.
    "usb_binding": {
        "type": "object",
        "description": (
            "USB device identity for the Android agent; unread by the runtime"
        ),
        "properties": {
            "vendor_id": {"type": "integer", "minimum": 0, "maximum": 0xFFFF},
            "product_id": {"type": "integer", "minimum": 0, "maximum": 0xFFFF},
            # Emitted only when the meter reports one, so it cannot be required.
            "serial_number": {"type": "string", "default": ""},
        },
    },
}
CALIBRATION_SCHEMAS: dict[str, dict] = {}

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
_DIRECT_SERIAL_GLOBS = ("/dev/ttyUSB*", "/dev/ttyACM*")
_TERMUX_USB_TIMEOUT_S = 2.0


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
        self._transport: str = "serial"
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
        if not self._device_path and bool(config.get("auto_detect_device_path", False)):
            self._device_path = _find_direct_serial_device()
        if not self._device_path:
            termux_devices = await asyncio.to_thread(_list_termux_usb_devices_sync)
            if termux_devices:
                devices = ", ".join(termux_devices)
                raise AdapterConnectionError(
                    "UsbSerialAdapter: termux-usb can see USB device(s) "
                    f"{devices}, but no serial stream is configured. Android's "
                    "termux-usb handle is a raw USB device, not a /dev/ttyUSB* "
                    "serial port. Configure device_path to a readable "
                    "/dev/ttyUSB*/ttyACM* path or to a pyserial URL such as "
                    "socket://127.0.0.1:7000 from an approved USB-serial bridge."
                )
            raise AdapterConnectionError(
                "UsbSerialAdapter: 'device_path' is required (e.g. /dev/ttyUSB0)"
            )

        self._baud_rate = resolve_baud_rate(
            has_canonical="baud_rate" in config,
            canonical=config.get("baud_rate"),
            has_legacy="baudrate" in config,
            legacy=config.get("baudrate"),
            default=_DEFAULT_BAUD_RATE,
            adapter_name="UsbSerialAdapter",
        )
        self._bytesize = int(config.get("bytesize", _DEFAULT_BYTESIZE))
        self._parity = str(config.get("parity", _DEFAULT_PARITY))
        self._stopbits = int(config.get("stopbits", _DEFAULT_STOPBITS))
        self._timeout_s = float(config.get("timeout_s", _DEFAULT_TIMEOUT_S))
        self._slave_id = int(config.get("slave_id", _DEFAULT_SLAVE_ID))
        self._transport = _transport_for_path(self._device_path)

        self._breaker = HardwareCircuitBreaker(self.adapter_name, config)

        try:
            await asyncio.to_thread(self._open_port_sync)
        except AdapterConnectionError:
            raise
        except Exception as exc:
            raise AdapterConnectionError(
                f"UsbSerialAdapter: failed to open '{self._device_path}': {exc}"
            ) from exc

        self._connected = True
        logger.info(
            "UsbSerialAdapter: connected device_path=%s transport=%s sensor_type=%s",
            self._device_path,
            self._transport,
            self._sensor_type,
        )

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
            read_timeout = self._timeout_s + 1.0
            try:
                raw = await asyncio.wait_for(
                    asyncio.to_thread(self._read_sync, register, count),
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
                    "transport": self._transport,
                    "slave_id": self._slave_id,
                    "register": register,
                    "raw": raw,
                },
            )

    async def close(self) -> None:
        try:
            if self._serial is not None and self._serial.is_open:
                await asyncio.to_thread(self._serial.close)
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
        serial_kwargs = {
            "baudrate": self._baud_rate,
            "bytesize": self._bytesize,
            "parity": self._parity,
            "stopbits": self._stopbits,
            "timeout": self._timeout_s,
        }
        serial_for_url = getattr(_serial_module, "serial_for_url", None)
        if callable(serial_for_url) and "://" in self._device_path:
            self._serial = serial_for_url(self._device_path, **serial_kwargs)
            return
        self._serial = _serial_module.Serial(port=self._device_path, **serial_kwargs)

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


def _transport_for_path(device_path: str) -> str:
    if device_path.startswith("socket://"):
        return "socket"
    if "://" in device_path:
        return "pyserial_url"
    return "serial"


def _find_direct_serial_device() -> str:
    candidates: list[str] = []
    for pattern in _DIRECT_SERIAL_GLOBS:
        candidates.extend(glob.glob(pattern))
    if not candidates:
        return ""
    return sorted(candidates)[0]


def _list_termux_usb_devices_sync() -> list[str]:
    if shutil.which("termux-usb") is None:
        return []
    try:
        result = subprocess.run(
            ["termux-usb", "-l"],
            check=False,
            capture_output=True,
            text=True,
            timeout=_TERMUX_USB_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    return parse_termux_usb_output(result.stdout)
