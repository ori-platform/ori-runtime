# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import struct
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ori.hal.base import AdapterConnectionError, AdapterReadError, CircuitState
from ori.hal.usb_serial_adapter import _SENSOR_MAP, UsbSerialAdapter, _crc16


def _config(
    sensor_type: str = "usb_power",
    failure_threshold: int = 3,
    device_path: str = "/dev/ttyUSB0",
) -> dict:
    return {
        "sensor_id": "mains-power",
        "sensor_type": sensor_type,
        "device_path": device_path,
        "baud_rate": 9600,
        "timeout_s": 0.2,
        "circuit_breaker": {
            "failure_threshold": failure_threshold,
            "recovery_timeout_s": 300,
            "success_threshold": 2,
        },
    }


def _modbus_response(slave_id: int, register_count: int, raw_value: int) -> bytes:
    if register_count == 1:
        data = struct.pack(">H", raw_value & 0xFFFF)
    else:
        data = struct.pack(">I", raw_value & 0xFFFFFFFF)
    payload = bytes([slave_id, 0x03, len(data)]) + data
    return payload + struct.pack("<H", _crc16(payload))


class _FakeSerial:
    def __init__(
        self,
        *,
        port: str,
        baudrate: int,
        bytesize: int,
        parity: str,
        stopbits: int,
        timeout: float,
    ):
        self.port = port
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits = stopbits
        self.timeout = timeout
        self.is_open = True
        self._responses: dict[tuple[int, int], bytes] = {}
        self._last_request: tuple[int, int, int] | None = None

    def reset_input_buffer(self) -> None:
        return None

    def write(self, request: bytes) -> int:
        slave_id, _fc, register, count = struct.unpack(">BBHH", request[:6])
        self._last_request = (slave_id, register, count)
        return len(request)

    def read(self, _size: int) -> bytes:
        if self._last_request is None:
            return b""
        slave_id, register, count = self._last_request
        return self._responses.get(
            (register, count), _modbus_response(slave_id, count, 0)
        )

    def close(self) -> None:
        self.is_open = False


def _raw_for_sensor(sensor_type: str) -> int:
    if sensor_type == "usb_voltage":
        return 2305  # 230.5V
    if sensor_type == "usb_current":
        return 752  # 7.52A
    if sensor_type == "usb_power":
        return 1567  # 156.7W
    if sensor_type == "usb_frequency":
        return 500  # 50.0Hz
    if sensor_type == "usb_energy":
        return 1234  # 12.34kWh
    raise AssertionError(f"Unknown sensor_type {sensor_type}")


def _expected_value(sensor_type: str) -> float:
    raw = _raw_for_sensor(sensor_type)
    _, _, scale, _ = _SENSOR_MAP[sensor_type]
    return round(raw * scale, 4)


class TestUsbSerialAdapter:
    @pytest.mark.asyncio
    async def test_graceful_import_failure(self):
        adapter = UsbSerialAdapter()
        with (
            patch("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", False),
            patch("ori.hal.usb_serial_adapter._serial_module", None),
        ):
            with pytest.raises(AdapterConnectionError, match="pyserial"):
                await adapter.connect(_config())
            assert adapter.is_connected is False
            with pytest.raises(AdapterConnectionError, match="pyserial"):
                await adapter.read("mains-power")

    @pytest.mark.asyncio
    async def test_connect_stores_config(self):
        adapter = UsbSerialAdapter()
        fake_module = SimpleNamespace(Serial=_FakeSerial)
        with (
            patch("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", True),
            patch("ori.hal.usb_serial_adapter._serial_module", fake_module),
        ):
            await adapter.connect(
                _config(sensor_type="usb_power", device_path="/dev/ttyUSB9")
            )

        assert adapter.is_connected is True
        assert adapter._device_path == "/dev/ttyUSB9"
        assert adapter._baud_rate == 9600
        assert adapter._sensor_type == "usb_power"

    @pytest.mark.asyncio
    async def test_read_sensor_types(self):
        fake_module = SimpleNamespace(Serial=_FakeSerial)

        with (
            patch("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", True),
            patch("ori.hal.usb_serial_adapter._serial_module", fake_module),
        ):
            for sensor_type, (register, count, _scale, unit) in _SENSOR_MAP.items():
                adapter = UsbSerialAdapter()
                await adapter.connect(_config(sensor_type=sensor_type))
                assert isinstance(adapter._serial, _FakeSerial)
                adapter._serial._responses[(register, count)] = _modbus_response(
                    1, count, _raw_for_sensor(sensor_type)
                )

                reading = await adapter.read("mains-power")
                assert reading.sensor_type == sensor_type
                assert reading.unit == unit
                assert reading.value == pytest.approx(_expected_value(sensor_type))
                assert reading.metadata["source"] == "usb_serial"
                await adapter.close()

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        adapter = UsbSerialAdapter()
        fake_module = SimpleNamespace(Serial=_FakeSerial)
        with (
            patch("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", True),
            patch("ori.hal.usb_serial_adapter._serial_module", fake_module),
        ):
            await adapter.connect(_config(failure_threshold=2))
            error = AdapterReadError("simulated read failure")
            with patch.object(adapter, "_read_sync", side_effect=error):
                with pytest.raises(AdapterReadError):
                    await adapter.read("mains-power")
                assert adapter._breaker is not None
                assert adapter._breaker.state == CircuitState.CLOSED

                with pytest.raises(AdapterReadError):
                    await adapter.read("mains-power")
                assert adapter._breaker.state == CircuitState.OPEN

                with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
                    await adapter.read("mains-power")
