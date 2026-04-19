# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    AdapterTimeoutError,
    HardwareCircuitBreaker,
)
from ori.hal.serial_adapter import (
    SerialAdapter,
    _build_read_request,
    _crc16,
    _parse_response,
)

# ─── Serial port guard ────────────────────────────────────────────────────────

skip_if_no_serial = pytest.mark.skipif(
    not __import__("os").path.exists("/dev/ttyUSB0"),
    reason="No serial device — not running on target hardware",
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _config(
    sensor_type: str = "voltage",
    port: str = "/dev/ttyUSB0",
    baudrate: int = 9600,
    slave_id: int = 1,
    timeout: float = 1.0,
    register: int | None = None,
) -> dict:
    cfg: dict = {
        "sensor_type": sensor_type,
        "port": port,
        "baudrate": baudrate,
        "slave_id": slave_id,
        "timeout": timeout,
    }
    if register is not None:
        cfg["register"] = register
    return cfg


def _connected_adapter(sensor_type: str = "voltage") -> SerialAdapter:
    adapter = SerialAdapter()
    adapter._connected = True
    adapter._sensor_type = sensor_type
    adapter._slave_id = 1
    adapter._port = "/dev/ttyUSB0"
    adapter._timeout = 1.0
    adapter._register = None
    adapter._breaker = HardwareCircuitBreaker("SerialAdapter", {})
    mock_serial = MagicMock()
    mock_serial.is_open = True
    adapter._serial = mock_serial
    return adapter


def _valid_response(slave_id: int, register_count: int, raw_value: int) -> bytes:
    """Build a well-formed Modbus FC 0x03 response for the given raw integer value."""
    byte_count = register_count * 2
    if register_count == 1:
        data = struct.pack(">H", raw_value)
    else:
        data = struct.pack(">I", raw_value)
    header = bytes([slave_id, 0x03, byte_count]) + data
    crc = _crc16(header)
    return header + struct.pack("<H", crc)


# ─── CRC ──────────────────────────────────────────────────────────────────────


class TestCrc16:
    def test_known_value(self):
        # Modbus RTU CRC for: slave 1, FC 03, reg 0x0000, count 2
        # Appended bytes in the frame are 0xC4 0x0B (little-endian) → integer 0x0BC4
        frame = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x02])
        assert _crc16(frame) == 0x0BC4

    def test_empty_returns_ffff(self):
        assert _crc16(b"") == 0xFFFF

    def test_different_data_gives_different_crc(self):
        assert _crc16(b"\x01\x03") != _crc16(b"\x01\x04")


# ─── Build request ────────────────────────────────────────────────────────────


class TestBuildReadRequest:
    def test_length(self):
        frame = _build_read_request(1, 0x0000, 2)
        assert len(frame) == 8  # 1+1+2+2+2 (addr+fc+reg+count+crc)

    def test_slave_id_and_fc(self):
        frame = _build_read_request(3, 0x0000, 1)
        assert frame[0] == 3  # slave id
        assert frame[1] == 0x03  # function code

    def test_register_encoded(self):
        frame = _build_read_request(1, 0x0046, 1)
        assert struct.unpack(">H", frame[2:4])[0] == 0x0046

    def test_count_encoded(self):
        frame = _build_read_request(1, 0x0000, 2)
        assert struct.unpack(">H", frame[4:6])[0] == 2

    def test_crc_appended_little_endian(self):
        frame = _build_read_request(1, 0x0000, 2)
        payload = frame[:-2]
        expected_crc = _crc16(payload)
        received_crc = struct.unpack("<H", frame[-2:])[0]
        assert received_crc == expected_crc


# ─── Parse response ───────────────────────────────────────────────────────────


class TestParseResponse:
    def test_1_register_returns_16bit_value(self):
        raw = 2350  # 235.0 Hz with ×0.1 scale
        response = _valid_response(1, 1, raw)
        assert _parse_response(response, 1) == raw

    def test_2_registers_returns_32bit_value(self):
        raw = 100000  # 10000.0 W with ×0.1 scale
        response = _valid_response(1, 2, raw)
        assert _parse_response(response, 2) == raw

    def test_short_response_raises(self):
        with pytest.raises(AdapterReadError, match="short"):
            _parse_response(b"\x01\x03", 1)

    def test_crc_mismatch_raises(self):
        response = _valid_response(1, 1, 1234)
        # Corrupt the last CRC byte
        corrupted = response[:-1] + bytes([response[-1] ^ 0xFF])
        with pytest.raises(AdapterReadError, match="CRC"):
            _parse_response(corrupted, 1)

    def test_modbus_exception_response_raises(self):
        # Exception response: fc has high bit set
        exception_frame = bytes([0x01, 0x83, 0x02])  # fc=0x83, exception=0x02
        crc = _crc16(exception_frame)
        response = exception_frame + struct.pack("<H", crc)
        with pytest.raises(AdapterReadError, match="exception"):
            _parse_response(response, 1)


# ─── connect ──────────────────────────────────────────────────────────────────


class TestConnect:
    async def test_missing_pyserial_raises(self):
        adapter = SerialAdapter()
        with (
            patch("ori.hal.serial_adapter._SERIAL_AVAILABLE", False),
            pytest.raises(AdapterConnectionError, match="pyserial"),
        ):
            await adapter.connect(_config())

    async def test_unsupported_sensor_type_raises(self):
        adapter = SerialAdapter()
        with pytest.raises(AdapterConnectionError, match="unsupported sensor_type"):
            await adapter.connect(_config(sensor_type="unknown"))

    async def test_missing_port_raises(self):
        adapter = SerialAdapter()
        cfg = _config()
        cfg["port"] = ""
        with pytest.raises(AdapterConnectionError, match="port"):
            await adapter.connect(cfg)

    async def test_connect_success(self):
        adapter = SerialAdapter()
        with (
            patch("ori.hal.serial_adapter._SERIAL_AVAILABLE", True),
            patch("ori.hal.serial_adapter.serial", create=True) as mock_serial_mod,
        ):
            mock_serial_mod.Serial.return_value = MagicMock(is_open=True)
            await adapter.connect(_config(sensor_type="voltage", baudrate=9600))

        assert adapter.is_connected is True
        assert adapter._sensor_type == "voltage"
        assert adapter._baudrate == 9600

    async def test_connect_stores_slave_id(self):
        adapter = SerialAdapter()
        with (
            patch("ori.hal.serial_adapter._SERIAL_AVAILABLE", True),
            patch("ori.hal.serial_adapter.serial", create=True) as mock_serial_mod,
        ):
            mock_serial_mod.Serial.return_value = MagicMock(is_open=True)
            await adapter.connect(_config(slave_id=5))

        assert adapter._slave_id == 5

    async def test_connect_stores_register_override(self):
        adapter = SerialAdapter()
        with (
            patch("ori.hal.serial_adapter._SERIAL_AVAILABLE", True),
            patch("ori.hal.serial_adapter.serial", create=True) as mock_serial_mod,
        ):
            mock_serial_mod.Serial.return_value = MagicMock(is_open=True)
            await adapter.connect(_config(register=0x0050))

        assert adapter._register == 0x0050

    async def test_port_open_failure_raises_connection_error(self):
        adapter = SerialAdapter()
        with (
            patch("ori.hal.serial_adapter._SERIAL_AVAILABLE", True),
            patch("ori.hal.serial_adapter.serial", create=True) as mock_serial_mod,
        ):
            mock_serial_mod.Serial.side_effect = OSError("permission denied")
            with pytest.raises(AdapterConnectionError):
                await adapter.connect(_config())


# ─── close ────────────────────────────────────────────────────────────────────


class TestClose:
    async def test_close_marks_disconnected(self):
        adapter = _connected_adapter()
        await adapter.close()
        assert adapter.is_connected is False

    async def test_close_clears_serial_handle(self):
        adapter = _connected_adapter()
        await adapter.close()
        assert adapter._serial is None

    async def test_close_calls_serial_close(self):
        adapter = _connected_adapter()
        mock_serial = adapter._serial
        await adapter.close()
        mock_serial.close.assert_called_once()

    async def test_close_when_not_connected_does_not_raise(self):
        adapter = SerialAdapter()
        await adapter.close()  # must not raise

    async def test_close_when_port_already_closed_does_not_raise(self):
        adapter = _connected_adapter()
        adapter._serial.is_open = False
        await adapter.close()  # must not raise


# ─── health_check ─────────────────────────────────────────────────────────────


class TestHealthCheck:
    async def test_healthy_when_connected_and_open(self):
        adapter = _connected_adapter()
        assert await adapter.health_check() is True

    async def test_unhealthy_when_disconnected(self):
        adapter = SerialAdapter()
        assert await adapter.health_check() is False

    async def test_unhealthy_when_serial_none(self):
        adapter = _connected_adapter()
        adapter._serial = None
        assert await adapter.health_check() is False

    async def test_unhealthy_when_port_closed(self):
        adapter = _connected_adapter()
        adapter._serial.is_open = False
        assert await adapter.health_check() is False


# ─── read ─────────────────────────────────────────────────────────────────────


class TestRead:
    async def test_not_connected_raises(self):
        adapter = SerialAdapter()
        adapter._sensor_type = "voltage"
        with pytest.raises(AdapterReadError, match="not connected"):
            await adapter.read("grid-voltage")

    async def test_voltage_reading(self):
        adapter = _connected_adapter("voltage")
        # raw=2300 × 0.1 = 230.0 V
        adapter._serial.read.return_value = _valid_response(1, 2, 2300)
        adapter._serial.reset_input_buffer = MagicMock()
        adapter._serial.write = MagicMock()

        reading = await adapter.read("grid-voltage")

        assert reading.sensor_type == "voltage"
        assert reading.value == pytest.approx(230.0)
        assert reading.unit == "volt"
        assert reading.quality == 1.0

    async def test_current_reading(self):
        adapter = _connected_adapter("current")
        # raw=1500 × 0.01 = 15.0 A
        adapter._serial.read.return_value = _valid_response(1, 2, 1500)
        adapter._serial.reset_input_buffer = MagicMock()
        adapter._serial.write = MagicMock()

        reading = await adapter.read("load-current")

        assert reading.value == pytest.approx(15.0)
        assert reading.unit == "ampere"

    async def test_frequency_reading(self):
        adapter = _connected_adapter("frequency")
        # raw=500 × 0.1 = 50.0 Hz (single register)
        adapter._serial.read.return_value = _valid_response(1, 1, 500)
        adapter._serial.reset_input_buffer = MagicMock()
        adapter._serial.write = MagicMock()

        reading = await adapter.read("freq-01")

        assert reading.value == pytest.approx(50.0)
        assert reading.unit == "hertz"

    async def test_energy_kwh_reading(self):
        adapter = _connected_adapter("energy_kwh")
        # raw=450000 × 0.01 = 4500.0 kWh
        adapter._serial.read.return_value = _valid_response(1, 2, 450000)
        adapter._serial.reset_input_buffer = MagicMock()
        adapter._serial.write = MagicMock()

        reading = await adapter.read("energy-01")

        assert reading.value == pytest.approx(4500.0)
        assert reading.unit == "kilowatt_hour"

    async def test_reading_metadata_contains_slave_id_register_raw(self):
        adapter = _connected_adapter("voltage")
        adapter._serial.read.return_value = _valid_response(1, 2, 2300)
        adapter._serial.reset_input_buffer = MagicMock()
        adapter._serial.write = MagicMock()

        reading = await adapter.read("grid-voltage")

        assert reading.metadata["slave_id"] == 1
        assert "register" in reading.metadata
        assert reading.metadata["raw"] == 2300

    async def test_register_override_used_in_request(self):
        adapter = _connected_adapter("voltage")
        adapter._register = 0x0050
        adapter._serial.read.return_value = _valid_response(1, 2, 1000)
        adapter._serial.reset_input_buffer = MagicMock()
        written_frames: list[bytes] = []
        adapter._serial.write = MagicMock(side_effect=written_frames.append)

        await adapter.read("grid-voltage")

        request = written_frames[0]
        reg_in_frame = struct.unpack(">H", request[2:4])[0]
        assert reg_in_frame == 0x0050

    async def test_no_response_raises_read_error(self):
        adapter = _connected_adapter("voltage")
        adapter._serial.read.return_value = b""
        adapter._serial.reset_input_buffer = MagicMock()
        adapter._serial.write = MagicMock()

        with pytest.raises(AdapterReadError, match="no response"):
            await adapter.read("grid-voltage")

    async def test_crc_error_raises_read_error(self):
        adapter = _connected_adapter("frequency")
        bad_response = _valid_response(1, 1, 500)
        bad_response = bad_response[:-1] + bytes([bad_response[-1] ^ 0xFF])
        adapter._serial.read.return_value = bad_response
        adapter._serial.reset_input_buffer = MagicMock()
        adapter._serial.write = MagicMock()

        with pytest.raises(AdapterReadError, match="CRC"):
            await adapter.read("freq-01")

    async def test_timeout_raises_adapter_timeout_error(self):
        adapter = _connected_adapter("voltage")

        with (
            patch.object(adapter, "_read_sync", return_value=0),
            patch("ori.hal.serial_adapter.asyncio") as mock_asyncio,
        ):
            mock_asyncio.wait_for = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_asyncio.get_running_loop = asyncio.get_running_loop
            mock_asyncio.TimeoutError = asyncio.TimeoutError
            with pytest.raises(AdapterTimeoutError):
                await adapter.read("grid-voltage")

    async def test_circuit_breaker_closed_allows_read(self):
        adapter = _connected_adapter("frequency")
        adapter._serial.read.return_value = _valid_response(1, 1, 500)
        adapter._serial.reset_input_buffer = MagicMock()
        adapter._serial.write = MagicMock()
        # Default stub always returns True
        assert adapter._breaker._allow_read() is True
        reading = await adapter.read("freq-01")
        assert reading is not None

    async def test_circuit_breaker_open_raises_read_error(self):
        adapter = _connected_adapter("voltage")
        with patch.object(adapter._breaker, "_allow_read", return_value=False):
            with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
                await adapter.read("grid-voltage")

    async def test_cb_record_success_called_on_good_read(self):
        adapter = _connected_adapter("frequency")
        adapter._serial.read.return_value = _valid_response(1, 1, 500)
        adapter._serial.reset_input_buffer = MagicMock()
        adapter._serial.write = MagicMock()

        with patch.object(adapter._breaker, "_record_success") as mock_success:
            await adapter.read("grid-freq")
            mock_success.assert_called_once()

    async def test_cb_record_failure_called_on_read_error(self):
        adapter = _connected_adapter("voltage")
        adapter._serial.read.return_value = b""
        adapter._serial.reset_input_buffer = MagicMock()
        adapter._serial.write = MagicMock()

        with patch.object(adapter._breaker, "_record_failure") as mock_failure:
            with pytest.raises(AdapterReadError):
                await adapter.read("grid-voltage")
            mock_failure.assert_called_once()


# ─── All supported sensor types round-trip ────────────────────────────────────


class TestAllSensorTypes:
    @pytest.mark.parametrize(
        "sensor_type,register_count,raw,expected_value,expected_unit",
        [
            ("voltage", 2, 2300, 230.0, "volt"),
            ("current", 2, 1500, 15.0, "ampere"),
            ("active_power", 2, 5000, 500.0, "watt"),
            ("apparent_power", 2, 5200, 520.0, "volt_ampere"),
            ("reactive_power", 2, 800, 80.0, "var"),
            ("power_factor", 1, 900, 0.9, "ratio"),
            ("frequency", 1, 500, 50.0, "hertz"),
            ("energy_kwh", 2, 10000, 100.0, "kilowatt_hour"),
        ],
    )
    async def test_sensor_type(
        self,
        sensor_type: str,
        register_count: int,
        raw: int,
        expected_value: float,
        expected_unit: str,
    ):
        adapter = _connected_adapter(sensor_type)
        adapter._serial.read.return_value = _valid_response(1, register_count, raw)
        adapter._serial.reset_input_buffer = MagicMock()
        adapter._serial.write = MagicMock()

        reading = await adapter.read("meter-01")

        assert reading.sensor_type == sensor_type
        assert reading.value == pytest.approx(expected_value)
        assert reading.unit == expected_unit
        assert reading.sensor_id == "meter-01"


# ─── Hardware integration (serial device required) ────────────────────────────


@skip_if_no_serial
class TestSerialIntegration:
    async def test_connect_and_read_voltage(self):
        adapter = SerialAdapter()
        await adapter.connect(
            {
                "sensor_type": "voltage",
                "port": "/dev/ttyUSB0",
                "baudrate": 9600,
                "slave_id": 1,
            }
        )
        assert adapter.is_connected
        reading = await adapter.read("grid-voltage")
        assert reading.sensor_type == "voltage"
        assert reading.unit == "volt"
        assert reading.value >= 0.0
        await adapter.close()
        assert not adapter.is_connected
