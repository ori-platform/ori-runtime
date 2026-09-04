# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import struct
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ori.hal.base import AdapterConnectionError, AdapterReadError, CircuitState
from ori.hal.config_schema import DocumentError, validate_document, validate_schema
from ori.hal.usb_serial_adapter import (
    _SENSOR_MAP,
    CONFIG_SCHEMA,
    UsbSerialAdapter,
    _crc16,
)


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
        assert adapter._transport == "serial"

    @pytest.mark.asyncio
    async def test_connect_uses_pyserial_url_transport(self):
        adapter = UsbSerialAdapter()
        opened: dict[str, object] = {}

        def serial_for_url(port: str, **kwargs):
            opened["port"] = port
            opened["kwargs"] = kwargs
            return _FakeSerial(port=port, **kwargs)

        fake_module = SimpleNamespace(Serial=_FakeSerial, serial_for_url=serial_for_url)
        with (
            patch("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", True),
            patch("ori.hal.usb_serial_adapter._serial_module", fake_module),
        ):
            await adapter.connect(
                _config(
                    sensor_type="usb_power",
                    device_path="socket://127.0.0.1:7000",
                )
            )

        assert adapter.is_connected is True
        assert adapter._transport == "socket"
        assert opened["port"] == "socket://127.0.0.1:7000"

    @pytest.mark.asyncio
    async def test_auto_detects_direct_serial_device_when_enabled(self):
        adapter = UsbSerialAdapter()
        fake_module = SimpleNamespace(Serial=_FakeSerial)
        config = _config()
        config.pop("device_path")
        config["auto_detect_device_path"] = True

        with (
            patch("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", True),
            patch("ori.hal.usb_serial_adapter._serial_module", fake_module),
            patch(
                "ori.hal.usb_serial_adapter._find_direct_serial_device",
                return_value="/dev/ttyACM0",
            ),
        ):
            await adapter.connect(config)

        assert adapter.is_connected is True
        assert adapter._device_path == "/dev/ttyACM0"

    @pytest.mark.asyncio
    async def test_termux_usb_without_serial_stream_has_actionable_error(self):
        adapter = UsbSerialAdapter()
        fake_module = SimpleNamespace(Serial=_FakeSerial)
        config = _config()
        config.pop("device_path")

        with (
            patch("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", True),
            patch("ori.hal.usb_serial_adapter._serial_module", fake_module),
            patch("ori.hal.usb_serial_adapter.asyncio.to_thread") as to_thread,
            patch(
                "ori.hal.usb_serial_adapter._list_termux_usb_devices_sync",
                return_value=["/dev/bus/usb/001/002"],
            ) as list_termux,
        ):

            async def run_in_thread(func, *args, **kwargs):
                return func(*args, **kwargs)

            to_thread.side_effect = run_in_thread
            with pytest.raises(AdapterConnectionError, match="termux-usb can see"):
                await adapter.connect(config)
            to_thread.assert_called_once_with(list_termux)

    @pytest.mark.asyncio
    async def test_prose_from_termux_usb_is_not_reported_as_a_device(self):
        """The join, not the parser.

        `termux-usb -l` exits zero while printing prose. Every non-device line
        used to come back as a device path, so a missing `device_path` was
        reported as a phantom USB device and the installer was sent after a
        USB-serial bridge instead of the setting that was actually absent.

        This drives the real `_list_termux_usb_devices_sync` over a subprocess
        result rather than stubbing its return value, so the parser and the
        error it feeds are exercised together.
        """
        adapter = UsbSerialAdapter()
        fake_module = SimpleNamespace(Serial=_FakeSerial)
        config = _config()
        config.pop("device_path")

        completed = SimpleNamespace(returncode=0, stdout="No USB devices found.\n")

        with (
            patch("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", True),
            patch("ori.hal.usb_serial_adapter._serial_module", fake_module),
            patch(
                "ori.hal.usb_serial_adapter.shutil.which",
                return_value="/data/data/com.termux/files/usr/bin/termux-usb",
            ),
            patch("ori.hal.usb_serial_adapter.subprocess.run", return_value=completed),
        ):
            with pytest.raises(AdapterConnectionError) as excinfo:
                await adapter.connect(config)

        message = str(excinfo.value)
        assert "'device_path' is required" in message
        assert "termux-usb can see" not in message
        assert "No USB devices found." not in message

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


class TestUsbBindingDeclaration:
    """The signed document carries a block this adapter does not read.

    There is one configuration document per device and the Android agent needs
    the meter's USB identity in it, so the block travels inside this sensor.
    The runtime's obligation is to load it, not to use it. Every phone starter
    ever onboarded carries one, and this schema refused all of them; nothing
    noticed because the phone package still ships a shell shim in place of a
    runtime binary, so no such document has ever been validated.
    """

    def _schema(self):
        return validate_schema(CONFIG_SCHEMA, name="usb_serial")

    def _document(self, **extra) -> dict:
        return {
            "device_path": "/dev/ttyUSB0",
            "auto_detect_device_path": False,
            "baud_rate": 9600,
            **extra,
        }

    def _load(self, document: dict) -> dict:
        return validate_document(
            document, self._schema(), context="sensors[0] (protocol='usb_serial')"
        )

    def test_a_document_carrying_a_binding_loads(self):
        resolved = self._load(
            self._document(usb_binding={"vendor_id": 4292, "product_id": 60000})
        )
        assert resolved["usb_binding"]["vendor_id"] == 4292
        assert resolved["usb_binding"]["product_id"] == 60000

    def test_the_serial_number_is_optional_and_defaults_empty(self):
        """It is emitted only when the meter reports one."""
        resolved = self._load(
            self._document(usb_binding={"vendor_id": 4292, "product_id": 60000})
        )
        assert resolved["usb_binding"]["serial_number"] == ""
        carried = self._load(
            self._document(
                usb_binding={
                    "vendor_id": 4292,
                    "product_id": 60000,
                    "serial_number": "0001",
                }
            )
        )
        assert carried["usb_binding"]["serial_number"] == "0001"

    def test_a_document_without_a_binding_still_loads(self):
        """A document that omits the block loads unchanged."""
        assert "usb_binding" not in self._load(self._document())
        assert "usb_binding" not in self._load({"auto_detect_device_path": True})

    def test_a_binding_that_names_no_device_is_accepted_like_an_absent_one(self):
        """Shape is this side's business; identity is the reading party's.

        Omitting the block entirely is accepted and is the same no-identity
        state, so refusing an empty one would draw a line the runtime cannot
        defend for a field it never reads.
        """
        assert self._load(self._document(usb_binding={}))["usb_binding"] == {
            "serial_number": ""
        }

    def test_a_zero_identifier_is_accepted_because_older_documents_carry_one(self):
        """Documents signed before the issuing side required real identifiers.

        Those were never recalled. The agent already declines to name a meter
        for them, which is a handled meter-binding failure; refusing them here
        would turn it into a runtime that will not start at all.
        """
        resolved = self._load(
            self._document(usb_binding={"vendor_id": 0, "product_id": 0})
        )
        assert resolved["usb_binding"]["vendor_id"] == 0

    def test_an_identifier_outside_sixteen_bits_is_refused(self):
        with pytest.raises(DocumentError, match="above the maximum"):
            self._load(
                self._document(usb_binding={"vendor_id": 0x10000, "product_id": 1})
            )

    def test_the_block_is_declared_field_by_field_not_left_open(self):
        """An undeclared object would reopen the pass-through one level down.

        The block is closed, so it cannot smuggle anything past the validator.
        The cost is that a field added on the issuing side is refused by every
        deployed runtime, which makes adding one a coordinated release.
        """
        with pytest.raises(DocumentError, match="not declared by the schema"):
            self._load(
                self._document(
                    usb_binding={"vendor_id": 1, "product_id": 2, "bus_number": 3}
                )
            )

    def test_a_binding_that_is_not_an_object_is_refused(self):
        with pytest.raises(DocumentError, match="expected object"):
            self._load(self._document(usb_binding=4292))
