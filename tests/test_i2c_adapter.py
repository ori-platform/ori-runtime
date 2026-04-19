# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    AdapterTimeoutError,
    HardwareCircuitBreaker,
)
from ori.hal.i2c_adapter import _DEFAULT_SENSITIVITY, I2CAdapter

# ─── Pi guard ─────────────────────────────────────────────────────────────────

skip_if_no_pi = pytest.mark.skipif(
    not os.path.exists("/dev/i2c-1"),
    reason="No I2C bus — not running on Pi",
)


@pytest.fixture(autouse=True)
def _clear_shared_i2c_bus_cache():
    """Ensure tests don't leak cached bus handles."""
    import ori.hal.i2c_adapter

    ori.hal.i2c_adapter._shared_busio_instances.clear()
    ori.hal.i2c_adapter._shared_busio_refs.clear()
    yield
    ori.hal.i2c_adapter._shared_busio_instances.clear()
    ori.hal.i2c_adapter._shared_busio_refs.clear()


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _config(
    sensor_type: str = "bme280",
    sensor_id: str = "env-01",
    address: int = 0x76,
    bus: int = 1,
    channel: int = 0,
    sensitivity: float = _DEFAULT_SENSITIVITY,
) -> dict:
    return {
        "sensor_type": sensor_type,
        "sensor_id": sensor_id,
        "address": address,
        "bus": bus,
        "channel": channel,
        "sensitivity": sensitivity,
    }


def _connected_bme280_adapter() -> I2CAdapter:
    """Return an I2CAdapter that appears connected to a BME280 (no real hardware)."""
    adapter = I2CAdapter()
    adapter._connected = True
    adapter._sensor_type = "bme280"
    adapter._address = 0x76
    adapter._breaker = HardwareCircuitBreaker("I2CAdapter", {})
    adapter._bus = MagicMock()
    adapter._bme280_params = MagicMock()
    return adapter


def _connected_ads_adapter(sensor_type: str = "ads1115_current") -> I2CAdapter:
    adapter = I2CAdapter()
    adapter._connected = True
    adapter._sensor_type = sensor_type
    adapter._channel = 0
    adapter._sensitivity = _DEFAULT_SENSITIVITY
    adapter._breaker = HardwareCircuitBreaker("I2CAdapter", {})
    adapter._ads = MagicMock()
    return adapter


def _connected_scd40_adapter() -> I2CAdapter:
    adapter = I2CAdapter()
    adapter._connected = True
    adapter._sensor_type = "scd40"
    adapter._breaker = HardwareCircuitBreaker("I2CAdapter", {})
    adapter._scd4x = MagicMock()
    return adapter


# ─── Module import (no hardware needed) ──────────────────────────────────────


class TestModuleImport:
    def test_imports_cleanly_without_hardware_libraries(self):
        """The module must import on any host regardless of smbus2/adafruit presence."""
        import ori.hal.i2c_adapter  # noqa: F401

    def test_adapter_instantiates_without_hardware(self):
        adapter = I2CAdapter()
        assert adapter is not None
        assert adapter.is_connected is False


# ─── connect — validation ─────────────────────────────────────────────────────


class TestConnect:
    async def test_unsupported_sensor_type_raises(self):
        adapter = I2CAdapter()
        with pytest.raises(AdapterConnectionError, match="unsupported sensor_type"):
            await adapter.connect(_config(sensor_type="unknown_sensor"))

    async def test_connect_bme280_missing_smbus_raises(self):
        adapter = I2CAdapter()
        with (
            patch("ori.hal.i2c_adapter._SMBUS_AVAILABLE", False),
            pytest.raises(AdapterConnectionError, match="smbus2"),
        ):
            await adapter.connect(_config(sensor_type="bme280"))

    async def test_connect_bme280_missing_bme280_lib_raises(self):
        adapter = I2CAdapter()
        with (
            patch("ori.hal.i2c_adapter._SMBUS_AVAILABLE", True),
            patch("ori.hal.i2c_adapter._BME280_AVAILABLE", False),
            pytest.raises(AdapterConnectionError, match="RPi.bme280"),
        ):
            await adapter.connect(_config(sensor_type="bme280"))

    async def test_connect_ads1115_missing_lib_raises(self):
        adapter = I2CAdapter()
        with (
            patch("ori.hal.i2c_adapter._ADS1115_AVAILABLE", False),
            pytest.raises(AdapterConnectionError, match="ADS1x15"),
        ):
            await adapter.connect(_config(sensor_type="ads1115_current"))

    async def test_connect_scd40_missing_lib_raises(self):
        adapter = I2CAdapter()
        with (
            patch("ori.hal.i2c_adapter._SCD40_AVAILABLE", False),
            pytest.raises(AdapterConnectionError, match="scd4x"),
        ):
            await adapter.connect(_config(sensor_type="scd40"))

    async def test_connect_bme280_success(self):
        adapter = I2CAdapter()
        mock_bus = MagicMock()
        mock_params = MagicMock()
        with (
            patch("ori.hal.i2c_adapter._SMBUS_AVAILABLE", True),
            patch("ori.hal.i2c_adapter._BME280_AVAILABLE", True),
            patch("ori.hal.i2c_adapter.smbus", create=True) as mock_smbus,
            patch("ori.hal.i2c_adapter._bme280_lib", create=True) as mock_bme280,
        ):
            mock_smbus.SMBus.return_value = mock_bus
            mock_bme280.load_calibration_params.return_value = mock_params
            await adapter.connect(_config(sensor_type="bme280", address=0x76, bus=1))

        assert adapter.is_connected is True
        assert adapter._sensor_type == "bme280"
        assert adapter._address == 0x76
        assert adapter._bus_number == 1

    async def test_connect_adafruit_unsupported_bus_raises(self):
        adapter = I2CAdapter()
        with patch("ori.hal.i2c_adapter._ADS1115_AVAILABLE", True):
            with pytest.raises(
                AdapterConnectionError, match="currently only support I2C bus 1"
            ):
                await adapter.connect(_config(sensor_type="ads1115_current", bus=3))

    async def test_connect_stores_sensitivity(self):
        adapter = I2CAdapter()
        with (
            patch("ori.hal.i2c_adapter._ADS1115_AVAILABLE", True),
            patch("ori.hal.i2c_adapter._busio", create=True),
            patch("ori.hal.i2c_adapter._board", create=True),
            patch("ori.hal.i2c_adapter._ads1115", create=True),
        ):
            await adapter.connect(
                _config(sensor_type="ads1115_current", sensitivity=0.05)
            )
        assert adapter._sensitivity == 0.05

    async def test_connect_stores_channel(self):
        adapter = I2CAdapter()
        with (
            patch("ori.hal.i2c_adapter._ADS1115_AVAILABLE", True),
            patch("ori.hal.i2c_adapter._busio", create=True),
            patch("ori.hal.i2c_adapter._board", create=True),
            patch("ori.hal.i2c_adapter._ads1115", create=True),
        ):
            await adapter.connect(_config(sensor_type="ads1115_current", channel=2))
        assert adapter._channel == 2

    async def test_connect_hardware_exception_raises_connection_error(self):
        adapter = I2CAdapter()
        with (
            patch("ori.hal.i2c_adapter._SMBUS_AVAILABLE", True),
            patch("ori.hal.i2c_adapter._BME280_AVAILABLE", True),
            patch("ori.hal.i2c_adapter.smbus", create=True) as mock_smbus,
        ):
            mock_smbus.SMBus.side_effect = OSError("I2C bus not found")
            with pytest.raises(AdapterConnectionError):
                await adapter.connect(_config(sensor_type="bme280"))


# ─── close ────────────────────────────────────────────────────────────────────


class TestClose:
    async def test_close_marks_disconnected(self):
        adapter = _connected_bme280_adapter()
        await adapter.close()
        assert adapter.is_connected is False

    async def test_close_clears_bus_handle(self):
        adapter = _connected_bme280_adapter()
        await adapter.close()
        assert adapter._bus is None

    async def test_close_stops_scd40_measurement(self):
        adapter = _connected_scd40_adapter()
        mock_scd4x = adapter._scd4x
        await adapter.close()
        mock_scd4x.stop_periodic_measurement.assert_called_once()
        assert adapter._scd4x is None

    async def test_close_when_already_disconnected_does_not_raise(self):
        adapter = I2CAdapter()
        await adapter.close()  # must not raise

    async def test_close_evicts_shared_bus_cache_for_ads1115(self):
        """After close(), if ref array hits 0, busio.I2C cache entry is removed."""
        import ori.hal.i2c_adapter as _mod

        adapter = _connected_ads_adapter("ads1115_current")
        adapter._bus_number = 1
        _mod._shared_busio_instances[1] = MagicMock()  # seed the cache
        _mod._shared_busio_refs[1] = 1  # seed the reference

        await adapter.close()

        assert 1 not in _mod._shared_busio_instances
        assert 1 not in _mod._shared_busio_refs

    async def test_close_evicts_shared_bus_cache_for_scd40(self):
        import ori.hal.i2c_adapter as _mod

        adapter = _connected_scd40_adapter()
        adapter._bus_number = 1
        _mod._shared_busio_instances[1] = MagicMock()
        _mod._shared_busio_refs[1] = 1

        await adapter.close()

        assert 1 not in _mod._shared_busio_instances
        assert 1 not in _mod._shared_busio_refs

    async def test_close_does_not_evict_if_references_remain(self):
        """If 2 sensors share a bus, close() on the first leaves the cache intact."""
        import ori.hal.i2c_adapter as _mod

        adapter = _connected_ads_adapter("ads1115_current")
        adapter._bus_number = 1
        sentinel = MagicMock()
        _mod._shared_busio_instances[1] = sentinel
        _mod._shared_busio_refs[1] = 2  # 2 sensors actively using the bus

        await adapter.close()

        # The cache MUST stay alive to serve the second sensor
        assert _mod._shared_busio_instances.get(1) is sentinel
        assert _mod._shared_busio_refs.get(1) == 1

    async def test_close_does_not_evict_cache_for_bme280(self):
        """BME280 uses smbus2 directly — it must not touch the busio cache."""
        import ori.hal.i2c_adapter as _mod

        adapter = _connected_bme280_adapter()
        adapter._bus_number = 1
        sentinel = MagicMock()
        _mod._shared_busio_instances[1] = sentinel

        await adapter.close()

        assert _mod._shared_busio_instances.get(1) is sentinel


# ─── health_check ─────────────────────────────────────────────────────────────


class TestHealthCheck:
    async def test_bme280_healthy_when_connected_with_handles(self):
        adapter = _connected_bme280_adapter()
        assert await adapter.health_check() is True

    async def test_bme280_unhealthy_when_bus_none(self):
        adapter = _connected_bme280_adapter()
        adapter._bus = None
        assert await adapter.health_check() is False

    async def test_ads1115_healthy_when_connected(self):
        adapter = _connected_ads_adapter("ads1115_current")
        assert await adapter.health_check() is True

    async def test_ads1115_unhealthy_when_ads_none(self):
        adapter = _connected_ads_adapter("ads1115_current")
        adapter._ads = None
        assert await adapter.health_check() is False

    async def test_scd40_healthy_when_connected(self):
        adapter = _connected_scd40_adapter()
        assert await adapter.health_check() is True

    async def test_unhealthy_when_disconnected(self):
        adapter = I2CAdapter()
        assert await adapter.health_check() is False


# ─── read — BME280 ────────────────────────────────────────────────────────────


class TestReadBme280:
    async def test_returns_sensor_reading(self):
        adapter = _connected_bme280_adapter()
        mock_data = MagicMock(temperature=22.5, pressure=1013.25, humidity=55.0)
        with patch("ori.hal.i2c_adapter._bme280_lib", create=True) as mock_lib:
            mock_lib.sample.return_value = mock_data
            reading = await adapter.read("env-01")

        assert reading.sensor_id == "env-01"
        assert reading.sensor_type == "bme280"
        assert reading.value == 22.5
        assert reading.unit == "celsius"
        assert reading.quality == 1.0

    async def test_pressure_and_humidity_in_metadata(self):
        adapter = _connected_bme280_adapter()
        mock_data = MagicMock(temperature=22.5, pressure=1013.25, humidity=55.0)
        with patch("ori.hal.i2c_adapter._bme280_lib", create=True) as mock_lib:
            mock_lib.sample.return_value = mock_data
            reading = await adapter.read("env-01")

        assert reading.metadata["pressure_hpa"] == 1013.25
        assert reading.metadata["humidity_percent"] == 55.0

    async def test_temperature_rounded_to_2dp(self):
        adapter = _connected_bme280_adapter()
        mock_data = MagicMock(temperature=22.5678, pressure=1013.0, humidity=50.0)
        with patch("ori.hal.i2c_adapter._bme280_lib", create=True) as mock_lib:
            mock_lib.sample.return_value = mock_data
            reading = await adapter.read("env-01")

        assert reading.value == 22.57

    async def test_read_when_not_connected_raises(self):
        adapter = I2CAdapter()
        adapter._sensor_type = "bme280"
        with pytest.raises(AdapterReadError, match="not connected"):
            await adapter.read("env-01")

    async def test_hardware_exception_raises_read_error(self):
        adapter = _connected_bme280_adapter()
        with patch("ori.hal.i2c_adapter._bme280_lib", create=True) as mock_lib:
            mock_lib.sample.side_effect = OSError("I2C read error")
            with pytest.raises(AdapterReadError):
                await adapter.read("env-01")


# ─── read — ADS1115 current ───────────────────────────────────────────────────


class TestReadAds1115Current:
    def _mock_channel(self, voltage: float) -> MagicMock:
        chan = MagicMock()
        chan.voltage = voltage
        return chan

    async def test_current_calibration_applied(self):
        """current_amps = adc_voltage / sensitivity"""
        adapter = _connected_ads_adapter("ads1115_current")
        adapter._sensitivity = 0.1
        mock_chan = self._mock_channel(0.5)  # 0.5V / 0.1 V/A = 5.0A

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as mock_analog:
            mock_analog.AnalogIn.return_value = mock_chan
            reading = await adapter.read("load-current")

        assert reading.value == 5.0
        assert reading.unit == "ampere"
        assert reading.sensor_type == "ads1115_current"

    async def test_custom_sensitivity_applied(self):
        adapter = _connected_ads_adapter("ads1115_current")
        adapter._sensitivity = 0.05  # 0.5V / 0.05 V/A = 10.0A
        mock_chan = self._mock_channel(0.5)

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as mock_analog:
            mock_analog.AnalogIn.return_value = mock_chan
            reading = await adapter.read("load-current")

        assert reading.value == 10.0

    async def test_adc_voltage_in_metadata(self):
        adapter = _connected_ads_adapter("ads1115_current")
        adapter._sensitivity = 0.1
        mock_chan = self._mock_channel(0.5)

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as mock_analog:
            mock_analog.AnalogIn.return_value = mock_chan
            reading = await adapter.read("load-current")

        assert reading.metadata["adc_voltage"] == 0.5
        assert reading.metadata["sensitivity_v_per_a"] == 0.1

    async def test_channel_used_correctly(self):
        adapter = _connected_ads_adapter("ads1115_current")
        adapter._channel = 2
        mock_chan = self._mock_channel(0.2)

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as mock_analog:
            mock_analog.AnalogIn.return_value = mock_chan
            await adapter.read("load-current")

        mock_analog.AnalogIn.assert_called_once_with(adapter._ads, 2)


# ─── read — ADS1115 voltage ───────────────────────────────────────────────────


class TestReadAds1115Voltage:
    async def test_returns_voltage_reading(self):
        adapter = _connected_ads_adapter("ads1115_voltage")
        mock_chan = MagicMock()
        mock_chan.voltage = 3.3

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as mock_analog:
            mock_analog.AnalogIn.return_value = mock_chan
            reading = await adapter.read("grid-voltage")

        assert reading.sensor_type == "ads1115_voltage"
        assert reading.value == 3.3
        assert reading.unit == "volt"

    async def test_channel_in_metadata(self):
        adapter = _connected_ads_adapter("ads1115_voltage")
        adapter._channel = 1
        mock_chan = MagicMock()
        mock_chan.voltage = 5.0

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as mock_analog:
            mock_analog.AnalogIn.return_value = mock_chan
            reading = await adapter.read("grid-voltage")

        assert reading.metadata["channel"] == 1


# ─── read — SCD40 ─────────────────────────────────────────────────────────────


class TestReadScd40:
    async def test_returns_co2_reading(self):
        adapter = _connected_scd40_adapter()
        adapter._scd4x.data_ready = True
        adapter._scd4x.CO2 = 412
        adapter._scd4x.temperature = 23.1
        adapter._scd4x.relative_humidity = 48.0

        reading = await adapter.read("co2-sensor")

        assert reading.sensor_type == "scd40"
        assert reading.value == 412.0
        assert reading.unit == "ppm"
        assert reading.quality == 1.0

    async def test_temperature_and_humidity_in_metadata(self):
        adapter = _connected_scd40_adapter()
        adapter._scd4x.data_ready = True
        adapter._scd4x.CO2 = 600
        adapter._scd4x.temperature = 25.5
        adapter._scd4x.relative_humidity = 60.0

        reading = await adapter.read("co2-sensor")

        assert reading.metadata["temperature_celsius"] == 25.5
        assert reading.metadata["humidity_percent"] == 60.0

    async def test_data_not_ready_raises_read_error(self):
        adapter = _connected_scd40_adapter()
        adapter._scd4x.data_ready = False

        with pytest.raises(AdapterReadError, match="not ready"):
            await adapter.read("co2-sensor")


# ─── read — timeout ───────────────────────────────────────────────────────────


class TestReadTimeout:
    async def test_slow_hardware_raises_timeout_error(self):
        adapter = _connected_bme280_adapter()

        # Patch _read_sync to block so wait_for would time out,
        # then simulate the TimeoutError by patching wait_for directly.
        with (
            patch.object(adapter, "_read_sync", return_value=MagicMock()),
            patch("ori.hal.i2c_adapter.asyncio") as mock_asyncio,
        ):
            mock_asyncio.wait_for = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_asyncio.get_running_loop = asyncio.get_running_loop
            mock_asyncio.TimeoutError = asyncio.TimeoutError
            with pytest.raises(AdapterTimeoutError):
                await adapter.read("env-01")


# ─── Pi-only integration tests ────────────────────────────────────────────────


@skip_if_no_pi
class TestPiIntegration:
    async def test_bme280_connect_and_read(self):
        adapter = I2CAdapter()
        await adapter.connect(
            {
                "sensor_type": "bme280",
                "sensor_id": "env-01",
                "address": 0x76,
                "bus": 1,
            }
        )
        assert adapter.is_connected
        reading = await adapter.read("env-01")
        assert reading.sensor_type == "bme280"
        assert -40.0 <= reading.value <= 85.0  # BME280 operating range
        await adapter.close()
        assert not adapter.is_connected

    async def test_ads1115_current_connect_and_read(self):
        adapter = I2CAdapter()
        await adapter.connect(
            {
                "sensor_type": "ads1115_current",
                "sensor_id": "load-current",
                "address": 0x48,
                "bus": 1,
                "channel": 0,
                "sensitivity": 0.1,
            }
        )
        assert adapter.is_connected
        reading = await adapter.read("load-current")
        assert reading.sensor_type == "ads1115_current"
        assert reading.unit == "ampere"
        await adapter.close()
