# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import math
import os
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    AdapterTimeoutError,
    HardwareCircuitBreaker,
)
from ori.hal.i2c_adapter import (
    _ADS1115_AVAILABLE,
    _BME280_AVAILABLE,
    I2CAdapter,
    _window_spec,
)

# ─── Pi guard ─────────────────────────────────────────────────────────────────

_HAS_I2C_BUS = os.path.exists("/dev/i2c-1")


def _needs_hardware(
    available: bool, package: str, part: str, address: int, article: str = "a"
):
    """Skip naming what is absent, rather than failing as though broken.

    An I2C bus node proves the host is a Pi. It does not prove a driver is
    installed or that anything answers at the address, and these tests need
    both. Reporting a missing driver as a failure reads as a defect in the
    adapter, so a Pi run showed two red tests that said nothing about the code.
    """
    return pytest.mark.skipif(
        not (_HAS_I2C_BUS and available),
        reason=(
            f"needs {article} {part} at I2C address 0x{address:02X} on bus 1 and the "
            f"{package} package; install it on the bench to run this for real"
        ),
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


# A 30 A : 1 V clamp on a 50 Hz supply. Stated rather than defaulted, because
# the adapter refuses to guess either.
CALIBRATION = {"sensitivity_v_per_amp": 1 / 30, "mains_frequency_hz": 50.0}


def _config(
    sensor_type: str = "bme280",
    sensor_id: str = "env-01",
    address: int = 0x76,
    bus: int = 1,
    channel: int = 0,
    calibration: dict | None = None,
) -> dict:
    config: dict = {
        "sensor_type": sensor_type,
        "sensor_id": sensor_id,
        "address": address,
        "bus": bus,
        "channel": channel,
    }
    if sensor_type == "ads1115_current":
        config["calibration"] = (
            dict(CALIBRATION) if calibration is None else calibration
        )
    return config


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


def _connected_ads_adapter(
    sensor_type: str = "ads1115_current", calibration: dict | None = None
) -> I2CAdapter:
    adapter = I2CAdapter()
    adapter._connected = True
    adapter._sensor_type = sensor_type
    adapter._channel = 0
    adapter._breaker = HardwareCircuitBreaker("I2CAdapter", {})
    adapter._ads = MagicMock()
    if sensor_type == "ads1115_current":
        from ori.hal.i2c_adapter import _resolve_calibration

        adapter._calibration = _resolve_calibration(
            {"calibration": dict(calibration or CALIBRATION)}
        )
        adapter._window = _window_spec(adapter._calibration)
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
            patch("ori.hal.i2c_adapter.smbus"),
            patch("ori.hal.i2c_adapter._BME280_AVAILABLE", False),
            pytest.raises(AdapterConnectionError, match="RPi.bme280"),
        ):
            await adapter.connect(_config(sensor_type="bme280"))

    async def test_connect_ads1115_missing_lib_raises(self):
        adapter = I2CAdapter()
        with (
            patch("ori.hal.i2c_adapter._ADS1115_AVAILABLE", False),
            pytest.raises(AdapterConnectionError) as excinfo,
        ):
            await adapter.connect(_config(sensor_type="ads1115_current"))
        message = str(excinfo.value)
        # Which sensor, which driver, and what to do about it — a bare library
        # name leaves an operator guessing which of several sensors is down.
        assert "ads1115_current" in message
        assert "ads1115" in message
        assert "pip install" in message

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
        with (
            patch("ori.hal.i2c_adapter._ADS1115_AVAILABLE", True),
            patch("ori.hal.i2c_adapter._BLINKA_AVAILABLE", True),
            patch("ori.hal.i2c_adapter._ads1115"),
            patch("ori.hal.i2c_adapter._ads1x15"),
            patch("ori.hal.i2c_adapter._analog_in"),
        ):
            with pytest.raises(
                AdapterConnectionError, match="currently only support I2C bus 1"
            ):
                await adapter.connect(_config(sensor_type="ads1115_current", bus=3))

    async def test_connect_resolves_the_declared_calibration(self):
        adapter = I2CAdapter()
        with (
            patch("ori.hal.i2c_adapter._ADS1115_AVAILABLE", True),
            patch("ori.hal.i2c_adapter._BLINKA_AVAILABLE", True),
            patch("ori.hal.i2c_adapter._busio", create=True),
            patch("ori.hal.i2c_adapter._board", create=True),
            patch("ori.hal.i2c_adapter._ads1115", create=True),
            patch("ori.hal.i2c_adapter._ads1x15", create=True),
            patch("ori.hal.i2c_adapter._analog_in", create=True),
        ):
            await adapter.connect(
                _config(
                    sensor_type="ads1115_current",
                    calibration={
                        "sensitivity_v_per_amp": 0.05,
                        "mains_frequency_hz": 60.0,
                    },
                )
            )
        assert adapter._calibration["sensitivity_v_per_amp"] == 0.05
        assert adapter._calibration["mains_frequency_hz"] == 60.0

    async def test_connect_stores_channel(self):
        adapter = I2CAdapter()
        with (
            patch("ori.hal.i2c_adapter._ADS1115_AVAILABLE", True),
            patch("ori.hal.i2c_adapter._BLINKA_AVAILABLE", True),
            patch("ori.hal.i2c_adapter._busio", create=True),
            patch("ori.hal.i2c_adapter._board", create=True),
            patch("ori.hal.i2c_adapter._ads1115", create=True),
            patch("ori.hal.i2c_adapter._ads1x15", create=True),
            patch("ori.hal.i2c_adapter._analog_in", create=True),
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


class TestCalibrationResolution:
    """Calibration is refused rather than defaulted, and owns only its own keys."""

    def _resolve(self, block: dict, top_level: dict | None = None) -> dict:
        from ori.hal.i2c_adapter import _resolve_calibration

        config: dict = {"calibration": block}
        config.update(top_level or {})
        return _resolve_calibration(config)

    def test_the_required_keys_have_no_defaults(self):
        """A guessed sensitivity produces a plausible number, not a measurement."""
        for missing in ("sensitivity_v_per_amp", "mains_frequency_hz"):
            block = dict(CALIBRATION)
            del block[missing]
            with pytest.raises(AdapterConnectionError, match=missing):
                self._resolve(block)

    def test_the_same_key_beside_the_block_is_refused_not_chosen(self):
        """The shape of the original defect, refused instead of resolved.

        A documented `sensitivity` sat at the sensor's top level, never reached
        the adapter, and the adapter's own default was used instead. Silently
        preferring one of two placements is what made that invisible.
        """
        with pytest.raises(AdapterConnectionError, match="not beside it"):
            self._resolve(dict(CALIBRATION), {"sensitivity_v_per_amp": 0.05})

    def test_a_misspelled_key_is_refused(self):
        block = dict(CALIBRATION)
        block["sensitivty_v_per_amp"] = 0.05
        with pytest.raises(AdapterConnectionError, match="unknown calibration keys"):
            self._resolve(block)

    def test_bounds_belonging_to_gateway_escalation_pass_through(self):
        """`calibration` is shared with escalation policy, which reads bounds here.

        Refusing unknown keys must not mean claiming the whole namespace.
        """
        block = dict(CALIBRATION)
        block.update({"min_value": 0.0, "max_value": 30.0})
        resolved = self._resolve(block)
        assert resolved["sensitivity_v_per_amp"] == pytest.approx(1 / 30)

    @pytest.mark.parametrize("bad", [0, -1, "abc", None, float("nan")])
    def test_a_value_that_is_not_a_positive_number_is_refused(self, bad):
        block = dict(CALIBRATION)
        block["sensitivity_v_per_amp"] = bad
        with pytest.raises(AdapterConnectionError):
            self._resolve(block)

    def test_a_fractional_window_is_refused_rather_than_truncated(self):
        """2.5 cycles truncated to 2 is a window that is not what config says."""
        block = dict(CALIBRATION)
        block["window_cycles"] = 2.5
        with pytest.raises(AdapterConnectionError, match="whole number of"):
            self._resolve(block)

    def test_a_rate_the_part_does_not_implement_is_refused(self):
        """The driver would substitute one, and the window would not be as declared."""
        block = dict(CALIBRATION)
        block["data_rate"] = 500
        with pytest.raises(AdapterConnectionError, match="not an ADS1115 rate"):
            self._resolve(block)

    def test_the_supply_rail_bounds_clipping_not_the_pga_range(self):
        """An ADS1115 on 3.3 V cannot see above 3.3 V, whatever the PGA is set to.

        Gain 1 is a +/-4.096 V conversion range. Treating that as the input
        limit would accept a waveform flattened against the 3.3 V supply rail,
        which reads as an honest, low RMS — an under-report, in the direction
        that talks a cutoff out of firing.
        """
        window = _window_spec(self._resolve(dict(CALIBRATION)))
        assert window.full_scale_volts == pytest.approx(3.3)

    def test_the_supply_rail_is_not_operator_calibration(self):
        """Raising it would disable the guard that catches a clipped waveform.

        It is a fact about the wiring, not a preference, so it is refused as a
        calibration key rather than accepted and used.
        """
        block = dict(CALIBRATION)
        block["supply_volts"] = 4.096
        with pytest.raises(AdapterConnectionError, match="unknown calibration keys"):
            self._resolve(block)

    def test_a_wider_pga_still_cannot_see_past_the_rail(self):
        """Gain 2/3 is +/-6.144 V; the input limit does not move with it."""
        block = dict(CALIBRATION)
        block["gain"] = 2 / 3
        assert _window_spec(self._resolve(block)).full_scale_volts == pytest.approx(3.3)


class TestReadAds1115Current:
    """The clamp path reads a window, not a sample.

    The old tests here set a single constant voltage and asserted a division.
    That is the defect, not the behaviour: one instantaneous sample of an
    alternating signal is a number whose value depends on when the poll landed.
    """

    def _waveform_channel(
        self, *, amplitude: float, bias: float = 1.65, cycles: int = 2
    ) -> MagicMock:
        """A channel whose voltage walks a sine, one step per read."""
        step = {"i": 0}

        def voltage() -> float:
            index = step["i"]
            step["i"] += 1
            # 64 points per window keeps the series smooth for any sample count
            # the adapter happens to take before its deadline.
            return bias + amplitude * math.sin(2 * math.pi * cycles * index / 64)

        channel = MagicMock()
        type(channel).voltage = property(lambda _self: voltage())
        return channel

    async def test_a_clamp_reading_is_the_rms_of_a_window(self):
        """1 V RMS into a 30 A : 1 V clamp is 30 A."""
        adapter = _connected_ads_adapter("ads1115_current")
        channel = self._waveform_channel(amplitude=math.sqrt(2))

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as analog:
            analog.AnalogIn.return_value = channel
            reading = await adapter.read("load-current")

        assert reading.unit == "ampere"
        assert reading.sensor_type == "ads1115_current"
        assert reading.value == pytest.approx(30.0, rel=0.05)

    async def test_the_declared_sensitivity_is_what_scales_the_reading(self):
        """The value the operator configured, not the adapter's own idea.

        A configured calibration that never reached the adapter is how a real
        10 A load could report as 1 A.
        """
        adapter = _connected_ads_adapter(
            "ads1115_current",
            calibration={"sensitivity_v_per_amp": 0.1, "mains_frequency_hz": 50.0},
        )
        channel = self._waveform_channel(amplitude=math.sqrt(2))

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as analog:
            analog.AnalogIn.return_value = channel
            reading = await adapter.read("load-current")

        assert reading.value == pytest.approx(10.0, rel=0.05)

    async def test_no_load_reads_as_no_current(self):
        adapter = _connected_ads_adapter("ads1115_current")
        channel = MagicMock()
        channel.voltage = 1.65

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as analog:
            analog.AnalogIn.return_value = channel
            reading = await adapter.read("load-current")

        assert reading.value == pytest.approx(0.0, abs=1e-3)

    async def test_metadata_records_what_the_window_actually_did(self):
        adapter = _connected_ads_adapter("ads1115_current")
        channel = self._waveform_channel(amplitude=1.0)

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as analog:
            analog.AnalogIn.return_value = channel
            reading = await adapter.read("load-current")

        assert reading.metadata["sensitivity_v_per_amp"] == pytest.approx(1 / 30)
        assert reading.metadata["mains_frequency_hz"] == 50.0
        assert reading.metadata["sample_count"] >= adapter._window.min_samples
        assert reading.metadata["window_ms"] > 0
        assert "bias_volts" in reading.metadata

    async def test_a_clipped_window_emits_no_reading_at_all(self):
        """The refusal must not arrive as a plausible number.

        A clipped waveform has lost its peaks, so its RMS reads low. Emitting
        that as amperes would under-report the current, which is the direction
        that talks a cutoff out of firing.
        """
        adapter = _connected_ads_adapter("ads1115_current")
        channel = MagicMock()
        channel.voltage = 4.09  # hard against the +/-4.096 V full scale

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as analog:
            analog.AnalogIn.return_value = channel
            with pytest.raises(AdapterReadError, match="clipped"):
                await adapter.read("load-current")

    async def test_a_window_the_hardware_could_not_fill_is_refused(self):
        """Too few samples cannot resolve a waveform, however plausible they look."""
        adapter = _connected_ads_adapter("ads1115_current")
        channel = MagicMock()
        slow = iter([1.65, 1.9, 1.4])

        def voltage() -> float:
            try:
                return next(slow)
            except StopIteration:
                time.sleep(adapter._window.nominal_seconds)
                return 1.65

        type(channel).voltage = property(lambda _self: voltage())

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as analog:
            analog.AnalogIn.return_value = channel
            with pytest.raises(AdapterReadError, match="fewer than"):
                await adapter.read("load-current")

    async def test_reads_are_paced_so_the_sample_floor_counts_conversions(self):
        """An unpaced loop counts reads, not conversions.

        In continuous mode the conversion register holds the last result and
        can be read far faster than the part converts, so a tight loop
        satisfies the sample floor with the same few values repeated. The
        floor would then be passing on nothing.
        """
        adapter = _connected_ads_adapter("ads1115_current")
        channel = self._waveform_channel(amplitude=1.0)
        reads: list[float] = []

        original = channel.__class__.voltage

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as analog:
            analog.AnalogIn.return_value = channel
            started = time.monotonic()
            reading = await adapter.read("load-current")
            elapsed = time.monotonic() - started

        del original, reads
        rate = adapter._calibration["data_rate"]
        expected = rate * adapter._window.nominal_seconds
        # Pacing bounds the count by the conversion rate. Without it the loop
        # takes thousands of reads in the same window.
        assert reading.metadata["sample_count"] <= expected * 1.2, (
            "more samples than the ADC could have converted in the window"
        )
        assert elapsed >= adapter._window.nominal_seconds * 0.9

    async def test_channel_used_correctly(self):
        adapter = _connected_ads_adapter("ads1115_current")
        adapter._channel = 2
        channel = self._waveform_channel(amplitude=1.0)

        with patch("ori.hal.i2c_adapter._analog_in", create=True) as analog:
            analog.AnalogIn.return_value = channel
            await adapter.read("load-current")

        analog.AnalogIn.assert_called_once_with(adapter._ads, 2)


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


class TestPiIntegration:
    """Real hardware. Skipped, with the reason named, when it is not present."""

    @_needs_hardware(_BME280_AVAILABLE, "bme280", "BME280", 0x76)
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

    @_needs_hardware(
        _ADS1115_AVAILABLE,
        "adafruit-circuitpython-ads1x15",
        "ADS1115",
        0x48,
        article="an",
    )
    async def test_ads1115_current_connect_and_read(self):
        adapter = I2CAdapter()
        await adapter.connect(
            {
                "sensor_type": "ads1115_current",
                "sensor_id": "load-current",
                "address": 0x48,
                "bus": 1,
                "channel": 0,
                "calibration": dict(CALIBRATION),
            }
        )
        assert adapter.is_connected
        reading = await adapter.read("load-current")
        assert reading.sensor_type == "ads1115_current"
        assert reading.unit == "ampere"
        await adapter.close()


class TestDriverGuardWidth:
    """The optional-driver guards must not care how a driver fails.

    adafruit-blinka's `board` raises RuntimeError when its platform library is
    absent, which an `except ImportError` guard let escape — crashing this
    module on import. It crashed only on a Raspberry Pi: a host with no blinka
    raises ImportError, so the narrow guard held everywhere the suite ran.
    """

    @staticmethod
    def _probe(error_expr: str) -> dict:
        """Import the adapter in a subprocess with `board` raising `error_expr`.

        A subprocess rather than a reimport: popping the module from
        `sys.modules` and re-importing leaves this file's module-level
        `I2CAdapter` bound to a stale class whose globals are the old module
        dict, so every later `patch("ori.hal.i2c_adapter....")` in this file
        would patch a different object. That is invisible while this class is
        last in the file and breaks two dozen unrelated tests the moment it is
        not.
        """
        import json
        import subprocess
        import sys
        from types import ModuleType  # noqa: F401  (used inside the child)

        program = f"""
import builtins, json, sys
from types import ModuleType

# The driver has to be importable for the guard to reach `board` at all: on a
# host without it the block fails at the first import and never gets there.
parent = ModuleType("adafruit_ads1x15")
sys.modules["adafruit_ads1x15"] = parent
for child in ("ads1x15", "ads1115", "analog_in"):
    module = ModuleType("adafruit_ads1x15." + child)
    setattr(parent, child, module)
    sys.modules["adafruit_ads1x15." + child] = module
sys.modules["busio"] = ModuleType("busio")

real_import = builtins.__import__
def fake_import(name, *args, **kwargs):
    if name == "board":
        raise {error_expr}
    return real_import(name, *args, **kwargs)
builtins.__import__ = fake_import

import ori.hal.i2c_adapter as m
print(json.dumps({{
    "ads1115_available": m._ADS1115_AVAILABLE,
    "blinka_available": m._BLINKA_AVAILABLE,
    "smbus_available": m._SMBUS_AVAILABLE,
    "ads_reason": m.i2c_driver_unavailable_reason("ads1115_current"),
    "scd40_reason": m.i2c_driver_unavailable_reason("scd40"),
    "bme280_reason": m.i2c_driver_unavailable_reason("bme280"),
}}))
"""
        completed = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        assert completed.returncode == 0, completed.stderr
        return json.loads(completed.stdout.strip().splitlines()[-1])

    def test_a_runtime_error_from_board_does_not_crash_the_import(self):
        result = self._probe(
            "RuntimeError(\"The platform library 'RPi' was not found\")"
        )

        # The ADS1115 driver itself imported: only blinka failed, and the two
        # are separate dependencies.
        assert result["ads1115_available"] is True
        assert result["blinka_available"] is False
        reason = result["ads_reason"]
        assert reason is not None
        assert "blinka" in reason
        assert "RuntimeError" in reason
        # The operator needs the real cause: "not installed" would send them
        # after a package that is already there.
        assert "platform library 'RPi'" in reason

    def test_an_import_error_is_still_handled(self):
        result = self._probe("ImportError(\"No module named 'board'\")")

        assert result["blinka_available"] is False
        assert "ImportError" in result["ads_reason"]

    def test_scd40_reports_blinka_and_not_the_ads1115_driver(self):
        """scd40 needs blinka for its bus, and the ADS1115 driver never.

        Folding board/busio into the ADS1115 guard made scd40 report a missing
        `adafruit_ads1x15` and told an operator to install a package their
        device does not use — while a CO2-only Pi, which has blinka and scd4x
        but no ads1x15, would be refused for a sensor that works.
        """
        result = self._probe(
            "RuntimeError(\"The platform library 'RPi' was not found\")"
        )

        reason = result["scd40_reason"]
        assert reason is not None
        assert "blinka" in reason
        assert "ads1115" not in reason

    def test_one_broken_guard_does_not_contaminate_another(self):
        """Each guarded block records only its own failure."""
        result = self._probe("RuntimeError('boom')")

        assert "boom" in result["ads_reason"]
        assert "boom" not in (result["bme280_reason"] or "")

    def test_bme280_reports_smbus2_which_it_also_needs(self):
        from ori.hal.i2c_adapter import _DRIVER_UNAVAILABLE, _SENSOR_TYPE_DRIVERS

        assert "smbus2" in _SENSOR_TYPE_DRIVERS["bme280"]
        # Every recorded driver must be reachable through some sensor type, or
        # the table and the guards have drifted.
        reachable = {d for drivers in _SENSOR_TYPE_DRIVERS.values() for d in drivers}
        assert set(_DRIVER_UNAVAILABLE) <= reachable

    def test_a_sensor_type_needing_no_driver_reports_nothing(self):
        from ori.hal.i2c_adapter import i2c_driver_unavailable_reason

        assert i2c_driver_unavailable_reason("cpu_percent") is None
