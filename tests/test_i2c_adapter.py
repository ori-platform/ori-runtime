# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import importlib
import itertools
import math
import os
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ori.hal import i2c_adapter as i2c_module
from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    AdapterTimeoutError,
    HardwareCircuitBreaker,
    MeasurementRefusedError,
)
from ori.hal.i2c_adapter import (
    _ADS1115_AVAILABLE,
    _BLINKA_AVAILABLE,
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

    `available` must cover every driver the sensor type reads through, not just
    the one that names it. An ADS1115 needs blinka for its bus as well as the
    ADC driver, and a guard that checked only the latter would run the test on
    a host that cannot open a bus — failing at connect, which is the outcome
    this decorator exists to prevent.
    """
    return pytest.mark.skipif(
        not (_HAS_I2C_BUS and available),
        reason=(
            f"needs {article} {part} at I2C address 0x{address:02X} on bus 1 and the "
            f"{package} package; install it on the bench to run this for real"
        ),
    )


@pytest.fixture(autouse=True)
def _clear_ads1115_claims():
    """One ADS1115 serves one adapter, and most tests never close theirs."""
    i2c_module._ADS1115_CLAIMS.clear()
    i2c_module._ADS1115_QUARANTINE.clear()
    yield
    i2c_module._ADS1115_CLAIMS.clear()
    i2c_module._ADS1115_QUARANTINE.clear()


@pytest.fixture(autouse=True)
def _clear_shared_i2c_bus_cache():
    """Ensure tests don't leak cached bus handles."""
    i2c_module._shared_busio_instances.clear()
    i2c_module._shared_busio_refs.clear()
    yield
    i2c_module._shared_busio_instances.clear()
    i2c_module._shared_busio_refs.clear()


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
    # The config readback before every measurement: the configured channel
    # single-ended (mux 4 + n), PGA gain 1, continuous, 860 SPS, comparator off.
    adapter._holds_shared_bus = True
    adapter._ads.gain = 1
    adapter._ads.data_rate = 860
    adapter._ads._read_register.side_effect = lambda *_a, **_k: (
        ((4 + adapter._channel) << 12) | 0x0200 | 0x00E0 | 0x0003
    )
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
    adapter._holds_shared_bus = True
    adapter._breaker = HardwareCircuitBreaker("I2CAdapter", {})
    adapter._scd4x = MagicMock()
    return adapter


# ─── Module import (no hardware needed) ──────────────────────────────────────


class TestModuleImport:
    def test_imports_cleanly_without_hardware_libraries(self):
        """The module must import on any host regardless of smbus2/adafruit presence."""
        importlib.import_module("ori.hal.i2c_adapter")

    def test_adapter_instantiates_without_hardware(self):
        adapter = I2CAdapter()
        assert adapter is not None
        assert adapter.is_connected is False


# ─── connect — validation ─────────────────────────────────────────────────────


class _PinnedDriverADS1115:
    """The 3.0.5 driver's channel, pointer and single-shot behaviour, reproduced.

    In `Mode.SINGLE`, writing a pin sets the mux and the OS bit and a read
    polls the conversion-complete bit — forever, if it never sets. In
    `Mode.CONTINUOUS` the pin is discarded and the chip's existing mux kept;
    once a pin has been read, later reads take a *fast* path that does not
    move the register pointer. Every config write moves the pointer to
    CONFIG; a fast read returns whatever the pointer is on, config word
    included.

    A fake more permissive than this on any of those lets a wrong connect
    sequence pass, which is exactly what happened once. The guard tests at
    the end of this file hold the fake to the driver.
    """

    SINGLE, CONTINUOUS = 0x0100, 0x0000
    POINTER_CONVERSION, POINTER_CONFIG = 0x00, 0x01

    def __init__(
        self,
        i2c,
        address=0x48,
        gain=1,
        data_rate=860,
        mode=None,
        *,
        chip_mux: int = 0,
        honours_pin_in_single: bool = True,
        conversion=0,
        completes: bool = True,
    ):
        self.address, self.gain, self.data_rate = address, gain, data_rate
        self._mux = chip_mux  # power-on default: A0-A1 differential
        self._honours = honours_pin_in_single
        self._mode = self.SINGLE if mode is None else mode
        # Normalised to a callable so a waveform and a fixed value take the
        # same path, and nothing has to call a value that might be an int.
        self._conversion = conversion if callable(conversion) else (lambda: conversion)
        self._completes = completes
        self._pointer = self.POINTER_CONFIG
        self._last_pin_read = None
        # The chip's gain and rate fields, settable so a test can be the other
        # process that rewrites them without touching the mux.
        self._gain_bits = 0x0200  # gain 1
        self._rate_bits = 0x00E0  # 860 SPS
        self.writes: list[tuple[str, int | None]] = []

    @property
    def mode(self):
        return self._mode

    @mode.setter
    def mode(self, value):
        self._mode = value
        self._write_config(None)

    def _config_word(self) -> int:
        return (
            (self._mux << 12) | self._gain_bits | self._mode | self._rate_bits | 0x0003
        )

    def _write_config(self, pin_config):
        if pin_config is not None and self._mode == self.SINGLE and self._honours:
            self._mux = pin_config & 0x7
        # else: continuous, or a driver that ignores the pin: keep the chip's mux
        self._pointer = self.POINTER_CONFIG
        self.writes.append(("config", pin_config))

    def _conversion_complete(self) -> int:
        return 0x8000 if self._completes else 0

    def _read(self, pin):
        self.writes.append(("sample", pin))
        if self._mode == self.CONTINUOUS and self._last_pin_read == pin:
            return self.get_last_result(True)
        self._last_pin_read = pin
        self._write_config(pin)
        if self._mode == self.SINGLE:
            while not self._conversion_complete():
                pass  # the real driver spins here with no bound
        return self.get_last_result(False)

    def read(self, pin):
        return self._read(pin)

    def get_last_result(self, fast: bool = False) -> int:
        return self._read_register(self.POINTER_CONVERSION, fast)

    def _read_register(self, pointer, fast: bool = False):
        if not fast:
            self._pointer = pointer
        if self._pointer == self.POINTER_CONFIG:
            return self._config_word()
        return self._conversion()


class _PinnedDriverAnalogIn:
    def __init__(self, ads, positive_pin, negative_pin=None):
        self._ads, self._pin = ads, positive_pin

    @property
    def value(self):
        # Single-ended AINn is mux code 4 + n, as the driver maps it.
        return self._ads.read(self._pin + 0x04)

    @property
    def voltage(self):
        # Gain 1: +/-4.096 V over a signed 16-bit range, as the driver scales.
        raw = self.value
        if raw >= 0x8000:
            raw -= 0x10000
        return raw * 4.096 / 32767


def _pinned_driver(monkeypatch, **ads_kwargs):
    """Install the reproduction as the adapter's driver for one test."""
    created: list[_PinnedDriverADS1115] = []

    def _construct(i2c, **kw):
        ads = _PinnedDriverADS1115(i2c, **kw, **ads_kwargs)
        created.append(ads)
        return ads

    class _Module:
        # The driver's class is spelled ADS1115; this must answer to that name.
        ADS1115 = staticmethod(_construct)

    class _Mode:
        SINGLE = _PinnedDriverADS1115.SINGLE
        CONTINUOUS = _PinnedDriverADS1115.CONTINUOUS

    class _X:
        Mode = _Mode

    class _AI:
        AnalogIn = _PinnedDriverAnalogIn

    monkeypatch.setattr(i2c_module, "_ADS1115_AVAILABLE", True)
    monkeypatch.setattr(i2c_module, "_BLINKA_AVAILABLE", True)
    monkeypatch.setattr(i2c_module, "_busio", MagicMock(), raising=False)
    monkeypatch.setattr(i2c_module, "_board", MagicMock(), raising=False)
    monkeypatch.setattr(i2c_module, "_ads1115", _Module, raising=False)
    monkeypatch.setattr(i2c_module, "_ads1x15", _X, raising=False)
    monkeypatch.setattr(i2c_module, "_analog_in", _AI, raising=False)
    return created


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

    async def test_connect_resolves_the_declared_calibration(self, monkeypatch):
        _pinned_driver(monkeypatch)
        adapter = I2CAdapter()
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

    async def test_connect_stores_channel(self, monkeypatch):
        created = _pinned_driver(monkeypatch)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_current", channel=2))
        assert adapter._channel == 2
        # And the chip agrees: single-ended AIN2 is mux code 6.
        assert created[0]._mux == 6

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
        adapter = _connected_ads_adapter("ads1115_current")
        adapter._bus_number = 1
        i2c_module._shared_busio_instances[1] = MagicMock()  # seed the cache
        i2c_module._shared_busio_refs[1] = 1  # seed the reference

        await adapter.close()

        assert 1 not in i2c_module._shared_busio_instances
        assert 1 not in i2c_module._shared_busio_refs

    async def test_close_evicts_shared_bus_cache_for_scd40(self):
        adapter = _connected_scd40_adapter()
        adapter._bus_number = 1
        i2c_module._shared_busio_instances[1] = MagicMock()
        i2c_module._shared_busio_refs[1] = 1

        await adapter.close()

        assert 1 not in i2c_module._shared_busio_instances
        assert 1 not in i2c_module._shared_busio_refs

    async def test_close_does_not_evict_if_references_remain(self):
        """If 2 sensors share a bus, close() on the first leaves the cache intact."""
        adapter = _connected_ads_adapter("ads1115_current")
        adapter._bus_number = 1
        sentinel = MagicMock()
        i2c_module._shared_busio_instances[1] = sentinel
        i2c_module._shared_busio_refs[1] = 2  # 2 sensors actively using the bus

        await adapter.close()

        # The cache MUST stay alive to serve the second sensor
        assert i2c_module._shared_busio_instances.get(1) is sentinel
        assert i2c_module._shared_busio_refs.get(1) == 1

    async def test_close_does_not_evict_cache_for_bme280(self):
        """BME280 uses smbus2 directly — it must not touch the busio cache."""
        adapter = _connected_bme280_adapter()
        adapter._bus_number = 1
        sentinel = MagicMock()
        i2c_module._shared_busio_instances[1] = sentinel

        await adapter.close()

        assert i2c_module._shared_busio_instances.get(1) is sentinel


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

    _ADS1115_GUARD = dict(
        available=_ADS1115_AVAILABLE and _BLINKA_AVAILABLE,
        package=(
            "adafruit-circuitpython-ads1x15 and a blinka platform library "
            "(python3-rpi-lgpio on Raspberry Pi OS Trixie)"
        ),
        part="ADS1115",
        address=0x48,
        article="an",
    )

    @_needs_hardware(**_ADS1115_GUARD)
    async def test_ads1115_voltage_connect_and_read(self):
        """The bus, the driver, the address and the read path, end to end.

        A DC read needs no signal conditioning, so this runs on the bench as
        wired: A0 tied to a header ground pin reads within a few millivolts
        of zero. It proves the ADS1115 answers at 0x48 through the release's
        driver stack; it says nothing about the current measurement contract.
        """
        adapter = I2CAdapter()
        await adapter.connect(
            {
                "sensor_type": "ads1115_voltage",
                "sensor_id": "a0-volts",
                "address": 0x48,
                "bus": 1,
                "channel": 0,
            }
        )
        assert adapter.is_connected
        reading = await adapter.read("a0-volts")
        assert reading.sensor_type == "ads1115_voltage"
        assert reading.unit == "volt"
        # A grounded input, not a floating one: unconnected channels on this
        # part float at roughly +0.56 V, which is the signature to exclude.
        assert abs(reading.value) < 0.05, reading.value
        await adapter.close()

    async def _a0_volts(self) -> float:
        adapter = I2CAdapter()
        await adapter.connect(
            {
                "sensor_type": "ads1115_voltage",
                "sensor_id": "probe",
                "address": 0x48,
                "bus": 1,
                "channel": 0,
            }
        )
        try:
            return (await adapter.read("probe")).value
        finally:
            await adapter.close()

    async def _a0_is_at_a_rail(self) -> bool:
        from ori.hal.i2c_adapter import _ADC_SUPPLY_VOLTS, _OPTIONAL_CALIBRATION

        volts = await self._a0_volts()
        margin = _OPTIONAL_CALIBRATION["clip_margin_volts"]
        return volts <= margin or volts >= _ADC_SUPPLY_VOLTS - margin

    async def _a0_is_biased_to_mid_rail(self) -> bool:
        """The bias network holds A0 near VDD/2. A floating pin does not.

        "Not at a rail" is not the same test: an unconnected A0 on this part
        floats at roughly +0.5 V, which is off both rails and would let the
        RMS test emit a current for a wire that is not attached to anything.
        """
        from ori.hal.i2c_adapter import _ADC_SUPPLY_VOLTS

        return abs(await self._a0_volts() - _ADC_SUPPLY_VOLTS / 2) < 0.2

    @_needs_hardware(**_ADS1115_GUARD)
    async def test_ads1115_current_refuses_an_input_pinned_at_a_rail(self):
        """A grounded A0 is refused as clipped, and that is the right answer.

        A current clamp rides on a mid-rail bias; a sample at either rail means
        the amplitude is unknown. The bench without its bias network puts A0
        at the low rail, so this is hardware evidence for the clip refusal's
        low-rail half — the only half a grounded input can exercise.
        """
        if not await self._a0_is_at_a_rail():
            pytest.skip("A0 is not at a rail; the bias network is connected")
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
        try:
            with pytest.raises(MeasurementRefusedError, match="clipped"):
                await adapter.read("load-current")
        finally:
            await adapter.close()

    @_needs_hardware(**_ADS1115_GUARD)
    async def test_ads1115_current_connect_and_read(self):
        """The measurement contract, over a real biased clamp signal.

        Needs the mid-rail bias network on A0 — two equal resistors from 3.3 V
        to ground with a capacitor holding the midpoint, and the SCT-013-030
        across the midpoint and A0. Without it A0 sits at a rail and the
        window is refused as clipped, which the test above asserts instead.
        """
        if not await self._a0_is_biased_to_mid_rail():
            pytest.skip(
                "A0 is not held at mid-rail: connect the bias network and the "
                "clamp to exercise the current measurement"
            )
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
        assert reading.metadata["sample_count"] > 0
        # The window measured a signal riding on the bias, not a floating pin.
        from ori.hal.i2c_adapter import _ADC_SUPPLY_VOLTS

        assert abs(reading.metadata["bias_volts"] - _ADC_SUPPLY_VOLTS / 2) < 0.2
        await adapter.close()


class TestAds1115ChannelSelection:
    """The configured channel must be the input the chip is actually reading.

    adafruit-circuitpython-ads1x15 3.0.5 never selects a channel in continuous
    mode, and the adapter used to build the object in continuous mode — so it
    read whatever mux the chip held, which on a fresh chip is the A0-A1
    differential. These tests drive the connect against a fake that behaves as
    that driver does.
    """

    async def test_connect_selects_the_channel_through_single_shot_then_goes_continuous(
        self, monkeypatch
    ):
        created = _pinned_driver(monkeypatch, chip_mux=0)  # power-on: A0-A1 diff
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_current", channel=0))
        ads = created[0]
        assert ads._mux == 4, "AIN0 single-ended is mux code 4"
        assert ads.mode == ads.CONTINUOUS
        # The order is what makes it work: the pin write happens in SINGLE.
        modes_at_pin_write = [w for w in ads.writes if w[1] is not None]
        assert modes_at_pin_write, "no pin was ever written"

    async def test_a_chip_left_on_another_channel_is_moved(self, monkeypatch):
        created = _pinned_driver(monkeypatch, chip_mux=7)  # left on AIN3 single
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_voltage", channel=1))
        assert created[0]._mux == 5

    async def test_a_driver_that_ignores_the_pin_entirely_is_refused(self, monkeypatch):
        """If even single-shot did not honour the pin, the readback catches it."""
        _pinned_driver(monkeypatch, chip_mux=0, honours_pin_in_single=False)
        adapter = I2CAdapter()
        with pytest.raises(AdapterConnectionError) as excinfo:
            await adapter.connect(_config(sensor_type="ads1115_current", channel=0))
        message = str(excinfo.value)
        assert "mux code 0" in message
        assert "channel 0" in message
        assert not adapter.is_connected

    async def test_a_readback_that_fails_refuses_rather_than_assumes(self, monkeypatch):
        """Only the config readback is broken: the mux-selecting read still works.

        Breaking every register read would fail the connect one step earlier,
        in the single-shot read, and prove nothing about the verification.
        """
        _pinned_driver(monkeypatch)
        adapter = I2CAdapter()
        original = _PinnedDriverADS1115._read_register

        def config_read_fails(self, pointer, fast=False):
            if pointer == self.POINTER_CONFIG:
                raise OSError("[Errno 121] Remote I/O error")
            return original(self, pointer, fast)

        monkeypatch.setattr(_PinnedDriverADS1115, "_read_register", config_read_fails)
        with pytest.raises(AdapterConnectionError, match="could not read back"):
            await adapter.connect(_config(sensor_type="ads1115_current", channel=0))
        assert not adapter.is_connected

    async def test_connect_leaves_the_pointer_on_the_conversion_register(
        self, monkeypatch
    ):
        """A fast read after connect must return a sample, not the config word.

        The mode switch and the mux readback both leave the chip's pointer on
        CONFIG. The driver's continuous-mode read is a fast read that does not
        move it, so without a pointered read at the end of connect every
        sample would be 0x42E3 — which scales to +2.14 V, a number no clip
        check questions. Measured on the bench before the fix.
        """
        created = _pinned_driver(monkeypatch, chip_mux=0, conversion=-2)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_voltage", channel=0))
        ads = created[0]
        assert ads._pointer == ads.POINTER_CONVERSION
        assert ads.get_last_result(True) == -2, "fast read returned the config word"

    async def test_the_reproduction_really_returns_the_config_word_on_a_fast_read(self):
        """Guards the fake: without this, the pointer test above proves nothing."""
        ads = _PinnedDriverADS1115(
            None, mode=_PinnedDriverADS1115.SINGLE, chip_mux=4, conversion=-2
        )
        ads._write_config(4)
        assert ads.get_last_result(True) == ads._config_word()
        ads.get_last_result(False)
        assert ads.get_last_result(True) == -2

    async def test_a_second_adapter_on_the_same_chip_is_refused(self, monkeypatch):
        """One ADS1115 serves one adapter: a second connect would move the mux.

        The shipped example puts load-current on A0 and grid-voltage on A1 at
        one address. With one driver object per adapter, the second connect
        moves the shared mux and the first adapter's fast reads then return
        the other channel — both connects having verified their own. Refused
        at connect rather than discovered as volts reported as amperes.
        """
        _pinned_driver(monkeypatch, chip_mux=0)
        first = I2CAdapter()
        await first.connect(_config(sensor_type="ads1115_current", channel=0))
        second = I2CAdapter()
        with pytest.raises(AdapterConnectionError, match="already driven"):
            await second.connect(_config(sensor_type="ads1115_voltage", channel=1))
        assert not second.is_connected
        await first.close()
        # Released on close: the chip can be claimed again.
        await second.connect(_config(sensor_type="ads1115_voltage", channel=1))
        assert second.is_connected
        await second.close()

    async def test_a_failed_connect_does_not_keep_the_claim(self, monkeypatch):
        _pinned_driver(monkeypatch, chip_mux=0, honours_pin_in_single=False)
        first = I2CAdapter()
        with pytest.raises(AdapterConnectionError):
            await first.connect(_config(sensor_type="ads1115_current", channel=0))
        _pinned_driver(monkeypatch, chip_mux=0)
        second = I2CAdapter()
        await second.connect(_config(sensor_type="ads1115_current", channel=0))
        assert second.is_connected
        await second.close()

    async def test_a_chip_that_never_completes_a_conversion_is_refused_not_hung(
        self, monkeypatch
    ):
        """A TMP102, LM75 or PCF8591 defaults to 0x48 and ACKs with bit 15 clear.

        The driver's own single-shot read spins on that bit with no bound; a
        connect that hangs never reaches the runtime's event loop, and Tier D
        never arms, with no log line to say so.
        """
        _pinned_driver(monkeypatch, chip_mux=0, completes=False)
        adapter = I2CAdapter()
        started = time.monotonic()
        with pytest.raises(
            AdapterConnectionError, match="never completed a conversion"
        ):
            await adapter.connect(_config(sensor_type="ads1115_current", channel=0))
        assert time.monotonic() - started < 2.0
        assert not adapter.is_connected

    @pytest.mark.parametrize("channel", [-1, -4, 4, 7])
    async def test_a_channel_this_part_does_not_have_is_refused(
        self, monkeypatch, channel
    ):
        """Below zero the readback's `4 + channel` lands on a differential code."""
        _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        with pytest.raises(AdapterConnectionError, match="channel must be 0-3"):
            await adapter.connect(
                _config(sensor_type="ads1115_voltage", channel=channel)
            )

    async def test_every_read_returns_a_conversion_not_the_config_word(
        self, monkeypatch
    ):
        """Driven through `adapter.read()`, the way the runtime reads.

        Read more than once. The per-measurement readback re-points the
        register itself, so a first read passes whether or not the read path
        does — the defect returns from the second read onward, which is where a
        runtime polling every second spends all of its time. -2 counts at gain
        1 is -0.00025 V; the config word is +2.14 V.
        """
        _pinned_driver(monkeypatch, chip_mux=0, conversion=0xFFFE)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_voltage", channel=0))
        for _ in range(3):
            reading = await adapter.read("s")
            assert abs(reading.value) < 0.01, reading.value
        await adapter.close()

    async def test_every_current_window_measures_the_signal(self, monkeypatch):
        """The current twin of the read above, and the one that reaches Tier D.

        A window of identical config words is neither clipped nor short, so it
        is emitted: a steady load becomes 0.0 A, silently, from the second poll
        onward. Two windows over the same signal must agree.
        """
        counts = itertools.count()
        bias, peak = 1.65, 0.5

        def square():
            volts = bias + (peak if next(counts) % 2 == 0 else -peak)
            return int(volts * 32767 / 4.096)

        _pinned_driver(monkeypatch, chip_mux=0, conversion=square)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_current", channel=0))
        first = (await adapter.read("s")).value
        second = (await adapter.read("s")).value
        # 0.5 V RMS over a 1/30 V/A clamp is 15 A.
        assert first > 10.0, first
        assert abs(second - first) < 0.1 * first, (first, second)
        await adapter.close()

    async def test_a_mux_moved_under_a_connected_adapter_refuses_the_measurement(
        self, monkeypatch
    ):
        """Verified at connect is not verified for the life of the process.

        Something in another process on the same chip can move the mux. The
        re-verification before every measurement is what catches it.
        """
        created = _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_voltage", channel=0))
        created[0]._mux = 5  # someone else selected A1 on the chip
        with pytest.raises(AdapterReadError, match="mux code 5"):
            await adapter.read("s")
        await adapter.close()

    async def test_a_mux_moved_under_a_current_adapter_refuses_the_window(
        self, monkeypatch
    ):
        """The current path is the one that reaches Tier D; it re-verifies too.

        Refused for the mux, before any sample is taken — not for the clipped
        window a grounded fake would otherwise produce.
        """
        created = _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_current", channel=0))
        created[0]._mux = 5
        with pytest.raises(AdapterReadError, match="mux code 5"):
            await adapter.read("s")
        assert not any(w[0] == "sample" for w in created[0].writes)
        await adapter.close()

    async def test_single_shot_mode_set_by_something_else_is_refused(self, monkeypatch):
        """Same mux, and the chip stops converting after one sample.

        A diagnostic script or a default driver instance reading this channel
        writes single-shot. The mux it writes is the one already configured, so
        a check on the mux alone passes while the window that follows is one
        held value repeated.
        """
        created = _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_current", channel=0))
        created[0]._mode = _PinnedDriverADS1115.SINGLE
        with pytest.raises(MeasurementRefusedError, match="conversion mode"):
            await adapter.read("s")
        await adapter.close()

    async def test_a_gain_set_by_something_else_is_refused(self, monkeypatch):
        """Same mux, every sample rescaled, and the error under-reports.

        At gain 2/3 against the gain 1 the adapter set, a current reads about
        two thirds of itself. Nothing about the number looks wrong.
        """
        created = _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_current", channel=0))
        created[0]._gain_bits = 0x0000  # gain 2/3
        with pytest.raises(MeasurementRefusedError, match="0x40E3"):
            await adapter.read("s")
        await adapter.close()

    async def test_a_data_rate_set_by_something_else_is_refused(self, monkeypatch):
        created = _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_voltage", channel=0))
        created[0]._rate_bits = 0x0080  # 128 SPS
        with pytest.raises(MeasurementRefusedError, match="data rate"):
            await adapter.read("s")
        await adapter.close()

    async def test_a_voltage_refusal_keeps_its_class(self, monkeypatch):
        """`MeasurementRefusedError` is what the runtime degrades and alerts on.

        Downgrading it to its parent here would leave a voltage sensor that
        cannot prove its input reporting nothing but a warning line, and a
        voltage channel can be a safety input.
        """
        created = _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_voltage", channel=0))
        created[0]._mux = 5
        with pytest.raises(MeasurementRefusedError):
            await adapter.read("s")
        await adapter.close()

    async def test_a_connect_that_fails_after_the_readback_releases_the_claim(
        self, monkeypatch
    ):
        """The claim is taken before the chip is touched, so it must not outlive it."""

        class _FailsLate(_PinnedDriverADS1115):
            """Fails on the last register access of connect, not the first.

            Connect makes two pointered conversion reads: one closing the
            single-shot channel select, one closing the whole sequence. Only
            the second is past the configuration readback, so only it reaches
            the window this test is about.
            """

            pointered = 0

            def get_last_result(self, fast: bool = False):
                if not fast:
                    _FailsLate.pointered += 1
                    if _FailsLate.pointered == 2:
                        raise OSError("bus fell over after the readback")
                return super().get_last_result(fast)

        _pinned_driver(monkeypatch, chip_mux=0)
        monkeypatch.setattr(i2c_module._ads1115, "ADS1115", _FailsLate)
        first = I2CAdapter()
        with pytest.raises(AdapterConnectionError):
            await first.connect(_config(sensor_type="ads1115_voltage", channel=0))
        monkeypatch.setattr(i2c_module._ads1115, "ADS1115", _PinnedDriverADS1115)
        second = I2CAdapter()
        await second.connect(_config(sensor_type="ads1115_voltage", channel=0))
        assert second.is_connected
        await second.close()

    @pytest.mark.parametrize("channel", [2.5, True, "1", None])
    async def test_a_channel_that_is_not_an_integer_is_refused(
        self, monkeypatch, channel
    ):
        """`int()` turns 2.5 into 2 and True into 1, both inside the range.

        Config load refuses these; an adapter reached directly must too, so
        that neither layer is the only one holding.
        """
        _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        with pytest.raises(AdapterConnectionError, match="must be an integer"):
            await adapter.connect(
                _config(sensor_type="ads1115_voltage", channel=channel)
            )

    async def test_a_refused_duplicate_does_not_pin_the_shared_bus(self, monkeypatch):
        """A refused connect is dropped by the runtime without a close().

        `ori/runtime.py` logs the failure and continues to the next sensor, so
        nothing calls the refused adapter's teardown. If connect() took a
        reference on the shared bus before refusing, that reference is never
        given back: the cached handle outlives its last real user, and the
        next connect on that bus is handed the stale one.
        """
        _pinned_driver(monkeypatch, chip_mux=0)
        first = I2CAdapter()
        await first.connect(_config(sensor_type="ads1115_current", channel=0))
        second = I2CAdapter()
        with pytest.raises(AdapterConnectionError, match="already driven"):
            await second.connect(_config(sensor_type="ads1115_voltage", channel=1))
        # The runtime's own handling: the refused adapter is simply dropped.
        del second
        assert i2c_module._shared_busio_refs.get(1) == 1
        await first.close()
        assert i2c_module._shared_busio_refs == {}
        assert i2c_module._shared_busio_instances == {}

    @pytest.mark.parametrize(
        "failure", ["channel", "claimed", "construct", "verify", "late_read"]
    )
    async def test_no_failed_connect_pins_the_shared_bus(self, monkeypatch, failure):
        """Every way connect() can fail gives the reference back.

        The refusal is the interesting one, but it is not the only path that
        raises after the bus is reachable, and a leak on any of them has the
        same effect on the next connect.
        """
        _pinned_driver(monkeypatch, chip_mux=0)
        holder = None
        config = _config(sensor_type="ads1115_voltage", channel=0)
        if failure == "channel":
            config = _config(sensor_type="ads1115_voltage", channel=9)
        elif failure == "claimed":
            holder = I2CAdapter()
            await holder.connect(_config(sensor_type="ads1115_voltage", channel=0))
        elif failure == "construct":

            def _explode(i2c, **kw):
                raise OSError("no device")

            monkeypatch.setattr(i2c_module._ads1115, "ADS1115", staticmethod(_explode))
        elif failure == "verify":
            _pinned_driver(monkeypatch, chip_mux=0, honours_pin_in_single=False)
        elif failure == "late_read":

            class _FailsLate(_PinnedDriverADS1115):
                pointered = 0

                def get_last_result(self, fast: bool = False):
                    if not fast:
                        _FailsLate.pointered += 1
                        if _FailsLate.pointered == 2:
                            raise OSError("bus fell over")
                    return super().get_last_result(fast)

            monkeypatch.setattr(i2c_module._ads1115, "ADS1115", _FailsLate)

        adapter = I2CAdapter()
        with pytest.raises(AdapterConnectionError):
            await adapter.connect(config)
        assert not adapter._holds_shared_bus
        expected = 1 if holder is not None else 0
        assert i2c_module._shared_busio_refs.get(1, 0) == expected
        if holder is not None:
            await holder.close()
        assert i2c_module._shared_busio_refs == {}

    async def test_a_second_close_does_not_release_a_reference_twice(self, monkeypatch):
        """The count is shared, so an extra release evicts someone else's handle."""
        _pinned_driver(monkeypatch, chip_mux=0)
        first = I2CAdapter()
        await first.connect(_config(sensor_type="ads1115_voltage", channel=0))
        # A second chip at its own address: a legitimate second reference on
        # the same bus, which is exactly what must survive the extra close.
        second = I2CAdapter()
        await second.connect(
            _config(
                sensor_type="ads1115_voltage",
                address=0x49,
                channel=1,
                sensor_id="v2",
            )
        )
        assert i2c_module._shared_busio_refs.get(1) == 2
        await first.close()
        await first.close()
        # The second adapter is still reading through this handle.
        assert i2c_module._shared_busio_refs.get(1) == 1
        assert 1 in i2c_module._shared_busio_instances
        await second.close()
        assert i2c_module._shared_busio_refs == {}

    async def test_a_refused_measurement_holds_and_never_rewrites_the_chip(
        self, monkeypatch
    ):
        """The refusal is terminal for the process, and it is read-only.

        A reading that refuses is evidence that something outside this process
        changed the configuration after connect. This adapter's claim keeps a
        second Ori adapter off the chip; it establishes nothing against another
        process, a reset line or a second controller. Writing the configuration
        back would be a contest with whatever moved it, and losing that
        intermittently produces a plausible number instead of a refusal.

        So every subsequent read refuses on its own terms, and the chip is left
        exactly as it was found. Recovery is a restart, after the competing
        writer is gone.
        """
        created = _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_current", channel=0))
        ads = created[0]

        # Something else takes the chip: same mux, different gain.
        ads._gain_bits = 0x0000
        settled = len([w for w in ads.writes if w[0] == "config"])

        for _ in range(3):
            with pytest.raises(MeasurementRefusedError, match="until runtime restart"):
                await adapter.read("s")

        assert len([w for w in ads.writes if w[0] == "config"]) == settled, (
            "the adapter wrote the ADS1115 while refusing, which is a writing "
            "contest with whatever changed it"
        )

        # The chip reading correct again does not clear it. Something outside
        # this process is writing the chip, and a reading taken between two of
        # its writes is a plausible number rather than a measurement — an
        # intermittent wrong value, which is worse than an outage because
        # nothing about it looks wrong. No reading can establish that the
        # competing writer is gone, so no reading clears the refusal.
        ads._gain_bits = 0x0200
        with pytest.raises(MeasurementRefusedError, match="until runtime restart"):
            await adapter.read("s")
        assert len([w for w in ads.writes if w[0] == "config"]) == settled
        await adapter.close()

        # And a new adapter over the same chip is refused too, before it can
        # acquire the bus or write anything. An adapter-scoped latch would let
        # a second object reconnect, rewrite the chip and start reading inside
        # the same process, which would make "until runtime restart" untrue.
        # Asserted on the acquisition, not on the reference count: a failed
        # connect gives its reference back, so counting before and after would
        # pass whether or not the bus was ever touched.
        acquisitions: list[int] = []
        real_acquire = i2c_module._get_shared_busio_i2c

        def _counted(bus_number):
            acquisitions.append(bus_number)
            return real_acquire(bus_number)

        monkeypatch.setattr(i2c_module, "_get_shared_busio_i2c", _counted)

        fresh = I2CAdapter()
        with pytest.raises(AdapterConnectionError, match="until runtime restart"):
            await fresh.connect(_config(sensor_type="ads1115_current", channel=0))
        assert not fresh.is_connected
        assert len([w for w in ads.writes if w[0] == "config"]) == settled
        assert acquisitions == [], "the refused connect reached the bus before refusing"

    async def test_a_quarantine_is_the_chip_not_the_bus(self, monkeypatch):
        """Keyed by (bus, address): another chip is a different device.

        A competing writer on one chip says nothing about a second one at its
        own address, and refusing that too would lose a measurement nothing
        established a problem with.
        """
        _pinned_driver(monkeypatch, chip_mux=0)
        first = I2CAdapter()
        await first.connect(_config(sensor_type="ads1115_voltage", channel=0))
        first._quarantine_ads1115("something took this chip")

        with pytest.raises(MeasurementRefusedError):
            await first.read("s")
        await first.close()

        other = I2CAdapter()
        await other.connect(
            _config(sensor_type="ads1115_voltage", address=0x49, channel=0)
        )
        assert other.is_connected
        assert abs((await other.read("s")).value) < 0.01
        await other.close()

    async def test_a_bus_error_on_the_readback_refuses_but_does_not_latch(
        self, monkeypatch
    ):
        """A readback that cannot be performed is not evidence of a writer.

        The latch exists because a chip running a configuration this adapter
        did not set means something else is writing it. A bus that dropped a
        transaction means nothing of the kind, and latching on it would turn
        one bad transfer into an outage lasting until restart.
        """
        _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_voltage", channel=0))

        original = _PinnedDriverADS1115._read_register
        broken = {"on": True}

        def config_read_fails(self, pointer, fast=False):
            if broken["on"] and pointer == self.POINTER_CONFIG and not fast:
                raise OSError("[Errno 121] Remote I/O error")
            return original(self, pointer, fast)

        monkeypatch.setattr(_PinnedDriverADS1115, "_read_register", config_read_fails)
        with pytest.raises(MeasurementRefusedError, match="could not read back"):
            await adapter.read("s")

        broken["on"] = False
        # The bus recovered, so the adapter does too, without a restart.
        assert abs((await adapter.read("s")).value) < 0.01
        await adapter.close()

    async def test_a_refusal_names_what_an_operator_should_do(self, monkeypatch):
        """A refusal an operator cannot act on is a log line, not a report."""
        created = _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_voltage", channel=0))
        created[0]._mux = 5

        with pytest.raises(MeasurementRefusedError) as raised:
            await adapter.read("s")

        message = str(raised.value)
        assert "withheld until runtime restart" in message
        assert "competing writer" in message
        await adapter.close()

    async def test_a_connect_refusal_does_not_promise_a_restart(self, monkeypatch):
        """Connect refuses the sensor outright; there is nothing to withhold."""
        _pinned_driver(monkeypatch, chip_mux=0, honours_pin_in_single=False)
        adapter = I2CAdapter()

        with pytest.raises(AdapterConnectionError) as raised:
            await adapter.connect(_config(sensor_type="ads1115_voltage", channel=0))

        assert "until runtime restart" not in str(raised.value)

    async def test_the_reproduction_spins_on_a_conversion_that_never_completes(self):
        """Guards the fake: without a real poll the hang test proves nothing."""
        ads = _PinnedDriverADS1115(
            None, mode=_PinnedDriverADS1115.SINGLE, completes=False
        )
        import threading

        done = threading.Event()

        def spin():
            _PinnedDriverAnalogIn(ads, 0).value
            done.set()

        t = threading.Thread(target=spin, daemon=True)
        t.start()
        assert not done.wait(0.2), (
            "the fake completed a conversion it was told never to"
        )
        ads._completes = True  # let the daemon thread exit
        done.wait(1.0)

    async def test_the_reproduction_takes_the_fast_path_after_the_first_read(self):
        """Guards the fake: the fast path is what returns the config word."""
        ads = _PinnedDriverADS1115(
            None, mode=_PinnedDriverADS1115.CONTINUOUS, chip_mux=4, conversion=7
        )
        first = _PinnedDriverAnalogIn(ads, 0).value  # slow path: pointered
        ads._write_config(None)  # pointer -> CONFIG
        second = _PinnedDriverAnalogIn(ads, 0).value  # fast path: does not move it
        assert first == 7
        assert second == ads._config_word()

    async def test_the_reproduction_really_ignores_the_pin_in_continuous_mode(self):
        """Guards the fake: a fake that honoured the pin in continuous mode would
        let a regression to the old connect sequence pass every test above."""
        ads = _PinnedDriverADS1115(
            None, mode=_PinnedDriverADS1115.CONTINUOUS, chip_mux=0
        )
        _PinnedDriverAnalogIn(ads, 2).value
        assert ads._mux == 0, "continuous mode must not move the mux, as 3.0.5 does not"
        ads = _PinnedDriverADS1115(None, mode=_PinnedDriverADS1115.SINGLE, chip_mux=0)
        _PinnedDriverAnalogIn(ads, 2).value
        assert ads._mux == 6


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


class TestCloseDuringConnect:
    """A close that overtakes an in-flight connect.

    `connect()` runs its hardware initialisation in a worker thread and used to
    mark itself connected when that thread returned, whatever had happened
    meanwhile. A `close()` in that window released what had been taken at the
    time while the thread went on taking more, leaving an adapter that believed
    it was connected holding a shared-bus reference `close()` had already given
    back. The runtime would then poll a sensor whose bus nobody believes is in
    use.

    Driven for every sensor type the adapter serves, and from both sides of the
    window, because the two orderings fail differently: a close landing after
    the acquisition is undone by the close itself, and one landing before it is
    undone only by the connect noticing.
    """

    def _install_drivers(self, monkeypatch, sensor_type: str):
        if sensor_type == "bme280":
            monkeypatch.setattr(i2c_module, "_SMBUS_AVAILABLE", True)
            monkeypatch.setattr(i2c_module, "_BME280_AVAILABLE", True)
            monkeypatch.setattr(i2c_module, "smbus", MagicMock(), raising=False)
            monkeypatch.setattr(i2c_module, "_bme280_lib", MagicMock(), raising=False)
            return
        if sensor_type == "scd40":
            monkeypatch.setattr(i2c_module, "_SCD40_AVAILABLE", True)
            monkeypatch.setattr(i2c_module, "_BLINKA_AVAILABLE", True)
            monkeypatch.setattr(i2c_module, "_busio", MagicMock(), raising=False)
            monkeypatch.setattr(i2c_module, "_board", MagicMock(), raising=False)
            monkeypatch.setattr(
                i2c_module, "adafruit_scd4x", MagicMock(), raising=False
            )
            return
        _pinned_driver(monkeypatch, chip_mux=0)

    def _gate(self, monkeypatch, when: str, started, release):
        """Hold the worker thread open, before or after it takes anything."""
        original = I2CAdapter._connect_sync

        def _gated(self, sensor_type):
            if when == "after":
                original(self, sensor_type)
            started.set()
            release.wait(5.0)
            if when == "before":
                original(self, sensor_type)

        monkeypatch.setattr(I2CAdapter, "_connect_sync", _gated)

    def _assert_nothing_held(self, adapter, sensor_type: str, before: dict) -> None:
        """Per type, on the resource that type actually takes."""
        assert adapter.is_connected is False
        assert i2c_module._shared_busio_refs == before, (
            "a shared bus reference outlived the connect that took it"
        )
        if sensor_type == "bme280":
            assert adapter._bus is None
        elif sensor_type == "scd40":
            assert adapter._scd4x is None
        else:
            assert i2c_module._ADS1115_CLAIMS == {}
            assert adapter._ads is None

    @pytest.mark.parametrize("when", ["before", "after"])
    @pytest.mark.parametrize(
        "sensor_type", ["bme280", "ads1115_voltage", "ads1115_current", "scd40"]
    )
    async def test_a_close_during_connect_leaves_nothing_held(
        self, monkeypatch, sensor_type, when
    ):
        import threading

        self._install_drivers(monkeypatch, sensor_type)
        started, release = threading.Event(), threading.Event()
        self._gate(monkeypatch, when, started, release)

        address = 0x76 if sensor_type == "bme280" else 0x48
        before = dict(i2c_module._shared_busio_refs)
        adapter = I2CAdapter()
        connecting = asyncio.create_task(
            adapter.connect(_config(sensor_type=sensor_type, address=address))
        )
        await asyncio.to_thread(started.wait, 5.0)

        closing = asyncio.create_task(adapter.close())
        await asyncio.sleep(0)
        release.set()

        with pytest.raises(AdapterConnectionError, match="closed while it was still"):
            await connecting
        await closing

        self._assert_nothing_held(adapter, sensor_type, before)

    async def test_a_close_part_way_through_its_teardown_blocks_a_new_connect(
        self, monkeypatch
    ):
        """The counter records that a close began, not that it finished.

        `_teardown()` awaits, so a close suspended inside it would otherwise be
        invisible to a connect starting in that gap, and the rest of the stale
        teardown would then release what the new connect had just taken. The
        lifecycle lock is what stops the two straddling each other.
        """
        import threading

        self._install_drivers(monkeypatch, "scd40")
        in_teardown, finish = threading.Event(), threading.Event()
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="scd40", address=0x62))
        before_connect = dict(i2c_module._shared_busio_refs)

        def _slow_stop():
            in_teardown.set()
            finish.wait(5.0)

        adapter._scd4x.stop_periodic_measurement = _slow_stop

        closing = asyncio.create_task(adapter.close())
        await asyncio.to_thread(in_teardown.wait, 5.0)

        # The close is suspended inside its own teardown. A connect starting
        # now must not run alongside it.
        reconnecting = asyncio.create_task(
            adapter.connect(_config(sensor_type="scd40", address=0x62))
        )
        await asyncio.sleep(0.05)
        assert not reconnecting.done(), "a connect ran inside a close's teardown"

        finish.set()
        await closing
        await reconnecting

        assert adapter.is_connected is True
        assert i2c_module._shared_busio_refs == before_connect, (
            "the suspended teardown released the later connect's reference"
        )
        await adapter.close()
        assert i2c_module._shared_busio_refs == {}

    async def test_a_close_declares_itself_before_it_waits(self, monkeypatch):
        """Recording the close after its teardown would reinstate the defect.

        The connect holds the lifecycle lock, so a close cannot tear anything
        down until the connect finishes. If it also did not record itself
        first, the connect would see nothing and report success.
        """
        import threading

        self._install_drivers(monkeypatch, "ads1115_voltage")
        started, release = threading.Event(), threading.Event()
        self._gate(monkeypatch, "after", started, release)

        adapter = I2CAdapter()
        connecting = asyncio.create_task(
            adapter.connect(_config(sensor_type="ads1115_voltage"))
        )
        await asyncio.to_thread(started.wait, 5.0)
        closing = asyncio.create_task(adapter.close())
        await asyncio.sleep(0)

        # The close has not torn anything down — it is waiting for the lock.
        assert adapter._close_count == 1
        release.set()
        with pytest.raises(AdapterConnectionError, match="closed while it was still"):
            await connecting
        await closing

    async def test_a_teardown_never_releases_another_adapters_claim(self, monkeypatch):
        """The property that makes the teardown safe to run from two places.

        Driven on the method rather than through a race, because the lifecycle
        lock now makes the interleaving that produced it hard to construct —
        and the ownership check has to hold regardless of how the state arose,
        since a stale teardown that stole a live claim would admit a third
        adapter onto a chip another is driving.
        """
        _pinned_driver(monkeypatch, chip_mux=0)
        first = I2CAdapter()
        await first.connect(_config(sensor_type="ads1115_voltage"))
        await first.close()

        second = I2CAdapter()
        await second.connect(_config(sensor_type="ads1115_voltage"))
        held = dict(i2c_module._ADS1115_CLAIMS)
        assert held, "the second adapter did not take the claim"

        await first._teardown()

        assert i2c_module._ADS1115_CLAIMS == held, (
            "a stale teardown released a claim another adapter holds"
        )
        assert second.is_connected is True
        await second.close()

    async def test_a_second_connect_cannot_change_the_first_ones_device(
        self, monkeypatch
    ):
        """Config written to the adapter before the lock is a second race.

        One connect holds the lifecycle lock while its worker is running; a
        second, for a different address and channel, would overwrite the
        address, channel and calibration the first is in the middle of using.
        The worker then opens whatever the second left behind: the wrong
        device, or the right one on the wrong channel.
        """
        import threading

        created = _pinned_driver(monkeypatch, chip_mux=0)
        started, release = threading.Event(), threading.Event()
        self._gate(monkeypatch, "before", started, release)

        adapter = I2CAdapter()
        first = asyncio.create_task(
            adapter.connect(
                _config(sensor_type="ads1115_voltage", address=0x48, channel=0)
            )
        )
        await asyncio.to_thread(started.wait, 5.0)

        # A second connect for a different chip and channel, while the first
        # is inside its own initialisation.
        second = asyncio.create_task(
            adapter.connect(
                _config(sensor_type="ads1115_voltage", address=0x49, channel=3)
            )
        )
        await asyncio.sleep(0.05)
        assert not second.done(), "the second connect ran alongside the first"

        release.set()
        await first

        # The first connected its own device, on its own channel.
        assert adapter._address == 0x48
        assert adapter._channel == 0
        assert [d.address for d in created] == [0x48]

        # And the second is refused rather than reconnecting in place, so it
        # takes no further shared-bus reference against the one release the
        # single close will make.
        with pytest.raises(AdapterConnectionError, match="already connected"):
            await second
        assert i2c_module._shared_busio_refs == {1: 1}

        await adapter.close()
        assert i2c_module._shared_busio_refs == {}
        assert i2c_module._ADS1115_CLAIMS == {}

    async def test_a_refused_second_connect_leaves_the_first_readable(
        self, monkeypatch
    ):
        """Refusing must not disturb the adapter that is already working."""
        _pinned_driver(monkeypatch, chip_mux=0, conversion=0xFFFE)
        adapter = I2CAdapter()
        await adapter.connect(
            _config(sensor_type="ads1115_voltage", address=0x48, channel=0)
        )

        with pytest.raises(AdapterConnectionError, match="already connected"):
            await adapter.connect(
                _config(sensor_type="ads1115_voltage", address=0x49, channel=3)
            )

        assert adapter.is_connected is True
        assert adapter._address == 0x48
        assert adapter._channel == 0
        assert abs((await adapter.read("s")).value) < 0.01
        await adapter.close()

    async def test_an_ordinary_connect_is_unaffected(self, monkeypatch):
        """The guard must not refuse a connect nothing closed."""
        _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_voltage"))
        assert adapter.is_connected is True
        await adapter.close()

    async def test_an_adapter_reconnects_after_a_clean_close(self, monkeypatch):
        """The close count is a comparison, not a latch."""
        _pinned_driver(monkeypatch, chip_mux=0)
        adapter = I2CAdapter()
        await adapter.connect(_config(sensor_type="ads1115_voltage"))
        await adapter.close()
        await adapter.connect(_config(sensor_type="ads1115_voltage"))
        assert adapter.is_connected is True
        await adapter.close()
