# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import math
import threading
import time
from collections.abc import Callable
from typing import Any

from ori.hal.ac_measurement import (
    WindowRefusedError,
    WindowSpec,
    summarise_window,
)
from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    AdapterTimeoutError,
    BaseAdapter,
    HardwareCircuitBreaker,
    MeasurementRefusedError,
)
from ori.network.events import SensorReading
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

CONFIG_SCHEMA = {
    "address": {"type": "integer", "default": 0, "minimum": 0, "maximum": 127},
    "bus": {"type": "integer", "default": 1, "minimum": 0},
    "channel": {"type": "integer", "default": 0, "minimum": 0},
}
CALIBRATION_SCHEMAS = {
    "ads1115_current": {
        "sensitivity_v_per_amp": {"type": "number", "required": True, "minimum": 0},
        "mains_frequency_hz": {"type": "integer", "required": True, "enum": [50, 60]},
        "window_cycles": {"type": "integer", "default": 2, "minimum": 1},
        "data_rate": {"type": "integer", "default": 860, "minimum": 1},
        "gain": {"type": "number", "default": 1, "minimum": 0},
        "overrun_tolerance": {"type": "number", "default": 1.5, "minimum": 0},
        "clip_margin_volts": {"type": "number", "default": 0.05, "minimum": 0},
    },
}

# Optional hardware libraries — guarded so the module imports cleanly on any host.
#
# The guards catch `ImportError` *and* `RuntimeError`, and the second one is the
# point. adafruit-blinka raises `RuntimeError` from
# `raise_for_missing_platform_dependency` when its platform library is absent,
# so an `ImportError` guard let that escape and crashed this module on import.
# It crashed only on a Raspberry Pi: a host with no blinka at all raises
# `ImportError` and the narrow guard held, so every developer machine and every
# CI job passed while the supported target could not import the module.
#
# It is deliberately not `except Exception`. A driver reporting an unusable
# platform is an expected state; a driver raising `TypeError` or `AttributeError`
# at import time is a defect, and swallowing that would turn a bug into a
# capability this runtime quietly does not have.
#
# The reason is kept rather than reduced to a boolean, so a refusal can say
# which import failed and why instead of guessing "not installed" at an
# operator whose problem is a missing platform library.
_DRIVER_FAILURE = (ImportError, RuntimeError)

_DRIVER_UNAVAILABLE: dict[str, str] = {}


def _unavailable(capability: str, exc: BaseException) -> None:
    _DRIVER_UNAVAILABLE[capability] = f"{type(exc).__name__}: {exc}"


try:
    import smbus2 as smbus  # type: ignore[import-untyped]

    _SMBUS_AVAILABLE = True
except _DRIVER_FAILURE as exc:  # pragma: no cover - exercised on non-Pi hosts
    smbus = None
    _SMBUS_AVAILABLE = False
    _unavailable("smbus2", exc)

try:
    import bme280 as _bme280_lib  # type: ignore[import-untyped]

    _BME280_AVAILABLE = True
except _DRIVER_FAILURE as exc:  # pragma: no cover - exercised on non-Pi hosts
    _bme280_lib = None
    _BME280_AVAILABLE = False
    _unavailable("bme280", exc)

try:
    import adafruit_ads1x15.ads1x15 as _ads1x15  # type: ignore[import-untyped]
    import adafruit_ads1x15.ads1115 as _ads1115  # type: ignore[import-untyped]
    import adafruit_ads1x15.analog_in as _analog_in  # type: ignore[import-untyped]

    _ADS1115_AVAILABLE = True
except _DRIVER_FAILURE as exc:  # pragma: no cover - exercised on non-Pi hosts
    _ads1115 = None
    _ads1x15 = None
    _analog_in = None
    _ADS1115_AVAILABLE = False
    _unavailable("ads1115", exc)

# blinka is a separate dependency from the ADS1115 driver and separate sensors
# need it. Folding the two into one block made `scd40` — which needs blinka for
# its bus but not the ADC driver at all — report a missing `adafruit_ads1x15`,
# and told an operator to install a package their device does not use.
try:
    import board as _board  # type: ignore[import-untyped]
    import busio as _busio  # type: ignore[import-untyped]

    _BLINKA_AVAILABLE = True
except _DRIVER_FAILURE as exc:  # pragma: no cover - exercised on non-Pi hosts
    _board = None
    _busio = None
    _BLINKA_AVAILABLE = False
    _unavailable("blinka", exc)

try:
    import adafruit_scd4x  # type: ignore[import-untyped]

    _SCD40_AVAILABLE = True
except _DRIVER_FAILURE as exc:  # pragma: no cover - exercised on non-Pi hosts
    adafruit_scd4x = None
    _SCD40_AVAILABLE = False
    _unavailable("scd40", exc)

# Sensor types that require the ADS1115 ADC
_ADS_SENSOR_TYPES = frozenset({"ads1115_current", "ads1115_voltage"})

# All sensor types handled by this adapter
_SUPPORTED = frozenset(
    {
        "bme280",
        "ads1115_current",
        "ads1115_voltage",
        "scd40",
    }
)

# Which drivers each sensor type cannot be read without. Tuples, not single
# names: `scd40` needs its own driver *and* the blinka bundle, because
# `busio`/`board` come from there, and `bme280` needs `smbus2` as well as the
# calibration library. A one-driver-per-type map looks right and silently
# under-reports exactly those two.
#
# `_require_drivers` below is called by every `_connect_*`, so this table and
# the connect path cannot disagree about what a type needs: a type whose entry
# is wrong fails at connect too, rather than passing a startup gate and being
# skipped later.
_SENSOR_TYPE_DRIVERS: dict[str, tuple[str, ...]] = {
    "bme280": ("smbus2", "bme280"),
    "ads1115_current": ("ads1115", "blinka"),
    "ads1115_voltage": ("ads1115", "blinka"),
    "scd40": ("scd40", "blinka"),
}

# What to tell an operator to install, per driver key.
_DRIVER_INSTALL_HINT = {
    "smbus2": "pip install smbus2",
    "bme280": "pip install RPi.bme280",
    "ads1115": "pip install adafruit-circuitpython-ads1x15",
    "blinka": "install a blinka platform library for this board (rpi-lgpio on Raspberry Pi OS Trixie)",
    "scd40": "pip install adafruit-circuitpython-scd4x",
}


# The availability flag remains the single answer to "can this be used". The
# reason dict only explains a False.
#
# Each entry names its flag directly rather than resolving it through
# `globals()`. The indirect form worked and made the flags invisible to static
# analysis, which then reported every one of them as an unused global — a tool
# reporting less than the truth because of how the code was written, which is
# worth avoiding rather than suppressing. A lambda reads the module global when
# it is called, so `patch("ori.hal.i2c_adapter._ADS1115_AVAILABLE", ...)` still
# takes, which is how the suite simulates a Pi.
_DRIVER_AVAILABLE: dict[str, Callable[[], bool]] = {
    "smbus2": lambda: _SMBUS_AVAILABLE,
    "bme280": lambda: _BME280_AVAILABLE,
    "ads1115": lambda: _ADS1115_AVAILABLE,
    "blinka": lambda: _BLINKA_AVAILABLE,
    "scd40": lambda: _SCD40_AVAILABLE,
}


def _driver_missing(driver: str) -> bool:
    return not _DRIVER_AVAILABLE[driver]()


def i2c_driver_unavailable_reason(sensor_type: str) -> str | None:
    """Why this sensor type's drivers are unusable, or ``None``.

    ``None`` means every driver it needs imported. It does **not** mean the
    sensor can be read: a wrong address, a bus this adapter refuses, an
    unsupported type, or a device that does not answer all fail later, at
    ``connect()``. The boundary covering those is the hardened refusal in the
    runtime's sensor startup, not this function.
    """
    reasons = []
    for driver in _SENSOR_TYPE_DRIVERS.get(sensor_type, ()):
        if not _driver_missing(driver):
            continue
        detail = _DRIVER_UNAVAILABLE.get(driver, "not available")
        reasons.append(f"{driver} ({detail})")
    return "; ".join(reasons) or None


def _require_drivers(sensor_type: str) -> None:
    """Refuse a connect whose drivers are unusable, naming what failed."""
    reason = i2c_driver_unavailable_reason(sensor_type)
    if reason is None:
        return
    hints = " ".join(
        _DRIVER_INSTALL_HINT[driver]
        for driver in _SENSOR_TYPE_DRIVERS.get(sensor_type, ())
        if _driver_missing(driver) and driver in _DRIVER_INSTALL_HINT
    )
    raise AdapterConnectionError(
        f"I2CAdapter: '{sensor_type}' needs drivers that did not import: "
        f"{reason}. Try: {hints}"
    )


# Calibration keys read from a sensor's nested ``calibration`` block. The two
# required ones have no default: a clamp's sensitivity and the supply frequency
# are facts about an installation, and guessing either produces a plausible
# number rather than a measurement.
_REQUIRED_CALIBRATION = ("sensitivity_v_per_amp", "mains_frequency_hz")
# PROVISIONAL — these four are datasheet figures, not measurements.
#
# Nothing here has been run against an ADS1115. The arithmetic and the refusals
# are tested against synthetic waveforms, which proves what the code does with
# samples and says nothing about what the hardware delivers. Whoever runs the
# first hardware session should expect to change these, and should treat a
# sensor that sits permanently degraded as a sign that one of them is wrong
# rather than that the sensor is:
#
#   data_rate            the part advertises 860 SPS. Whether adafruit-blinka
#                        over I2C on a Pi 4 sustains it, and with what jitter,
#                        is unmeasured. If the achieved rate is lower, the
#                        sample floor below refuses every window.
#   _MIN_SAMPLE_FRACTION derived from data_rate, so wrong for the same reason.
#   clip_margin_volts    assumes a saturated input reads near the rail. The
#                        real signature may differ, and if it does the clipping
#                        refusal never fires and an under-report passes.
#   overrun_tolerance    a guess at how much scheduling slop a loaded Pi adds.
#
# `window_cycles` and `gain` are not in that list: two whole cycles is a
# property of the measurement, and gain 1 is the only PGA range that spans a
# 3.3 V-referenced input.
_OPTIONAL_CALIBRATION = {
    # Whole cycles per window. Two spans a full period twice over, so a small
    # timing error cannot leave the window covering a fraction of a cycle.
    "window_cycles": 2,
    # The ADS1115's fastest advertised rate. At 50 Hz this is roughly 17
    # samples per cycle; the driver default of 128 SPS yields about two, which
    # cannot resolve a sine at all.
    "data_rate": 860,
    # Gain 1 is +/-4.096 V full scale, which spans a 3.3 V-referenced input.
    # A narrower range would clip a clamp biased at mid-rail.
    "gain": 1,
    # A window is refused rather than trusted once it runs this much over.
    "overrun_tolerance": 1.5,
    # How close to a rail counts as clipped.
    "clip_margin_volts": 0.05,
}

# What fraction of the samples the configured rate should have produced must
# actually arrive for a window to count. Two thirds leaves room for scheduling
# slop without accepting a window that covers only part of its cycles.
# Provisional with `data_rate`: both describe the same unmeasured assumption.
_MIN_SAMPLE_FRACTION = 2 / 3
_CALIBRATION_KEYS = frozenset(_REQUIRED_CALIBRATION) | frozenset(_OPTIONAL_CALIBRATION)

# The `calibration` block is a shared namespace: `ori/reasoning/escalation_policy.py`
# reads bounds from it to decide gateway escalation. The adapter refuses keys it
# does not know so a typo cannot silently become a default, which means it has
# to know which keys are somebody else's rather than claiming the whole block.
_FOREIGN_CALIBRATION_KEYS = frozenset(
    {
        "min_value",
        "minimum_value",
        "calibrated_min",
        "safe_min",
        "max_value",
        "maximum_value",
        "calibrated_max",
        "safe_max",
    }
)

# The ADC's supply rail on the supported wiring: an ADS1115 powered from the
# Raspberry Pi's 3.3 V pin. Deliberately not a calibration key. The PGA range
# and the physical input limit are separate, and this is the one that bounds
# clipping — a waveform flattened against the rail sits well inside a
# +/-4.096 V conversion range and reads as an honest, low RMS. An operator who
# could raise this number could disable the guard that catches it, so it is
# reviewed here until a commissioned hardware binding can carry it.
_ADC_SUPPLY_VOLTS = 3.3

# Conversion rates the ADS1115 implements, in samples per second.
_ADS1115_DATA_RATES = frozenset({8, 16, 32, 64, 128, 250, 475, 860})

# Full-scale voltage for each ADS1115 PGA setting. This is the conversion
# range, not the input range: see `supply_volts`.
_GAIN_FULL_SCALE = {
    2 / 3: 6.144,
    1: 4.096,
    2: 2.048,
    4: 1.024,
    8: 0.512,
    16: 0.256,
}


def _resolve_calibration(config: dict) -> dict[str, float]:
    """Read a current clamp's calibration from its nested ``calibration`` block.

    Nested is canonical. The same names are refused at the sensor's top level
    rather than one of the two being chosen: a deployment that sets a value in
    the wrong place must be told, not silently given a different one. That is
    how a documented `sensitivity` sat in config unread while the adapter used
    its own default.

    Required, with no defaults, because both are facts about an installation
    that cannot be guessed:

    - ``sensitivity_v_per_amp`` — the clamp's output in volts RMS per ampere
      RMS. A 30 A : 1 V clamp is ``0.0333``.
    - ``mains_frequency_hz`` — the supply frequency the window is aligned to.
    """
    duplicated = sorted(_CALIBRATION_KEYS & set(config))
    if duplicated:
        raise AdapterConnectionError(
            "I2CAdapter: calibration keys belong in the sensor's 'calibration' "
            f"block, not beside it: {duplicated}"
        )
    raw = config.get("calibration")
    if not isinstance(raw, dict):
        raise AdapterConnectionError(
            "I2CAdapter: 'ads1115_current' requires a 'calibration' block "
            f"declaring {list(_REQUIRED_CALIBRATION)}"
        )
    unknown = sorted(set(raw) - _CALIBRATION_KEYS - _FOREIGN_CALIBRATION_KEYS)
    if unknown:
        raise AdapterConnectionError(
            f"I2CAdapter: unknown calibration keys {unknown}; "
            f"expected {sorted(_CALIBRATION_KEYS)}"
        )
    resolved: dict[str, float] = {}
    for key in _REQUIRED_CALIBRATION:
        if key not in raw:
            raise AdapterConnectionError(
                f"I2CAdapter: calibration is missing required key '{key}'"
            )
        resolved[key] = _positive(raw[key], key)
    for key, fallback in _OPTIONAL_CALIBRATION.items():
        resolved[key] = _positive(raw.get(key, fallback), key)
    if resolved["gain"] not in _GAIN_FULL_SCALE:
        raise AdapterConnectionError(
            f"I2CAdapter: gain {raw.get('gain')} is not an ADS1115 setting; "
            f"expected one of {sorted(_GAIN_FULL_SCALE)}"
        )
    # These two are refused rather than coerced. A fractional window would be
    # truncated to a different number of cycles than the one declared, and an
    # unsupported rate would be silently replaced by whatever the driver picks
    # instead — in both cases the window would not be what its config says.
    if resolved["window_cycles"] != int(resolved["window_cycles"]):
        raise AdapterConnectionError(
            "I2CAdapter: calibration 'window_cycles' must be a whole number of "
            f"cycles, got {raw.get('window_cycles')!r}"
        )
    if resolved["data_rate"] not in _ADS1115_DATA_RATES:
        raise AdapterConnectionError(
            f"I2CAdapter: data_rate {raw.get('data_rate')!r} is not an ADS1115 "
            f"rate; expected one of {sorted(_ADS1115_DATA_RATES)}"
        )
    return resolved


def _positive(value: Any, key: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise AdapterConnectionError(
            f"I2CAdapter: calibration '{key}' is not a number: {value!r}"
        ) from exc
    # isfinite covers NaN and both infinities; the ordering matters because a
    # NaN comparison is False, so `number <= 0` alone would let one through.
    if not math.isfinite(number) or number <= 0:
        raise AdapterConnectionError(
            f"I2CAdapter: calibration '{key}' must be a positive number, got {value!r}"
        )
    return number


def _window_spec(calibration: dict[str, float]) -> WindowSpec:
    """Derive the window a measurement must fill from the declared calibration.

    The sample floor is a fraction of what the configured rate should deliver
    over the window. Below that the hardware is not keeping up, and the samples
    no longer span the cycles they are supposed to.

    Both the rate and the fraction are provisional until measured on hardware;
    see the note beside `_OPTIONAL_CALIBRATION`.
    """
    cycles = int(calibration["window_cycles"])
    seconds = cycles / calibration["mains_frequency_hz"]
    expected = calibration["data_rate"] * seconds
    return WindowSpec(
        mains_frequency_hz=calibration["mains_frequency_hz"],
        window_cycles=cycles,
        min_samples=max(8, int(expected * _MIN_SAMPLE_FRACTION)),
        # Whichever limit binds first. Above the supply the input is clamped by
        # the part itself; above the PGA range the conversion saturates.
        full_scale_volts=min(_GAIN_FULL_SCALE[calibration["gain"]], _ADC_SUPPLY_VOLTS),
        clip_margin_volts=calibration["clip_margin_volts"],
        overrun_tolerance=calibration["overrun_tolerance"],
    )


# ── Shared I2C bus singleton registry ─────────────────────────────────────
# ARCHITECTURE NOTE: Module-level state is explicitly prohibited by CLAUDE.md.
# This is a permitted exception: the Raspberry Pi's I2C bus pins are a hardware
# singleton — there is physically only one I2C-1 bus. This registry mirrors that
# physical constraint in software using reference counting.
# INVARIANT: This cache must never be accessed from outside this module.
# Upper layers (EventBus, runtime, skills) must never reference these dicts.
_shared_busio_instances: dict[int, Any] = {}
_shared_busio_refs: dict[int, int] = {}
_shared_busio_lock = threading.Lock()


def _get_shared_busio_i2c(bus_number: int) -> Any:
    """Return a shared busio.I2C instance for the given bus number."""
    if bus_number != 1:
        raise AdapterConnectionError(
            f"I2CAdapter: Adafruit sensor drivers currently only support "
            f"I2C bus 1 on Raspberry Pi. You requested bus {bus_number}."
        )

    if _busio is None or _board is None:
        raise AdapterConnectionError(
            "I2CAdapter: Adafruit I2C drivers are not installed. "
            "Run: pip install adafruit-blinka adafruit-circuitpython-ads1x15"
        )

    with _shared_busio_lock:
        if bus_number not in _shared_busio_instances:
            _shared_busio_instances[bus_number] = _busio.I2C(_board.SCL, _board.SDA)
            _shared_busio_refs[bus_number] = 0
        _shared_busio_refs[bus_number] += 1
        return _shared_busio_instances[bus_number]


def _release_shared_busio_i2c(bus_number: int) -> None:
    """Evict the cached busio.I2C handle for *bus_number*.

    Called by :meth:`I2CAdapter.close` so that the next :meth:`I2CAdapter.connect`
    call always creates a fresh bus instance.  Existing references held by other
    adapters remain valid — this only removes the cache entry; it does NOT call
    ``deinit()`` on the object.
    """
    with _shared_busio_lock:
        if bus_number in _shared_busio_refs:
            _shared_busio_refs[bus_number] -= 1
            if _shared_busio_refs[bus_number] <= 0:
                _shared_busio_instances.pop(bus_number, None)
                _shared_busio_refs.pop(bus_number, None)


class I2CAdapter(BaseAdapter):
    """I2C hardware adapter for Raspberry Pi.

    Supports the following sensor devices:

    - **bme280** — Bosch BME280 environmental sensor (temperature, pressure, humidity)
    - **ads1115_current** — ADS1115 ADC + current clamp; applies calibration:
      ``current_amps = adc_voltage / sensitivity`` (default sensitivity: 0.1 V/A)
    - **ads1115_voltage** — ADS1115 ADC voltage reading
    - **scd40** — Sensirion SCD40 CO₂ sensor (CO₂ ppm, temperature, humidity)

    All hardware library imports are guarded with ``try/except`` so this module
    loads cleanly on non-Pi hosts.  Operations that require missing libraries
    raise :exc:`~ori.hal.base.AdapterConnectionError` at :meth:`connect` time.

    Usage example (ori.yaml sensor entry)::

        sensors:
          - id: outdoor-env
            type: bme280
            protocol: i2c
            address: 0x76
            bus: 1
    """

    def __init__(self) -> None:
        self._connected: bool = False
        self._sensor_id: str = ""
        self._sensor_type: str = ""
        self._address: int = 0x00
        self._bus_number: int = 1
        self._channel: int = 0  # ADS1115 channel (0–3)
        self._calibration: dict[str, float] = {}
        self._window: WindowSpec | None = None

        # Held device handles — populated in connect()
        self._bus: Any = None  # smbus2.SMBus
        self._bme280_params: Any = None  # bme280 calibration params
        self._ads: Any = None  # ADS1115 instance
        self._scd4x: Any = None  # SCD4X instance

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self, config: dict) -> None:
        """Open the I2C bus and initialise the sensor device.

        Args:
            config: Sensor config dict from ``ori.yaml``.  Required keys:

                - ``sensor_id`` (str)
                - ``sensor_type`` (str) — one of the supported types above
                - ``address`` (int) — I2C device address, e.g. ``0x76``

                Optional keys:

                - ``bus`` (int, default ``1``) — I2C bus number
                - ``channel`` (int, default ``0``) — ADC channel for ADS1115
                - ``calibration`` (dict) — required for ``ads1115_current``;
                  see :func:`_resolve_calibration`

        Raises:
            :exc:`AdapterConnectionError`: Unsupported sensor type, missing
                hardware library, or I2C bus cannot be opened.
        """
        sensor_type = config.get("sensor_type", "")
        if sensor_type not in _SUPPORTED:
            raise AdapterConnectionError(
                f"I2CAdapter: unsupported sensor_type '{sensor_type}'. "
                f"Supported: {sorted(_SUPPORTED)}"
            )

        self._sensor_id = config.get("sensor_id", "")
        self._sensor_type = sensor_type
        self._address = int(config.get("address", 0x00))
        self._bus_number = int(config.get("bus", 1))
        self._channel = int(config.get("channel", 0))
        if sensor_type == "ads1115_current":
            self._calibration = _resolve_calibration(config)
            self._window = _window_spec(self._calibration)

        try:
            await asyncio.to_thread(self._connect_sync, sensor_type)
        except AdapterConnectionError:
            raise
        except Exception as exc:
            raise AdapterConnectionError(
                f"I2CAdapter: failed to connect to '{sensor_type}' at "
                f"address 0x{self._address:02X} on bus {self._bus_number}: {exc}"
            ) from exc

        self._breaker = HardwareCircuitBreaker(
            getattr(self, "adapter_name", type(self).__name__), config
        )
        self._connected = True

    def _connect_sync(self, sensor_type: str) -> None:
        """Blocking I2C initialisation — runs in executor."""
        if sensor_type == "bme280":
            self._connect_bme280()
        elif sensor_type in _ADS_SENSOR_TYPES:
            self._connect_ads1115()
        elif sensor_type == "scd40":
            self._connect_scd40()

    def _connect_bme280(self) -> None:
        _require_drivers("bme280")
        assert smbus is not None and _bme280_lib is not None
        self._bus = smbus.SMBus(self._bus_number)
        self._bme280_params = _bme280_lib.load_calibration_params(
            self._bus, self._address
        )

    def _connect_ads1115(self) -> None:
        _require_drivers(self._sensor_type)
        assert _ads1115 is not None and _ads1x15 is not None
        i2c = _get_shared_busio_i2c(self._bus_number)
        # The driver defaults are 128 SPS in single-shot mode, which yields
        # about two samples per 50 Hz cycle. Continuous conversion at the
        # configured rate is what makes a window resolvable at all.
        self._ads = _ads1115.ADS1115(
            i2c,
            address=self._address,
            gain=self._calibration.get("gain", 1),
            data_rate=int(self._calibration.get("data_rate", 860)),
            mode=_ads1x15.Mode.CONTINUOUS,
        )

    def _connect_scd40(self) -> None:
        # scd40 needs blinka as well as its own driver, because busio and board
        # come from there — but not the ADS1115 driver. The table says so.
        _require_drivers("scd40")
        assert adafruit_scd4x is not None
        i2c = _get_shared_busio_i2c(self._bus_number)
        self._scd4x = adafruit_scd4x.SCD4X(i2c)
        self._scd4x.start_periodic_measurement()

    async def close(self) -> None:
        """Release I2C bus resources and stop any periodic measurements.

        For Adafruit-based sensors (ADS1115, SCD40) the shared ``busio.I2C``
        cache entry is evicted so that a subsequent :meth:`connect` call
        creates a fresh bus handle.  Existing references held by other adapters
        sharing the same bus are unaffected.
        """
        try:
            if self._scd4x is not None:
                await asyncio.to_thread(self._scd4x.stop_periodic_measurement)
                self._scd4x = None
            if self._bus is not None:
                await asyncio.to_thread(self._bus.close)
                self._bus = None
            if self._sensor_type in _ADS_SENSOR_TYPES | {"scd40"}:
                _release_shared_busio_i2c(self._bus_number)
        except Exception:
            logger.warning("I2CAdapter: exception during close — already disconnected?")
        finally:
            self._connected = False

    async def health_check(self) -> bool:
        """Return ``True`` when connected and the device handle is open."""
        if not self._connected:
            return False
        if self._sensor_type == "bme280":
            return self._bus is not None and self._bme280_params is not None
        if self._sensor_type in _ADS_SENSOR_TYPES:
            return self._ads is not None
        if self._sensor_type == "scd40":
            return self._scd4x is not None
        return False

    # ── Read ──────────────────────────────────────────────────────────────────

    async def read(self, sensor_id: str) -> SensorReading:
        """Sample the sensor and return a normalised :class:`~ori.network.events.SensorReading`.

        Args:
            sensor_id: Logical sensor id from ``ori.yaml``.

        Raises:
            :exc:`AdapterReadError`: Sensor read failed or circuit breaker open.
            :exc:`AdapterTimeoutError`: Hardware did not respond within 5 s.
        """
        if not self._connected:
            raise AdapterReadError("I2CAdapter: not connected — call connect() first")

        async with self._breaker:
            try:
                reading = await asyncio.wait_for(
                    asyncio.to_thread(self._read_sync, sensor_id),
                    timeout=5.0,
                )
            except asyncio.TimeoutError as exc:
                raise AdapterTimeoutError(
                    f"I2CAdapter: read timed out for '{self._sensor_type}' "
                    f"(sensor_id={sensor_id})"
                ) from exc
            except (AdapterReadError, AdapterTimeoutError):
                raise
            except Exception as exc:
                raise AdapterReadError(
                    f"I2CAdapter: unexpected error reading '{self._sensor_type}': {exc}"
                ) from exc
            return reading

    def _read_sync(self, sensor_id: str) -> SensorReading:
        t = self._sensor_type
        if t == "bme280":
            return self._read_bme280(sensor_id)
        if t == "ads1115_current":
            return self._read_ads1115_current(sensor_id)
        if t == "ads1115_voltage":
            return self._read_ads1115_voltage(sensor_id)
        if t == "scd40":
            return self._read_scd40(sensor_id)
        raise AdapterReadError(f"I2CAdapter: unknown sensor type '{t}'")

    # ── BME280 ────────────────────────────────────────────────────────────────

    def _read_bme280(self, sensor_id: str) -> SensorReading:
        if _bme280_lib is None:
            raise AdapterConnectionError(
                "I2CAdapter: the BME280 driver is not loaded; connect() must run first"
            )
        data = _bme280_lib.sample(self._bus, self._address, self._bme280_params)
        # bme280.sample returns an object with .temperature (°C), .pressure (hPa),
        # .humidity (%).  Temperature is the primary value; the other two travel
        # in metadata so callers that need all three can access them.
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="bme280",
            value=round(data.temperature, 2),
            unit="celsius",
            timestamp=now_ms(),
            quality=1.0,
            metadata={
                "pressure_hpa": round(data.pressure, 2),
                "humidity_percent": round(data.humidity, 2),
            },
        )

    # ── ADS1115 current ───────────────────────────────────────────────────────

    def _read_ads1115_current(self, sensor_id: str) -> SensorReading:
        """Measure RMS current over a frequency-aligned window, or refuse.

        A current clamp outputs an alternating signal riding on a mid-rail bias.
        One instantaneous sample of that is a number, not a measurement: the
        same steady load reads near zero or near peak depending only on when the
        poll landed. A threshold over such numbers is decided by sampling phase.

        A refused window raises rather than returning a value, so no reading
        carrying a plausible ampere figure can be emitted from samples that were
        never a measurement.
        """
        if _analog_in is None:
            raise AdapterConnectionError(
                "I2CAdapter: the ADS1115 driver is not loaded; connect() must run first"
            )
        window = self._window
        if window is None:
            raise AdapterReadError(
                "I2CAdapter: current calibration was not resolved at connect()"
            )
        channel = _analog_in.AnalogIn(self._ads, self._channel)

        # Monotonic throughout: a wall clock stepped by NTP mid-window would
        # otherwise make an overrun look like a normal window, or the reverse.
        #
        # Reads are paced at the conversion interval rather than taken as fast
        # as the bus allows. In continuous mode the conversion register holds
        # the last result and can be read many times over, so an unpaced loop
        # counts reads instead of conversions and satisfies the sample floor
        # with the same few values repeated. That is the sample-count guard
        # passing on nothing.
        interval = 1.0 / self._calibration["data_rate"]
        samples: list[float] = []
        started = time.monotonic()
        deadline = started + window.nominal_seconds
        due = started
        while True:
            now = time.monotonic()
            if now >= deadline:
                break
            if now < due:
                time.sleep(due - now)
            samples.append(float(channel.voltage))
            due += interval
        elapsed = time.monotonic() - started

        try:
            measured = summarise_window(samples, elapsed, window)
        except WindowRefusedError as exc:
            raise MeasurementRefusedError(
                f"I2CAdapter: refused a current window on '{sensor_id}': {exc}"
            ) from exc

        sensitivity = self._calibration["sensitivity_v_per_amp"]
        current_amps = measured.rms_volts / sensitivity
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="ads1115_current",
            value=round(current_amps, 4),
            unit="ampere",
            timestamp=now_ms(),
            quality=1.0,
            metadata={
                "rms_volts": round(measured.rms_volts, 6),
                "bias_volts": round(measured.bias_volts, 6),
                "sample_count": measured.sample_count,
                "window_ms": round(measured.elapsed_s * 1000, 3),
                "sensitivity_v_per_amp": sensitivity,
                "mains_frequency_hz": self._calibration["mains_frequency_hz"],
                "channel": self._channel,
            },
        )

    # ── ADS1115 voltage ───────────────────────────────────────────────────────

    def _read_ads1115_voltage(self, sensor_id: str) -> SensorReading:
        if _analog_in is None:
            raise AdapterConnectionError(
                "I2CAdapter: the ADS1115 driver is not loaded; connect() must run first"
            )
        chan = _analog_in.AnalogIn(self._ads, self._channel)
        voltage = chan.voltage
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="ads1115_voltage",
            value=round(voltage, 4),
            unit="volt",
            timestamp=now_ms(),
            quality=1.0,
            metadata={"channel": self._channel},
        )

    # ── SCD40 ─────────────────────────────────────────────────────────────────

    def _read_scd40(self, sensor_id: str) -> SensorReading:
        if not self._scd4x.data_ready:
            raise AdapterReadError(
                "I2CAdapter: SCD40 measurement not ready — "
                "wait at least 5 s after start_periodic_measurement()"
            )
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="scd40",
            value=float(self._scd4x.CO2),
            unit="ppm",
            timestamp=now_ms(),
            quality=1.0,
            metadata={
                "temperature_celsius": round(self._scd4x.temperature, 2),
                "humidity_percent": round(self._scd4x.relative_humidity, 2),
            },
        )
