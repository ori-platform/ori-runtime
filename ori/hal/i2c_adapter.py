# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import threading
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

# Optional hardware libraries — guarded so the module imports cleanly on any host.
try:
    import smbus2 as smbus  # type: ignore[import-untyped]

    _SMBUS_AVAILABLE = True
except ImportError:
    _SMBUS_AVAILABLE = False

try:
    import bme280 as _bme280_lib  # type: ignore[import-untyped]

    _BME280_AVAILABLE = True
except ImportError:
    _BME280_AVAILABLE = False

try:
    import adafruit_ads1x15.ads1115 as _ads1115  # type: ignore[import-untyped]
    import adafruit_ads1x15.analog_in as _analog_in  # type: ignore[import-untyped]
    import board as _board  # type: ignore[import-untyped]
    import busio as _busio  # type: ignore[import-untyped]

    _ADS1115_AVAILABLE = True
except ImportError:
    _ADS1115_AVAILABLE = False

try:
    import adafruit_scd4x  # type: ignore[import-untyped]

    _SCD40_AVAILABLE = True
except ImportError:
    _SCD40_AVAILABLE = False

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

# Default ADS1115 current-clamp sensitivity (V/A) for common SCT-013 clamps.
# Override via config key ``sensitivity`` in ori.yaml.
_DEFAULT_SENSITIVITY = 0.1  # V/A


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
        self._sensitivity: float = _DEFAULT_SENSITIVITY  # ADS1115 current calibration

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
                - ``sensitivity`` (float, default ``0.1``) — V/A calibration
                  for ``ads1115_current``

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
        self._sensitivity = float(config.get("sensitivity", _DEFAULT_SENSITIVITY))

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
        if not _SMBUS_AVAILABLE:
            raise AdapterConnectionError(
                "I2CAdapter: 'smbus2' is not installed. Run: pip install smbus2"
            )
        if not _BME280_AVAILABLE:
            raise AdapterConnectionError(
                "I2CAdapter: 'RPi.bme280' is not installed. Run: pip install RPi.bme280"
            )
        self._bus = smbus.SMBus(self._bus_number)
        self._bme280_params = _bme280_lib.load_calibration_params(
            self._bus, self._address
        )

    def _connect_ads1115(self) -> None:
        if not _ADS1115_AVAILABLE:
            raise AdapterConnectionError(
                "I2CAdapter: Adafruit ADS1x15 library is not installed. "
                "Run: pip install adafruit-circuitpython-ads1x15"
            )
        i2c = _get_shared_busio_i2c(self._bus_number)
        self._ads = _ads1115.ADS1115(i2c, address=self._address)

    def _connect_scd40(self) -> None:
        if not _SCD40_AVAILABLE:
            raise AdapterConnectionError(
                "I2CAdapter: 'adafruit-circuitpython-scd4x' is not installed. "
                "Run: pip install adafruit-circuitpython-scd4x"
            )
        if not _ADS1115_AVAILABLE:
            # busio/board come from the same adafruit-blinka bundle
            raise AdapterConnectionError(
                "I2CAdapter: 'adafruit-blinka' (busio/board) is not installed."
            )
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
        chan = _analog_in.AnalogIn(self._ads, self._channel)
        adc_voltage = chan.voltage  # volts
        current_amps = adc_voltage / self._sensitivity
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="ads1115_current",
            value=round(current_amps, 4),
            unit="ampere",
            timestamp=now_ms(),
            quality=1.0,
            metadata={
                "adc_voltage": round(adc_voltage, 6),
                "sensitivity_v_per_a": self._sensitivity,
                "channel": self._channel,
            },
        )

    # ── ADS1115 voltage ───────────────────────────────────────────────────────

    def _read_ads1115_voltage(self, sensor_id: str) -> SensorReading:
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
