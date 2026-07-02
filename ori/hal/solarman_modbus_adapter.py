# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
from typing import Any

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    BaseAdapter,
    HardwareCircuitBreaker,
)
from ori.hal.inverter_profiles import (
    InverterProfile,
    InverterProfileError,
    ProfileStatus,
    decode_metric,
    load_profile,
)
from ori.network.events import SensorReading
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

try:
    from pysolarmanv5 import (
        PySolarmanV5 as _PySolarmanV5,  # type: ignore[import-untyped]
    )

    _PYSOLARMAN_AVAILABLE = True
except ImportError:
    _PySolarmanV5 = None
    _PYSOLARMAN_AVAILABLE = False


class SolarmanModbusAdapter(BaseAdapter):
    """Profile-driven SolarmanV5 inverter adapter.

    The register map lives in `ori.hal.inverter_profiles`; this adapter only
    handles the SolarmanV5 transport and read-only Modbus register reads.
    Inverter writes are physical actions and must be implemented separately
    through the action dispatcher with Tier B/C policy, never in the HAL.
    """

    def __init__(self) -> None:
        self._connected: bool = False
        self._sensor_type: str = ""
        self._host: str = ""
        self._port: int = 8899
        self._serial: str = ""
        self._profile: InverterProfile | None = None
        self._client: Any = None
        self._breaker: HardwareCircuitBreaker | None = None

    async def connect(self, config: dict) -> None:
        profile_name = str(config.get("profile", "")).strip()
        if not profile_name:
            raise AdapterConnectionError(
                "SolarmanModbusAdapter: 'profile' is required."
            )
        try:
            profile = load_profile(profile_name)
        except InverterProfileError as exc:
            raise AdapterConnectionError(f"SolarmanModbusAdapter: {exc}") from exc

        if profile.transport != "solarman_v5":
            raise AdapterConnectionError(
                f"SolarmanModbusAdapter: profile {profile_name!r} declares "
                f"transport={profile.transport!r}; this adapter only supports "
                "transport='solarman_v5'."
            )
        if profile.status == ProfileStatus.EXPERIMENTAL:
            raise AdapterConnectionError(
                f"SolarmanModbusAdapter: profile {profile_name!r} is experimental "
                "and cannot be used for live perception."
            )

        sensor_type = str(config.get("sensor_type", ""))
        if sensor_type not in profile.metrics:
            raise AdapterConnectionError(
                f"SolarmanModbusAdapter: profile {profile_name!r} has no metric "
                f"{sensor_type!r}. Available: {sorted(profile.metrics)}"
            )
        metric = profile.metric(sensor_type)
        if metric.value_type != "numeric":
            raise AdapterConnectionError(
                f"SolarmanModbusAdapter: metric {sensor_type!r} has "
                f"value_type={metric.value_type!r}; live SensorReading values "
                "must be numeric."
            )

        self._host = str(config.get("host", "")).strip()
        self._serial = str(config.get("serial", "")).strip()
        self._port = int(config.get("port", profile.default_port))
        if not self._host:
            raise AdapterConnectionError(
                "SolarmanModbusAdapter: 'host' is required in sensor config."
            )
        if not self._serial:
            raise AdapterConnectionError(
                "SolarmanModbusAdapter: 'serial' logger serial is required."
            )
        if self._port <= 0:
            raise AdapterConnectionError(
                "SolarmanModbusAdapter: 'port' must be greater than zero."
            )
        if not _PYSOLARMAN_AVAILABLE:
            raise AdapterConnectionError(
                "SolarmanModbusAdapter: 'pysolarmanv5' is not installed. "
                "Install the runtime or phone-growatt dependency set."
            )

        if profile.status != ProfileStatus.FIELD_QUALIFIED:
            logger.warning(
                "SolarmanModbusAdapter: profile %r is %s, not field_qualified; "
                "readings are advisory and must not back physical authority",
                profile.profile,
                profile.status,
            )

        self._profile = profile
        self._sensor_type = sensor_type
        self._breaker = HardwareCircuitBreaker(self.adapter_name, config)
        self._connected = True

    async def close(self) -> None:
        client = self._client
        self._client = None
        self._connected = False
        if client is None:
            return

        closer = getattr(client, "disconnect", None)
        if closer is None:
            closer = getattr(client, "close", None)
        if callable(closer):
            try:
                await asyncio.to_thread(closer)
            except Exception:
                logger.warning("SolarmanModbusAdapter: exception during client close")

    @property
    def is_connected(self) -> bool:
        return self._connected and _PYSOLARMAN_AVAILABLE

    async def read(self, sensor_id: str) -> SensorReading:
        if not _PYSOLARMAN_AVAILABLE:
            raise AdapterConnectionError(
                "SolarmanModbusAdapter: 'pysolarmanv5' is not installed."
            )
        if not self._connected or self._profile is None or self._breaker is None:
            raise AdapterReadError(
                "SolarmanModbusAdapter: not connected; call connect() first."
            )

        async with self._breaker:
            try:
                return await asyncio.to_thread(self._read_sync, sensor_id)
            except ConnectionRefusedError as exc:
                raise AdapterReadError(
                    f"SolarmanModbusAdapter: connection refused for "
                    f"{self._host}:{self._port}"
                ) from exc
            except (AdapterConnectionError, AdapterReadError):
                raise
            except Exception as exc:
                raise AdapterReadError(
                    f"SolarmanModbusAdapter: unexpected error reading "
                    f"{self._sensor_type!r}: {exc}"
                ) from exc

    def _read_sync(self, sensor_id: str) -> SensorReading:
        if self._profile is None:
            raise AdapterReadError("SolarmanModbusAdapter: profile is not loaded")
        spec = self._profile.metric(self._sensor_type)
        client = self._ensure_client_sync()
        raw_registers = self._read_registers_sync(client, spec.register, spec.count)
        value = decode_metric(self._profile, self._sensor_type, raw_registers)
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type=self._sensor_type,
            value=value,
            unit=spec.unit,
            timestamp=now_ms(),
            quality=1.0,
            metadata={
                "source": "solarman_modbus",
                "profile": self._profile.profile,
                "profile_status": self._profile.status,
                "profile_field_qualified": self._profile.is_field_qualified,
                "brand": self._profile.brand,
                "host": self._host,
                "port": self._port,
                "register": spec.register,
                "register_count": spec.count,
                "raw_registers": raw_registers,
            },
        )

    def _ensure_client_sync(self) -> Any:
        if self._client is not None:
            return self._client
        if _PySolarmanV5 is None:
            raise AdapterConnectionError(
                "SolarmanModbusAdapter: 'pysolarmanv5' is not installed."
            )
        try:
            try:
                self._client = _PySolarmanV5(
                    self._host,
                    self._serial,
                    port=self._port,
                )
            except TypeError:
                self._client = _PySolarmanV5(self._host, self._serial, self._port)
        except Exception as exc:
            raise AdapterConnectionError(
                f"SolarmanModbusAdapter: failed to create client for "
                f"{self._host}:{self._port}: {exc}"
            ) from exc
        return self._client

    def _read_registers_sync(self, client: Any, register: int, count: int) -> list[int]:
        read_fn = getattr(client, "read_holding_registers", None)
        if read_fn is None:
            read_fn = getattr(client, "read_input_registers", None)
        if read_fn is None:
            raise AdapterConnectionError(
                "SolarmanModbusAdapter: Solarman client has no supported read method."
            )

        raw = read_fn(register, count)
        if isinstance(raw, int):
            raw = [raw]
        if isinstance(raw, tuple):
            raw = list(raw)
        if not isinstance(raw, list) or len(raw) < count:
            raise AdapterReadError(
                f"SolarmanModbusAdapter: invalid register response for "
                f"register={register}: {raw!r}"
            )
        try:
            return [int(value) for value in raw[:count]]
        except Exception as exc:
            raise AdapterReadError(
                f"SolarmanModbusAdapter: non-numeric registers for register={register}"
            ) from exc
