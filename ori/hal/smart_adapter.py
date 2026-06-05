# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
import logging
import re
import subprocess
from typing import Any

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    BaseAdapter,
    HardwareCircuitBreaker,
)
from ori.network.events import SensorReading
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

try:
    from pySMART import Device as _PySmartDevice  # type: ignore[import-untyped]

    _PYSMART_AVAILABLE = True
except ImportError:
    _PySmartDevice = None
    _PYSMART_AVAILABLE = False

_SUPPORTED_SENSOR_TYPES = frozenset(
    {
        "drive_temp_celsius",
        "tbw_remaining_tb",
        "reallocated_sectors",
        "power_on_hours",
    }
)

_SENSOR_UNITS = {
    "drive_temp_celsius": "celsius",
    "tbw_remaining_tb": "terabytes",
    "reallocated_sectors": "count",
    "power_on_hours": "hours",
}


def _to_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            match = re.search(r"-?\d+(?:\.\d+)?", text)
            if match:
                return float(match.group(0))
    return None


def _get_nested(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _extract_ata_attr_raw(
    payload: dict[str, Any], *, names: set[str], ids: set[int]
) -> float | None:
    table = _get_nested(payload, "ata_smart_attributes", "table")
    if not isinstance(table, list):
        return None
    normalized_names = {n.lower() for n in names}
    for row in table:
        if not isinstance(row, dict):
            continue
        row_id = row.get("id")
        row_name = str(row.get("name", "")).lower()
        if row_id not in ids and row_name not in normalized_names:
            continue
        raw = row.get("raw")
        if isinstance(raw, dict):
            value = _to_float(raw.get("value"))
            if value is not None:
                return value
        value = _to_float(raw)
        if value is not None:
            return value
        value = _to_float(row.get("value"))
        if value is not None:
            return value
    return None


def _extract_temperature(payload: dict[str, Any]) -> float | None:
    for path in (
        ("temperature", "current"),
        ("temperature", "drive_temperature"),
        ("nvme_smart_health_information_log", "temperature"),
    ):
        value = _to_float(_get_nested(payload, *path))
        if value is not None:
            return value
    return _extract_ata_attr_raw(
        payload,
        names={"temperature_celsius", "airflow_temperature_cel"},
        ids={190, 194},
    )


def _extract_reallocated_sectors(payload: dict[str, Any]) -> float | None:
    value = _extract_ata_attr_raw(
        payload,
        names={"reallocated_sector_ct"},
        ids={5},
    )
    if value is not None:
        return value
    nvme_media_errors = _to_float(
        _get_nested(payload, "nvme_smart_health_information_log", "media_errors")
    )
    return nvme_media_errors


def _extract_power_on_hours(payload: dict[str, Any]) -> float | None:
    for path in (
        ("power_on_time", "hours"),
        ("power_on_time", "value"),
    ):
        value = _to_float(_get_nested(payload, *path))
        if value is not None:
            return value
    return _extract_ata_attr_raw(
        payload,
        names={"power_on_hours", "power-on_hours"},
        ids={9},
    )


def _extract_written_tb(payload: dict[str, Any]) -> float | None:
    # NVMe: data_units_written (1000 * 512-byte units)
    data_units_written = _to_float(
        _get_nested(payload, "nvme_smart_health_information_log", "data_units_written")
    )
    if data_units_written is not None:
        return (data_units_written * 512000.0) / 1_000_000_000_000.0

    # ATA: Total LBAs written (512-byte sectors)
    total_lbas_written = _extract_ata_attr_raw(
        payload,
        names={"total_lbas_written"},
        ids={241},
    )
    if total_lbas_written is not None:
        return (total_lbas_written * 512.0) / 1_000_000_000_000.0

    # Vendor variation: host writes in 32 MiB units
    host_writes_32mib = _extract_ata_attr_raw(
        payload,
        names={"host_writes_32mib"},
        ids={246},
    )
    if host_writes_32mib is not None:
        return (host_writes_32mib * 32.0 * 1024.0 * 1024.0) / 1_000_000_000_000.0

    return None


def _extract_percent_used(payload: dict[str, Any]) -> float | None:
    value = _to_float(
        _get_nested(payload, "nvme_smart_health_information_log", "percentage_used")
    )
    if value is not None:
        return value
    return _extract_ata_attr_raw(
        payload,
        names={"percentage_used", "media_wearout_indicator"},
        ids={233},
    )


def _extract_tbw_remaining(payload: dict[str, Any]) -> float | None:
    for path in (
        ("tbw_remaining_tb",),
        ("endurance", "tbw_remaining_tb"),
    ):
        value = _to_float(_get_nested(payload, *path))
        if value is not None:
            return value

    written_tb = _extract_written_tb(payload)
    percent_used = _extract_percent_used(payload)
    if written_tb is None or percent_used is None:
        return None
    if percent_used <= 0.0 or percent_used >= 100.0:
        return None

    estimated_total_tb = written_tb / (percent_used / 100.0)
    remaining_tb = estimated_total_tb - written_tb
    if remaining_tb < 0.0:
        return 0.0
    return remaining_tb


class SmartAdapter(BaseAdapter):
    """SMART health adapter with pySMART-first and smartctl fallback."""

    def __init__(self) -> None:
        self._connected = False
        self._sensor_type: str = ""
        self._device: str = ""
        self._poll_interval_ms: int = 0
        self._breaker: HardwareCircuitBreaker | None = None

    async def connect(self, config: dict) -> None:
        sensor_type = str(config.get("sensor_type", "")).strip()
        if sensor_type not in _SUPPORTED_SENSOR_TYPES:
            raise AdapterConnectionError(
                f"SmartAdapter: unsupported sensor_type '{sensor_type}'. "
                f"Supported: {sorted(_SUPPORTED_SENSOR_TYPES)}"
            )

        device = str(config.get("device", "")).strip()
        if not device:
            raise AdapterConnectionError(
                "SmartAdapter: 'device' is required (e.g. /dev/sda, /dev/nvme0n1)"
            )

        self._sensor_type = sensor_type
        self._device = device
        self._poll_interval_ms = int(config.get("poll_interval_ms", 0))
        self._breaker = HardwareCircuitBreaker(self.adapter_name, config)
        self._connected = True

        if not _PYSMART_AVAILABLE:
            logger.info(
                "SmartAdapter: pySMART unavailable — using smartctl subprocess fallback"
            )

    async def read(self, sensor_id: str) -> SensorReading:
        if not self._connected:
            raise AdapterReadError("SmartAdapter: not connected — call connect() first")
        if self._breaker is None:
            raise AdapterReadError("SmartAdapter: circuit breaker is not initialized")

        async with self._breaker:
            try:
                metrics = await asyncio.to_thread(self._read_metrics_sync)
            except AdapterReadError:
                raise
            except Exception as exc:
                raise AdapterReadError(
                    f"SmartAdapter: unexpected SMART read failure: {exc}"
                ) from exc

            value = metrics.get(self._sensor_type)
            if value is None:
                raise AdapterReadError(
                    f"SmartAdapter: metric '{self._sensor_type}' is unavailable for "
                    f"device '{self._device}'."
                )

            return SensorReading(
                sensor_id=sensor_id,
                sensor_type=self._sensor_type,
                value=round(float(value), 4),
                unit=_SENSOR_UNITS[self._sensor_type],
                timestamp=now_ms(),
                quality=1.0,
                metadata={
                    "source": "smart",
                    "device": self._device,
                    "backend": "pysmart" if _PYSMART_AVAILABLE else "smartctl",
                },
            )

    async def close(self) -> None:
        self._connected = False

    def _read_metrics_sync(self) -> dict[str, float | None]:
        # Try pySMART first, then fallback to smartctl subprocess.
        if _PYSMART_AVAILABLE and _PySmartDevice is not None:
            try:
                return self._read_via_pysmart_sync()
            except Exception as exc:
                logger.warning(
                    "SmartAdapter: pySMART read failed for %s (%s) — falling back to smartctl",
                    self._device,
                    exc,
                )
        return self._read_via_smartctl_sync()

    def _read_via_pysmart_sync(self) -> dict[str, float | None]:
        if _PySmartDevice is None:
            raise AdapterReadError("SmartAdapter: pySMART unavailable")

        device = _PySmartDevice(self._device)
        if hasattr(device, "update"):
            try:
                device.update()
            except Exception:
                # Continue; some pySMART implementations lazily update fields.
                pass

        payload = self._build_payload_from_pysmart(device)
        return self._extract_metrics(payload)

    def _build_payload_from_pysmart(self, device: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {}

        smart_capable = getattr(device, "smart_capable", None)
        smart_enabled = getattr(device, "smart_enabled", None)
        payload["smart_support"] = {
            "available": bool(smart_capable) if smart_capable is not None else True,
            "enabled": bool(smart_enabled) if smart_enabled is not None else True,
        }

        payload["temperature"] = {"current": getattr(device, "temperature", None)}
        payload["power_on_time"] = {"hours": getattr(device, "power_on_hours", None)}

        attrs = getattr(device, "attributes", None)
        if isinstance(attrs, list):
            payload["ata_smart_attributes"] = {"table": attrs}
        elif isinstance(attrs, dict):
            payload["ata_smart_attributes"] = {"table": list(attrs.values())}

        return payload

    def _read_via_smartctl_sync(self) -> dict[str, float | None]:
        payload = self._run_smartctl_json()
        return self._extract_metrics(payload)

    def _run_smartctl_json(self) -> dict[str, Any]:
        try:
            proc = subprocess.run(
                ["smartctl", "-a", "-j", self._device],
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
        except FileNotFoundError as exc:
            raise AdapterReadError(
                "SmartAdapter: smartctl is not installed. Install smartmontools "
                "or install pySMART."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise AdapterReadError(
                f"SmartAdapter: smartctl timed out for device '{self._device}'"
            ) from exc
        except OSError as exc:
            raise AdapterReadError(
                f"SmartAdapter: failed to execute smartctl: {exc}"
            ) from exc

        if proc.returncode not in {0, 2, 4}:  # smartctl uses bitmask-style exit codes.
            stderr = (proc.stderr or "").strip()
            raise AdapterReadError(
                f"SmartAdapter: smartctl failed for '{self._device}' "
                f"(exit={proc.returncode}): {stderr or 'no stderr'}"
            )

        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AdapterReadError(
                "SmartAdapter: smartctl produced invalid JSON output"
            ) from exc
        if not isinstance(data, dict):
            raise AdapterReadError(
                "SmartAdapter: smartctl JSON output is not an object"
            )
        return data

    def _extract_metrics(self, payload: dict[str, Any]) -> dict[str, float | None]:
        smart_support = payload.get("smart_support")
        if isinstance(smart_support, dict):
            available = smart_support.get("available")
            enabled = smart_support.get("enabled")
            if available is False or enabled is False:
                raise AdapterReadError(
                    f"SmartAdapter: SMART is not available/enabled on device '{self._device}'."
                )

        return {
            "drive_temp_celsius": _extract_temperature(payload),
            "tbw_remaining_tb": _extract_tbw_remaining(payload),
            "reallocated_sectors": _extract_reallocated_sectors(payload),
            "power_on_hours": _extract_power_on_hours(payload),
        }
