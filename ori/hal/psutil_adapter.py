# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import platform
import re
import shutil
import time
from functools import partial

import psutil

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    BaseAdapter,
    HardwareCircuitBreaker,
)
from ori.network.events import SensorReading

logger = logging.getLogger(__name__)

# Sensor types handled by this adapter
_SUPPORTED = frozenset(
    {
        "cpu_percent",
        "memory_percent",
        "memory_used_mb",
        "battery_percent",
        "battery_time_remaining",
        "cpu_temp",
        "disk_percent",
        "disk_write_mb",
        "disk_read_mb",
        "disk_write_count",
        "disk_read_count",
        "net_bytes_sent_mb",
        "net_bytes_recv_mb",
        "net_listening_sockets",
        "net_established_connections",
        "active_terminal_users",
        "battery_drain_rate",
        "sleep_blocking_process",
    }
)

_DISK_IO_META = {"note": "cumulative since boot - use delta between readings for rate"}


def _now_ms() -> int:
    return int(time.time() * 1000)


class PsutilAdapter(BaseAdapter):
    """Hardware-free adapter that exposes host system metrics via psutil.

    Works on macOS, Linux, and Windows/WSL — no physical hardware required. This is the PC-Ori adapter used for development and host-machine monitoring.
    """

    def __init__(self, state_store=None) -> None:
        """
        Args:
            state_store: Optional :class:`~ori.state.store.StateStore` instance.
                Required for the ``battery_drain_rate`` calculated sensor.
                If ``None``, ``battery_drain_rate`` returns ``value=0.0, quality=0.0``.
        """
        self._state_store = state_store
        self._sensor_id: str = ""
        self._sensor_type: str = ""
        self._connected: bool = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self, config: dict) -> None:
        """Validate sensor type and mark adapter as connected.

        Args:
            config: Must contain ``sensor_id`` (str) and ``sensor_type`` (str).

        Raises:
            :exc:`AdapterConnectionError`: If ``sensor_type`` is not supported.
        """
        sensor_type = config.get("sensor_type", "")
        if sensor_type not in _SUPPORTED:
            raise AdapterConnectionError(
                f"PsutilAdapter: unsupported sensor_type '{sensor_type}'. "
                f"Supported: {sorted(_SUPPORTED)}"
            )
        self._sensor_id = config.get("sensor_id", "")
        self._sensor_type = sensor_type
        self._breaker = HardwareCircuitBreaker(
            getattr(self, "adapter_name", type(self).__name__), config
        )
        self._connected = True

    async def close(self) -> None:
        """Release resources (no-op for psutil — marks as disconnected)."""
        self._connected = False

    async def health_check(self) -> bool:
        """Return ``True`` if psutil is importable and adapter is connected."""
        return self._connected

    # ── Read dispatcher ───────────────────────────────────────────────────────

    async def read(self, sensor_id: str) -> SensorReading:
        """Sample the configured sensor and return a normalised reading."""
        async with self._breaker:
            t = self._sensor_type
            if t == "battery_drain_rate":
                result = await self._battery_drain_rate_async(sensor_id)
            elif t == "cpu_temp":
                result = await self._cpu_temp_async(sensor_id)
            elif t == "sleep_blocking_process":
                result = await self._sleep_blocking_async(sensor_id)
            else:
                loop = asyncio.get_running_loop()
                try:
                    result = await loop.run_in_executor(
                        None, partial(self._read_sync, sensor_id)
                    )
                except (AdapterReadError, AdapterConnectionError):
                    raise
                except Exception as exc:
                    raise AdapterReadError(
                        f"PsutilAdapter: unexpected error reading '{self._sensor_type}': {exc}"
                    ) from exc
            return result

    def _read_sync(self, sensor_id: str) -> SensorReading:
        t = self._sensor_type
        if t == "cpu_percent":
            return self._cpu_percent(sensor_id)
        if t == "memory_percent":
            return self._memory_percent(sensor_id)
        if t == "memory_used_mb":
            return self._memory_used_mb(sensor_id)
        if t == "battery_percent":
            return self._battery_percent(sensor_id)
        if t == "battery_time_remaining":
            return self._battery_time_remaining(sensor_id)
        if t == "disk_percent":
            return self._disk_percent(sensor_id)
        if t == "disk_write_mb":
            return self._disk_io(sensor_id, "write_mb")
        if t == "disk_read_mb":
            return self._disk_io(sensor_id, "read_mb")
        if t == "disk_write_count":
            return self._disk_io(sensor_id, "write_count")
        if t == "disk_read_count":
            return self._disk_io(sensor_id, "read_count")
        if t == "net_bytes_sent_mb":
            return self._net(sensor_id, "sent")
        if t == "net_bytes_recv_mb":
            return self._net(sensor_id, "recv")
        if t == "net_listening_sockets":
            return self._net_connections_reading(sensor_id, "LISTEN")
        if t == "net_established_connections":
            return self._net_connections_reading(sensor_id, "ESTABLISHED")
        if t == "active_terminal_users":
            return self._active_terminal_users(sensor_id)
        raise AdapterReadError(f"Unknown sensor type: {t}")

    # ── System resources ──────────────────────────────────────────────────────

    def _cpu_percent(self, sensor_id: str) -> SensorReading:
        value = psutil.cpu_percent(interval=0.1)
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="cpu_percent",
            value=float(value),
            unit="percent",
            timestamp=_now_ms(),
            quality=1.0,
        )

    def _memory_percent(self, sensor_id: str) -> SensorReading:
        value = psutil.virtual_memory().percent
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="memory_percent",
            value=float(value),
            unit="percent",
            timestamp=_now_ms(),
            quality=1.0,
        )

    def _memory_used_mb(self, sensor_id: str) -> SensorReading:
        value = psutil.virtual_memory().used / 1_048_576
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="memory_used_mb",
            value=round(value, 2),
            unit="megabytes",
            timestamp=_now_ms(),
            quality=1.0,
        )

    def _battery_percent(self, sensor_id: str) -> SensorReading:
        battery = psutil.sensors_battery()
        if battery is None:
            return SensorReading(
                sensor_id=sensor_id,
                sensor_type="battery_percent",
                value=0.0,
                unit="percent",
                timestamp=_now_ms(),
                quality=0.0,
                metadata={"unavailable": True, "reason": "no battery detected"},
            )
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="battery_percent",
            value=float(battery.percent),
            unit="percent",
            timestamp=_now_ms(),
            quality=1.0,
        )

    def _battery_time_remaining(self, sensor_id: str) -> SensorReading:
        battery = psutil.sensors_battery()
        if battery is None:
            return SensorReading(
                sensor_id=sensor_id,
                sensor_type="battery_time_remaining",
                value=0.0,
                unit="minutes",
                timestamp=_now_ms(),
                quality=0.0,
                metadata={"unavailable": True, "reason": "no battery detected"},
            )
        secsleft = battery.secsleft
        # POWER_TIME_UNLIMITED (-2) or POWER_TIME_UNKNOWN (-1) or charging
        if battery.power_plugged or secsleft < 0:
            return SensorReading(
                sensor_id=sensor_id,
                sensor_type="battery_time_remaining",
                value=-1.0,
                unit="minutes",
                timestamp=_now_ms(),
                quality=1.0,
                metadata={"power_plugged": battery.power_plugged},
            )
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="battery_time_remaining",
            value=round(secsleft / 60.0, 2),
            unit="minutes",
            timestamp=_now_ms(),
            quality=1.0,
        )

    # ── CPU Temperature ───────────────────────────────────────────────────────

    async def _cpu_temp_async(self, sensor_id: str) -> SensorReading:
        system = platform.system()

        # (i) psutil.sensors_temperatures — Linux / WSL
        if hasattr(psutil, "sensors_temperatures"):
            loop = asyncio.get_running_loop()
            temps = await loop.run_in_executor(None, psutil.sensors_temperatures)
            for key in ("coretemp", "k10temp", "cpu_thermal", "acpitz"):
                if key in temps and temps[key]:
                    readings = temps[key]
                    avg = sum(r.current for r in readings) / len(readings)
                    return SensorReading(
                        sensor_id=sensor_id,
                        sensor_type="cpu_temp",
                        value=round(avg, 2),
                        unit="celsius",
                        timestamp=_now_ms(),
                        quality=1.0,
                        metadata={"source": key, "core_count": len(readings)},
                    )

        # (ii) osx-cpu-temp subprocess — macOS only
        if system == "Darwin" and shutil.which("osx-cpu-temp"):
            temp = await self._read_osx_cpu_temp()
            if temp is not None:
                return SensorReading(
                    sensor_id=sensor_id,
                    sensor_type="cpu_temp",
                    value=temp,
                    unit="celsius",
                    timestamp=_now_ms(),
                    quality=0.8,
                    metadata={
                        "source": "osx-cpu-temp",
                        "install": "brew install osx-cpu-temp",
                    },
                )

        # (iii) Not available
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="cpu_temp",
            value=0.0,
            unit="celsius",
            timestamp=_now_ms(),
            quality=0.0,
            metadata={
                "unavailable": True,
                "reason": "no thermal sensors accessible",
            },
        )

    async def _read_osx_cpu_temp(self) -> float | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "osx-cpu-temp",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
            stdout = stdout_bytes.decode()
            match = re.search(r"([\d.]+)\s*°?C", stdout)
            if match:
                return float(match.group(1))
        except (FileNotFoundError, asyncio.TimeoutError, OSError, ValueError):
            pass
        return None

    # ── Storage ───────────────────────────────────────────────────────────────

    def _disk_percent(self, sensor_id: str) -> SensorReading:
        value = psutil.disk_usage("/").percent
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="disk_percent",
            value=float(value),
            unit="percent",
            timestamp=_now_ms(),
            quality=1.0,
        )

    def _disk_io(self, sensor_id: str, metric: str) -> SensorReading:
        counters = psutil.disk_io_counters()
        if counters is None:
            return SensorReading(
                sensor_id=sensor_id,
                sensor_type=f"disk_{metric}",
                value=0.0,
                unit="megabytes" if metric.endswith("_mb") else "count",
                timestamp=_now_ms(),
                quality=0.0,
                metadata={**_DISK_IO_META, "unavailable": True},
            )
        if metric == "write_mb":
            value = counters.write_bytes / 1_048_576
            unit = "megabytes"
            sensor_type = "disk_write_mb"
        elif metric == "read_mb":
            value = counters.read_bytes / 1_048_576
            unit = "megabytes"
            sensor_type = "disk_read_mb"
        elif metric == "write_count":
            value = float(counters.write_count)
            unit = "count"
            sensor_type = "disk_write_count"
        else:  # read_count
            value = float(counters.read_count)
            unit = "count"
            sensor_type = "disk_read_count"
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type=sensor_type,
            value=round(value, 2),
            unit=unit,
            timestamp=_now_ms(),
            quality=1.0,
            metadata=dict(_DISK_IO_META),
        )

    # ── Network ───────────────────────────────────────────────────────────────

    def _net(self, sensor_id: str, direction: str) -> SensorReading:
        counters = psutil.net_io_counters()
        if direction == "sent":
            value = counters.bytes_sent / 1_048_576
            sensor_type = "net_bytes_sent_mb"
        else:
            value = counters.bytes_recv / 1_048_576
            sensor_type = "net_bytes_recv_mb"
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type=sensor_type,
            value=round(value, 2),
            unit="megabytes",
            timestamp=_now_ms(),
            quality=1.0,
        )

    def _permission_degraded_reading(
        self, sensor_id: str, sensor_type: str, exc: Exception
    ) -> SensorReading:
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type=sensor_type,
            value=0.0,
            unit="count",
            timestamp=_now_ms(),
            quality=0.3,
            metadata={
                "source": "psutil",
                "coverage": "partial",
                "permission_denied": True,
                "note": "Run with elevated permissions for full socket visibility",
                "error": str(exc),
            },
        )

    @staticmethod
    def _extract_port(addr: object) -> int | None:
        if hasattr(addr, "port"):
            try:
                return int(getattr(addr, "port"))
            except (TypeError, ValueError):
                return None
        if isinstance(addr, tuple) and len(addr) >= 2:
            try:
                return int(addr[1])
            except (TypeError, ValueError):
                return None
        return None

    def _net_connections_reading(self, sensor_id: str, status: str) -> SensorReading:
        sensor_type = (
            "net_listening_sockets"
            if status == "LISTEN"
            else "net_established_connections"
        )
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError, OSError) as exc:
            return self._permission_degraded_reading(sensor_id, sensor_type, exc)

        filtered = [c for c in connections if getattr(c, "status", "") == status]
        ports: list[int] = []
        pids: list[int] = []
        for conn in filtered:
            port = self._extract_port(getattr(conn, "laddr", None))
            if port is not None:
                ports.append(port)
            pid = getattr(conn, "pid", None)
            if isinstance(pid, int):
                pids.append(pid)

        return SensorReading(
            sensor_id=sensor_id,
            sensor_type=sensor_type,
            value=float(len(filtered)),
            unit="count",
            timestamp=_now_ms(),
            quality=1.0,
            metadata={
                "source": "psutil",
                "coverage": "full",
                "status_filter": status,
                "total_inet_connections": len(connections),
                "listener_ports" if status == "LISTEN" else "local_ports": sorted(
                    set(ports)
                ),
                "sample_pids": sorted(set(pids))[:10],
            },
        )

    def _active_terminal_users(self, sensor_id: str) -> SensorReading:
        sensor_type = "active_terminal_users"
        try:
            users = psutil.users()
        except (psutil.AccessDenied, PermissionError, OSError) as exc:
            return self._permission_degraded_reading(sensor_id, sensor_type, exc)

        sessions: list[dict] = []
        for user in users:
            sessions.append(
                {
                    "name": str(getattr(user, "name", "")),
                    "terminal": str(getattr(user, "terminal", "")),
                    "host": str(getattr(user, "host", "")),
                }
            )

        usernames = [s["name"] for s in sessions if s["name"]]
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type=sensor_type,
            value=float(len(sessions)),
            unit="count",
            timestamp=_now_ms(),
            quality=1.0,
            metadata={
                "source": "psutil",
                "coverage": "full",
                "sessions": sessions,
                "usernames": usernames,
            },
        )

    # ── Battery drain rate (calculated, async) ────────────────────────────────

    async def _battery_drain_rate_async(self, sensor_id: str) -> SensorReading:
        """Compute % drain per hour using StateStore history."""
        _zero = SensorReading(
            sensor_id=sensor_id,
            sensor_type="battery_drain_rate",
            value=0.0,
            unit="percent_per_hour",
            timestamp=_now_ms(),
            quality=0.0,
        )

        if self._state_store is None:
            return _zero

        # Current battery reading (non-blocking via executor)
        loop = asyncio.get_running_loop()
        battery = await loop.run_in_executor(None, psutil.sensors_battery)
        if battery is None:
            return _zero

        now = _now_ms()
        current_pct = float(battery.percent)

        # Fetch previous battery_percent reading for this sensor
        history = await self._state_store.get_history(sensor_id, limit=2)
        battery_history = [r for r in history if r.sensor_type == "battery_percent"]

        if not battery_history:
            return _zero

        last = battery_history[0]
        elapsed_hours = (now - last.timestamp) / 3_600_000

        if elapsed_hours < 0.5:
            return SensorReading(
                sensor_id=sensor_id,
                sensor_type="battery_drain_rate",
                value=0.0,
                unit="percent_per_hour",
                timestamp=now,
                quality=0.0,
                metadata={"reason": "elapsed_time_too_short"},
            )

        drain_rate = (last.value - current_pct) / elapsed_hours

        if drain_rate <= 0:
            return SensorReading(
                sensor_id=sensor_id,
                sensor_type="battery_drain_rate",
                value=0.0,
                unit="percent_per_hour",
                timestamp=now,
                quality=0.0,
                metadata={"reason": "charging_or_no_change"},
            )

        sleep_suspected = elapsed_hours > 0.33 and len(history) < 2

        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="battery_drain_rate",
            value=round(drain_rate, 3),
            unit="percent_per_hour",
            timestamp=now,
            quality=1.0,
            metadata={"sleep_suspected": sleep_suspected},
        )

    # ── Sleep process detection ───────────────────────────────────────────────

    async def _sleep_blocking_async(self, sensor_id: str) -> SensorReading:
        system = platform.system()
        processes: list[dict] = []
        quality = 0.0

        if system == "Darwin":
            processes, quality = await self._pmset_assertions_async()
        elif system == "Linux":
            processes, quality = await self._systemd_inhibit_async()

        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="sleep_blocking_process",
            value=float(len(processes)),
            unit="count",
            timestamp=_now_ms(),
            quality=quality,
            metadata={
                "processes": processes,
                "recommended_process": processes[0] if processes else None,
            },
        )

    async def _pmset_assertions_async(self) -> tuple[list[dict], float]:
        """Parse ``pmset -g assertions`` on macOS."""
        if not shutil.which("pmset"):
            return [], 0.0

        try:
            proc = await asyncio.create_subprocess_exec(
                "pmset",
                "-g",
                "assertions",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
            stdout = stdout_bytes.decode()
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            return [], 0.0

        processes: list[dict] = []
        assertion_types = ("PreventUserIdleSystemSleep", "PreventSystemSleep")

        for line in stdout.splitlines():
            for assertion in assertion_types:
                if assertion not in line:
                    continue
                # Lines look like:
                #   pid 1234(Zoom): [assertion type] named "..." 00:00:00
                pid_match = re.search(r"pid\s+(\d+)\(([^)]+)\)", line)
                if pid_match:
                    processes.append(
                        {
                            "pid": int(pid_match.group(1)),
                            "name": pid_match.group(2),
                            "assertion": assertion,
                        }
                    )

        return processes, 1.0

    async def _systemd_inhibit_async(self) -> tuple[list[dict], float]:
        """Parse ``systemd-inhibit --list`` on Linux."""
        if not shutil.which("systemd-inhibit"):
            return [], 0.0

        try:
            proc = await asyncio.create_subprocess_exec(
                "systemd-inhibit",
                "--list",
                "--no-legend",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
            stdout = stdout_bytes.decode()
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            return [], 0.0

        processes: list[dict] = []
        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                # Column order: WHO  UID  PID  WHAT  WHY  MODE
                # Best-effort parse; layout varies by systemd version
                name = parts[0]
                pid_str = parts[2] if len(parts) > 2 else ""
                try:
                    pid = int(pid_str)
                except ValueError:
                    pid = -1
                processes.append(
                    {"pid": pid, "name": name, "assertion": "sleep_inhibit"}
                )

        return processes, 1.0
