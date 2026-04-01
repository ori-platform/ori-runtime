# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import shutil
import time
from unittest.mock import AsyncMock, MagicMock, patch

import psutil
import pytest

from ori.hal.base import AdapterConnectionError
from ori.hal.psutil_adapter import PsutilAdapter
from ori.network.events import SensorReading

# ─── Skip markers ─────────────────────────────────────────────────────────────

skip_if_no_battery = pytest.mark.skipif(
    psutil.sensors_battery() is None,
    reason="No battery detected",
)

skip_if_no_thermal = pytest.mark.skipif(
    not (
        (
            hasattr(psutil, "sensors_temperatures")
            and any(
                k in psutil.sensors_temperatures()
                for k in ("coretemp", "k10temp", "cpu_thermal", "acpitz")
            )
        )
        or shutil.which("osx-cpu-temp") is not None
    ),
    reason="No thermal sensors available",
)


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _ms() -> int:
    return int(time.time() * 1000)


async def _make_adapter(sensor_type: str, state_store=None) -> PsutilAdapter:
    adapter = PsutilAdapter(state_store=state_store)
    await adapter.connect({"sensor_id": sensor_type, "sensor_type": sensor_type})
    return adapter


def _assert_reading(
    reading: SensorReading,
    sensor_id: str,
    sensor_type: str,
    unit: str,
    *,
    value_min: float | None = None,
    value_max: float | None = None,
    quality_min: float = 0.0,
) -> None:
    assert isinstance(reading, SensorReading)
    assert reading.sensor_id == sensor_id
    assert reading.sensor_type == sensor_type
    assert reading.unit == unit
    assert reading.timestamp > 0
    assert 0.0 <= reading.quality <= 1.0
    assert reading.quality >= quality_min
    if value_min is not None:
        assert reading.value >= value_min
    if value_max is not None:
        assert reading.value <= value_max


# ─── connect() validation ─────────────────────────────────────────────────────


class TestConnect:
    async def test_unsupported_sensor_type_raises(self):
        adapter = PsutilAdapter()
        with pytest.raises(AdapterConnectionError, match="unsupported sensor_type"):
            await adapter.connect({"sensor_id": "x", "sensor_type": "flux_capacitor"})

    async def test_connect_marks_connected(self):
        adapter = PsutilAdapter()
        assert adapter.is_connected is False
        await adapter.connect({"sensor_id": "cpu", "sensor_type": "cpu_percent"})
        assert adapter.is_connected is True

    async def test_close_marks_disconnected(self):
        adapter = await _make_adapter("cpu_percent")
        await adapter.close()
        assert adapter.is_connected is False

    async def test_adapter_name(self):
        assert PsutilAdapter().adapter_name == "PsutilAdapter"

    async def test_health_check_after_connect(self):
        adapter = await _make_adapter("cpu_percent")
        assert await adapter.health_check() is True

    async def test_health_check_after_close(self):
        adapter = await _make_adapter("cpu_percent")
        await adapter.close()
        assert await adapter.health_check() is False


# ─── System resources ─────────────────────────────────────────────────────────


class TestSystemResources:
    async def test_cpu_percent(self):
        adapter = await _make_adapter("cpu_percent")
        r = await adapter.read("cpu_percent")
        _assert_reading(
            r,
            "cpu_percent",
            "cpu_percent",
            "percent",
            value_min=0.0,
            value_max=100.0,
            quality_min=1.0,
        )

    async def test_memory_percent(self):
        adapter = await _make_adapter("memory_percent")
        r = await adapter.read("memory_percent")
        _assert_reading(
            r,
            "memory_percent",
            "memory_percent",
            "percent",
            value_min=0.0,
            value_max=100.0,
            quality_min=1.0,
        )

    async def test_memory_used_mb(self):
        adapter = await _make_adapter("memory_used_mb")
        r = await adapter.read("memory_used_mb")
        _assert_reading(
            r,
            "memory_used_mb",
            "memory_used_mb",
            "megabytes",
            value_min=0.0,
            quality_min=1.0,
        )

    @skip_if_no_battery
    async def test_battery_percent_with_battery(self):
        adapter = await _make_adapter("battery_percent")
        r = await adapter.read("battery_percent")
        _assert_reading(
            r,
            "battery_percent",
            "battery_percent",
            "percent",
            value_min=0.0,
            value_max=100.0,
            quality_min=1.0,
        )

    async def test_battery_percent_no_battery(self):
        adapter = await _make_adapter("battery_percent")
        with patch("psutil.sensors_battery", return_value=None):
            r = await adapter.read("battery_percent")
        assert r.quality == 0.0
        assert r.metadata.get("unavailable") is True

    @skip_if_no_battery
    async def test_battery_time_remaining_plugged(self):
        adapter = await _make_adapter("battery_time_remaining")
        r = await adapter.read("battery_time_remaining")
        # On this machine it's plugged in — expect -1.0
        battery = psutil.sensors_battery()
        if battery and battery.power_plugged:
            assert r.value == -1.0

    async def test_battery_time_remaining_no_battery(self):
        adapter = await _make_adapter("battery_time_remaining")
        with patch("psutil.sensors_battery", return_value=None):
            r = await adapter.read("battery_time_remaining")
        assert r.quality == 0.0
        assert r.metadata.get("unavailable") is True

    async def test_battery_time_remaining_discharging(self):
        fake_battery = MagicMock()
        fake_battery.percent = 80.0
        fake_battery.power_plugged = False
        fake_battery.secsleft = 3600  # 60 minutes
        adapter = await _make_adapter("battery_time_remaining")
        with patch("psutil.sensors_battery", return_value=fake_battery):
            r = await adapter.read("battery_time_remaining")
        assert r.value == pytest.approx(60.0)
        assert r.unit == "minutes"
        assert r.quality == 1.0


# ─── CPU Temperature ──────────────────────────────────────────────────────────


class TestCpuTemp:
    @skip_if_no_thermal
    async def test_cpu_temp_returns_celsius(self):
        adapter = await _make_adapter("cpu_temp")
        r = await adapter.read("cpu_temp")
        _assert_reading(
            r, "cpu_temp", "cpu_temp", "celsius", value_min=0.0, quality_min=0.8
        )

    async def test_cpu_temp_unavailable_returns_zero_quality(self):
        adapter = await _make_adapter("cpu_temp")
        with (
            patch("psutil.sensors_temperatures", return_value={}, create=True),
            patch("shutil.which", return_value=None),
        ):
            r = await adapter.read("cpu_temp")
        assert r.quality == 0.0
        assert r.value == 0.0
        assert r.metadata.get("unavailable") is True

    async def test_cpu_temp_osx_cpu_temp_parsed(self):
        adapter = await _make_adapter("cpu_temp")
        fake_proc = MagicMock()
        fake_proc.communicate = AsyncMock(return_value=(b"58.2\xc2\xb0C\n", b""))
        with (
            patch("platform.system", return_value="Darwin"),
            patch("psutil.sensors_temperatures", return_value={}, create=True),
            patch("shutil.which", return_value="/usr/local/bin/osx-cpu-temp"),
            patch("asyncio.create_subprocess_exec", return_value=fake_proc),
        ):
            r = await adapter.read("cpu_temp")
        assert r.value == pytest.approx(58.2)
        assert r.quality == pytest.approx(0.8)
        assert r.metadata["source"] == "osx-cpu-temp"

    async def test_cpu_temp_linux_coretemp(self):
        fake_entry = MagicMock()
        fake_entry.current = 55.0
        fake_temps = {"coretemp": [fake_entry, fake_entry]}
        adapter = await _make_adapter("cpu_temp")
        with (
            patch("platform.system", return_value="Linux"),
            # create=True: psutil.sensors_temperatures doesn't exist on macOS
            patch("psutil.sensors_temperatures", return_value=fake_temps, create=True),
            patch(
                "ori.hal.psutil_adapter.psutil.sensors_temperatures",
                return_value=fake_temps,
                create=True,
            ),
        ):
            r = await adapter.read("cpu_temp")
        assert r.value == pytest.approx(55.0)
        assert r.quality == 1.0
        assert r.metadata["source"] == "coretemp"


# ─── Storage ──────────────────────────────────────────────────────────────────


class TestStorage:
    async def test_disk_percent(self):
        adapter = await _make_adapter("disk_percent")
        r = await adapter.read("disk_percent")
        _assert_reading(
            r,
            "disk_percent",
            "disk_percent",
            "percent",
            value_min=0.0,
            value_max=100.0,
            quality_min=1.0,
        )

    async def test_disk_write_mb(self):
        adapter = await _make_adapter("disk_write_mb")
        r = await adapter.read("disk_write_mb")
        _assert_reading(
            r,
            "disk_write_mb",
            "disk_write_mb",
            "megabytes",
            value_min=0.0,
            quality_min=1.0,
        )
        assert "cumulative since boot" in r.metadata.get("note", "")

    async def test_disk_read_mb(self):
        adapter = await _make_adapter("disk_read_mb")
        r = await adapter.read("disk_read_mb")
        _assert_reading(
            r,
            "disk_read_mb",
            "disk_read_mb",
            "megabytes",
            value_min=0.0,
            quality_min=1.0,
        )

    async def test_disk_write_count(self):
        adapter = await _make_adapter("disk_write_count")
        r = await adapter.read("disk_write_count")
        _assert_reading(
            r,
            "disk_write_count",
            "disk_write_count",
            "count",
            value_min=0.0,
            quality_min=1.0,
        )

    async def test_disk_read_count(self):
        adapter = await _make_adapter("disk_read_count")
        r = await adapter.read("disk_read_count")
        _assert_reading(
            r,
            "disk_read_count",
            "disk_read_count",
            "count",
            value_min=0.0,
            quality_min=1.0,
        )

    async def test_disk_io_none_returns_zero_quality(self):
        adapter = await _make_adapter("disk_write_mb")
        with patch("psutil.disk_io_counters", return_value=None):
            r = await adapter.read("disk_write_mb")
        assert r.quality == 0.0
        assert r.value == 0.0
        assert r.metadata.get("unavailable") is True


# ─── Network ──────────────────────────────────────────────────────────────────


class TestNetwork:
    async def test_net_bytes_sent(self):
        adapter = await _make_adapter("net_bytes_sent_mb")
        r = await adapter.read("net_bytes_sent_mb")
        _assert_reading(
            r,
            "net_bytes_sent_mb",
            "net_bytes_sent_mb",
            "megabytes",
            value_min=0.0,
            quality_min=1.0,
        )

    async def test_net_bytes_recv(self):
        adapter = await _make_adapter("net_bytes_recv_mb")
        r = await adapter.read("net_bytes_recv_mb")
        _assert_reading(
            r,
            "net_bytes_recv_mb",
            "net_bytes_recv_mb",
            "megabytes",
            value_min=0.0,
            quality_min=1.0,
        )


# ─── Battery drain rate ───────────────────────────────────────────────────────


class TestBatteryDrainRate:
    async def test_no_state_store_returns_zero_quality(self):
        adapter = await _make_adapter("battery_drain_rate", state_store=None)
        r = await adapter.read("battery_drain_rate")
        assert r.quality == 0.0
        assert r.value == 0.0

    async def test_no_battery_returns_zero_quality(self):
        adapter = await _make_adapter("battery_drain_rate", state_store=MagicMock())
        with patch("psutil.sensors_battery", return_value=None):
            r = await adapter.read("battery_drain_rate")
        assert r.quality == 0.0

    async def test_no_history_returns_zero_quality(self):
        store = MagicMock()
        store.get_history = AsyncMock(return_value=[])
        adapter = await _make_adapter("battery_drain_rate", state_store=store)
        r = await adapter.read("battery_drain_rate")
        assert r.quality == 0.0

    async def test_elapsed_too_short_returns_zero_quality(self):
        now = _ms()
        store = MagicMock()
        store.get_history = AsyncMock(
            return_value=[
                SensorReading(
                    sensor_id="battery_drain_rate",
                    sensor_type="battery_percent",
                    value=90.0,
                    unit="percent",
                    timestamp=now - 10 * 60 * 1000,  # 10 minutes ago
                    quality=1.0,
                )
            ]
        )
        fake_battery = MagicMock()
        fake_battery.percent = 88.0
        adapter = await _make_adapter("battery_drain_rate", state_store=store)
        with patch("psutil.sensors_battery", return_value=fake_battery):
            r = await adapter.read("battery_drain_rate")
        assert r.quality == 0.0
        assert r.metadata.get("reason") == "elapsed_time_too_short"

    async def test_charging_returns_zero_quality(self):
        now = _ms()
        store = MagicMock()
        store.get_history = AsyncMock(
            return_value=[
                SensorReading(
                    sensor_id="battery_drain_rate",
                    sensor_type="battery_percent",
                    value=80.0,
                    unit="percent",
                    timestamp=now - 3_600_000,  # 1 hour ago
                    quality=1.0,
                )
            ]
        )
        fake_battery = MagicMock()
        fake_battery.percent = 90.0  # went UP — charging
        adapter = await _make_adapter("battery_drain_rate", state_store=store)
        with patch("psutil.sensors_battery", return_value=fake_battery):
            r = await adapter.read("battery_drain_rate")
        assert r.quality == 0.0
        assert r.metadata.get("reason") == "charging_or_no_change"

    async def test_drain_rate_computed_correctly(self):
        now = _ms()
        one_hour_ago = now - 3_600_000
        store = MagicMock()
        store.get_history = AsyncMock(
            return_value=[
                SensorReading(
                    sensor_id="battery_drain_rate",
                    sensor_type="battery_percent",
                    value=80.0,
                    unit="percent",
                    timestamp=one_hour_ago,
                    quality=1.0,
                )
            ]
        )
        fake_battery = MagicMock()
        fake_battery.percent = 70.0  # dropped 10% in ~1 hour
        adapter = await _make_adapter("battery_drain_rate", state_store=store)
        with patch("psutil.sensors_battery", return_value=fake_battery):
            r = await adapter.read("battery_drain_rate")
        assert r.quality == 1.0
        assert r.unit == "percent_per_hour"
        # 10% drop in 1 hour → ~10%/hr (allow small float drift)
        assert r.value == pytest.approx(10.0, abs=0.1)

    async def test_sleep_suspected_flag(self):
        now = _ms()
        # 30 minutes ago with only 1 history entry → sleep suspected
        store = MagicMock()
        store.get_history = AsyncMock(
            return_value=[
                SensorReading(
                    sensor_id="battery_drain_rate",
                    sensor_type="battery_percent",
                    value=80.0,
                    unit="percent",
                    timestamp=now - 35 * 60 * 1000,  # 35 minutes ago
                    quality=1.0,
                )
            ]
        )
        fake_battery = MagicMock()
        fake_battery.percent = 74.0
        adapter = await _make_adapter("battery_drain_rate", state_store=store)
        with patch("psutil.sensors_battery", return_value=fake_battery):
            r = await adapter.read("battery_drain_rate")
        assert r.quality == 1.0
        assert r.metadata.get("sleep_suspected") is True


# ─── Sleep process detection ──────────────────────────────────────────────────


class TestSleepBlockingProcess:
    async def test_returns_sensor_reading(self):
        adapter = await _make_adapter("sleep_blocking_process")
        r = await adapter.read("sleep_blocking_process")
        assert isinstance(r, SensorReading)
        assert r.unit == "count"
        assert r.value >= 0.0
        assert isinstance(r.metadata.get("processes"), list)

    async def test_macos_pmset_parsed(self):
        pmset_output = (
            "Assertion status system-wide:\n"
            "   PreventUserIdleSystemSleep  1\n"
            "Listed by owning process:\n"
            "   pid 1234(Zoom): [PreventUserIdleSystemSleep] named "
            '"Zoom video call" 00:01:23\n'
            "   pid 5678(Slack): [PreventSystemSleep] named "
            '"Slack notification" 00:00:05\n'
        )
        fake_proc = MagicMock()
        fake_proc.communicate = AsyncMock(return_value=(pmset_output.encode(), b""))

        adapter = await _make_adapter("sleep_blocking_process")
        with (
            patch("platform.system", return_value="Darwin"),
            patch("asyncio.create_subprocess_exec", return_value=fake_proc),
        ):
            r = await adapter.read("sleep_blocking_process")

        assert r.value == 2.0
        procs = r.metadata["processes"]
        assert any(p["name"] == "Zoom" and p["pid"] == 1234 for p in procs)
        assert any(p["name"] == "Slack" and p["pid"] == 5678 for p in procs)
        assert r.quality == 1.0

    async def test_linux_systemd_inhibit_parsed(self):
        inhibit_output = (
            "firefox  1000  4321  sleep:idle  video  block\n"
            "spotify  1000  8765  idle        audio  block\n"
        )
        fake_proc = MagicMock()
        fake_proc.communicate = AsyncMock(return_value=(inhibit_output.encode(), b""))

        adapter = await _make_adapter("sleep_blocking_process")
        with (
            patch("platform.system", return_value="Linux"),
            patch("shutil.which", return_value="/usr/bin/systemd-inhibit"),
            patch("asyncio.create_subprocess_exec", return_value=fake_proc),
        ):
            r = await adapter.read("sleep_blocking_process")

        assert r.value == 2.0
        procs = r.metadata["processes"]
        assert any(p["name"] == "firefox" for p in procs)
        assert r.quality == 1.0

    async def test_linux_no_systemd_inhibit_zero_quality(self):
        adapter = await _make_adapter("sleep_blocking_process")
        with (
            patch("platform.system", return_value="Linux"),
            patch("shutil.which", return_value=None),
        ):
            r = await adapter.read("sleep_blocking_process")
        assert r.quality == 0.0
        assert r.value == 0.0

    async def test_subprocess_failure_graceful(self):
        adapter = await _make_adapter("sleep_blocking_process")
        with (
            patch("platform.system", return_value="Darwin"),
            patch("asyncio.create_subprocess_exec", side_effect=OSError("boom")),
        ):
            r = await adapter.read("sleep_blocking_process")
        assert r.quality == 0.0
        assert r.value == 0.0
