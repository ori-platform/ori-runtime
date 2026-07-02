# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ori.hal.base import AdapterReadError, CircuitState
from ori.hal.smart_adapter import SmartAdapter


def _config(
    sensor_type: str = "drive_temp_celsius",
    failure_threshold: int = 3,
    device: str = "/dev/sda",
) -> dict:
    return {
        "sensor_id": "drive-health",
        "sensor_type": sensor_type,
        "device": device,
        "poll_interval_ms": 60000,
        "circuit_breaker": {
            "failure_threshold": failure_threshold,
            "recovery_timeout_s": 300,
            "success_threshold": 2,
        },
    }


def _smartctl_payload() -> dict:
    return {
        "smart_support": {"available": True, "enabled": True},
        "temperature": {"current": 44},
        "power_on_time": {"hours": 8123},
        "ata_smart_attributes": {
            "table": [
                {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 2}},
                {"id": 9, "name": "Power_On_Hours", "raw": {"value": 8123}},
                {
                    "id": 241,
                    "name": "Total_LBAs_Written",
                    "raw": {"value": 1_500_000_000},
                },
                {"id": 233, "name": "Media_Wearout_Indicator", "raw": {"value": 30}},
            ]
        },
    }


class TestSmartAdapter:
    @pytest.mark.asyncio
    async def test_graceful_import_failure(self):
        adapter = SmartAdapter()
        payload = _smartctl_payload()
        with patch("ori.hal.smart_adapter._PYSMART_AVAILABLE", False):
            await adapter.connect(_config(sensor_type="drive_temp_celsius"))
            with patch.object(adapter, "_run_smartctl_json", return_value=payload):
                reading = await adapter.read("drive-health")
            assert reading.sensor_type == "drive_temp_celsius"
            assert reading.value == pytest.approx(44.0)

    @pytest.mark.asyncio
    async def test_read_temperature(self):
        adapter = SmartAdapter()
        payload = _smartctl_payload()
        with (
            patch("ori.hal.smart_adapter._PYSMART_AVAILABLE", False),
        ):
            await adapter.connect(_config(sensor_type="drive_temp_celsius"))
            with patch.object(adapter, "_run_smartctl_json", return_value=payload):
                reading = await adapter.read("drive-health")
        assert reading.value == pytest.approx(44.0)
        assert reading.unit == "celsius"
        assert reading.metadata["source"] == "smart"

    @pytest.mark.asyncio
    async def test_read_tbw(self):
        adapter = SmartAdapter()
        payload = _smartctl_payload()
        with patch("ori.hal.smart_adapter._PYSMART_AVAILABLE", False):
            await adapter.connect(_config(sensor_type="tbw_remaining_tb"))
            with patch.object(adapter, "_run_smartctl_json", return_value=payload):
                reading = await adapter.read("drive-health")
        assert reading.value > 0.0
        assert reading.unit == "terabytes"

    @pytest.mark.asyncio
    async def test_no_smart_support(self):
        adapter = SmartAdapter()
        payload = {"smart_support": {"available": False, "enabled": False}}
        with patch("ori.hal.smart_adapter._PYSMART_AVAILABLE", False):
            await adapter.connect(_config(sensor_type="power_on_hours"))
            with patch.object(adapter, "_run_smartctl_json", return_value=payload):
                with pytest.raises(
                    AdapterReadError, match="SMART is not available/enabled"
                ):
                    await adapter.read("drive-health")

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        adapter = SmartAdapter()
        with patch("ori.hal.smart_adapter._PYSMART_AVAILABLE", False):
            await adapter.connect(_config(failure_threshold=2))

        error = AdapterReadError("simulated SMART read failure")
        with patch.object(adapter, "_read_metrics_sync", side_effect=error):
            with pytest.raises(AdapterReadError):
                await adapter.read("drive-health")
            assert adapter._breaker is not None
            assert adapter._breaker.state == CircuitState.CLOSED

            with pytest.raises(AdapterReadError):
                await adapter.read("drive-health")
            assert adapter._breaker.state == CircuitState.OPEN

            with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
                await adapter.read("drive-health")

    def test_smartctl_invalid_json_raises(self):
        adapter = SmartAdapter()
        adapter._device = "/dev/sda"
        proc = SimpleNamespace(returncode=0, stdout="{not-json", stderr="")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(AdapterReadError, match="invalid JSON"):
                adapter._run_smartctl_json()

    def test_smartctl_execution_failure_raises(self):
        adapter = SmartAdapter()
        adapter._device = "/dev/sda"
        proc = SimpleNamespace(
            returncode=8, stdout=json.dumps({}), stderr="permission denied"
        )
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(AdapterReadError, match="smartctl failed"):
                adapter._run_smartctl_json()
