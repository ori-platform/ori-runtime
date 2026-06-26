# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from ori.hal.base import AdapterConnectionError
from ori.hal.inverter_profiles import (
    InverterProfileError,
    ProfileStatus,
    decode_metric,
    decode_raw_registers,
    list_bundled_profiles,
    load_profile,
    load_profile_data,
)
from ori.hal.solarman_modbus_adapter import SolarmanModbusAdapter


def test_bundled_profiles_are_present():
    assert {"growatt_spf", "deye_hybrid"} <= set(list_bundled_profiles())


@pytest.mark.parametrize("profile_name", list_bundled_profiles())
def test_bundled_profile_loads(profile_name):
    profile = load_profile(profile_name)

    assert profile.profile == profile_name
    assert profile.metrics
    assert profile.vectors
    assert profile.status in {
        ProfileStatus.EXPERIMENTAL,
        ProfileStatus.COMMUNITY_DERIVED,
        ProfileStatus.FIELD_QUALIFIED,
    }


@pytest.mark.parametrize("profile_name", list_bundled_profiles())
def test_bundled_profile_vectors_decode_within_tolerance(profile_name):
    profile = load_profile(profile_name)

    for vector in profile.vectors:
        decoded = decode_metric(profile, vector.metric, vector.raw_registers)
        assert abs(decoded - vector.expected_value) <= vector.tolerance, (
            f"{profile_name}:{vector.metric} decoded {decoded}, expected "
            f"{vector.expected_value} +/- {vector.tolerance}"
        )


@pytest.mark.parametrize("profile_name", list_bundled_profiles())
def test_every_bundled_metric_has_a_qualification_vector(profile_name):
    profile = load_profile(profile_name)
    covered = {vector.metric for vector in profile.vectors}

    assert set(profile.metrics) <= covered


def test_signed_decode_guards_import_export_signs():
    growatt = load_profile("growatt_spf")
    deye = load_profile("deye_hybrid")

    assert decode_metric(growatt, "growatt_grid_power", [65535, 65306]) == -230.0
    assert decode_metric(deye, "deye_grid_power", [65136]) == -400.0


def test_decode_supports_word_order_mask_and_offset():
    profile = load_profile_data(
        {
            "profile": "fixture",
            "transport": "solarman_v5",
            "status": ProfileStatus.COMMUNITY_DERIVED,
            "metrics": {
                "fixture_metric": {
                    "register": 1,
                    "count": 2,
                    "scale": 0.5,
                    "offset": -10,
                    "mask": 0x00FF,
                    "word_order": "little",
                    "unit": "watt",
                }
            },
            "qualification_vectors": [
                {
                    "metric": "fixture_metric",
                    "raw_registers": [0x0012, 0x0000],
                    "expected_value": -1.0,
                }
            ],
        }
    )

    assert decode_metric(profile, "fixture_metric", [0x0012, 0x0000]) == -1.0
    assert decode_raw_registers([0xFFFF], signed=True) == -1


def test_field_qualified_profiles_require_firmware_verified():
    with pytest.raises(InverterProfileError, match="firmware"):
        load_profile_data(
            {
                "profile": "unsafe",
                "transport": "solarman_v5",
                "status": ProfileStatus.FIELD_QUALIFIED,
                "metrics": {
                    "soc": {
                        "register": 1,
                        "scale": 1,
                        "unit": "percent",
                    }
                },
                "qualification_vectors": [
                    {"metric": "soc", "raw_registers": [85], "expected_value": 85}
                ],
            }
        )


def test_metric_without_vector_is_rejected():
    with pytest.raises(InverterProfileError, match="without qualification vectors"):
        load_profile_data(
            {
                "profile": "incomplete",
                "transport": "solarman_v5",
                "status": ProfileStatus.COMMUNITY_DERIVED,
                "metrics": {
                    "soc": {"register": 1, "scale": 1, "unit": "percent"},
                    "pv": {"register": 2, "scale": 1, "unit": "watt"},
                },
                "qualification_vectors": [
                    {"metric": "soc", "raw_registers": [85], "expected_value": 85}
                ],
            }
        )


def test_unknown_profile_is_rejected():
    with pytest.raises(InverterProfileError, match="unknown inverter profile"):
        load_profile("does-not-exist")


class _FakeSolarman:
    def __init__(self, *_args, **_kwargs):
        self._responses: dict[tuple[int, int], list[int]] = {}

    def read_holding_registers(self, register: int, count: int) -> list[int]:
        return self._responses[(register, count)]

    def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_solarman_modbus_adapter_decodes_via_profile(monkeypatch):
    fake = _FakeSolarman()
    profile = load_profile("deye_hybrid")
    spec = profile.metric("deye_grid_power")
    fake._responses[(spec.register, spec.count)] = [65136]

    monkeypatch.setattr("ori.hal.solarman_modbus_adapter._PYSOLARMAN_AVAILABLE", True)
    monkeypatch.setattr(
        "ori.hal.solarman_modbus_adapter._PySolarmanV5", lambda *a, **k: fake
    )

    adapter = SolarmanModbusAdapter()
    await adapter.connect(
        {
            "profile": "deye_hybrid",
            "sensor_type": "deye_grid_power",
            "host": "192.168.1.50",
            "serial": "1234567890",
            "circuit_breaker": {"failure_threshold": 2},
        }
    )
    reading = await adapter.read("inverter-grid")

    assert reading.sensor_type == "deye_grid_power"
    assert reading.value == -400.0
    assert reading.unit == "watt"
    assert reading.metadata["source"] == "solarman_modbus"
    assert reading.metadata["profile"] == "deye_hybrid"
    assert reading.metadata["profile_status"] == ProfileStatus.COMMUNITY_DERIVED
    assert reading.metadata["profile_field_qualified"] is False


@pytest.mark.asyncio
async def test_solarman_modbus_adapter_rejects_wrong_transport(monkeypatch):
    profile = load_profile_data(
        {
            "profile": "serial_only",
            "transport": "modbus_serial",
            "status": ProfileStatus.COMMUNITY_DERIVED,
            "metrics": {
                "soc": {"register": 1, "scale": 1, "unit": "percent"},
            },
            "qualification_vectors": [
                {"metric": "soc", "raw_registers": [85], "expected_value": 85}
            ],
        }
    )

    monkeypatch.setattr(
        "ori.hal.solarman_modbus_adapter.load_profile", lambda _: profile
    )
    adapter = SolarmanModbusAdapter()

    with pytest.raises(
        AdapterConnectionError, match="only supports transport='solarman_v5'"
    ):
        await adapter.connect(
            {
                "profile": "serial_only",
                "sensor_type": "soc",
                "host": "192.168.1.50",
                "serial": "1234567890",
            }
        )


@pytest.mark.asyncio
async def test_solarman_modbus_adapter_rejects_experimental_profile(monkeypatch):
    profile = load_profile_data(
        {
            "profile": "experimental_profile",
            "transport": "solarman_v5",
            "status": ProfileStatus.EXPERIMENTAL,
            "metrics": {
                "soc": {"register": 1, "scale": 1, "unit": "percent"},
            },
            "qualification_vectors": [
                {"metric": "soc", "raw_registers": [85], "expected_value": 85}
            ],
        }
    )

    monkeypatch.setattr(
        "ori.hal.solarman_modbus_adapter.load_profile", lambda _: profile
    )
    adapter = SolarmanModbusAdapter()

    with pytest.raises(AdapterConnectionError, match="experimental"):
        await adapter.connect(
            {
                "profile": "experimental_profile",
                "sensor_type": "soc",
                "host": "192.168.1.50",
                "serial": "1234567890",
            }
        )


@pytest.mark.asyncio
async def test_adapter_gracefully_reports_missing_pysolarman(monkeypatch):
    monkeypatch.setattr("ori.hal.solarman_modbus_adapter._PYSOLARMAN_AVAILABLE", False)

    adapter = SolarmanModbusAdapter()
    with pytest.raises(AdapterConnectionError, match="pysolarmanv5"):
        await adapter.connect(
            {
                "profile": "growatt_spf",
                "sensor_type": "growatt_battery_soc",
                "host": "192.168.1.50",
                "serial": "1234567890",
            }
        )
