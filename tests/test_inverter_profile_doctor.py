# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json

from ori import inverter_profile_doctor


def test_lists_bundled_profiles(capsys):
    result = inverter_profile_doctor.main(["--list"])

    assert result == 0
    output = capsys.readouterr().out
    assert "growatt_spf" in output
    assert "deye_hybrid" in output


def test_profile_json_reports_vector_status(capsys):
    result = inverter_profile_doctor.main(["--profile", "deye_hybrid", "--json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["profile"] == "deye_hybrid"
    assert payload["status"] == "community_derived"
    assert payload["field_qualified"] is False
    assert payload["vectors_pass"] is True
    assert "deye_grid_power" in payload["metrics"]


def test_decodes_raw_registers(capsys):
    result = inverter_profile_doctor.main(
        [
            "--profile",
            "deye_hybrid",
            "--decode",
            "deye_grid_power",
            "--raw",
            "65136",
            "--json",
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "decoded": -400.0,
        "field_qualified": False,
        "metric": "deye_grid_power",
        "profile": "deye_hybrid",
        "profile_status": "community_derived",
        "raw_registers": [65136],
        "unit": "watt",
    }


def test_decodes_hex_raw_registers(capsys):
    result = inverter_profile_doctor.main(
        [
            "--profile",
            "growatt_spf",
            "--decode",
            "growatt_grid_power",
            "--raw",
            "0xffff,0xff1a",
        ]
    )

    assert result == 0
    output = capsys.readouterr().out
    assert "-> -230.0 watt" in output
    assert "not field_qualified" in output


def test_invalid_raw_register_returns_error(capsys):
    result = inverter_profile_doctor.main(
        [
            "--profile",
            "deye_hybrid",
            "--decode",
            "deye_grid_power",
            "--raw",
            "70000",
            "--json",
        ]
    )

    assert result == 2
    payload = json.loads(capsys.readouterr().out)
    assert "outside uint16 range" in payload["error"]


def test_missing_profile_returns_error(capsys):
    result = inverter_profile_doctor.main(["--profile", "missing"])

    assert result == 2
    assert "unknown inverter profile" in capsys.readouterr().err
