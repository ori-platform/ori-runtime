# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

from ori import inverter_profile_doctor
from ori.hal.inverter_profiles import ProfileStatus, load_profile_data


def _write_evidence(tmp_path, overrides=None):
    payload = {
        "schema_version": "ori.inverter_evidence.v1",
        "profile": "deye_hybrid",
        "brand": "Deye",
        "model": "SUN-8K-SG04LP3",
        "firmware": "MW3_16U_5406",
        "logger_serial": "1234567890",
        "captured_at_ms": 1782465600000,
        "source": "customer_field_capture",
        "samples": [
            {
                "metric": "deye_grid_power",
                "raw_registers": [65136],
                "observed_value": -400.0,
                "tolerance": 1.0,
                "ground_truth": "timestamped_inverter_lcd_photo",
            }
        ],
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


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


def test_evidence_json_reports_promotion_candidate(tmp_path, capsys):
    path = _write_evidence(tmp_path)

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path), "--json"]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["evidence_pass"] is True
    assert payload["identity_complete"] is True
    assert payload["promotion_candidate"] is True
    assert payload["sample_checks"][0]["pass"] is True
    assert "does not mutate bundled profiles" in payload["note"]


def test_evidence_template_contains_profile_samples(capsys):
    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence-template"]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "ori.inverter_evidence.v1"
    assert payload["profile"] == "deye_hybrid"
    assert payload["profile_status"] == "community_derived"
    assert payload["profile_field_qualified"] is False
    assert payload["captured_at_ms"] == 0
    assert (
        "Do not reuse fixture_hint values as field evidence." in payload["instructions"]
    )
    samples = {sample["metric"]: sample for sample in payload["samples"]}
    assert "deye_grid_power" in samples
    assert samples["deye_grid_power"]["raw_registers"] == []
    assert samples["deye_grid_power"]["observed_value"] == ""
    assert samples["deye_grid_power"]["fixture_hint"]["expected_value"] == -400.0


def test_evidence_template_rejects_decode_mix(capsys):
    with pytest.raises(SystemExit):
        inverter_profile_doctor.main(
            [
                "--profile",
                "deye_hybrid",
                "--evidence-template",
                "--decode",
                "deye_grid_power",
                "--raw",
                "65136",
            ]
        )

    assert "cannot be combined" in capsys.readouterr().err


def test_evidence_outside_tolerance_returns_failure(tmp_path, capsys):
    path = _write_evidence(
        tmp_path,
        {
            "samples": [
                {
                    "metric": "deye_grid_power",
                    "raw_registers": [65136],
                    "observed_value": -300.0,
                    "tolerance": 5.0,
                    "ground_truth": "timestamped_inverter_lcd_photo",
                }
            ]
        },
    )

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path), "--json"]
    )

    assert result == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["evidence_pass"] is False
    assert payload["samples_pass"] is False
    assert payload["sample_checks"][0]["delta"] == 100.0


def test_evidence_missing_identity_blocks_promotion(tmp_path, capsys):
    path = _write_evidence(tmp_path, {"firmware": ""})

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path)]
    )

    assert result == 1
    output = capsys.readouterr().out
    assert "FAIL identity: missing firmware" in output
    assert "Result: FAIL" in output


def test_evidence_invalid_capture_timestamp_blocks_promotion(tmp_path, capsys):
    path = _write_evidence(tmp_path, {"captured_at_ms": None})

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path), "--json"]
    )

    assert result == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["identity_complete"] is False
    assert "captured_at_ms" in payload["missing_identity_fields"]


def test_evidence_missing_ground_truth_blocks_sample_pass(tmp_path, capsys):
    path = _write_evidence(
        tmp_path,
        {
            "samples": [
                {
                    "metric": "deye_grid_power",
                    "raw_registers": [65136],
                    "observed_value": -400.0,
                    "tolerance": 1.0,
                }
            ]
        },
    )

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path), "--json"]
    )

    assert result == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["samples_pass"] is False
    assert payload["sample_checks"][0]["ground_truth_present"] is False


def test_evidence_profile_mismatch_returns_error(tmp_path, capsys):
    path = _write_evidence(tmp_path, {"profile": "growatt_spf"})

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path), "--json"]
    )

    assert result == 2
    payload = json.loads(capsys.readouterr().out)
    assert "does not match --profile" in payload["error"]


def test_evidence_unknown_metric_returns_error(tmp_path, capsys):
    path = _write_evidence(
        tmp_path,
        {
            "samples": [
                {
                    "metric": "unknown_metric",
                    "raw_registers": [1],
                    "observed_value": 1.0,
                    "tolerance": 0.0,
                    "ground_truth": "timestamped_inverter_lcd_photo",
                }
            ]
        },
    )

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path)]
    )

    assert result == 2
    assert "has no metric" in capsys.readouterr().err


def test_decode_supports_enum_metric(monkeypatch, capsys):
    profile = load_profile_data(
        {
            "profile": "fixture",
            "transport": "solarman_v5",
            "status": ProfileStatus.COMMUNITY_DERIVED,
            "metrics": {
                "status": {
                    "register": 1,
                    "unit": "state",
                    "value_type": "enum",
                    "lookup": {2: "fault"},
                }
            },
            "qualification_vectors": [
                {"metric": "status", "raw_registers": [2], "expected_value": "fault"}
            ],
        }
    )
    monkeypatch.setattr(inverter_profile_doctor, "load_profile", lambda _: profile)

    result = inverter_profile_doctor.main(
        ["--profile", "fixture", "--decode", "status", "--raw", "2", "--json"]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decoded"] == "fault"
    assert payload["unit"] == "state"


def test_evidence_supports_string_observed_value(monkeypatch, tmp_path, capsys):
    profile = load_profile_data(
        {
            "profile": "fixture",
            "transport": "solarman_v5",
            "status": ProfileStatus.COMMUNITY_DERIVED,
            "metrics": {
                "firmware": {
                    "register": 1,
                    "count": 3,
                    "unit": "text",
                    "value_type": "string",
                }
            },
            "qualification_vectors": [
                {
                    "metric": "firmware",
                    "raw_registers": [0x5631, 0x2E32, 0x0000],
                    "expected_value": "V1.2",
                }
            ],
        }
    )
    monkeypatch.setattr(inverter_profile_doctor, "load_profile", lambda _: profile)
    path = _write_evidence(
        tmp_path,
        {
            "profile": "fixture",
            "samples": [
                {
                    "metric": "firmware",
                    "raw_registers": [0x5631, 0x2E32, 0x0000],
                    "observed_value": "V1.2",
                    "ground_truth": "timestamped_inverter_lcd_photo",
                }
            ],
        },
    )

    result = inverter_profile_doctor.main(
        ["--profile", "fixture", "--evidence", str(path), "--json"]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sample_checks"][0]["decoded"] == "V1.2"
    assert payload["sample_checks"][0]["delta"] is None
    assert payload["sample_checks"][0]["pass"] is True
