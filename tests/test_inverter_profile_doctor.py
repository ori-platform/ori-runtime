# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

from ori import inverter_profile_doctor
from ori.hal.inverter_profiles import ProfileStatus, load_profile_data

_LCD_REF = "lcd-2026-06-26T12-00-00Z.jpg"
_PZEM_REF = "pzem-2026-06-26T12-00-00Z.jpg"


def _sample(
    metric,
    raw_registers,
    observed_value,
    tolerance,
    *,
    ground_truth_source="inverter_lcd_photo",
    ground_truth_ref=_LCD_REF,
):
    return {
        "metric": metric,
        "raw_registers": raw_registers,
        "observed_value": observed_value,
        "tolerance": tolerance,
        "ground_truth_source": ground_truth_source,
        "ground_truth_ref": ground_truth_ref,
    }


def _deye_full_samples(*, grid_ground_truth_source="inverter_lcd_photo"):
    grid_ref = (
        _PZEM_REF if grid_ground_truth_source == "pzem_or_clamp_photo" else _LCD_REF
    )
    return [
        _sample("deye_battery_soc", [85], 85.0, 1.0),
        _sample("deye_battery_voltage", [5320], 53.2, 0.1),
        _sample(
            "deye_grid_power",
            [65136],
            -400.0,
            5.0,
            ground_truth_source=grid_ground_truth_source,
            ground_truth_ref=grid_ref,
        ),
        _sample("deye_load_power", [900], 900.0, 5.0),
        _sample("deye_pv1_power", [1500], 1500.0, 5.0),
    ]


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
        "transport_proof": "termux tcp 192.168.1.45:8899 raw read ok",
        "operating_state": "daytime grid-import battery-idle",
        "attachments": {
            "inverter_lcd_photo": _LCD_REF,
            "vendor_app_screenshot": "",
            "pzem_or_clamp_photo": "",
        },
        "samples": [
            _sample("deye_grid_power", [65136], -400.0, 1.0),
        ],
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_deye_full_evidence(tmp_path, overrides=None):
    payload = {
        "schema_version": "ori.inverter_evidence.v1",
        "profile": "deye_hybrid",
        "brand": "Deye",
        "model": "SUN-8K-SG04LP3",
        "firmware": "MW3_16U_5406",
        "logger_serial": "1234567890",
        "captured_at_ms": 1782465600000,
        "source": "customer_field_capture",
        "transport_proof": "termux tcp 192.168.1.45:8899 raw read ok",
        "operating_state": "daytime grid-import battery-idle",
        "attachments": {
            "inverter_lcd_photo": _LCD_REF,
            "vendor_app_screenshot": "",
            "pzem_or_clamp_photo": "",
        },
        "samples": _deye_full_samples(),
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / "full-evidence.json"
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
    path = _write_deye_full_evidence(tmp_path)

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path), "--json"]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["evidence_pass"] is True
    assert payload["identity_complete"] is True
    assert payload["context_complete"] is True
    assert payload["primary_attachment_present"] is True
    assert payload["samples_cover_profile"] is True
    assert payload["promotion_candidate"] is True
    assert payload["sample_checks"][0]["pass"] is True
    assert payload["qualification_report"][-1] == {
        "check": "promotion_candidate",
        "detail": (
            "eligible for maintainer review; doctor does not mutate profile status"
        ),
        "pass": True,
    }
    assert "does not mutate bundled profiles" in payload["note"]


def test_evidence_partial_metric_coverage_blocks_promotion(tmp_path, capsys):
    path = _write_evidence(tmp_path)

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path), "--json"]
    )

    assert result == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["samples_pass"] is True
    assert payload["samples_cover_profile"] is False
    assert payload["promotion_candidate"] is False
    assert "deye_battery_soc" in payload["missing_sample_metrics"]


def test_evidence_text_reports_missing_metric_coverage(tmp_path, capsys):
    path = _write_evidence(tmp_path)

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path)]
    )

    assert result == 1
    output = capsys.readouterr().out
    assert "FAIL coverage: missing samples for" in output
    assert "deye_battery_soc" in output


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
    assert samples["deye_grid_power"]["ground_truth_source"] == ""
    assert samples["deye_grid_power"]["ground_truth_ref"] == ""
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
                _sample("deye_grid_power", [65136], -300.0, 5.0),
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


def test_evidence_missing_context_blocks_promotion(tmp_path, capsys):
    path = _write_deye_full_evidence(
        tmp_path,
        {"transport_proof": "", "operating_state": ""},
    )

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path), "--json"]
    )

    assert result == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["context_complete"] is False
    assert payload["missing_context_fields"] == ["transport_proof", "operating_state"]
    assert payload["evidence_pass"] is False
    assert payload["promotion_candidate"] is False


def test_evidence_text_reports_missing_context_and_attachment(tmp_path, capsys):
    path = _write_deye_full_evidence(
        tmp_path,
        {
            "transport_proof": "",
            "attachments": {
                "inverter_lcd_photo": "",
                "vendor_app_screenshot": "",
                "pzem_or_clamp_photo": "",
            },
        },
    )

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path)]
    )

    assert result == 1
    output = capsys.readouterr().out
    assert "FAIL context: missing transport_proof" in output
    assert (
        "FAIL attachments: missing inverter LCD or vendor app proof reference" in output
    )


def test_evidence_missing_primary_attachment_blocks_promotion(tmp_path, capsys):
    path = _write_deye_full_evidence(
        tmp_path,
        {
            "attachments": {
                "inverter_lcd_photo": "",
                "vendor_app_screenshot": "",
                "pzem_or_clamp_photo": "",
            }
        },
    )

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path), "--json"]
    )

    assert result == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["primary_attachment_present"] is False
    assert payload["samples_pass"] is True
    assert payload["evidence_pass"] is False


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
                _sample(
                    "deye_grid_power",
                    [65136],
                    -400.0,
                    1.0,
                    ground_truth_ref="",
                ),
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


def test_evidence_invalid_ground_truth_source_fails_sample(tmp_path, capsys):
    path = _write_evidence(
        tmp_path,
        {
            "samples": [
                {
                    "metric": "deye_grid_power",
                    "raw_registers": [65136],
                    "observed_value": -400.0,
                    "tolerance": 1.0,
                    "ground_truth_source": "unverified_spreadsheet",
                    "ground_truth_ref": "sheet-row-1",
                }
            ]
        },
    )

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path), "--json"]
    )

    assert result == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["sample_checks"][0]["ground_truth_source_valid"] is False
    assert payload["sample_checks"][0]["ground_truth_present"] is False


def test_evidence_pzem_source_requires_pzem_attachment(tmp_path, capsys):
    path = _write_deye_full_evidence(
        tmp_path,
        {"samples": _deye_full_samples(grid_ground_truth_source="pzem_or_clamp_photo")},
    )

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path), "--json"]
    )

    assert result == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["pzem_comparison_used"] is True
    assert payload["pzem_attachment_present"] is False
    assert payload["pzem_comparison_complete"] is False
    assert payload["samples_pass"] is True
    assert payload["evidence_pass"] is False


def test_evidence_pzem_source_passes_with_pzem_attachment(tmp_path, capsys):
    path = _write_deye_full_evidence(
        tmp_path,
        {
            "attachments": {
                "inverter_lcd_photo": _LCD_REF,
                "vendor_app_screenshot": "",
                "pzem_or_clamp_photo": _PZEM_REF,
            },
            "samples": _deye_full_samples(
                grid_ground_truth_source="pzem_or_clamp_photo"
            ),
        },
    )

    result = inverter_profile_doctor.main(
        ["--profile", "deye_hybrid", "--evidence", str(path), "--json"]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["pzem_comparison_used"] is True
    assert payload["pzem_comparison_complete"] is True
    assert payload["evidence_pass"] is True


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
                _sample("unknown_metric", [1], 1.0, 0.0),
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
                    "ground_truth_source": "inverter_lcd_photo",
                    "ground_truth_ref": _LCD_REF,
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
