# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ori.hal.inverter_profiles import (
    InverterProfile,
    InverterProfileError,
    decode_metric_value,
    list_bundled_profiles,
    load_profile,
)

_EVIDENCE_SCHEMA_VERSION = "ori.inverter_evidence.v1"
_REQUIRED_EVIDENCE_IDENTITY_FIELDS = (
    "brand",
    "model",
    "firmware",
    "logger_serial",
    "captured_at_ms",
)


def _evidence_template(profile: InverterProfile) -> dict[str, Any]:
    vectors_by_metric = {vector.metric: vector for vector in profile.vectors}
    samples: list[dict[str, Any]] = []
    for metric_name, spec in sorted(profile.metrics.items(), key=lambda item: item[0]):
        vector = vectors_by_metric.get(metric_name)
        sample: dict[str, Any] = {
            "metric": metric_name,
            "register": spec.register,
            "count": spec.count,
            "unit": spec.unit,
            "value_type": spec.value_type,
            "raw_registers": [],
            "observed_value": "",
            "tolerance": 0.0 if spec.value_type != "numeric" else 1.0,
            "ground_truth": "",
        }
        if spec.value_type == "enum":
            sample["lookup"] = {str(key): value for key, value in spec.lookup.items()}
        if vector is not None:
            sample["fixture_hint"] = {
                "raw_registers": list(vector.raw_registers),
                "expected_value": vector.expected_value,
                "ground_truth": vector.ground_truth,
            }
        samples.append(sample)

    return {
        "schema_version": _EVIDENCE_SCHEMA_VERSION,
        "profile": profile.profile,
        "profile_status": profile.status,
        "profile_field_qualified": profile.is_field_qualified,
        "brand": profile.brand,
        "model": "",
        "firmware": "",
        "logger_serial": "",
        "captured_at_ms": 0,
        "source": "field_capture",
        "transport_proof": "",
        "operating_state": "",
        "attachments": {
            "inverter_lcd_photo": "",
            "vendor_app_screenshot": "",
            "pzem_or_clamp_photo": "",
        },
        "instructions": [
            "Replace every placeholder before review.",
            "Use raw registers captured from the live unit at the same timestamp as the ground-truth reading.",
            "Use inverter LCD, vendor app, or independent PZEM/clamp evidence as ground_truth.",
            "Do not reuse fixture_hint values as field evidence.",
        ],
        "samples": samples,
    }


def _parse_registers(raw: str) -> list[int]:
    registers: list[int] = []
    for part in str(raw or "").split(","):
        token = part.strip()
        if not token:
            continue
        try:
            value = int(token, 0)
        except ValueError as exc:
            raise InverterProfileError(
                f"invalid raw register {token!r}; use decimal or 0x-prefixed hex"
            ) from exc
        if not (0 <= value <= 0xFFFF):
            raise InverterProfileError(
                f"raw register {token!r} is outside uint16 range 0..65535"
            )
        registers.append(value)
    if not registers:
        raise InverterProfileError("at least one raw register is required")
    return registers


def _parse_evidence_registers(raw: object, sample_index: int) -> list[int]:
    if not isinstance(raw, list):
        raise InverterProfileError(
            f"evidence sample {sample_index}: raw_registers must be a list"
        )
    registers: list[int] = []
    for value in raw:
        if not isinstance(value, int) or isinstance(value, bool):
            raise InverterProfileError(
                f"evidence sample {sample_index}: raw register {value!r} "
                "must be an integer"
            )
        if not (0 <= value <= 0xFFFF):
            raise InverterProfileError(
                f"evidence sample {sample_index}: raw register {value!r} "
                "is outside uint16 range 0..65535"
            )
        registers.append(value)
    if not registers:
        raise InverterProfileError(
            f"evidence sample {sample_index}: at least one raw_registers value is required"
        )
    return registers


def _read_evidence_bundle(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InverterProfileError(
            f"unable to read evidence file {path}: {exc}"
        ) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InverterProfileError(
            f"invalid JSON evidence file {path}: {exc.msg}"
        ) from exc
    if not isinstance(data, dict):
        raise InverterProfileError("evidence file must contain a JSON object")
    return data


def _has_evidence_identity_value(field: str, value: object) -> bool:
    if field == "captured_at_ms":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value > 0
        )
    if value is None or isinstance(value, bool):
        return False
    return bool(str(value).strip())


def _coerce_observed_value(value: object, *, sample_index: int) -> float | str:
    if isinstance(value, bool):
        raise InverterProfileError(
            f"evidence sample {sample_index}: observed_value cannot be boolean"
        )
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        raise InverterProfileError(
            f"evidence sample {sample_index}: observed_value is required"
        )
    return text


def _compare_decoded_value(
    decoded: float | str,
    expected: float | str,
    tolerance: float,
) -> tuple[bool, float | None]:
    if isinstance(decoded, str) or isinstance(expected, str):
        return str(decoded) == str(expected), None
    delta = abs(float(decoded) - float(expected))
    return delta <= tolerance, round(delta, 4)


def _vector_checks(profile: InverterProfile) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for vector in profile.vectors:
        decoded = decode_metric_value(profile, vector.metric, vector.raw_registers)
        passed, delta = _compare_decoded_value(
            decoded,
            vector.expected_value,
            vector.tolerance,
        )
        checks.append(
            {
                "metric": vector.metric,
                "raw_registers": list(vector.raw_registers),
                "decoded": decoded,
                "expected": vector.expected_value,
                "delta": delta,
                "tolerance": vector.tolerance,
                "pass": passed,
                "ground_truth": vector.ground_truth,
            }
        )
    return checks


def _review_evidence_sample(
    profile: InverterProfile,
    sample: object,
    index: int,
) -> dict[str, Any]:
    if not isinstance(sample, dict):
        raise InverterProfileError(f"evidence sample {index}: must be a JSON object")

    metric = str(sample.get("metric", "")).strip()
    if not metric:
        raise InverterProfileError(f"evidence sample {index}: metric is required")
    registers = _parse_evidence_registers(sample.get("raw_registers"), index)
    try:
        raw_tolerance = sample.get("tolerance", 0.0)
        if isinstance(raw_tolerance, bool):
            raise ValueError("boolean is not numeric evidence")
        observed = _coerce_observed_value(sample["observed_value"], sample_index=index)
        tolerance = float(raw_tolerance)
    except KeyError as exc:
        raise InverterProfileError(
            f"evidence sample {index}: observed_value is required"
        ) from exc
    except (TypeError, ValueError) as exc:
        raise InverterProfileError(
            f"evidence sample {index}: tolerance must be numeric"
        ) from exc
    if tolerance < 0:
        raise InverterProfileError(f"evidence sample {index}: tolerance must be >= 0")

    ground_truth = str(sample.get("ground_truth", "")).strip()
    decoded = decode_metric_value(profile, metric, registers)
    passed, delta = _compare_decoded_value(decoded, observed, tolerance)
    ground_truth_present = bool(ground_truth)
    return {
        "index": index,
        "metric": metric,
        "raw_registers": registers,
        "decoded": decoded,
        "observed_value": observed,
        "delta": delta,
        "tolerance": tolerance,
        "pass": passed and ground_truth_present,
        "ground_truth": ground_truth,
        "ground_truth_present": ground_truth_present,
    }


def _evidence_summary(profile: InverterProfile, path: Path) -> dict[str, Any]:
    bundle = _read_evidence_bundle(path)
    schema_version = str(bundle.get("schema_version", "")).strip()
    if schema_version != _EVIDENCE_SCHEMA_VERSION:
        raise InverterProfileError(
            "evidence schema_version must be "
            f"{_EVIDENCE_SCHEMA_VERSION!r}, got {schema_version!r}"
        )

    bundle_profile = str(bundle.get("profile", "")).strip()
    if bundle_profile != profile.profile:
        raise InverterProfileError(
            f"evidence profile {bundle_profile!r} does not match --profile "
            f"{profile.profile!r}"
        )

    missing_identity = [
        field
        for field in _REQUIRED_EVIDENCE_IDENTITY_FIELDS
        if not _has_evidence_identity_value(field, bundle.get(field))
    ]
    samples = bundle.get("samples")
    if not isinstance(samples, list) or not samples:
        raise InverterProfileError("evidence samples must be a non-empty list")

    sample_checks = [
        _review_evidence_sample(profile, sample, index)
        for index, sample in enumerate(samples, start=1)
    ]
    samples_pass = all(check["pass"] for check in sample_checks)
    identity_complete = not missing_identity
    evidence_pass = identity_complete and samples_pass
    return {
        "schema_version": schema_version,
        "profile": profile.profile,
        "profile_status": profile.status,
        "profile_field_qualified": profile.is_field_qualified,
        "evidence_file": str(path),
        "identity": {
            "brand": bundle.get("brand"),
            "model": bundle.get("model"),
            "firmware": bundle.get("firmware"),
            "logger_serial": bundle.get("logger_serial"),
            "captured_at_ms": bundle.get("captured_at_ms"),
            "source": bundle.get("source", ""),
        },
        "identity_complete": identity_complete,
        "missing_identity_fields": missing_identity,
        "sample_checks": sample_checks,
        "samples_pass": samples_pass,
        "evidence_pass": evidence_pass,
        "promotion_candidate": evidence_pass and not profile.is_field_qualified,
        "note": (
            "Offline evidence review only; this command does not mutate bundled "
            "profiles, promote qualification status, open inverter transports, "
            "or write control registers."
        ),
    }


def _profile_summary(profile: InverterProfile) -> dict[str, Any]:
    checks = _vector_checks(profile)
    return {
        "profile": profile.profile,
        "brand": profile.brand,
        "models": list(profile.models),
        "transport": profile.transport,
        "status": profile.status,
        "field_qualified": profile.is_field_qualified,
        "default_port": profile.default_port,
        "source": profile.source,
        "upstream_license": profile.upstream_license,
        "upstream_commit": profile.upstream_commit,
        "metrics": {
            name: asdict(spec)
            for name, spec in sorted(profile.metrics.items(), key=lambda item: item[0])
        },
        "vector_checks": checks,
        "vectors_pass": all(check["pass"] for check in checks),
    }


def _decode_summary(profile: InverterProfile, metric: str, raw: str) -> dict[str, Any]:
    registers = _parse_registers(raw)
    spec = profile.metric(metric)
    decoded = decode_metric_value(profile, metric, registers)
    return {
        "profile": profile.profile,
        "metric": metric,
        "raw_registers": registers,
        "decoded": decoded,
        "unit": spec.unit,
        "profile_status": profile.status,
        "field_qualified": profile.is_field_qualified,
    }


def _print_list(json_output: bool) -> int:
    names = list_bundled_profiles()
    if json_output:
        print(json.dumps({"profiles": names}, indent=2, sort_keys=True))
        return 0
    print("Bundled inverter profiles:")
    for name in names:
        profile = load_profile(name)
        print(f"- {profile.profile} ({profile.brand}, {profile.status})")
    return 0


def _print_profile(profile: InverterProfile, json_output: bool) -> int:
    summary = _profile_summary(profile)
    if json_output:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary["vectors_pass"] else 1

    print(f"Profile: {profile.profile}")
    print(f"Brand: {profile.brand or '-'}")
    print(f"Transport: {profile.transport}")
    print(f"Status: {profile.status}")
    print(f"Field qualified: {profile.is_field_qualified}")
    print(f"Metrics: {', '.join(sorted(profile.metrics))}")
    print("Vector checks:")
    for check in summary["vector_checks"]:
        status = "PASS" if check["pass"] else "FAIL"
        print(
            f"- {status} {check['metric']}: decoded={check['decoded']} "
            f"expected={check['expected']} delta={check['delta']} "
            f"tolerance={check['tolerance']}"
        )
    if not profile.is_field_qualified:
        print(
            "Note: profile is not field_qualified; readings are advisory and "
            "must not back physical action authority."
        )
    return 0 if summary["vectors_pass"] else 1


def _print_decode(summary: dict[str, Any], json_output: bool) -> int:
    if json_output:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    print(
        f"{summary['profile']}:{summary['metric']} "
        f"{summary['raw_registers']} -> {summary['decoded']} {summary['unit']}"
    )
    if not summary["field_qualified"]:
        print(
            "Note: profile is not field_qualified; decoded value is advisory "
            "until field evidence confirms this model/firmware/logger."
        )
    return 0


def _print_evidence_template(profile: InverterProfile) -> int:
    print(json.dumps(_evidence_template(profile), indent=2, sort_keys=True))
    return 0


def _print_evidence(summary: dict[str, Any], json_output: bool) -> int:
    if json_output:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary["evidence_pass"] else 1

    print(f"Evidence file: {summary['evidence_file']}")
    print(f"Profile: {summary['profile']} ({summary['profile_status']})")
    identity = summary["identity"]
    print(
        "Unit: "
        f"{identity['brand'] or '-'} {identity['model'] or '-'} "
        f"firmware={identity['firmware'] or '-'} "
        f"logger={identity['logger_serial'] or '-'}"
    )
    if not summary["identity_complete"]:
        missing = ", ".join(summary["missing_identity_fields"])
        print(f"FAIL identity: missing {missing}")
    else:
        print("PASS identity: brand/model/firmware/logger/timestamp present")

    print("Evidence samples:")
    for check in summary["sample_checks"]:
        status = "PASS" if check["pass"] else "FAIL"
        print(
            f"- {status} {check['metric']}: decoded={check['decoded']} "
            f"observed={check['observed_value']} delta={check['delta']} "
            f"tolerance={check['tolerance']} ground_truth={check['ground_truth'] or '-'}"
        )
    if summary["promotion_candidate"]:
        print(
            "Result: PASS - this bundle is a field-qualification evidence candidate. "
            "A maintainer must still review and update the profile in a separate PR."
        )
    elif summary["evidence_pass"]:
        print("Result: PASS - evidence agrees with an already field-qualified profile.")
    else:
        print("Result: FAIL - evidence is incomplete or outside tolerance.")
    print(f"Note: {summary['note']}")
    return 0 if summary["evidence_pass"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect and validate bundled Ori inverter profiles."
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List bundled inverter profiles.",
    )
    parser.add_argument(
        "--profile",
        help="Bundled profile name to inspect, for example deye_hybrid.",
    )
    parser.add_argument(
        "--decode",
        metavar="METRIC",
        help="Decode one metric from --raw registers using --profile.",
    )
    parser.add_argument(
        "--raw",
        help="Comma-separated uint16 registers, decimal or 0x-prefixed hex.",
    )
    parser.add_argument(
        "--evidence",
        metavar="PATH",
        help=(
            "Review an offline inverter evidence JSON bundle for --profile. "
            "This never contacts hardware or promotes profile status."
        ),
    )
    parser.add_argument(
        "--evidence-template",
        action="store_true",
        help=(
            "Emit a fill-in JSON evidence template for --profile. This never "
            "reviews evidence, contacts hardware, or promotes profile status."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.list:
            return _print_list(args.json)
        if not args.profile:
            parser.error("--profile is required unless --list is used")

        profile = load_profile(args.profile)
        if args.evidence_template:
            if args.evidence or args.decode or args.raw:
                parser.error(
                    "--evidence-template cannot be combined with --evidence, "
                    "--decode, or --raw"
                )
            return _print_evidence_template(profile)
        if args.evidence:
            return _print_evidence(
                _evidence_summary(profile, Path(args.evidence)),
                args.json,
            )
        if args.decode or args.raw:
            if not args.decode or not args.raw:
                parser.error("--decode and --raw must be provided together")
            return _print_decode(
                _decode_summary(profile, args.decode, args.raw),
                args.json,
            )
        return _print_profile(profile, args.json)
    except InverterProfileError as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}, indent=2, sort_keys=True))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
