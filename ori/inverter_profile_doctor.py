# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any

from ori.hal.inverter_profiles import (
    InverterProfile,
    InverterProfileError,
    decode_metric,
    list_bundled_profiles,
    load_profile,
)


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


def _vector_checks(profile: InverterProfile) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for vector in profile.vectors:
        decoded = decode_metric(profile, vector.metric, vector.raw_registers)
        delta = abs(decoded - vector.expected_value)
        checks.append(
            {
                "metric": vector.metric,
                "raw_registers": list(vector.raw_registers),
                "decoded": decoded,
                "expected": vector.expected_value,
                "tolerance": vector.tolerance,
                "pass": delta <= vector.tolerance,
                "ground_truth": vector.ground_truth,
            }
        )
    return checks


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
    decoded = decode_metric(profile, metric, registers)
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
            f"expected={check['expected']} tolerance={check['tolerance']}"
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
