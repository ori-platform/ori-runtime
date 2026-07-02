# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Data-driven inverter register profiles.

An inverter profile is data, not code. Each profile maps a brand/model's
Modbus register layout to Ori sensor metrics and carries golden decode vectors
so the mapping is provable in CI without owning the physical inverter.

This is the brand-agnostic primitive: adding support for a new inverter means
adding a validated profile YAML file, not writing a new adapter class. Transport
adapters such as SolarmanV5/Modbus read those profiles through the shared decode
path.

Qualification status ladder:

- experimental: decode is asserted but unproven; never authoritative.
- community_derived: decode matches a published/community register map and
  passes golden vectors, but has not been confirmed against a real unit. It is
  read-only and advisory.
- field_qualified: confirmed against one or more real units with independent
  ground-truth cross-checks such as an inverter screen, vendor app, or Ori
  PZEM/USB clamp. Only this status may ever back physical Tier B+ authority for
  that profile.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_PROFILE_DIR = Path(__file__).resolve().parent

_VALID_TRANSPORTS = frozenset({"solarman_v5", "modbus_serial", "modbus_tcp"})
_VALID_STATUSES = frozenset({"experimental", "community_derived", "field_qualified"})
_VALID_VALUE_TYPES = frozenset({"numeric", "enum", "string"})
_VALID_WORD_ORDERS = frozenset({"big", "little"})


class ProfileStatus:
    """Qualification status values for inverter profiles."""

    EXPERIMENTAL = "experimental"
    COMMUNITY_DERIVED = "community_derived"
    FIELD_QUALIFIED = "field_qualified"


class InverterProfileError(Exception):
    """Raised when an inverter profile is missing, malformed, or unsupported."""


@dataclass(frozen=True)
class MetricSpec:
    """How to decode one metric from one or more Modbus registers."""

    register: int
    count: int
    scale: float
    unit: str
    signed: bool = False
    offset: float = 0.0
    mask: int | None = None
    word_order: str = "big"
    value_type: str = "numeric"
    lookup: dict[int, str] = field(default_factory=dict)


@dataclass(frozen=True)
class GoldenVector:
    """A raw-register fixture and the engineering value it must decode to."""

    metric: str
    raw_registers: tuple[int, ...]
    expected_value: float | str
    tolerance: float
    ground_truth: str = ""


@dataclass(frozen=True)
class InverterProfile:
    """Validated inverter profile loaded from bundled YAML."""

    profile: str
    brand: str
    transport: str
    status: str
    default_port: int
    metrics: dict[str, MetricSpec]
    vectors: tuple[GoldenVector, ...]
    models: tuple[str, ...] = ()
    firmware_verified: tuple[str, ...] = ()
    source: str = ""
    upstream_license: str = ""
    upstream_commit: str = ""
    notes: str = ""

    def metric(self, name: str) -> MetricSpec:
        try:
            return self.metrics[name]
        except KeyError as exc:
            raise InverterProfileError(
                f"profile {self.profile!r} has no metric {name!r}; "
                f"available: {sorted(self.metrics)}"
            ) from exc

    @property
    def is_field_qualified(self) -> bool:
        return self.status == ProfileStatus.FIELD_QUALIFIED


def decode_raw_registers(
    registers: Sequence[int],
    *,
    signed: bool,
    word_order: str = "big",
    mask: int | None = None,
) -> int:
    """Decode uint16 registers as a concatenated integer.

    Word order is explicit because several inverter maps use paired registers.
    The default is big-endian register order, matching the existing Growatt
    adapter. A mask applies before two's-complement signed decoding.
    """

    regs = [int(register) & 0xFFFF for register in registers]
    if not regs:
        raise InverterProfileError("empty register payload")
    if word_order not in _VALID_WORD_ORDERS:
        raise InverterProfileError(
            f"unsupported word_order {word_order!r}; expected {sorted(_VALID_WORD_ORDERS)}"
        )

    ordered = regs if word_order == "big" else list(reversed(regs))
    value = 0
    for register in ordered:
        value = (value << 16) | register

    width_bits = 16 * len(ordered)
    if mask is not None:
        value &= int(mask)
        width_bits = max(1, int(mask).bit_length())

    if signed and value >= (1 << (width_bits - 1)):
        value -= 1 << width_bits
    return value


def decode_string_registers(
    registers: Sequence[int],
    *,
    word_order: str = "big",
) -> str:
    """Decode uint16 registers as a null-trimmed big-endian ASCII/UTF-8 string."""

    regs = [int(register) & 0xFFFF for register in registers]
    if not regs:
        raise InverterProfileError("empty register payload")
    if word_order not in _VALID_WORD_ORDERS:
        raise InverterProfileError(
            f"unsupported word_order {word_order!r}; expected {sorted(_VALID_WORD_ORDERS)}"
        )

    ordered = regs if word_order == "big" else list(reversed(regs))
    raw = bytearray()
    for register in ordered:
        raw.extend(((register >> 8) & 0xFF, register & 0xFF))
    return bytes(raw).rstrip(b"\x00").decode("utf-8", errors="replace").strip()


def decode_metric_value(
    profile: InverterProfile,
    metric_name: str,
    raw_registers: Sequence[int],
) -> float | str:
    """Decode raw registers into the configured engineering value type."""

    spec = profile.metric(metric_name)
    if len(raw_registers) < spec.count:
        raise InverterProfileError(
            f"profile {profile.profile!r} metric {metric_name!r}: expected "
            f"{spec.count} registers, got {len(raw_registers)}"
        )

    if spec.value_type == "string":
        return decode_string_registers(
            raw_registers[: spec.count],
            word_order=spec.word_order,
        )

    raw = decode_raw_registers(
        raw_registers[: spec.count],
        signed=spec.signed,
        word_order=spec.word_order,
        mask=spec.mask,
    )
    if spec.value_type == "enum":
        try:
            return spec.lookup[raw]
        except KeyError as exc:
            raise InverterProfileError(
                f"profile {profile.profile!r} metric {metric_name!r}: "
                f"raw enum value {raw} is not in lookup"
            ) from exc
    return round((float(raw) * spec.scale) + spec.offset, 4)


def decode_metric(
    profile: InverterProfile,
    metric_name: str,
    raw_registers: Sequence[int],
) -> float:
    """Decode raw registers into a scaled engineering value for *metric_name*."""

    value = decode_metric_value(profile, metric_name, raw_registers)
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise InverterProfileError(
            f"profile {profile.profile!r} metric {metric_name!r} has "
            f"value_type={profile.metric(metric_name).value_type!r}; "
            "decode_metric() returns numeric values only"
        )
    return float(value)


def _parse_lookup(
    raw_lookup: object, metric_name: str, profile_name: str
) -> dict[int, str]:
    if raw_lookup in (None, ""):
        return {}
    if not isinstance(raw_lookup, dict):
        raise InverterProfileError(
            f"profile {profile_name!r} metric {metric_name!r}: lookup must be a map"
        )

    lookup: dict[int, str] = {}
    for raw_key, raw_value in raw_lookup.items():
        if isinstance(raw_key, bool):
            raise InverterProfileError(
                f"profile {profile_name!r} metric {metric_name!r}: "
                "lookup keys must be integers"
            )
        try:
            key = int(raw_key)
        except (TypeError, ValueError) as exc:
            raise InverterProfileError(
                f"profile {profile_name!r} metric {metric_name!r}: "
                f"lookup key {raw_key!r} is not an integer"
            ) from exc
        if key < 0:
            raise InverterProfileError(
                f"profile {profile_name!r} metric {metric_name!r}: "
                "lookup keys must be >= 0"
            )
        value = str(raw_value).strip()
        if not value:
            raise InverterProfileError(
                f"profile {profile_name!r} metric {metric_name!r}: "
                f"lookup value for {key} is empty"
            )
        lookup[key] = value
    if not lookup:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {metric_name!r}: lookup cannot be empty"
        )
    return lookup


def _parse_metric(name: str, data: object, profile_name: str) -> MetricSpec:
    if not isinstance(data, dict):
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r} must be a mapping"
        )
    try:
        register = int(data["register"])
        count = int(data.get("count", 1))
        scale = float(data.get("scale", 1.0))
        unit = str(data["unit"]).strip()
        signed = bool(data.get("signed", False))
        offset = float(data.get("offset", 0.0))
        word_order = str(data.get("word_order", "big")).strip()
        value_type = str(data.get("value_type", "numeric")).strip()
        raw_mask = data.get("mask")
        mask = None if raw_mask is None else int(raw_mask)
        lookup = _parse_lookup(data.get("lookup"), name, profile_name)
    except (KeyError, TypeError, ValueError) as exc:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: invalid spec ({exc})"
        ) from exc

    if register < 0:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: register must be >= 0"
        )
    max_count = 32 if value_type == "string" else 4
    if count < 1 or count > max_count:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: count must be 1..{max_count}"
        )
    if not unit:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: unit is required"
        )
    if value_type not in _VALID_VALUE_TYPES:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: value_type must be one "
            f"of {sorted(_VALID_VALUE_TYPES)}"
        )
    if word_order not in _VALID_WORD_ORDERS:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: word_order must be one "
            f"of {sorted(_VALID_WORD_ORDERS)}"
        )
    if mask is not None and mask < 0:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: mask must be >= 0"
        )
    if value_type == "numeric" and lookup:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: numeric metrics cannot declare lookup"
        )
    if value_type == "enum" and not lookup:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: enum metrics require lookup"
        )
    if value_type == "string":
        if lookup:
            raise InverterProfileError(
                f"profile {profile_name!r} metric {name!r}: string metrics cannot declare lookup"
            )
        if signed:
            raise InverterProfileError(
                f"profile {profile_name!r} metric {name!r}: string metrics cannot be signed"
            )
        if mask is not None:
            raise InverterProfileError(
                f"profile {profile_name!r} metric {name!r}: string metrics cannot declare mask"
            )
        if scale != 1.0 or offset != 0.0:
            raise InverterProfileError(
                f"profile {profile_name!r} metric {name!r}: string metrics cannot scale or offset"
            )

    return MetricSpec(
        register=register,
        count=count,
        scale=scale,
        unit=unit,
        signed=signed,
        offset=offset,
        mask=mask,
        word_order=word_order,
        value_type=value_type,
        lookup=lookup,
    )


def _parse_vector(data: object, profile_name: str) -> GoldenVector:
    if not isinstance(data, dict):
        raise InverterProfileError(
            f"profile {profile_name!r}: each qualification vector must be a mapping"
        )
    try:
        metric = str(data["metric"]).strip()
        raw_registers = tuple(int(v) for v in data["raw_registers"])
        raw_expected_value = data["expected_value"]
        if raw_expected_value is None:
            raise ValueError("expected_value cannot be null")
        if isinstance(raw_expected_value, bool):
            raise ValueError("expected_value cannot be boolean")
        if isinstance(raw_expected_value, int | float):
            expected_value: float | str = float(raw_expected_value)
        else:
            expected_value = str(raw_expected_value).strip()
        tolerance = float(data.get("tolerance", 0.0))
        ground_truth = str(data.get("ground_truth", "")).strip()
    except (KeyError, TypeError, ValueError) as exc:
        raise InverterProfileError(
            f"profile {profile_name!r}: invalid qualification vector ({exc})"
        ) from exc
    if not metric:
        raise InverterProfileError(
            f"profile {profile_name!r}: qualification vector metric is required"
        )
    if expected_value == "":
        raise InverterProfileError(
            f"profile {profile_name!r}: vector for {metric!r} has empty expected_value"
        )
    if not raw_registers:
        raise InverterProfileError(
            f"profile {profile_name!r}: vector for {metric!r} has no raw_registers"
        )
    if tolerance < 0:
        raise InverterProfileError(
            f"profile {profile_name!r}: vector tolerance must be >= 0"
        )
    return GoldenVector(
        metric=metric,
        raw_registers=raw_registers,
        expected_value=expected_value,
        tolerance=tolerance,
        ground_truth=ground_truth,
    )


def load_profile_data(
    data: dict[str, Any], *, profile_name: str = ""
) -> InverterProfile:
    """Validate a profile mapping and return an :class:`InverterProfile`."""

    if not isinstance(data, dict):
        raise InverterProfileError("profile must be a mapping")

    name = str(data.get("profile", profile_name) or profile_name).strip()
    if not name:
        raise InverterProfileError("profile is missing required field 'profile'")

    transport = str(data.get("transport", "")).strip()
    if transport not in _VALID_TRANSPORTS:
        raise InverterProfileError(
            f"profile {name!r}: transport must be one of "
            f"{sorted(_VALID_TRANSPORTS)}, got {transport!r}"
        )

    status = str(data.get("status", "")).strip()
    if status not in _VALID_STATUSES:
        raise InverterProfileError(
            f"profile {name!r}: status must be one of {sorted(_VALID_STATUSES)}, "
            f"got {status!r}"
        )

    raw_metrics = data.get("metrics")
    if not isinstance(raw_metrics, dict) or not raw_metrics:
        raise InverterProfileError(
            f"profile {name!r}: 'metrics' must be a non-empty map"
        )
    metrics = {str(k): _parse_metric(str(k), v, name) for k, v in raw_metrics.items()}

    raw_vectors = data.get("qualification_vectors")
    if not isinstance(raw_vectors, list) or not raw_vectors:
        raise InverterProfileError(
            f"profile {name!r}: 'qualification_vectors' must be a non-empty list"
        )
    vectors = tuple(_parse_vector(vector, name) for vector in raw_vectors)

    covered = {vector.metric for vector in vectors}
    missing = sorted(set(metrics) - covered)
    if missing:
        raise InverterProfileError(
            f"profile {name!r}: metrics without qualification vectors: {missing}"
        )
    unknown = sorted(covered - set(metrics))
    if unknown:
        raise InverterProfileError(
            f"profile {name!r}: vectors reference unknown metrics: {unknown}"
        )

    for vector in vectors:
        spec = metrics[vector.metric]
        if len(vector.raw_registers) < spec.count:
            raise InverterProfileError(
                f"profile {name!r}: vector for {vector.metric!r} has "
                f"{len(vector.raw_registers)} registers; expected {spec.count}"
            )
        if spec.value_type == "numeric" and not isinstance(
            vector.expected_value, int | float
        ):
            raise InverterProfileError(
                f"profile {name!r}: numeric vector for {vector.metric!r} "
                "must use a numeric expected_value"
            )
        if spec.value_type != "numeric" and not isinstance(vector.expected_value, str):
            raise InverterProfileError(
                f"profile {name!r}: {spec.value_type} vector for {vector.metric!r} "
                "must use a string expected_value"
            )

    firmware_verified = tuple(
        str(item).strip()
        for item in data.get("firmware_verified", [])
        if str(item).strip()
    )
    if status == ProfileStatus.FIELD_QUALIFIED and not firmware_verified:
        raise InverterProfileError(
            f"profile {name!r}: field_qualified profiles must list at least "
            "one verified firmware in 'firmware_verified'"
        )

    try:
        default_port = int(data.get("default_port", 8899))
    except (TypeError, ValueError) as exc:
        raise InverterProfileError(
            f"profile {name!r}: default_port must be an integer"
        ) from exc
    if default_port <= 0:
        raise InverterProfileError(
            f"profile {name!r}: default_port must be greater than zero"
        )

    return InverterProfile(
        profile=name,
        brand=str(data.get("brand", "")).strip(),
        transport=transport,
        status=status,
        default_port=default_port,
        metrics=metrics,
        vectors=vectors,
        models=tuple(str(m).strip() for m in data.get("models", []) if str(m).strip()),
        firmware_verified=firmware_verified,
        source=str(data.get("source", "")).strip(),
        upstream_license=str(data.get("upstream_license", "")).strip(),
        upstream_commit=str(data.get("upstream_commit", "")).strip(),
        notes=str(data.get("notes", "")).strip(),
    )


def load_profile(name: str) -> InverterProfile:
    """Load and validate a bundled inverter profile by name."""

    safe = str(name or "").strip()
    if not safe or "/" in safe or "\\" in safe or safe.startswith("."):
        raise InverterProfileError(f"invalid profile name: {name!r}")

    path = _PROFILE_DIR / f"{safe}.yaml"
    if not path.is_file():
        raise InverterProfileError(
            f"unknown inverter profile {safe!r}; available: {list_bundled_profiles()}"
        )
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise InverterProfileError(
            f"profile {safe!r}: YAML parse error: {exc}"
        ) from exc
    return load_profile_data(data, profile_name=safe)


def list_bundled_profiles() -> list[str]:
    """Return bundled profile names without the `.yaml` suffix."""

    return sorted(path.stem for path in _PROFILE_DIR.glob("*.yaml"))


__all__ = [
    "GoldenVector",
    "InverterProfile",
    "InverterProfileError",
    "MetricSpec",
    "ProfileStatus",
    "decode_metric",
    "decode_metric_value",
    "decode_raw_registers",
    "decode_string_registers",
    "list_bundled_profiles",
    "load_profile",
    "load_profile_data",
]
