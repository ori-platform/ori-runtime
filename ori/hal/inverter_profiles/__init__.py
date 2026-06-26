# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Data-driven inverter register profiles.

Profiles turn inverter support into validated data: a metric name maps to a
register layout, scaling rule, and qualification vectors. The runtime adapter
and the test harness use the same decode functions so CI protects the exact
production decode path.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_PROFILE_DIR = Path(__file__).resolve().parent

_VALID_TRANSPORTS = frozenset({"solarman_v5", "modbus_serial", "modbus_tcp"})
_VALID_STATUSES = frozenset({"experimental", "community_derived", "field_qualified"})
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


@dataclass(frozen=True)
class GoldenVector:
    """A raw-register fixture and the engineering value it must decode to."""

    metric: str
    raw_registers: tuple[int, ...]
    expected_value: float
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


def decode_metric(
    profile: InverterProfile,
    metric_name: str,
    raw_registers: Sequence[int],
) -> float:
    """Decode raw registers into a scaled engineering value for *metric_name*."""

    spec = profile.metric(metric_name)
    if len(raw_registers) < spec.count:
        raise InverterProfileError(
            f"profile {profile.profile!r} metric {metric_name!r}: expected "
            f"{spec.count} registers, got {len(raw_registers)}"
        )
    raw = decode_raw_registers(
        raw_registers[: spec.count],
        signed=spec.signed,
        word_order=spec.word_order,
        mask=spec.mask,
    )
    return round((float(raw) * spec.scale) + spec.offset, 4)


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
        raw_mask = data.get("mask")
        mask = None if raw_mask is None else int(raw_mask)
    except (KeyError, TypeError, ValueError) as exc:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: invalid spec ({exc})"
        ) from exc

    if register < 0:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: register must be >= 0"
        )
    if count < 1 or count > 4:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: count must be 1..4"
        )
    if not unit:
        raise InverterProfileError(
            f"profile {profile_name!r} metric {name!r}: unit is required"
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

    return MetricSpec(
        register=register,
        count=count,
        scale=scale,
        unit=unit,
        signed=signed,
        offset=offset,
        mask=mask,
        word_order=word_order,
    )


def _parse_vector(data: object, profile_name: str) -> GoldenVector:
    if not isinstance(data, dict):
        raise InverterProfileError(
            f"profile {profile_name!r}: each qualification vector must be a mapping"
        )
    try:
        metric = str(data["metric"]).strip()
        raw_registers = tuple(int(v) for v in data["raw_registers"])
        expected_value = float(data["expected_value"])
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
    "decode_raw_registers",
    "list_bundled_profiles",
    "load_profile",
    "load_profile_data",
]
