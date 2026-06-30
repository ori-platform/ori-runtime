# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Versioned tariff/export-credit policy profiles for advisory energy logic.

Tariff profiles are operational decision inputs, not billing records. Ori uses
them to decide whether a Tier A consume/store/export advisory is worth sending.
The DisCo revenue-grade import/export meter and DisCo monthly statement remain
the regulated billing source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

_VALID_STATUSES = frozenset(
    {"draft", "operator_provided", "published_order", "field_verified"}
)
_ADVISORY_STATUSES = frozenset(
    {"operator_provided", "published_order", "field_verified"}
)
_VALID_SOURCE_TYPES = frozenset(
    {"operator_estimate", "disco_statement", "tariff_order", "regulatory_notice"}
)
METER_OF_RECORD_BOUNDARY = (
    "Ori tariff profiles are operational estimates for advisory logic. "
    "DisCo revenue-grade dual-register meter statements remain billing truth."
)


class TariffProfileError(Exception):
    """Raised when a tariff profile is missing, malformed, or unsafe to use."""


class TariffStatus:
    """Qualification status values for tariff/export-credit profiles."""

    DRAFT = "draft"
    OPERATOR_PROVIDED = "operator_provided"
    PUBLISHED_ORDER = "published_order"
    FIELD_VERIFIED = "field_verified"


@dataclass(frozen=True)
class TariffSource:
    """Where the tariff/export-credit values came from."""

    source_type: str
    reference: str
    retrieved_at: str = ""


@dataclass(frozen=True)
class TariffProfile:
    """Validated tariff/export-credit policy used by advisory skills."""

    profile: str
    version: str
    status: str
    country: str
    currency: str
    disco: str
    effective_from: str
    import_tariff_per_kwh: float
    export_credit_per_kwh: float
    export_credit_formula: str
    source: TariffSource
    effective_until: str = ""
    fixed_charges_per_month: float = 0.0
    interconnection_charges_per_kwh: float = 0.0
    notes: str = ""

    @property
    def advisory_qualified(self) -> bool:
        """Whether this profile may drive Tier A advisory recommendations."""

        return self.status in _ADVISORY_STATUSES

    @property
    def meter_of_record_boundary(self) -> str:
        """Human-readable billing boundary for UI/reporting surfaces."""

        return METER_OF_RECORD_BOUNDARY


def _text(data: dict[str, Any], key: str, *, required: bool = True) -> str:
    value = data.get(key)
    if value is None or isinstance(value, bool):
        value = ""
    text = str(value).strip()
    if required and not text:
        raise TariffProfileError(f"tariff profile {key!r} is required")
    return text


def _money(data: dict[str, Any], key: str, *, minimum: float) -> float:
    value = data.get(key)
    if value is None or isinstance(value, bool):
        raise TariffProfileError(f"tariff profile {key!r} must be numeric")
    try:
        amount = float(value)
    except (TypeError, ValueError) as exc:
        raise TariffProfileError(f"tariff profile {key!r} must be numeric") from exc
    if amount < minimum:
        raise TariffProfileError(
            f"tariff profile {key!r} must be >= {minimum:g}, got {amount:g}"
        )
    return amount


def _date_text(data: dict[str, Any], key: str, *, required: bool = True) -> str:
    text = _text(data, key, required=required)
    if not text:
        return ""
    try:
        date.fromisoformat(text)
    except ValueError as exc:
        raise TariffProfileError(
            f"tariff profile {key!r} must use YYYY-MM-DD format"
        ) from exc
    return text


def _source(data: dict[str, Any]) -> TariffSource:
    raw = data.get("source")
    if not isinstance(raw, dict):
        raise TariffProfileError("tariff profile 'source' must be an object")
    source_type = _text(raw, "type")
    if source_type not in _VALID_SOURCE_TYPES:
        raise TariffProfileError(
            "tariff profile source.type must be one of "
            f"{sorted(_VALID_SOURCE_TYPES)}, got {source_type!r}"
        )
    return TariffSource(
        source_type=source_type,
        reference=_text(raw, "reference"),
        retrieved_at=_date_text(raw, "retrieved_at", required=False),
    )


def load_tariff_profile_data(data: dict[str, Any]) -> TariffProfile:
    """Validate tariff profile data from config/backend provisioning.

    The function accepts plain dictionaries so product provisioning can generate signed
    runtime configs without requiring this package to read a database or contact
    a network service. Validation is deliberately strict because these values
    shape economic recommendations.
    """

    if not isinstance(data, dict):
        raise TariffProfileError("tariff profile must be an object")

    status = _text(data, "status")
    if status not in _VALID_STATUSES:
        raise TariffProfileError(
            f"tariff profile status must be one of {sorted(_VALID_STATUSES)}, "
            f"got {status!r}"
        )

    effective_from = _date_text(data, "effective_from")
    effective_until = _date_text(data, "effective_until", required=False)
    if effective_until and effective_until < effective_from:
        raise TariffProfileError(
            "tariff profile 'effective_until' must not be before 'effective_from'"
        )

    source = _source(data)

    return TariffProfile(
        profile=_text(data, "profile"),
        version=_text(data, "version"),
        status=status,
        country=_text(data, "country"),
        currency=_text(data, "currency"),
        disco=_text(data, "disco"),
        effective_from=effective_from,
        effective_until=effective_until,
        import_tariff_per_kwh=_money(data, "import_tariff_per_kwh", minimum=0.0001),
        export_credit_per_kwh=_money(data, "export_credit_per_kwh", minimum=0.0),
        export_credit_formula=_text(data, "export_credit_formula"),
        fixed_charges_per_month=_money(data, "fixed_charges_per_month", minimum=0.0),
        interconnection_charges_per_kwh=_money(
            data, "interconnection_charges_per_kwh", minimum=0.0
        ),
        source=source,
        notes=_text(data, "notes", required=False),
    )
