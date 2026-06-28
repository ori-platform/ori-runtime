# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Prosumer energy ledger primitives for operational advice.

The fast-loop ledger is an operational estimate derived from runtime telemetry.
It is useful for consume/store/export advice and product dashboards, but it is
not the billing ledger. Monthly DisCo statements from revenue-grade dual-
register meters remain the settlement source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

PROSUMER_METER_OF_RECORD_BOUNDARY = (
    "Ori fast-loop ledger values are operational estimates. DisCo revenue-grade "
    "dual-register meter statements remain settlement and billing truth."
)


class ProsumerLedgerError(Exception):
    """Raised when prosumer ledger policy data is malformed."""


@dataclass(frozen=True)
class FastLoopInterval:
    """Bounded time interval used for fast-loop kWh estimates."""

    hours: float
    interval_ms: int
    capped: bool
    usable: bool
    reason: str


@dataclass(frozen=True)
class SettlementSource:
    """Where a settlement statement came from."""

    source_type: str
    reference: str
    retrieved_at: str = ""


@dataclass(frozen=True)
class SettlementStatement:
    """Validated monthly DisCo settlement statement metadata.

    These fields are for reconciliation and reporting. They do not override
    runtime telemetry, and runtime telemetry does not override them.
    """

    statement_id: str
    disco: str
    period_start: str
    period_end: str
    import_kwh: float
    export_kwh: float
    import_value: float
    export_credit_value: float
    net_value: float
    currency: str
    source: SettlementSource
    notes: str = ""

    @property
    def meter_of_record_boundary(self) -> str:
        return PROSUMER_METER_OF_RECORD_BOUNDARY


_VALID_SETTLEMENT_SOURCE_TYPES = frozenset(
    {"disco_statement", "customer_bill", "operator_reconciled"}
)


def _text(data: dict[str, Any], key: str, *, required: bool = True) -> str:
    value = data.get(key)
    if value is None or isinstance(value, bool):
        value = ""
    text = str(value).strip()
    if required and not text:
        raise ProsumerLedgerError(f"settlement statement {key!r} is required")
    return text


def _number(data: dict[str, Any], key: str, *, minimum: float | None = None) -> float:
    value = data.get(key)
    if value is None or isinstance(value, bool):
        raise ProsumerLedgerError(f"settlement statement {key!r} must be numeric")
    try:
        amount = float(value)
    except (TypeError, ValueError) as exc:
        raise ProsumerLedgerError(
            f"settlement statement {key!r} must be numeric"
        ) from exc
    if minimum is not None and amount < minimum:
        raise ProsumerLedgerError(
            f"settlement statement {key!r} must be >= {minimum:g}, got {amount:g}"
        )
    return amount


def _date_text(data: dict[str, Any], key: str, *, required: bool = True) -> str:
    text = _text(data, key, required=required)
    if not text:
        return ""
    try:
        date.fromisoformat(text)
    except ValueError as exc:
        raise ProsumerLedgerError(
            f"settlement statement {key!r} must use YYYY-MM-DD format"
        ) from exc
    return text


def _source(data: dict[str, Any]) -> SettlementSource:
    raw = data.get("source")
    if not isinstance(raw, dict):
        raise ProsumerLedgerError("settlement statement 'source' must be an object")
    source_type = _text(raw, "type")
    if source_type not in _VALID_SETTLEMENT_SOURCE_TYPES:
        raise ProsumerLedgerError(
            "settlement statement source.type must be one of "
            f"{sorted(_VALID_SETTLEMENT_SOURCE_TYPES)}, got {source_type!r}"
        )
    return SettlementSource(
        source_type=source_type,
        reference=_text(raw, "reference"),
        retrieved_at=_date_text(raw, "retrieved_at", required=False),
    )


def bounded_fast_loop_interval(
    previous_timestamp_ms: int | None,
    current_timestamp_ms: int,
    *,
    max_interval_seconds: float,
) -> FastLoopInterval:
    """Return a safe interval for watt-to-kWh conversion.

    First samples, backward clocks, and non-positive max intervals produce a
    zero-hour unusable interval. Long gaps are capped so a device that was
    offline for hours does not fabricate a large energy delta from one stale
    power snapshot.
    """

    current = int(current_timestamp_ms)
    if previous_timestamp_ms is None:
        return FastLoopInterval(0.0, 0, False, False, "first_sample")
    previous = int(previous_timestamp_ms)
    if current <= previous:
        return FastLoopInterval(0.0, 0, False, False, "non_monotonic_timestamp")
    max_ms = int(max(0.0, float(max_interval_seconds)) * 1000)
    if max_ms <= 0:
        return FastLoopInterval(0.0, 0, False, False, "disabled")
    raw_ms = current - previous
    interval_ms = min(raw_ms, max_ms)
    return FastLoopInterval(
        hours=interval_ms / 3_600_000.0,
        interval_ms=interval_ms,
        capped=raw_ms > max_ms,
        usable=True,
        reason="capped" if raw_ms > max_ms else "ok",
    )


def kwh_from_watts(watts: float, hours: float) -> float:
    """Convert an instantaneous watt estimate over hours into kWh."""

    return (max(0.0, float(watts)) / 1000.0) * max(0.0, float(hours))


def load_settlement_statement_data(data: dict[str, Any]) -> SettlementStatement:
    """Validate a monthly settlement statement supplied by provisioning/cloud."""

    if not isinstance(data, dict):
        raise ProsumerLedgerError("settlement statement must be an object")

    period_start = _date_text(data, "period_start")
    period_end = _date_text(data, "period_end")
    if period_end < period_start:
        raise ProsumerLedgerError(
            "settlement statement 'period_end' must not be before 'period_start'"
        )

    return SettlementStatement(
        statement_id=_text(data, "statement_id"),
        disco=_text(data, "disco"),
        period_start=period_start,
        period_end=period_end,
        import_kwh=_number(data, "import_kwh", minimum=0.0),
        export_kwh=_number(data, "export_kwh", minimum=0.0),
        import_value=_number(data, "import_value", minimum=0.0),
        export_credit_value=_number(data, "export_credit_value", minimum=0.0),
        net_value=_number(data, "net_value"),
        currency=_text(data, "currency"),
        source=_source(data),
        notes=_text(data, "notes", required=False),
    )
