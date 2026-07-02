# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""NERC net-billing compliance tracking primitives for advisory logic.

This module validates a site-level compliance snapshot supplied by
product provisioning. It does not contact DisCos, NERC, NEMSA, or any cloud
service, and it does not make Ori the regulatory source of truth. The runtime
uses this data only to surface Tier A operator attention when a required
registration, certificate, export-cap value, monthly statement, or credit risk
needs review.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

NET_BILLING_BOUNDARY = (
    "Ori tracks operator-supplied net-billing compliance context for advice "
    "and reconciliation. DisCo, NERC, and NEMSA records remain authoritative."
)

_VALID_PROFILE_STATUSES = frozenset({"draft", "operator_provided", "verified"})
_TRACKING_STATUSES = frozenset({"operator_provided", "verified"})
_VALID_SOURCE_TYPES = frozenset(
    {"operator_record", "disco_record", "nerc_record", "nemsa_record"}
)
_VALID_STEP_STATUSES = frozenset(
    {"not_started", "submitted", "approved", "rejected", "expired"}
)
_VALID_INSPECTION_STATUSES = frozenset(
    {"not_started", "scheduled", "submitted", "passed", "failed", "expired"}
)
_VALID_STATEMENT_STATUSES = frozenset(
    {"not_required", "missing", "uploaded", "reconciled"}
)


class NetBillingComplianceError(Exception):
    """Raised when net-billing compliance data is malformed."""


@dataclass(frozen=True)
class ComplianceSource:
    """Where the compliance snapshot came from."""

    source_type: str
    reference: str
    retrieved_at: str = ""


@dataclass(frozen=True)
class ComplianceStep:
    """One regulatory workflow step supplied by provisioning/backend."""

    status: str
    reference: str = ""
    submitted_at: str = ""
    due_by: str = ""
    completed_at: str = ""
    certificate_id: str = ""


@dataclass(frozen=True)
class StatementTracking:
    """Monthly statement/reconciliation tracking fields."""

    status: str
    required: bool
    expected_statement_id: str = ""
    period_start: str = ""
    period_end: str = ""
    due_by: str = ""
    reference: str = ""


@dataclass(frozen=True)
class CreditCarryForward:
    """Credit carry-forward values supplied by the billing/reconciliation layer."""

    value: float
    currency: str
    kwh: float = 0.0
    as_of: str = ""


@dataclass(frozen=True)
class NetBillingComplianceProfile:
    """Validated site-level net-billing compliance profile."""

    profile: str
    version: str
    status: str
    country: str
    disco: str
    source: ComplianceSource
    disco_feasibility: ComplianceStep
    nerc_registration: ComplianceStep
    nemsa_inspection: ComplianceStep
    statement_tracking: StatementTracking
    credit_carry_forward: CreditCarryForward
    export_cap_watts: float = 0.0
    export_cap_reference: str = ""
    site_relocation_planned: bool = False
    relocation_effective_date: str = ""
    notes: str = ""

    @property
    def tracking_qualified(self) -> bool:
        return self.status in _TRACKING_STATUSES

    @property
    def boundary(self) -> str:
        return NET_BILLING_BOUNDARY


@dataclass(frozen=True)
class NetBillingComplianceEvaluation:
    """Computed attention state for a validated compliance profile."""

    attention_required: bool
    attention_codes: tuple[str, ...]
    attention_summary: str
    export_cap_matches_runtime: bool


def _text(data: dict[str, Any], key: str, *, required: bool = True) -> str:
    value = data.get(key)
    if value is None or isinstance(value, bool):
        value = ""
    text = str(value).strip()
    if required and not text:
        raise NetBillingComplianceError(f"net-billing {key!r} is required")
    return text


def _number(data: dict[str, Any], key: str, *, minimum: float) -> float:
    value = data.get(key)
    if value is None or isinstance(value, bool):
        raise NetBillingComplianceError(f"net-billing {key!r} must be numeric")
    try:
        amount = float(value)
    except (TypeError, ValueError) as exc:
        raise NetBillingComplianceError(f"net-billing {key!r} must be numeric") from exc
    if amount < minimum:
        raise NetBillingComplianceError(
            f"net-billing {key!r} must be >= {minimum:g}, got {amount:g}"
        )
    return amount


def _bool(data: dict[str, Any], key: str, *, default: bool = False) -> bool:
    value = data.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no", ""}:
            return False
    raise NetBillingComplianceError(f"net-billing {key!r} must be boolean")


def _date_text(data: dict[str, Any], key: str, *, required: bool = True) -> str:
    text = _text(data, key, required=required)
    if not text:
        return ""
    try:
        date.fromisoformat(text)
    except ValueError as exc:
        raise NetBillingComplianceError(
            f"net-billing {key!r} must use YYYY-MM-DD format"
        ) from exc
    return text


def _source(data: dict[str, Any]) -> ComplianceSource:
    raw = data.get("source")
    if not isinstance(raw, dict):
        raise NetBillingComplianceError("net-billing 'source' must be an object")
    source_type = _text(raw, "type")
    if source_type not in _VALID_SOURCE_TYPES:
        raise NetBillingComplianceError(
            "net-billing source.type must be one of "
            f"{sorted(_VALID_SOURCE_TYPES)}, got {source_type!r}"
        )
    return ComplianceSource(
        source_type=source_type,
        reference=_text(raw, "reference"),
        retrieved_at=_date_text(raw, "retrieved_at", required=False),
    )


def _step(
    data: dict[str, Any],
    key: str,
    *,
    valid_statuses: frozenset[str],
) -> ComplianceStep:
    raw = data.get(key)
    if not isinstance(raw, dict):
        raise NetBillingComplianceError(f"net-billing {key!r} must be an object")
    status = _text(raw, "status")
    if status not in valid_statuses:
        raise NetBillingComplianceError(
            f"net-billing {key}.status must be one of {sorted(valid_statuses)}, "
            f"got {status!r}"
        )
    return ComplianceStep(
        status=status,
        reference=_text(raw, "reference", required=False),
        submitted_at=_date_text(raw, "submitted_at", required=False),
        due_by=_date_text(raw, "due_by", required=False),
        completed_at=_date_text(raw, "completed_at", required=False),
        certificate_id=_text(raw, "certificate_id", required=False),
    )


def _statement_tracking(data: dict[str, Any]) -> StatementTracking:
    raw = data.get("monthly_statement")
    if not isinstance(raw, dict):
        raise NetBillingComplianceError(
            "net-billing 'monthly_statement' must be an object"
        )
    status = _text(raw, "status")
    if status not in _VALID_STATEMENT_STATUSES:
        raise NetBillingComplianceError(
            "net-billing monthly_statement.status must be one of "
            f"{sorted(_VALID_STATEMENT_STATUSES)}, got {status!r}"
        )
    period_start = _date_text(raw, "period_start", required=False)
    period_end = _date_text(raw, "period_end", required=False)
    if period_start and period_end and period_end < period_start:
        raise NetBillingComplianceError(
            "net-billing monthly_statement.period_end must not be before period_start"
        )
    return StatementTracking(
        status=status,
        required=_bool(raw, "required", default=False),
        expected_statement_id=_text(raw, "expected_statement_id", required=False),
        period_start=period_start,
        period_end=period_end,
        due_by=_date_text(raw, "due_by", required=False),
        reference=_text(raw, "reference", required=False),
    )


def _credit(data: dict[str, Any]) -> CreditCarryForward:
    raw = data.get("credit_carry_forward")
    if not isinstance(raw, dict):
        raise NetBillingComplianceError(
            "net-billing 'credit_carry_forward' must be an object"
        )
    try:
        return CreditCarryForward(
            value=_number(raw, "value", minimum=0.0),
            currency=_text(raw, "currency"),
            kwh=_number(raw, "kwh", minimum=0.0),
            as_of=_date_text(raw, "as_of", required=False),
        )
    except NetBillingComplianceError as exc:
        raise NetBillingComplianceError(
            f"net-billing credit_carry_forward invalid: {exc}"
        ) from exc


def load_net_billing_compliance_data(
    data: dict[str, Any],
) -> NetBillingComplianceProfile:
    """Validate a net-billing compliance snapshot from signed provisioning data."""

    if not isinstance(data, dict):
        raise NetBillingComplianceError("net-billing compliance must be an object")

    status = _text(data, "status")
    if status not in _VALID_PROFILE_STATUSES:
        raise NetBillingComplianceError(
            f"net-billing status must be one of {sorted(_VALID_PROFILE_STATUSES)}, "
            f"got {status!r}"
        )

    return NetBillingComplianceProfile(
        profile=_text(data, "profile"),
        version=_text(data, "version"),
        status=status,
        country=_text(data, "country"),
        disco=_text(data, "disco"),
        source=_source(data),
        export_cap_watts=_number(data, "export_cap_watts", minimum=0.0),
        export_cap_reference=_text(data, "export_cap_reference", required=False),
        disco_feasibility=_step(
            data,
            "disco_feasibility",
            valid_statuses=_VALID_STEP_STATUSES,
        ),
        nerc_registration=_step(
            data,
            "nerc_registration",
            valid_statuses=_VALID_STEP_STATUSES,
        ),
        nemsa_inspection=_step(
            data,
            "nemsa_inspection",
            valid_statuses=_VALID_INSPECTION_STATUSES,
        ),
        statement_tracking=_statement_tracking(data),
        credit_carry_forward=_credit(data),
        site_relocation_planned=_bool(data, "site_relocation_planned", default=False),
        relocation_effective_date=_date_text(
            data,
            "relocation_effective_date",
            required=False,
        ),
        notes=_text(data, "notes", required=False),
    )


def _due_or_overdue(due_by: str, current_date: str) -> bool:
    return bool(due_by and current_date and due_by <= current_date)


def _append_step_attention(
    codes: list[str],
    *,
    name: str,
    step: ComplianceStep,
    complete_status: str,
    current_date: str,
) -> None:
    if step.status in {"rejected", "failed", "expired"}:
        codes.append(f"{name}_{step.status}")
        return
    if step.status != complete_status:
        codes.append(f"{name}_pending")
    if _due_or_overdue(step.due_by, current_date) and step.status != complete_status:
        codes.append(f"{name}_due")
    if step.status == complete_status and not (step.certificate_id or step.reference):
        codes.append(f"{name}_proof_missing")


def evaluate_net_billing_compliance(
    profile: NetBillingComplianceProfile,
    *,
    current_date: str,
    configured_export_cap_watts: float,
    settlement_statement_valid: bool,
    settlement_statement_id: str = "",
) -> NetBillingComplianceEvaluation:
    """Evaluate a validated compliance profile for Tier A operator attention."""

    if not profile.tracking_qualified:
        return NetBillingComplianceEvaluation(
            attention_required=False,
            attention_codes=(),
            attention_summary="net-billing compliance profile is draft",
            export_cap_matches_runtime=False,
        )

    codes: list[str] = []
    _append_step_attention(
        codes,
        name="disco_feasibility",
        step=profile.disco_feasibility,
        complete_status="approved",
        current_date=current_date,
    )
    _append_step_attention(
        codes,
        name="nerc_registration",
        step=profile.nerc_registration,
        complete_status="approved",
        current_date=current_date,
    )
    _append_step_attention(
        codes,
        name="nemsa_inspection",
        step=profile.nemsa_inspection,
        complete_status="passed",
        current_date=current_date,
    )

    configured_cap = max(0.0, float(configured_export_cap_watts))
    profile_cap = max(0.0, profile.export_cap_watts)
    export_cap_matches_runtime = False
    if profile_cap <= 0.0:
        codes.append("export_cap_missing")
    elif configured_cap <= 0.0:
        codes.append("runtime_export_cap_unconfigured")
    else:
        tolerance = max(1.0, profile_cap * 0.001)
        export_cap_matches_runtime = abs(profile_cap - configured_cap) <= tolerance
        if not export_cap_matches_runtime:
            codes.append("runtime_export_cap_mismatch")

    statement = profile.statement_tracking
    if statement.required:
        if not settlement_statement_valid:
            codes.append("monthly_statement_missing")
        if statement.status in {"missing", "not_required"}:
            codes.append("monthly_statement_not_uploaded")
        if _due_or_overdue(statement.due_by, current_date) and statement.status in {
            "missing",
            "not_required",
        }:
            codes.append("monthly_statement_due")
        if (
            statement.expected_statement_id
            and settlement_statement_id
            and statement.expected_statement_id != settlement_statement_id
        ):
            codes.append("monthly_statement_id_mismatch")

    if profile.site_relocation_planned and profile.credit_carry_forward.value > 0.0:
        codes.append("relocation_credit_loss_risk")

    deduped_codes = tuple(dict.fromkeys(codes))
    if deduped_codes:
        summary = ", ".join(deduped_codes[:4])
        if len(deduped_codes) > 4:
            summary += f", +{len(deduped_codes) - 4} more"
    else:
        summary = "net-billing compliance context is current"

    return NetBillingComplianceEvaluation(
        attention_required=bool(deduped_codes),
        attention_codes=deduped_codes,
        attention_summary=summary,
        export_cap_matches_runtime=export_cap_matches_runtime,
    )
