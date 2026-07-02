# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from ori.policy.nerc_net_billing import (
    NetBillingComplianceError,
    evaluate_net_billing_compliance,
    load_net_billing_compliance_data,
)


def _profile_data():
    return {
        "profile": "ng-net-billing-example",
        "version": "2026-06",
        "status": "operator_provided",
        "country": "NG",
        "disco": "Ikeja Electric",
        "source": {
            "type": "operator_record",
            "reference": "product policy sha256:abc123",
            "retrieved_at": "2026-06-28",
        },
        "export_cap_watts": 5000.0,
        "export_cap_reference": "approved export cap letter",
        "disco_feasibility": {
            "status": "approved",
            "reference": "feasibility report",
            "submitted_at": "2026-06-01",
            "due_by": "2026-06-11",
            "completed_at": "2026-06-08",
        },
        "nerc_registration": {
            "status": "approved",
            "reference": "NERC certificate PDF",
            "certificate_id": "NERC-NB-001",
            "submitted_at": "2026-06-09",
            "due_by": "2026-06-19",
            "completed_at": "2026-06-15",
        },
        "nemsa_inspection": {
            "status": "passed",
            "reference": "NEMSA certificate PDF",
            "certificate_id": "NEMSA-001",
            "submitted_at": "2026-06-16",
            "due_by": "2026-06-26",
            "completed_at": "2026-06-20",
        },
        "monthly_statement": {
            "status": "reconciled",
            "required": True,
            "expected_statement_id": "ikeja-2026-06",
            "period_start": "2026-06-01",
            "period_end": "2026-06-30",
            "due_by": "2026-07-10",
            "reference": "statement PDF sha256:def456",
        },
        "credit_carry_forward": {
            "value": 0.0,
            "currency": "NGN",
            "kwh": 0.0,
            "as_of": "2026-06-30",
        },
        "site_relocation_planned": False,
        "relocation_effective_date": "",
        "notes": "Operator-provided compliance snapshot.",
    }


def test_load_net_billing_compliance_profile() -> None:
    profile = load_net_billing_compliance_data(_profile_data())

    assert profile.profile == "ng-net-billing-example"
    assert profile.tracking_qualified is True
    assert profile.disco_feasibility.status == "approved"
    assert profile.nerc_registration.certificate_id == "NERC-NB-001"
    assert profile.nemsa_inspection.status == "passed"
    assert profile.statement_tracking.expected_statement_id == "ikeja-2026-06"
    assert profile.credit_carry_forward.currency == "NGN"


def test_completed_profile_evaluates_without_attention() -> None:
    profile = load_net_billing_compliance_data(_profile_data())

    result = evaluate_net_billing_compliance(
        profile,
        current_date="2026-07-01",
        configured_export_cap_watts=5000.0,
        settlement_statement_valid=True,
        settlement_statement_id="ikeja-2026-06",
    )

    assert result.attention_required is False
    assert result.attention_codes == ()
    assert result.export_cap_matches_runtime is True


def test_pending_and_overdue_workflow_steps_raise_attention() -> None:
    data = _profile_data()
    data["disco_feasibility"]["status"] = "submitted"
    data["disco_feasibility"]["due_by"] = "2026-06-20"
    data["nemsa_inspection"]["status"] = "failed"
    profile = load_net_billing_compliance_data(data)

    result = evaluate_net_billing_compliance(
        profile,
        current_date="2026-06-28",
        configured_export_cap_watts=5000.0,
        settlement_statement_valid=True,
        settlement_statement_id="ikeja-2026-06",
    )

    assert result.attention_required is True
    assert "disco_feasibility_pending" in result.attention_codes
    assert "disco_feasibility_due" in result.attention_codes
    assert "nemsa_inspection_failed" in result.attention_codes


def test_export_cap_and_statement_mismatch_raise_attention() -> None:
    data = _profile_data()
    data["monthly_statement"]["status"] = "missing"
    data["monthly_statement"]["due_by"] = "2026-06-27"
    profile = load_net_billing_compliance_data(data)

    result = evaluate_net_billing_compliance(
        profile,
        current_date="2026-06-28",
        configured_export_cap_watts=4000.0,
        settlement_statement_valid=False,
        settlement_statement_id="",
    )

    assert result.export_cap_matches_runtime is False
    assert "runtime_export_cap_mismatch" in result.attention_codes
    assert "monthly_statement_missing" in result.attention_codes
    assert "monthly_statement_not_uploaded" in result.attention_codes
    assert "monthly_statement_due" in result.attention_codes


def test_relocation_with_credit_carry_forward_warns() -> None:
    data = _profile_data()
    data["credit_carry_forward"]["value"] = 9000.0
    data["credit_carry_forward"]["kwh"] = 45.0
    data["site_relocation_planned"] = True
    data["relocation_effective_date"] = "2026-08-01"
    profile = load_net_billing_compliance_data(data)

    result = evaluate_net_billing_compliance(
        profile,
        current_date="2026-07-01",
        configured_export_cap_watts=5000.0,
        settlement_statement_valid=True,
        settlement_statement_id="ikeja-2026-06",
    )

    assert result.attention_codes == ("relocation_credit_loss_risk",)


def test_draft_profile_loads_but_does_not_trigger_attention() -> None:
    data = _profile_data()
    data["status"] = "draft"
    profile = load_net_billing_compliance_data(data)

    result = evaluate_net_billing_compliance(
        profile,
        current_date="2026-07-01",
        configured_export_cap_watts=0.0,
        settlement_statement_valid=False,
    )

    assert profile.tracking_qualified is False
    assert result.attention_required is False
    assert result.attention_codes == ()


def test_rejects_invalid_step_status() -> None:
    data = _profile_data()
    data["nerc_registration"]["status"] = "done"

    with pytest.raises(NetBillingComplianceError, match="nerc_registration.status"):
        load_net_billing_compliance_data(data)


def test_rejects_negative_credit_value() -> None:
    data = _profile_data()
    data["credit_carry_forward"]["value"] = -1.0

    with pytest.raises(NetBillingComplianceError, match="credit_carry_forward"):
        load_net_billing_compliance_data(data)
