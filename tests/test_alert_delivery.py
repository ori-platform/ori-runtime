# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from ori.actions.alert_delivery import (
    AlertIntent,
    OutboundAlert,
    build_outbound_alert,
)


@pytest.mark.parametrize(
    ("intent", "variables"),
    [
        (AlertIntent.STARTUP, ("Abuja", 3, 9)),
        (
            AlertIntent.TIER_A_ALERT,
            ("overcurrent", "Abuja", "Wednesday 23:00"),
        ),
        (
            AlertIntent.TIER_C_APPROVAL,
            ("open circuit", "Abuja", "Wednesday 23:00", "AB12CD34", 300),
        ),
        (
            AlertIntent.TIER_C_ESCALATION,
            ("AB12CD34", "Abuja", "Wednesday 23:00", "completed"),
        ),
    ],
)
def test_each_business_intent_has_a_fixed_bounded_variable_contract(intent, variables):
    alert = build_outbound_alert(
        intent=intent,
        sms_body="Detailed operator reasoning stays on SMS.",
        template_variables=variables,
    )

    assert alert.intent is intent
    assert all(alert.template_variables)
    assert "reasoning stays" not in " ".join(alert.template_variables)


def test_template_variable_count_cannot_be_used_as_a_free_form_escape_hatch():
    with pytest.raises(ValueError, match="requires 3 template variables"):
        OutboundAlert(
            intent=AlertIntent.TIER_A_ALERT,
            sms_body="Detailed SMS body",
            template_variables=("one arbitrary model paragraph",),
        )


def test_builder_compacts_and_bounds_operator_controlled_fields():
    alert = build_outbound_alert(
        intent=AlertIntent.TIER_A_ALERT,
        sms_body="Detailed SMS body",
        template_variables=("category\nwith\tspacing", "x" * 200, "Wednesday 23:00"),
    )

    assert alert.template_variables[0] == "category with spacing"
    assert len(alert.template_variables[1]) == 80
    assert alert.template_variables[1].endswith("...")


def test_direct_construction_rejects_control_text():
    with pytest.raises(ValueError, match="control text"):
        OutboundAlert(
            intent=AlertIntent.TIER_A_ALERT,
            sms_body="Detailed SMS body",
            template_variables=("risk\ncategory", "Abuja", "Wednesday 23:00"),
        )
