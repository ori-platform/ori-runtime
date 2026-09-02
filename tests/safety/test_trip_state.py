# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The trip-state machine held to the vendored lifecycle corpus, event by event."""

import json
import math
from pathlib import Path
from typing import Any

import pytest

from ori.safety.evaluation import EvaluationVerdict, evaluate_reading
from ori.safety.trip_state import (
    DurableStateError,
    Transition,
    VerdictError,
    ZoneTripState,
)

CORPUS = json.loads(
    (Path(__file__).parent.parent / "vectors/safety_profile/lifecycle.json").read_text()
)
NON_FINITE = {"nan": math.nan, "+inf": math.inf, "-inf": -math.inf}


def _decode_value(raw: Any) -> Any:
    if isinstance(raw, dict) and set(raw) == {"non_finite"}:
        return NON_FINITE[raw["non_finite"]]
    return raw


def _apply(machine: ZoneTripState, case: dict, event: dict) -> Transition:
    kind = event["event"]
    if kind in ("startup", "restart"):
        durable = event["durable_state"]
        return machine.startup(None if durable == "none" else durable)
    if kind == "safety_path_confirmed":
        return machine.confirm_safety_path()
    if kind == "reading":
        sensor = case["zone"]["sensor"]
        verdict = evaluate_reading(
            _decode_value(event["value"]),
            sensor["unit"],
            event.get("quality", 1.0),
            expected_unit=sensor["unit"],
            trip_point=case["trip_point"],
            range_min=sensor["range_min"],
            range_max=sensor["range_max"],
        )
        return machine.observe(verdict)
    if kind == "arm_attempt":
        return machine.arm()
    if kind == "reset_attempt":
        return machine.reset()
    if kind == "external":
        return machine.external(event["source"])
    raise AssertionError(f"unknown corpus event {kind}")


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["name"])
def test_lifecycle_case(case: dict) -> None:
    machine = ZoneTripState()
    for index, event in enumerate(case["events"]):
        transition = _apply(machine, case, event)
        where = f"event {index} ({event['event']})"
        assert transition.state == event["expect_state"], where
        assert machine.state == event["expect_state"], where
        assert transition.refusal == event.get("expect_refusal"), where
        assert transition.outcome == event.get("expect_outcome"), where
        assert transition.rejected == event.get("expect_rejected"), where


def test_refusal_vocabularies_match_the_corpus() -> None:
    assert CORPUS["arm_refusals"] == [
        "tripped",
        "safety_path_unconfirmed",
        "no_credible_reading",
    ]
    assert CORPUS["reset_refusals"] == [
        "not_tripped",
        "no_credible_reading",
        "condition_active",
    ]
    assert CORPUS["external_refusal"] == "no_authority"


def test_every_external_source_is_refused_in_every_state() -> None:
    """One machine walked through inactive, armed, and tripped, with every
    external source refused in each state and nothing reset in between."""
    sources = (
        "remote_command",
        "skill",
        "configuration",
        "device_policy",
        "binding_revision",
    )
    machine = ZoneTripState()

    machine.startup(None)
    assert machine.state == "inactive"
    for source in sources:
        assert machine.external(source).refusal == "no_authority"
        assert machine.state == "inactive"

    machine.confirm_safety_path()
    machine.observe(
        evaluate_reading(
            5.0,
            "ampere",
            1.0,
            expected_unit="ampere",
            trip_point=20.0,
            range_min=0.0,
            range_max=30.0,
        )
    )
    assert machine.arm().state == "armed"
    for source in sources:
        assert machine.external(source).refusal == "no_authority"
        assert machine.state == "armed"

    machine.observe(
        evaluate_reading(
            25.0,
            "ampere",
            1.0,
            expected_unit="ampere",
            trip_point=20.0,
            range_min=0.0,
            range_max=30.0,
        )
    )
    assert machine.state == "tripped"
    for source in sources:
        assert machine.external(source).refusal == "no_authority"
        assert machine.state == "tripped"


def test_arm_refusal_order_tripped_before_unconfirmed_path() -> None:
    """A tripped zone with an unconfirmed safety path refuses as tripped:
    the contract orders the refusals, and telling an operator to confirm the
    safety path of a zone that is latched open misstates which fact governs."""
    machine = ZoneTripState()
    machine.startup("tripped")
    transition = machine.arm()
    assert transition.refusal == "tripped"
    assert machine.state == "tripped"


@pytest.mark.parametrize("durable", ["trippped", "future_state", "", "TRIPPED", "none"])
def test_unknown_durable_state_refuses_startup(durable: str) -> None:
    """A record the machine never wrote must refuse, never normalise to
    inactive: corruption, truncation, and a future version's vocabulary are
    indistinguishable, and each would otherwise erase a latch."""
    machine = ZoneTripState()
    machine.startup("tripped")
    with pytest.raises(DurableStateError):
        machine.startup(durable)


def test_armed_and_inactive_durable_records_return_to_inactive() -> None:
    for durable in (None, "inactive", "armed"):
        machine = ZoneTripState()
        assert machine.startup(durable).state == "inactive"


def test_unknown_verdict_cannot_authorize_reset() -> None:
    """The demonstrated attack: an invalid internal verdict counted as a
    credible, condition-clear reading would let reset close the protected
    circuit. It must refuse without touching any per-start fact."""
    machine = ZoneTripState()
    machine.startup("tripped")
    with pytest.raises(VerdictError):
        machine.observe(EvaluationVerdict("future_verdict"))
    assert machine.state == "tripped"
    transition = machine.reset()
    assert transition.refusal == "no_credible_reading"
    assert machine.state == "tripped"


@pytest.mark.parametrize(
    "verdict",
    [
        EvaluationVerdict("rejected_input", "future_reason"),
        EvaluationVerdict("rejected_input"),
        EvaluationVerdict("trip", "out_of_range"),
        EvaluationVerdict("no_trip", "boolean"),
    ],
    ids=[
        "rejected_unknown_reason",
        "rejected_no_reason",
        "trip_with_reason",
        "no_trip_with_reason",
    ],
)
def test_contradictory_verdict_reason_pairs_refuse(verdict: EvaluationVerdict) -> None:
    machine = ZoneTripState()
    machine.startup(None)
    machine.confirm_safety_path()
    with pytest.raises(VerdictError):
        machine.observe(verdict)
    assert machine.arm().refusal == "no_credible_reading"
