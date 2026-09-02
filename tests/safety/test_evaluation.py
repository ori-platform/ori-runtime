# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Evaluation held to the vendored safety-profile corpus, case by case."""

import json
import math
from pathlib import Path
from typing import Any

import pytest

from ori.safety.evaluation import REASON_ORDER, evaluate_reading

CORPUS = json.loads(
    (
        Path(__file__).parent.parent / "vectors/safety_profile/evaluation.json"
    ).read_text()
)
NON_FINITE = {"nan": math.nan, "+inf": math.inf, "-inf": -math.inf}


def _decode_value(raw: Any) -> Any:
    if isinstance(raw, dict) and set(raw) == {"non_finite"}:
        return NON_FINITE[raw["non_finite"]]
    return raw


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["name"])
def test_evaluation_case(case: dict) -> None:
    reading = case["reading"]
    verdict = evaluate_reading(
        _decode_value(reading.get("value")),
        reading.get("unit"),
        reading.get("quality"),
        expected_unit=case["zone"]["sensor"]["unit"],
        trip_point=case["trip_point"],
        range_min=case["zone"]["sensor"]["range_min"],
        range_max=case["zone"]["sensor"]["range_max"],
    )
    assert verdict.verdict == case["expect"]["verdict"]
    assert verdict.reason == case["expect"].get("reason")


def test_reason_order_matches_the_corpus() -> None:
    assert list(REASON_ORDER) == CORPUS["rejection_reason_order"]


def test_every_verdict_and_reason_is_exercised() -> None:
    """The corpus must stop at every verdict and every rejection reason, so a
    silently narrowed vendored corpus cannot leave a reason untested."""
    verdicts = {c["expect"]["verdict"] for c in CORPUS["cases"]}
    reasons = {
        c["expect"]["reason"] for c in CORPUS["cases"] if "reason" in c["expect"]
    }
    assert verdicts == {"trip", "no_trip", "rejected_input"}
    assert reasons == set(REASON_ORDER)


BOUNDS = {
    "expected_unit": "ampere",
    "trip_point": 20.0,
    "range_min": 0.0,
    "range_max": 30.0,
}


@pytest.mark.parametrize(
    ("name", "value", "unit", "quality", "verdict", "reason"),
    [
        # A reading is data from a wire; the evaluator returns a verdict for
        # every input and never raises. Integers beyond float range are
        # finite numbers and get the contractually selected verdict.
        ("huge_positive_int_trips", 10**400, "ampere", 1.0, "trip", None),
        (
            "huge_negative_int_out_of_range",
            -(10**400),
            "ampere",
            1.0,
            "rejected_input",
            "out_of_range",
        ),
        ("huge_int_quality_evaluates", 25.0, "ampere", 10**400, "trip", None),
        # Overlapping faults resolve to the first reason in the decided
        # order, which the corpus does not isolate for these pairs.
        (
            "non_numeric_before_unit",
            "25.0",
            "volt",
            1.0,
            "rejected_input",
            "non_numeric",
        ),
        (
            "non_finite_before_unit",
            math.nan,
            "volt",
            1.0,
            "rejected_input",
            "non_finite",
        ),
        (
            "non_finite_before_quality",
            math.inf,
            "ampere",
            0.0,
            "rejected_input",
            "non_finite",
        ),
        (
            "zero_quality_before_out_of_range",
            -5.0,
            "ampere",
            0.0,
            "rejected_input",
            "zero_quality",
        ),
        (
            "nan_quality_is_zero_quality",
            25.0,
            "ampere",
            math.nan,
            "rejected_input",
            "zero_quality",
        ),
    ],
    ids=lambda v: (
        v if isinstance(v, str) and not v.replace(".", "").isdigit() else None
    ),
)
def test_hostile_and_overlapping_readings(
    name: str, value: Any, unit: Any, quality: Any, verdict: str, reason: Any
) -> None:
    got = evaluate_reading(value, unit, quality, **BOUNDS)
    assert (got.verdict, got.reason) == (verdict, reason)
