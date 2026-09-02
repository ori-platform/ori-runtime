# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""One reading against one active profile: trip, no_trip, or rejected_input.

The comparison is decided first: a saturating sensor reporting beyond full
scale on the hazard side still reports more than the trip point, because the
trip point is bounded to lie within range at activation. Only a reading that
does not satisfy the condition is then tested against the declared range, and
a value outside it on the non-hazard side is a sensor reporting something it
cannot have measured. A rejected reading never trips and never silently
vanishes; the alerting that obligation implies belongs to the runtime wiring,
not to this decision.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

TRIP = "trip"
NO_TRIP = "no_trip"
REJECTED_INPUT = "rejected_input"

# The contract's closed rejection vocabulary, in its decided order. A boolean
# is tested before a number because in some languages it is one; zero_quality
# covers a quality that is absent, not a number, or not greater than zero.
REASON_ORDER = (
    "boolean",
    "non_numeric",
    "non_finite",
    "unit_mismatch",
    "zero_quality",
    "out_of_range",
)


@dataclass(frozen=True)
class EvaluationVerdict:
    verdict: str
    reason: str | None = None


def evaluate_reading(
    value: Any,
    unit: Any,
    quality: Any,
    *,
    expected_unit: str,
    trip_point: float,
    range_min: float,
    range_max: float,
) -> EvaluationVerdict:
    """The contract's evaluation verdict for one reading on one active zone."""
    if isinstance(value, bool):
        return EvaluationVerdict(REJECTED_INPUT, "boolean")
    if not isinstance(value, (int, float)):
        return EvaluationVerdict(REJECTED_INPUT, "non_numeric")
    # Every int is finite, at any magnitude; math.isfinite would raise
    # OverflowError converting one beyond float range, and a hostile reading
    # must produce a verdict, never an exception. Comparisons below stay
    # exact: Python compares arbitrary-precision ints against floats without
    # converting through float.
    if isinstance(value, float) and not math.isfinite(value):
        return EvaluationVerdict(REJECTED_INPUT, "non_finite")
    if unit != expected_unit:
        return EvaluationVerdict(REJECTED_INPUT, "unit_mismatch")
    if (
        isinstance(quality, bool)
        or not isinstance(quality, (int, float))
        or not quality > 0
    ):
        return EvaluationVerdict(REJECTED_INPUT, "zero_quality")
    if value > trip_point:
        return EvaluationVerdict(TRIP)
    if range_min <= value <= range_max:
        return EvaluationVerdict(NO_TRIP)
    return EvaluationVerdict(REJECTED_INPUT, "out_of_range")
