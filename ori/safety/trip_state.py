# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""One zone's trip state: inactive, armed, tripped — and what may move it.

The machine is pure: durable state arrives as an input at every start, and
the outcomes it names (`close_protected_circuit` on a successful arm or
reset, `open_protected_circuit` on a trip) are commands for the caller to
execute through the zone's commissioned mapping — executed before the record
is written, because safety never waits for storage. The crash window that
ordering opens is closed by the arming rule, not by a pre-write: a runtime
that trips, dies before recording, and restarts into a live hazard never
arms, because it has no credible reading until the first one arrives, and
that one trips it.

A trip latches. From tripped, no reading, restart, configuration value,
skill, remote command, DevicePolicy, entitlement change, or binding revision
moves the zone anywhere; the only exit is the local, manual, conditional
reset. `armed` is not durable: a restart from armed returns to inactive, and
the safety path is confirmed again before the circuit is closed.
"""

from __future__ import annotations

from dataclasses import dataclass

from ori.safety.evaluation import (
    NO_TRIP,
    REASON_ORDER,
    REJECTED_INPUT,
    TRIP,
    EvaluationVerdict,
)

INACTIVE = "inactive"
ARMED = "armed"
TRIPPED = "tripped"


class DurableStateError(ValueError):
    """The durable record holds a value this machine never wrote. Corruption,
    truncation, and a future version's vocabulary are indistinguishable here,
    and none of them may silently erase a latch: the caller refuses startup."""


class VerdictError(ValueError):
    """An evaluation verdict outside the closed vocabulary, or a reason that
    contradicts it. An invalid internal verdict must never clear the
    condition, count as credible, or move the state."""


OPEN_PROTECTED_CIRCUIT = "open_protected_circuit"
CLOSE_PROTECTED_CIRCUIT = "close_protected_circuit"

NO_AUTHORITY = "no_authority"


@dataclass(frozen=True)
class Transition:
    state: str
    refusal: str | None = None
    outcome: str | None = None
    rejected: str | None = None


class ZoneTripState:
    """The safety-profile trip-state machine for one active zone."""

    def __init__(self) -> None:
        self.state = INACTIVE
        self._safety_path_confirmed = False
        self._credible_reading_seen = False
        self._condition_active = False

    def startup(self, durable_state: str | None) -> Transition:
        """A (re)start: durable `tripped` reloads; `armed` is contractually
        non-durable and returns to inactive, as do `inactive` and no record
        at all. Anything else is a record this machine never wrote and
        refuses before any per-start fact is touched — an unknown value
        normalised to inactive would erase a latch."""
        if durable_state not in (None, INACTIVE, ARMED, TRIPPED):
            raise DurableStateError(
                f"durable trip state {durable_state!r} is outside the vocabulary"
            )
        self._safety_path_confirmed = False
        self._credible_reading_seen = False
        self._condition_active = False
        self.state = TRIPPED if durable_state == TRIPPED else INACTIVE
        return Transition(self.state)

    def confirm_safety_path(self) -> Transition:
        self._safety_path_confirmed = True
        return Transition(self.state)

    def observe(self, verdict: EvaluationVerdict) -> Transition:
        """A reading's evaluation verdict, applied to the state. Only the
        closed vocabulary is accepted: an unknown verdict, or a reason that
        contradicts its verdict, refuses without touching any per-start fact
        — treating it as credible would let an invalid internal value clear
        the condition and close the protected circuit."""
        if verdict.verdict == REJECTED_INPUT:
            if verdict.reason not in REASON_ORDER:
                raise VerdictError(
                    f"rejected_input carries reason {verdict.reason!r}, "
                    "outside the closed vocabulary"
                )
            return Transition(self.state, rejected=verdict.reason)
        if verdict.verdict not in (TRIP, NO_TRIP) or verdict.reason is not None:
            raise VerdictError(
                f"verdict {verdict.verdict!r} with reason {verdict.reason!r} "
                "is outside the closed vocabulary"
            )
        self._credible_reading_seen = True
        self._condition_active = verdict.verdict == TRIP
        if verdict.verdict == TRIP and self.state != TRIPPED:
            self.state = TRIPPED
            return Transition(self.state, outcome=OPEN_PROTECTED_CIRCUIT)
        return Transition(self.state)

    def arm(self) -> Transition:
        """Arming closes the circuit; the refusals are ordered by contract."""
        if self.state == TRIPPED:
            return Transition(self.state, refusal=TRIPPED)
        if not self._safety_path_confirmed:
            return Transition(self.state, refusal="safety_path_unconfirmed")
        if not self._credible_reading_seen:
            return Transition(self.state, refusal="no_credible_reading")
        self.state = ARMED
        return Transition(self.state, outcome=CLOSE_PROTECTED_CIRCUIT)

    def reset(self) -> Transition:
        """The local, manual, conditional exit from tripped."""
        if self.state != TRIPPED:
            return Transition(self.state, refusal="not_tripped")
        if not self._credible_reading_seen:
            return Transition(self.state, refusal="no_credible_reading")
        if self._condition_active:
            return Transition(self.state, refusal="condition_active")
        self.state = ARMED
        return Transition(self.state, outcome=CLOSE_PROTECTED_CIRCUIT)

    def external(self, source: str) -> Transition:
        """A remote command, skill, configuration document, DevicePolicy, or
        binding revision. Refused in every state; nothing moves."""
        del source
        return Transition(self.state, refusal=NO_AUTHORITY)
