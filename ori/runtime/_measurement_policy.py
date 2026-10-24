# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""When a refused measurement degrades a sensor, and the notices it is owed."""

# How many consecutive refused measurement windows mark a sensor degraded. One
# refusal is a transient the poll cadence will retry; a run of them means the
# signal, the wiring or the timing has changed and the reading is not coming
# back on its own.
MEASUREMENT_REFUSALS_BEFORE_DEGRADED = 3


# And how many consecutive good windows clear it. Recovery is deliberately
# slower than failure: a measurement path that alternates is not trustworthy,
# and flapping between degraded and healthy would produce an alert stream that
# operators learn to ignore.
MEASUREMENT_WINDOWS_TO_RECOVER = 5


#: Measurement-state writes that may wait for a busy store before one is lost.
MEASUREMENT_WRITER_CEILING = 256


#: The store's busy timeout: how long a closing writer lets a write in flight land.
MEASUREMENT_CLOSE_GRACE_S = 5.0


# How many times a degradation warning is retried when it could not be
# delivered or durably queued. Paced by the poll interval, and bounded so a
# broken alert path does not retry forever on every refused window.
MEASUREMENT_NOTIFY_MAX_ATTEMPTS = 5


# The escalation schedule for a measurement loss that does not resolve, in
# elapsed milliseconds since the degradation began.
#
# A device that cannot establish a trustworthy measurement said so once and
# then waited indefinitely for a person. The first notice is not the problem;
# the silence after it is, because a channel that is not being measured is a
# channel nothing is protecting, and the operator has no reminder that it is
# still in that state.
#
#   immediate   the primary contact, on the transition into degraded
#   6 hours     the primary contact again
#   12 hours    the secondary contact, or the primary where none is configured
#   daily       the same escalation contact, indefinitely
#
# **There is no give-up.** A still-unprotected channel must not become
# permanently silent, so nothing here stops on a message count or a delivery
# cost. It stops when the sensor produces credible measurements again. Two
# further stop conditions are sanctioned and neither is implemented: removal
# of the affected safety pair, which belongs with the active-pair supervision
# design, and a locally audited maintenance acknowledgement with a short
# expiry, which needs an inbound, audited authority surface of its own. Until
# they exist, recovery is the only way this stops, and an operator who has
# accepted the fault keeps being reminded of it.
#
# Release-owned rather than site-configurable, deliberately. A setting here
# would let a deployment configure a persistent measurement loss into silence,
# which is the condition this schedule exists to prevent. Measure real pilot
# message volume first; any later configuration must be a surface that cannot
# disable, indefinitely defer, or remove the escalation.
#
# The cadence keeps message volume to two primary messages and then one daily
# escalation, rather than repeating to everybody every day.
#
# `docs/MEASUREMENT_SUPERVISION.md` carries what this schedule is part of and
# what it deliberately is not: the pair-scoped supervision this precedes, the
# connect-time contention case, and what a reset-based response would have to
# prove first.
MEASUREMENT_REMINDER_AFTER_MS = 6 * 60 * 60 * 1000


MEASUREMENT_ESCALATE_AFTER_MS = 12 * 60 * 60 * 1000


MEASUREMENT_ESCALATION_REPEAT_MS = 24 * 60 * 60 * 1000


def measurement_notice_stage_due(elapsed_ms: int) -> int:
    """Which notice the schedule owes at this point in a degradation.

    Stage 0 is the notice sent on the transition itself. The schedule is a
    function of elapsed time alone, never of what was delivered, so a reminder
    that could not be sent is superseded by the next stage rather than
    cancelling it.
    """
    if elapsed_ms < MEASUREMENT_REMINDER_AFTER_MS:
        return 0
    if elapsed_ms < MEASUREMENT_ESCALATE_AFTER_MS:
        return 1
    repeats = (elapsed_ms - MEASUREMENT_ESCALATE_AFTER_MS) // (
        MEASUREMENT_ESCALATION_REPEAT_MS
    )
    return 2 + int(repeats)
