# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""One zone-profile pair's trip state, and the durable journal that carries it.

The machine is pure: durable state and the trip-intent journal arrive as
inputs at every start, and the outcomes it names are commands for the caller
to execute through the zone's commissioned mapping before any record is
written. The crash window is closed by three mechanisms together — the
intent journal, the arming rule, and the terminal-state-conditioned startup
command — and the journal is loaded under a closed grammar in which
resolution is a sequence invariant: only a later record or durable clear can
justify a resolved mark.

A trip latches. Command status is what the driver reported, never what the
circuit did; effect verification is its own axis; record persistence is its
own obligation. Absence of evidence migrates to the retryable status, an
intent commanded under a binding no longer in force loads orphaned and never
actuates, and every value outside a vocabulary refuses rather than loading
as something else.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

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

OPEN_PROTECTED_CIRCUIT = "open_protected_circuit"
CLOSE_PROTECTED_CIRCUIT = "close_protected_circuit"

NO_AUTHORITY = "no_authority"

COMMAND_STATUSES = ("none", "command_pending", "driver_refused", "command_issued")
EFFECT_STATES = ("unknown", "matched", "mismatched")
INTENT_FIELDS = frozenset(
    {
        "zone_id",
        "profile_id",
        "attempt_id",
        "binding_seq",
        "outcome",
        "created_at_ms",
        "resolved",
    }
)


class DurableStateError(ValueError):
    """A durable record or journal holds what this machine never wrote.

    Corruption, truncation, and a future version's vocabulary are
    indistinguishable here, and none may silently erase or invent a latch:
    the caller refuses startup.
    """


class VerdictError(ValueError):
    """An evaluation verdict outside the closed vocabulary, or a reason that
    contradicts it. It must never count as credible or move the state."""


class CommandSequenceError(ValueError):
    """A driver result recorded out of order. The contract's evidence
    sequence is trip -> command_pending -> driver result, and a result with
    no pending command to answer is a claim about a call nothing made."""


@dataclass(frozen=True)
class Transition:
    state: str
    refusal: str | None = None
    outcome: str | None = None
    rejected: str | None = None
    startup_command: str | None = None
    retry: str | None = None


def _positive_int(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value > 0


def _intent_is_well_formed(intent: Any, zone_id: str, profile_id: str) -> bool:
    if not isinstance(intent, Mapping) or set(intent) != INTENT_FIELDS:
        return False
    for key in ("zone_id", "profile_id"):
        if not isinstance(intent[key], str) or not intent[key]:
            return False
    if intent["zone_id"] != zone_id or intent["profile_id"] != profile_id:
        return False
    if not isinstance(intent["attempt_id"], str) or not intent["attempt_id"]:
        return False
    if not _positive_int(intent["binding_seq"]) or not _positive_int(
        intent["created_at_ms"]
    ):
        return False
    if intent["outcome"] != OPEN_PROTECTED_CIRCUIT:
        return False
    if not isinstance(intent["resolved"], bool):
        return False
    return True


def _load_journal(
    journal: Iterable[Mapping[str, Any]], zone_id: str, profile_id: str
) -> tuple[str | None, Any]:
    """Walk the journal in append order.

    Returns (record_status, governing_intent) where record_status is the
    surviving full record's command status ("legacy" for one predating the
    vocabulary) and governing_intent is the latest unresolved intent
    appended after any record or clear — the string "corrupt" for a
    malformed but positionally identifiable entry. Raises DurableStateError
    for corruption beyond the entry level.
    """
    record_status: str | None = None
    unresolved: list[Any] = []
    attempt_ids: set[str] = set()
    unjustified_resolutions = 0
    for entry in journal:
        if not isinstance(entry, Mapping) or len(entry) != 1:
            raise DurableStateError(
                "journal entry is not one of intent, record, clear, corrupt"
            )
        if "corrupt" in entry:
            if entry["corrupt"] == "identifiable":
                unresolved.append("corrupt")
                continue
            raise DurableStateError("the intent journal cannot be read")
        if "clear" in entry:
            record_status = None
            unresolved = []
            unjustified_resolutions = 0
            continue
        if "record" in entry:
            unresolved = []
            unjustified_resolutions = 0
            status = entry["record"].get("command_status")
            # A journal record is current-format by construction: legacy
            # treatment exists only for the pre-journal durable source, so a
            # missing or empty status here is corruption, not history.
            if status not in COMMAND_STATUSES or status == "none":
                raise DurableStateError(
                    f"journal record carries command status {status!r}, "
                    "outside the vocabulary"
                )
            record_status = status
            continue
        if "intent" in entry:
            intent = entry["intent"]
            if not _intent_is_well_formed(intent, zone_id, profile_id):
                unresolved.append("corrupt")
                continue
            if intent["attempt_id"] in attempt_ids:
                raise DurableStateError("the intent journal repeats an attempt id")
            attempt_ids.add(intent["attempt_id"])
            if intent["resolved"]:
                unjustified_resolutions += 1
                continue
            unresolved.append(intent)
            continue
        raise DurableStateError(
            "journal entry is not one of intent, record, clear, corrupt"
        )
    if unjustified_resolutions:
        raise DurableStateError(
            "a resolved intent with no later record or clear claims a "
            "resolution nothing durable performed"
        )
    return record_status, (unresolved[-1] if unresolved else None)


class ZoneTripState:
    """The safety-profile trip-state machine for one zone-profile pair."""

    def __init__(
        self, zone_id: str, profile_id: str, *, terminal_state: str = "open"
    ) -> None:
        if terminal_state not in ("open", "closed"):
            raise DurableStateError(
                f"unknown de_energised_terminal_state {terminal_state!r}"
            )
        self.zone_id = zone_id
        self.profile_id = profile_id
        self.terminal_state = terminal_state
        self.state = INACTIVE
        self.command_status = "none"
        self.record_state = "committed"
        self.effect = "unknown"
        self.orphaned = False
        self.retired = False
        self._safety_path_confirmed = False
        self._credible_reading_seen = False
        self._condition_active = False
        self._retry_cancelled = False
        self._driver_attempt_in_flight = False

    def startup(
        self,
        durable_state: str | None,
        journal: Iterable[Mapping[str, Any]] = (),
        *,
        durable_command_status: str | None = None,
        binding_seq_in_force: int = 1,
    ) -> Transition:
        """A (re)start: load the durables, forget every per-start fact, and
        return the startup coil decision for this pair's zone."""
        if durable_state not in (None, INACTIVE, ARMED, TRIPPED):
            raise DurableStateError(
                f"durable trip state {durable_state!r} is outside the vocabulary"
            )
        self._safety_path_confirmed = False
        self._credible_reading_seen = False
        self._condition_active = False
        self._retry_cancelled = False
        self._driver_attempt_in_flight = False
        self.effect = "unknown"
        journal = list(journal)
        record_status, governing_intent = _load_journal(
            journal, self.zone_id, self.profile_id
        )
        if durable_state == TRIPPED and not journal:
            record_status = durable_command_status or "legacy"
            if record_status not in COMMAND_STATUSES and record_status != "legacy":
                raise DurableStateError(
                    f"unknown durable command status {record_status!r}"
                )
        if governing_intent is not None:
            # Append order governs: an unresolved intent survives only after
            # the last record or clear, so it outranks any earlier record.
            self.state = TRIPPED
            self.command_status = "command_pending"
            self.orphaned = (
                governing_intent != "corrupt"
                and governing_intent["binding_seq"] != binding_seq_in_force
            )
            return Transition(self.state, startup_command="none")
        if record_status is not None:
            if durable_state != TRIPPED:
                raise DurableStateError(
                    "a surviving full record requires durable_state tripped"
                )
            self.state = TRIPPED
            # A record predating the status vocabulary proves no acceptance:
            # absence migrates to the retryable status, never to the one
            # that stops retries.
            self.command_status = (
                "command_pending" if record_status == "legacy" else record_status
            )
            return Transition(self.state, startup_command="none")
        if durable_state == TRIPPED:
            raise DurableStateError(
                "durable_state tripped requires a record, in the journal or legacy"
            )
        self.state = INACTIVE
        self.command_status = "none"
        command = "de_energised" if self.terminal_state == "open" else "deferred"
        return Transition(self.state, startup_command=command)

    def confirm_safety_path(self) -> Transition:
        self._safety_path_confirmed = True
        return Transition(self.state)

    def observe(self, verdict: EvaluationVerdict) -> Transition:
        """A reading's evaluation verdict, applied to the state. A trip
        moves the pair to tripped with command_pending — the evidence status
        before any driver call — and the caller commands the outcome, then
        reports what the driver said through record_driver_result()."""
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
            self._retry_cancelled = False
            self.command_status = "command_pending"
            return Transition(self.state, outcome=OPEN_PROTECTED_CIRCUIT)
        return Transition(self.state)

    def begin_driver_attempt(self) -> Transition:
        """Acquire the single in-flight driver attempt. One lease, one
        physical call: a second acquisition while a call may still be
        awaiting its result is refused, which is what keeps a retry tick
        from doubling a command already on the wire. The lease is
        non-durable — a crash drops it while the durable pending posture
        survives, so startup may safely retry."""
        if self.state != TRIPPED or self.command_status not in (
            "command_pending",
            "driver_refused",
        ):
            raise CommandSequenceError(
                f"no command to attempt in state {self.state!r} "
                f"with status {self.command_status!r}"
            )
        if self._driver_attempt_in_flight:
            raise CommandSequenceError("a driver attempt is already in flight")
        self._driver_attempt_in_flight = True
        return Transition(self.state)

    def release_driver_attempt(self) -> Transition:
        """A timed-out or failed call releases the lease without a result;
        the status stays as it was and the retry loop schedules backoff."""
        if not self._driver_attempt_in_flight:
            raise CommandSequenceError("no driver attempt in flight to release")
        self._driver_attempt_in_flight = False
        return Transition(self.state)

    def record_driver_result(self, *, accepted: bool) -> Transition:
        """What the driver reported, consuming the in-flight lease. Never
        callable without a begun attempt: a result with nothing pending, or
        with no call on the wire, is a claim about a call nothing made — and
        an accepted command is never answered twice."""
        if self.state != TRIPPED or self.command_status not in (
            "command_pending",
            "driver_refused",
        ):
            raise CommandSequenceError(
                f"no pending command to answer in state {self.state!r} "
                f"with status {self.command_status!r}"
            )
        if not self._driver_attempt_in_flight:
            raise CommandSequenceError("no driver attempt in flight to answer")
        self._driver_attempt_in_flight = False
        self.command_status = "command_issued" if accepted else "driver_refused"
        return Transition(self.state)

    def outcome_retry(self) -> Transition:
        """Whether the registry-owned retry loop may attempt the command
        now. An accepted command is never re-issued, an orphaned pair never
        actuates through a binding it was not commanded under, and a reset
        cancels anything scheduled before it. On "attempted" the caller
        commands the driver and reports through record_driver_result()."""
        if (
            self.state != TRIPPED
            or self._retry_cancelled
            or self.orphaned
            or self._driver_attempt_in_flight
            or self.command_status == "command_issued"
        ):
            return Transition(self.state, retry="skipped")
        return Transition(self.state, retry="attempted")

    def record_retry(self, *, committed: bool) -> Transition:
        """Persistence recovery: its own obligation, on its own schedule,
        never touching the physical command."""
        if self.record_state == "pending" and committed:
            self.record_state = "committed"
        return Transition(self.state)

    def record_write_failed(self) -> None:
        self.record_state = "pending"

    def effect_report(self, result: str) -> Transition:
        """Physical verification: its own axis, never implied by any command
        status and never moving the latch."""
        if result not in ("matched", "mismatched"):
            raise VerdictError(f"unknown effect verification {result!r}")
        self.effect = result
        return Transition(self.state)

    def arm(self) -> Transition:
        if self.state == TRIPPED:
            return Transition(self.state, refusal=TRIPPED)
        if not self._safety_path_confirmed:
            return Transition(self.state, refusal="safety_path_unconfirmed")
        if not self._credible_reading_seen:
            return Transition(self.state, refusal="no_credible_reading")
        self.state = ARMED
        return Transition(self.state, outcome=CLOSE_PROTECTED_CIRCUIT)

    def reset(self) -> Transition:
        """The local, manual, conditional exit from tripped. Serialised with
        the retry loop: no retry scheduled before this may fire after it."""
        if self.state != TRIPPED:
            return Transition(self.state, refusal="not_tripped")
        if not self._credible_reading_seen:
            return Transition(self.state, refusal="no_credible_reading")
        if self._condition_active:
            return Transition(self.state, refusal="condition_active")
        self.state = ARMED
        self._retry_cancelled = True
        return Transition(self.state, outcome=CLOSE_PROTECTED_CIRCUIT)

    def external(self, source: str) -> Transition:
        """A remote command, skill, configuration document, DevicePolicy, or
        binding revision. Refused in every state; nothing moves."""
        del source
        return Transition(self.state, refusal=NO_AUTHORITY)

    def binding_removed(self) -> Transition:
        self.orphaned = True
        return Transition(self.state)

    def retire_orphan(self) -> Transition:
        """Local orphan retirement: actuates nothing, refused while the zone
        is still bound, and terminal."""
        if not self.orphaned:
            return Transition(self.state, refusal="not_orphaned")
        self.retired = True
        return Transition(self.state)


class DeferredStartupGate:
    """The zonal deferred-startup decision for a closed-terminal zone.

    The closing command is licensed only by a credible reading that trips no
    active profile on the zone — and never while any pair on the zone is
    tripped, because a latched zone's circuit is closed only by reset. The
    corpus does not yet carry the tripped-then-clear case; this rule is
    held here until it does.
    """

    def __init__(self, *, deferred: bool) -> None:
        self._pending = deferred

    @property
    def pending(self) -> bool:
        return self._pending

    def note_trip(self) -> None:
        self._pending = False

    def note_credible_reading(self, *, any_pair_tripped: bool) -> str | None:
        if not self._pending or any_pair_tripped:
            if any_pair_tripped:
                self._pending = False
            return None
        self._pending = False
        return "de_energised"
