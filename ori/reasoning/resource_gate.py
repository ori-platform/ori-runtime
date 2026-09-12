# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""One runtime-global gate deciding what may drive a resource, and when.

A bare mutex would let a later request wait for release and then perform the
same physical act a second time, which is the opposite of coalescing. So the
gate holds an in-flight record per resource — the admitted outcome, the
dispatch tier, the contributing triggers and how far the attempt has got — and
precedence depends on that state rather than on arrival order.

Contention is decided on ``resource_key`` alone; ``desired_outcome`` then
decides whether two admitted actions coalesce or conflict.

``docs/DISPATCH_PLAN.md`` is the contract this module implements.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
from dataclasses import dataclass, field
from typing import Any

from ori.reasoning.action_registry import tier_rank
from ori.reasoning.dispatch_plan import ResourceIdentity, opposes
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

# How many recent gate decisions are kept in memory for health and tests. Every
# one is also logged, which is what survives the process.
_SUPPRESSION_HISTORY = 256

# The arbitration scope an admission belongs to, carried per task rather than
# per process. Events are dispatched concurrently, so a scope read from a
# process-global stack is whichever event opened one most recently — not the
# event doing the admitting. That mis-tagged record was then freed when the
# unrelated event closed, releasing a completed protective act's foreclosure
# while the event that licensed it was still running. An asyncio task inherits
# the context it was created in, so the scope set inside one event's dispatch
# reaches everything that event awaits and every task it schedules, and nothing
# else.
_ARBITRATION_SCOPE: contextvars.ContextVar[str] = contextvars.ContextVar(
    "ori_arbitration_scope", default=""
)


class HolderState:
    """How far the current holder of a resource has got."""

    RESERVED = "reserved"
    # The act completed and the resource stays foreclosed until the event that
    # licensed it is settled. Without it a Tier D trip retired the moment its
    # executor returned, and the same event's lower-authority opposite was
    # admitted against an empty gate.
    HELD = "held"
    PROPOSAL = "proposal"
    RUNNING = "running"
    UNCERTAIN = "uncertain"
    RETIRED = "retired"


class Admission:
    """What the gate decided about one request."""

    ADMITTED = "admitted"
    JOINED = "joined"
    REFUSED = "refused"
    PREEMPTED_HOLDER = "preempted_holder"


# Recorded refusal reasons. Closed values so an operator can find every instance
# of a state without matching prose.
OPPOSING_EQUAL_TIER = "opposing_equal_tier"
OPPOSING_HIGHER_TIER_HOLDS = "opposing_higher_tier_holds"
OPPOSING_ACT_RUNNING = "opposing_act_running"
OPPOSING_COMMAND_UNCERTAIN = "opposing_command_uncertain"
CONFLICT_RESOLVED_BY_TIMING = "conflict_resolved_by_timing"
FORECLOSED_BY_COMPLETED_ACT = "foreclosed_by_completed_act"
PROPOSAL_INVALIDATED = "proposal_invalidated"
PROPOSAL_NO_LONGER_HELD = "proposal_no_longer_held"
UNRESOLVED_SAFETY_CONFLICT = "unresolved_safety_conflict"


@dataclass
class Contributor:
    """One trigger's claim on an admitted act. Joining merges execution, never licensing."""

    skill_name: str
    trigger_name: str
    action: str
    dispatch_tier: str
    correlation_id: str = ""
    tier_d_granted: bool = False


@dataclass
class _Record:
    identity: ResourceIdentity
    tier: str
    state: str
    contributors: list[Contributor] = field(default_factory=list)
    admitted_at_ms: int = 0
    proposal_id: str = ""
    invalidated: bool = False
    result: Any = None
    scope: str = ""
    done: asyncio.Event = field(default_factory=asyncio.Event)

    @property
    def holds_tier_d(self) -> bool:
        return any(c.tier_d_granted for c in self.contributors)


@dataclass
class GateDecision:
    """The gate's answer, and the record it attaches to."""

    admission: str
    reason: str = ""
    token: _Record | None = None
    displaced: _Record | None = None
    safety_conflict: bool = False

    @property
    def may_execute(self) -> bool:
        return self.admission in (Admission.ADMITTED, Admission.PREEMPTED_HOLDER)


class ResourceGate:
    """Runtime-global admission for physical acts, keyed by resource."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, ...], _Record] = {}
        self._lock = asyncio.Lock()
        self._suppressions: list[dict[str, Any]] = []
        # Open arbitration scopes, one per event being dispatched. A record
        # admitted inside one is foreclosed for the rest of that event rather
        # than freed when its own attempt finishes.
        self._scopes: set[str] = set()

    @property
    def suppressions(self) -> list[dict[str, Any]]:
        """Every refusal, preemption, coalescing, invalidation and delay recorded.

        A dropped proposal that leaves no trace is indistinguishable from one
        that was never raised.
        """
        return list(self._suppressions)

    def _record_event(self, kind: str, **fields: Any) -> None:
        entry = {"kind": kind, "at_ms": now_ms(), **fields}
        self._suppressions.append(entry)
        # Bounded: this list lives for the process and a device runs for months.
        # It is a recent-history window for health and tests, not the durable
        # audit record — that is the log line, and persisting these decisions to
        # the action log is not done here.
        if len(self._suppressions) > _SUPPRESSION_HISTORY:
            del self._suppressions[:-_SUPPRESSION_HISTORY]
        logger.info("ResourceGate: %s %s", kind, fields)

    def open_scope(self, scope: str) -> contextvars.Token[str]:
        """Begin an arbitration scope for one event.

        Foreclosure has to outlive the attempt that established it. A Tier D
        act that opens a circuit must keep the same event's lower-authority
        close from being admitted afterwards, and two triggers naming the same
        outcome must coalesce into one executor call even when the first has
        already finished — both of which a record retiring at its own
        completion made impossible.

        Returns the token that restores the previous scope. Pass it back to
        :meth:`close_scope` from the same task, which is the only place it is
        valid to reset.
        """
        self._scopes.add(scope)
        return _ARBITRATION_SCOPE.set(scope)

    async def close_scope(
        self, scope: str, token: contextvars.Token[str] | None = None
    ) -> None:
        """End the scope and free everything it was holding."""
        if token is not None:
            _ARBITRATION_SCOPE.reset(token)
        async with self._lock:
            self._scopes.discard(scope)
            for key, record in list(self._records.items()):
                if record.scope == scope and record.state == HolderState.HELD:
                    record.state = HolderState.RETIRED
                    record.done.set()
                    self._records.pop(key, None)

    @property
    def _current_scope(self) -> str:
        """The scope of the task admitting, never of whoever opened one last."""
        return _ARBITRATION_SCOPE.get()

    async def request(
        self,
        identity: ResourceIdentity,
        tier: str,
        contributor: Contributor,
        *,
        awaits_operator: bool = False,
    ) -> GateDecision:
        """Ask to drive *identity* at *tier* on behalf of *contributor*.

        *awaits_operator* says the caller will ask a person before acting, so
        the record is created as a proposal rather than a reservation. It is
        settled here, under the same lock as the admission, because a caller
        that admitted as `reserved` and marked the proposal afterwards left a
        window in which a Tier D arrival saw a reservation and coalesced —
        making a safety trip wait out an approval round trip it must displace.
        """
        async with self._lock:
            holder = self._records.get(identity.resource_key)
            if holder is None or holder.state == HolderState.RETIRED:
                return self._admit(
                    identity, tier, contributor, awaits_operator=awaits_operator
                )

            if holder.identity.join_key == identity.join_key:
                return self._same_outcome(
                    holder, tier, contributor, awaits_operator=awaits_operator
                )

            if opposes(holder.identity, identity):
                return self._opposing(
                    holder,
                    identity,
                    tier,
                    contributor,
                    awaits_operator=awaits_operator,
                )

            # Same resource, neither the same act nor its opposite — a different
            # command on one actuator. It is not coalescable and the holder
            # stands until it retires.
            self._record_event(
                "refused",
                resource=identity.resource_key,
                reason=OPPOSING_HIGHER_TIER_HOLDS,
                contributor=contributor.trigger_name,
            )
            return GateDecision(
                Admission.REFUSED, OPPOSING_HIGHER_TIER_HOLDS, token=None
            )

    def _admit(
        self,
        identity: ResourceIdentity,
        tier: str,
        contributor: Contributor,
        *,
        awaits_operator: bool = False,
    ) -> GateDecision:
        record = _Record(
            identity=identity,
            tier=tier,
            state=(HolderState.PROPOSAL if awaits_operator else HolderState.RESERVED),
            contributors=[contributor],
            admitted_at_ms=now_ms(),
            scope=self._current_scope,
        )
        self._records[identity.resource_key] = record
        return GateDecision(Admission.ADMITTED, token=record)

    def _same_outcome(
        self,
        holder: _Record,
        tier: str,
        contributor: Contributor,
        *,
        awaits_operator: bool = False,
    ) -> GateDecision:
        if holder.state == HolderState.PROPOSAL and tier_rank(tier) >= tier_rank("D"):
            # A proposal is not an attempt. Joining one would make a safety trip
            # wait for a human, the exact inversion Tier D exists to prevent.
            holder.invalidated = True
            self._record_event(
                "proposal_invalidated",
                resource=holder.identity.resource_key,
                by=contributor.trigger_name,
                proposal_id=holder.proposal_id,
            )
            displaced = holder
            decision = self._admit(
                holder.identity, tier, contributor, awaits_operator=awaits_operator
            )
            decision.displaced = displaced
            return decision

        holder.contributors.append(contributor)
        self._record_event(
            "coalesced",
            resource=holder.identity.resource_key,
            holder_state=holder.state,
            contributor=contributor.trigger_name,
        )
        return GateDecision(Admission.JOINED, token=holder)

    def _opposing(
        self,
        holder: _Record,
        identity: ResourceIdentity,
        tier: str,
        contributor: Contributor,
        *,
        awaits_operator: bool = False,
    ) -> GateDecision:
        arriving_d = tier_rank(tier) >= tier_rank("D")

        if holder.holds_tier_d and arriving_d:
            # Nothing acts, so nothing is protected. Filing it as a routine
            # refusal would let a device that protects nothing look like a
            # device that made a decision.
            self._record_event(
                "safety_conflict",
                resource=identity.resource_key,
                holder=holder.identity.desired_outcome,
                arriving=identity.desired_outcome,
                contributor=contributor.trigger_name,
            )
            return GateDecision(
                Admission.REFUSED,
                UNRESOLVED_SAFETY_CONFLICT,
                safety_conflict=True,
            )

        # Checked after the safety conflict above, deliberately. Both can be
        # true at once, and a device with two opposing Tier D outcomes is
        # unprotected whatever the in-flight command is doing; filing that as a
        # routine uncertainty would lose the condition that must degrade safety
        # status.
        if holder.state == HolderState.UNCERTAIN:
            # A timeout must not become two contradictory commands to one
            # actuator, however long the uncertainty lasts.
            self._record_event(
                "refused",
                resource=identity.resource_key,
                reason=OPPOSING_COMMAND_UNCERTAIN,
                contributor=contributor.trigger_name,
            )
            return GateDecision(Admission.REFUSED, OPPOSING_COMMAND_UNCERTAIN)

        if holder.state == HolderState.HELD:
            # The act completed inside this event and still forecloses lower
            # authority on its resource. A strictly higher authority may still
            # act — that is a new act, not a preemption, because there is
            # nothing in flight to displace.
            if tier_rank(tier) > tier_rank(holder.tier):
                return self._admit(
                    identity, tier, contributor, awaits_operator=awaits_operator
                )
            self._record_event(
                "refused",
                resource=identity.resource_key,
                reason=FORECLOSED_BY_COMPLETED_ACT,
                contributor=contributor.trigger_name,
                holder=holder.identity.desired_outcome,
            )
            return GateDecision(Admission.REFUSED, FORECLOSED_BY_COMPLETED_ACT)

        if holder.state == HolderState.RUNNING:
            # Issuing opposite commands concurrently to one actuator is worse
            # than waiting. A Tier D arrival latches instead; the safety
            # registry retries it from a loop that does not wait on this gate.
            reason = OPPOSING_ACT_RUNNING
            self._record_event(
                "refused",
                resource=identity.resource_key,
                reason=reason,
                contributor=contributor.trigger_name,
                latched=arriving_d,
            )
            return GateDecision(Admission.REFUSED, reason)

        if holder.state == HolderState.PROPOSAL:
            if tier_rank(tier) > tier_rank(holder.tier):
                holder.invalidated = True
                self._record_event(
                    "proposal_invalidated",
                    resource=identity.resource_key,
                    by=contributor.trigger_name,
                    proposal_id=holder.proposal_id,
                )
                displaced = holder
                decision = self._admit(
                    identity, tier, contributor, awaits_operator=awaits_operator
                )
                decision.displaced = displaced
                return decision
            self._record_event(
                "refused",
                resource=identity.resource_key,
                reason=OPPOSING_HIGHER_TIER_HOLDS,
                contributor=contributor.trigger_name,
            )
            return GateDecision(Admission.REFUSED, OPPOSING_HIGHER_TIER_HOLDS)

        # Reserved, not started.
        if tier_rank(tier) > tier_rank(holder.tier):
            displaced = holder
            displaced.state = HolderState.RETIRED
            displaced.done.set()
            self._record_event(
                "preempted",
                resource=identity.resource_key,
                holder=displaced.identity.desired_outcome,
                by=contributor.trigger_name,
            )
            decision = self._admit(
                identity, tier, contributor, awaits_operator=awaits_operator
            )
            decision.admission = Admission.PREEMPTED_HOLDER
            decision.displaced = displaced
            return decision

        if tier_rank(tier) == tier_rank(holder.tier):
            # Equal-tier opposing requests are both refused where refusal is
            # still possible — neither has started, so neither acts.
            holder.state = HolderState.RETIRED
            holder.done.set()
            self._records.pop(identity.resource_key, None)
            self._record_event(
                "refused",
                resource=identity.resource_key,
                reason=OPPOSING_EQUAL_TIER,
                contributor=contributor.trigger_name,
                holder_also_refused=True,
            )
            return GateDecision(Admission.REFUSED, OPPOSING_EQUAL_TIER)

        self._record_event(
            "refused",
            resource=identity.resource_key,
            reason=OPPOSING_HIGHER_TIER_HOLDS,
            contributor=contributor.trigger_name,
        )
        return GateDecision(Admission.REFUSED, OPPOSING_HIGHER_TIER_HOLDS)

    async def reply_admitted(self, token: _Record) -> bool:
        """Whether an operator's reply to *token*'s proposal may still act.

        A proposal a Tier D outcome displaced is not merely stale: acting on it
        would undo the protective act that displaced it. The contract requires
        the late reply to be refused and the refusal recorded, and this is the
        only thing that reads `invalidated` — without it the invalidation is a
        flag nothing consults.
        """
        async with self._lock:
            if token.invalidated:
                self._record_event(
                    "late_reply_refused",
                    resource=token.identity.resource_key,
                    proposal_id=token.proposal_id,
                    reason=PROPOSAL_INVALIDATED,
                )
                return False
            current = self._records.get(token.identity.resource_key)
            if current is not token:
                self._record_event(
                    "late_reply_refused",
                    resource=token.identity.resource_key,
                    proposal_id=token.proposal_id,
                    reason=PROPOSAL_NO_LONGER_HELD,
                )
                return False
            token.state = HolderState.RUNNING
            return True

    async def mark_proposal(self, token: _Record, proposal_id: str) -> None:
        """The holder has asked an operator and is waiting."""
        async with self._lock:
            if token.state in (HolderState.RESERVED,):
                token.state = HolderState.PROPOSAL
                token.proposal_id = proposal_id

    async def mark_running(self, token: _Record) -> None:
        """The holder's executor has been entered."""
        async with self._lock:
            token.state = HolderState.RUNNING

    async def mark_uncertain(self, token: _Record) -> None:
        """The driver call did not return within its timeout.

        Acceptance is what the driver reports, and silence is not a report. The
        command is neither accepted nor refused, and no opposing outcome is
        admitted while it stands.
        """
        async with self._lock:
            token.state = HolderState.UNCERTAIN
            self._record_event(
                "command_uncertain",
                resource=token.identity.resource_key,
                outcome=token.identity.desired_outcome,
            )

    async def retire(self, token: _Record, result: Any = None) -> None:
        """The attempt is over. A later request for the same outcome is a new act."""
        async with self._lock:
            if token.state == HolderState.UNCERTAIN:
                # An uncertain command is never retired into acceptance. It stays
                # in the way of an opposing outcome until something resolves it.
                return
            token.result = result
            token.done.set()
            if token.scope and token.scope in self._scopes:
                # The attempt is over; the foreclosure is not. It lasts until
                # the event that licensed it is settled.
                token.state = HolderState.HELD
                return
            token.state = HolderState.RETIRED
            if self._records.get(token.identity.resource_key) is token:
                self._records.pop(token.identity.resource_key, None)

    async def resolve_uncertain(self, token: _Record, accepted: bool) -> None:
        """The driver finally reported. Only this clears an uncertain command."""
        async with self._lock:
            if token.state != HolderState.UNCERTAIN:
                return
            token.state = HolderState.RETIRED
            token.result = accepted
            token.done.set()
            if self._records.get(token.identity.resource_key) is token:
                self._records.pop(token.identity.resource_key, None)
            self._record_event(
                "command_resolved",
                resource=token.identity.resource_key,
                accepted=accepted,
            )

    def state_of(self, resource_key: tuple[str, ...]) -> str:
        """The holder state for *resource_key*, or ``retired`` when unheld."""
        record = self._records.get(resource_key)
        return HolderState.RETIRED if record is None else record.state

    def uncertain_resources(self) -> list[tuple[str, ...]]:
        """Resources whose command was issued and whose physical outcome is unverified."""
        return [
            key
            for key, record in self._records.items()
            if record.state == HolderState.UNCERTAIN
        ]
