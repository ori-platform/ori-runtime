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
    # The key reserved for this dispatch's action-log row before it acts, so a
    # request that joins it can name it whatever order the two rows land in.
    record_key: str = ""
    # The holder's own record, settled when its row is handed to the writer, so
    # a joiner's row is written after it, never before.
    record_future: Any = None
    # The event this claim was made in, set by the gate. A joiner's event
    # forecloses on the act it joined as the admitting event does.
    scope: str = ""


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
    # Set when the executor is entered, by mark_running or an approved reply.
    entered: bool = False
    # Set when the operator was asked: the ask was accepted, or a console listens.
    asked: bool = False
    entries: dict[str, _Entry] = field(default_factory=dict)
    done: asyncio.Event = field(default_factory=asyncio.Event)

    @property
    def holds_tier_d(self) -> bool:
        return any(c.tier_d_granted for c in self.contributors)


@dataclass
class _Entry:
    """What one event's completed act still forecloses, kept apart from the record.

    The record describes one attempt and is replaced, retired or resolved; the
    event's foreclosure has to outlive all three.
    """

    identity: ResourceIdentity
    tier: str
    entered: bool
    ran: bool
    holds_tier_d: bool
    asked: bool = False
    # A copy taken when the attempt ended: a joiner's row names the holder's
    # reserved key and is written after the holder's row.
    contributors: tuple[Contributor, ...] = ()

    @property
    def forecloses(self) -> bool:
        return self.entered


@dataclass
class GateDecision:
    """The gate's answer, and the record it attaches to."""

    admission: str
    reason: str = ""
    token: Any = None
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
        # Open arbitration scopes, one per event being dispatched, each with the
        # entries its completed acts left. They clear only when the scope closes.
        self._scopes: dict[str, list[_Entry]] = {}

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
        self._scopes.setdefault(scope, [])
        return _ARBITRATION_SCOPE.set(scope)

    async def close_scope(
        self, scope: str, token: contextvars.Token[str] | None = None
    ) -> None:
        """End the scope and clear its entries, and nothing else.

        Done before any await, so a cancelled close still clears them. An
        uncertain command stays in flight: closing its event does not let an
        opposing outcome past it.
        """
        if token is not None:
            _ARBITRATION_SCOPE.reset(token)
        self._scopes.pop(scope, None)

    def foreclosures(self, resource_key: tuple[str, ...]) -> list[tuple[str, str]]:
        """``(outcome, tier)`` of every open event's foreclosing entry on *resource_key*."""
        return [
            (entry.identity.desired_outcome, entry.tier)
            for entries in self._scopes.values()
            for entry in entries
            if entry.forecloses and entry.identity.resource_key == resource_key
        ]

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
            if holder is not None and holder.state == HolderState.RETIRED:
                holder = None

            refused = self._refuse_opposing(holder, identity, tier, contributor)
            if refused is not None:
                return refused

            if holder is None:
                joined = self._join_completed(identity, tier, contributor)
                if joined is not None:
                    return joined
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

    def _refuse_opposing(
        self,
        holder: _Record | None,
        identity: ResourceIdentity,
        tier: str,
        contributor: Contributor,
    ) -> GateDecision | None:
        """Rules 1 to 3 of the order in ``docs/DISPATCH_PLAN.md``, before any join."""
        arriving_d = tier_rank(tier) >= tier_rank("D")
        entries = [
            entry
            for scoped in self._scopes.values()
            for entry in scoped
            if entry.forecloses
            and entry.identity.resource_key == identity.resource_key
            and opposes(entry.identity, identity)
        ]
        holder_opposes = holder is not None and opposes(holder.identity, identity)
        if arriving_d and (
            (holder_opposes and holder is not None and holder.holds_tier_d)
            or any(entry.holds_tier_d for entry in entries)
        ):
            # Nothing acts, so nothing is protected. Filing it as a routine
            # refusal would let a device that protects nothing look like a
            # device that made a decision.
            self._record_event(
                "safety_conflict",
                resource=identity.resource_key,
                arriving=identity.desired_outcome,
                contributor=contributor.trigger_name,
            )
            return GateDecision(
                Admission.REFUSED, UNRESOLVED_SAFETY_CONFLICT, safety_conflict=True
            )
        if holder_opposes and holder is not None:
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
        foreclosing = [e for e in entries if tier_rank(tier) <= tier_rank(e.tier)]
        if foreclosing:
            self._record_event(
                "refused",
                resource=identity.resource_key,
                reason=FORECLOSED_BY_COMPLETED_ACT,
                contributor=contributor.trigger_name,
                holder=foreclosing[0].identity.desired_outcome,
            )
            return GateDecision(Admission.REFUSED, FORECLOSED_BY_COMPLETED_ACT)
        return None

    def _join_completed(
        self, identity: ResourceIdentity, tier: str, contributor: Contributor
    ) -> GateDecision | None:
        """Join a completed act of the requester's own event, or return None.

        Tier D joins only an act that ran. Below Tier D, a proposal whose
        operator was asked and whose executor was never entered is joined too,
        so the event does not ask its NO again; a failed execution never is.
        """
        arriving_d = tier_rank(tier) >= tier_rank("D")
        entries = self._scopes.get(self._current_scope)
        for entry in entries or ():
            if entry.identity.join_key != identity.join_key:
                continue
            if entry.ran or (not arriving_d and not entry.entered and entry.asked):
                if entry.ran and entries is not None:
                    # The joiner's authority stands behind the act too, so the
                    # event forecloses at it. Execution is merged, licence not.
                    entries.append(
                        _Entry(
                            identity=entry.identity,
                            tier=tier,
                            entered=True,
                            ran=True,
                            holds_tier_d=contributor.tier_d_granted,
                            contributors=entry.contributors,
                        )
                    )
                self._record_event(
                    "coalesced",
                    resource=identity.resource_key,
                    holder_state="completed",
                    contributor=contributor.trigger_name,
                )
                return GateDecision(Admission.JOINED, token=entry)
        return None

    def _admit(
        self,
        identity: ResourceIdentity,
        tier: str,
        contributor: Contributor,
        *,
        awaits_operator: bool = False,
    ) -> GateDecision:
        contributor.scope = self._current_scope
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

        contributor.scope = self._current_scope
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
        # The safety conflict and an uncertain holder were decided in
        # _refuse_opposing, ahead of this.
        arriving_d = tier_rank(tier) >= tier_rank("D")

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
            token.entered = True
            return True

    async def mark_proposal(self, token: _Record, proposal_id: str) -> None:
        """The holder has asked an operator and is waiting."""
        async with self._lock:
            token.asked = True
            token.proposal_id = proposal_id
            if token.state in (HolderState.RESERVED,):
                token.state = HolderState.PROPOSAL

    async def mark_running(self, token: _Record) -> None:
        """The holder's executor has been entered."""
        async with self._lock:
            token.state = HolderState.RUNNING
            token.entered = True

    async def mark_uncertain(self, token: _Record) -> None:
        """The driver call did not return within its timeout.

        Acceptance is what the driver reports, and silence is not a report. The
        command is neither accepted nor refused, and no opposing outcome is
        admitted while it stands.
        """
        async with self._lock:
            token.state = HolderState.UNCERTAIN
            token.entered = True
            self._record_entries(token, ran=False)
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
            # The attempt is over; its event's foreclosure is not.
            self._record_entries(token, ran=result is True)
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
            # Every open claimant, joiners since the uncertainty included, either way.
            self._record_entries(token, ran=accepted)
            if self._records.get(token.identity.resource_key) is token:
                self._records.pop(token.identity.resource_key, None)
            self._record_event(
                "command_resolved",
                resource=token.identity.resource_key,
                accepted=accepted,
            )

    def _record_entries(self, token: _Record, *, ran: bool) -> None:
        """Record *token*'s current account under every open event that claims it.

        The admitting event and each event whose request joined the attempt
        foreclose alike, each at its own highest claim. Called whenever the
        attempt's account changes: it ends, it becomes uncertain, or the driver
        reports, either way, so a request that joined while it was uncertain is
        counted then; until then the uncertain record refuses every opposite
        itself. An existing entry is
        replaced, never mutated; a closed event gets nothing, so a late callback
        cannot recreate its foreclosure.
        """
        for scope in self._claiming_scopes(token):
            entries = self._scopes.get(scope)
            if entries is None:
                continue
            new = self._entry_for(token, scope, ran=ran)
            old = token.entries.get(scope)
            if old is not None and old in entries:
                entries[entries.index(old)] = new
            else:
                entries.append(new)
            token.entries[scope] = new

    @staticmethod
    def _claiming_scopes(token: _Record) -> list[str]:
        scopes = [token.scope, *(c.scope for c in token.contributors)]
        return [s for s in dict.fromkeys(scopes) if s]

    @staticmethod
    def _entry_for(token: _Record, scope: str, *, ran: bool) -> _Entry:
        # The highest authority this event put behind the act.
        claims = [c for c in token.contributors if c.scope == scope]
        tiers = [c.dispatch_tier for c in claims]
        if token.scope == scope:
            tiers.append(token.tier)
        return _Entry(
            identity=token.identity,
            tier=max(tiers, key=tier_rank),
            entered=token.entered,
            ran=ran and token.entered,
            holds_tier_d=any(c.tier_d_granted for c in claims),
            asked=token.asked,
            contributors=tuple(token.contributors),
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
