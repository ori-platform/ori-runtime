# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Foreclosure belongs to the event, not to the record holding the resource.

``docs/DISPATCH_PLAN.md`` (*Foreclosure belongs to the event*): a completed act
keeps its event's lower-authority opposite out however the resource's record is
later replaced, retired or resolved; only its own event can join it; a failed
execution is never joined; and its entry clears only when its event closes.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

import pytest

from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.dispatch_coordinator import DispatchCoordinator
from ori.reasoning.dispatch_plan import ResourceIdentity, resource_identity
from ori.reasoning.elevator import IntelligenceElevator
from ori.reasoning.resource_gate import (
    _ARBITRATION_SCOPE,
    FORECLOSED_BY_COMPLETED_ACT,
    OPPOSING_COMMAND_UNCERTAIN,
    UNRESOLVED_SAFETY_CONFLICT,
    Admission,
    Contributor,
    HolderState,
    ResourceGate,
)
from tests.test_dispatch_plan import BOUND, ZONE, FakeSkill, _event, _trigger

TRIP = "close_gas_valve"
NOTICE = "alert_whatsapp"


def _identity(action: str) -> ResourceIdentity:
    identity = resource_identity(action, zone_identity_key=ZONE)
    assert identity is not None
    return identity


OPEN = _identity(TRIP)
CLOSE = _identity("release_relay")


def _who(trigger: str, tier: str) -> Contributor:
    return Contributor(
        skill_name="s",
        trigger_name=trigger,
        action=TRIP,
        dispatch_tier=tier,
        tier_d_granted=tier == "D",
        record_key=f"key-{trigger}",
    )


async def _completed(
    gate: ResourceGate, identity: Any, tier: str, ran: bool, trigger: str = "t1"
) -> Any:
    decision = await gate.request(identity, tier, _who(trigger, tier))
    assert decision.admission == Admission.ADMITTED, decision
    await gate.mark_running(decision.token)
    await gate.retire(decision.token, ran)
    return decision.token


class TestReadingsThroughTheDispatcher:
    """The reproductions of #978's defects 1 and 2, through the real path."""

    @pytest.mark.parametrize("fault", ["ran", "raises", "returns_false"])
    async def test_every_reading_attempts_while_an_earlier_notice_is_pending(
        self, fault: str
    ):
        gate = ResourceGate()
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        dispatcher.bind_resource_gate(gate, BOUND)
        trips: list[str] = []

        async def trip(action: str, _context: Any) -> bool:
            trips.append(action)
            if fault == "raises":
                raise RuntimeError("driver fault")
            return fault == "ran"

        async def notice(_action: str, _context: Any) -> None:
            await asyncio.sleep(0.4)

        dispatcher.register_executor(TRIP, trip)
        dispatcher.register_executor(NOTICE, notice)
        skill = FakeSkill(
            triggers=[_trigger("trip", "D", bypass=True)],
            actions={
                "available": [
                    {"name": TRIP, "tier": "D"},
                    {"name": NOTICE, "tier": "A"},
                ],
                "defaults": {"trip": [TRIP, NOTICE]},
            },
        )
        coordinator = DispatchCoordinator(
            elevator=IntelligenceElevator(),
            dispatcher=dispatcher,
            state_store=None,
            gate=gate,
        )
        coordinator.set_binding(BOUND)
        coordinator.add_skill(skill)

        readings = []
        for _ in range(5):
            readings.append(asyncio.create_task(coordinator.dispatch_event(_event())))
            await asyncio.sleep(0.02)
        await asyncio.gather(*readings)
        await coordinator.drain()

        assert trips == [TRIP] * 5
        assert gate.foreclosures(ZONE) == []


class TestJoining:
    @pytest.mark.parametrize(
        "ran, same_event, joined",
        [
            (True, True, True),
            (False, True, False),
            (True, False, False),
            (False, False, False),
        ],
    )
    async def test_tier_d_joins_only_an_act_that_ran_in_its_own_event(
        self, ran: bool, same_event: bool, joined: bool
    ):
        gate = ResourceGate()
        first_scope = gate.open_scope("a")
        first = await _completed(gate, OPEN, "D", ran)
        other = None if same_event else gate.open_scope("b")
        second = await gate.request(OPEN, "D", _who("t2", "D"))
        if other is not None:
            await gate.close_scope("b", other)
        await gate.close_scope("a", first_scope)

        assert second.admission == (Admission.JOINED if joined else Admission.ADMITTED)
        if joined:
            assert (
                second.token.contributors[0].record_key
                == first.contributors[0].record_key
            )

    async def test_a_declined_proposal_suppresses_a_repeat_ask_in_its_event(self):
        gate = ResourceGate()
        scope = gate.open_scope("a")
        first = await gate.request(OPEN, "C", _who("t1", "C"), awaits_operator=True)
        await gate.mark_proposal(first.token, "P1")
        await gate.retire(first.token, False)
        again = await gate.request(OPEN, "C", _who("t2", "C"), awaits_operator=True)
        trip = await gate.request(OPEN, "D", _who("t3", "D"))
        await gate.mark_running(trip.token)
        await gate.retire(trip.token, False)
        await gate.close_scope("a", scope)
        later = await gate.request(OPEN, "C", _who("t4", "C"), awaits_operator=True)

        assert again.admission == Admission.JOINED
        assert trip.admission == Admission.ADMITTED, "a NO never satisfies a trip"
        assert later.admission != Admission.JOINED

    async def test_an_approved_execution_that_failed_is_never_joined(self):
        gate = ResourceGate()
        scope = gate.open_scope("a")
        first = await gate.request(OPEN, "C", _who("t1", "C"), awaits_operator=True)
        assert await gate.reply_admitted(first.token)
        await gate.retire(first.token, False)
        again = await gate.request(OPEN, "C", _who("t2", "C"), awaits_operator=True)
        await gate.close_scope("a", scope)

        assert again.admission == Admission.ADMITTED

    async def test_a_matching_entry_cannot_hide_a_conflicting_one(self):
        gate = ResourceGate()
        a = gate.open_scope("a")
        await _completed(gate, OPEN, "C", True)
        b = gate.open_scope("b")
        await _completed(gate, CLOSE, "D", True, trigger="t2")
        refused = await gate.request(OPEN, "C", _who("t3", "C"))
        await gate.close_scope("b", b)
        await gate.close_scope("a", a)

        assert refused.reason == FORECLOSED_BY_COMPLETED_ACT


class TestForeclosureOutlivesTheRecord:
    @pytest.mark.parametrize("first_ran", [True, False])
    async def test_a_readmitted_act_keeps_the_first_event_s_foreclosure(
        self, first_ran: bool
    ):
        gate = ResourceGate()
        a = gate.open_scope("a")
        await _completed(gate, OPEN, "D", first_ran)
        b = gate.open_scope("b")
        await _completed(gate, OPEN, "D", True, trigger="t2")
        await gate.close_scope("b", b)

        opposite = await gate.request(CLOSE, "C", _who("t3", "C"))
        assert opposite.reason == FORECLOSED_BY_COMPLETED_ACT
        await gate.close_scope("a", a)
        assert gate.foreclosures(ZONE) == []

    @pytest.mark.parametrize("close_first", [False, True])
    async def test_uncertainty_resolved_before_or_after_its_event_closes(
        self, close_first: bool
    ):
        gate = ResourceGate()
        a = gate.open_scope("a")
        decision = await gate.request(OPEN, "D", _who("t1", "D"))
        await gate.mark_running(decision.token)
        await gate.mark_uncertain(decision.token)
        if close_first:
            await gate.close_scope("a", a)
            # Closing the event leaves the uncertain command in the way.
            blocked = await gate.request(CLOSE, "C", _who("t2", "C"))
            assert blocked.reason == OPPOSING_COMMAND_UNCERTAIN
            await gate.resolve_uncertain(decision.token, True)
            assert gate.foreclosures(ZONE) == [], "a late resolution recreated it"
        else:
            await gate.resolve_uncertain(decision.token, True)
            opposite = await gate.request(CLOSE, "C", _who("t2", "C"))
            assert opposite.reason == FORECLOSED_BY_COMPLETED_ACT
            await gate.close_scope("a", a)
        assert gate.state_of(ZONE) == HolderState.RETIRED

    async def test_an_invalidated_proposal_and_an_equal_tier_refusal_lose_nothing(
        self,
    ):
        gate = ResourceGate()
        a = gate.open_scope("a")
        await _completed(gate, OPEN, "B", False)
        b = gate.open_scope("b")
        proposal = await gate.request(OPEN, "C", _who("t2", "C"), awaits_operator=True)
        trip = await gate.request(OPEN, "D", _who("t3", "D"))
        assert trip.displaced is proposal.token
        await gate.mark_running(trip.token)
        await gate.retire(trip.token, True)
        await gate.close_scope("b", b)
        reserved = await gate.request(OPEN, "B", _who("t4", "B"))
        clash = await gate.request(CLOSE, "B", _who("t5", "B"))

        assert reserved.admission == Admission.ADMITTED
        assert clash.reason == FORECLOSED_BY_COMPLETED_ACT
        await gate.close_scope("a", a)

    async def test_late_callbacks_of_a_closed_event_change_nothing(self):
        gate = ResourceGate()
        a = gate.open_scope("a")
        first = await gate.request(OPEN, "C", _who("t1", "C"))
        await gate.mark_running(first.token)
        await gate.close_scope("a", a)
        b = gate.open_scope("b")
        await gate.retire(first.token, True)
        second = await gate.request(OPEN, "D", _who("t2", "D"))
        assert second.admission == Admission.ADMITTED
        await gate.mark_running(second.token)
        await gate.retire(first.token, False)
        await gate.resolve_uncertain(first.token, True)

        assert gate.state_of(ZONE) == HolderState.RUNNING, "a late A evicted B"
        assert gate.foreclosures(ZONE) == []
        await gate.retire(second.token, True)
        assert gate.foreclosures(ZONE) == [("open_protected_circuit", "D")]
        await gate.close_scope("b", b)

    async def test_opposing_tier_d_against_a_tier_d_entry_is_a_safety_conflict(self):
        gate = ResourceGate()
        a = gate.open_scope("a")
        await _completed(gate, OPEN, "D", True)
        b = gate.open_scope("b")
        conflict = await gate.request(CLOSE, "D", _who("t2", "D"))
        await gate.close_scope("b", b)
        await gate.close_scope("a", a)

        assert conflict.reason == UNRESOLVED_SAFETY_CONFLICT
        assert conflict.safety_conflict


class TestEntriesLiveOnlyAsLongAsOpenEvents:
    async def test_a_cancelled_close_still_clears_its_entries(self):
        gate = ResourceGate()
        a = gate.open_scope("a")
        await _completed(gate, OPEN, "D", True)
        closing = asyncio.ensure_future(gate.close_scope("a", a))
        closing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await closing
        # A coroutine cancelled before its first step never ran; the
        # coordinator awaits it directly, so model that path too.
        await gate.close_scope("a")
        assert gate.foreclosures(ZONE) == []

    async def test_a_cancelled_event_closes_its_scope(self):
        gate = ResourceGate()
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        dispatcher.bind_resource_gate(gate, BOUND)
        started = asyncio.Event()

        async def trip(_action: str, _context: Any) -> bool:
            return True

        async def notice(_action: str, _context: Any) -> None:
            started.set()
            await asyncio.sleep(0.3)

        dispatcher.register_executor(TRIP, trip)
        dispatcher.register_executor(NOTICE, notice)
        skill = FakeSkill(
            triggers=[_trigger("trip", "D", bypass=True)],
            actions={
                "available": [
                    {"name": TRIP, "tier": "D"},
                    {"name": NOTICE, "tier": "A"},
                ],
                "defaults": {"trip": [TRIP, NOTICE]},
            },
        )
        coordinator = DispatchCoordinator(
            elevator=IntelligenceElevator(),
            dispatcher=dispatcher,
            state_store=None,
            gate=gate,
        )
        coordinator.set_binding(BOUND)
        coordinator.add_skill(skill)
        running = asyncio.create_task(coordinator.dispatch_event(_event()))
        await asyncio.wait_for(started.wait(), 10)
        assert gate.foreclosures(ZONE) == [("open_protected_circuit", "D")]

        running.cancel()
        await asyncio.gather(running, return_exceptions=True)
        await coordinator.drain()
        assert gate.foreclosures(ZONE) == []


class TestSeededModel:
    """Random sequences against the rules as the contract states them.

    The model tracks only what each event completed, from the operations it
    issued, and checks every gate answer against three rules: an opposite at
    or below an open completed act's tier is refused; nothing joins a completed
    act of another event or a failed execution; and Tier D joins only an act
    that ran.
    """

    @pytest.mark.parametrize("seed", range(400))
    async def test_the_gate_keeps_the_event_rules(self, seed: int):
        rng = random.Random(seed)
        gate = ResourceGate()
        tiers = ["B", "C", "D"]
        open_scopes: dict[str, Any] = {}
        # scope -> [(outcome, tier, entered, ran)]
        completed: dict[str, list[tuple[Any, str, bool, bool | None]]] = {}
        live: list[tuple[Any, str, Any, str]] = []  # token, scope, identity, tier
        # Every event that claimed an in-flight attempt, the joiners' included.
        claims: dict[int, list[tuple[str, str]]] = {}
        # Uncertain commands, resolved by an operation of their own, so a
        # request can join one before the driver reports.
        uncertain: dict[int, tuple[Any, Any]] = {}  # id -> token, identity
        n = 0

        def record(token_id: int, identity: Any, ran: bool | None) -> None:
            for claimant, claimed_tier in claims.get(token_id, []):
                if claimant in completed:
                    completed[claimant].append((identity, claimed_tier, True, ran))

        for _ in range(80):
            op = rng.choice(
                ["open", "close", "request", "request", "end", "uncertain", "resolve"]
            )
            n += 1
            if op == "open" or not open_scopes:
                name = f"e{n}"
                open_scopes[name] = gate.open_scope(name)
                completed[name] = []
                continue
            if op == "close":
                name = rng.choice(sorted(open_scopes))
                await gate.close_scope(name)
                del open_scopes[name], completed[name]
                continue
            if op == "resolve" and uncertain:
                key = rng.choice(sorted(uncertain))
                token, identity = uncertain.pop(key)
                await gate.resolve_uncertain(token, rng.random() < 0.5)
                # Joinable or not, the model checks only refusals for it.
                record(key, identity, None)
                continue
            if op in ("end", "uncertain") and live:
                token, scope, identity, tier = live.pop(rng.randrange(len(live)))
                await gate.mark_running(token)
                if op == "uncertain":
                    await gate.mark_uncertain(token)
                    uncertain[id(token)] = (token, identity)
                    record(id(token), identity, None)
                else:
                    ran = rng.random() < 0.5
                    await gate.retire(token, ran)
                    record(id(token), identity, ran)
                continue

            scope = rng.choice(sorted(open_scopes))
            identity = rng.choice([OPEN, CLOSE])
            tier = rng.choice(tiers)
            # Requests run inside their event's context, as the coordinator's do.
            token_ctx = _ARBITRATION_SCOPE.set(scope)
            decision = await gate.request(identity, tier, _who(f"t{n}", tier))
            _ARBITRATION_SCOPE.reset(token_ctx)

            rank = tiers.index(tier)
            foreclosing = [
                entry
                for entries in completed.values()
                for entry in entries
                if entry[0] is not identity
                and entry[2]
                and rank <= tiers.index(entry[1])
            ]
            if foreclosing:
                assert decision.admission == Admission.REFUSED, (seed, n)
            if decision.admission == Admission.JOINED and decision.token is not None:
                if not hasattr(decision.token, "state"):  # a completed entry
                    own = completed.get(scope, [])
                    assert any(e[0] is identity for e in own), (seed, n)
                    assert decision.token.entered is False or decision.token.ran
                    if tier == "D":
                        assert decision.token.ran, (seed, n)
            if decision.admission == Admission.ADMITTED:
                live.append((decision.token, scope, identity, tier))
                claims[id(decision.token)] = [(scope, tier)]
            elif decision.admission == Admission.JOINED and hasattr(
                decision.token, "state"
            ):
                claims.setdefault(id(decision.token), []).append((scope, tier))
                if id(decision.token) in uncertain:
                    # Joined while uncertain: its event claims it from now.
                    completed[scope].append((identity, tier, True, None))

        for name in list(open_scopes):
            await gate.close_scope(name)
        assert gate.foreclosures(ZONE) == []


class TestWhatAnEntryRecords:
    async def test_a_proposal_that_never_acted_forecloses_nothing(self):
        gate = ResourceGate()
        a = gate.open_scope("a")
        first = await gate.request(OPEN, "C", _who("t1", "C"), awaits_operator=True)
        await gate.retire(first.token, False)
        b = gate.open_scope("b")
        opposite = await gate.request(CLOSE, "C", _who("t2", "C"))
        await gate.close_scope("b", b)
        await gate.close_scope("a", a)

        assert opposite.admission == Admission.ADMITTED
        assert gate.foreclosures(ZONE) == []

    async def test_an_accepted_resolution_in_an_open_event_can_be_joined(self):
        gate = ResourceGate()
        a = gate.open_scope("a")
        decision = await gate.request(OPEN, "D", _who("t1", "D"))
        await gate.mark_running(decision.token)
        await gate.mark_uncertain(decision.token)
        await gate.resolve_uncertain(decision.token, True)
        joined = await gate.request(OPEN, "D", _who("t2", "D"))
        await gate.close_scope("a", a)

        assert joined.admission == Admission.JOINED


class TestAJoinerSAuthorityForecloses:
    """A Tier D trip that joined a lower-tier act still forecloses at Tier D."""

    @pytest.mark.parametrize("completed_first", [False, True])
    @pytest.mark.parametrize(
        "arriving, reason",
        [
            ("C", FORECLOSED_BY_COMPLETED_ACT),
            ("D", UNRESOLVED_SAFETY_CONFLICT),
        ],
    )
    async def test_a_lower_act_joined_by_tier_d(
        self, completed_first: bool, arriving: str, reason: str
    ):
        gate = ResourceGate()
        a = gate.open_scope("a")
        first = await gate.request(OPEN, "B", _who("t1", "B"))
        if completed_first:
            await gate.mark_running(first.token)
            await gate.retire(first.token, True)
            joined = await gate.request(OPEN, "D", _who("t2", "D"))
        else:
            joined = await gate.request(OPEN, "D", _who("t2", "D"))
            await gate.mark_running(first.token)
            await gate.retire(first.token, True)
        assert joined.admission == Admission.JOINED
        b = gate.open_scope("b")
        opposite = await gate.request(CLOSE, arriving, _who("t3", arriving))
        await gate.close_scope("b", b)
        await gate.close_scope("a", a)

        assert opposite.reason == reason


class TestReviewFindings:
    async def test_a_proposal_no_operator_was_asked_is_not_joined(self):
        gate = ResourceGate()
        a = gate.open_scope("a")
        first = await gate.request(OPEN, "C", _who("t1", "C"), awaits_operator=True)
        await gate.retire(first.token, False)  # the workflow raised before asking
        again = await gate.request(OPEN, "C", _who("t2", "C"), awaits_operator=True)
        await gate.close_scope("a", a)

        assert again.admission == Admission.ADMITTED

    @pytest.mark.parametrize(
        "arriving, reason",
        [
            ("C", FORECLOSED_BY_COMPLETED_ACT),
            ("D", UNRESOLVED_SAFETY_CONFLICT),
        ],
    )
    async def test_a_trip_that_joined_another_event_s_act_forecloses_for_its_event(
        self, arriving: str, reason: str
    ):
        gate = ResourceGate()
        a_ctx = gate.open_scope("a")
        held = await gate.request(OPEN, "D", _who("t1", "D"))
        await gate.mark_running(held.token)
        _ARBITRATION_SCOPE.reset(a_ctx)
        b_ctx = gate.open_scope("b")
        joined = await gate.request(OPEN, "D", _who("t2", "D"))
        assert joined.admission == Admission.JOINED
        await gate.retire(held.token, True)
        await gate.close_scope("a")

        opposite = await gate.request(CLOSE, arriving, _who("t3", arriving))
        await gate.close_scope("b", b_ctx)

        assert opposite.reason == reason
        assert gate.foreclosures(ZONE) == []

    async def test_a_cancel_landing_in_the_final_gather_still_closes_the_event(self):
        gate = ResourceGate()
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        dispatcher.bind_resource_gate(gate, BOUND)

        async def trip(_action: str, _context: Any) -> bool:
            return True

        async def notice(_action: str, _context: Any) -> None:
            await asyncio.sleep(1.0)

        dispatcher.register_executor(TRIP, trip)
        dispatcher.register_executor(NOTICE, notice)
        skill = FakeSkill(
            triggers=[_trigger("trip", "D", bypass=True)],
            actions={
                "available": [
                    {"name": TRIP, "tier": "D"},
                    {"name": NOTICE, "tier": "A"},
                ],
                "defaults": {"trip": [TRIP, NOTICE]},
            },
        )
        coordinator = DispatchCoordinator(
            elevator=IntelligenceElevator(),
            dispatcher=dispatcher,
            state_store=None,
            gate=gate,
        )
        coordinator.set_binding(BOUND)
        coordinator.add_skill(skill)
        running = asyncio.create_task(coordinator.dispatch_event(_event()))
        # Past the head start, so the cancel lands in the final gather.
        await asyncio.sleep(0.6)
        assert gate.foreclosures(ZONE) == [("open_protected_circuit", "D")]
        running.cancel()
        await asyncio.gather(running, return_exceptions=True)

        assert gate.foreclosures(ZONE) == []


class TestTheDispatcherMarksAnAskOnlyWhenOneWentOut:
    @pytest.mark.parametrize(
        "outcome, has_comms, console, asked",
        [
            ("accepted", True, False, True),
            ("refused", True, False, False),
            ("raises", True, False, False),
            ("refused", False, True, True),
            ("refused", False, False, False),
        ],
    )
    async def test_ask(self, outcome: str, has_comms: bool, console: bool, asked: bool):
        from ori.actions.alert_delivery import AlertSendReceipt

        class Sender:
            async def send(self, **_kwargs: Any) -> AlertSendReceipt:
                if outcome == "raises":
                    raise RuntimeError("provider down")
                if outcome == "accepted":
                    return AlertSendReceipt(accepted=True, channel="sms")
                return AlertSendReceipt.refused(channel="sms")

        gate = ResourceGate()
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        dispatcher.bind_resource_gate(gate, BOUND)
        dispatcher._alert_sender = Sender()  # type: ignore[assignment]
        dispatcher._local_console_enabled = console
        held = await gate.request(OPEN, "C", _who("t1", "C"), awaits_operator=True)

        _receipt, listening = await dispatcher._ask_operator(
            object(), "+2348000000000", has_comms, TRIP, held.token, "P1"
        )

        assert held.token.asked is asked
        assert listening is (console and not has_comms)


class TestALateClaimOnAnUncertainCommand:
    """A request that joins a command already uncertain claims it from then on,
    whatever the driver later reports and whichever event closes first."""

    @pytest.mark.parametrize("accepted", [True, False])
    @pytest.mark.parametrize("cross_event", [True, False])
    @pytest.mark.parametrize("close", ["before", "after", "never"])
    async def test_the_joiner_s_event_forecloses_at_its_own_claim(
        self, accepted: bool, cross_event: bool, close: str
    ):
        gate = ResourceGate()
        a_ctx = gate.open_scope("a")
        held = await gate.request(OPEN, "B", _who("t1", "B"))
        await gate.mark_running(held.token)
        await gate.mark_uncertain(held.token)
        joiner_scope = "a"
        if cross_event:
            _ARBITRATION_SCOPE.reset(a_ctx)
            gate.open_scope("b")
            joiner_scope = "b"
        joined = await gate.request(OPEN, "D", _who("t2", "D"))
        assert joined.admission == Admission.JOINED
        if cross_event and close == "before":
            await gate.close_scope("a")
        await gate.resolve_uncertain(held.token, accepted)
        if cross_event and close == "after":
            await gate.close_scope("a")

        opposite = await gate.request(CLOSE, "C", _who("t3", "C"))
        conflict = await gate.request(CLOSE, "D", _who("t4", "D"))

        assert opposite.reason == FORECLOSED_BY_COMPLETED_ACT
        assert conflict.reason == UNRESOLVED_SAFETY_CONFLICT
        open_claimants = 1 if not cross_event or close != "never" else 2
        assert len(gate.foreclosures(ZONE)) == open_claimants, "one entry per event"
        assert ("open_protected_circuit", "D") in gate.foreclosures(ZONE)
        await gate.close_scope(joiner_scope)
        await gate.close_scope("a")
        assert gate.foreclosures(ZONE) == []

    async def test_a_closed_joiner_gets_nothing_back_from_a_late_resolution(self):
        gate = ResourceGate()
        a_ctx = gate.open_scope("a")
        held = await gate.request(OPEN, "B", _who("t1", "B"))
        await gate.mark_running(held.token)
        await gate.mark_uncertain(held.token)
        _ARBITRATION_SCOPE.reset(a_ctx)
        gate.open_scope("b")
        await gate.request(OPEN, "D", _who("t2", "D"))
        await gate.close_scope("b")
        await gate.close_scope("a")
        await gate.resolve_uncertain(held.token, True)

        assert gate.foreclosures(ZONE) == []
