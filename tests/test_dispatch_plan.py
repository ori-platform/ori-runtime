# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""What runs, at what authority, against which resource.

The obligations in ``docs/DISPATCH_PLAN.md`` are the subject. Tests permute
trigger declaration order rather than asserting one arrangement, because
declaration order deciding the outcome is the defect.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ori.network.events import OriEvent, SensorReading
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.dispatch_coordinator import DispatchCoordinator
from ori.reasoning.dispatch_plan import (
    CLOSE_PROTECTED_CIRCUIT,
    OPEN_PROTECTED_CIRCUIT,
    BindingView,
    DispatchOutcome,
    assign_action_tier,
    consumes_cooldown,
    is_informational,
    opposes,
    resource_identity,
    strongest_outcome,
)
from ori.reasoning.elevator import IntelligenceElevator
from ori.reasoning.resource_gate import (
    OPPOSING_ACT_RUNNING,
    OPPOSING_COMMAND_UNCERTAIN,
    OPPOSING_EQUAL_TIER,
    PROPOSAL_INVALIDATED,
    UNRESOLVED_SAFETY_CONFLICT,
    Admission,
    Contributor,
    HolderState,
    ResourceGate,
)
from ori.utils.time_utils import now_ms

ZONE = ("local_gpio", "pin:26")
BOUND = BindingView(
    zone_identity_key=ZONE,
    binding_revision="7",
    consequence_by_outcome={
        OPEN_PROTECTED_CIRCUIT: "hard",
        CLOSE_PROTECTED_CIRCUIT: "hard",
    },
)


class FakeSkill:
    """A skill-shaped object whose trigger order the test controls."""

    def __init__(
        self,
        triggers: list[dict[str, Any]],
        actions: dict[str, Any],
        *,
        name: str = "fake-skill",
        first_party: bool = True,
    ) -> None:
        self.name = name
        self.version = "1.0.0"
        self.triggers: list[Any] = list(triggers)
        self.actions = actions
        self.config: dict[str, Any] = {}
        self.hooks = None
        self.first_party = first_party
        self.sensors_required = [{"type": "current_clamp"}]

    def get_default_actions(self, _sensor_type: str) -> list[str]:
        return []


def _event(value: float = 5.0, sensor_type: str = "current_clamp") -> OriEvent:
    reading = SensorReading(
        sensor_id="load-current",
        sensor_type=sensor_type,
        value=value,
        unit="ampere",
        timestamp=now_ms(),
        quality=1.0,
    )
    return OriEvent.from_reading(reading, "test-device")


def _trigger(name: str, tier: str, *, bypass: bool = False) -> dict[str, Any]:
    return {
        "name": name,
        "condition": "value > 3.0",
        "action_tier": tier,
        "bypass_llm": bypass,
        "cooldown_seconds": 0,
    }


def _coordinator(
    skill: Any,
    dispatcher: Any,
    *,
    binding: BindingView | None = BOUND,
    elevator: Any = None,
) -> DispatchCoordinator:
    coordinator = DispatchCoordinator(
        elevator=elevator or IntelligenceElevator(),
        dispatcher=dispatcher,
        state_store=None,
    )
    coordinator.set_binding(binding)
    coordinator.add_skill(skill)
    return coordinator


def _dispatcher_double(executors: tuple[str, ...] = ()) -> Any:
    double = AsyncMock()
    double._executors = dict.fromkeys(executors, object())
    return double


async def _dispatched(dispatcher: Any) -> list[tuple[str, str]]:
    await asyncio.sleep(0.05)
    return [
        (call.kwargs["action"], call.kwargs["tier"])
        for call in dispatcher.dispatch.call_args_list
    ]


# ── declaration order is not authority ───────────────────────────────────────


class TestDeclarationOrder:
    @pytest.mark.parametrize("order", [("notice", "trip"), ("trip", "notice")])
    async def test_both_orders_produce_identical_outcomes(self, order):
        """`[A, D]` and `[D, A]` are the same device."""
        by_name = {
            "notice": _trigger("notice", "A"),
            "trip": _trigger("trip", "D", bypass=True),
        }
        skill = FakeSkill(
            triggers=[by_name[n] for n in order],
            actions={
                "available": [
                    {"name": "alert_whatsapp", "tier": "A"},
                    {"name": "close_gas_valve", "tier": "D"},
                ],
                "defaults": {
                    "notice": ["alert_whatsapp"],
                    "trip": ["close_gas_valve"],
                },
            },
        )
        dispatcher = _dispatcher_double(("close_gas_valve", "alert_whatsapp"))
        await _coordinator(skill, dispatcher).dispatch_event(_event())

        assert sorted(await _dispatched(dispatcher)) == sorted(
            [("close_gas_valve", "D"), ("alert_whatsapp", "A")]
        )

    async def test_a_tier_c_proposal_below_a_tier_a_notice_still_reaches_dispatch(self):
        """The shipped shape: byte-identical conditions, Tier A declared first.

        The Tier C action could never be proposed — no approval request, no log
        line, nothing — because a winner was selected by comparing one match's
        name against the handler's own trigger.
        """
        skill = FakeSkill(
            triggers=[_trigger("notice", "A"), _trigger("candidate", "C")],
            actions={
                "available": [
                    {"name": "alert_whatsapp", "tier": "A"},
                    {"name": "terminate_process", "tier": "C"},
                ],
                "defaults": {
                    "notice": ["alert_whatsapp"],
                    "candidate": ["terminate_process"],
                },
            },
        )
        dispatcher = _dispatcher_double(("terminate_process", "alert_whatsapp"))
        await _coordinator(skill, dispatcher).dispatch_event(_event())

        dispatched = await _dispatched(dispatcher)
        assert ("terminate_process", "C") in dispatched
        assert ("alert_whatsapp", "A") in dispatched

    async def test_a_tier_d_match_is_attempted_before_reasoning_is_scheduled(self):
        """Preempt means evaluated and attempted before lower-authority work.

        Across the whole discovery set, not within one skill: the Tier D trip
        lives in a second skill that nothing had discovered when the first
        skill's notice would otherwise have been scheduled.
        """
        order: list[str] = []

        notice_skill = FakeSkill(
            triggers=[_trigger("notice", "A")],
            actions={
                "available": [{"name": "alert_whatsapp", "tier": "A"}],
                "defaults": {"notice": ["alert_whatsapp"]},
            },
            name="notifier",
        )
        trip_skill = FakeSkill(
            triggers=[_trigger("trip", "D", bypass=True)],
            actions={
                "available": [{"name": "close_gas_valve", "tier": "D"}],
                "defaults": {"trip": ["close_gas_valve"]},
            },
            name="protector",
        )

        dispatcher = _dispatcher_double(("close_gas_valve", "alert_whatsapp"))

        async def record(**kwargs):
            order.append(f"{kwargs['action']}@{kwargs['tier']}")

        dispatcher.dispatch.side_effect = record

        coordinator = _coordinator(notice_skill, dispatcher)
        coordinator.add_skill(trip_skill)
        await coordinator.dispatch_event(_event())
        await asyncio.sleep(0.05)

        assert order[0] == "close_gas_valve@D", order
        assert "alert_whatsapp@A" in order


# ── the two axes ─────────────────────────────────────────────────────────────


class TestActionTier:
    def test_a_notification_in_a_tier_d_plan_is_tier_a(self):
        planned = assign_action_tier(
            action="alert_whatsapp",
            incident_tier="D",
            declared_tier="D",
            bypass_llm=True,
            first_party=True,
            declared_actions=("alert_whatsapp",),
            binding=BOUND,
            has_executor=True,
        )
        assert planned.dispatch_tier == "A"
        assert planned.tier_d_granted is False

    def test_a_notification_in_a_tier_c_plan_needs_no_approval(self):
        planned = assign_action_tier(
            action="alert_whatsapp",
            incident_tier="C",
            declared_tier="A",
            bypass_llm=False,
            first_party=True,
            declared_actions=("alert_whatsapp",),
            binding=BOUND,
            has_executor=True,
        )
        assert planned.dispatch_tier == "A"

    def test_a_reversible_action_is_not_promoted_by_a_hard_incident(self):
        planned = assign_action_tier(
            action="terminate_process",
            incident_tier="C",
            declared_tier="B",
            bypass_llm=False,
            first_party=True,
            declared_actions=("terminate_process",),
            binding=BOUND,
            has_executor=True,
        )
        assert planned.dispatch_tier == "B"

    def test_an_ancillary_action_in_a_tier_d_plan_keeps_its_own_authority(self):
        planned = assign_action_tier(
            action="terminate_process",
            incident_tier="D",
            declared_tier="B",
            bypass_llm=True,
            first_party=True,
            declared_actions=("terminate_process",),
            binding=BOUND,
            has_executor=True,
        )
        assert planned.dispatch_tier == "B"

    def test_the_registry_floor_still_raises_under_a_tier_a_incident(self):
        planned = assign_action_tier(
            action="terminate_process",
            incident_tier="A",
            declared_tier="A",
            bypass_llm=False,
            first_party=True,
            declared_actions=("terminate_process",),
            binding=BOUND,
            has_executor=True,
        )
        assert planned.dispatch_tier == "B"

    def test_closing_the_circuit_is_not_what_a_safety_condition_licenses(self):
        planned = assign_action_tier(
            action="release_relay",
            incident_tier="D",
            declared_tier="D",
            bypass_llm=True,
            first_party=True,
            declared_actions=("release_relay",),
            binding=BOUND,
            has_executor=True,
        )
        assert planned.dispatch_tier == "C"
        assert planned.tier_d_granted is False

    def test_the_binding_may_raise_the_floor(self):
        soft_zone = BindingView(
            zone_identity_key=ZONE,
            binding_revision="7",
            consequence_by_outcome={OPEN_PROTECTED_CIRCUIT: "hard"},
        )
        planned = assign_action_tier(
            action="trip_relay",
            incident_tier="A",
            declared_tier="A",
            bypass_llm=False,
            first_party=True,
            declared_actions=("trip_relay",),
            binding=soft_zone,
            has_executor=True,
        )
        assert planned.dispatch_tier == "C"

    def test_the_binding_may_never_lower_the_registry_floor(self):
        """A registry floor is the runtime's reviewed judgement; a binding is site data."""
        lying_zone = BindingView(
            zone_identity_key=ZONE,
            binding_revision="7",
            consequence_by_outcome={OPEN_PROTECTED_CIRCUIT: "soft"},
        )
        planned = assign_action_tier(
            action="trip_relay",
            incident_tier="A",
            declared_tier="A",
            bypass_llm=False,
            first_party=True,
            declared_actions=("trip_relay",),
            binding=lying_zone,
            has_executor=True,
        )
        assert planned.dispatch_tier == "C"

    def test_an_action_needing_a_binding_with_no_zone_is_not_dispatched(self):
        planned = assign_action_tier(
            action="trip_relay",
            incident_tier="D",
            declared_tier="D",
            bypass_llm=True,
            first_party=True,
            declared_actions=("trip_relay",),
            binding=None,
            has_executor=True,
        )
        assert planned.admitted is False
        assert planned.refusal == "unbound_actuator"

    def test_an_ungoverned_action_is_refused_at_admission(self):
        planned = assign_action_tier(
            action="launch_missiles",
            incident_tier="D",
            declared_tier="D",
            bypass_llm=True,
            first_party=True,
            declared_actions=("launch_missiles",),
            binding=BOUND,
            has_executor=False,
        )
        assert planned.admitted is False
        assert planned.refusal == "ungoverned_action"

    def test_only_the_registry_decides_what_is_informational(self):
        assert is_informational("alert_whatsapp") is True
        assert is_informational("trip_relay") is False
        assert is_informational("launch_missiles") is False


class TestTierDGrant:
    def _grant(self, **overrides: Any) -> Any:
        kwargs: dict[str, Any] = dict(
            action="close_gas_valve",
            incident_tier="D",
            declared_tier="D",
            bypass_llm=True,
            first_party=True,
            declared_actions=("close_gas_valve",),
            binding=BOUND,
            has_executor=True,
        )
        kwargs.update(overrides)
        return assign_action_tier(**kwargs)

    def test_every_clause_holding_grants_tier_d(self):
        planned = self._grant()
        assert planned.dispatch_tier == "D"
        assert planned.tier_d_granted is True

    @pytest.mark.parametrize(
        "override",
        [
            {"incident_tier": "C"},
            {"bypass_llm": False},
            {"first_party": False},
            {"declared_actions": ()},
            {"has_executor": False},
        ],
    )
    def test_any_clause_failing_withholds_it(self, override):
        planned = self._grant(**override)
        assert planned.tier_d_granted is False
        assert planned.dispatch_tier == "C"

    def test_a_skill_that_is_not_first_party_cannot_reach_tier_d(self):
        assert self._grant(first_party=False).dispatch_tier == "C"

    def test_the_defaults_list_narrows_and_never_grants(self):
        """Naming an action cannot license one the condition does not cover."""
        planned = self._grant(
            action="release_relay", declared_actions=("release_relay",)
        )
        assert planned.tier_d_granted is False


# ── resource identity ────────────────────────────────────────────────────────


class TestResourceIdentity:
    def test_two_names_for_one_act_share_an_identity(self):
        trip = resource_identity("trip_relay", zone_identity_key=ZONE)
        valve = resource_identity("close_gas_valve", zone_identity_key=ZONE)
        assert trip is not None and valve is not None
        assert trip.join_key == valve.join_key

    def test_opposite_outcomes_share_a_resource_and_conflict(self):
        opening = resource_identity("trip_relay", zone_identity_key=ZONE)
        closing = resource_identity("release_relay", zone_identity_key=ZONE)
        assert opening is not None and closing is not None
        assert opening.resource_key == closing.resource_key
        assert opposes(opening, closing) is True

    def test_the_outcome_is_not_part_of_the_resource(self):
        """Folding it in would make the one collision the gate exists to catch invisible."""
        opening = resource_identity("trip_relay", zone_identity_key=ZONE)
        closing = resource_identity("release_relay", zone_identity_key=ZONE)
        assert opening is not None and closing is not None
        assert opening.desired_outcome != closing.desired_outcome

    def test_informational_actions_hold_no_resource(self):
        assert resource_identity("alert_whatsapp") is None

    def test_a_coap_command_to_one_uri_with_another_payload_is_another_act(self):
        one = resource_identity(
            "coap_command", coap_uri="coap://x/a", coap_parameters=(("body", "open"),)
        )
        two = resource_identity(
            "coap_command", coap_uri="coap://x/a", coap_parameters=(("body", "shut"),)
        )
        assert one is not None and two is not None
        assert one.resource_key == two.resource_key
        assert one.join_key != two.join_key


# ── the gate ─────────────────────────────────────────────────────────────────


def _token(decision: Any) -> Any:
    """The admitted record, asserted present.

    `GateDecision.token` is optional because a refusal carries none; every use
    below follows an admission, and saying so keeps the assertion in the test
    rather than in the reader's head.
    """
    assert decision.token is not None, decision
    return decision.token


def _contributor(trigger: str, tier: str, *, tier_d: bool = False) -> Contributor:
    return Contributor(
        skill_name="s",
        trigger_name=trigger,
        action="trip_relay",
        dispatch_tier=tier,
        tier_d_granted=tier_d,
    )


class TestResourceGate:
    def _identity(self, action: str = "trip_relay"):
        identity = resource_identity(action, zone_identity_key=ZONE)
        assert identity is not None
        return identity

    async def test_the_same_outcome_coalesces_into_one_act(self):
        gate = ResourceGate()
        opening = self._identity()
        first = await gate.request(opening, "C", _contributor("t1", "C"))
        second = await gate.request(opening, "C", _contributor("t2", "C"))

        assert first.admission == Admission.ADMITTED
        assert second.admission == Admission.JOINED
        assert _token(second) is _token(first)
        assert [c.trigger_name for c in _token(first).contributors] == ["t1", "t2"]

    async def test_a_join_keeps_each_contributor_s_own_licence(self):
        gate = ResourceGate()
        opening = self._identity()
        holder = await gate.request(opening, "C", _contributor("t1", "C"))
        await gate.request(opening, "D", _contributor("t2", "D", tier_d=True))
        assert [c.tier_d_granted for c in _token(holder).contributors] == [False, True]

    async def test_opposing_acts_at_equal_tier_are_both_refused(self):
        gate = ResourceGate()
        first = await gate.request(self._identity(), "C", _contributor("t1", "C"))
        second = await gate.request(
            self._identity("release_relay"), "C", _contributor("t2", "C")
        )
        assert first.admission == Admission.ADMITTED
        assert second.admission == Admission.REFUSED
        assert second.reason == OPPOSING_EQUAL_TIER
        assert gate.state_of(ZONE) == HolderState.RETIRED

    async def test_a_higher_tier_preempts_a_reservation_that_has_not_started(self):
        gate = ResourceGate()
        await gate.request(
            self._identity("release_relay"), "C", _contributor("t1", "C")
        )
        taking = await gate.request(
            self._identity(), "D", _contributor("t2", "D", tier_d=True)
        )
        assert taking.admission == Admission.PREEMPTED_HOLDER
        assert taking.displaced is not None

    async def test_tier_d_never_joins_an_unapproved_proposal(self):
        """A proposal is not an attempt, so joining one would make a trip wait."""
        gate = ResourceGate()
        opening = self._identity()
        holder = await gate.request(opening, "C", _contributor("t1", "C"))
        await gate.mark_proposal(_token(holder), "PROP1234")

        trip = await gate.request(opening, "D", _contributor("t2", "D", tier_d=True))
        assert trip.admission == Admission.ADMITTED
        assert _token(trip) is not _token(holder)
        assert _token(holder).invalidated is True

    async def test_a_running_opposing_act_is_not_interrupted(self):
        gate = ResourceGate()
        holder = await gate.request(
            self._identity("release_relay"), "C", _contributor("t1", "C")
        )
        await gate.mark_running(_token(holder))
        trip = await gate.request(
            self._identity(), "D", _contributor("t2", "D", tier_d=True)
        )
        assert trip.admission == Admission.REFUSED
        assert trip.reason == OPPOSING_ACT_RUNNING

    async def test_an_uncertain_command_blocks_the_opposite_outcome(self):
        """Acceptance is what the driver reports, and silence is not a report."""
        gate = ResourceGate()
        holder = await gate.request(self._identity(), "D", _contributor("t1", "D"))
        await gate.mark_running(_token(holder))
        await gate.mark_uncertain(_token(holder))

        opposing = await gate.request(
            self._identity("release_relay"), "D", _contributor("t2", "D")
        )
        assert opposing.admission == Admission.REFUSED
        assert opposing.reason == OPPOSING_COMMAND_UNCERTAIN
        assert ZONE in gate.uncertain_resources()

    async def test_retiring_an_uncertain_command_does_not_clear_it(self):
        gate = ResourceGate()
        holder = await gate.request(self._identity(), "D", _contributor("t1", "D"))
        await gate.mark_uncertain(_token(holder))
        await gate.retire(_token(holder), True)
        assert gate.state_of(ZONE) == HolderState.UNCERTAIN

        await gate.resolve_uncertain(_token(holder), True)
        assert gate.state_of(ZONE) == HolderState.RETIRED

    async def test_two_opposing_tier_d_outcomes_are_a_safety_conflict(self):
        """Nothing acts, so nothing is protected. That is its own condition."""
        gate = ResourceGate()
        await gate.request(self._identity(), "D", _contributor("t1", "D", tier_d=True))
        conflict = await gate.request(
            self._identity("release_relay"),
            "D",
            _contributor("t2", "D", tier_d=True),
        )
        assert conflict.admission == Admission.REFUSED
        assert conflict.reason == UNRESOLVED_SAFETY_CONFLICT
        assert conflict.safety_conflict is True

    async def test_coalescing_spans_the_in_flight_attempt_only(self):
        """A repeat trip after a repeat condition is a real event."""
        gate = ResourceGate()
        first = await gate.request(self._identity(), "D", _contributor("t1", "D"))
        await gate.retire(_token(first), True)
        second = await gate.request(self._identity(), "D", _contributor("t2", "D"))
        assert second.admission == Admission.ADMITTED
        assert _token(second) is not _token(first)

    async def test_every_decision_is_recorded(self):
        gate = ResourceGate()
        await gate.request(self._identity(), "C", _contributor("t1", "C"))
        await gate.request(self._identity(), "C", _contributor("t2", "C"))
        await gate.request(
            self._identity("release_relay"), "C", _contributor("t3", "C")
        )
        kinds = [entry["kind"] for entry in gate.suppressions]
        assert "coalesced" in kinds
        assert "refused" in kinds


# ── the boundary below the planner ───────────────────────────────────────────


class TestExecutionBoundary:
    async def test_the_dispatcher_admits_against_the_gate_whatever_called_it(self):
        """A check that holds only because an earlier check held is not a boundary."""
        from ori.network.events import ReasoningResult
        from ori.reasoning.elevator import SkillContext

        gate = ResourceGate()
        # Relay use is permitted here so the action reaches the resource at all:
        # a policy-suppressed relay action is rewritten to the safe default
        # before admission, and would drive nothing to be admitted against.
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        dispatcher.bind_resource_gate(gate, BOUND)

        skill = FakeSkill(triggers=[], actions={})
        context = SkillContext(
            skill=skill, event=_event(), state_store=None, trigger_name="t"
        )
        result = ReasoningResult(
            text="", tier="rule", model="m", tokens_used=0, latency_ms=0
        )

        # A holder that has already started the opposite act on this resource.
        opening = resource_identity("trip_relay", zone_identity_key=ZONE)
        assert opening is not None
        holder = await gate.request(opening, "D", _contributor("other", "D"))
        await gate.mark_running(_token(holder))

        outcome = await dispatcher.dispatch(
            action="release_relay", tier="C", context=context, result=result
        )
        assert outcome.executed is False
        assert outcome.action_taken == f"refused_{OPPOSING_ACT_RUNNING}"


# ── cooldown ─────────────────────────────────────────────────────────────────


class TestCooldownAccounting:
    @pytest.mark.parametrize(
        "outcome,consumes",
        [
            (DispatchOutcome.ATTEMPTED, True),
            (DispatchOutcome.JOINED_ATTEMPT, True),
            (DispatchOutcome.PROPOSAL_OPENED, True),
            (DispatchOutcome.PREEMPTED, False),
            (DispatchOutcome.FULLY_REFUSED, False),
            (DispatchOutcome.CONDITION_FALSE, False),
        ],
    )
    def test_only_a_turn_taken_spends_the_cooldown(self, outcome, consumes):
        assert consumes_cooldown(outcome) is consumes

    def test_a_trigger_consumes_once_on_its_strongest_outcome(self):
        assert (
            strongest_outcome(
                [DispatchOutcome.PROPOSAL_OPENED, DispatchOutcome.ATTEMPTED]
            )
            == DispatchOutcome.ATTEMPTED
        )
        assert (
            strongest_outcome(
                [DispatchOutcome.PREEMPTED, DispatchOutcome.FULLY_REFUSED]
            )
            == DispatchOutcome.PREEMPTED
        )

    def test_an_unresolved_action_reached_nothing(self):
        assert strongest_outcome([DispatchOutcome.PENDING]) == (
            DispatchOutcome.FULLY_REFUSED
        )

    async def test_a_trigger_that_never_matched_consumes_nothing(self):
        skill = FakeSkill(
            triggers=[_trigger("notice", "A")],
            actions={
                "available": [{"name": "alert_whatsapp", "tier": "A"}],
                "defaults": {"notice": ["alert_whatsapp"]},
            },
        )
        skill.triggers[0]["cooldown_seconds"] = 60
        elevator = IntelligenceElevator()
        dispatcher = _dispatcher_double(("alert_whatsapp",))
        coordinator = _coordinator(skill, dispatcher, elevator=elevator)

        await coordinator.dispatch_event(_event(value=1.0))
        assert elevator._rule_engine.in_cooldown("notice", 60, "fake-skill") is False

    async def test_a_trigger_whose_turn_was_taken_consumes_its_cooldown(self):
        skill = FakeSkill(
            triggers=[_trigger("notice", "A")],
            actions={
                "available": [{"name": "alert_whatsapp", "tier": "A"}],
                "defaults": {"notice": ["alert_whatsapp"]},
            },
        )
        skill.triggers[0]["cooldown_seconds"] = 60
        elevator = IntelligenceElevator()
        dispatcher = _dispatcher_double(("alert_whatsapp",))
        coordinator = _coordinator(skill, dispatcher, elevator=elevator)

        await coordinator.dispatch_event(_event())
        await asyncio.sleep(0.05)
        assert elevator._rule_engine.in_cooldown("notice", 60, "fake-skill") is True


# ── the barrier itself ───────────────────────────────────────────────────────


class TestDiscoveryBarrier:
    async def test_one_event_is_evaluated_once_however_many_handlers_arrive(self):
        skill = FakeSkill(
            triggers=[_trigger("notice", "A")],
            actions={
                "available": [{"name": "alert_whatsapp", "tier": "A"}],
                "defaults": {"notice": ["alert_whatsapp"]},
            },
        )
        dispatcher = _dispatcher_double(("alert_whatsapp",))
        coordinator = _coordinator(skill, dispatcher)
        event = _event()

        await asyncio.gather(*(coordinator.handle_event(event) for _ in range(5)))
        await asyncio.sleep(0.05)

        assert await _dispatched(dispatcher) == [("alert_whatsapp", "A")]

    async def test_a_failing_skill_does_not_remove_another_skill_s_trip(self):
        class Exploding(FakeSkill):
            pass

        broken = Exploding(
            triggers=[{"name": "bad", "condition": "value >", "action_tier": "A"}],
            actions={"available": [], "defaults": {}},
            name="broken",
        )
        trip_skill = FakeSkill(
            triggers=[_trigger("trip", "D", bypass=True)],
            actions={
                "available": [{"name": "close_gas_valve", "tier": "D"}],
                "defaults": {"trip": ["close_gas_valve"]},
            },
            name="protector",
        )
        dispatcher = _dispatcher_double(("close_gas_valve",))
        coordinator = _coordinator(broken, dispatcher)
        coordinator.add_skill(trip_skill)

        await coordinator.dispatch_event(_event())
        assert ("close_gas_valve", "D") in await _dispatched(dispatcher)


# ── the evidence record ──────────────────────────────────────────────────────


class TestSealingOnTheActionTier:
    async def test_a_notification_in_a_tier_d_plan_is_not_sealed_as_a_safety_action(
        self, tmp_path
    ):
        """The chain must distinguish a safety action from a message about one.

        Only actions dispatched at C or D become safety-action rows, whatever
        incident accompanied them. A notification inheriting the trip's tier is
        what recorded a WhatsApp message as a physical-authority event.
        """
        from ori.network.events import ReasoningResult
        from ori.reasoning.elevator import SkillContext
        from ori.state.store import StateStore

        attested: list[str] = []

        store = StateStore(str(tmp_path / "state.db"))
        await store.open()
        try:
            dispatcher = ActionDispatcher(
                state_store=store,
                config={"relay_enabled": True},
                evidence_attestor=object(),
            )
            dispatcher.bind_resource_gate(ResourceGate(), BOUND)

            async def record_attestation(_store, _row_id, result, *_args, **_kwargs):
                attested.append(result.action_name)

            dispatcher._attest_action = record_attestation  # type: ignore[method-assign]

            skill = FakeSkill(
                triggers=[_trigger("trip", "D", bypass=True)],
                actions={
                    "available": [
                        {"name": "alert_whatsapp", "tier": "A"},
                        {"name": "trip_relay", "tier": "D"},
                    ],
                    "defaults": {"trip": ["trip_relay", "alert_whatsapp"]},
                },
            )
            context = SkillContext(
                skill=skill, event=_event(), state_store=store, trigger_name="trip"
            )
            result = ReasoningResult(
                text="", tier="rule", model="m", tokens_used=0, latency_ms=0
            )

            await dispatcher.dispatch(
                action="trip_relay", tier="D", context=context, result=result
            )
            await dispatcher.dispatch(
                action="alert_whatsapp", tier="A", context=context, result=result
            )

            assert "trip_relay" in attested
            assert "alert_whatsapp" not in attested
        finally:
            await store.close()


# ── the reproduction from the issue ──────────────────────────────────────────


class TestShippedSkillReproduction:
    async def test_a_shipped_tier_c_action_shadowed_by_an_earlier_notice_now_fires(
        self,
    ):
        """`pc-system-health` declares two triggers with byte-identical conditions.

        `sleep_blocked` is Tier A and declared first; the Tier C
        `sleep_blocked_terminate_candidate` could never be proposed. Both
        conditions read only the sensor type and value, so this reproduces the
        shadowing with no hook-derived state — and the two triggers matching
        together is what the old first-match selection could not survive.
        """
        from ori.network.event_bus import EventBus
        from ori.reasoning.action_registry import ACTION_REGISTRY
        from ori.skills.loader import SkillLoader

        loader = SkillLoader()
        skill = next(
            s for s in loader.load_all("skills") if s.name == "pc-system-health"
        )
        names = [t.name for t in skill.triggers]
        assert names.index("sleep_blocked") < names.index(
            "sleep_blocked_terminate_candidate"
        ), "the reproduction requires the Tier A trigger to be declared first"

        dispatched: list[tuple[str, str]] = []

        async def record(**kwargs):
            dispatched.append((kwargs["action"], kwargs["tier"]))

        dispatcher = AsyncMock()
        dispatcher.dispatch.side_effect = record
        dispatcher._executors = dict.fromkeys(ACTION_REGISTRY, object())

        elevator = IntelligenceElevator()
        coordinator = DispatchCoordinator(
            elevator=elevator, dispatcher=dispatcher, state_store=None
        )
        coordinator.set_binding(BOUND)
        coordinator.add_skill(skill)

        bus = EventBus()
        SkillLoader(
            elevator=elevator, dispatcher=dispatcher, coordinator=coordinator
        ).register(skill, bus)

        reading = SensorReading(
            sensor_id="sleep-blockers",
            sensor_type="sleep_blocking_process",
            value=2.0,
            unit="count",
            timestamp=now_ms(),
            quality=1.0,
        )
        await bus.publish(OriEvent.from_reading(reading, "bench-device"))
        await asyncio.sleep(0.1)

        assert ("terminate_process", "C") in dispatched, dispatched
        assert ("alert_whatsapp", "A") in dispatched, dispatched

    async def test_the_shipped_overcurrent_trigger_is_discovered_not_shadowed(self):
        """`energy-anomaly-detector` declares `dangerous_overcurrent` fourth.

        This proves discovery and dispatch through the public event path, and
        **not** a Tier D protective attempt. That skill's Tier D defaults were
        deliberately reduced to notifications because no executable protective
        action was bound to it, so there is no trip here to fire: the assertions
        below require every dispatched action to be Tier A. A test whose name
        claimed the trip fired would be describing the criterion rather than
        what ran.
        """
        from ori.network.event_bus import EventBus
        from ori.reasoning.action_registry import ACTION_REGISTRY
        from ori.skills.loader import SkillLoader

        loader = SkillLoader()
        skills = loader.load_all("skills")
        skill = next(s for s in skills if s.name == "energy-anomaly-detector")

        tier_d_position = [t.action_tier for t in skill.triggers].index("D")
        assert tier_d_position > 0, (
            "the reproduction requires the Tier D trigger to be declared after "
            "at least one other; reordering the skill is not the fix"
        )

        dispatched: list[tuple[str, str]] = []

        async def record(**kwargs):
            dispatched.append((kwargs["action"], kwargs["tier"]))

        dispatcher = AsyncMock()
        dispatcher.dispatch.side_effect = record
        dispatcher._executors = dict.fromkeys(ACTION_REGISTRY, object())

        elevator = IntelligenceElevator()
        coordinator = DispatchCoordinator(
            elevator=elevator, dispatcher=dispatcher, state_store=None
        )
        coordinator.set_binding(BOUND)
        coordinator.add_skill(skill)

        bus = EventBus()
        wired = SkillLoader(
            elevator=elevator, dispatcher=dispatcher, coordinator=coordinator
        )
        wired.register(skill, bus)

        reading = SensorReading(
            sensor_id="load-current",
            sensor_type="current_clamp",
            value=99.0,
            unit="ampere",
            timestamp=now_ms(),
            quality=1.0,
        )
        await bus.publish(OriEvent.from_reading(reading, "bench-device"))
        await asyncio.sleep(0.1)

        # The incident is discovered; its notifications ride at their own
        # authority rather than inheriting the incident's.
        assert dispatched, "no action reached dispatch for a 99 A reading"
        assert all(tier == "A" for _, tier in dispatched), dispatched
        assert {action for action, _ in dispatched} == {
            "alert_whatsapp",
            "log_to_dashboard",
        }


# ── boundaries that must hold on their own ───────────────────────────────────


class TestIndependentBoundaries:
    """Each check fails closed by itself.

    A check that holds only because an earlier check held is not a boundary, so
    each of these drives the layer directly rather than through a caller whose
    own guard would answer first.
    """

    def test_the_grant_refuses_an_informational_action_on_its_own(self):
        """`assign_action_tier` answers first; this is the clause beneath it."""
        from ori.reasoning.dispatch_plan import tier_d_grant

        grant = tier_d_grant(
            action="alert_whatsapp",
            incident_tier="D",
            bypass_llm=True,
            first_party=True,
            declared_actions=("alert_whatsapp",),
            binding=BOUND,
            has_executor=True,
        )
        assert grant.granted is False

    def test_the_binding_disagreement_is_reported_not_silently_absorbed(self, caplog):
        """A binding calling an irreversible act reversible is a commissioning error."""
        from ori.reasoning.dispatch_plan import effective_floor

        lying_zone = BindingView(
            zone_identity_key=ZONE,
            binding_revision="7",
            consequence_by_outcome={OPEN_PROTECTED_CIRCUIT: "soft"},
        )
        with caplog.at_level("WARNING"):
            floor = effective_floor("trip_relay", lying_zone)

        assert floor == "C"
        assert any(
            "below the registry floor" in record.message for record in caplog.records
        ), [r.message for r in caplog.records]

    async def test_the_elevator_gate_admits_a_trigger_that_is_not_the_first_match(self):
        """Driven with no plan, so the elevator's own gate is the thing under test."""
        from dataclasses import replace

        skill = FakeSkill(
            triggers=[_trigger("notice", "A"), _trigger("candidate", "C")],
            actions={
                "available": [
                    {"name": "alert_whatsapp", "tier": "A"},
                    {"name": "terminate_process", "tier": "C"},
                ],
                "defaults": {
                    "notice": ["alert_whatsapp"],
                    "candidate": ["terminate_process"],
                },
            },
        )
        dispatcher = _dispatcher_double(("terminate_process",))
        event = _event()
        scoped = replace(
            event,
            context={
                **(event.context or {}),
                "__handler_trigger_name": "candidate",
            },
        )
        await IntelligenceElevator().reason_and_dispatch(
            event=scoped, skill=skill, state_store=None, dispatcher=dispatcher
        )

        assert ("terminate_process", "C") in await _dispatched(dispatcher)

    async def test_a_refused_trigger_consumes_no_cooldown(self):
        """A plan that reached nothing did not get its turn."""
        skill = FakeSkill(
            triggers=[_trigger("trip", "D", bypass=True)],
            actions={
                "available": [{"name": "launch_missiles", "tier": "D"}],
                "defaults": {"trip": ["launch_missiles"]},
            },
        )
        skill.triggers[0]["cooldown_seconds"] = 60
        elevator = IntelligenceElevator()
        dispatcher = _dispatcher_double()
        coordinator = _coordinator(skill, dispatcher, elevator=elevator)

        await coordinator.dispatch_event(_event())
        await asyncio.sleep(0.05)

        assert await _dispatched(dispatcher) == []
        assert elevator._rule_engine.in_cooldown("trip", 60, "fake-skill") is False


class TestExhaustiveEvaluation:
    async def test_the_engine_reports_every_match_not_the_first(self):
        from ori.reasoning.rule_engine import RuleEngine

        rules = [
            _trigger("notice", "A"),
            _trigger("candidate", "C"),
            _trigger("trip", "D", bypass=True),
        ]
        matches = await RuleEngine().evaluate_all(_event(), rules)
        assert [m.rule_name for m in matches] == ["notice", "candidate", "trip"]


class TestCooldownIsScopedToItsSkill:
    async def test_one_skill_does_not_silence_another_s_identical_trigger_name(self):
        """Trigger names come from `skill.yaml`, so they are not identities.

        One rule engine serves every skill. Keyed on the bare name, a fire in
        one skill suppressed an unrelated trigger of the same name in another —
        including a trigger whose condition had not yet been true.
        """

        def named(skill_name: str, condition: str) -> FakeSkill:
            skill = FakeSkill(
                triggers=[
                    {
                        "name": "high_temp",
                        "condition": condition,
                        "action_tier": "A",
                        "bypass_llm": False,
                        "cooldown_seconds": 600,
                    }
                ],
                actions={
                    "available": [{"name": "alert_whatsapp", "tier": "A"}],
                    "defaults": {"high_temp": ["alert_whatsapp"]},
                },
                name=skill_name,
            )
            return skill

        elevator = IntelligenceElevator()
        dispatcher = _dispatcher_double(("alert_whatsapp",))
        coordinator = _coordinator(
            named("skill-one", "value > 3.0"), dispatcher, elevator=elevator
        )
        coordinator.add_skill(named("skill-two", "value > 90.0"))

        await coordinator.dispatch_event(_event(value=5.0))
        await asyncio.sleep(0.05)
        assert len(dispatcher.dispatch.call_args_list) == 1

        dispatcher.dispatch.reset_mock()
        await coordinator.dispatch_event(_event(value=99.0))
        await asyncio.sleep(0.05)
        assert len(dispatcher.dispatch.call_args_list) == 1, (
            "the second skill's trigger was suppressed by the first skill's fire"
        )


class TestARefusedTripCanReRaise:
    async def test_a_tier_d_action_refused_at_the_gate_consumes_no_cooldown(self):
        """A trip that never acted has not had its turn.

        The next event is what re-raises it against the state that actually
        obtains, and a charged cooldown would sit that out.
        """
        from ori.network.events import ActionResult

        skill = FakeSkill(
            triggers=[_trigger("trip", "D", bypass=True)],
            actions={
                "available": [{"name": "close_gas_valve", "tier": "D"}],
                "defaults": {"trip": ["close_gas_valve"]},
            },
        )
        skill.triggers[0]["cooldown_seconds"] = 600

        dispatcher = _dispatcher_double(("close_gas_valve",))

        async def refuse(**kwargs):
            return ActionResult(
                action_name=kwargs["action"],
                tier=kwargs["tier"],
                executed=False,
                approved=None,
                action_taken=f"refused_{OPPOSING_ACT_RUNNING}",
                timestamp=now_ms(),
            )

        dispatcher.dispatch.side_effect = refuse

        elevator = IntelligenceElevator()
        coordinator = _coordinator(skill, dispatcher, elevator=elevator)
        await coordinator.dispatch_event(_event())
        await asyncio.sleep(0.05)

        assert elevator._rule_engine.in_cooldown("trip", 600, "fake-skill") is False

    async def test_a_tier_d_action_that_ran_does_consume_its_cooldown(self):
        """The control: an executor that ran charges it, whatever it returned."""
        from ori.network.events import ActionResult

        skill = FakeSkill(
            triggers=[_trigger("trip", "D", bypass=True)],
            actions={
                "available": [{"name": "close_gas_valve", "tier": "D"}],
                "defaults": {"trip": ["close_gas_valve"]},
            },
        )
        skill.triggers[0]["cooldown_seconds"] = 600

        dispatcher = _dispatcher_double(("close_gas_valve",))

        async def ran_and_failed(**kwargs):
            return ActionResult(
                action_name=kwargs["action"],
                tier=kwargs["tier"],
                executed=False,
                approved=None,
                action_taken=kwargs["action"],
                timestamp=now_ms(),
            )

        dispatcher.dispatch.side_effect = ran_and_failed

        elevator = IntelligenceElevator()
        coordinator = _coordinator(skill, dispatcher, elevator=elevator)
        await coordinator.dispatch_event(_event())
        await asyncio.sleep(0.05)

        assert elevator._rule_engine.in_cooldown("trip", 600, "fake-skill") is True


# ── what an adversarial review found ─────────────────────────────────────────


class TestALateApprovalCannotUndoATrip:
    async def test_a_yes_on_an_invalidated_proposal_is_refused(self):
        """Tier D invalidates a proposal; the late reply must be refused too.

        Without the refusal, a Tier D trip opens the circuit and the operator's
        subsequent YES closes the circuit the trip had just opened — sealed
        under the device key as an approved, executed action.
        """
        from ori.network.events import ReasoningResult
        from ori.reasoning.elevator import SkillContext

        gate = ResourceGate()
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        dispatcher.bind_resource_gate(gate, BOUND)

        skill = FakeSkill(triggers=[], actions={})
        context = SkillContext(
            skill=skill, event=_event(), state_store=None, trigger_name="t"
        )
        result = ReasoningResult(
            text="", tier="rule", model="m", tokens_used=0, latency_ms=0
        )

        closing = resource_identity("release_relay", zone_identity_key=ZONE)
        assert closing is not None
        proposal = await gate.request(
            closing,
            "C",
            _contributor("operator_asked", "C"),
            awaits_operator=True,
        )
        assert gate.state_of(ZONE) == HolderState.PROPOSAL

        # The trip arrives and displaces the proposal.
        outcome = await dispatcher.dispatch(
            action="trip_relay", tier="D", context=context, result=result
        )
        assert not str(outcome.action_taken).startswith("refused_")
        assert _token(proposal).invalidated is True

        # The operator's YES arrives afterwards.
        assert await gate.reply_admitted(_token(proposal)) is False

        # The refusal is recorded, and recorded as a displacement rather than as
        # a proposal that merely went stale. Both refuse; only one says a higher
        # authority took the resource, which is what an operator reading the
        # record needs to know.
        refusals = [
            entry
            for entry in gate.suppressions
            if entry["kind"] == "late_reply_refused"
        ]
        assert refusals, gate.suppressions
        assert refusals[-1]["reason"] == PROPOSAL_INVALIDATED, refusals


class TestTierDDoesNotWaitOnAnApproval:
    async def test_an_action_that_will_ask_an_operator_is_admitted_as_a_proposal(self):
        """Settled under the admission lock, not marked afterwards.

        Marking it after `request()` released the lock left a window in which a
        Tier D arrival saw a reservation and coalesced — making the trip wait
        out the approval round trip it exists to displace, then take its result.
        """
        gate = ResourceGate()
        opening = resource_identity("trip_relay", zone_identity_key=ZONE)
        assert opening is not None

        holder = await gate.request(
            opening, "C", _contributor("asks", "C"), awaits_operator=True
        )
        assert gate.state_of(ZONE) == HolderState.PROPOSAL

        trip = await gate.request(opening, "D", _contributor("trips", "D", tier_d=True))
        assert trip.admission == Admission.ADMITTED
        assert _token(trip) is not _token(holder)
        assert _token(holder).invalidated is True

    async def test_the_dispatcher_admits_a_tier_c_action_as_a_proposal(self):
        """Driven through the real dispatcher, not the gate alone."""
        from ori.network.events import ReasoningResult
        from ori.reasoning.elevator import SkillContext

        gate = ResourceGate()
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        dispatcher.bind_resource_gate(gate, BOUND)
        seen: list[str] = []

        async def watch_state(**_kwargs):
            seen.append(gate.state_of(ZONE))
            return None

        dispatcher._listen_for_response = watch_state  # type: ignore[method-assign]

        skill = FakeSkill(triggers=[], actions={})
        context = SkillContext(
            skill=skill, event=_event(), state_store=None, trigger_name="t"
        )
        result = ReasoningResult(
            text="", tier="rule", model="m", tokens_used=0, latency_ms=0
        )
        await dispatcher.dispatch(
            action="trip_relay",
            tier="C",
            context=context,
            result=result,
            approval_timeout=1,
        )
        assert seen == [HolderState.PROPOSAL], seen


class TestACancelledTripDoesNotFreeTheResource:
    async def test_a_shielded_executor_still_driving_leaves_the_command_uncertain(self):
        """Retiring on the awaiting frame's exit let the opposite command through.

        The Tier D executor runs shielded and survives the cancellation, so the
        resource is still being driven. Freeing it there allowed two opposing
        commands to reach one actuator concurrently.
        """
        from ori.network.events import ReasoningResult
        from ori.reasoning.elevator import SkillContext

        gate = ResourceGate()
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        dispatcher.bind_resource_gate(gate, BOUND)

        started = asyncio.Event()

        async def slow_trip(*_args, **_kwargs):
            started.set()
            await asyncio.sleep(5)
            return True

        dispatcher.register_executor("trip_relay", slow_trip)

        skill = FakeSkill(triggers=[], actions={})
        context = SkillContext(
            skill=skill, event=_event(), state_store=None, trigger_name="t"
        )
        result = ReasoningResult(
            text="", tier="rule", model="m", tokens_used=0, latency_ms=0
        )

        task = asyncio.create_task(
            dispatcher.dispatch(
                action="trip_relay", tier="D", context=context, result=result
            )
        )
        await started.wait()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

        assert gate.state_of(ZONE) == HolderState.UNCERTAIN

        closing = resource_identity("release_relay", zone_identity_key=ZONE)
        assert closing is not None
        opposing = await gate.request(closing, "C", _contributor("closer", "C"))
        assert opposing.admission == Admission.REFUSED
        assert opposing.reason == OPPOSING_COMMAND_UNCERTAIN

    async def test_two_opposing_tier_d_outcomes_outrank_the_uncertainty(self):
        """Both are true; the safety conflict is the one that must be reported.

        A device with two opposing Tier D outcomes is unprotected whatever the
        command in flight is doing, and filing that as a routine uncertainty
        would lose the condition that has to degrade safety status.
        """
        gate = ResourceGate()
        opening = resource_identity("trip_relay", zone_identity_key=ZONE)
        closing = resource_identity("release_relay", zone_identity_key=ZONE)
        assert opening is not None and closing is not None

        holder = await gate.request(
            opening, "D", _contributor("trips", "D", tier_d=True)
        )
        await gate.mark_uncertain(_token(holder))

        conflict = await gate.request(
            closing, "D", _contributor("closes", "D", tier_d=True)
        )
        assert conflict.reason == UNRESOLVED_SAFETY_CONFLICT
        assert conflict.safety_conflict is True


class TestPublishIsNotHeldByTheEvent:
    async def test_a_handler_returns_before_the_plan_runs(self):
        """`EventBus.publish` awaits handlers one after another.

        Awaiting the whole event in a handler held the publishing coroutine —
        and the sensor poll loop with it — for the length of every executor the
        plan reached, a Tier D relay command included.
        """
        import time

        from ori.network.event_bus import EventBus
        from ori.skills.loader import SkillLoader

        skill = next(
            s
            for s in SkillLoader().load_all("skills")
            if s.name == "hvac-refrigerant-monitor"
        )

        async def slow(**_kwargs):
            await asyncio.sleep(0.4)

        dispatcher = _dispatcher_double(("close_gas_valve",))
        dispatcher.dispatch.side_effect = slow

        elevator = IntelligenceElevator()
        coordinator = _coordinator(skill, dispatcher, elevator=elevator)

        bus = EventBus()
        SkillLoader(
            elevator=elevator, dispatcher=dispatcher, coordinator=coordinator
        ).register(skill, bus)

        leak = SensorReading(
            sensor_id="gas",
            sensor_type="gas_concentration",
            value=9999.0,
            unit="ppm",
            timestamp=now_ms(),
            quality=1.0,
        )
        started = time.perf_counter()
        await bus.publish(OriEvent.from_reading(leak, "test-device"))
        published_in = time.perf_counter() - started

        assert published_in < 0.2, f"publish held for {published_in * 1000:.0f} ms"
        await coordinator.drain()
        assert dispatcher.dispatch.call_args_list, "the work still has to happen"


class TestCooldownSeesWhatTheTaskReached:
    async def test_an_action_refused_at_the_gate_in_the_reasoning_path_charges_nothing(
        self,
    ):
        """Charging at scheduling time assumed away the outcomes that consume nothing."""
        from ori.network.events import ActionResult

        skill = FakeSkill(
            triggers=[_trigger("candidate", "C")],
            actions={
                "available": [{"name": "terminate_process", "tier": "C"}],
                "defaults": {"candidate": ["terminate_process"]},
            },
        )
        skill.triggers[0]["cooldown_seconds"] = 600

        dispatcher = _dispatcher_double(("terminate_process",))

        async def refuse(**kwargs):
            return ActionResult(
                action_name=kwargs["action"],
                tier=kwargs["tier"],
                executed=False,
                approved=None,
                action_taken=f"refused_{OPPOSING_ACT_RUNNING}",
                timestamp=now_ms(),
            )

        dispatcher.dispatch.side_effect = refuse

        elevator = IntelligenceElevator()
        coordinator = _coordinator(skill, dispatcher, elevator=elevator)
        await coordinator.dispatch_event(_event())
        await coordinator.drain()

        assert (
            elevator._rule_engine.in_cooldown("candidate", 600, "fake-skill") is False
        )

    async def test_an_operator_asked_consumes_the_cooldown(self):
        """`proposal_opened` is reachable in production and consumes."""
        from ori.network.events import ActionResult

        skill = FakeSkill(
            triggers=[_trigger("candidate", "C")],
            actions={
                "available": [{"name": "terminate_process", "tier": "C"}],
                "defaults": {"candidate": ["terminate_process"]},
            },
        )
        skill.triggers[0]["cooldown_seconds"] = 600

        dispatcher = _dispatcher_double(("terminate_process",))

        async def asked_and_refused(**kwargs):
            return ActionResult(
                action_name=kwargs["action"],
                tier=kwargs["tier"],
                executed=True,
                approved=False,
                action_taken="log_to_dashboard",
                timestamp=now_ms(),
            )

        dispatcher.dispatch.side_effect = asked_and_refused

        elevator = IntelligenceElevator()
        coordinator = _coordinator(skill, dispatcher, elevator=elevator)
        await coordinator.dispatch_event(_event())
        await coordinator.drain()

        assert elevator._rule_engine.in_cooldown("candidate", 600, "fake-skill") is True


class TestEventScopedArbitration:
    """A completed act forecloses for the rest of its event, not just in flight."""

    def _skill(
        self, name: str, tier: str, actions: list[str], *, bypass: bool = False
    ) -> Any:
        from ori.skills.loader import Trigger

        skill = FakeSkill(triggers=[], actions={})
        skill.name = name
        skill.triggers = [
            Trigger(
                name="t",
                condition="value > 3.0",
                action_tier=tier,
                bypass_llm=bypass,
                cooldown_seconds=0,
            )
        ]
        skill.actions = {
            "available": [{"name": a, "tier": tier} for a in actions],
            "defaults": {"t": actions},
        }
        return skill

    async def _run(self, skills: list[Any]) -> list[str]:
        ran: list[str] = []
        gate = ResourceGate()
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        dispatcher.bind_resource_gate(gate, BOUND)

        def executor(name: str):
            async def _run_it(*_args, **_kwargs):
                ran.append(name)
                return True

            return _run_it

        for action in ("close_gas_valve", "trip_relay", "release_relay"):
            dispatcher.register_executor(action, executor(action))

        coordinator = DispatchCoordinator(
            elevator=IntelligenceElevator(),
            dispatcher=dispatcher,
            state_store=None,
            gate=gate,
        )
        coordinator.set_binding(BOUND)
        for skill in skills:
            coordinator.add_skill(skill)
        await coordinator.dispatch_event(_event())
        await coordinator.drain()
        return ran

    async def test_a_completed_trip_forecloses_the_opposite_act_in_the_same_event(self):
        """Retiring at the attempt's end let the same event's close through.

        The trip's executor returns, the record retires, and the Tier C close
        arriving moments later in the same event met an empty gate — closing
        the circuit the trip had just opened.
        """
        ran = await self._run(
            [
                self._skill("protector", "D", ["close_gas_valve"], bypass=True),
                self._skill("restorer", "C", ["release_relay"]),
            ]
        )
        assert ran == ["close_gas_valve"], ran

    async def test_two_plans_naming_one_outcome_produce_one_physical_act(self):
        """Coalescing has to survive the plans being attempted in sequence."""
        ran = await self._run(
            [
                self._skill("a", "D", ["close_gas_valve"], bypass=True),
                self._skill("b", "D", ["trip_relay"], bypass=True),
            ]
        )
        assert len(ran) == 1, ran

    async def test_the_foreclosure_ends_with_the_event(self):
        """A repeat condition on a later event is a real event, not an absorbed one."""
        skills = [self._skill("protector", "D", ["close_gas_valve"], bypass=True)]
        first = await self._run(skills)
        second = await self._run(skills)
        assert first == ["close_gas_valve"] and second == ["close_gas_valve"]


class TestOnlyEligibleSkillsAreEvaluated:
    async def test_a_reading_never_reaches_a_skill_that_does_not_declare_it(self):
        """The EventBus was the eligibility boundary and the barrier removed it.

        Evaluating every loaded skill for every event is worse than the
        shadowing this change fixes: a condition belonging to a gas or current
        channel can match a reading from an unrelated one, and only a condition
        that happens to test `sensor_type` would notice — a guard written in the
        manifest this framework exists to constrain.
        """
        from ori.skills.loader import Trigger

        def sensing(name: str, sensor_type: str, action: str) -> Any:
            skill = FakeSkill(triggers=[], actions={})
            skill.name = name
            skill.sensors_required = [{"type": sensor_type}]
            skill.triggers = [
                Trigger(
                    name="t",
                    condition="value > 3.0",
                    action_tier="A",
                    bypass_llm=False,
                    cooldown_seconds=0,
                )
            ]
            skill.actions = {
                "available": [{"name": action, "tier": "A"}],
                "defaults": {"t": [action]},
            }
            return skill

        dispatcher = _dispatcher_double(("alert_whatsapp", "alert_sms"))
        elevator = IntelligenceElevator()
        coordinator = _coordinator(
            sensing("temp-skill", "temperature", "alert_whatsapp"),
            dispatcher,
            elevator=elevator,
        )
        coordinator.add_skill(sensing("current-skill", "current_clamp", "alert_sms"))

        await coordinator.dispatch_event(_event(sensor_type="temperature"))
        await coordinator.drain()

        assert [a for a, _ in await _dispatched(dispatcher)] == ["alert_whatsapp"]


class TestTheBoundaryFailsClosed:
    async def test_a_physical_action_with_no_resolvable_resource_is_refused(self):
        """An unresolved resource must refuse, not execute unarbitrated.

        Consulting the gate only when a resource could be established meant the
        one case where arbitration is impossible was the one case that skipped
        it — an action that looks arbitrated and is not.
        """
        from ori.network.events import ReasoningResult
        from ori.reasoning.elevator import SkillContext

        ran: list[str] = []

        async def executor(*_args, **_kwargs):
            ran.append("trip_relay")
            return True

        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        # A gate, and no binding — so the zone this action drives is unknown.
        dispatcher.bind_resource_gate(ResourceGate(), None)
        dispatcher.register_executor("trip_relay", executor)

        skill = FakeSkill(triggers=[], actions={})
        context = SkillContext(
            skill=skill, event=_event(), state_store=None, trigger_name="t"
        )
        result = ReasoningResult(
            text="", tier="rule", model="m", tokens_used=0, latency_ms=0
        )
        outcome = await dispatcher.dispatch(
            action="trip_relay", tier="D", context=context, result=result
        )

        assert ran == []
        assert outcome.action_taken == "refused_unresolved_resource"
        assert outcome.executed is False

    async def test_an_informational_action_needs_no_resource(self):
        """The control: only a registry-proven inert action legitimately has none."""
        from ori.network.events import ReasoningResult
        from ori.reasoning.elevator import SkillContext

        dispatcher = ActionDispatcher()
        dispatcher.bind_resource_gate(ResourceGate(), None)
        skill = FakeSkill(triggers=[], actions={})
        context = SkillContext(
            skill=skill, event=_event(), state_store=None, trigger_name="t"
        )
        result = ReasoningResult(
            text="", tier="rule", model="m", tokens_used=0, latency_ms=0
        )
        outcome = await dispatcher.dispatch(
            action="log_to_dashboard", tier="A", context=context, result=result
        )
        assert outcome.action_taken != "refused_unresolved_resource"


class TestScopesBelongToTheirEvent:
    """Concurrent events must not free each other's foreclosures.

    Events are dispatched in their own tasks, so a scope read from anything
    process-global is whichever event opened one most recently rather than the
    event doing the admitting. A record tagged that way was freed when the
    unrelated event closed, releasing a completed protective act's foreclosure
    while the event that licensed it was still running.
    """

    async def test_two_tasks_admit_into_their_own_scopes(self):
        gate = ResourceGate()
        opening = resource_identity("trip_relay", zone_identity_key=ZONE)
        other = resource_identity(
            "coap_command", coap_uri="coap://valve/a", coap_parameters=(("p", "1"),)
        )
        assert opening is not None and other is not None

        b_open = asyncio.Event()
        a_admitted = asyncio.Event()

        async def event_a() -> str:
            token = gate.open_scope("event-A")
            try:
                await b_open.wait()
                decision = await gate.request(
                    opening, "D", _contributor("tripA", "D", tier_d=True)
                )
                await gate.retire(_token(decision), True)
                a_admitted.set()
                # Held until this event is done, whatever else opened or closed.
                await asyncio.sleep(0.05)
                return _token(decision).scope
            finally:
                await gate.close_scope("event-A", token)

        async def event_b() -> None:
            token = gate.open_scope("event-B")
            b_open.set()
            await a_admitted.wait()
            await gate.close_scope("event-B", token)

        scope_of_a, _ = await asyncio.gather(event_a(), event_b())
        assert scope_of_a == "event-A", scope_of_a

    async def test_closing_one_event_cannot_release_another_s_foreclosure(self):
        """Interleaved through the real coordinator, dispatcher and gate."""
        from ori.skills.loader import Trigger

        def skill(name: str, tier: str, actions: list[str], *, bypass: bool = False):
            built = FakeSkill(triggers=[], actions={})
            built.name = name
            built.triggers = [
                Trigger(
                    name="t",
                    condition="value > 3.0",
                    action_tier=tier,
                    bypass_llm=bypass,
                    cooldown_seconds=0,
                )
            ]
            built.actions = {
                "available": [{"name": a, "tier": tier} for a in actions],
                "defaults": {"t": actions},
            }
            return built

        ran: list[str] = []
        gate = ResourceGate()
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        dispatcher.bind_resource_gate(gate, BOUND)
        for action in ("close_gas_valve", "release_relay", "trip_relay"):

            def executor(*_args, _name=action, **_kwargs):
                async def _run():
                    ran.append(_name)
                    return True

                return _run()

            dispatcher.register_executor(action, executor)

        # Event A's remainder is held open at a real seam, so its completed
        # Tier D act is still foreclosing when event B runs to completion.
        elevator_a = IntelligenceElevator()
        reached, proceed = asyncio.Event(), asyncio.Event()
        original = elevator_a.reason_and_dispatch

        async def paused(**kwargs):
            reached.set()
            await proceed.wait()
            return await original(**kwargs)

        elevator_a.reason_and_dispatch = paused  # type: ignore[method-assign]

        event_a = DispatchCoordinator(
            elevator=elevator_a, dispatcher=dispatcher, state_store=None, gate=gate
        )
        event_a.set_binding(BOUND)
        event_a.add_skill(skill("protector", "D", ["close_gas_valve"], bypass=True))
        event_a.add_skill(skill("restorer", "C", ["release_relay"]))

        event_b = DispatchCoordinator(
            elevator=IntelligenceElevator(),
            dispatcher=dispatcher,
            state_store=None,
            gate=gate,
        )
        event_b.set_binding(BOUND)
        event_b.add_skill(skill("other", "D", ["trip_relay"], bypass=True))

        running_a = asyncio.create_task(event_a.dispatch_event(_event()))
        await asyncio.wait_for(reached.wait(), 10)
        assert gate.state_of(ZONE) == HolderState.HELD

        await asyncio.wait_for(event_b.dispatch_event(_event()), 10)
        assert gate.state_of(ZONE) == HolderState.HELD, (
            "event B's close released event A's foreclosure"
        )

        proceed.set()
        await asyncio.wait_for(running_a, 10)
        await event_a.drain()
        assert ran == ["close_gas_valve"], ran
