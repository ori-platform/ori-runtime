# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""No cooldown, and no in-flight hold, reads or charges against a Tier D attempt.

A trigger's cooldown rate-limits only what it does besides its Tier D act. Each
case sends repeated matching readings through the real rule engine and
coordinator and counts the acts the dispatcher was asked for.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from ori.network.events import ActionResult
from ori.reasoning.elevator import IntelligenceElevator
from ori.reasoning.resource_gate import (
    OPPOSING_ACT_RUNNING,
)
from ori.reasoning.rule_engine import RuleEngine
from ori.utils.time_utils import now_ms
from tests.test_dispatch_plan import (
    FakeSkill,
    _coordinator,
    _dispatcher_double,
    _event,
    _trigger,
)
from tests.waiting import quiesce

COOLDOWN = 600
TRIP = "close_gas_valve"
NOTICE = "alert_whatsapp"


def _skill(defaults: list[str], *, tier: str = "D") -> FakeSkill:
    skill = FakeSkill(
        triggers=[_trigger("trip", tier, bypass=tier == "D")],
        actions={
            "available": [
                {"name": TRIP, "tier": "D"},
                {"name": NOTICE, "tier": "A"},
            ],
            "defaults": {"trip": defaults},
        },
    )
    skill.triggers[0]["cooldown_seconds"] = COOLDOWN
    return skill


def _dispatcher(trip: str = "ran", *, notice_delay: float = 0.0) -> Any:
    """`trip` is what the Tier D act reports: ran, failed, or refused at the gate."""
    dispatcher = _dispatcher_double((TRIP, NOTICE))

    async def dispatch(**kwargs: Any) -> ActionResult:
        action = kwargs["action"]
        executed = True
        taken = action
        if action == TRIP and trip == "failed":
            executed = False
        elif action == TRIP and trip == "refused":
            executed = False
            taken = f"refused_{OPPOSING_ACT_RUNNING}"
        elif action == NOTICE and notice_delay:
            await asyncio.sleep(notice_delay)
        return ActionResult(
            action_name=action,
            tier=kwargs["tier"],
            executed=executed,
            approved=None,
            action_taken=taken,
            timestamp=now_ms(),
        )

    dispatcher.dispatch.side_effect = dispatch
    return dispatcher


def _calls(dispatcher: Any, action: str) -> list[str]:
    return [
        call.kwargs["tier"]
        for call in dispatcher.dispatch.call_args_list
        if call.kwargs["action"] == action
    ]


async def _settled_readings(coordinator: Any, count: int) -> None:
    for _ in range(count):
        await coordinator.dispatch_event(_event())
        await quiesce(what="the reading's scheduled work")
        await coordinator.drain()


class TestTheEngineNeverDropsTierD:
    async def test_a_charged_tier_d_rule_still_matches(self):
        engine = RuleEngine()
        rules = [
            {**_trigger("trip", "D", bypass=True), "cooldown_seconds": COOLDOWN},
            {**_trigger("notice", "A"), "cooldown_seconds": COOLDOWN},
        ]
        engine.record_fire("trip", "fake-skill")
        engine.record_fire("notice", "fake-skill")

        matches = await engine.evaluate_all(_event(), rules, scope="fake-skill")

        assert [m.rule_name for m in matches] == ["trip"]


class TestRepeatedReadingsReachTierD:
    @pytest.mark.parametrize("trip", ["ran", "failed", "refused"])
    async def test_every_reading_attempts_the_trip(self, trip: str):
        dispatcher = _dispatcher(trip)
        elevator = IntelligenceElevator()
        coordinator = _coordinator(_skill([TRIP]), dispatcher, elevator=elevator)

        await _settled_readings(coordinator, 3)

        assert _calls(dispatcher, TRIP) == ["D"] * 3
        assert not elevator._rule_engine.in_cooldown("trip", COOLDOWN, "fake-skill")

    async def test_only_the_notice_of_a_mixed_plan_waits_out_the_window(self):
        dispatcher = _dispatcher("ran")
        elevator = IntelligenceElevator()
        coordinator = _coordinator(
            _skill([TRIP, NOTICE]), dispatcher, elevator=elevator
        )

        await _settled_readings(coordinator, 3)

        assert _calls(dispatcher, TRIP) == ["D"] * 3
        assert _calls(dispatcher, NOTICE) == ["A"]
        assert elevator._rule_engine.in_cooldown("trip", COOLDOWN, "fake-skill")

    async def test_a_pending_notice_neither_holds_the_trip_nor_repeats(self):
        """Counts the dispatches the plan asks for. Whether each drives the
        actuator or joins an act already made is the resource gate's decision."""
        dispatcher = _dispatcher("ran", notice_delay=0.3)
        coordinator = _coordinator(_skill([TRIP, NOTICE]), dispatcher)

        readings = []
        for _ in range(3):
            readings.append(asyncio.create_task(coordinator.dispatch_event(_event())))
            await asyncio.sleep(0.02)
        await asyncio.gather(*readings)
        await coordinator.drain()

        assert _calls(dispatcher, TRIP) == ["D"] * 3
        assert _calls(dispatcher, NOTICE) == ["A"]

    async def test_a_refused_notice_lets_the_next_reading_send_it(self):
        """The trip's turn is not the notice's: a refused notice charged nothing."""
        dispatcher = _dispatcher("ran")
        original = dispatcher.dispatch.side_effect
        notices = 0

        async def refuse_first_notice(**kwargs: Any) -> ActionResult:
            nonlocal notices
            if kwargs["action"] == NOTICE:
                notices += 1
            if kwargs["action"] == NOTICE and notices == 1:
                return ActionResult(
                    action_name=NOTICE,
                    tier=kwargs["tier"],
                    executed=False,
                    approved=None,
                    action_taken=f"refused_{OPPOSING_ACT_RUNNING}",
                    timestamp=now_ms(),
                )
            return await original(**kwargs)

        dispatcher.dispatch.side_effect = refuse_first_notice
        coordinator = _coordinator(_skill([TRIP, NOTICE]), dispatcher)

        await _settled_readings(coordinator, 3)

        assert _calls(dispatcher, TRIP) == ["D"] * 3
        assert _calls(dispatcher, NOTICE) == ["A"] * 2


class TestATriggerGrantingNoTierDIsStillRateLimited:
    async def test_a_tier_d_trigger_that_only_notifies_keeps_its_window(self):
        """With no protective outcome in its plan there is no Tier D act to
        protect, so its notice is held like any other trigger's."""
        dispatcher = _dispatcher("ran")
        coordinator = _coordinator(_skill([NOTICE]), dispatcher)

        await _settled_readings(coordinator, 3)

        assert _calls(dispatcher, NOTICE) == ["A"]
        assert _calls(dispatcher, TRIP) == []
