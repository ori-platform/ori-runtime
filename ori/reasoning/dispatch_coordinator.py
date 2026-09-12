# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""One event, one evaluation of every skill, before anything is dispatched.

A lock on a resource is not enough to make Tier D preemptive. Plans are built
per skill, and one skill can have its reasoning scheduled before another skill
has even been evaluated — so a Tier A notice from skill X races a Tier D trip in
skill Y that nothing has discovered yet. A resource lock cannot fix that,
because at that moment the Tier D action does not exist to take it.

So admission has two phases. The first is event-wide: evaluate every registered
skill exhaustively and assemble the full set of matched triggers across all of
them, before any action is dispatched and before any reasoning task is
scheduled. The second is resource admission, which
:mod:`ori.reasoning.resource_gate` decides.

``docs/DISPATCH_PLAN.md`` is the contract this module implements.
"""

from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from dataclasses import replace
from typing import Any

from ori.network.events import OriEvent, ReasoningResult
from ori.reasoning.dispatch_plan import (
    UNBOUND_ACTUATOR,
    UNGOVERNED_ACTION,
    BindingView,
    DispatchOutcome,
    PlannedAction,
    TriggerPlan,
    assign_action_tier,
    consumes_cooldown,
)
from ori.reasoning.resource_gate import ResourceGate
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

# How many event ids the barrier remembers. One handler per (trigger,
# sensor_type) is subscribed, so every handler for one event calls in; the first
# performs the event-wide evaluation and the rest return. The window only has to
# outlive the fan-out of a single event.
_CLAIM_WINDOW = 512


class DispatchCoordinator:
    """The event-wide discovery barrier, and what it admits afterwards."""

    def __init__(
        self,
        *,
        elevator: Any = None,
        dispatcher: Any = None,
        state_store: Any = None,
        gate: ResourceGate | None = None,
    ) -> None:
        self._elevator = elevator
        self._dispatcher = dispatcher
        self._state_store = state_store
        self._gate = gate or ResourceGate()
        self._skills: list[Any] = []
        self._claimed: OrderedDict[str, int] = OrderedDict()
        self._binding: BindingView | None = None
        self._tasks: set[asyncio.Task[Any]] = set()

    # ── registration ─────────────────────────────────────────────────────────

    @property
    def gate(self) -> ResourceGate:
        return self._gate

    @property
    def skills(self) -> list[Any]:
        return list(self._skills)

    def add_skill(self, skill: Any) -> None:
        """Include *skill* in every future discovery set."""
        name = getattr(skill, "name", None)
        self._skills = [s for s in self._skills if getattr(s, "name", None) != name]
        self._skills.append(skill)

    def remove_skill(self, skill: Any) -> None:
        name = getattr(skill, "name", None)
        self._skills = [s for s in self._skills if getattr(s, "name", None) != name]

    def clear_skills(self) -> None:
        self._skills = []

    def set_binding(self, binding: BindingView | None) -> None:
        """Record what the commissioned binding establishes on this device."""
        self._binding = binding

    def bind_runtime(
        self,
        *,
        elevator: Any = None,
        dispatcher: Any = None,
        state_store: Any = None,
    ) -> None:
        if elevator is not None:
            self._elevator = elevator
        if dispatcher is not None:
            self._dispatcher = dispatcher
        if state_store is not None:
            self._state_store = state_store

    # ── the barrier ──────────────────────────────────────────────────────────

    def _claim(self, event: OriEvent) -> bool:
        """Whether this call is the one that evaluates *event*.

        Synchronous on purpose: no await separates the check from the insert, so
        two handlers for one event cannot both claim it.
        """
        key = str(getattr(event, "event_id", "") or "")
        if not key:
            return True
        if key in self._claimed:
            return False
        self._claimed[key] = now_ms()
        while len(self._claimed) > _CLAIM_WINDOW:
            self._claimed.popitem(last=False)
        return True

    async def handle_event(self, event: OriEvent) -> None:
        """EventBus entry point. Every trigger handler funnels through here.

        The claim is synchronous and the work is not. `EventBus.publish` awaits
        its handlers one after another, so awaiting the whole event here would
        hold the publishing coroutine — and with it the sensor poll loop — for
        the length of every skill's evaluation and every executor the plan
        reaches, a Tier D relay command included. Scheduling the work instead
        costs the barrier nothing: the ordering it guarantees is established
        inside `dispatch_event`, which discovers before it dispatches and
        attempts Tier D before it schedules any reasoning.
        """
        if not self._claim(event):
            return
        task = asyncio.create_task(
            self._dispatch_guarded(event),
            name=f"dispatch:{getattr(event, 'event_id', '?')}",
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _dispatch_guarded(self, event: OriEvent) -> None:
        try:
            await self.dispatch_event(event)
        except Exception:
            logger.exception(
                "DispatchCoordinator: dispatch failed for event_id=%s sensor=%s",
                getattr(event, "event_id", "?"),
                getattr(event, "sensor_id", "?"),
            )

    async def drain(self, timeout: float = 5.0) -> None:
        """Wait for scheduled dispatch work to finish, for shutdown and tests."""
        while self._tasks:
            pending = list(self._tasks)
            done, _ = await asyncio.wait(pending, timeout=timeout)
            if not done:
                return

    async def dispatch_event(self, event: OriEvent) -> None:
        """Phase 1 discovery, then Tier D, then everything else."""
        plans = await self._discover(event)
        if not plans:
            return

        # One arbitration scope for the event. A Tier D act that completes
        # inside it keeps foreclosing lower authority on its resource until the
        # event is settled, and two plans naming one outcome coalesce into a
        # single executor call even though they are attempted in sequence.
        scope = str(getattr(event, "event_id", "") or id(event))
        scope_token = self._gate.open_scope(scope)
        scheduled: list[asyncio.Task[Any]] = []
        try:
            # Phase 2 — a Tier D match anywhere in the discovery set is
            # attempted before any reasoning task is scheduled anywhere in it.
            for plan in plans:
                if plan.grants_tier_d:
                    await self._attempt_tier_d(plan, event)

            # Phase 3 — the rest of each plan, through the reasoning path.
            for plan in plans:
                task = await self._schedule_remainder(plan, event)
                if task is not None:
                    scheduled.append(task)

            # Phase 4 — one owner for cooldown, charged against what was
            # reached by the plans that scheduled nothing.
            self._charge_cooldowns(plans)
        finally:
            if scheduled:
                await asyncio.gather(*scheduled, return_exceptions=True)
            await self._gate.close_scope(scope, scope_token)

    @staticmethod
    def _eligible(skill: Any, event: OriEvent) -> bool:
        """Whether *event* is one *skill* subscribes to.

        The EventBus was the eligibility boundary: it routed a reading only to
        handlers whose skill declared that sensor type. Evaluating every loaded
        skill for every event removes that boundary, and the result is worse
        than the shadowing this change exists to fix — a condition belonging to
        a gas or current channel can match a reading from an unrelated one.
        Only a condition that happens to test `sensor_type` would notice, and
        that guard is written in `skill.yaml`, which is the thing being
        constrained.

        Decided by :func:`_unique_sensor_types`, the same function the loader
        subscribes from, so the discovery set is by construction the set the bus
        would have delivered to.
        """
        from ori.skills.loader import _unique_sensor_types

        declared = _unique_sensor_types(getattr(skill, "sensors_required", []) or [])
        if "*" in declared:
            return True
        reading = getattr(event, "reading", None)
        sensor_type = str(getattr(reading, "sensor_type", "") or "")
        return sensor_type in declared

    async def _discover(self, event: OriEvent) -> list[TriggerPlan]:
        """Every trigger that matched, across every skill eligible for this event."""
        plans: list[TriggerPlan] = []
        for skill in self._skills:
            if not self._eligible(skill, event):
                continue
            try:
                matches = await self._matches_for(event, skill)
            except Exception:
                logger.exception(
                    "DispatchCoordinator: evaluation failed for skill=%r",
                    getattr(skill, "name", "?"),
                )
                continue
            for rule_result in matches:
                plans.append(self._plan_for(skill, rule_result, event))
        return plans

    async def _matches_for(self, event: OriEvent, skill: Any) -> list[Any]:
        if self._elevator is None:
            return []
        matches, _ = await self._elevator.evaluate_matches_with_hooks(
            event, skill, self._state_store
        )
        return list(matches)

    def _plan_for(self, skill: Any, rule_result: Any, event: OriEvent) -> TriggerPlan:

        trigger_name = str(getattr(rule_result, "rule_name", "") or "")
        incident_tier = str(getattr(rule_result, "action_tier", "A") or "A").upper()
        declared = tuple(self._declared_actions(skill, trigger_name))
        first_party = bool(getattr(skill, "first_party", False))
        bypass_llm = bool(getattr(rule_result, "bypass_llm", False))

        plan = TriggerPlan(
            skill_name=str(getattr(skill, "name", "") or ""),
            trigger_name=trigger_name,
            incident_tier=incident_tier,
            bypass_llm=bypass_llm,
            first_party=first_party,
            cooldown_seconds=self._cooldown_for(skill, trigger_name),
        )
        plan.rule_result = rule_result

        for action in declared:
            planned = assign_action_tier(
                action=action,
                incident_tier=incident_tier,
                declared_tier=self._declared_tier(skill, action),
                bypass_llm=bypass_llm,
                first_party=first_party,
                declared_actions=declared,
                binding=self._binding,
                has_executor=self._has_executor(action),
                zone_identity_key=(
                    self._binding.zone_identity_key if self._binding else None
                ),
                binding_revision=(
                    self._binding.binding_revision if self._binding else ""
                ),
                target=str(getattr(event, "sensor_id", "") or ""),
            )
            if planned.refusal:
                logger.warning(
                    "DispatchCoordinator: refusing action=%r for skill=%r "
                    "trigger=%r at admission — %s",
                    action,
                    plan.skill_name,
                    trigger_name,
                    planned.refusal,
                )
            plan.actions.append(planned)
        return plan

    # ── Tier D ───────────────────────────────────────────────────────────────

    async def _attempt_tier_d(self, plan: TriggerPlan, event: OriEvent) -> None:
        """Attempt the licensed protective outcome, before any reasoning.

        Awaited rather than scheduled: the ordering this phase exists to
        establish is that a Tier D match anywhere in the discovery set is
        attempted before a reasoning task is scheduled anywhere in it, and a
        task scheduled here would only promise that its turn came first.

        Resource admission is not decided here. It is decided once, at the
        final execution boundary in the dispatcher, so a physical act is
        admitted whether it arrived through this phase or through reasoning.
        A second gate here would have to hand its token down or deadlock
        against itself.
        """
        if self._dispatcher is None:
            return
        for planned in plan.actions:
            if not planned.tier_d_granted or not planned.admitted:
                continue
            outcome = await self._dispatch(plan, planned, event)
            # A refusal at the gate is not a turn taken. Charging it would let a
            # trip that never acted sit out its cooldown, and the next event is
            # what re-raises it against the state that actually obtains.
            refused = str(getattr(outcome, "action_taken", "") or "").startswith(
                "refused_"
            )
            if refused:
                planned.outcome = DispatchOutcome.FULLY_REFUSED
                planned.refusal = str(outcome.action_taken)[len("refused_") :]
            elif str(getattr(outcome, "action_taken", "")) == "coalesced":
                planned.outcome = DispatchOutcome.JOINED_ATTEMPT
            else:
                planned.outcome = DispatchOutcome.ATTEMPTED

    async def _dispatch(
        self,
        plan: TriggerPlan,
        planned: PlannedAction,
        event: OriEvent,
    ) -> Any:
        """Hand one planned action to the dispatcher at the authority it earned."""
        from ori.reasoning.elevator import SkillContext

        skill = self._skill_named(plan.skill_name)
        if skill is None or self._dispatcher is None:
            return None
        result = ReasoningResult(
            text=f"Rule matched: {plan.trigger_name}",
            tier="rule",
            model="rule_engine",
            tokens_used=0,
            latency_ms=0,
            confidence=1.0,
            action_tier=planned.dispatch_tier,
            proposed_action=planned.action,
        )
        context = SkillContext(
            skill=skill,
            event=event,
            state_store=self._state_store,
            trigger_name=plan.trigger_name,
        )
        try:
            return await self._dispatcher.dispatch(
                action=planned.action,
                tier=planned.dispatch_tier,
                context=context,
                result=result,
            )
        except Exception:
            # An executor ran, so the attempt stands whatever it raised.
            logger.exception(
                "DispatchCoordinator: action=%r failed for trigger=%r",
                planned.action,
                plan.trigger_name,
            )
            return None

    # ── everything below Tier D ──────────────────────────────────────────────

    async def _schedule_remainder(
        self, plan: TriggerPlan, event: OriEvent
    ) -> asyncio.Task[Any] | None:
        """Hand the trigger's remaining actions to the ordinary reasoning path.

        The task is returned so the caller can keep the event's arbitration
        scope open until it settles; it is still scheduled rather than awaited
        here, so the Tier D ordering this phase follows is unaffected.
        """
        if self._elevator is None:
            return None
        skill = self._skill_named(plan.skill_name)
        if skill is None:
            return None
        remaining = [
            a
            for a in plan.actions
            if a.admitted and a.outcome == DispatchOutcome.PENDING
        ]
        if not remaining:
            return None
        plan.scheduled = True
        dispatch_event = replace(
            event,
            context={
                **(event.context or {}),
                "__handler_trigger_name": plan.trigger_name,
                "__trigger_plan": plan,
                # The match itself, so the reasoning path does not evaluate the
                # rules a second time. Re-evaluating also read the cooldown this
                # plan had just charged, and the trigger suppressed itself.
                "__rule_result": plan.rule_result,
            },
        )
        task = asyncio.create_task(
            self._elevator.reason_and_dispatch(
                event=dispatch_event,
                skill=skill,
                state_store=self._state_store,
                dispatcher=self._dispatcher,
            ),
            name=f"reason:{plan.skill_name}:{plan.trigger_name}",
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        task.add_done_callback(lambda _finished: self._charge_plan(plan))
        return task

    def _charge_plan(self, plan: TriggerPlan) -> None:
        """Charge one trigger's cooldown once its scheduled work has settled.

        Charging at scheduling time was wrong, and the reasoning behind it —
        that all three consuming outcomes agree, so the distinction could not
        change the answer — left out the outcomes that consume nothing. An
        action admitted into the reasoning path can still be refused at the
        resource gate, and a trigger refused there has not had its turn: it must
        be able to re-raise on the next event rather than sit out its window.
        """
        engine = getattr(self._elevator, "_rule_engine", None)
        if engine is None or not hasattr(engine, "record_fire"):
            return
        if not plan.trigger_name:
            return
        for planned in plan.actions:
            if planned.outcome != DispatchOutcome.PENDING:
                continue
            # The reasoning path dispatched it and nothing recorded a refusal.
            planned.outcome = DispatchOutcome.ATTEMPTED
        outcome = plan.outcome
        if consumes_cooldown(outcome):
            engine.record_fire(plan.trigger_name, plan.skill_name)
        else:
            logger.debug(
                "DispatchCoordinator: trigger=%r consumed no cooldown (%s)",
                plan.trigger_name,
                outcome,
            )

    def _charge_cooldowns(self, plans: list[TriggerPlan]) -> None:
        engine = getattr(self._elevator, "_rule_engine", None)
        if engine is None or not hasattr(engine, "record_fire"):
            return
        for plan in plans:
            if plan.scheduled:
                # Charged when its task settles, so a refusal at the gate is
                # seen rather than assumed away.
                continue
            if not plan.trigger_name:
                continue
            outcome = plan.outcome
            if consumes_cooldown(outcome):
                engine.record_fire(plan.trigger_name, plan.skill_name)
            else:
                logger.debug(
                    "DispatchCoordinator: trigger=%r consumed no cooldown (%s)",
                    plan.trigger_name,
                    outcome,
                )

    # ── skill lookups ────────────────────────────────────────────────────────

    def _skill_named(self, name: str) -> Any:
        for skill in self._skills:
            if getattr(skill, "name", None) == name:
                return skill
        return None

    @staticmethod
    def _declared_actions(skill: Any, trigger_name: str) -> list[str]:
        actions = getattr(skill, "actions", None)
        if not isinstance(actions, dict):
            return []
        defaults = actions.get("defaults")
        if not isinstance(defaults, dict):
            return []
        named = defaults.get(trigger_name)
        if isinstance(named, str):
            return [named]
        if isinstance(named, list):
            return [str(a) for a in named if isinstance(a, str)]
        return []

    @staticmethod
    def _declared_tier(skill: Any, action: str) -> str:
        actions = getattr(skill, "actions", None)
        if not isinstance(actions, dict):
            return "A"
        for entry in actions.get("available") or []:
            if isinstance(entry, dict) and entry.get("name") == action:
                return str(entry.get("tier", "A")).upper()
        return "A"

    @staticmethod
    def _cooldown_for(skill: Any, trigger_name: str) -> int:
        for trigger in getattr(skill, "triggers", []) or []:
            name = (
                trigger.get("name")
                if isinstance(trigger, dict)
                else getattr(trigger, "name", None)
            )
            if name == trigger_name:
                raw = (
                    trigger.get("cooldown_seconds", 0)
                    if isinstance(trigger, dict)
                    else getattr(trigger, "cooldown_seconds", 0)
                )
                try:
                    return int(raw)
                except (TypeError, ValueError):
                    return 0
        return 0

    def _has_executor(self, action: str) -> bool:
        executors = getattr(self._dispatcher, "_executors", None)
        if not isinstance(executors, dict):
            return False
        return action in executors


__all__ = [
    "UNBOUND_ACTUATOR",
    "UNGOVERNED_ACTION",
    "DispatchCoordinator",
]
