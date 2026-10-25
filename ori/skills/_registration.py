# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Handler registration, hook loading and the cooldown tracker."""

import asyncio
import importlib.metadata
import importlib.util
import inspect
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from ori.network.events import OriEvent
from ori.skills._core import (
    LoaderCore,
)
from ori.skills._manifest import (
    MAX_SUBSCRIPTIONS_PER_SKILL,
    MAX_TOTAL_SUBSCRIPTIONS,
    Skill,
    SkillValidationError,
    Trigger,
    unique_sensor_types,
)
from ori.skills.sandbox import SkillSecurityError
from ori.utils.path_utils import shown

# Every part of the loader logs as it did before the split, under one name an
# operator's logging configuration may already select.
logger = logging.getLogger("ori.skills.loader")


def refuse_asynchronous_hooks(skill_name: str, hooks: Any) -> None:
    """Hooks are synchronous: they run on the hook thread, never the event loop.

    A coroutine function would hand its body back to the loop to run, where
    synchronous work before its first await holds every reading behind it.
    """
    if hooks is None:
        return
    for name in ("pre_trigger_eval", "post_reasoning"):
        fn = getattr(hooks, name, None)
        if fn is not None and inspect.iscoroutinefunction(fn):
            raise SkillValidationError(
                f"Skill '{skill_name}' hook {name} is asynchronous; skill hooks "
                "must be synchronous functions, run on the hook thread."
            )


# ── Cooldown tracker ─────────────────────────────────────────────────────────


class _CooldownTracker:
    """Tracks the last fire time for each trigger by name."""

    def __init__(self) -> None:
        self._last_fired: dict[str, float] = {}

    def can_fire(self, trigger_name: str, cooldown_seconds: int) -> bool:
        """Return ``True`` if *trigger_name* is not in its cooldown window."""
        now = time.monotonic()
        last = self._last_fired.get(trigger_name)
        if last is None or (now - last) >= cooldown_seconds:
            return True
        return False

    def record_fire(self, trigger_name: str) -> None:
        """Record that *trigger_name* just fired."""
        self._last_fired[trigger_name] = time.monotonic()


class SkillRegistration(LoaderCore):
    """Handler registration and hook loading."""

    def register(self, skill: Skill, event_bus: Any) -> list[tuple[str, Any]]:
        """Wire EventBus handlers for every trigger in *skill*.

        One handler is registered per (trigger, sensor_type) pair, and the skill
        is added to the coordinator's discovery set when one is configured.
        Every handler returns immediately, adding no latency to EventBus
        delivery for subsequent subscribers: with a coordinator it funnels the
        event into the barrier, which decides once for the whole event; without
        one it checks its trigger's cooldown and schedules reasoning itself.

        Args:
            skill: A loaded and validated :class:`Skill`.
            event_bus: The :class:`~ori.network.event_bus.EventBus` instance
                to subscribe handlers on.
        Returns:
            List of ``(sensor_type, handler)`` tuples that were subscribed.
            Callers can reuse this list to unsubscribe the exact handlers later.
        """
        # Enforced here as well as at load, because this is the method that
        # actually creates handlers. `register()` is public and reachable
        # without `load_all()`, so relying on load-time validation would leave
        # the budget holding only for one call path.
        cost = self._subscription_cost(skill)
        if cost > MAX_SUBSCRIPTIONS_PER_SKILL:
            raise SkillValidationError(
                f"Skill {skill.name!r}: registering {cost} handlers exceeds the "
                f"limit of {MAX_SUBSCRIPTIONS_PER_SKILL}."
            )
        if self._registered_subscriptions + cost > MAX_TOTAL_SUBSCRIPTIONS:
            raise SkillValidationError(
                f"Skill {skill.name!r}: registering {cost} handlers would take "
                f"this loader past the cumulative limit of "
                f"{MAX_TOTAL_SUBSCRIPTIONS} subscriptions "
                f"({self._registered_subscriptions} already registered)."
            )

        if self._coordinator is not None:
            self._coordinator.add_skill(skill)

        tracker = _CooldownTracker()
        subscriptions: list[tuple[str, Callable[[OriEvent], Awaitable[None]]]] = []

        # Deduplicated so registration matches _subscription_cost() exactly.
        # The cost counted unique types while this loop registered one handler
        # per list entry, so a skill declaring the same sensor twenty times was
        # charged once and registered twenty handlers — the budget measuring
        # something other than what it was bounding. Duplicate declarations are
        # also pointless: two handlers on one sensor type fire on the same
        # events.
        sensor_types = unique_sensor_types(skill.sensors_required)

        for trigger in skill.triggers:
            for sensor_type in sensor_types:
                handler = self._make_handler(skill, trigger, tracker)
                event_bus.subscribe(sensor_type, handler)
                subscriptions.append((sensor_type, handler))
                logger.debug(
                    "SkillLoader: registered handler skill=%r trigger=%r sensor_type=%r",
                    skill.name,
                    trigger.name,
                    sensor_type,
                )
        self._registered_subscriptions += len(subscriptions)
        return subscriptions

    def unregister(
        self,
        subscriptions: list[tuple[str, Callable[[OriEvent], Awaitable[None]]]],
        event_bus: Any,
    ) -> None:
        """Remove handlers and return their capacity to the budget.

        The budget counts **active** subscriptions, not subscriptions ever
        created. Without this the counter only ever rose, so a runtime that
        reloads its skills — replacing the same handlers over and over —
        exhausted it after enough cycles and then failed to register anything,
        having already removed the previous graph. A reload is not new load.

        Callers must route unsubscription through here rather than calling
        ``event_bus.unsubscribe`` directly, or the accounting drifts the same
        way again.
        """
        if self._coordinator is not None and subscriptions:
            # The runtime replaces its handler graph wholesale, so removing
            # handlers removes the skills they represent. A skill left in the
            # discovery set after its handlers are gone would keep being
            # evaluated by whatever handler remains.
            self._coordinator.clear_skills()

        removed = 0
        for sensor_type, handler in subscriptions:
            if event_bus is not None:
                event_bus.unsubscribe(sensor_type, handler)
            removed += 1
        self._registered_subscriptions = max(
            0, self._registered_subscriptions - removed
        )

    @property
    def active_subscriptions(self) -> int:
        """Handlers currently registered through this loader."""
        return self._registered_subscriptions

    def planned_subscription_cost(self, skills: list[Skill]) -> int:
        """Total handlers *skills* would register, for pre-flight checks."""
        return sum(self._subscription_cost(skill) for skill in skills)

    @staticmethod
    def _subscription_cost(skill: Skill) -> int:
        """Handlers this skill will create: triggers × distinct sensor types.

        Shares :func:`unique_sensor_types` with :meth:`register` so the number
        charged is by construction the number registered.
        """
        return len(skill.triggers) * len(unique_sensor_types(skill.sensors_required))

    def _make_handler(
        self,
        skill: Skill,
        trigger: Trigger,
        tracker: _CooldownTracker,
    ) -> Callable[[OriEvent], Awaitable[None]]:
        """Return a coroutine function suitable for EventBus subscription.

        With a coordinator configured the handler hands the event to the
        event-wide barrier and returns; the barrier owns evaluation, ordering
        and cooldown, so this handler decides nothing about its own trigger.

        Without one it keeps the standalone behaviour:

        - Checks cooldown **synchronously** and returns in microseconds if in
          cooldown.
        - Records the fire timestamp before dispatching so back-to-back events
          during inference do not double-fire.
        - Wraps the full reasoning pipeline in ``asyncio.create_task()`` so that
          EventBus delivery to subsequent subscribers is never blocked by LLM
          inference (which takes 3–8 seconds for a local model).

        Args:
            skill: The owning skill.
            trigger: The trigger this handler fires for.
            tracker: Shared cooldown state for the skill.

        Returns:
            An ``async def`` function that accepts a single :class:`OriEvent`.
        """
        elevator = self._elevator
        state_store = self._state_store
        dispatcher = self._dispatcher

        coordinator = self._coordinator

        async def handler(event: OriEvent) -> None:
            if coordinator is not None:
                # The barrier decides once, for the whole event, across every
                # registered skill. The first handler to arrive performs that
                # evaluation and the rest return; cooldown is charged there,
                # against the outcome each trigger actually reached, rather
                # than here before the condition is known to match.
                await coordinator.handle_event(event)
                return

            if not tracker.can_fire(trigger.name, trigger.cooldown_seconds):
                logger.debug(
                    "SkillLoader: trigger=%r in cooldown — skipping event_id=%s",
                    trigger.name,
                    event.event_id,
                )
                return

            # Record fire time before dispatching — prevents double-fire during inference
            tracker.record_fire(trigger.name)

            if elevator is None:
                logger.warning(
                    "SkillLoader: no elevator configured — cannot reason for trigger=%r",
                    trigger.name,
                )
                return

            # CRITICAL: create_task returns immediately. LLM inference, network I/O,
            # and GPIO all happen inside the background task. This handler must not
            # block EventBus delivery to subsequent subscribers.
            dispatch_event = replace(
                event,
                context={
                    **(event.context or {}),
                    "__handler_trigger_name": trigger.name,
                },
            )
            asyncio.create_task(
                elevator.reason_and_dispatch(
                    event=dispatch_event,
                    skill=skill,
                    state_store=state_store,
                    dispatcher=dispatcher,
                ),
                name=f"reason:{skill.name}:{trigger.name}",
            )

        # Give the handler a useful name for logging
        handler.__name__ = f"{skill.name}:{trigger.name}"
        return handler

    def _assert_hooks_activatable(self, skill_dir: Path) -> Path | None:
        """Apply the hook activation policy. Executes nothing.

        Provenance decides execution. First-party skills are packaged with the
        runtime and reviewed with it, so their hooks may be imported.
        Everything else is community content, and there is currently no
        supported way to execute community hook code — see
        :mod:`ori.skills.sandbox`.

        A community skill that carries ``hooks.py`` is refused outright rather
        than loaded with its hooks quietly missing. Its triggers were written
        expecting derived values the runtime will not produce, so loading it
        would activate a skill whose conditions no longer mean what the author
        wrote — including, potentially, its safety conditions.

        Separated from loading so that validation can reach the same verdict
        the runtime will, without running anything to get there.

        Returns:
            The path to ``hooks.py``, or ``None`` when the skill has none.
        """
        hooks_path = skill_dir / "hooks.py"
        if not hooks_path.exists():
            return None
        if self._is_core_bundled_skill(skill_dir):
            return hooks_path
        raise SkillSecurityError(
            f"skill at {skill_dir} is not first-party and carries hooks.py. "
            "Community hook execution is disabled: the in-process loader was "
            "not a security boundary and has been removed. The skill is not "
            "loaded, because running it without its hooks would change what "
            "its triggers evaluate."
        )

    def _load_hooks(self, skill_dir: Path) -> Any:
        """Apply the activation policy, then import the hooks it permits."""
        hooks_path = self._assert_hooks_activatable(skill_dir)
        if hooks_path is None:
            return None
        return self._load_hooks_direct(hooks_path)

    def _load_hooks_direct(self, hooks_path: Path) -> Any:
        # Used for core team reviewed bundled skills only.
        try:
            spec = importlib.util.spec_from_file_location(
                f"ori_skill_{hooks_path.parent.name}_hooks", hooks_path
            )
            if spec is None or spec.loader is None:
                return None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception:
            logger.exception(
                "SkillLoader: failed to load hooks.py for %s",
                shown(hooks_path.parent.name),
            )
            return None
