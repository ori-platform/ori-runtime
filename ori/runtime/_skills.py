# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Reloading skills, and removing a skill's handlers from the event bus."""

import asyncio
import logging

from ori.runtime._core import RuntimeCore
from ori.skills.loader import MAX_TOTAL_SUBSCRIPTIONS as SKILL_SUBSCRIPTION_BUDGET
from ori.skills.selection import load_selection, skills_dir_for
from ori.utils.path_utils import shown

logger = logging.getLogger("ori.runtime")


class SkillReload(RuntimeCore):
    """Reloading skills in place."""

    # ── Public API ────────────────────────────────────────────────────────────

    async def reload_skills(self, *, refuse_unresolved: bool = False) -> bool:
        """Reload the skills ``skills:`` names without restarting the runtime.

        A ``skills:`` entry that names no skill, or names one whose manifest
        disagrees with it, keeps the existing handlers; with
        *refuse_unresolved*, as at startup, it raises
        :class:`SkillSelectionError` instead.

        This method preserves the same validation and sandbox rules as startup:
        it reuses :class:`ori.skills.loader.SkillLoader` and only swaps handlers
        after the new skill set has been loaded successfully.

        Semantics:
        - Reload affects **new events only** after handler swap.
        - In-flight ``reason_and_dispatch`` tasks continue under the skill/config
          snapshot they started with. This avoids mutating active Tier C/Tier D
          flows mid-execution.
        """
        if self._skill_reload_lock is None:
            self._skill_reload_lock = asyncio.Lock()

        async with self._skill_reload_lock:
            if self._event_bus is None or self._skill_loader is None:
                logger.warning(
                    "[runtime] skill reload requested before startup completed"
                )
                return False

            skills_dir = skills_dir_for(self._skills_dir, self._config_path)
            loaded = load_selection(
                self._skill_loader,
                self._skill_selection,
                skills_dir,
                refuse_unresolved=refuse_unresolved,
            )
            if loaded is None:
                return False

            # Safety-first fallback: do not replace a working handler graph
            # with an empty one due to a transient load issue.
            if not loaded and self._loaded_skills:
                logger.warning(
                    "[runtime] skill reload found 0 valid skills in %s — keeping existing handlers",
                    shown(skills_dir),
                )
                return False

            # Check the whole plan before removing anything. Registration is
            # what enforces the subscription budget, so discovering mid-way
            # that the new set does not fit would leave the runtime with the
            # old handlers already gone and only some replacements installed —
            # including, potentially, missing Tier D coverage.
            planned = self._skill_loader.planned_subscription_cost(loaded)
            if planned > SKILL_SUBSCRIPTION_BUDGET:
                logger.error(
                    "[runtime] skill reload rejected — %d handlers exceeds the "
                    "budget of %d; keeping the existing handler graph",
                    planned,
                    SKILL_SUBSCRIPTION_BUDGET,
                )
                return False

            self._unregister_skill_handlers()
            try:
                for skill in loaded:
                    subscriptions = self._skill_loader.register(skill, self._event_bus)
                    self._skill_subscriptions.extend(subscriptions)
            except Exception:
                # The old graph is already gone. Report at CRITICAL rather than
                # letting a partially registered runtime look healthy.
                logger.critical(
                    "[runtime] skill registration failed mid-reload — the "
                    "handler graph is incomplete and safety triggers may be "
                    "missing. Restart the runtime.",
                    exc_info=True,
                )
                raise

            self._loaded_skills = loaded
            for skill in loaded:
                self._startup_skill_configs.setdefault(skill.name, dict(skill.config))
            logger.info(
                "[runtime] skills reloaded — skills=%d triggers=%d source=%s",
                len(self._loaded_skills),
                sum(len(s.triggers) for s in self._loaded_skills),
                shown(skills_dir),
            )
            return True

    def _unregister_skill_handlers(self) -> None:
        # Routed through the loader so the subscription budget is credited
        # back. Unsubscribing directly from the bus removes the handlers but
        # leaves the loader believing they are still registered, which made a
        # long-running runtime exhaust its budget through ordinary reloads.
        loader = getattr(self, "_skill_loader", None)
        if loader is not None:
            loader.unregister(self._skill_subscriptions, self._event_bus)
        elif self._event_bus is not None:
            for sensor_type, handler in self._skill_subscriptions:
                self._event_bus.unsubscribe(sensor_type, handler)
        self._skill_subscriptions.clear()
