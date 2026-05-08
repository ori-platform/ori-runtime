# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Skill loader — reads skill.yaml directories and wires EventBus handlers.

Usage::

    loader = SkillLoader(elevator, state_store, dispatcher)
    skills = loader.load_all("/path/to/skills")
    for skill in skills:
        loader.register(skill, event_bus)

The EventBus handler registered for each trigger returns in microseconds:
it checks cooldown synchronously, then fires
``asyncio.create_task(elevator.reason_and_dispatch(...))`` and returns.
All I/O (LLM inference, network, GPIO) runs inside the background task.
"""

import asyncio
import importlib.util
import logging
import re
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from ori.network.events import OriEvent
from ori.skills.os_sandbox import load_community_hooks
from ori.skills.sandbox import SkillSecurityError
from ori.skills.signing import verify_community_skill_signature

logger = logging.getLogger(__name__)

_VALID_TIERS = frozenset({"A", "B", "C", "D"})
_TRIGGER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_HUB_ROOT_PUBLIC_KEY_B64 = "PENDING_REPLACE_AT_HUB_LAUNCH"


# ── Exceptions ────────────────────────────────────────────────────────────────


class SkillValidationError(Exception):
    """Raised when a skill.yaml violates the Action Tier Framework rules."""


# ── Data model ────────────────────────────────────────────────────────────────


@dataclass
class Trigger:
    """One condition entry from a skill's ``triggers:`` list.

    Args:
        name: Unique trigger identifier within the skill (e.g. ``'anomalous_draw'``).
        condition: Python expression evaluated by the rule engine.
        action_tier: Required. One of ``'A'`` | ``'B'`` | ``'C'`` | ``'D'``.
        cooldown_seconds: Minimum seconds between consecutive fires. Default 0.
        escalate_to: ``'rule'`` | ``'local_slm'`` | ``'gateway'`` | ``'cloud'``.
        bypass_llm: If ``True``, the rule engine handles this trigger without
            any LLM call.  Always ``True`` for Tier D triggers (enforced).
        approval_timeout_seconds: Seconds to wait for operator approval (Tier C).
        safe_default_action: Action executed on approval timeout / NO response
            (Tier C).
    """

    name: str
    condition: str
    action_tier: str  # required — validated at load time
    cooldown_seconds: int = 0
    escalate_to: str = "local_slm"
    bypass_llm: bool = False
    approval_timeout_seconds: int = 300
    safe_default_action: str = "log_to_dashboard"


@dataclass
class Skill:
    """Parsed, validated representation of a ``skill.yaml`` file.

    Args:
        name: Skill name (e.g. ``'energy-anomaly-detector'``).
        version: SemVer string (e.g. ``'0.2.1'``).
        author: Author handle.
        sensors_required: List of sensor descriptor dicts (``type``, ``protocol``).
        triggers: Validated :class:`Trigger` objects.
        prompts: Mapping of trigger name → prompt template string.
        actions: Raw ``actions:`` dict from YAML (``available`` + ``defaults``).
        config: Free-form config dict forwarded to every reasoning call.
        hooks: Optional module loaded from ``hooks.py`` alongside ``skill.yaml``.
    """

    name: str
    version: str
    author: str
    sensors_required: list[dict] = field(default_factory=list)
    triggers: list[Trigger] = field(default_factory=list)
    prompts: dict[str, str] = field(default_factory=dict)
    actions: dict = field(default_factory=dict)
    config: dict = field(default_factory=dict)
    hooks: Any = None  # loaded module or None

    def get_default_actions_for_trigger(self, trigger_name: str) -> list[str]:
        """Return default actions for an exact trigger name."""
        defaults: dict[str, list[str]] = self.actions.get("defaults") or {}
        actions = defaults.get(trigger_name, [])
        if isinstance(actions, list):
            return list(actions)
        return []

    def get_default_actions(self, sensor_type: str) -> list[str]:
        """Return the list of default action names for *sensor_type*.

        The ``actions.defaults`` dict in the YAML maps trigger names to action
        lists.  This method finds the first matching trigger for *sensor_type*
        and returns its default actions.

        Args:
            sensor_type: The ``SensorReading.sensor_type`` value
                (e.g. ``'current_clamp'``).

        Returns:
            List of action name strings, or ``[]`` if no defaults are configured.
        """
        defaults: dict[str, list[str]] = self.actions.get("defaults") or {}
        # Find triggers that match sensor_type via sensors_required
        matching_sensor_types = {s.get("type") for s in self.sensors_required}
        for trigger in self.triggers:
            if sensor_type in matching_sensor_types:
                actions = defaults.get(trigger.name, [])
                if actions:
                    return actions
        return []

    def is_action_declared(self, action_name: str) -> bool:
        """Return True if *action_name* is declared in actions.available."""
        available = self.actions.get("available") or []
        for entry in available:
            if isinstance(entry, dict) and entry.get("name") == action_name:
                return True
            if isinstance(entry, str) and entry == action_name:
                return True
        return False


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


# ── Loader ───────────────────────────────────────────────────────────────────


class SkillLoader:
    """Loads, validates, and registers skills from the filesystem.

    Args:
        elevator: :class:`~ori.reasoning.elevator.IntelligenceElevator` instance.
        state_store: :class:`~ori.state.store.StateStore` instance (may be ``None``
            during testing).
        dispatcher: :class:`~ori.reasoning.action_dispatcher.ActionDispatcher`
            instance (may be ``None`` during testing).
    """

    def __init__(
        self,
        elevator: Any = None,
        state_store: Any = None,
        dispatcher: Any = None,
        os_sandbox_config: dict[str, Any] | None = None,
    ) -> None:
        self._elevator = elevator
        self._state_store = state_store
        self._dispatcher = dispatcher
        self._os_sandbox_config = (
            dict(os_sandbox_config) if isinstance(os_sandbox_config, dict) else {}
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def load_all(self, skills_dir: str) -> list[Skill]:
        """Load every skill sub-directory found under *skills_dir*.

        Each immediate child directory that contains a ``skill.yaml`` is treated
        as a skill.  Directories without ``skill.yaml`` are silently skipped.
        Skills that fail validation are logged and skipped — a single bad skill
        must not prevent the others from loading.

        Args:
            skills_dir: Path to the directory containing skill sub-directories.

        Returns:
            List of successfully loaded :class:`Skill` objects.
        """
        root = Path(skills_dir)
        if not root.is_dir():
            logger.warning("SkillLoader: skills_dir %r does not exist", skills_dir)
            return []

        skills: list[Skill] = []
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            # Template scaffolds are documentation assets, not runtime skills.
            if child.name == "template":
                continue
            yaml_path = child / "skill.yaml"
            if not yaml_path.exists():
                continue
            try:
                skill = self.load_one(child)
                skills.append(skill)
                logger.info(
                    "SkillLoader: loaded skill %r v%s from %s",
                    skill.name,
                    skill.version,
                    child,
                )
            except SkillValidationError as exc:
                logger.error(
                    "SkillLoader: validation failed for %s — %s", child.name, exc
                )
            except SkillSecurityError as exc:
                logger.error(
                    "SkillLoader: security validation failed for %s — %s",
                    child.name,
                    exc,
                )
            except Exception:
                logger.exception(
                    "SkillLoader: unexpected error loading skill from %s", child
                )
        return skills

    def load_one(self, skill_dir: Path | str) -> Skill:
        """Load and validate a single skill from *skill_dir*.

        Reads ``skill.yaml`` (required) and ``hooks.py`` (optional) from
        *skill_dir*.

        Args:
            skill_dir: Path to the skill directory (``str`` or :class:`~pathlib.Path`).

        Returns:
            A validated :class:`Skill` instance.

        Raises:
            SkillValidationError: If any trigger violates the Action Tier Framework.
            FileNotFoundError: If ``skill.yaml`` is missing.
            yaml.YAMLError: If the YAML is malformed.
        """
        skill_dir = Path(skill_dir)
        yaml_path = skill_dir / "skill.yaml"
        raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise SkillValidationError(
                f"Skill {skill_dir.name!r}: skill.yaml must be a mapping"
            )

        self._validate_skill_metadata(raw, skill_dir.name)

        triggers = self._parse_triggers(
            raw.get("triggers") or [], raw.get("name", "<unknown>")
        )
        actions = raw.get("actions") or {}
        self._validate_actions(
            actions,
            raw.get("name", "<unknown>"),
            trigger_names=[t.name for t in triggers],
        )
        self._verify_community_signature(raw, skill_dir)
        hooks = self._load_hooks(skill_dir)

        return Skill(
            name=raw.get("name", ""),
            version=str(raw.get("version", "0.0.0")),
            author=raw.get("author", ""),
            sensors_required=raw.get("sensors_required") or [],
            triggers=triggers,
            prompts=raw.get("prompts") or {},
            actions=raw.get("actions") or {},
            config=raw.get("config") or {},
            hooks=hooks,
        )

    def _verify_community_signature(
        self,
        raw: dict[str, Any],
        skill_dir: Path,
    ) -> None:
        """Verify signatures for community-installed skills only."""
        if self._is_bundled_skill(skill_dir):
            return

        if _HUB_ROOT_PUBLIC_KEY_B64 == "PENDING_REPLACE_AT_HUB_LAUNCH":
            raise SkillSecurityError(
                "community skill verification trust anchor is not configured"
            )

        verify_community_skill_signature(
            raw_skill=raw,
            trust_anchor_public_key_b64=_HUB_ROOT_PUBLIC_KEY_B64,
        )

    def _validate_skill_metadata(
        self, raw: dict[str, Any], skill_dir_name: str
    ) -> None:
        """Validate core metadata presence for runtime-loadable skills."""
        name = str(raw.get("name") or "").strip()
        version = str(raw.get("version") or "").strip()
        author = str(raw.get("author") or "").strip()
        triggers = raw.get("triggers")

        if not name:
            raise SkillValidationError(
                f"Skill directory {skill_dir_name!r}: missing required field 'name'"
            )
        if not version:
            raise SkillValidationError(
                f"Skill {name!r}: missing required field 'version'"
            )
        if not author:
            raise SkillValidationError(
                f"Skill {name!r}: missing required field 'author'"
            )
        if not isinstance(triggers, list) or len(triggers) == 0:
            raise SkillValidationError(
                f"Skill {name!r}: triggers must be a non-empty list"
            )

    def register(self, skill: Skill, event_bus: Any) -> list[tuple[str, Any]]:
        """Wire EventBus handlers for every trigger in *skill*.

        One handler is registered per (trigger, sensor_type) pair.  The handler:

        1. Checks the cooldown for the trigger synchronously.
        2. Evaluates whether the rule engine would even consider this trigger
           (sensor-type matching is handled at EventBus routing level).
        3. Fires ``asyncio.create_task(elevator.reason_and_dispatch(...))``
           and **returns immediately** — the handler adds zero latency to
           EventBus delivery for subsequent subscribers.

        Args:
            skill: A loaded and validated :class:`Skill`.
            event_bus: The :class:`~ori.network.event_bus.EventBus` instance
                to subscribe handlers on.
        Returns:
            List of ``(sensor_type, handler)`` tuples that were subscribed.
            Callers can reuse this list to unsubscribe the exact handlers later.
        """
        tracker = _CooldownTracker()
        subscriptions: list[tuple[str, Any]] = []

        for trigger in skill.triggers:
            sensor_types = [
                s.get("type") for s in skill.sensors_required if s.get("type")
            ]
            if not sensor_types:
                # Subscribe to wildcard if no sensor types declared
                sensor_types = ["*"]

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
        return subscriptions

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _validate_actions(
        self, actions_dict: dict, skill_name: str, trigger_names: list[str]
    ) -> None:
        """Enforce Explicit Capability validation for skill actions.

        Every action referenced in ``actions.defaults`` must be explicitly
        declared in ``actions.available`` with an appropriate tier.
        """
        available = actions_dict.get("available") or []
        defaults = actions_dict.get("defaults") or {}
        trigger_name_set = set(trigger_names)

        if not isinstance(defaults, dict):
            raise SkillValidationError(
                f"Skill {skill_name!r}: actions.defaults must be a mapping of "
                "trigger_name -> [action_names]"
            )

        available_names = {
            a.get("name") for a in available if isinstance(a, dict) and "name" in a
        }

        extra_defaults = sorted(set(defaults.keys()) - trigger_name_set)
        if extra_defaults:
            raise SkillValidationError(
                f"Skill {skill_name!r}: actions.defaults contains unknown trigger(s): "
                f"{extra_defaults}. Each defaults key must map to a declared trigger."
            )

        missing_defaults = sorted(trigger_name_set - set(defaults.keys()))
        if missing_defaults:
            raise SkillValidationError(
                f"Skill {skill_name!r}: missing actions.defaults mapping for trigger(s): "
                f"{missing_defaults}. Every trigger must declare default actions."
            )

        for trigger_name, default_action_list in defaults.items():
            if not isinstance(default_action_list, list):
                raise SkillValidationError(
                    f"Skill {skill_name!r}: actions.defaults.{trigger_name} must be a list"
                )
            if not default_action_list:
                raise SkillValidationError(
                    f"Skill {skill_name!r}: actions.defaults.{trigger_name} must "
                    "contain at least one action."
                )
            for action_name in default_action_list:
                if action_name not in available_names:
                    raise SkillValidationError(
                        f"Skill {skill_name!r}: trigger {trigger_name!r} defaults to "
                        f"undeclared action {action_name!r}. All actions must be explicitly "
                        f"declared in actions.available."
                    )

    def _parse_triggers(
        self, raw_triggers: list[dict], skill_name: str
    ) -> list[Trigger]:
        """Parse and validate raw trigger dicts from YAML.

        Validation rules (Action Tier Framework):
        - ``action_tier`` is required on every trigger.
        - ``action_tier`` must be one of ``A``, ``B``, ``C``, ``D``.
        - Tier D triggers must have ``bypass_llm: true`` (enforced automatically).
        - Tier C triggers must declare ``safe_default_action``.
        - ``bypass_llm: true`` without ``action_tier: D`` is a configuration error.

        Args:
            raw_triggers: List of trigger dicts from the YAML file.
            skill_name: Skill name used in error messages.

        Returns:
            List of validated :class:`Trigger` objects.

        Raises:
            SkillValidationError: On any validation failure.
        """
        triggers: list[Trigger] = []
        seen_trigger_names: set[str] = set()
        for raw in raw_triggers:
            if not isinstance(raw, dict):
                raise SkillValidationError(
                    f"Skill '{skill_name}': each trigger must be a mapping."
                )

            raw_name = raw.get("name")
            if not isinstance(raw_name, str) or not raw_name.strip():
                raise SkillValidationError(
                    f"Skill '{skill_name}' has a trigger with missing/empty name. "
                    "Trigger names must be non-empty strings."
                )
            name = raw_name.strip()
            if not _TRIGGER_NAME_RE.fullmatch(name):
                raise SkillValidationError(
                    f"Skill '{skill_name}' trigger '{name}' has invalid name format. "
                    "Use letters, numbers, underscore, and hyphen only."
                )
            if name in seen_trigger_names:
                raise SkillValidationError(
                    f"Skill '{skill_name}' has duplicate trigger name '{name}'. "
                    "Trigger names must be unique per skill."
                )
            seen_trigger_names.add(name)

            action_tier = raw.get("action_tier")

            if not action_tier:
                raise SkillValidationError(
                    f"Skill '{skill_name}' trigger '{name}' is missing required field 'action_tier'. "
                    f"Every trigger must declare its tier (A, B, C, or D)."
                )

            if action_tier not in _VALID_TIERS:
                raise SkillValidationError(
                    f"Skill '{skill_name}' trigger '{name}' has invalid action_tier={action_tier!r}. "
                    f"Must be one of: A, B, C, D."
                )

            bypass_llm = bool(raw.get("bypass_llm", False))

            # Tier D: enforce bypass_llm — safety-critical actions never reach LLM
            if action_tier == "D":
                bypass_llm = True

            # bypass_llm without Tier D is a misconfiguration
            if bypass_llm and action_tier != "D":
                raise SkillValidationError(
                    f"Skill '{skill_name}' trigger '{name}' sets bypass_llm=true but "
                    f"action_tier={action_tier!r}. bypass_llm is reserved for Tier D "
                    f"safety-critical triggers only."
                )

            safe_default_action = raw.get("safe_default_action", "log_to_dashboard")

            # Tier C must always have a fallback — do not allow it to be blank
            if action_tier == "C" and not safe_default_action:
                raise SkillValidationError(
                    f"Skill '{skill_name}' trigger '{name}' is Tier C (hard physical) "
                    f"but 'safe_default_action' is empty. Tier C triggers must always "
                    f"declare a safe_default_action for approval timeout / NO response."
                )

            triggers.append(
                Trigger(
                    name=name,
                    condition=raw.get("condition", ""),
                    action_tier=action_tier,
                    cooldown_seconds=int(raw.get("cooldown_seconds", 0)),
                    escalate_to=raw.get("escalate_to", "local_slm"),
                    bypass_llm=bypass_llm,
                    approval_timeout_seconds=int(
                        raw.get("approval_timeout_seconds", 300)
                    ),
                    safe_default_action=safe_default_action,
                )
            )
        return triggers

    def _load_hooks(self, skill_dir: Path) -> Any:
        hooks_path = skill_dir / "hooks.py"
        if not hooks_path.exists():
            return None
        # SECURITY: Community skills load through the restricted sandbox.
        # Bundled skills in the main repository (energy-anomaly-detector,
        # pc-system-health) are reviewed by the core team — they bypass
        # the sandbox via _is_bundled_skill(). Third-party installed skills
        # always use the restricted loader.
        if self._is_bundled_skill(skill_dir):
            return self._load_hooks_direct(hooks_path)
        return self._load_hooks_sandboxed(hooks_path)

    def _is_bundled_skill(self, skill_dir: Path) -> bool:
        # Bundled skills live in the skills/ directory of the repository.
        # Installed community skills live in ~/.ori/skills/.
        # A skill is bundled if its path is relative to the project root
        # (i.e., not under the user's home directory).
        import os

        home = Path(os.path.expanduser("~")).resolve()
        try:
            skill_dir.resolve().relative_to(home / ".ori" / "skills")
            return False  # Under ~/.ori/skills/ — community skill
        except ValueError:
            return True  # Not under user home — bundled skill

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
                "SkillLoader: failed to load hooks.py for %s", hooks_path.parent.name
            )
            return None

    def _load_hooks_sandboxed(self, hooks_path: Path) -> Any:
        # Used for all community skills installed from the Skills Hub.
        try:
            module = load_community_hooks(
                hooks_path=hooks_path,
                state_store=self._state_store,
                skill_name=hooks_path.parent.name,
                os_sandbox_config=self._os_sandbox_config,
            )
            if module is None:
                return None
            logger.info("SkillLoader: loaded hooks for %s", hooks_path.parent.name)
            return module
        except SkillSecurityError as exc:
            logger.error(
                "SkillLoader: security violation in %s hooks.py: %s",
                hooks_path.parent.name,
                exc,
            )
            return None  # Skill loads but hooks are disabled — safer than refusing entirely

    def _make_handler(
        self,
        skill: Skill,
        trigger: Trigger,
        tracker: _CooldownTracker,
    ):
        """Return a coroutine function suitable for EventBus subscription.

        The returned handler:

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

        async def handler(event: OriEvent) -> None:
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
