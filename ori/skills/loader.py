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
import errno
import importlib.util
import logging
import os
import re
import stat
import sysconfig
import time
import unicodedata
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from ori.network.events import OriEvent
from ori.reasoning.action_registry import (
    capability,
    is_safe_default_eligible,
    minimum_tier,
    tier_rank,
)
from ori.reasoning.rule_engine import RESERVED_CONTEXT_NAMES
from ori.skills.sandbox import SkillSecurityError
from ori.skills.signing import verify_community_skill_signature

logger = logging.getLogger(__name__)

_VALID_TIERS = frozenset({"A", "B", "C", "D"})
_TRIGGER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_HISTORY_PLACEHOLDER_PATTERN = re.compile(r"\{history\.[^{}]+\}")
_MAX_HISTORY_PLACEHOLDERS = 16
_BUNDLED_SIGNATURE_SENTINEL = "bundled"
# Generous for a manifest — the largest bundled skill.yaml is a few KiB.
# This bounds resource use before trust is established, not authorship.
_MAX_MANIFEST_BYTES = 1 << 20

# ── Workload budgets ─────────────────────────────────────────────────────────
#
# The parser limits above bound *syntax*: how large a document may be and how
# deeply it may nest. They say nothing about how much work the accepted document
# creates. Registration produces one EventBus handler per trigger × required
# sensor type, so a structurally valid manifest well inside every syntax limit
# can still ask for tens of thousands of subscriptions, each scheduling a
# reasoning task on the event loop that Tier D safety processing shares.
#
# Valid provenance does not make a resource-exhausting skill safe: a signed
# community skill is still untrusted in this respect, and a first-party skill
# can be wrong by accident. These are runtime safety boundaries, not an
# authoring style guide.
#
# Current packaged inventory, for reference when these are revisited:
#   9 skills, 370 subscriptions in total
#   largest single skill: prosumer-energy-advisor, 8 triggers x 20 sensor types
#                         = 160 subscriptions
#   maxima across all nine: 8 triggers, 20 sensor types, 5 declared actions,
#                           4 actions in one default list, 20 default references,
#                           8 prompts, 19 config entries
#
# Headroom against that inventory is *not* the justification for these values,
# and must not be used to raise them. Handler count is a proxy: actual load also
# depends on sensor event frequency, reasoning duration, cooldowns and
# concurrent tasks, so a skill with few handlers on a fast sensor can cost more
# than a larger quiet one. Raising a cap requires event-loop benchmarking on the
# supported deployment targets, not an inventory measurement.
_MAX_SKILLS_PER_LOAD = 64
_MAX_TRIGGERS_PER_SKILL = 64
_MAX_SENSORS_PER_SKILL = 32
_MAX_SUBSCRIPTIONS_PER_SKILL = 256
_MAX_ACTIONS_AVAILABLE = 64
# Actions dispatched when one trigger fires. The elevator iterates this list
# and dispatches every entry, so it is execution work, not declaration size.
# The longest list in any packaged skill is 4.
_MAX_ACTIONS_PER_TRIGGER = 16
# Total default-action references across one skill; the packaged maximum is 20.
_MAX_TOTAL_DEFAULT_REFERENCES = 256
_MAX_PROMPTS_PER_SKILL = 64
_MAX_CONFIG_ENTRIES = 256
# Cumulative across a whole load: individually legal skills must not add up to
# an illegal total. Without this, the per-skill caps are a per-file courtesy.
MAX_TOTAL_SUBSCRIPTIONS = 1024
_MAX_TOTAL_SUBSCRIPTIONS = MAX_TOTAL_SUBSCRIPTIONS
# Directory entries examined during discovery. Bounds the walk itself, so a
# directory padded with non-skill entries cannot force an unbounded scan.
_MAX_DIRECTORY_ENTRIES = 4096

# Identity fields appear in logs, operator alerts and audit records, so they are
# bounded and stripped of control characters — a name carrying an escape
# sequence can rewrite what an operator sees a decision attributed to.
_MAX_NAME_LENGTH = 64
_MAX_AUTHOR_LENGTH = 128
_MAX_VERSION_LENGTH = 32
_SKILL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


# ── Exceptions ────────────────────────────────────────────────────────────────


class SkillValidationError(Exception):
    """Raised when a skill.yaml violates the Action Tier Framework rules."""


def _packaged_skill_names() -> frozenset[str]:
    """Directory names of every skill that ships with the runtime.

    Read from the packaged roots rather than a hard-coded list so a skill added
    to the package is protected from impersonation without a second edit.
    """
    names: set[str] = set()
    for root in first_party_skill_roots():
        try:
            for child in root.iterdir():
                if (child / "skill.yaml").is_file():
                    names.add(child.name)
        except OSError:
            continue
    return frozenset(names)


def _display_unsafe_character(value: str) -> str | None:
    """Describe the first character that could misrepresent *value*, if any.

    ASCII C0/DEL was not enough. Unicode format characters (category ``Cf``)
    include the bidirectional overrides — U+202E RIGHT-TO-LEFT OVERRIDE and
    friends — which reverse how following text is *displayed* without changing
    what is stored. An author string carrying one renders in a log or an
    operator's terminal as something other than what was recorded, which is
    precisely the property these fields are checked for.

    Line and paragraph separators are refused for the same reason as newlines:
    a single log line becoming two lets a name forge a second record.
    """
    for char in value:
        category = unicodedata.category(char)
        if category == "Cc" or char == "\x7f":
            return f"a control character (U+{ord(char):04X})"
        if category == "Cf":
            return f"a Unicode format character (U+{ord(char):04X})"
        if category in {"Zl", "Zp"}:
            return f"a line or paragraph separator (U+{ord(char):04X})"
        if category == "Cs":
            return f"a surrogate (U+{ord(char):04X})"
    return None


def _unique_sensor_types(sensors_required: list[dict[str, Any]]) -> list[str]:
    """Distinct sensor types a skill subscribes to, in declaration order.

    The single definition used by both registration and cost accounting. When
    they computed it separately they disagreed, and a budget that measures
    something other than what it bounds is not a budget.

    A skill declaring no usable sensor type subscribes to the wildcard, which
    is the expensive case — a wildcard handler runs for every reading on the
    bus — so it counts as one subscription rather than none.
    """
    seen: list[str] = []
    for sensor in sensors_required:
        if not isinstance(sensor, dict):
            continue
        sensor_type = sensor.get("type")
        if isinstance(sensor_type, str) and sensor_type and sensor_type not in seen:
            seen.append(sensor_type)
    return seen or ["*"]


class _UniqueStringKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader with bounded structure and no aliases.

    The byte cap in :meth:`SkillLoader._read_manifest_bytes` bounds the file on
    disk, not the structure it expands into. A small document can describe a
    very large one: aliases let a node be referenced repeatedly, so repeated
    referencing multiplies the constructed object graph far beyond the source
    size, and deep nesting can exhaust the recursion the composer uses.

    That matters here specifically because **parsing happens before signature
    verification** — the manifest has to be constructed to be canonicalised and
    checked — so every limit below applies to content the runtime has not yet
    decided to trust. Signed YAML-only community skills are a supported case,
    and an unsigned manifest still reaches this composer before its signature is
    rejected. Deferring these limits would have left startup exposed to a
    pathological or hostile manifest.

    Aliases are refused outright rather than budgeted. Defining expansion
    semantics that are safe under adversarial input is harder than doing
    without them, and no skill needs them: no bundled skill uses an anchor, and
    a manifest is a flat declaration, not a program.
    """

    # Room for the deepest legitimate manifest with a wide margin: the bundled
    # skills reach depth 5. These bound hostile input, not authorship.
    max_depth = 32
    max_nodes = 20_000
    max_collection_entries = 1_000

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self._depth = 0
        self._node_count = 0

    def _limit_error(self, detail: str) -> SkillValidationError:
        return SkillValidationError(f"skill.yaml exceeds manifest limits: {detail}")

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.events.AliasEvent):
            event = self.peek_event()
            raise self._limit_error(
                f"YAML aliases are not permitted (*{event.anchor}). Write the "
                "value out in full — a manifest is a declaration, not a program."
            )

        self._node_count += 1
        if self._node_count > self.max_nodes:
            raise self._limit_error(f"more than {self.max_nodes} nodes")

        self._depth += 1
        if self._depth > self.max_depth:
            raise self._limit_error(f"nesting deeper than {self.max_depth} levels")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def compose_sequence_node(self, anchor: Any) -> Any:
        node = super().compose_sequence_node(anchor)
        if len(node.value) > self.max_collection_entries:
            raise self._limit_error(
                f"a sequence with more than {self.max_collection_entries} entries"
            )
        return node

    def compose_mapping_node(self, anchor: Any) -> Any:
        node = super().compose_mapping_node(anchor)
        if len(node.value) > self.max_collection_entries:
            raise self._limit_error(
                f"a mapping with more than {self.max_collection_entries} keys"
            )
        return node


def _construct_unique_string_mapping(
    loader: _UniqueStringKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[str, Any]:
    loader.flatten_mapping(node)
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise yaml.constructor.ConstructorError(
                "while constructing a skill mapping",
                node.start_mark,
                "skill mapping keys must be strings",
                key_node.start_mark,
            )
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a skill mapping",
                node.start_mark,
                f"duplicate skill mapping key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueStringKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_string_mapping,
)
_HUB_ROOT_PUBLIC_KEY_B64 = "PENDING_REPLACE_AT_HUB_LAUNCH"
_HUB_TRUST_ANCHOR_ENV = "ORI_HUB_ROOT_PUBLIC_KEY_B64"

# Where first-party skills live. A source checkout keeps them beside the
# package; an installed wheel puts them under the interpreter's data path.
# Both are shipped with the runtime and reviewed with it.
_SKILLS_DATA_DIR = Path("share") / "ori-runtime" / "skills"


def first_party_skill_roots() -> tuple[Path, ...]:
    """Every directory whose contents ship with the runtime.

    This is the single definition of first-party provenance. It was previously
    duplicated — the loader knew only about the source checkout while
    ``bundled_skill_path()`` also resolved the installed layout, so a packaged
    skill loaded from a wheel was classified as untrusted community content and
    refused. Both call this now, because two definitions of "shipped with the
    runtime" is one more than a trust boundary can have.

    Only roots that exist are returned, so a layout that does not apply cannot
    contribute a directory an attacker might otherwise create.
    """
    candidates = (
        Path(__file__).resolve().parents[2] / "skills",
        Path(sysconfig.get_path("data")) / _SKILLS_DATA_DIR,
    )
    roots: list[Path] = []
    for candidate in candidates:
        try:
            if candidate.is_dir():
                roots.append(candidate.resolve())
        except OSError:  # unreadable or unresolvable — not a usable root
            continue
    return tuple(roots)


# ── Data model ────────────────────────────────────────────────────────────────


@dataclass
class Trigger:
    """One condition entry from a skill's ``triggers:`` list.

    Args:
        name: Unique trigger identifier within the skill (e.g. ``'anomalous_draw'``).
        condition: Python expression evaluated by the rule engine.
        action_tier: Required. One of ``'A'`` | ``'B'`` | ``'C'`` | ``'D'``.
        cooldown_seconds: Minimum seconds between consecutive fires. Default 0.
        escalate_to: ``'rule'`` | ``'local_slm'`` | ``'gateway'``.
        bypass_llm: If ``True``, the rule engine handles this trigger without
            any LLM call.  Always ``True`` for Tier D triggers (enforced).
        requires_approval: If ``True``, Tier B trigger dispatch uses the approval
            workflow instead of autonomous execution.
        reasoning_policy: Optional execution/reasoning policy. ``post_action`` is
            valid only for Tier B and executes the deterministic action before
            asynchronous advisory reasoning.
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
    requires_approval: bool = False
    reasoning_policy: str = ""
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
    sensors_required: list[dict[str, Any]] = field(default_factory=list)
    triggers: list[Trigger] = field(default_factory=list)
    prompts: dict[str, str] = field(default_factory=dict)
    actions: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    hooks: Any = None  # loaded module or None
    # Whether this skill ships with the runtime. Set by SkillLoader from the
    # packaged skill roots; never read from skill.yaml, so a skill cannot claim
    # it. Tier D authority depends on it.
    first_party: bool = False

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
        matching_sensor_types: set[str] = set()
        for sensor in self.sensors_required:
            declared_sensor_type = sensor.get("type")
            if isinstance(declared_sensor_type, str):
                matching_sensor_types.add(declared_sensor_type)
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
        community_trust_anchor_public_key_b64: str | None = None,
        require_signed: bool = False,
    ) -> None:
        self._elevator = elevator
        self._state_store = state_store
        self._dispatcher = dispatcher
        self._os_sandbox_config = (
            dict(os_sandbox_config) if isinstance(os_sandbox_config, dict) else {}
        )
        self._community_trust_anchor_public_key_b64 = (
            str(community_trust_anchor_public_key_b64).strip()
            if isinstance(community_trust_anchor_public_key_b64, str)
            else None
        )
        self._require_signed = bool(require_signed)
        # Running total of handlers this loader has subscribed, so the
        # cumulative budget survives across separate register() calls.
        self._registered_subscriptions = 0

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
        seen_names: dict[str, Path] = {}
        subscription_total = 0
        for child in self._discover_candidates(root):
            try:
                skill = self.load_one(child)

                # Names identify skills in logs, action records and operator
                # messages. Two skills answering to one name makes those records
                # ambiguous exactly where they are used to attribute a physical
                # action, so the second is refused rather than silently shadowing
                # the first.
                previous = seen_names.get(skill.name)
                if previous is not None:
                    logger.error(
                        "SkillLoader: skipping %s — skill name %r is already "
                        "loaded from %s",
                        child,
                        skill.name,
                        previous,
                    )
                    continue

                # Per-skill caps are a per-file courtesy without this: sixty
                # individually legal skills add up to an illegal total, and the
                # event loop sees the sum, not the individual files.
                cost = self._subscription_cost(skill)
                if subscription_total + cost > _MAX_TOTAL_SUBSCRIPTIONS:
                    logger.error(
                        "SkillLoader: skipping %s — its %d handlers would take "
                        "the load past the cumulative limit of %d "
                        "subscriptions (%d already committed)",
                        child,
                        cost,
                        _MAX_TOTAL_SUBSCRIPTIONS,
                        subscription_total,
                    )
                    continue
                subscription_total += cost

                seen_names[skill.name] = child
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

    def validate_one(self, skill_dir: Path | str) -> Skill:
        """Answer "would the runtime activate this?" **without executing it**.

        Inspecting a skill must not run it: listing and validation used to go
        through :meth:`load_one`, which imports ``hooks.py``, so displaying an
        untrusted skill's name executed its top-level code.

        Every check the runtime applies is applied here, including the hook
        activation policy — only the execution is skipped. A validation that
        approved skills the runtime then refused would be worse than none,
        because it would be consulted precisely when someone is deciding
        whether a skill is safe to install.

        Args:
            skill_dir: Path to the skill directory.

        Returns:
            A validated :class:`Skill` with no hooks attached.

        Raises:
            SkillSecurityError: If the runtime would refuse to activate it.
        """
        return self.load_one(skill_dir, load_hooks=False)

    def inspect_one(self, skill_dir: Path | str) -> Skill:
        """Parse and validate for **reporting**, without the activation policy.

        This is for listing: a skill the runtime will not activate still has a
        name and a version worth showing, and an operator looking at the list
        is usually trying to find out why. Use :meth:`validate_one` to decide
        whether a skill is usable; use this only to describe one.

        Nothing is executed here either.
        """
        return self.load_one(skill_dir, load_hooks=False, enforce_hook_policy=False)

    def load_one(
        self,
        skill_dir: Path | str,
        *,
        load_hooks: bool = True,
        enforce_hook_policy: bool = True,
    ) -> Skill:
        """Load and validate a single skill from *skill_dir*.

        Reads ``skill.yaml`` (required) and ``hooks.py`` (optional) from
        *skill_dir*.

        Args:
            load_hooks: When ``False``, ``hooks.py`` is neither read nor
                executed and ``Skill.hooks`` is ``None``. The activation policy
                still applies unless *enforce_hook_policy* is also ``False``.
            enforce_hook_policy: When ``False``, a skill whose hooks the runtime
                would refuse to activate is still returned. For reporting only.
                Prefer :meth:`validate_one` or :meth:`inspect_one` over passing
                these directly.
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
        raw = (
            yaml.load(
                self._read_manifest_bytes(yaml_path),
                Loader=_UniqueStringKeySafeLoader,
            )
            or {}
        )
        if not isinstance(raw, dict):
            raise SkillValidationError(
                f"Skill {skill_dir.name!r}: skill.yaml must be a mapping"
            )

        self._validate_skill_metadata(raw, skill_dir)
        self._validate_identity_fields(raw, skill_dir)
        self._validate_workload_budgets(raw, raw.get("name", "<unknown>"))

        first_party = self._is_core_bundled_skill(skill_dir)
        triggers = self._parse_triggers(
            raw.get("triggers") or [],
            raw.get("name", "<unknown>"),
            first_party=first_party,
        )
        actions = raw.get("actions") or {}
        self._validate_actions(
            actions,
            raw.get("name", "<unknown>"),
            trigger_names=[t.name for t in triggers],
        )
        self._validate_tier_b_trigger_policies(
            triggers,
            actions,
            raw.get("name", "<unknown>"),
        )
        prompts = raw.get("prompts") or {}
        self._validate_history_placeholder_count(
            prompts=prompts,
            skill_name=raw.get("name", "<unknown>"),
            trigger_names=[t.name for t in triggers],
        )
        self._validate_reserved_config_names(
            raw.get("config") or {},
            raw.get("name", "<unknown>"),
        )
        self._verify_community_signature(raw, skill_dir)
        if load_hooks:
            hooks = self._load_hooks(skill_dir)
        else:
            if enforce_hook_policy:
                self._assert_hooks_activatable(skill_dir)
            hooks = None

        return Skill(
            name=raw.get("name", ""),
            version=str(raw.get("version", "0.0.0")),
            author=raw.get("author", ""),
            sensors_required=raw.get("sensors_required") or [],
            triggers=triggers,
            prompts=prompts,
            actions=raw.get("actions") or {},
            config=raw.get("config") or {},
            hooks=hooks,
            first_party=first_party,
        )

    def _read_manifest_bytes(self, yaml_path: Path) -> str:
        """Read ``skill.yaml`` under admission limits, before parsing it.

        The path is opened **once**, and every decision is taken from that one
        descriptor. An earlier version called ``lstat()``, validated the result,
        then opened the path separately — which is check-then-use: the path can
        be replaced with a symlink, FIFO or device node between the two calls,
        so the file that was inspected need not be the file that was read. That
        defeats the exact property the check claimed to establish.

        The flags carry the guarantees instead:

        - ``O_NOFOLLOW`` fails if the final component is a symlink, so the
          symlink case is refused by the kernel rather than by a prior check.
        - ``O_NONBLOCK`` means opening a FIFO returns immediately instead of
          blocking until a writer appears — a named pipe in the skills
          directory fails startup rather than hanging it indefinitely.
        - ``O_CLOEXEC`` keeps the descriptor out of any child process.

        ``fstat()`` on the descriptor then decides the file type, and the bytes
        are read from that same descriptor under an explicit cap, so an
        oversized manifest cannot exhaust memory before the runtime has decided
        whether to trust it.

        Structural limits — alias rejection, nesting depth, node and collection
        budgets — are enforced during parsing by
        :class:`_UniqueStringKeySafeLoader`, because a byte bound does not bound
        the structure a document expands into.
        """
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        # Both are POSIX; guarded so a platform without them still builds
        # rather than failing at import.
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)

        try:
            fd = os.open(yaml_path, flags)
        except FileNotFoundError:
            raise
        except OSError as exc:
            # ELOOP is O_NOFOLLOW refusing a symlink. Anything else is reported
            # as an inspection failure rather than guessed at.
            if exc.errno == errno.ELOOP:
                raise SkillSecurityError(
                    f"Skill {yaml_path.parent.name!r}: skill.yaml is a symlink. "
                    "Manifests must be regular files so the bytes validated are "
                    "the bytes on disk."
                ) from exc
            raise SkillValidationError(
                f"Skill {yaml_path.parent.name!r}: skill.yaml could not be "
                f"opened ({exc.__class__.__name__})."
            ) from exc

        try:
            stat_result = os.fstat(fd)
            if not stat.S_ISREG(stat_result.st_mode):
                raise SkillSecurityError(
                    f"Skill {yaml_path.parent.name!r}: skill.yaml is not a "
                    "regular file. A FIFO or device node would block startup "
                    "rather than fail it."
                )
            if stat_result.st_size > _MAX_MANIFEST_BYTES:
                raise SkillValidationError(
                    f"Skill {yaml_path.parent.name!r}: skill.yaml is "
                    f"{stat_result.st_size} bytes, above the "
                    f"{_MAX_MANIFEST_BYTES} byte limit."
                )

            # One byte beyond the cap distinguishes "at the limit" from
            # "truncated", covering a file that grows after fstat.
            chunks: list[bytes] = []
            remaining = _MAX_MANIFEST_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        finally:
            os.close(fd)

        if len(data) > _MAX_MANIFEST_BYTES:
            raise SkillValidationError(
                f"Skill {yaml_path.parent.name!r}: skill.yaml exceeds the "
                f"{_MAX_MANIFEST_BYTES} byte limit."
            )
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SkillValidationError(
                f"Skill {yaml_path.parent.name!r}: skill.yaml is not valid UTF-8."
            ) from exc

    def _discover_candidates(self, root: Path) -> list[Path]:
        """Find at most ``_MAX_SKILLS_PER_LOAD`` manifests to attempt.

        The cap counts **candidates**, not successes. Counting successes made
        the limit meaningless against the case it exists for: rejected
        manifests — unsigned, malformed, duplicate, over-budget — never
        incremented it, so an unlimited number of them could each be driven
        through file admission, parsing and validation before being thrown
        away. The work is spent whether or not the skill loads.

        Discovery streams with :func:`os.scandir` and stops early, rather than
        materialising the whole directory first. A directory with a million
        entries should not become a million ``Path`` objects before the limit
        is consulted.

        A separate ceiling bounds entries *examined*, so a directory padded
        with non-skill entries cannot force an unbounded walk looking for the
        64th candidate.

        Candidates are sorted before loading so the set that loads is stable
        for a given directory. Which candidates are found is filesystem order
        when the caps bite; that is the cost of not reading everything first,
        and the limits exist precisely for directories nobody curated.
        """
        candidates: list[Path] = []
        examined = 0
        truncated = False
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    examined += 1
                    if examined > _MAX_DIRECTORY_ENTRIES:
                        truncated = True
                        logger.error(
                            "SkillLoader: stopping discovery in %s after %d "
                            "entries — the directory is larger than the runtime "
                            "will scan",
                            root,
                            _MAX_DIRECTORY_ENTRIES,
                        )
                        break
                    # Template scaffolds are documentation, not runtime skills.
                    if entry.name == "template":
                        continue
                    try:
                        if not entry.is_dir(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    child = Path(entry.path)
                    if not (child / "skill.yaml").exists():
                        continue
                    candidates.append(child)
                    if len(candidates) >= _MAX_SKILLS_PER_LOAD:
                        truncated = True
                        logger.error(
                            "SkillLoader: %d candidate manifests found in %s — "
                            "the limit per load is %d; the rest are not read",
                            len(candidates),
                            root,
                            _MAX_SKILLS_PER_LOAD,
                        )
                        break
        except OSError:
            logger.exception("SkillLoader: could not scan skills directory %s", root)
            return []

        if truncated:
            logger.warning(
                "SkillLoader: skill discovery was truncated in %s — some "
                "manifests were not considered",
                root,
            )
        return sorted(candidates)

    def _validate_workload_budgets(self, raw: dict[str, Any], skill_name: str) -> None:
        """Bound the work this manifest will create once it is registered.

        Syntax limits bound the document; these bound the runtime. Registration
        creates one handler per trigger × required sensor type, and each handler
        schedules a reasoning task on the same event loop Tier D safety
        processing runs on, so the product is the number that matters — not
        either factor alone. A skill declaring 60 triggers and 30 sensors passes
        both individual caps and asks for 1,800 subscriptions.
        """
        triggers = raw.get("triggers") or []
        sensors = raw.get("sensors_required") or []
        trigger_count = len(triggers) if isinstance(triggers, list) else 0
        sensor_count = len(sensors) if isinstance(sensors, list) else 0

        if trigger_count > _MAX_TRIGGERS_PER_SKILL:
            raise SkillValidationError(
                f"Skill {skill_name!r}: {trigger_count} triggers exceeds the "
                f"limit of {_MAX_TRIGGERS_PER_SKILL}."
            )
        if sensor_count > _MAX_SENSORS_PER_SKILL:
            raise SkillValidationError(
                f"Skill {skill_name!r}: {sensor_count} required sensors exceeds "
                f"the limit of {_MAX_SENSORS_PER_SKILL}."
            )

        # A skill with no declared sensor type subscribes to the wildcard once
        # per trigger, so the floor is the trigger count rather than zero.
        subscriptions = trigger_count * max(sensor_count, 1)
        if subscriptions > _MAX_SUBSCRIPTIONS_PER_SKILL:
            raise SkillValidationError(
                f"Skill {skill_name!r}: {trigger_count} triggers × "
                f"{max(sensor_count, 1)} sensor types would register "
                f"{subscriptions} handlers, above the limit of "
                f"{_MAX_SUBSCRIPTIONS_PER_SKILL}."
            )

        actions = raw.get("actions") or {}
        if isinstance(actions, dict):
            available = actions.get("available") or []
            if isinstance(available, list) and len(available) > _MAX_ACTIONS_AVAILABLE:
                raise SkillValidationError(
                    f"Skill {skill_name!r}: {len(available)} declared actions "
                    f"exceeds the limit of {_MAX_ACTIONS_AVAILABLE}."
                )
            defaults = actions.get("defaults") or {}
            if isinstance(defaults, dict):
                if len(defaults) > _MAX_TRIGGERS_PER_SKILL:
                    raise SkillValidationError(
                        f"Skill {skill_name!r}: {len(defaults)} action default "
                        f"entries exceeds the limit of {_MAX_TRIGGERS_PER_SKILL}."
                    )

                # Capping the number of *keys* bounded nothing that matters:
                # the elevator iterates each trigger's action list and
                # dispatches every entry, so one trigger with a thousand
                # `alert_sms` entries sends a thousand messages and does a
                # thousand dispatches sequentially — inside every other budget.
                # The list length and the total across the skill are what the
                # runtime actually executes.
                total_references = 0
                for trigger_name, action_list in defaults.items():
                    if not isinstance(action_list, list):
                        continue
                    if len(action_list) > _MAX_ACTIONS_PER_TRIGGER:
                        raise SkillValidationError(
                            f"Skill {skill_name!r}: trigger {trigger_name!r} "
                            f"lists {len(action_list)} default actions, above "
                            f"the limit of {_MAX_ACTIONS_PER_TRIGGER}. Each one "
                            "is dispatched when the trigger fires."
                        )
                    # A repeated action is dispatched repeatedly. There is no
                    # legitimate reason to name one twice, and it is the
                    # cheapest way to multiply work inside a short list.
                    seen: set[str] = set()
                    for action_name in action_list:
                        if not isinstance(action_name, str):
                            continue
                        if action_name in seen:
                            raise SkillValidationError(
                                f"Skill {skill_name!r}: trigger "
                                f"{trigger_name!r} lists action "
                                f"{action_name!r} more than once. Each entry is "
                                "dispatched separately."
                            )
                        seen.add(action_name)
                    total_references += len(action_list)

                if total_references > _MAX_TOTAL_DEFAULT_REFERENCES:
                    raise SkillValidationError(
                        f"Skill {skill_name!r}: {total_references} total default "
                        f"action references exceeds the limit of "
                        f"{_MAX_TOTAL_DEFAULT_REFERENCES}."
                    )

        prompts = raw.get("prompts") or {}
        if isinstance(prompts, dict) and len(prompts) > _MAX_PROMPTS_PER_SKILL:
            raise SkillValidationError(
                f"Skill {skill_name!r}: {len(prompts)} prompts exceeds the "
                f"limit of {_MAX_PROMPTS_PER_SKILL}."
            )

        config = raw.get("config") or {}
        if isinstance(config, dict) and len(config) > _MAX_CONFIG_ENTRIES:
            raise SkillValidationError(
                f"Skill {skill_name!r}: {len(config)} config entries exceeds "
                f"the limit of {_MAX_CONFIG_ENTRIES}."
            )

    def _validate_identity_fields(self, raw: dict[str, Any], skill_dir: Path) -> None:
        """Bound the fields that name this skill in logs and operator messages.

        Skill identity is authority-adjacent: it is what an action log, a Tier C
        approval message and an operator's decision are attributed to. An
        unbounded field can flood a log line, and a control character can move
        the cursor or inject an escape sequence, so what an operator reads is
        not what the record says. Neither is a parsing concern, which is why
        the YAML limits do not cover it.
        """
        checks = (
            ("name", _MAX_NAME_LENGTH),
            ("author", _MAX_AUTHOR_LENGTH),
            ("version", _MAX_VERSION_LENGTH),
        )
        for field_name, limit in checks:
            value = raw.get(field_name)
            # A non-string is refused rather than skipped. Skipping meant a
            # numeric `version: 1.0` bypassed every check below and was then
            # coerced with str() downstream — the validation silently not
            # applying to a value that still reached the logs.
            if not isinstance(value, str):
                raise SkillValidationError(
                    f"Skill directory {skill_dir.name!r}: {field_name} must be "
                    f"a string, got {type(value).__name__}. Quote the value."
                )
            if len(value) > limit:
                raise SkillValidationError(
                    f"Skill directory {skill_dir.name!r}: {field_name} is "
                    f"{len(value)} characters, above the limit of {limit}."
                )
            offending = _display_unsafe_character(value)
            if offending is not None:
                raise SkillValidationError(
                    f"Skill directory {skill_dir.name!r}: {field_name} contains "
                    f"{offending}. Identity fields appear in logs and operator "
                    "messages and must be plain text."
                )

        name = raw.get("name")
        if isinstance(name, str) and not _SKILL_NAME_RE.fullmatch(name):
            raise SkillValidationError(
                f"Skill directory {skill_dir.name!r}: name {name!r} must start "
                "with a letter or digit and use only letters, digits, dot, "
                "underscore and hyphen."
            )

        # A community skill must not answer to a packaged skill's name. Logs,
        # action records and operator messages identify skills by name, so a
        # collision makes an untrusted skill indistinguishable from a reviewed
        # one in exactly the records used to decide whether to trust it.
        if isinstance(name, str) and not self._is_core_bundled_skill(skill_dir):
            if name in _packaged_skill_names():
                raise SkillSecurityError(
                    f"Skill directory {skill_dir.name!r}: name {name!r} is the "
                    "name of a skill that ships with the runtime. Community "
                    "skills must not adopt packaged identities."
                )

    def _validate_reserved_config_names(self, config: Any, skill_name: str) -> None:
        """Refuse skill config that shadows the sensor reading.

        The rule engine overwrites these names with the real reading, so a
        skill defining them cannot change what a condition evaluates. It is
        still rejected here: a skill that sets ``value`` is either confused
        about what its conditions test or is attempting to steer them, and
        neither should load silently.
        """
        if not isinstance(config, dict):
            return
        reserved = RESERVED_CONTEXT_NAMES.intersection(config)
        if reserved:
            raise SkillValidationError(
                f"Skill {skill_name!r}: config defines {sorted(reserved)}, which "
                f"are reserved for the sensor reading. Rename these keys — "
                f"conditions read them from the event, never from config."
            )

    def _verify_community_signature(
        self,
        raw: dict[str, Any],
        skill_dir: Path,
    ) -> None:
        """Verify signatures for every skill that is not first-party.

        Provenance is established positively: a skill is trusted because it
        ships inside this package, not because its path failed to match a
        directory the runtime expected untrusted skills to live in. Anywhere
        else — an operator-managed skills directory beside ori.yaml, a
        temporary path, removable media — is community content and verifies.
        """
        if self._is_core_bundled_skill(skill_dir):
            return

        signature = str(raw.get("signature") or "").strip()
        if signature == _BUNDLED_SIGNATURE_SENTINEL:
            raise SkillSecurityError(
                "skill uses the bundled signature sentinel but does not ship "
                "with the runtime. Re-sign it with an 'ed25519:' signature."
            )

        trust_anchor = self._resolve_community_trust_anchor()
        if trust_anchor == "PENDING_REPLACE_AT_HUB_LAUNCH":
            raise SkillSecurityError(
                "community skill verification trust anchor is not configured"
            )

        verify_community_skill_signature(
            raw_skill=raw,
            trust_anchor_public_key_b64=trust_anchor,
        )

    def _resolve_community_trust_anchor(self) -> str:
        """Resolve trust anchor: constructor override > env var > built-in sentinel."""
        if self._community_trust_anchor_public_key_b64:
            return self._community_trust_anchor_public_key_b64

        env_value = os.getenv(_HUB_TRUST_ANCHOR_ENV, "").strip()
        if env_value:
            return env_value

        return _HUB_ROOT_PUBLIC_KEY_B64

    def _validate_skill_metadata(self, raw: dict[str, Any], skill_dir: Path) -> None:
        """Validate core metadata presence for runtime-loadable skills."""
        skill_dir_name = skill_dir.name
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

        if not self._is_core_bundled_skill(skill_dir):
            return

        # First-party skills shipped inside this package. Only the declaration
        # prefix is checked here: an `ed25519:` value is not decoded, and its
        # signature is not verified. A packaged skill's authenticity comes from
        # the signed release artifact it was installed from, not from a
        # declaration inside the file it would also control. An unrecognised
        # prefix is a packaging mistake rather than an attack, and is reported
        # as one.
        signature = str(raw.get("signature") or "").strip()
        if self._require_signed and not (
            signature == _BUNDLED_SIGNATURE_SENTINEL or signature.startswith("ed25519:")
        ):
            raise SkillSecurityError(
                f"Skill {name!r}: security.skills.require_signed is enabled — "
                f"bundled skills must carry {_BUNDLED_SIGNATURE_SENTINEL!r} or an "
                f"'ed25519:' signature. Got {signature!r}."
            )
        if signature and not (
            signature == _BUNDLED_SIGNATURE_SENTINEL or signature.startswith("ed25519:")
        ):
            raise SkillValidationError(
                f"Skill {name!r}: bundled skill signature must be either "
                f"{_BUNDLED_SIGNATURE_SENTINEL!r} or an 'ed25519:' signature."
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
        # Enforced here as well as at load, because this is the method that
        # actually creates handlers. `register()` is public and reachable
        # without `load_all()`, so relying on load-time validation would leave
        # the budget holding only for one call path.
        cost = self._subscription_cost(skill)
        if cost > _MAX_SUBSCRIPTIONS_PER_SKILL:
            raise SkillValidationError(
                f"Skill {skill.name!r}: registering {cost} handlers exceeds the "
                f"limit of {_MAX_SUBSCRIPTIONS_PER_SKILL}."
            )
        if self._registered_subscriptions + cost > _MAX_TOTAL_SUBSCRIPTIONS:
            raise SkillValidationError(
                f"Skill {skill.name!r}: registering {cost} handlers would take "
                f"this loader past the cumulative limit of "
                f"{_MAX_TOTAL_SUBSCRIPTIONS} subscriptions "
                f"({self._registered_subscriptions} already registered)."
            )

        tracker = _CooldownTracker()
        subscriptions: list[tuple[str, Callable[[OriEvent], Awaitable[None]]]] = []

        # Deduplicated so registration matches _subscription_cost() exactly.
        # The cost counted unique types while this loop registered one handler
        # per list entry, so a skill declaring the same sensor twenty times was
        # charged once and registered twenty handlers — the budget measuring
        # something other than what it was bounding. Duplicate declarations are
        # also pointless: two handlers on one sensor type fire on the same
        # events.
        sensor_types = _unique_sensor_types(skill.sensors_required)

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

        Shares :func:`_unique_sensor_types` with :meth:`register` so the number
        charged is by construction the number registered.
        """
        return len(skill.triggers) * len(_unique_sensor_types(skill.sensors_required))

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

        # A skill declares the tier it believes an action belongs to. For any
        # action the runtime can actually execute, that belief is checked
        # against the runtime's own registry here, so a skill that labels a
        # relay action as informational is refused at load rather than relying
        # on the dispatcher catching it later.
        for entry in available:
            if not isinstance(entry, dict):
                continue
            action_name = entry.get("name")
            declared = str(entry.get("tier") or "").upper()
            if not isinstance(action_name, str):
                continue
            floor = minimum_tier(action_name)
            if not declared:
                # An action the runtime can execute must state its tier. Letting
                # it through to be repaired at dispatch would mean a skill could
                # omit the field and have the tier decided somewhere the operator
                # never sees. An undeclared tier on an inert action name stays
                # a documentation matter, caught by the flat-action-list rule.
                if floor is not None:
                    raise SkillValidationError(
                        f"Skill {skill_name!r}: action {action_name!r} is "
                        f"declared without a tier, and the runtime can execute "
                        f"it. Declare 'tier: {floor}' or higher."
                    )
                continue
            if floor is None or tier_rank(declared) >= tier_rank(floor):
                continue
            entry_capability = capability(action_name)
            summary = entry_capability.summary if entry_capability else action_name
            raise SkillValidationError(
                f"Skill {skill_name!r}: action {action_name!r} is declared as "
                f"Tier {declared}, but it {summary} and the runtime requires at "
                f"least Tier {floor}. Raise the declared tier — an action cannot "
                f"be given less authority than the runtime assigns it."
            )

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
        self,
        raw_triggers: list[dict],
        skill_name: str,
        *,
        first_party: bool = False,
    ) -> list[Trigger]:
        """Parse and validate raw trigger dicts from YAML.

        Validation rules (Action Tier Framework):
        - ``action_tier`` is required on every trigger.
        - ``action_tier`` must be one of ``A``, ``B``, ``C``, ``D``.
        - Tier D triggers must have ``bypass_llm: true`` (enforced automatically).
        - Tier D triggers are accepted only from first-party skills.
        - Tier C triggers must declare ``safe_default_action``.
        - ``bypass_llm: true`` without ``action_tier: D`` is a configuration error.

        Args:
            raw_triggers: List of trigger dicts from the YAML file.
            skill_name: Skill name used in error messages.
            first_party: Whether the skill ships with the runtime. Only
                first-party skills may declare Tier D triggers.

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

            # Tier D is the one tier that removes the operator from the loop:
            # it fires immediately, before any LLM, and cannot be overridden.
            # A signature proves who wrote a skill, not that the runtime granted
            # it that authority — so a correctly signed community skill could
            # otherwise declare an always-true Tier D trigger on a relay action
            # and obtain autonomous physical actuation, with every other check
            # in this file passing. Until a capability grant binding skill
            # identity, trigger, action and permitted maximum tier exists, Tier
            # D is confined to skills that ship with the runtime and are
            # reviewed and released with it.
            if action_tier == "D" and not first_party:
                raise SkillSecurityError(
                    f"Skill '{skill_name}' trigger '{name}' declares Tier D, but "
                    "the skill does not ship with the runtime. Tier D fires "
                    "autonomously with no approval and cannot be overridden, so "
                    "it is not something a skill file can grant itself. Use "
                    "Tier C to propose the action for operator approval."
                )

            bypass_llm = bool(raw.get("bypass_llm", False))
            requires_approval = bool(raw.get("requires_approval", False))
            reasoning_policy = str(raw.get("reasoning_policy") or "").strip()
            escalate_to = str(raw.get("escalate_to", "local_slm")).strip().lower()
            if escalate_to not in {"rule", "local_slm", "gateway"}:
                raise SkillValidationError(
                    f"Skill '{skill_name}' trigger '{name}' has invalid "
                    f"escalate_to={escalate_to!r}. Supported runtime tiers: rule, "
                    "local_slm, gateway. Cloud reasoning is a gateway backend; "
                    "use escalate_to: gateway."
                )

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

            if reasoning_policy and reasoning_policy != "post_action":
                raise SkillValidationError(
                    f"Skill '{skill_name}' trigger '{name}' has invalid "
                    f"reasoning_policy={reasoning_policy!r}. Supported values: "
                    "post_action."
                )

            if reasoning_policy == "post_action" and action_tier != "B":
                raise SkillValidationError(
                    f"Skill '{skill_name}' trigger '{name}' sets "
                    "reasoning_policy=post_action but is not Tier B. post_action is "
                    "reserved for Tier B soft physical triggers."
                )

            safe_default_action = raw.get("safe_default_action", "log_to_dashboard")

            # Tier C must always have a fallback — do not allow it to be blank
            if action_tier == "C" and not safe_default_action:
                raise SkillValidationError(
                    f"Skill '{skill_name}' trigger '{name}' is Tier C (hard physical) "
                    f"but 'safe_default_action' is empty. Tier C triggers must always "
                    f"declare a safe_default_action for approval timeout / NO response."
                )

            # The safe default runs when the operator says NO or says nothing,
            # with no approval of its own. Naming an actuating action here
            # would invert the approval workflow, so it is refused at load as
            # well as at dispatch.
            if safe_default_action and not is_safe_default_eligible(
                safe_default_action
            ):
                entry_capability = capability(safe_default_action)
                summary = (
                    entry_capability.summary
                    if entry_capability
                    else str(safe_default_action)
                )
                raise SkillValidationError(
                    f"Skill '{skill_name}' trigger '{name}' names "
                    f"{safe_default_action!r} as safe_default_action, but it "
                    f"{summary}. A safe default executes without approval, so it "
                    f"must not be able to actuate anything."
                )

            triggers.append(
                Trigger(
                    name=name,
                    condition=raw.get("condition", ""),
                    action_tier=action_tier,
                    cooldown_seconds=int(raw.get("cooldown_seconds", 0)),
                    escalate_to=escalate_to,
                    bypass_llm=bypass_llm,
                    requires_approval=requires_approval,
                    reasoning_policy=reasoning_policy,
                    approval_timeout_seconds=int(
                        raw.get("approval_timeout_seconds", 300)
                    ),
                    safe_default_action=safe_default_action,
                )
            )
        return triggers

    def _validate_tier_b_trigger_policies(
        self,
        triggers: list[Trigger],
        actions_dict: dict,
        skill_name: str,
    ) -> None:
        """Require explicit execution policy for physical Tier B triggers."""
        defaults = actions_dict.get("defaults") or {}
        available = actions_dict.get("available") or []
        action_tiers: dict[str, str] = {}
        for entry in available:
            if isinstance(entry, dict):
                name = entry.get("name")
                tier = str(entry.get("tier", "A")).upper()
                if isinstance(name, str) and name:
                    action_tiers[name] = tier

        for trigger in triggers:
            if trigger.action_tier != "B":
                continue
            default_actions = defaults.get(trigger.name, [])
            physical_default = any(
                action_tiers.get(str(action_name), "") == "B"
                for action_name in default_actions
                if isinstance(action_name, str)
            )
            if not physical_default:
                continue
            if trigger.requires_approval or trigger.reasoning_policy == "post_action":
                if trigger.reasoning_policy == "post_action":
                    has_notification_default = any(
                        action_tiers.get(str(action_name), "A") == "A"
                        for action_name in default_actions
                        if isinstance(action_name, str)
                    )
                    if not has_notification_default:
                        raise SkillValidationError(
                            f"Skill '{skill_name}' trigger '{trigger.name}' uses "
                            "reasoning_policy=post_action but has no Tier A default "
                            "action for post-action operator notification."
                        )
                continue
            raise SkillValidationError(
                f"Skill '{skill_name}' trigger '{trigger.name}' is Tier B with "
                "Tier B default action(s) but declares neither requires_approval=true "
                "nor reasoning_policy=post_action. Physical Tier B triggers must "
                "choose an explicit execution policy."
            )

    def _validate_history_placeholder_count(
        self,
        *,
        prompts: Any,
        skill_name: str,
        trigger_names: list[str],
    ) -> None:
        """Fail fast when prompt templates exceed history placeholder cap."""
        if not isinstance(prompts, dict):
            return
        trigger_name_set = set(trigger_names)
        for prompt_key, template in prompts.items():
            if not isinstance(template, str):
                continue
            count = len(_HISTORY_PLACEHOLDER_PATTERN.findall(template))
            if count <= _MAX_HISTORY_PLACEHOLDERS:
                continue
            scope = (
                "trigger"
                if isinstance(prompt_key, str) and prompt_key in trigger_name_set
                else "prompt key"
            )
            raise SkillValidationError(
                f"Skill {skill_name!r}: {scope} {prompt_key!r} contains {count} "
                f"history placeholders; maximum allowed is {_MAX_HISTORY_PLACEHOLDERS}."
            )

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

    def _is_core_bundled_skill(self, skill_dir: Path) -> bool:
        """Return True for first-party skills shipped with the runtime."""
        resolved = skill_dir.resolve()
        for root in first_party_skill_roots():
            try:
                resolved.relative_to(root)
                return True
            except ValueError:
                continue
        return False

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

    def _make_handler(
        self,
        skill: Skill,
        trigger: Trigger,
        tracker: _CooldownTracker,
    ) -> Callable[[OriEvent], Awaitable[None]]:
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
