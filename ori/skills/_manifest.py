# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The skill manifest: its data model, its grammar and its workload budgets."""

import datetime
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Every part of the loader logs as it did before the split, under one name an
# operator's logging configuration may already select.
logger = logging.getLogger("ori.skills.loader")

# The one YAML type each manifest field the loader reads admits: skills-package
# v2 types the top-level and trigger fields, and the rest follow the shapes v1
# describes. Checked once, before any value is read, so no reader coerces: an
# integer field refuses a bool, and null is not a value. Values under `config`
# are the skill's own and are checked where they are read.
TOP_LEVEL_FIELD_TYPES: dict[str, type] = {
    "name": str,
    "version": str,
    "author": str,
    "signature": str,
    "triggers": list,
    "sensors_required": list,
    "actions": dict,
    "prompts": dict,
    "config": dict,
}
TRIGGER_FIELD_TYPES: dict[str, type] = {
    "name": str,
    "condition": str,
    "action_tier": str,
    "cooldown_seconds": int,
    "escalate_to": str,
    "bypass_llm": bool,
    "requires_approval": bool,
    "reasoning_policy": str,
    "approval_timeout_seconds": int,
    "safe_default_action": str,
}
ACTIONS_FIELD_TYPES: dict[str, type] = {"available": list, "defaults": dict}
ACTION_FIELD_TYPES: dict[str, type] = {"name": str, "tier": str}
SENSOR_FIELD_TYPES: dict[str, type] = {"type": str}

TRIGGER_ALLOWED_KEYS = frozenset(TRIGGER_FIELD_TYPES)
ACTION_ALLOWED_KEYS = frozenset(ACTION_FIELD_TYPES)

VALID_TIERS = frozenset({"A", "B", "C", "D"})


TRIGGER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*\Z")
HISTORY_PLACEHOLDER_PATTERN = re.compile(r"\{history\.[^{}]+\}")
MAX_HISTORY_PLACEHOLDERS = 16
BUNDLED_SIGNATURE_SENTINEL = "bundled"
# Generous for a manifest — the largest bundled skill.yaml is a few KiB.
# This bounds resource use before trust is established, not authorship.
MAX_MANIFEST_BYTES = 1 << 20

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
MAX_SKILLS_PER_LOAD = 64
MAX_TRIGGERS_PER_SKILL = 64
MAX_SENSORS_PER_SKILL = 32
MAX_SUBSCRIPTIONS_PER_SKILL = 256
MAX_ACTIONS_AVAILABLE = 64
# Actions dispatched when one trigger fires. The elevator iterates this list
# and dispatches every entry, so it is execution work, not declaration size.
# The longest list in any packaged skill is 4.
MAX_ACTIONS_PER_TRIGGER = 16
# Total default-action references across one skill; the packaged maximum is 20.
MAX_TOTAL_DEFAULT_REFERENCES = 256
MAX_PROMPTS_PER_SKILL = 64
MAX_CONFIG_ENTRIES = 256
# Cumulative across a whole load: individually legal skills must not add up to
# an illegal total. Without this, the per-skill caps are a per-file courtesy.
MAX_TOTAL_SUBSCRIPTIONS = 1024
# Directory entries examined during discovery. Bounds the walk itself, so a
# directory padded with non-skill entries cannot force an unbounded scan.
MAX_DIRECTORY_ENTRIES = 4096

# Identity fields appear in logs, operator alerts and audit records, so they are
# bounded and stripped of control characters — a name carrying an escape
# sequence can rewrite what an operator sees a decision attributed to.
MAX_AUTHOR_LENGTH = 128
MAX_VERSION_LENGTH = 32


# ── Exceptions ────────────────────────────────────────────────────────────────


#: The longest refusal a skill can produce. A manifest is untrusted, and every
#: refusal names what it refused, so the message is bounded where it is made.
MAX_REFUSAL_CHARS = 1000


class SkillValidationError(Exception):
    """Raised when a skill.yaml violates the Action Tier Framework rules.

    Its message keeps its head and its tail within `MAX_REFUSAL_CHARS`, so text
    a manifest supplied can neither flood a log nor push the reason out of it.
    """

    def __init__(self, message: object = "") -> None:
        text = str(message)
        if len(text) > MAX_REFUSAL_CHARS:
            half = (MAX_REFUSAL_CHARS - 5) // 2
            text = f"{text[:half]} ... {text[-half:]}"
        super().__init__(text)


@dataclass(frozen=True)
class SelectedSkill:
    """One ``skills:`` entry as resolution decided it, read by everything after."""

    name: str
    version: str
    path: Path
    packaged: bool


class SkillSelectionError(Exception):
    """Raised when a deployment's ``skills:`` list names a skill that cannot run."""


def _admits(value: Any, expected: type) -> bool:
    if expected is int or expected is bool:
        return type(value) is expected  # bool is an int subclass; neither stands in
    return isinstance(value, expected)


_TYPE_NAMES = {
    str: "a string",
    int: "an integer",
    bool: "a YAML boolean",
    list: "a list",
    dict: "a mapping",
}


def _refuse(skill: str, label: str, key: str, expected: type, value: Any) -> None:
    hint = (
        "; YAML reads an unquoted number, boolean or date as that type, so quote "
        "the value"
        if expected is str and isinstance(value, (bool, int, float, datetime.date))
        else ""
    )
    raise SkillValidationError(
        f"Skill {skill!r}: {label}{key} must be {_TYPE_NAMES[expected]}, got "
        f"{type(value).__name__}: {key}={_shown(value)}{hint}"
    )


def _shown(value: Any) -> str:
    """*value* as a refusal echoes it, bounded: a manifest is untrusted input."""
    text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


def _check_fields(
    mapping: dict[Any, Any], types: dict[str, type], skill: str, label: str = ""
) -> None:
    for key, expected in types.items():
        if key in mapping and not _admits(mapping[key], expected):
            _refuse(skill, label, key, expected, mapping[key])


def _check_items(items: list[Any], expected: type, skill: str, where: str) -> list[Any]:
    for index, item in enumerate(items):
        if not _admits(item, expected):
            _refuse(skill, "", f"{where}[{index}]", expected, item)
    return items


def _named(entry: dict[Any, Any], kind: str, where: str) -> str:
    """How a refusal names a trigger or action: by its name when it has one."""
    name = entry.get("name")
    return (
        f"{kind} {_shown(name)}: " if isinstance(name, str) and name else f"{where}: "
    )


def check_manifest_field_types(raw: dict[Any, Any], skill_dir_name: str) -> None:
    """Refuse a manifest value of any type but the one its field admits.

    Walks every field the loader reads (the tables above) before anything reads
    one, so a wrong type is a refusal naming the skill, the trigger or action,
    the field and the type received, never a traceback or a value used with
    another meaning.
    """
    name = raw.get("name")
    skill = name if isinstance(name, str) and name else skill_dir_name
    _check_fields(raw, TOP_LEVEL_FIELD_TYPES, skill)
    for index, trigger in enumerate(
        _check_items(raw.get("triggers", []), dict, skill, "triggers")
    ):
        label = _named(trigger, "trigger", f"triggers[{index}]")
        _check_fields(trigger, TRIGGER_FIELD_TYPES, skill, label)
    for index, sensor in enumerate(
        _check_items(raw.get("sensors_required", []), dict, skill, "sensors_required")
    ):
        _check_fields(sensor, SENSOR_FIELD_TYPES, skill, f"sensors_required[{index}]: ")
    actions = raw.get("actions", {})
    _check_fields(actions, ACTIONS_FIELD_TYPES, skill, "actions: ")
    for index, entry in enumerate(
        _check_items(actions.get("available", []), dict, skill, "actions.available")
    ):
        label = _named(entry, "action", f"actions.available[{index}]")
        _check_fields(entry, ACTION_FIELD_TYPES, skill, label)
    for trigger_name, listed in actions.get("defaults", {}).items():
        where = f"actions.defaults.{trigger_name}"
        if not isinstance(listed, list):
            _refuse(skill, "", where, list, listed)
        _check_items(listed, str, skill, where)
    for prompt_name, template in raw.get("prompts", {}).items():
        if not isinstance(template, str):
            _refuse(skill, "", f"prompts.{prompt_name}", str, template)


def display_unsafe_character(value: str) -> str | None:
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


def unique_sensor_types(sensors_required: list[dict[str, Any]]) -> list[str]:
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


class UniqueStringKeySafeLoader(yaml.SafeLoader):
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
    loader: UniqueStringKeySafeLoader,
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


UniqueStringKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_string_mapping,
)


# ── Data model ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CommunitySkillAdmission:
    """Whether this deployment can admit community skills, and what it dropped.

    Reporting and attribution are separate questions, and conflating them is
    how a device goes quiet. An anchor that is a well-formed key but not the
    Hub's refuses every community skill with a signature failure, which cannot
    be told apart from a tampered skill — so it is not attributed. The device
    still knows the skills did not load, and that is what `refused_skills`
    carries.

    Args:
        anchor_usable: Whether the community trust anchor can verify anything.
            False only where the anchor itself is at fault beyond doubt.
        anchor_fault: Why it cannot, in the words the refusal uses.
        refused_skills: Community skills the last load did not admit, for any
            reason. Zero on a deployment that carries none, which is why an
            unusable anchor is reported without being treated as a fault on
            its own — the default anchor is unconfigured, and a device running
            only first-party skills is not degraded by that.
    """

    anchor_usable: bool
    anchor_fault: str | None
    refused_skills: int


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
    # it. Tier D is never package-granted: this flag contains the legacy package
    # path until the release-owned safety profile replaces it, at which point
    # packages do not participate in the Tier D decision at all.
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
