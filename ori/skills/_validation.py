# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Manifest, trigger and action validation for the skill loader."""

import ast
import datetime
import logging
import math
from pathlib import Path
from typing import Any

from ori.config import MAX_SKILL_NAME_LENGTH, SKILL_NAME_RE
from ori.reasoning.action_registry import (
    capability,
    is_safe_default_eligible,
    minimum_tier,
    tier_rank,
)
from ori.reasoning.action_taken import is_reserved as is_reserved_action_taken
from ori.reasoning.approval_bounds import (
    MAX_PROPOSAL_LIFETIME_S,
    approval_timeout_accepted,
)
from ori.reasoning.rule_engine import (
    MAX_CONDITION_CHARS,
    RESERVED_CONTEXT_NAMES,
    RuleEngineSafetyError,
    validated_history_calls,
)
from ori.skills._core import (
    LoaderCore,
)
from ori.skills._manifest import (
    ACTION_ALLOWED_KEYS,
    BUNDLED_SIGNATURE_SENTINEL,
    HISTORY_PLACEHOLDER_PATTERN,
    MAX_ACTIONS_AVAILABLE,
    MAX_ACTIONS_PER_TRIGGER,
    MAX_AUTHOR_LENGTH,
    MAX_CONFIG_ENTRIES,
    MAX_HISTORY_PLACEHOLDERS,
    MAX_PROMPTS_PER_SKILL,
    MAX_SENSORS_PER_SKILL,
    MAX_SUBSCRIPTIONS_PER_SKILL,
    MAX_TOTAL_DEFAULT_REFERENCES,
    MAX_TRIGGERS_PER_SKILL,
    MAX_VERSION_LENGTH,
    TRIGGER_ALLOWED_KEYS,
    TRIGGER_NAME_RE,
    VALID_TIERS,
    SkillValidationError,
    Trigger,
    display_unsafe_character,
)
from ori.skills._provenance import (
    packaged_skill_names,
)
from ori.skills.sandbox import SkillSecurityError

# Every part of the loader logs as it did before the split, under one name an
# operator's logging configuration may already select.
logger = logging.getLogger("ori.skills.loader")


def _parsed(condition: str) -> ast.Expression | None:
    """*condition* parsed, or None when the rule engine's own check refuses it.

    The prechecks below read the tree; anything unparseable, over-long or
    unencodable is left to `_refuse_unevaluable_condition`, never raised here.
    """
    if len(condition) > MAX_CONDITION_CHARS:
        return None
    try:
        return ast.parse(condition, mode="eval")
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None


def _refuse_history_in_tier_d_condition(
    skill_name: str, trigger_name: str, condition: str
) -> None:
    """A Tier D condition may not name `history`; what a hook derives is beyond this check.

    Stored history is ordered and aged by the store's receipts, and every
    helper over it can be made to look stale or current by what arrived and
    when. This refuses the direct route. A hook's derived values reach the
    same condition and are not inspected here; the safety-profile migration
    removes hooks from Tier D conditions altogether.
    """
    tree = _parsed(condition)
    if tree is None:
        return  # the rule engine's check refuses it with its own message
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "history":
            raise SkillValidationError(
                f"Skill '{skill_name}' trigger '{trigger_name}' is Tier D and its "
                f"condition reads history: {condition!r}. A Tier D condition "
                "evaluates the reading in hand only; stored history is ordered by "
                "when the runtime received each reading, and a safety cutoff must "
                "not depend on delivery order or on how current the store believes "
                "a reading is. This guard reads the condition text only; it does not "
                "see a hook, a prompt, or what an executor reads."
            )


def _refuse_unevaluable_condition(
    skill_name: str, trigger_name: str, condition: str, *, tier_d: bool
) -> None:
    """Refuse a condition the rule engine cannot evaluate, by its own check.

    Such a trigger never fires. A Tier D trigger must also have a condition:
    with none, a protective trigger has nothing to decide.
    """
    if condition == "" and not tier_d:
        # The engine reads only "" as no condition; any other text is evaluated.
        return
    if not condition.strip():
        raise SkillValidationError(
            f"Skill '{skill_name}' trigger '{trigger_name}' has no condition to "
            "evaluate"
            + (", so the protective trigger could never fire." if tier_d else ".")
        )
    try:
        validated_history_calls(condition)
    except RuleEngineSafetyError as exc:
        raise SkillValidationError(
            f"Skill '{skill_name}' trigger '{trigger_name}': the rule engine cannot "
            f"evaluate its condition, so it could never fire. {exc}"
        ) from exc


def refuse_unresolved_names_in_tier_d_condition(
    skill_name: str,
    trigger_name: str,
    condition: str,
    config: dict[str, Any],
) -> None:
    """A Tier D condition may name only the reading and the skill's own configuration.

    An allowlist, not a search for what a hook might write: that is all the
    rule engine gives a Tier D condition, before any hook runs. A configured
    value it names must be a finite number, since nothing coerces it.
    """
    tree = _parsed(condition)
    if tree is None:
        return
    named = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    unresolved = sorted(named - RESERVED_CONTEXT_NAMES - set(config) - {"history"})
    if unresolved:
        raise SkillValidationError(
            f"Skill '{skill_name}' trigger '{trigger_name}' is Tier D and its "
            f"condition names {unresolved}, which neither the reading nor the "
            "skill's configuration supplies. A Tier D condition is decided from "
            "the reading and the skill's configuration before any hook runs, so "
            "a hook can neither delay nor decide it."
        )
    for name in sorted(named & set(config)):
        value = config[name]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise SkillValidationError(
                f"Skill '{skill_name}' trigger '{trigger_name}' is Tier D and its "
                f"condition reads config {name!r} = {value!r}, which is not a "
                "finite number; a Tier D input is compared as configured."
            )


def _refuse_reserved_action_name(skill_name: str, action_name: Any, where: str) -> None:
    """Refuse an action named as the runtime records an action not taken."""
    if isinstance(action_name, str) and is_reserved_action_taken(action_name):
        raise SkillValidationError(
            f"Skill {skill_name!r}: {where} names {action_name!r}, which the runtime "
            "records to say no action was taken, so its row would read as the "
            "runtime's own decision. Rename the action."
        )


def _trigger_name(raw: object, skill_name: str, seen_trigger_names: set[str]) -> str:
    """The name of one trigger entry, refused unless it is a mapping of known
    keys whose name is well formed and unique in the skill."""
    if not isinstance(raw, dict):
        raise SkillValidationError(
            f"Skill '{skill_name}': each trigger must be a mapping."
        )

    unknown_keys = set(raw.keys()) - TRIGGER_ALLOWED_KEYS
    if unknown_keys:
        trigger_name_for_err = raw.get("name", "<unnamed>")
        raise SkillValidationError(
            f"Skill '{skill_name}' trigger '{trigger_name_for_err}' contains "
            f"unrecognized key(s) which the runtime does not read: "
            f"{', '.join(sorted(unknown_keys))}"
        )

    raw_name = raw.get("name")
    if not isinstance(raw_name, str) or not raw_name.strip():
        raise SkillValidationError(
            f"Skill '{skill_name}' has a trigger with missing/empty name. "
            "Trigger names must be non-empty strings."
        )
    name = raw_name.strip()
    if not TRIGGER_NAME_RE.fullmatch(name):
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
    return name


def _trigger_tier(raw: dict, skill_name: str, name: str, *, first_party: bool) -> str:
    """The trigger's declared tier, refused unless it is one of A to D, and
    Tier D unless the skill ships with the runtime."""
    action_tier = raw.get("action_tier")

    if not action_tier:
        raise SkillValidationError(
            f"Skill '{skill_name}' trigger '{name}' is missing required field 'action_tier'. "
            f"Every trigger must declare its tier (A, B, C, or D)."
        )

    if action_tier not in VALID_TIERS:
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
    # in this file passing. Tier D is therefore confined to skills that
    # ship with the runtime and are reviewed and released with it. A
    # capability grant binding skill identity, trigger, action and
    # permitted maximum tier does not change that: such a grant governs
    # Tier A to C and must never confer Tier D, because an issuer able
    # to grant it gives safety authority an expiry and a revocation
    # path. Provenance is the answer here, not a placeholder for one.
    if action_tier == "D" and not first_party:
        raise SkillSecurityError(
            f"Skill '{skill_name}' trigger '{name}' declares Tier D, but "
            "the skill does not ship with the runtime. Tier D fires "
            "autonomously with no approval and cannot be overridden, so "
            "it is not something a skill file can grant itself. Use "
            "Tier C to propose the action for operator approval."
        )
    # One of A to D by now: the type a YAML value carries is settled.
    return str(action_tier)


def _trigger_reasoning(
    raw: dict, skill_name: str, name: str, action_tier: str
) -> tuple[bool, bool, str, str]:
    """``bypass_llm``, ``requires_approval``, ``reasoning_policy`` and
    ``escalate_to``, each refused where the tier does not admit it; Tier D
    always bypasses the model."""
    bypass_llm = bool(raw.get("bypass_llm", False))
    requires_approval = raw.get("requires_approval", False)
    if not isinstance(requires_approval, bool):
        raise SkillValidationError(
            f"Skill '{skill_name}' trigger '{name}' has "
            f"requires_approval={requires_approval!r} of type "
            f"{type(requires_approval).__name__}; it must be a YAML "
            "boolean, true or false, unquoted."
        )
    reasoning_policy = str(raw.get("reasoning_policy") or "").strip()
    escalate_to = str(raw.get("escalate_to", "local_slm")).strip().lower()
    if escalate_to not in {"rule", "local_slm", "gateway"}:
        raise SkillValidationError(
            f"Skill '{skill_name}' trigger '{name}' has invalid "
            f"escalate_to={escalate_to!r}. Supported runtime tiers: rule, "
            "local_slm, gateway. Cloud reasoning is a gateway backend; "
            "use escalate_to: gateway."
        )

    if raw.get("cooldown_seconds", 0) < 0:
        raise SkillValidationError(
            f"Skill '{skill_name}' trigger '{name}' has a negative cooldown_seconds."
        )

    # Tier D: enforce bypass_llm — safety-critical actions never reach LLM
    if action_tier == "D":
        bypass_llm = True
        _refuse_history_in_tier_d_condition(
            skill_name, name, str(raw.get("condition", "") or "")
        )
    _refuse_unevaluable_condition(
        skill_name, name, raw.get("condition", ""), tier_d=action_tier == "D"
    )

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

    if reasoning_policy == "post_action" and requires_approval:
        raise SkillValidationError(
            f"Skill '{skill_name}' trigger '{name}' declares both "
            "requires_approval=true and reasoning_policy=post_action. "
            "requires_approval waits for an operator before acting; "
            "post_action acts and explains afterwards. Declare one."
        )
    return bypass_llm, requires_approval, reasoning_policy, escalate_to


def _trigger_safe_default(
    raw: dict, skill_name: str, name: str, action_tier: str
) -> Any:
    """The trigger's safe default, refused when a Tier C trigger has none, when
    it is a reserved name, or when it could actuate."""
    safe_default_action = raw.get("safe_default_action", "log_to_dashboard")

    # Tier C must always have a fallback — do not allow it to be blank
    if action_tier == "C" and not safe_default_action:
        raise SkillValidationError(
            f"Skill '{skill_name}' trigger '{name}' is Tier C (hard physical) "
            f"but 'safe_default_action' is empty. Tier C triggers must always "
            f"declare a safe_default_action for approval timeout / NO response."
        )

    where = f"trigger {name!r} safe_default_action"
    _refuse_reserved_action_name(skill_name, safe_default_action, where)

    # The safe default runs when the operator says NO or says nothing,
    # with no approval of its own. Naming an actuating action here
    # would invert the approval workflow, so it is refused at load as
    # well as at dispatch.
    if safe_default_action and not is_safe_default_eligible(safe_default_action):
        entry_capability = capability(safe_default_action)
        summary = (
            entry_capability.summary if entry_capability else str(safe_default_action)
        )
        raise SkillValidationError(
            f"Skill '{skill_name}' trigger '{name}' names "
            f"{safe_default_action!r} as safe_default_action, but it "
            f"{summary}. A safe default executes without approval, so it "
            f"must not be able to actuate anything."
        )
    return safe_default_action


class SkillValidation(LoaderCore):
    """Manifest, trigger and action validation."""

    def _validate_workload_budgets(self, raw: dict[str, Any], skill_name: str) -> None:
        """Bound the work this manifest will create once it is registered.

        Syntax limits bound the document; these bound the runtime. Registration
        creates one handler per trigger × required sensor type on the same event
        loop Tier D safety processing runs on, so the product is the number that
        matters — not either factor alone. A skill declaring 60 triggers and 30
        sensors passes both individual caps and asks for 1,800 subscriptions.
        The barrier means only one of those handlers does the work for a given
        event, which bounds the reasoning fan-out but not the subscriptions.
        """
        triggers = raw.get("triggers") or []
        sensors = raw.get("sensors_required") or []
        trigger_count = len(triggers) if isinstance(triggers, list) else 0
        sensor_count = len(sensors) if isinstance(sensors, list) else 0

        if trigger_count > MAX_TRIGGERS_PER_SKILL:
            raise SkillValidationError(
                f"Skill {skill_name!r}: {trigger_count} triggers exceeds the "
                f"limit of {MAX_TRIGGERS_PER_SKILL}."
            )
        if sensor_count > MAX_SENSORS_PER_SKILL:
            raise SkillValidationError(
                f"Skill {skill_name!r}: {sensor_count} required sensors exceeds "
                f"the limit of {MAX_SENSORS_PER_SKILL}."
            )

        # A skill with no declared sensor type subscribes to the wildcard once
        # per trigger, so the floor is the trigger count rather than zero.
        subscriptions = trigger_count * max(sensor_count, 1)
        if subscriptions > MAX_SUBSCRIPTIONS_PER_SKILL:
            raise SkillValidationError(
                f"Skill {skill_name!r}: {trigger_count} triggers × "
                f"{max(sensor_count, 1)} sensor types would register "
                f"{subscriptions} handlers, above the limit of "
                f"{MAX_SUBSCRIPTIONS_PER_SKILL}."
            )

        actions = raw.get("actions") or {}
        if isinstance(actions, dict):
            available = actions.get("available") or []
            if isinstance(available, list) and len(available) > MAX_ACTIONS_AVAILABLE:
                raise SkillValidationError(
                    f"Skill {skill_name!r}: {len(available)} declared actions "
                    f"exceeds the limit of {MAX_ACTIONS_AVAILABLE}."
                )
            defaults = actions.get("defaults") or {}
            if isinstance(defaults, dict):
                if len(defaults) > MAX_TRIGGERS_PER_SKILL:
                    raise SkillValidationError(
                        f"Skill {skill_name!r}: {len(defaults)} action default "
                        f"entries exceeds the limit of {MAX_TRIGGERS_PER_SKILL}."
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
                    if len(action_list) > MAX_ACTIONS_PER_TRIGGER:
                        raise SkillValidationError(
                            f"Skill {skill_name!r}: trigger {trigger_name!r} "
                            f"lists {len(action_list)} default actions, above "
                            f"the limit of {MAX_ACTIONS_PER_TRIGGER}. Each one "
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

                if total_references > MAX_TOTAL_DEFAULT_REFERENCES:
                    raise SkillValidationError(
                        f"Skill {skill_name!r}: {total_references} total default "
                        f"action references exceeds the limit of "
                        f"{MAX_TOTAL_DEFAULT_REFERENCES}."
                    )

        prompts = raw.get("prompts") or {}
        if isinstance(prompts, dict) and len(prompts) > MAX_PROMPTS_PER_SKILL:
            raise SkillValidationError(
                f"Skill {skill_name!r}: {len(prompts)} prompts exceeds the "
                f"limit of {MAX_PROMPTS_PER_SKILL}."
            )

        config = raw.get("config") or {}
        if isinstance(config, dict) and len(config) > MAX_CONFIG_ENTRIES:
            raise SkillValidationError(
                f"Skill {skill_name!r}: {len(config)} config entries exceeds "
                f"the limit of {MAX_CONFIG_ENTRIES}."
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
            ("name", MAX_SKILL_NAME_LENGTH),
            ("author", MAX_AUTHOR_LENGTH),
            ("version", MAX_VERSION_LENGTH),
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
            offending = display_unsafe_character(value)
            if offending is not None:
                raise SkillValidationError(
                    f"Skill directory {skill_dir.name!r}: {field_name} contains "
                    f"{offending}. Identity fields appear in logs and operator "
                    "messages and must be plain text."
                )

        name = raw.get("name")
        if isinstance(name, str) and not SKILL_NAME_RE.fullmatch(name):
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
            if name in packaged_skill_names():
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

    def _validate_skill_metadata(self, raw: dict[str, Any], skill_dir: Path) -> None:
        """Validate core metadata presence for runtime-loadable skills."""
        skill_dir_name = skill_dir.name
        declared_name = raw.get("name")
        who = (
            f"Skill {declared_name!r}"
            if isinstance(declared_name, str) and declared_name.strip()
            else f"Skill directory {skill_dir_name!r}"
        )
        for key in ("name", "version", "author"):
            value = raw.get(key)
            if value is not None and not isinstance(value, str):
                hint = (
                    "; YAML reads an unquoted number, boolean or date as that "
                    "type, so quote the value"
                    if isinstance(value, (bool, int, float, datetime.date))
                    else ""
                )
                raise SkillValidationError(
                    f"{who}: {key} must be a string, "
                    f"got {type(value).__name__}: {value!r}{hint}"
                )
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
            signature == BUNDLED_SIGNATURE_SENTINEL or signature.startswith("ed25519:")
        ):
            raise SkillSecurityError(
                f"Skill {name!r}: security.skills.require_signed is enabled — "
                f"bundled skills must carry {BUNDLED_SIGNATURE_SENTINEL!r} or an "
                f"'ed25519:' signature. Got {signature!r}."
            )
        if signature and not (
            signature == BUNDLED_SIGNATURE_SENTINEL or signature.startswith("ed25519:")
        ):
            raise SkillValidationError(
                f"Skill {name!r}: bundled skill signature must be either "
                f"{BUNDLED_SIGNATURE_SENTINEL!r} or an 'ed25519:' signature."
            )

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
            if "requires_approval" in entry:
                raise SkillValidationError(
                    f"Skill {skill_name!r}: action {action_name!r} declares "
                    "requires_approval in actions.available, where the runtime "
                    "does not read it. Approval is decided per trigger: declare "
                    "requires_approval on the trigger that defaults to this action."
                )

            unknown_keys = set(entry.keys()) - ACTION_ALLOWED_KEYS
            if unknown_keys:
                action_name = entry.get("name", "<unnamed>")
                raise SkillValidationError(
                    f"Skill {skill_name!r}: action {action_name!r} in actions.available contains "
                    f"unrecognized key(s) which the runtime does not read: "
                    f"{', '.join(sorted(unknown_keys))}"
                )

            # A tier letter in either case, as skills-package/v2 shipped: an
            # unrecognised tier is refused, never read as Tier A.
            # An omitted tier is decided below; a present one must be a letter,
            # so `tier: ""` is refused, never read as omitted.
            raw_tier = entry.get("tier", "")
            declared = raw_tier.upper() if raw_tier.isascii() else raw_tier
            if "tier" in entry and declared not in VALID_TIERS:
                raise SkillValidationError(
                    f"Skill {skill_name!r}: action {action_name!r} declares "
                    f"tier={raw_tier!r}; a tier is one of {sorted(VALID_TIERS)}."
                )
            if not isinstance(action_name, str):
                continue
            _refuse_reserved_action_name(skill_name, action_name, "actions.available")
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
            if floor is None:
                # An ungoverned name cannot actuate: `register_executor` refuses
                # an action with no registry entry, so nothing can ever be bound
                # to it. Declaring one at Tier A is legitimate — a skill may
                # name its own informational action, and dispatch records the
                # intent. Declaring one at B, C or D is a claim to change the
                # world that the runtime has no way to honour, and a trigger
                # defaulting to it reads as protection while being incapable of
                # it. Registry membership is a closed, decidable fact, so this
                # is refused at load rather than discovered when the trigger
                # fires — which for a Tier D trigger is the worst possible
                # moment to find out.
                if tier_rank(declared) > tier_rank("A"):
                    raise SkillValidationError(
                        f"Skill {skill_name!r}: action {action_name!r} is "
                        f"declared as Tier {declared}, but the runtime has no "
                        f"capability by that name and can never execute it. "
                        f"Declare an action the runtime holds, or declare this "
                        f"one as Tier A if it is informational. Giving the "
                        f"runtime this capability is a runtime change, not a "
                        f"configuration one: nothing in `ori.yaml` replaces a "
                        f"skill's action lists. Until the capability exists, a "
                        f"skill declares its notifications only."
                    )
                continue
            if tier_rank(declared) >= tier_rank(floor):
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
            # Each step refuses in the order the checks always ran, so a
            # malformed trigger is refused for the same reason as before.
            name = _trigger_name(raw, skill_name, seen_trigger_names)
            action_tier = _trigger_tier(raw, skill_name, name, first_party=first_party)
            bypass_llm, requires_approval, reasoning_policy, escalate_to = (
                _trigger_reasoning(raw, skill_name, name, action_tier)
            )
            safe_default_action = _trigger_safe_default(
                raw, skill_name, name, action_tier
            )
            approval_timeout = raw.get("approval_timeout_seconds", 300)
            if not approval_timeout_accepted(approval_timeout):
                raise SkillValidationError(
                    f"trigger {name!r}: approval_timeout_seconds must be an integer "
                    f"from 1 to {MAX_PROPOSAL_LIFETIME_S}, got {approval_timeout!r}"
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
                    approval_timeout_seconds=int(approval_timeout),
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
            count = len(HISTORY_PLACEHOLDER_PATTERN.findall(template))
            if count <= MAX_HISTORY_PLACEHOLDERS:
                continue
            scope = (
                "trigger"
                if isinstance(prompt_key, str) and prompt_key in trigger_name_set
                else "prompt key"
            )
            raise SkillValidationError(
                f"Skill {skill_name!r}: {scope} {prompt_key!r} contains {count} "
                f"history placeholders; maximum allowed is {MAX_HISTORY_PLACEHOLDERS}."
            )
