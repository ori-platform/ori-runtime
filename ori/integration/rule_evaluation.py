# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Stable in-process rule-evaluation boundary for demos and product tests.

This module lets product/demo consumers prove Ori runtime rule decisions without
starting the full runtime loop. It uses the real SkillLoader and RuleEngine, but
it deliberately does not touch hardware, MQTT, LLMs, actions, or SQLite unless a
caller explicitly supplies a compatible state-store object for history lookups.
"""

from __future__ import annotations

import asyncio
import re
import sysconfig
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

from ori.network.events import OriEvent, SensorReading
from ori.reasoning.rule_engine import RuleEngine, RuleResult
from ori.skills.hooks_api import HookContext
from ori.skills.loader import Skill, SkillLoader, Trigger

ActionTier = Literal["A", "B", "C", "D"]

_THRESHOLD_VAR_RE = re.compile(r"\bvalue\s*(?:>=|>|<=|<)\s*([A-Za-z_][A-Za-z0-9_]*)")
_THRESHOLD_LITERAL_RE = re.compile(
    r"\bvalue\s*(?:>=|>|<=|<)\s*(-?(?:\d+(?:\.\d*)?|\.\d+))\b"
)
_DEFAULT_SKILLS_DATA_DIR = Path("share") / "ori-runtime" / "skills"
# Process-local sessions intentionally preserve cooldown state for default
# demo/API evaluations. Tests that assert cooldown behavior should construct an
# explicit RuleEvaluationSession to avoid cross-test coupling.
_DEFAULT_SESSIONS: dict[tuple[str, str | None], "RuleEvaluationSession"] = {}


@dataclass(frozen=True)
class RuleEvaluationRequest:
    """Typed input for deterministic runtime rule evaluation.

    ``skill_config_overrides`` exists for demos and product tests that need to
    model a site-specific configuration, such as a different overcurrent
    threshold, without modifying the bundled skill file.
    """

    sensor_id: str
    sensor_type: str
    value: float
    unit: str
    timestamp_ms: int
    quality: float = 1.0
    device_id: str = "demo-device-01"
    skill_name: str = "energy-anomaly-detector"
    skills_root: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    event_context: dict[str, object] = field(default_factory=dict)
    skill_config_overrides: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_request(self)


@dataclass(frozen=True)
class RuleEvaluationResult:
    """Typed output with proof fields suitable for demo Proof Mode."""

    matched: bool
    action_tier: ActionTier
    trigger_name: str | None
    proposed_action: str | None
    default_actions: tuple[str, ...]
    latency_ms: int
    proof_rule_condition: str
    proof_threshold: float | None
    proof_threshold_name: str | None
    proof_sensor_value: float
    proof_tier_selected: ActionTier
    skill_name: str
    skill_version: str
    escalation_target: str | None
    bypass_llm: bool
    reasoning_policy: str | None
    requires_approval: bool


class RuleEvaluationSession:
    """Reusable rule-evaluation session with stable skill and cooldown state."""

    def __init__(
        self,
        *,
        skill_name: str = "energy-anomaly-detector",
        skills_root: str | None = None,
        rule_engine: RuleEngine | None = None,
    ) -> None:
        self._key = _session_key(skill_name, skills_root)
        self._skill = SkillLoader().load_one(_skill_dir(skill_name, skills_root))
        self._rule_engine = rule_engine or RuleEngine()

    async def evaluate(
        self,
        request: RuleEvaluationRequest,
        *,
        state_store: object | None = None,
    ) -> RuleEvaluationResult:
        if _session_key(request.skill_name, request.skills_root) != self._key:
            raise ValueError(
                "RuleEvaluationSession can only evaluate requests for its skill"
            )
        return await _evaluate_with_skill(
            request,
            skill=self._skill,
            rule_engine=self._rule_engine,
            state_store=state_store,
        )


def _session_key(skill_name: str, skills_root: str | None) -> tuple[str, str | None]:
    root = str(Path(skills_root).resolve(strict=False)) if skills_root else None
    return _validate_skill_name(skill_name), root


def bundled_skill_path(skill_name: str) -> Path:
    """Return the path for a bundled skill in source checkouts or installed wheels."""
    clean_name = _validate_skill_name(skill_name)

    source_candidate = Path(__file__).resolve().parents[2] / "skills" / clean_name
    if (source_candidate / "skill.yaml").is_file():
        return source_candidate

    installed_candidate = (
        Path(sysconfig.get_path("data")) / _DEFAULT_SKILLS_DATA_DIR / clean_name
    )
    if (installed_candidate / "skill.yaml").is_file():
        return installed_candidate

    raise FileNotFoundError(f"bundled skill {clean_name!r} was not found")


async def evaluate_sensor_reading(
    request: RuleEvaluationRequest,
    *,
    state_store: object | None = None,
) -> RuleEvaluationResult:
    """Evaluate one reading through the real runtime rule engine.

    This is intentionally in-process and deterministic. It is for product demos,
    tests, and SDK runtime extras; production product surfaces should use the
    gateway/runtime transport contracts instead.

    Repeated calls for the same skill reuse a session so trigger cooldown state
    and skill loading semantics match the long-lived runtime more closely.
    """
    session = _default_session(request)
    return await session.evaluate(request, state_store=state_store)


async def _evaluate_with_skill(
    request: RuleEvaluationRequest,
    *,
    skill: Skill,
    rule_engine: RuleEngine,
    state_store: object | None,
) -> RuleEvaluationResult:
    start = time.perf_counter()

    skill_config = _merged_skill_config(skill, request.skill_config_overrides)
    event = _event_from_request(request)
    context = await _rule_context(event, skill, skill_config, state_store)
    rule_result = await rule_engine.evaluate(
        event,
        skill.triggers,
        context=context,
        state_store=state_store,
    )
    latency_ms = max(0, int((time.perf_counter() - start) * 1000))

    return _result_from_rule(
        request=request,
        skill=skill,
        context=context,
        rule_result=rule_result,
        latency_ms=latency_ms,
    )


def _default_session(request: RuleEvaluationRequest) -> RuleEvaluationSession:
    key = _session_key(request.skill_name, request.skills_root)
    session = _DEFAULT_SESSIONS.get(key)
    if session is None:
        session = RuleEvaluationSession(
            skill_name=request.skill_name,
            skills_root=request.skills_root,
        )
        _DEFAULT_SESSIONS[key] = session
    return session


def _validate_request(request: RuleEvaluationRequest) -> None:
    if not request.sensor_id.strip():
        raise ValueError("sensor_id must not be empty")
    if not request.sensor_type.strip():
        raise ValueError("sensor_type must not be empty")
    if not request.unit.strip():
        raise ValueError("unit must not be empty")
    if not (0.0 <= request.quality <= 1.0):
        raise ValueError("quality must be between 0.0 and 1.0")
    if request.timestamp_ms < 0:
        raise ValueError("timestamp_ms must be non-negative")
    _validate_skill_name(request.skill_name)


def _validate_skill_name(skill_name: str) -> str:
    clean_name = skill_name.strip()
    if not clean_name:
        raise ValueError("skill_name must not be empty")
    if any(part in clean_name for part in ("/", "\\", "..")):
        raise ValueError("skill_name must be a bundled skill directory name")
    if len(Path(clean_name).parts) != 1:
        raise ValueError("skill_name must be a single directory name")
    return clean_name


def _skill_dir(skill_name: str, skills_root: str | None) -> Path:
    clean_name = _validate_skill_name(skill_name)
    if skills_root is None:
        return bundled_skill_path(clean_name)

    root = Path(skills_root).resolve(strict=False)
    skill_dir = (root / clean_name).resolve(strict=False)
    try:
        skill_dir.relative_to(root)
    except ValueError as exc:
        raise ValueError("skill_name resolves outside skills_root") from exc
    if not (skill_dir / "skill.yaml").is_file():
        raise FileNotFoundError(f"skill {clean_name!r} was not found under {root}")
    return skill_dir


def _merged_skill_config(
    skill: Skill,
    overrides: dict[str, object],
) -> dict[str, object]:
    config: dict[str, object] = dict(skill.config)
    config.update(overrides)
    return config


def _event_from_request(request: RuleEvaluationRequest) -> OriEvent:
    reading = SensorReading(
        sensor_id=request.sensor_id,
        sensor_type=request.sensor_type,
        value=request.value,
        unit=request.unit,
        timestamp=request.timestamp_ms,
        quality=request.quality,
        metadata=dict(request.metadata),
    )
    event = OriEvent.from_reading(reading, request.device_id)
    event.context.update(request.event_context)
    return event


async def _rule_context(
    event: OriEvent,
    skill: Skill,
    skill_config: dict[str, object],
    state_store: object | None,
) -> dict[str, object]:
    context: dict[str, object] = dict(skill_config)
    hooks = skill.hooks
    pre_trigger_eval = getattr(hooks, "pre_trigger_eval", None)
    if not callable(pre_trigger_eval):
        return context

    hook_ctx = HookContext.build(
        event,
        state_store,
        skill.name,
        skill_config=skill_config,
    )
    maybe = pre_trigger_eval(hook_ctx)
    if asyncio.iscoroutine(maybe):
        await maybe
    context.update(hook_ctx.derived)
    return context


def _result_from_rule(
    *,
    request: RuleEvaluationRequest,
    skill: Skill,
    context: dict[str, object],
    rule_result: RuleResult,
    latency_ms: int,
) -> RuleEvaluationResult:
    action_tier = _as_action_tier(rule_result.action_tier)
    trigger = _trigger_by_name(skill, rule_result.rule_name)
    condition = trigger.condition if trigger is not None else ""
    threshold_name, threshold = _proof_threshold(condition, context)
    default_actions = tuple(
        skill.get_default_actions_for_trigger(rule_result.rule_name or "")
    )
    proposed_action = rule_result.action or (
        default_actions[0] if default_actions else None
    )

    return RuleEvaluationResult(
        matched=rule_result.matched,
        action_tier=action_tier,
        trigger_name=rule_result.rule_name,
        proposed_action=proposed_action,
        default_actions=default_actions,
        latency_ms=latency_ms,
        proof_rule_condition=condition,
        proof_threshold=threshold,
        proof_threshold_name=threshold_name,
        proof_sensor_value=request.value,
        proof_tier_selected=action_tier,
        skill_name=skill.name,
        skill_version=skill.version,
        escalation_target=rule_result.escalate_to,
        bypass_llm=rule_result.bypass_llm,
        reasoning_policy=rule_result.reasoning_policy,
        requires_approval=rule_result.requires_approval,
    )


def _trigger_by_name(skill: Skill, trigger_name: str | None) -> Trigger | None:
    if trigger_name is None:
        return None
    for trigger in skill.triggers:
        if trigger.name == trigger_name:
            return trigger
    return None


def _proof_threshold(
    condition: str,
    context: dict[str, object],
) -> tuple[str | None, float | None]:
    match = _THRESHOLD_VAR_RE.search(condition)
    if match is not None:
        name = match.group(1)
        raw = context.get(name)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return name, None
        return name, float(raw)

    literal_match = _THRESHOLD_LITERAL_RE.search(condition)
    if literal_match is None:
        return None, None
    return None, float(literal_match.group(1))


def _as_action_tier(value: str) -> ActionTier:
    if value not in {"A", "B", "C", "D"}:
        return "A"
    return cast(ActionTier, value)
