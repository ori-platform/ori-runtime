# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Intelligence Elevator — Tier 1–4 reasoning selector.

The elevator picks the cheapest reasoning tier that can handle a given event
and returns a :class:`~ori.network.events.ReasoningResult`.

.. important::

   Callers MUST use ``asyncio.create_task(elevator.reason_and_dispatch(...))``
   not direct ``await``.  Direct ``await`` blocks EventBus delivery to all
   other subscribers for the full LLM inference duration (3–8 seconds).
   The ``create_task()`` call at the EventBus-handler boundary is the single
   point where control is yielded back to the event loop immediately.
"""

import ast
import asyncio
import datetime
import inspect
import json
import logging
import re
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ori.network.events import OriEvent, ReasoningResult
from ori.reasoning.capability_posture import (
    CapabilityPosture,
)
from ori.reasoning.causal_memory import CausalMemory
from ori.reasoning.context_enricher import ContextEnricher
from ori.reasoning.escalation_policy import (
    GATEWAY_ESCALATION_CONTEXT_KEY,
    attach_gateway_escalation_context,
    evaluate_gateway_escalation,
)
from ori.reasoning.rule_engine import RuleEngine, RuleEngineSafetyError
from ori.utils.time_utils import now_ms

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)
_HISTORY_PLACEHOLDER_PATTERN = re.compile(r"\{history\.[^{}]+\}")
_MAX_HISTORY_PLACEHOLDERS = 16
_UNRESOLVED_HISTORY_PLACEHOLDER_SENTINEL = "null"
_DECISION_HISTORY_WINDOW_LIMIT = 10


# ── Shared dispatch context ───────────────────────────────────────────────────
# SkillContext is the lightweight boundary object passed from reasoning into
# action dispatch. Keep it small and serializable-adjacent; richer runtime data
# should live on OriEvent.context or in StateStore.


@dataclass
class SkillContext:
    """Lightweight context bundle threaded through the reasoning pipeline."""

    skill: Any  # Skill instance (loader.py step 14)
    event: OriEvent
    state_store: Any  # StateStore
    trigger_name: str = ""


@dataclass(frozen=True)
class _ParsedHistoryCall:
    method: str
    args: tuple[Any, ...]


def _hour_now(event: OriEvent | None = None) -> int:
    tz_name = ""
    if event is not None and isinstance(getattr(event, "context", None), dict):
        tz_name = str(event.context.get("device_timezone", "") or "").strip()
    if tz_name:
        try:
            return datetime.datetime.now(ZoneInfo(tz_name)).hour
        except (ZoneInfoNotFoundError, ValueError):
            logger.warning(
                "IntelligenceElevator: invalid device_timezone %r; falling back to UTC",
                tz_name,
            )
    return datetime.datetime.now(datetime.timezone.utc).hour


def _complexity_score(
    current_value: float,
    avg_24h: float | None,
    history: list[float],
    hour: int,
) -> float:
    """Score 0.0–1.0 reflecting how much reasoning effort an event warrants.

    Three signals contribute equally (1/3 each):

    **Deviation** — how far the current reading is from the 24-hour average.
    Capped at 2× the average; above that it's always 1.0.

    **Volatility** — standard deviation of the last N readings, normalised by
    the mean.  High variance = higher complexity.

    **Unusual hour** — readings outside 06:00–22:00 are slightly elevated
    because nocturnal anomalies are less expected.
    """
    scores: list[float] = []

    # 1. Deviation from 24-hour average
    if avg_24h and avg_24h > 0:
        deviation_ratio = abs(current_value - avg_24h) / avg_24h
        scores.append(min(deviation_ratio / 2.0, 1.0))
    else:
        scores.append(0.0)

    # 2. Recent history volatility (coefficient of variation)
    if len(history) >= 2:
        mean = sum(history) / len(history)
        if mean > 0:
            variance = sum((x - mean) ** 2 for x in history) / len(history)
            cv = (variance**0.5) / mean
            scores.append(min(cv, 1.0))
        else:
            scores.append(0.0)
    else:
        scores.append(0.0)

    # 3. Unusual hour (outside 06:00–22:00)
    scores.append(0.0 if 6 <= hour <= 22 else 0.3)

    return sum(scores) / len(scores)


class IntelligenceElevator:
    """Selects the cheapest reasoning tier and returns a :class:`~ori.network.events.ReasoningResult`.

    Tier selection order (cheapest first):

    1. **Rule engine** — microseconds, always evaluated first.
       If a Tier D rule fires, returns immediately without LLM.
    2. **Local SLM** — 3–8 seconds, offline capable.
    3. **Gateway LLM** — 1–3 seconds, LAN/MQTT gateway required.

    Fallback is always ``local_slm``.
    Cloud reasoning, when used, is a gateway backend, not a runtime tier.

    Args:
        local_llm: A :class:`~ori.reasoning.local_llm.LocalLLM` instance
            (optional — if ``None`` or unavailable, falls back to a stub result).
        rule_engine: A :class:`~ori.reasoning.rule_engine.RuleEngine` instance.
            Created internally if not provided.
    """

    def __init__(
        self,
        local_llm: Any = None,
        gateway_reasoner: Any = None,
        rule_engine: RuleEngine | None = None,
        config: Any = None,
        context_enricher: ContextEnricher | None = None,
    ) -> None:
        self._local_llm = local_llm
        self._gateway_reasoner = gateway_reasoner
        self._rule_engine = rule_engine or RuleEngine()
        self._config = (
            config  # ReasoningConfig from ori.yaml; None in test environments
        )
        self._context_enricher = context_enricher
        self._event_bus: Any = None
        self._last_power_mode: str = "normal"
        self._capability_posture: CapabilityPosture | None = None

    def attach_event_bus(self, event_bus: Any) -> None:
        """Attach EventBus for synthetic runtime alerts emitted by the elevator."""
        self._event_bus = event_bus

    def update_capability_posture(self, posture: CapabilityPosture) -> None:
        """Inject latest runtime capability posture snapshot."""
        self._capability_posture = posture

    def get_capability_posture(self) -> CapabilityPosture | None:
        """Return latest posture snapshot, or None if unavailable."""
        return self._capability_posture

    # ── Public API ────────────────────────────────────────────────────────────

    async def reason(
        self,
        event: OriEvent,
        skill: Any,
        state_store: Any,
    ) -> ReasoningResult:
        """Select the cheapest tier and return a reasoning result.

        .. warning::

           Must only be called via ``asyncio.create_task()``, never with direct
           ``await``, when invoked from an EventBus handler.

        Args:
            event: The sensor event to reason about.
            skill: The :class:`~ori.skills.loader.Skill` instance whose triggers
                are evaluated first by the rule engine.
            state_store: A :class:`~ori.state.store.StateStore` for history
                queries used in complexity scoring.

        Returns:
            :class:`~ori.network.events.ReasoningResult` from whichever tier
            handled the request.
        """
        result, _ = await self._reason_with_rule_result(
            event=event,
            skill=skill,
            state_store=state_store,
            precomputed_rule_result=None,
        )
        return result

    async def _reason_with_rule_result(
        self,
        event: OriEvent,
        skill: Any,
        state_store: Any,
        precomputed_rule_result: Any = None,
    ) -> tuple[ReasoningResult, Any]:
        """Run reasoning and return both the model result and evaluated rule result."""
        rule_result = precomputed_rule_result
        if rule_result is None:
            rule_result, _ = await self._evaluate_rules_with_hooks(
                event, skill, state_store
            )

        tier = await self._select_tier_from_rule_result(
            event=event,
            skill=skill,
            state_store=state_store,
            rule_result=rule_result,
        )

        rejection_record = await self._lookup_rejection_record(
            event=event,
            skill=skill,
            rule_result=rule_result,
            state_store=state_store,
        )
        rejection_note: str | None = None
        if rejection_record is not None:
            operator_reason = self._sanitize_prompt_input(
                rejection_record.get("operator_response") or "",
                is_reply=True,  # sanitised — AGENTS.md Rule 4.
            )
            if operator_reason:
                rejection_note = (
                    "NOTE: A similar pattern was previously rejected by the operator. "
                    f"Reason: {operator_reason}. Consider this context."
                )
            else:
                rejection_note = (
                    "NOTE: A similar pattern was previously rejected by the operator. "
                    "Consider this context."
                )
            if isinstance(event.context, dict):
                event.context["__rejection_cap_tier_a"] = True

        if tier == "rule":
            return (
                ReasoningResult(
                    text=f"Rule matched: {rule_result.rule_name}",
                    tier="rule",
                    model="rule_engine",
                    tokens_used=0,
                    latency_ms=0,
                    confidence=rule_result.confidence,
                    action_tier=rule_result.action_tier,
                    proposed_action=rule_result.action,
                ),
                rule_result,
            )

        causal_hit = await self._lookup_causal_resolution(
            event=event,
            rule_result=rule_result,
            state_store=state_store,
        )
        if causal_hit is not None:
            pattern_key, cached_text = causal_hit
            if isinstance(getattr(event, "context", None), dict):
                event.context["__causal_memory_hit"] = True
                event.context["__causal_memory_key"] = pattern_key
            return (
                ReasoningResult(
                    text=cached_text,
                    tier="local_slm",
                    model="causal_memory",
                    tokens_used=0,
                    latency_ms=0,
                    confidence=1.0,
                    action_tier=(
                        "A" if rejection_record is not None else rule_result.action_tier
                    ),
                    proposed_action=rule_result.action,
                ),
                rule_result,
            )

        if tier == "gateway" and self._gateway_reasoner is not None:
            prompt = await self._build_prompt(
                event,
                skill,
                state_store=state_store,
                trigger_name=rule_result.rule_name if rule_result.matched else None,
                rejection_note=rejection_note,
            )
            try:
                result = await self._call_gateway_reasoner(
                    prompt=prompt,
                    event=event,
                    rule_result=rule_result,
                    state_store=state_store,
                )
                result.tier = "gateway"
                result.prompt = prompt
                if (
                    rule_result.matched
                    and result.action_tier != "D"
                    and rejection_record is None
                ):
                    result.action_tier = rule_result.action_tier
                if rejection_record is not None:
                    result.action_tier = "A"
                result.proposed_action = result.proposed_action or rule_result.action
                return result, rule_result
            except Exception:
                logger.exception(
                    "IntelligenceElevator: gateway inference failed for "
                    "sensor_id=%s — falling back according to gateway policy",
                    event.sensor_id if event else "unknown",
                )
                if self._gateway_floor_selected(event):
                    stub = self._stub_result("gateway", event)
                    if (
                        rule_result.matched
                        and stub.action_tier != "D"
                        and rejection_record is None
                    ):
                        stub.action_tier = rule_result.action_tier
                        stub.proposed_action = rule_result.action
                    if rejection_record is not None:
                        stub.action_tier = "A"
                    return stub, rule_result
                tier = "local_slm"

        if tier in ("local_slm",) and self._local_llm is not None:
            pattern_key: str | None = None
            if self._causal_memory_enabled() and rule_result.matched:
                trigger_name = str(getattr(rule_result, "rule_name", "") or "")
                if trigger_name and event.reading is not None:
                    try:
                        pattern_key = CausalMemory.generate_key(event, trigger_name)
                    except Exception:
                        pattern_key = None
            prompt = await self._build_prompt(
                event,
                skill,
                state_store=state_store,
                trigger_name=rule_result.rule_name if rule_result.matched else None,
                rejection_note=rejection_note,
            )
            try:
                result = await self._local_llm.reason(prompt)
                result.prompt = prompt
                if (
                    rule_result.matched
                    and result.action_tier != "D"
                    and rejection_record is None
                ):
                    result.action_tier = rule_result.action_tier
                if rejection_record is not None:
                    result.action_tier = "A"
                result.proposed_action = result.proposed_action or rule_result.action
                await self._store_causal_resolution(
                    state_store=state_store,
                    pattern_key=pattern_key,
                    text=result.text,
                    confidence=float(getattr(result, "confidence", 0.0) or 0.0),
                )
                return result, rule_result
            except Exception:
                logger.exception(
                    "IntelligenceElevator: local_slm inference failed for "
                    "sensor_id=%s — returning stub result",
                    event.sensor_id if event else "unknown",
                )

        # Fallback stub for unavailable reasoning tiers.
        stub = self._stub_result(tier, event)
        if rule_result.matched and stub.action_tier != "D" and rejection_record is None:
            stub.action_tier = rule_result.action_tier
            stub.proposed_action = rule_result.action
        if rejection_record is not None:
            stub.action_tier = "A"
        return stub, rule_result

    async def _call_gateway_reasoner(
        self,
        *,
        prompt: str,
        event: OriEvent,
        rule_result: Any,
        state_store: Any,
    ) -> ReasoningResult:
        """Call rich gateway reasoners with context, prompt-only mocks without it."""
        reason = self._gateway_reasoner.reason
        try:
            signature = inspect.signature(reason)
        except (TypeError, ValueError):
            return await reason(prompt)
        params = signature.parameters
        accepts_context = any(
            param.kind == inspect.Parameter.VAR_KEYWORD for param in params.values()
        ) or {"event", "rule_result", "state_store"}.issubset(params)
        if accepts_context:
            return await reason(
                prompt,
                event=event,
                rule_result=rule_result,
                state_store=state_store,
            )
        return await reason(prompt)

    @staticmethod
    def _gateway_floor_selected(event: OriEvent) -> bool:
        """Return True when a trigger-declared gateway floor selected Tier 3."""
        if not isinstance(getattr(event, "context", None), dict):
            return False
        ctx = event.context.get(GATEWAY_ESCALATION_CONTEXT_KEY)
        if not isinstance(ctx, dict) or not bool(ctx.get("selected", False)):
            return False
        signals = ctx.get("signals")
        if not isinstance(signals, list):
            return False
        return any(
            isinstance(signal, dict)
            and signal.get("code") == "trigger_declares_gateway"
            for signal in signals
        )

    async def _evaluate_rules_with_hooks(
        self, event: OriEvent, skill: Any, state_store: Any
    ):
        """Build context with derived hook variables, and evaluate against RuleEngine."""
        rules = getattr(skill, "triggers", [])
        ctx: dict[str, Any] = {}
        if hasattr(skill, "config") and isinstance(skill.config, dict):
            ctx.update(skill.config)

        hook_ctx = None
        if hasattr(skill, "hooks") and hasattr(skill.hooks, "pre_trigger_eval"):
            from ori.skills.hooks_api import HookContext

            hook_ctx = HookContext.build(
                event,
                state_store,
                getattr(skill, "name", "unknown"),
                skill_config=getattr(skill, "config", None),
            )
            try:
                maybe = skill.hooks.pre_trigger_eval(hook_ctx)
                if asyncio.iscoroutine(maybe):
                    await maybe
                ctx.update(hook_ctx.derived)
            except Exception:
                logger.exception(
                    "IntelligenceElevator: pre_trigger_eval hook failed for %r",
                    getattr(skill, "name", "unknown"),
                )

        rule_result = await self._rule_engine.evaluate(
            event, rules, context=ctx, state_store=state_store
        )
        return rule_result, hook_ctx

    async def select_tier(
        self,
        event: OriEvent,
        skill: Any,
        state_store: Any,
    ) -> str:
        """Choose ``'rule'`` | ``'local_slm'`` | ``'gateway'``.

        Selection logic:

        1. Run the rule engine.  If Tier D fires → ``'rule'`` immediately.
        2. Score complexity (0.0–1.0) from deviation, volatility, hour.
        3. ``complexity < 0.3`` → ``'local_slm'``
           deterministic gateway signals → ``'gateway'`` when reachable
           fallback → ``'local_slm'``
        """
        rule_result, _ = await self._evaluate_rules_with_hooks(
            event, skill, state_store
        )
        return await self._select_tier_from_rule_result(
            event=event,
            skill=skill,
            state_store=state_store,
            rule_result=rule_result,
        )

    async def _select_tier_from_rule_result(
        self,
        event: OriEvent,
        skill: Any,
        state_store: Any,
        rule_result: Any,
    ) -> str:
        """Select reasoning tier using a pre-evaluated rule result."""
        # Energy-aware throttle: cap to rule-only under low battery to preserve
        # power for safety actions. Tier D remains guaranteed by rule execution
        # in the reasoning path.
        energy_cfg = self._energy_aware_cfg()
        if bool(energy_cfg.get("enabled", False)):
            battery_pct = await self._get_battery_percent(state_store)
            if battery_pct is not None:
                critical = float(energy_cfg.get("critical_threshold_percent", 10))
                throttle = float(energy_cfg.get("throttle_threshold_percent", 20))
                if battery_pct < critical:
                    if self._last_power_mode != "critical":
                        await self._emit_power_alert(
                            battery_pct=battery_pct, level="critical", event=event
                        )
                    self._last_power_mode = "critical"
                    return "rule"
                if battery_pct < throttle:
                    if self._last_power_mode != "low":
                        await self._emit_power_alert(
                            battery_pct=battery_pct, level="low", event=event
                        )
                    self._last_power_mode = "low"
                    return "rule"
                self._last_power_mode = "normal"

        # Tier D is always handled by the rule engine — return immediately
        if rule_result.matched and rule_result.action_tier == "D":
            return "rule"

        # Any bypass_llm rule also skips LLM
        if rule_result.matched and rule_result.bypass_llm:
            return "rule"

        # The matched trigger's escalate_to is an authoritative floor for
        # reasoning tier selection on non-bypass paths.
        tier_order: dict[str, int] = {
            "rule": 1,
            "local_slm": 2,
            "gateway": 3,
        }
        tier_floor = "local_slm"
        if rule_result.matched:
            declared = str(rule_result.escalate_to or "local_slm").strip().lower()
            if declared in tier_order:
                tier_floor = declared

        def _apply_floor(candidate: str) -> str:
            candidate_rank = tier_order.get(candidate, tier_order["local_slm"])
            floor_rank = tier_order.get(tier_floor, tier_order["local_slm"])
            if candidate_rank < floor_rank:
                return tier_floor
            return candidate

        # Complexity scoring needs current value and history
        current_value = event.reading.value if event.reading else 0.0
        avg_24h: float | None = None
        history: list[float] = []
        history_query_failed = False

        if state_store is not None and event.reading is not None:
            try:
                avg_24h = await state_store.avg_last_hours(event.reading.sensor_id, 24)
                readings = await state_store.get_history(
                    event.reading.sensor_id, limit=10
                )
                history = [r.value for r in readings]
            except Exception:
                history_query_failed = True
                logger.debug(
                    "IntelligenceElevator: could not fetch history for %s",
                    event.sensor_id,
                )
        else:
            history_query_failed = event.reading is not None

        gateway_available = self._gateway_reasoning_available()
        gateway_decision = evaluate_gateway_escalation(
            event=event,
            rule_result=rule_result,
            avg_24h=avg_24h,
            history=history,
            history_query_failed=history_query_failed,
        )
        trigger_floor_gateway = any(
            signal.code == "trigger_declares_gateway"
            for signal in gateway_decision.signals
        )
        if gateway_decision.should_escalate:
            selected = trigger_floor_gateway or gateway_available
            attach_gateway_escalation_context(
                event,
                gateway_decision,
                selected=selected,
                gateway_available=gateway_available,
            )
            if selected:
                return "gateway"

        complexity = _complexity_score(
            current_value, avg_24h, history, _hour_now(event)
        )

        threshold = (
            getattr(self._config, "escalation_threshold", 0.70)
            if self._config
            else 0.70
        )

        if complexity < 0.3:
            return _apply_floor("local_slm")

        if complexity < threshold:
            # Gateway selection is deterministic, not confidence/complexity-only.
            return _apply_floor("local_slm")

        # Cloud reasoning, when used, is a gateway backend.
        return _apply_floor("local_slm")

    def _gateway_reasoning_available(self) -> bool:
        """Return True only when gateway transport and fresh reachability exist."""
        if self._gateway_reasoner is None:
            return False
        if self._capability_posture is None or self._capability_posture.is_stale():
            return False
        return bool(self._capability_posture.gateway_reachable)

    def _energy_aware_cfg(self) -> dict[str, Any]:
        """Return energy-aware throttle config from either dataclass or dict."""
        cfg = self._config
        if cfg is None:
            return {}
        if isinstance(cfg, dict):
            raw = cfg.get("energy_aware_reasoning") or {}
            return raw if isinstance(raw, dict) else {}
        raw = getattr(cfg, "energy_aware_reasoning", {}) or {}
        return raw if isinstance(raw, dict) else {}

    async def _get_battery_percent(self, state_store: Any) -> float | None:
        """Read latest battery percentage from configured history sensor."""
        cfg = self._energy_aware_cfg()
        battery_sensor_id = str(cfg.get("battery_sensor_id", "")).strip()
        if not battery_sensor_id:
            return None
        if state_store is None or not hasattr(state_store, "get_history"):
            return None
        try:
            rows = await state_store.get_history(battery_sensor_id, limit=1)
        except Exception:
            logger.debug(
                "IntelligenceElevator: failed to read battery history for %s",
                battery_sensor_id,
            )
            return None

        if not rows:
            return None
        latest = rows[0]
        raw_value: Any
        if hasattr(latest, "value"):
            raw_value = latest.value
        elif isinstance(latest, dict):
            raw_value = latest.get("value")
        else:
            return None
        try:
            return float(raw_value)
        except (TypeError, ValueError):
            return None

    async def _emit_power_alert(
        self, battery_pct: float, level: str, event: OriEvent
    ) -> None:
        """Publish one low-power alert per threshold crossing."""
        cfg = self._energy_aware_cfg()
        if not bool(cfg.get("alert_on_throttle", True)):
            return

        msg = (
            "Device in low-power mode — LLM reasoning disabled. "
            "Safety rules remain active."
        )
        logger.warning(
            "IntelligenceElevator: %s battery throttle active at %.2f%% — %s",
            level,
            battery_pct,
            msg,
        )

        if self._event_bus is None:
            return

        alert_event = OriEvent(
            event_id=str(uuid.uuid4()),
            event_type="power.low_battery_throttle",
            device_id=event.device_id,
            sensor_id=event.sensor_id,
            timestamp=now_ms(),
            reading=None,
            context={
                "message": msg,
                "level": level,
                "battery_percent": battery_pct,
                "action_tier": "A",
            },
            source="elevator",
        )
        try:
            await self._event_bus.publish(alert_event)
        except Exception:
            logger.exception(
                "IntelligenceElevator: failed to publish low-power alert event"
            )

    def _causal_memory_cfg(self) -> dict[str, Any]:
        """Return causal-memory config from either dataclass or raw dict."""
        cfg = self._config
        if cfg is None:
            return {}
        if isinstance(cfg, dict):
            raw = cfg.get("causal_memory") or {}
            return raw if isinstance(raw, dict) else {}
        raw = getattr(cfg, "causal_memory", {}) or {}
        return raw if isinstance(raw, dict) else {}

    def _causal_memory_enabled(self) -> bool:
        cfg = self._causal_memory_cfg()
        if not cfg:
            return False
        return bool(cfg.get("enabled", False))

    def _causal_memory_min_confidence(self) -> float:
        cfg = self._causal_memory_cfg()
        raw = cfg.get("min_confidence_to_store", 0.0)
        try:
            return float(raw)
        except (TypeError, ValueError):
            return 0.0

    async def _lookup_causal_resolution(
        self,
        event: OriEvent,
        rule_result: Any,
        state_store: Any,
    ) -> tuple[str, str] | None:
        """Return ``(pattern_key, cached_text)`` for a causal-memory hit."""
        if not self._causal_memory_enabled():
            return None
        if state_store is None or event.reading is None:
            return None
        if not getattr(rule_result, "matched", False):
            return None
        trigger_name = str(getattr(rule_result, "rule_name", "") or "")
        if not trigger_name:
            return None
        if not hasattr(state_store, "lookup_causal_memory"):
            return None

        try:
            pattern_key = CausalMemory.generate_key(event, trigger_name)
            cache = CausalMemory(state_store)
            cached = await cache.lookup(pattern_key)
            if isinstance(cached, str) and cached.strip():
                return pattern_key, cached.strip()
        except Exception:
            logger.exception(
                "IntelligenceElevator: causal-memory lookup failed for trigger=%r",
                trigger_name,
            )
        return None

    async def _store_causal_resolution(
        self,
        state_store: Any,
        pattern_key: str | None,
        text: str,
        confidence: float,
    ) -> None:
        if not self._causal_memory_enabled():
            return
        if state_store is None:
            return
        if not pattern_key:
            return
        if not hasattr(state_store, "store_causal_memory"):
            return
        if not text.strip():
            return
        if confidence < self._causal_memory_min_confidence():
            return
        try:
            cache = CausalMemory(state_store)
            await cache.store(pattern_key, text.strip(), confidence)
        except Exception:
            logger.exception("IntelligenceElevator: causal-memory store failed")

    @staticmethod
    def _tier_rank(tier: str) -> int:
        return {"A": 1, "B": 2, "C": 3, "D": 4}.get(str(tier).upper(), 0)

    @staticmethod
    def _resolve_default_action_for_trigger(
        skill: Any, trigger_name: str
    ) -> str | None:
        actions: list[str] = []
        if hasattr(skill, "get_default_actions_for_trigger"):
            maybe = skill.get_default_actions_for_trigger(trigger_name)
            if isinstance(maybe, list):
                actions = [a for a in maybe if isinstance(a, str) and a]
        elif hasattr(skill, "actions") and isinstance(skill.actions, dict):
            defaults = skill.actions.get("defaults") or {}
            if isinstance(defaults, dict):
                maybe = defaults.get(trigger_name, [])
                if isinstance(maybe, list):
                    actions = [a for a in maybe if isinstance(a, str) and a]
        return actions[0] if actions else None

    async def _lookup_rejection_record(
        self,
        event: OriEvent,
        skill: Any,
        rule_result: Any,
        state_store: Any,
    ) -> dict[str, Any] | None:
        """Lookup a previously rejected pattern for the matched trigger/action."""
        cfg = self._causal_memory_cfg()
        expiry_days = int(cfg.get("rejection_expiry_days", 0))
        if expiry_days == 0 and not cfg:
            return None
        if state_store is None:
            return None
        if not hasattr(type(state_store), "lookup_rejection") or not hasattr(
            type(state_store), "_build_rejection_pattern_key"
        ):
            return None
        if not getattr(rule_result, "matched", False):
            return None
        if event.reading is None:
            return None

        trigger_name = str(getattr(rule_result, "rule_name", "") or "")
        if not trigger_name:
            return None

        proposed_action = str(getattr(rule_result, "action", "") or "")
        if not proposed_action:
            proposed_action = (
                self._resolve_default_action_for_trigger(skill, trigger_name) or ""
            )
        if not proposed_action:
            return None

        try:
            pattern_key = state_store._build_rejection_pattern_key(
                event.reading.sensor_type,
                trigger_name,
                proposed_action,
                float(event.reading.value),
                int(event.timestamp),
            )
            record = await state_store.lookup_rejection(pattern_key)
            if isinstance(record, dict):
                return record
        except Exception:
            logger.exception(
                "IntelligenceElevator: rejection lookup failed for trigger=%r action=%r",
                trigger_name,
                proposed_action,
            )
        return None

    def _filter_actions_by_max_tier(
        self,
        skill: Any,
        actions: list[str],
        max_tier: str,
    ) -> list[str]:
        available = []
        if hasattr(skill, "actions") and isinstance(skill.actions, dict):
            available = skill.actions.get("available") or []
        if not isinstance(available, list):
            return []

        tiers_by_action: dict[str, str] = {}
        for entry in available:
            if isinstance(entry, dict):
                name = entry.get("name")
                tier = str(entry.get("tier", "A")).upper()
                if isinstance(name, str) and name:
                    tiers_by_action[name] = tier
            elif isinstance(entry, str):
                tiers_by_action[entry] = "A"

        max_rank = self._tier_rank(max_tier)
        filtered: list[str] = []
        for action_name in actions:
            tier = tiers_by_action.get(action_name)
            if tier is None:
                continue
            if self._tier_rank(tier) <= max_rank:
                filtered.append(action_name)
        return filtered

    @staticmethod
    def _matched_trigger(skill: Any, rule_result: Any) -> Any | None:
        if not getattr(rule_result, "matched", False):
            return None
        rule_name = str(getattr(rule_result, "rule_name", "") or "")
        if not rule_name:
            return None
        for trigger in getattr(skill, "triggers", []):
            trigger_name = (
                trigger.get("name")
                if isinstance(trigger, dict)
                else getattr(trigger, "name", None)
            )
            if trigger_name == rule_name:
                return trigger
        return None

    @staticmethod
    def _trigger_value(trigger: Any, key: str, default: Any = None) -> Any:
        if trigger is None:
            return default
        if isinstance(trigger, dict):
            return trigger.get(key, default)
        return getattr(trigger, key, default)

    def _actions_for_rule_result(
        self,
        *,
        skill: Any,
        result: ReasoningResult,
        rule_result: Any,
    ) -> list[str]:
        actions: list[str] = []
        if getattr(rule_result, "matched", False) and getattr(
            rule_result, "rule_name", None
        ):
            if hasattr(skill, "get_default_actions_for_trigger"):
                actions = skill.get_default_actions_for_trigger(rule_result.rule_name)
            elif hasattr(skill, "actions") and isinstance(skill.actions, dict):
                defaults = skill.actions.get("defaults") or {}
                if isinstance(defaults, dict):
                    maybe_actions = defaults.get(rule_result.rule_name, [])
                    if isinstance(maybe_actions, list):
                        actions = maybe_actions
        elif result.proposed_action:
            proposed = result.proposed_action
            if hasattr(skill, "is_action_declared"):
                if skill.is_action_declared(proposed):
                    actions = [proposed]
            elif (
                hasattr(skill, "actions")
                and isinstance(skill.actions, dict)
                and isinstance(skill.actions.get("available"), list)
            ):
                available = skill.actions.get("available") or []
                for entry in available:
                    if isinstance(entry, dict) and entry.get("name") == proposed:
                        actions = [proposed]
                        break
        return [action for action in actions if isinstance(action, str) and action]

    @staticmethod
    def _action_tiers(skill: Any) -> dict[str, str]:
        available = []
        if hasattr(skill, "actions") and isinstance(skill.actions, dict):
            available = skill.actions.get("available") or []
        tiers: dict[str, str] = {}
        for entry in available if isinstance(available, list) else []:
            if isinstance(entry, dict):
                name = entry.get("name")
                tier = str(entry.get("tier", "A")).upper()
                if isinstance(name, str) and name:
                    tiers[name] = tier
            elif isinstance(entry, str):
                tiers[entry] = "A"
        return tiers

    def _tier_b_first(self, skill: Any, actions: list[str]) -> list[str]:
        tiers = self._action_tiers(skill)
        return sorted(actions, key=lambda action: 0 if tiers.get(action) == "B" else 1)

    def _tier_a_actions(self, skill: Any, actions: list[str]) -> list[str]:
        tiers = self._action_tiers(skill)
        return [action for action in actions if tiers.get(action, "A") == "A"]

    @staticmethod
    def _ensure_correlation_id(event: OriEvent) -> str:
        if not isinstance(getattr(event, "context", None), dict):
            event.context = {}
        existing = str(event.context.get("correlation_id") or "").strip()
        if existing:
            return existing
        correlation_id = f"corr-{uuid.uuid4().hex}"
        event.context["correlation_id"] = correlation_id
        return correlation_id

    def _approval_timeout_seconds(self, skill: Any, rule_result: Any) -> int:
        matched_trigger = self._matched_trigger(skill, rule_result)
        raw_timeout = self._trigger_value(
            matched_trigger, "approval_timeout_seconds", 300
        )
        try:
            return int(raw_timeout)
        except (TypeError, ValueError):
            return 300

    @staticmethod
    def _clamp_result_to_rule(
        *,
        result: ReasoningResult,
        rule_result: Any,
        rejection_capped: bool,
    ) -> None:
        if not (
            getattr(rule_result, "matched", False)
            and rule_result.action_tier in {"A", "B", "C", "D"}
        ):
            return
        allow_rejection_downgrade = (
            rejection_capped
            and result.action_tier == "A"
            and rule_result.action_tier != "D"
        )
        if result.action_tier == rule_result.action_tier or allow_rejection_downgrade:
            return
        logger.warning(
            "IntelligenceElevator: clamping action tier from %s to %s for trigger=%r",
            result.action_tier,
            rule_result.action_tier,
            rule_result.rule_name,
        )
        result.action_tier = rule_result.action_tier

    async def _run_post_reasoning_hook(
        self,
        *,
        result: ReasoningResult,
        event: OriEvent,
        skill: Any,
        state_store: Any,
        rule_result: Any,
    ) -> None:
        if not (hasattr(skill, "hooks") and hasattr(skill.hooks, "post_reasoning")):
            return
        from ori.skills.hooks_api import HookContext

        pt_ctx = HookContext.build(
            event,
            state_store,
            getattr(skill, "name", "unknown"),
            skill_config=getattr(skill, "config", None),
        )
        pt_ctx.trigger_name = rule_result.rule_name if rule_result.matched else ""

        try:
            maybe = skill.hooks.post_reasoning(result, pt_ctx)
            if asyncio.iscoroutine(maybe):
                await maybe
        except Exception:
            logger.exception(
                "IntelligenceElevator: post_reasoning hook failed for %r",
                getattr(skill, "name", "unknown"),
            )

    async def _handle_tier_b_post_action(
        self,
        *,
        event: OriEvent,
        skill: Any,
        state_store: Any,
        dispatcher: Any,
        rule_result: Any,
    ) -> None:
        """Execute Tier B action first, then enrich audit/operator text."""
        correlation_id = self._ensure_correlation_id(event)
        immediate_result = ReasoningResult(
            text="Action executed. Explanation pending.",
            tier="rule",
            model="post_action",
            tokens_used=0,
            latency_ms=0,
            confidence=float(getattr(rule_result, "confidence", 1.0) or 1.0),
            action_tier="B",
            proposed_action=getattr(rule_result, "action", None),
            reasoning_status="pending",
            correlation_id=correlation_id,
        )
        actions = self._actions_for_rule_result(
            skill=skill, result=immediate_result, rule_result=rule_result
        )
        actions = self._tier_b_first(skill, actions)

        await self._attach_decision_history_window(event, state_store)
        context = SkillContext(
            skill=skill,
            event=event,
            state_store=state_store,
            trigger_name=rule_result.rule_name if rule_result.matched else "",
        )
        if isinstance(getattr(event, "context", None), dict):
            event.context["operator_message"] = immediate_result.text

        approval_timeout_seconds = self._approval_timeout_seconds(skill, rule_result)
        action_tiers = self._action_tiers(skill)
        tier_b_actions = [
            action for action in actions if action_tiers.get(action) == "B"
        ]
        physical_failed = False
        for action in tier_b_actions:
            try:
                action_result = await dispatcher.dispatch(
                    action=action,
                    tier=action_tiers.get(action, "B"),
                    context=context,
                    result=immediate_result,
                    approval_timeout=approval_timeout_seconds,
                )
            except Exception:
                physical_failed = True
                logger.exception(
                    "IntelligenceElevator: Tier B post-action dispatch failed for "
                    "action=%r trigger=%r",
                    action,
                    getattr(rule_result, "rule_name", ""),
                )
                break
            if action_tiers.get(action) == "B" and not bool(
                getattr(action_result, "executed", True)
            ):
                physical_failed = True
                break

        if physical_failed:
            skipped = self._post_action_skipped_result(rule_result, event)
            skipped.correlation_id = correlation_id
            if isinstance(getattr(event, "context", None), dict):
                event.context["operator_message"] = str(skipped.text or "")
            tier_a_actions = self._tier_a_actions(skill, actions)
            for action in tier_a_actions:
                await dispatcher.dispatch(
                    action=action,
                    tier="A",
                    context=context,
                    result=skipped,
                    approval_timeout=approval_timeout_seconds,
                )
            if state_store is not None and hasattr(state_store, "log_reasoning"):
                await state_store.log_reasoning(
                    result=skipped,
                    trigger_name=event.sensor_id,
                    device_id=event.device_id,
                )
            return

        enrichment = await self._post_action_enrichment_result(
            event=event,
            skill=skill,
            state_store=state_store,
            rule_result=rule_result,
        )
        enrichment.correlation_id = correlation_id
        if isinstance(getattr(event, "context", None), dict):
            event.context["operator_message"] = str(enrichment.text or "")

        await self._run_post_reasoning_hook(
            result=enrichment,
            event=event,
            skill=skill,
            state_store=state_store,
            rule_result=rule_result,
        )

        tier_a_actions = self._tier_a_actions(skill, actions)
        for action in tier_a_actions:
            await dispatcher.dispatch(
                action=action,
                tier="A",
                context=context,
                result=enrichment,
                approval_timeout=approval_timeout_seconds,
            )

        if state_store is not None and hasattr(state_store, "log_reasoning"):
            await state_store.log_reasoning(
                result=enrichment,
                trigger_name=event.sensor_id,
                device_id=event.device_id,
            )

    async def _post_action_enrichment_result(
        self,
        *,
        event: OriEvent,
        skill: Any,
        state_store: Any,
        rule_result: Any,
    ) -> ReasoningResult:
        try:
            result, _ = await self._reason_with_rule_result(
                event=event,
                skill=skill,
                state_store=state_store,
                precomputed_rule_result=rule_result,
            )
            if result.model == "stub":
                incomplete = self._post_action_incomplete_result(rule_result, event)
                incomplete.correlation_id = self._ensure_correlation_id(event)
                return incomplete
            self._clamp_result_to_rule(
                result=result,
                rule_result=rule_result,
                rejection_capped=False,
            )
            result.reasoning_status = "complete"
            result.correlation_id = self._ensure_correlation_id(event)
            result.proposed_action = result.proposed_action or getattr(
                rule_result, "action", None
            )
            return result
        except Exception:
            logger.exception(
                "IntelligenceElevator: post-action reasoning failed for trigger=%r",
                getattr(rule_result, "rule_name", ""),
            )
            incomplete = self._post_action_incomplete_result(rule_result, event)
            incomplete.correlation_id = self._ensure_correlation_id(event)
            return incomplete

    @staticmethod
    def _post_action_incomplete_result(
        rule_result: Any, event: OriEvent
    ) -> ReasoningResult:
        return ReasoningResult(
            text="Action executed. Explanation unavailable.",
            tier="post_action",
            model="post_action_fallback",
            tokens_used=0,
            latency_ms=0,
            confidence=0.0,
            action_tier=str(getattr(rule_result, "action_tier", "B") or "B"),
            proposed_action=getattr(rule_result, "action", None),
            reasoning_status="incomplete",
        )

    @staticmethod
    def _post_action_skipped_result(
        rule_result: Any, event: OriEvent
    ) -> ReasoningResult:
        return ReasoningResult(
            text="Action failed. Explanation skipped.",
            tier="post_action",
            model="post_action_skipped",
            tokens_used=0,
            latency_ms=0,
            confidence=0.0,
            action_tier=str(getattr(rule_result, "action_tier", "B") or "B"),
            proposed_action=getattr(rule_result, "action", None),
            reasoning_status="skipped",
        )

    async def reason_and_dispatch(
        self,
        event: OriEvent,
        skill: Any,
        state_store: Any,
        dispatcher: Any,
    ) -> None:
        """Full reasoning + action pipeline.

        This is the coroutine that ``asyncio.create_task()`` wraps at the
        EventBus handler boundary.  All exceptions are caught — a reasoning
        failure must never crash the runtime or go unlogged.

        1. Run :meth:`reason` to get a :class:`~ori.network.events.ReasoningResult`.
        2. Look up the default actions for the event's sensor type from the skill.
        3. Dispatch each action through the :class:`~ori.reasoning.action_dispatcher.ActionDispatcher`.
        4. Log the reasoning result to the ``reasoning_log`` table.

        Args:
            event: The triggering event.
            skill: The matched :class:`~ori.skills.loader.Skill`.
            state_store: :class:`~ori.state.store.StateStore` for logging and history.
            dispatcher: :class:`~ori.reasoning.action_dispatcher.ActionDispatcher`.
        """
        try:
            handler_trigger_name = ""
            if isinstance(getattr(event, "context", None), dict):
                handler_trigger_name = str(
                    event.context.get("__handler_trigger_name") or ""
                )
            correlation_id = self._ensure_correlation_id(event)

            pre_rule_result, _ = await self._evaluate_rules_with_hooks(
                event, skill, state_store
            )
            if handler_trigger_name:
                if not pre_rule_result.matched:
                    return
                if pre_rule_result.rule_name != handler_trigger_name:
                    return

            if (
                pre_rule_result.matched
                and pre_rule_result.action_tier == "B"
                and getattr(pre_rule_result, "reasoning_policy", "") == "post_action"
            ):
                await self._handle_tier_b_post_action(
                    event=event,
                    skill=skill,
                    state_store=state_store,
                    dispatcher=dispatcher,
                    rule_result=pre_rule_result,
                )
                return

            result, rule_res = await self._reason_with_rule_result(
                event=event,
                skill=skill,
                state_store=state_store,
                precomputed_rule_result=pre_rule_result,
            )
            result.correlation_id = correlation_id

            # Clamp any model-produced tier to the matched trigger's declared tier.
            # Trigger tier is the authority; model output must not escalate or
            # downgrade physical actuation boundaries.
            rejection_capped = bool(
                isinstance(getattr(event, "context", None), dict)
                and event.context.get("__rejection_cap_tier_a")
            )
            if rule_res.matched and rule_res.action_tier in {"A", "B", "C", "D"}:
                allow_rejection_downgrade = (
                    rejection_capped
                    and result.action_tier == "A"
                    and rule_res.action_tier != "D"
                )
                if (
                    result.action_tier != rule_res.action_tier
                    and not allow_rejection_downgrade
                ):
                    logger.warning(
                        "IntelligenceElevator: clamping action tier from %s to %s "
                        "for trigger=%r",
                        result.action_tier,
                        rule_res.action_tier,
                        rule_res.rule_name,
                    )
                    result.action_tier = rule_res.action_tier

            if hasattr(skill, "hooks") and hasattr(skill.hooks, "post_reasoning"):
                from ori.skills.hooks_api import HookContext

                pt_ctx = HookContext.build(
                    event,
                    state_store,
                    getattr(skill, "name", "unknown"),
                    skill_config=getattr(skill, "config", None),
                )
                pt_ctx.trigger_name = rule_res.rule_name if rule_res.matched else ""

                try:
                    maybe = skill.hooks.post_reasoning(result, pt_ctx)
                    if asyncio.iscoroutine(maybe):
                        await maybe
                except Exception:
                    logger.exception(
                        "IntelligenceElevator: post_reasoning hook failed for %r",
                        getattr(skill, "name", "unknown"),
                    )

            # Expose composed operator text to dispatch executors so channel
            # formatting can happen without re-running skill hooks.
            if isinstance(getattr(event, "context", None), dict):
                event.context["operator_message"] = str(
                    getattr(result, "text", "") or ""
                )

            actions: list[str] = []
            if rule_res.matched and rule_res.rule_name:
                if hasattr(skill, "get_default_actions_for_trigger"):
                    actions = skill.get_default_actions_for_trigger(rule_res.rule_name)
                elif hasattr(skill, "actions") and isinstance(skill.actions, dict):
                    defaults = skill.actions.get("defaults") or {}
                    if isinstance(defaults, dict):
                        maybe_actions = defaults.get(rule_res.rule_name, [])
                        if isinstance(maybe_actions, list):
                            actions = maybe_actions
            elif result.proposed_action:
                proposed = result.proposed_action
                if hasattr(skill, "is_action_declared"):
                    if skill.is_action_declared(proposed):
                        actions = [proposed]
                elif (
                    hasattr(skill, "actions")
                    and isinstance(skill.actions, dict)
                    and isinstance(skill.actions.get("available"), list)
                ):
                    available = skill.actions.get("available") or []
                    for entry in available:
                        if isinstance(entry, dict) and entry.get("name") == proposed:
                            actions = [proposed]
                            break

            if rejection_capped and actions:
                actions = self._filter_actions_by_max_tier(skill, actions, max_tier="A")
                if not actions:
                    logger.warning(
                        "IntelligenceElevator: rejection cap active but no Tier A "
                        "actions declared for trigger=%r — falling back to log_to_dashboard",
                        rule_res.rule_name,
                    )
                    actions = ["log_to_dashboard"]

            await self._attach_decision_history_window(event, state_store)
            context = SkillContext(
                skill=skill,
                event=event,
                state_store=state_store,
                trigger_name=rule_res.rule_name if rule_res.matched else "",
            )
            approval_timeout_seconds = 300
            if rule_res.matched and rule_res.rule_name:
                matched_trigger = None
                for trigger in getattr(skill, "triggers", []):
                    trigger_name = (
                        trigger.get("name")
                        if isinstance(trigger, dict)
                        else getattr(trigger, "name", None)
                    )
                    if trigger_name == rule_res.rule_name:
                        matched_trigger = trigger
                        break
                if matched_trigger is not None:
                    raw_timeout = (
                        matched_trigger.get("approval_timeout_seconds", 300)
                        if isinstance(matched_trigger, dict)
                        else getattr(matched_trigger, "approval_timeout_seconds", 300)
                    )
                    try:
                        approval_timeout_seconds = int(raw_timeout)
                    except (TypeError, ValueError):
                        approval_timeout_seconds = 300
            for action in actions:
                await dispatcher.dispatch(
                    action=action,
                    tier=result.action_tier,
                    context=context,
                    result=result,
                    approval_timeout=approval_timeout_seconds,
                )

            # Persist reasoning result
            if state_store is not None and hasattr(state_store, "log_reasoning"):
                result.correlation_id = correlation_id
                await state_store.log_reasoning(
                    result=result,
                    trigger_name=event.sensor_id,
                    device_id=event.device_id,
                )

        except RuleEngineSafetyError as exc:
            logger.error(
                "IntelligenceElevator: Safety check blocked reasoning: %s", exc
            )

            text = (
                f"Sensor safety check failed: {exc}. "
                f"Tier D protection for this sensor is suspended until "
                f"the sensor returns valid readings."
            )

            result = ReasoningResult(
                text=text,
                tier="rule",
                model="safety_fallback",
                tokens_used=0,
                latency_ms=0,
                confidence=1.0,
                action_tier="A",
            )

            synthetic_event = OriEvent(
                event_type="sensor.invalid_value",
                event_id=f"syn-{event.event_id}",
                device_id=event.device_id,
                sensor_id=event.sensor_id,
                timestamp=now_ms(),
                reading=event.reading,
            )
            synthetic_event.context["operator_message"] = str(result.text)

            actions = []
            if hasattr(skill, "get_default_actions"):
                actions = skill.get_default_actions("sensor.invalid_value")

            if not actions:
                actions = ["alert_whatsapp"]
                # Dispatch alert_sms if configured
                available_actions = []
                if hasattr(skill, "actions") and isinstance(skill.actions, dict):
                    available_acts = skill.actions.get("available", [])
                    for a in available_acts:
                        if isinstance(a, dict):
                            available_actions.append(a.get("name"))
                        elif isinstance(a, str):
                            available_actions.append(a)
                if "alert_sms" in available_actions:
                    actions.append("alert_sms")

            context = SkillContext(
                skill=skill,
                event=synthetic_event,
                state_store=state_store,
                trigger_name="sensor.invalid_value",
            )
            for action in actions:
                await dispatcher.dispatch(
                    action=action,
                    tier=result.action_tier,
                    context=context,
                    result=result,
                )

        except Exception:
            skill_name = getattr(skill, "name", "<unknown>")
            logger.exception(
                "IntelligenceElevator: reasoning pipeline failed for "
                "skill=%s trigger=%s",
                skill_name,
                event.sensor_id,
            )

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _attach_decision_history_window(
        self,
        event: OriEvent,
        state_store: Any,
    ) -> None:
        """Attach recent readings for downstream Tier C decision logging."""
        if event is None or event.reading is None:
            return
        if not isinstance(getattr(event, "context", None), dict):
            event.context = {}
        if event.context.get("history_window") is not None:
            return
        if state_store is None or not hasattr(state_store, "get_history"):
            event.context["history_window"] = []
            return
        try:
            readings = await state_store.get_history(
                event.reading.sensor_id,
                limit=_DECISION_HISTORY_WINDOW_LIMIT,
            )
        except Exception:
            logger.debug(
                "IntelligenceElevator: could not attach decision history for %s",
                event.reading.sensor_id,
                exc_info=True,
            )
            event.context["history_window"] = []
            return

        history_window: list[dict[str, Any]] = []
        for reading in readings:
            history_window.append(
                {
                    "sensor_id": getattr(reading, "sensor_id", ""),
                    "sensor_type": getattr(reading, "sensor_type", ""),
                    "value": getattr(reading, "value", None),
                    "unit": getattr(reading, "unit", ""),
                    "timestamp": getattr(reading, "timestamp", None),
                    "quality": getattr(reading, "quality", None),
                }
            )
        event.context["history_window"] = history_window

    async def _build_prompt(
        self,
        event: OriEvent,
        skill: Any,
        state_store: Any,
        trigger_name: str | None = None,
        rejection_note: str | None = None,
    ) -> str:
        """Build a plain-text prompt from the event and skill metadata."""
        lines: list[str] = []
        if event.reading:
            r = event.reading
            sensor_id = self._sanitize_prompt_input(
                r.sensor_id
            )  # sanitised — AGENTS.md Rule 4.
            sensor_type = self._sanitize_prompt_input(
                r.sensor_type
            )  # sanitised — AGENTS.md Rule 4.
            value = self._sanitize_prompt_input(
                str(r.value)
            )  # sanitised — AGENTS.md Rule 4.
            unit = self._sanitize_prompt_input(r.unit)  # sanitised — AGENTS.md Rule 4.
            quality = self._sanitize_prompt_input(
                str(r.quality)
            )  # sanitised — AGENTS.md Rule 4.
            lines.append(f"Sensor: {sensor_id} ({sensor_type})")
            lines.append(f"Current value: {value} {unit}")
            lines.append(f"Quality: {quality}")
        device_id = self._sanitize_prompt_input(
            event.device_id
        )  # sanitised — AGENTS.md Rule 4.
        lines.append(f"Device: {device_id}")
        prompt_template: str | None = None
        if hasattr(skill, "prompts") and isinstance(skill.prompts, dict):
            if trigger_name:
                prompt_template = skill.prompts.get(trigger_name)
            if prompt_template is None:
                prompt_template = skill.prompts.get(
                    event.reading.sensor_type if event.reading else ""
                )
        if prompt_template:
            prompt_text = str(prompt_template)
            if event.reading is not None:
                reading = event.reading
                formatted_time = datetime.datetime.fromtimestamp(
                    reading.timestamp / 1000,
                    tz=datetime.timezone.utc,
                ).strftime("%Y-%m-%d %H:%M:%S UTC")
                substitutions = {
                    "{value}": self._sanitize_prompt_input(
                        str(reading.value)
                    ),  # sanitised — AGENTS.md Rule 4.
                    "{unit}": self._sanitize_prompt_input(
                        reading.unit
                    ),  # sanitised — AGENTS.md Rule 4.
                    "{sensor_id}": self._sanitize_prompt_input(
                        reading.sensor_id
                    ),  # sanitised — AGENTS.md Rule 4.
                    "{sensor_type}": self._sanitize_prompt_input(
                        reading.sensor_type
                    ),  # sanitised — AGENTS.md Rule 4.
                    "{device_id}": self._sanitize_prompt_input(
                        event.device_id
                    ),  # sanitised — AGENTS.md Rule 4.
                    "{time}": self._sanitize_prompt_input(
                        formatted_time
                    ),  # sanitised — AGENTS.md Rule 4.
                    "{quality}": self._sanitize_prompt_input(
                        str(round(reading.quality, 2))
                    ),  # sanitised — AGENTS.md Rule 4.
                }
                for key, val in substitutions.items():
                    prompt_text = prompt_text.replace(key, val)
                prompt_text = await self._interpolate_history_placeholders(
                    prompt_text=prompt_text,
                    event=event,
                    state_store=state_store,
                )
            lines.append(prompt_text)
        else:
            lines.append("Is this reading anomalous? What is the most likely cause?")
            lines.append("Answer in plain English, 2-3 sentences, no jargon.")
        if rejection_note:
            lines.append("")
            lines.append(rejection_note)
        prompt = "\n".join(lines)
        if self._context_enricher is not None:
            prompt = await self._context_enricher.enrich(prompt, event, state_store)
        return prompt

    async def _interpolate_history_placeholders(
        self,
        *,
        prompt_text: str,
        event: OriEvent,
        state_store: Any,
    ) -> str:
        matches = list(_HISTORY_PLACEHOLDER_PATTERN.finditer(prompt_text))
        if not matches:
            return prompt_text
        unique_tokens = list(dict.fromkeys(match.group(0) for match in matches))
        if state_store is None:
            logger.warning(
                "Prompt template contains history placeholders but no state_store is available for sensor_id=%s. "
                "Using sentinel value %r.",
                event.sensor_id,
                _UNRESOLVED_HISTORY_PLACEHOLDER_SENTINEL,
            )
            for token in unique_tokens:
                prompt_text = prompt_text.replace(
                    token, _UNRESOLVED_HISTORY_PLACEHOLDER_SENTINEL
                )
            return prompt_text

        replacements: dict[str, str] = {}
        for index, token in enumerate(unique_tokens):
            if index >= _MAX_HISTORY_PLACEHOLDERS:
                replacements[token] = _UNRESOLVED_HISTORY_PLACEHOLDER_SENTINEL
                continue
            expr = token[1:-1]
            replacement = await self._resolve_history_expression(
                expression=expr,
                event=event,
                state_store=state_store,
            )
            replacements[token] = (
                replacement
                if replacement is not None
                else _UNRESOLVED_HISTORY_PLACEHOLDER_SENTINEL
            )

        if len(unique_tokens) > _MAX_HISTORY_PLACEHOLDERS:
            logger.warning(
                "Prompt template contained %d unique history placeholders; max is %d. "
                "Remaining placeholders were replaced with sentinel value %r for sensor_id=%s.",
                len(unique_tokens),
                _MAX_HISTORY_PLACEHOLDERS,
                _UNRESOLVED_HISTORY_PLACEHOLDER_SENTINEL,
                event.sensor_id,
            )

        for token, replacement in replacements.items():
            prompt_text = prompt_text.replace(token, replacement)
        return prompt_text

    async def _resolve_history_expression(
        self,
        *,
        expression: str,
        event: OriEvent,
        state_store: Any,
    ) -> str | None:
        from ori.skills.hooks_api import HookHistoryAdapter

        parsed = self._parse_history_expression(expression)
        if parsed is None:
            logger.warning(
                "Unsupported history placeholder syntax for sensor_id=%s: %s",
                event.sensor_id,
                expression,
            )
            return None

        event_context = event.context if isinstance(event.context, dict) else {}
        adapter = HookHistoryAdapter(
            state_store,
            reference_timestamp_ms=event.timestamp,
            timezone=str(event_context.get("device_timezone") or "UTC"),
        )
        try:
            raw = await asyncio.to_thread(
                self._execute_history_call_sync,
                adapter,
                parsed,
                event,
            )
        except Exception:
            logger.warning(
                "Failed to resolve history placeholder for sensor_id=%s: %s",
                event.sensor_id,
                expression,
                exc_info=True,
            )
            return None
        return self._format_history_placeholder_value(raw)

    def _parse_history_expression(self, expression: str) -> _ParsedHistoryCall | None:
        try:
            node = ast.parse(expression, mode="eval")
        except SyntaxError:
            return None
        if not isinstance(node, ast.Expression) or not isinstance(node.body, ast.Call):
            return None
        call = node.body
        if call.keywords:
            return None
        if not isinstance(call.func, ast.Attribute):
            return None
        root = call.func.value
        if not isinstance(root, ast.Name) or root.id != "history":
            return None

        args: list[Any] = []
        for arg in call.args:
            if isinstance(arg, ast.Constant):
                args.append(arg.value)
                continue
            if (
                isinstance(arg, ast.UnaryOp)
                and isinstance(arg.op, ast.USub)
                and isinstance(arg.operand, ast.Constant)
                and isinstance(arg.operand.value, (int, float))
            ):
                args.append(-arg.operand.value)
                continue
            return None
        return _ParsedHistoryCall(method=str(call.func.attr), args=tuple(args))

    def _execute_history_call_sync(
        self,
        adapter: Any,
        parsed: _ParsedHistoryCall,
        event: OriEvent,
    ) -> Any:
        method = parsed.method
        args = parsed.args
        if method == "last_n":
            sensor_id, n = self._parse_sensor_and_int_arg_pair(
                args,
                default_sensor_id=event.sensor_id,
                default_n=6,
            )
            rows = adapter.fetch_history(sensor_id, limit=n)
            return [row.get("value") for row in rows]
        if method == "avg_hours":
            sensor_id, hours = self._parse_sensor_and_int_arg_pair(
                args,
                default_sensor_id=event.sensor_id,
                default_n=24,
            )
            return adapter.avg_hours(sensor_id, hours)
        if method == "avg_last_n":
            sensor_id, n = self._parse_sensor_and_int_arg_pair(
                args,
                default_sensor_id=event.sensor_id,
                default_n=6,
            )
            return adapter.avg_last_n(sensor_id, n)
        if method == "last_value":
            sensor_id = self._parse_sensor_single_arg(args, event.sensor_id)
            return adapter.last_value(sensor_id)
        if method == "last_timestamp":
            sensor_id = self._parse_sensor_single_arg(args, event.sensor_id)
            return adapter.last_timestamp(sensor_id)
        if method == "fetch_history":
            sensor_id, limit = self._parse_sensor_and_int_arg_pair(
                args,
                default_sensor_id=event.sensor_id,
                default_n=1,
            )
            rows = adapter.fetch_history(sensor_id, limit=limit)
            compact: list[dict[str, Any]] = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                compact.append(
                    {
                        "value": row.get("value"),
                        "timestamp": row.get("timestamp"),
                    }
                )
            return compact
        raise ValueError(f"unsupported history method: {method}")

    def _parse_sensor_single_arg(
        self,
        args: tuple[Any, ...],
        default_sensor_id: str,
    ) -> str:
        if len(args) == 0:
            return str(default_sensor_id)
        if len(args) != 1 or not isinstance(args[0], str):
            raise ValueError("expected a single string sensor_id argument")
        return str(args[0])[:128]

    def _parse_sensor_and_int_arg_pair(
        self,
        args: tuple[Any, ...],
        *,
        default_sensor_id: str,
        default_n: int,
    ) -> tuple[str, int]:
        if len(args) == 0:
            return str(default_sensor_id), int(default_n)
        if len(args) == 1:
            if not isinstance(args[0], str):
                raise ValueError("first argument must be sensor_id string")
            return str(args[0])[:128], int(default_n)
        if len(args) != 2:
            raise ValueError("expected one or two arguments")
        sensor_raw, n_raw = args
        if not isinstance(sensor_raw, str) or not isinstance(n_raw, (int, float)):
            raise ValueError("expected (sensor_id: str, count: int)")
        n = max(1, min(int(n_raw), 100))
        return str(sensor_raw)[:128], n

    def _format_history_placeholder_value(self, raw: Any) -> str:
        if raw is None:
            return "null"
        if isinstance(raw, bool):
            return "true" if raw else "false"
        if isinstance(raw, (int, float)):
            return str(raw)
        if isinstance(raw, list):
            normalized: list[Any] = []
            for item in raw[:50]:
                if isinstance(item, (int, float)):
                    normalized.append(item)
                elif isinstance(item, dict):
                    normalized.append(
                        {
                            "value": item.get("value"),
                            "timestamp": item.get("timestamp"),
                        }
                    )
                else:
                    normalized.append(str(item))
            text = json.dumps(normalized, separators=(",", ":"))
            return text[:400]
        if isinstance(raw, dict):
            text = json.dumps(raw, separators=(",", ":"))
            return text[:400]
        return str(raw)[:200]

    def _sanitize_prompt_input(self, text: str, is_reply: bool = False) -> str:
        """Sanitize untrusted values before interpolation into prompt text."""
        import re

        if not isinstance(text, str):
            text = str(text)
        if is_reply:
            text = re.sub(r"[<>{}\[\]\\$`]", "", text)
            return text[:500].strip()
        text = re.sub(r"[^\w\s\-\./°%]", "", text)
        return text[:200].strip()

    @staticmethod
    def _stub_result(tier: str, event: OriEvent) -> ReasoningResult:
        """Return a safe stub result when a tier is unavailable."""
        return ReasoningResult(
            text=f"[{tier} unavailable] No reasoning performed for {event.sensor_id}.",
            tier=tier,
            model="stub",
            tokens_used=0,
            latency_ms=0,
            confidence=0.0,
            action_tier="A",
        )
