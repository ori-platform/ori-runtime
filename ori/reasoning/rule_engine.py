# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import ast
import logging
import math
from dataclasses import dataclass
from typing import Any

from ori.network.events import OriEvent
from ori.time_utils import now_ms

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AST-based condition safety validation (Phase 2 upgrade)
# ---------------------------------------------------------------------------
# The ONLY object whose attributes may be accessed inside a condition.
_ALLOWED_ATTRIBUTE_ROOTS = frozenset({"history"})
_ALLOWED_HISTORY_METHODS = frozenset({"avg_24h", "last_n"})
_MAX_LAST_N = 1000

# AST node types that are unconditionally safe in condition expressions.
_SAFE_NODE_TYPES: frozenset[type] = frozenset(
    {
        # Structure
        ast.Expression,
        ast.Load,
        # Values
        ast.Name,
        ast.Constant,
        # Comparisons
        ast.Compare,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.Is,
        ast.IsNot,
        ast.In,
        ast.NotIn,
        # Boolean logic
        ast.BoolOp,
        ast.And,
        ast.Or,
        # Arithmetic
        ast.BinOp,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.FloorDiv,
        ast.Mod,
        ast.Pow,
        # Unary
        ast.UnaryOp,
        ast.Not,
        ast.UAdd,
        ast.USub,
    }
)


class RuleEngineSafetyError(Exception):
    """Raised when a rule condition contains a forbidden pattern."""


@dataclass
class RuleResult:
    """Outcome of a single :meth:`RuleEngine.evaluate` call."""

    matched: bool
    action_tier: str  # 'A' | 'B' | 'C' | 'D'
    rule_name: str | None = None
    escalate_to: str | None = None  # 'rule' | 'local_slm' | 'gateway'
    bypass_llm: bool = False
    reasoning_policy: str | None = None  # e.g. 'post_action' for Tier B triggers
    requires_approval: bool = False
    action: str | None = None
    confidence: float = 1.0


@dataclass
class _CooldownRecord:
    last_fired_ms: int


class EvalContext:
    """Thin wrapper that exposes sensor history helpers inside rule expressions.

    Passes through a simple ``context`` dict as the primary evaluation
    namespace.  The ``history`` attribute is available as ``history`` inside
    expressions.
    """

    def __init__(
        self, values: dict[str, Any], history_cache: dict[tuple, Any] | None = None
    ) -> None:
        self._values = values
        self._cache = history_cache or {}

    # ------------------------------------------------------------------
    # History helpers exposed as ``history.avg_24h(...)`` etc.
    # ------------------------------------------------------------------

    def avg_24h(self, sensor_id: str) -> float:
        """Return 24-hour rolling average for *sensor_id* (0.0 if unavailable)."""
        return self._cache.get(("avg_24h", sensor_id), 0.0)

    def last_n(self, sensor_id: str, n: int) -> list[float]:
        """Return the last *n* values for *sensor_id* (empty list if unavailable)."""
        return self._cache.get(("last_n", sensor_id, n), [])

    def as_dict(self) -> dict[str, Any]:
        """Return the namespace dict used for ``eval``."""
        return {**self._values, "history": self}


def _extract_history_calls(condition: str) -> list[tuple[str, list[Any]]]:
    """Parse condition AST and return validated history helper calls.

    Raises RuleEngineSafetyError for unsupported history helpers or invalid args.
    """
    calls: list[tuple[str, list[Any]]] = []
    tree = ast.parse(condition, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or not isinstance(
            node.func.value, ast.Name
        ):
            continue
        if node.func.value.id != "history":
            continue

        method = node.func.attr
        if method not in _ALLOWED_HISTORY_METHODS:
            raise RuleEngineSafetyError(
                f"Rule condition uses unsupported history helper "
                f"{method!r}: {condition!r}"
            )
        if node.keywords:
            raise RuleEngineSafetyError(
                f"Rule condition uses keyword args in history helper call: "
                f"{condition!r}"
            )

        args: list[Any] = []
        for arg in node.args:
            try:
                args.append(ast.literal_eval(arg))
            except Exception as exc:
                raise RuleEngineSafetyError(
                    f"Rule condition history helper args must be literals: "
                    f"{condition!r}"
                ) from exc

        if method == "avg_24h":
            if len(args) != 1 or not isinstance(args[0], str) or not args[0].strip():
                raise RuleEngineSafetyError(
                    "history.avg_24h requires exactly one non-empty string "
                    f"sensor_id argument: {condition!r}"
                )
        elif method == "last_n":
            if len(args) != 2 or not isinstance(args[0], str) or not args[0].strip():
                raise RuleEngineSafetyError(
                    "history.last_n requires sensor_id as first string argument: "
                    f"{condition!r}"
                )
            if not isinstance(args[1], int) or args[1] < 1 or args[1] > _MAX_LAST_N:
                raise RuleEngineSafetyError(
                    f"history.last_n count must be 1..{_MAX_LAST_N}: {condition!r}"
                )

        calls.append((method, args))
    return calls


def _validate_sensor_value(value: Any, rule_name: str) -> None:
    """Raise :exc:`RuleEngineSafetyError` if *value* is not a finite number.

    Rejects NaN, ±Inf, and any non-numeric type.  Called before the eval
    context is constructed so that malformed readings never reach rule
    expressions.
    """
    if not isinstance(value, (int, float)):
        raise RuleEngineSafetyError(
            f"Rule {rule_name!r}: sensor value {value!r} is not numeric "
            f"(got {type(value).__name__}). Refusing to evaluate rules against "
            "a non-numeric reading."
        )
    if math.isnan(value):
        raise RuleEngineSafetyError(
            f"Rule {rule_name!r}: sensor value is NaN. "
            "NaN in a rule expression produces undefined comparisons."
        )
    if math.isinf(value):
        raise RuleEngineSafetyError(
            f"Rule {rule_name!r}: sensor value is {'Inf' if value > 0 else '-Inf'}. "
            "Infinite values cannot be safely used in rule expressions."
        )


def _check_safety_ast(condition: str) -> None:
    """Validate *condition* using AST whitelist analysis.

    Parses the condition string into an abstract syntax tree and walks
    every node.  Only node types present in :data:`_SAFE_NODE_TYPES` are
    allowed unconditionally.  ``ast.Attribute`` and ``ast.Call`` nodes
    are allowed **only** when they reference a method on the ``history``
    object (e.g. ``history.avg_24h('load_current')``).  Everything else
    — imports, assignments, function definitions, comprehensions, lambda,
    subscripts, arbitrary function calls, attribute access on non-history
    objects — is rejected with :exc:`RuleEngineSafetyError`.

    This replaces the Phase 1 string-pattern blacklist with a strict
    whitelist that cannot be bypassed by creative encoding.
    """
    try:
        tree = ast.parse(condition, mode="eval")
    except SyntaxError as exc:
        raise RuleEngineSafetyError(
            f"Rule condition is not a valid expression: {condition!r} ({exc})"
        ) from exc

    for node in ast.walk(tree):
        node_type = type(node)

        # Fast path: unconditionally safe nodes.
        if node_type in _SAFE_NODE_TYPES:
            continue

        # ast.Call — only permit history.method(...) calls.
        if node_type is ast.Call:
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id in _ALLOWED_ATTRIBUTE_ROOTS
            ):
                # The call target is safe; the arguments will be
                # validated when ast.walk visits them individually.
                continue
            raise RuleEngineSafetyError(
                f"Rule condition contains a forbidden function call: {condition!r}"
            )

        # ast.Attribute — only permit access on the history object.
        if node_type is ast.Attribute:
            if (
                isinstance(node.value, ast.Name)
                and node.value.id in _ALLOWED_ATTRIBUTE_ROOTS
            ):
                continue
            raise RuleEngineSafetyError(
                f"Rule condition contains forbidden attribute access: {condition!r}"
            )

        # Everything else is forbidden.
        raise RuleEngineSafetyError(
            f"Rule condition contains forbidden construct "
            f"{node_type.__name__}: {condition!r}"
        )


def _rule_get(rule: Any, key: str, default: Any = None) -> Any:
    """Read rule fields from either dict rules or Trigger dataclasses."""
    if isinstance(rule, dict):
        return rule.get(key, default)
    return getattr(rule, key, default)


def _eval_checked_condition(condition: str, namespace: dict[str, Any]) -> bool:
    return bool(eval(condition, {"__builtins__": {}}, namespace))  # noqa: S307


def evaluate_condition_safely(
    condition: str,
    context: dict[str, Any],
    *,
    history_cache: dict[tuple, Any] | None = None,
) -> bool:
    """Validate and evaluate one rule condition with the RuleEngine sandbox.

    This helper is for code paths that need rule-condition semantics without
    constructing a full :class:`RuleEngine` event evaluation. It applies the
    same AST whitelist and ``history`` namespace wrapper used by RuleEngine.

    Raises:
        RuleEngineSafetyError: if the condition contains unsupported syntax.
        Exception: if evaluation fails because required context is unavailable.
    """
    _check_safety_ast(condition)
    namespace = EvalContext(dict(context), history_cache).as_dict()
    return _eval_checked_condition(condition, namespace)


class RuleEngine:
    """Deterministic, LLM-free rule evaluator — Tier 1 of the Intelligence Elevator.

    Rules are plain dicts (as loaded from skill YAML).  Each rule must carry:

    - ``name`` (str)
    - ``condition`` (str) — a Python expression evaluated against sensor values
    - ``action_tier`` (str) — ``'A'``, ``'B'``, ``'C'``, or ``'D'``

    Optional rule keys:

    - ``bypass_llm`` (bool, default ``False``)
    - ``escalate_to`` (str) — which Intelligence Elevator tier to use if the
      rule matches but does *not* bypass the LLM
    - ``action`` (str) — action name to pass to the dispatcher
    - ``cooldown_seconds`` (int, default ``0``) — minimum seconds between
      successive fires of this rule

    **Tier D handling:** Any rule with ``bypass_llm=True`` and
    ``action_tier='D'`` is treated as safety-critical.  The engine returns
    immediately upon encountering the first such rule that matches — it does
    not continue evaluating remaining rules.
    """

    def __init__(self) -> None:
        # rule_name → last-fired timestamp
        self._cooldowns: dict[str, _CooldownRecord] = {}

    async def evaluate(
        self,
        event: OriEvent,
        rules: list[Any],
        context: dict[str, Any] | None = None,
        state_store: Any = None,
    ) -> RuleResult:
        """Evaluate *rules* against *event* and return the first match.

        Args:
            event: The incoming sensor event.
            rules: Ordered list of rule dicts (from skill YAML ``triggers``).
            context: Extra key→value pairs available inside condition expressions
                (e.g. ``{'rated_capacity': 10.0}``).  ``value``, ``sensor_id``,
                and ``sensor_type`` are always injected from the event.
            state_store: Optional :class:`~ori.state.store.StateStore` instance
                passed to :class:`EvalContext` for history helpers.

        Returns:
            A :class:`RuleResult`.  ``matched=False`` means no rule fired.

        Raises:
            :exc:`RuleEngineSafetyError`: if any rule condition contains a
                forbidden pattern (checked before evaluation).
        """
        base_ctx: dict[str, Any] = dict(context or {})
        if event.reading is not None:
            first_rule_name = (
                _rule_get(rules[0], "name", "<unnamed>") if rules else "<unknown>"
            )
            _validate_sensor_value(event.reading.value, first_rule_name)
            base_ctx.setdefault("value", event.reading.value)
            base_ctx.setdefault("sensor_id", event.reading.sensor_id)
            base_ctx.setdefault("sensor_type", event.reading.sensor_type)
            base_ctx.setdefault("unit", event.reading.unit)
            base_ctx.setdefault("quality", event.reading.quality)

        # Pre-fetch history if needed to safely inject into synchronous eval.
        history_cache: dict[tuple, Any] = {}
        for rule in rules:
            condition = _rule_get(rule, "condition", "")
            if not condition:
                continue
            _check_safety_ast(condition)
            history_calls = _extract_history_calls(condition)
            if state_store is None:
                continue
            for method, args in history_calls:
                if method == "avg_24h":
                    key = ("avg_24h", args[0])
                    if key in history_cache:
                        continue
                    try:
                        val = await state_store.avg_last_hours(args[0], 24)
                        history_cache[key] = val if val is not None else 0.0
                    except Exception:
                        history_cache[key] = 0.0
                        logger.warning(
                            "RuleEngine: history prefetch failed for avg_24h(%r); "
                            "using 0.0",
                            args[0],
                        )
                elif method == "last_n":
                    key = ("last_n", args[0], args[1])
                    if key in history_cache:
                        continue
                    try:
                        readings = await state_store.get_history(args[0], limit=args[1])
                        history_cache[key] = (
                            [r.value for r in readings] if readings else []
                        )
                    except Exception:
                        history_cache[key] = []
                        logger.warning(
                            "RuleEngine: history prefetch failed for last_n(%r, %d); "
                            "using []",
                            args[0],
                            args[1],
                        )

        eval_ctx = EvalContext(base_ctx, history_cache)
        namespace = eval_ctx.as_dict()

        for rule in rules:
            name: str = _rule_get(rule, "name", "<unnamed>")
            condition: str = _rule_get(rule, "condition", "")
            bypass_llm: bool = bool(_rule_get(rule, "bypass_llm", False))
            action_tier: str = str(_rule_get(rule, "action_tier", "A"))
            escalate_to: str | None = _rule_get(rule, "escalate_to")
            reasoning_policy: str | None = _rule_get(rule, "reasoning_policy")
            requires_approval: bool = bool(_rule_get(rule, "requires_approval", False))
            action: str | None = _rule_get(rule, "action")
            cooldown_s: int = int(_rule_get(rule, "cooldown_seconds", 0))

            if not condition:
                continue

            try:
                matched = _eval_checked_condition(condition, namespace)
            except NameError as exc:
                # Expected: sensor variable not present in this event's namespace.
                # The runtime evaluates all triggers on every event; sensors not
                # included in the current reading will always produce NameError.
                # Log at DEBUG — this is not an error, it is a skip.
                logger.debug(
                    "RuleEngine: skipping rule %r — sensor not in event (%s)",
                    name,
                    exc,
                )
                continue
            except Exception:
                logger.exception(
                    "RuleEngine: error evaluating condition %r for rule %r",
                    condition,
                    name,
                )
                continue

            if not matched:
                continue

            # Check cooldown
            if cooldown_s > 0:
                rec = self._cooldowns.get(name)
                if (
                    rec is not None
                    and (now_ms() - rec.last_fired_ms) < cooldown_s * 1000
                ):
                    logger.debug(
                        "RuleEngine: rule %r suppressed by cooldown (%ds)",
                        name,
                        cooldown_s,
                    )
                    continue

            # Record fire time
            self._cooldowns[name] = _CooldownRecord(last_fired_ms=now_ms())

            logger.info(
                "RuleEngine: rule %r matched (tier=%s, bypass_llm=%s)",
                name,
                action_tier,
                bypass_llm,
            )

            return RuleResult(
                matched=True,
                rule_name=name,
                escalate_to=escalate_to,
                bypass_llm=bypass_llm,
                reasoning_policy=reasoning_policy,
                requires_approval=requires_approval,
                action=action,
                action_tier=action_tier,
                confidence=1.0,
            )

        return RuleResult(matched=False, action_tier="A")
