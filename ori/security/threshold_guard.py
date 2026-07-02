# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tier D threshold safety checks for the SET_THRESHOLD remote command.

Identifies which skill config keys are referenced in Tier D trigger conditions
and enforces the invariants from AGENTS.md §13:

1. Startup sensitivity: a Tier D threshold key must not be remotely changed in
   any direction that makes the Tier D condition less sensitive than startup
   configuration.
2. Active suppression: a change that causes any active Tier D condition to stop
   firing must be rejected.  The check evaluates the actual trigger expression
   under both old and new config so that lower-bound conditions (``value <
   low_voltage_threshold``) are protected equally with upper-bound ones.
"""

from __future__ import annotations

import ast
import math
from typing import Any

from ori.reasoning.rule_engine import evaluate_condition_safely

_UPPER_BOUND = "upper_bound"
_LOWER_BOUND = "lower_bound"


def extract_trigger_refs(condition: str) -> frozenset[str]:
    """Return all bare Name identifiers referenced in a condition expression."""
    try:
        tree = ast.parse(condition, mode="eval")
    except SyntaxError:
        return frozenset()
    return frozenset(node.id for node in ast.walk(tree) if isinstance(node, ast.Name))


def all_trigger_condition_refs(skill: Any) -> frozenset[str]:
    """Return Name refs across all trigger conditions (Tier D and non-Tier-D)."""
    refs: set[str] = set()
    for trigger in getattr(skill, "triggers", []):
        refs |= extract_trigger_refs(getattr(trigger, "condition", ""))
    return frozenset(refs)


def tier_d_config_keys(skill: Any) -> frozenset[str]:
    """Return config keys referenced in any Tier D trigger condition."""
    config_keys = frozenset(getattr(skill, "config", {}).keys())
    tier_d_keys: set[str] = set()
    for trigger in getattr(skill, "triggers", []):
        if getattr(trigger, "action_tier", None) == "D":
            tier_d_keys |= config_keys & extract_trigger_refs(
                getattr(trigger, "condition", "")
            )
    return frozenset(tier_d_keys)


def _compare_direction_for_key(node: ast.Compare, threshold_key: str) -> str | None:
    """Infer how changing ``threshold_key`` affects one comparison."""
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return None

    left = node.left
    right = node.comparators[0]
    op = node.ops[0]
    left_is_key = isinstance(left, ast.Name) and left.id == threshold_key
    right_is_key = isinstance(right, ast.Name) and right.id == threshold_key

    if left_is_key == right_is_key:
        return None

    if right_is_key:
        if isinstance(op, (ast.Gt, ast.GtE)):
            return _UPPER_BOUND
        if isinstance(op, (ast.Lt, ast.LtE)):
            return _LOWER_BOUND
        return None

    if left_is_key:
        if isinstance(op, (ast.Lt, ast.LtE)):
            return _UPPER_BOUND
        if isinstance(op, (ast.Gt, ast.GtE)):
            return _LOWER_BOUND
        return None

    return None


def _tier_d_threshold_directions(skill: Any, threshold_key: str) -> frozenset[str]:
    """Return proven sensitivity directions for a Tier D config key."""
    directions: set[str] = set()
    for trigger in getattr(skill, "triggers", []):
        if getattr(trigger, "action_tier", None) != "D":
            continue
        condition = str(getattr(trigger, "condition", "") or "")
        if threshold_key not in extract_trigger_refs(condition):
            continue
        try:
            tree = ast.parse(condition, mode="eval")
        except SyntaxError:
            return frozenset()
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                direction = _compare_direction_for_key(node, threshold_key)
                if direction is not None:
                    directions.add(direction)
    return frozenset(directions)


def check_tier_d_startup_sensitivity(
    skill: Any,
    *,
    threshold_key: str,
    new_value: float,
    startup_value: float | None,
) -> tuple[bool, str]:
    """Reject Tier D changes that make startup safety less sensitive.

    For common threshold forms, this proves the safe direction statically:

    - ``value > threshold``: remote value must be ``<=`` startup.
    - ``value < threshold``: remote value must be ``>=`` startup.

    If the condition is too complex to prove, the function fails closed and
    rejects any remote change away from startup.

    Returns:
        ``(True, "")`` when the change is no less sensitive than startup.
        ``(False, detail)`` when the change must be rejected.
    """
    if startup_value is None:
        return (
            False,
            f"SET_THRESHOLD rejected: missing startup value for Tier D key "
            f"{threshold_key!r}; cannot prove startup sensitivity is preserved",
        )
    try:
        sv = float(startup_value)
    except (TypeError, ValueError):
        return (
            False,
            f"SET_THRESHOLD rejected: startup value for Tier D key "
            f"{threshold_key!r} is not numeric",
        )
    if not math.isfinite(sv):
        return (
            False,
            f"SET_THRESHOLD rejected: startup value for Tier D key "
            f"{threshold_key!r} is not finite",
        )

    directions = _tier_d_threshold_directions(skill, threshold_key)
    if directions == frozenset({_UPPER_BOUND}):
        if new_value > sv:
            return (
                False,
                f"SET_THRESHOLD rejected: {threshold_key!r} new value {new_value} "
                f"would make Tier D less sensitive than startup value {sv}",
            )
        return True, ""

    if directions == frozenset({_LOWER_BOUND}):
        if new_value < sv:
            return (
                False,
                f"SET_THRESHOLD rejected: {threshold_key!r} new value {new_value} "
                f"would make Tier D less sensitive than startup value {sv}",
            )
        return True, ""

    if new_value != sv:
        return (
            False,
            f"SET_THRESHOLD rejected: cannot prove remote change to Tier D key "
            f"{threshold_key!r} preserves startup sensitivity; change must be "
            "made through local config or signed maintenance workflow",
        )

    return True, ""


def check_tier_d_condition_suppression(
    skill: Any,
    threshold_key: str,
    old_config: dict[str, Any],
    new_config: dict[str, Any],
    recent_readings: list[Any],
) -> tuple[bool, str]:
    """Evaluate each Tier D trigger condition under old and new config.

    For every recent sensor reading and every Tier D trigger, evaluates the
    trigger expression with both configurations.  If the condition was ``True``
    with the old config but would be ``False`` with the new config, the change
    suppresses an active Tier D condition and is rejected.

    When a condition cannot be evaluated (e.g. a missing context variable),
    the check is conservative: it treats the old condition as active and the
    new condition as inactive, causing the change to be rejected.

    Args:
        skill: Loaded :class:`~ori.skills.loader.Skill` instance.
        threshold_key: Config key being modified (used in rejection messages).
        old_config: Skill config dict *before* the proposed change.
        new_config: Skill config dict *after* the proposed change.
        recent_readings: Recent :class:`~ori.network.events.SensorReading` objects
            for sensors associated with the skill.

    Returns:
        ``(True, "")`` when the change is safe.
        ``(False, detail)`` when the change must be rejected.
    """
    tier_d_triggers = [
        t
        for t in getattr(skill, "triggers", [])
        if getattr(t, "action_tier", None) == "D"
    ]
    if not tier_d_triggers or not recent_readings:
        return True, ""

    for trigger in tier_d_triggers:
        condition = getattr(trigger, "condition", "")
        if not condition:
            continue
        for reading in recent_readings:
            base: dict[str, Any] = {
                "value": float(reading.value),
                "sensor_id": str(reading.sensor_id),
                "sensor_type": str(reading.sensor_type),
            }
            ctx_old = {**base, **old_config}
            ctx_new = {**base, **new_config}

            try:
                was_active = evaluate_condition_safely(condition, ctx_old)
            except Exception:
                was_active = True  # cannot evaluate → assume active (fail-closed)

            try:
                would_be_active = evaluate_condition_safely(condition, ctx_new)
            except Exception:
                would_be_active = (
                    False  # cannot evaluate → assume suppressed (fail-closed)
                )

            if was_active and not would_be_active:
                trigger_name = getattr(trigger, "name", "?")
                return (
                    False,
                    f"SET_THRESHOLD would suppress active Tier D condition "
                    f"'{trigger_name}': reading {reading.value} triggers with "
                    f"{threshold_key}={old_config.get(threshold_key)} "
                    f"but not with {threshold_key}={new_config.get(threshold_key)}",
                )

    return True, ""
