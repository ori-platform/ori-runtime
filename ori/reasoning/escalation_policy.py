# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Deterministic Tier 2 -> Tier 3 escalation signals.

Local SLM confidence is not authoritative. This module captures observable
conditions where the runtime should prefer gateway reasoning before invoking
the local SLM, provided a gateway reasoning transport is available.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ori.network.events import OriEvent

GATEWAY_ESCALATION_CONTEXT_KEY = "gateway_escalation"


@dataclass(frozen=True)
class GatewayEscalationSignal:
    code: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "detail": self.detail}


@dataclass(frozen=True)
class GatewayEscalationDecision:
    signals: tuple[GatewayEscalationSignal, ...]

    @property
    def should_escalate(self) -> bool:
        return bool(self.signals)

    def as_context(self, *, selected: bool, gateway_available: bool) -> dict[str, Any]:
        return {
            "target_tier": "gateway",
            "selected": bool(selected),
            "gateway_available": bool(gateway_available),
            "signals": [signal.as_dict() for signal in self.signals],
        }


def evaluate_gateway_escalation(
    *,
    event: OriEvent,
    rule_result: Any,
    avg_24h: float | None,
    history: list[float],
    history_query_failed: bool,
) -> GatewayEscalationDecision:
    """Return deterministic gateway-escalation signals for *event*.

    The returned decision is pure policy. Callers decide whether gateway
    reasoning is currently available and how to fall back if it is not.
    """

    signals: list[GatewayEscalationSignal] = []

    if _trigger_declares_gateway(rule_result):
        signals.append(
            GatewayEscalationSignal(
                code="trigger_declares_gateway",
                detail="matched trigger declares escalate_to: gateway",
            )
        )

    if history_query_failed:
        signals.append(
            GatewayEscalationSignal(
                code="history_query_failed",
                detail="sensor history lookup failed before local SLM reasoning",
            )
        )
    elif event.reading is not None and avg_24h is None and not history:
        signals.append(
            GatewayEscalationSignal(
                code="no_baseline_available",
                detail="no 24h average or recent history is available for this sensor",
            )
        )

    range_signal = _calibrated_range_signal(event)
    if range_signal is not None:
        signals.append(range_signal)

    conflict_signal = _conflicting_related_sensor_signal(event)
    if conflict_signal is not None:
        signals.append(conflict_signal)

    return GatewayEscalationDecision(signals=tuple(signals))


def attach_gateway_escalation_context(
    event: OriEvent,
    decision: GatewayEscalationDecision,
    *,
    selected: bool,
    gateway_available: bool,
) -> None:
    if not decision.should_escalate:
        return
    if not isinstance(getattr(event, "context", None), dict):
        event.context = {}
    event.context[GATEWAY_ESCALATION_CONTEXT_KEY] = decision.as_context(
        selected=selected,
        gateway_available=gateway_available,
    )


def _trigger_declares_gateway(rule_result: Any) -> bool:
    if not bool(getattr(rule_result, "matched", False)):
        return False
    return str(getattr(rule_result, "escalate_to", "") or "").strip().lower() == (
        "gateway"
    )


def _calibrated_range_signal(event: OriEvent) -> GatewayEscalationSignal | None:
    if event.reading is None:
        return None
    context = event.context if isinstance(event.context, dict) else {}
    calibration = context.get("sensor_calibration") or event.reading.metadata.get(
        "calibration"
    )
    if not isinstance(calibration, dict):
        return None

    minimum = _first_number(
        calibration,
        "min_value",
        "minimum_value",
        "calibrated_min",
        "safe_min",
    )
    maximum = _first_number(
        calibration,
        "max_value",
        "maximum_value",
        "calibrated_max",
        "safe_max",
    )
    value = float(event.reading.value)

    if minimum is not None and value < minimum:
        return GatewayEscalationSignal(
            code="sensor_outside_calibrated_range",
            detail=f"reading {value:g} is below calibrated minimum {minimum:g}",
        )
    if maximum is not None and value > maximum:
        return GatewayEscalationSignal(
            code="sensor_outside_calibrated_range",
            detail=f"reading {value:g} is above calibrated maximum {maximum:g}",
        )
    return None


def _conflicting_related_sensor_signal(
    event: OriEvent,
) -> GatewayEscalationSignal | None:
    if event.reading is None:
        return None
    context = event.context if isinstance(event.context, dict) else {}
    related = context.get("related_sensor_readings")
    if not isinstance(related, list):
        return None

    tolerance = _first_number(context, "related_sensor_conflict_tolerance")
    if tolerance is None:
        tolerance = _first_number(
            context.get("sensor_calibration") if isinstance(context, dict) else {},
            "related_sensor_conflict_tolerance",
            "conflict_tolerance",
            "conflict_delta",
        )
    if tolerance is None or tolerance < 0:
        return None

    current_value = float(event.reading.value)
    for item in related:
        if not isinstance(item, dict):
            continue
        try:
            related_value = float(item.get("value"))
        except (TypeError, ValueError):
            continue
        if abs(current_value - related_value) > tolerance:
            related_id = str(item.get("sensor_id", "related sensor") or "")
            return GatewayEscalationSignal(
                code="conflicting_related_sensor_reading",
                detail=(
                    f"reading differs from {related_id or 'related sensor'} "
                    f"by more than {tolerance:g}"
                ),
            )
    return None


def _first_number(mapping: Any, *keys: str) -> float | None:
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        if key not in mapping:
            continue
        try:
            return float(mapping[key])
        except (TypeError, ValueError):
            continue
    return None
