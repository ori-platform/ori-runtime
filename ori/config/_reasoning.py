# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``reasoning`` section."""

from dataclasses import dataclass, field
from typing import Any

from ori.config._fields import ConfigValidationError


@dataclass
class ReasoningConfig:
    default_tier: str
    local_model: str
    model_path: str
    escalation_threshold: float = 0.70
    energy_aware_reasoning: dict = field(default_factory=dict)
    capability_posture: dict = field(default_factory=dict)
    causal_memory: dict = field(default_factory=dict)
    context_enricher: dict = field(default_factory=dict)


def parse_reasoning(data: Any) -> ReasoningConfig:
    if not isinstance(data, dict):
        raise ConfigValidationError("'reasoning' section must be a mapping.")

    energy_aware = data.get("energy_aware_reasoning") or {}
    if not isinstance(energy_aware, dict):
        raise ConfigValidationError(
            "'reasoning.energy_aware_reasoning' must be a mapping when provided."
        )
    causal_memory = data.get("causal_memory") or {}
    if not isinstance(causal_memory, dict):
        raise ConfigValidationError(
            "'reasoning.causal_memory' must be a mapping when provided."
        )
    capability_posture = data.get("capability_posture") or {}
    if not isinstance(capability_posture, dict):
        raise ConfigValidationError(
            "'reasoning.capability_posture' must be a mapping when provided."
        )

    try:
        probe_interval_seconds = int(
            capability_posture.get("probe_interval_seconds", 30)
        )
        gateway_heartbeat_ttl_seconds = int(
            capability_posture.get("gateway_heartbeat_ttl_seconds", 30)
        )
        internet_probe_timeout_ms = int(
            capability_posture.get("internet_probe_timeout_ms", 1000)
        )
        internet_probe_port = int(capability_posture.get("internet_probe_port", 53))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "reasoning.capability_posture numeric fields must be valid integers."
        ) from exc

    if not (1 <= probe_interval_seconds <= 30):
        raise ConfigValidationError(
            "reasoning.capability_posture.probe_interval_seconds must be between 1 and 30."
        )
    if gateway_heartbeat_ttl_seconds < 1:
        raise ConfigValidationError(
            "reasoning.capability_posture.gateway_heartbeat_ttl_seconds must be >= 1."
        )
    if internet_probe_timeout_ms < 100:
        raise ConfigValidationError(
            "reasoning.capability_posture.internet_probe_timeout_ms must be >= 100."
        )
    if not (1 <= internet_probe_port <= 65535):
        raise ConfigValidationError(
            "reasoning.capability_posture.internet_probe_port must be between 1 and 65535."
        )
    internet_probe_host = str(
        capability_posture.get("internet_probe_host", "one.one.one.one")
    ).strip()
    if not internet_probe_host:
        raise ConfigValidationError(
            "reasoning.capability_posture.internet_probe_host must not be empty."
        )

    capability_posture_cfg = {
        "enabled": (
            str(capability_posture.get("enabled", "true")).strip().lower() == "true"
            or capability_posture.get("enabled") is True
        ),
        "probe_interval_seconds": probe_interval_seconds,
        "gateway_heartbeat_ttl_seconds": gateway_heartbeat_ttl_seconds,
        "internet_probe_timeout_ms": internet_probe_timeout_ms,
        "internet_probe_port": internet_probe_port,
        "internet_probe_host": internet_probe_host,
    }

    default_tier = str(data.get("default_tier", "local")).strip().lower()
    if default_tier not in {"rule", "local"}:
        raise ConfigValidationError(
            "reasoning.default_tier must be one of: rule, local. "
            "gateway is selected by escalation policy; cloud is a gateway backend."
        )

    context_enricher = data.get("context_enricher") or {}
    if not isinstance(context_enricher, dict):
        raise ConfigValidationError(
            "'reasoning.context_enricher' must be a mapping when provided."
        )
    if context_enricher:
        try:
            ce_staleness = int(context_enricher.get("staleness_window_ms", 60_000))
            ce_max_entries = int(context_enricher.get("max_entries", 5))
        except (TypeError, ValueError) as exc:
            raise ConfigValidationError(
                "reasoning.context_enricher numeric fields must be valid integers."
            ) from exc
        if ce_staleness < 100:
            raise ConfigValidationError(
                "reasoning.context_enricher.staleness_window_ms must be >= 100."
            )
        if not (1 <= ce_max_entries <= 20):
            raise ConfigValidationError(
                "reasoning.context_enricher.max_entries must be between 1 and 20."
            )
        ce_sources = context_enricher.get("include_sources") or []
        if not isinstance(ce_sources, list) or not all(
            isinstance(s, str) for s in ce_sources
        ):
            raise ConfigValidationError(
                "reasoning.context_enricher.include_sources must be a list of strings."
            )
        context_enricher = {
            "enabled": (
                str(context_enricher.get("enabled", "false")).strip().lower() == "true"
                or context_enricher.get("enabled") is True
            ),
            "staleness_window_ms": ce_staleness,
            "max_entries": ce_max_entries,
            "include_sources": list(ce_sources),
        }

    return ReasoningConfig(
        default_tier=default_tier,
        local_model=str(data.get("local_model", "")),
        model_path=str(data.get("model_path", "")),
        escalation_threshold=float(data.get("escalation_threshold", 0.70)),
        energy_aware_reasoning=energy_aware,
        capability_posture=capability_posture_cfg,
        causal_memory=causal_memory,
        context_enricher=context_enricher,
    )
