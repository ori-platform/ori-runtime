# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ori.config import ConfigValidationError, _parse_reasoning
from ori.network.events import OriEvent, SensorReading
from ori.reasoning.context_enricher import (
    _SNAPSHOT_HEADER,
    ContextEnricher,
    ContextEnricherConfig,
)

# ── helpers ──────────────────────────────────────────────────────────────────


def _reading(
    sensor_id: str,
    sensor_type: str = "temperature",
    value: float = 22.0,
    unit: str = "celsius",
    quality: float = 1.0,
    source: str = "i2c",
    timestamp: int = 1_717_000_000_000,
) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp=timestamp,
        quality=quality,
        metadata={"source": source},
    )


def _event(sensor_id: str = "primary-sensor") -> OriEvent:
    r = _reading(sensor_id)
    return OriEvent.from_reading(r, "test-device")


def _store(readings: list[SensorReading]) -> AsyncMock:
    store = AsyncMock()
    store.get_latest_readings_snapshot = AsyncMock(return_value=readings)
    return store


def _enricher(
    enabled: bool = True,
    staleness_window_ms: int = 60_000,
    max_entries: int = 5,
    include_sources: list[str] | None = None,
) -> ContextEnricher:
    return ContextEnricher(
        ContextEnricherConfig(
            enabled=enabled,
            staleness_window_ms=staleness_window_ms,
            max_entries=max_entries,
            include_sources=include_sources or [],
        )
    )


# ── unit tests: ContextEnricher behaviour ────────────────────────────────────


@pytest.mark.asyncio
async def test_disabled_by_default_returns_prompt_unchanged():
    store = _store([_reading("other-sensor")])
    enricher = _enricher(enabled=False)
    original = "Current: 8.2A"

    result = await enricher.enrich(original, _event(), store)

    assert result == original
    store.get_latest_readings_snapshot.assert_not_called()


@pytest.mark.asyncio
async def test_injects_fresh_snapshot_lines():
    readings = [
        _reading("voltage-sensor", "voltage", 230.1, "volt"),
        _reading("temp-sensor", "temperature", 28.3, "celsius"),
    ]
    enricher = _enricher()
    event = _event("current-sensor")
    original = "Current: 8.2A"

    result = await enricher.enrich(original, event, _store(readings))

    assert result.startswith(original)
    assert _SNAPSHOT_HEADER in result
    assert "voltage-sensor" in result
    assert "temp-sensor" in result
    assert "230.1" in result


@pytest.mark.asyncio
async def test_empty_snapshot_returns_prompt_unchanged():
    enricher = _enricher()
    original = "Current: 8.2A"

    result = await enricher.enrich(original, _event(), _store([]))

    assert result == original
    assert _SNAPSHOT_HEADER not in result


@pytest.mark.asyncio
async def test_excludes_triggering_sensor_from_store_query():
    enricher = _enricher()
    store = _store([])
    event = _event("load-current-01")

    await enricher.enrich("prompt", event, store)

    store.get_latest_readings_snapshot.assert_called_once()
    call_kwargs = store.get_latest_readings_snapshot.call_args
    assert call_kwargs.kwargs["exclude_sensor_id"] == "load-current-01"


@pytest.mark.asyncio
async def test_staleness_window_passed_to_store():
    enricher = _enricher(staleness_window_ms=30_000)
    store = _store([])

    with patch("ori.reasoning.context_enricher.now_ms", return_value=1_000_000):
        await enricher.enrich("prompt", _event(), store)

    call_kwargs = store.get_latest_readings_snapshot.call_args
    assert call_kwargs.kwargs["since_ms"] == 1_000_000 - 30_000


@pytest.mark.asyncio
async def test_respects_max_entries_passed_to_store():
    enricher = _enricher(max_entries=3)
    store = _store([])

    await enricher.enrich("prompt", _event(), store)

    call_kwargs = store.get_latest_readings_snapshot.call_args
    assert call_kwargs.kwargs["max_entries"] == 3


@pytest.mark.asyncio
async def test_filters_by_include_sources():
    readings = [
        _reading("mqtt-sensor", source="mqtt"),
        _reading("serial-sensor", source="serial"),
    ]
    enricher = _enricher(include_sources=["mqtt"])

    result = await enricher.enrich("prompt", _event(), _store(readings))

    assert "mqtt-sensor" in result
    assert "serial-sensor" not in result


@pytest.mark.asyncio
async def test_empty_include_sources_allows_all():
    readings = [
        _reading("mqtt-sensor", source="mqtt"),
        _reading("i2c-sensor", source="i2c"),
        _reading("serial-sensor", source="serial"),
    ]
    enricher = _enricher(include_sources=[])

    result = await enricher.enrich("prompt", _event(), _store(readings))

    assert "mqtt-sensor" in result
    assert "i2c-sensor" in result
    assert "serial-sensor" in result


@pytest.mark.asyncio
async def test_sanitizes_injected_sensor_values():
    malicious = _reading(
        "sensor<script>",
        sensor_type="type{inject}",
        value=9.9,
        unit="A</script>",
    )
    enricher = _enricher()

    result = await enricher.enrich("prompt", _event(), _store([malicious]))

    assert "<script>" not in result
    assert "{inject}" not in result
    assert "</script>" not in result
    assert "9.9" in result


@pytest.mark.asyncio
async def test_falls_back_on_store_error(caplog):
    store = AsyncMock()
    store.get_latest_readings_snapshot = AsyncMock(side_effect=RuntimeError("db gone"))
    enricher = _enricher()
    original = "Current: 8.2A"

    with caplog.at_level(logging.WARNING, logger="ori.reasoning.context_enricher"):
        result = await enricher.enrich(original, _event(), store)

    assert result == original
    assert any("enrichment failed" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_falls_back_on_source_filter_error(caplog):
    bad_reading = MagicMock(spec=SensorReading)
    bad_reading.metadata = MagicMock()
    bad_reading.metadata.get = MagicMock(side_effect=TypeError("broken"))
    store = _store([bad_reading])
    enricher = _enricher(include_sources=["mqtt"])
    original = "prompt"

    with caplog.at_level(logging.WARNING, logger="ori.reasoning.context_enricher"):
        result = await enricher.enrich(original, _event(), store)

    assert result == original


@pytest.mark.asyncio
async def test_snapshot_appended_after_prompt_body():
    readings = [_reading("volt-01", "voltage", 230.0, "volt")]
    enricher = _enricher()
    original = "Line 1\nLine 2"

    result = await enricher.enrich(original, _event(), _store(readings))

    header_pos = result.index(_SNAPSHOT_HEADER)
    assert result[:header_pos].strip() == original


# ── unit tests: config validation ────────────────────────────────────────────


def test_config_validated_staleness_minimum():
    with pytest.raises(ConfigValidationError, match="staleness_window_ms"):
        _parse_reasoning(
            {
                "default_tier": "local",
                "context_enricher": {"enabled": True, "staleness_window_ms": 50},
            }
        )


def test_config_validated_max_entries_too_low():
    with pytest.raises(ConfigValidationError, match="max_entries"):
        _parse_reasoning(
            {
                "default_tier": "local",
                "context_enricher": {"max_entries": 0},
            }
        )


def test_config_validated_max_entries_too_high():
    with pytest.raises(ConfigValidationError, match="max_entries"):
        _parse_reasoning(
            {
                "default_tier": "local",
                "context_enricher": {"max_entries": 21},
            }
        )


def test_config_validated_include_sources_must_be_list():
    with pytest.raises(ConfigValidationError, match="include_sources"):
        _parse_reasoning(
            {
                "default_tier": "local",
                "context_enricher": {"include_sources": "mqtt"},
            }
        )


def test_config_validated_non_mapping_raises():
    with pytest.raises(ConfigValidationError, match="context_enricher"):
        _parse_reasoning(
            {
                "default_tier": "local",
                "context_enricher": "enabled",
            }
        )


def test_config_valid_defaults_parse_cleanly():
    cfg = _parse_reasoning({"default_tier": "local"})
    assert cfg.context_enricher == {}


def test_config_enabled_false_by_default_when_block_present():
    cfg = _parse_reasoning(
        {"default_tier": "local", "context_enricher": {"max_entries": 3}}
    )
    assert cfg.context_enricher["enabled"] is False
    assert cfg.context_enricher["max_entries"] == 3


def test_config_valid_full_block():
    cfg = _parse_reasoning(
        {
            "default_tier": "local",
            "context_enricher": {
                "enabled": True,
                "staleness_window_ms": 30_000,
                "max_entries": 8,
                "include_sources": ["i2c", "mqtt"],
            },
        }
    )
    assert cfg.context_enricher["enabled"] is True
    assert cfg.context_enricher["staleness_window_ms"] == 30_000
    assert cfg.context_enricher["max_entries"] == 8
    assert cfg.context_enricher["include_sources"] == ["i2c", "mqtt"]


# ── integration: elevator wires enricher into prompt ─────────────────────────


@pytest.mark.asyncio
async def test_elevator_calls_enricher_for_local_slm():
    """Elevator passes the assembled prompt through the enricher before the LLM."""
    from ori.reasoning.elevator import IntelligenceElevator

    enricher = MagicMock(spec=ContextEnricher)
    enriched_prompt = "original prompt\n\nOther sensors..."
    enricher.enrich = AsyncMock(return_value=enriched_prompt)

    llm = AsyncMock()
    from ori.network.events import ReasoningResult

    llm.reason = AsyncMock(
        return_value=ReasoningResult(
            text="ok", tier="local_slm", model="stub", tokens_used=0, latency_ms=0
        )
    )

    elevator = IntelligenceElevator(
        local_llm=llm,
        context_enricher=enricher,
    )

    skill = MagicMock()
    skill.triggers = []
    skill.prompts = {}
    skill.config = {}
    skill.name = "test-skill"

    event = _event()
    store = AsyncMock()
    store.avg_last_n = AsyncMock(return_value=None)
    store.avg_last_hours = AsyncMock(return_value=None)

    await elevator.reason(event, skill, store)

    enricher.enrich.assert_called_once()
    call_args = enricher.enrich.call_args
    assert call_args.args[1] is event
    assert call_args.args[2] is store
    assert llm.reason.call_args.args[0] == enriched_prompt


@pytest.mark.asyncio
async def test_tier_d_bypass_never_reaches_enricher():
    """Tier D bypass_llm exits rule engine before _build_prompt; enricher untouched."""
    from ori.reasoning.elevator import IntelligenceElevator

    enricher = MagicMock(spec=ContextEnricher)
    enricher.enrich = AsyncMock()

    elevator = IntelligenceElevator(context_enricher=enricher)

    skill = MagicMock()
    skill.config = {}
    skill.name = "test-skill"
    skill.prompts = {}

    from ori.skills.loader import Trigger

    tier_d_trigger = Trigger(
        name="dangerous_overcurrent",
        condition="value > 50.0",
        action_tier="D",
        bypass_llm=True,
        cooldown_seconds=0,
        escalate_to="rule",
    )
    skill.triggers = [tier_d_trigger]

    reading = _reading("load-current", value=55.0, unit="A")
    event = OriEvent.from_reading(reading, "test-device")
    store = AsyncMock()

    await elevator.reason(event, skill, store)

    enricher.enrich.assert_not_called()
