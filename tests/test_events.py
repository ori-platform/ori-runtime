# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from ori.network.events import (
    ActionResult,
    ActionTier,
    OriEvent,
    ReasoningResult,
    SensorReading,
    compute_fingerprint,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_reading() -> SensorReading:
    return SensorReading(
        sensor_id="current-01",
        sensor_type="current",
        value=8.2,
        unit="ampere",
        timestamp=1_700_000_000_000,
        quality=0.95,
        metadata={"source": "i2c"},
        raw=None,
    )


# ---------------------------------------------------------------------------
# SensorReading
# ---------------------------------------------------------------------------


def test_sensor_reading_creation(sample_reading: SensorReading) -> None:
    assert sample_reading.sensor_id == "current-01"
    assert sample_reading.sensor_type == "current"
    assert sample_reading.value == 8.2
    assert sample_reading.unit == "ampere"
    assert sample_reading.timestamp == 1_700_000_000_000
    assert sample_reading.quality == 0.95
    assert sample_reading.metadata == {"source": "i2c"}
    assert sample_reading.raw is None


def test_sensor_reading_metadata_defaults_to_empty_dict() -> None:
    reading = SensorReading(
        sensor_id="temp-01",
        sensor_type="temperature",
        value=25.0,
        unit="celsius",
        timestamp=1_700_000_000_000,
        quality=1.0,
    )
    assert reading.metadata == {}
    assert reading.raw is None


# ---------------------------------------------------------------------------
# OriEvent.from_reading
# ---------------------------------------------------------------------------


def test_ori_event_from_reading_event_type(sample_reading: SensorReading) -> None:
    event = OriEvent.from_reading(sample_reading, device_id="dev-01")
    assert event.event_type == "sensor.reading"


def test_ori_event_from_reading_sensor_id(sample_reading: SensorReading) -> None:
    event = OriEvent.from_reading(sample_reading, device_id="dev-01")
    assert event.sensor_id == sample_reading.sensor_id


def test_ori_event_from_reading_propagates_timestamp(
    sample_reading: SensorReading,
) -> None:
    event = OriEvent.from_reading(sample_reading, device_id="dev-01")
    assert event.timestamp == sample_reading.timestamp


def test_ori_event_from_reading_device_id(sample_reading: SensorReading) -> None:
    event = OriEvent.from_reading(sample_reading, device_id="dev-01")
    assert event.device_id == "dev-01"


def test_ori_event_from_reading_source_from_metadata(
    sample_reading: SensorReading,
) -> None:
    event = OriEvent.from_reading(sample_reading, device_id="dev-01")
    assert event.source == "i2c"


def test_ori_event_from_reading_source_empty_when_no_metadata() -> None:
    reading = SensorReading(
        sensor_id="temp-01",
        sensor_type="temperature",
        value=25.0,
        unit="celsius",
        timestamp=1_700_000_000_000,
        quality=1.0,
    )
    event = OriEvent.from_reading(reading, device_id="dev-01")
    assert event.source == ""


def test_ori_event_from_reading_unique_event_ids(sample_reading: SensorReading) -> None:
    event_a = OriEvent.from_reading(sample_reading, device_id="dev-01")
    event_b = OriEvent.from_reading(sample_reading, device_id="dev-01")
    assert event_a.event_id != event_b.event_id


def test_ori_event_from_reading_attaches_reading(sample_reading: SensorReading) -> None:
    event = OriEvent.from_reading(sample_reading, device_id="dev-01")
    assert event.reading is sample_reading


# ---------------------------------------------------------------------------
# compute_fingerprint
# ---------------------------------------------------------------------------


def test_fingerprint_same_regardless_of_timestamp(
    sample_reading: SensorReading,
) -> None:
    # Timestamp is excluded from the fingerprint; window enforcement is the
    # deduplicator's responsibility, not compute_fingerprint's.
    base_ts = 1_700_000_000_000
    r1 = SensorReading(
        sensor_id="current-01",
        sensor_type="current",
        value=8.2,
        unit="ampere",
        timestamp=base_ts,
        quality=1.0,
    )
    r2 = SensorReading(
        sensor_id="current-01",
        sensor_type="current",
        value=8.2,
        unit="ampere",
        timestamp=base_ts + 10_000,  # 10 seconds later — same fingerprint
        quality=1.0,
    )
    assert compute_fingerprint(r1, "dev-01") == compute_fingerprint(r2, "dev-01")


def test_fingerprint_stable_across_bucket_boundary(
    sample_reading: SensorReading,
) -> None:
    # Old approach produced different fingerprints at bucket boundaries for
    # identical readings — this is the regression guard.
    base_ts = 1_700_000_000_000
    next_bucket_ts = ((base_ts // 5000) + 1) * 5000
    r1 = SensorReading(
        sensor_id="current-01",
        sensor_type="current",
        value=8.2,
        unit="ampere",
        timestamp=base_ts,
        quality=1.0,
    )
    r2 = SensorReading(
        sensor_id="current-01",
        sensor_type="current",
        value=8.2,
        unit="ampere",
        timestamp=next_bucket_ts,
        quality=1.0,
    )
    # Fingerprints must be equal — timestamp no longer part of the hash
    assert compute_fingerprint(r1, "dev-01") == compute_fingerprint(r2, "dev-01")


def test_fingerprint_different_for_different_sensor_types() -> None:
    ts = 1_700_000_000_000
    current_reading = SensorReading(
        sensor_id="s-01",
        sensor_type="current",
        value=8.2,
        unit="ampere",
        timestamp=ts,
        quality=1.0,
    )
    voltage_reading = SensorReading(
        sensor_id="s-01",
        sensor_type="voltage",
        value=8.2,
        unit="volt",
        timestamp=ts,
        quality=1.0,
    )
    assert compute_fingerprint(current_reading, "dev-01") != compute_fingerprint(
        voltage_reading, "dev-01"
    )


def test_fingerprint_different_for_different_devices() -> None:
    ts = 1_700_000_000_000
    reading = SensorReading(
        sensor_id="s-01",
        sensor_type="current",
        value=8.2,
        unit="ampere",
        timestamp=ts,
        quality=1.0,
    )
    assert compute_fingerprint(reading, "dev-01") != compute_fingerprint(
        reading, "dev-02"
    )


def test_fingerprint_rounds_value_to_one_decimal() -> None:
    ts = 1_700_000_000_000
    r1 = SensorReading(
        sensor_id="s-01",
        sensor_type="current",
        value=8.24,
        unit="ampere",
        timestamp=ts,
        quality=1.0,
    )
    r2 = SensorReading(
        sensor_id="s-01",
        sensor_type="current",
        value=8.21,
        unit="ampere",
        timestamp=ts,
        quality=1.0,
    )
    # Both round to 8.2
    assert compute_fingerprint(r1, "dev-01") == compute_fingerprint(r2, "dev-01")


def test_fingerprint_different_for_different_sensor_ids() -> None:
    ts = 1_700_000_000_000
    r1 = SensorReading(
        sensor_id="load-current",
        sensor_type="current_clamp",
        value=5.0,
        unit="ampere",
        timestamp=ts,
        quality=1.0,
    )
    r2 = SensorReading(
        sensor_id="grid-current",
        sensor_type="current_clamp",
        value=5.0,
        unit="ampere",
        timestamp=ts,
        quality=1.0,
    )
    assert compute_fingerprint(r1, "dev-01") != compute_fingerprint(r2, "dev-01")


def test_fingerprint_same_for_same_sensor_id_any_timestamp() -> None:
    base_ts = 1_700_000_000_000
    r1 = SensorReading(
        sensor_id="load-current",
        sensor_type="current_clamp",
        value=5.0,
        unit="ampere",
        timestamp=base_ts,
        quality=1.0,
    )
    r2 = SensorReading(
        sensor_id="load-current",
        sensor_type="current_clamp",
        value=5.0,
        unit="ampere",
        timestamp=base_ts + 60_000,  # 60 s later — still same fingerprint
        quality=1.0,
    )
    assert compute_fingerprint(r1, "dev-01") == compute_fingerprint(r2, "dev-01")


def test_fingerprint_is_hex_string() -> None:
    ts = 1_700_000_000_000
    reading = SensorReading(
        sensor_id="s-01",
        sensor_type="current",
        value=8.2,
        unit="ampere",
        timestamp=ts,
        quality=1.0,
    )
    fp = compute_fingerprint(reading, "dev-01")
    assert len(fp) == 64
    int(fp, 16)  # raises ValueError if not valid hex


# ---------------------------------------------------------------------------
# ActionResult
# ---------------------------------------------------------------------------


def test_action_result_tier_a_approved_is_none() -> None:
    result = ActionResult(
        action_name="alert_whatsapp",
        tier=ActionTier.INFORMATIONAL,
        executed=True,
        approved=None,
        action_taken="alert_whatsapp",
        timestamp=1_700_000_000_000,
    )
    assert result.approved is None
    assert result.operator_response is None


def test_action_result_tier_c_approved_true() -> None:
    result = ActionResult(
        action_name="open_safety_circuit",
        tier=ActionTier.HARD_PHYSICAL,
        executed=True,
        approved=True,
        action_taken="open_safety_circuit",
        timestamp=1_700_000_000_000,
        operator_response="YES",
    )
    assert result.approved is True
    assert result.operator_response == "YES"


def test_action_result_tier_c_approved_false_uses_safe_default() -> None:
    result = ActionResult(
        action_name="open_safety_circuit",
        tier=ActionTier.HARD_PHYSICAL,
        executed=False,
        approved=False,
        action_taken="log_to_dashboard",
        timestamp=1_700_000_000_000,
        operator_response="NO",
    )
    assert result.approved is False
    assert result.action_taken == "log_to_dashboard"


# ---------------------------------------------------------------------------
# ReasoningResult
# ---------------------------------------------------------------------------


def test_reasoning_result_action_tier_defaults_to_a() -> None:
    result = ReasoningResult(
        text="All nominal.",
        tier="local_slm",
        model="qwen2.5-0.5b",
        tokens_used=42,
        latency_ms=350,
    )
    assert result.action_tier == "A"


def test_reasoning_result_confidence_defaults_to_zero() -> None:
    result = ReasoningResult(
        text="All nominal.",
        tier="rule",
        model="rule_engine",
        tokens_used=0,
        latency_ms=0,
    )
    assert result.confidence == 0.0


def test_reasoning_result_proposed_action_defaults_to_none() -> None:
    result = ReasoningResult(
        text="All nominal.",
        tier="rule",
        model="rule_engine",
        tokens_used=0,
        latency_ms=0,
    )
    assert result.proposed_action is None


def test_reasoning_result_explicit_fields() -> None:
    result = ReasoningResult(
        text="Overcurrent detected.",
        tier="rule",
        model="rule_engine",
        tokens_used=0,
        latency_ms=1,
        confidence=0.99,
        action_tier="D",
        proposed_action="emergency_cutoff",
    )
    assert result.action_tier == "D"
    assert result.confidence == 0.99
    assert result.proposed_action == "emergency_cutoff"


# ---------------------------------------------------------------------------
# ActionTier constants
# ---------------------------------------------------------------------------


def test_action_tier_constants_are_single_uppercase_chars() -> None:
    for tier in (
        ActionTier.INFORMATIONAL,
        ActionTier.SOFT_PHYSICAL,
        ActionTier.HARD_PHYSICAL,
        ActionTier.SAFETY_CRITICAL,
    ):
        assert len(tier) == 1
        assert tier.isupper()


def test_action_tier_constant_values() -> None:
    assert ActionTier.INFORMATIONAL == "A"
    assert ActionTier.SOFT_PHYSICAL == "B"
    assert ActionTier.HARD_PHYSICAL == "C"
    assert ActionTier.SAFETY_CRITICAL == "D"


def test_action_tier_constants_are_distinct() -> None:
    tiers = {
        ActionTier.INFORMATIONAL,
        ActionTier.SOFT_PHYSICAL,
        ActionTier.HARD_PHYSICAL,
        ActionTier.SAFETY_CRITICAL,
    }
    assert len(tiers) == 4
