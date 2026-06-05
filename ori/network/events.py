# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SensorReading:
    sensor_id: str
    sensor_type: str  # 'temperature' | 'current' | 'voltage' | 'humidity' etc.
    value: float
    unit: str  # 'celsius' | 'ampere' | 'volt' | 'percent' etc.
    timestamp: int  # unix milliseconds, always UTC
    quality: float  # 0.0 to 1.0
    metadata: dict = field(default_factory=dict)
    raw: Optional[bytes] = None


@dataclass
class OriEvent:
    event_id: str
    event_type: str  # 'sensor.reading' | 'device.heartbeat' | 'skill.trigger'
    device_id: str
    sensor_id: str
    timestamp: int  # unix milliseconds, always UTC
    reading: Optional[SensorReading]
    context: dict = field(default_factory=dict)
    source: str = ""  # 'gpio' | 'i2c' | 'serial' | 'mqtt' | 'sysfs' | 'psutil'
    fingerprint: str = ""

    @classmethod
    def from_reading(cls, reading: SensorReading, device_id: str) -> "OriEvent":
        return cls(
            event_id=str(uuid.uuid4()),
            event_type="sensor.reading",
            device_id=device_id,
            sensor_id=reading.sensor_id,
            timestamp=reading.timestamp,
            reading=reading,
            source=reading.metadata.get("source", ""),
        )


@dataclass
class ActionResult:
    """Returned by ActionDispatcher after every action attempt."""

    action_name: str
    tier: str  # 'A' | 'B' | 'C' | 'D'
    executed: bool
    approved: bool | None  # None for Tiers A/B/D (no approval step)
    action_taken: str  # actual action executed (may be safe_default)
    timestamp: int
    operator_response: str | None = None
    proposal_id: str | None = None
    safe_default_used: bool = False
    correlation_id: str = ""


@dataclass
class ReasoningResult:
    """Returned by the Intelligence Elevator after every reasoning call."""

    text: str
    tier: str  # 'rule' | 'local_slm' | 'gateway'
    model: str
    tokens_used: int
    latency_ms: int
    confidence: float = 0.0
    action_tier: str = "A"  # Default: informational only
    proposed_action: str | None = None
    prompt: str = ""  # LLM prompt used to produce this result; "" for rule engine
    reasoning: str = (
        ""  # fuller explanation for Tier C approval messages; falls back to text
    )
    reasoning_status: str = ""  # "complete" | "incomplete" | "skipped"
    correlation_id: str = ""


class ActionTier:
    INFORMATIONAL = "A"
    SOFT_PHYSICAL = "B"
    HARD_PHYSICAL = "C"
    SAFETY_CRITICAL = "D"


def compute_fingerprint(reading: SensorReading, device_id: str) -> str:
    """sha256(device_id + sensor_id + sensor_type + str(round(value, 1)))

    Timestamp is intentionally excluded — deduplication windows are enforced
    by :class:`~ori.network.deduplicator.EventDeduplicator` using
    ``first_seen``, avoiding edge-case leakage at bucket boundaries.
    """
    raw = (
        device_id
        + reading.sensor_id
        + reading.sensor_type
        + str(round(reading.value, 1))
    )
    return hashlib.sha256(raw.encode()).hexdigest()
