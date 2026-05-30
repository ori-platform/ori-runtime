# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import datetime
import time
from dataclasses import dataclass, field
from unittest.mock import AsyncMock

import pytest

from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.elevator import IntelligenceElevator, SkillContext
from ori.state.store import StateStore


def _ms() -> int:
    return int(time.time() * 1000)


def _reading(
    value: float = 5.0,
    sensor_id: str = "load-current",
    sensor_type: str = "current_clamp",
) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit="ampere",
        timestamp=_ms(),
        quality=1.0,
        metadata={"source": "psutil"},
    )


def _event(value: float = 5.0, timestamp_ms: int | None = None) -> OriEvent:
    r = _reading(value=value)
    if timestamp_ms is not None:
        r.timestamp = timestamp_ms
    return OriEvent.from_reading(r, device_id="dev-01")


@dataclass
class _FakeSkill:
    name: str = "rejection-skill"
    triggers: list = field(
        default_factory=lambda: [
            {
                "name": "overcurrent_trip",
                "condition": "value > 3.0",
                "action_tier": "C",
                "bypass_llm": False,
                "cooldown_seconds": 0,
            }
        ]
    )
    actions: dict = field(
        default_factory=lambda: {
            "available": [
                {"name": "open_safety_circuit", "tier": "C"},
                {"name": "alert_whatsapp", "tier": "A"},
            ],
            "defaults": {"overcurrent_trip": ["open_safety_circuit", "alert_whatsapp"]},
        }
    )
    prompts: dict = field(default_factory=dict)
    config: dict = field(default_factory=dict)

    def get_default_actions_for_trigger(self, trigger_name: str) -> list[str]:
        defaults = self.actions.get("defaults", {})
        if isinstance(defaults, dict):
            maybe = defaults.get(trigger_name, [])
            if isinstance(maybe, list):
                return maybe
        return []

    def is_action_declared(self, action_name: str) -> bool:
        for entry in self.actions.get("available", []):
            if isinstance(entry, dict) and entry.get("name") == action_name:
                return True
        return False


@pytest.fixture
async def store(tmp_path):
    s = StateStore(db_path=str(tmp_path / "rejection.db"))
    await s.open()
    yield s
    await s.close()


def _elevator_config() -> object:
    return type(
        "Cfg",
        (object,),
        {
            "offline_fallback": "local_slm",
            "escalation_threshold": 0.7,
            "causal_memory": {"rejection_expiry_days": 30},
        },
    )()


class TestRejectionMemory:
    @pytest.mark.asyncio
    async def test_store_and_lookup_rejection(self, store):
        await store.store_rejection(
            pattern_key="abc123",
            trigger_name="overcurrent_trip",
            proposed_action="open_safety_circuit",
            operator_response="no scheduled load test",
            device_id="dev-01",
            sensor_type="current_clamp",
            value_bucket=7.5,
            time_of_day_hour=2,
            day_of_week=3,
            expiry_days=30,
        )
        row = await store.lookup_rejection("abc123")
        assert row is not None
        assert row["pattern_key"] == "abc123"
        assert row["trigger_name"] == "overcurrent_trip"
        assert row["proposed_action"] == "open_safety_circuit"
        assert row["operator_response"] == "no scheduled load test"

    def test_pattern_key_bucketing(self):
        ts = int(
            datetime.datetime(
                2026, 1, 1, 2, 30, tzinfo=datetime.timezone.utc
            ).timestamp()
            * 1000
        )
        k1 = StateStore._build_rejection_pattern_key(
            "current_clamp", "overcurrent_trip", "open_safety_circuit", 10.1, ts
        )
        k2 = StateStore._build_rejection_pattern_key(
            "current_clamp", "overcurrent_trip", "open_safety_circuit", 10.2, ts
        )
        k3 = StateStore._build_rejection_pattern_key(
            "current_clamp", "overcurrent_trip", "open_safety_circuit", 11.2, ts
        )
        assert k1 == k2
        assert k1 != k3

    def test_time_bucketing(self):
        ts_2am = int(
            datetime.datetime(
                2026, 1, 1, 2, 0, tzinfo=datetime.timezone.utc
            ).timestamp()
            * 1000
        )
        ts_3am = int(
            datetime.datetime(
                2026, 1, 1, 3, 0, tzinfo=datetime.timezone.utc
            ).timestamp()
            * 1000
        )
        ts_5am = int(
            datetime.datetime(
                2026, 1, 1, 5, 0, tzinfo=datetime.timezone.utc
            ).timestamp()
            * 1000
        )
        k_2 = StateStore._build_rejection_pattern_key(
            "current_clamp", "overcurrent_trip", "open_safety_circuit", 10.0, ts_2am
        )
        k_3 = StateStore._build_rejection_pattern_key(
            "current_clamp", "overcurrent_trip", "open_safety_circuit", 10.0, ts_3am
        )
        k_5 = StateStore._build_rejection_pattern_key(
            "current_clamp", "overcurrent_trip", "open_safety_circuit", 10.0, ts_5am
        )
        assert k_2 == k_3
        assert k_2 != k_5

    @pytest.mark.asyncio
    async def test_rejection_caps_at_tier_a(self, store, monkeypatch):
        event = _event(value=5.0)
        skill = _FakeSkill()
        pattern_key = store._build_rejection_pattern_key(
            event.reading.sensor_type,
            "overcurrent_trip",
            "open_safety_circuit",
            event.reading.value,
            event.timestamp,
        )
        await store.store_rejection(
            pattern_key=pattern_key,
            trigger_name="overcurrent_trip",
            proposed_action="open_safety_circuit",
            operator_response="scheduled overnight run",
            device_id=event.device_id,
            sensor_type=event.reading.sensor_type,
            value_bucket=round(event.reading.value * 2) / 2.0,
            time_of_day_hour=2,
            day_of_week=3,
            expiry_days=30,
        )

        llm = AsyncMock()
        llm.reason.return_value = ReasoningResult(
            text="open safety circuit now",
            tier="local_slm",
            model="qwen",
            tokens_used=10,
            latency_ms=120,
            confidence=0.8,
            action_tier="C",
            proposed_action="open_safety_circuit",
        )
        elevator = IntelligenceElevator(local_llm=llm, config=_elevator_config())

        monkeypatch.setattr("ori.reasoning.elevator._is_offline", lambda: True)
        result = await elevator.reason(event, skill, store)
        assert result.action_tier == "A"

    @pytest.mark.asyncio
    async def test_expired_rejection_ignored(self, store, monkeypatch):
        event = _event(value=5.0)
        skill = _FakeSkill()
        pattern_key = store._build_rejection_pattern_key(
            event.reading.sensor_type,
            "overcurrent_trip",
            "open_safety_circuit",
            event.reading.value,
            event.timestamp,
        )
        await store.store_rejection(
            pattern_key=pattern_key,
            trigger_name="overcurrent_trip",
            proposed_action="open_safety_circuit",
            operator_response="old rejection",
            device_id=event.device_id,
            sensor_type=event.reading.sensor_type,
            value_bucket=round(event.reading.value * 2) / 2.0,
            time_of_day_hour=2,
            day_of_week=3,
            expiry_days=1,
        )
        now = _ms()
        monkeypatch.setattr("ori.state.store.now_ms", lambda: now + (3 * 86_400_000))

        llm = AsyncMock()
        llm.reason.return_value = ReasoningResult(
            text="open safety circuit now",
            tier="local_slm",
            model="qwen",
            tokens_used=10,
            latency_ms=120,
            confidence=0.8,
            action_tier="C",
            proposed_action="open_safety_circuit",
        )
        elevator = IntelligenceElevator(local_llm=llm, config=_elevator_config())
        monkeypatch.setattr("ori.reasoning.elevator._is_offline", lambda: True)
        result = await elevator.reason(event, skill, store)
        assert result.action_tier == "C"

    @pytest.mark.asyncio
    async def test_rejection_context_in_prompt(self, store, monkeypatch):
        event = _event(value=5.0)
        pattern_key = store._build_rejection_pattern_key(
            event.reading.sensor_type,
            "overcurrent_trip",
            "open_safety_circuit",
            event.reading.value,
            event.timestamp,
        )
        await store.store_rejection(
            pattern_key=pattern_key,
            trigger_name="overcurrent_trip",
            proposed_action="open_safety_circuit",
            operator_response="scheduled run",
            device_id=event.device_id,
            sensor_type=event.reading.sensor_type,
            value_bucket=round(event.reading.value * 2) / 2.0,
            time_of_day_hour=2,
            day_of_week=3,
            expiry_days=30,
        )

        llm = AsyncMock()
        llm.reason.return_value = ReasoningResult(
            text="alert only",
            tier="local_slm",
            model="qwen",
            tokens_used=10,
            latency_ms=120,
            confidence=0.8,
            action_tier="C",
            proposed_action="open_safety_circuit",
        )
        elevator = IntelligenceElevator(local_llm=llm, config=_elevator_config())
        monkeypatch.setattr("ori.reasoning.elevator._is_offline", lambda: True)

        result = await elevator.reason(event, _FakeSkill(), store)
        assert "previously rejected by the operator" in result.prompt
        assert "scheduled run" in result.prompt

    @pytest.mark.asyncio
    async def test_approval_does_not_create_rejection(self):
        mock_sender = AsyncMock()
        mock_sender.send = AsyncMock(return_value=True)
        mock_sender.listen_for_response = AsyncMock(return_value="YES")

        store = AsyncMock()
        dispatcher = ActionDispatcher(
            state_store=store,
            alert_sender=mock_sender,
            config={
                "operator_contact": "+2340000000",
                "approval_timeout_seconds": 30,
                "rejection_expiry_days": 30,
            },
        )
        ctx = SkillContext(
            skill=_FakeSkill(), event=_event(value=5.0), state_store=store
        )
        res = ReasoningResult(
            text="open safety circuit",
            tier="local_slm",
            model="qwen",
            tokens_used=8,
            latency_ms=50,
            confidence=0.9,
            action_tier="C",
            proposed_action="open_safety_circuit",
        )
        await dispatcher.dispatch(
            action="open_safety_circuit",
            tier="C",
            context=ctx,
            result=res,
        )
        store.store_rejection.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_response_creates_rejection_record(self, store):
        mock_sender = AsyncMock()
        mock_sender.send = AsyncMock(return_value=True)
        mock_sender.listen_for_response = AsyncMock(return_value="NO")

        dispatcher = ActionDispatcher(
            state_store=store,
            alert_sender=mock_sender,
            config={
                "operator_contact": "+2340000000",
                "approval_timeout_seconds": 30,
                "rejection_expiry_days": 30,
            },
        )
        evt = _event(value=5.0)
        evt.context["__handler_trigger_name"] = "overcurrent_trip"
        ctx = SkillContext(skill=_FakeSkill(), event=evt, state_store=store)
        res = ReasoningResult(
            text="open safety circuit",
            tier="local_slm",
            model="qwen",
            tokens_used=8,
            latency_ms=50,
            confidence=0.9,
            action_tier="C",
            proposed_action="open_safety_circuit",
        )
        await dispatcher.dispatch(
            action="open_safety_circuit",
            tier="C",
            context=ctx,
            result=res,
        )
        key = store._build_rejection_pattern_key(
            evt.reading.sensor_type,
            "overcurrent_trip",
            "open_safety_circuit",
            evt.reading.value,
            evt.timestamp,
        )
        row = await store.lookup_rejection(key)
        assert row is not None
