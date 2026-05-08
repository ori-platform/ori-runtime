# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import time
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, patch

import pytest

from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning.capability_posture import CapabilityPosture
from ori.reasoning.elevator import IntelligenceElevator, SkillContext, _complexity_score

# ─── Helpers ──────────────────────────────────────────────────────────────────


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
    )


def _event(value: float = 5.0, sensor_type: str = "current_clamp") -> OriEvent:
    return OriEvent.from_reading(
        _reading(value=value, sensor_type=sensor_type), "dev-01"
    )


@dataclass
class FakeSkill:
    name: str = "test-skill"
    triggers: list = field(default_factory=list)
    config: dict = field(default_factory=dict)
    prompts: dict = field(default_factory=dict)
    _actions: dict = field(default_factory=dict)
    actions: dict = field(default_factory=dict)

    def get_default_actions(self, sensor_type: str) -> list[str]:
        return self._actions.get(sensor_type, [])

    def get_default_actions_for_trigger(self, trigger_name: str) -> list[str]:
        defaults = self.actions.get("defaults", {})
        if isinstance(defaults, dict):
            maybe = defaults.get(trigger_name, [])
            if isinstance(maybe, list):
                return maybe
        return self._actions.get(trigger_name, [])

    def is_action_declared(self, action_name: str) -> bool:
        available = self.actions.get("available", [])
        for entry in available:
            if isinstance(entry, dict) and entry.get("name") == action_name:
                return True
            if isinstance(entry, str) and entry == action_name:
                return True
        return False


def _tier_d_skill() -> FakeSkill:
    return FakeSkill(
        triggers=[
            {
                "name": "dangerous_overcurrent",
                "condition": "value > 4.0",
                "action_tier": "D",
                "bypass_llm": True,
                "cooldown_seconds": 0,
            }
        ]
    )


def _tier_a_skill() -> FakeSkill:
    return FakeSkill(
        triggers=[
            {
                "name": "anomalous_draw",
                "condition": "value > 3.0",
                "action_tier": "A",
                "bypass_llm": False,
                "cooldown_seconds": 0,
            }
        ],
        actions={
            "available": [{"name": "alert_whatsapp", "tier": "A"}],
            "defaults": {"anomalous_draw": ["alert_whatsapp"]},
        },
    )


def _mock_state_store(
    avg: float | None = None, history: list | None = None
) -> AsyncMock:
    store = AsyncMock()
    store.avg_last_hours.return_value = avg
    store.get_history.return_value = [_reading(v) for v in (history or [])]
    store.log_reasoning = AsyncMock()
    return store


class _PromptHistoryStore:
    def __init__(self, values_by_sensor: dict[str, list[float]]) -> None:
        self._values_by_sensor = values_by_sensor

    def _run_read_with_conn(self, fn, *args):
        return fn(*args)

    def _avg_last_hours_sync(self, sensor_id: str, _hours: int) -> float | None:
        values = self._values_by_sensor.get(sensor_id, [])
        if not values:
            return None
        return sum(values) / len(values)

    def _avg_last_n_sync(self, sensor_id: str, n: int) -> float | None:
        values = self._values_by_sensor.get(sensor_id, [])[:n]
        if not values:
            return None
        return sum(values) / len(values)

    def _get_history_sync(self, sensor_id: str, limit: int):
        values = self._values_by_sensor.get(sensor_id, [])[:limit]
        return [_reading(value=v, sensor_id=sensor_id) for v in values]


# ─── _complexity_score ────────────────────────────────────────────────────────


class TestComplexityScore:
    def test_no_history_no_avg_returns_zero(self):
        score = _complexity_score(5.0, None, [], hour=12)
        assert score == pytest.approx(0.0)

    def test_large_deviation_increases_score(self):
        # 50% deviation → deviation score = 0.25 → complexity ~0.083
        low = _complexity_score(5.0, 10.0, [], hour=12)
        # 200% deviation → deviation score = 1.0 → complexity ~0.333
        high = _complexity_score(30.0, 10.0, [], hour=12)
        assert high > low

    def test_unusual_hour_increases_score(self):
        normal = _complexity_score(5.0, None, [], hour=12)
        unusual = _complexity_score(5.0, None, [], hour=2)
        assert unusual > normal

    def test_volatile_history_increases_score(self):
        stable = _complexity_score(5.0, 5.0, [5.0, 5.0, 5.0, 5.0], hour=12)
        volatile = _complexity_score(5.0, 5.0, [1.0, 9.0, 2.0, 8.0], hour=12)
        assert volatile > stable

    def test_score_bounded_0_to_1(self):
        score = _complexity_score(100.0, 1.0, [0.1, 200.0, 0.1, 200.0], hour=3)
        assert 0.0 <= score <= 1.0


# ─── select_tier ──────────────────────────────────────────────────────────────


class TestSelectTier:
    async def test_tier_d_rule_returns_rule_immediately(self):
        elevator = IntelligenceElevator()
        skill = _tier_d_skill()
        tier = await elevator.select_tier(_event(value=5.0), skill, None)
        assert tier == "rule"

    async def test_bypass_llm_rule_returns_rule(self):
        elevator = IntelligenceElevator()
        skill = FakeSkill(
            triggers=[
                {
                    "name": "r",
                    "condition": "value > 3.0",
                    "action_tier": "B",
                    "bypass_llm": True,
                    "cooldown_seconds": 0,
                }
            ]
        )
        tier = await elevator.select_tier(_event(value=5.0), skill, None)
        assert tier == "rule"

    async def test_offline_returns_local_slm(self):
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(config=conf)
        skill = FakeSkill()
        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            tier = await elevator.select_tier(_event(), skill, None)
        assert tier == "local_slm"

    async def test_low_complexity_returns_local_slm(self):
        elevator = IntelligenceElevator()
        skill = FakeSkill()
        store = _mock_state_store(avg=5.0, history=[5.0, 5.0, 5.0])
        with patch("ori.reasoning.elevator._is_offline", return_value=False):
            with patch("ori.reasoning.elevator._hour_now", return_value=12):
                tier = await elevator.select_tier(_event(value=5.1), skill, store)
        assert tier == "local_slm"

    async def test_no_state_store_returns_local_slm(self):
        elevator = IntelligenceElevator()
        skill = FakeSkill()
        with patch("ori.reasoning.elevator._is_offline", return_value=False):
            tier = await elevator.select_tier(_event(), skill, None)
        assert tier == "local_slm"

    async def test_tier_d_does_not_reach_state_store(self):
        elevator = IntelligenceElevator()
        skill = _tier_d_skill()
        store = _mock_state_store()
        await elevator.select_tier(_event(value=5.0), skill, store)
        # History not fetched for Tier D — returns immediately
        store.avg_last_hours.assert_not_called()

    async def test_escalate_to_local_slm_floors_tier_when_offline_fallback_is_rule(
        self,
    ):
        conf = type("obj", (object,), {"offline_fallback": "rule"})()
        elevator = IntelligenceElevator(config=conf)
        skill = FakeSkill(
            triggers=[
                {
                    "name": "anomalous_draw",
                    "condition": "value > 3.0",
                    "action_tier": "A",
                    "escalate_to": "local_slm",
                    "bypass_llm": False,
                    "cooldown_seconds": 0,
                }
            ]
        )
        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            tier = await elevator.select_tier(_event(value=5.0), skill, None)
        assert tier == "local_slm"

    async def test_fresh_capability_posture_is_used_without_probe(self):
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(config=conf)
        posture = CapabilityPosture(
            sms_available=True,
            whatsapp_available=True,
            gateway_reachable=False,
            local_slm_loaded=True,
            relay_connected=False,
            internet_available=False,
            checked_at_ms=_ms(),
            expires_at_ms=_ms() + 60_000,
            gateway_last_heartbeat_ms=None,
        )
        elevator.update_capability_posture(posture)
        with patch(
            "ori.reasoning.elevator._is_offline",
            side_effect=AssertionError("offline probe should not run"),
        ):
            tier = await elevator.select_tier(_event(value=5.0), FakeSkill(), None)
        assert tier == "local_slm"


# ─── reason ───────────────────────────────────────────────────────────────────


class TestReason:
    async def test_tier_d_result_has_rule_tier(self):
        elevator = IntelligenceElevator()
        skill = _tier_d_skill()
        result = await elevator.reason(_event(value=5.0), skill, None)
        assert result.tier == "rule"
        assert result.action_tier == "D"

    async def test_tier_d_result_has_rule_name_in_text(self):
        elevator = IntelligenceElevator()
        skill = _tier_d_skill()
        result = await elevator.reason(_event(value=5.0), skill, None)
        assert "dangerous_overcurrent" in result.text

    async def test_local_slm_called_when_available(self):
        mock_llm = AsyncMock()
        mock_llm.reason.return_value = ReasoningResult(
            text="Load is anomalous.",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=20,
            latency_ms=500,
        )
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = FakeSkill()

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            result = await elevator.reason(_event(), skill, None)

        mock_llm.reason.assert_called_once()
        assert result.tier == "local_slm"
        assert result.text == "Load is anomalous."

    async def test_local_slm_prompt_attached_to_result(self):
        """After LLM reasoning, result.prompt is populated with the built prompt."""
        mock_llm = AsyncMock()
        mock_llm.reason.return_value = ReasoningResult(
            text="Load is anomalous.",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=20,
            latency_ms=500,
        )
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = FakeSkill()

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            result = await elevator.reason(_event(), skill, None)

        assert result.prompt != ""
        assert "load-current" in result.prompt  # sensor_id appears in prompt

    async def test_trigger_prompt_template_preferred_over_sensor_prompt(self):
        mock_llm = AsyncMock()
        mock_llm.reason.return_value = ReasoningResult(
            text="ok",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=12,
            latency_ms=100,
        )
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = _tier_a_skill()
        skill.prompts = {
            "anomalous_draw": "TRIGGER_PROMPT",
            "current_clamp": "SENSOR_PROMPT",
        }

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            result = await elevator.reason(_event(value=5.0), skill, None)

        assert "TRIGGER_PROMPT" in result.prompt
        assert "SENSOR_PROMPT" not in result.prompt

    async def test_sensor_prompt_used_when_trigger_prompt_missing(self):
        mock_llm = AsyncMock()
        mock_llm.reason.return_value = ReasoningResult(
            text="ok",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=12,
            latency_ms=100,
        )
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = _tier_a_skill()
        skill.prompts = {"current_clamp": "SENSOR_PROMPT"}

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            result = await elevator.reason(_event(value=5.0), skill, None)

        assert "SENSOR_PROMPT" in result.prompt

    async def test_prompt_template_substitutes_basic_placeholders(self):
        mock_llm = AsyncMock()
        mock_llm.reason.return_value = ReasoningResult(
            text="ok",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=12,
            latency_ms=100,
        )
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = _tier_a_skill()
        skill.prompts = {"anomalous_draw": "Value is {value}{unit} on {device_id}"}
        event = OriEvent.from_reading(
            SensorReading(
                sensor_id="load-current",
                sensor_type="current_clamp",
                value=8.2,
                unit="A",
                timestamp=_ms(),
                quality=1.0,
            ),
            "ikeja-01",
        )

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            result = await elevator.reason(event, skill, None)

        assert "Value is 8.2A on ikeja-01" in result.prompt

    async def test_history_placeholders_substitute_last_n_alias(self):
        mock_llm = AsyncMock()
        mock_llm.reason.return_value = ReasoningResult(
            text="ok",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=12,
            latency_ms=100,
        )
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = _tier_a_skill()
        skill.prompts = {
            "anomalous_draw": "History snapshot: {history.last_n('load-current', 6)}"
        }
        store = _PromptHistoryStore({"load-current": [12.4, 12.5, 12.6]})

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            result = await elevator.reason(_event(value=8.2), skill, store)

        assert "{history.last_n('load-current', 6)}" not in result.prompt
        assert "[12.4,12.5,12.6]" in result.prompt

    async def test_history_placeholder_unsupported_method_stays_literal(self, caplog):
        mock_llm = AsyncMock()
        mock_llm.reason.return_value = ReasoningResult(
            text="ok",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=12,
            latency_ms=100,
        )
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = _tier_a_skill()
        skill.prompts = {
            "anomalous_draw": "Check: {history.not_a_method('load-current', 2)}"
        }
        store = _PromptHistoryStore({"load-current": [1.0, 2.0]})

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            with caplog.at_level(logging.DEBUG):
                result = await elevator.reason(_event(value=8.2), skill, store)

        assert "{history.not_a_method('load-current', 2)}" in result.prompt
        assert "Failed to resolve history placeholder" in caplog.text

    async def test_history_placeholder_avg_hours_is_substituted(self):
        mock_llm = AsyncMock()
        mock_llm.reason.return_value = ReasoningResult(
            text="ok",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=12,
            latency_ms=100,
        )
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = _tier_a_skill()
        skill.prompts = {
            "anomalous_draw": '24h avg: {history.avg_hours("load-current", 24)}'
        }
        store = _PromptHistoryStore({"load-current": [10.0, 14.0]})

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            result = await elevator.reason(_event(value=8.2), skill, store)

        assert '{history.avg_hours("load-current", 24)}' not in result.prompt
        assert "24h avg: 12.0" in result.prompt

    async def test_history_placeholder_malformed_expression_stays_literal(self):
        mock_llm = AsyncMock()
        mock_llm.reason.return_value = ReasoningResult(
            text="ok",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=12,
            latency_ms=100,
        )
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = _tier_a_skill()
        skill.prompts = {
            "anomalous_draw": "Broken: {history.last_n(sensor_id='load-current', n=2)}"
        }
        store = _PromptHistoryStore({"load-current": [10.0, 14.0]})

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            result = await elevator.reason(_event(value=8.2), skill, store)

        assert "{history.last_n(sensor_id='load-current', n=2)}" in result.prompt

    async def test_prompt_template_sanitizes_malicious_sensor_id(self):
        mock_llm = AsyncMock()
        mock_llm.reason.return_value = ReasoningResult(
            text="ok",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=12,
            latency_ms=100,
        )
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = _tier_a_skill()
        skill.prompts = {"anomalous_draw": "Sensor reference: {sensor_id}"}
        event = OriEvent.from_reading(
            SensorReading(
                sensor_id="{malicious: inject}",
                sensor_type="current_clamp",
                value=8.2,
                unit="A",
                timestamp=_ms(),
                quality=1.0,
            ),
            "ikeja-01",
        )

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            result = await elevator.reason(event, skill, None)

        assert "{malicious: inject}" not in result.prompt
        assert "malicious inject" in result.prompt

    async def test_rejection_note_strips_operator_reply_angle_brackets(self):
        mock_llm = AsyncMock()
        mock_llm.reason.return_value = ReasoningResult(
            text="ok",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=12,
            latency_ms=100,
        )
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = _tier_a_skill()

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            with patch.object(
                elevator,
                "_lookup_rejection_record",
                new=AsyncMock(return_value={"operator_response": "<override safety>"}),
            ):
                result = await elevator.reason(_event(value=5.0), skill, None)

        assert "<override safety>" not in result.prompt
        assert "override safety" in result.prompt

    async def test_rejection_note_keeps_normal_operator_reply_text(self):
        mock_llm = AsyncMock()
        mock_llm.reason.return_value = ReasoningResult(
            text="ok",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=12,
            latency_ms=100,
        )
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = _tier_a_skill()

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            with patch.object(
                elevator,
                "_lookup_rejection_record",
                new=AsyncMock(
                    return_value={"operator_response": "yes, proceed with caution"}
                ),
            ):
                result = await elevator.reason(_event(value=5.0), skill, None)

        assert "yes, proceed with caution" in result.prompt

    def test_sanitize_prompt_input_coerces_float_to_string(self):
        elevator = IntelligenceElevator()
        assert elevator._sanitize_prompt_input(12.5) == "12.5"

    async def test_rule_engine_result_has_empty_prompt(self):
        """Rule engine (Tier D, bypass_llm=True) must leave prompt as empty string."""
        elevator = IntelligenceElevator()
        skill = _tier_d_skill()

        result = await elevator.reason(_event(value=5.0), skill, None)

        assert result.tier == "rule"
        assert result.action_tier == "D"
        assert result.prompt == ""

    async def test_local_slm_failure_falls_back_to_stub(self):
        mock_llm = AsyncMock()
        mock_llm.reason.side_effect = RuntimeError("model crashed")
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=mock_llm, config=conf)
        skill = FakeSkill()

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            result = await elevator.reason(_event(), skill, None)

        # Must not raise — returns a stub result
        assert result.model == "stub"
        assert result.action_tier == "A"

    async def test_no_llm_returns_stub(self):
        conf = type("obj", (object,), {"offline_fallback": "local_slm"})()
        elevator = IntelligenceElevator(local_llm=None, config=conf)
        skill = FakeSkill()

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            result = await elevator.reason(_event(), skill, None)

        assert result.model == "stub"

    async def test_returns_reasoning_result_instance(self):
        elevator = IntelligenceElevator()
        result = await elevator.reason(_event(), FakeSkill(), None)
        assert isinstance(result, ReasoningResult)


# ─── reason_and_dispatch ──────────────────────────────────────────────────────


class TestReasonAndDispatch:
    async def test_dispatcher_called_with_actions(self):
        mock_dispatcher = AsyncMock()
        skill = _tier_a_skill()
        elevator = IntelligenceElevator()

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            await elevator.reason_and_dispatch(
                _event(value=5.0), skill, None, mock_dispatcher
            )

        mock_dispatcher.dispatch.assert_called_once()
        call = mock_dispatcher.dispatch.call_args
        assert call[1]["action"] == "alert_whatsapp"

    async def test_action_tier_from_result_passed_to_dispatcher(self):
        """The tier passed to dispatcher comes from ReasoningResult, not hardcoded."""
        mock_dispatcher = AsyncMock()
        skill = _tier_d_skill()
        skill.actions = {
            "available": [{"name": "emergency_cutoff", "tier": "D"}],
            "defaults": {"dangerous_overcurrent": ["emergency_cutoff"]},
        }
        elevator = IntelligenceElevator()

        await elevator.reason_and_dispatch(
            _event(value=5.0), skill, None, mock_dispatcher
        )

        call = mock_dispatcher.dispatch.call_args
        assert call[1]["tier"] == "D"

    async def test_approval_timeout_from_trigger_passed_to_dispatcher(self):
        mock_dispatcher = AsyncMock()
        skill = FakeSkill(
            triggers=[
                {
                    "name": "sleep_blocked_terminate_candidate",
                    "condition": "value > 3.0",
                    "action_tier": "C",
                    "bypass_llm": False,
                    "cooldown_seconds": 0,
                    "approval_timeout_seconds": 60,
                }
            ],
            actions={
                "available": [{"name": "terminate_process", "tier": "C"}],
                "defaults": {
                    "sleep_blocked_terminate_candidate": ["terminate_process"]
                },
            },
        )
        elevator = IntelligenceElevator()
        event = _event(value=5.0)
        event.context = {"__handler_trigger_name": "sleep_blocked_terminate_candidate"}

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            await elevator.reason_and_dispatch(event, skill, None, mock_dispatcher)

        call = mock_dispatcher.dispatch.call_args
        assert call[1]["approval_timeout"] == 60

    async def test_reason_and_dispatch_clamps_result_tier_to_trigger_tier(self):
        mock_dispatcher = AsyncMock()
        skill = _tier_a_skill()
        elevator = IntelligenceElevator()

        with patch.object(
            elevator,
            "reason",
            return_value=ReasoningResult(
                text="injected",
                tier="local_slm",
                model="stub",
                tokens_used=0,
                latency_ms=0,
                action_tier="D",
            ),
        ):
            await elevator.reason_and_dispatch(
                _event(value=5.0), skill, None, mock_dispatcher
            )

        call = mock_dispatcher.dispatch.call_args
        assert call[1]["tier"] == "A"

    async def test_exception_in_reason_is_caught(self):
        """A crash inside reason() must not propagate from reason_and_dispatch."""
        mock_dispatcher = AsyncMock()
        elevator = IntelligenceElevator()

        with patch.object(elevator, "reason", side_effect=RuntimeError("boom")):
            # Must not raise
            await elevator.reason_and_dispatch(
                _event(), FakeSkill(), None, mock_dispatcher
            )

        mock_dispatcher.dispatch.assert_not_called()

    async def test_exception_in_dispatcher_is_caught(self):
        mock_dispatcher = AsyncMock()
        mock_dispatcher.dispatch.side_effect = RuntimeError("dispatch boom")
        skill = _tier_a_skill()
        elevator = IntelligenceElevator()

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            # Must not raise
            await elevator.reason_and_dispatch(
                _event(value=5.0), skill, None, mock_dispatcher
            )

    async def test_reasoning_logged_when_store_has_log_reasoning(self):
        store = _mock_state_store()
        skill = _tier_a_skill()
        elevator = IntelligenceElevator()
        mock_dispatcher = AsyncMock()

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            await elevator.reason_and_dispatch(
                _event(value=5.0), skill, store, mock_dispatcher
            )

        store.log_reasoning.assert_called_once()

    async def test_no_actions_dispatcher_not_called(self):
        """If the skill has no default actions, dispatch is never called."""
        mock_dispatcher = AsyncMock()
        skill = FakeSkill()  # no _actions configured
        elevator = IntelligenceElevator()

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            await elevator.reason_and_dispatch(_event(), skill, None, mock_dispatcher)

        mock_dispatcher.dispatch.assert_not_called()

    async def test_actions_selected_by_matched_trigger_not_sensor_type(self):
        mock_dispatcher = AsyncMock()
        skill = FakeSkill(
            triggers=[
                {
                    "name": "minor",
                    "condition": "value > 100.0",
                    "action_tier": "A",
                    "bypass_llm": False,
                    "cooldown_seconds": 0,
                },
                {
                    "name": "major",
                    "condition": "value > 7.0",
                    "action_tier": "A",
                    "bypass_llm": False,
                    "cooldown_seconds": 0,
                },
            ],
            actions={
                "available": [
                    {"name": "alert_whatsapp", "tier": "A"},
                    {"name": "log_to_dashboard", "tier": "A"},
                ],
                "defaults": {
                    "minor": ["alert_whatsapp"],
                    "major": ["log_to_dashboard"],
                },
            },
        )
        elevator = IntelligenceElevator()
        event = _event(value=8.0)
        # Ensure "major" is the matched rule for this event.
        event.context = {"__handler_trigger_name": "major"}

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            await elevator.reason_and_dispatch(event, skill, None, mock_dispatcher)

        call = mock_dispatcher.dispatch.call_args
        assert call[1]["action"] == "log_to_dashboard"

    async def test_no_rule_match_dispatches_nothing(self):
        mock_dispatcher = AsyncMock()
        skill = FakeSkill(
            triggers=[
                {
                    "name": "never",
                    "condition": "value > 100.0",
                    "action_tier": "A",
                    "bypass_llm": False,
                    "cooldown_seconds": 0,
                }
            ],
            actions={
                "available": [{"name": "alert_whatsapp", "tier": "A"}],
                "defaults": {"never": ["alert_whatsapp"]},
            },
        )
        elevator = IntelligenceElevator()
        event = _event(value=5.0)
        event.context = {"__handler_trigger_name": "never"}

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            await elevator.reason_and_dispatch(event, skill, None, mock_dispatcher)

        mock_dispatcher.dispatch.assert_not_called()

    async def test_skill_context_passed_to_dispatcher(self):
        mock_dispatcher = AsyncMock()
        skill = _tier_a_skill()
        elevator = IntelligenceElevator()
        store = _mock_state_store()

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            await elevator.reason_and_dispatch(
                _event(value=5.0), skill, store, mock_dispatcher
            )

        call = mock_dispatcher.dispatch.call_args
        ctx = call[1]["context"]
        assert isinstance(ctx, SkillContext)
        assert ctx.skill is skill

    async def test_reason_and_dispatch_is_safe_as_create_task(self):
        """Verify the coroutine can be wrapped in create_task without issues."""
        mock_dispatcher = AsyncMock()
        skill = FakeSkill()
        elevator = IntelligenceElevator()

        with patch("ori.reasoning.elevator._is_offline", return_value=True):
            task = asyncio.create_task(
                elevator.reason_and_dispatch(_event(), skill, None, mock_dispatcher)
            )
            await task  # must complete without raising

    async def test_reason_and_dispatch_catches_safety_error_and_dispatches_tier_a(self):
        """A RuleEngineSafetyError must be caught and routed as a Tier A synthetic event."""
        from ori.reasoning.rule_engine import RuleEngineSafetyError

        mock_dispatcher = AsyncMock()
        elevator = IntelligenceElevator()
        skill = FakeSkill()
        # Mock some actions to verify sms inclusion if available
        skill._actions = {}
        skill.actions = {"available": [{"name": "alert_sms", "tier": "A"}]}

        with patch.object(
            elevator, "reason", side_effect=RuleEngineSafetyError("NaN in reading")
        ):
            await elevator.reason_and_dispatch(_event(), skill, None, mock_dispatcher)

        # It should dispatch Tier A fallback for whatsapp and sms
        assert mock_dispatcher.dispatch.call_count == 2
        calls = mock_dispatcher.dispatch.call_args_list
        actions_called = [call[1]["action"] for call in calls]
        assert "alert_whatsapp" in actions_called
        assert "alert_sms" in actions_called

        for call in calls:
            assert call[1]["tier"] == "A"
            assert (
                "Sensor safety check failed: NaN in reading" in call[1]["result"].text
            )
            ctx = call[1]["context"]
            assert ctx.event.event_type == "sensor.invalid_value"


# ─── SkillContext ─────────────────────────────────────────────────────────────


class TestSkillContext:
    def test_fields_accessible(self):
        skill = FakeSkill()
        event = _event()
        ctx = SkillContext(skill=skill, event=event, state_store=None)
        assert ctx.skill is skill
        assert ctx.event is event
        assert ctx.state_store is None
