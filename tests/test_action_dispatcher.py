# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import time
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, patch

from ori.network.events import (
    ActionResult,
    ActionTier,
    OriEvent,
    ReasoningResult,
    SensorReading,
)
from ori.policy.device_policy import DevicePolicy
from ori.reasoning.action_dispatcher import ActionDispatcher, _parse_approval_response
from ori.reasoning.capability_posture import CapabilityPosture
from ori.reasoning.elevator import SkillContext

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _ms() -> int:
    return int(time.time() * 1000)


def _reading(value: float = 5.0) -> SensorReading:
    return SensorReading(
        sensor_id="load-current",
        sensor_type="current_clamp",
        value=value,
        unit="ampere",
        timestamp=_ms(),
        quality=1.0,
    )


def _event() -> OriEvent:
    return OriEvent.from_reading(_reading(), "dev-01")


@dataclass
class FakeSkill:
    name: str = "test-skill"
    config: dict = field(default_factory=dict)
    actions: dict = field(default_factory=dict)


def _context(
    skill_config: dict | None = None, actions: dict | None = None
) -> SkillContext:
    skill = FakeSkill(config=skill_config or {}, actions=actions or {})
    return SkillContext(skill=skill, event=_event(), state_store=None)


def _result(
    text: str = "Load is 40% above baseline.",
    confidence: float = 0.85,
    action_tier: str = "A",
) -> ReasoningResult:
    return ReasoningResult(
        text=text,
        tier="local_slm",
        model="qwen.gguf",
        tokens_used=20,
        latency_ms=500,
        confidence=confidence,
        action_tier=action_tier,
    )


def _mock_store() -> AsyncMock:
    store = AsyncMock()
    store.log_action = AsyncMock(return_value=None)
    return store


# ─── _parse_approval_response (module-level) ──────────────────────────────────


class TestParseApprovalResponse:
    def test_yes_returns_true(self):
        assert _parse_approval_response("YES") is True

    def test_y_returns_true(self):
        assert _parse_approval_response("Y") is True

    def test_approve_returns_true(self):
        assert _parse_approval_response("approve") is True

    def test_go_returns_true(self):
        assert _parse_approval_response("go") is True

    def test_no_returns_false(self):
        assert _parse_approval_response("NO") is False

    def test_cancel_returns_false(self):
        assert _parse_approval_response("cancel") is False

    def test_none_returns_false(self):
        assert _parse_approval_response(None) is False

    def test_gibberish_returns_false(self):
        assert _parse_approval_response("maybe") is False

    def test_case_insensitive(self):
        assert _parse_approval_response("Yes") is True
        assert _parse_approval_response("YES") is True
        assert _parse_approval_response("yes") is True

    def test_strips_whitespace(self):
        assert _parse_approval_response("  yes  ") is True


# ─── Tier A — executes immediately ────────────────────────────────────────────


class TestTierA:
    async def test_executes_immediately(self):
        d = ActionDispatcher()
        result = await d.dispatch(
            "alert_whatsapp", ActionTier.INFORMATIONAL, _context(), _result()
        )
        assert result.executed is True

    async def test_approved_is_none(self):
        d = ActionDispatcher()
        result = await d.dispatch(
            "alert_whatsapp", ActionTier.INFORMATIONAL, _context(), _result()
        )
        assert result.approved is None

    async def test_action_name_in_result(self):
        d = ActionDispatcher()
        result = await d.dispatch(
            "alert_whatsapp", ActionTier.INFORMATIONAL, _context(), _result()
        )
        assert result.action_name == "alert_whatsapp"

    async def test_tier_in_result(self):
        d = ActionDispatcher()
        result = await d.dispatch(
            "alert_sms", ActionTier.INFORMATIONAL, _context(), _result()
        )
        assert result.tier == ActionTier.INFORMATIONAL

    async def test_registered_executor_called(self):
        mock_exec = AsyncMock()
        d = ActionDispatcher()
        d.register_executor("alert_whatsapp", mock_exec)
        ctx = _context()
        await d.dispatch("alert_whatsapp", ActionTier.INFORMATIONAL, ctx, _result())
        mock_exec.assert_awaited_once_with("alert_whatsapp", ctx)

    async def test_no_executor_still_returns_executed_true(self):
        """No executor registered → logs intent only, but executed=True."""
        d = ActionDispatcher()
        result = await d.dispatch(
            "unknown_action", ActionTier.INFORMATIONAL, _context(), _result()
        )
        assert result.executed is True

    async def test_logged_to_state_store(self):
        store = _mock_store()
        ctx = SkillContext(skill=FakeSkill(), event=_event(), state_store=store)
        d = ActionDispatcher()
        await d.dispatch("alert_whatsapp", ActionTier.INFORMATIONAL, ctx, _result())
        store.log_action.assert_awaited_once()

    async def test_returns_action_result_instance(self):
        d = ActionDispatcher()
        result = await d.dispatch(
            "log_to_dashboard", ActionTier.INFORMATIONAL, _context(), _result()
        )
        assert isinstance(result, ActionResult)


# ─── Tier D — executes immediately, safety-critical ──────────────────────────


class TestTierD:
    async def test_executes_immediately(self):
        d = ActionDispatcher()
        result = await d.dispatch(
            "emergency_cutoff", ActionTier.SAFETY_CRITICAL, _context(), _result()
        )
        assert result.executed is True

    async def test_approved_is_none(self):
        d = ActionDispatcher()
        result = await d.dispatch(
            "emergency_cutoff", ActionTier.SAFETY_CRITICAL, _context(), _result()
        )
        assert result.approved is None

    async def test_tier_d_in_result(self):
        d = ActionDispatcher()
        result = await d.dispatch(
            "emergency_cutoff", ActionTier.SAFETY_CRITICAL, _context(), _result()
        )
        assert result.tier == ActionTier.SAFETY_CRITICAL

    async def test_registered_executor_called(self):
        mock_exec = AsyncMock()
        d = ActionDispatcher()
        d.register_executor("emergency_cutoff", mock_exec)
        ctx = _context()
        await d.dispatch("emergency_cutoff", ActionTier.SAFETY_CRITICAL, ctx, _result())
        mock_exec.assert_awaited_once()

    async def test_bypasses_approval_workflow(self):
        d = ActionDispatcher()
        with patch.object(d, "_approval_workflow", new=AsyncMock()) as mock_wf:
            await d.dispatch(
                "emergency_cutoff", ActionTier.SAFETY_CRITICAL, _context(), _result()
            )
        mock_wf.assert_not_awaited()

    async def test_tier_d_tasks_are_tracked_without_task_attribute_hacks(self):
        running_flags: list[bool] = []
        started = asyncio.Event()
        release = asyncio.Event()

        async def _capturing_executor(action, context):
            running_flags.append(
                asyncio.current_task() in d.get_inflight_tier_d_tasks()
            )
            started.set()
            await release.wait()

        d = ActionDispatcher()
        d.register_executor("emergency_cutoff", _capturing_executor)

        dispatch_task = asyncio.create_task(
            d.dispatch(
                "emergency_cutoff", ActionTier.SAFETY_CRITICAL, _context(), _result()
            )
        )
        await started.wait()
        assert running_flags == [True]
        assert len(d.get_inflight_tier_d_tasks()) == 1

        release.set()
        await dispatch_task
        assert d.get_inflight_tier_d_tasks() == set()

    async def test_executor_failure_logs_critical_and_calls_emergency_sms(self):
        """When a Tier D executor raises, logger.critical fires and
        _emergency_sms is awaited — _emergency_sms is mocked to avoid
        real SMS calls."""

        async def _failing_executor(action, context):
            raise RuntimeError("relay hardware fault")

        d = ActionDispatcher(config={"operator_contact": "+234000000000"})
        d.register_executor("emergency_cutoff", _failing_executor)

        with (
            patch.object(d, "_emergency_sms", new=AsyncMock()) as mock_sms,
            patch("ori.reasoning.action_dispatcher.logger") as mock_logger,
        ):
            result = await d.dispatch(
                "emergency_cutoff", ActionTier.SAFETY_CRITICAL, _context(), _result()
            )

        assert result.executed is False

        # logger.critical must have been called (at least the TIER D FAILED message)
        critical_messages = [
            str(call.args) for call in mock_logger.critical.call_args_list
        ]
        assert any("TIER D ACTION FAILED" in msg for msg in critical_messages), (
            f"Expected 'TIER D ACTION FAILED' in critical log calls: {critical_messages}"
        )

        # _emergency_sms must have been awaited with the action name and device_id
        mock_sms.assert_awaited_once()
        call_args = mock_sms.call_args
        assert call_args.args[0] == "emergency_cutoff"


# ─── Tier B — autonomous by default ──────────────────────────────────────────


class TestTierBAutonomous:
    async def test_executes_without_approval_by_default(self):
        d = ActionDispatcher()
        ctx = _context(skill_config={})
        result = await d.dispatch(
            "switch_power_source", ActionTier.SOFT_PHYSICAL, ctx, _result()
        )
        assert result.executed is True
        assert result.approved is None

    async def test_requires_approval_false_executes_immediately(self):
        d = ActionDispatcher()
        ctx = _context(skill_config={"requires_approval": False})
        result = await d.dispatch(
            "switch_power_source", ActionTier.SOFT_PHYSICAL, ctx, _result()
        )
        assert result.approved is None

    async def test_executor_called_for_tier_b(self):
        mock_exec = AsyncMock()
        d = ActionDispatcher()
        d.register_executor("switch_power_source", mock_exec)
        ctx = _context()
        await d.dispatch(
            "switch_power_source", ActionTier.SOFT_PHYSICAL, ctx, _result()
        )
        mock_exec.assert_awaited_once()


# ─── Tier B with requires_approval=True → approval workflow ──────────────────


class TestTierBWithApproval:
    async def test_calls_approval_workflow_when_configured(self):
        d = ActionDispatcher()
        ctx = _context(skill_config={"requires_approval": True})

        with patch.object(
            d,
            "_approval_workflow",
            new=AsyncMock(
                return_value=ActionResult(
                    action_name="switch_power_source",
                    tier=ActionTier.SOFT_PHYSICAL,
                    executed=True,
                    approved=True,
                    action_taken="switch_power_source",
                    timestamp=_ms(),
                )
            ),
        ) as mock_wf:
            result = await d.dispatch(
                "switch_power_source",
                ActionTier.SOFT_PHYSICAL,
                ctx,
                _result(),
            )

        mock_wf.assert_awaited_once()
        assert result.approved is True

    async def test_does_not_call_approval_without_config(self):
        d = ActionDispatcher()
        ctx = _context(skill_config={})

        with patch.object(d, "_approval_workflow", new=AsyncMock()) as mock_wf:
            await d.dispatch(
                "switch_power_source", ActionTier.SOFT_PHYSICAL, ctx, _result()
            )

        mock_wf.assert_not_awaited()


# ─── Tier C — approval workflow ALWAYS ───────────────────────────────────────


class TestTierC:
    async def test_always_calls_approval_workflow(self):
        d = ActionDispatcher()
        ctx = _context()

        with patch.object(
            d,
            "_approval_workflow",
            new=AsyncMock(
                return_value=ActionResult(
                    action_name="trip_main_breaker",
                    tier=ActionTier.HARD_PHYSICAL,
                    executed=False,
                    approved=False,
                    action_taken="log_to_dashboard",
                    timestamp=_ms(),
                )
            ),
        ) as mock_wf:
            await d.dispatch(
                "trip_main_breaker", ActionTier.HARD_PHYSICAL, ctx, _result()
            )

        mock_wf.assert_awaited_once()

    async def test_tier_c_with_yes_response_executes_action(self):
        d = ActionDispatcher()
        mock_sender = AsyncMock()
        d._alert_sender = mock_sender
        d._config = {"operator_contact": "+234800000000"}
        ctx = _context()

        with patch.object(d, "_listen_for_response", new=AsyncMock(return_value="YES")):
            result = await d.dispatch(
                "trip_main_breaker",
                ActionTier.HARD_PHYSICAL,
                ctx,
                _result(),
                approval_timeout_seconds=10,
            )

        assert result.approved is True
        assert result.executed is True
        assert result.action_taken == "trip_main_breaker"

    async def test_tier_c_with_no_response_executes_safe_default(self):
        d = ActionDispatcher()
        ctx = _context()

        with patch.object(d, "_listen_for_response", new=AsyncMock(return_value="NO")):
            result = await d.dispatch(
                "trip_main_breaker",
                ActionTier.HARD_PHYSICAL,
                ctx,
                _result(),
                safe_default_action="log_to_dashboard",
                approval_timeout_seconds=10,
            )

        assert result.approved is False
        assert result.operator_response == "NO"
        assert result.action_taken == "log_to_dashboard"

    async def test_tier_c_timeout_executes_safe_default(self):
        d = ActionDispatcher()
        ctx = _context()

        async def slow_listen():
            await asyncio.sleep(999)
            return None  # pragma: no cover

        with patch.object(d, "_listen_for_response", new=slow_listen):
            result = await d.dispatch(
                "trip_main_breaker",
                ActionTier.HARD_PHYSICAL,
                ctx,
                _result(),
                safe_default_action="log_to_dashboard",
                approval_timeout_seconds=0,  # expire immediately
            )

        assert result.approved is False
        assert result.action_taken == "log_to_dashboard"

    async def test_tier_c_uses_provided_approval_timeout(self):
        d = ActionDispatcher()
        ctx = _context()
        captured: dict[str, float] = {}

        async def slow_listen(*args, **kwargs):
            await asyncio.sleep(999)
            return None  # pragma: no cover

        async def fake_wait_for(awaitable, timeout):
            captured["timeout"] = timeout
            raise asyncio.TimeoutError

        with patch.object(d, "_listen_for_response", new=slow_listen):
            with patch(
                "ori.reasoning.action_dispatcher.asyncio.wait_for",
                new=AsyncMock(side_effect=fake_wait_for),
            ):
                result = await d.dispatch(
                    "trip_main_breaker",
                    ActionTier.HARD_PHYSICAL,
                    ctx,
                    _result(),
                    safe_default_action="log_to_dashboard",
                    approval_timeout=60,
                )

        assert result.approved is False
        assert result.action_taken == "log_to_dashboard"
        assert captured["timeout"] == 61.0

    async def test_tier_c_timeout_escalates_to_secondary(self):
        mock_sender = AsyncMock()
        d = ActionDispatcher(
            alert_sender=mock_sender,
            config={
                "operator_contact": "+234800000000",
                "secondary_contact": "+234800000001",
            },
        )
        ctx = _context()

        async def slow_listen():
            await asyncio.sleep(999)
            return None  # pragma: no cover

        with patch.object(d, "_listen_for_response", new=slow_listen):
            await d.dispatch(
                "trip_main_breaker",
                ActionTier.HARD_PHYSICAL,
                ctx,
                _result(),
                approval_timeout_seconds=0,
            )

        # send() called: once for operator (approval request), once for secondary (escalation)
        assert mock_sender.send.await_count >= 1
        # Check secondary was notified
        calls = [str(c) for c in mock_sender.send.await_args_list]
        assert any("+234800000001" in c for c in calls)

    async def test_tier_c_approved_flag_true_on_yes(self):
        d = ActionDispatcher()
        ctx = _context()

        with patch.object(d, "_listen_for_response", new=AsyncMock(return_value="yes")):
            result = await d.dispatch(
                "trip_main_breaker",
                ActionTier.HARD_PHYSICAL,
                ctx,
                _result(),
                approval_timeout_seconds=10,
            )

        assert result.approved is True

    async def test_tier_c_operator_response_preserved_in_result(self):
        d = ActionDispatcher()
        ctx = _context()

        with patch.object(d, "_listen_for_response", new=AsyncMock(return_value="YES")):
            result = await d.dispatch(
                "trip_main_breaker",
                ActionTier.HARD_PHYSICAL,
                ctx,
                _result(),
                approval_timeout_seconds=10,
            )

        assert result.operator_response == "YES"

    async def test_tier_c_logged_to_store(self):
        store = _mock_store()
        ctx = SkillContext(skill=FakeSkill(), event=_event(), state_store=store)
        d = ActionDispatcher()

        with patch.object(d, "_listen_for_response", new=AsyncMock(return_value="NO")):
            await d.dispatch(
                "trip_main_breaker",
                ActionTier.HARD_PHYSICAL,
                ctx,
                _result(),
                approval_timeout_seconds=10,
            )

        store.log_action.assert_awaited_once()

    async def test_tier_c_uses_local_console_fallback_when_comms_unavailable(self):
        d = ActionDispatcher(
            config={
                "operator_contact": "+234800000000",
                "local_console_enabled": True,
                "local_console_poll_interval_ms": 100,
                "local_console_channel_id": "local_console",
            }
        )
        d.update_capability_posture(
            CapabilityPosture(
                sms_available=False,
                whatsapp_available=False,
                gateway_reachable=False,
                local_slm_loaded=True,
                relay_connected=True,
                internet_available=False,
                checked_at_ms=_ms(),
                expires_at_ms=_ms() + 30_000,
            )
        )
        ctx = _context()

        with (
            patch.object(
                d,
                "_listen_for_local_console_response",
                new=AsyncMock(return_value="YES"),
            ) as local_listener,
            patch.object(
                d,
                "_listen_for_response",
                new=AsyncMock(return_value="NO"),
            ) as remote_listener,
        ):
            result = await d.dispatch(
                "trip_main_breaker",
                ActionTier.HARD_PHYSICAL,
                ctx,
                _result(),
                approval_timeout_seconds=10,
            )

        local_listener.assert_awaited_once()
        remote_listener.assert_not_awaited()
        assert result.approved is True
        assert result.operator_response == "LOCAL:YES"
        assert result.action_taken == "trip_main_breaker"

    async def test_tier_c_local_console_no_response_runs_safe_default(self):
        d = ActionDispatcher(
            config={
                "operator_contact": "+234800000000",
                "local_console_enabled": True,
                "local_console_poll_interval_ms": 100,
                "local_console_channel_id": "local_console",
            }
        )
        d.update_capability_posture(
            CapabilityPosture(
                sms_available=False,
                whatsapp_available=False,
                gateway_reachable=False,
                local_slm_loaded=True,
                relay_connected=True,
                internet_available=False,
                checked_at_ms=_ms(),
                expires_at_ms=_ms() + 30_000,
            )
        )
        ctx = _context()

        with patch.object(
            d,
            "_listen_for_local_console_response",
            new=AsyncMock(return_value=None),
        ):
            result = await d.dispatch(
                "trip_main_breaker",
                ActionTier.HARD_PHYSICAL,
                ctx,
                _result(),
                safe_default_action="log_to_dashboard",
                approval_timeout_seconds=10,
            )

        assert result.approved is False
        assert result.action_taken == "log_to_dashboard"

    async def test_tier_c_uses_remote_listener_when_comms_available(self):
        mock_sender = AsyncMock()
        d = ActionDispatcher(
            alert_sender=mock_sender,
            config={
                "operator_contact": "+234800000000",
                "local_console_enabled": True,
            },
        )
        ctx = _context()
        with (
            patch.object(
                d,
                "_listen_for_response",
                new=AsyncMock(return_value="YES"),
            ) as remote_listener,
            patch.object(
                d,
                "_listen_for_local_console_response",
                new=AsyncMock(return_value="NO"),
            ) as local_listener,
        ):
            result = await d.dispatch(
                "trip_main_breaker",
                ActionTier.HARD_PHYSICAL,
                ctx,
                _result(),
                approval_timeout_seconds=10,
            )
        remote_listener.assert_awaited_once()
        local_listener.assert_not_awaited()
        assert result.approved is True


# ─── Failed action — exception handling ───────────────────────────────────────


class TestFailedAction:
    async def test_executor_raises_returns_executed_false(self):
        async def boom(action, context):
            raise RuntimeError("GPIO failure")

        d = ActionDispatcher()
        d.register_executor("trip_breaker", boom)
        result = await d.dispatch(
            "trip_breaker", ActionTier.INFORMATIONAL, _context(), _result()
        )
        assert result.executed is False

    async def test_executor_raises_still_returns_action_result(self):
        async def boom(action, context):
            raise RuntimeError("network down")

        d = ActionDispatcher()
        d.register_executor("alert_sms", boom)
        result = await d.dispatch(
            "alert_sms", ActionTier.INFORMATIONAL, _context(), _result()
        )
        assert isinstance(result, ActionResult)

    async def test_unhandled_exception_returns_action_result(self):
        d = ActionDispatcher()

        with patch.object(
            d, "_execute_immediately", side_effect=RuntimeError("very unexpected")
        ):
            result = await d.dispatch(
                "alert_whatsapp", ActionTier.INFORMATIONAL, _context(), _result()
            )

        assert isinstance(result, ActionResult)
        assert result.executed is False

    async def test_failed_log_does_not_raise(self):
        store = AsyncMock()
        store.log_action.side_effect = RuntimeError("db locked")
        ctx = SkillContext(skill=FakeSkill(), event=_event(), state_store=store)
        d = ActionDispatcher()
        # Must not raise even when logging fails
        result = await d.dispatch(
            "alert_whatsapp", ActionTier.INFORMATIONAL, ctx, _result()
        )
        assert isinstance(result, ActionResult)


# ─── Logging ──────────────────────────────────────────────────────────────────


class TestLogging:
    async def test_dispatcher_store_used_when_context_has_none(self):
        store = _mock_store()
        ctx = SkillContext(skill=FakeSkill(), event=_event(), state_store=None)
        d = ActionDispatcher(state_store=store)
        await d.dispatch("alert_whatsapp", ActionTier.INFORMATIONAL, ctx, _result())
        store.log_action.assert_awaited_once()

    async def test_context_store_takes_priority(self):
        ctx_store = _mock_store()
        dispatcher_store = _mock_store()
        ctx = SkillContext(skill=FakeSkill(), event=_event(), state_store=ctx_store)
        d = ActionDispatcher(state_store=dispatcher_store)
        await d.dispatch("alert_whatsapp", ActionTier.INFORMATIONAL, ctx, _result())
        ctx_store.log_action.assert_awaited_once()
        dispatcher_store.log_action.assert_not_awaited()

    async def test_no_store_does_not_raise(self):
        ctx = SkillContext(skill=FakeSkill(), event=_event(), state_store=None)
        d = ActionDispatcher(state_store=None)
        result = await d.dispatch(
            "alert_whatsapp", ActionTier.INFORMATIONAL, ctx, _result()
        )
        assert isinstance(result, ActionResult)

    async def test_log_called_on_execution_failure_too(self):
        store = _mock_store()
        ctx = SkillContext(skill=FakeSkill(), event=_event(), state_store=store)
        d = ActionDispatcher()

        async def boom(action, context):
            raise RuntimeError("fail")

        d.register_executor("alert_whatsapp", boom)
        await d.dispatch("alert_whatsapp", ActionTier.INFORMATIONAL, ctx, _result())
        store.log_action.assert_awaited_once()


# ─── Approval message format ─────────────────────────────────────────────────


class TestApprovalMessageFormat:
    def test_contains_device_id(self):
        d = ActionDispatcher()
        msg = d._format_approval_message(
            device_id="dev-lagos-01",
            timestamp_ms=1_700_000_000_000,
            result=_result(text="AC unit drawing 40% above baseline."),
            action="trip_main_breaker",
            timeout_seconds=300,
            device_timezone="Africa/Lagos",
        )
        assert "dev-lagos-01" in msg

    def test_contains_observation_text(self):
        d = ActionDispatcher()
        msg = d._format_approval_message(
            device_id="dev-01",
            timestamp_ms=_ms(),
            result=_result(text="Dangerous overcurrent detected."),
            action="emergency_cutoff",
            timeout_seconds=60,
        )
        assert "Dangerous overcurrent detected." in msg

    def test_contains_action_name(self):
        d = ActionDispatcher()
        msg = d._format_approval_message(
            device_id="dev-01",
            timestamp_ms=_ms(),
            result=_result(),
            action="trip_main_breaker",
            timeout_seconds=300,
        )
        assert "trip_main_breaker" in msg

    def test_contains_confidence_percentage(self):
        d = ActionDispatcher()
        msg = d._format_approval_message(
            device_id="dev-01",
            timestamp_ms=_ms(),
            result=_result(confidence=0.85),
            action="a",
            timeout_seconds=300,
        )
        assert "85%" in msg

    def test_contains_timeout_value(self):
        d = ActionDispatcher()
        msg = d._format_approval_message(
            device_id="dev-01",
            timestamp_ms=_ms(),
            result=_result(),
            action="a",
            timeout_seconds=120,
        )
        assert "120" in msg

    def test_contains_yes_no_instructions(self):
        d = ActionDispatcher()
        msg = d._format_approval_message(
            device_id="dev-01",
            timestamp_ms=_ms(),
            result=_result(),
            action="a",
            timeout_seconds=300,
        )
        assert "YES" in msg
        assert "NO" in msg

    def test_contains_observation_and_reasoning_sections(self):
        """Message must have both OBSERVATION: and REASONING: blocks."""
        d = ActionDispatcher()
        msg = d._format_approval_message(
            device_id="dev-01",
            timestamp_ms=_ms(),
            result=_result(text="Overcurrent detected."),
            action="trip_main_breaker",
            timeout_seconds=300,
        )
        assert "OBSERVATION:" in msg
        assert "REASONING:" in msg

    def test_reasoning_field_used_when_set(self):
        """When result.reasoning is non-empty it appears under REASONING:,
        not result.text."""
        from ori.network.events import ReasoningResult

        d = ActionDispatcher()
        result = ReasoningResult(
            text="Short summary.",
            tier="local_slm",
            model="qwen.gguf",
            tokens_used=10,
            latency_ms=100,
            confidence=0.9,
            action_tier="C",
            reasoning="Detailed explanation of the fault pattern.",
        )
        msg = d._format_approval_message(
            device_id="dev-01",
            timestamp_ms=_ms(),
            result=result,
            action="trip_main_breaker",
            timeout_seconds=300,
        )
        assert "Detailed explanation of the fault pattern." in msg
        assert "REASONING:" in msg

    def test_timestamp_is_human_readable_day_name(self):
        """Timestamp must contain a day name (e.g. 'Wednesday'), not 'UTC'."""
        d = ActionDispatcher()
        # 1_700_000_000_000 ms = 2023-11-14 22:13:20 UTC = 2023-11-14 23:13 WAT
        msg = d._format_approval_message(
            device_id="dev-01",
            timestamp_ms=1_700_000_000_000,
            result=_result(),
            action="a",
            timeout_seconds=300,
            device_timezone="Africa/Lagos",
        )
        assert "UTC" not in msg
        days = {
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        }
        assert any(day in msg for day in days), f"No day name found in: {msg!r}"

    def test_timezone_shifts_day_at_boundary(self):
        """23:30 UTC on a Monday = 00:30 WAT on a Tuesday — timezone must shift
        the displayed day, not just the hour."""
        import datetime
        from zoneinfo import ZoneInfo

        d = ActionDispatcher()
        # Find a Monday 23:30 UTC timestamp
        utc = ZoneInfo("UTC")
        ZoneInfo("Africa/Lagos")
        # 2024-01-01 is a Monday
        monday_2330_utc = datetime.datetime(2024, 1, 1, 23, 30, tzinfo=utc)
        ts_ms = int(monday_2330_utc.timestamp() * 1000)

        msg_utc = d._format_approval_message(
            device_id="d",
            timestamp_ms=ts_ms,
            result=_result(),
            action="a",
            timeout_seconds=300,
            device_timezone="UTC",
        )
        msg_wat = d._format_approval_message(
            device_id="d",
            timestamp_ms=ts_ms,
            result=_result(),
            action="a",
            timeout_seconds=300,
            device_timezone="Africa/Lagos",
        )
        assert "Monday" in msg_utc
        assert "Tuesday" in msg_wat


# ─── Capability tier guard ───────────────────────────────────────────────────


class TestCapabilityTierGuard:
    async def test_capability_tier_can_escalate(self):
        d = ActionDispatcher(
            config={"operator_contact": "+234000", "relay_enabled": True},
            alert_sender=AsyncMock(),
        )
        ctx = _context(actions={"available": [{"name": "trip_relay", "tier": "C"}]})

        with patch.object(d, "_listen_for_response", return_value="no"):
            result = await d.dispatch("trip_relay", "B", ctx, _result(action_tier="B"))

        assert result.tier == "C"
        assert d._alert_sender.send.called

    async def test_capability_tier_never_downgrades(self):
        d = ActionDispatcher(
            config={"operator_contact": "+234000", "relay_enabled": True},
            alert_sender=AsyncMock(),
        )
        ctx = _context(actions={"available": [{"name": "trip_relay", "tier": "A"}]})

        with patch.object(d, "_listen_for_response", return_value="no"):
            result = await d.dispatch("trip_relay", "C", ctx, _result(action_tier="C"))

        assert result.tier == "C"
        assert d._alert_sender.send.called


# ─── Unknown tier fallback ────────────────────────────────────────────────────


class TestUnknownTier:
    async def test_unknown_tier_falls_back_to_execute_immediately(self):
        d = ActionDispatcher()
        result = await d.dispatch("some_action", "X", _context(), _result())
        assert result.executed is True
        assert result.approved is None


# ─── Cancellation Shielding & Logging ─────────────────────────────────────────


class TestCancellationHandling:
    async def test_asyncio_shield_prevents_tier_d_abandonment_on_cancellation(self):
        d = ActionDispatcher()
        executor_ran = asyncio.Event()

        async def _mock_exec(action, ctx):
            await asyncio.sleep(0.1)
            executor_ran.set()

        d.register_executor("emergency_cutoff", _mock_exec)

        task = asyncio.create_task(
            d.dispatch(
                "emergency_cutoff", ActionTier.SAFETY_CRITICAL, _context(), _result()
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()

        await task
        # Wait for the shielded task to finish in the background
        await asyncio.sleep(0.1)

        assert executor_ran.is_set(), "Shielded executor was abandoned"

    async def test_cancelled_error_on_non_tier_d_logs_at_exception_not_critical(
        self, caplog
    ):
        import logging

        d = ActionDispatcher()

        async def _mock_exec(action, ctx):
            raise asyncio.CancelledError()

        d.register_executor("alert_whatsapp", _mock_exec)

        with caplog.at_level(logging.ERROR):
            result = await d.dispatch(
                "alert_whatsapp", ActionTier.INFORMATIONAL, _context(), _result()
            )

        assert result.executed is False
        assert any(record.levelno == logging.ERROR for record in caplog.records)
        assert not any(record.levelno == logging.CRITICAL for record in caplog.records)

    async def test_cancelled_error_on_tier_d_logs_at_critical_level(self, caplog):
        import logging

        d = ActionDispatcher()

        async def _mock_exec(action, ctx):
            raise asyncio.CancelledError()

        d.register_executor("emergency_cutoff", _mock_exec)

        with caplog.at_level(logging.WARNING):
            result = await d.dispatch(
                "emergency_cutoff", ActionTier.SAFETY_CRITICAL, _context(), _result()
            )

        assert result.executed is False
        assert any(record.levelno == logging.CRITICAL for record in caplog.records)
        assert any("Tier D" in record.message for record in caplog.records)


class _StatusSpy:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def set_tier_c_pending(self, *, has_comms: bool) -> None:
        self.calls.append(("tier_c_pending", has_comms))

    def clear_tier_c_pending(self) -> None:
        self.calls.append(("tier_c_clear", None))

    def set_tier_d_firing(self) -> None:
        self.calls.append(("tier_d_set", None))

    def clear_tier_d_firing(self) -> None:
        self.calls.append(("tier_d_clear", None))

    def set_policy_state(self, state: str) -> None:
        self.calls.append(("policy", state))


class TestStatusSignalingHooks:
    async def test_tier_c_pending_set_and_cleared(self):
        status = _StatusSpy()
        d = ActionDispatcher(status_indicator=status)
        ctx = _context()

        with patch.object(d, "_listen_for_response", new=AsyncMock(return_value="NO")):
            await d.dispatch(
                "trip_main_breaker",
                ActionTier.HARD_PHYSICAL,
                ctx,
                _result(),
                approval_timeout_seconds=10,
            )

        assert ("tier_c_pending", False) in status.calls
        assert ("tier_c_clear", None) in status.calls

    async def test_tier_d_set_and_clear(self):
        status = _StatusSpy()
        d = ActionDispatcher(status_indicator=status)
        await d.dispatch(
            "emergency_cutoff", ActionTier.SAFETY_CRITICAL, _context(), _result()
        )
        assert ("tier_d_set", None) in status.calls
        assert ("tier_d_clear", None) in status.calls

    def test_policy_state_restricted_for_expired_policy(self):
        status = _StatusSpy()
        d = ActionDispatcher(status_indicator=status)
        expired = DevicePolicy(
            tier="cloud",
            relay_b_enabled=True,
            relay_c_enabled=True,
            cloud_llm_enabled=True,
            valid_until=int(time.time()) - 1,
            policy_version=1,
            issued_at=0,
            signature="ed25519:test",
        )
        d.update_policy(expired)
        assert ("policy", "restricted") in status.calls


class TestEmergencySmsSender:
    async def test_emergency_sms_uses_injected_sender(self):
        injected_sms = AsyncMock()
        injected_sms.send = AsyncMock(return_value=True)
        d = ActionDispatcher(
            emergency_sms_sender=injected_sms,
            config={"operator_contact": "+2348000000000"},
        )

        await d._emergency_sms("trip_relay", "dev-01")

        injected_sms.send.assert_awaited_once()
