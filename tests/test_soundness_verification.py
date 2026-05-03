# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import AsyncMock, patch

import pytest

from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.elevator import SkillContext
from ori.reasoning.rule_engine import RuleEngine
from ori.skills.loader import Skill, SkillLoader, SkillValidationError


def _event(value=10.0, sensor_type="current_clamp") -> OriEvent:
    reading = SensorReading(
        sensor_id="test-sensor",
        sensor_type=sensor_type,
        value=value,
        unit="ampere",
        timestamp=1000,
        quality=1.0,
    )
    return OriEvent.from_reading(reading, "dev-01")


@pytest.mark.asyncio
async def test_rule_history_async_safety():
    """Verify RuleEngine pre-fetches history and doesn't block event loop."""
    engine = RuleEngine()

    # Mock a state store with a slow (async) history fetcher
    mock_store = AsyncMock()
    # history.avg_24h('test-sensor') -> calls avg_last_hours(sensor_id, 24)
    mock_store.avg_last_hours.return_value = 5.0

    rules = [
        {
            "name": "history_rule",
            "condition": "value > history.avg_24h('test-sensor') * 1.5",
            "action_tier": "A",
        }
    ]

    # This should not raise "RuntimeError: This event loop is already running"
    result = await engine.evaluate(_event(value=10.0), rules, state_store=mock_store)

    assert result.matched is True
    assert result.rule_name == "history_rule"
    mock_store.avg_last_hours.assert_awaited_with("test-sensor", 24)


@pytest.mark.asyncio
async def test_tier_c_dispatch_upgrade():
    """Verify ActionDispatcher upgrades tier if requested tier is lower than capability tier."""
    config = {
        "operator_contact": "+234000",
    }
    mock_sender = AsyncMock()
    dispatcher = ActionDispatcher(config=config, alert_sender=mock_sender)

    # Skill declares relay is Tier C
    skill = Skill(
        name="test",
        version="0.1.0",
        author="test",
        sensors_required=[],
        triggers=[],
        actions={"available": [{"name": "relay", "tier": "C"}]},
    )

    ctx = SkillContext(skill=skill, event=_event(), state_store=None)

    # Reasoning Result mistakenly tries to dispatch at Tier B
    with patch.object(dispatcher, "_listen_for_response", return_value="no"):
        await dispatcher.dispatch(
            action="relay",
            tier="B",  # Mismatched lower tier
            context=ctx,
            result=ReasoningResult(
                text="testing",
                tier="rule",
                model="test",
                confidence=1.0,
                tokens_used=0,
                latency_ms=0,
            ),
        )

        # Dispatcher should have UPGRADED to C, entered _approval_workflow, and called send()
        mock_sender.send.assert_called_once()
        args, kwargs = mock_sender.send.call_args
        assert "PROPOSED ACTION:\nrelay" in kwargs["message"]


@pytest.mark.asyncio
async def test_dispatcher_never_downgrades_tier():
    """If the requested tier is stricter than capability metadata, keep stricter tier."""
    config = {"operator_contact": "+234000", "relay_enabled": True}
    mock_sender = AsyncMock()
    dispatcher = ActionDispatcher(config=config, alert_sender=mock_sender)

    # Capability metadata is accidentally lower than incoming request.
    skill = Skill(
        name="test",
        version="0.1.0",
        author="test",
        sensors_required=[],
        triggers=[],
        actions={"available": [{"name": "trip_relay", "tier": "A"}]},
    )
    ctx = SkillContext(skill=skill, event=_event(), state_store=None)

    with patch.object(dispatcher, "_listen_for_response", return_value="no"):
        result = await dispatcher.dispatch(
            action="trip_relay",
            tier="C",
            context=ctx,
            result=ReasoningResult(
                text="testing",
                tier="rule",
                model="test",
                confidence=1.0,
                tokens_used=0,
                latency_ms=0,
            ),
        )

    # Tier C must stay Tier C (approval workflow, no downgrade).
    assert result.tier == "C"
    assert mock_sender.send.called


@pytest.mark.asyncio
async def test_sender_keyword_validation():
    """Verify alert_sender.send is called with keyword arguments in _approval_workflow."""
    config = {
        "operator_contact": "+234000",
    }
    mock_sender = AsyncMock()
    dispatcher = ActionDispatcher(config=config, alert_sender=mock_sender)

    # Use Tier C to trigger _approval_workflow -> _alert_sender.send
    skill = Skill(
        name="s",
        version="1",
        author="a",
        sensors_required=[],
        triggers=[],
        actions={"available": [{"name": "any_action", "tier": "C"}]},
    )
    ctx = SkillContext(skill=skill, event=_event(), state_store=None)

    with patch.object(dispatcher, "_listen_for_response", return_value="no"):
        await dispatcher.dispatch(
            action="any_action",
            tier="C",
            context=ctx,
            result=ReasoningResult(
                text="Emergency!",
                tier="rule",
                model="test",
                confidence=1.0,
                tokens_used=0,
                latency_ms=0,
            ),
        )

        # Check that it was called with keyword 'message' and 'to_number'
        assert mock_sender.send.called
        args, kwargs = mock_sender.send.call_args
        assert "message" in kwargs
        assert "to_number" in kwargs
        assert kwargs["to_number"] == "+234000"


@pytest.mark.asyncio
async def test_loader_capability_validation():
    """Verify SkillLoader rejects skills where defaults reference undeclared available actions."""
    loader = SkillLoader()

    invalid_actions = {
        "available": [{"name": "alert_whatsapp", "tier": "A"}],
        "defaults": {"over_threshold": ["alert_sms"]},
    }

    with pytest.raises(SkillValidationError, match="undeclared action 'alert_sms'"):
        loader._validate_actions(
            invalid_actions, "bad-skill", trigger_names=["over_threshold"]
        )

    valid_actions = {
        "available": [{"name": "alert_whatsapp", "tier": "A"}],
        "defaults": {"over_threshold": ["alert_whatsapp"]},
    }
    loader._validate_actions(
        valid_actions, "good-skill", trigger_names=["over_threshold"]
    )


@pytest.mark.asyncio
async def test_executor_returning_false_marks_action_not_executed():
    dispatcher = ActionDispatcher()

    async def _failing_executor(action, ctx):
        return False

    dispatcher.register_executor("failing_action", _failing_executor)
    ctx = SkillContext(
        skill=Skill(name="test", version="0.1.0", author="test", actions={}),
        event=_event(),
        state_store=None,
    )

    result = await dispatcher.dispatch(
        action="failing_action",
        tier="A",
        context=ctx,
        result=ReasoningResult(
            text="test",
            tier="rule",
            model="rule_engine",
            confidence=1.0,
            tokens_used=0,
            latency_ms=0,
        ),
    )
    assert result.executed is False
