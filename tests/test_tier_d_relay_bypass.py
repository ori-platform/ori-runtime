# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from ori.network.events import ActionTier, OriEvent, ReasoningResult
from ori.policy.device_policy import DevicePolicy
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.elevator import SkillContext


@pytest.fixture
def dispatcher():
    disp = ActionDispatcher(config={"relay_enabled": True})
    disp._alert_sender = AsyncMock()
    disp._emergency_sms = AsyncMock()

    mock_executor = AsyncMock(return_value=True)
    disp.register_executor("trip_relay", mock_executor)

    return disp, mock_executor


@pytest.fixture
def context():
    ctx = MagicMock(spec=SkillContext)
    ctx.event = MagicMock(spec=OriEvent)
    ctx.event.device_id = "test-device"
    return ctx


@pytest.fixture
def result():
    return MagicMock(spec=ReasoningResult)


@pytest.mark.asyncio
async def test_tier_d_relay_fires_when_policy_expired(dispatcher, context, result):
    disp, executor = dispatcher

    expired_policy = DevicePolicy(
        tier="cloud",
        relay_b_enabled=True,
        relay_c_enabled=True,
        cloud_llm_enabled=True,
        valid_until=int(time.time()) - 1000,
        policy_version=1,
        issued_at=0,
        signature="test",
    )
    disp.update_policy(expired_policy)

    result_action = await disp.dispatch(
        "trip_relay", ActionTier.SAFETY_CRITICAL, context, result
    )

    assert result_action.executed is True
    executor.assert_called_once()
    disp._emergency_sms.assert_not_called()


@pytest.mark.asyncio
async def test_tier_d_relay_fires_when_policy_missing(dispatcher, context, result):
    disp, executor = dispatcher

    disp.update_policy(None)

    result_action = await disp.dispatch(
        "trip_relay", ActionTier.SAFETY_CRITICAL, context, result
    )

    assert result_action.executed is True
    executor.assert_called_once()


@pytest.mark.asyncio
async def test_tier_d_relay_fires_when_policy_parse_fails(dispatcher, context, result):
    disp, executor = dispatcher

    # Keep a restrictive policy loaded, then simulate a parse failure while
    # fetching a replacement payload. The loaded policy remains unchanged.
    restrictive_policy = DevicePolicy(
        tier="cloud",
        relay_b_enabled=False,
        relay_c_enabled=False,
        cloud_llm_enabled=False,
        valid_until=int(time.time()) + 1000,
        policy_version=1,
        issued_at=0,
        signature="test",
    )
    disp.update_policy(restrictive_policy)

    def _parse_policy_payload(_: object) -> DevicePolicy:
        raise ValueError("invalid payload")

    with pytest.raises(ValueError):
        _parse_policy_payload({"malformed": True})

    result_action = await disp.dispatch(
        "trip_relay", ActionTier.SAFETY_CRITICAL, context, result
    )

    assert result_action.executed is True
    executor.assert_called_once()


@pytest.mark.asyncio
async def test_tier_d_relay_fires_when_policy_refresh_fails(
    dispatcher, context, result
):
    disp, executor = dispatcher

    # Simulate refresh failure: stale cached policy remains loaded.
    stale_policy = DevicePolicy(
        tier="cloud",
        relay_b_enabled=False,
        relay_c_enabled=False,
        cloud_llm_enabled=False,
        valid_until=int(time.time()) - 1000,
        policy_version=1,
        issued_at=0,
        signature="test",
    )
    disp.update_policy(stale_policy)

    async def _refresh_policy_from_cloud() -> DevicePolicy:
        raise TimeoutError("cloud refresh failed")

    with pytest.raises(TimeoutError):
        await _refresh_policy_from_cloud()

    result_action = await disp.dispatch(
        "trip_relay", ActionTier.SAFETY_CRITICAL, context, result
    )

    assert result_action.executed is True
    executor.assert_called_once()


@pytest.mark.asyncio
async def test_tier_d_logs_critical_when_executor_not_initialised(
    dispatcher, context, result
):
    disp, _ = dispatcher

    disp._executors.pop("trip_relay")

    result_action = await disp.dispatch(
        "trip_relay", ActionTier.SAFETY_CRITICAL, context, result
    )

    assert result_action.executed is False
    disp._emergency_sms.assert_called_once_with("trip_relay", "test-device")
