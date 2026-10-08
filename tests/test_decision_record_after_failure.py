# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A decision an approval workflow carried out is recorded, or counted lost.

The act and its action row come first; the decision record is queued after.
A fault between the two used to return the act with no decision recorded.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from ori.reasoning.action_dispatcher import ActionDispatcher, ActionTier, SkillContext
from tests.test_action_dispatcher import FakeSkill, _event, _mock_store, _result
from tests.waiting import drained


def _dispatcher_and_context() -> tuple[ActionDispatcher, Any, SkillContext]:
    store = _mock_store()
    ctx = SkillContext(
        skill=FakeSkill(name="energy-anomaly-detector"),
        event=_event(),
        state_store=store,
        trigger_name="overcurrent",
    )
    d = ActionDispatcher(
        config={"device_timezone": "Africa/Lagos", "relay_enabled": True}
    )
    return d, store, ctx


def _faulting(d: ActionDispatcher, prefix: str, *, once: bool = True) -> Any:
    """`_defer_record` raising for records whose label starts with *prefix*."""
    original = d._defer_record
    raised = {"n": 0}

    def defer(write: Any, **kwargs: Any) -> None:
        label = kwargs.get("label", "")
        # A callable label is read only once its record settles; leave it.
        text = "" if callable(label) else str(label)
        if text.startswith(prefix) and (not once or raised["n"] == 0):
            raised["n"] += 1
            raise RuntimeError("injected")
        original(write, **kwargs)

    return defer


async def _dispatch(d: ActionDispatcher, ctx: SkillContext, reply: str | None) -> Any:
    with patch.object(d, "_listen_for_response", new=AsyncMock(return_value=reply)):
        return await d.dispatch(
            "terminate_process",
            ActionTier.HARD_PHYSICAL,
            ctx,
            _result(action_tier="C"),
            safe_default_action="log_to_dashboard",
            approval_timeout_seconds=10,
        )


@pytest.mark.parametrize("prefix", ["override_log", "rejection_pattern"])
async def test_a_fault_after_a_rejection_still_records_it(prefix: str) -> None:
    d, store, ctx = _dispatcher_and_context()
    with patch.object(d, "_defer_record", new=_faulting(d, prefix)):
        result = await _dispatch(d, ctx, "NO")
    assert result.approved is False
    await drained(d)
    store.log_tier_c_decision.assert_awaited_once()
    assert (
        store.log_tier_c_decision.await_args.kwargs["operator_decision"] == "rejected"
    )
    store.log_action_for_event.assert_awaited()


async def test_a_fault_while_escalating_a_timeout_still_records_it() -> None:
    d, store, ctx = _dispatcher_and_context()
    with patch.object(
        d, "_escalate_to_secondary", new=AsyncMock(side_effect=RuntimeError("injected"))
    ):
        result = await _dispatch(d, ctx, None)
    assert result.approved is False
    await drained(d)
    store.log_tier_c_decision.assert_awaited_once()
    decision = store.log_tier_c_decision.await_args.kwargs["operator_decision"]
    assert decision not in {"approved", "rejected", "approval_error"}


async def test_a_decision_that_cannot_be_queued_is_counted_lost() -> None:
    d, store, ctx = _dispatcher_and_context()
    with patch.object(
        d, "_defer_record", new=_faulting(d, "tier_c_decision", once=False)
    ):
        result = await _dispatch(d, ctx, "NO")
    assert result.approved is False
    await drained(d)
    store.log_tier_c_decision.assert_not_awaited()
    assert d._decision_records_lost == 1


async def test_a_decision_queued_once_is_not_queued_again() -> None:
    d, store, ctx = _dispatcher_and_context()
    with patch.object(d, "_listen_for_response", new=AsyncMock(return_value="NO")):
        await d.dispatch(
            "terminate_process",
            ActionTier.HARD_PHYSICAL,
            ctx,
            _result(action_tier="C"),
            safe_default_action="log_to_dashboard",
            approval_timeout_seconds=10,
        )
    await drained(d)
    store.log_tier_c_decision.assert_awaited_once()


async def test_a_cancellation_after_the_act_still_records_the_decision_and_the_act() -> (
    None
):
    import asyncio

    d, store, ctx = _dispatcher_and_context()
    escalating = asyncio.Event()

    async def hang(*_args: Any, **_kwargs: Any) -> Any:
        escalating.set()
        await asyncio.Event().wait()

    with (
        patch.object(d, "_listen_for_response", new=AsyncMock(return_value=None)),
        patch.object(d, "_escalate_to_secondary", new=hang),
    ):
        task = asyncio.create_task(
            d.dispatch(
                "terminate_process",
                ActionTier.HARD_PHYSICAL,
                ctx,
                _result(action_tier="C"),
                safe_default_action="log_to_dashboard",
                approval_timeout_seconds=10,
            )
        )
        await asyncio.wait_for(escalating.wait(), 2)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    await drained(d)
    store.log_tier_c_decision.assert_awaited_once()
    recorded = [c.args[0] for c in store.log_action_for_event.await_args_list]
    acts = [r for r in recorded if r.action_name == "terminate_process"]
    assert acts and acts[-1].executed is True and acts[-1].safe_default_used is True
