# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A durable record that fails to land is counted lost, never read as written.

The dispatcher writes the records of an act after it, through one ordered
writer that retries a locked or busy store and counts anything else lost. A
record stage that swallowed a failure the writer did not retry made a lost
operator decision look written: health stayed healthy and nothing counted it.
"""

from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from ori.reasoning.action_dispatcher import ActionDispatcher, ActionTier
from ori.runtime import OriRuntime
from ori.state.store import StateStore
from tests.test_action_dispatcher import _context, _result

NOT_A_LOCK = sqlite3.DatabaseError("disk I/O error")


async def _dispatch(
    tmp_path: Path, *, reply: str = "NO", fail: dict[str, Any] | None = None
) -> tuple[Any, ActionDispatcher, AsyncMock, AsyncMock, dict[str, AsyncMock], int]:
    """A host-state Tier C proposal answered *reply*, with store stages failing."""
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    failing: dict[str, AsyncMock] = {}
    for name, failures in (fail or {}).items():
        real = getattr(store, name)
        pending = list(failures)

        async def attempt(
            *args: Any, _real: Any = real, _pending: list = pending, **kwargs: Any
        ) -> Any:
            if _pending:
                raise _pending.pop(0)
            return await _real(*args, **kwargs)

        mock = AsyncMock(side_effect=attempt)
        setattr(store, name, mock)
        failing[name] = mock
    d = ActionDispatcher(config={"operator_contact": "+2348000000000"})
    action = AsyncMock()
    safe_default = AsyncMock()
    d.register_executor("terminate_process", action)
    d.register_executor("log_to_dashboard", safe_default)
    context = _context()
    context.state_store = store
    try:
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch.object(d, "_tier_c_comms_available", return_value=True)
            )
            stack.enter_context(
                patch.object(
                    d, "_listen_for_response", new=AsyncMock(return_value=reply)
                )
            )
            result = await d.dispatch(
                "terminate_process",
                ActionTier.HARD_PHYSICAL,
                context,
                _result(action_tier="C"),
                approval_timeout_seconds=1,
            )
        await d.drain_records()
    finally:
        await store.close()
    with sqlite3.connect(tmp_path / "state.db") as conn:
        decisions = conn.execute("SELECT COUNT(*) FROM tier_c_decision_log").fetchone()[
            0
        ]
    return result, d, action, safe_default, failing, decisions


async def _health_status(dispatcher: ActionDispatcher) -> str:
    runtime: Any = OriRuntime(config_path="ori.yaml")
    runtime._dispatcher = dispatcher
    snapshot = await runtime._build_health_snapshot()
    return str(snapshot["status"])


async def test_a_lost_tier_c_decision_is_counted_and_makes_health_critical(
    tmp_path: Path,
) -> None:
    result, d, action, safe_default, failing, decisions = await _dispatch(
        tmp_path, fail={"log_tier_c_decision": [NOT_A_LOCK]}
    )

    # Not a lock, so the writer does not retry it: one attempt, counted lost.
    assert failing["log_tier_c_decision"].await_count == 1
    assert decisions == 0
    assert d.decision_records_lost() == 1
    assert d.record_backlog()["lost"] == 1
    assert await _health_status(d) == "critical"
    # The operator's decision stands as reported, and ran once.
    assert result.approved is False
    assert result.safe_default_used is True
    action.assert_not_awaited()
    safe_default.assert_awaited_once()


async def test_a_locked_decision_write_is_retried_and_lands(tmp_path: Path) -> None:
    locked = sqlite3.OperationalError("database is locked")
    _outcome, d, _action, safe_default, failing, decisions = await _dispatch(
        tmp_path, fail={"log_tier_c_decision": [locked]}
    )

    assert failing["log_tier_c_decision"].await_count == 2
    assert decisions == 1
    assert d.decision_records_lost() == 0
    assert d.record_backlog()["lost"] == 0
    safe_default.assert_awaited_once()


@pytest.mark.parametrize(
    "stage",
    [
        pytest.param("store_rejection", id="rejection-pattern"),
        pytest.param("log_action_for_event", id="action-log"),
    ],
)
async def test_a_lost_record_that_is_not_a_decision_is_counted_as_a_record(
    tmp_path: Path, stage: str
) -> None:
    result, d, action, safe_default, failing, decisions = await _dispatch(
        tmp_path, fail={stage: [NOT_A_LOCK]}
    )

    assert failing[stage].await_count >= 1
    assert d.record_backlog()["lost"] >= 1
    assert d.decision_records_lost() == 0
    assert decisions == 1
    assert await _health_status(d) == "degraded"
    assert result.approved is False
    action.assert_not_awaited()
    safe_default.assert_awaited_once()
