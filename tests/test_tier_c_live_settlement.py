# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A governed Tier C approval whose workflow fails after its commit.

Before the executor is invoked, the row is settled live as a restart would
settle it (`dispatch_not_proven`, reason `workflow_failed`), and the live result
names only what the row is confirmed to hold. After the act, the executor's
result is kept whatever befalls its record, notice or decision log. Every test
runs the real dispatcher against a real SQLite store.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import pytest

from ori.reasoning import tier_c_admission as adm
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.action_taken import UNRECORDED_SUFFIX
from ori.reasoning.elevator import SkillContext
from ori.state.store import StateStore
from ori.utils.time_utils import now_ms
from tests.test_tier_c_governed_approval import (
    DEVICE,
    ZONE,
    _dispatcher,
    _event,
    _Operator,
    _propose,
    _settle,
    _Skill,
)
from tests.waiting import drained

BINDING = "sha256:" + "b" * 64


class _FailingGate:
    """A resource gate that fails when the approved act is admitted."""

    async def mark_proposal(self, _token: Any, _proposal_id: str) -> None:
        return None

    async def reply_admitted(self, _token: Any) -> bool:
        raise RuntimeError("the gate failed")


async def _admitted(store: StateStore, proposal_id: str, *, zone: str = ZONE) -> None:
    assert (
        await store.create_tier_c_proposal(
            proposal_id=proposal_id,
            device_id=DEVICE,
            action="trip_relay",
            target="relay-gpio-26",
            zone_id=zone,
            outcome="open_protected_circuit",
            safe_default_action="log_to_dashboard",
            binding_digest=BINDING,
            authority_json="{}",
            created_at_ms=now_ms(),
            expires_at_ms=now_ms() + 300_000,
        )
        == "committed"
    )
    assert (
        await store.admit_tier_c_approval(
            proposal_id,
            binding_digest=BINDING,
            authority_json="{}",
            reservation_ceiling=64,
        )
        == "committed"
    )


def _row(proposal_id: str) -> dict[str, Any]:
    return {
        "proposal_id": proposal_id,
        "device_id": DEVICE,
        "safe_default_action": "log_to_dashboard",
        "zone_id": ZONE,
        "outcome": "open_protected_circuit",
    }


async def _dispatch_admitted(
    dispatcher: ActionDispatcher, store: StateStore, proposal_id: str
) -> Any:
    return await dispatcher._dispatch_admitted(  # type: ignore[attr-defined]
        "trip_relay",
        SkillContext(
            skill=_Skill(), event=_event(), state_store=store, trigger_name="t"
        ),
        store,
        _row(proposal_id),
        object(),
        asyncio.get_running_loop().time() + 30,
        "YES-" + proposal_id,
    )


async def _state(store: StateStore, proposal_id: str) -> str:
    row = await store.get_tier_c_proposal(proposal_id)
    assert row is not None
    return str(row["decision_state"])


@pytest.fixture
async def store(tmp_path: Any) -> Any:
    s = StateStore(str(tmp_path / "s.db"))
    await s.open()
    yield s
    await s.close()


# --- before the act ------------------------------------------------------------


async def test_a_failure_before_the_act_settles_the_row_and_tells_the_operator(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")
    operator, journal = _Operator(), []
    dispatcher = _dispatcher(store, operator, journal)
    dispatcher._resource_gate = _FailingGate()  # type: ignore[assignment]

    result = await _dispatch_admitted(dispatcher, store, "P1")
    await _settle(dispatcher)

    assert (result.executed, result.approved) == (False, True)
    assert result.action_taken == adm.DISPATCH_NOT_PROVEN
    assert await _state(store, "P1") == adm.DISPATCH_NOT_PROVEN
    held = await store.get_tier_c_proposal("P1")
    assert held is not None and held["state_reason"] == "workflow_failed"
    assert dispatcher._uncertain == {"P1": adm.DISPATCH_NOT_PROVEN}
    assert "P1" not in dispatcher._pending_outcomes
    assert journal == []
    assert any("P1" in notice for notice in operator.notices)


async def test_the_settled_outcome_blocks_only_its_own_outcome_and_zone(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])
    dispatcher._resource_gate = _FailingGate()  # type: ignore[assignment]
    await _dispatch_admitted(dispatcher, store, "P1")

    def proposal(proposal_id: str, zone: str) -> Any:
        return store.create_tier_c_proposal(
            proposal_id=proposal_id,
            device_id=DEVICE,
            action="trip_relay",
            target="relay-gpio-26",
            zone_id=zone,
            outcome="open_protected_circuit",
            safe_default_action="log_to_dashboard",
            binding_digest=BINDING,
            authority_json="{}",
            created_at_ms=now_ms(),
            expires_at_ms=now_ms() + 300_000,
        )

    assert await proposal("P2", ZONE) == "blocked"
    assert await proposal("P3", "zone-other") == "committed"


async def test_a_marker_that_won_is_reported_as_the_row_holds_it(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")
    assert await store.advance_tier_c_proposal(
        "P1", adm.DISPATCH_STARTED, from_states=(adm.APPROVED_PENDING_DISPATCH,)
    )
    operator = _Operator()
    dispatcher = _dispatcher(store, operator, [])
    dispatcher._resource_gate = _FailingGate()  # type: ignore[assignment]

    result = await _dispatch_admitted(dispatcher, store, "P1")

    assert result.action_taken == adm.DISPATCH_STARTED
    assert await _state(store, "P1") == adm.DISPATCH_STARTED
    assert dispatcher._uncertain == {}
    assert any("P1" in notice for notice in operator.notices)


async def test_a_queued_marker_that_runs_after_the_settlement_changes_nothing(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The settlement lands first, then the held marker write runs and loses."""
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])
    real_advance = store.advance_tier_c_proposal
    settled = asyncio.Event()
    marker: list[bool] = []

    async def advance(proposal_id: str, state: str, **kwargs: Any) -> bool:
        if state == adm.DISPATCH_STARTED:
            await settled.wait()
            marker.append(await real_advance(proposal_id, state, **kwargs))
            return marker[-1]
        moved = await real_advance(proposal_id, state, **kwargs)
        if state == adm.DISPATCH_NOT_PROVEN:
            settled.set()
        return moved

    monkeypatch.setattr(store, "advance_tier_c_proposal", advance)
    real_track = dispatcher._track_tier_d_task

    def track_then_fail(task: asyncio.Task[Any]) -> None:
        real_track(task)
        if task.get_name() == "dispatch-started":
            raise RuntimeError("tracking failed after the marker was created")

    dispatcher._track_tier_d_task = track_then_fail  # type: ignore[method-assign]

    result = await _dispatch_admitted(dispatcher, store, "P1")
    await _settle(dispatcher)

    assert result.action_taken == adm.DISPATCH_NOT_PROVEN
    assert marker == [False]
    assert await _state(store, "P1") == adm.DISPATCH_NOT_PROVEN
    # The marker's entry was made; the abandoned attempt removes it.
    assert "P1" not in dispatcher._pending_outcomes


async def test_a_settlement_that_neither_lands_nor_reads_back_is_unrecorded(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _admitted(store, "P1")
    operator = _Operator()
    dispatcher = _dispatcher(store, operator, [])
    dispatcher._resource_gate = _FailingGate()  # type: ignore[assignment]

    async def fails(*_a: Any, **_k: Any) -> Any:
        raise OSError("the store is gone")

    monkeypatch.setattr(store, "advance_tier_c_proposal", fails)
    monkeypatch.setattr(store, "get_tier_c_proposal", fails)

    result = await _dispatch_admitted(dispatcher, store, "P1")
    await _settle(dispatcher)

    assert result.action_taken == f"{adm.DISPATCH_NOT_PROVEN}{UNRECORDED_SUFFIX}"
    assert dispatcher._uncertain == {}
    assert any("P1" in notice for notice in operator.notices)


async def test_a_raised_write_that_committed_is_confirmed_only_by_reading_back(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])
    dispatcher._resource_gate = _FailingGate()  # type: ignore[assignment]
    real = store.advance_tier_c_proposal

    async def commits_then_raises(*a: Any, **k: Any) -> Any:
        await real(*a, **k)
        raise OSError("the answer was lost")

    monkeypatch.setattr(store, "advance_tier_c_proposal", commits_then_raises)

    result = await _dispatch_admitted(dispatcher, store, "P1")

    assert result.action_taken == adm.DISPATCH_NOT_PROVEN
    assert dispatcher._uncertain == {"P1": adm.DISPATCH_NOT_PROVEN}


async def test_a_failed_notice_keeps_the_settlement(store: StateStore) -> None:
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])
    dispatcher._resource_gate = _FailingGate()  # type: ignore[assignment]

    def notice_fails(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("no channel")

    dispatcher._governed_notify = notice_fails  # type: ignore[method-assign]

    result = await _dispatch_admitted(dispatcher, store, "P1")

    assert result.action_taken == adm.DISPATCH_NOT_PROVEN
    assert await _state(store, "P1") == adm.DISPATCH_NOT_PROVEN


async def test_a_cancellation_before_the_act_is_not_settled(store: StateStore) -> None:
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])

    class _CancellingGate(_FailingGate):
        async def reply_admitted(self, _token: Any) -> bool:
            raise asyncio.CancelledError

    dispatcher._resource_gate = _CancellingGate()  # type: ignore[assignment]

    with pytest.raises(asyncio.CancelledError):
        await _dispatch_admitted(dispatcher, store, "P1")
    assert await _state(store, "P1") == adm.APPROVED_PENDING_DISPATCH
    assert dispatcher._uncertain == {}


async def test_a_restart_after_a_live_settlement_settles_nothing_again(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])
    dispatcher._resource_gate = _FailingGate()  # type: ignore[assignment]
    await _dispatch_admitted(dispatcher, store, "P1")

    restarted = _dispatcher(store, _Operator(), [])
    counts = await restarted.recover_tier_c_at_start(store)

    assert counts["dispatch_unproven"] == 0
    assert await _state(store, "P1") == adm.DISPATCH_NOT_PROVEN
    assert restarted._uncertain == {"P1": adm.DISPATCH_NOT_PROVEN}


# --- after the act ------------------------------------------------------------------


async def test_an_outcome_record_that_fails_keeps_the_executor_result(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")
    journal: list[str] = []
    dispatcher = _dispatcher(store, _Operator(), journal)

    def record_fails(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("the outcome could not be recorded")

    dispatcher._record_outcome = record_fails  # type: ignore[method-assign]

    result = await _dispatch_admitted(dispatcher, store, "P1")

    assert journal == ["act:trip_relay"]
    assert (result.executed, result.approved) == (True, True)


async def test_an_outcome_task_that_cannot_be_created_is_held_as_unknown(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])
    loop = asyncio.get_running_loop()
    real_create = loop.create_task

    def create(coro: Any, **kwargs: Any) -> Any:
        if str(kwargs.get("name", "")).startswith("tier-c-outcome:"):
            raise RuntimeError("no task")
        return real_create(coro, **kwargs)

    monkeypatch.setattr(loop, "create_task", create)

    result = await _dispatch_admitted(dispatcher, store, "P1")
    monkeypatch.undo()
    await _settle(dispatcher)

    assert result.executed is True
    assert dispatcher._unknown_live == {"P1": (ZONE, "open_protected_circuit")}
    assert "P1" not in dispatcher._pending_outcomes


async def test_a_confirmed_outcome_clears_an_unknown_diagnostic(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])
    dispatcher._unknown_live["P1"] = (ZONE, "open_protected_circuit")

    await _dispatch_admitted(dispatcher, store, "P1")
    await _settle(dispatcher)

    assert await _state(store, "P1") == adm.EXECUTED
    assert "P1" not in dispatcher._unknown_live


async def test_a_decision_log_failure_after_the_act_keeps_the_result(
    tmp_path: Any,
) -> None:
    store = StateStore(str(tmp_path / "w.db"))
    await store.open()
    journal: list[str] = []
    try:
        dispatcher = _dispatcher(store, _Operator(), journal)

        real_defer = dispatcher._defer_record

        def decision_log_fails(write: Any, *, label: Any = "", **kwargs: Any) -> Any:
            if isinstance(label, str) and label.startswith("tier_c_decision"):
                raise RuntimeError("the decision record could not be queued")
            return real_defer(write, label=label, **kwargs)

        dispatcher._defer_record = decision_log_fails  # type: ignore[method-assign]
        outcome = await _propose(dispatcher, store)
        await _settle(dispatcher)
    finally:
        await store.close()

    assert journal == ["act:trip_relay"]
    assert (outcome.executed, outcome.approved) == (True, True)


async def test_a_failure_after_a_committed_refusal_reports_it_without_a_block(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _admitted(store, "P1")
    operator = _Operator()
    dispatcher = _dispatcher(store, operator, [])

    class _Contended(_FailingGate):
        async def reply_admitted(self, _token: Any) -> bool:
            return False

    dispatcher._resource_gate = _Contended()  # type: ignore[assignment]

    async def safe_default_fails(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("the safe default could not be attempted")

    monkeypatch.setattr(dispatcher, "_safe_default_intent", safe_default_fails)

    result = await _dispatch_admitted(dispatcher, store, "P1")
    await _settle(dispatcher)

    assert result.action_taken == adm.DISPATCH_REFUSED_CONTENTION
    assert dispatcher._uncertain == {}
    assert not any("blocked" in notice for notice in operator.notices)


async def test_a_cancellation_during_the_settlement_leaves_the_durable_block(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The move commits and the task is cancelled: the row blocks at admission,
    and the live block waits for the next start."""
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])
    dispatcher._resource_gate = _FailingGate()  # type: ignore[assignment]
    real = store.advance_tier_c_proposal

    async def commits_then_cancelled(*a: Any, **k: Any) -> Any:
        await real(*a, **k)
        raise asyncio.CancelledError

    monkeypatch.setattr(store, "advance_tier_c_proposal", commits_then_cancelled)

    with pytest.raises(asyncio.CancelledError):
        await _dispatch_admitted(dispatcher, store, "P1")
    assert await _state(store, "P1") == adm.DISPATCH_NOT_PROVEN


async def test_a_cancellation_during_the_act_reports_the_outcome_unknown(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")
    started = asyncio.Event()

    async def hangs(*_a: Any, **_k: Any) -> Any:
        started.set()
        await asyncio.Event().wait()

    dispatcher = _dispatcher(store, _Operator(), [], executor=hangs)
    task = asyncio.create_task(_dispatch_admitted(dispatcher, store, "P1"))
    await started.wait()
    task.cancel()
    # The executor may still be driving, so the act is not abandoned: the
    # dispatch answers, and both the row and the result say it is unknown.
    result = await task
    await _settle(dispatcher)

    assert (result.executed, result.action_taken) == (
        False,
        adm.DISPATCH_OUTCOME_UNKNOWN,
    )
    assert await _state(store, "P1") == adm.DISPATCH_OUTCOME_UNKNOWN


async def test_a_failed_notice_after_the_act_keeps_the_result(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")

    async def not_performed(*_a: Any, **_k: Any) -> bool:
        return False

    dispatcher = _dispatcher(store, _Operator(), [], executor=not_performed)

    def notice_fails(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("no channel")

    dispatcher._governed_notify = notice_fails  # type: ignore[method-assign]

    result = await _dispatch_admitted(dispatcher, store, "P1")
    await _settle(dispatcher)

    assert (result.executed, result.approved) == (False, True)
    assert await _state(store, "P1") != adm.APPROVED_PENDING_DISPATCH


async def test_an_outcome_task_whose_tracking_fails_still_lands_and_drains(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])
    real_track = dispatcher._track_tier_d_task

    def track_then_fail(task: asyncio.Task[Any]) -> None:
        real_track(task)
        if task.get_name().startswith("tier-c-outcome:"):
            raise RuntimeError("tracking failed after the append was created")

    dispatcher._track_tier_d_task = track_then_fail  # type: ignore[method-assign]

    result = await _dispatch_admitted(dispatcher, store, "P1")
    await _settle(dispatcher)

    assert result.executed is True
    assert await _state(store, "P1") == adm.EXECUTED
    assert dispatcher.get_inflight_tier_d_tasks() == set()


async def test_an_outcome_that_cannot_be_serialised_is_held_as_unknown(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json as real_json
    from types import SimpleNamespace

    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])

    def dumps(value: Any, **kwargs: Any) -> str:
        if isinstance(value, dict) and "executed" in value:
            raise TypeError("not serialisable")
        return real_json.dumps(value, **kwargs)

    monkeypatch.setattr(
        "ori.reasoning.action_dispatcher.json",
        SimpleNamespace(dumps=dumps, loads=real_json.loads),
    )

    result = await _dispatch_admitted(dispatcher, store, "P1")
    monkeypatch.undo()
    await _settle(dispatcher)

    assert result.executed is True
    assert dispatcher._unknown_live == {"P1": (ZONE, "open_protected_circuit")}


async def test_recovery_repeated_over_a_live_settlement_changes_nothing(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])
    dispatcher._resource_gate = _FailingGate()  # type: ignore[assignment]
    await _dispatch_admitted(dispatcher, store, "P1")
    records = await store.get_tier_c_proposal_records("P1")

    for _ in range(2):
        restarted = _dispatcher(store, _Operator(), [])
        counts = await restarted.recover_tier_c_at_start(store)
        assert (counts["dispatch_unproven"], counts["outcome_unknown"]) == (0, 0)

    assert await store.get_tier_c_proposal_records("P1") == records


async def test_an_executor_that_raised_keeps_its_result_when_the_record_fails(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")

    dispatcher = _dispatcher(store, _Operator(), [])

    async def raises(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("the act's path failed")

    dispatcher._execute_immediately = raises  # type: ignore[method-assign]

    def record_fails(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("the outcome could not be recorded")

    dispatcher._record_outcome = record_fails  # type: ignore[method-assign]

    result = await _dispatch_admitted(dispatcher, store, "P1")

    assert (result.executed, result.action_taken) == (
        False,
        adm.DISPATCH_OUTCOME_UNKNOWN,
    )


# --- through the public dispatch --------------------------------------------------


async def _public(tmp_path: Any, name: str) -> StateStore:
    store = StateStore(str(tmp_path / name))
    await store.open()
    return store


async def test_a_result_construction_failure_after_the_act_keeps_the_act(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ori.reasoning import action_dispatcher as module

    store = await _public(tmp_path, "c.db")
    journal: list[str] = []
    real_now = module.now_ms
    failed: list[bool] = []

    def now_ms_once_after_the_act() -> int:
        # The first clock read after the act, in the result's construction or the
        # workflow's own, fails; the executor's internal reads are left alone.
        caller = sys._getframe(1).f_code.co_name
        if journal and not failed and caller in ("resolved", "_run_governed_workflow"):
            failed.append(True)
            raise RuntimeError("the clock failed once")
        return real_now()

    try:
        dispatcher = _dispatcher(store, _Operator(), journal)
        monkeypatch.setattr(module, "now_ms", now_ms_once_after_the_act)
        outcome = await _propose(dispatcher, store)
        monkeypatch.undo()
        await _settle(dispatcher)
        rows = await store.get_tier_c_proposals()
    finally:
        await store.close()

    assert failed == [True]
    assert journal == ["act:trip_relay"]
    assert (outcome.executed, outcome.approved) == (True, True)
    assert [row["decision_state"] for row in rows] == [adm.EXECUTED]


async def test_an_expiry_whose_notice_fails_keeps_its_completed_safe_default(
    tmp_path: Any,
) -> None:
    store = await _public(tmp_path, "e.db")
    journal: list[str] = []
    real_admit = store.admit_tier_c_approval

    try:
        dispatcher = _dispatcher(store, _Operator(), journal)

        async def admitted_then_late(*args: Any, **kwargs: Any) -> Any:
            admitted = await real_admit(*args, **kwargs)
            # The approval is admitted; its deadline passes before dispatch.
            dispatcher._clock = lambda: float("inf")
            return admitted

        store.admit_tier_c_approval = admitted_then_late  # type: ignore[method-assign]
        real_notify = dispatcher._governed_notify

        def notice_fails(action: str, context: Any, what: str) -> None:
            if "expired" in what:
                raise RuntimeError("no channel")
            real_notify(action, context, what)

        dispatcher._governed_notify = notice_fails  # type: ignore[method-assign]
        outcome = await _propose(dispatcher, store)
        await _settle(dispatcher)
        rows = await store.get_tier_c_proposals()
    finally:
        await store.close()

    assert journal == ["act:log_to_dashboard"]
    assert outcome.safe_default_used is True
    assert [row["decision_state"] for row in rows] == [
        adm.APPROVAL_EXPIRED_UNDISPATCHED
    ]


async def test_a_cancellation_during_the_act_propagates_through_dispatch(
    tmp_path: Any,
) -> None:
    store = await _public(tmp_path, "x.db")
    started = asyncio.Event()

    async def hangs(*_a: Any, **_k: Any) -> Any:
        started.set()
        await asyncio.Event().wait()

    try:
        dispatcher = _dispatcher(store, _Operator(), [], executor=hangs)
        task = asyncio.create_task(_propose(dispatcher, store))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await _settle(dispatcher)
        rows = await store.get_tier_c_proposals()
    finally:
        await store.close()

    assert [row["decision_state"] for row in rows] == [adm.DISPATCH_OUTCOME_UNKNOWN]


async def test_a_contention_whose_notice_fails_keeps_its_completed_safe_default(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")
    journal: list[str] = []
    dispatcher = _dispatcher(store, _Operator(), journal)

    class _Contended(_FailingGate):
        async def reply_admitted(self, _token: Any) -> bool:
            return False

    dispatcher._resource_gate = _Contended()  # type: ignore[assignment]

    def notice_fails(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("no channel")

    dispatcher._governed_notify = notice_fails  # type: ignore[method-assign]

    result = await _dispatch_admitted(dispatcher, store, "P1")
    await _settle(dispatcher)

    assert journal == ["act:log_to_dashboard"]
    assert (result.action_taken, result.safe_default_used) == (
        adm.DISPATCH_REFUSED_CONTENTION,
        True,
    )


async def test_a_failed_marker_and_outcome_then_a_restart_is_not_proven(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])
    real_advance = store.advance_tier_c_proposal

    async def marker_fails(proposal_id: str, state: str, **kwargs: Any) -> bool:
        if state == adm.DISPATCH_STARTED:
            raise OSError("the marker could not be written")
        return await real_advance(proposal_id, state, **kwargs)

    monkeypatch.setattr(store, "advance_tier_c_proposal", marker_fails)
    loop = asyncio.get_running_loop()
    real_create = loop.create_task

    def create(coro: Any, **kwargs: Any) -> Any:
        if str(kwargs.get("name", "")).startswith("tier-c-outcome:"):
            raise RuntimeError("no task")
        return real_create(coro, **kwargs)

    monkeypatch.setattr(loop, "create_task", create)
    result = await _dispatch_admitted(dispatcher, store, "P1")
    await _settle(dispatcher)
    monkeypatch.undo()
    assert result.executed is True
    assert "P1" in dispatcher._unknown_live
    assert await _state(store, "P1") == adm.APPROVED_PENDING_DISPATCH

    counts = await _dispatcher(store, _Operator(), []).recover_tier_c_at_start(store)

    assert counts["dispatch_unproven"] == 1
    assert await _state(store, "P1") == adm.DISPATCH_NOT_PROVEN


def _clock_fails_in(module: Any, monkeypatch: pytest.MonkeyPatch, caller: str) -> None:
    real_now = module.now_ms

    def now_ms() -> int:
        if sys._getframe(1).f_code.co_name == caller:
            raise RuntimeError("the clock failed")
        return real_now()

    monkeypatch.setattr(module, "now_ms", now_ms)


async def test_an_executor_that_raised_reports_unknown_when_the_clock_fails(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ori.reasoning import action_dispatcher as module

    await _admitted(store, "P1")

    async def raises(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("the executor failed mid-act")

    dispatcher = _dispatcher(store, _Operator(), [])
    dispatcher._execute_immediately = raises  # type: ignore[method-assign]
    _clock_fails_in(module, monkeypatch, "resolved")
    result = await _dispatch_admitted(dispatcher, store, "P1")
    monkeypatch.undo()
    await _settle(dispatcher)

    assert (result.executed, result.action_taken) == (
        False,
        adm.DISPATCH_OUTCOME_UNKNOWN,
    )
    # Stamped by the read taken before the act.
    assert abs(result.timestamp - now_ms()) < 60_000
    assert await _state(store, "P1") == adm.DISPATCH_OUTCOME_UNKNOWN


async def test_a_failing_clock_never_keeps_an_approved_act_from_running(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ori.reasoning import action_dispatcher as module

    await _admitted(store, "P1")
    journal: list[str] = []
    dispatcher = _dispatcher(store, _Operator(), journal)
    _clock_fails_in(module, monkeypatch, "_dispatch_admitted")
    result = await _dispatch_admitted(dispatcher, store, "P1")
    monkeypatch.undo()
    await _settle(dispatcher)

    assert journal == ["act:trip_relay"]
    assert result.executed is True
    assert await _state(store, "P1") == adm.EXECUTED


async def test_a_cancellation_survives_a_failed_outcome_record(
    store: StateStore,
) -> None:
    await _admitted(store, "P1")
    dispatcher = _dispatcher(store, _Operator(), [])

    async def cancelled_mid_act(*_a: Any, **_k: Any) -> Any:
        task = asyncio.current_task()
        assert task is not None
        task.cancel()
        await asyncio.sleep(0)

    def record_fails(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("the record failed")

    dispatcher._execute_immediately = cancelled_mid_act  # type: ignore[method-assign]
    dispatcher._record_outcome = record_fails  # type: ignore[method-assign]
    task = asyncio.create_task(_dispatch_admitted(dispatcher, store, "P1"))
    with pytest.raises(asyncio.CancelledError):
        await task
    await _settle(dispatcher)


async def test_a_failed_close_after_the_workflow_fails_keeps_the_result(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ori.reasoning import action_dispatcher as module

    store = await _public(tmp_path, "a.db")
    journal: list[str] = []
    try:
        dispatcher = _dispatcher(store, _Operator(), journal)

        async def close_fails(*_a: Any, **_k: Any) -> None:
            raise RuntimeError("the close failed")

        dispatcher._abort_open_proposal = close_fails  # type: ignore[method-assign]
        _clock_fails_in(module, monkeypatch, "_run_governed_workflow")
        outcome = await _propose(dispatcher, store)
        monkeypatch.undo()
        await _settle(dispatcher)
    finally:
        await store.close()

    assert journal == ["act:trip_relay"]
    assert outcome.executed is True


async def test_a_failed_tracking_and_an_unlanded_outcome_reconcile_after_shutdown(
    tmp_path: Any,
) -> None:
    store = await _public(tmp_path, "t.db")
    journal: list[str] = []
    real_advance = store.advance_tier_c_proposal

    async def outcome_never_lands(proposal_id: str, state: str, **kwargs: Any) -> bool:
        if state == adm.EXECUTED:
            raise OSError("the store will not take the outcome")
        return await real_advance(proposal_id, state, **kwargs)

    try:
        dispatcher = _dispatcher(store, _Operator(), journal)
        real_track = dispatcher._track_tier_d_task

        def track_then_fail(task: asyncio.Task[Any]) -> None:
            real_track(task)
            if task.get_name().startswith("tier-c-outcome:"):
                raise RuntimeError("tracking failed after the append was created")

        dispatcher._track_tier_d_task = track_then_fail  # type: ignore[method-assign]
        store.advance_tier_c_proposal = outcome_never_lands  # type: ignore[method-assign]
        outcome = await _propose(dispatcher, store)
        await asyncio.gather(
            *(
                task
                for task in dispatcher.get_inflight_tier_d_tasks()
                if task.get_name() == "dispatch-started"
            )
        )
        outcome_tasks = [
            task
            for task in dispatcher.get_inflight_tier_d_tasks()
            if task.get_name().startswith("tier-c-outcome:")
        ]
        # Shutdown: the retrying append is still tracked, so the stop reaches it.
        for task in dispatcher.get_inflight_tier_d_tasks():
            task.cancel()
        await asyncio.gather(*outcome_tasks, return_exceptions=True)
        await drained(dispatcher)
        store.advance_tier_c_proposal = real_advance  # type: ignore[method-assign]
        rows = await store.get_tier_c_proposals()
        assert [row["decision_state"] for row in rows] == [adm.DISPATCH_STARTED]

        counts = await _dispatcher(store, _Operator(), []).recover_tier_c_at_start(
            store
        )
        rows = await store.get_tier_c_proposals()
    finally:
        await store.close()

    assert journal == ["act:trip_relay"]
    assert outcome.executed is True
    assert len(outcome_tasks) == 1
    assert counts["outcome_unknown"] == 1
    assert [row["decision_state"] for row in rows] == [adm.DISPATCH_OUTCOME_UNKNOWN]


def _clock_fails_once_in(
    module: Any, monkeypatch: pytest.MonkeyPatch, caller: str
) -> list[bool]:
    real_now = module.now_ms
    failed: list[bool] = []

    def now_ms() -> int:
        if not failed and sys._getframe(1).f_code.co_name == caller:
            failed.append(True)
            raise RuntimeError("the clock failed once")
        return real_now()

    monkeypatch.setattr(module, "now_ms", now_ms)
    return failed


async def test_an_expiry_keeps_its_safe_default_when_the_clock_fails(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ori.reasoning import action_dispatcher as module

    store = await _public(tmp_path, "ec.db")
    journal: list[str] = []
    real_admit = store.admit_tier_c_approval
    try:
        dispatcher = _dispatcher(store, _Operator(), journal)

        async def admitted_then_late(*args: Any, **kwargs: Any) -> Any:
            admitted = await real_admit(*args, **kwargs)
            dispatcher._clock = lambda: float("inf")
            return admitted

        store.admit_tier_c_approval = admitted_then_late  # type: ignore[method-assign]
        failed = _clock_fails_once_in(module, monkeypatch, "resolved")
        outcome = await _propose(dispatcher, store)
        monkeypatch.undo()
        await _settle(dispatcher)
        rows = await store.get_tier_c_proposals()
    finally:
        await store.close()

    assert journal == ["act:log_to_dashboard"]
    assert (outcome.action_taken, outcome.safe_default_used) == (
        adm.APPROVAL_EXPIRED_UNDISPATCHED,
        True,
    )
    assert [row["decision_state"] for row in rows] == [
        adm.APPROVAL_EXPIRED_UNDISPATCHED
    ]
    assert failed == []


async def test_a_contention_keeps_its_safe_default_when_the_clock_fails(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ori.reasoning import action_dispatcher as module

    await _admitted(store, "P1")
    journal: list[str] = []
    dispatcher = _dispatcher(store, _Operator(), journal)

    class _Contended(_FailingGate):
        async def reply_admitted(self, _token: Any) -> bool:
            return False

    dispatcher._resource_gate = _Contended()  # type: ignore[assignment]
    failed = _clock_fails_once_in(module, monkeypatch, "resolved")
    result = await _dispatch_admitted(dispatcher, store, "P1")
    monkeypatch.undo()
    await _settle(dispatcher)

    assert journal == ["act:log_to_dashboard"]
    assert (result.action_taken, result.safe_default_used) == (
        adm.DISPATCH_REFUSED_CONTENTION,
        True,
    )
    assert failed == []


async def test_a_safe_default_whose_completion_clock_fails_is_kept_and_not_resent(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ori.reasoning import action_dispatcher as module

    await _admitted(store, "P1")
    journal: list[str] = []
    dispatcher = _dispatcher(store, _Operator(), journal)
    dispatcher._clock = lambda: float("inf")  # type: ignore[method-assign]
    real_now = module.now_ms
    failed: list[bool] = []

    def now_ms() -> int:
        if (
            journal
            and not failed
            and sys._getframe(1).f_code.co_name == ("_completed_at")
        ):
            failed.append(True)
            raise RuntimeError("the clock failed after the safe default")
        return real_now()

    monkeypatch.setattr(module, "now_ms", now_ms)
    result = await _dispatch_admitted(dispatcher, store, "P1")
    monkeypatch.undo()
    await _settle(dispatcher)
    counts = await _dispatcher(store, _Operator(), journal).recover_tier_c_at_start(
        store
    )

    assert failed == [True]
    assert (result.action_taken, result.safe_default_used) == (
        adm.APPROVAL_EXPIRED_UNDISPATCHED,
        True,
    )
    assert counts["safe_defaults_resumed"] == 0
    assert journal == ["act:log_to_dashboard"]
