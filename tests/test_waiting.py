# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The wait helpers fail loudly, within their deadline, on what they name."""

from __future__ import annotations

import asyncio

import pytest

from tests.waiting import latency_bounds_apply, quiesce, settle, wait_until


async def test_a_hung_async_predicate_fails_within_the_deadline_naming_it() -> None:
    async def hung() -> bool:
        await asyncio.Event().wait()
        return True

    with pytest.raises(AssertionError, match="the hung condition"):
        # The outer bound is only a backstop: the helper's own must fire first.
        await asyncio.wait_for(
            wait_until(hung, what="the hung condition", deadline_s=0.05), 5
        )


async def test_a_false_predicate_fails_naming_it() -> None:
    with pytest.raises(AssertionError, match="never true"):
        await wait_until(lambda: False, what="never true", deadline_s=0.05)


async def test_a_slow_async_predicate_that_holds_returns() -> None:
    calls = 0

    async def slow() -> bool:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        return calls >= 3

    await wait_until(slow, what="the third answer")
    assert calls == 3


async def test_a_predicate_exception_propagates_unchanged() -> None:
    def broken() -> bool:
        raise KeyError("the predicate's own error")

    with pytest.raises(KeyError):
        await wait_until(broken, what="unreachable")


async def test_cancellation_from_outside_is_not_turned_into_a_failure() -> None:
    waiter = asyncio.create_task(wait_until(lambda: False, what="never"))
    await asyncio.sleep(0.01)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.gather(waiter)


async def test_settle_names_the_task_that_did_not_finish() -> None:
    held = asyncio.create_task(asyncio.Event().wait(), name="the-held-task")
    try:
        with pytest.raises(AssertionError, match="the-held-task"):
            await settle({held}, what="the held work", deadline_s=0.05)
    finally:
        held.cancel()
        await asyncio.gather(held, return_exceptions=True)


async def test_quiesce_waits_for_every_generation_of_spawned_tasks() -> None:
    done: list[str] = []

    async def grandchild() -> None:
        await asyncio.sleep(0.01)
        done.append("grandchild")

    async def child() -> None:
        await asyncio.sleep(0.01)
        asyncio.create_task(grandchild())

    async def parent() -> None:
        asyncio.create_task(child())

    asyncio.create_task(parent())
    await quiesce(what="the spawned chain")
    assert done == ["grandchild"]


async def test_quiesce_sees_a_task_a_due_callback_starts() -> None:
    done: list[str] = []

    async def late() -> None:
        done.append("late")

    asyncio.get_running_loop().call_soon(lambda: asyncio.create_task(late()))
    await quiesce(what="the callback's task")
    assert done == ["late"]


async def test_quiesce_fails_on_a_spawned_task_that_never_ends() -> None:
    children: list[asyncio.Task[bool]] = []

    async def parent() -> None:
        children.append(
            asyncio.create_task(asyncio.Event().wait(), name="the-held-child")
        )

    asyncio.create_task(parent())
    try:
        with pytest.raises(AssertionError, match="the-held-child"):
            await quiesce(what="the held chain", deadline_s=0.05)
    finally:
        for task in children:
            task.cancel()
        await asyncio.gather(*children, return_exceptions=True)


@pytest.mark.parametrize(
    ("stall", "scale", "worker", "applies"),
    [
        ("", "", "", True),
        ("20", "", "", False),
        ("", "1000", "", False),
        ("0", "0", "", True),
        ("", "", "gw3", False),
    ],
)
def test_a_latency_bound_is_waived_under_a_simulation_or_a_parallel_worker(
    monkeypatch: pytest.MonkeyPatch, stall: str, scale: str, worker: str, applies: bool
) -> None:
    monkeypatch.setenv("ORI_TEST_STALL_MS", stall)
    monkeypatch.setenv("ORI_TEST_CLOCK_SCALE", scale)
    if worker:
        monkeypatch.setenv("PYTEST_XDIST_WORKER", worker)
    else:
        monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    assert latency_bounds_apply() is applies
