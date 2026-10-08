# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Wait for the event a test asserts, never for an interval.

A test that sleeps a fixed window and then asserts on work another task does,
or that bounds a wait and ignores the bound running out, passes on an idle
machine and fails on a loaded one without any product defect. These helpers
wait for the condition itself. Their deadline only bounds a hang, so it is
generous, and running out of it is a failure that names what was awaited —
never a silent fall-through to an assertion that then reports the wrong thing.

`tests/test_wait_discipline.py` refuses the patterns these replace.
"""

from __future__ import annotations

import asyncio
import inspect
import os
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

#: Bounds a hang, not a latency: a condition that holds arrives long before it.
#: Measured on the loop's clock, so it is stretched by any ORI_TEST_CLOCK_SCALE
#: to stay thirty real seconds.
DEADLINE_S = 30.0 * max(1.0, float(os.environ.get("ORI_TEST_CLOCK_SCALE", "") or 0))

_POLL_S = 0.005


async def wait_until(
    predicate: Callable[[], Any | Awaitable[Any]],
    *,
    what: str,
    deadline_s: float = DEADLINE_S,
) -> None:
    """Return once *predicate* (sync or async) is truthy; fail naming *what*."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + deadline_s
    while True:
        answer = predicate()
        if inspect.isawaitable(answer):
            answer = await answer
        if answer:
            return
        if loop.time() >= deadline:
            raise AssertionError(f"waited {deadline_s}s for {what}; it never happened")
        await asyncio.sleep(_POLL_S)


async def settle(
    tasks: Iterable[asyncio.Future[Any]],
    *,
    what: str,
    deadline_s: float = DEADLINE_S,
) -> None:
    """Wait for every task in *tasks* to finish; fail naming those that did not."""
    waiting = {task for task in tasks if not task.done()}
    if not waiting:
        return
    _, pending = await asyncio.wait(waiting, timeout=deadline_s)
    if pending:
        names = sorted(
            task.get_name() if isinstance(task, asyncio.Task) else repr(task)
            for task in pending
        )
        raise AssertionError(
            f"waited {deadline_s}s for {what}; still running: {', '.join(names)}"
        )


async def drained(dispatcher: Any, *, deadline_s: float = DEADLINE_S) -> None:
    """Wait for the dispatcher's record writer to empty; fail if it did not.

    `ActionDispatcher.drain_records` returns quietly when its timeout runs out,
    as shutdown needs; a test reading the store afterwards needs to know.
    Records of acts that have not settled — an approval still waiting on its
    operator — are not the writer's yet and are not waited for.
    """
    await dispatcher.drain_records(timeout=deadline_s)
    backlog = dispatcher.record_backlog()
    if backlog["pending"]:
        raise AssertionError(
            f"waited {deadline_s}s for the action-record writer to drain; "
            f"{backlog['pending']} record(s) still queued: {backlog}"
        )


async def quiesce(*, what: str, deadline_s: float = DEADLINE_S) -> None:
    """Wait for every other task on the running loop to finish.

    For a test that owns its loop and asserts on work the code under test
    scheduled out of sight. A task that never ends fails this loudly, which is
    the point: work still running is work the assertion has not seen.
    """
    current = asyncio.current_task()
    await settle(
        {task for task in asyncio.all_tasks() if task is not current},
        what=what,
        deadline_s=deadline_s,
    )
