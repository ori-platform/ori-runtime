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

#: How long a test holds an obstruction it releases itself: a hook, a lock, a
#: delivery. Longer than every wait, so an act that waited on the obstruction
#: fails its wait instead of slipping through when the hold runs out. That is
#: what lets "the act came while the obstruction was held" prove the act never
#: waited on it, under any load.
HOLD_S = 2 * DEADLINE_S

_POLL_S = 0.005


def latency_bounds_apply() -> bool:
    """Whether a wall-clock latency bound means anything in this run.

    Under ORI_TEST_STALL_MS or ORI_TEST_CLOCK_SCALE every latency is inflated
    or distorted by construction, and under parallel workers it is the run's
    load, so a bound on one says nothing there. CI runs the modules
    that carry a budget alone, in "Run the latency budgets alone". Only
    the latency assertion consults this; every functional assertion in the
    same test runs either way.
    """
    if os.environ.get("PYTEST_XDIST_WORKER"):
        # A worker shares the host with every other worker, so its wall clock
        # measures the run's load, not the code. Budgets run in a serial run.
        return False
    return not any(
        float(os.environ.get(name, "") or 0) > 0
        for name in ("ORI_TEST_STALL_MS", "ORI_TEST_CLOCK_SCALE")
    )


async def wait_until(
    predicate: Callable[[], Any | Awaitable[Any]],
    *,
    what: str,
    deadline_s: float = DEADLINE_S,
) -> None:
    """Return once *predicate* (sync or async) is truthy; fail naming *what*.

    The deadline covers the whole wait, an async predicate's own awaits
    included, so a predicate that hangs fails here rather than holding the
    test. A predicate's exception propagates unchanged. A synchronous
    predicate that blocks the loop cannot be interrupted by any asyncio
    deadline: predicates must not block.
    """
    try:
        async with asyncio.timeout(deadline_s):
            while True:
                answer = predicate()
                if inspect.isawaitable(answer):
                    answer = await answer
                if answer:
                    return
                await asyncio.sleep(_POLL_S)
    except TimeoutError:
        raise AssertionError(
            f"waited {deadline_s}s for {what}; it never happened"
        ) from None


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
    """Wait until no other task on the running loop is left, under one deadline.

    For a test that owns its loop and asserts on work the code under test
    scheduled out of sight. A task that spawns another before it ends does not
    end the wait: every generation is waited for, and the loop is given a turn
    after the last one so a callback already due can start its task. A task
    that never ends fails this loudly, which is the point: work still running
    is work the assertion has not seen.

    It cannot see work that exists only as a timer not yet due (`call_later`)
    and has created no task; code that defers work that way needs its own
    completion boundary.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + deadline_s
    current = asyncio.current_task()
    quiet_turns = 0
    while quiet_turns < 2:
        others = {
            task
            for task in asyncio.all_tasks()
            if task is not current and not task.done()
        }
        if not others:
            quiet_turns += 1
            await asyncio.sleep(0)
            continue
        quiet_turns = 0
        await settle(others, what=what, deadline_s=max(0.0, deadline - loop.time()))
