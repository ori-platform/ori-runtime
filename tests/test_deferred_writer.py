# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The writer that keeps records off the path of the acts they record."""

from __future__ import annotations

import asyncio
import contextvars
import sqlite3

from ori.state.deferred_writer import DeferredWriter, is_transient_store_error


def _write(log: list[str], name: str, *, fail: list[BaseException] | None = None):
    failures = list(fail or [])

    async def write() -> None:
        if failures:
            raise failures.pop(0)
        log.append(name)

    return write


async def test_a_locked_store_is_retried_and_order_is_kept() -> None:
    log: list[str] = []
    writer = DeferredWriter("t", ceiling=10)
    locked = sqlite3.OperationalError("database is locked")
    writer.submit(_write(log, "a", fail=[locked, locked]))
    writer.submit(_write(log, "b"))
    await writer.drain(timeout=5)
    assert log == ["a", "b"]
    assert writer.lost == 0


async def test_a_store_that_will_never_take_it_counts_it_lost() -> None:
    log: list[str] = []
    writer = DeferredWriter("t", ceiling=10)
    writer.submit(
        _write(
            log,
            "a",
            fail=[sqlite3.OperationalError("attempt to write a readonly database")],
        )
    )
    writer.submit(_write(log, "b"))
    await writer.drain(timeout=5)
    assert log == ["b"]
    assert writer.lost == 1


async def test_a_cancelled_write_does_not_stop_the_writer() -> None:
    log: list[str] = []
    writer = DeferredWriter("t", ceiling=10)
    writer.submit(_write(log, "a", fail=[asyncio.CancelledError()]))
    writer.submit(_write(log, "b"))
    await writer.drain(timeout=5)
    assert log == ["b"]
    assert writer.lost == 1


async def test_the_ceiling_counts_rather_than_waits() -> None:
    writer = DeferredWriter("t", ceiling=2)
    release = asyncio.Event()

    async def held() -> None:
        await release.wait()

    assert writer.submit(held) and writer.submit(held)
    assert writer.submit(held) is False
    assert writer.pending == 2 and writer.lost == 1
    await asyncio.sleep(0.02)
    assert writer.oldest_pending_age_ms() >= 10
    release.set()
    await writer.drain(timeout=5)
    assert writer.pending == 0 and writer.oldest_pending_age_ms() == 0


async def test_close_counts_what_the_store_never_took() -> None:
    writer = DeferredWriter("t", ceiling=10)
    release = asyncio.Event()

    async def held() -> None:
        await release.wait()

    writer.submit(held)
    writer.submit(held)
    assert await writer.close() == 2
    assert writer.lost == 2
    assert writer.submit(held) is False
    assert writer.lost == 3


async def test_a_write_runs_in_the_context_of_the_act_it_records() -> None:
    """A record carries the submitter's context variables, not the writer's.

    The writer's task is created once; a later write submitted from another
    context would otherwise run under the first submitter's variables, so a
    correlation id or a diagnostic scope read inside the store would name the
    wrong act.
    """
    scope: contextvars.ContextVar[str] = contextvars.ContextVar("scope", default="")
    seen: list[str] = []
    writer = DeferredWriter("t", ceiling=10)

    async def observe() -> None:
        seen.append(scope.get())

    scope.set("first act")
    writer.submit(observe)
    scope.set("second act")
    writer.submit(observe)
    scope.set("after both")
    await writer.drain(timeout=1.0)
    assert seen == ["first act", "second act"]


async def test_close_cancels_the_write_in_flight_rather_than_orphaning_it() -> None:
    started = asyncio.Event()
    cancelled = asyncio.Event()
    writer = DeferredWriter("t", ceiling=10)

    async def held() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    writer.submit(held)
    await asyncio.wait_for(started.wait(), 1.0)
    await writer.close()
    await asyncio.wait_for(cancelled.wait(), 1.0)


async def test_a_write_in_flight_at_close_is_unknown_not_lost() -> None:
    """The statement runs on a thread the cancel does not reach; the store may
    still take it. Only writes that never started are lost."""
    writer = DeferredWriter("t", ceiling=10)
    release = asyncio.Event()
    started = asyncio.Event()
    landed: list[str] = []

    async def head() -> None:
        started.set()
        await release.wait()
        landed.append("head")

    async def queued() -> None:
        landed.append("queued")

    writer.submit(head, label="head")
    writer.submit(queued, label="queued")
    await asyncio.wait_for(started.wait(), 1.0)
    assert await writer.close(grace_s=0.05) == 1
    assert writer.lost == 1 and writer.unknown == 1
    assert landed == []


async def test_close_gives_the_write_in_flight_the_stores_grace() -> None:
    writer = DeferredWriter("t", ceiling=10)
    started = asyncio.Event()
    landed: list[str] = []

    async def slow() -> None:
        started.set()
        await asyncio.sleep(0.1)
        landed.append("slow")

    writer.submit(slow)
    await asyncio.wait_for(started.wait(), 1.0)
    assert await writer.close(grace_s=1.0) == 0
    assert landed == ["slow"]
    assert writer.lost == 0 and writer.unknown == 0


async def test_an_exception_whose_text_raises_does_not_wedge_the_writer() -> None:
    class _Hostile(sqlite3.OperationalError):
        def __str__(self) -> str:
            raise RuntimeError("no text")

    log: list[str] = []
    writer = DeferredWriter("t", ceiling=10)
    writer.submit(_write(log, "a", fail=[_Hostile()]))
    writer.submit(_write(log, "b"))
    await writer.drain(timeout=1.0)
    assert log == ["b"]
    assert writer.lost == 1
    assert writer.pending == 0


def test_only_locked_or_busy_is_transient() -> None:
    assert is_transient_store_error(sqlite3.OperationalError("database is locked"))
    assert is_transient_store_error(sqlite3.OperationalError("database is busy"))
    assert not is_transient_store_error(sqlite3.OperationalError("disk I/O error"))
    assert not is_transient_store_error(RuntimeError("database is locked"))
