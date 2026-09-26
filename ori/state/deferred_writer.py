# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Store writes taken off the path of whatever they record.

A write that records an act must never run ahead of the act, or ahead of the
next one: a store that is busy, locked or failing would otherwise hold it. The
writer takes writes in the order they were submitted, retries a store that is
only locked or busy, and never grows without limit. Past its ceiling a write is
counted lost and reported rather than waited for, because the one thing it must
not do is make its caller wait.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import sqlite3
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_RETRY_FIRST_S = 0.05
_RETRY_MAX_S = 5.0


def is_transient_store_error(exc: BaseException) -> bool:
    """Whether *exc* is a store that will answer later: locked or busy.

    Anything else — a read-only database, a full disk, a corrupt file — does not
    improve by being retried, and retrying it at the head of the queue would
    hold every write behind it for ever.
    """
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    message = str(exc).lower()
    return "locked" in message or "busy" in message


async def _nothing() -> None:
    return None


@dataclass
class _Pending:
    write: Callable[[], Awaitable[None]]
    label: str
    report: bool
    on_lost: Callable[[], None] | None = None
    submitted: float = field(default_factory=time.monotonic)
    #: The submitter's context, so a write runs with the correlation and
    #: diagnostic variables of the act it records, not the writer's own.
    context: contextvars.Context = field(default_factory=contextvars.copy_context)


class DeferredWriter:
    """One ordered writer with a hard ceiling and an honest loss count."""

    def __init__(
        self, name: str, *, ceiling: int, loss_level: int = logging.CRITICAL
    ) -> None:
        self._name = name
        self.ceiling = ceiling
        self._loss_level = loss_level
        self._queue: deque[_Pending] = deque()
        self._task: asyncio.Task[None] | None = None
        self._closed = False
        self._in_flight: _Pending | None = None
        self.lost = 0
        #: Writes that were in flight when the writer closed. The store may
        #: still have taken them: SQLite runs on a thread the cancel does not
        #: reach, so their outcome is unknown rather than lost.
        self.unknown = 0

    @property
    def pending(self) -> int:
        return len(self._queue)

    @property
    def closed(self) -> bool:
        return self._closed

    def oldest_pending_age_ms(self) -> int:
        if not self._queue:
            return 0
        return int((time.monotonic() - self._queue[0].submitted) * 1000)

    def submit(
        self,
        write: Callable[[], Awaitable[None]],
        *,
        label: str = "",
        report: bool = False,
        on_lost: Callable[[], None] | None = None,
    ) -> bool:
        """Queue *write*; never waits. False when it was counted lost instead.

        With *report*, a loss is logged with *label* every time rather than at
        the first and each doubling, for records whose identity must survive
        their loss — an operator's decision among them. *on_lost* runs if the
        write is lost, so its owner can say what that leaves unknown.
        """
        item = _Pending(write, label, report, on_lost)
        if self._closed:
            self._lose(item, "the writer is shut down")
            return False
        if len(self._queue) >= self.ceiling:
            self._lose(item, f"{self.ceiling} writes are already waiting for the store")
            return False
        self._queue.append(item)
        if self._task is None or self._task.done():
            self._task = asyncio.get_running_loop().create_task(
                self._run(), name=f"deferred-writer:{self._name}"
            )
        return True

    async def drain(self, timeout: float) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while self._queue:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            task = self._task
            if task is None or task.done():
                return
            await asyncio.wait({task}, timeout=remaining)

    async def close(self, *, grace_s: float = 5.0) -> int:
        """Stop writing; count what the store never took as lost.

        A write in flight is given *grace_s* to finish, the store's own busy
        timeout, because the statement runs on a thread the cancel does not
        reach and may land regardless; one still in flight after that is
        counted `unknown`, never lost, and said so. Writes that never started
        are lost.
        """
        self._closed = True
        task = self._task
        head: _Pending | None = None
        if task is not None and not task.done():
            if self._in_flight is not None and grace_s > 0:
                await asyncio.wait({task}, timeout=grace_s)
            if not task.done():
                # Read before the cancel, which lets the worker clear it.
                head = self._in_flight
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        stranded = list(self._queue)
        self._queue.clear()
        self._in_flight = None
        if stranded and head is not None and stranded[0] is head:
            stranded.pop(0)
            self.unknown += 1
            logger.log(
                self._loss_level,
                "%s: a record's outcome is unknown — its write was in flight at "
                "shutdown and the store may still have taken it%s",
                self._name,
                f" ({head.label})" if head.label else "",
            )
        for item in stranded:
            self._lose(item, "the store did not take it before shutdown")
        return len(stranded)

    def lose(self, label: str, *, report: bool, why: str) -> None:
        """Count a write that never reached the queue."""
        self._lose(_Pending(_nothing, label, report), why)

    def _lose(self, item: _Pending, why: str) -> None:
        self.lost += 1
        lost = self.lost
        if item.report or lost & (lost - 1) == 0:
            logger.log(
                self._loss_level,
                "%s: a record was lost — %s%s; %d lost so far",
                self._name,
                why,
                f" ({item.label})" if item.label else "",
                lost,
            )
        if item.on_lost is not None:
            try:
                item.on_lost()
            except Exception:
                logger.exception("%s: a loss handler failed", self._name)

    async def _run(self) -> None:
        delay = _RETRY_FIRST_S
        while self._queue:
            item = self._queue[0]

            async def run(pending: _Pending = item) -> None:
                await pending.write()

            write: asyncio.Task[None] = asyncio.get_running_loop().create_task(
                run(), name=f"deferred-write:{self._name}", context=item.context
            )
            self._in_flight = item
            try:
                await write
            except asyncio.CancelledError:
                current = asyncio.current_task()
                if current is not None and current.cancelling():
                    # This writer is being closed; its write goes with it.
                    if not write.done():
                        write.cancel()
                        await asyncio.gather(write, return_exceptions=True)
                    raise
                # The write itself was cancelled, not this writer: it has no
                # result to record, and the writes behind it still do.
                self._queue.popleft()
                self._lose(item, "its write was cancelled")
                continue
            except Exception as exc:
                try:
                    transient = is_transient_store_error(exc)
                except Exception:
                    # An exception whose own text raises is not a store that
                    # will answer later; the queue must not wedge on it.
                    transient = False
                if transient:
                    logger.warning(
                        "%s: the store did not take a record (%s); retrying in %.2fs",
                        self._name,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, _RETRY_MAX_S)
                    continue
                logger.exception("%s: a record was not written", self._name)
                self._queue.popleft()
                self._lose(item, f"the store refused it ({exc!r})")
                continue
            finally:
                self._in_flight = None
            self._queue.popleft()
            delay = _RETRY_FIRST_S
