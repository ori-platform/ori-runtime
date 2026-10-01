# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Synchronous skill hooks, run on their own thread, never on the event loop.

A hook is first-party Python that may read history, write skill state, or
simply compute; any of it can be slow. On the event loop that time is taken
from every reading behind it. Here a hook runs on one daemon thread fed by a
small fixed queue, with a deadline. A hook that is still queued at its
deadline never starts; one that runs past it, or is abandoned at stop, has its
result and its skill-state writes discarded. The triggers that need its output
are then not evaluated for that reading. Tier D, decided before any hook runs,
never waits for one.

Hooks are synchronous. A hook that returns a coroutine is refused at load;
one that reaches here anyway is closed unrun, never awaited on the loop.
"""

from __future__ import annotations

import asyncio
import logging
import queue
import threading
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)

#: Hook calls waiting behind the one running. Past it a hook is skipped.
HOOK_QUEUE_CAPACITY = 4
#: How long a reading's hook has, from being queued. A shipped hook makes a
#: handful of store calls, each bounded by the hooks' 50 ms busy timeout, and
#: some arithmetic; two seconds is ample for that on a loaded Pi, and a hook
#: slower than this only delays the notices that depend on it, so they are
#: dropped.
HOOK_TIMEOUT_S = 2.0
#: How long stop waits for a running hook before abandoning it.
HOOK_SHUTDOWN_S = 2.0


class HookSkippedError(RuntimeError):
    """A hook did not run, or did not finish, in time for its reading."""


class _Item:
    """One queued hook call: its deadline, and whether its result still counts."""

    __slots__ = (
        "fn",
        "args",
        "commit",
        "done",
        "loop",
        "deadline",
        "cancelled",
        "accepted",
        "lock",
    )

    def __init__(
        self,
        fn: Callable[..., Any],
        args: tuple[Any, ...],
        commit: Callable[[], None] | None,
        done: asyncio.Future[Any],
        loop: asyncio.AbstractEventLoop,
        deadline: float,
    ) -> None:
        self.fn = fn
        self.args = args
        self.commit = commit
        self.done = done
        self.loop = loop
        self.deadline = deadline
        self.cancelled = False
        self.accepted = False
        self.lock = threading.Lock()

    def cancel(self) -> bool:
        """Withdraw the call; False when its result was already accepted."""
        with self.lock:
            if self.accepted:
                return False
            self.cancelled = True
            return True

    def accept(self) -> bool:
        """Claim the result for its reading, if it is still wanted in time."""
        with self.lock:
            if self.cancelled or time.monotonic() > self.deadline:
                self.cancelled = True
                return False
            self.accepted = True
            return True


class HookRunner:
    """One daemon thread and a bounded queue for synchronous skill hooks."""

    def __init__(
        self,
        *,
        capacity: int = HOOK_QUEUE_CAPACITY,
        timeout_s: float = HOOK_TIMEOUT_S,
    ) -> None:
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=capacity)
        self._timeout_s = timeout_s
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._closed = False
        self._current: _Item | None = None
        self.skipped_saturated = 0
        self.timed_out = 0
        self.expired_unstarted = 0
        self.discarded = 0
        self.lost_at_shutdown = 0

    @property
    def pending(self) -> int:
        """Hook calls queued, not counting one running."""
        return self._queue.qsize()

    async def run(
        self,
        fn: Callable[..., Any],
        *args: Any,
        commit: Callable[[], None] | None = None,
    ) -> Any:
        """Run ``fn(*args)`` on the hook thread, within the hook deadline.

        *commit*, when given, runs on the hook thread after ``fn`` returns and
        only if the result is still wanted: it is how a hook's buffered
        skill-state writes are kept or discarded with its result.
        """
        loop = asyncio.get_running_loop()
        done: asyncio.Future[Any] = loop.create_future()
        # Settled after a timeout, when nobody is awaiting it any more.
        done.add_done_callback(lambda f: f.cancelled() or f.exception())
        item = _Item(fn, args, commit, done, loop, time.monotonic() + self._timeout_s)
        with self._lock:
            if self._closed:
                raise HookSkippedError("the hook runner has stopped")
            try:
                self._queue.put_nowait(item)
            except queue.Full:
                self.skipped_saturated += 1
                raise HookSkippedError("the hook queue is full") from None
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(
                    target=self._work, name="ori-skill-hooks", daemon=True
                )
                self._thread.start()
        try:
            return await asyncio.wait_for(asyncio.shield(done), self._timeout_s)
        except asyncio.TimeoutError:
            if not item.cancel():
                # Accepted before its deadline and committing its writes: the
                # commit is a handful of bounded store calls, so it is awaited.
                return await done
            self.timed_out += 1
            raise HookSkippedError(
                f"the hook did not finish within {self._timeout_s:.1f}s"
            ) from None

    def _work(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            with item.lock:
                start = not item.cancelled and time.monotonic() <= item.deadline
                if not start:
                    item.cancelled = True
            if not start:
                self.expired_unstarted += 1
                _settle(item, error=HookSkippedError("expired before it started"))
                continue
            self._current = item
            try:
                result = item.fn(*item.args)
                if asyncio.iscoroutine(result):
                    result.close()
                    raise HookSkippedError("an asynchronous hook is not run")
                if not item.accept():
                    self.discarded += 1
                    _settle(item, error=HookSkippedError("finished too late"))
                    continue
                if item.commit is not None:
                    item.commit()
            except BaseException as exc:  # noqa: BLE001 - handed to the awaiting loop
                _settle(item, error=exc)
            else:
                _settle(item, result=result)
            finally:
                self._current = None

    async def close(self, timeout_s: float = HOOK_SHUTDOWN_S) -> int:
        """Stop taking hooks; wait a bounded time; return how many were lost.

        A hook still queued never starts, and one still running has its
        result and its skill-state writes discarded.
        """
        with self._lock:
            self._closed = True
            thread = self._thread
        lost = 0
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if item is not None:
                item.cancel()
                lost += 1
                _settle(item, error=HookSkippedError("stopped"))
        running = self._current
        if thread is not None and thread.is_alive():
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass
            deadline = time.monotonic() + timeout_s
            while thread.is_alive() and time.monotonic() < deadline:
                await asyncio.sleep(0.01)
            if thread.is_alive():
                current = self._current or running
                if current is not None:
                    current.cancel()
                lost += 1
                logger.warning(
                    "[skills] a skill hook did not finish within %.1fs of stop; "
                    "it is abandoned, its writes discarded, and counted lost",
                    timeout_s,
                )
        self.lost_at_shutdown += lost
        return lost


def _settle(
    item: _Item, *, result: Any = None, error: BaseException | None = None
) -> None:
    done = item.done

    def apply() -> None:
        if done.done():
            return
        if error is not None:
            done.set_exception(error)
        else:
            done.set_result(result)

    try:
        item.loop.call_soon_threadsafe(apply)
    except RuntimeError:
        pass  # the loop has closed; nobody is waiting
