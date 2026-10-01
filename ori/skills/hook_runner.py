# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Synchronous skill hooks, run on their own thread, never on the event loop.

A hook is first-party Python that may read history, write skill state, or
simply compute; any of it can be slow. On the event loop that time is taken
from every reading behind it, Tier D included. Here a hook runs on one daemon
thread fed by a small fixed queue, is awaited for a bounded time, and on
saturation or timeout is skipped: the triggers that need its output are not
evaluated for that reading, and Tier D, decided before any hook runs, never
waits for it.
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
#: How long a reading's hook is awaited. A shipped hook makes a handful of
#: store calls, each bounded by the hooks' 50 ms busy timeout, and some
#: arithmetic; two seconds is ample for that on a loaded Pi, and a hook slower
#: than this only delays the notices that depend on it, so they are dropped.
HOOK_TIMEOUT_S = 2.0
#: How long stop waits for a running hook before abandoning it.
HOOK_SHUTDOWN_S = 2.0


class HookSkippedError(RuntimeError):
    """A hook did not run, or did not finish, in time for its reading."""


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
        self._running = False
        self.skipped_saturated = 0
        self.timed_out = 0
        self.lost_at_shutdown = 0

    @property
    def pending(self) -> int:
        """Hook calls queued, not counting one running."""
        return self._queue.qsize()

    async def run(self, fn: Callable[..., Any], *args: Any) -> Any:
        """Run ``fn(*args)`` on the hook thread; await it for the timeout.

        A coroutine the hook returns is awaited on the loop within what is
        left of the same timeout.
        """
        loop = asyncio.get_running_loop()
        done: asyncio.Future[Any] = loop.create_future()
        # Settled after a timeout, when nobody is awaiting it any more.
        done.add_done_callback(lambda f: f.cancelled() or f.exception())
        with self._lock:
            if self._closed:
                raise HookSkippedError("the hook runner has stopped")
            try:
                self._queue.put_nowait((fn, args, done, loop))
            except queue.Full:
                self.skipped_saturated += 1
                raise HookSkippedError("the hook queue is full") from None
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(
                    target=self._work, name="ori-skill-hooks", daemon=True
                )
                self._thread.start()
        started = time.monotonic()
        try:
            result = await asyncio.wait_for(asyncio.shield(done), self._timeout_s)
            if asyncio.iscoroutine(result):
                remaining = max(0.0, self._timeout_s - (time.monotonic() - started))
                result = await asyncio.wait_for(result, remaining)
            return result
        except asyncio.TimeoutError:
            self.timed_out += 1
            raise HookSkippedError(
                f"the hook did not finish within {self._timeout_s:.1f}s"
            ) from None

    def _work(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            fn, args, done, loop = item
            self._running = True
            try:
                result = fn(*args)
            except BaseException as exc:  # noqa: BLE001 - handed to the awaiting loop
                _settle(loop, done, error=exc)
            else:
                _settle(loop, done, result=result)
            finally:
                self._running = False

    async def close(self, timeout_s: float = HOOK_SHUTDOWN_S) -> int:
        """Stop taking hooks; wait a bounded time; return how many were lost."""
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
                lost += 1
                _settle(item[3], item[2], error=HookSkippedError("stopped"))
        if thread is not None and thread.is_alive():
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass
            deadline = time.monotonic() + timeout_s
            while thread.is_alive() and time.monotonic() < deadline:
                await asyncio.sleep(0.01)
            if thread.is_alive():
                lost += 1
                logger.warning(
                    "[skills] a skill hook did not finish within %.1fs of stop; "
                    "it is abandoned and counted lost",
                    timeout_s,
                )
        self.lost_at_shutdown += lost
        return lost


def _settle(
    loop: asyncio.AbstractEventLoop,
    done: asyncio.Future[Any],
    *,
    result: Any = None,
    error: BaseException | None = None,
) -> None:
    def apply() -> None:
        if done.done():
            return
        if error is not None:
            done.set_exception(error)
        else:
            done.set_result(result)

    try:
        loop.call_soon_threadsafe(apply)
    except RuntimeError:
        pass  # the loop has closed; nobody is waiting
