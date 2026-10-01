# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""A gateway route's own thread for blocking MQTT client calls.

A route on the loop's default executor shares it with everything else that
blocks a thread there, so a broker that stops answering, or traffic that
arrives faster than it is handled, would hold threads that unrelated work is
queued behind. One thread per route keeps a stalled route's cost on that route.
"""

from __future__ import annotations

import asyncio
import functools
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, TypeVar

T = TypeVar("T")

#: Client calls admitted to a route's thread and not yet finished. Past it a
#: call is refused rather than queued behind a broker that stopped answering.
PENDING_CEILING = 32


class RouteIOSaturatedError(RuntimeError):
    """Raised when a route's thread already holds as much work as it admits."""


class RouteIO:
    """Runs one route's blocking client calls on that route's own thread."""

    def __init__(self, name: str, *, ceiling: int = PENDING_CEILING) -> None:
        self._name = name
        self._ceiling = ceiling
        self._pending = 0
        self._lock = threading.Lock()
        self._executor: ThreadPoolExecutor | None = None

    @property
    def pending(self) -> int:
        """Calls admitted and not yet finished."""
        return self._pending

    async def run(self, fn: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
        with self._lock:
            if self._pending >= self._ceiling:
                raise RouteIOSaturatedError(
                    f"{self._name} holds {self._pending} client calls already"
                )
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix=self._name
                )
            self._pending += 1
            future = self._executor.submit(functools.partial(fn, *args, **kwargs))
        future.add_done_callback(self._finished)
        return await asyncio.wrap_future(future)

    def _finished(self, _future: Any) -> None:
        with self._lock:
            self._pending -= 1

    def shutdown(self) -> None:
        """Release the thread without waiting on a call the broker never answered."""
        with self._lock:
            executor, self._executor = self._executor, None
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
