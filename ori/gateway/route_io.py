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
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, TypeVar

T = TypeVar("T")


class RouteIO:
    """Runs one route's blocking client calls on that route's own thread."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._executor: ThreadPoolExecutor | None = None

    async def run(self, fn: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix=self._name
            )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor, functools.partial(fn, *args, **kwargs)
        )

    def shutdown(self) -> None:
        """Release the thread without waiting on a call the broker never answered."""
        executor, self._executor = self._executor, None
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
