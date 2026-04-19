# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import inspect
import logging
import time
from collections import defaultdict
from typing import Awaitable, Callable

from ori.network.events import OriEvent

logger = logging.getLogger(__name__)

Handler = Callable[[OriEvent], Awaitable[None]]

_WILDCARD = "*"


class EventBus:
    """Asyncio pub/sub bus. Skills subscribe; the runtime publishes.

    Subscriptions are keyed on ``sensor_type`` (e.g. ``'current_clamp'``).
    The special key ``'*'`` receives every published event regardless of type.

    Delivery is direct — handlers are awaited inline inside :meth:`publish`,
    not queued.  Handler exceptions are caught, logged, and never allowed to
    interrupt delivery to other subscribers.

    Skill handlers that perform I/O (LLM calls, network requests, GPIO)
    must wrap that work in ``asyncio.create_task()`` to avoid blocking
    delivery to subsequent handlers.  The EventBus dispatches synchronously
    by design — handlers are responsible for yielding control.
    """

    def __init__(
        self, handler_timeout_s: float | None = None, strict_exceptions: bool = False
    ) -> None:
        # sensor_type → list of handlers (preserves registration order)
        self._subscribers: dict[str, list[Handler]] = defaultdict(list)
        self._handler_timeout_s = handler_timeout_s
        self._strict_exceptions = strict_exceptions

    def subscribe(self, sensor_type: str, handler: Handler) -> None:
        """Register *handler* to receive events of *sensor_type*.

        Args:
            sensor_type: The ``OriEvent.reading.sensor_type`` value to match,
                or ``'*'`` to receive all events.
            handler: An async callable that accepts a single :class:`OriEvent`.
        """
        if not inspect.iscoroutinefunction(handler):
            handler_name = getattr(handler, "__name__", repr(handler))
            logger.warning(
                "Handler %s registered for '%s' is not async. "
                "Wrap it with asyncio or it will fail silently.",
                handler_name,
                sensor_type,
            )
        self._subscribers[sensor_type].append(handler)

    def unsubscribe(self, sensor_type: str, handler: Handler) -> None:
        """Remove a previously registered *handler*.

        Silently does nothing if *handler* is not registered for *sensor_type*.
        """
        handlers = self._subscribers.get(sensor_type)
        if handlers and handler in handlers:
            handlers.remove(handler)

    def subscriber_count(self, sensor_type: str) -> int:
        """Return the number of handlers registered for *sensor_type*."""
        return len(self._subscribers.get(sensor_type, []))

    def clear(self) -> None:
        """Remove all subscriptions."""
        self._subscribers.clear()

    async def publish(self, event: OriEvent) -> None:
        """Deliver *event* to every matching subscriber and to wildcard handlers.

        Matching is by ``event.reading.sensor_type`` when a reading is present,
        otherwise by ``event.event_type``.  Wildcard (``'*'``) handlers always
        receive the event.

        Exceptions raised by individual handlers are caught and logged so that
        a misbehaving handler never prevents delivery to other subscribers.

        Logs a warning when no handlers are registered for the event.
        """
        sensor_type = (
            event.reading.sensor_type if event.reading is not None else event.event_type
        )

        specific = list(self._subscribers.get(sensor_type, []))
        wildcards = list(self._subscribers.get(_WILDCARD, []))
        targets = specific + [h for h in wildcards if h not in specific]

        if not targets:
            logger.warning(
                "EventBus: no subscribers for sensor_type=%r (event_id=%s)",
                sensor_type,
                event.event_id,
            )
            return

        for handler in targets:
            start = time.perf_counter()
            handler_name = getattr(handler, "__name__", repr(handler))
            try:
                if self._handler_timeout_s is not None and self._handler_timeout_s > 0:
                    await asyncio.wait_for(
                        handler(event), timeout=self._handler_timeout_s
                    )
                else:
                    await handler(event)
                duration_ms = (time.perf_counter() - start) * 1000.0
                logger.debug(
                    "EventBus: handler=%s event_id=%s completed in %.2fms",
                    handler_name,
                    event.event_id,
                    duration_ms,
                )
            except asyncio.TimeoutError:
                duration_ms = (time.perf_counter() - start) * 1000.0
                logger.error(
                    "EventBus: handler %r timed out for event_id=%s after %.2fms "
                    "(timeout=%.3fs)",
                    handler_name,
                    event.event_id,
                    duration_ms,
                    self._handler_timeout_s,
                )
                if self._strict_exceptions:
                    raise
            except Exception:
                duration_ms = (time.perf_counter() - start) * 1000.0
                logger.exception(
                    "EventBus: handler %r raised an exception for event_id=%s (%.2fms)",
                    handler_name,
                    event.event_id,
                    duration_ms,
                )
                if self._strict_exceptions:
                    raise
