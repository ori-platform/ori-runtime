# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Recurring reconciliation of outstanding epoch confirmations.

Approval records a durable ``confirmation_pending`` obligation, and authority
becomes effective only once the runtime store and the evidence store agree on
the same ``anchor_epoch_id``. The coordinator that reconciles them was reached
from exactly two places: a drain at startup, and the pre-signing gate on
firmware-sourced evidence. Its own docstring said recurring retries would be
"layered on later", and they were not.

That is survivable while confirmation is a same-process call that either works
or does not. It stops being survivable once confirmation crosses a boundary and
arrives asynchronously: a normally approved device with no firmware traffic
then waits for a restart, because nothing re-examines the obligation.

This worker is that missing layer, and it is deliberately thin. The
coordinator is unchanged — an already-confirmed epoch is left alone, a
quarantined one is terminal until an operator clears it, an unreachable store
stays pending rather than optimistic, and attempts are recorded so a stuck
grant is visibly being worked. The store's pending query already excludes
terminal rows. All that was missing was something to call it again.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Frequent enough that a confirmation arriving out of band is acted on while
# an operator is still watching, rare enough to be no load at all.
DEFAULT_INTERVAL_S = 60.0
# An unreachable evidence store is the expected failure, not an exceptional
# one. Backing off keeps a site that is offline for a day from retrying
# thousands of times. It is also the upper bound on the configurable base
# interval: a base delay above this ceiling would leave the backoff nowhere
# to go, making the ceiling a false claim for that configuration.
#
# Worst case after a long outage is therefore one ceiling — a quarter of an
# hour — when nothing signals. A restored transport nudges and clears the
# backoff, so the reachable-again case recovers at once rather than waiting.
DEFAULT_MAX_INTERVAL_S = 900.0
# Devices are reconciled concurrently, but not unboundedly: a large pending
# set must not monopolise the event loop the rest of the runtime shares.
DEFAULT_MAX_CONCURRENT = 4
# Rows per cycle, oldest first. A site's firmware fleet is far smaller than
# this; the bound exists so one cycle cannot read an unbounded set, and a full
# window is reported rather than silently truncated.
_PENDING_WINDOW = 100


class FirmwareConfirmationReconciler:
    """Re-drives outstanding confirmation obligations until they resolve."""

    def __init__(
        self,
        *,
        store: Any,
        coordinator: Any,
        interval_s: float = DEFAULT_INTERVAL_S,
        max_interval_s: float = DEFAULT_MAX_INTERVAL_S,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
    ) -> None:
        if not (interval_s > 0) or not (max_interval_s >= interval_s):
            raise ValueError(
                "reconciliation interval must be positive and no greater than "
                "the maximum backoff"
            )
        if max_concurrent < 1:
            raise ValueError("reconciliation concurrency must be at least 1")
        self._store = store
        self._coordinator = coordinator
        self._interval_s = float(interval_s)
        self._max_interval_s = float(max_interval_s)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._wake = asyncio.Event()

    def nudge(self) -> None:
        """Ask for a reconciliation now, from any coroutine on this loop.

        A restored transport is new information: it is the most likely moment
        for a pending confirmation to resolve, so waiting out the remaining
        backoff would be the wrong response to the one event that suggests
        retrying will work.
        """
        self._wake.set()

    async def reconcile_once(self) -> tuple[int, int]:
        """Reconcile every outstanding obligation once. Returns (confirmed, seen)."""
        device_ids = await self._pending_device_ids()
        if not device_ids:
            return 0, 0
        results = await asyncio.gather(
            *(self._confirm(device_id) for device_id in device_ids)
        )
        return sum(1 for confirmed in results if confirmed), len(device_ids)

    async def serve_until(self, shutdown: asyncio.Event) -> None:
        """Reconcile periodically until *shutdown*, backing off when stuck."""
        delay = self._interval_s
        while not shutdown.is_set():
            if await self._sleep_or_wake(delay, shutdown):
                # Woken deliberately rather than by the timer, so the backoff
                # a previous failure earned no longer applies.
                delay = self._interval_s
            if shutdown.is_set():
                return
            try:
                confirmed, seen = await self.reconcile_once()
            except Exception:
                logger.warning("[confirmation] reconciliation cycle failed")
                delay = min(delay * 2, self._max_interval_s)
                continue
            if seen and not confirmed:
                # Obligations outstanding and none resolved: the far side is
                # unreachable or still disagrees. Retrying at full rate would
                # add load without adding information.
                delay = min(delay * 2, self._max_interval_s)
            else:
                delay = self._interval_s
            if confirmed:
                logger.info(
                    "[confirmation] reconciled %d of %d outstanding obligations",
                    confirmed,
                    seen,
                )

    async def _sleep_or_wake(self, delay: float, shutdown: asyncio.Event) -> bool:
        """Wait *delay*, returning True when woken by a nudge instead."""
        waiters = [
            asyncio.ensure_future(self._wake.wait()),
            asyncio.ensure_future(shutdown.wait()),
        ]
        try:
            done, _ = await asyncio.wait(
                waiters, timeout=delay, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            for waiter in waiters:
                waiter.cancel()
        nudged = self._wake.is_set()
        self._wake.clear()
        return nudged and not shutdown.is_set()

    async def _pending_device_ids(self) -> list[str]:
        """Distinct devices with outstanding obligations, order preserved.

        One `confirm()` reconciles a device's active epoch, so several
        obligations for the same device collapse to one call.
        """
        if not hasattr(self._store, "list_pending_firmware_confirmations"):
            return []
        try:
            pending = await self._store.list_pending_firmware_confirmations(
                limit=_PENDING_WINDOW
            )
        except Exception:
            logger.warning("[confirmation] failed to list pending confirmations")
            return []
        if len(pending) >= _PENDING_WINDOW:
            # The query is oldest-first and bounded, so obligations beyond the
            # window are not reconciled this cycle. They are reached as earlier
            # ones resolve — but a window that stays full means they are not
            # resolving, and newer devices are waiting behind them. Say so
            # rather than let the shortfall be invisible.
            logger.warning(
                "[confirmation] pending obligations fill the %d-row window; "
                "devices beyond it wait for earlier ones to resolve",
                _PENDING_WINDOW,
            )
        seen: set[str] = set()
        device_ids: list[str] = []
        for row in pending:
            device_id = str(row.get("device_id", "") or "")
            if device_id and device_id not in seen:
                seen.add(device_id)
                device_ids.append(device_id)
        return device_ids

    async def _confirm(self, device_id: str) -> bool:
        async with self._semaphore:
            try:
                status = await self._coordinator.confirm(device_id)
            except Exception:
                logger.warning("[confirmation] reconciling %s failed", device_id)
                return False
        return bool(status == "confirmed")
