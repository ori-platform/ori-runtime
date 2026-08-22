# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Single-threaded ownership for the runtime's evidence state.

``EvidenceChain``, ``EvidenceDeliveryLedger`` and the ingest service each hold a
``sqlite3`` connection opened with the default ``check_same_thread=True``. Such a
connection may only be used from the thread that created it; touching it from
another raises ``sqlite3.ProgrammingError``. One worker thread owns all of them,
and every call reaches them through this executor.

Thread affinity is the reason, but not the only one. The delivery ledger seals
an envelope and allocates its ``local_seq`` inside a single ``BEGIN IMMEDIATE``
transaction, and that design assumes one writer. Serialising here keeps
attestation and inbound ingest from interleaving against the same rows, so the
guarantee is structural rather than a lock somebody must remember to take.

Do not relax this by opening connections with ``check_same_thread=False``. That
converts a constraint the interpreter enforces into one this codebase would have
to enforce by convention, in the module that seals evidence.
"""

from __future__ import annotations

import asyncio
import functools
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, TypeVar

T = TypeVar("T")

#: How long a second closer waits for the closer in progress to finish.
_CLOSE_WAIT_TIMEOUT_S = 30.0


class EvidenceExecutorClosedError(RuntimeError):
    """Raised when work is submitted after the evidence executor is closed."""


class EvidenceExecutor:
    """Owns the evidence worker thread and marshals every call onto it."""

    _OPEN = "open"
    _CLOSING = "closing"
    _CLOSED = "closed"

    def __init__(self, *, thread_name_prefix: str = "ori-evidence") -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix=thread_name_prefix
        )
        # Recorded by asking the worker itself, so the identity cannot drift
        # from the thread that will actually own the connections.
        self._owner_ident: int = self._executor.submit(threading.get_ident).result()
        # Lifecycle is OPEN -> CLOSING -> CLOSED under a lock. Checking a bare
        # flag and then submitting is two steps, and teardown can land between
        # them: the worker may still be busy when close() is called, so the
        # teardown sits in the queue while another caller reads "not closed" and
        # queues work behind it. That work then runs against closed SQLite
        # objects. The state must move to CLOSING before teardown is queued, and
        # ordinary submission must be refused from that instant.
        self._lock = threading.Lock()
        self._state = self._OPEN
        # Set once the lifecycle reaches CLOSED. A second caller of close()
        # waits on it rather than returning early: a caller that has returned
        # from close() should be entitled to assume teardown has finished, and
        # returning while the first closer is still tearing down would hand it
        # an executor whose SQLite objects are mid-close.
        self._closed_event = threading.Event()

    @property
    def owns_current_thread(self) -> bool:
        """Whether the caller is already running on the evidence worker."""
        return threading.get_ident() == self._owner_ident

    def run(self, fn: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
        """Run *fn* on the evidence worker and return its result.

        A call already executing on the worker runs inline. Submitting to a
        single-slot executor from its own worker and then blocking on the future
        would wait for a slot that only this frame can free, which deadlocks
        permanently rather than raising. Any nesting -- an ingest that consults
        the ledger, a checkpoint taken while sealing -- would otherwise hang the
        evidence path with no error to explain it.
        """
        if self.owns_current_thread:
            # The inline path still has to respect the lifecycle. Teardown runs
            # on this same thread, so without this check a worker could close
            # its own SQLite objects and then keep operating on them -- the very
            # use-after-teardown the external path already refuses. Work is
            # still admitted during CLOSING, because an operation admitted
            # before shutdown began must be able to finish the nested calls it
            # was already making; teardown is queued behind it either way.
            with self._lock:
                if self._state == self._CLOSED:
                    raise EvidenceExecutorClosedError("the evidence executor is closed")
            return fn(*args, **kwargs)
        return self._submit(fn, *args, **kwargs)

    def _submit(self, fn: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
        """Admit work only while the lifecycle is OPEN.

        The admission check and the submission happen under one lock, so a
        caller cannot be admitted and then queue behind a teardown that was
        accepted in between.
        """
        with self._lock:
            if self._state != self._OPEN:
                raise EvidenceExecutorClosedError(
                    f"the evidence executor is {self._state}"
                )
            future = self._executor.submit(fn, *args, **kwargs)
        return future.result()

    async def run_async(self, fn: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
        """Await *fn* on the evidence worker without blocking the event loop.

        The event loop thread is never the evidence worker, so this always
        marshals; there is no inline case to consider.
        """
        loop = asyncio.get_running_loop()
        with self._lock:
            if self._state != self._OPEN:
                raise EvidenceExecutorClosedError(
                    f"the evidence executor is {self._state}"
                )
            future = loop.run_in_executor(
                self._executor, functools.partial(fn, *args, **kwargs)
            )
        return await future

    def close(self, *, teardown: Callable[[], None] | None = None) -> None:
        """Refuse further work, run *teardown* on the owning thread, then stop.

        SQLite objects must be closed by the thread that created them, so
        teardown is marshalled rather than run by the caller. Closing is
        idempotent, and a caller that returns from it may assume teardown has
        finished -- including when another thread owns the shutdown. A closer
        that cannot establish that within ``_CLOSE_WAIT_TIMEOUT_S`` raises
        rather than returning a guarantee it has not met.
        """
        closing_elsewhere = False
        with self._lock:
            claimed = self._state == self._OPEN
            if claimed:
                # Ordinary submission is refused from here, before teardown is
                # queued, so nothing can be admitted behind it.
                self._state = self._CLOSING
                pending = (
                    self._executor.submit(teardown)
                    if teardown is not None and not self.owns_current_thread
                    else None
                )
            else:
                # Someone else owns the shutdown. Decide here and wait outside
                # the lock: that closer must take this same lock to record
                # CLOSED, so waiting while holding it would deadlock both.
                pending = None
                closing_elsewhere = (
                    self._state == self._CLOSING and not self.owns_current_thread
                )

        if not claimed:
            if closing_elsewhere and not self._closed_event.wait(
                timeout=_CLOSE_WAIT_TIMEOUT_S
            ):
                # Returning here would report a finished teardown that has not
                # finished, which is the guarantee this method makes. A caller
                # that then reopened or reused evidence state would be acting on
                # that false report, so the timeout is raised rather than
                # swallowed.
                raise EvidenceExecutorClosedError(
                    "timed out waiting for evidence executor teardown"
                )
            return

        try:
            if pending is not None:
                pending.result()
            elif teardown is not None:
                # Already on the owning thread: run inline, since submitting
                # here would wait on a slot only this frame can free.
                teardown()
        finally:
            with self._lock:
                self._state = self._CLOSED
            self._closed_event.set()
            # shutdown() joins the worker, and a thread cannot join itself. A
            # close() issued from the owning thread therefore never waits.
            self._executor.shutdown(wait=not self.owns_current_thread)
