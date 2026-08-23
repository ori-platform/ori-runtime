# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The evidence executor owns every thread-bound SQLite object."""

from __future__ import annotations

import asyncio
import pathlib
import sqlite3
import subprocess
import sys
import threading
import time

import pytest

from ori.security import evidence_executor
from ori.security.evidence_executor import (
    EvidenceExecutor,
    EvidenceExecutorClosedError,
)


def _open(tmp_path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(tmp_path / "e.db"), isolation_level=None)
    conn.execute("CREATE TABLE IF NOT EXISTS t(x INTEGER)")
    return conn


def test_direct_wrong_thread_use_reproduces_the_failure(tmp_path) -> None:
    """The constraint the executor exists for is real, not folklore.

    If this ever stops raising, the marshalling below is dead weight and should
    be reconsidered rather than left in place unexplained.
    """
    executor = EvidenceExecutor()
    try:
        conn = executor.run(_open, tmp_path)
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1").fetchone()
    finally:
        executor.close()


def test_bound_call_succeeds_from_a_foreign_worker(tmp_path) -> None:
    """A caller on another thread reaches the connection through the executor."""
    executor = EvidenceExecutor()
    try:
        conn = executor.run(_open, tmp_path)
        result: dict = {}

        def worker() -> None:
            try:
                result["value"] = executor.run(
                    lambda: conn.execute("SELECT 42").fetchone()[0]
                )
            except Exception as exc:  # pragma: no cover - failure detail
                result["error"] = exc

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=5)
        assert result.get("error") is None
        assert result["value"] == 42
    finally:
        executor.close()


def test_ingest_from_a_foreign_thread_runs_on_the_owner_thread(tmp_path) -> None:
    """Inbound artifacts arrive on MQTT callback threads, not the owner."""
    executor = EvidenceExecutor()
    try:
        owner = executor.run(threading.get_ident)
        seen: dict = {}

        def worker() -> None:
            seen["ran_on"] = executor.run(threading.get_ident)
            seen["caller"] = threading.get_ident()

        thread = threading.Thread(target=worker, name="fake-mqtt")
        thread.start()
        thread.join(timeout=5)
        assert seen["ran_on"] == owner
        assert seen["caller"] != owner
    finally:
        executor.close()


@pytest.mark.asyncio
async def test_bound_call_succeeds_from_asyncio_to_thread(tmp_path) -> None:
    """The confirmation coordinator drives evidence state this way."""
    executor = EvidenceExecutor()
    try:
        conn = executor.run(_open, tmp_path)
        value = await asyncio.to_thread(
            executor.run, lambda: conn.execute("SELECT 7").fetchone()[0]
        )
        assert value == 7
    finally:
        executor.close()


_NESTED_PROBE = """
import sys, threading
sys.path.insert(0, {repo!r})
from ori.security.evidence_executor import EvidenceExecutor

executor = EvidenceExecutor()

def outer():
    return executor.run(lambda: (executor.owns_current_thread, 5))

result = executor.run(outer)
assert result == (True, 5), result
executor.close()
print("OK")
"""


def test_nested_submission_does_not_deadlock() -> None:
    """A single-slot executor cannot wait on itself.

    Submitting from the worker and blocking on the future would wait for a slot
    only this frame can free. That does not raise -- it hangs, and it hangs the
    interpreter too, because the wedged worker is a non-daemon thread that exit
    must join. So the inline path is a correctness requirement, and this runs in
    a subprocess: in-process, removing the guard would hang the whole suite
    instead of failing this one test.
    """
    repo = str(pathlib.Path(__file__).resolve().parents[1])
    proc = subprocess.run(
        [sys.executable, "-B", "-c", _NESTED_PROBE.format(repo=repo)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, (
        f"nested submission deadlocked or failed: {proc.stderr}"
    )
    assert "OK" in proc.stdout


def test_concurrent_work_is_serialised() -> None:
    """Attestation and ingest must not interleave against the same rows."""
    executor = EvidenceExecutor()
    try:
        overlap = {"max": 0, "current": 0}
        lock = threading.Lock()

        def body() -> None:
            with lock:
                overlap["current"] += 1
                overlap["max"] = max(overlap["max"], overlap["current"])
            # A real sleep, not a busy loop. A busy loop finishes far too
            # quickly for a second worker to be observed inside it, which makes
            # the assertion below pass whether or not the work is serialised.
            time.sleep(0.05)
            with lock:
                overlap["current"] -= 1

        threads = [
            threading.Thread(target=lambda: executor.run(body)) for _ in range(6)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert overlap["max"] == 1, "evidence work ran concurrently"
    finally:
        executor.close()


def test_shutdown_closes_sqlite_on_its_owning_thread(tmp_path) -> None:
    """SQLite objects must be closed by the thread that created them."""
    executor = EvidenceExecutor()
    conn = executor.run(_open, tmp_path)
    closed_on: dict = {}

    def teardown() -> None:
        closed_on["thread"] = threading.get_ident()
        conn.close()

    owner = executor.run(threading.get_ident)
    executor.close(teardown=teardown)
    assert closed_on["thread"] == owner
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")


def test_close_is_idempotent_and_refuses_later_work() -> None:
    executor = EvidenceExecutor()
    executor.close()
    executor.close()
    with pytest.raises(EvidenceExecutorClosedError):
        executor.run(lambda: None)


def test_owner_thread_cannot_work_after_its_own_teardown() -> None:
    """The inline path must respect the lifecycle too.

    Teardown runs on the worker itself, so an owner-thread call that skipped the
    state check could close its own SQLite objects and then keep operating on
    them -- the same use-after-teardown the external path refuses, reached by a
    different door.
    """
    executor = EvidenceExecutor()
    state = {"torn": False, "after_teardown": False, "refused": False}

    def teardown() -> None:
        state["torn"] = True

    def more_work() -> None:
        state["after_teardown"] = state["torn"]

    def on_owner() -> None:
        executor.close(teardown=teardown)
        try:
            executor.run(more_work)
        except EvidenceExecutorClosedError:
            state["refused"] = True

    executor.run(on_owner)

    assert state["torn"] is True
    assert state["after_teardown"] is False, "work ran against torn-down state"
    assert state["refused"] is True


def test_nested_owner_calls_still_run_while_open() -> None:
    """The lifecycle check must not break ordinary nesting."""
    executor = EvidenceExecutor()
    try:
        assert executor.run(lambda: executor.run(lambda: "inner")) == "inner"
    finally:
        executor.close()


def test_teardown_may_still_use_evidence_state_while_closing() -> None:
    """Teardown itself runs nested calls, and must be allowed to.

    Closing a chain and a ledger is evidence work performed during CLOSING. If
    the inline path refused everything but OPEN, teardown could not do its job.
    """
    executor = EvidenceExecutor()
    performed: list[str] = []

    def teardown() -> None:
        performed.append(executor.run(lambda: "closed-a-connection"))

    executor.close(teardown=teardown)
    assert performed == ["closed-a-connection"]


def test_a_second_close_waits_for_the_first_to_finish() -> None:
    """Returning from close() must mean teardown is done, not merely started."""
    executor = EvidenceExecutor()
    torn = threading.Event()
    observed: dict = {}

    def teardown() -> None:
        time.sleep(0.2)
        torn.set()

    first = threading.Thread(target=lambda: executor.close(teardown=teardown))
    first.start()
    # Let the first closer take the lifecycle to CLOSING.
    time.sleep(0.05)

    def second() -> None:
        executor.close()
        observed["torn_on_return"] = torn.is_set()

    other = threading.Thread(target=second)
    other.start()
    other.join(timeout=10)
    first.join(timeout=10)

    assert observed.get("torn_on_return") is True, (
        "close() returned while another closer was still tearing down"
    )


def test_a_second_close_surfaces_a_teardown_timeout(monkeypatch) -> None:
    """A timeout must be visible, not reported as a completed teardown.

    ``close()`` promises that returning means teardown finished. Swallowing the
    wait's timeout would break that promise silently, and a caller acting on the
    false report could reuse evidence state that is still being torn down.
    """
    monkeypatch.setattr(evidence_executor, "_CLOSE_WAIT_TIMEOUT_S", 0.05)
    executor = EvidenceExecutor()
    release = threading.Event()
    observed: dict = {}

    def teardown() -> None:
        release.wait(timeout=10)

    first = threading.Thread(target=lambda: executor.close(teardown=teardown))
    first.start()
    time.sleep(0.05)  # let the first closer reach CLOSING

    def second() -> None:
        try:
            executor.close()
            observed["outcome"] = "returned"
        except EvidenceExecutorClosedError as exc:
            observed["outcome"] = "raised"
            observed["message"] = str(exc)

    other = threading.Thread(target=second)
    other.start()
    other.join(timeout=10)

    release.set()
    first.join(timeout=10)

    assert observed.get("outcome") == "raised", (
        "close() returned while teardown was still running"
    )
    assert "timed out" in observed.get("message", "")
