# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The bound façades are the only way evidence state is reached off-thread.

These exercise real façade instances. Asserting that ``executor.run`` marshals a
bare callable proves the executor works and says nothing about whether the
façades use it -- a façade that called its service directly would pass such a
test and fail on the first artifact a gateway delivered.
"""

from __future__ import annotations

import sqlite3
import threading

import pytest

from ori.security.evidence.bound import (
    BoundIngestService,
    ExecutorBoundConfirmationBackend,
)
from ori.security.evidence.executor import EvidenceExecutor
from ori.security.evidence.ingest_service import IngestOutcome


class _RecordingIngest:
    """Stands in for EvidenceIngestService, recording its calling thread.

    Real ingest needs a ledger, a key registry and a device identity; none of
    that changes which thread the call lands on, which is what these tests are
    about. The thread-affinity failure itself is proven against a real sqlite3
    connection in test_executor.py.
    """

    def __init__(self) -> None:
        self.threads: dict[str, int] = {}
        self.calls: list[tuple[str, object]] = []

    def _record(self, name: str, artifact: object) -> IngestOutcome:
        self.threads[name] = threading.get_ident()
        self.calls.append((name, artifact))
        # A real IngestOutcome, not a stand-in: the façade must hand the
        # service's own result back unchanged, and a double returning some
        # other type would let a mangled return value pass unnoticed.
        return IngestOutcome(artifact=name, state="accepted", detail="recorded")

    def accept_custody(self, artifact: object) -> IngestOutcome:
        return self._record("accept_custody", artifact)

    def accept_receipt(self, artifact: object) -> IngestOutcome:
        return self._record("accept_receipt", artifact)

    def accept_epoch_confirmation(self, artifact: object) -> IngestOutcome:
        return self._record("accept_epoch_confirmation", artifact)

    def accept_disposition(self, artifact: object) -> IngestOutcome:
        return self._record("accept_disposition", artifact)

    @property
    def rejections(self) -> tuple[IngestOutcome, ...]:
        self.threads["rejections"] = threading.get_ident()
        return ()


class _RecordingReader:
    def __init__(self) -> None:
        self.thread: int | None = None

    def active_anchor_epoch_id(self, device_id: str) -> str | None:
        self.thread = threading.get_ident()
        return "epoch-1" if device_id == "dev-01" else None


@pytest.fixture()
def executor():
    ex = EvidenceExecutor()
    try:
        yield ex
    finally:
        ex.close()


@pytest.mark.parametrize(
    "method",
    [
        "accept_custody",
        "accept_receipt",
        "accept_epoch_confirmation",
        "accept_disposition",
    ],
)
def test_ingest_methods_run_on_the_owner_thread(executor, method) -> None:
    """Inbound artifacts arrive on MQTT callback threads, never the owner."""
    service = _RecordingIngest()
    bound = BoundIngestService(executor, service)
    owner = executor.run(threading.get_ident)

    caller_thread: dict[str, int] = {}
    returned: dict = {}

    def caller() -> None:
        caller_thread["ident"] = threading.get_ident()
        returned["value"] = getattr(bound, method)({"v": 1})

    thread = threading.Thread(target=caller, name="fake-mqtt")
    thread.start()
    thread.join(timeout=5)

    assert service.threads[method] == owner
    assert caller_thread["ident"] != owner
    assert service.calls == [(method, {"v": 1})]
    # The façade marshals; it must not transform. A returned outcome that
    # arrived altered would mean the boundary is doing more than it claims.
    outcome = returned["value"]
    assert isinstance(outcome, IngestOutcome)
    assert outcome.artifact == method
    assert outcome.detail == "recorded"


def test_ingest_rejections_are_read_on_the_owner_thread(executor) -> None:
    service = _RecordingIngest()
    bound = BoundIngestService(executor, service)
    owner = executor.run(threading.get_ident)

    thread = threading.Thread(target=lambda: bound.rejections)
    thread.start()
    thread.join(timeout=5)
    assert service.threads["rejections"] == owner


def test_active_anchor_epoch_id_runs_on_the_owner_thread(executor) -> None:
    """The confirmation coordinator calls this from asyncio.to_thread."""
    reader = _RecordingReader()
    backend = ExecutorBoundConfirmationBackend(executor, reader)
    owner = executor.run(threading.get_ident)

    result: dict = {}

    def caller() -> None:
        result["value"] = backend.active_anchor_epoch_id("dev-01")

    thread = threading.Thread(target=caller, name="fake-coordinator-worker")
    thread.start()
    thread.join(timeout=5)

    assert reader.thread == owner
    assert result["value"] == "epoch-1"


def test_facade_marshals_a_genuinely_thread_bound_object(executor, tmp_path) -> None:
    """End-to-end: a real sqlite3-backed reader reached from a foreign thread.

    The recording doubles above prove which thread a call lands on. This proves
    that landing there is what makes the call legal at all.
    """

    def _open_reader():
        conn = sqlite3.connect(str(tmp_path / "epochs.db"), isolation_level=None)
        conn.execute("CREATE TABLE epochs(device_id TEXT PRIMARY KEY, epoch TEXT)")
        conn.execute("INSERT INTO epochs VALUES('dev-01', 'epoch-9')")

        class _Reader:
            def active_anchor_epoch_id(self, device_id: str) -> str | None:
                row = conn.execute(
                    "SELECT epoch FROM epochs WHERE device_id = ?", (device_id,)
                ).fetchone()
                return row[0] if row else None

        return _Reader(), conn

    reader, conn = executor.run(_open_reader)
    backend = ExecutorBoundConfirmationBackend(executor, reader)

    # Unbound access from this thread is what the façade prevents.
    with pytest.raises(sqlite3.ProgrammingError):
        reader.active_anchor_epoch_id("dev-01")

    result: dict = {}
    thread = threading.Thread(
        target=lambda: result.update(value=backend.active_anchor_epoch_id("dev-01"))
    )
    thread.start()
    thread.join(timeout=5)
    assert result["value"] == "epoch-9"
    executor.run(conn.close)
