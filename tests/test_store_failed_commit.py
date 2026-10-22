# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A commit the store refuses persists nothing, whatever is written after it.

The writer connection is shared by every domain, so a transaction a failed
commit leaves open would be committed by the next unrelated write.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from ori.security.approvers.registry import ApproverRegistry
from ori.state.store import StateStore
from tests.test_approver_registry_engine import Site


class _RefusesOneCommit:
    """The connection, except that its next commit is denied."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self.armed = True

    def commit(self) -> None:
        if self.armed:
            self.armed = False
            raise sqlite3.OperationalError("database is locked")
        self._conn.commit()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    real = s._conn
    try:
        yield s
    finally:
        s._conn = real
        await s.close()


def _refuse_next_commit(store: StateStore) -> _RefusesOneCommit:
    assert store._conn is not None
    proxy = _RefusesOneCommit(store._conn)
    store._conn = proxy  # type: ignore[assignment]
    return proxy


async def _count(store: StateStore, table: str) -> int:
    row = await store._run_read(
        lambda conn: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # noqa: S608
    )
    return int(row[0])


async def test_a_refused_write_is_not_committed_by_the_next(store: StateStore) -> None:
    _refuse_next_commit(store)
    with pytest.raises(sqlite3.OperationalError):
        await store.set_skill_state("skill", "refused", "1")
    await store.set_skill_state("skill", "later", "2")
    assert await store.get_skill_state("skill", "refused") is None
    assert await store.get_skill_state("skill", "later") == "2"


async def test_a_refused_registry_operation_is_not_committed_by_the_next(
    store: StateStore,
) -> None:
    site = Site(store)
    _refuse_next_commit(store)
    with pytest.raises(sqlite3.OperationalError):
        await site.issue("recover", None)
    await store.set_skill_state("skill", "later", "2")
    assert await _count(store, "approver_challenges") == 0


async def test_a_refused_retirement_is_not_committed_by_the_next(
    store: StateStore,
) -> None:
    site = Site(store)
    await site.issue("recover", None)
    _refuse_next_commit(store)
    with pytest.raises(sqlite3.OperationalError):
        await store.retire_approver_runs("another run")
    await store.set_skill_state("skill", "later", "2")
    assert await _count(store, "approver_challenges") == 1


def test_the_registry_leaves_no_transaction_after_a_refused_commit(
    tmp_path: Path,
) -> None:
    """The registry fails closed on its own, without the store around it."""
    conn = sqlite3.connect(tmp_path / "bare.db")
    conn.execute("CREATE TABLE t (v INTEGER)")
    conn.commit()
    proxy = _RefusesOneCommit(conn)

    def write(c: Any) -> Any:
        c.execute("INSERT INTO t VALUES (1)")

    registry = ApproverRegistry.__new__(ApproverRegistry)
    with pytest.raises(sqlite3.OperationalError):
        registry.run(proxy, write)  # type: ignore[arg-type]
    assert not conn.in_transaction
    conn.execute("INSERT INTO t VALUES (2)")
    conn.commit()
    assert conn.execute("SELECT v FROM t").fetchall() == [(2,)]
    conn.close()


async def test_a_refused_hook_write_is_not_committed_by_the_next(
    store: StateStore,
) -> None:
    conn = store._hook_connection()
    store._hook_local.conn = _RefusesOneCommit(conn)
    with pytest.raises(sqlite3.OperationalError):
        store.hooks_set_skill_state("skill", "refused", "1")
    store._hook_busy_until = 0.0
    store.hooks_set_skill_state("skill", "later", "2")
    assert await store.get_skill_state("skill", "refused") is None
    assert await store.get_skill_state("skill", "later") == "2"
