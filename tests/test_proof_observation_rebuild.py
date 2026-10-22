# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The legacy commissioning proof table is rebuilt atomically, or finished.

A proof observation is the audit of a consent and the coil command it
permitted, so no step of the rebuild may lose one.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from ori.state.store import StateStore

LEGACY = "_commissioning_proof_observation_legacy"
OLD_SCHEMA = """
CREATE TABLE {name} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binding_hash TEXT NOT NULL, zone_id TEXT NOT NULL,
    gpio_pin INTEGER NOT NULL, active_high INTEGER NOT NULL,
    outcome TEXT NOT NULL, coil_state_commanded TEXT NOT NULL,
    level_driven TEXT NOT NULL, consent_nonce TEXT NOT NULL,
    consented_at_ms INTEGER NOT NULL, commanded_at_ms INTEGER NOT NULL,
    executed INTEGER NOT NULL, observation_json TEXT, outcome_note TEXT
)
"""


def _old_rows(conn: sqlite3.Connection, table: str, ids: range) -> None:
    for row_id in ids:
        conn.execute(
            f"INSERT INTO {table} (id, binding_hash, zone_id, gpio_pin, active_high, "  # noqa: S608
            "outcome, coil_state_commanded, level_driven, consent_nonce, "
            "consented_at_ms, commanded_at_ms, executed, observation_json, "
            "outcome_note) VALUES (?, 'sha256:old', 'bench', 26, 1, "
            "'open_protected_circuit', 'energised', 'high', ?, 1, 2, 1, NULL, ?)",
            (row_id, f"N{row_id}", f"row {row_id}"),
        )


def _legacy_store(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute(OLD_SCHEMA.format(name="commissioning_proof_observation"))
    _old_rows(conn, "commissioning_proof_observation", range(1, 4))
    conn.commit()
    conn.close()


def _tables(path: Path) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        return {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    finally:
        conn.close()


async def _notes(path: Path) -> list[str]:
    store = StateStore(str(path))
    await store.open()
    try:
        rows = await store.commissioning_proof_observations("sha256:old")
    finally:
        await store.close()
    return sorted(row["outcome_note"] for row in rows)


class _FailsOn(sqlite3.Connection):
    fail_on = ""

    def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:  # type: ignore[override]
        if _FailsOn.fail_on and _FailsOn.fail_on in sql:
            raise sqlite3.OperationalError("disk I/O error")
        return super().execute(sql, *args)


@pytest.mark.parametrize(
    "step", ["INSERT INTO commissioning_proof_observation", "DROP TABLE"]
)
async def test_a_rebuild_that_fails_partway_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    db = tmp_path / "state.db"
    _legacy_store(db)
    connect = sqlite3.connect

    def failing(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        kwargs.setdefault("factory", _FailsOn)
        return connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", failing)
    _FailsOn.fail_on = step
    try:
        with pytest.raises(sqlite3.OperationalError):
            await StateStore(str(db)).open()
    finally:
        _FailsOn.fail_on = ""
        monkeypatch.setattr(sqlite3, "connect", connect)
    # Rolled back whole: still the old table, under its own name, every row.
    assert LEGACY not in _tables(db)
    conn = sqlite3.connect(db)
    try:
        columns = {
            r[1]
            for r in conn.execute("PRAGMA table_info(commissioning_proof_observation)")
        }
        count = conn.execute(
            "SELECT COUNT(*) FROM commissioning_proof_observation"
        ).fetchone()
    finally:
        conn.close()
    assert "executed" in columns and count == (3,)
    assert await _notes(db) == ["row 1", "row 2", "row 3"]
    assert LEGACY not in _tables(db)


async def test_a_store_an_earlier_rebuild_stranded_is_finished(tmp_path: Path) -> None:
    """The earlier rebuild committed the rename, then crashed: the rows sit in
    the legacy table and the current one is empty."""
    db = tmp_path / "state.db"
    _legacy_store(db)
    conn = sqlite3.connect(db)
    conn.execute(f"ALTER TABLE commissioning_proof_observation RENAME TO {LEGACY}")
    conn.commit()
    conn.close()
    # A first open of the current build creates the empty current table.
    assert await _notes(db) == ["row 1", "row 2", "row 3"]
    assert LEGACY not in _tables(db)


async def test_a_partly_carried_store_gains_no_duplicate(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    _legacy_store(db)
    store = StateStore(str(db))
    await store.open()
    await store.close()
    # Strand rows 1-3 again beside a current table already holding row 1.
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM commissioning_proof_observation WHERE id > 1")
    conn.execute(OLD_SCHEMA.format(name=LEGACY))
    _old_rows(conn, LEGACY, range(1, 4))
    conn.commit()
    conn.close()
    assert await _notes(db) == ["row 1", "row 2", "row 3"]
    assert LEGACY not in _tables(db)


async def test_two_legacy_tables_refuse_to_open(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    _legacy_store(db)
    conn = sqlite3.connect(db)
    conn.execute(OLD_SCHEMA.format(name=LEGACY))
    conn.commit()
    conn.close()
    with pytest.raises(sqlite3.DatabaseError, match="needs repair"):
        await StateStore(str(db)).open()


async def test_rows_written_after_a_stranding_keep_every_legacy_row(
    tmp_path: Path,
) -> None:
    """The earlier rebuild stranded rows 1-3 and the store went on: the empty
    current table, its id sequence taken with the legacy table, wrote new rows
    from id 1. Every one of the five observations survives the carry-over."""
    from ori.state._migrations import _PROOF_OBSERVATION_DDL

    db = tmp_path / "state.db"
    conn = sqlite3.connect(db)
    # What the earlier build left: rows 1-3 stranded under the legacy name,
    # and a current table that has since recorded two observations of its own.
    conn.execute(OLD_SCHEMA.format(name=LEGACY))
    _old_rows(conn, LEGACY, range(1, 4))
    conn.execute(_PROOF_OBSERVATION_DDL)
    for row_id in (1, 2):
        conn.execute(
            "INSERT INTO commissioning_proof_observation (id, binding_hash, zone_id, "
            "gpio_pin, active_high, outcome, coil_state_commanded, level_driven, "
            "consent_nonce, consented_at_ms, commanded_at_ms, command_issued, "
            "release_requested, outcome_note) VALUES (?, 'sha256:old', 'bench', 26, "
            "1, 'open_protected_circuit', 'energised', 'high', ?, 9, 10, 1, 0, ?)",
            (row_id, f"NEW{row_id}", f"new {row_id}"),
        )
    conn.commit()
    conn.close()
    assert await _notes(db) == ["new 1", "new 2", "row 1", "row 2", "row 3"]
    assert LEGACY not in _tables(db)


def test_pending_earlier_work_is_committed_before_the_rebuild(tmp_path: Path) -> None:
    """An earlier step's implicit transaction is kept, not lost to the rebuild."""
    from ori.state._migrations import StoreMigrations

    db = tmp_path / "state.db"
    _legacy_store(db)
    conn = sqlite3.connect(db)
    try:
        conn.execute("CREATE TABLE earlier (x INTEGER)")
        conn.execute("INSERT INTO earlier VALUES (1)")
        assert conn.in_transaction
        assert StoreMigrations._rebuild_proof_observation_if_legacy(
            StoreMigrations.__new__(StoreMigrations), conn
        )
    finally:
        conn.close()
    check = sqlite3.connect(db)
    try:
        assert check.execute("SELECT x FROM earlier").fetchall() == [(1,)]
    finally:
        check.close()


async def test_identity_is_the_whole_consent_and_a_free_id_is_kept(
    tmp_path: Path,
) -> None:
    """A current row sharing a legacy row's nonce, but not its binding or its
    consent time, is another observation: both are kept. A legacy row whose
    id is free keeps that id."""
    from ori.state._migrations import _PROOF_OBSERVATION_DDL

    db = tmp_path / "state.db"
    conn = sqlite3.connect(db)
    conn.execute(OLD_SCHEMA.format(name=LEGACY))
    _old_rows(conn, LEGACY, range(1, 4))  # nonces N1-N3, consented at 1
    conn.execute(_PROOF_OBSERVATION_DDL)
    for row_id, binding, nonce, consented in (
        (10, "sha256:other", "N1", 1),  # N1, another binding
        (11, "sha256:old", "N2", 99),  # N2, another consent time
    ):
        conn.execute(
            "INSERT INTO commissioning_proof_observation (id, binding_hash, zone_id, "
            "gpio_pin, active_high, outcome, coil_state_commanded, level_driven, "
            "consent_nonce, consented_at_ms, commanded_at_ms, command_issued, "
            "release_requested, outcome_note) VALUES (?, ?, 'bench', 26, 1, "
            "'open_protected_circuit', 'energised', 'high', ?, ?, 10, 1, 0, ?)",
            (row_id, binding, nonce, consented, f"current {row_id}"),
        )
    conn.commit()
    conn.close()
    store = StateStore(str(db))
    await store.open()
    await store.close()
    check = sqlite3.connect(db)
    try:
        rows = dict(
            check.execute(
                "SELECT id, outcome_note FROM commissioning_proof_observation"
            ).fetchall()
        )
    finally:
        check.close()
    assert rows == {
        1: "row 1",
        2: "row 2",
        3: "row 3",
        10: "current 10",
        11: "current 11",
    }
