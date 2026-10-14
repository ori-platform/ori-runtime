# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The evidence store's one transaction helper, and its reopen.

A raw BEGIN, COMMIT or ROLLBACK anywhere else in the evidence package is a
transaction whose failed rollback nothing heals, so the guard below refuses
one wherever it is spelled as a literal. It cannot see a statement assembled
at runtime, or one issued through a connection the package does not own.
"""

from __future__ import annotations

import ast
import pathlib
import sqlite3

import pytest

from ori.security.evidence.store import (
    EvidenceConnection,
    EvidenceStoreFaultError,
)

PACKAGE = pathlib.Path(__file__).resolve().parents[2] / "ori" / "security" / "evidence"
HELPER = PACKAGE / "store.py"
_CONTROL = ("BEGIN", "COMMIT", "ROLLBACK", "END", "SAVEPOINT", "RELEASE")


def _raw_transactions(path: pathlib.Path) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            words = node.value.split()
            # Uppercase as SQL is written here, or any case as a whole short
            # statement; prose that begins with the word is not one.
            if words and (
                words[0] in _CONTROL
                or (words[0].upper() in _CONTROL and len(words) <= 3)
            ):
                found.append(f"{path.name}:{node.lineno} {node.value!r}")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("commit", "rollback")
        ):
            found.append(f"{path.name}:{node.lineno} .{node.func.attr}()")
    return found


def test_no_evidence_module_opens_a_transaction_outside_the_helper() -> None:
    offenders = [
        hit
        for path in sorted(PACKAGE.glob("*.py"))
        if path != HELPER
        for hit in _raw_transactions(path)
    ]
    assert not offenders, (
        "a transaction is opened, committed or rolled back outside "
        "EvidenceConnection.transaction(), where a failed rollback is never "
        f"healed: {offenders}. This guard reads literals only; a statement "
        "built at runtime is not seen."
    )


def test_the_guard_sees_the_helper_it_exempts() -> None:
    """Pointed at the helper, the scan must find its statements."""
    assert len(_raw_transactions(HELPER)) >= 3


@pytest.fixture(
    params=["plain", "with?query#fragment%41"], ids=["plain", "uri-characters"]
)
def store_path(tmp_path, request) -> pathlib.Path:
    directory = tmp_path / request.param
    directory.mkdir()
    return directory / "evidence.db"


def _pragmas(connection: sqlite3.Connection) -> dict[str, object]:
    return {
        name: connection.execute(f"PRAGMA {name}").fetchone()[0]
        for name in ("busy_timeout", "journal_mode", "foreign_keys", "synchronous")
    }


def test_a_reopen_opens_the_same_file_under_the_same_pragmas(store_path) -> None:
    store = EvidenceConnection(str(store_path))
    with store.transaction() as connection:
        connection.execute("CREATE TABLE t (x INTEGER)")
        connection.execute("INSERT INTO t VALUES (7)")
    store._discard()

    assert store.connection.execute("SELECT x FROM t").fetchone()[0] == 7
    assert _pragmas(store.connection) == {
        "busy_timeout": 5000,
        "journal_mode": "wal",
        "foreign_keys": 1,
        "synchronous": 2,
    }
    store.close()


def test_a_reopen_never_creates_the_file_it_lost(store_path) -> None:
    """Under a dropped mount, a new empty file would pin the wrong inode."""
    store = EvidenceConnection(str(store_path))
    store.close()
    store_path.rename(store_path.with_name("moved.db"))
    store._reopen_owed = True

    with pytest.raises(EvidenceStoreFaultError):
        _ = store.connection

    assert not store_path.exists()
    assert sorted(p.name for p in store_path.parent.iterdir()) == ["moved.db"]
