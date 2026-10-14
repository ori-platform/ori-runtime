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
from typing import Any

import pytest

from ori.security.evidence.store import (
    EvidenceConnection,
    EvidenceStoreFaultError,
    NestedEvidenceTransactionError,
)

PACKAGE = pathlib.Path(__file__).resolve().parents[2] / "ori" / "security" / "evidence"
HELPER = PACKAGE / "store.py"
_CONTROL = ("BEGIN", "COMMIT", "ROLLBACK", "END", "SAVEPOINT", "RELEASE")


#: The schema scripts at open, the only places `executescript` may run:
#: it commits whatever is open first, so anywhere else it splits a transaction.
SCHEMA_SCRIPTS = {("chain.py", "__init__"), ("ledger.py", "__init__")}
_CONNECTION_NAMES = ("connection", "_connection", "conn", "_live", "db")


def _named(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _raw_transactions(path: pathlib.Path) -> list[str]:
    """Every literal way to run a transaction outside the helper, by line."""
    found = []
    tree = ast.parse(path.read_text())
    owner: dict[ast.AST, str] = {}
    for function in ast.walk(tree):
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for inner in ast.walk(function):
                owner.setdefault(inner, function.name)
    where = (
        str(path.relative_to(PACKAGE)) if path.is_relative_to(PACKAGE) else path.name
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            words = node.value.split()
            # Uppercase as SQL is written here, or any case as a whole short
            # statement; prose that begins with the word is not one.
            if words and (
                words[0] in _CONTROL
                or (words[0].upper() in _CONTROL and len(words) <= 3)
            ):
                found.append(f"{where}:{node.lineno} {node.value!r}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("commit", "rollback"):
                found.append(f"{where}:{node.lineno} .{node.func.attr}()")
            if (
                node.func.attr == "executescript"
                and (
                    path.name,
                    owner.get(node, ""),
                )
                not in SCHEMA_SCRIPTS
            ):
                found.append(f"{where}:{node.lineno} .executescript()")
        if isinstance(node, ast.Call) and any(
            keyword.arg == "isolation_level" for keyword in node.keywords
        ):
            found.append(f"{where}:{node.lineno} isolation_level=")
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(_named(target) == "isolation_level" for target in targets):
                found.append(f"{where}:{node.lineno} isolation_level assignment")
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if _named(item.context_expr).endswith(_CONNECTION_NAMES):
                    found.append(
                        f"{where}:{node.lineno} with {_named(item.context_expr)}:"
                    )
    return found


def test_no_evidence_module_opens_a_transaction_outside_the_helper() -> None:
    offenders = [
        hit
        for path in sorted(PACKAGE.rglob("*.py"))
        if path != HELPER
        for hit in _raw_transactions(path)
    ]
    assert not offenders, (
        "a transaction is opened, committed, rolled back, split by "
        "executescript, run as `with <connection>:` or given an isolation "
        "level outside EvidenceConnection.transaction(), where a failed "
        f"rollback is never healed: {offenders}. This guard reads literals and "
        "syntax only; a statement built at runtime, or a connection under "
        "another name, is not seen."
    )


@pytest.mark.parametrize(
    "source",
    [
        'c.execute("BEGIN IMMEDIATE")',
        'c.execute("rollback")',
        "c.commit()",
        "def f():\n    c.executescript(s)",
        "with self._connection:\n    pass",
        "c.isolation_level = 'DEFERRED'",
        "sqlite3.connect(p, isolation_level=None)",
    ],
)
def test_the_guard_refuses_each_raw_shape(tmp_path, source) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text(source + "\n")
    assert _raw_transactions(probe), source


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


def test_a_nested_transaction_is_refused_and_the_outer_keeps_its_own(
    store_path,
) -> None:
    """Refused, not healed as a leak: the outer commits exactly its writes."""
    store = EvidenceConnection(str(store_path))
    with store.transaction() as connection:
        connection.execute("CREATE TABLE t (x INTEGER)")
    with store.transaction() as connection:
        connection.execute("INSERT INTO t VALUES (1)")
        with pytest.raises(NestedEvidenceTransactionError):
            with store.transaction():
                pass  # pragma: no cover - refused on entry
        connection.execute("INSERT INTO t VALUES (2)")
        assert connection is store.connection, "the outer was discarded"

    rows = [r[0] for r in store.connection.execute("SELECT x FROM t ORDER BY x")]
    assert rows == [1, 2]
    store.close()


def test_the_original_error_survives_a_rollback_on_a_discarded_connection(
    store_path,
) -> None:
    store = EvidenceConnection(str(store_path))
    with store.transaction() as connection:
        connection.execute("CREATE TABLE t (x INTEGER)")

    with pytest.raises(LookupError, match="the original"):
        with store.transaction() as connection:
            connection.execute("INSERT INTO t VALUES (1)")
            store._discard()
            raise LookupError("the original")

    assert store.connection.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0
    store.close()


class _RefusingBegin:
    """A connection whose BEGIN fails as a busy store would."""

    def __init__(self, real: sqlite3.Connection) -> None:
        self._real = real

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)

    def execute(self, sql: str, parameters: Any = ()) -> sqlite3.Cursor:
        if sql.startswith("BEGIN"):
            raise sqlite3.OperationalError("database is locked")
        return self._real.execute(sql, parameters)


def test_a_store_error_at_begin_is_raised_as_the_callers_error(store_path) -> None:
    store = EvidenceConnection(str(store_path))
    store.connection = _RefusingBegin(store.connection)  # type: ignore[assignment]

    with pytest.raises(ValueError, match="could not begin") as raised:
        with store.transaction(on_begin_failure=lambda: ValueError("could not begin")):
            pass  # pragma: no cover - BEGIN failed

    assert isinstance(raised.value.__cause__, sqlite3.OperationalError)
    store.close()


def test_a_reopen_opens_the_file_it_was_given_wherever_the_process_now_is(
    tmp_path, monkeypatch
) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.chdir(first)
    store = EvidenceConnection("evidence.db")
    with store.transaction() as connection:
        connection.execute("CREATE TABLE t (x INTEGER)")
        connection.execute("INSERT INTO t VALUES (7)")
    sqlite3.connect(second / "evidence.db").close()

    monkeypatch.chdir(second)
    store._discard()

    assert store.connection.execute("SELECT x FROM t").fetchone()[0] == 7
    store.close()
