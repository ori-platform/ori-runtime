# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A connection whose open fails after the connect is closed, never collected.

A dropped connection holds its file open, and any write transaction its
statements began, until the collector finds it; a store opened again in that
window waits on its lock.
"""

from __future__ import annotations

import ast
import asyncio
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from ori.security.signing_clock import SigningClock
from ori.state.store import StateStore
from tests.waiting import wait_until

ORI = Path(__file__).resolve().parents[1] / "ori"


def _calls(node: ast.AST, attr: str, name: str) -> bool:
    return any(
        isinstance(sub, ast.Call)
        and isinstance(sub.func, ast.Attribute)
        and sub.func.attr == attr
        and isinstance(sub.func.value, ast.Name)
        and sub.func.value.id == name
        for sub in ast.walk(node)
    )


def _aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Names bound to the sqlite3 module, and to its connect or Connection."""
    modules, functions = {"sqlite3"}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sqlite3":
                    modules.add(alias.asname or "sqlite3")
        elif isinstance(node, ast.ImportFrom) and node.module == "sqlite3":
            for alias in node.names:
                if alias.name in ("connect", "Connection"):
                    functions.add(alias.asname or alias.name)
    return modules, functions


def _is_connect(call: ast.Call, modules: set[str], functions: set[str]) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id in modules and func.attr in ("connect", "Connection")
    return isinstance(func, ast.Name) and func.id in functions


def _called_as(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Whether *node* is the function its parent call invokes."""
    parent = parents.get(node)
    return isinstance(parent, ast.Call) and parent.func is node


def _closes(block: ast.AST | list[ast.stmt], name: str) -> bool:
    """A top-level `name.close()` in the block: nested under an `if`, it may not run."""
    body = block if isinstance(block, list) else getattr(block, "body", [])
    return any(
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Attribute)
        and statement.value.func.attr == "close"
        and isinstance(statement.value.func.value, ast.Name)
        and statement.value.func.value.id == name
        for statement in body
    )


def _catches_all(handler: ast.ExceptHandler) -> bool:
    return handler.type is None or (
        isinstance(handler.type, ast.Name) and handler.type.id == "BaseException"
    )


def _hand_off(statement: ast.stmt, name: str) -> bool:
    """Stored on an object, or returned: from here its owner closes it."""
    if isinstance(statement, ast.Assign):
        return (
            isinstance(statement.value, ast.Name)
            and statement.value.id == name
            and all(isinstance(t, ast.Attribute) for t in statement.targets)
        )
    if isinstance(statement, ast.Return) and statement.value is not None:
        value = statement.value
        parts = value.elts if isinstance(value, ast.Tuple) else [value]
        return any(isinstance(p, ast.Name) and p.id == name for p in parts) and all(
            isinstance(p, (ast.Name, ast.Constant)) for p in parts
        )
    return False


def _row_factory(statement: ast.stmt, name: str, modules: set[str]) -> bool:
    """Setting the row factory to sqlite3.Row, which cannot fail."""
    return (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and ast.unparse(statement.targets[0]) == f"{name}.row_factory"
        and isinstance(statement.value, ast.Attribute)
        and statement.value.attr == "Row"
        and isinstance(statement.value.value, ast.Name)
        and statement.value.value.id in modules
    )


def _is_close(statement: ast.stmt, name: str) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Attribute)
        and statement.value.func.attr == "close"
        and isinstance(statement.value.func.value, ast.Name)
        and statement.value.func.value.id == name
    )


def _closing_with(statement: ast.stmt, name: str) -> bool:
    """`with closed_on_failure(name):` and nothing else in the with."""
    if not isinstance(statement, ast.With) or len(statement.items) != 1:
        return False
    expr = statement.items[0].context_expr
    return (
        isinstance(expr, ast.Call)
        and getattr(expr.func, "id", "") == "closed_on_failure"
        and [ast.unparse(arg) for arg in expr.args] == [name]
        and not expr.keywords
    )


def _closing_handler(statement: ast.stmt, name: str) -> bool:
    """One catch-all handler that closes first and re-raises last, alone."""
    return (
        isinstance(statement, ast.Try)
        and len(statement.handlers) == 1
        and _catches_all(statement.handlers[0])
        and bool(statement.handlers[0].body)
        and _is_close(statement.handlers[0].body[0], name)
        and isinstance(statement.handlers[0].body[-1], ast.Raise)
        and not statement.orelse
        and not statement.finalbody
    )


def _closing_finally(statement: ast.stmt, name: str) -> bool:
    """A finally whose first statement closes: nothing in it runs before."""
    return (
        isinstance(statement, ast.Try)
        and bool(statement.finalbody)
        and _is_close(statement.finalbody[0], name)
    )


def _safe_after(statements: list[ast.stmt], name: str, modules: set[str]) -> bool:
    """Every statement up to the hand-off keeps *name* closed if it fails.

    Conservative: only shapes whose cleanup provably runs are accepted.
    """
    for statement in statements:
        if _hand_off(statement, name):
            return True
        if _row_factory(statement, name, modules) or _closing_with(statement, name):
            continue
        if _closing_finally(statement, name):
            return True  # closed on every path from here
        if _closing_handler(statement, name):
            if any(_hand_off(inner, name) for inner in statement.body):  # type: ignore[attr-defined]
                return True  # handed off inside the guarded body
            continue
        return False
    return False


def _enclosed_safely(tree: ast.AST, target: ast.stmt) -> bool:
    """Whether every construct enclosing *target* lets its hand-off happen.

    Conservative: a connect may sit directly in a function body, in a branch
    of an `if`, or in the body of a plain `try` with no `finally`. Anything
    else (an `except`, `else` or `finally` block, a `with`, a `try` with a
    `finally`, `except*`, a loop, a `match`) can exit around the hand-off,
    and is refused rather than modelled.
    """
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    node: ast.AST = target
    while node in parents:
        parent = parents[node]
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node in parent.body
        if isinstance(parent, ast.If):
            pass
        elif type(parent) is ast.Try and not parent.finalbody and node in parent.body:
            pass
        else:
            return False
        node = parent
    return False


def _following(tree: ast.AST, target: ast.stmt) -> list[ast.stmt]:
    """The statements that run after *target*, up to its function."""
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    after: list[ast.stmt] = []
    node: ast.AST = target
    while node in parents:
        parent = parents[node]
        for field in ("body", "orelse", "finalbody"):
            block = getattr(parent, field, None)
            if isinstance(block, list) and node in block:
                after.extend(block[block.index(node) + 1 :])
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            break
        node = parent
    return after


def _unguarded_connects(source: str, where: str) -> list[str]:
    """Every connect the scan cannot show is closed if its open fails.

    Fails closed: a connect in any shape but `name = connect(...)` (plain or
    annotated) or `return connect(...)` is reported, as is one where any
    statement before its hand-off is not inside `closed_on_failure(name)` or
    a `try` whose `finally`, or catch-all handler, closes it.
    """
    tree = ast.parse(source)
    modules, functions = _aliases(tree)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    found: list[str] = []
    for node in ast.walk(tree):
        # What the scan cannot follow is reported, never assumed safe.
        if isinstance(node, ast.ImportFrom) and node.module in (
            "sqlite3",
            "sqlite3.dbapi2",
        ):
            if node.module == "sqlite3.dbapi2" or any(
                alias.name in ("*", "dbapi2") for alias in node.names
            ):
                found.append(f"{where}:{node.lineno}")
        elif isinstance(node, ast.Import) and any(
            alias.name == "sqlite3.dbapi2" for alias in node.names
        ):
            found.append(f"{where}:{node.lineno}")
        elif isinstance(node, ast.ClassDef) and any(
            ast.unparse(base).endswith("Connection")
            and (
                ast.unparse(base).split(".")[0] in modules
                or ast.unparse(base) in functions
            )
            for base in node.bases
        ):
            found.append(f"{where}:{node.lineno}")
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in modules
            and node.attr in ("connect", "dbapi2")
            and not isinstance(parents.get(node), ast.Call)
        ) or (
            isinstance(node, ast.Name)
            and node.id in functions - {"Connection"}
            and not _called_as(node, parents)
            and not isinstance(parents.get(node), ast.alias)
        ):
            found.append(f"{where}:{node.lineno}")
        elif isinstance(node, ast.Attribute) and isinstance(
            parents.get(node), ast.Call
        ):
            if (
                not _called_as(node, parents)
                and isinstance(node.value, ast.Name)
                and node.value.id in modules
                and node.attr == "connect"
            ):
                found.append(f"{where}:{node.lineno}")
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and _is_connect(call, modules, functions)):
            continue
        statement = parents.get(call)
        # A connect returned at once is its own hand-off, under the same
        # enclosing rule as any other: a finally or an exit can still fail.
        if (
            isinstance(statement, ast.Return)
            and statement.value is call
            and _enclosed_safely(tree, statement)
        ):
            continue
        name: str | None = None
        if isinstance(statement, ast.Assign) and statement.value is call:
            if len(statement.targets) == 1 and isinstance(
                statement.targets[0], ast.Name
            ):
                name = statement.targets[0].id
        elif isinstance(statement, ast.AnnAssign) and statement.value is call:
            if isinstance(statement.target, ast.Name):
                name = statement.target.id
        if (
            name is None
            or not isinstance(statement, ast.stmt)
            or not _safe_after(_following(tree, statement), name, modules)
            or not _enclosed_safely(tree, statement)
        ):
            found.append(f"{where}:{call.lineno}")
    return found


def test_every_connect_is_closed_if_its_open_fails() -> None:
    found = [
        hit
        for path in sorted(ORI.rglob("*.py"))
        for hit in _unguarded_connects(
            path.read_text(encoding="utf-8"), str(path.relative_to(ORI.parent))
        )
    ]
    assert found == [], (
        "a connection is used after its connect with nothing closing it if that "
        "use fails; wrap the use in ori.utils.sqlite_utils.closed_on_failure. "
        "This scan sees connects in the module they are made in, and reports any "
        "reference to connect it cannot follow; a connection a helper returns is "
        "the caller's to guard, and fully dynamic lookups (getattr, importlib) "
        "are invisible to it; only the behavioural tests below check those."
    )


GUARDED = (
    "def h(p, ok):\n    if ok:\n        conn = sqlite3.connect(p)\n"
    "        conn.row_factory = sqlite3.Row\n        return conn\n    return None\n",
    "def i(p):\n    try:\n        conn = sqlite3.connect(p)\n"
    "        with closed_on_failure(conn):\n            conn.execute('a')\n"
    "    except sqlite3.Error:\n        return None\n    return conn\n",
    "def g(self, p):\n    conn = sqlite3.connect(p)\n    try:\n        self.c = conn\n"
    "        conn.execute('x')\n    except BaseException:\n        conn.close()\n"
    "        self.c = None\n        raise\n",
    "def a(p):\n    conn = sqlite3.connect(p)\n    with closed_on_failure(conn):\n"
    "        conn.execute('x')\n    return conn\n",
    "def b(p):\n    conn = sqlite3.connect(p)\n    conn.row_factory = sqlite3.Row\n"
    "    return conn\n",
    "def c(p):\n    conn = sqlite3.connect(p)\n    try:\n        conn.execute('x')\n"
    "    finally:\n        conn.close()\n",
    "def d(self, p):\n    conn = sqlite3.connect(p)\n    try:\n        conn.execute('x')\n"
    "    except BaseException:\n        conn.close()\n        raise\n    self.c = conn\n",
    "def e(p):\n    return sqlite3.connect(p)\n",
    "def e2(p, ok):\n    if ok:\n        try:\n            return sqlite3.connect(p)\n"
    "        except sqlite3.Error:\n            return None\n    return None\n",
)
UNGUARDED = (
    # work after the guarded block, before the hand-off
    "def f(p):\n    conn = sqlite3.connect(p)\n    with closed_on_failure(conn):\n"
    "        pass\n    conn.execute('x')\n    return conn\n",
    # the guard names another connection
    "def f(p, other):\n    conn = sqlite3.connect(p)\n    with closed_on_failure(other):\n"
    "        conn.execute('x')\n    return conn\n",
    # closed only on an unrelated exception
    "def f(p):\n    conn = sqlite3.connect(p)\n    try:\n        conn.execute('x')\n"
    "    except KeyError:\n        conn.close()\n    return conn\n",
    "def f(p):\n    conn: sqlite3.Connection = sqlite3.connect(p)\n"
    "    conn.execute('x')\n    return conn\n",
    "import sqlite3 as sq\ndef f(p):\n    conn = sq.connect(p)\n    conn.execute('x')\n"
    "    return conn\n",
    "from sqlite3 import connect\ndef f(p):\n    conn = connect(p)\n"
    "    conn.execute('x')\n    return conn\n",
    "def f(p):\n    with sqlite3.connect(p) as conn:\n        conn.execute('x')\n",
    "def f(self, p):\n    self.c = sqlite3.connect(p)\n    self.c.execute('x')\n",
    "def f(p):\n    use(sqlite3.connect(p))\n",
    "def f(p):\n    conn = sqlite3.connect(p)\n    return conn.execute('x')\n",
    "def f(p):\n    conn = sqlite3.connect(p)\n    conn.row_factory = make()\n"
    "    return conn\n",
    "def f(p):\n    conn = sqlite3.connect(p)\n",
    # an else clause runs outside the catch-all handler
    "def f(p):\n    conn = sqlite3.connect(p)\n    try:\n        pass\n"
    "    except BaseException:\n        conn.close()\n        raise\n"
    "    else:\n        conn.execute('a')\n    return conn\n",
    # a conditional close may not run
    "def f(p, never):\n    conn = sqlite3.connect(p)\n    try:\n        conn.execute('a')\n"
    "    except BaseException:\n        if never:\n            conn.close()\n"
    "        raise\n    return conn\n",
    "def f(p):\n    opener = sqlite3.connect\n    return opener(p)\n",
    "import sqlite3.dbapi2 as db\ndef f(p):\n    return db.connect(p)\n",
    "from sqlite3 import dbapi2\ndef f(p):\n    return dbapi2.connect(p)\n",
    "from sqlite3 import *\ndef f(p):\n    return connect(p)\n",
    "def f(p):\n    return functools.partial(sqlite3.connect, p)()\n",
    "class C(sqlite3.Connection):\n    pass\n",
    # an earlier handler swallows before the closing one
    "def f(p):\n    conn = sqlite3.connect(p)\n    try:\n        conn.execute('a')\n"
    "    except KeyError:\n        pass\n    except BaseException:\n"
    "        conn.close()\n        raise\n    return conn\n",
    # finally raises before close
    "def f(p):\n    conn = sqlite3.connect(p)\n    try:\n        conn.execute('a')\n"
    "    finally:\n        boom()\n        conn.close()\n",
    # another context manager can fail before the guard enters
    "def f(p):\n    conn = sqlite3.connect(p)\n    with other(), closed_on_failure(conn):\n"
    "        conn.execute('a')\n    return conn\n",
    # a failing finally follows the guarded body
    "def f(p):\n    try:\n        conn = sqlite3.connect(p)\n"
    "        with closed_on_failure(conn):\n            conn.execute('a')\n"
    "        return conn\n    finally:\n        boom()\n",
    # connect in an except block, a raising finally after
    "def f(p):\n    try:\n        pass\n    except KeyError:\n"
    "        conn = sqlite3.connect(p)\n        return conn\n    finally:\n"
    "        boom()\n",
    # connect in an else block
    "def f(p):\n    try:\n        pass\n    except KeyError:\n        pass\n"
    "    else:\n        conn = sqlite3.connect(p)\n        return conn\n",
    # connect inside a context manager whose exit can raise
    "def f(p):\n    with ctx():\n        conn = sqlite3.connect(p)\n        return conn\n",
    # connect inside try/except*
    "def f(p):\n    try:\n        conn = sqlite3.connect(p)\n        return conn\n"
    "    except* KeyError:\n        pass\n",
    # returned at once, inside each enclosure that can fail around the return
    "def f(p):\n    try:\n        return sqlite3.connect(p)\n    finally:\n"
    "        boom()\n",
    "def f(p):\n    with ctx():\n        return sqlite3.connect(p)\n",
    "def f(p):\n    try:\n        pass\n    except KeyError:\n"
    "        return sqlite3.connect(p)\n",
    "def f(p):\n    try:\n        pass\n    finally:\n        return sqlite3.connect(p)\n",
    "def f(p):\n    try:\n        return sqlite3.connect(p)\n    except* KeyError:\n"
    "        pass\n",
    "def f(p):\n    for _ in range(1):\n        return sqlite3.connect(p)\n",
    "def f(p):\n    async with ctx():\n        return sqlite3.connect(p)\n",
    # connect at module level
    "conn = sqlite3.connect('x')\n",
    # connect inside a loop
    "def f(p):\n    for _ in range(1):\n        conn = sqlite3.connect(p)\n"
    "        return conn\n",
)


@pytest.mark.parametrize("source", GUARDED)
def test_the_guard_accepts_a_guarded_shape(source: str) -> None:
    assert _unguarded_connects(source, "x") == []


@pytest.mark.parametrize("source", UNGUARDED)
def test_the_guard_refuses_an_unguarded_shape(source: str) -> None:
    assert _unguarded_connects(source, "x") != []


def test_closed_on_failure_closes_on_an_interrupt_too() -> None:
    from ori.utils.sqlite_utils import closed_on_failure

    def interrupted() -> None:
        raise KeyboardInterrupt

    conn = _Failing(":memory:")
    with pytest.raises(KeyboardInterrupt), closed_on_failure(conn):
        interrupted()
    assert conn.closed


async def test_a_store_whose_history_read_fails_closes_its_writer(
    tmp_path: Path, failing: type[_Failing], monkeypatch: pytest.MonkeyPatch
) -> None:
    store = StateStore(db_path=str(tmp_path / "state.db"))

    def failing_read(_conn: sqlite3.Connection) -> int:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store, "_history_sequence_sync", failing_read)
    with pytest.raises(sqlite3.OperationalError):
        await store.open()
    # Closed on the writer thread: drained once that thread runs what follows.
    assert store._write_executor is not None
    await asyncio.get_running_loop().run_in_executor(
        store._write_executor, lambda: None
    )
    assert store._conn is None and failing.opened[0].closed


async def test_a_reopen_whose_setup_fails_leaves_no_connection(
    tmp_path: Path, failing: type[_Failing], monkeypatch: pytest.MonkeyPatch
) -> None:
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    await store.close()
    opened = len(failing.opened)

    def failing_writer() -> Any:
        raise RuntimeError("setup failed")

    monkeypatch.setattr(store, "_new_history_writer", failing_writer)
    with pytest.raises(RuntimeError):
        await store.open()
    assert store._conn is None
    assert all(conn.closed for conn in failing.opened[opened:])
    monkeypatch.undo()
    await store.open()
    assert store._conn is not None
    await store.close()


class _Failing(sqlite3.Connection):
    """A connection that fails its first statement matching ``fail_on``."""

    fail_on = ""
    opened: list[_Failing] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.closed = False
        _Failing.opened.append(self)

    def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:  # type: ignore[override]
        if _Failing.fail_on and _Failing.fail_on in sql:
            raise sqlite3.OperationalError("disk I/O error")
        return super().execute(sql, *args)

    def close(self) -> None:
        import threading

        self.closed = True
        self.closed_on = threading.current_thread().name
        super().close()


@pytest.fixture
def failing(monkeypatch: pytest.MonkeyPatch) -> type[_Failing]:
    connect = sqlite3.connect
    _Failing.opened = []
    _Failing.fail_on = ""

    def connecting(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        kwargs.setdefault("factory", _Failing)
        return connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", connecting)
    return _Failing


async def test_a_store_whose_migration_fails_closes_its_connection(
    tmp_path: Path, failing: type[_Failing], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A migration's write is left uncommitted; the next writer is not held."""
    db = tmp_path / "state.db"
    store = StateStore(db_path=str(db))

    def failing_migration(conn: sqlite3.Connection) -> None:
        conn.execute("CREATE TABLE IF NOT EXISTS t (x INTEGER)")
        conn.execute("INSERT INTO t VALUES (1)")
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store, "_migrate_sync", failing_migration)
    with pytest.raises(sqlite3.OperationalError) as refused:
        await store.open()
    writer = failing.opened[-1]
    assert writer.closed
    # The refusal is still held, and its frames with it: only an explicit
    # close, not the collector, can have released the write lock.
    assert refused.value is not None
    other = sqlite3.connect(db, timeout=0, isolation_level=None)
    try:
        other.execute("BEGIN IMMEDIATE")
        other.execute("ROLLBACK")
    finally:
        other.close()


async def test_a_read_connection_whose_pragma_fails_is_closed(
    tmp_path: Path, failing: type[_Failing]
) -> None:
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        failing.fail_on = "PRAGMA foreign_keys"
        before = len(failing.opened)
        with pytest.raises(sqlite3.OperationalError):
            store._open_read_conn_sync()
        assert failing.opened[before:] and all(
            c.closed for c in failing.opened[before:]
        )
    finally:
        failing.fail_on = ""
        await store.close()


def test_a_signing_clock_whose_open_fails_closes_every_attempt(
    tmp_path: Path, failing: type[_Failing]
) -> None:
    """It retries every second while the store fails: no attempt is leaked."""
    failing.fail_on = "PRAGMA synchronous"
    clock = SigningClock(str(tmp_path / "state.db"))
    try:
        for _ in range(3):
            assert clock._open() is None
        assert len(failing.opened) >= 3 and all(c.closed for c in failing.opened)
    finally:
        failing.fail_on = ""
        clock.stop()


async def test_a_cancelled_open_closes_the_connection_the_writer_still_makes(
    tmp_path: Path, failing: type[_Failing], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cancelled while the writer migrates: the writer finishes the open on its
    own, and the connection it returns is closed, never left live."""
    import threading

    store = StateStore(db_path=str(tmp_path / "state.db"))
    migrating, release = threading.Event(), threading.Event()
    migrate = store._migrate_sync

    def paused_migration(conn: sqlite3.Connection) -> None:
        migrating.set()
        release.wait(5)
        migrate(conn)

    monkeypatch.setattr(store, "_migrate_sync", paused_migration)
    opening = asyncio.ensure_future(store.open())
    try:
        while not migrating.is_set():
            await asyncio.sleep(0.01)
        opening.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(opening, timeout=10)
    finally:
        release.set()
    assert store._write_executor is not None
    executor = store._write_executor
    loop = asyncio.get_running_loop()
    # The open, then the close its done-callback submits, both on the writer.
    await loop.run_in_executor(executor, lambda: None)
    await asyncio.sleep(0)
    await loop.run_in_executor(executor, lambda: None)
    assert store._conn is None
    assert failing.opened and all(c.closed for c in failing.opened)


def _paused_store(
    path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[StateStore, Any, Any]:
    import threading

    store = StateStore(db_path=str(path))
    migrating, release = threading.Event(), threading.Event()
    migrate = store._migrate_sync

    def paused_migration(conn: sqlite3.Connection) -> None:
        migrating.set()
        release.wait(10)
        migrate(conn)

    monkeypatch.setattr(store, "_migrate_sync", paused_migration)
    return store, migrating, release


def _closed_on_the_writer(failing: type[_Failing]) -> bool:
    return bool(failing.opened) and all(
        c.closed and c.closed_on.startswith("ori-store-write") for c in failing.opened
    )


def test_a_loop_shut_down_mid_open_still_closes_on_the_writer(
    tmp_path: Path, failing: type[_Failing], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`asyncio.run` returns while the writer migrates: its shutdown cancels
    every task, and the writer job closes the connection it goes on to make."""
    import time

    store, migrating, release = _paused_store(tmp_path / "state.db", monkeypatch)

    async def main() -> None:
        asyncio.ensure_future(store.open())
        await asyncio.to_thread(migrating.wait, 10)

    asyncio.run(main())
    release.set()
    deadline = time.monotonic() + 10
    while not _closed_on_the_writer(failing) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert _closed_on_the_writer(failing)
    assert store._conn is None


async def test_a_store_closed_after_a_cancelled_open_still_closes_on_the_writer(
    tmp_path: Path, failing: type[_Failing], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, migrating, release = _paused_store(tmp_path / "state.db", monkeypatch)
    opening = asyncio.ensure_future(store.open())
    while not migrating.is_set():
        await asyncio.sleep(0.01)
    opening.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(opening, timeout=10)
    await store.close()  # clears the executor before the open job finishes
    release.set()
    await wait_until(
        lambda: _closed_on_the_writer(failing),
        what="the abandoned open's connection closed on the writer thread",
    )
    assert store._conn is None


async def test_an_open_abandoned_after_delivery_closes_what_was_delivered(
    tmp_path: Path, failing: type[_Failing], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The writer job delivered its connection; the cancellation lands before
    the open takes it. The open closes what was delivered."""
    store = StateStore(db_path=str(tmp_path / "state.db"))

    async def delivered_then_cancelled(fn: Any, *args: Any) -> Any:
        fn(*args)  # the real job: opens, reads, delivers
        raise asyncio.CancelledError

    monkeypatch.setattr(store, "_on_writer", delivered_then_cancelled)
    with pytest.raises(asyncio.CancelledError):
        await store.open()
    assert failing.opened and all(c.closed for c in failing.opened)
    assert store._conn is None
