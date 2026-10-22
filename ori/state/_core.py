# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Connections, executors and the lifecycle every store domain runs on."""

import asyncio
import contextlib
import functools
import logging
import math
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Concatenate, Optional, ParamSpec, TypeVar

from ori.state._migrations import StoreMigrations
from ori.state.deferred_writer import DeferredWriter

_P = ParamSpec("_P")


_T = TypeVar("_T")


#: The oldest SQLite this store's queries are known to run on.
#:
#: The sensor-history averages and the compaction read path use a ``HAVING``
#: clause on an aggregate query that has no ``GROUP BY``. SQLite refused that
#: form with ``a GROUP BY clause is required before HAVING`` until it was
#: allowed on any aggregate query, so on an older library those reads fail at
#: query time rather than at startup. An operator meets that as a skill that
#: stopped working, which is the wrong place to learn the platform is
#: unsupported.
#:
#: Measured rather than inferred from release notes. 3.34.1 (Debian Bullseye)
#: and 3.37.2 (Ubuntu 22.04) refuse the form; 3.40.1 (Debian Bookworm) and
#: 3.46.1 (Debian Trixie) accept it, which bounds the floor to this release.
#:
#: ``sqlite3`` binds to whatever library the host supplies, so this is the one
#: dependency the hash-locked wheelhouse cannot pin. The stock distribution
#: tuples this runtime is tested on clear the floor with their own libraries:
#: Debian Bookworm 3.40.1, Ubuntu 24.04 3.45.1, Debian Trixie 3.46.1.
#:
#: Clearing the interpreter floor does not imply clearing this one, and the two
#: must not be conflated. A newer Python built by hand on an older
#: distribution -- the trusted-symlink shape the installer admits by design --
#: satisfies the interpreter requirement while the host library stays where the
#: distribution left it. That combination is what this refusal exists to
#: catch.
MINIMUM_SQLITE_VERSION = (3, 39, 0)


class UnsupportedSQLiteError(RuntimeError):
    """The host's SQLite library is too old for this store's queries."""


def require_supported_sqlite() -> None:
    """Refuse a SQLite that cannot run the queries this store issues.

    Compared as a tuple of integers. Comparing the version *strings* would
    order ``"3.9"`` after ``"3.40"``, so a lexical check would admit exactly
    the old libraries this exists to refuse.
    """
    if sqlite3.sqlite_version_info >= MINIMUM_SQLITE_VERSION:
        return
    required = ".".join(str(part) for part in MINIMUM_SQLITE_VERSION)
    raise UnsupportedSQLiteError(
        f"SQLite {sqlite3.sqlite_version} is too old for this runtime; "
        f"{required} or newer is required. Python's `sqlite3` uses the library "
        f"the host supplies, so this is a property of the platform rather than "
        f"of the installed dependencies -- upgrade the distribution, or build "
        f"the interpreter against a newer SQLite."
    )


_SQLITE_INT_MIN = -(2**63)


_SQLITE_INT_MAX = 2**63 - 1


def _audit_bindable(value: Any) -> Any:
    """A value as an audit row can hold it, so a refusal or decision is never
    lost to how it was spelled: lone surrogates escaped, and an integer outside
    SQLite's range or a non-finite float recorded as NULL rather than as a
    plausible number the producer never sent."""
    if isinstance(value, str):
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if _SQLITE_INT_MIN <= value <= _SQLITE_INT_MAX else None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


#: History rows that may wait for a busy store before one is counted lost.
HISTORY_ADMISSION_CEILING = 1024


#: How long a closing store waits for admitted history rows before it closes
#: the writer. A write still in flight then has the writer's own grace, the
#: store's busy timeout, so a close under a held lock takes several seconds.
HISTORY_DRAIN_S = 2.0


#: Threads serving reads; each opens its own short-lived connection.
_READ_WORKERS = 4


#: How long a skill hook's store call waits on a lock. Hooks run on the event
#: loop, so this is how long a hook can hold it; past it the call fails.
HOOK_BUSY_TIMEOUT_S = 0.05


#: After a hook's store call meets a lock, how long further hook calls fail at
#: once rather than each waiting out the timeout again.
HOOK_BUSY_BACKOFF_S = 1.0


class StoreCore(StoreMigrations):
    """Connections, executors and the lifecycle every store domain runs on."""

    def __init__(
        self,
        db_path: str = "ori_state.db",
        *,
        allow_history_rebuild: bool = False,
        read_only: bool = False,
    ) -> None:
        if read_only and (db_path == ":memory:" or allow_history_rebuild):
            raise ValueError("a read-only store is an existing file and never migrates")
        self._db_path = db_path
        # A read-only store changes nothing on disk: no DDL, no WAL pragma, no
        # permission change, and no -wal or -shm file it did not find.
        self._read_only = read_only
        # Only the runtime's startup passes True: the rebuild discards rows,
        # and a tool that only reads must never do that on the way in.
        self._allow_history_rebuild = allow_history_rebuild
        self._conn: Optional[sqlite3.Connection] = None
        # What the last future-receipt warning reported, and when, so a
        # persistent condition is reported on change and daily, not every cycle.
        self._future_receipts_logged: tuple[dict[str, int], int] | None = None
        self._write_lock = asyncio.Lock()
        self._lifecycle_lock = asyncio.Lock()
        # The last sensor_history row committed; ids are assigned in commit
        # order, so every row at or below it was committed before it was read.
        self._history_frontier = 0
        self._history_writer = self._new_history_writer()
        # The store's own threads. On the loop's default executor, anything
        # else that blocks a thread there -- a gateway route, a library call --
        # would queue an approval commit or a history read behind it. Writes
        # are serialised by the write lock, so one thread serves them, and a
        # flood of reads cannot take it.
        self._write_executor: ThreadPoolExecutor | None = None
        self._read_executor: ThreadPoolExecutor | None = None
        self._read_admission: asyncio.Semaphore | None = None
        # Skill hooks' own connections, one per calling thread (the hook
        # thread, and the loop for prompt history): never the writer's, each
        # used only by the thread that opened it, with a short busy timeout.
        self._hook_local = threading.local()
        self._hook_conns: list[tuple[threading.Thread, sqlite3.Connection]] = []
        self._hook_lock = threading.Lock()
        self._hook_busy_until = 0.0

    # ─── Lifecycle ────────────────────────────────────────────────────────────

    async def open(self) -> None:
        """Open the database connection and apply DDL migrations."""
        async with self._lifecycle_lock:
            if self._conn is not None:
                return
            conn = await self._on_writer(self._open_sync)
            if not self._read_only:
                self._history_frontier = await self._on_writer(
                    self._history_sequence_sync, conn
                )
            if self._history_writer.closed:
                self._history_writer = self._new_history_writer()
            self._conn = conn

    @staticmethod
    def _new_history_writer() -> DeferredWriter:
        return DeferredWriter(
            "history", ceiling=HISTORY_ADMISSION_CEILING, loss_level=logging.WARNING
        )

    @staticmethod
    def _history_sequence_sync(conn: sqlite3.Connection) -> int:
        # AUTOINCREMENT never reuses an id, so the sequence bounds every row,
        # including ones compaction has since removed.
        row = conn.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = 'sensor_history'"
        ).fetchone()
        return int(row[0]) if row is not None and row[0] is not None else 0

    def _open_sync(self) -> sqlite3.Connection:
        # Refuse here rather than at import, so a tool that merely imports this
        # module on an unsupported host still runs. Opening the store is the
        # first moment the requirement is real.
        #
        # Checking only here is complete rather than merely convenient. The
        # read path in `_open_read_conn_sync` is what actually issues the
        # query this floor exists for, and it is reachable only through an
        # opened store -- but the reason one check suffices is that
        # `sqlite3.sqlite_version_info` is fixed for the life of the process.
        # It cannot become false after this returns, so re-checking per
        # connection would cost a comparison on every read to re-establish
        # something already known.
        require_supported_sqlite()
        if self._read_only:
            return self._connect_read_only()
        # Decided on a read-only connection before this one exists: a refused
        # open must leave the file byte-for-byte as it found it, and the WAL
        # pragma below already writes the header.
        self._refuse_unreceipted_history_unless_allowed()
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._restrict_db_file_permissions()
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        self._migrate_sync(conn)
        return conn

    def _restrict_db_file_permissions(self) -> None:
        """Keep local SQLite state readable/writable only by the runtime user."""
        if self._db_path == ":memory:":
            return
        try:
            os.chmod(self._db_path, 0o600)
        except FileNotFoundError:
            return
        except PermissionError:
            return

    async def close(self) -> None:
        # Admitted history lands before the connection goes, within a bound;
        # what the store never took is counted lost with its reading named.
        await self._history_writer.drain(HISTORY_DRAIN_S)
        await self._history_writer.close()
        async with self._lifecycle_lock:
            async with self._write_lock:
                conn = self._conn
                self._conn = None
            if conn is not None:
                await self._on_writer(conn.close)
            # A read still in flight finishes on its own thread; nothing waits.
            for executor in (self._write_executor, self._read_executor):
                if executor is not None:
                    executor.shutdown(wait=False)
            self._write_executor = self._read_executor = None
            self._read_admission = None
            with self._hook_lock:
                hook_conns, self._hook_conns = self._hook_conns, []
                self._hook_local = threading.local()
            for owner, hook_conn in hook_conns:
                # A hook abandoned mid-call still holds its connection; it is
                # left to the abandoned thread rather than closed under it.
                if owner is threading.current_thread() or not owner.is_alive():
                    with contextlib.suppress(sqlite3.Error):
                        hook_conn.close()

    def _immediate(
        self, fn: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs
    ) -> _T:
        """Run a read-decide-write callable inside one `BEGIN IMMEDIATE`.

        The write lock serialises this store's writers only; another connection
        to the same file can still write between a decision's reads and its
        writes. Taking the database's write lock first makes the reads the ones
        the writes act on. A callable that returns without committing changed
        nothing it meant to keep, so the transaction is rolled back.
        """
        conn = self._conn
        if conn is None:
            raise sqlite3.ProgrammingError("the state store is not open")
        conn.execute("BEGIN IMMEDIATE")
        try:
            result = fn(*args, **kwargs)
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise
        if conn.in_transaction:
            conn.rollback()
        return result

    async def _run_write(
        self, fn: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs
    ) -> _T:
        """Run a synchronous write callable in the executor under write lock."""
        if self._read_only:
            raise PermissionError("this store was opened read-only")
        async with self._write_lock:
            return await self._on_writer(fn, *args, **kwargs)

    async def _run_read(
        self,
        fn: Callable[Concatenate[sqlite3.Connection, _P], _T],
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> _T:
        """Run a synchronous read callable in the executor without write lock."""
        if self._db_path == ":memory:":
            # In-memory SQLite cannot be shared with short-lived read
            # connections, so route reads through the primary connection
            # under the write lock to avoid cross-thread misuse.
            def call_primary() -> _T:
                return self._run_read_on_primary_conn(fn, *args, **kwargs)

            return await self._run_write(call_primary)

        def call_with_conn() -> _T:
            return self._run_read_with_conn(fn, *args, **kwargs)

        if self._read_executor is None:
            self._read_executor = ThreadPoolExecutor(
                max_workers=_READ_WORKERS, thread_name_prefix="ori-store-read"
            )
        # Admission, not a queue: no more reads are handed to the pool than it
        # has threads, and the rest wait here holding nothing.
        if self._read_admission is None:
            self._read_admission = asyncio.Semaphore(_READ_WORKERS)
        async with self._read_admission:
            return await asyncio.get_running_loop().run_in_executor(
                self._read_executor, call_with_conn
            )

    async def _on_writer(
        self, fn: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs
    ) -> _T:
        """Run *fn* on the store's write thread, never the loop's default pool."""
        if self._write_executor is None:
            self._write_executor = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="ori-store-write"
            )
        return await asyncio.get_running_loop().run_in_executor(
            self._write_executor, functools.partial(self._settled, fn, *args, **kwargs)
        )

    def _settled(self, fn: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs) -> _T:
        """Run *fn* and leave no transaction open on the writer, however it ends.

        Every domain shares this connection, so a transaction left open is
        everyone's: after a failed commit, the next unrelated write would commit
        the failed operation. Whatever *fn* did not commit is rolled back.
        """
        try:
            return fn(*args, **kwargs)
        finally:
            conn = self._conn
            if conn is not None and conn.in_transaction:
                conn.rollback()

    def _run_read_on_primary_conn(
        self,
        fn: Callable[Concatenate[sqlite3.Connection, _P], _T],
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> _T:
        assert self._conn is not None
        return fn(self._conn, *args, **kwargs)

    def _run_read_with_conn(
        self,
        fn: Callable[Concatenate[sqlite3.Connection, _P], _T],
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> _T:
        conn, close_when_done = self._open_read_conn_sync()
        try:
            return fn(conn, *args, **kwargs)
        finally:
            if close_when_done:
                conn.close()

    def _connect_read_only(self) -> sqlite3.Connection:
        """A connection that cannot change the file or create one beside it.

        A read-only open of a WAL database creates its -wal and -shm files when
        they are absent, owned by whoever opened it; a store the runtime then
        cannot open is a change, however read-only the query. With no -wal the
        runtime is not writing, so the file alone is the database and is read
        immutable. A runtime starting during the read leaves it answering from
        the file as it stood before, or failing; it never changes the file. A
        binding exported that way is one the device held, and a revision built
        on a superseded one is refused at delivery.
        """
        path = Path(self._db_path)
        if not path.is_file():
            raise FileNotFoundError(f"no state database at {path}")
        mode = "ro" if Path(f"{path}-wal").exists() else "ro&immutable=1"
        conn = sqlite3.connect(
            f"{path.resolve().as_uri()}?mode={mode}", uri=True, check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        return conn

    def _run_hook(
        self,
        fn: Callable[Concatenate[sqlite3.Connection, _P], _T],
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> _T:
        """Run a skill hook's store call on the hooks' own connection.

        Hooks run synchronously on the event loop, so a call here must not wait
        out the store's ordinary busy timeout, and must never touch the
        writer's connection, whose transactions it would otherwise commit in
        the middle of. A locked store fails the call within
        ``HOOK_BUSY_TIMEOUT_S``, and the calls after it fail at once for
        ``HOOK_BUSY_BACKOFF_S``.
        """
        if self._db_path == ":memory:" or self._read_only:
            conn, close_when_done = self._open_read_conn_sync()
            opened_here = not conn.in_transaction
            try:
                return fn(conn, *args, **kwargs)
            except BaseException:
                if opened_here and conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                if close_when_done:
                    conn.close()
        if time.monotonic() < self._hook_busy_until:
            raise sqlite3.OperationalError(
                "database is locked; hook store access is deferred"
            )
        conn = self._hook_connection()
        try:
            return fn(conn, *args, **kwargs)
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc) or "busy" in str(exc):
                self._hook_busy_until = time.monotonic() + HOOK_BUSY_BACKOFF_S
            raise
        finally:
            # This thread's later hook writes would commit whatever is left.
            if conn.in_transaction:
                with contextlib.suppress(sqlite3.Error):
                    conn.rollback()

    def _hook_connection(self) -> sqlite3.Connection:
        """This thread's hook connection, opened on first use by this thread."""
        conn: sqlite3.Connection | None = getattr(self._hook_local, "conn", None)
        if conn is None:
            # Thread affinity is enforced by sqlite3 itself: a connection
            # used from any thread but its opener raises ProgrammingError.
            conn = sqlite3.connect(self._db_path, timeout=HOOK_BUSY_TIMEOUT_S)
            conn.row_factory = sqlite3.Row
            self._hook_local.conn = conn
            with self._hook_lock:
                self._hook_conns.append((threading.current_thread(), conn))
        return conn

    def _open_read_conn_sync(self) -> tuple[sqlite3.Connection, bool]:
        """Open a short-lived read connection safe for concurrent executor threads."""
        if self._db_path == ":memory:":
            assert self._conn is not None
            return self._conn, False
        if self._read_only:
            return self._connect_read_only(), True

        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn, True

    async def _run(self, fn, *args):
        """Backward-compatible wrapper for legacy callers/tests."""
        return await self._run_write(fn, *args)
