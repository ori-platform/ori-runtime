# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""One evidence store connection, and the only place a transaction is opened.

A transaction whose rollback also fails leaves the connection inside it, and
every later BEGIN on that connection fails until the process restarts. So the
rule lives here once: a rollback that fails, or a transaction found already
open, discards the connection and reopens it, and the reopen opens the file
that exists rather than creating an empty one in its place.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import urllib.parse
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from ori.security.evidence.policy import safe_failure_reason

logger = logging.getLogger(__name__)


class EvidenceStoreFaultError(RuntimeError):
    """The store could not give what a decision needs; nothing was decided."""


class NestedEvidenceTransactionError(RuntimeError):
    """A transaction was opened inside a live one: a defect in the caller.

    SQLite has no nested BEGIN, and healing the outer one as a leak would
    split it, so the inner one is refused and the outer one is left alone.
    """


def configure(connection: sqlite3.Connection) -> None:
    """The pragmas every evidence connection runs under, busy timeout first.

    Switching to WAL takes a brief exclusive lock of its own, so a busy
    timeout set afterwards is set too late for the statement that needs it.
    """
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA journal_mode=WAL")
    # Enforced for this connection. Triggers are what make constraints hold for
    # every other one, since this pragma does not travel with the file.
    connection.execute("PRAGMA foreign_keys=ON")
    # A row acknowledged and then lost to a power cut is worse than a slower
    # write, because the act it records already happened.
    connection.execute("PRAGMA synchronous=FULL")


def _in_transaction(connection: sqlite3.Connection) -> bool:
    """Whether *connection* holds an open transaction; a closed one holds none."""
    try:
        return bool(connection.in_transaction)
    except sqlite3.ProgrammingError:
        return False


def _uri(path: str) -> str:
    """A read-write URI for an existing file; `?`, `#` and `%` are quoted."""
    return "file:" + urllib.parse.quote(path, safe="/") + "?mode=rw"


class EvidenceConnection:
    """A store connection that heals a transaction it could not roll back."""

    def __init__(self, path: str) -> None:
        # Resolved once: a reopen after the working directory changed must
        # open this file, not one with the same name somewhere else.
        self._path = os.path.abspath(str(path))
        self._reopen_owed = False
        self._depth = 0
        # The first open may create the file: the owner then writes its schema.
        connection = sqlite3.connect(self._path, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            configure(connection)
        except BaseException:
            connection.close()
            raise
        self._live = connection

    @property
    def connection(self) -> sqlite3.Connection:
        """The live connection, reopened first when a failure discarded it."""
        if self._reopen_owed:
            self._reopen()
        return self._live

    @connection.setter
    def connection(self, connection: sqlite3.Connection) -> None:
        self._live = connection

    def close(self) -> None:
        self._live.close()

    @contextmanager
    def transaction(
        self, *, on_begin_failure: Callable[[], Exception] | None = None
    ) -> Iterator[sqlite3.Connection]:
        """`BEGIN IMMEDIATE` ... `COMMIT`, rolled back whole on any exception.

        The exception that ended the transaction is the one raised, also when
        the rollback after it fails. A connection found inside a transaction
        while no transaction of this store is live is a leak, and is discarded
        first so it heals here; one opened inside a live transaction is
        refused. *on_begin_failure* names the error a store error at BEGIN is
        raised as.
        """
        if self._depth:
            raise NestedEvidenceTransactionError(
                "an evidence transaction cannot be opened inside another"
            )
        self._depth += 1
        try:
            connection = self.connection
            # No frame of this store is live here, the nesting check above
            # having refused one, so an open transaction is a leak.
            if connection.in_transaction:
                logger.error("[evidence] a transaction was left open; reopening")
                self._discard()
                connection = self.connection
            try:
                connection.execute("BEGIN IMMEDIATE")
            except BaseException as exc:
                if _in_transaction(connection):
                    self._discard()
                if on_begin_failure is not None and isinstance(exc, sqlite3.Error):
                    raise on_begin_failure() from exc
                raise
            try:
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                self._roll_back(connection)
                raise
        finally:
            self._depth -= 1

    def _roll_back(self, connection: sqlite3.Connection) -> None:
        """Roll back, never raising: the caller re-raises the original error."""
        if connection is not self._live or not _in_transaction(connection):
            # Already discarded, or already rolled back by SQLite.
            return
        try:
            connection.execute("ROLLBACK")
        except Exception as exc:
            logger.error("[evidence] rollback failed (%s)", safe_failure_reason(exc))
        if _in_transaction(connection):
            # Closing discards the transaction; SQLite rolls back what reached
            # the file when it is next opened.
            self._discard()

    def _discard(self) -> None:
        self._reopen_owed = True
        try:
            self._live.close()
        except Exception as exc:
            logger.error(
                "[evidence] a failed connection did not close (%s)",
                safe_failure_reason(exc),
            )
        try:
            self._reopen()
        except Exception as exc:
            logger.error(
                "[evidence] the store could not be reopened (%s); the next use retries",
                safe_failure_reason(exc),
            )

    def _reopen(self) -> None:
        """The existing file, read-write, or a store fault: never a new file."""
        try:
            connection = sqlite3.connect(
                _uri(self._path), uri=True, isolation_level=None
            )
        except sqlite3.Error as exc:
            raise EvidenceStoreFaultError("the store could not be reopened") from exc
        try:
            connection.row_factory = sqlite3.Row
            configure(connection)
        except BaseException as exc:
            connection.close()
            if isinstance(exc, sqlite3.Error):
                raise EvidenceStoreFaultError(
                    "the reopened store could not be configured"
                ) from exc
            raise
        self._live = connection
        self._reopen_owed = False
