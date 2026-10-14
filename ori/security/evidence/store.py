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


def _uri(path: str) -> str:
    """A read-write URI for an existing file; `?`, `#` and `%` are quoted."""
    return "file:" + urllib.parse.quote(os.path.abspath(path), safe="/") + "?mode=rw"


class EvidenceConnection:
    """A store connection that heals a transaction it could not roll back."""

    def __init__(self, path: str) -> None:
        self._path = str(path)
        self._reopen_owed = False
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
        the rollback after it fails. A connection found already inside a
        transaction is discarded first, so a leak from anywhere heals here.
        *on_begin_failure* names the error a store error at BEGIN is raised as.
        """
        connection = self.connection
        if connection.in_transaction:
            logger.error("[evidence] a transaction was left open; reopening")
            self._discard()
            connection = self.connection
        try:
            connection.execute("BEGIN IMMEDIATE")
        except BaseException as exc:
            if connection.in_transaction:
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

    def _roll_back(self, connection: sqlite3.Connection) -> None:
        if not connection.in_transaction:
            return
        try:
            connection.execute("ROLLBACK")
        except Exception as exc:
            logger.error("[evidence] rollback failed (%s)", safe_failure_reason(exc))
        if connection.in_transaction:
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
