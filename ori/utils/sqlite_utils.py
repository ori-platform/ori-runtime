# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Connections that never outlive a failed open."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def closed_on_failure(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Yield *conn*, closing it if anything inside raises.

    Whatever runs between a connect and the connection's hand-off (pragmas,
    a schema, a migration) can fail, and a connection dropped there holds its
    file open, and any write transaction its statements began, until the
    collector finds it. A failure always closes it here, its cause propagating.
    """
    try:
        yield conn
    except BaseException:
        conn.close()
        raise
