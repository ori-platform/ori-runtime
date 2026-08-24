# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The SQLite floor this store's queries depend on."""

import sqlite3

import pytest

from ori.state.store import (
    MINIMUM_SQLITE_VERSION,
    StateStore,
    UnsupportedSQLiteError,
    require_supported_sqlite,
)


def test_the_floor_is_the_version_that_allows_having_without_group_by():
    """The constant records why it is where it is, not a round number.

    The binding construct is a `HAVING` clause on an aggregate query with no
    `GROUP BY`. Measured: 3.34.1 and 3.37.2 refuse it, 3.40.1 and 3.46.1
    accept it. A floor below that range would admit a library that cannot run
    the sensor-history averages.
    """
    assert MINIMUM_SQLITE_VERSION == (3, 39, 0)


def test_this_host_runs_the_query_the_floor_exists_for():
    """The floor is checked against the construct rather than trusted.

    If this host satisfies the declared minimum, it must actually execute the
    form. A floor that is declared but wrong would otherwise pass unnoticed
    until a device met it.
    """
    if sqlite3.sqlite_version_info < MINIMUM_SQLITE_VERSION:
        pytest.skip(f"host SQLite {sqlite3.sqlite_version} is below the floor")

    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE t(x)")
        connection.execute("INSERT INTO t VALUES (1)")
        rows = connection.execute("SELECT SUM(x) FROM t HAVING SUM(x) > 0").fetchall()
    finally:
        connection.close()

    assert rows == [(1,)]


@pytest.mark.parametrize(
    "version",
    [(3, 0, 0), (3, 9, 0), (3, 34, 1), (3, 37, 2), (3, 38, 5), (3, 39, 0)],
)
def test_the_comparison_is_numeric_rather_than_lexical(monkeypatch, version):
    """`"3.9" > "3.40"` as strings, and 3.9 is exactly what must be refused.

    A lexical comparison passes 3.9.0 and refuses 3.40.1 — precisely inverted
    for two of the versions measured. Each case here is a real library
    version: Bullseye ships 3.34.1 and Ubuntu 22.04 ships 3.37.2.
    """
    monkeypatch.setattr(sqlite3, "sqlite_version_info", version)
    monkeypatch.setattr(sqlite3, "sqlite_version", ".".join(str(p) for p in version))

    if version >= MINIMUM_SQLITE_VERSION:
        require_supported_sqlite()
        return
    with pytest.raises(UnsupportedSQLiteError) as error:
        require_supported_sqlite()
    assert ".".join(str(p) for p in version) in str(error.value)
    assert "3.39.0" in str(error.value)


@pytest.mark.asyncio
async def test_opening_the_store_refuses_an_unsupported_library(monkeypatch, tmp_path):
    """The refusal reaches the caller, rather than being raised in a thread.

    `_open_sync` runs through `asyncio.to_thread`, so a check that raised
    somewhere the exception could not propagate would leave the store looking
    open. Opening is the first moment the requirement is real.
    """
    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 34, 1))
    monkeypatch.setattr(sqlite3, "sqlite_version", "3.34.1")
    store = StateStore(str(tmp_path / "state.db"))

    with pytest.raises(UnsupportedSQLiteError):
        await store.open()


@pytest.mark.asyncio
async def test_a_supported_library_opens_normally(tmp_path):
    """The guard must not refuse the hosts it is meant to admit."""
    if sqlite3.sqlite_version_info < MINIMUM_SQLITE_VERSION:
        pytest.skip(f"host SQLite {sqlite3.sqlite_version} is below the floor")

    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        assert store._conn is not None
    finally:
        await store.close()
