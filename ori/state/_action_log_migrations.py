# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The action log's in-place migrations: record kinds and its page-order index."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable

from ori.state._action_records import _action_record_members

logger = logging.getLogger("ori.state.store")

#: Adds a column to a table when it is missing: (conn, table, column, typedef).
AddColumn = Callable[[sqlite3.Connection, str, str, str], None]


# Every row _action_record_members can read as another kind or link than it
# stores, once a coalesced row stored as a dispatch is reclassified (the
# statement before the pass that uses this). Any other row stores `dispatch`
# with no link and an action other than `coalesced`, and is read exactly so.
_ACTION_RECORD_CANDIDATES = (
    "record_kind IS NOT 'dispatch' OR contributed_to IS NOT NULL"
)


# Where duplicated keys already stop the unique index from being built, these
# hold every later insert and key update to a key no other row carries.
_RECORD_KEY_UNIQUE_TRIGGER_NAMES = (
    "trg_action_log_record_key_unique_insert",
    "trg_action_log_record_key_unique_update",
)


_RECORD_KEY_UNIQUE_TRIGGERS = (
    """
    CREATE TRIGGER IF NOT EXISTS trg_action_log_record_key_unique_insert
    BEFORE INSERT ON action_log
    WHEN NEW.record_key <> ''
         AND EXISTS (SELECT 1 FROM action_log WHERE record_key = NEW.record_key)
    BEGIN
        SELECT RAISE(ABORT, 'action_log.record_key is already in use');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_action_log_record_key_unique_update
    BEFORE UPDATE OF record_key ON action_log
    WHEN NEW.record_key <> ''
         AND EXISTS (
             SELECT 1 FROM action_log
             WHERE record_key = NEW.record_key AND id <> OLD.id
         )
    BEGIN
        SELECT RAISE(ABORT, 'action_log.record_key is already in use');
    END
    """,
)


def add_action_record_kind(conn: sqlite3.Connection, add_column: AddColumn) -> None:
    """record_kind on an action log, held on every open, not only the first.

    A joined row records a request that performed nothing, so it is a
    contributor; one the previous release wrote has no holder link, and
    nothing is invented to make one. This runs on every open because a
    rolled-back release keeps writing joined rows as ordinary ones, and a
    roll-forward must reclassify those too. A legacy row still awaiting
    attestation is settled refused as history, not reported as corrupt.
    Added columns cannot carry the table's CHECKs, so the writer and the
    readers hold the shape on such a database.
    """
    add_column(conn, "action_log", "record_kind", "TEXT NOT NULL DEFAULT 'dispatch'")
    add_column(conn, "action_log", "record_key", "TEXT NOT NULL DEFAULT ''")
    add_column(conn, "action_log", "contributed_to", "TEXT")
    conn.execute(
        "UPDATE action_log SET record_kind = 'contributor_legacy'"
        " WHERE action_taken = 'coalesced' AND record_kind = 'dispatch'"
    )
    # Any other row whose fields disagree with its kind, which only a table
    # without the CHECKs can hold, is rewritten to what every reader reads
    # it as (_action_record_members), so attestation, the summary and the
    # exports agree. It is never attested once rewritten.
    rows = conn.execute(
        "SELECT id, record_kind, record_key, contributed_to, action_taken,"
        " executed, attestation_status FROM action_log"
        f" WHERE {_ACTION_RECORD_CANDIDATES}"
    ).fetchall()
    rewritten: list[tuple[str, int]] = []
    for row in rows:
        read = _action_record_members(row)
        if (row["record_kind"], row["contributed_to"]) == (
            read["record_kind"],
            read["contributed_to"],
        ):
            continue
        conn.execute(
            "UPDATE action_log SET record_kind = ?, contributed_to = NULL,"
            " attestation_status = CASE WHEN attestation_status IN"
            " ('pending', 'failed') THEN 'refused' ELSE attestation_status END,"
            " attestation_reason = CASE WHEN attestation_status IN"
            " ('pending', 'failed') THEN 'reclassified_record'"
            " ELSE attestation_reason END"
            " WHERE id = ?",
            (read["record_kind"], int(row["id"])),
        )
        rewritten.append((read["record_kind"], int(row["id"])))
    if rewritten:
        logger.critical(
            "[action_log] %d rows' fields disagreed with their record kind and "
            "are recorded as every reader reads them, never attested: %s",
            len(rewritten),
            rewritten[:20],
        )
    conn.execute(
        "UPDATE action_log SET attestation_status = 'refused',"
        " attestation_reason = 'legacy_contributor'"
        " WHERE record_kind = 'contributor_legacy'"
        " AND attestation_status IN ('pending', 'failed')"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_action_log_record_key ON action_log(record_key)"
    )
    # A key names one row. Rows a rolled-back release wrote carry the
    # default '' and stay outside the constraint. Keys already duplicated
    # are reported, not a reason to refuse the store: Tier D does not wait
    # on evidence, and the unresolved count treats such a key as no link.
    # Every later write is still held to one row per key, by triggers
    # where the index cannot be built.
    try:
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_action_log_record_key_unique"
            " ON action_log(record_key) WHERE record_key <> ''"
        )
    except sqlite3.IntegrityError:
        logger.critical(
            "[action_log] record keys are duplicated, so a contributor's link "
            "cannot name one holder row; those links are counted unresolved "
            "until the rows are repaired, and no new key may reuse one"
        )
        for statement in _RECORD_KEY_UNIQUE_TRIGGERS:
            conn.execute(statement)
    else:
        for name in _RECORD_KEY_UNIQUE_TRIGGER_NAMES:
            conn.execute(f"DROP TRIGGER IF EXISTS {name}")


def index_action_log_pages(conn: sqlite3.Connection) -> None:
    """The index gateway-api/v2 Page Order pages the action log by.

    `(device_id, timestamp, id)` descending per device. Created after the
    column migrations, since `device_id` arrives by one on an older store.
    """
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_action_log_device_timestamp"
        " ON action_log (device_id, timestamp DESC, id DESC)"
    )


def migrate_action_log(conn: sqlite3.Connection, add_column: AddColumn) -> None:
    """Every action-log migration an open applies, in order."""
    add_action_record_kind(conn, add_column)
    index_action_log_pages(conn)
