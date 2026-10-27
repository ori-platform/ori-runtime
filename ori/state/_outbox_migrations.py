# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The alert outbox's migrations: the queue receipt and each row's notice kind."""

from __future__ import annotations

import sqlite3

from ori.utils.time_utils import now_ms

_LEGACY_OUTBOX_INDEXES: tuple[str, ...] = ("idx_alert_outbox_status_tier_ts",)


def migrate_alert_outbox(conn: sqlite3.Connection) -> None:
    """Queue order is arrival; rows from before the column get the migration moment."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(alert_outbox)")}
    if "queued_at_ms" not in columns:
        conn.execute(
            "ALTER TABLE alert_outbox ADD COLUMN queued_at_ms INTEGER NOT NULL DEFAULT 0"
        )
    conn.execute(
        "UPDATE alert_outbox SET queued_at_ms = ? WHERE queued_at_ms <= 0",
        (now_ms(),),
    )
    for name in _LEGACY_OUTBOX_INDEXES:
        conn.execute(f"DROP INDEX IF EXISTS {name}")
    if "retry_seq" not in columns:
        # Queue position: the next value when queued and after each failure.
        conn.execute("ALTER TABLE alert_outbox ADD COLUMN retry_seq INTEGER")
    # An earlier release queues rows without one: they keep their arrival order
    # and go behind every row already placed.
    conn.execute(
        "UPDATE alert_outbox SET retry_seq = id + "
        "(SELECT COALESCE(MAX(retry_seq), 0) FROM alert_outbox) "
        "WHERE retry_seq IS NULL"
    )
    classify_outbox_notices(conn)
    conn.commit()


def classify_outbox_notices(conn: sqlite3.Connection) -> None:
    """Classify the rows an earlier release wrote, on every open.

    This release writes every row's kind when it creates it, and only a row
    with none is touched here, so a rolled-back release's rows are caught
    and none this release decided is decided again. Tier D rows stay
    mandatory. A row whose trigger name is one the runtime's protection
    notices use is marked protection_degraded, a skill trigger sharing the
    name included, erring toward never dropping. An earlier release's Tier D
    trigger notice is not recoverable: its row holds the action's tier.
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(alert_outbox)")}
    if "notice_kind" not in columns:
        conn.execute("ALTER TABLE alert_outbox ADD COLUMN notice_kind TEXT")
    if "trigger_name" not in columns:
        # The oldest outboxes name no trigger; only the tier is evidence.
        conn.execute(
            "UPDATE alert_outbox SET notice_kind = CASE WHEN action_tier = 'D' "
            "THEN 'tier_d' ELSE 'optional' END WHERE notice_kind IS NULL"
        )
        return
    conn.execute(
        r"""
        UPDATE alert_outbox SET notice_kind = CASE
            WHEN action_tier = 'D' THEN 'tier_d'
            WHEN trigger_name LIKE 'safety\_%' ESCAPE '\'
              OR trigger_name IN ('sensor_unconnected_warning',
                                  'sensor_connected_notice')
              OR trigger_name LIKE 'measurement\_degraded:%' ESCAPE '\'
              OR trigger_name LIKE 'measurement\_degraded\_persists:%'
                 ESCAPE '\'
            THEN 'protection_degraded'
            ELSE 'optional'
        END
         WHERE notice_kind IS NULL
        """
    )
