# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Schema creation and the in-place migrations `open()` applies."""

import logging
import sqlite3
from pathlib import Path
from typing import Optional

from ori.state._action_records import (
    _ACTION_RECORD_CANDIDATES,
    _RECORD_KEY_UNIQUE_TRIGGER_NAMES,
    _RECORD_KEY_UNIQUE_TRIGGERS,
    _action_record_members,
)
from ori.state._schema import (
    _CORE_DDL,
    _DDL,
    _FIRMWARE_FAULT_EVENTS_DDL,
    _HISTORY_DDL,
    _HISTORY_DDL_STATEMENTS,
    _HISTORY_RECEIPT_COLUMNS,
    _LEGACY_HISTORY_INDEXES,
    _LEGACY_OUTBOX_INDEXES,
)
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.state.store")


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _unreceipted_history(conn: sqlite3.Connection) -> tuple[list[str], dict[str, int]]:
    """History tables present without their receipt column, and every present table's row count."""
    present = {table: _table_columns(conn, table) for table in _HISTORY_RECEIPT_COLUMNS}
    missing = [
        table
        for table, column in _HISTORY_RECEIPT_COLUMNS.items()
        if present[table] and column not in present[table]
    ]
    counts = {
        table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table, columns in present.items()
        if columns
    }
    return missing, counts


def _history_rebuild_statements() -> tuple[str, ...]:
    """Drop the unreceipted pyramid and recreate it, as one statement list."""
    drops = tuple(
        f"DROP INDEX IF EXISTS {name}" for name in _LEGACY_HISTORY_INDEXES
    ) + tuple(f"DROP TABLE IF EXISTS {table}" for table in _HISTORY_RECEIPT_COLUMNS)
    return drops + _HISTORY_DDL_STATEMENTS


# Marks a migrated identity whose activation history cannot be
# reconstructed. Revocation sets `approved = 0`, so a pre-lifecycle
# revoked row is identical whether it was revoked after being promoted or
# before ever being promoted. Compared as a constant rather than matched
# as text, so the marker and its reader cannot drift apart.
_MIGRATION_ACTIVATION_UNPROVABLE = (
    "backfilled from a pre-lifecycle revoked registry row; whether this "
    "anchor was ever promoted cannot be determined, because revocation "
    "cleared the approval flag"
)


# The reason written by the first lifecycle release's backfill. Databases
# upgraded by that release already hold an anchor row, so the backfill
# skips them; this constant is how the follow-up migration recognises
# them and completes their activation history.
_MIGRATION_BACKFILL_REASON = "backfilled from a pre-lifecycle registry row"


# Appended by the follow-up migration when an already-backfilled anchor's
# activation cannot be safely reconstructed.
_MIGRATION_ACTIVATION_UNRECONSTRUCTABLE = (
    "already backfilled by an earlier release; whether this anchor was "
    "ever promoted cannot be reconstructed from the recorded history"
)


# Recorded for an approved legacy row. Being approved proves the anchor is
# active when the migration observes it; it does not prove when the
# approval happened. `provisioned_at_ms` is when the device was
# provisioned, which can be long before it was approved, so using it as
# the start would vouch for evidence produced in between.
_MIGRATION_ACTIVATION_START_UNKNOWN = (
    "observed active at the migration boundary; the original approval was "
    "never recorded, so activation before this point is unknown"
)


def _require_attribution(operation: str, actor: str, reason: str) -> None:
    """Mandatory audit fields for a trust transition.

    ori-specs/device-provisioning/v1.md requires actor and reason on every
    operator decision that changes acceptance. An unattributed anchor
    change is indistinguishable from a compromise after the fact, so this
    refuses before any state moves rather than writing a blank row.
    """
    if not str(actor).strip():
        raise ValueError(
            f"{operation} requires an actor: trust transitions are audited"
        )
    if not str(reason).strip():
        raise ValueError(
            f"{operation} requires a reason: trust transitions are audited"
        )


class HistoryReceiptMigrationRequiredError(RuntimeError):
    """The history tables predate the receipt column and this opener may not rebuild them.

    Rebuilding discards every history row, so only the runtime's own startup
    asks for it. A read path that meets this store reports it instead.
    """


class StoreMigrations:
    """Schema creation and the in-place migrations `open()` applies."""

    _db_path: str
    _allow_history_rebuild: bool
    _conn: Optional[sqlite3.Connection]

    def _migrate_sync(self, conn: sqlite3.Connection) -> None:
        conn.executescript(_CORE_DDL)
        # Before the history DDL: its receipt index cannot be created over a
        # table that predates the column, so an unreceipted pyramid is rebuilt
        # first and a fresh store gets its tables from the DDL after.
        self._rebuild_history_schema_if_unreceipted(conn)
        conn.executescript(_HISTORY_DDL)
        self._add_history_producer_time(conn)
        self._migrate_alert_outbox_receipt(conn)
        self._key_firmware_fault_events_by_epoch(conn)
        # Add columns that may be missing from databases created before this
        # migration.  SQLite does not support ALTER TABLE ADD COLUMN IF NOT EXISTS
        # so duplicate-column errors are handled explicitly.
        _new_reasoning_cols = [
            ("device_id", "TEXT    NOT NULL DEFAULT ''"),
            ("model", "TEXT    NOT NULL DEFAULT ''"),
            ("tokens_used", "INTEGER NOT NULL DEFAULT 0"),
            ("latency_ms", "INTEGER NOT NULL DEFAULT 0"),
            ("proposed_action", "TEXT"),
            ("reasoning_status", "TEXT NOT NULL DEFAULT ''"),
            ("correlation_id", "TEXT NOT NULL DEFAULT ''"),
        ]
        for col, typedef in _new_reasoning_cols:
            self._add_column_if_missing_on_conn(conn, "reasoning_log", col, typedef)
        for col, typedef in (
            ("degraded_since", "INTEGER"),
            ("notice_stage", "INTEGER NOT NULL DEFAULT 0"),
        ):
            self._add_column_if_missing_on_conn(
                conn, "sensor_measurement_state", col, typedef
            )
        self._add_column_if_missing_on_conn(
            conn,
            "action_log",
            "proposal_id",
            "TEXT    NOT NULL DEFAULT ''",
        )
        # Nullable with no default, deliberately. An empty string or `{}` would
        # be a snapshot claiming something, and there is nothing truthful to
        # claim for a row written before the column existed: the licence was
        # never recorded and cannot be recovered. NULL says exactly that, and
        # the attestation path refuses such a row rather than sealing it.
        self._add_column_if_missing_on_conn(
            conn,
            "action_log",
            "authority_json",
            "TEXT",
        )
        self._add_column_if_missing_on_conn(
            conn,
            "action_log",
            "attestation_reason",
            "TEXT    NOT NULL DEFAULT ''",
        )
        # A bench device commissioned on an earlier build of this branch holds
        # the proof table with `executed` and none of the facts that replaced
        # it. `CREATE TABLE IF NOT EXISTS` leaves such a row set untouched, and
        # adding the new columns is not enough on its own: the legacy
        # `executed` is NOT NULL with no default, so every later insert fails.
        # The table is rebuilt instead, carrying the recorded commands across.
        legacy = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(commissioning_proof_observation)"
            )
        }
        if "executed" in legacy:
            conn.execute(
                "ALTER TABLE commissioning_proof_observation RENAME TO "
                "_commissioning_proof_observation_legacy"
            )
            conn.executescript(_DDL)
            conn.execute(
                """
                INSERT INTO commissioning_proof_observation
                    (id, binding_hash, zone_id, gpio_pin, active_high, outcome,
                     coil_state_commanded, level_driven, consent_nonce,
                     consented_at_ms, commanded_at_ms, command_issued,
                     effect_verified, operator_attestation, release_requested,
                     held_ms, observation_json, outcome_note)
                SELECT id, binding_hash, zone_id, gpio_pin, active_high, outcome,
                       coil_state_commanded, level_driven, consent_nonce,
                       consented_at_ms, commanded_at_ms, executed,
                       0, NULL, 0, 0, observation_json, outcome_note
                  FROM _commissioning_proof_observation_legacy
                """
            )
            conn.execute("DROP TABLE _commissioning_proof_observation_legacy")
            conn.commit()
        else:
            for col, typedef in (
                ("command_issued", "INTEGER NOT NULL DEFAULT 0"),
                ("effect_verified", "INTEGER NOT NULL DEFAULT 0"),
                ("operator_attestation", "TEXT"),
                ("release_requested", "INTEGER NOT NULL DEFAULT 0"),
                ("held_ms", "INTEGER NOT NULL DEFAULT 0"),
            ):
                self._add_column_if_missing_on_conn(
                    conn, "commissioning_proof_observation", col, typedef
                )
        for col, typedef in (
            ("safe_default_used", "INTEGER NOT NULL DEFAULT 0"),
            ("device_id", "TEXT    NOT NULL DEFAULT ''"),
            ("sensor_id", "TEXT    NOT NULL DEFAULT ''"),
            ("sensor_type", "TEXT    NOT NULL DEFAULT ''"),
            ("input_attestation_grade", "TEXT    NOT NULL DEFAULT 'unattested'"),
            ("input_posture", "TEXT    NOT NULL DEFAULT ''"),
            ("binding_seq", "INTEGER"),
            ("input_firmware_device_id", "TEXT    NOT NULL DEFAULT ''"),
            ("input_firmware_boot_id", "INTEGER NOT NULL DEFAULT 0"),
            ("input_firmware_seq", "INTEGER NOT NULL DEFAULT 0"),
            ("input_firmware_registration", "TEXT    NOT NULL DEFAULT ''"),
            ("correlation_id", "TEXT    NOT NULL DEFAULT ''"),
            # Evidence attestation (Option B append-after-log): '' means the
            # row predates evidence signing or signing is disabled; rows
            # written while signing is enabled move pending -> signed/failed,
            # and startup reconciliation repairs failures to 'reconciled'.
            ("attestation_status", "TEXT    NOT NULL DEFAULT ''"),
            ("attestation_seq", "INTEGER"),
        ):
            self._add_column_if_missing_on_conn(conn, "action_log", col, typedef)
        self._add_action_record_kind(conn)
        self._add_column_if_missing_on_conn(
            conn,
            "firmware_device_registry",
            "last_cmd_seq",
            "INTEGER NOT NULL DEFAULT 0",
        )
        self._add_column_if_missing_on_conn(
            conn,
            "firmware_device_registry",
            "last_provision_seq",
            "INTEGER NOT NULL DEFAULT 0",
        )
        self._add_column_if_missing_on_conn(
            conn,
            "firmware_device_registry",
            "last_runtime_seq",
            "INTEGER NOT NULL DEFAULT 0",
        )
        # NULL until the first message after upgrade seeds it.
        self._add_column_if_missing_on_conn(
            conn, "firmware_device_registry", "last_uptime_ms", "INTEGER"
        )
        # The mark the stored uptime was written with: key epoch, boot and
        # seq. A writer that moves any of them without the uptime (a release
        # without these columns, after a rollback) leaves it incomparable, and
        # the next message re-seeds it.
        self._add_column_if_missing_on_conn(
            conn, "firmware_device_registry", "last_uptime_mark", "TEXT"
        )
        for col, typedef in (
            ("proposal_id", "TEXT    NOT NULL DEFAULT ''"),
            ("operator_response_channel", "TEXT NOT NULL DEFAULT ''"),
            (
                "operator_response_provider_message_id",
                "TEXT NOT NULL DEFAULT ''",
            ),
            ("operator_response_from_number", "TEXT NOT NULL DEFAULT ''"),
            ("operator_response_received_at_ms", "INTEGER"),
        ):
            self._add_column_if_missing_on_conn(
                conn, "tier_c_decision_log", col, typedef
            )
        self._add_column_if_missing_on_conn(
            conn,
            "remote_command_log",
            "from_number",
            "TEXT    NOT NULL DEFAULT ''",
        )
        for col, typedef in (
            ("intent", "TEXT NOT NULL DEFAULT 'tier_a_alert'"),
            ("template_variables_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("accepted_channel", "TEXT NOT NULL DEFAULT ''"),
            ("provider_message_id", "TEXT NOT NULL DEFAULT ''"),
            ("provider_status", "TEXT NOT NULL DEFAULT ''"),
            ("accepted_at_ms", "INTEGER"),
            ("delivered_at_ms", "INTEGER"),
            ("last_status_at_ms", "INTEGER"),
        ):
            self._add_column_if_missing_on_conn(conn, "alert_outbox", col, typedef)
        # Earlier releases called a successful provider submission "delivered".
        # That fact proves acceptance only, so preserve it without inventing a
        # handset receipt that was never observed.
        conn.execute(
            """
            UPDATE alert_outbox
               SET status = 'accepted',
                   accepted_channel = CASE
                       WHEN accepted_channel = '' THEN channel
                       ELSE accepted_channel
                   END,
                   provider_status = CASE
                       WHEN provider_status = '' THEN 'legacy_provider_success'
                       ELSE provider_status
                   END,
                   accepted_at_ms = COALESCE(accepted_at_ms, last_attempt_ts),
                   delivered_at_ms = NULL
             WHERE status = 'delivered'
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alert_outbox_acceptance_receipt
                ON alert_outbox (
                    status, accepted_channel, delivered_at_ms, original_ts ASC
                )
            """
        )
        for col, typedef in (
            ("manifest_json", "TEXT    NOT NULL DEFAULT '{}'"),
            ("channel_map_json", "TEXT    NOT NULL DEFAULT '{}'"),
            # Device provisioning lifecycle: the active anchor's epochs.
            ("anchor_epoch_id", "TEXT    NOT NULL DEFAULT ''"),
            ("key_epoch_id", "TEXT    NOT NULL DEFAULT ''"),
        ):
            self._add_column_if_missing_on_conn(
                conn, "firmware_device_registry", col, typedef
            )
        self._backfill_firmware_anchor_epochs_on_conn(conn)
        # Runs after, and independently: it repairs identities the first
        # lifecycle release already backfilled, which the call above skips
        # because they now have an anchor row.
        self._complete_backfilled_activation_history_on_conn(conn)
        self._backfill_firmware_confirmation_obligations_on_conn(conn)
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_remote_command_log_sender_rejections
                ON remote_command_log (channel, from_number, accepted, received_at_ms DESC)
            """
        )
        conn.commit()

    def _add_column_if_missing(self, table: str, column: str, typedef: str) -> None:
        """Backward-compatible helper used by tests and migrations."""
        assert self._conn is not None
        self._add_column_if_missing_on_conn(self._conn, table, column, typedef)

    def _backfill_firmware_anchor_epochs_on_conn(
        self, conn: sqlite3.Connection
    ) -> None:
        """Give pre-lifecycle rows their epoch identifiers and an anchor
        history entry.

        Databases created before the provisioning lifecycle hold an
        active anchor in firmware_device_registry with no row in
        firmware_device_anchors. Absence of history is the detection
        signal — NOT an empty anchor_epoch_id, which now legitimately
        means "registered, nothing promoted yet" and would make the
        backfill fire on every freshly registered device. Derive the ids from what is
        already stored and record the anchor, so existing devices are not
        invisible to the lifecycle.

        An approved, unrevoked row becomes `active`. A revoked row becomes
        `revoked` — never `pending`, which would hand a revoked identity a
        promotable anchor. Anything else becomes `pending`, because it was
        never trusted for acceptance.
        """
        from ori.security.firmware.telemetry import (
            anchor_epoch_id as _anchor_epoch_id,
        )
        from ori.security.firmware.telemetry import (
            key_epoch_id as _key_epoch_id,
        )

        # The receiver-anchored boundary: the moment this store observed
        # these rows. Every inferred activation starts here, never at a
        # timestamp carried over from the old schema.
        migration_at_ms = now_ms()

        rows = conn.execute(
            """
            SELECT r.device_id, r.public_key_b64, r.posture, r.capability_hash,
                   r.manifest_json, r.channel_map_json, r.board_profile,
                   r.approved, r.revoked, r.provisioned_at_ms, r.revoked_at_ms
              FROM firmware_device_registry r
             WHERE NOT EXISTS (
                       SELECT 1 FROM firmware_device_anchors a
                        WHERE a.device_id = r.device_id
                   )
            """
        ).fetchall()
        for row in rows:
            kid = _key_epoch_id(
                device_id=row["device_id"], public_key_b64=row["public_key_b64"]
            )
            aid = _anchor_epoch_id(
                device_id=row["device_id"],
                public_key_b64=row["public_key_b64"],
                posture=row["posture"],
                capability_hash=row["capability_hash"],
            )
            conn.execute(
                """
                UPDATE firmware_device_registry
                   SET anchor_epoch_id = ?, key_epoch_id = ?
                 WHERE device_id = ?
                """,
                (aid, kid, row["device_id"]),
            )
            if row["revoked"]:
                # A revoked identity must NOT acquire a promotable pending
                # anchor. The anchor is retained in `revoked` so a later
                # reinstatement has something to return to.
                state = "revoked"
            elif row["approved"]:
                state = "active"
            else:
                state = "pending"
            conn.execute(
                """
                INSERT OR IGNORE INTO firmware_device_anchors
                    (anchor_epoch_id, device_id, key_epoch_id, public_key_b64,
                     posture, capability_hash, manifest_json, channel_map_json,
                     board_profile, state, created_at_ms, state_changed_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    aid,
                    row["device_id"],
                    kid,
                    row["public_key_b64"],
                    row["posture"],
                    row["capability_hash"],
                    row["manifest_json"],
                    row["channel_map_json"],
                    row["board_profile"],
                    state,
                    row["provisioned_at_ms"],
                    row["provisioned_at_ms"],
                ),
            )
            conn.execute(
                """
                INSERT INTO firmware_anchor_transitions
                    (device_id, transition, from_epoch_id, to_epoch_id,
                     key_epoch_id, actor, reason, occurred_at_ms)
                VALUES (?, 'registered', NULL, ?, ?, 'migration', ?, ?)
                """,
                (
                    row["device_id"],
                    aid,
                    kid,
                    _MIGRATION_ACTIVATION_UNPROVABLE
                    if state == "revoked"
                    else _MIGRATION_BACKFILL_REASON,
                    row["provisioned_at_ms"],
                ),
            )

            # An approved, unrevoked legacy row IS active, so it was
            # promoted at some point. Recording that is what stops the
            # derived activation history from reporting the anchor as
            # never active and losing the attribution for everything it
            # authorised before the upgrade.
            #
            # A REVOKED row is deliberately excluded. Revocation sets
            # `approved = 0`, so a revoked legacy row reads
            # `approved=0, revoked=1` whether it was revoked after being
            # promoted or before ever being promoted. The two are
            # indistinguishable in a pre-lifecycle database, and inventing
            # a promotion for both would manufacture authorisation for an
            # identity that may never have had any — failing open on
            # exactly the question this history exists to answer. Its
            # activation history is unprovable, and is recorded as such
            # rather than guessed.
            #
            # The interval opens at the MIGRATION BOUNDARY, not at
            # `provisioned_at_ms`. Approval proves the anchor is active
            # when the migration observes it; it says nothing about when
            # the approval happened, and a device is often provisioned
            # long before it is approved. Starting the interval at
            # provisioning would vouch for evidence produced in between,
            # which is precisely the window nobody can account for.
            if state == "active":
                conn.execute(
                    """
                    INSERT INTO firmware_anchor_transitions
                        (device_id, transition, from_epoch_id, to_epoch_id,
                         key_epoch_id, actor, reason, occurred_at_ms)
                    VALUES (?, 'promoted', NULL, ?, ?, 'migration', ?, ?)
                    """,
                    (
                        row["device_id"],
                        aid,
                        kid,
                        _MIGRATION_ACTIVATION_START_UNKNOWN,
                        migration_at_ms,
                    ),
                )

    def _backfill_firmware_confirmation_obligations_on_conn(
        self, conn: sqlite3.Connection
    ) -> None:
        """Give every active anchor without an obligation a fail-closed one.

        Cross-store confirmation was introduced after devices had already
        been approved. Those anchors are active in the runtime store but
        have no ``firmware_confirmation_outbox`` row, so the command and
        evidence gates — which treat a missing row as *not confirmed* —
        would refuse them, while the coordinator's resolve update, finding
        no row to update, would change nothing yet report success. Neither
        state is trustworthy.

        The safe reconciliation is to enrol each active anchor as
        ``confirmation_pending``, exactly as a fresh approval would. The
        obligation is then visible to the reconciliation path and becomes
        effective only once the evidence store confirms the identical
        epoch. Failing closed here means a legacy device pauses until it is
        confirmed, never that it operates on authority the evidence store
        cannot back.

        Only ``active`` anchors are enrolled: a pending, superseded, or
        revoked anchor asserts no current authority to confirm. Idempotent
        via ``ON CONFLICT DO NOTHING`` — a device already carrying an
        obligation (including a ``confirmed`` or ``quarantined`` one) keeps
        it untouched, so reopening a database backfills nothing and never
        reopens a resolved obligation.
        """
        created_at_ms = now_ms()
        conn.execute(
            """
            INSERT INTO firmware_confirmation_outbox
                (device_id, anchor_epoch_id, status, attempt_count,
                 created_at_ms)
            SELECT a.device_id, a.anchor_epoch_id, 'confirmation_pending', 0, ?
              FROM firmware_device_anchors a
             WHERE a.state = 'active'
            ON CONFLICT (device_id, anchor_epoch_id) DO NOTHING
            """,
            (created_at_ms,),
        )

    def _complete_backfilled_activation_history_on_conn(
        self, conn: sqlite3.Connection
    ) -> None:
        """Finish the activation history of rows an earlier release already
        backfilled.

        The first lifecycle release gave pre-lifecycle rows an anchor and a
        generic ``registered`` transition. Those identities therefore have
        an anchor row, so the backfill above — which only fires when there
        is none — never revisits them, and they would keep an activation
        history that says an approved device was never active.

        The transition log is append-only, so nothing here rewrites the
        earlier entry; this appends what was missing.

        Idempotent: each branch first checks whether its entry is already
        present, so reopening a database adds nothing.
        """
        migration_at_ms = now_ms()

        rows = conn.execute(
            """
            SELECT a.device_id, a.anchor_epoch_id, a.key_epoch_id, a.state,
                   a.created_at_ms,
                   (SELECT MIN(t.id) FROM firmware_anchor_transitions t
                     WHERE t.device_id = a.device_id
                       AND t.actor = 'migration'
                       AND t.reason = ?
                       AND t.to_epoch_id = a.anchor_epoch_id) AS backfill_id
              FROM firmware_device_anchors a
             WHERE backfill_id IS NOT NULL
            """,
            (_MIGRATION_BACKFILL_REASON,),
        ).fetchall()

        for row in rows:
            aid = row["anchor_epoch_id"]

            already_repaired = conn.execute(
                """
                SELECT 1 FROM firmware_anchor_transitions
                 WHERE device_id = ? AND actor = 'migration' AND reason IN (?, ?)
                 LIMIT 1
                """,
                (
                    row["device_id"],
                    _MIGRATION_ACTIVATION_START_UNKNOWN,
                    _MIGRATION_ACTIVATION_UNRECONSTRUCTABLE,
                ),
            ).fetchone()
            if already_repaired is not None:
                continue

            # The earlier release wrote the same generic reason whichever
            # state it chose, so the log does not say directly whether this
            # anchor was backfilled `active` or `pending`. The first
            # transition to touch the anchor afterwards does say.
            #
            # An anchor backfilled PENDING leaves that state one of two
            # ways, and both are provable:
            #   `promoted to=A`    a real, recorded first activation
            #   `discarded from=A` replaced as a candidate. Only a PENDING
            #                      anchor is ever discarded, so this proves
            #                      it was never active.
            #
            # An anchor backfilled ACTIVE must first LEAVE active, so its
            # first subsequent mention carries it in from_epoch_id
            # (`revoked from=A`, or `promoted from=A` when another anchor
            # superseded it). Its pre-migration activation was never
            # recorded, and a later re-promotion does not make that earlier
            # interval provable.
            first_after = conn.execute(
                """
                SELECT transition, from_epoch_id, to_epoch_id
                  FROM firmware_anchor_transitions
                 WHERE device_id = ? AND id > ?
                   AND (from_epoch_id = ? OR to_epoch_id = ?)
                 ORDER BY id ASC LIMIT 1
                """,
                (row["device_id"], row["backfill_id"], aid, aid),
            ).fetchone()

            if first_after is not None:
                if (
                    first_after["transition"] == "promoted"
                    and first_after["to_epoch_id"] == aid
                ):
                    # Backfilled pending, then genuinely promoted. Nothing
                    # is missing and nothing is uncertain.
                    continue
                if (
                    first_after["transition"] == "discarded"
                    and first_after["from_epoch_id"] == aid
                ):
                    # Backfilled pending, then replaced as a candidate.
                    # Provably never active, which is a stronger answer
                    # than "cannot say" — marking it unprovable would
                    # discard a fact the log does establish.
                    continue
                # Backfilled active. Fall through to the marker below: the
                # promotion that would have to be reconstructed sits before
                # entries already in the log, and an append cannot express
                # that without misordering the interval.
                row = dict(row)
                row["state"] = "_was_active_before_migration"

            if row["state"] == "active":
                # It is active now, so it is known active from this
                # boundary onward. When it BECAME active is unknown, and
                # `created_at_ms` is the backfill's own timestamp rather
                # than an approval, so the interval opens here and not
                # there. Nothing closes it, so appending cannot misorder.
                conn.execute(
                    """
                    INSERT INTO firmware_anchor_transitions
                        (device_id, transition, from_epoch_id, to_epoch_id,
                         key_epoch_id, actor, reason, occurred_at_ms)
                    VALUES (?, 'promoted', NULL, ?, ?, 'migration', ?, ?)
                    """,
                    (
                        row["device_id"],
                        aid,
                        row["key_epoch_id"],
                        _MIGRATION_ACTIVATION_START_UNKNOWN,
                        migration_at_ms,
                    ),
                )
                continue

            if row["state"] == "pending":
                # Provably never promoted: the earlier backfill only chose
                # `pending` for a row that was never approved.
                continue

            # `revoked`, an anchor that was active before the migration, or
            # `superseded`/`discarded` reached by later activity. None of
            # these can say when — or whether — the anchor was active
            # before the upgrade, so all fail closed.
            conn.execute(
                """
                INSERT INTO firmware_anchor_transitions
                    (device_id, transition, from_epoch_id, to_epoch_id,
                     key_epoch_id, actor, reason, occurred_at_ms)
                VALUES (?, 'registered', NULL, ?, ?, 'migration', ?, ?)
                """,
                (
                    row["device_id"],
                    aid,
                    row["key_epoch_id"],
                    _MIGRATION_ACTIVATION_UNRECONSTRUCTABLE,
                    migration_at_ms,
                ),
            )

    @staticmethod
    def _key_firmware_fault_events_by_epoch(conn: sqlite3.Connection) -> None:
        """Rebuild a pre-epoch fault table under the epoch key, every row and id kept."""
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(firmware_fault_events)")
        }
        if "key_epoch_id" in columns:
            return
        kept = (
            "id, device_id, boot_id, seq, grade, posture, capability_hash, code, "
            "subject, detail, device_uptime_ms, received_at_ms, fault_json"
        )
        conn.commit()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "ALTER TABLE firmware_fault_events "
                "RENAME TO _firmware_fault_events_unkeyed"
            )
            conn.execute(_FIRMWARE_FAULT_EVENTS_DDL)
            conn.execute(
                f"INSERT INTO firmware_fault_events ({kept}, key_epoch_id) "
                f"SELECT {kept}, '' FROM _firmware_fault_events_unkeyed"
            )
            # AUTOINCREMENT never reissues an id the old table spent.
            spent = conn.execute(
                "SELECT seq FROM sqlite_sequence "
                "WHERE name = '_firmware_fault_events_unkeyed'"
            ).fetchone()
            if spent is not None:
                conn.execute(
                    "DELETE FROM sqlite_sequence WHERE name = 'firmware_fault_events'"
                )
                conn.execute(
                    "INSERT INTO sqlite_sequence (name, seq) "
                    "VALUES ('firmware_fault_events', ?)",
                    (int(spent[0]),),
                )
            conn.execute("DROP TABLE _firmware_fault_events_unkeyed")
            conn.commit()
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

    @staticmethod
    def _add_history_producer_time(conn: sqlite3.Connection) -> None:
        """producer_time on raw history, every row kept and read as unknown.

        Checked again inside the IMMEDIATE transaction, so a concurrent opener
        finds it added rather than adding it twice. A release that predates the
        column inserts without it and its rows take the default, unknown.
        """
        if "producer_time" in _table_columns(conn, "sensor_history"):
            return
        conn.commit()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if "producer_time" not in _table_columns(conn, "sensor_history"):
                conn.execute(
                    "ALTER TABLE sensor_history ADD COLUMN producer_time TEXT "
                    "NOT NULL DEFAULT 'unknown' CHECK "
                    "(producer_time IN ('reported', 'not_reported', 'unknown'))"
                )
            conn.commit()
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

    def _refuse_unreceipted_history_unless_allowed(self) -> None:
        """Raise before any write when the store needs the rebuild and this opener may not do it."""
        if self._allow_history_rebuild or self._db_path == ":memory:":
            return
        path = Path(self._db_path)
        if not path.is_file():
            return
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            missing, counts = _unreceipted_history(conn)
        finally:
            conn.close()
        if missing:
            raise HistoryReceiptMigrationRequiredError(
                f"history tables {', '.join(missing)} predate the receipt column; "
                f"migrating rebuilds them and discards {sum(counts.values())} rows "
                f"({counts}). Nothing was changed. Start the runtime under this "
                "release to migrate; a read-only tool does not."
            )

    def _rebuild_history_schema_if_unreceipted(self, conn: sqlite3.Connection) -> None:
        """Discard history rows that carry no receipt; the loss is logged, never silent.

        A row written before the store recorded receipts has only the producer's
        clock, and copying that into the receipt would rank the store's history
        on the very value this schema exists to keep out of rankings. The
        rebuild is one transaction: a failure leaves the old tables and rows.
        """
        missing, counts = _unreceipted_history(conn)
        if not missing:
            return
        if not self._allow_history_rebuild:
            raise HistoryReceiptMigrationRequiredError(
                f"history tables {', '.join(missing)} predate the receipt column; "
                f"migrating rebuilds them and discards {sum(counts.values())} rows "
                f"({counts}). Nothing was changed. Start the runtime under this "
                "release to migrate; a read-only tool does not."
            )
        conn.commit()
        try:
            conn.execute("BEGIN IMMEDIATE")
            for statement in _history_rebuild_statements():
                conn.execute(statement)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        logger.warning(
            "[store] history tables predate the receipt column (%s); rebuilt "
            "them and discarded %d rows (%s). Rows without a receipt cannot be "
            "ranked as current or aged, so they are not carried forward.",
            ", ".join(missing),
            sum(counts.values()),
            counts,
        )

    def _migrate_alert_outbox_receipt(self, conn: sqlite3.Connection) -> None:
        """Queue order is arrival; rows from before the column get the migration moment."""
        if "queued_at_ms" not in _table_columns(conn, "alert_outbox"):
            self._add_column_if_missing_on_conn(
                conn, "alert_outbox", "queued_at_ms", "INTEGER NOT NULL DEFAULT 0"
            )
        conn.execute(
            "UPDATE alert_outbox SET queued_at_ms = ? WHERE queued_at_ms <= 0",
            (now_ms(),),
        )
        for name in _LEGACY_OUTBOX_INDEXES:
            conn.execute(f"DROP INDEX IF EXISTS {name}")
        conn.commit()

    def _add_action_record_kind(self, conn: sqlite3.Connection) -> None:
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
        self._add_column_if_missing_on_conn(
            conn, "action_log", "record_kind", "TEXT NOT NULL DEFAULT 'dispatch'"
        )
        self._add_column_if_missing_on_conn(
            conn, "action_log", "record_key", "TEXT NOT NULL DEFAULT ''"
        )
        self._add_column_if_missing_on_conn(
            conn, "action_log", "contributed_to", "TEXT"
        )
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
            "CREATE INDEX IF NOT EXISTS idx_action_log_record_key"
            " ON action_log(record_key)"
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

    def _add_column_if_missing_on_conn(
        self,
        conn: sqlite3.Connection,
        table: str,
        column: str,
        typedef: str,
    ) -> None:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {typedef}")
        except sqlite3.OperationalError as exc:
            msg = str(exc).lower()
            if "duplicate column name" in msg:
                return
            raise
