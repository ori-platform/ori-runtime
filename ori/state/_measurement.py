# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Measurement degradation and its notice schedule."""

import sqlite3

from ori.state._core import StoreCore
from ori.utils.time_utils import now_ms


class MeasurementStore(StoreCore):
    """Measurement degradation and its notice schedule."""

    # ─── skill_state ──────────────────────────────────────────────────────────

    async def get_measurement_degradation(self) -> dict[str, bool]:
        """Degraded sensors, mapped to whether the operator has been told.

        Restored at startup so a crash-looping runtime does not re-send the
        same warning on every restart, and so one whose warning never got out
        still sends it.
        """
        return await self._run_read(self._get_measurement_degradation_sync)

    def _get_measurement_degradation_sync(
        self, conn: sqlite3.Connection
    ) -> dict[str, bool]:
        rows = conn.execute(
            "SELECT sensor_id, notified_at FROM sensor_measurement_state "
            "WHERE degraded = 1"
        ).fetchall()
        return {str(row[0]): row[1] is not None for row in rows}

    async def get_measurement_notice_schedule(self) -> dict[str, tuple[int, int]]:
        """Per degraded sensor, when it began and which notice stage it reached.

        Restored at startup so the escalation schedule survives a restart: the
        clock is not reset, and a stage already delivered is not repeated.
        """
        return await self._run_read(self._get_measurement_notice_schedule_sync)

    def _get_measurement_notice_schedule_sync(
        self, conn: sqlite3.Connection
    ) -> dict[str, tuple[int, int]]:
        rows = conn.execute(
            "SELECT sensor_id, degraded_since, updated_at, notice_stage "
            "FROM sensor_measurement_state WHERE degraded = 1"
        ).fetchall()
        # `degraded_since` is absent on a row written before this column
        # existed. Falling back to `updated_at` dates the degradation to the
        # last write rather than inventing "now", so an upgrade does not
        # restart the schedule from zero for a sensor already long degraded.
        return {
            str(row[0]): (
                int(row[1] if row[1] is not None else row[2]),
                int(row[3] or 0),
            )
            for row in rows
        }

    async def set_measurement_notice_stage(self, sensor_id: str, stage: int) -> None:
        """Record the highest notification stage this degradation has reached."""
        await self._run_write(self._set_measurement_notice_stage_sync, sensor_id, stage)

    def _set_measurement_notice_stage_sync(self, sensor_id: str, stage: int) -> None:
        assert self._conn is not None
        self._conn.execute(
            "UPDATE sensor_measurement_state SET notice_stage = ?, updated_at = ? "
            "WHERE sensor_id = ?",
            (int(stage), now_ms(), sensor_id),
        )
        self._conn.commit()

    async def record_measurement_notice_delivered(
        self, sensor_id: str, stage: int, *, degraded_since: int
    ) -> None:
        """Record a delivered notice: the degradation, the stage, and that it went.

        One statement, one commit. Written separately, a crash between them
        leaves the disk saying a later stage was sent while still saying
        nobody was notified, and the next start sends the notice for the
        transition all over again — which is the duplicate message this state
        exists to prevent.

        An upsert rather than an update, because the row may not exist. The
        write that records the degradation can itself fail — the store is
        allowed to be transiently unavailable, and a failure there is logged
        and does not stop polling — so a later escalation can be the first
        write that lands. An `UPDATE` would match nothing, raise nothing, and
        leave the runtime believing the operator had been told about a
        degradation the disk has no record of at all: the next start would
        find no degraded sensor and forget the measurement loss entirely.

        `degraded_since` comes from the runtime's in-memory value so a
        reconstructed row carries the real start of the loss rather than the
        moment the disk caught up, and the schedule does not restart. Where
        the row already exists, its own start and `notified_at` are kept: the
        latter marks *that* the operator has been told, not when they were
        last told, and the stage carries the schedule's own position.
        """
        await self._run_write(
            self._record_measurement_notice_delivered_sync,
            sensor_id,
            stage,
            degraded_since,
        )

    def _record_measurement_notice_delivered_sync(
        self, sensor_id: str, stage: int, degraded_since: int
    ) -> None:
        assert self._conn is not None
        now = now_ms()
        cursor = self._conn.execute(
            """
            INSERT INTO sensor_measurement_state
                (sensor_id, degraded, notified_at, degraded_since,
                 notice_stage, updated_at)
            VALUES (?, 1, ?, ?, ?, ?)
            ON CONFLICT(sensor_id) DO UPDATE SET
                degraded = 1,
                notified_at = COALESCE(
                    sensor_measurement_state.notified_at, excluded.notified_at
                ),
                degraded_since = COALESCE(
                    sensor_measurement_state.degraded_since, excluded.degraded_since
                ),
                notice_stage = excluded.notice_stage,
                updated_at = excluded.updated_at
            """,
            (sensor_id, now, int(degraded_since), int(stage), now),
        )
        if cursor.rowcount != 1:
            # Unreachable while the statement above is an upsert, which always
            # affects exactly one row. It is here so that a return to a plain
            # `UPDATE` fails closed rather than silently: that statement
            # matches nothing when the row is absent, raises nothing, and the
            # caller would mark an operator as told about a degradation the
            # disk has no record of. Nothing written means nothing recorded,
            # and the caller keeps the obligation.
            self._conn.rollback()
            raise RuntimeError(f"measurement notice for {sensor_id!r} was not recorded")
        self._conn.commit()

    async def set_measurement_degraded(self, sensor_id: str, *, notified: bool) -> None:
        """Record a degradation, and separately whether it has been reported."""
        await self._run_write(self._set_measurement_degraded_sync, sensor_id, notified)

    def _set_measurement_degraded_sync(self, sensor_id: str, notified: bool) -> None:
        assert self._conn is not None
        now = now_ms()
        self._conn.execute(
            """
            INSERT INTO sensor_measurement_state
                (sensor_id, degraded, notified_at, degraded_since, updated_at)
            VALUES (?, 1, ?, ?, ?)
            ON CONFLICT(sensor_id) DO UPDATE SET
                degraded = 1,
                -- The start of the degradation, not of the latest write: the
                -- escalation schedule is measured from when measurement was
                -- lost, so a second write must not move it forward.
                degraded_since = COALESCE(
                    sensor_measurement_state.degraded_since, excluded.degraded_since
                ),
                -- Once reported, stays reported. A later write that has not
                -- itself notified must not reopen the alert.
                notified_at = COALESCE(
                    sensor_measurement_state.notified_at, excluded.notified_at
                ),
                updated_at = excluded.updated_at
            """,
            (sensor_id, now if notified else None, now, now),
        )
        self._conn.commit()

    async def clear_measurement_degraded(self, sensor_id: str) -> None:
        """Record that a sensor is measuring again."""
        await self._run_write(self._clear_measurement_degraded_sync, sensor_id)

    def _clear_measurement_degraded_sync(self, sensor_id: str) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO sensor_measurement_state
                (sensor_id, degraded, notified_at, degraded_since, updated_at)
            VALUES (?, 0, NULL, NULL, ?)
            ON CONFLICT(sensor_id) DO UPDATE SET
                degraded = 0,
                notified_at = NULL,
                degraded_since = NULL,
                notice_stage = 0,
                updated_at = excluded.updated_at
            """,
            (sensor_id, now_ms()),
        )
        self._conn.commit()
