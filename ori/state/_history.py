# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Sensor history: admission, compaction, reads and export."""

import datetime
import json
import logging
import sqlite3
from typing import Any, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ori.network.events import (
    OriEvent,
    SensorReading,
    StoredReading,
)
from ori.network.producer_time import read_producer_time
from ori.state._core import StoreCore
from ori.state._migrations import _HISTORY_RECEIPT_COLUMNS
from ori.state.deferred_writer import DeferredWriter
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.state.store")


#: Compacted history and the basis its rows carry: none in the pyramid an
#: earlier release compacts into, so those read as unknown.
_COMPACTED_TIERS: tuple[tuple[str, str, str], ...] = (
    ("5min", "sensor_history_5min", "'unknown'"),
    ("hourly", "sensor_history_hourly", "'unknown'"),
    ("daily", "sensor_history_daily", "'unknown'"),
    ("5min", "sensor_history_basis_5min", "producer_time"),
    ("hourly", "sensor_history_basis_hourly", "producer_time"),
    ("daily", "sensor_history_basis_daily", "producer_time"),
)


# How long raw readings stay in `sensor_history`, by receipt, before they are
# compacted into five-minute buckets.
RAW_HISTORY_RETENTION_MS = 48 * 3600 * 1000


# How far past a reference time a receipt may be and still count as inside a
# window ending there. It covers the store stamping a row just after the event
# that carried it, and a small backward step of the clock; a receipt written
# while the clock ran ahead is hours or days out, far beyond it.
RECEIPT_READ_TOLERANCE_MS = 60_000


def _stored_reading(row: sqlite3.Row) -> StoredReading:
    return StoredReading(
        sensor_id=row["sensor_id"],
        sensor_type=row["sensor_type"],
        value=row["value"],
        unit=row["unit"],
        timestamp=row["timestamp"],
        quality=row["quality"],
        metadata=json.loads(row["metadata"]),
        received_at_ms=int(row["received_at_ms"]),
        producer_time=read_producer_time(row["producer_time"]),
    )


# The greatest receipt gateway-api/v2 admits: an integer a JSON double holds exactly.
_MAX_EXPORTED_RECEIPT = 2**53 - 1


def _exported_producer_time(row: sqlite3.Row) -> str:
    """A history row's basis, unknown for a raw not_reported row without a usable receipt."""
    basis = read_producer_time(row["producer_time"])
    receipt = row["received_at_ms"]
    if (
        basis == "not_reported"
        and row["tier"] == "raw"
        and not (isinstance(receipt, int) and 1 <= receipt <= _MAX_EXPORTED_RECEIPT)
    ):
        return "unknown"
    return basis


class HistoryStore(StoreCore):
    """Sensor history: admission, compaction, reads and export."""

    # ─── sensor_history ───────────────────────────────────────────────────────

    async def compact_history(self, max_backward_skew_ms: int = 3600000) -> None:
        """Compact raw sensor history into time-bucketed averages.

        Called from ori/runtime/_loops.py via asyncio.create_task() on a 5-minute
        schedule using asyncio periodic task pattern.
        """
        current_ms = now_ms()
        cutoffs = {
            "raw": current_ms - RAW_HISTORY_RETENTION_MS,
            "5min": current_ms - (30 * 86400 * 1000),  # 30 days
            "hourly": current_ms - (365 * 86400 * 1000),  # 1 year
        }
        await self._run_write(
            self._compact_sync,
            cutoffs,
            current_ms,
            max_backward_skew_ms,
        )

    def _compact_sync(
        self,
        cutoffs: dict,
        now_ms: int,
        max_backward_skew_ms: int = 3600000,
    ) -> None:
        if self._conn is None:
            raise RuntimeError("StateStore is not open")

        if max_backward_skew_ms < 0:
            raise RuntimeError("Invalid compaction skew threshold: must be >= 0")

        if not (cutoffs["hourly"] < cutoffs["5min"] < cutoffs["raw"] < now_ms):
            raise RuntimeError(
                "Invalid compaction cutoffs: must be strictly ordered in the past"
            )

        # A receipt beyond the skew bound is either a row written while the
        # clock ran ahead, or a clock now running behind. Compaction runs in
        # both cases: a clock behind only moves the cutoffs earlier, so it
        # deletes less, never more. Halting instead stopped retention for as
        # long as the bad receipt stayed ahead of the clock. Nothing is deleted
        # for it either: the kernel cannot say which clock is right, and a
        # source that steps it back while reporting synchronized would turn a
        # prune into the loss of an incident's raw trace. Such rows stay out of
        # age windows until the clock passes them.
        horizon = now_ms + max_backward_skew_ms
        future = {
            table: int(
                self._conn.execute(
                    f"SELECT COUNT(*) AS n FROM {table} WHERE {column} > ?",
                    (horizon,),
                ).fetchone()["n"]
            )
            for table, column in _HISTORY_RECEIPT_COLUMNS.items()
        }
        self._report_future_receipts(future, now_ms, max_backward_skew_ms)

        # Retention is decided on receipt: a row leaves a tier once the store
        # received it before the cutoff. Buckets are keyed on the reading's
        # `timestamp` and its basis, so one bucket can gain samples across
        # compaction runs and the insert merges the weighted average instead of
        # ignoring them, and readings of two bases never share a bucket row.
        # Raw rows compact into the pyramid by basis. The pyramid without one
        # is what an earlier release compacts into, and here it only ages.
        # 1. raw → 5-minute buckets by basis, received more than 48h ago
        self._conn.execute(
            """
            INSERT INTO sensor_history_basis_5min
            (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count,
             max_received_at_ms, producer_time)
            SELECT sensor_id, sensor_type,
                   (timestamp / 300000) * 300000 AS bucket_ms,
                   AVG(value), unit, COUNT(*), MAX(received_at_ms), producer_time
            FROM sensor_history
            WHERE received_at_ms < ?
            GROUP BY sensor_id, (timestamp / 300000), producer_time
            ON CONFLICT(sensor_id, bucket_ms, producer_time) DO UPDATE SET
                avg_value = (sensor_history_basis_5min.avg_value
                             * sensor_history_basis_5min.sample_count
                             + excluded.avg_value * excluded.sample_count)
                            / (sensor_history_basis_5min.sample_count
                               + excluded.sample_count),
                sample_count = sensor_history_basis_5min.sample_count
                               + excluded.sample_count,
                max_received_at_ms = MAX(sensor_history_basis_5min.max_received_at_ms,
                                         excluded.max_received_at_ms)
            """,
            (cutoffs["raw"],),
        )
        self._conn.execute(
            "DELETE FROM sensor_history WHERE received_at_ms < ?",
            (cutoffs["raw"],),
        )

        # 2. 5-minute → hourly, received more than 30d ago, in both pyramids
        self._conn.execute(
            """
            INSERT INTO sensor_history_hourly
            (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count,
             max_received_at_ms)
            SELECT sensor_id, sensor_type,
                   (bucket_ms / 3600000) * 3600000 AS bucket_ms,
                   SUM(avg_value * sample_count) / SUM(sample_count), unit,
                   SUM(sample_count), MAX(max_received_at_ms)
            FROM sensor_history_5min
            WHERE max_received_at_ms < ?
            GROUP BY sensor_id, (bucket_ms / 3600000)
            ON CONFLICT(sensor_id, bucket_ms) DO UPDATE SET
                avg_value = (sensor_history_hourly.avg_value * sensor_history_hourly.sample_count
                             + excluded.avg_value * excluded.sample_count)
                            / (sensor_history_hourly.sample_count + excluded.sample_count),
                sample_count = sensor_history_hourly.sample_count + excluded.sample_count,
                max_received_at_ms = MAX(sensor_history_hourly.max_received_at_ms,
                                         excluded.max_received_at_ms)
            """,
            (cutoffs["5min"],),
        )
        self._conn.execute(
            "DELETE FROM sensor_history_5min WHERE max_received_at_ms < ?",
            (cutoffs["5min"],),
        )
        self._conn.execute(
            """
            INSERT INTO sensor_history_basis_hourly
            (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count,
             max_received_at_ms, producer_time)
            SELECT sensor_id, sensor_type,
                   (bucket_ms / 3600000) * 3600000 AS bucket_ms,
                   SUM(avg_value * sample_count) / SUM(sample_count), unit,
                   SUM(sample_count), MAX(max_received_at_ms), producer_time
            FROM sensor_history_basis_5min
            WHERE max_received_at_ms < ?
            GROUP BY sensor_id, (bucket_ms / 3600000), producer_time
            ON CONFLICT(sensor_id, bucket_ms, producer_time) DO UPDATE SET
                avg_value = (sensor_history_basis_hourly.avg_value * sensor_history_basis_hourly.sample_count
                             + excluded.avg_value * excluded.sample_count)
                            / (sensor_history_basis_hourly.sample_count + excluded.sample_count),
                sample_count = sensor_history_basis_hourly.sample_count + excluded.sample_count,
                max_received_at_ms = MAX(sensor_history_basis_hourly.max_received_at_ms,
                                         excluded.max_received_at_ms)
            """,
            (cutoffs["5min"],),
        )
        self._conn.execute(
            "DELETE FROM sensor_history_basis_5min WHERE max_received_at_ms < ?",
            (cutoffs["5min"],),
        )

        # 3. hourly → daily, received more than 1 year ago, in both pyramids
        self._conn.execute(
            """
            INSERT INTO sensor_history_daily
            (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count,
             max_received_at_ms)
            SELECT sensor_id, sensor_type,
                   (bucket_ms / 86400000) * 86400000 AS bucket_ms,
                   SUM(avg_value * sample_count) / SUM(sample_count), unit,
                   SUM(sample_count), MAX(max_received_at_ms)
            FROM sensor_history_hourly
            WHERE max_received_at_ms < ?
            GROUP BY sensor_id, (bucket_ms / 86400000)
            ON CONFLICT(sensor_id, bucket_ms) DO UPDATE SET
                avg_value = (sensor_history_daily.avg_value * sensor_history_daily.sample_count
                             + excluded.avg_value * excluded.sample_count)
                            / (sensor_history_daily.sample_count + excluded.sample_count),
                sample_count = sensor_history_daily.sample_count + excluded.sample_count,
                max_received_at_ms = MAX(sensor_history_daily.max_received_at_ms,
                                         excluded.max_received_at_ms)
            """,
            (cutoffs["hourly"],),
        )
        self._conn.execute(
            "DELETE FROM sensor_history_hourly WHERE max_received_at_ms < ?",
            (cutoffs["hourly"],),
        )
        self._conn.execute(
            """
            INSERT INTO sensor_history_basis_daily
            (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count,
             max_received_at_ms, producer_time)
            SELECT sensor_id, sensor_type,
                   (bucket_ms / 86400000) * 86400000 AS bucket_ms,
                   SUM(avg_value * sample_count) / SUM(sample_count), unit,
                   SUM(sample_count), MAX(max_received_at_ms), producer_time
            FROM sensor_history_basis_hourly
            WHERE max_received_at_ms < ?
            GROUP BY sensor_id, (bucket_ms / 86400000), producer_time
            ON CONFLICT(sensor_id, bucket_ms, producer_time) DO UPDATE SET
                avg_value = (sensor_history_basis_daily.avg_value * sensor_history_basis_daily.sample_count
                             + excluded.avg_value * excluded.sample_count)
                            / (sensor_history_basis_daily.sample_count + excluded.sample_count),
                sample_count = sensor_history_basis_daily.sample_count + excluded.sample_count,
                max_received_at_ms = MAX(sensor_history_basis_daily.max_received_at_ms,
                                         excluded.max_received_at_ms)
            """,
            (cutoffs["hourly"],),
        )
        self._conn.execute(
            "DELETE FROM sensor_history_basis_hourly WHERE max_received_at_ms < ?",
            (cutoffs["hourly"],),
        )

        self._conn.commit()

    def _report_future_receipts(
        self,
        kept: dict[str, int],
        now_ms: int,
        max_backward_skew_ms: int,
    ) -> None:
        """Log history received beyond the clock, on change and daily."""
        if not any(kept.values()):
            self._future_receipts_logged = None
            return
        last = self._future_receipts_logged
        if last is not None and last[0] == kept and now_ms - last[1] < 86_400_000:
            return
        self._future_receipts_logged = (dict(kept), now_ms)
        logger.warning(
            "[compaction] history received after the clock by more than %d ms is "
            "kept, and left out of age windows until the clock passes it: %s",
            max_backward_skew_ms,
            kept,
        )

    @property
    def history_frontier(self) -> int:
        """The last history row committed; evaluation-time reads stop at a frontier."""
        return self._history_frontier

    @property
    def history_admission(self) -> DeferredWriter:
        return self._history_writer

    def admit_history(self, event: OriEvent) -> bool:
        """Queue *event*'s history row without waiting, stamping its frontier first.

        The frontier is taken before the row is queued, so the reading is never
        in its own evaluation-time history. False when the row was counted lost.
        """
        event.history_frontier = self._history_frontier
        if event.reading is None:
            return True
        reading = event.reading
        return self._history_writer.submit(
            lambda: self.append_history(event),
            label=(
                f"history sensor={reading.sensor_id} timestamp={reading.timestamp} "
                f"event={event.event_id}"
            ),
            report=True,
        )

    async def append_history(self, event: OriEvent) -> None:
        """Persist a sensor reading from an OriEvent."""
        if event.reading is None:
            return
        r = event.reading
        await self._run_write(self._insert_reading_sync, r)

    def _insert_reading_sync(self, r: SensorReading) -> None:
        assert self._conn is not None
        cursor = self._conn.execute(
            """
            INSERT INTO sensor_history
                (sensor_id, sensor_type, value, unit, timestamp, quality, metadata,
                 received_at_ms, producer_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                r.sensor_id,
                r.sensor_type,
                r.value,
                r.unit,
                r.timestamp,
                r.quality,
                json.dumps(r.metadata),
                now_ms(),  # the store's own clock; a reading never brings its receipt
                r.producer_time,
            ),
        )
        self._conn.commit()
        if cursor.lastrowid is not None:
            self._history_frontier = max(self._history_frontier, cursor.lastrowid)

    async def get_history(
        self, sensor_id: str, limit: int = 100, *, frontier: int | None = None
    ) -> list[StoredReading]:
        """Newest first. With *frontier*, only rows committed at or before it."""
        return await self._run_read(self._get_history_sync, sensor_id, limit, frontier)

    def hooks_get_history(
        self, sensor_id: str, limit: int = 100, *, frontier: int | None = None
    ) -> list[StoredReading]:
        """Stable sync facade for hook history lookups."""
        return self._run_hook(self._get_history_sync, sensor_id, limit, frontier)

    def _get_history_sync(
        self,
        conn: sqlite3.Connection,
        sensor_id: str,
        limit: int,
        frontier: int | None = None,
    ) -> list[StoredReading]:
        rows = conn.execute(
            """
            SELECT sensor_id, sensor_type, value, unit, timestamp, quality, metadata,
                   received_at_ms, producer_time
            FROM sensor_history
            WHERE sensor_id = ? AND (? IS NULL OR id <= ?)
            ORDER BY id DESC
            LIMIT ?
            """,
            (sensor_id, frontier, frontier, limit),
        ).fetchall()
        return [_stored_reading(row) for row in rows]

    async def avg_last_n(
        self, sensor_id: str, n: int, *, frontier: int | None = None
    ) -> Optional[float]:
        """Average of the n most-recent readings for a sensor."""
        return await self._run_read(self._avg_last_n_sync, sensor_id, n, frontier)

    def hooks_avg_last_n(
        self, sensor_id: str, n: int, *, frontier: int | None = None
    ) -> Optional[float]:
        """Stable sync facade for hook rolling-N average lookups."""
        return self._run_hook(self._avg_last_n_sync, sensor_id, n, frontier)

    def _avg_last_n_sync(
        self,
        conn: sqlite3.Connection,
        sensor_id: str,
        n: int,
        frontier: int | None = None,
    ) -> Optional[float]:
        row = conn.execute(
            """
            SELECT AVG(value) AS avg_val
            FROM (
                SELECT value
                FROM sensor_history
                WHERE sensor_id = ? AND (? IS NULL OR id <= ?)
                ORDER BY id DESC
                LIMIT ?
            )
            """,
            (sensor_id, frontier, frontier, n),
        ).fetchone()
        return row["avg_val"] if row else None

    async def avg_last_hours(
        self, sensor_id: str, hours: int, *, frontier: int | None = None
    ) -> Optional[float]:
        """Average of all readings within the last *hours* hours."""
        return await self._run_read(
            self._avg_last_hours_sync, sensor_id, hours, frontier
        )

    def hooks_avg_last_hours(
        self, sensor_id: str, hours: int, *, frontier: int | None = None
    ) -> Optional[float]:
        """Stable sync facade for hook average-over-hours lookups."""
        return self._run_hook(self._avg_last_hours_sync, sensor_id, hours, frontier)

    def _avg_last_hours_sync(
        self,
        conn: sqlite3.Connection,
        sensor_id: str,
        hours: int,
        frontier: int | None = None,
    ) -> Optional[float]:
        current_ms = now_ms()
        cutoff_ms = current_ms - hours * 3_600_000

        # "Within the last N hours" is an age, and an age is the greater of the
        # two intervals: a row qualifies only if it was both received and
        # measured inside the window. The measured bound can exclude a late
        # flush; it can never admit a row the store received too long ago. A
        # receipt well after now was written while the clock ran ahead, so its
        # age is unknown and it is left out.
        row = conn.execute(
            """
            SELECT SUM(val * cnt) / SUM(cnt) AS avg_val
            FROM (
                SELECT value AS val, 1 AS cnt
                FROM sensor_history
                WHERE sensor_id = ? AND received_at_ms BETWEEN ? AND ?
                  AND timestamp >= ? AND (? IS NULL OR id <= ?)
            """
            + "".join(
                f"""
                UNION ALL
                SELECT avg_value AS val, sample_count AS cnt
                FROM {table}
                WHERE sensor_id = ? AND max_received_at_ms BETWEEN ? AND ?
                  AND bucket_ms >= ?
                """
                for _tier, table, _basis in _COMPACTED_TIERS
            )
            + """
            )
            HAVING SUM(cnt) > 0
            """,
            # A frontier bounds raw rows only: compaction takes a raw row once
            # it is RAW_HISTORY_RETENTION_MS old by the store's clock, so an
            # aggregate never holds a row admitted during an evaluation.
            (
                sensor_id,
                cutoff_ms,
                current_ms + RECEIPT_READ_TOLERANCE_MS,
                cutoff_ms,
                frontier,
                frontier,
            )
            + (sensor_id, cutoff_ms, current_ms + RECEIPT_READ_TOLERANCE_MS, cutoff_ms)
            * len(_COMPACTED_TIERS),
        ).fetchone()
        return row["avg_val"] if row and row["avg_val"] is not None else None

    async def time_of_week_baseline(
        self,
        *,
        sensor_id: str,
        reference_timestamp_ms: int,
        timezone: str = "UTC",
        lookback_weeks: int = 8,
        min_weeks: int = 3,
    ) -> dict[str, Any]:
        """Return a site-local same-weekday/hour baseline from hourly history."""
        return await self._run_read(
            self._time_of_week_baseline_sync,
            sensor_id,
            reference_timestamp_ms,
            timezone,
            lookback_weeks,
            min_weeks,
        )

    def hooks_time_of_week_baseline(
        self,
        sensor_id: str,
        reference_timestamp_ms: int,
        timezone: str = "UTC",
        lookback_weeks: int = 8,
        min_weeks: int = 3,
    ) -> dict[str, Any]:
        """Stable sync facade for hook site-local baseline lookups."""
        return self._run_hook(
            self._time_of_week_baseline_sync,
            sensor_id,
            reference_timestamp_ms,
            timezone,
            lookback_weeks,
            min_weeks,
        )

    def _time_of_week_baseline_sync(
        self,
        conn: sqlite3.Connection,
        sensor_id: str,
        reference_timestamp_ms: int,
        timezone: str,
        lookback_weeks: int,
        min_weeks: int,
    ) -> dict[str, Any]:
        lookback = max(1, min(int(lookback_weeks), 52))
        min_required_weeks = max(1, min(int(min_weeks), lookback))
        reference_ms = int(reference_timestamp_ms)
        tz_name = str(timezone or "UTC").strip() or "UTC"
        try:
            tz = ZoneInfo(tz_name)
        except ZoneInfoNotFoundError:
            tz_name = "UTC"
            tz = ZoneInfo("UTC")

        reference_dt = datetime.datetime.fromtimestamp(reference_ms / 1000.0, tz=tz)
        target_weekday = int(reference_dt.weekday())
        target_hour = int(reference_dt.hour)
        start_ms = reference_ms - (lookback * 7 * 24 * 3_600_000)

        rows = conn.execute(
            """
            SELECT bucket_ms, avg_value, sample_count, unit
            FROM (
                SELECT bucket_ms, avg_value, sample_count, unit, sensor_id
                FROM sensor_history_hourly
                UNION ALL
                SELECT bucket_ms, avg_value, sample_count, unit, sensor_id
                FROM sensor_history_basis_hourly
            )
            WHERE sensor_id = ?
              AND bucket_ms >= ?
              AND bucket_ms < ?
            ORDER BY bucket_ms ASC
            """,
            (str(sensor_id), int(start_ms), reference_ms),
        ).fetchall()

        total = 0.0
        sample_count = 0
        covered_weeks: set[tuple[int, int]] = set()
        unit = ""
        for row in rows:
            bucket_ms = int(row["bucket_ms"])
            local_dt = datetime.datetime.fromtimestamp(bucket_ms / 1000.0, tz=tz)
            if local_dt.weekday() != target_weekday or local_dt.hour != target_hour:
                continue
            count = max(0, int(row["sample_count"] or 0))
            if count <= 0:
                continue
            value = float(row["avg_value"])
            total += value * count
            sample_count += count
            iso = local_dt.isocalendar()
            covered_weeks.add((int(iso.year), int(iso.week)))
            unit = str(row["unit"] or unit)

        covered_week_count = len(covered_weeks)
        avg_value = (total / sample_count) if sample_count > 0 else None
        usable = sample_count > 0 and covered_week_count >= min_required_weeks
        if sample_count <= 0:
            reason = "no_history"
        elif not usable:
            reason = "low_coverage"
        else:
            reason = "ok"

        return {
            "sensor_id": str(sensor_id),
            "reference_timestamp_ms": reference_ms,
            "timezone": tz_name,
            "target_weekday": target_weekday,
            "target_hour": target_hour,
            "lookback_weeks": lookback,
            "min_weeks": min_required_weeks,
            "avg_value": avg_value,
            "unit": unit,
            "sample_count": sample_count,
            "covered_weeks": covered_week_count,
            "usable": usable,
            "reason": reason,
            "tier": "hourly",
        }

    async def get_latest_readings_snapshot(
        self,
        exclude_sensor_id: str,
        since_ms: int,
        max_entries: int,
        *,
        frontier: int | None = None,
    ) -> list[StoredReading]:
        """Return the latest-arrived reading per sensor_id if its age is within since_ms.

        Which reading is latest is decided first, on arrival order alone. Age
        is then the greater of the two intervals, so that reading qualifies
        only if it was both received and measured at or after since_ms. A
        sensor whose latest arrival is stale by either clock is absent, never
        represented by an older row: a late flush of an old measurement is
        not fresh context, and neither is what it superseded.

        The triggering sensor (exclude_sensor_id) is always excluded.
        Results are bounded to max_entries, ordered by sensor_id for
        deterministic prompt output across calls. With *frontier*, only rows
        committed at or before it are candidates.
        """
        return await self._run_read(
            self._get_latest_readings_snapshot_sync,
            exclude_sensor_id,
            since_ms,
            max_entries,
            frontier,
        )

    def _get_latest_readings_snapshot_sync(
        self,
        conn: sqlite3.Connection,
        exclude_sensor_id: str,
        since_ms: int,
        max_entries: int,
        frontier: int | None = None,
    ) -> list[StoredReading]:
        # The latest reading per sensor is the last one the store received
        # (MAX(id) is arrival order), chosen over every row for the sensor.
        # The freshness bounds are applied to that row afterwards, in the
        # outer query: filtering before choosing would let an older row stand
        # in for a sensor whose latest arrival is stale.
        rows = conn.execute(
            """
            SELECT h.sensor_id, h.sensor_type, h.value, h.unit,
                   h.timestamp, h.quality, h.metadata, h.received_at_ms,
                   h.producer_time
            FROM sensor_history AS h
            INNER JOIN (
                SELECT sensor_id, MAX(id) AS latest_id
                FROM sensor_history
                WHERE sensor_id != ? AND (? IS NULL OR id <= ?)
                GROUP BY sensor_id
            ) AS latest
              ON h.id = latest.latest_id
            WHERE h.received_at_ms BETWEEN ? AND ?
              AND h.timestamp >= ?
            ORDER BY h.sensor_id
            LIMIT ?
            """,
            (
                exclude_sensor_id,
                frontier,
                frontier,
                since_ms,
                now_ms() + RECEIPT_READ_TOLERANCE_MS,
                since_ms,
                max(1, max_entries),
            ),
        ).fetchall()
        return [_stored_reading(row) for row in rows]

    async def get_timeseries(
        self, sensor_id: str, start_ms: int, end_ms: int
    ) -> list[tuple[int, float]]:
        """Fetch chart data from the appropriate compaction tier."""
        return await self._run_read(
            self._get_timeseries_sync, sensor_id, start_ms, end_ms
        )

    def _get_timeseries_sync(
        self, conn: sqlite3.Connection, sensor_id: str, start_ms: int, end_ms: int
    ) -> list[tuple[int, float]]:
        duration_ms = end_ms - start_ms

        # Choose tier based on requested range
        if duration_ms <= 48 * 3600 * 1000:
            rows = conn.execute(
                """
                SELECT timestamp AS ts, value AS val
                FROM sensor_history
                WHERE sensor_id = ? AND timestamp BETWEEN ? AND ?
                ORDER BY timestamp ASC
                """,
                (sensor_id, start_ms, end_ms),
            ).fetchall()
            return [(row["ts"], row["val"]) for row in rows]
        if duration_ms <= 30 * 86400 * 1000:
            tier = "5min"
        elif duration_ms <= 365 * 86400 * 1000:
            tier = "hourly"
        else:
            tier = "daily"
        # One point per bucket: its rows of every basis, in both pyramids.
        sources = " UNION ALL ".join(
            f"SELECT sensor_id, bucket_ms, avg_value, sample_count FROM {table}"
            for name, table, _basis in _COMPACTED_TIERS
            if name == tier
        )
        rows = conn.execute(
            f"""
            SELECT bucket_ms AS ts,
                   SUM(avg_value * sample_count) / SUM(sample_count) AS val
            FROM ({sources})
            WHERE sensor_id = ? AND bucket_ms BETWEEN ? AND ?
            GROUP BY bucket_ms
            ORDER BY bucket_ms ASC
            """,
            (sensor_id, start_ms, end_ms),
        ).fetchall()
        return [(row["ts"], row["val"]) for row in rows]

    async def export_sensor_history(
        self,
        *,
        sensor_id: str,
        start_ms: int,
        end_ms: int,
        limit: int = 10_000,
    ) -> list[dict]:
        """Return bounded sensor history across raw and compacted tiers.

        The gateway/reporting layer should use this method instead of reaching
        into SQLite table names. Rows are ordered oldest-first and include the
        compaction tier so report generators can decide how to aggregate.
        """
        return await self._run_read(
            self._export_sensor_history_sync,
            sensor_id,
            start_ms,
            end_ms,
            limit,
        )

    def _export_sensor_history_sync(
        self,
        conn: sqlite3.Connection,
        sensor_id: str,
        start_ms: int,
        end_ms: int,
        limit: int,
    ) -> list[dict]:
        if int(end_ms) < int(start_ms):
            return []

        capped_limit = max(1, min(int(limit), 10_000))
        window = (str(sensor_id), int(start_ms), int(end_ms))
        params: tuple[Any, ...] = window * (1 + len(_COMPACTED_TIERS)) + (capped_limit,)
        compacted = "".join(
            f"""
                UNION ALL
                SELECT
                    sensor_id,
                    sensor_type,
                    bucket_ms AS timestamp,
                    avg_value AS value,
                    unit,
                    NULL AS quality,
                    sample_count,
                    '{tier}' AS tier,
                    max_received_at_ms AS received_at_ms,
                    {basis} AS producer_time
                FROM {table}
                WHERE sensor_id = ? AND bucket_ms BETWEEN ? AND ?
            """
            for tier, table, basis in _COMPACTED_TIERS
        )
        rows = conn.execute(
            f"""
            SELECT *
            FROM (
                SELECT
                    sensor_id,
                    sensor_type,
                    timestamp AS timestamp,
                    value AS value,
                    unit,
                    quality,
                    1 AS sample_count,
                    'raw' AS tier,
                    received_at_ms,
                    producer_time
                FROM sensor_history
                WHERE sensor_id = ? AND timestamp BETWEEN ? AND ?
                {compacted}
            )
            ORDER BY timestamp ASC
            LIMIT ?
            """,
            params,
        ).fetchall()
        return [
            {
                "sensor_id": row["sensor_id"],
                "sensor_type": row["sensor_type"],
                "timestamp": row["timestamp"],
                "value": row["value"],
                "unit": row["unit"],
                "quality": row["quality"],
                "sample_count": row["sample_count"],
                "tier": row["tier"],
                "received_at_ms": row["received_at_ms"],
                "producer_time": _exported_producer_time(row),
            }
            for row in rows
        ]
