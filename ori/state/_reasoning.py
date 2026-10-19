# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Reasoning and override logs, causal memory and rejection memory."""

import datetime
import hashlib
import sqlite3
from typing import Any, Optional

from ori.network.events import (
    ReasoningResult,
)
from ori.state._core import (
    StoreCore,
    _audit_bindable,
)
from ori.utils.time_utils import now_ms


class ReasoningStore(StoreCore):
    """Reasoning and override logs, causal memory and rejection memory."""

    # ─── reasoning_log ───────────────────────────────────────────────────────

    async def log_reasoning(
        self,
        result: ReasoningResult,
        trigger_name: str,
        device_id: str,
    ) -> None:
        """Persist a :class:`~ori.network.events.ReasoningResult` to reasoning_log."""
        await self._run_write(self._log_reasoning_sync, result, trigger_name, device_id)

    def _log_reasoning_sync(
        self,
        result: ReasoningResult,
        trigger_name: str,
        device_id: str,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO reasoning_log
                (trigger_name, tier_used, prompt, response, confidence,
                 action_tier, device_id, model, tokens_used, latency_ms,
                 proposed_action, reasoning_status, correlation_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trigger_name,
                result.tier,
                result.prompt,
                result.text,
                result.confidence,
                result.action_tier,
                device_id,
                result.model,
                result.tokens_used,
                result.latency_ms,
                result.proposed_action,
                result.reasoning_status,
                result.correlation_id,
                now_ms(),
            ),
        )
        self._conn.commit()

    async def export_reasoning_log(
        self,
        *,
        device_id: str | None = None,
        since_ms: int | None = None,
        until_ms: int | None = None,
        tier_used: str | None = None,
        action_tier: str | None = None,
        reasoning_status: str | None = None,
        correlation_id: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return a bounded reasoning-log export for gateway/cloud sync."""
        return await self._run_read(
            self._export_reasoning_log_sync,
            device_id,
            since_ms,
            until_ms,
            tier_used,
            action_tier,
            reasoning_status,
            correlation_id,
            limit,
        )

    def _export_reasoning_log_sync(
        self,
        conn: sqlite3.Connection,
        device_id: str | None,
        since_ms: int | None,
        until_ms: int | None,
        tier_used: str | None,
        action_tier: str | None,
        reasoning_status: str | None,
        correlation_id: str | None,
        limit: int,
    ) -> list[dict]:
        where = []
        params: list[Any] = []
        if device_id:
            where.append("device_id = ?")
            params.append(str(device_id))
        if since_ms is not None:
            where.append("timestamp >= ?")
            params.append(int(since_ms))
        if until_ms is not None:
            where.append("timestamp <= ?")
            params.append(int(until_ms))
        if tier_used:
            where.append("tier_used = ?")
            params.append(str(tier_used))
        if action_tier:
            where.append("action_tier = ?")
            params.append(str(action_tier).upper())
        if reasoning_status:
            where.append("reasoning_status = ?")
            params.append(str(reasoning_status))
        if correlation_id:
            where.append("correlation_id = ?")
            params.append(str(correlation_id))
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        params.append(max(1, min(int(limit), 1000)))
        query = (
            """
            SELECT trigger_name, tier_used, prompt, response, confidence,
                   action_tier, device_id, model, tokens_used, latency_ms,
                   proposed_action, reasoning_status, correlation_id, timestamp
            FROM reasoning_log
            """
            + where_sql
            + """
            ORDER BY timestamp DESC
            LIMIT ?
            """
        )
        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    # ─── override_log ─────────────────────────────────────────────────────────

    async def log_override(
        self,
        trigger_name: str,
        action: str,
        reason: str,
        operator_response: Optional[str],
        override_type: str,
        device_id: str,
    ) -> None:
        """Persist an operator rejection or autonomous Tier D override."""
        await self._run_write(
            self._log_override_sync,
            *(
                _audit_bindable(value)
                for value in (
                    trigger_name,
                    action,
                    reason,
                    operator_response,
                    override_type,
                    device_id,
                )
            ),
        )

    def _log_override_sync(
        self,
        trigger_name: str,
        action: str,
        reason: str,
        operator_response: Optional[str],
        override_type: str,
        device_id: str,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO override_log
                (trigger_name, action, reason, operator_response,
                 override_type, device_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trigger_name,
                action,
                reason,
                operator_response,
                override_type,
                device_id,
                now_ms(),
            ),
        )
        self._conn.commit()

    # ─── causal_memory ────────────────────────────────────────────────────────

    async def lookup_causal_memory(self, pattern_key: str) -> Optional[str]:
        # Intentional write-path lock: lookup also updates hit_count/last_seen
        # in the same transaction for causal-memory ranking.
        return await self._run_write(self._lookup_causal_sync, pattern_key)

    def _lookup_causal_sync(self, pattern_key: str) -> Optional[str]:
        assert self._conn is not None
        row = self._conn.execute(
            """
            SELECT resolution FROM causal_memory WHERE pattern_key = ?
            """,
            (pattern_key,),
        ).fetchone()
        if row is None:
            return None
        # Increment hit_count and update last_seen in the same transaction
        self._conn.execute(
            """
            UPDATE causal_memory
            SET hit_count = hit_count + 1, last_seen = ?
            WHERE pattern_key = ?
            """,
            (now_ms(), pattern_key),
        )
        self._conn.commit()
        return str(row["resolution"])

    async def store_causal_memory(
        self, pattern_key: str, resolution: str, confidence: float
    ) -> None:
        await self._run_write(
            self._store_causal_sync, pattern_key, resolution, confidence
        )

    def _store_causal_sync(
        self, pattern_key: str, resolution: str, confidence: float
    ) -> None:
        assert self._conn is not None
        now = now_ms()
        self._conn.execute(
            """
            INSERT INTO causal_memory
                (pattern_key, resolution, confidence, created_at, last_seen, hit_count)
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(pattern_key) DO UPDATE SET
                resolution = excluded.resolution,
                confidence = excluded.confidence,
                last_seen  = excluded.last_seen,
                hit_count  = hit_count + 1
            """,
            (pattern_key, resolution, confidence, now, now),
        )
        self._conn.commit()

    # ─── causal_memory_rejections ────────────────────────────────────────────

    async def store_rejection(
        self,
        pattern_key: str,
        trigger_name: str,
        proposed_action: str,
        operator_response: str | None,
        device_id: str,
        sensor_type: str,
        value_bucket: float,
        time_of_day_hour: int,
        day_of_week: int,
        expiry_days: int = 30,
    ) -> None:
        await self._run_write(
            self._store_rejection_sync,
            pattern_key,
            trigger_name,
            proposed_action,
            operator_response,
            device_id,
            sensor_type,
            value_bucket,
            time_of_day_hour,
            day_of_week,
            expiry_days,
        )

    def _store_rejection_sync(
        self,
        pattern_key: str,
        trigger_name: str,
        proposed_action: str,
        operator_response: str | None,
        device_id: str,
        sensor_type: str,
        value_bucket: float,
        time_of_day_hour: int,
        day_of_week: int,
        expiry_days: int,
    ) -> None:
        assert self._conn is not None
        rejected_at = now_ms()
        expiry_ms: int | None = None
        if expiry_days > 0:
            expiry_ms = int(expiry_days * 86_400_000)
        self._conn.execute(
            """
            INSERT INTO causal_memory_rejections
                (pattern_key, trigger_name, proposed_action, operator_response,
                 device_id, sensor_type, value_bucket, time_of_day_hour,
                 day_of_week, rejected_at, expiry_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(pattern_key, proposed_action) DO UPDATE SET
                trigger_name = excluded.trigger_name,
                operator_response = excluded.operator_response,
                device_id = excluded.device_id,
                sensor_type = excluded.sensor_type,
                value_bucket = excluded.value_bucket,
                time_of_day_hour = excluded.time_of_day_hour,
                day_of_week = excluded.day_of_week,
                rejected_at = excluded.rejected_at,
                expiry_ms = excluded.expiry_ms
            """,
            (
                pattern_key,
                trigger_name,
                proposed_action,
                operator_response,
                device_id,
                sensor_type,
                value_bucket,
                time_of_day_hour,
                day_of_week,
                rejected_at,
                expiry_ms,
            ),
        )
        self._conn.commit()

    async def lookup_rejection(self, pattern_key: str) -> Optional[dict]:
        return await self._run_read(self._lookup_rejection_sync, pattern_key)

    def _lookup_rejection_sync(
        self, conn: sqlite3.Connection, pattern_key: str
    ) -> Optional[dict]:
        row = conn.execute(
            """
            SELECT id, pattern_key, trigger_name, proposed_action, operator_response,
                   device_id, sensor_type, value_bucket, time_of_day_hour,
                   day_of_week, rejected_at, expiry_ms
            FROM causal_memory_rejections
            WHERE pattern_key = ?
            ORDER BY rejected_at DESC
            LIMIT 1
            """,
            (pattern_key,),
        ).fetchone()
        if row is None:
            return None

        expiry_ms = row["expiry_ms"]
        if expiry_ms is not None:
            expires_at = int(row["rejected_at"]) + int(expiry_ms)
            if expires_at < now_ms():
                return None

        return dict(row)

    @staticmethod
    def _build_rejection_pattern_key(
        sensor_type: str,
        trigger_name: str,
        proposed_action: str,
        value: float,
        timestamp_ms: int,
    ) -> str:
        value_bucket = round(float(value) * 2.0) / 2.0
        dt = datetime.datetime.fromtimestamp(
            timestamp_ms / 1000.0, tz=datetime.timezone.utc
        )
        two_hour_bucket = (dt.hour // 2) * 2
        day_of_week = dt.weekday()
        raw = (
            f"{sensor_type}|{trigger_name}|{proposed_action}|"
            f"{value_bucket:.1f}|{two_hour_bucket}|{day_of_week}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
