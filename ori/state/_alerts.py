# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The outbound alert outbox and delivery receipts."""

import json
import sqlite3

from ori.state._core import StoreCore
from ori.utils.time_utils import now_ms


class AlertOutboxStore(StoreCore):
    """The outbound alert outbox and delivery receipts."""

    # ─── alert_outbox ─────────────────────────────────────────────────────────

    async def enqueue_alert(
        self,
        *,
        alert_id: str,
        channel: str,
        recipient: str,
        message: str,
        intent: str = "tier_a_alert",
        template_variables: tuple[str, ...] = (),
        action_tier: str,
        trigger_name: str,
        original_ts: int,
        notice_kind: str,
    ) -> bool:
        """Insert an outbound alert row into alert_outbox.

        Returns:
            True if a new row was inserted, False if a row with alert_id already
            exists (deduplicated by UNIQUE constraint).
        """
        return await self._run_write(
            self._enqueue_alert_sync,
            alert_id,
            channel,
            recipient,
            message,
            intent,
            template_variables,
            action_tier,
            trigger_name,
            original_ts,
            notice_kind,
        )

    def _enqueue_alert_sync(
        self,
        alert_id: str,
        channel: str,
        recipient: str,
        message: str,
        intent: str,
        template_variables: tuple[str, ...],
        action_tier: str,
        trigger_name: str,
        original_ts: int,
        notice_kind: str,
    ) -> bool:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            INSERT INTO alert_outbox
                (alert_id, channel, recipient, message, intent,
                 template_variables_json, action_tier, trigger_name, original_ts,
                 queued_at_ms, notice_kind, retry_seq, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    (SELECT COALESCE(MAX(retry_seq), 0) + 1 FROM alert_outbox), 'pending')
            ON CONFLICT(alert_id) DO NOTHING
            """,
            (
                alert_id,
                channel,
                recipient,
                message,
                intent,
                json.dumps(list(template_variables), separators=(",", ":")),
                action_tier,
                trigger_name,
                original_ts,
                now_ms(),
                notice_kind,
            ),
        )
        self._conn.commit()
        return int(cur.rowcount) > 0

    async def get_retryable_alerts(
        self, limit: int = 50, *, mandatory: bool | None = None
    ) -> list[dict]:
        """Fetch pending/failed outbox alerts in queue order, first in first out.

        A row takes the next ``retry_seq`` when it is queued and again when an
        attempt fails, so a failed row goes behind every row queued before then
        and none can be overtaken for ever. The order reads no clock. With
        *mandatory*, only mandatory (``True``) or optional (``False``) rows.
        """
        return await self._run_read(self._get_retryable_alerts_sync, limit, mandatory)

    def _get_retryable_alerts_sync(
        self,
        conn: sqlite3.Connection,
        limit: int,
        mandatory: bool | None,
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT alert_id, channel, recipient, message, intent,
                   template_variables_json, action_tier, trigger_name,
                   original_ts, queued_at_ms, attempt_count, last_attempt_ts, status,
                   notice_kind
            FROM alert_outbox
            WHERE status IN ('pending', 'failed')
              AND (? IS NULL OR (COALESCE(notice_kind, '') != 'optional') = ?)
            ORDER BY retry_seq ASC, id ASC
            LIMIT ?
            """,
            (mandatory, mandatory, limit),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["template_variables"] = tuple(
                json.loads(item.pop("template_variables_json"))
            )
            result.append(item)
        return result

    async def get_alert_outbox_summary(self) -> dict[str, int | None]:
        """Return a bounded health summary for pending/failed outbound alerts."""
        return await self._run_read(self._get_alert_outbox_summary_sync)

    def _get_alert_outbox_summary_sync(
        self,
        conn: sqlite3.Connection,
    ) -> dict[str, int | None]:
        row = conn.execute(
            """
            SELECT COUNT(*) AS backlog_count,
                   MIN(original_ts) AS oldest_queued_original_ts,
                   MIN(queued_at_ms) AS oldest_queued_at_ms
            FROM alert_outbox
            WHERE status IN ('pending', 'failed')
            """
        ).fetchone()
        backlog_count = int(row["backlog_count"] or 0)
        oldest_ts = (
            int(row["oldest_queued_original_ts"])
            if row["oldest_queued_original_ts"] is not None
            else None
        )
        oldest_queued_at = (
            int(row["oldest_queued_at_ms"])
            if row["oldest_queued_at_ms"] is not None
            else None
        )
        return {
            "backlog_count": backlog_count,
            # The producer's account, reported beside the store's own receipt.
            "oldest_queued_original_ts": oldest_ts,
            "oldest_queued_at_ms": oldest_queued_at,
        }

    async def mark_alert_accepted(
        self,
        alert_id: str,
        *,
        accepted_channel: str,
        provider_message_id: str,
        provider_status: str,
        accepted_at_ms: int,
        delivered_at_ms: int | None = None,
    ) -> None:
        """Record provider acceptance without claiming handset delivery."""

        await self._run_write(
            self._mark_alert_accepted_sync,
            alert_id,
            accepted_channel,
            provider_message_id,
            provider_status,
            accepted_at_ms,
            delivered_at_ms,
        )

    def _mark_alert_accepted_sync(
        self,
        alert_id: str,
        accepted_channel: str,
        provider_message_id: str,
        provider_status: str,
        accepted_at_ms: int,
        delivered_at_ms: int | None,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            UPDATE alert_outbox
               SET status = 'accepted',
                   retry_seq = (SELECT COALESCE(MAX(retry_seq), 0) + 1 FROM alert_outbox),
                   accepted_channel = ?,
                   provider_message_id = ?,
                   provider_status = ?,
                   accepted_at_ms = ?,
                   delivered_at_ms = ?,
                   last_attempt_ts = ?,
                   last_status_at_ms = ?
             WHERE alert_id = ?
            """,
            (
                accepted_channel,
                provider_message_id,
                provider_status,
                accepted_at_ms,
                delivered_at_ms,
                accepted_at_ms,
                accepted_at_ms,
                alert_id,
            ),
        )
        self._conn.commit()

    async def get_alerts_awaiting_delivery_receipt(
        self,
        limit: int = 50,
    ) -> list[dict]:
        return await self._run_read(
            self._get_alerts_awaiting_delivery_receipt_sync, limit
        )

    def _get_alerts_awaiting_delivery_receipt_sync(
        self,
        conn: sqlite3.Connection,
        limit: int,
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT alert_id, accepted_channel, provider_message_id,
                   provider_status, accepted_at_ms, action_tier, attempt_count,
                   notice_kind
              FROM alert_outbox
             WHERE status = 'accepted'
               AND delivered_at_ms IS NULL
               AND provider_message_id != ''
             ORDER BY retry_seq ASC, id ASC
             LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    async def requeue_alert_receipt_poll(self, alert_id: str) -> None:
        """Move an accepted row awaiting its receipt behind every other one."""
        await self._run_write(self._requeue_alert_receipt_poll_sync, alert_id)

    def _requeue_alert_receipt_poll_sync(self, alert_id: str) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            UPDATE alert_outbox
               SET retry_seq = (SELECT COALESCE(MAX(retry_seq), 0) + 1 FROM alert_outbox)
             WHERE alert_id = ? AND status = 'accepted' AND delivered_at_ms IS NULL
            """,
            (alert_id,),
        )
        self._conn.commit()

    async def record_alert_delivery_status(
        self,
        alert_id: str,
        *,
        provider_status: str,
        observed_at_ms: int,
        delivered_at_ms: int | None,
        terminal_failure: bool,
    ) -> None:
        await self._run_write(
            self._record_alert_delivery_status_sync,
            alert_id,
            provider_status,
            observed_at_ms,
            delivered_at_ms,
            terminal_failure,
        )

    async def record_alert_delivery_status_by_provider_id(
        self,
        *,
        channel: str,
        provider_message_id: str,
        provider_status: str,
        observed_at_ms: int,
        delivered_at_ms: int | None,
        terminal_failure: bool,
    ) -> bool:
        """Apply a provider callback only to its uniquely accepted alert."""

        return bool(
            await self._run_write(
                self._record_alert_delivery_status_by_provider_id_sync,
                channel,
                provider_message_id,
                provider_status,
                observed_at_ms,
                delivered_at_ms,
                terminal_failure,
            )
        )

    def _record_alert_delivery_status_by_provider_id_sync(
        self,
        channel: str,
        provider_message_id: str,
        provider_status: str,
        observed_at_ms: int,
        delivered_at_ms: int | None,
        terminal_failure: bool,
    ) -> bool:
        assert self._conn is not None
        rows = self._conn.execute(
            """
            SELECT alert_id
              FROM alert_outbox
             WHERE status = 'accepted'
               AND accepted_channel = ?
               AND provider_message_id = ?
             ORDER BY id ASC
             LIMIT 2
            """,
            (channel, provider_message_id),
        ).fetchall()
        if len(rows) != 1:
            return False
        self._record_alert_delivery_status_sync(
            str(rows[0]["alert_id"]),
            provider_status,
            observed_at_ms,
            delivered_at_ms,
            terminal_failure,
        )
        return True

    def _record_alert_delivery_status_sync(
        self,
        alert_id: str,
        provider_status: str,
        observed_at_ms: int,
        delivered_at_ms: int | None,
        terminal_failure: bool,
    ) -> None:
        assert self._conn is not None
        if terminal_failure:
            self._conn.execute(
                """
                UPDATE alert_outbox
                   SET status = 'failed',
                       provider_status = ?,
                       last_status_at_ms = ?,
                       attempt_count = attempt_count + 1,
                       retry_seq = (SELECT COALESCE(MAX(retry_seq), 0) + 1 FROM alert_outbox)
                 WHERE alert_id = ? AND status = 'accepted'
                """,
                (provider_status, observed_at_ms, alert_id),
            )
        else:
            self._conn.execute(
                """
                UPDATE alert_outbox
                   SET provider_status = ?,
                       last_status_at_ms = ?,
                       delivered_at_ms = COALESCE(delivered_at_ms, ?)
                 WHERE alert_id = ? AND status = 'accepted'
                """,
                (provider_status, observed_at_ms, delivered_at_ms, alert_id),
            )
        self._conn.commit()

    async def mark_alert_attempt_failed(
        self, alert_id: str, failed_ts_ms: int | None = None
    ) -> None:
        await self._run_write(
            self._mark_alert_attempt_failed_sync,
            alert_id,
            failed_ts_ms if failed_ts_ms is not None else now_ms(),
        )

    def _mark_alert_attempt_failed_sync(self, alert_id: str, failed_ts_ms: int) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            UPDATE alert_outbox
            SET attempt_count = attempt_count + 1,
                last_attempt_ts = ?,
                status = 'failed',
                retry_seq = (SELECT COALESCE(MAX(retry_seq), 0) + 1 FROM alert_outbox)
            WHERE alert_id = ?
            """,
            (failed_ts_ms, alert_id),
        )
        self._conn.commit()

    async def mark_alert_abandoned(
        self, alert_id: str, abandoned_ts_ms: int | None = None
    ) -> bool:
        """Abandon an optional notice; return whether a row was abandoned.

        Only ``notice_kind = 'optional'`` is ever abandoned, whoever asks, so a
        mandatory or unrecognised notice stays queued.
        """
        return await self._run_write(
            self._mark_alert_abandoned_sync,
            alert_id,
            abandoned_ts_ms if abandoned_ts_ms is not None else now_ms(),
        )

    def _mark_alert_abandoned_sync(self, alert_id: str, abandoned_ts_ms: int) -> bool:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            UPDATE alert_outbox
            SET status = 'abandoned',
                last_attempt_ts = ?
            WHERE alert_id = ? AND notice_kind = 'optional'
            """,
            (abandoned_ts_ms, alert_id),
        )
        self._conn.commit()
        return int(cur.rowcount) > 0
