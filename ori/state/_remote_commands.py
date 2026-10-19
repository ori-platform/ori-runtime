# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Inbound messages, webhook nonces, remote commands and offline tokens."""

import sqlite3
from typing import Optional

from ori.state._core import (
    StoreCore,
    _audit_bindable,
)
from ori.utils.time_utils import now_ms


class RemoteCommandStore(StoreCore):
    """Inbound messages, webhook nonces, remote commands and offline tokens."""

    # ─── inbound_messages ─────────────────────────────────────────────────────

    async def store_incoming_message(
        self,
        channel: str,
        from_number: str,
        message: str,
        received_at_ms: int | None = None,
        *,
        keep_unconsumed: int | None = None,
        retain_ms: int | None = None,
    ) -> None:
        """Store one inbound message, bounding what the channel keeps.

        With *keep_unconsumed*, only that many of the sender's newest unread
        messages are kept; a listener reads the earliest it has not consumed
        since it began, so the newest replies are the ones that can still
        answer. With *retain_ms*, the channel's messages received longer ago
        than that are removed: no listener waits longer, so none can read them.
        """
        await self._run_write(
            self._store_incoming_message_sync,
            channel,
            from_number,
            message,
            received_at_ms if received_at_ms is not None else now_ms(),
            keep_unconsumed,
            retain_ms,
        )

    def _store_incoming_message_sync(
        self,
        channel: str,
        from_number: str,
        message: str,
        received_at_ms: int,
        keep_unconsumed: int | None = None,
        retain_ms: int | None = None,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO inbound_messages
                (channel, from_number, message, received_at, consumed_at)
            VALUES (?, ?, ?, ?, NULL)
            """,
            (channel, from_number, message, received_at_ms),
        )
        if keep_unconsumed is not None:
            self._conn.execute(
                """
                DELETE FROM inbound_messages
                WHERE id IN (
                    SELECT id FROM inbound_messages
                    WHERE channel = ? AND from_number = ? AND consumed_at IS NULL
                    ORDER BY received_at DESC, id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (channel, from_number, max(1, int(keep_unconsumed))),
            )
        if retain_ms is not None:
            self._conn.execute(
                "DELETE FROM inbound_messages WHERE channel = ? AND received_at < ?",
                (channel, received_at_ms - max(0, int(retain_ms))),
            )
        self._conn.commit()

    async def consume_incoming_message(
        self,
        channel: str,
        from_number: str,
        since_ms: int,
    ) -> Optional[str]:
        return await self._run_write(
            self._consume_incoming_message_sync, channel, from_number, since_ms
        )

    def _consume_incoming_message_sync(
        self,
        channel: str,
        from_number: str,
        since_ms: int,
    ) -> Optional[str]:
        assert self._conn is not None
        row = self._conn.execute(
            """
            SELECT id, message
            FROM inbound_messages
            WHERE channel = ?
              AND from_number = ?
              AND received_at >= ?
              AND consumed_at IS NULL
            ORDER BY received_at ASC, id ASC
            LIMIT 1
            """,
            (channel, from_number, since_ms),
        ).fetchone()
        if row is None:
            return None

        self._conn.execute(
            """
            UPDATE inbound_messages
            SET consumed_at = ?
            WHERE id = ? AND consumed_at IS NULL
            """,
            (now_ms(), row["id"]),
        )
        self._conn.commit()
        return str(row["message"])

    # ─── webhook_replay_log ───────────────────────────────────────────────────

    async def record_webhook_nonce(
        self,
        *,
        source: str,
        nonce: str,
        received_at_ms: int,
        expires_at_ms: int,
    ) -> bool:
        """Record a webhook nonce and return False when it is a replay."""
        return await self._run_write(
            self._record_webhook_nonce_sync,
            source,
            nonce,
            received_at_ms,
            expires_at_ms,
        )

    def _record_webhook_nonce_sync(
        self,
        source: str,
        nonce: str,
        received_at_ms: int,
        expires_at_ms: int,
    ) -> bool:
        assert self._conn is not None
        self._conn.execute(
            "DELETE FROM webhook_replay_log WHERE expires_at_ms <= ?",
            (int(received_at_ms),),
        )
        cursor = self._conn.execute(
            """
            INSERT OR IGNORE INTO webhook_replay_log
                (source, nonce, received_at_ms, expires_at_ms)
            VALUES (?, ?, ?, ?)
            """,
            (
                str(source or ""),
                str(nonce or ""),
                int(received_at_ms),
                int(expires_at_ms),
            ),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    # ─── remote_command_log ───────────────────────────────────────────────────

    async def has_remote_command(self, command_id: str) -> bool:
        return await self._run_read(self._has_remote_command_sync, command_id)

    def _has_remote_command_sync(
        self, conn: sqlite3.Connection, command_id: str
    ) -> bool:
        row = conn.execute(
            """
            SELECT 1
            FROM remote_command_log
            WHERE command_id = ? AND accepted = 1
            LIMIT 1
            """,
            (str(command_id or ""),),
        ).fetchone()
        return row is not None

    async def log_remote_command_attempt(
        self,
        *,
        command_id: str,
        channel: str,
        from_number: str = "",
        command: str,
        accepted: bool,
        reason: str,
        issued_at_ms: int | None = None,
        received_at_ms: int | None = None,
    ) -> None:
        await self._run_write(
            self._log_remote_command_attempt_sync,
            *(
                _audit_bindable(value)
                for value in (
                    command_id,
                    channel,
                    from_number,
                    command,
                    accepted,
                    reason,
                    issued_at_ms,
                    received_at_ms if received_at_ms is not None else now_ms(),
                )
            ),
        )

    def _log_remote_command_attempt_sync(
        self,
        command_id: str,
        channel: str,
        from_number: str,
        command: str,
        accepted: bool,
        reason: str,
        issued_at_ms: int | None,
        received_at_ms: int,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO remote_command_log
                (command_id, channel, from_number, command, accepted, reason, issued_at_ms, received_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(command_id or ""),
                str(channel or ""),
                str(from_number or ""),
                str(command or ""),
                1 if accepted else 0,
                str(reason or ""),
                issued_at_ms,
                received_at_ms,
            ),
        )
        self._conn.commit()

    async def get_remote_command_log(self, limit: int = 50) -> list[dict]:
        return await self._run_read(self._get_remote_command_log_sync, limit)

    def _get_remote_command_log_sync(
        self, conn: sqlite3.Connection, limit: int
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT command_id, channel, from_number, command, accepted, reason, issued_at_ms, received_at_ms
            FROM remote_command_log
            ORDER BY received_at_ms DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["accepted"] = bool(item["accepted"])
            result.append(item)
        return result

    async def count_recent_remote_command_rejections(
        self,
        *,
        channel: str,
        from_number: str,
        since_ms: int,
    ) -> int:
        return await self._run_read(
            self._count_recent_remote_command_rejections_sync,
            channel,
            from_number,
            since_ms,
        )

    def _count_recent_remote_command_rejections_sync(
        self,
        conn: sqlite3.Connection,
        channel: str,
        from_number: str,
        since_ms: int,
    ) -> int:
        row = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM remote_command_log
            WHERE channel = ?
              AND from_number = ?
              AND accepted = 0
              AND received_at_ms >= ?
            """,
            (str(channel or ""), str(from_number or ""), int(since_ms)),
        ).fetchone()
        return int(row["n"] if row is not None else 0)

    async def log_remote_command_security_incident(
        self,
        *,
        incident_id: str,
        channel: str,
        from_number: str,
        reason: str,
        rejection_count: int,
        threshold: int,
        window_ms: int,
        created_at_ms: int | None = None,
    ) -> bool:
        return await self._run_write(
            self._log_remote_command_security_incident_sync,
            incident_id,
            channel,
            from_number,
            reason,
            rejection_count,
            threshold,
            window_ms,
            created_at_ms if created_at_ms is not None else now_ms(),
        )

    def _log_remote_command_security_incident_sync(
        self,
        incident_id: str,
        channel: str,
        from_number: str,
        reason: str,
        rejection_count: int,
        threshold: int,
        window_ms: int,
        created_at_ms: int,
    ) -> bool:
        assert self._conn is not None
        cursor = self._conn.execute(
            """
            INSERT OR IGNORE INTO remote_command_security_incident_log
                (incident_id, channel, from_number, reason, rejection_count,
                 threshold, window_ms, created_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(incident_id or ""),
                str(channel or ""),
                str(from_number or ""),
                str(reason or ""),
                int(rejection_count),
                int(threshold),
                int(window_ms),
                int(created_at_ms),
            ),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    async def get_remote_command_security_incidents(
        self,
        limit: int = 50,
    ) -> list[dict]:
        return await self._run_read(
            self._get_remote_command_security_incidents_sync,
            limit,
        )

    def _get_remote_command_security_incidents_sync(
        self,
        conn: sqlite3.Connection,
        limit: int,
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT incident_id, channel, from_number, reason, rejection_count,
                   threshold, window_ms, created_at_ms
            FROM remote_command_security_incident_log
            ORDER BY created_at_ms DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    async def count_recent_remote_command_security_incidents(
        self,
        *,
        channel: str,
        from_number: str,
        since_ms: int,
    ) -> int:
        return await self._run_read(
            self._count_recent_remote_command_security_incidents_sync,
            channel,
            from_number,
            since_ms,
        )

    def _count_recent_remote_command_security_incidents_sync(
        self,
        conn: sqlite3.Connection,
        channel: str,
        from_number: str,
        since_ms: int,
    ) -> int:
        row = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM remote_command_security_incident_log
            WHERE channel = ?
              AND from_number = ?
              AND created_at_ms >= ?
            """,
            (str(channel or ""), str(from_number or ""), int(since_ms)),
        ).fetchone()
        return int(row["n"] if row is not None else 0)

    async def get_recent_remote_command_incident_senders(
        self,
        *,
        since_ms: int,
        limit: int = 50,
    ) -> list[dict]:
        return await self._run_read(
            self._get_recent_remote_command_incident_senders_sync,
            since_ms,
            limit,
        )

    def _get_recent_remote_command_incident_senders_sync(
        self,
        conn: sqlite3.Connection,
        since_ms: int,
        limit: int,
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT channel, from_number, MAX(created_at_ms) AS last_incident_at_ms,
                   COUNT(*) AS incident_count
            FROM remote_command_security_incident_log
            WHERE created_at_ms >= ?
            GROUP BY channel, from_number
            ORDER BY last_incident_at_ms DESC
            LIMIT ?
            """,
            (int(since_ms), max(1, int(limit))),
        ).fetchall()
        return [dict(row) for row in rows]

    async def log_remote_command_execution(
        self,
        *,
        command_id: str,
        channel: str,
        command: str,
        status: str,
        detail: str,
        executed: bool,
        executed_at_ms: int | None = None,
    ) -> None:
        await self._run_write(
            self._log_remote_command_execution_sync,
            command_id,
            channel,
            command,
            status,
            detail,
            executed,
            executed_at_ms if executed_at_ms is not None else now_ms(),
        )

    def _log_remote_command_execution_sync(
        self,
        command_id: str,
        channel: str,
        command: str,
        status: str,
        detail: str,
        executed: bool,
        executed_at_ms: int,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO remote_command_execution_log
                (command_id, channel, command, status, detail, executed, executed_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(command_id or ""),
                str(channel or ""),
                str(command or ""),
                str(status or ""),
                str(detail or ""),
                1 if executed else 0,
                executed_at_ms,
            ),
        )
        self._conn.commit()

    async def get_remote_command_execution_log(self, limit: int = 50) -> list[dict]:
        return await self._run_read(self._get_remote_command_execution_log_sync, limit)

    def _get_remote_command_execution_log_sync(
        self, conn: sqlite3.Connection, limit: int
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT command_id, channel, command, status, detail, executed, executed_at_ms
            FROM remote_command_execution_log
            ORDER BY executed_at_ms DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["executed"] = bool(item["executed"])
            result.append(item)
        return result

    # ─── offline_token_consumption / offline_token_audit ─────────────────────

    async def claim_offline_token(
        self,
        *,
        token_id: str,
        device_id: str,
        action: str,
        consumed_at_ms: int | None = None,
    ) -> bool:
        return await self._run_write(
            self._claim_offline_token_sync,
            token_id,
            device_id,
            action,
            consumed_at_ms if consumed_at_ms is not None else now_ms(),
        )

    def _claim_offline_token_sync(
        self,
        token_id: str,
        device_id: str,
        action: str,
        consumed_at_ms: int,
    ) -> bool:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            INSERT INTO offline_token_consumption (token_id, device_id, action, consumed_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(token_id) DO NOTHING
            """,
            (token_id, device_id, action, consumed_at_ms),
        )
        self._conn.commit()
        return int(cur.rowcount) > 0

    async def log_offline_token_attempt(
        self,
        *,
        token_id: str,
        device_id: str,
        action: str,
        approved: bool,
        reason: str,
        attempted_at_ms: int | None = None,
    ) -> None:
        await self._run_write(
            self._log_offline_token_attempt_sync,
            token_id,
            device_id,
            action,
            approved,
            reason,
            attempted_at_ms if attempted_at_ms is not None else now_ms(),
        )

    def _log_offline_token_attempt_sync(
        self,
        token_id: str,
        device_id: str,
        action: str,
        approved: bool,
        reason: str,
        attempted_at_ms: int,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO offline_token_audit
                (token_id, device_id, action, approved, reason, attempted_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (token_id, device_id, action, int(bool(approved)), reason, attempted_at_ms),
        )
        self._conn.commit()
