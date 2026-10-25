# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The action log and its attestation."""

import json
import sqlite3
from typing import Any, Optional

from ori.network.events import (
    ActionResult,
)
from ori.state._action_records import (
    RECORD_DISPATCH,
    _action_record_members,
    _check_action_record_shape,
    _normalise_input_evidence,
)
from ori.state._core import StoreCore


class ActionLogStore(StoreCore):
    """The action log and its attestation."""

    # ─── action_log ───────────────────────────────────────────────────────────

    async def log_action(
        self,
        result: ActionResult,
        trigger_name: str,
        *,
        attestation_pending: bool = False,
        record_key: str,
        record_kind: str = "dispatch",
        contributed_to: str | None = None,
    ) -> int:
        return await self._run_write(
            self._log_action_sync,
            result,
            trigger_name,
            {
                "attestation_pending": attestation_pending,
                "record_kind": record_kind,
                "record_key": record_key,
                "contributed_to": contributed_to,
            },
        )

    async def log_action_for_event(
        self,
        result: ActionResult,
        *,
        trigger_name: str,
        device_id: str = "",
        sensor_id: str = "",
        sensor_type: str = "",
        input_attestation_grade: str = "unattested",
        input_posture: str = "",
        input_firmware_device_id: str = "",
        input_firmware_boot_id: int = 0,
        input_firmware_seq: int = 0,
        input_firmware_registration: str = "",
        attestation_pending: bool = False,
        binding_seq: int | None = None,
        authority_json: str | None = None,
        record_key: str,
        record_kind: str = "dispatch",
        contributed_to: str | None = None,
    ) -> int:
        """Persist action result with sensor/device context for reporting.

        ``input_firmware_registration`` is the provisioning snapshot with
        approval provenance, stored in the SAME insert as the action row so
        a crash cannot leave a pending action whose provenance was to be
        written by a later transaction.

        ``authority_json`` is the licence that permitted this action, captured
        here for the same reason and a stronger one: reconciliation after a
        restart must replay the authority that was in force when the action was
        dispatched, and the skill, profile or binding loaded afterwards may be a
        different one. None where the action produces no runtime_action
        evidence.
        """
        return await self._run_write(
            self._log_action_sync,
            result,
            trigger_name,
            {
                "device_id": device_id,
                "sensor_id": sensor_id,
                "sensor_type": sensor_type,
                "input_attestation_grade": input_attestation_grade,
                "input_posture": input_posture,
                "input_firmware_device_id": input_firmware_device_id,
                "input_firmware_boot_id": input_firmware_boot_id,
                "input_firmware_seq": input_firmware_seq,
                "input_firmware_registration": input_firmware_registration,
                "attestation_pending": attestation_pending,
                "binding_seq": binding_seq,
                "authority_json": authority_json,
                "record_kind": record_kind,
                "record_key": record_key,
                "contributed_to": contributed_to,
            },
        )

    def _log_action_sync(
        self,
        result: ActionResult,
        trigger_name: str,
        context_fields: dict | None = None,
    ) -> int:
        assert self._conn is not None
        context_fields = context_fields or {}
        approved_int: Optional[int] = None
        if result.approved is not None:
            approved_int = 1 if result.approved else 0
        attestation_status = (
            "pending" if context_fields.get("attestation_pending") else ""
        )
        record_kind = str(context_fields.get("record_kind", RECORD_DISPATCH))
        record_key = context_fields.get("record_key")
        if not isinstance(record_key, str) or not record_key:
            # The empty key is what rows from before keys hold; a new row that
            # wrote one could never be named, resolved or exported as a key.
            raise ValueError("an action record needs a non-empty record_key")
        contributed_to = context_fields.get("contributed_to")
        _check_action_record_shape(
            record_kind,
            executed=bool(result.executed),
            approved=result.approved,
            action_taken=result.action_taken,
            authority_json=context_fields.get("authority_json"),
            attestation_status=attestation_status,
            contributed_to=contributed_to,
        )
        input_grade, input_posture = _normalise_input_evidence(
            context_fields.get("input_attestation_grade", "unattested"),
            context_fields.get("input_posture", ""),
        )
        cursor = self._conn.execute(
            """
            INSERT INTO action_log
                (action_name, tier, executed, approved, action_taken,
                 operator_response, proposal_id, safe_default_used, device_id,
                 sensor_id, sensor_type, input_attestation_grade, input_posture,
                 input_firmware_device_id, input_firmware_boot_id, input_firmware_seq,
                 input_firmware_registration,
                 correlation_id, trigger_name, timestamp, attestation_status,
                 binding_seq, authority_json, record_kind, record_key,
                 contributed_to)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?)
            """,
            (
                result.action_name,
                result.tier,
                1 if result.executed else 0,
                approved_int,
                result.action_taken,
                result.operator_response,
                result.proposal_id or "",
                1 if result.safe_default_used else 0,
                str(context_fields.get("device_id", "") or ""),
                str(context_fields.get("sensor_id", "") or ""),
                str(context_fields.get("sensor_type", "") or ""),
                input_grade,
                input_posture,
                str(context_fields.get("input_firmware_device_id", "") or ""),
                int(context_fields.get("input_firmware_boot_id", 0) or 0),
                int(context_fields.get("input_firmware_seq", 0) or 0),
                str(context_fields.get("input_firmware_registration", "") or ""),
                result.correlation_id,
                trigger_name,
                result.timestamp,
                attestation_status,
                (
                    int(context_fields["binding_seq"])
                    if context_fields.get("binding_seq") is not None
                    else None
                ),
                context_fields.get("authority_json"),
                record_kind,
                record_key,
                contributed_to,
            ),
        )
        self._conn.commit()
        return int(cursor.lastrowid or 0)

    async def set_action_attestation(
        self,
        action_id: int,
        *,
        status: str,
        attestation_seq: int | None = None,
        reason: str = "",
    ) -> None:
        """Record the evidence-signing outcome for one action_log row."""
        await self._run_write(
            self._set_action_attestation_sync,
            action_id,
            status,
            attestation_seq,
            reason,
        )

    def _set_action_attestation_sync(
        self,
        action_id: int,
        status: str,
        attestation_seq: int | None,
        reason: str = "",
    ) -> None:
        assert self._conn is not None
        if status not in {"pending", "signed", "failed", "reconciled", "refused"}:
            raise ValueError(f"invalid attestation status: {status!r}")
        kind = self._conn.execute(
            "SELECT record_kind FROM action_log WHERE id = ?", (action_id,)
        ).fetchone()
        if kind is not None and kind[0] != RECORD_DISPATCH and status != "refused":
            raise ValueError(
                f"action_log id={action_id} is a {kind[0]} record; it performed "
                "nothing and is never attested"
            )
        self._conn.execute(
            "UPDATE action_log SET attestation_status = ?, attestation_seq = ?, "
            "attestation_reason = ? WHERE id = ?",
            (status, attestation_seq, reason, action_id),
        )
        self._conn.commit()

    async def get_actions_needing_attestation(self, limit: int = 500) -> list[dict]:
        """Rows whose evidence signing did not complete and may yet succeed.

        `refused` is deliberately not among them. It marks a row that cannot be
        attested however many times it is retried — its licence was never
        recorded and cannot be recovered — and re-selecting it would retry a
        failure forever and log once per pass, burying the transient failures
        this loop exists to repair.
        """
        return await self._run_read(self._get_actions_needing_attestation_sync, limit)

    def _get_actions_needing_attestation_sync(
        self, conn: sqlite3.Connection, limit: int
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT id, action_name, tier, executed, approved, action_taken,
                   proposal_id, safe_default_used, device_id, sensor_id,
                   sensor_type, input_attestation_grade, input_posture, correlation_id,
                   input_firmware_device_id, input_firmware_boot_id, input_firmware_seq,
                   input_firmware_registration,
                   trigger_name, timestamp, attestation_status, authority_json,
                   binding_seq, record_kind
            FROM action_log
            WHERE attestation_status IN ('pending', 'failed')
            ORDER BY id
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
        out: list[dict] = []
        for row in rows:
            d = dict(row)
            # Restore the persisted registration snapshot so reconciliation
            # has the same durable provenance the original attestation did.
            raw = d.pop("input_firmware_registration", "") or ""
            d["input_firmware_registration"] = json.loads(raw) if raw else None
            out.append(d)
        return out

    async def get_attestation_summary(self) -> dict:
        """Aggregate evidence-signing state for health snapshots."""
        return await self._run_read(self._get_attestation_summary_sync)

    def _get_attestation_summary_sync(self, conn: sqlite3.Connection) -> dict:
        status_rows = conn.execute(
            """
            SELECT attestation_status, COUNT(*) AS n
            FROM action_log
            WHERE attestation_status != ''
            GROUP BY attestation_status
            """
        ).fetchall()
        status_counts = {str(row[0]): int(row[1]) for row in status_rows}
        last_attested = conn.execute(
            """
            SELECT MAX(id) FROM action_log
            WHERE attestation_status IN ('signed', 'reconciled')
            """
        ).fetchone()
        gap_count = int(
            status_counts.get("pending", 0) + status_counts.get("failed", 0)
        )
        # A contributor names the holder it joined; a holder row that never
        # appeared is lost evidence of the act, reported rather than repaired.
        # The contributor's row is written after its holder's, so no grace is
        # needed for a holder still deciding. A link resolves to exactly one
        # dispatch row, never to whichever of several shares the key.
        unresolved = conn.execute(
            """
            SELECT COUNT(*) FROM action_log AS c
            WHERE c.record_kind = 'contributor'
              AND (
                  SELECT COUNT(*) FROM action_log AS h
                  WHERE h.record_kind = 'dispatch'
                    AND h.record_key = c.contributed_to
              ) <> 1
            """
        ).fetchone()
        return {
            "status_counts": status_counts,
            "last_attested_action_id": (
                int(last_attested[0]) if last_attested and last_attested[0] else None
            ),
            "attestation_gap_count": gap_count,
            "contributor_links_unresolved": int(unresolved[0]),
        }

    async def get_action_log(self, limit: int = 50) -> list[dict]:
        return await self._run_read(self._get_action_log_sync, limit)

    def _get_action_log_sync(self, conn: sqlite3.Connection, limit: int) -> list[dict]:
        rows = conn.execute(
            """
            SELECT action_name, tier, executed, approved, action_taken,
                   operator_response, proposal_id, safe_default_used, device_id,
                   sensor_id, sensor_type, input_attestation_grade, input_posture,
                   input_firmware_device_id, input_firmware_boot_id, input_firmware_seq,
                   correlation_id,
                   trigger_name, timestamp, attestation_status, attestation_seq,
                   record_kind, record_key, contributed_to
            FROM action_log
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            approved_val: Optional[bool] = None
            if row["approved"] is not None:
                approved_val = bool(row["approved"])
            result.append(
                {
                    "action_name": row["action_name"],
                    "tier": row["tier"],
                    "executed": bool(row["executed"]),
                    "approved": approved_val,
                    "action_taken": row["action_taken"],
                    "operator_response": row["operator_response"],
                    "proposal_id": row["proposal_id"],
                    "safe_default_used": bool(row["safe_default_used"]),
                    "device_id": row["device_id"],
                    "sensor_id": row["sensor_id"],
                    "sensor_type": row["sensor_type"],
                    "input_attestation_grade": row["input_attestation_grade"],
                    "input_posture": row["input_posture"],
                    "input_firmware_device_id": row["input_firmware_device_id"],
                    "input_firmware_boot_id": row["input_firmware_boot_id"],
                    "input_firmware_seq": row["input_firmware_seq"],
                    "correlation_id": row["correlation_id"],
                    "trigger_name": row["trigger_name"],
                    "timestamp": row["timestamp"],
                    "attestation_status": row["attestation_status"],
                    "attestation_seq": row["attestation_seq"],
                    **_action_record_members(row),
                }
            )
        return result

    async def export_action_log(
        self,
        *,
        device_id: str | None = None,
        since_ms: int | None = None,
        until_ms: int | None = None,
        tier: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return a bounded action-log export for gateway/reporting sync."""
        return await self._run_read(
            self._export_action_log_sync,
            device_id,
            since_ms,
            until_ms,
            tier,
            limit,
        )

    def _export_action_log_sync(
        self,
        conn: sqlite3.Connection,
        device_id: str | None,
        since_ms: int | None,
        until_ms: int | None,
        tier: str | None,
        limit: int,
    ) -> list[dict]:
        # A refusal stores the tier it was handed, which may be none of A to D;
        # the export carries only the four, so such a row is omitted from it,
        # in the query so paging counts only what is sent. The store keeps it.
        where = ["tier IN ('A', 'B', 'C', 'D')"]
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
        if tier:
            where.append("tier = ?")
            params.append(str(tier).upper())
        where_sql = f"WHERE {' AND '.join(where)}"
        params.append(max(1, min(int(limit), 1000)))
        query = (
            """
            SELECT action_name, tier, executed, approved, action_taken,
                   operator_response, proposal_id, safe_default_used, device_id,
                   sensor_id, sensor_type, input_attestation_grade, input_posture,
                   input_firmware_device_id, input_firmware_boot_id, input_firmware_seq,
                   correlation_id,
                   trigger_name, timestamp, attestation_status, attestation_seq,
                   record_kind, record_key, contributed_to
            FROM action_log
            """
            + where_sql
            + """
            ORDER BY timestamp DESC
            LIMIT ?
            """
        )
        rows = conn.execute(query, tuple(params)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["executed"] = bool(item["executed"])
            item["approved"] = (
                bool(item["approved"]) if item["approved"] is not None else None
            )
            item["safe_default_used"] = bool(item["safe_default_used"])
            item.update(_action_record_members(row))
            result.append(item)
        return result
