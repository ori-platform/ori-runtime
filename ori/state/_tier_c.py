# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tier C proposals, their records, safe-default intents and decisions."""

import json
import logging
import sqlite3
from typing import Any

from ori.state._core import (
    StoreCore,
    _audit_bindable,
)
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.state.store")


#: The closed decision states of tier-c-approval/v1 as this store spells them;
#: `tests/test_tier_c_proposal_store.py` holds it equal to the admission module's.
_TIER_C_DECISION_STATES: frozenset[str] = frozenset(
    {
        "proposed",
        "proposal_expired",
        "rejected",
        "approved_pending_dispatch",
        "dispatch_started",
        "executed",
        "approval_expired_undispatched",
        "approval_aborted_undispatched",
        "proposal_aborted_restart",
        "approval_binding_changed",
        "proposal_blocked_uncertain_outcome",
        "dispatch_refused_contention",
        "dispatch_failed",
        "dispatch_outcome_unknown",
        "dispatch_not_proven",
        "reconciled_executed",
        "reconciled_not_executed",
    }
)


class TierCStore(StoreCore):
    """Tier C proposals, their records, safe-default intents and decisions."""

    # ─── tier_c_proposals ──────────────────────────────────────────────────────

    async def create_tier_c_proposal(self, **row: Any) -> str:
        """Commit a proposal row; only then does a proposal exist.

        ``committed``, ``blocked`` when an unresolved approval already commands
        the same outcome on the same zone, or ``duplicate``. Raises when the
        store cannot take it, and then no proposal exists.
        """
        return await self._run_write(self._create_tier_c_proposal_sync, row)

    def _create_tier_c_proposal_sync(self, row: dict[str, Any]) -> str:
        assert self._conn is not None
        conn = self._conn
        now = now_ms()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if self._tier_c_outcome_blocked(
                conn, row["zone_id"], row["outcome"], None, in_flight_blocks=False
            ):
                conn.rollback()
                return "blocked"
            inserted = conn.execute(
                """
                INSERT INTO tier_c_proposals
                    (proposal_id, device_id, action, target, zone_id, outcome,
                     event_id, skill_name, trigger_name, safe_default_action,
                     binding_digest, authority_json, created_at_ms, expires_at_ms,
                     decision_state, updated_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?)
                ON CONFLICT(proposal_id) DO NOTHING
                """,
                (
                    row["proposal_id"],
                    row["device_id"],
                    row["action"],
                    row.get("target", ""),
                    row["zone_id"],
                    row["outcome"],
                    row.get("event_id", ""),
                    row.get("skill_name", ""),
                    row.get("trigger_name", ""),
                    row.get("safe_default_action", ""),
                    row.get("binding_digest", ""),
                    row.get("authority_json", ""),
                    int(row["created_at_ms"]),
                    int(row["expires_at_ms"]),
                    now,
                ),
            )
            if int(inserted.rowcount) == 0:
                conn.rollback()
                return "duplicate"
            self._append_tier_c_record(conn, row["proposal_id"], "proposed", "", now)
            conn.commit()
            return "committed"
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

    @staticmethod
    def _tier_c_outcome_blocked(
        conn: sqlite3.Connection,
        zone_id: str,
        outcome: str,
        except_proposal: str | None,
        *,
        in_flight_blocks: bool = True,
    ) -> bool:
        """Whether an unresolved approval commands *outcome* on *zone_id*.

        At reply admission an approval still in flight blocks too; at proposal
        creation only an unresolved uncertainty does, and one merely in flight
        is caught when the later reply is admitted.
        """
        states = (
            "('approved_pending_dispatch', 'dispatch_started', "
            "'dispatch_outcome_unknown', 'dispatch_not_proven')"
            if in_flight_blocks
            else "('dispatch_outcome_unknown', 'dispatch_not_proven')"
        )
        cur = conn.execute(
            f"""
            SELECT 1 FROM tier_c_proposals
             WHERE zone_id = ? AND outcome = ?
               AND decision_state IN {states}
               AND (? IS NULL OR proposal_id != ?)
             LIMIT 1
            """,
            (zone_id, outcome, except_proposal, except_proposal),
        )
        return cur.fetchone() is not None

    @staticmethod
    def _append_tier_c_record(
        conn: sqlite3.Connection, proposal_id: str, state: str, reason: str, at_ms: int
    ) -> None:
        conn.execute(
            """
            INSERT INTO tier_c_proposal_records
                (proposal_id, decision_state, state_reason, recorded_at_ms)
            VALUES (?, ?, ?, ?)
            """,
            (proposal_id, state, reason, at_ms),
        )

    async def admit_tier_c_approval(
        self,
        proposal_id: str,
        *,
        binding_digest: str,
        authority_json: str,
        reservation_ceiling: int,
        ingress_channel: str = "",
        ingress_from: str = "",
        ingress_message_id: str = "",
        operator_response: str = "",
        offline_token_id: str = "",
    ) -> str:
        """Admit an operator's affirmative reply; one transaction, one answer.

        ``committed`` and the reply is an approval. ``duplicate`` when it was
        already admitted. ``binding_changed`` when the binding or authority
        bytes differ from the proposal's (the proposal is closed so). ``blocked``
        when an unresolved approval commands the same outcome on the same zone
        (closed so). ``reservation_unavailable`` when the pending-outcome
        ceiling leaves no room for this approval's terminal record; the proposal
        stays open. ``token_replayed`` when the token was already claimed.
        ``closed:<state>`` when the proposal is no longer open. Raises when the
        store cannot answer, and the reply is then not an approval.
        """
        return await self._run_write(
            self._admit_tier_c_approval_sync,
            proposal_id,
            binding_digest,
            authority_json,
            int(reservation_ceiling),
            {
                "ingress_channel": ingress_channel,
                "ingress_from": ingress_from,
                "ingress_message_id": ingress_message_id,
                "operator_response": operator_response,
                "offline_token_id": offline_token_id,
            },
        )

    def _admit_tier_c_approval_sync(
        self,
        proposal_id: str,
        binding_digest: str,
        authority_json: str,
        ceiling: int,
        ingress: dict[str, str],
    ) -> str:
        assert self._conn is not None
        conn = self._conn
        now = now_ms()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM tier_c_proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
            if row is None:
                conn.rollback()
                return "closed:none"
            state = str(row["decision_state"])
            if state != "proposed":
                conn.rollback()
                admitted = (
                    "approved_pending_dispatch",
                    "dispatch_started",
                    "executed",
                    "approval_expired_undispatched",
                    "approval_aborted_undispatched",
                    "dispatch_refused_contention",
                    "dispatch_failed",
                    "dispatch_outcome_unknown",
                    "dispatch_not_proven",
                    "reconciled_executed",
                    "reconciled_not_executed",
                )
                return "duplicate" if state in admitted else f"closed:{state}"
            if str(row["binding_digest"]) != str(binding_digest) or str(
                row["authority_json"]
            ) != str(authority_json):
                self._move_tier_c(
                    conn, proposal_id, "approval_binding_changed", "", now
                )
                self._insert_tier_c_intent(
                    conn,
                    proposal_id,
                    str(row["safe_default_action"]),
                    "approval_binding_changed",
                    now,
                )
                conn.commit()
                return "binding_changed"
            if self._tier_c_outcome_blocked(
                conn, str(row["zone_id"]), str(row["outcome"]), proposal_id
            ):
                self._move_tier_c(
                    conn, proposal_id, "proposal_blocked_uncertain_outcome", "", now
                )
                self._insert_tier_c_intent(
                    conn,
                    proposal_id,
                    str(row["safe_default_action"]),
                    "proposal_blocked_uncertain_outcome",
                    now,
                )
                conn.commit()
                return "blocked"
            reserved = conn.execute(
                """
                SELECT count(*) FROM tier_c_proposals
                 WHERE decision_state IN ('approved_pending_dispatch', 'dispatch_started')
                """
            ).fetchone()[0]
            if int(reserved) >= ceiling:
                conn.rollback()
                return "reservation_unavailable"
            token_id = str(ingress.get("offline_token_id") or "")
            if token_id:
                claimed = conn.execute(
                    """
                    INSERT INTO offline_token_consumption
                        (token_id, device_id, action, consumed_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(token_id) DO NOTHING
                    """,
                    (token_id, str(row["device_id"]), str(row["action"]), now),
                )
                if int(claimed.rowcount) == 0:
                    conn.rollback()
                    return "token_replayed"
            conn.execute(
                """
                UPDATE tier_c_proposals
                   SET decision_state = 'approved_pending_dispatch', state_reason = '',
                       ingress_channel = ?, ingress_from = ?, ingress_message_id = ?,
                       operator_response = ?, offline_token_id = ?,
                       committed_at_ms = ?, updated_at_ms = ?
                 WHERE proposal_id = ? AND decision_state = 'proposed'
                """,
                (
                    ingress.get("ingress_channel", ""),
                    ingress.get("ingress_from", ""),
                    ingress.get("ingress_message_id", ""),
                    ingress.get("operator_response", ""),
                    token_id,
                    now,
                    now,
                    proposal_id,
                ),
            )
            self._append_tier_c_record(
                conn, proposal_id, "approved_pending_dispatch", "", now
            )
            conn.commit()
            return "committed"
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

    @staticmethod
    def _move_tier_c(
        conn: sqlite3.Connection,
        proposal_id: str,
        state: str,
        reason: str,
        now: int,
        outcome_json: str | None = None,
    ) -> None:
        conn.execute(
            """
            UPDATE tier_c_proposals
               SET decision_state = ?, state_reason = ?,
                   outcome_json = COALESCE(?, outcome_json), updated_at_ms = ?
             WHERE proposal_id = ?
            """,
            (state, reason, outcome_json, now, proposal_id),
        )
        TierCStore._append_tier_c_record(conn, proposal_id, state, reason, now)

    async def advance_tier_c_proposal(
        self,
        proposal_id: str,
        state: str,
        *,
        from_states: tuple[str, ...],
        reason: str = "",
        outcome_json: str | None = None,
        safe_default_action: str | None = None,
    ) -> bool:
        """Move a proposal forward; never back. False when it was elsewhere.

        A target outside the closed decision states, or `proposed` itself, is
        refused: the store is the transaction boundary the contract makes
        authoritative, and it does not take a state it cannot answer for. With
        *safe_default_action*, the proposal's one safe-default intent is created
        in the same transaction as the move, so a close that applies a safe
        default never lands without the obligation to attempt it.
        """
        if state not in _TIER_C_DECISION_STATES or state == "proposed":
            logger.error(
                "StateStore: refusing to move proposal %s to %r, which is not a "
                "decision state a proposal may be moved to",
                proposal_id,
                state,
            )
            return False
        return await self._run_write(
            self._advance_tier_c_proposal_sync,
            proposal_id,
            state,
            from_states,
            reason,
            outcome_json,
            safe_default_action,
        )

    def _advance_tier_c_proposal_sync(
        self,
        proposal_id: str,
        state: str,
        from_states: tuple[str, ...],
        reason: str,
        outcome_json: str | None,
        safe_default_action: str | None = None,
    ) -> bool:
        assert self._conn is not None
        conn = self._conn
        now = now_ms()
        try:
            conn.execute("BEGIN IMMEDIATE")
            placeholders = ",".join("?" for _ in from_states)
            cur = conn.execute(
                f"""
                UPDATE tier_c_proposals
                   SET decision_state = ?, state_reason = ?,
                       outcome_json = COALESCE(?, outcome_json), updated_at_ms = ?
                 WHERE proposal_id = ? AND decision_state IN ({placeholders})
                """,
                (state, reason, outcome_json, now, proposal_id, *from_states),
            )
            moved = int(cur.rowcount) > 0
            if moved:
                self._append_tier_c_record(conn, proposal_id, state, reason, now)
                if safe_default_action:
                    self._insert_tier_c_intent(
                        conn, proposal_id, safe_default_action, reason, now
                    )
            conn.commit()
            return moved
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

    async def get_tier_c_proposals(self, *states: str) -> list[dict]:
        """Proposals in *states*, oldest first; every proposal when none named."""
        return await self._run_read(self._get_tier_c_proposals_sync, states)

    def _get_tier_c_proposals_sync(
        self, conn: sqlite3.Connection, states: tuple[str, ...]
    ) -> list[dict]:
        query = "SELECT * FROM tier_c_proposals"
        params: tuple[str, ...] = ()
        if states:
            query += f" WHERE decision_state IN ({','.join('?' for _ in states)})"
            params = states
        cursor = conn.execute(query + " ORDER BY created_at_ms, proposal_id", params)
        names = [c[0] for c in cursor.description]
        return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]

    async def get_tier_c_proposal(self, proposal_id: str) -> dict | None:
        rows = await self._run_read(self._get_tier_c_proposal_sync, proposal_id)
        return rows[0] if rows else None

    def _get_tier_c_proposal_sync(
        self, conn: sqlite3.Connection, proposal_id: str
    ) -> list[dict]:
        cursor = conn.execute(
            "SELECT * FROM tier_c_proposals WHERE proposal_id = ?", (proposal_id,)
        )
        names = [c[0] for c in cursor.description]
        return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]

    async def get_tier_c_proposal_records(self, proposal_id: str) -> list[str]:
        """The decision states *proposal_id* passed through, in order."""
        return await self._run_read(self._get_tier_c_proposal_records_sync, proposal_id)

    def _get_tier_c_proposal_records_sync(
        self, conn: sqlite3.Connection, proposal_id: str
    ) -> list[str]:
        cursor = conn.execute(
            """
            SELECT decision_state FROM tier_c_proposal_records
             WHERE proposal_id = ? ORDER BY id
            """,
            (proposal_id,),
        )
        return [str(row[0]) for row in cursor.fetchall()]

    async def tier_c_outcome_blocked(
        self, zone_id: str, outcome: str, *, in_flight_blocks: bool = False
    ) -> bool:
        """Whether an unresolved uncertainty blocks a proposal for *outcome* on *zone_id*."""
        return await self._run_read(
            lambda conn: self._tier_c_outcome_blocked(
                conn, zone_id, outcome, None, in_flight_blocks=in_flight_blocks
            )
        )

    async def create_tier_c_safe_default_intent(
        self, proposal_id: str, action: str, *, reason: str = ""
    ) -> bool:
        """The one safe-default intent a proposal may hold. False when it exists."""
        return await self._run_write(
            self._create_tier_c_safe_default_intent_sync, proposal_id, action, reason
        )

    def _create_tier_c_safe_default_intent_sync(
        self, proposal_id: str, action: str, reason: str
    ) -> bool:
        assert self._conn is not None
        created = self._insert_tier_c_intent(
            self._conn, proposal_id, action, reason, now_ms()
        )
        self._conn.commit()
        return created

    @staticmethod
    def _insert_tier_c_intent(
        conn: sqlite3.Connection, proposal_id: str, action: str, reason: str, at_ms: int
    ) -> bool:
        """The one pending intent a proposal may hold; False when it exists."""
        if not action:
            return False
        cur = conn.execute(
            """
            INSERT INTO tier_c_safe_default_intents
                (proposal_id, action, reason, outcome, created_at_ms, updated_at_ms)
            VALUES (?, ?, ?, 'pending', ?, ?)
            ON CONFLICT(proposal_id) DO NOTHING
            """,
            (proposal_id, action, reason, at_ms, at_ms),
        )
        return int(cur.rowcount) > 0

    async def ensure_tier_c_safe_default_intent(
        self, proposal_id: str, action: str, *, reason: str = ""
    ) -> str:
        """The intent's outcome after making sure it exists.

        ``pending`` is an obligation to attempt the safe default now, whether
        the row was just created or a previous attempt never reported; any
        other outcome means the proposal's one attempt has been made.
        """
        return await self._run_write(
            self._ensure_tier_c_safe_default_intent_sync, proposal_id, action, reason
        )

    def _ensure_tier_c_safe_default_intent_sync(
        self, proposal_id: str, action: str, reason: str
    ) -> str:
        assert self._conn is not None
        conn = self._conn
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._insert_tier_c_intent(conn, proposal_id, action, reason, now_ms())
            row = conn.execute(
                "SELECT outcome FROM tier_c_safe_default_intents WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            conn.commit()
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise
        return str(row["outcome"]) if row is not None else "pending"

    async def get_pending_tier_c_safe_default_intents(self) -> list[dict]:
        """Intents never reported done, with their proposal's identity for the attempt."""
        return await self._run_read(self._get_pending_tier_c_safe_default_intents_sync)

    def _get_pending_tier_c_safe_default_intents_sync(
        self, conn: sqlite3.Connection
    ) -> list[dict]:
        cursor = conn.execute(
            """
            SELECT i.proposal_id, i.action AS safe_default_action, i.reason,
                   p.action, p.device_id, p.zone_id, p.outcome, p.event_id,
                   p.trigger_name, p.decision_state
              FROM tier_c_safe_default_intents AS i
              JOIN tier_c_proposals AS p ON p.proposal_id = i.proposal_id
             WHERE i.outcome = 'pending'
             ORDER BY i.created_at_ms, i.proposal_id
            """
        )
        names = [c[0] for c in cursor.description]
        return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]

    async def mark_tier_c_safe_default_intent(
        self, proposal_id: str, outcome: str
    ) -> None:
        await self._run_write(
            self._mark_tier_c_safe_default_intent_sync, proposal_id, outcome
        )

    def _mark_tier_c_safe_default_intent_sync(
        self, proposal_id: str, outcome: str
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            UPDATE tier_c_safe_default_intents
               SET outcome = ?, updated_at_ms = ? WHERE proposal_id = ?
            """,
            (outcome, now_ms(), proposal_id),
        )
        self._conn.commit()

    async def get_tier_c_safe_default_intents(
        self, proposal_id: str = ""
    ) -> list[dict]:
        return await self._run_read(
            self._get_tier_c_safe_default_intents_sync, proposal_id
        )

    def _get_tier_c_safe_default_intents_sync(
        self, conn: sqlite3.Connection, proposal_id: str
    ) -> list[dict]:
        if proposal_id:
            cursor = conn.execute(
                "SELECT * FROM tier_c_safe_default_intents WHERE proposal_id = ?",
                (proposal_id,),
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM tier_c_safe_default_intents ORDER BY created_at_ms"
            )
        names = [c[0] for c in cursor.description]
        return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]

    async def reconcile_tier_c(
        self,
        *,
        proposal_id: str,
        device_id: str,
        runtime_device_id: str,
        zone_id: str,
        outcome: str,
        reason: str,
        note: str | None,
        source: str,
        entry_point: str,
        principal_uid: int | None,
        principal_account: str | None,
        principal_login_uid: int | None,
    ) -> dict[str, Any]:
        """Append an observed terminal outcome to an uncertain dispatch.

        Returns ``{"ok": True, "record": {...}, "already_recorded": bool}`` or
        ``{"ok": False, "error": code}`` with the contract's codes in its order:
        ``device_mismatch``, ``unknown_proposal``, ``zone_mismatch``,
        ``already_reconciled``, ``not_uncertain``. The append is durable before
        the answer; a failure raises and records nothing.
        """
        return await self._run_write(
            self._reconcile_tier_c_sync,
            {
                "proposal_id": proposal_id,
                "device_id": device_id,
                "runtime_device_id": runtime_device_id,
                "zone_id": zone_id,
                "outcome": outcome,
                "reason": reason,
                "note": note,
                "source": source,
                "entry_point": entry_point,
                "principal_uid": principal_uid,
                "principal_account": principal_account,
                "principal_login_uid": principal_login_uid,
            },
        )

    def _reconcile_tier_c_sync(self, req: dict[str, Any]) -> dict[str, Any]:
        assert self._conn is not None
        if req.get("outcome") not in ("executed", "not-executed"):
            return {"ok": False, "error": "invalid_arguments"}
        conn = self._conn
        now = now_ms()
        state = (
            "reconciled_executed"
            if req["outcome"] == "executed"
            else "reconciled_not_executed"
        )
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM tier_c_proposals WHERE proposal_id = ?",
                (req["proposal_id"],),
            ).fetchone()
            if str(req["device_id"]) != str(req["runtime_device_id"]):
                conn.rollback()
                return {"ok": False, "error": "device_mismatch"}
            if row is None or str(row["device_id"]) != str(req["device_id"]):
                conn.rollback()
                return {"ok": False, "error": "unknown_proposal"}
            if str(row["zone_id"]) != str(req["zone_id"]):
                conn.rollback()
                return {"ok": False, "error": "zone_mismatch"}
            existing = conn.execute(
                "SELECT * FROM tier_c_reconciliations WHERE proposal_id = ?",
                (req["proposal_id"],),
            ).fetchone()
            if existing is not None:
                identical = (
                    str(existing["decision_state"]) == state
                    and str(existing["reason"]) == str(req["reason"])
                    and existing["note"] == req["note"]
                )
                if not identical:
                    conn.rollback()
                    return {"ok": False, "error": "already_reconciled"}
                same_principal = (
                    existing["principal_uid"] == req["principal_uid"]
                    and existing["principal_login_uid"] == req["principal_login_uid"]
                )
                if not same_principal:
                    conn.execute(
                        """
                        INSERT INTO tier_c_reconcile_attempts
                            (proposal_id, kind, principal_uid, principal_account,
                             principal_login_uid, recorded_at_ms)
                        VALUES (?, 'identical_repeat', ?, ?, ?, ?)
                        """,
                        (
                            req["proposal_id"],
                            req["principal_uid"],
                            req["principal_account"],
                            req["principal_login_uid"],
                            now,
                        ),
                    )
                conn.commit()
                return {
                    "ok": True,
                    "already_recorded": True,
                    "record": dict(existing),
                }
            if str(row["decision_state"]) not in (
                "dispatch_outcome_unknown",
                "dispatch_not_proven",
            ):
                conn.rollback()
                return {"ok": False, "error": "not_uncertain"}
            conn.execute(
                """
                INSERT INTO tier_c_reconciliations
                    (proposal_id, device_id, zone_id, decision_state, reason, note,
                     source, principal_uid, principal_account, principal_login_uid,
                     entry_point, recorded_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    req["proposal_id"],
                    req["device_id"],
                    req["zone_id"],
                    state,
                    req["reason"],
                    req["note"],
                    req["source"],
                    req["principal_uid"],
                    req["principal_account"],
                    req["principal_login_uid"],
                    req["entry_point"],
                    now,
                ),
            )
            self._move_tier_c(conn, req["proposal_id"], state, str(req["source"]), now)
            record = conn.execute(
                "SELECT * FROM tier_c_reconciliations WHERE proposal_id = ?",
                (req["proposal_id"],),
            ).fetchone()
            conn.commit()
            return {"ok": True, "already_recorded": False, "record": dict(record)}
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

    # ─── tier_c_decision_log ───────────────────────────────────────────────────

    async def log_tier_c_decision(self, **fields) -> None:
        """Persist a full Tier C proposal/decision record for analytics.

        This table is intentionally richer than ``action_log``.  It captures the
        sensor context, reasoning proposal, operator decision, latency, and final
        action outcome needed for future approval/rejection learning.
        """
        await self._run_write(
            self._log_tier_c_decision_sync,
            {key: _audit_bindable(value) for key, value in fields.items()},
        )

    def _log_tier_c_decision_sync(self, fields: dict) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO tier_c_decision_log
                (device_id, site_type, location, timezone, sensor_id, sensor_type,
                 reading_value, reading_unit, reading_timestamp, history_window_json,
                 skill_name, trigger_name, proposed_action, confidence,
                 reasoning_tier, reasoning_model, prompt_context_summary,
                 operator_decision, operator_response, operator_response_channel,
                 operator_response_provider_message_id, operator_response_from_number,
                 operator_response_received_at_ms, decision_latency_ms,
                 approval_timeout_seconds, safe_default_action, safe_default_used,
                 action_taken, action_executed, final_action_result_json,
                 later_outcome_json, proposal_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(fields.get("device_id", "") or ""),
                str(fields.get("site_type", "") or ""),
                str(fields.get("location", "") or ""),
                str(fields.get("timezone", "") or ""),
                str(fields.get("sensor_id", "") or ""),
                str(fields.get("sensor_type", "") or ""),
                fields.get("reading_value"),
                str(fields.get("reading_unit", "") or ""),
                fields.get("reading_timestamp"),
                json.dumps(fields.get("history_window"), sort_keys=True),
                str(fields.get("skill_name", "") or ""),
                str(fields.get("trigger_name", "") or ""),
                str(fields.get("proposed_action", "") or ""),
                float(fields.get("confidence", 0.0) or 0.0),
                str(fields.get("reasoning_tier", "") or ""),
                str(fields.get("reasoning_model", "") or ""),
                str(fields.get("prompt_context_summary", "") or ""),
                str(fields.get("operator_decision", "") or ""),
                fields.get("operator_response"),
                str(fields.get("operator_response_channel", "") or ""),
                str(fields.get("operator_response_provider_message_id", "") or ""),
                str(fields.get("operator_response_from_number", "") or ""),
                fields.get("operator_response_received_at_ms"),
                int(fields.get("decision_latency_ms", 0) or 0),
                int(fields.get("approval_timeout_seconds", 0) or 0),
                str(fields.get("safe_default_action", "") or ""),
                1 if fields.get("safe_default_used") else 0,
                str(fields.get("action_taken", "") or ""),
                1 if fields.get("action_executed") else 0,
                json.dumps(fields.get("final_action_result", {}), sort_keys=True),
                json.dumps(fields.get("later_outcome"), sort_keys=True),
                str(fields.get("proposal_id", "") or ""),
                int(fields.get("created_at") or now_ms()),
            ),
        )
        self._conn.commit()

    async def get_tier_c_decision_log(self, limit: int = 50) -> list[dict]:
        return await self._run_read(self._get_tier_c_decision_log_sync, limit)

    def _get_tier_c_decision_log_sync(
        self, conn: sqlite3.Connection, limit: int
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT *
            FROM tier_c_decision_log
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            result.append(self._decode_tier_c_decision_row(row))
        return result

    async def export_tier_c_decision_log(
        self,
        *,
        device_id: str | None = None,
        since_ms: int | None = None,
        until_ms: int | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return a bounded Tier C decision-log export for cloud sync."""
        return await self._run_read(
            self._export_tier_c_decision_log_sync,
            device_id,
            since_ms,
            until_ms,
            limit,
        )

    def _export_tier_c_decision_log_sync(
        self,
        conn: sqlite3.Connection,
        device_id: str | None,
        since_ms: int | None,
        until_ms: int | None,
        limit: int,
    ) -> list[dict]:
        where = []
        params: list[Any] = []
        if device_id:
            where.append("device_id = ?")
            params.append(str(device_id))
        if since_ms is not None:
            where.append("created_at >= ?")
            params.append(int(since_ms))
        if until_ms is not None:
            where.append("created_at <= ?")
            params.append(int(until_ms))
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        params.append(max(1, min(int(limit), 1000)))
        query = (
            """
            SELECT *
            FROM tier_c_decision_log
            """
            + where_sql
            + """
            ORDER BY created_at DESC
            LIMIT ?
            """
        )
        rows = conn.execute(query, tuple(params)).fetchall()
        return [self._decode_tier_c_decision_row(row) for row in rows]

    @staticmethod
    def _decode_tier_c_decision_row(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["history_window"] = json.loads(item.pop("history_window_json"))
        item["safe_default_used"] = bool(item["safe_default_used"])
        item["action_executed"] = bool(item["action_executed"])
        item["final_action_result"] = json.loads(item.pop("final_action_result_json"))
        item["later_outcome"] = json.loads(item.pop("later_outcome_json"))
        return item
