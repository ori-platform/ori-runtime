# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Commissioned and provisional bindings, and proof observations."""

import json
import sqlite3
from typing import Any

from ori.state._core import StoreCore
from ori.utils.time_utils import now_ms


class CommissioningStore(StoreCore):
    """Commissioned and provisional bindings, and proof observations."""

    # ─── device_policy_cache ─────────────────────────────────────────────────

    async def retain_commissioned_binding(
        self,
        *,
        binding_seq: int,
        canonical_hash: str,
        device_id: str,
        inventory_generation: int,
        signer_id: str,
        supersedes: str | None,
        canonical_json: str,
        signature: str,
        zones_json: str,
        accepted_at_ms: int | None = None,
    ) -> None:
        """Retain an accepted binding and retire the one it supersedes."""
        await self._run_write(
            self._retain_commissioned_binding_sync,
            binding_seq,
            canonical_hash,
            device_id,
            inventory_generation,
            signer_id,
            supersedes,
            canonical_json,
            signature,
            zones_json,
            accepted_at_ms if accepted_at_ms is not None else now_ms(),
        )

    def _retain_commissioned_binding_sync(
        self,
        binding_seq: int,
        canonical_hash: str,
        device_id: str,
        inventory_generation: int,
        signer_id: str,
        supersedes: str | None,
        canonical_json: str,
        signature: str,
        zones_json: str,
        accepted_at_ms: int,
    ) -> None:
        from ori.security.commissioning.binding import zone_row_in_force_eligible

        assert self._conn is not None
        try:
            zones = json.loads(zones_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"zones_json is not a JSON document: {exc}") from exc
        if (
            not isinstance(zones, list)
            or not zones
            or not all(zone_row_in_force_eligible(z) for z in zones)
        ):
            raise ValueError(
                "a binding with an unproven proof leg is provisional and cannot "
                "be retained as the binding in force"
            )
        self._conn.execute(
            """
            UPDATE commissioned_binding SET retired_at_ms = ?
             WHERE retired_at_ms IS NULL
            """,
            (int(accepted_at_ms),),
        )
        self._conn.execute(
            """
            INSERT INTO commissioned_binding
                (binding_seq, canonical_hash, device_id, inventory_generation,
                 signer_id, supersedes, canonical_json, signature, zones_json,
                 accepted_at_ms, retired_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                int(binding_seq),
                canonical_hash,
                device_id,
                int(inventory_generation),
                signer_id,
                supersedes,
                canonical_json,
                signature,
                zones_json,
                int(accepted_at_ms),
            ),
        )
        self._conn.commit()

    async def record_evidence_commissioning_reference(
        self,
        *,
        device_id: str,
        anchor_epoch_id: str,
        commissioning_reference: str,
        force: bool,
        recorded_at_ms: int,
    ) -> dict[str, Any]:
        """Record the reference for one epoch, durably before the answer.

        Returns ``{"ok": True, "replaced": bool}`` or ``{"ok": False, "error":
        code}`` with `reference_device_mismatch` or `reference_already_recorded`.
        The read, the decision and the write are one `BEGIN IMMEDIATE`
        transaction; a failure raises and records nothing.
        """
        return await self._run_write(
            self._record_evidence_commissioning_reference_sync,
            str(device_id),
            str(anchor_epoch_id),
            str(commissioning_reference),
            bool(force),
            int(recorded_at_ms),
        )

    def _record_evidence_commissioning_reference_sync(
        self,
        device_id: str,
        anchor_epoch_id: str,
        commissioning_reference: str,
        force: bool,
        recorded_at_ms: int,
    ) -> dict[str, Any]:
        conn = self._conn
        if conn is None:
            raise sqlite3.ProgrammingError("the state store is not open")
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT device_id, commissioning_reference
                  FROM evidence_commissioning_reference
                 WHERE anchor_epoch_id = ?
                """,
                (anchor_epoch_id,),
            ).fetchone()
            replaced = False
            if row is None:
                conn.execute(
                    """
                    INSERT INTO evidence_commissioning_reference (
                        anchor_epoch_id, device_id, commissioning_reference,
                        recorded_at_ms
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        anchor_epoch_id,
                        device_id,
                        commissioning_reference,
                        recorded_at_ms,
                    ),
                )
            elif str(row[0]) != device_id:
                conn.rollback()
                return {"ok": False, "error": "reference_device_mismatch"}
            elif str(row[1]) == commissioning_reference:
                pass
            elif not force:
                conn.rollback()
                return {"ok": False, "error": "reference_already_recorded"}
            else:
                conn.execute(
                    """
                    UPDATE evidence_commissioning_reference
                       SET commissioning_reference = ?, recorded_at_ms = ?,
                           replacements = replacements + 1
                     WHERE anchor_epoch_id = ?
                    """,
                    (commissioning_reference, recorded_at_ms, anchor_epoch_id),
                )
                replaced = True
            conn.commit()
            return {"ok": True, "replaced": replaced}
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

    async def get_evidence_commissioning_reference(
        self, *, device_id: str, anchor_epoch_id: str
    ) -> str | None:
        """The reference recorded for this device's *anchor_epoch_id*, or None."""
        return await self._run_read(
            self._get_evidence_commissioning_reference_sync,
            str(device_id),
            str(anchor_epoch_id),
        )

    def _get_evidence_commissioning_reference_sync(
        self, conn: sqlite3.Connection, device_id: str, anchor_epoch_id: str
    ) -> str | None:
        row = conn.execute(
            """
            SELECT commissioning_reference FROM evidence_commissioning_reference
             WHERE anchor_epoch_id = ? AND device_id = ?
            """,
            (anchor_epoch_id, device_id),
        ).fetchone()
        return None if row is None else str(row[0])

    async def get_commissioned_binding_in_force(self) -> dict | None:
        return await self._run_read(self._get_commissioned_binding_in_force_sync)

    def _get_commissioned_binding_in_force_sync(
        self, conn: sqlite3.Connection
    ) -> dict | None:
        row = conn.execute(
            """
            SELECT binding_seq, canonical_hash, device_id, inventory_generation,
                   signer_id, supersedes, canonical_json, signature, zones_json,
                   accepted_at_ms
              FROM commissioned_binding
             WHERE retired_at_ms IS NULL
             ORDER BY binding_seq DESC
             LIMIT 1
            """
        ).fetchone()
        if row is None:
            return None
        keys = (
            "binding_seq",
            "canonical_hash",
            "device_id",
            "inventory_generation",
            "signer_id",
            "supersedes",
            "canonical_json",
            "signature",
            "zones_json",
            "accepted_at_ms",
        )
        return dict(zip(keys, row, strict=True))

    async def retain_provisional_binding(
        self,
        *,
        binding_seq: int,
        canonical_hash: str,
        device_id: str,
        inventory_generation: int,
        signer_id: str,
        supersedes: str | None,
        canonical_json: str,
        signature: str,
        zones_json: str,
        verified_at_ms: int | None = None,
    ) -> None:
        """Retain the current provisional binding, replacing any earlier one."""
        await self._run_write(
            self._retain_provisional_binding_sync,
            binding_seq,
            canonical_hash,
            device_id,
            inventory_generation,
            signer_id,
            supersedes,
            canonical_json,
            signature,
            zones_json,
            verified_at_ms if verified_at_ms is not None else now_ms(),
        )

    def _retain_provisional_binding_sync(
        self,
        binding_seq: int,
        canonical_hash: str,
        device_id: str,
        inventory_generation: int,
        signer_id: str,
        supersedes: str | None,
        canonical_json: str,
        signature: str,
        zones_json: str,
        verified_at_ms: int,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT OR REPLACE INTO commissioned_binding_provisional
                (id, binding_seq, canonical_hash, device_id, inventory_generation,
                 signer_id, supersedes, canonical_json, signature, zones_json,
                 verified_at_ms)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(binding_seq),
                canonical_hash,
                device_id,
                int(inventory_generation),
                signer_id,
                supersedes,
                canonical_json,
                signature,
                zones_json,
                int(verified_at_ms),
            ),
        )
        self._conn.commit()

    async def get_provisional_binding(self) -> dict | None:
        return await self._run_read(self._get_provisional_binding_sync)

    def _get_provisional_binding_sync(self, conn: sqlite3.Connection) -> dict | None:
        row = conn.execute(
            """
            SELECT binding_seq, canonical_hash, device_id, inventory_generation,
                   signer_id, supersedes, canonical_json, signature, zones_json,
                   verified_at_ms
              FROM commissioned_binding_provisional
             WHERE id = 1
            """
        ).fetchone()
        if row is None:
            return None
        keys = (
            "binding_seq",
            "canonical_hash",
            "device_id",
            "inventory_generation",
            "signer_id",
            "supersedes",
            "canonical_json",
            "signature",
            "zones_json",
            "verified_at_ms",
        )
        return dict(zip(keys, row, strict=True))

    async def clear_provisional_binding(self) -> None:
        """Drop the provisional record; a binding that came into force replaces it."""
        await self._run_write(self._clear_provisional_binding_sync)

    def _clear_provisional_binding_sync(self) -> None:
        assert self._conn is not None
        self._conn.execute("DELETE FROM commissioned_binding_provisional")
        self._conn.commit()

    async def retire_commissioned_binding_in_force(self) -> None:
        """Retire whatever is in force, keeping it for audit."""
        await self._run_write(self._retire_commissioned_binding_in_force_sync)

    def _retire_commissioned_binding_in_force_sync(self) -> None:
        assert self._conn is not None
        self._conn.execute(
            "UPDATE commissioned_binding SET retired_at_ms = ? "
            "WHERE retired_at_ms IS NULL",
            (now_ms(),),
        )
        self._conn.commit()

    async def record_commissioning_proof_observation(
        self,
        *,
        binding_hash: str,
        zone_id: str,
        gpio_pin: int,
        active_high: bool,
        outcome: str,
        coil_state_commanded: str,
        level_driven: str,
        consent_nonce: str,
        consented_at_ms: int,
        commanded_at_ms: int,
        command_issued: bool,
        held_ms: int,
        observation_json: str | None,
        outcome_note: str | None,
    ) -> int:
        """Append the consent and the intent, returning the row to complete.

        Written before the coil moves: a record made afterwards can fail after
        the actuation, leaving a commanded coil with nothing recording it.
        """
        return await self._run_write(
            self._record_commissioning_proof_observation_sync,
            binding_hash,
            zone_id,
            gpio_pin,
            active_high,
            outcome,
            coil_state_commanded,
            level_driven,
            consent_nonce,
            consented_at_ms,
            commanded_at_ms,
            command_issued,
            held_ms,
            observation_json,
            outcome_note,
        )

    def _record_commissioning_proof_observation_sync(
        self,
        binding_hash: str,
        zone_id: str,
        gpio_pin: int,
        active_high: bool,
        outcome: str,
        coil_state_commanded: str,
        level_driven: str,
        consent_nonce: str,
        consented_at_ms: int,
        commanded_at_ms: int,
        command_issued: bool,
        held_ms: int,
        observation_json: str | None,
        outcome_note: str | None,
    ) -> int:
        assert self._conn is not None
        cursor = self._conn.execute(
            """
            INSERT INTO commissioning_proof_observation
                (binding_hash, zone_id, gpio_pin, active_high, outcome,
                 coil_state_commanded, level_driven, consent_nonce,
                 consented_at_ms, commanded_at_ms, command_issued,
                 effect_verified, operator_attestation, release_requested,
                 held_ms, observation_json, outcome_note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, 0, ?, ?, ?)
            """,
            (
                binding_hash,
                zone_id,
                int(gpio_pin),
                1 if active_high else 0,
                outcome,
                coil_state_commanded,
                level_driven,
                consent_nonce,
                int(consented_at_ms),
                int(commanded_at_ms),
                1 if command_issued else 0,
                int(held_ms),
                observation_json,
                outcome_note,
            ),
        )
        self._conn.commit()
        return int(cursor.lastrowid or 0)

    async def complete_commissioning_proof_observation(
        self,
        *,
        row_id: int,
        commanded_at_ms: int,
        command_issued: bool,
        operator_attestation: str | None,
        release_requested: bool,
        held_ms: int,
        observation_json: str | None,
        outcome_note: str | None,
    ) -> None:
        """Complete the row the consent opened, once the command has been issued.

        `effect_verified` is never set here and has no parameter. The runtime
        does not observe the coil, so nothing it records may assert that the
        commanded effect occurred.
        """
        await self._run_write(
            self._complete_commissioning_proof_observation_sync,
            row_id,
            commanded_at_ms,
            command_issued,
            operator_attestation,
            release_requested,
            held_ms,
            observation_json,
            outcome_note,
        )

    def _complete_commissioning_proof_observation_sync(
        self,
        row_id: int,
        commanded_at_ms: int,
        command_issued: bool,
        operator_attestation: str | None,
        release_requested: bool,
        held_ms: int,
        observation_json: str | None,
        outcome_note: str | None,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            UPDATE commissioning_proof_observation
               SET commanded_at_ms = ?, command_issued = ?,
                   operator_attestation = ?, release_requested = ?,
                   held_ms = ?, observation_json = ?, outcome_note = ?
             WHERE id = ?
            """,
            (
                int(commanded_at_ms),
                1 if command_issued else 0,
                operator_attestation,
                1 if release_requested else 0,
                int(held_ms),
                observation_json,
                outcome_note,
                int(row_id),
            ),
        )
        self._conn.commit()

    async def commissioning_proof_observations(self, binding_hash: str) -> list[dict]:
        """Every recorded command for one provisional binding, oldest first."""
        return await self._run_read(
            self._commissioning_proof_observations_sync, binding_hash
        )

    def _commissioning_proof_observations_sync(
        self, conn: sqlite3.Connection, binding_hash: str
    ) -> list[dict]:
        keys = (
            "binding_hash",
            "zone_id",
            "gpio_pin",
            "active_high",
            "outcome",
            "coil_state_commanded",
            "level_driven",
            "consent_nonce",
            "consented_at_ms",
            "commanded_at_ms",
            "command_issued",
            "effect_verified",
            "operator_attestation",
            "release_requested",
            "held_ms",
            "observation_json",
            "outcome_note",
        )
        rows = conn.execute(
            f"SELECT {', '.join(keys)} FROM commissioning_proof_observation "
            "WHERE binding_hash = ? ORDER BY id ASC",
            (binding_hash,),
        ).fetchall()
        return [dict(zip(keys, r, strict=True)) for r in rows]

    async def commissioned_binding_history(self) -> list[dict]:
        return await self._run_read(self._commissioned_binding_history_sync)

    def _commissioned_binding_history_sync(
        self, conn: sqlite3.Connection
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT binding_seq, canonical_hash, accepted_at_ms, retired_at_ms
              FROM commissioned_binding
             ORDER BY binding_seq ASC
            """
        ).fetchall()
        return [
            {
                "binding_seq": int(r[0]),
                "canonical_hash": r[1],
                "accepted_at_ms": int(r[2]),
                "retired_at_ms": r[3],
            }
            for r in rows
        ]
