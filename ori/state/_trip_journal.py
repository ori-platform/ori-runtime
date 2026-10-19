# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The safety registry's durable trip-intent journal."""

import sqlite3
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ori.state.store import StateStore


TRIP_JOURNAL_COLUMNS = (
    "seq, entry_kind, attempt_id, binding_seq, outcome, command_status, "
    "resolved, created_at_ms"
)


class TripJournal:
    """The durable trip-intent journal for the safety registry.

    One append-ordered journal per zone-profile pair, in the shape the trip
    machine loads. The write ordering is the contract's: the intent append
    precedes the command, the full record commits in its own transaction,
    and only after that commit does the resolution mark touch the intents —
    and only those appended before the latest record or clear, so this store
    is structurally unable to write the unwitnessed resolution the journal
    grammar refuses.
    """

    def __init__(self, store: "StateStore") -> None:
        self._store = store

    async def append_intent(
        self,
        zone_id: str,
        profile_id: str,
        *,
        attempt_id: str,
        binding_seq: int,
        outcome: str,
        created_at_ms: int,
    ) -> None:
        def write() -> None:
            conn = self._store._conn
            assert conn is not None
            conn.execute(
                "INSERT INTO safety_trip_journal "
                "(zone_id, profile_id, entry_kind, attempt_id, binding_seq, "
                " outcome, created_at_ms) "
                "VALUES (?, ?, 'intent', ?, ?, ?, ?)",
                (zone_id, profile_id, attempt_id, binding_seq, outcome, created_at_ms),
            )
            conn.commit()

        await self._store._run_write(write)

    async def append_record(
        self,
        zone_id: str,
        profile_id: str,
        *,
        command_status: str,
        created_at_ms: int,
    ) -> None:
        if command_status not in (
            "command_pending",
            "driver_refused",
            "command_issued",
        ):
            raise ValueError(
                f"journal record command status {command_status!r} is outside "
                "the vocabulary; legacy treatment is the pre-journal source's"
            )

        def write() -> None:
            conn = self._store._conn
            assert conn is not None
            conn.execute(
                "INSERT INTO safety_trip_journal "
                "(zone_id, profile_id, entry_kind, command_status, created_at_ms) "
                "VALUES (?, ?, 'record', ?, ?)",
                (zone_id, profile_id, command_status, created_at_ms),
            )
            conn.commit()

        await self._store._run_write(write)

    async def append_clear(
        self, zone_id: str, profile_id: str, *, created_at_ms: int
    ) -> None:
        def write() -> None:
            conn = self._store._conn
            assert conn is not None
            conn.execute(
                "INSERT INTO safety_trip_journal "
                "(zone_id, profile_id, entry_kind, created_at_ms) "
                "VALUES (?, ?, 'clear', ?)",
                (zone_id, profile_id, created_at_ms),
            )
            conn.commit()

        await self._store._run_write(write)

    async def mark_resolved(self, zone_id: str, profile_id: str) -> None:
        """Resolve the intents a committed record or clear justifies.

        Only intents appended before the pair's latest record or clear are
        touched; with no such entry the call resolves nothing, because a
        resolution nothing durable performed must be unwritable here.
        """

        def write() -> None:
            conn = self._store._conn
            assert conn is not None
            row = conn.execute(
                "SELECT MAX(seq) FROM safety_trip_journal "
                "WHERE zone_id = ? AND profile_id = ? "
                "AND entry_kind IN ('record', 'clear')",
                (zone_id, profile_id),
            ).fetchone()
            threshold = row[0]
            if threshold is None:
                return
            conn.execute(
                "UPDATE safety_trip_journal SET resolved = 1 "
                "WHERE zone_id = ? AND profile_id = ? AND entry_kind = 'intent' "
                "AND resolved = 0 AND seq < ?",
                (zone_id, profile_id, threshold),
            )
            conn.commit()

        await self._store._run_write(write)

    async def load(
        self, zone_id: str, profile_id: str
    ) -> tuple[str | None, list[dict]]:
        """The pair's journal in machine shape, with its derived durable
        state: tripped exactly when a record survives the last clear. The
        derivation is deliberately checked by the machine itself, which
        refuses a mismatch in either direction."""

        def read(conn: sqlite3.Connection):
            return conn.execute(
                f"SELECT {TRIP_JOURNAL_COLUMNS} FROM safety_trip_journal "
                "WHERE zone_id = ? AND profile_id = ? ORDER BY seq",
                (zone_id, profile_id),
            ).fetchall()

        rows = await self._store._run_read(read)
        journal: list[dict] = []
        record_survives = False
        for (
            _seq,
            entry_kind,
            attempt_id,
            binding_seq,
            outcome,
            command_status,
            resolved,
            created_at_ms,
        ) in rows:
            if entry_kind == "intent":
                journal.append(
                    {
                        "intent": {
                            "zone_id": zone_id,
                            "profile_id": profile_id,
                            "attempt_id": attempt_id,
                            "binding_seq": binding_seq,
                            "outcome": outcome,
                            "created_at_ms": created_at_ms,
                            "resolved": bool(resolved),
                        }
                    }
                )
            elif entry_kind == "record":
                journal.append({"record": {"command_status": command_status}})
                record_survives = True
            elif entry_kind == "clear":
                journal.append({"clear": True})
                record_survives = False
            else:
                journal.append({"corrupt": "unidentifiable"})
        return ("tripped" if record_survives else None), journal

    async def pairs(self) -> list[tuple[str, str]]:
        def read(conn: sqlite3.Connection):
            return conn.execute(
                "SELECT DISTINCT zone_id, profile_id FROM safety_trip_journal "
                "ORDER BY zone_id, profile_id"
            ).fetchall()

        return [(z, p) for z, p in await self._store._run_read(read)]
