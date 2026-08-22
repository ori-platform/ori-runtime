# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The runtime's own evidence chain, per `ori-specs/evidence/v2`.

The runtime produces hash-chained, device-signed rows locally. It does not
implement an authoritative store: cross-device ordering, receipt issuance, gap
analysis and insurer-facing retention belong to the off-device authority, and
reimplementing them here would put the record inside the site whose conduct it
constrains.

What the device can prove is chain integrity, not chain completeness. A
device-local attacker can destroy or roll back this file. Completeness rests on
delivery and checkpointing, not on this table.

Naming follows the contract's rule for operator-reachable components: tables
describe what they hold. A schema created on the device is as visible as a log
line — a `.tables` listing, a schema dump, or a trigger named in an integrity
error all reach whoever holds the device.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from ori.security.evidence_canonical import canonical_json
from ori.security.evidence_device_key import EvidenceDeviceKey

SCHEMA_VERSION = "ori.evidence.v2"
GENESIS_PREIMAGE = b"ori.evidence.genesis.v2"
GENESIS_PREV_EVENT_HASH = hashlib.sha256(GENESIS_PREIMAGE).hexdigest()

EVENT_ID_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://oriplatform.dev/specs/evidence/v2/event-id"
)

EVENT_TYPES = frozenset(
    {
        "UPTIME_HEARTBEAT",
        "OUTAGE_STARTED",
        "OUTAGE_RESOLVED",
        "DISPLACEMENT_RECORD",
        "MAINTENANCE_PERFORMED",
        "REVENUE_COLLECTED",
        "UTILISATION_RECORD",
        "KEY_ROTATION",
        "SAFETY_ACTION_EXECUTED",
    }
)

# Only `exported` and `exported_at_ms` may change after a row is written. The
# triggers below enforce that in the database rather than by convention: an
# invariant that holds only because application code remembers to honour it is
# not an invariant, and this one is what makes a row's history meaningful.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_chain (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT    NOT NULL UNIQUE,
    event_type      TEXT    NOT NULL,
    device_id       TEXT    NOT NULL,
    emitted_at_ms   INTEGER NOT NULL,
    payload_json    TEXT    NOT NULL,
    canonical_json  TEXT    NOT NULL,
    event_hash      TEXT    NOT NULL,
    prev_event_hash TEXT    NOT NULL,
    signature       TEXT    NOT NULL,
    exported        INTEGER NOT NULL DEFAULT 0,
    exported_at_ms  INTEGER,
    created_at_ms   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_chain_exported
    ON evidence_chain (exported, seq);
CREATE INDEX IF NOT EXISTS idx_evidence_chain_device
    ON evidence_chain (device_id, seq);

CREATE TRIGGER IF NOT EXISTS evidence_chain_no_delete
BEFORE DELETE ON evidence_chain
BEGIN
    SELECT RAISE(ABORT, 'evidence chain rows are immutable');
END;

CREATE TRIGGER IF NOT EXISTS evidence_chain_no_signed_update
BEFORE UPDATE ON evidence_chain
WHEN OLD.seq             IS NOT NEW.seq
  OR OLD.event_id        IS NOT NEW.event_id
  OR OLD.event_type      IS NOT NEW.event_type
  OR OLD.device_id       IS NOT NEW.device_id
  OR OLD.emitted_at_ms   IS NOT NEW.emitted_at_ms
  OR OLD.payload_json    IS NOT NEW.payload_json
  OR OLD.canonical_json  IS NOT NEW.canonical_json
  OR OLD.event_hash      IS NOT NEW.event_hash
  OR OLD.prev_event_hash IS NOT NEW.prev_event_hash
  OR OLD.signature       IS NOT NEW.signature
  OR OLD.created_at_ms   IS NOT NEW.created_at_ms
BEGIN
    SELECT RAISE(ABORT, 'signed evidence columns are immutable');
END;
"""

# The eight fields evidence/v2 defines. A row carrying more or fewer is
# reported rather than tolerated: an unknown field would be covered by the
# signature while meaning nothing to a verifier.
ENVELOPE_FIELDS = frozenset(
    {
        "device_id",
        "emitted_at_ms",
        "event_id",
        "event_type",
        "payload",
        "prev_event_hash",
        "schema_version",
        "sequence_num",
    }
)

SIGNED_COLUMNS = (
    "seq",
    "event_id",
    "event_type",
    "device_id",
    "emitted_at_ms",
    "payload_json",
    "canonical_json",
    "event_hash",
    "prev_event_hash",
    "signature",
    "created_at_ms",
)


class EvidenceChainError(RuntimeError):
    """The chain could not be opened, appended to, or trusted."""


def attestation_event_id(device_id: str, action_log_id: int) -> str:
    """Deterministic idempotency key for one action_log row.

    A retry after a crash reproduces this identity, so an append that
    succeeded but whose status update was lost cannot double-attest.
    """
    return str(
        uuid.uuid5(EVENT_ID_NAMESPACE, f"{device_id}:action_log:{int(action_log_id)}")
    )


class EvidenceChain:
    """Append-only, hash-chained, device-signed rows."""

    def __init__(
        self, db_path: str | Path, device_key: EvidenceDeviceKey, device_id: str
    ) -> None:
        if not device_id:
            raise EvidenceChainError("a chain must be bound to a device identity")
        self._db_path = str(db_path)
        self._key = device_key
        self._device_id = str(device_id)
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self._db_path, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        # Set before any other pragma. Switching to WAL takes a brief exclusive
        # lock of its own, so a busy timeout applied afterwards is applied too
        # late to protect the statement that most needs it — several processes
        # opening the same database at once is exactly when that happens.
        #
        # SQLite's default is zero: a concurrent writer gets "database is
        # locked" immediately rather than waiting. Every write here is short and
        # bounded, so waiting is the right answer; failing turns ordinary
        # contention into a spurious evidence failure, and evidence that fails
        # because two things happened at once is worse than useless.
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA journal_mode=WAL")
        # Durability matters more than throughput here: a row acknowledged as
        # signed and then lost to a power cut is worse than a slower append,
        # because the action it attests already happened.
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.executescript(_SCHEMA)
        self._assert_single_device()

    def _assert_single_device(self) -> None:
        """One key, one device, one chain.

        A key that can sign rows for several device identities makes
        same-device attribution something the producer hopes callers preserve
        rather than something it enforces, and a verifier resolving a row's
        signature "to a key registered for that same device identity" would be
        checking a property the producer never guaranteed. Reopening a chain
        under a different identity is refused for the same reason.
        """
        rows = self._connection.execute(
            "SELECT DISTINCT device_id FROM evidence_chain"
        ).fetchall()
        foreign = sorted({str(row["device_id"]) for row in rows} - {self._device_id})
        if foreign:
            raise EvidenceChainError(
                f"this chain holds rows for {len(foreign)} other device "
                f"identities; it is bound to {self._device_id!r}"
            )

    @property
    def device_id(self) -> str:
        return self._device_id

    @property
    def public_key_hex(self) -> str:
        return self._key.public_key_hex

    def close(self) -> None:
        self._connection.close()

    def head(self) -> tuple[int, str]:
        """The current (seq, event_hash). Genesis when the chain is empty."""
        row = self._connection.execute(
            "SELECT seq, event_hash FROM evidence_chain ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return 0, GENESIS_PREV_EVENT_HASH
        return int(row["seq"]), str(row["event_hash"])

    def find_by_event_id(self, event_id: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._connection.execute(
            "SELECT * FROM evidence_chain WHERE event_id = ?", (event_id,)
        ).fetchone()
        return row

    @staticmethod
    def _reconcile_replay(
        existing: sqlite3.Row, intent: tuple[str, str, int, bytes]
    ) -> sqlite3.Row:
        """Return the existing row only when the replay means the same thing.

        Idempotency is "same identity, same intended content". Returning the
        stored row for a request that differs would report success for
        evidence that was never recorded — the caller believes its event is
        attested, and something else is. A deterministic identity colliding
        with different content is a defect upstream, and it has to surface.
        """
        event_type, device_id, emitted_at_ms, payload_bytes = intent
        stored = (
            str(existing["event_type"]),
            str(existing["device_id"]),
            int(existing["emitted_at_ms"]),
            str(existing["payload_json"]).encode("utf-8"),
        )
        if stored == (event_type, device_id, emitted_at_ms, payload_bytes):
            return existing
        differing = [
            name
            for name, was, now in zip(
                ("event_type", "device_id", "emitted_at_ms", "payload"),
                stored,
                intent,
                strict=True,
            )
            if was != now
        ]
        raise EvidenceChainError(
            f"event_id {existing['event_id']} is already attested with different "
            f"content ({', '.join(differing)}); the same identity must mean the "
            "same event"
        )

    def append(
        self,
        *,
        event_id: str,
        event_type: str,
        emitted_at_ms: int,
        payload: dict[str, Any],
        created_at_ms: int,
    ) -> sqlite3.Row:
        """Sign and append one event. Idempotent on ``event_id``.

        The whole append is one transaction: the sequence is read, the row is
        signed against that head, and the row is written, with nothing able to
        interleave. Reading the head outside the transaction would let two
        concurrent appends sign against the same predecessor and produce a
        forked chain that verifies row by row and is wrong as a whole.
        """
        if not event_id:
            raise EvidenceChainError("event_id must be a non-empty idempotency key")
        if event_type not in EVENT_TYPES:
            raise EvidenceChainError(f"{event_type!r} is not an evidence event type")

        device_id = self._device_id
        payload_bytes = canonical_json(payload)
        intent = (event_type, device_id, int(emitted_at_ms), payload_bytes)

        existing = self.find_by_event_id(event_id)
        if existing is not None:
            return self._reconcile_replay(existing, intent)

        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise EvidenceChainError("could not begin an evidence append") from exc
        try:
            # Re-check inside the transaction: another writer may have appended
            # this same event between the lookup above and the lock.
            existing = self.find_by_event_id(event_id)
            if existing is not None:
                self._connection.execute("ROLLBACK")
                return self._reconcile_replay(existing, intent)

            previous_seq, previous_hash = self.head()
            sequence_num = previous_seq + 1
            envelope = {
                "device_id": device_id,
                "emitted_at_ms": int(emitted_at_ms),
                "event_id": event_id,
                "event_type": event_type,
                "payload": payload,
                "prev_event_hash": previous_hash,
                "schema_version": SCHEMA_VERSION,
                "sequence_num": sequence_num,
            }
            signed_bytes = canonical_json(envelope)
            event_hash = hashlib.sha256(signed_bytes).hexdigest()
            signature = "ed25519:" + _b64(self._key.sign(signed_bytes))

            self._connection.execute(
                """
                INSERT INTO evidence_chain (
                    seq, event_id, event_type, device_id, emitted_at_ms,
                    payload_json, canonical_json, event_hash, prev_event_hash,
                    signature, exported, exported_at_ms, created_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)
                """,
                (
                    sequence_num,
                    event_id,
                    event_type,
                    device_id,
                    int(emitted_at_ms),
                    payload_bytes.decode("utf-8"),
                    signed_bytes.decode("utf-8"),
                    event_hash,
                    previous_hash,
                    signature,
                    int(created_at_ms),
                ),
            )
            self._connection.execute("COMMIT")
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        row = self.find_by_event_id(event_id)
        if row is None:  # pragma: no cover - the insert committed
            raise EvidenceChainError("the appended row could not be read back")
        return row

    def mark_exported(self, seq: int, exported_at_ms: int) -> None:
        """The only mutation the schema permits."""
        self._connection.execute(
            "UPDATE evidence_chain SET exported = 1, exported_at_ms = ? WHERE seq = ?",
            (int(exported_at_ms), int(seq)),
        )

    def verify_chain(self) -> list[str]:
        """Walk the chain and report every row that fails a contract rule.

        Reports rather than raises, and names the rule rather than saying a row
        is bad: a caller needs to know whether the chain was tampered with, was
        written by another key, or simply has a hash it cannot reproduce.
        """
        problems: list[str] = []
        expected_seq = 1
        expected_prev = GENESIS_PREV_EVENT_HASH
        for row in self._connection.execute(
            "SELECT * FROM evidence_chain ORDER BY seq"
        ):
            seq = int(row["seq"])
            signed_bytes = str(row["canonical_json"]).encode("utf-8")
            if seq != expected_seq:
                problems.append(f"seq {seq}: not the expected successor {expected_seq}")
            if str(row["prev_event_hash"]) != expected_prev:
                problems.append(f"seq {seq}: prev_event_hash does not chain")
            if hashlib.sha256(signed_bytes).hexdigest() != str(row["event_hash"]):
                problems.append(f"seq {seq}: event_hash disagrees with canonical_json")
            try:
                self._key.verify(_unb64(str(row["signature"])), signed_bytes)
            except Exception:
                problems.append(
                    f"seq {seq}: signature does not verify under the device key"
                )
            try:
                envelope = json.loads(signed_bytes)
            except ValueError:
                # A row whose stored bytes will not parse cannot be evaluated
                # against the remaining rules, and raising would abandon the
                # walk — leaving every later row unexamined because one is
                # corrupt. Report it and carry on.
                problems.append(f"seq {seq}: canonical_json is not parseable JSON")
                expected_seq = seq + 1
                expected_prev = str(row["event_hash"])
                continue
            if not isinstance(envelope, dict):
                problems.append(f"seq {seq}: canonical_json is not a JSON object")
                expected_seq = seq + 1
                expected_prev = str(row["event_hash"])
                continue
            undefined = sorted(set(envelope) - ENVELOPE_FIELDS)
            absent = sorted(ENVELOPE_FIELDS - set(envelope))
            if undefined:
                problems.append(
                    f"seq {seq}: envelope carries undefined fields {undefined}"
                )
            if absent:
                problems.append(f"seq {seq}: envelope is missing fields {absent}")
            if envelope.get("schema_version") != SCHEMA_VERSION:
                problems.append(f"seq {seq}: schema_version is not {SCHEMA_VERSION}")
            for field, column in (
                ("sequence_num", "seq"),
                ("prev_event_hash", "prev_event_hash"),
                ("event_id", "event_id"),
                ("event_type", "event_type"),
                ("device_id", "device_id"),
                ("emitted_at_ms", "emitted_at_ms"),
            ):
                if envelope.get(field) != row[column]:
                    problems.append(
                        f"seq {seq}: column {column} disagrees with the envelope"
                    )
            try:
                stored_payload = json.loads(str(row["payload_json"]))
            except ValueError:
                problems.append(f"seq {seq}: payload_json is not parseable JSON")
            else:
                if stored_payload != envelope.get("payload"):
                    problems.append(
                        f"seq {seq}: payload_json disagrees with the envelope payload"
                    )
            expected_seq = seq + 1
            expected_prev = str(row["event_hash"])
        return problems


def _b64(raw: bytes) -> str:
    import base64

    return base64.b64encode(raw).decode("ascii")


def _unb64(wire: str) -> bytes:
    import base64

    return base64.b64decode(wire.split("ed25519:", 1)[-1])
