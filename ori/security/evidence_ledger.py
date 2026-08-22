# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The runtime's delivery ledger, per `ori-specs/evidence-exchange/v1`.

A chain row is evidence. Getting it to the off-device authority is a separate
problem with separate failure modes, and this is where that problem lives: what
was sealed, in what order, what the gateway says it holds, what the authority
says it accepted, and what failed locally.

The runtime does not implement an authoritative store. Cross-device ordering,
receipt issuance and gap analysis belong to the authority. What the device owns
is its own outbound sequence and an honest record of what it could not do.

Two distinctions carry most of the weight here.

**Custody is not delivery.** A gateway acknowledging custody has said it holds
the bytes durably. Only a receipt signed by the authority says the evidence
arrived. They are separate columns because conflating them would let a stalled
gateway look like successful delivery — and the gateway is the party whose
stalling the evidence exists to detect.

**A gap is something this device observed.** The runtime can record that it
failed to seal or failed to send. It cannot record that something was deleted
in transit, because it cannot see that, and a row implying otherwise would be
fabricating evidence of tampering. Completeness rests on the authority
comparing what it received against the checkpoints this device signs.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from ori.security.evidence_canonical import canonical_json
from ori.security.evidence_device_key import EvidenceDeviceKey

ENVELOPE_VERSION = 1
ENVELOPE_DOMAIN = b"ori.evidence_delivery_envelope.v1\x00"
CHECKPOINT_VERSION = 1
CHECKPOINT_DOMAIN = b"ori.evidence_checkpoint.v1\x00"
DEFAULT_CHECKPOINT_INTERVAL_S = 900.0

# Delivery state is two independent facts, not one progression. A row can hold
# custody without a receipt, and — after a gateway restart replays it — a
# receipt without recorded custody.
CUSTODY_NONE = "none"
CUSTODY_HELD = "held"
RECEIPT_NONE = "none"
RECEIPT_ACCEPTED = "accepted"

# What this device can honestly say went wrong. Both are failures it performed
# and observed; neither claims anything about what happened after the bytes
# left.
FAILURE_SEAL = "seal_failed"
FAILURE_SEND = "send_failed"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_delivery_ledger (
    local_seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id          TEXT    NOT NULL UNIQUE,
    chain_seq         INTEGER NOT NULL,
    device_id         TEXT    NOT NULL,
    anchor_epoch_id   TEXT    NOT NULL,
    key_id            TEXT    NOT NULL,
    envelope_json     TEXT    NOT NULL,
    envelope_digest   TEXT    NOT NULL,
    chain_row_digest  TEXT    NOT NULL,
    sealed_at_ms      INTEGER NOT NULL,
    custody_state     TEXT    NOT NULL DEFAULT 'none',
    custody_at_ms     INTEGER,
    custody_key_id    TEXT,
    receipt_state     TEXT    NOT NULL DEFAULT 'none',
    receipt_at_ms     INTEGER,
    receipt_key_id    TEXT,
    attempts          INTEGER NOT NULL DEFAULT 0,
    last_attempt_ms   INTEGER,
    last_failure      TEXT,
    CHECK (custody_state IN ('none', 'held')),
    CHECK (receipt_state IN ('none', 'accepted'))
);

CREATE INDEX IF NOT EXISTS idx_evidence_ledger_undelivered
    ON evidence_delivery_ledger (receipt_state, local_seq);

-- Locally observed delivery failures. Separate from the ledger because a
-- failure is not an envelope: several attempts can fail for one row, and a
-- failure to seal produces no row at all.
-- One row, holding the boot counter. Durable and strictly increasing across
-- restarts, so a restart is visible to the authority as a new boot rather than
-- reading as a sequence regression.
CREATE TABLE IF NOT EXISTS evidence_boot_counter (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    boot_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_delivery_gaps (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    kind           TEXT    NOT NULL,
    local_seq      INTEGER,
    event_id       TEXT,
    reason         TEXT    NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    CHECK (kind IN ('seal_failed', 'send_failed'))
);

-- The sealed envelope and its identity are immutable. Delivery bookkeeping is
-- not: custody, receipt and retry columns change as the world does.
CREATE TRIGGER IF NOT EXISTS evidence_ledger_no_delete
BEFORE DELETE ON evidence_delivery_ledger
BEGIN
    SELECT RAISE(ABORT, 'delivery ledger rows are immutable');
END;

CREATE TRIGGER IF NOT EXISTS evidence_ledger_no_sealed_update
BEFORE UPDATE ON evidence_delivery_ledger
WHEN OLD.local_seq        IS NOT NEW.local_seq
  OR OLD.event_id         IS NOT NEW.event_id
  OR OLD.chain_seq        IS NOT NEW.chain_seq
  OR OLD.device_id        IS NOT NEW.device_id
  OR OLD.anchor_epoch_id  IS NOT NEW.anchor_epoch_id
  OR OLD.key_id           IS NOT NEW.key_id
  OR OLD.envelope_json    IS NOT NEW.envelope_json
  OR OLD.envelope_digest  IS NOT NEW.envelope_digest
  OR OLD.chain_row_digest IS NOT NEW.chain_row_digest
  OR OLD.sealed_at_ms     IS NOT NEW.sealed_at_ms
BEGIN
    SELECT RAISE(ABORT, 'sealed envelope columns are immutable');
END;

-- Custody must never be able to stand in for a receipt. Enforced here rather
-- than in the caller, because the whole point is that a stalled gateway cannot
-- make delivery look complete, and a caller is exactly what a bug lives in.
CREATE TRIGGER IF NOT EXISTS evidence_ledger_receipt_needs_authority
BEFORE UPDATE ON evidence_delivery_ledger
WHEN NEW.receipt_state = 'accepted'
 AND (NEW.receipt_key_id IS NULL OR NEW.receipt_at_ms IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a receipt must name the authority key that issued it');
END;

-- The boot counter only ever moves forward. A replayed boot_id would let a
-- device present an old checkpoint as current, which is the one thing the
-- counter exists to make impossible.
CREATE TRIGGER IF NOT EXISTS evidence_boot_counter_monotonic
BEFORE UPDATE ON evidence_boot_counter
WHEN NEW.boot_id <= OLD.boot_id
BEGIN
    SELECT RAISE(ABORT, 'the boot counter must strictly increase');
END;

CREATE TRIGGER IF NOT EXISTS evidence_ledger_gaps_no_delete
BEFORE DELETE ON evidence_delivery_gaps
BEGIN
    SELECT RAISE(ABORT, 'observed delivery failures are immutable');
END;
"""

SEALED_COLUMNS = (
    "local_seq",
    "event_id",
    "chain_seq",
    "device_id",
    "anchor_epoch_id",
    "key_id",
    "envelope_json",
    "envelope_digest",
    "chain_row_digest",
    "sealed_at_ms",
)


class DeliveryLedgerError(RuntimeError):
    """The ledger could not seal, record, or be trusted."""


class EvidenceDeliveryLedger:
    """Seals chain rows into signed envelopes and tracks what became of them."""

    def __init__(
        self,
        db_path: str | Path,
        device_key: EvidenceDeviceKey,
        device_id: str,
        *,
        anchor_epoch_id: str,
        key_id: str,
    ) -> None:
        if not device_id:
            raise DeliveryLedgerError("a ledger must be bound to a device identity")
        if not anchor_epoch_id or not key_id:
            raise DeliveryLedgerError(
                "an envelope names the epoch and key that signed it; both are required"
            )
        self._key = device_key
        self._device_id = str(device_id)
        self._anchor_epoch_id = str(anchor_epoch_id)
        self._key_id = str(key_id)
        self._db_path = str(db_path)
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
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.executescript(_SCHEMA)
        self._boot_id: int | None = None

    @property
    def boot_id(self) -> int:
        """The boot this ledger is signing checkpoints under.

        Allocated on first use rather than at open. Only checkpoints carry a
        boot id, so opening a ledger to read it — a diagnostic tool, an
        operator inspecting delivery state — must not consume one: the counter
        means "this device restarted", and a read is not a restart. Allocating
        at open also made construction a write, which turned every reader into
        a writer contending for the same lock.
        """
        if self._boot_id is None:
            self._boot_id = self._allocate_boot_id()
        return self._boot_id

    def _allocate_boot_id(self) -> int:
        """Claim the next boot, durably, before anything is signed under it.

        Claimed once per ledger instance and then held: several checkpoints
        within one run are one boot, and re-allocating per checkpoint would
        make an ordinary interval look like a restart.
        """
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT boot_id FROM evidence_boot_counter WHERE id = 1"
            ).fetchone()
            if row is None:
                boot_id = 1
                self._connection.execute(
                    "INSERT INTO evidence_boot_counter (id, boot_id) VALUES (1, ?)",
                    (boot_id,),
                )
            else:
                boot_id = int(row["boot_id"]) + 1
                self._connection.execute(
                    "UPDATE evidence_boot_counter SET boot_id = ? WHERE id = 1",
                    (boot_id,),
                )
            self._connection.execute("COMMIT")
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        return boot_id

    def checkpoint(self, *, issued_at_ms: int) -> dict[str, Any]:
        """A device-signed assertion of the highest `local_seq` sealed.

        This is what turns unexplained silence into a missed obligation, so it
        is signed by the device key and never carried on the runtime-gateway
        HMAC envelope. The gateway holds that shared secret, which would make
        an HMAC-authenticated checkpoint forgeable by exactly the party the
        checkpoint exists to constrain: a stalling gateway could manufacture
        checkpoints proving nothing was missing.

        `issued_at_ms` is signed diagnostic evidence of what the device
        believed the time was. It is never the input to any deadline — the
        authority measures against its own clock, because deriving the deadline
        from a device-supplied timestamp would hand the schedule to the party
        being measured.
        """
        checkpoint: dict[str, Any] = {
            "v": CHECKPOINT_VERSION,
            "device_id": self._device_id,
            "high_water_seq": self.high_water_seq(),
            "anchor_epoch_id": self._anchor_epoch_id,
            "boot_id": self.boot_id,
            "key_id": self._key_id,
            "issued_at_ms": int(issued_at_ms),
        }
        import base64

        signature = self._key.sign(CHECKPOINT_DOMAIN + canonical_json(checkpoint))
        checkpoint["signature"] = "ed25519:" + base64.b64encode(signature).decode(
            "ascii"
        )
        return checkpoint

    def close(self) -> None:
        self._connection.close()

    # -- sealing ---------------------------------------------------------

    def seal(
        self, chain_row: sqlite3.Row | dict[str, Any], *, sealed_at_ms: int
    ) -> sqlite3.Row:
        """Wrap one chain row in a signed delivery envelope. Idempotent.

        Allocation and signing happen in one transaction, and they have to:
        the envelope carries `local_seq`, so it cannot be signed before that
        number exists, and the number cannot be allocated and then abandoned
        without leaving a hole in a sequence the contract requires to be
        gapless by construction.
        """
        row = dict(chain_row)
        event_id = str(row.get("event_id", ""))
        if not event_id:
            raise DeliveryLedgerError(
                "a chain row without an event_id cannot be sealed"
            )
        if str(row.get("device_id")) != self._device_id:
            raise DeliveryLedgerError(
                "this ledger is bound to a different device than the row it was given"
            )

        existing = self.find(event_id)
        if existing is not None:
            return existing

        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise DeliveryLedgerError("could not begin a seal") from exc
        try:
            existing = self.find(event_id)
            if existing is not None:
                self._connection.execute("ROLLBACK")
                return existing

            local_seq = self._next_local_seq()
            envelope = self._build_envelope(row, local_seq, sealed_at_ms)
            wire = canonical_json(envelope)
            self._connection.execute(
                """
                INSERT INTO evidence_delivery_ledger (
                    local_seq, event_id, chain_seq, device_id, anchor_epoch_id,
                    key_id, envelope_json, envelope_digest, chain_row_digest,
                    sealed_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    local_seq,
                    event_id,
                    int(row["seq"]),
                    self._device_id,
                    self._anchor_epoch_id,
                    self._key_id,
                    wire.decode("utf-8"),
                    "sha256:" + hashlib.sha256(wire).hexdigest(),
                    envelope["chain_row_digest"],
                    int(sealed_at_ms),
                ),
            )
            self._connection.execute("COMMIT")
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        sealed = self.find(event_id)
        if sealed is None:  # pragma: no cover - the insert committed
            raise DeliveryLedgerError("the sealed envelope could not be read back")
        return sealed

    def _next_local_seq(self) -> int:
        """Gapless by construction: the successor of the highest ever allocated.

        Read inside the sealing transaction. AUTOINCREMENT would also be
        monotonic, but reading it explicitly is what lets the envelope carry
        the number it is signed with.
        """
        row = self._connection.execute(
            "SELECT COALESCE(MAX(local_seq), 0) AS head FROM evidence_delivery_ledger"
        ).fetchone()
        return int(row["head"]) + 1

    def _build_envelope(
        self, row: dict[str, Any], local_seq: int, sealed_at_ms: int
    ) -> dict[str, Any]:
        canonical = str(row["canonical_json"])
        # Only the chain row's immutable columns travel. Export bookkeeping is
        # local and says nothing a receiver should act on.
        chain_row = {
            "canonical_json": canonical,
            "created_at_ms": int(row["created_at_ms"]),
            "device_id": str(row["device_id"]),
            "emitted_at_ms": int(row["emitted_at_ms"]),
            "event_hash": str(row["event_hash"]),
            "event_id": str(row["event_id"]),
            "event_type": str(row["event_type"]),
            "payload_json": str(row["payload_json"]),
            "prev_event_hash": str(row["prev_event_hash"]),
            "seq": int(row["seq"]),
            "signature": str(row["signature"]),
        }
        envelope: dict[str, Any] = {
            "v": ENVELOPE_VERSION,
            "device_id": self._device_id,
            "anchor_epoch_id": self._anchor_epoch_id,
            "key_id": self._key_id,
            "local_seq": local_seq,
            "chain_row": chain_row,
            "chain_row_digest": "sha256:"
            + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "sealed_at_ms": int(sealed_at_ms),
        }
        signature = self._key.sign(ENVELOPE_DOMAIN + canonical_json(envelope))
        import base64

        envelope["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
        return envelope

    # -- delivery state --------------------------------------------------

    def record_custody(
        self, local_seq: int, *, custody_at_ms: int, key_id: str
    ) -> None:
        """The gateway says it holds these bytes. That is not delivery."""
        if not key_id:
            raise DeliveryLedgerError(
                "a custody acknowledgement must name its key generation"
            )
        self._connection.execute(
            """
            UPDATE evidence_delivery_ledger
               SET custody_state = ?, custody_at_ms = ?, custody_key_id = ?
             WHERE local_seq = ?
            """,
            (CUSTODY_HELD, int(custody_at_ms), str(key_id), int(local_seq)),
        )

    def record_receipt(
        self, local_seq: int, *, receipt_at_ms: int, key_id: str
    ) -> None:
        """The authority says it accepted the evidence. Only this is delivery."""
        if not key_id:
            raise DeliveryLedgerError(
                "a receipt must name the authority key that issued it"
            )
        self._connection.execute(
            """
            UPDATE evidence_delivery_ledger
               SET receipt_state = ?, receipt_at_ms = ?, receipt_key_id = ?
             WHERE local_seq = ?
            """,
            (RECEIPT_ACCEPTED, int(receipt_at_ms), str(key_id), int(local_seq)),
        )

    def record_attempt(
        self, local_seq: int, *, at_ms: int, failure: str | None
    ) -> None:
        self._connection.execute(
            """
            UPDATE evidence_delivery_ledger
               SET attempts = attempts + 1, last_attempt_ms = ?, last_failure = ?
             WHERE local_seq = ?
            """,
            (int(at_ms), failure, int(local_seq)),
        )

    def record_local_failure(
        self,
        kind: str,
        *,
        reason: str,
        observed_at_ms: int,
        local_seq: int | None = None,
        event_id: str | None = None,
    ) -> None:
        """Record something this device did and failed at.

        Refuses anything else. A runtime cannot observe a truncation performed
        elsewhere, and a row implying it could would be fabricating evidence of
        tampering — which is worse than recording nothing, because the record
        is the thing being trusted.
        """
        if kind not in (FAILURE_SEAL, FAILURE_SEND):
            raise DeliveryLedgerError(
                f"{kind!r} is not a locally observable failure; this device can "
                "record what it failed to do, not what happened after the bytes left"
            )
        self._connection.execute(
            """
            INSERT INTO evidence_delivery_gaps (kind, local_seq, event_id, reason, observed_at_ms)
            VALUES (?, ?, ?, ?, ?)
            """,
            (kind, local_seq, event_id, str(reason), int(observed_at_ms)),
        )

    # -- reading ---------------------------------------------------------

    def find(self, event_id: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._connection.execute(
            "SELECT * FROM evidence_delivery_ledger WHERE event_id = ?", (event_id,)
        ).fetchone()
        return row

    def high_water_seq(self) -> int:
        """The highest `local_seq` sealed. What a checkpoint asserts."""
        row = self._connection.execute(
            "SELECT COALESCE(MAX(local_seq), 0) AS head FROM evidence_delivery_ledger"
        ).fetchone()
        return int(row["head"])

    def undelivered(self, limit: int = 100) -> list[sqlite3.Row]:
        """Sealed but unreceipted, oldest first. Custody does not count."""
        return list(
            self._connection.execute(
                """
                SELECT * FROM evidence_delivery_ledger
                 WHERE receipt_state = ?
                 ORDER BY local_seq
                 LIMIT ?
                """,
                (RECEIPT_NONE, int(limit)),
            )
        )

    def local_failures(self) -> list[sqlite3.Row]:
        return list(
            self._connection.execute("SELECT * FROM evidence_delivery_gaps ORDER BY id")
        )

    def verify_sequence(self) -> list[str]:
        """Report any hole in the local sequence.

        Gapless is a construction property, so a hole means the database was
        edited rather than that delivery failed. Reported rather than raised,
        for the same reason the chain reports: one bad row must not hide the
        rest.
        """
        problems: list[str] = []
        expected = 1
        for row in self._connection.execute(
            "SELECT local_seq, envelope_json, envelope_digest FROM evidence_delivery_ledger"
            " ORDER BY local_seq"
        ):
            actual = int(row["local_seq"])
            if actual != expected:
                problems.append(
                    f"local_seq {actual}: expected {expected}; the sequence has a hole"
                )
                expected = actual
            wire = str(row["envelope_json"]).encode("utf-8")
            digest = "sha256:" + hashlib.sha256(wire).hexdigest()
            if digest != str(row["envelope_digest"]):
                problems.append(
                    f"local_seq {actual}: envelope_digest disagrees with the stored bytes"
                )
            try:
                envelope = json.loads(wire)
            except ValueError:
                problems.append(
                    f"local_seq {actual}: envelope_json is not parseable JSON"
                )
                expected = actual + 1
                continue
            if envelope.get("local_seq") != actual:
                problems.append(
                    f"local_seq {actual}: the signed envelope numbers itself differently"
                )
            expected = actual + 1
        return problems
