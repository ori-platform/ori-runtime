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

import base64
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from ori.security.evidence_canonical import canonical_json
from ori.security.evidence_chain import ENVELOPE_FIELDS, SCHEMA_VERSION
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

# What this device can honestly say went wrong about *delivery*.
#
# Failing before an envelope is sealed is deliberately not here. It allocates
# no sequence and produces no envelope, so there is nothing that could be
# missing in transit — the contract calls that an evidence/v2 attestation gap,
# recorded against the action row, and duplicating it here would report one
# failure as two in different registers.
FAILURE_SEND = "send_failed"
FAILURE_REASONS = frozenset(
    {
        "unreachable",
        "timeout",
        "refused",
        "queue_full",
        "auth_failed",
        "malformed_response",
        "internal_error",
    }
)

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
    CHECK (receipt_state IN ('none', 'accepted')),
    -- Both directions, because a half-written state is as wrong as a forbidden
    -- one. 'held' with no timestamp and no key is a custody claim naming
    -- nobody and no moment, which reads as recorded custody to every query
    -- that checks the state column; 'none' carrying metadata is the residue of
    -- a withdrawal that should not have been possible.
    CHECK (
        (custody_state = 'none'
             AND custody_at_ms IS NULL AND custody_key_id IS NULL)
     OR (custody_state = 'held'
             AND custody_at_ms IS NOT NULL
             AND custody_key_id IS NOT NULL AND length(custody_key_id) > 0)
    ),
    CHECK (
        (receipt_state = 'none'
             AND receipt_at_ms IS NULL AND receipt_key_id IS NULL)
     OR (receipt_state = 'accepted'
             AND receipt_at_ms IS NOT NULL
             AND receipt_key_id IS NOT NULL AND length(receipt_key_id) > 0)
    )
);

CREATE INDEX IF NOT EXISTS idx_evidence_ledger_undelivered
    ON evidence_delivery_ledger (receipt_state, local_seq);

-- Locally observed delivery failures. Separate from the ledger because a
-- failure is not an envelope: several attempts can fail for one row, and a
-- failure to seal produces no row at all.
-- Anchor epochs this device has seen confirmed by the authority.
--
-- The confirmation coordinator needs to know whether an epoch is active before
-- firmware authority becomes effective, and under the off-device topology that
-- answer arrives as a signed epoch confirmation rather than from a chain object
-- in this process. This is where the answer is kept once it has been proven.
CREATE TABLE IF NOT EXISTS evidence_device_epochs (
    device_id       TEXT PRIMARY KEY,
    anchor_epoch_id TEXT    NOT NULL,
    pubkey_hex      TEXT    NOT NULL,
    actor           TEXT    NOT NULL,
    confirmed_at_ms INTEGER NOT NULL,
    key_id          TEXT    NOT NULL,
    CHECK (length(anchor_epoch_id) > 0),
    CHECK (length(key_id) > 0)
);

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
    local_seq      INTEGER NOT NULL,
    reason         TEXT    NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    CHECK (kind = 'send_failed'),
    -- The vocabulary is constrained in the schema, not only in the application.
    -- Foreign keys and application checks are both connection-local or
    -- process-local; a CHECK travels with the database, so another connection
    -- cannot write disclosure-bearing text into a file an operator can read.
    CHECK (reason IN (
        'unreachable', 'timeout', 'refused', 'queue_full',
        'auth_failed', 'malformed_response', 'internal_error'
    )),
    FOREIGN KEY (local_seq) REFERENCES evidence_delivery_ledger (local_seq)
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
-- Neither acceptance can be withdrawn or restated. A receipt that could be
-- reverted to 'none', or whose issuing key could be rewritten afterwards,
-- would let local state disagree with what the authority actually signed —
-- and local state is what the runtime acts on.
CREATE TRIGGER IF NOT EXISTS evidence_ledger_custody_is_final
BEFORE UPDATE ON evidence_delivery_ledger
WHEN OLD.custody_state = 'held'
 AND (NEW.custody_state <> 'held'
   OR NEW.custody_at_ms  IS NOT OLD.custody_at_ms
   OR NEW.custody_key_id IS NOT OLD.custody_key_id)
BEGIN
    SELECT RAISE(ABORT, 'recorded custody cannot be withdrawn or rewritten');
END;

CREATE TRIGGER IF NOT EXISTS evidence_ledger_receipt_is_final
BEFORE UPDATE ON evidence_delivery_ledger
WHEN OLD.receipt_state = 'accepted'
 AND (NEW.receipt_state <> 'accepted'
   OR NEW.receipt_at_ms  IS NOT OLD.receipt_at_ms
   OR NEW.receipt_key_id IS NOT OLD.receipt_key_id)
BEGIN
    SELECT RAISE(ABORT, 'a recorded receipt cannot be withdrawn or rewritten');
END;

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
-- Deleting the row and reinserting it resets the generation, which is the same
-- attack the monotonic trigger blocks, taking one step around it. The contract
-- says a boot id cannot reset: an operator who could reset it can replay an old
-- checkpoint generation as current.
CREATE TRIGGER IF NOT EXISTS evidence_boot_counter_no_delete
BEFORE DELETE ON evidence_boot_counter
BEGIN
    SELECT RAISE(ABORT, 'the boot counter cannot be reset');
END;

CREATE TRIGGER IF NOT EXISTS evidence_boot_counter_monotonic
BEFORE UPDATE ON evidence_boot_counter
WHEN NEW.boot_id <= OLD.boot_id
BEGIN
    SELECT RAISE(ABORT, 'the boot counter must strictly increase');
END;

-- Foreign-key enforcement is off by default and is a per-connection setting,
-- so the reference above constrains only connections that opted in. A trigger
-- is part of the database and applies to every writer, which is what the
-- invariant actually needs: a delivery failure naming an envelope that was
-- never sealed has no referent.
CREATE TRIGGER IF NOT EXISTS evidence_ledger_gaps_need_envelope
BEFORE INSERT ON evidence_delivery_gaps
WHEN NOT EXISTS (
    SELECT 1 FROM evidence_delivery_ledger WHERE local_seq = NEW.local_seq
)
BEGIN
    SELECT RAISE(ABORT, 'a delivery failure must name a sealed envelope');
END;

CREATE TRIGGER IF NOT EXISTS evidence_ledger_gaps_no_delete
BEFORE DELETE ON evidence_delivery_gaps
BEGIN
    SELECT RAISE(ABORT, 'observed delivery failures are immutable');
END;

-- A failure that can be edited afterwards is not a record of what happened.
-- Blocking deletion alone left every field rewritable, which is the same hole
-- with extra steps.
CREATE TRIGGER IF NOT EXISTS evidence_ledger_gaps_no_update
BEFORE UPDATE ON evidence_delivery_gaps
BEGIN
    SELECT RAISE(ABORT, 'observed delivery failures are immutable');
END;
"""

# The chain row's immutable columns, exactly as evidence/v2 defines them.
# These are what travel, and therefore what "the same evidence" means.
CARRIED_CHAIN_COLUMNS = (
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


SIGNATURE_PREFIX = "ed25519:"
_SIGNATURE_BYTES = 64


def _decode_wire_signature(wire: str) -> bytes:
    """Decode `ed25519:<standard base64>`, refusing anything else.

    Verification proves a signature is mathematically valid over some bytes. It
    says nothing about whether the artifact follows the wire contract, and the
    two are easy to conflate: an earlier version split on the prefix and took
    the last part, which returns the whole string unchanged when the prefix is
    absent — so a prefixless signature verified and was accepted. A receiver
    parsing strictly would then reject an artifact this device considered good.

    Strict Base64 for the same reason: permissive decoding accepts whitespace
    and alternative alphabets, so two implementations disagree on whether the
    same artifact is well-formed.
    """
    if not wire.startswith(SIGNATURE_PREFIX):
        raise DeliveryLedgerError(
            f"a signature must carry exactly one {SIGNATURE_PREFIX!r} prefix"
        )
    body = wire[len(SIGNATURE_PREFIX) :]
    if SIGNATURE_PREFIX in body:
        raise DeliveryLedgerError("a signature must carry exactly one prefix")
    try:
        raw = base64.b64decode(body, validate=True)
    except Exception as exc:
        raise DeliveryLedgerError("a signature must be standard Base64") from exc
    if len(raw) != _SIGNATURE_BYTES:
        raise DeliveryLedgerError(
            f"an Ed25519 signature is {_SIGNATURE_BYTES} bytes, not {len(raw)}"
        )
    return raw


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
        # Enforced for this connection. The triggers above are what make the
        # constraint hold for every other one, since this pragma is off by
        # default and cannot be relied on to travel with the file.
        self._connection.execute("PRAGMA foreign_keys=ON")
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

        # Validated before the idempotency lookup, not after. A row that does
        # not verify must never reach the ledger at all, and a lookup that
        # short-circuits on identity alone would let an unverified row past
        # whenever its identity happened to match one already sealed.
        self._verify_chain_row(row)
        carried = {name: row[name] for name in CARRIED_CHAIN_COLUMNS}

        existing = self.find(event_id)
        if existing is not None:
            return self._reconcile_reseal(existing, carried)

        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise DeliveryLedgerError("could not begin a seal") from exc
        try:
            existing = self.find(event_id)
            if existing is not None:
                self._connection.execute("ROLLBACK")
                return self._reconcile_reseal(existing, carried)

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

    def _verify_chain_row(self, row: dict[str, Any]) -> None:
        """Prove the row is this device's, well-formed, and self-consistent.

        The envelope binds delivery framing to evidence, so a row that does not
        verify is not evidence and must not be wrapped as though it were. Every
        check here is one a receiver performs, and failing them locally is
        cheaper than discovering it after the bytes have left.
        """
        missing = [name for name in CARRIED_CHAIN_COLUMNS if name not in row]
        if missing:
            raise DeliveryLedgerError(f"the chain row is missing columns {missing}")

        signed = str(row["canonical_json"]).encode("utf-8")
        try:
            envelope = json.loads(signed)
        except ValueError as exc:
            raise DeliveryLedgerError(
                "the chain row's signed bytes are not JSON"
            ) from exc
        if not isinstance(envelope, dict) or set(envelope) != set(ENVELOPE_FIELDS):
            raise DeliveryLedgerError(
                "the chain row's signed envelope does not carry exactly the "
                "fields evidence/v2 defines"
            )
        if envelope.get("schema_version") != SCHEMA_VERSION:
            raise DeliveryLedgerError(
                f"the chain row declares {envelope.get('schema_version')!r}, "
                f"not {SCHEMA_VERSION}"
            )
        # Parsing proves the bytes are JSON. It does not prove they are *the*
        # canonical form, and the contract is about exact bytes: an indented or
        # unsorted encoding of the same object signs and verifies perfectly
        # while being a different artifact from the one a receiver reproduces.
        # Re-canonicalising and comparing is also what rejects duplicate keys
        # and out-of-zone numbers, since the canonicaliser refuses both.
        try:
            recanonicalised = canonical_json(envelope)
        except Exception as exc:
            raise DeliveryLedgerError(
                "the chain row's signed bytes are not canonicalisable"
            ) from exc
        if recanonicalised != signed:
            raise DeliveryLedgerError(
                "the chain row's signed bytes are not in canonical form; the "
                "same object encoded differently is a different artifact"
            )

        # The outer columns are what a reader queries; the envelope is what was
        # signed. A row whose columns describe a different event than its bytes
        # is what rules 5 to 10 of the chain contract exist to catch.
        for field, column in (
            ("sequence_num", "seq"),
            ("prev_event_hash", "prev_event_hash"),
            ("event_id", "event_id"),
            ("event_type", "event_type"),
            ("device_id", "device_id"),
            ("emitted_at_ms", "emitted_at_ms"),
        ):
            if envelope.get(field) != row[column]:
                raise DeliveryLedgerError(
                    f"the chain row's {column} disagrees with its signed envelope"
                )
        try:
            stored_payload = json.loads(str(row["payload_json"]))
        except ValueError as exc:
            raise DeliveryLedgerError(
                "the chain row's payload_json is not JSON"
            ) from exc
        if stored_payload != envelope.get("payload"):
            raise DeliveryLedgerError(
                "the chain row's payload_json disagrees with its signed envelope"
            )
        if hashlib.sha256(signed).hexdigest() != str(row["event_hash"]):
            raise DeliveryLedgerError(
                "the chain row's event_hash disagrees with its bytes"
            )

        signature = _decode_wire_signature(str(row["signature"]))
        try:
            self._key.verify(signature, signed)
        except Exception as exc:
            raise DeliveryLedgerError(
                "the chain row's signature does not verify under this device's key"
            ) from exc

    @staticmethod
    def _reconcile_reseal(
        existing: sqlite3.Row, carried: dict[str, Any]
    ) -> sqlite3.Row:
        """Return the sealed envelope only when the request means the same row.

        Idempotency is "same identity and same content". Returning the stored
        envelope for a different row would tell the caller its evidence is
        queued for delivery when something else is — the same defect the chain
        producer had, one layer up. The digest covers the signed bytes, so it
        is the whole of what "the same row" means.
        """
        stored = json.loads(str(existing["envelope_json"]))["chain_row"]
        differing = sorted(
            name for name in CARRIED_CHAIN_COLUMNS if stored.get(name) != carried[name]
        )
        if not differing:
            return existing
        raise DeliveryLedgerError(
            f"event_id {existing['event_id']} is already sealed over a different "
            f"chain row ({', '.join(differing)}); the same identity must mean "
            "the same evidence"
        )

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

    def _apply_verified_epoch(
        self,
        device_id: str,
        *,
        anchor_epoch_id: str,
        pubkey_hex: str,
        actor: str,
        confirmed_at_ms: int,
        key_id: str,
    ) -> None:
        """Persist an epoch confirmation whose signature and bindings are proven.

        Not a public boundary, for the same reason the delivery transitions are
        not: this method cannot check what it is told. A caller able to assert
        an active epoch without an authority signature could make firmware
        authority effective on its own say-so, which is the decision the epoch
        confirmation exists to take out of the device's hands.

        Last confirmation wins. The authority is the sole source of epoch
        truth, so a later statement supersedes an earlier one rather than
        conflicting with it; a device holding two and choosing between them
        would be adjudicating something it does not decide.
        """
        self._connection.execute(
            """
            INSERT INTO evidence_device_epochs (
                device_id, anchor_epoch_id, pubkey_hex, actor, confirmed_at_ms, key_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                anchor_epoch_id = excluded.anchor_epoch_id,
                pubkey_hex      = excluded.pubkey_hex,
                actor           = excluded.actor,
                confirmed_at_ms = excluded.confirmed_at_ms,
                key_id          = excluded.key_id
            """,
            (
                str(device_id),
                str(anchor_epoch_id),
                str(pubkey_hex),
                str(actor),
                int(confirmed_at_ms),
                str(key_id),
            ),
        )

    def active_anchor_epoch_id(self, device_id: str) -> str | None:
        """The epoch the authority last confirmed for this device, if any.

        The read the confirmation coordinator performs. `None` means no
        confirmation has been proven — which keeps the obligation pending
        rather than granting authority by default.
        """
        row = self._connection.execute(
            "SELECT anchor_epoch_id FROM evidence_device_epochs WHERE device_id = ?",
            (str(device_id),),
        ).fetchone()
        return str(row["anchor_epoch_id"]) if row is not None else None

    def confirmed_epoch(self, device_id: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._connection.execute(
            "SELECT * FROM evidence_device_epochs WHERE device_id = ?",
            (str(device_id),),
        ).fetchone()
        return row

    def envelope_digests(self, from_seq: int, to_seq: int) -> dict[int, str]:
        """Digests for a closed interval, for checking a receipt's range claim."""
        rows = self._connection.execute(
            "SELECT local_seq, envelope_digest FROM evidence_delivery_ledger"
            " WHERE local_seq BETWEEN ? AND ?",
            (int(from_seq), int(to_seq)),
        )
        return {int(r["local_seq"]): str(r["envelope_digest"]) for r in rows}

    def _require_sealed(self, local_seq: int) -> sqlite3.Row:
        """Refuse to act on a sequence this ledger never allocated.

        A silent zero-row update is the worst outcome: the caller believes it
        recorded delivery state and nothing did.
        """
        row: sqlite3.Row | None = self._connection.execute(
            "SELECT * FROM evidence_delivery_ledger WHERE local_seq = ?",
            (int(local_seq),),
        ).fetchone()
        if row is None:
            raise DeliveryLedgerError(
                f"local_seq {local_seq} has no sealed envelope in this ledger"
            )
        return row

    def _apply_verified_custody(
        self, local_seq: int, *, custody_at_ms: int, key_id: str
    ) -> None:
        """Record custody that has already been authenticated.

        Deliberately not a public boundary. Marking a row as held is a claim
        about what a gateway did, and this method cannot check that — it takes
        whatever it is given. The MAC verification that makes the claim
        meaningful belongs to ingest, and a public unverified route into the
        same state would make that verification optional in practice.
        """
        if not key_id:
            raise DeliveryLedgerError(
                "a custody acknowledgement must name its key generation"
            )
        self._require_sealed(local_seq)
        self._connection.execute(
            """
            UPDATE evidence_delivery_ledger
               SET custody_state = ?, custody_at_ms = ?, custody_key_id = ?
             WHERE local_seq = ?
            """,
            (CUSTODY_HELD, int(custody_at_ms), str(key_id), int(local_seq)),
        )

    def _apply_verified_receipt(
        self, local_seq: int, *, receipt_at_ms: int, key_id: str
    ) -> None:
        """Record a receipt whose signature, purpose and range are already checked.

        Same reasoning as custody, and it matters more here: this is the state
        that means "delivered". A public method flipping it on any non-empty
        string would let a caller assert a delivery no authority ever issued,
        and the trigger guarding it proves only that a string exists — not that
        it names a key which signed anything. Ingest is the sole route in.
        """
        if not key_id:
            raise DeliveryLedgerError(
                "a receipt must name the authority key that issued it"
            )
        self._require_sealed(local_seq)
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
        """Note a delivery attempt. The reason, if any, is from the closed set."""
        self._require_sealed(local_seq)
        if failure is not None and failure not in FAILURE_REASONS:
            raise DeliveryLedgerError(
                f"{failure!r} is not a recognised failure reason; reasons are a "
                "closed set so transport detail cannot reach this database"
            )
        self._connection.execute(
            """
            UPDATE evidence_delivery_ledger
               SET attempts = attempts + 1, last_attempt_ms = ?, last_failure = ?
             WHERE local_seq = ?
            """,
            (int(at_ms), failure, int(local_seq)),
        )

    def record_delivery_failure(
        self,
        local_seq: int,
        *,
        reason: str,
        observed_at_ms: int,
    ) -> None:
        """Record a failure to deliver an envelope this device sealed.

        Three constraints, each closing a different way of writing something
        untrue into the record.

        It must name a sealed envelope. A delivery failure without one has no
        referent — failing before sealing allocates nothing and is an
        evidence/v2 attestation gap against the action row, not a hole in a
        delivery sequence that never had a member.

        It cannot describe anything but sending. A runtime cannot witness a
        truncation performed elsewhere, and a row implying it could would
        fabricate evidence of tampering, which is worse than recording nothing
        when the record is the thing being trusted.

        The reason comes from a closed set. Arbitrary exception text would put
        transport detail — a hostname, an endpoint, a private identity — into a
        database an operator can read, which is the disclosure boundary the
        evidence path exists behind.
        """
        self._require_sealed(local_seq)
        if reason not in FAILURE_REASONS:
            raise DeliveryLedgerError(
                f"{reason!r} is not a recognised failure reason; reasons are a "
                "closed set so transport detail cannot reach this database"
            )
        self._connection.execute(
            """
            INSERT INTO evidence_delivery_gaps (kind, local_seq, reason, observed_at_ms)
            VALUES (?, ?, ?, ?)
            """,
            (FAILURE_SEND, int(local_seq), reason, int(observed_at_ms)),
        )

    # -- reading ---------------------------------------------------------

    def find(self, event_id: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._connection.execute(
            "SELECT * FROM evidence_delivery_ledger WHERE event_id = ?", (event_id,)
        ).fetchone()
        return row

    def find_by_local_seq(self, local_seq: int) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._connection.execute(
            "SELECT * FROM evidence_delivery_ledger WHERE local_seq = ?",
            (int(local_seq),),
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
