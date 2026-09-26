# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The runtime's delivery ledger, per `ori-specs/evidence-exchange/v2`.

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

from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.chain import ENVELOPE_FIELDS, SCHEMA_VERSION
from ori.security.evidence.device_key import EvidenceDeviceKey
from ori.security.evidence.disposition import DispositionValue, VerifiedDisposition
from ori.security.evidence.registration import reoffer_due

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
# missing in transit — the contract calls that an evidence/v3 attestation gap,
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

_DELIVERY_SCHEMA = """
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

-- Device-signed artifacts that are not envelopes -- checkpoints and anchor
-- registrations -- retained until the courier's authenticated acknowledgement
-- says its durable queue owns retry. The bytes are the exact signed wire, so a
-- republish after a lost acknowledgement carries the same digest and the
-- gateway's idempotent queue recovers the same entry.
CREATE TABLE IF NOT EXISTS evidence_outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_type   TEXT    NOT NULL,
    artifact_json   TEXT    NOT NULL,
    artifact_digest TEXT    NOT NULL UNIQUE,
    created_at_ms   INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_attempt_ms INTEGER,
    retired_at_ms   INTEGER,
    retire_outcome  TEXT,
    CHECK (artifact_type IN ('checkpoint', 'anchor_registration')),
    CHECK (
        (retired_at_ms IS NULL AND retire_outcome IS NULL)
     OR (retired_at_ms IS NOT NULL AND retire_outcome IN ('queued', 'refused'))
    )
);

CREATE TRIGGER IF NOT EXISTS evidence_outbox_no_delete
BEFORE DELETE ON evidence_outbox
BEGIN
    SELECT RAISE(ABORT, 'queued evidence artifacts are immutable');
END;

CREATE TRIGGER IF NOT EXISTS evidence_outbox_no_artifact_update
BEFORE UPDATE ON evidence_outbox
WHEN OLD.artifact_type   IS NOT NEW.artifact_type
  OR OLD.artifact_json   IS NOT NEW.artifact_json
  OR OLD.artifact_digest IS NOT NEW.artifact_digest
  OR OLD.created_at_ms   IS NOT NEW.created_at_ms
BEGIN
    SELECT RAISE(ABORT, 'a queued artifact cannot be rewritten');
END;

CREATE TRIGGER IF NOT EXISTS evidence_outbox_retirement_is_final
BEFORE UPDATE ON evidence_outbox
WHEN OLD.retired_at_ms IS NOT NULL
 AND (NEW.retired_at_ms IS NOT OLD.retired_at_ms
   OR NEW.retire_outcome IS NOT OLD.retire_outcome)
BEGIN
    SELECT RAISE(ABORT, 'a retired artifact cannot be requeued or restated');
END;

-- A retained copy whose bytes can no longer be carried as sealed: they are
-- not UTF-8 text, or no longer hash to the digest recorded with them. The
-- bytes stay where they are; the copy leaves the courier route and the
-- checkpoint order, so it holds nothing behind it. Recorded once, and final.
CREATE TABLE IF NOT EXISTS evidence_artifact_fault (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    holder         TEXT    NOT NULL,
    holder_id      INTEGER NOT NULL,
    reason         TEXT    NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    CHECK (holder IN ('outbox', 'obligation', 'envelope')),
    CHECK (reason IN ('unreadable', 'digest_mismatch')),
    UNIQUE (holder, holder_id)
);

CREATE TRIGGER IF NOT EXISTS evidence_artifact_fault_no_delete
BEFORE DELETE ON evidence_artifact_fault
BEGIN
    SELECT RAISE(ABORT, 'a recorded artifact fault cannot be cleared');
END;

CREATE TRIGGER IF NOT EXISTS evidence_artifact_fault_no_update
BEFORE UPDATE ON evidence_artifact_fault
BEGIN
    SELECT RAISE(ABORT, 'a recorded artifact fault cannot be cleared');
END;
"""

#: Every table the anchor registration and its dispositions keep, and nothing
#: else. Kept apart so what counts as registration state is derivable.
_REGISTRATION_SCHEMA = """
-- The confirmation obligation for a sealed anchor registration. Separate from
-- the outbox row, which is only the courier handoff copy: a `queued`
-- acknowledgement retires that copy and never this. The exact sealed bytes
-- stay here and are re-offered until a verified epoch confirmation for the
-- epoch closes the obligation, or a replacement reference supersedes it.
CREATE TABLE IF NOT EXISTS evidence_registration_obligation (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id               TEXT    NOT NULL,
    anchor_epoch_id         TEXT    NOT NULL,
    pubkey_hex              TEXT    NOT NULL,
    commissioning_reference TEXT    NOT NULL,
    artifact_json           TEXT    NOT NULL,
    artifact_digest         TEXT    NOT NULL UNIQUE,
    sealed_at_ms            INTEGER NOT NULL,
    offers                  INTEGER NOT NULL DEFAULT 0,
    last_offer_ms           INTEGER,
    state                   TEXT    NOT NULL DEFAULT 'open',
    closed_at_ms            INTEGER,
    -- A verified `retained_pending` disposition: re-offers stop, the
    -- obligation stays open.
    suspended_at_ms         INTEGER,
    -- The terminal disposition value that closed the attempt.
    closed_reason           TEXT,
    CHECK (state IN ('open', 'confirmed', 'superseded', 'closed')),
    CHECK (
        (state = 'open' AND closed_at_ms IS NULL)
     OR (state <> 'open' AND closed_at_ms IS NOT NULL)
    ),
    CHECK ((state = 'closed') = (closed_reason IS NOT NULL)),
    CHECK (
        length(anchor_epoch_id) = 71
        AND substr(anchor_epoch_id, 1, 7) = 'sha256:'
        AND substr(anchor_epoch_id, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (
        length(commissioning_reference) = 71
        AND substr(commissioning_reference, 1, 7) = 'sha256:'
        AND substr(commissioning_reference, 8) NOT GLOB '*[^0-9a-f]*'
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_registration_obligation_open
    ON evidence_registration_obligation (anchor_epoch_id) WHERE state = 'open';

CREATE TRIGGER IF NOT EXISTS evidence_registration_obligation_no_delete
BEFORE DELETE ON evidence_registration_obligation
BEGIN
    SELECT RAISE(ABORT, 'a registration obligation cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS evidence_registration_obligation_sealed
BEFORE UPDATE ON evidence_registration_obligation
WHEN OLD.device_id               IS NOT NEW.device_id
  OR OLD.anchor_epoch_id         IS NOT NEW.anchor_epoch_id
  OR OLD.pubkey_hex              IS NOT NEW.pubkey_hex
  OR OLD.commissioning_reference IS NOT NEW.commissioning_reference
  OR OLD.artifact_json           IS NOT NEW.artifact_json
  OR OLD.artifact_digest         IS NOT NEW.artifact_digest
  OR OLD.sealed_at_ms            IS NOT NEW.sealed_at_ms
BEGIN
    SELECT RAISE(ABORT, 'sealed registration bytes are immutable');
END;

CREATE TRIGGER IF NOT EXISTS evidence_registration_obligation_closed_is_final
BEFORE UPDATE ON evidence_registration_obligation
WHEN OLD.state <> 'open'
 AND (NEW.state IS NOT OLD.state
   OR NEW.closed_at_ms IS NOT OLD.closed_at_ms
   OR NEW.closed_reason IS NOT OLD.closed_reason)
BEGIN
    SELECT RAISE(ABORT, 'a closed registration obligation cannot be reopened');
END;

CREATE TRIGGER IF NOT EXISTS evidence_registration_obligation_suspension_is_final
BEFORE UPDATE ON evidence_registration_obligation
WHEN OLD.suspended_at_ms IS NOT NULL
 AND NEW.suspended_at_ms IS NOT OLD.suspended_at_ms
BEGIN
    SELECT RAISE(ABORT, 'a suspended re-offer is resumed only by a new attempt');
END;

-- Verified epoch confirmations for epochs this device sealed a registration
-- under, keyed by epoch. What `confirmed` is read from. The first verified
-- confirmation for an epoch stands; a replay changes nothing.
CREATE TABLE IF NOT EXISTS evidence_registration_confirmation (
    anchor_epoch_id TEXT    PRIMARY KEY,
    device_id       TEXT    NOT NULL,
    pubkey_hex      TEXT    NOT NULL,
    actor           TEXT    NOT NULL,
    confirmed_at_ms INTEGER NOT NULL,
    key_id          TEXT    NOT NULL,
    applied_at_ms   INTEGER NOT NULL
);

CREATE TRIGGER IF NOT EXISTS evidence_registration_confirmation_final
BEFORE UPDATE ON evidence_registration_confirmation
BEGIN
    SELECT RAISE(ABORT, 'a recorded confirmation cannot be rewritten');
END;

CREATE TRIGGER IF NOT EXISTS evidence_registration_confirmation_no_delete
BEFORE DELETE ON evidence_registration_confirmation
BEGIN
    SELECT RAISE(ABORT, 'a recorded confirmation cannot be deleted');
END;

-- The anchor this runtime is sealing under, recorded each time it opens its
-- evidence, so a local tool can bind the epoch a health socket reports to the
-- configured installation's own files.
CREATE TABLE IF NOT EXISTS evidence_current_anchor (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    device_id       TEXT    NOT NULL,
    anchor_epoch_id TEXT    NOT NULL,
    key_id          TEXT    NOT NULL,
    pubkey_hex      TEXT    NOT NULL,
    posture         TEXT    NOT NULL,
    recorded_at_ms  INTEGER NOT NULL
);

-- Every verified disposition applied, keyed by its own digest so a
-- byte-identical repetition adds nothing. Immutable.
CREATE TABLE IF NOT EXISTS evidence_disposition (
    digest            TEXT    PRIMARY KEY,
    triggering_digest TEXT    NOT NULL,
    artifact_type     TEXT    NOT NULL,
    device_id         TEXT    NOT NULL,
    anchor_epoch_id   TEXT    NOT NULL,
    scope             TEXT    NOT NULL,
    disposition       TEXT    NOT NULL,
    decided_at_ms     INTEGER NOT NULL,
    key_id            TEXT    NOT NULL,
    observed_at_ms    INTEGER NOT NULL,
    CHECK (scope IN ('artifact', 'epoch', 'identity'))
);

CREATE TRIGGER IF NOT EXISTS evidence_disposition_final
BEFORE UPDATE ON evidence_disposition
BEGIN
    SELECT RAISE(ABORT, 'an applied disposition cannot be rewritten');
END;

CREATE TRIGGER IF NOT EXISTS evidence_disposition_no_delete
BEFORE DELETE ON evidence_disposition
BEGIN
    SELECT RAISE(ABORT, 'an applied disposition cannot be deleted');
END;

-- Offers an authority disposition stopped: every checkpoint and registration
-- re-offer for the identity, or those for one epoch. Neither restart,
-- acknowledgement nor configuration clears one, so rows are immutable.
CREATE TABLE IF NOT EXISTS evidence_offer_stop (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scope           TEXT    NOT NULL,
    device_id       TEXT    NOT NULL,
    anchor_epoch_id TEXT,
    disposition     TEXT    NOT NULL,
    artifact_digest TEXT    NOT NULL,
    stopped_at_ms   INTEGER NOT NULL,
    CHECK (scope IN ('epoch', 'identity')),
    CHECK ((scope = 'epoch') = (anchor_epoch_id IS NOT NULL))
);

CREATE TRIGGER IF NOT EXISTS evidence_offer_stop_no_delete
BEFORE DELETE ON evidence_offer_stop
BEGIN
    SELECT RAISE(ABORT, 'a stopped offer cannot be cleared');
END;

CREATE TRIGGER IF NOT EXISTS evidence_offer_stop_no_update
BEFORE UPDATE ON evidence_offer_stop
BEGIN
    SELECT RAISE(ABORT, 'a stopped offer cannot be cleared');
END;
"""

_REFUSAL_SCHEMA = """
-- Authority artifacts ingest refused, kept so a refused receipt is
-- distinguishable from one that never arrived after a restart. Bounded: the
-- newest rows are what an operator diagnoses from, and an attacker who can
-- publish rubbish on the inbound topic must not be able to grow a device's
-- database without limit. Rows are never rewritten.
CREATE TABLE IF NOT EXISTS evidence_ingest_refusals (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_type  TEXT    NOT NULL,
    reason         TEXT    NOT NULL,
    detail         TEXT    NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    CHECK (length(artifact_type) BETWEEN 1 AND 64),
    CHECK (length(reason) BETWEEN 1 AND 64),
    CHECK (length(detail) <= 256)
);

CREATE TRIGGER IF NOT EXISTS evidence_ingest_refusals_no_update
BEFORE UPDATE ON evidence_ingest_refusals
BEGIN
    SELECT RAISE(ABORT, 'ingest refusals are immutable');
END;

CREATE TRIGGER IF NOT EXISTS evidence_ingest_refusals_bounded
AFTER INSERT ON evidence_ingest_refusals
BEGIN
    DELETE FROM evidence_ingest_refusals WHERE id <= NEW.id - 200;
END;
"""

_SCHEMA = _DELIVERY_SCHEMA + _REGISTRATION_SCHEMA + _REFUSAL_SCHEMA

#: The column the outbox gains for a withdrawn registration copy, which the
#: registration schema cannot declare because the table predates it.
OUTBOX_WITHDRAWAL_COLUMN = "withdrawn_at_ms"

#: Rows the refusal history keeps; older rows are dropped by trigger.
INGEST_REFUSAL_RETENTION = 200

#: Closed outbox vocabulary; the delivery envelope has its own table.
OUTBOX_CHECKPOINT = "checkpoint"
OUTBOX_ANCHOR_REGISTRATION = "anchor_registration"
OUTBOX_ARTIFACT_TYPES = frozenset({OUTBOX_CHECKPOINT, OUTBOX_ANCHOR_REGISTRATION})
RETIRE_QUEUED = "queued"
RETIRE_REFUSED = "refused"

#: Where a faulted copy is held, and why it cannot be carried.
FAULT_HOLDER_OUTBOX = "outbox"
FAULT_HOLDER_OBLIGATION = "obligation"
FAULT_HOLDER_ENVELOPE = "envelope"
FAULT_UNREADABLE = "unreadable"
FAULT_DIGEST_MISMATCH = "digest_mismatch"

OBLIGATION_OPEN = "open"
OBLIGATION_CONFIRMED = "confirmed"
OBLIGATION_SUPERSEDED = "superseded"
OBLIGATION_CLOSED = "closed"

#: What applying a verified disposition did: applied, or a byte-identical
#: repetition of one already applied, which adds no state.
DISPOSITION_APPLIED = "applied"
DISPOSITION_REPEATED = "repeated"

# The chain row's immutable columns, exactly as evidence/v3 defines them.
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


class DispositionRefusedError(DeliveryLedgerError):
    """A verified disposition this ledger will not apply; `reason` says why."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _reoffer_due_row(row: sqlite3.Row, at_ms: int) -> bool:
    """Whether an obligation's next re-offer is due.

    The delay runs from the previous attempted offer of these bytes: the last
    re-offer when there has been one, otherwise the courier copy's last
    handoff attempt. Sealing time is never the anchor. A row with no attempt
    recorded, or whose schedule cannot be computed, is due rather than an
    error in the drain.
    """
    try:
        last = row["last_offer_ms"]
        if last is None:
            last = row["copy_attempt_ms"]
        if last is None:
            return True
        return reoffer_due(int(row["offers"]), int(last), at_ms=at_ms)
    except (TypeError, ValueError, OverflowError):
        return True


def copy_fault(wire: bytes, digest: str) -> str | None:
    """Why a retained copy's bytes cannot be carried as sealed, or None."""
    try:
        wire.decode("utf-8")
    except UnicodeDecodeError:
        return FAULT_UNREADABLE
    if "sha256:" + hashlib.sha256(wire).hexdigest() != digest:
        return FAULT_DIGEST_MISMATCH
    return None


def _copy(row: sqlite3.Row, name: str) -> dict[str, Any]:
    """One retained copy, its text columns read as bytes so none can fail the read.

    `<name>_bytes` is exactly what is stored; `<name>_json` is its text, or
    None when it is not UTF-8; the digest is decoded leniently, so a damaged
    one reads as a digest that matches nothing.
    """
    out = dict(row)
    wire = bytes(out.pop(f"{name}_bytes"))
    out[f"{name}_bytes"] = wire
    try:
        out[f"{name}_json"] = wire.decode("utf-8")
    except UnicodeDecodeError:
        out[f"{name}_json"] = None
    digest_field = "envelope_digest" if name == "envelope" else "artifact_digest"
    out[digest_field] = bytes(out.pop("digest_bytes")).decode("utf-8", "replace")
    return out


def read_current_anchor(db_path: str | Path) -> dict[str, Any] | None:
    """The anchor a runtime last recorded in this evidence store, read-only.

    Creates nothing: an absent file is None, and a store with no write-ahead
    log is read immutable, as the state store's read-only tools do.
    """
    path = Path(db_path)
    if not path.is_file() or path.stat().st_size == 0:
        return None
    mode = "ro" if Path(f"{path}-wal").exists() else "ro&immutable=1"
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode={mode}", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        try:
            row = conn.execute(
                "SELECT device_id, anchor_epoch_id, key_id, pubkey_hex, posture"
                " FROM evidence_current_anchor WHERE id = 1"
            ).fetchone()
        except sqlite3.OperationalError as exc:
            if str(exc).startswith("no such table"):
                return None
            raise
        return None if row is None else dict(row)
    finally:
        conn.close()


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
        self._add_outbox_withdrawal_column()
        self._boot_id: int | None = None

    def _add_outbox_withdrawal_column(self) -> None:
        """`withdrawn_at_ms` on an outbox created before the column existed.

        Added rather than folded into the retirement outcome: the shipped
        table's CHECK admits only `queued` and `refused`, and a withdrawn
        courier copy was neither.
        """
        columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(evidence_outbox)")
        }
        if "withdrawn_at_ms" not in columns:
            self._connection.execute(
                "ALTER TABLE evidence_outbox ADD COLUMN withdrawn_at_ms INTEGER"
            )
        self._connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS evidence_outbox_withdrawal_is_final
            BEFORE UPDATE ON evidence_outbox
            WHEN OLD.withdrawn_at_ms IS NOT NULL
             AND NEW.withdrawn_at_ms IS NOT OLD.withdrawn_at_ms
            BEGIN
                SELECT RAISE(ABORT, 'a withdrawn courier copy cannot be restored');
            END
            """
        )
        # Every drain reads the few copies still waiting from an outbox that
        # only grows; retired rows are the bulk and are never read again.
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_evidence_outbox_waiting
                ON evidence_outbox (id)
             WHERE retired_at_ms IS NULL AND withdrawn_at_ms IS NULL
            """
        )

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

    def issue_checkpoint(self, *, issued_at_ms: int) -> sqlite3.Row:
        """Sign a checkpoint and retain it for the courier, durably.

        Signing without retaining would produce an obligation the authority
        never hears of, and a shutdown checkpoint that is signed and dropped
        makes an orderly stop indistinguishable from a crash.
        """
        checkpoint = self.checkpoint(issued_at_ms=issued_at_ms)
        return self.queue_artifact(
            OUTBOX_CHECKPOINT, canonical_json(checkpoint), created_at_ms=issued_at_ms
        )

    # -- outbox ----------------------------------------------------------

    def queue_artifact(
        self, artifact_type: str, wire: bytes, *, created_at_ms: int
    ) -> sqlite3.Row:
        """Retain one signed artifact's exact bytes for carriage. Idempotent."""
        if artifact_type not in OUTBOX_ARTIFACT_TYPES:
            raise DeliveryLedgerError(
                f"{artifact_type!r} is not an artifact this outbox carries"
            )
        try:
            decoded = json.loads(wire)
        except ValueError as exc:
            raise DeliveryLedgerError("a queued artifact must be JSON") from exc
        if not isinstance(decoded, dict) or decoded.get("device_id") != self._device_id:
            raise DeliveryLedgerError(
                "a queued artifact must name the device this ledger is bound to"
            )
        digest = "sha256:" + hashlib.sha256(wire).hexdigest()
        self._connection.execute(
            """
            INSERT OR IGNORE INTO evidence_outbox (
                artifact_type, artifact_json, artifact_digest, created_at_ms
            ) VALUES (?, ?, ?, ?)
            """,
            (artifact_type, wire.decode("utf-8"), digest, int(created_at_ms)),
        )
        row = self.find_artifact(digest)
        if row is None:  # pragma: no cover - the insert committed
            raise DeliveryLedgerError("the queued artifact could not be read back")
        return row

    def find_artifact(self, artifact_digest: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._connection.execute(
            "SELECT * FROM evidence_outbox WHERE artifact_digest = ?",
            (str(artifact_digest),),
        ).fetchone()
        return row

    def pending_artifacts(
        self,
        limit: int = 100,
        *,
        artifact_type: str | None = None,
        after_id: int = 0,
        only_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Queued artifacts no acknowledgement has retired, oldest first.

        Narrowed by type and by position in the SQL itself, so every row the
        limit admits is one the caller can carry; and by `only_id` to ask
        whether one copy is still carriable, under the same conditions.

        Text columns are read as bytes (`_copy`): a row whose bytes are not
        UTF-8 must not make this query fail. A copy with a recorded fault is
        not carried.

        A copy an evidence disposition has stopped is not carried: a
        checkpoint or registration whose epoch, or whose identity, is under an
        offer stop, and a registration a `retained_pending` suspended. Nor is
        a copy sealed under another device identity, which the courier can
        only refuse. The outbox holds only those two types, so a delivery
        envelope's handoff is unaffected by any stop.

        A copy is another identity's only when its bytes are a JSON object
        naming a text `device_id` other than this one. Anything else -- bytes
        that are not JSON, a non-object, a missing or non-text `device_id` --
        is carried, so the courier's refusal can retire it, and bytes that are
        not JSON are never read as JSON here: one such row must not make this
        query, and with it the route, fail.
        """
        rows = self._connection.execute(
            """
                SELECT b.id, b.artifact_type, b.created_at_ms, b.attempts,
                       b.last_attempt_ms,
                       CAST(b.artifact_json AS BLOB) AS artifact_bytes,
                       CAST(b.artifact_digest AS BLOB) AS digest_bytes
                  FROM evidence_outbox AS b
                 WHERE b.retired_at_ms IS NULL AND b.withdrawn_at_ms IS NULL
                   AND b.id > ?
                   AND (? IS NULL OR b.id = ?)
                   AND (? IS NULL OR b.artifact_type = ?)
                   AND NOT EXISTS (
                       SELECT 1 FROM evidence_artifact_fault AS f
                        WHERE f.holder = 'outbox' AND f.holder_id = b.id
                   )
                   AND NOT COALESCE(
                       CASE WHEN json_valid(b.artifact_json)
                            THEN json_type(b.artifact_json, '$.device_id') = 'text'
                             AND json_extract(b.artifact_json, '$.device_id') <> ?
                       END, 0)
                   AND NOT EXISTS (
                       SELECT 1 FROM evidence_offer_stop AS s
                        WHERE s.device_id = CASE WHEN json_valid(b.artifact_json)
                              THEN json_extract(b.artifact_json, '$.device_id') END
                          AND (s.scope = 'identity'
                               OR s.anchor_epoch_id = CASE
                                  WHEN json_valid(b.artifact_json)
                                  THEN json_extract(b.artifact_json, '$.anchor_epoch_id')
                                  END)
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM evidence_registration_obligation AS o
                        WHERE o.artifact_digest = b.artifact_digest
                          AND o.suspended_at_ms IS NOT NULL
                   )
                 ORDER BY b.id
                 LIMIT ?
                """,
            (
                int(after_id),
                only_id,
                only_id,
                artifact_type,
                artifact_type,
                self._device_id,
                int(limit),
            ),
        )
        return [_copy(row, "artifact") for row in rows]

    def foreign_identity_pending_count(self) -> int:
        """Unretired copies sealed under another device identity, never carried."""
        row = self._connection.execute(
            """
            SELECT COUNT(*) AS n FROM evidence_outbox
             WHERE retired_at_ms IS NULL AND withdrawn_at_ms IS NULL
               AND COALESCE(
                   CASE WHEN json_valid(artifact_json)
                        THEN json_type(artifact_json, '$.device_id') = 'text'
                         AND json_extract(artifact_json, '$.device_id') <> ?
                   END, 0)
            """,
            (self._device_id,),
        ).fetchone()
        return int(row["n"])

    def record_artifact_fault(
        self, holder: str, holder_id: int, *, reason: str, at_ms: int
    ) -> None:
        """Take a copy that cannot be carried as sealed off the route, once."""
        self._connection.execute(
            """
            INSERT OR IGNORE INTO evidence_artifact_fault (
                holder, holder_id, reason, observed_at_ms
            ) VALUES (?, ?, ?, ?)
            """,
            (str(holder), int(holder_id), str(reason), int(at_ms)),
        )

    def note_artifact_attempt(self, artifact_digest: str, *, at_ms: int) -> None:
        self._connection.execute(
            """
            UPDATE evidence_outbox
               SET attempts = attempts + 1, last_attempt_ms = ?
             WHERE artifact_digest = ?
            """,
            (int(at_ms), str(artifact_digest)),
        )

    def retire_artifact(
        self, artifact_digest: str, *, outcome: str, at_ms: int
    ) -> bool:
        """Release an artifact the courier's queue now owns, or has refused.

        Returns False when nothing was retired: an unknown digest, or one
        already retired, which is what a re-delivered acknowledgement produces.
        """
        if outcome not in (RETIRE_QUEUED, RETIRE_REFUSED):
            raise DeliveryLedgerError(f"{outcome!r} is not a retirement outcome")
        cursor = self._connection.execute(
            """
            UPDATE evidence_outbox
               SET retired_at_ms = ?, retire_outcome = ?
             WHERE artifact_digest = ? AND retired_at_ms IS NULL
            """,
            (int(at_ms), outcome, str(artifact_digest)),
        )
        return cursor.rowcount == 1

    # -- registration obligation -----------------------------------------

    def open_registration_obligation(self, anchor_epoch_id: str) -> sqlite3.Row | None:
        """The open confirmation obligation for *anchor_epoch_id*, if any."""
        row: sqlite3.Row | None = self._connection.execute(
            """
            SELECT * FROM evidence_registration_obligation
             WHERE anchor_epoch_id = ? AND state = ?
            """,
            (str(anchor_epoch_id), OBLIGATION_OPEN),
        ).fetchone()
        return row

    def current_registration_obligation(
        self, anchor_epoch_id: str
    ) -> sqlite3.Row | None:
        """The latest attempt for *anchor_epoch_id* that a replacement has not superseded."""
        row: sqlite3.Row | None = self._connection.execute(
            """
            SELECT * FROM evidence_registration_obligation
             WHERE anchor_epoch_id = ? AND state <> ?
             ORDER BY id DESC
             LIMIT 1
            """,
            (str(anchor_epoch_id), OBLIGATION_SUPERSEDED),
        ).fetchone()
        return row

    def offers_stopped(self, anchor_epoch_id: str) -> bool:
        """Whether a disposition stopped this identity's, or this epoch's, offers."""
        row = self._connection.execute(
            """
            SELECT 1 FROM evidence_offer_stop
             WHERE device_id = ?
               AND (scope = 'identity' OR anchor_epoch_id = ?)
             LIMIT 1
            """,
            (self._device_id, str(anchor_epoch_id)),
        ).fetchone()
        return row is not None

    def offer_stop_scope(self, anchor_epoch_id: str) -> str | None:
        """`identity` or `epoch` when a stop covers this epoch; identity wins."""
        if self._identity_stopped():
            return "identity"
        row = self._connection.execute(
            """
            SELECT 1 FROM evidence_offer_stop
             WHERE device_id = ? AND scope = 'epoch' AND anchor_epoch_id = ?
             LIMIT 1
            """,
            (self._device_id, str(anchor_epoch_id)),
        ).fetchone()
        return "epoch" if row is not None else None

    def registration_confirmed(self, anchor_epoch_id: str, pubkey_hex: str) -> bool:
        """Whether a verified confirmation of a registration sealed here is held."""
        row = self._connection.execute(
            """
            SELECT 1 FROM evidence_registration_confirmation
             WHERE anchor_epoch_id = ? AND device_id = ? AND pubkey_hex = ?
            """,
            (str(anchor_epoch_id), self._device_id, str(pubkey_hex).lower()),
        ).fetchone()
        return row is not None

    def registration_sealed(self, anchor_epoch_id: str, pubkey_hex: str) -> bool:
        """Whether this device sealed a registration for this epoch and key."""
        row = self._connection.execute(
            """
            SELECT 1 FROM evidence_registration_obligation
             WHERE anchor_epoch_id = ? AND device_id = ? AND pubkey_hex = ?
             LIMIT 1
            """,
            (str(anchor_epoch_id), self._device_id, str(pubkey_hex).lower()),
        ).fetchone()
        return row is not None

    def record_current_anchor(self, *, posture: str, recorded_at_ms: int) -> None:
        """Record the anchor this ledger seals under, for a local tool to bind to."""
        self._connection.execute(
            """
            INSERT INTO evidence_current_anchor (
                id, device_id, anchor_epoch_id, key_id, pubkey_hex, posture,
                recorded_at_ms
            ) VALUES (1, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                device_id       = excluded.device_id,
                anchor_epoch_id = excluded.anchor_epoch_id,
                key_id          = excluded.key_id,
                pubkey_hex      = excluded.pubkey_hex,
                posture         = excluded.posture,
                recorded_at_ms  = excluded.recorded_at_ms
            """,
            (
                self._device_id,
                self._anchor_epoch_id,
                self._key_id,
                self._key.public_key_hex,
                str(posture),
                int(recorded_at_ms),
            ),
        )

    def seal_registration(
        self, registration: dict[str, Any], *, sealed_at_ms: int
    ) -> sqlite3.Row:
        """Retain a signed registration as its obligation and its courier copy.

        One transaction, so the obligation never exists without the handoff
        copy or the reverse. An open obligation for the same epoch under a
        different reference is superseded in the same transaction: the
        replacement reference is what the operator recorded with ``--force``.
        """
        if registration.get("device_id") != self._device_id:
            raise DeliveryLedgerError(
                "a registration must name the device this ledger is bound to"
            )
        wire = canonical_json(registration)
        digest = "sha256:" + hashlib.sha256(wire).hexdigest()
        epoch = str(registration["anchor_epoch_id"])
        reference = str(registration["commissioning_digest"])
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.open_registration_obligation(epoch)
            if current is not None and str(current["commissioning_reference"]) == (
                reference
            ):
                self._connection.execute("ROLLBACK")
                return current
            if current is not None:
                self._connection.execute(
                    """
                    UPDATE evidence_registration_obligation
                       SET state = ?, closed_at_ms = ?
                     WHERE id = ?
                    """,
                    (OBLIGATION_SUPERSEDED, int(sealed_at_ms), int(current["id"])),
                )
                # The superseded registration's courier copy is withdrawn with
                # it: carrying bytes the operator replaced would ask the
                # authority to retain the reference they corrected.
                self._connection.execute(
                    """
                    UPDATE evidence_outbox
                       SET withdrawn_at_ms = ?
                     WHERE artifact_digest = ?
                       AND retired_at_ms IS NULL
                       AND withdrawn_at_ms IS NULL
                    """,
                    (int(sealed_at_ms), str(current["artifact_digest"])),
                )
            self._connection.execute(
                """
                INSERT INTO evidence_registration_obligation (
                    device_id, anchor_epoch_id, pubkey_hex, commissioning_reference,
                    artifact_json, artifact_digest, sealed_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self._device_id,
                    epoch,
                    str(registration["pubkey_hex"]).lower(),
                    reference,
                    wire.decode("utf-8"),
                    digest,
                    int(sealed_at_ms),
                ),
            )
            self._connection.execute(
                """
                INSERT OR IGNORE INTO evidence_outbox (
                    artifact_type, artifact_json, artifact_digest, created_at_ms
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    OUTBOX_ANCHOR_REGISTRATION,
                    wire.decode("utf-8"),
                    digest,
                    int(sealed_at_ms),
                ),
            )
            self._connection.execute("COMMIT")
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        sealed = self.open_registration_obligation(epoch)
        if sealed is None:  # pragma: no cover - the insert committed
            raise DeliveryLedgerError("the sealed registration could not be read back")
        return sealed

    def registration_reoffers_due(
        self, *, at_ms: int, limit: int = 100, only_id: int | None = None
    ) -> list[dict[str, Any]]:
        """Open obligations whose courier copy is retired and whose delay has run.

        While the handoff copy is still pending the outbox carries it on its
        own schedule; offering the obligation as well would carry it twice.
        Each epoch's obligation is independent: one left open under an earlier
        epoch is re-offered under the same rules until it resolves, because
        evidence sealed under that epoch is accepted only once it is confirmed.

        Whether the delay has run is computed here, not in SQL, so candidates
        are read page by page until `limit` due ones are found: a page of
        obligations not yet due must not hide one that is. `only_id` asks
        whether one obligation is still due to be offered.
        """
        due: list[dict[str, Any]] = []
        after_id = 0
        while len(due) < limit:
            rows = self._connection.execute(
                """
                SELECT o.id, o.device_id, o.anchor_epoch_id, o.sealed_at_ms,
                       o.offers, o.last_offer_ms,
                       (SELECT MAX(b.last_attempt_ms) FROM evidence_outbox AS b
                         WHERE b.artifact_digest = o.artifact_digest)
                         AS copy_attempt_ms,
                       CAST(o.artifact_json AS BLOB) AS artifact_bytes,
                       CAST(o.artifact_digest AS BLOB) AS digest_bytes
                  FROM evidence_registration_obligation AS o
                 WHERE o.state = ?
                   AND o.device_id = ?
                   AND o.suspended_at_ms IS NULL
                   AND o.id > ?
                   AND (? IS NULL OR o.id = ?)
                   AND NOT EXISTS (
                       SELECT 1 FROM evidence_artifact_fault AS f
                        WHERE f.holder = 'obligation' AND f.holder_id = o.id
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM evidence_outbox AS b
                        WHERE b.artifact_digest = o.artifact_digest
                          AND b.retired_at_ms IS NULL
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM evidence_offer_stop AS s
                        WHERE s.device_id = o.device_id
                          AND (s.scope = 'identity' OR s.anchor_epoch_id = o.anchor_epoch_id)
                   )
                 ORDER BY o.id
                 LIMIT ?
                """,
                (
                    OBLIGATION_OPEN,
                    self._device_id,
                    after_id,
                    only_id,
                    only_id,
                    int(limit),
                ),
            ).fetchall()
            if not rows:
                break
            after_id = int(rows[-1]["id"])
            due.extend(
                _copy(row, "artifact") for row in rows if _reoffer_due_row(row, at_ms)
            )
        return due[:limit]

    def _apply_verified_disposition(
        self, disposition: VerifiedDisposition, *, at_ms: int
    ) -> str:
        """Verification steps 4 to 6 and the effect, in one transaction.

        Not a public boundary: it trusts the signature it is told was checked.
        It checks everything local state can decide -- the device, that the
        triggering digest names an artifact this device sealed for delivery
        under the epoch the disposition names, and whether the effect is
        already in force -- and raises `DispositionRefusedError` otherwise,
        changing nothing.
        """
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            outcome = self._apply_disposition_in_transaction(disposition, at_ms)
            self._connection.execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        return outcome

    def _apply_disposition_in_transaction(
        self, disposition: VerifiedDisposition, at_ms: int
    ) -> str:
        applied = self._connection.execute(
            "SELECT 1 FROM evidence_disposition WHERE digest = ?",
            (str(disposition.digest),),
        ).fetchone()
        if applied is not None:
            return DISPOSITION_REPEATED
        if disposition.device_id != self._device_id:
            raise DispositionRefusedError(
                "binding_mismatch", "the disposition names another device"
            )
        sealed = self.sealed_artifact(disposition.triggering_digest)
        if sealed is None:
            raise DispositionRefusedError(
                "binding_mismatch",
                "the disposition names an artifact this device did not seal",
            )
        artifact_type, artifact_epoch, artifact_device = sealed
        if artifact_device != self._device_id:
            raise DispositionRefusedError(
                "binding_mismatch",
                "the disposition names an artifact another device identity sealed",
            )
        if disposition.anchor_epoch_id not in ("", artifact_epoch):
            raise DispositionRefusedError(
                "binding_mismatch",
                "the disposition names an epoch its artifact does not",
            )
        value = disposition.value
        registration = artifact_type == OUTBOX_ANCHOR_REGISTRATION
        if value is DispositionValue.RETAINED_PENDING and not registration:
            raise DispositionRefusedError(
                "binding_mismatch", "retained_pending names no anchor registration"
            )

        row: sqlite3.Row | None = None
        if registration and value in (
            DispositionValue.RETAINED_PENDING,
            DispositionValue.ARTIFACT_TERMINAL,
        ):
            row = self._connection.execute(
                "SELECT * FROM evidence_registration_obligation WHERE artifact_digest = ?",
                (str(disposition.triggering_digest),),
            ).fetchone()
            if row is None or str(row["state"]) != OBLIGATION_OPEN:
                raise DispositionRefusedError(
                    "superseded", "that registration is already confirmed or closed"
                )
        if value is DispositionValue.EPOCH_REPROVISIONING_REQUIRED and (
            self.offers_stopped(artifact_epoch)
        ):
            raise DispositionRefusedError(
                "superseded", "offers under that epoch are already stopped"
            )
        if value is DispositionValue.IDENTITY_REPLACEMENT_REQUIRED and (
            self._identity_stopped()
        ):
            raise DispositionRefusedError(
                "superseded", "offers for this identity are already stopped"
            )

        if value is DispositionValue.RETAINED_PENDING:
            assert row is not None
            if row["suspended_at_ms"] is None:
                self._connection.execute(
                    "UPDATE evidence_registration_obligation"
                    " SET suspended_at_ms = ? WHERE id = ?",
                    (int(at_ms), int(row["id"])),
                )
        elif value is DispositionValue.ARTIFACT_TERMINAL and row is not None:
            self._connection.execute(
                """
                UPDATE evidence_registration_obligation
                   SET state = ?, closed_at_ms = ?, closed_reason = ?
                 WHERE id = ?
                """,
                (OBLIGATION_CLOSED, int(at_ms), value.value, int(row["id"])),
            )
            self._connection.execute(
                """
                UPDATE evidence_outbox
                   SET withdrawn_at_ms = ?
                 WHERE artifact_digest = ?
                   AND retired_at_ms IS NULL
                   AND withdrawn_at_ms IS NULL
                """,
                (int(at_ms), str(disposition.triggering_digest)),
            )
        elif value in (
            DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
            DispositionValue.IDENTITY_REPLACEMENT_REQUIRED,
        ):
            identity = value is DispositionValue.IDENTITY_REPLACEMENT_REQUIRED
            self._connection.execute(
                """
                INSERT INTO evidence_offer_stop (
                    scope, device_id, anchor_epoch_id, disposition,
                    artifact_digest, stopped_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "identity" if identity else "epoch",
                    self._device_id,
                    None if identity else artifact_epoch,
                    value.value,
                    str(disposition.triggering_digest),
                    int(at_ms),
                ),
            )
        self._connection.execute(
            """
            INSERT INTO evidence_disposition (
                digest, triggering_digest, artifact_type, device_id,
                anchor_epoch_id, scope, disposition, decided_at_ms, key_id,
                observed_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(disposition.digest),
                str(disposition.triggering_digest),
                artifact_type,
                self._device_id,
                artifact_epoch,
                disposition.scope.value,
                value.value,
                int(disposition.decided_at_ms),
                str(disposition.key_id),
                int(at_ms),
            ),
        )
        return DISPOSITION_APPLIED

    def sealed_artifact(self, digest: str) -> tuple[str, str, str] | None:
        """The type, epoch and device of an artifact sealed for delivery here.

        Answered from the tables that hold every sealed artifact for the life
        of the identity, none of which permits deletion: registrations and
        checkpoints in the outbox, envelopes in the delivery ledger. The device
        is the one the artifact names, which is not necessarily this ledger's:
        the same files can outlive a change of device identity.
        """
        row = self._connection.execute(
            "SELECT artifact_type, artifact_json FROM evidence_outbox"
            " WHERE artifact_digest = ?",
            (str(digest),),
        ).fetchone()
        if row is not None:
            try:
                artifact = json.loads(str(row["artifact_json"]))
            except ValueError:
                return None
            if not isinstance(artifact, dict):
                return None
            return (
                str(row["artifact_type"]),
                str(artifact.get("anchor_epoch_id") or ""),
                str(artifact.get("device_id") or ""),
            )
        envelope = self._connection.execute(
            "SELECT anchor_epoch_id, device_id FROM evidence_delivery_ledger"
            " WHERE envelope_digest = ?",
            (str(digest),),
        ).fetchone()
        if envelope is not None:
            return (
                "delivery_envelope",
                str(envelope["anchor_epoch_id"]),
                str(envelope["device_id"]),
            )
        return None

    def _identity_stopped(self) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM evidence_offer_stop"
            " WHERE device_id = ? AND scope = 'identity' LIMIT 1",
            (self._device_id,),
        ).fetchone()
        return row is not None

    def last_disposition(self) -> sqlite3.Row | None:
        """The most recently applied disposition, if any."""
        row: sqlite3.Row | None = self._connection.execute(
            "SELECT disposition, scope, observed_at_ms FROM evidence_disposition"
            " ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        return row

    def note_registration_offer(self, artifact_digest: str, *, at_ms: int) -> None:
        """Record one re-offer of an open obligation's sealed bytes."""
        self._connection.execute(
            """
            UPDATE evidence_registration_obligation
               SET offers = offers + 1, last_offer_ms = ?
             WHERE artifact_digest = ? AND state = ?
            """,
            (int(at_ms), str(artifact_digest), OBLIGATION_OPEN),
        )

    # -- ingest refusals -------------------------------------------------

    def record_ingest_refusal(
        self, *, artifact_type: str, reason: str, detail: str, observed_at_ms: int
    ) -> None:
        """Retain one refused authority artifact for the operator's diagnosis."""
        self._connection.execute(
            """
            INSERT INTO evidence_ingest_refusals
                (artifact_type, reason, detail, observed_at_ms)
            VALUES (?, ?, ?, ?)
            """,
            (str(artifact_type), str(reason), str(detail)[:256], int(observed_at_ms)),
        )

    def ingest_refusals(
        self, limit: int = INGEST_REFUSAL_RETENTION
    ) -> list[sqlite3.Row]:
        """Retained refusals, oldest first."""
        return list(
            self._connection.execute(
                "SELECT * FROM evidence_ingest_refusals ORDER BY id LIMIT ?",
                (int(limit),),
            )
        )

    def ingest_refusal_summary(self) -> tuple[int, sqlite3.Row | None]:
        """How many refusals are retained, and the most recent one."""
        count = int(
            self._connection.execute(
                "SELECT COUNT(*) AS n FROM evidence_ingest_refusals"
            ).fetchone()["n"]
        )
        last: sqlite3.Row | None = self._connection.execute(
            "SELECT * FROM evidence_ingest_refusals ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return count, last

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
                "fields evidence/v3 defines"
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

    def _apply_verified_epoch_confirmation(
        self,
        device_id: str,
        *,
        anchor_epoch_id: str,
        pubkey_hex: str,
        actor: str,
        confirmed_at_ms: int,
        key_id: str,
        closed_at_ms: int,
    ) -> int:
        """Persist a verified confirmation and close the obligation it answers.

        Bound to a registration this device sealed for that epoch and key, and
        refused otherwise: a confirmation is an answer, and one naming nothing
        this device asked for answers nothing. The active epoch moves only
        when the confirmed epoch is the one this ledger seals under, so a late
        confirmation for an earlier epoch never rolls it back.

        One transaction: a confirmation recorded without closing its
        obligation would leave the device re-offering an applied registration,
        and an obligation closed without the confirmation would report
        `confirmed` with nothing held. Returns the obligations closed.
        """
        pubkey = str(pubkey_hex).lower()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            if str(device_id) != self._device_id or not self.registration_sealed(
                anchor_epoch_id, pubkey
            ):
                raise DeliveryLedgerError(
                    "the confirmation names no registration this device sealed"
                )
            self._connection.execute(
                """
                INSERT OR IGNORE INTO evidence_registration_confirmation (
                    anchor_epoch_id, device_id, pubkey_hex, actor,
                    confirmed_at_ms, key_id, applied_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(anchor_epoch_id),
                    self._device_id,
                    pubkey,
                    str(actor),
                    int(confirmed_at_ms),
                    str(key_id),
                    int(closed_at_ms),
                ),
            )
            if str(anchor_epoch_id) == self._anchor_epoch_id:
                self._apply_verified_epoch(
                    device_id,
                    anchor_epoch_id=anchor_epoch_id,
                    pubkey_hex=pubkey,
                    actor=actor,
                    confirmed_at_ms=confirmed_at_ms,
                    key_id=key_id,
                )
            cursor = self._connection.execute(
                """
                UPDATE evidence_registration_obligation
                   SET state = ?, closed_at_ms = ?
                 WHERE anchor_epoch_id = ? AND pubkey_hex = ? AND state = ?
                """,
                (
                    OBLIGATION_CONFIRMED,
                    int(closed_at_ms),
                    str(anchor_epoch_id),
                    pubkey,
                    OBLIGATION_OPEN,
                ),
            )
            closed = cursor.rowcount
            self._connection.execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        return closed

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
        evidence/v3 attestation gap against the action row, not a hole in a
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

    def find_by_envelope_digest(self, envelope_digest: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._connection.execute(
            "SELECT * FROM evidence_delivery_ledger WHERE envelope_digest = ?",
            (str(envelope_digest),),
        ).fetchone()
        return row

    def awaiting_custody(
        self, limit: int = 100, *, after_seq: int = 0, only_seq: int | None = None
    ) -> list[dict[str, Any]]:
        """Sealed envelopes no courier has acknowledged holding, oldest first.

        What the publisher carries. Retained until a verified custody
        acknowledgement arrives through ingest: a `queued` transport
        acknowledgement does not release an envelope, per gateway-api/v1.
        `after_seq` pages through them; `only_seq` asks whether one envelope
        is still carriable, under the same conditions.

        An envelope whose epoch or identity an evidence disposition stopped
        is not handed off: it stays sealed and durable here, its delivery
        state `stopped`, which is derived from the stop record rather than
        written onto the envelope, so nothing sealed is rewritten. Nor is one
        with a recorded fault. The envelope is read as bytes (`_copy`), so a
        damaged row cannot make this query fail.
        """
        rows = self._connection.execute(
            """
                SELECT l.local_seq, l.chain_seq, l.sealed_at_ms, l.attempts,
                       l.last_attempt_ms,
                       CAST(l.envelope_json AS BLOB) AS envelope_bytes,
                       CAST(l.envelope_digest AS BLOB) AS digest_bytes
                  FROM evidence_delivery_ledger AS l
                 WHERE l.custody_state = ?
                   AND l.local_seq > ?
                   AND (? IS NULL OR l.local_seq = ?)
                   AND NOT EXISTS (
                       SELECT 1 FROM evidence_artifact_fault AS f
                        WHERE f.holder = 'envelope' AND f.holder_id = l.local_seq
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM evidence_offer_stop AS s
                        WHERE s.device_id = l.device_id
                          AND (s.scope = 'identity'
                               OR s.anchor_epoch_id = l.anchor_epoch_id)
                   )
                 ORDER BY l.local_seq
                 LIMIT ?
                """,
            (CUSTODY_NONE, int(after_seq), only_seq, only_seq, int(limit)),
        )
        return [_copy(row, "envelope") for row in rows]

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

    def awaiting_custody_count(self) -> int:
        """Sealed envelopes the courier has not acknowledged holding.

        This counts the delivery ledger, not the chain. A chain row exists the
        moment an action is signed; an envelope exists only once sealing
        completes, and counting chain rows would report evidence as awaiting a
        courier before there was anything for a courier to take.

        Custody is deliberately the measure rather than receipt. Custody says a
        courier holds the bytes; a receipt says the authority accepted them, and
        those degrade for different reasons. A rising custody count means
        delivery has stalled at the first hop, which is the failure this metric
        exists to make visible.

        An envelope under a stop is still counted: it is sealed and no courier
        holds it, which is what the field means; `stopped_local` says how many
        of them a stop keeps here.
        """
        row = self._connection.execute(
            """
            SELECT COUNT(*) AS pending FROM evidence_delivery_ledger AS l
             WHERE l.custody_state = 'none'
            """
        ).fetchone()
        return int(row["pending"])

    def stopped_local(self) -> tuple[int, int, int | None]:
        """Count, bytes and earliest entry into stopped custody, across epochs.

        Retained artifacts a durable stop covers, matched by the predicate the
        carry queries exclude them by: envelopes no courier holds, and outbox
        copies neither retired nor withdrawn. An artifact entered stopped
        custody when the first stop covering it was recorded, or when it was
        sealed if that was later. Diagnostics only.
        """
        row = self._connection.execute(
            """
            WITH stopped (size, since) AS (
                SELECT length(CAST(l.envelope_json AS BLOB)),
                       MAX(l.sealed_at_ms, (
                           SELECT MIN(s.stopped_at_ms) FROM evidence_offer_stop AS s
                            WHERE s.device_id = l.device_id
                              AND (s.scope = 'identity'
                                   OR s.anchor_epoch_id = l.anchor_epoch_id)))
                  FROM evidence_delivery_ledger AS l
                 WHERE l.custody_state = 'none'
                   AND EXISTS (
                       SELECT 1 FROM evidence_offer_stop AS s
                        WHERE s.device_id = l.device_id
                          AND (s.scope = 'identity'
                               OR s.anchor_epoch_id = l.anchor_epoch_id)
                   )
                UNION ALL
                SELECT length(CAST(b.artifact_json AS BLOB)),
                       MAX(b.created_at_ms, (
                           SELECT MIN(s.stopped_at_ms) FROM evidence_offer_stop AS s
                            WHERE s.device_id = CASE WHEN json_valid(b.artifact_json)
                                  THEN json_extract(b.artifact_json, '$.device_id') END
                              AND (s.scope = 'identity'
                                   OR s.anchor_epoch_id = CASE
                                      WHEN json_valid(b.artifact_json)
                                      THEN json_extract(b.artifact_json, '$.anchor_epoch_id')
                                      END)))
                  FROM evidence_outbox AS b
                 WHERE b.retired_at_ms IS NULL AND b.withdrawn_at_ms IS NULL
                   AND EXISTS (
                       SELECT 1 FROM evidence_offer_stop AS s
                        WHERE s.device_id = CASE WHEN json_valid(b.artifact_json)
                              THEN json_extract(b.artifact_json, '$.device_id') END
                          AND (s.scope = 'identity'
                               OR s.anchor_epoch_id = CASE
                                  WHEN json_valid(b.artifact_json)
                                  THEN json_extract(b.artifact_json, '$.anchor_epoch_id')
                                  END)
                   )
            )
            SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS size, MIN(since) AS since
              FROM stopped
            """
        ).fetchone()
        count = int(row["n"])
        return count, int(row["size"]), (None if count == 0 else int(row["since"]))

    def awaiting_receipt_count(self) -> int:
        """Envelopes held by a courier but not yet receipted by the authority.

        Separate from the custody count on purpose: conflating them would hide
        which hop is failing, and the two have different remedies.
        """
        row = self._connection.execute(
            "SELECT COUNT(*) AS pending FROM evidence_delivery_ledger "
            "WHERE custody_state = 'held' AND receipt_state = 'none'"
        ).fetchone()
        return int(row["pending"])

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
