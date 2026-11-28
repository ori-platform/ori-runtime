# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The evidence delivery ledger's SQLite schema: its tables and triggers.

Held apart from `ledger.py` so the ledger's logic stays within its size
ceiling; nothing here runs, it is the text the ledger executes at open.
"""

# Recorded custody is final, this runtime's own record time included, so a
# redelivered acknowledgement cannot make a held envelope look newer.
CUSTODY_FINAL_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS evidence_ledger_custody_is_final
BEFORE UPDATE ON evidence_delivery_ledger
WHEN OLD.custody_state = 'held'
 AND (NEW.custody_state <> 'held'
   OR NEW.custody_at_ms  IS NOT OLD.custody_at_ms
   OR NEW.custody_key_id IS NOT OLD.custody_key_id
   OR (OLD.custody_recorded_at_ms IS NOT NULL
       AND NEW.custody_recorded_at_ms IS NOT OLD.custody_recorded_at_ms))
BEGIN
    SELECT RAISE(ABORT, 'recorded custody cannot be withdrawn or rewritten');
END;
"""

_DELIVERY_SCHEMA = (
    """
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
    custody_recorded_at_ms INTEGER,
    receipt_state     TEXT    NOT NULL DEFAULT 'none',
    receipt_at_ms     INTEGER,
    receipt_key_id    TEXT,
    attempts          INTEGER NOT NULL DEFAULT 0,
    last_attempt_ms   INTEGER,
    last_failure      TEXT,
    courier_answer    TEXT
        CHECK (courier_answer IS NULL
               OR courier_answer IN ('queued', 'queue_full', 'refused')),
    courier_answer_at_ms INTEGER,
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

-- Found by the digest a courier acknowledgement or an authority disposition
-- names, once per message: by index, not by scanning a ledger that is never
-- pruned.
CREATE INDEX IF NOT EXISTS idx_evidence_ledger_envelope_digest
    ON evidence_delivery_ledger (envelope_digest);

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
"""
    + CUSTODY_FINAL_TRIGGER
    + """

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
)

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

SCHEMA = _DELIVERY_SCHEMA + _REGISTRATION_SCHEMA + _REFUSAL_SCHEMA
