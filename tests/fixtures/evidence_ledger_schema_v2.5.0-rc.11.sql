-- The evidence ledger schema as v2.5.0-rc.11 shipped it (`_SCHEMA` in
-- ori/security/evidence/ledger.py), comments removed. A store built by that
-- release is what this release must open and carry forward.

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
    CHECK (reason IN (
        'unreachable', 'timeout', 'refused', 'queue_full',
        'auth_failed', 'malformed_response', 'internal_error'
    )),
    FOREIGN KEY (local_seq) REFERENCES evidence_delivery_ledger (local_seq)
);

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

CREATE TRIGGER IF NOT EXISTS evidence_ledger_gaps_no_update
BEFORE UPDATE ON evidence_delivery_gaps
BEGIN
    SELECT RAISE(ABORT, 'observed delivery failures are immutable');
END;

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
