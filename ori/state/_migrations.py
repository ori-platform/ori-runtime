# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Schema creation and the in-place migrations `open()` applies."""

import logging
import sqlite3
from pathlib import Path
from typing import Optional

from ori.state._action_records import _action_record_members
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.state.store")


#: The commissioning reference, kept apart so what counts as registration state
#: in this store is derivable from its own DDL.
EVIDENCE_REFERENCE_DDL = """
-- The commissioning reference for one evidence epoch, recorded only by
-- `evidence commission` at the device. A reference is bound to the epoch it was
-- recorded against and is never rewritten to name another, so the epoch and
-- device columns are immutable and a row is never deleted; a replacement for
-- the same epoch changes only the reference.
CREATE TABLE IF NOT EXISTS evidence_commissioning_reference (
    anchor_epoch_id         TEXT    PRIMARY KEY,
    device_id               TEXT    NOT NULL,
    commissioning_reference TEXT    NOT NULL,
    recorded_at_ms          INTEGER NOT NULL,
    replacements            INTEGER NOT NULL DEFAULT 0,
    CHECK (
        length(anchor_epoch_id) = 71
        AND substr(anchor_epoch_id, 1, 7) = 'sha256:'
        AND substr(anchor_epoch_id, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (
        length(commissioning_reference) = 71
        AND substr(commissioning_reference, 1, 7) = 'sha256:'
        AND substr(commissioning_reference, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (length(device_id) > 0)
);

CREATE TRIGGER IF NOT EXISTS evidence_commissioning_reference_bound
BEFORE UPDATE ON evidence_commissioning_reference
WHEN OLD.anchor_epoch_id IS NOT NEW.anchor_epoch_id
  OR OLD.device_id IS NOT NEW.device_id
BEGIN
    SELECT RAISE(ABORT, 'a commissioning reference is bound to its epoch');
END;

CREATE TRIGGER IF NOT EXISTS evidence_commissioning_reference_no_delete
BEFORE DELETE ON evidence_commissioning_reference
BEGIN
    SELECT RAISE(ABORT, 'a commissioning reference cannot be deleted');
END;
"""


# A device's (boot_id, seq) restarts with a new key, so a fault is keyed under
# the key epoch it was verified against.
_FIRMWARE_FAULT_EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS firmware_fault_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id         TEXT    NOT NULL,
    key_epoch_id      TEXT    NOT NULL DEFAULT '',
    boot_id           INTEGER NOT NULL,
    seq               INTEGER NOT NULL,
    grade             TEXT    NOT NULL,
    posture           TEXT    NOT NULL,
    capability_hash   TEXT    NOT NULL,
    code              TEXT    NOT NULL,
    subject           TEXT    NOT NULL DEFAULT '',
    detail            TEXT    NOT NULL DEFAULT '',
    device_uptime_ms  INTEGER NOT NULL,
    received_at_ms    INTEGER NOT NULL,
    fault_json        TEXT    NOT NULL,
    UNIQUE(device_id, key_epoch_id, boot_id, seq)
);
"""


#: Kept apart so its legacy rebuild can recreate this one table inside its own
#: transaction, which `executescript` of the whole schema would commit.
_PROOF_OBSERVATION_DDL = """-- What the commissioning proof operation did, one row per command. The consent
-- and the actuation it permitted are the same record: the contract requires
-- them audited together, and a consent stored apart from its command is a
-- credential rather than an attestation. A row is opened when consent is given
-- and completed once the command has been issued, so a store failure cannot
-- leave a commanded coil unrecorded; a row whose commanded_at_ms is 0 records a
-- consent whose command never completed, which is itself the honest outcome.
CREATE TABLE IF NOT EXISTS commissioning_proof_observation (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    binding_hash         TEXT    NOT NULL,
    zone_id              TEXT    NOT NULL,
    gpio_pin             INTEGER NOT NULL,
    active_high          INTEGER NOT NULL,
    outcome              TEXT    NOT NULL,
    coil_state_commanded TEXT    NOT NULL,
    level_driven         TEXT    NOT NULL,
    consent_nonce        TEXT    NOT NULL,
    consented_at_ms      INTEGER NOT NULL,
    commanded_at_ms      INTEGER NOT NULL,
    command_issued       INTEGER NOT NULL,
    -- The runtime does not observe the coil, so nothing it records may say the
    -- commanded effect occurred. Enforced here rather than by convention.
    effect_verified      INTEGER NOT NULL DEFAULT 0 CHECK (effect_verified = 0),
    operator_attestation TEXT,
    release_requested    INTEGER NOT NULL,
    held_ms              INTEGER NOT NULL DEFAULT 0,
    observation_json     TEXT,
    outcome_note         TEXT
);
"""

_CORE_DDL = (
    EVIDENCE_REFERENCE_DDL
    + """
CREATE TABLE IF NOT EXISTS reasoning_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    trigger_name   TEXT    NOT NULL,
    tier_used      TEXT    NOT NULL,
    prompt         TEXT    NOT NULL DEFAULT '',
    response       TEXT    NOT NULL,
    confidence     REAL    NOT NULL,
    action_tier    TEXT    NOT NULL,
    device_id      TEXT    NOT NULL DEFAULT '',
    model          TEXT    NOT NULL DEFAULT '',
    tokens_used    INTEGER NOT NULL DEFAULT 0,
    latency_ms     INTEGER NOT NULL DEFAULT 0,
    proposed_action TEXT,
    reasoning_status TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL DEFAULT '',
    timestamp      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reasoning_log_device_timestamp
    ON reasoning_log (device_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_reasoning_log_correlation_id
    ON reasoning_log (correlation_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS override_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    trigger_name      TEXT    NOT NULL,
    action            TEXT    NOT NULL,
    reason            TEXT    NOT NULL DEFAULT '',
    operator_response TEXT,
    override_type     TEXT    NOT NULL,   -- 'rejection' | 'autonomous_tier_d'
    device_id         TEXT    NOT NULL DEFAULT '',
    timestamp         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS action_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    action_name       TEXT    NOT NULL,
    tier              TEXT    NOT NULL,
    executed          INTEGER NOT NULL,   -- 0 or 1
    approved          INTEGER,            -- NULL for Tiers A/B/D, 0/1 for C
    action_taken      TEXT    NOT NULL,
    operator_response TEXT,
    proposal_id       TEXT    NOT NULL DEFAULT '',
    safe_default_used INTEGER NOT NULL DEFAULT 0,
    device_id         TEXT    NOT NULL DEFAULT '',
    sensor_id         TEXT    NOT NULL DEFAULT '',
    sensor_type       TEXT    NOT NULL DEFAULT '',
    input_attestation_grade TEXT NOT NULL DEFAULT 'unattested',
    input_posture     TEXT    NOT NULL DEFAULT '',
    input_firmware_device_id TEXT NOT NULL DEFAULT '',
    input_firmware_boot_id INTEGER NOT NULL DEFAULT 0,
    input_firmware_seq INTEGER NOT NULL DEFAULT 0,
    -- The provisioning registration snapshot, including approval
    -- provenance, captured at attestation time. Persisted so a crash or
    -- signing outage does not lose it: reconciliation reloads the exact
    -- decision that was published rather than re-querying a registry that
    -- may have moved on. '' when the action had no firmware source.
    input_firmware_registration TEXT NOT NULL DEFAULT '',
    correlation_id    TEXT    NOT NULL DEFAULT '',
    trigger_name      TEXT    NOT NULL,
    -- The complete typed authority that licensed this action, as canonical
    -- JSON matching one `evidence/v3` variant, captured when the row is first
    -- written. NULL on rows created before the column existed, and on rows
    -- that produce no runtime_action evidence.
    --
    -- Reconciliation replays this snapshot; it never rebuilds an authority
    -- from whichever skill, profile or binding is loaded after a restart,
    -- because those may have moved on and the licence is a fact about the
    -- moment the action was dispatched. A row whose snapshot is absent cannot
    -- be sealed conformantly and is refused rather than invented.
    authority_json    TEXT,
    -- Why attestation reached a terminal state, when it did. Empty while a row
    -- is pending, signed, reconciled, or transiently failed.
    attestation_reason TEXT   NOT NULL DEFAULT '',
    -- What the row records. 'dispatch' is a dispatch's own attempt at its
    -- action, whatever its outcome. 'contributor' is a request that joined an
    -- act another dispatch held: it performed nothing, holds no licence and is
    -- never attested, and contributed_to names the holder's record_key, the
    -- holder it joined, which is not proof the holder's row was written.
    -- 'contributor_legacy' is a joined row written before the link existed.
    -- attestation_status is added by migration, so a contributor's empty
    -- status is held by the writer and the attestation update, not here. A
    -- dispatch claiming 'coalesced' is refused by the writer, not here: a
    -- release rolled back to writes its joined rows that way, and every open
    -- reclassifies them.
    record_kind       TEXT    NOT NULL DEFAULT 'dispatch'
        CHECK (record_kind IN ('dispatch', 'contributor', 'contributor_legacy')),
    record_key        TEXT    NOT NULL DEFAULT '',
    contributed_to    TEXT,
    timestamp         INTEGER NOT NULL,
    CHECK (
        (record_kind = 'dispatch' AND contributed_to IS NULL)
        OR (record_kind = 'contributor' AND executed = 0 AND approved IS NULL
            AND action_taken = 'coalesced' AND authority_json IS NULL
            AND contributed_to IS NOT NULL
            AND contributed_to != '')
        OR (record_kind = 'contributor_legacy' AND contributed_to IS NULL
            AND action_taken = 'coalesced')
    )
);

CREATE TABLE IF NOT EXISTS tier_c_decision_log (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id                TEXT    NOT NULL DEFAULT '',
    site_type                TEXT    NOT NULL DEFAULT '',
    location                 TEXT    NOT NULL DEFAULT '',
    timezone                 TEXT    NOT NULL DEFAULT '',
    sensor_id                TEXT    NOT NULL DEFAULT '',
    sensor_type              TEXT    NOT NULL DEFAULT '',
    reading_value            REAL,
    reading_unit             TEXT    NOT NULL DEFAULT '',
    -- The reading's timestamp: the producer's own time where it reports one.
    -- A firmware device reports none, so for its readings this is the time the
    -- runtime received the reading, never when it was measured.
    reading_timestamp        INTEGER,
    history_window_json      TEXT    NOT NULL DEFAULT 'null',
    skill_name               TEXT    NOT NULL DEFAULT '',
    trigger_name             TEXT    NOT NULL DEFAULT '',
    proposed_action          TEXT    NOT NULL DEFAULT '',
    confidence               REAL    NOT NULL DEFAULT 0,
    reasoning_tier           TEXT    NOT NULL DEFAULT '',
    reasoning_model          TEXT    NOT NULL DEFAULT '',
    prompt_context_summary   TEXT    NOT NULL DEFAULT '',
    -- Not a closed set. Written: 'approved', 'rejected', 'timeout',
    -- 'undelivered', 'no_reply', 'approval_error', 'refused_uncommissioned',
    -- 'refused_recovery_incomplete', 'refused_policy', and for a governed
    -- proposal the tier-c-approval/v1 state it closed in
    -- ('approval_binding_changed', 'proposal_blocked_uncertain_outcome', any
    -- state an admission found it already in, or 'none' when its row was gone).
    -- A governed value is suffixed '_unrecorded' when the proposal row does not
    -- hold that decision.
    operator_decision        TEXT    NOT NULL DEFAULT '',
    operator_response        TEXT,
    operator_response_channel TEXT   NOT NULL DEFAULT '',
    operator_response_provider_message_id TEXT NOT NULL DEFAULT '',
    operator_response_from_number TEXT NOT NULL DEFAULT '',
    operator_response_received_at_ms INTEGER,
    decision_latency_ms      INTEGER NOT NULL DEFAULT 0,
    approval_timeout_seconds INTEGER NOT NULL DEFAULT 0,
    safe_default_action      TEXT    NOT NULL DEFAULT '',
    safe_default_used        INTEGER NOT NULL DEFAULT 0,
    action_taken             TEXT    NOT NULL DEFAULT '',
    action_executed          INTEGER NOT NULL DEFAULT 0,
    final_action_result_json TEXT    NOT NULL DEFAULT '{}',
    later_outcome_json       TEXT    NOT NULL DEFAULT 'null',
    proposal_id              TEXT    NOT NULL DEFAULT '',
    created_at               INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tier_c_decision_log_device_ts
    ON tier_c_decision_log (device_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_tier_c_decision_log_skill_trigger
    ON tier_c_decision_log (skill_name, trigger_name, created_at DESC);

CREATE TABLE IF NOT EXISTS causal_memory (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_key TEXT    NOT NULL UNIQUE,
    resolution  TEXT    NOT NULL,
    confidence  REAL    NOT NULL,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    hit_count   INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS causal_memory_rejections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_key TEXT NOT NULL,
    trigger_name TEXT NOT NULL,
    proposed_action TEXT NOT NULL,
    operator_response TEXT,
    device_id TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    value_bucket REAL,
    time_of_day_hour INTEGER,
    day_of_week INTEGER,
    rejected_at INTEGER NOT NULL,
    expiry_ms INTEGER,
    UNIQUE(pattern_key, proposed_action)
);

CREATE TABLE IF NOT EXISTS skill_state (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    skill_name  TEXT    NOT NULL,
    key         TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    updated_at  INTEGER NOT NULL,
    UNIQUE (skill_name, key)
);

CREATE TABLE IF NOT EXISTS inbound_messages (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    channel             TEXT    NOT NULL,
    from_number         TEXT    NOT NULL,
    message             TEXT    NOT NULL,
    received_at         INTEGER NOT NULL,
    consumed_at         INTEGER
);

CREATE INDEX IF NOT EXISTS idx_inbound_lookup
    ON inbound_messages (channel, from_number, received_at, consumed_at);

CREATE INDEX IF NOT EXISTS idx_inbound_age
    ON inbound_messages (channel, received_at);

CREATE TABLE IF NOT EXISTS webhook_replay_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    source         TEXT    NOT NULL DEFAULT '',
    nonce          TEXT    NOT NULL,
    received_at_ms INTEGER NOT NULL,
    expires_at_ms  INTEGER NOT NULL,
    UNIQUE(source, nonce)
);

CREATE INDEX IF NOT EXISTS idx_webhook_replay_log_expiry
    ON webhook_replay_log (expires_at_ms);

CREATE TABLE IF NOT EXISTS remote_command_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id     TEXT    NOT NULL DEFAULT '',
    channel        TEXT    NOT NULL DEFAULT '',
    from_number    TEXT    NOT NULL DEFAULT '',
    command        TEXT    NOT NULL DEFAULT '',
    accepted       INTEGER NOT NULL,
    reason         TEXT    NOT NULL,
    issued_at_ms   INTEGER,
    received_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remote_command_log_command_id
    ON remote_command_log (command_id, accepted, received_at_ms DESC);

CREATE TABLE IF NOT EXISTS remote_command_security_incident_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     TEXT    NOT NULL UNIQUE,
    channel         TEXT    NOT NULL DEFAULT '',
    from_number     TEXT    NOT NULL DEFAULT '',
    reason          TEXT    NOT NULL DEFAULT '',
    rejection_count INTEGER NOT NULL DEFAULT 0,
    threshold       INTEGER NOT NULL DEFAULT 0,
    window_ms       INTEGER NOT NULL DEFAULT 0,
    created_at_ms   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remote_command_security_incident_sender
    ON remote_command_security_incident_log (channel, from_number, created_at_ms DESC);

CREATE TABLE IF NOT EXISTS remote_command_execution_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id     TEXT    NOT NULL DEFAULT '',
    channel        TEXT    NOT NULL DEFAULT '',
    command        TEXT    NOT NULL DEFAULT '',
    status         TEXT    NOT NULL,
    detail         TEXT    NOT NULL DEFAULT '',
    executed       INTEGER NOT NULL,
    executed_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remote_command_execution_log_command_id
    ON remote_command_execution_log (command_id, executed_at_ms DESC);

CREATE TABLE IF NOT EXISTS alert_outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        TEXT    NOT NULL UNIQUE,
    channel         TEXT    NOT NULL,   -- 'sms' | 'whatsapp'
    recipient       TEXT    NOT NULL,
    message         TEXT    NOT NULL,
    intent          TEXT    NOT NULL DEFAULT 'tier_a_alert',
    template_variables_json TEXT NOT NULL DEFAULT '[]',
    action_tier     TEXT    NOT NULL,   -- 'A' | 'B' | 'C' | 'D'
    trigger_name    TEXT    NOT NULL DEFAULT '',
    original_ts     INTEGER NOT NULL,   -- the event's producer time, kept raw
    queued_at_ms    INTEGER NOT NULL DEFAULT 0,  -- the store's clock at enqueue; 0 only before migration
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    last_attempt_ts INTEGER,
    status          TEXT    NOT NULL DEFAULT 'pending', -- queue: pending|failed|accepted|abandoned
    accepted_channel TEXT   NOT NULL DEFAULT '',
    provider_message_id TEXT NOT NULL DEFAULT '',
    provider_status TEXT    NOT NULL DEFAULT '',
    accepted_at_ms  INTEGER,
    delivered_at_ms INTEGER,
    last_status_at_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_alert_outbox_status_tier_id
    ON alert_outbox (status, action_tier, id ASC);

CREATE TABLE IF NOT EXISTS safety_trip_journal (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    zone_id        TEXT    NOT NULL,
    profile_id     TEXT    NOT NULL,
    entry_kind     TEXT    NOT NULL,   -- 'intent' | 'record' | 'clear'
    attempt_id     TEXT,               -- intents only
    binding_seq    INTEGER,            -- intents only
    outcome        TEXT,               -- intents only
    command_status TEXT,               -- records only
    resolved       INTEGER NOT NULL DEFAULT 0,  -- intents only
    created_at_ms  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_safety_trip_journal_pair
    ON safety_trip_journal (zone_id, profile_id, seq);

CREATE TABLE IF NOT EXISTS device_policy_cache (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_version    INTEGER NOT NULL UNIQUE,
    tier              TEXT    NOT NULL,
    relay_b_enabled   INTEGER NOT NULL,
    relay_c_enabled   INTEGER NOT NULL,
    cloud_llm_enabled INTEGER NOT NULL,
    valid_until       INTEGER NOT NULL,
    issued_at         INTEGER NOT NULL,
    signature         TEXT    NOT NULL,
    raw_payload       TEXT    NOT NULL,
    cached_at         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_policy_cache_version
    ON device_policy_cache (policy_version DESC, cached_at DESC);

CREATE TABLE IF NOT EXISTS offline_token_consumption (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id    TEXT    NOT NULL UNIQUE,
    device_id   TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    consumed_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS offline_token_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id    TEXT    NOT NULL DEFAULT '',
    device_id   TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    approved    INTEGER NOT NULL,
    reason      TEXT    NOT NULL,
    attempted_at INTEGER NOT NULL
);

-- A Tier C proposal and what became of it: one row per proposal, its
-- decision_state moving forward only. The row is the proposal (committed
-- before the operator is asked), the approval (the admission commit moves it
-- to approved_pending_dispatch inside one transaction with the token claim
-- and the same-outcome block), and the terminal uncertainty record that the
-- admission reserves.
CREATE TABLE IF NOT EXISTS tier_c_proposals (
    proposal_id          TEXT    PRIMARY KEY,
    device_id            TEXT    NOT NULL,
    action               TEXT    NOT NULL,
    target               TEXT    NOT NULL DEFAULT '',
    zone_id              TEXT    NOT NULL DEFAULT '',
    outcome              TEXT    NOT NULL DEFAULT '',
    event_id             TEXT    NOT NULL DEFAULT '',
    skill_name           TEXT    NOT NULL DEFAULT '',
    trigger_name         TEXT    NOT NULL DEFAULT '',
    safe_default_action  TEXT    NOT NULL DEFAULT '',
    binding_digest       TEXT    NOT NULL DEFAULT '',
    authority_json       TEXT    NOT NULL DEFAULT '',
    created_at_ms        INTEGER NOT NULL,
    expires_at_ms        INTEGER NOT NULL,
    decision_state       TEXT    NOT NULL,
    state_reason         TEXT    NOT NULL DEFAULT '',
    ingress_channel      TEXT    NOT NULL DEFAULT '',
    ingress_from         TEXT    NOT NULL DEFAULT '',
    ingress_message_id   TEXT    NOT NULL DEFAULT '',
    operator_response    TEXT    NOT NULL DEFAULT '',
    offline_token_id     TEXT    NOT NULL DEFAULT '',
    committed_at_ms      INTEGER,
    outcome_json         TEXT,
    updated_at_ms        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tier_c_proposals_zone_outcome
    ON tier_c_proposals (zone_id, outcome, decision_state);

-- Every decision_state a proposal passed through, in order. Appended in the
-- same transaction as the change; never rewritten.
CREATE TABLE IF NOT EXISTS tier_c_proposal_records (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    proposal_id    TEXT    NOT NULL,
    decision_state TEXT    NOT NULL,
    state_reason   TEXT    NOT NULL DEFAULT '',
    recorded_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tier_c_proposal_records_proposal
    ON tier_c_proposal_records (proposal_id, id);

-- An operator's or commissioned feedback's observation of an uncertain
-- dispatch, appended beside it and never rewriting it. One per proposal; a
-- repeat by another principal is an audit attempt, not a second record.
CREATE TABLE IF NOT EXISTS tier_c_reconciliations (
    proposal_id    TEXT    PRIMARY KEY,
    device_id      TEXT    NOT NULL,
    zone_id        TEXT    NOT NULL,
    decision_state TEXT    NOT NULL,
    reason         TEXT    NOT NULL,
    note           TEXT,
    source         TEXT    NOT NULL,
    principal_uid  INTEGER,
    principal_account TEXT,
    principal_login_uid INTEGER,
    entry_point    TEXT    NOT NULL,
    recorded_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tier_c_reconcile_attempts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    proposal_id    TEXT    NOT NULL,
    kind           TEXT    NOT NULL,
    principal_uid  INTEGER,
    principal_account TEXT,
    principal_login_uid INTEGER,
    recorded_at_ms INTEGER NOT NULL
);

-- The one non-actuating safe-default intent a proposal may create, keyed by
-- the proposal, so a repeated reply, a restart or a later refusal of the same
-- proposal creates no second one.
CREATE TABLE IF NOT EXISTS tier_c_safe_default_intents (
    proposal_id    TEXT    PRIMARY KEY,
    action         TEXT    NOT NULL,
    reason         TEXT    NOT NULL DEFAULT '',
    outcome        TEXT    NOT NULL DEFAULT 'pending',
    created_at_ms  INTEGER NOT NULL,
    updated_at_ms  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS firmware_device_registry (
    device_id         TEXT    PRIMARY KEY,
    public_key_b64    TEXT    NOT NULL,
    alg               TEXT    NOT NULL DEFAULT 'ed25519',
    posture           TEXT    NOT NULL,
    capability_hash   TEXT    NOT NULL,
    manifest_json     TEXT    NOT NULL DEFAULT '{}',
    channel_map_json  TEXT    NOT NULL DEFAULT '{}',
    board_profile     TEXT    NOT NULL DEFAULT '',
    approved          INTEGER NOT NULL DEFAULT 0,
    provisioned_at_ms INTEGER NOT NULL,
    last_boot_id      INTEGER NOT NULL DEFAULT 0,
    last_seq          INTEGER NOT NULL DEFAULT 0,
    last_cmd_seq      INTEGER NOT NULL DEFAULT 0,
    last_provision_seq INTEGER NOT NULL DEFAULT 0,
    last_runtime_seq  INTEGER NOT NULL DEFAULT 0,
    last_uptime_ms    INTEGER,
    last_uptime_mark  TEXT,
    revoked           INTEGER NOT NULL DEFAULT 0,
    revoked_at_ms     INTEGER
);

-- Append-only anchor history for the device provisioning lifecycle
-- (ori-specs/device-provisioning/v1.md).
--
-- firmware_device_registry holds the ACTIVE anchor and identity-level
-- state (revocation, freshness). This table holds every anchor an
-- identity has ever had, including pending candidates that were never
-- promoted. Rows are never updated in place except to move `state`,
-- because evidence outlives the anchor that authorised it: an
-- overwritten anchor makes old evidence unattributable.
CREATE TABLE IF NOT EXISTS firmware_device_anchors (
    anchor_epoch_id     TEXT    PRIMARY KEY,
    device_id           TEXT    NOT NULL,
    key_epoch_id        TEXT    NOT NULL,
    public_key_b64      TEXT    NOT NULL,
    alg                 TEXT    NOT NULL DEFAULT 'ed25519',
    posture             TEXT    NOT NULL,
    capability_hash     TEXT    NOT NULL,
    manifest_json       TEXT    NOT NULL DEFAULT '{}',
    channel_map_json    TEXT    NOT NULL DEFAULT '{}',
    board_profile       TEXT    NOT NULL DEFAULT '',
    -- The normative anchor states. `revoked` is the anchor retained when
    -- the identity was revoked, so reinstatement has something to return
    -- to. Constrained by the database: an unrecognised state would make
    -- every acceptance decision below unsound.
    state               TEXT    NOT NULL
        CHECK (state IN ('pending', 'active', 'superseded', 'discarded',
                         'revoked')),
    created_at_ms       INTEGER NOT NULL,
    state_changed_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_firmware_anchors_device
    ON firmware_device_anchors (device_id, state);

-- At most one active and one pending anchor per identity. Enforced by
-- the database rather than by convention, because "two active anchors"
-- is a state no amount of careful calling code should be trusted to
-- prevent.
CREATE UNIQUE INDEX IF NOT EXISTS idx_firmware_anchors_one_active
    ON firmware_device_anchors (device_id) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS idx_firmware_anchors_one_pending
    ON firmware_device_anchors (device_id) WHERE state = 'pending';

-- Append-only audit of every trust transition. An unattributed anchor
-- change is indistinguishable from a compromise after the fact.
CREATE TABLE IF NOT EXISTS firmware_anchor_transitions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id      TEXT    NOT NULL,
    -- registered | promoted | superseded | discarded | revoked
    -- | reinstated | reprovisioned
    transition     TEXT    NOT NULL,
    from_epoch_id  TEXT,
    to_epoch_id    TEXT,
    key_epoch_id   TEXT    NOT NULL DEFAULT '',
    actor          TEXT    NOT NULL DEFAULT '',
    reason         TEXT    NOT NULL DEFAULT '',
    occurred_at_ms INTEGER NOT NULL,
    -- Promotion, revocation, reinstatement and re-provisioning are
    -- operator decisions that change what a receiver will accept, so they
    -- MUST be attributed. Only device-initiated registration and the
    -- replacement of a pending candidate may be unattributed — they grant
    -- nothing. Enforced here so an unattributed trust transition cannot be
    -- written by any code path, however careful.
    -- trim(): `actor <> ''` would accept "   ", which is attribution in
    -- form only.
    CHECK (
        transition IN ('registered', 'discarded')
        OR (length(trim(actor)) > 0 AND length(trim(reason)) > 0)
    )
);

CREATE INDEX IF NOT EXISTS idx_firmware_anchor_transitions_device
    ON firmware_anchor_transitions (device_id, occurred_at_ms DESC);

-- Cross-store epoch confirmation, per ori-specs/device-provisioning/v1.md.
-- An approval promotes an anchor locally, but MUST NOT reach firmware until
-- the evidence store has confirmed the identical anchor_epoch_id.
-- This table is the durable outbox that records that obligation: a grant is
-- confirmation_pending until the evidence store agrees (confirmed) or is found to
-- disagree (quarantined). It lives with the provisioning lifecycle; the
-- reconciliation worker services retries against it.
CREATE TABLE IF NOT EXISTS firmware_confirmation_outbox (
    device_id        TEXT    NOT NULL,
    -- The exact epoch approved locally. One obligation per epoch: a new
    -- key or manifest promotes a new anchor_epoch_id and a new row; a
    -- superseded epoch's row is retained as history.
    anchor_epoch_id  TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'confirmation_pending'
                       CHECK (status IN
                         ('confirmation_pending', 'confirmed', 'quarantined')),
    attempt_count    INTEGER NOT NULL DEFAULT 0,
    created_at_ms    INTEGER NOT NULL,
    last_attempt_ms  INTEGER,
    resolved_at_ms   INTEGER,
    PRIMARY KEY (device_id, anchor_epoch_id)
);

CREATE INDEX IF NOT EXISTS idx_firmware_confirmation_outbox_status
    ON firmware_confirmation_outbox (status, created_at_ms ASC);

-- Append-only issuer and response audit for
-- ori-specs/firmware-mqtt-provisioning/v1.md. Request and response facts are
-- separate rows: a later device result never rewrites the request that was
-- signed and handed to an untrusted transport.
CREATE TABLE IF NOT EXISTS firmware_mqtt_provisioning_audit (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id           TEXT    NOT NULL,
    event_kind          TEXT    NOT NULL
        CHECK (event_kind IN ('request_signed', 'response_verified')),
    operation_kind      TEXT    NOT NULL
        CHECK (operation_kind IN ('create_csr', 'install', 'revoke', 'status')),
    provision_seq       INTEGER,
    request_id          TEXT    NOT NULL DEFAULT '',
    anchor_epoch_id     TEXT    NOT NULL,
    actor               TEXT    NOT NULL,
    reason              TEXT    NOT NULL DEFAULT '',
    request_sha256      TEXT    NOT NULL,
    verdict             TEXT    NOT NULL DEFAULT '',
    certificate_sha256  TEXT    NOT NULL DEFAULT '',
    broker_uri          TEXT    NOT NULL DEFAULT '',
    payload_sha256      TEXT    NOT NULL,
    occurred_at_ms      INTEGER NOT NULL,
    CHECK (length(trim(actor)) > 0),
    CHECK (
        (event_kind = 'request_signed' AND verdict = '')
        OR
        (event_kind = 'response_verified' AND verdict IN (
            'accepted', 'malformed', 'wrong_device', 'bad_signature',
            'anchor_not_approved', 'anchor_epoch_mismatch', 'replayed',
            'audit_required', 'unsupported_operation', 'invalid_material',
            'no_pending_key', 'key_certificate_mismatch', 'storage_failure'
        ))
    ),
    CHECK (
        (operation_kind = 'status' AND provision_seq IS NULL
         AND request_id <> '' AND reason = '')
        OR
        (operation_kind <> 'status' AND provision_seq BETWEEN 1 AND 9007199254740991
         AND request_id = '' AND length(reason) > 0)
    )
);

CREATE INDEX IF NOT EXISTS idx_firmware_mqtt_provisioning_audit_device
    ON firmware_mqtt_provisioning_audit (device_id, id ASC);

CREATE TRIGGER IF NOT EXISTS firmware_mqtt_provisioning_audit_no_update
BEFORE UPDATE ON firmware_mqtt_provisioning_audit
BEGIN
    SELECT RAISE(ABORT, 'firmware MQTT provisioning audit is append-only');
END;

CREATE TRIGGER IF NOT EXISTS firmware_mqtt_provisioning_audit_no_delete
BEFORE DELETE ON firmware_mqtt_provisioning_audit
BEGIN
    SELECT RAISE(ABORT, 'firmware MQTT provisioning audit is append-only');
END;

-- Durable public correlation records for the authenticated local operator
-- service. The signed request bytes contain no private material. Keeping them
-- here lets an operator submit a device response after a runtime restart
-- without giving the CLI direct database or issuer access.
CREATE TABLE IF NOT EXISTS firmware_mqtt_operator_requests (
    correlation_id       TEXT    PRIMARY KEY,
    parent_correlation_id TEXT   NOT NULL DEFAULT '',
    operation_kind       TEXT    NOT NULL
        CHECK (operation_kind IN ('create_csr', 'install', 'revoke', 'status')),
    message               BLOB    NOT NULL,
    request               BLOB    NOT NULL,
    device_id             TEXT    NOT NULL,
    anchor_epoch_id       TEXT    NOT NULL,
    provision_seq         INTEGER,
    request_id            TEXT    NOT NULL DEFAULT '',
    actor                 TEXT    NOT NULL,
    reason                TEXT    NOT NULL DEFAULT '',
    request_sha256        TEXT    NOT NULL,
    certificate_sha256    TEXT    NOT NULL DEFAULT '',
    broker_uri            TEXT    NOT NULL DEFAULT '',
    audit_id              INTEGER NOT NULL,
    certificate_serial    TEXT    NOT NULL DEFAULT '',
    not_valid_before      TEXT    NOT NULL DEFAULT '',
    not_valid_after       TEXT    NOT NULL DEFAULT '',
    created_at_ms         INTEGER NOT NULL,
    CHECK (length(correlation_id) = 32),
    CHECK (length(trim(actor)) > 0),
    CHECK (
        (operation_kind = 'status' AND provision_seq IS NULL
         AND request_id <> '' AND reason = '')
        OR
        (operation_kind <> 'status' AND provision_seq BETWEEN 1 AND 9007199254740991
         AND request_id = '' AND length(reason) > 0)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_firmware_mqtt_operator_request_child
    ON firmware_mqtt_operator_requests (parent_correlation_id)
    WHERE parent_correlation_id <> '';

CREATE INDEX IF NOT EXISTS idx_firmware_mqtt_operator_request_device
    ON firmware_mqtt_operator_requests (device_id, created_at_ms DESC);

CREATE TRIGGER IF NOT EXISTS firmware_mqtt_operator_request_no_update
BEFORE UPDATE ON firmware_mqtt_operator_requests
BEGIN
    SELECT RAISE(ABORT, 'firmware MQTT operator requests are immutable');
END;

CREATE TRIGGER IF NOT EXISTS firmware_mqtt_operator_request_no_delete
BEFORE DELETE ON firmware_mqtt_operator_requests
BEGIN
    SELECT RAISE(ABORT, 'firmware MQTT operator requests are retained');
END;

CREATE TABLE IF NOT EXISTS firmware_mqtt_operator_responses (
    correlation_id  TEXT    PRIMARY KEY,
    verdict         TEXT    NOT NULL CHECK (verdict IN (
        'accepted', 'malformed', 'wrong_device', 'bad_signature',
        'anchor_not_approved', 'anchor_epoch_mismatch', 'replayed',
        'audit_required', 'unsupported_operation', 'invalid_material',
        'no_pending_key', 'key_certificate_mismatch', 'storage_failure'
    )),
    payload_sha256  TEXT    NOT NULL,
    completed_at_ms INTEGER NOT NULL,
    FOREIGN KEY (correlation_id)
        REFERENCES firmware_mqtt_operator_requests(correlation_id)
);

CREATE TRIGGER IF NOT EXISTS firmware_mqtt_operator_response_no_update
BEFORE UPDATE ON firmware_mqtt_operator_responses
BEGIN
    SELECT RAISE(ABORT, 'firmware MQTT operator responses are immutable');
END;

CREATE TRIGGER IF NOT EXISTS firmware_mqtt_operator_response_no_delete
BEFORE DELETE ON firmware_mqtt_operator_responses
BEGIN
    SELECT RAISE(ABORT, 'firmware MQTT operator responses are retained');
END;

CREATE TABLE IF NOT EXISTS sensor_measurement_state (
    sensor_id     TEXT    PRIMARY KEY,
    degraded      INTEGER NOT NULL,
    -- NULL means degraded but the operator has not been told yet. Recording
    -- the degradation and recording that it was reported are separate facts:
    -- collapsing them means a restart restores an unreported sensor as
    -- already reported, and the warning is suppressed permanently.
    notified_at   INTEGER,
    -- When this degradation began, and how far its notification schedule has
    -- run. The schedule advances on elapsed time rather than on delivery, so
    -- a reminder that could not be sent never cancels the escalation after
    -- it; both are persisted so a restart neither resets the clock nor
    -- repeats a stage the operator already has.
    degraded_since INTEGER,
    notice_stage  INTEGER NOT NULL DEFAULT 0,
    updated_at    INTEGER NOT NULL
);

"""
    + _FIRMWARE_FAULT_EVENTS_DDL
    + """

-- Commissioned safety bindings, retained whole. Every accepted document stays
-- so the binding in force at any past time can be produced for audit; the
-- one with no retired_at_ms is in force.
CREATE TABLE IF NOT EXISTS commissioned_binding (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    binding_seq          INTEGER NOT NULL UNIQUE,
    canonical_hash       TEXT    NOT NULL UNIQUE,
    device_id            TEXT    NOT NULL,
    inventory_generation INTEGER NOT NULL,
    signer_id            TEXT    NOT NULL,
    supersedes           TEXT,
    canonical_json       TEXT    NOT NULL,
    signature            TEXT    NOT NULL,
    zones_json           TEXT    NOT NULL,
    accepted_at_ms       INTEGER NOT NULL,
    retired_at_ms        INTEGER
);

-- A provisional binding: verified, retained and reported, never in force. It
-- is a separate table rather than a column so no read of the table above can
-- return one, and it is a single row because it is not a succession.
CREATE TABLE IF NOT EXISTS commissioned_binding_provisional (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    binding_seq          INTEGER NOT NULL,
    canonical_hash       TEXT    NOT NULL,
    device_id            TEXT    NOT NULL,
    inventory_generation INTEGER NOT NULL,
    signer_id            TEXT    NOT NULL,
    supersedes           TEXT,
    canonical_json       TEXT    NOT NULL,
    signature            TEXT    NOT NULL,
    zones_json           TEXT    NOT NULL,
    verified_at_ms       INTEGER NOT NULL
);

"""
    + _PROOF_OBSERVATION_DDL
)


#: The history pyramid, kept apart from the core DDL because the receipt
#: migration rebuilds exactly these tables inside one transaction.
_HISTORY_DDL_STATEMENTS: tuple[str, ...] = (
    """CREATE TABLE IF NOT EXISTS sensor_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id   TEXT    NOT NULL,
    sensor_type TEXT    NOT NULL,
    value       REAL    NOT NULL,
    unit        TEXT    NOT NULL,
    -- Kept raw, never a ranking key; producer_time says what it is. A
    -- firmware device reports no measurement time, so for its readings this
    -- is the value's arrival, marked not_reported.
    timestamp   INTEGER NOT NULL,
    quality     REAL    NOT NULL,
    metadata    TEXT    NOT NULL DEFAULT '{}',
    received_at_ms INTEGER NOT NULL CHECK (received_at_ms > 0),  -- the store's clock at insert
    producer_time TEXT NOT NULL DEFAULT 'unknown'
        CHECK (producer_time IN ('reported', 'not_reported', 'unknown'))
)""",
    """-- Arrival order is `id` and arrival time is `received_at_ms`. Both are the
-- store's own observation, which is why "latest" and "within the last N
-- hours" rank and filter on them and never on the producer's `timestamp`.
CREATE INDEX IF NOT EXISTS idx_sensor_history_sensor_id
    ON sensor_history (sensor_id)""",
    """CREATE INDEX IF NOT EXISTS idx_sensor_history_sensor_id_received
    ON sensor_history (sensor_id, received_at_ms DESC)""",
    """CREATE TABLE IF NOT EXISTS sensor_history_5min (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    bucket_ms INTEGER NOT NULL,   -- bucket of the producer's measured time
    avg_value REAL NOT NULL,
    unit TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    max_received_at_ms INTEGER NOT NULL CHECK (max_received_at_ms > 0),  -- greatest receipt among the samples
    UNIQUE(sensor_id, bucket_ms)
)""",
    """CREATE TABLE IF NOT EXISTS sensor_history_hourly (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    bucket_ms INTEGER NOT NULL,   -- bucket of the producer's measured time
    avg_value REAL NOT NULL,
    unit TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    max_received_at_ms INTEGER NOT NULL CHECK (max_received_at_ms > 0),  -- greatest receipt among the samples
    UNIQUE(sensor_id, bucket_ms)
)""",
    """CREATE TABLE IF NOT EXISTS sensor_history_daily (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    bucket_ms INTEGER NOT NULL,   -- bucket of the producer's measured time
    avg_value REAL NOT NULL,
    unit TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    max_received_at_ms INTEGER NOT NULL CHECK (max_received_at_ms > 0),  -- greatest receipt among the samples
    UNIQUE(sensor_id, bucket_ms)
)""",
    """-- The pyramid by basis. The tables above keep the shape every earlier
-- release compacts into, so a release rolled back to keeps compacting; their
-- rows carry no basis and read as unknown.
CREATE TABLE IF NOT EXISTS sensor_history_basis_5min (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    bucket_ms INTEGER NOT NULL,   -- bucket of the reading's timestamp
    avg_value REAL NOT NULL,
    unit TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    max_received_at_ms INTEGER NOT NULL CHECK (max_received_at_ms > 0),  -- greatest receipt among the samples
    producer_time TEXT NOT NULL
        CHECK (producer_time IN ('reported', 'not_reported', 'unknown')),
    UNIQUE(sensor_id, bucket_ms, producer_time)
)""",
    """CREATE TABLE IF NOT EXISTS sensor_history_basis_hourly (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    bucket_ms INTEGER NOT NULL,   -- bucket of the reading's timestamp
    avg_value REAL NOT NULL,
    unit TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    max_received_at_ms INTEGER NOT NULL CHECK (max_received_at_ms > 0),  -- greatest receipt among the samples
    producer_time TEXT NOT NULL
        CHECK (producer_time IN ('reported', 'not_reported', 'unknown')),
    UNIQUE(sensor_id, bucket_ms, producer_time)
)""",
    """CREATE TABLE IF NOT EXISTS sensor_history_basis_daily (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    bucket_ms INTEGER NOT NULL,   -- bucket of the reading's timestamp
    avg_value REAL NOT NULL,
    unit TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    max_received_at_ms INTEGER NOT NULL CHECK (max_received_at_ms > 0),  -- greatest receipt among the samples
    producer_time TEXT NOT NULL
        CHECK (producer_time IN ('reported', 'not_reported', 'unknown')),
    UNIQUE(sensor_id, bucket_ms, producer_time)
)""",
)


_HISTORY_DDL = ";\n".join(_HISTORY_DDL_STATEMENTS) + ";\n"


#: tier-c-approvers/v1: the approver registry. A missing header row is a
#: locked registry. Challenges, phone authorizations and pending phone
#: operations belong to the run that created them (`run_id`); every query is
#: scoped to the run, and other runs' rows are deleted when a run's registry
#: is prepared.
_APPROVER_DDL = """
CREATE TABLE IF NOT EXISTS approver_registry (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    device_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    identity_epoch TEXT NOT NULL,
    revision INTEGER NOT NULL,
    last_external_revision INTEGER NOT NULL,
    last_external_document_sha256 TEXT,
    credential_sequence INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS approver_credentials (
    credential_id TEXT PRIMARY KEY,
    approver_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    value TEXT NOT NULL,
    value_key TEXT NOT NULL UNIQUE,
    -- lan_ed25519 only: the RFC 8410 SubjectPublicKeyInfo DER SHA-256, hex.
    spki_sha256 TEXT,
    sequence INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS approver_tombstones (
    kind TEXT NOT NULL CHECK (kind IN ('credential', 'approver', 'value')),
    name TEXT NOT NULL,
    approver_id TEXT,
    value TEXT,
    PRIMARY KEY (kind, name)
);
CREATE TABLE IF NOT EXISTS approver_challenges (
    challenge_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    canonical BLOB NOT NULL,
    issued_at_ms INTEGER NOT NULL,
    credential_sequence_at_issue INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    code_sha256 TEXT,
    -- 1 when the runtime minted the candidate's approver ID.
    approver_minted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS approver_phone_authorizations (
    arrival INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    challenge_id TEXT NOT NULL,
    challenge_sha256 TEXT NOT NULL,
    authorizer_credential_id TEXT
);
CREATE TABLE IF NOT EXISTS approver_pending_phone (
    value TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    challenge_id TEXT NOT NULL UNIQUE,
    channel TEXT NOT NULL,
    candidate_json TEXT NOT NULL,
    code_sha256 TEXT,
    window_start_ms INTEGER NOT NULL,
    authorizer_credential_id TEXT NOT NULL,
    registry_revision INTEGER NOT NULL,
    identity_epoch TEXT NOT NULL,
    site_id TEXT NOT NULL,
    approver_minted INTEGER NOT NULL DEFAULT 0
);
-- Pending phone operations a recovery ended, so a late reply to one is told
-- its epoch changed rather than that nothing was pending.
CREATE TABLE IF NOT EXISTS approver_invalidated_phone (
    challenge_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    PRIMARY KEY (challenge_id, run_id)
);
"""


_DDL = _CORE_DDL + "\n" + _HISTORY_DDL


_HISTORY_RECEIPT_COLUMNS: dict[str, str] = {
    "sensor_history": "received_at_ms",
    "sensor_history_5min": "max_received_at_ms",
    "sensor_history_hourly": "max_received_at_ms",
    "sensor_history_daily": "max_received_at_ms",
    "sensor_history_basis_5min": "max_received_at_ms",
    "sensor_history_basis_hourly": "max_received_at_ms",
    "sensor_history_basis_daily": "max_received_at_ms",
}


_LEGACY_HISTORY_INDEXES: tuple[str, ...] = ("idx_sensor_history_sensor_id_ts",)


_LEGACY_OUTBOX_INDEXES: tuple[str, ...] = ("idx_alert_outbox_status_tier_ts",)


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _unreceipted_history(conn: sqlite3.Connection) -> tuple[list[str], dict[str, int]]:
    """History tables present without their receipt column, and every present table's row count."""
    present = {table: _table_columns(conn, table) for table in _HISTORY_RECEIPT_COLUMNS}
    missing = [
        table
        for table, column in _HISTORY_RECEIPT_COLUMNS.items()
        if present[table] and column not in present[table]
    ]
    counts = {
        table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table, columns in present.items()
        if columns
    }
    return missing, counts


def _history_rebuild_statements() -> tuple[str, ...]:
    """Drop the unreceipted pyramid and recreate it, as one statement list."""
    drops = tuple(
        f"DROP INDEX IF EXISTS {name}" for name in _LEGACY_HISTORY_INDEXES
    ) + tuple(f"DROP TABLE IF EXISTS {table}" for table in _HISTORY_RECEIPT_COLUMNS)
    return drops + _HISTORY_DDL_STATEMENTS


# Marks a migrated identity whose activation history cannot be
# reconstructed. Revocation sets `approved = 0`, so a pre-lifecycle
# revoked row is identical whether it was revoked after being promoted or
# before ever being promoted. Compared as a constant rather than matched
# as text, so the marker and its reader cannot drift apart.
_MIGRATION_ACTIVATION_UNPROVABLE = (
    "backfilled from a pre-lifecycle revoked registry row; whether this "
    "anchor was ever promoted cannot be determined, because revocation "
    "cleared the approval flag"
)


# The reason written by the first lifecycle release's backfill. Databases
# upgraded by that release already hold an anchor row, so the backfill
# skips them; this constant is how the follow-up migration recognises
# them and completes their activation history.
_MIGRATION_BACKFILL_REASON = "backfilled from a pre-lifecycle registry row"


# Appended by the follow-up migration when an already-backfilled anchor's
# activation cannot be safely reconstructed.
_MIGRATION_ACTIVATION_UNRECONSTRUCTABLE = (
    "already backfilled by an earlier release; whether this anchor was "
    "ever promoted cannot be reconstructed from the recorded history"
)


# Recorded for an approved legacy row. Being approved proves the anchor is
# active when the migration observes it; it does not prove when the
# approval happened. `provisioned_at_ms` is when the device was
# provisioned, which can be long before it was approved, so using it as
# the start would vouch for evidence produced in between.
_MIGRATION_ACTIVATION_START_UNKNOWN = (
    "observed active at the migration boundary; the original approval was "
    "never recorded, so activation before this point is unknown"
)


def _require_attribution(operation: str, actor: str, reason: str) -> None:
    """Mandatory audit fields for a trust transition.

    ori-specs/device-provisioning/v1.md requires actor and reason on every
    operator decision that changes acceptance. An unattributed anchor
    change is indistinguishable from a compromise after the fact, so this
    refuses before any state moves rather than writing a blank row.
    """
    if not str(actor).strip():
        raise ValueError(
            f"{operation} requires an actor: trust transitions are audited"
        )
    if not str(reason).strip():
        raise ValueError(
            f"{operation} requires a reason: trust transitions are audited"
        )


class HistoryReceiptMigrationRequiredError(RuntimeError):
    """The history tables predate the receipt column and this opener may not rebuild them.

    Rebuilding discards every history row, so only the runtime's own startup
    asks for it. A read path that meets this store reports it instead.
    """


# Every row _action_record_members can read as another kind or link than it
# stores, once a coalesced row stored as a dispatch is reclassified (the
# statement before the pass that uses this). Any other row stores `dispatch`
# with no link and an action other than `coalesced`, and is read exactly so.
_ACTION_RECORD_CANDIDATES = (
    "record_kind IS NOT 'dispatch' OR contributed_to IS NOT NULL"
)


# Where duplicated keys already stop the unique index from being built, these
# hold every later insert and key update to a key no other row carries.
_RECORD_KEY_UNIQUE_TRIGGER_NAMES = (
    "trg_action_log_record_key_unique_insert",
    "trg_action_log_record_key_unique_update",
)


_RECORD_KEY_UNIQUE_TRIGGERS = (
    """
    CREATE TRIGGER IF NOT EXISTS trg_action_log_record_key_unique_insert
    BEFORE INSERT ON action_log
    WHEN NEW.record_key <> ''
         AND EXISTS (SELECT 1 FROM action_log WHERE record_key = NEW.record_key)
    BEGIN
        SELECT RAISE(ABORT, 'action_log.record_key is already in use');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_action_log_record_key_unique_update
    BEFORE UPDATE OF record_key ON action_log
    WHEN NEW.record_key <> ''
         AND EXISTS (
             SELECT 1 FROM action_log
             WHERE record_key = NEW.record_key AND id <> OLD.id
         )
    BEGIN
        SELECT RAISE(ABORT, 'action_log.record_key is already in use');
    END
    """,
)


class StoreMigrations:
    """Schema creation and the in-place migrations `open()` applies."""

    _db_path: str
    _allow_history_rebuild: bool
    _conn: Optional[sqlite3.Connection]

    def _migrate_sync(self, conn: sqlite3.Connection) -> None:
        conn.executescript(_CORE_DDL)
        # Before the history DDL: its receipt index cannot be created over a
        # table that predates the column, so an unreceipted pyramid is rebuilt
        # first and a fresh store gets its tables from the DDL after.
        self._rebuild_history_schema_if_unreceipted(conn)
        conn.executescript(_HISTORY_DDL)
        conn.executescript(_APPROVER_DDL)
        # A header written before it carried its device is not this device's
        # registry: its NULL device_id reads as locked.
        self._add_column_if_missing_on_conn(
            conn, "approver_registry", "device_id", "TEXT"
        )
        self._add_history_producer_time(conn)
        self._migrate_alert_outbox_receipt(conn)
        self._key_firmware_fault_events_by_epoch(conn)
        # Add columns that may be missing from databases created before this
        # migration.  SQLite does not support ALTER TABLE ADD COLUMN IF NOT EXISTS
        # so duplicate-column errors are handled explicitly.
        _new_reasoning_cols = [
            ("device_id", "TEXT    NOT NULL DEFAULT ''"),
            ("model", "TEXT    NOT NULL DEFAULT ''"),
            ("tokens_used", "INTEGER NOT NULL DEFAULT 0"),
            ("latency_ms", "INTEGER NOT NULL DEFAULT 0"),
            ("proposed_action", "TEXT"),
            ("reasoning_status", "TEXT NOT NULL DEFAULT ''"),
            ("correlation_id", "TEXT NOT NULL DEFAULT ''"),
        ]
        for col, typedef in _new_reasoning_cols:
            self._add_column_if_missing_on_conn(conn, "reasoning_log", col, typedef)
        for col, typedef in (
            ("degraded_since", "INTEGER"),
            ("notice_stage", "INTEGER NOT NULL DEFAULT 0"),
        ):
            self._add_column_if_missing_on_conn(
                conn, "sensor_measurement_state", col, typedef
            )
        self._add_column_if_missing_on_conn(
            conn,
            "action_log",
            "proposal_id",
            "TEXT    NOT NULL DEFAULT ''",
        )
        # Nullable with no default, deliberately. An empty string or `{}` would
        # be a snapshot claiming something, and there is nothing truthful to
        # claim for a row written before the column existed: the licence was
        # never recorded and cannot be recovered. NULL says exactly that, and
        # the attestation path refuses such a row rather than sealing it.
        self._add_column_if_missing_on_conn(
            conn,
            "action_log",
            "authority_json",
            "TEXT",
        )
        self._add_column_if_missing_on_conn(
            conn,
            "action_log",
            "attestation_reason",
            "TEXT    NOT NULL DEFAULT ''",
        )
        # A bench device commissioned on an earlier build of this branch holds
        # the proof table with `executed` and none of the facts that replaced
        # it. `CREATE TABLE IF NOT EXISTS` leaves such a row set untouched, and
        # adding the new columns is not enough on its own: the legacy
        # `executed` is NOT NULL with no default, so every later insert fails.
        # The table is rebuilt instead, carrying the recorded commands across.
        if not self._rebuild_proof_observation_if_legacy(conn):
            for col, typedef in (
                ("command_issued", "INTEGER NOT NULL DEFAULT 0"),
                ("effect_verified", "INTEGER NOT NULL DEFAULT 0"),
                ("operator_attestation", "TEXT"),
                ("release_requested", "INTEGER NOT NULL DEFAULT 0"),
                ("held_ms", "INTEGER NOT NULL DEFAULT 0"),
            ):
                self._add_column_if_missing_on_conn(
                    conn, "commissioning_proof_observation", col, typedef
                )
        for col, typedef in (
            ("safe_default_used", "INTEGER NOT NULL DEFAULT 0"),
            ("device_id", "TEXT    NOT NULL DEFAULT ''"),
            ("sensor_id", "TEXT    NOT NULL DEFAULT ''"),
            ("sensor_type", "TEXT    NOT NULL DEFAULT ''"),
            ("input_attestation_grade", "TEXT    NOT NULL DEFAULT 'unattested'"),
            ("input_posture", "TEXT    NOT NULL DEFAULT ''"),
            ("binding_seq", "INTEGER"),
            ("input_firmware_device_id", "TEXT    NOT NULL DEFAULT ''"),
            ("input_firmware_boot_id", "INTEGER NOT NULL DEFAULT 0"),
            ("input_firmware_seq", "INTEGER NOT NULL DEFAULT 0"),
            ("input_firmware_registration", "TEXT    NOT NULL DEFAULT ''"),
            ("correlation_id", "TEXT    NOT NULL DEFAULT ''"),
            # Evidence attestation (Option B append-after-log): '' means the
            # row predates evidence signing or signing is disabled; rows
            # written while signing is enabled move pending -> signed/failed,
            # and startup reconciliation repairs failures to 'reconciled'.
            ("attestation_status", "TEXT    NOT NULL DEFAULT ''"),
            ("attestation_seq", "INTEGER"),
        ):
            self._add_column_if_missing_on_conn(conn, "action_log", col, typedef)
        self._add_action_record_kind(conn)
        self._add_column_if_missing_on_conn(
            conn,
            "firmware_device_registry",
            "last_cmd_seq",
            "INTEGER NOT NULL DEFAULT 0",
        )
        self._add_column_if_missing_on_conn(
            conn,
            "firmware_device_registry",
            "last_provision_seq",
            "INTEGER NOT NULL DEFAULT 0",
        )
        self._add_column_if_missing_on_conn(
            conn,
            "firmware_device_registry",
            "last_runtime_seq",
            "INTEGER NOT NULL DEFAULT 0",
        )
        # NULL until the first message after upgrade seeds it.
        self._add_column_if_missing_on_conn(
            conn, "firmware_device_registry", "last_uptime_ms", "INTEGER"
        )
        # The mark the stored uptime was written with: key epoch, boot and
        # seq. A writer that moves any of them without the uptime (a release
        # without these columns, after a rollback) leaves it incomparable, and
        # the next message re-seeds it.
        self._add_column_if_missing_on_conn(
            conn, "firmware_device_registry", "last_uptime_mark", "TEXT"
        )
        for col, typedef in (
            ("proposal_id", "TEXT    NOT NULL DEFAULT ''"),
            ("operator_response_channel", "TEXT NOT NULL DEFAULT ''"),
            (
                "operator_response_provider_message_id",
                "TEXT NOT NULL DEFAULT ''",
            ),
            ("operator_response_from_number", "TEXT NOT NULL DEFAULT ''"),
            ("operator_response_received_at_ms", "INTEGER"),
        ):
            self._add_column_if_missing_on_conn(
                conn, "tier_c_decision_log", col, typedef
            )
        self._add_column_if_missing_on_conn(
            conn,
            "remote_command_log",
            "from_number",
            "TEXT    NOT NULL DEFAULT ''",
        )
        for col, typedef in (
            ("intent", "TEXT NOT NULL DEFAULT 'tier_a_alert'"),
            ("template_variables_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("accepted_channel", "TEXT NOT NULL DEFAULT ''"),
            ("provider_message_id", "TEXT NOT NULL DEFAULT ''"),
            ("provider_status", "TEXT NOT NULL DEFAULT ''"),
            ("accepted_at_ms", "INTEGER"),
            ("delivered_at_ms", "INTEGER"),
            ("last_status_at_ms", "INTEGER"),
        ):
            self._add_column_if_missing_on_conn(conn, "alert_outbox", col, typedef)
        # Earlier releases called a successful provider submission "delivered".
        # That fact proves acceptance only, so preserve it without inventing a
        # handset receipt that was never observed.
        conn.execute(
            """
            UPDATE alert_outbox
               SET status = 'accepted',
                   accepted_channel = CASE
                       WHEN accepted_channel = '' THEN channel
                       ELSE accepted_channel
                   END,
                   provider_status = CASE
                       WHEN provider_status = '' THEN 'legacy_provider_success'
                       ELSE provider_status
                   END,
                   accepted_at_ms = COALESCE(accepted_at_ms, last_attempt_ts),
                   delivered_at_ms = NULL
             WHERE status = 'delivered'
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alert_outbox_acceptance_receipt
                ON alert_outbox (
                    status, accepted_channel, delivered_at_ms, original_ts ASC
                )
            """
        )
        for col, typedef in (
            ("manifest_json", "TEXT    NOT NULL DEFAULT '{}'"),
            ("channel_map_json", "TEXT    NOT NULL DEFAULT '{}'"),
            # Device provisioning lifecycle: the active anchor's epochs.
            ("anchor_epoch_id", "TEXT    NOT NULL DEFAULT ''"),
            ("key_epoch_id", "TEXT    NOT NULL DEFAULT ''"),
        ):
            self._add_column_if_missing_on_conn(
                conn, "firmware_device_registry", col, typedef
            )
        self._backfill_firmware_anchor_epochs_on_conn(conn)
        # Runs after, and independently: it repairs identities the first
        # lifecycle release already backfilled, which the call above skips
        # because they now have an anchor row.
        self._complete_backfilled_activation_history_on_conn(conn)
        self._backfill_firmware_confirmation_obligations_on_conn(conn)
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_remote_command_log_sender_rejections
                ON remote_command_log (channel, from_number, accepted, received_at_ms DESC)
            """
        )
        conn.commit()

    def _add_column_if_missing(self, table: str, column: str, typedef: str) -> None:
        """Backward-compatible helper used by tests and migrations."""
        assert self._conn is not None
        self._add_column_if_missing_on_conn(self._conn, table, column, typedef)

    def _backfill_firmware_anchor_epochs_on_conn(
        self, conn: sqlite3.Connection
    ) -> None:
        """Give pre-lifecycle rows their epoch identifiers and an anchor
        history entry.

        Databases created before the provisioning lifecycle hold an
        active anchor in firmware_device_registry with no row in
        firmware_device_anchors. Absence of history is the detection
        signal — NOT an empty anchor_epoch_id, which now legitimately
        means "registered, nothing promoted yet" and would make the
        backfill fire on every freshly registered device. Derive the ids from what is
        already stored and record the anchor, so existing devices are not
        invisible to the lifecycle.

        An approved, unrevoked row becomes `active`. A revoked row becomes
        `revoked` — never `pending`, which would hand a revoked identity a
        promotable anchor. Anything else becomes `pending`, because it was
        never trusted for acceptance.
        """
        from ori.security.firmware.telemetry import (
            anchor_epoch_id as _anchor_epoch_id,
        )
        from ori.security.firmware.telemetry import (
            key_epoch_id as _key_epoch_id,
        )

        # The receiver-anchored boundary: the moment this store observed
        # these rows. Every inferred activation starts here, never at a
        # timestamp carried over from the old schema.
        migration_at_ms = now_ms()

        rows = conn.execute(
            """
            SELECT r.device_id, r.public_key_b64, r.posture, r.capability_hash,
                   r.manifest_json, r.channel_map_json, r.board_profile,
                   r.approved, r.revoked, r.provisioned_at_ms, r.revoked_at_ms
              FROM firmware_device_registry r
             WHERE NOT EXISTS (
                       SELECT 1 FROM firmware_device_anchors a
                        WHERE a.device_id = r.device_id
                   )
            """
        ).fetchall()
        for row in rows:
            kid = _key_epoch_id(
                device_id=row["device_id"], public_key_b64=row["public_key_b64"]
            )
            aid = _anchor_epoch_id(
                device_id=row["device_id"],
                public_key_b64=row["public_key_b64"],
                posture=row["posture"],
                capability_hash=row["capability_hash"],
            )
            conn.execute(
                """
                UPDATE firmware_device_registry
                   SET anchor_epoch_id = ?, key_epoch_id = ?
                 WHERE device_id = ?
                """,
                (aid, kid, row["device_id"]),
            )
            if row["revoked"]:
                # A revoked identity must NOT acquire a promotable pending
                # anchor. The anchor is retained in `revoked` so a later
                # reinstatement has something to return to.
                state = "revoked"
            elif row["approved"]:
                state = "active"
            else:
                state = "pending"
            conn.execute(
                """
                INSERT OR IGNORE INTO firmware_device_anchors
                    (anchor_epoch_id, device_id, key_epoch_id, public_key_b64,
                     posture, capability_hash, manifest_json, channel_map_json,
                     board_profile, state, created_at_ms, state_changed_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    aid,
                    row["device_id"],
                    kid,
                    row["public_key_b64"],
                    row["posture"],
                    row["capability_hash"],
                    row["manifest_json"],
                    row["channel_map_json"],
                    row["board_profile"],
                    state,
                    row["provisioned_at_ms"],
                    row["provisioned_at_ms"],
                ),
            )
            conn.execute(
                """
                INSERT INTO firmware_anchor_transitions
                    (device_id, transition, from_epoch_id, to_epoch_id,
                     key_epoch_id, actor, reason, occurred_at_ms)
                VALUES (?, 'registered', NULL, ?, ?, 'migration', ?, ?)
                """,
                (
                    row["device_id"],
                    aid,
                    kid,
                    _MIGRATION_ACTIVATION_UNPROVABLE
                    if state == "revoked"
                    else _MIGRATION_BACKFILL_REASON,
                    row["provisioned_at_ms"],
                ),
            )

            # An approved, unrevoked legacy row IS active, so it was
            # promoted at some point. Recording that is what stops the
            # derived activation history from reporting the anchor as
            # never active and losing the attribution for everything it
            # authorised before the upgrade.
            #
            # A REVOKED row is deliberately excluded. Revocation sets
            # `approved = 0`, so a revoked legacy row reads
            # `approved=0, revoked=1` whether it was revoked after being
            # promoted or before ever being promoted. The two are
            # indistinguishable in a pre-lifecycle database, and inventing
            # a promotion for both would manufacture authorisation for an
            # identity that may never have had any — failing open on
            # exactly the question this history exists to answer. Its
            # activation history is unprovable, and is recorded as such
            # rather than guessed.
            #
            # The interval opens at the MIGRATION BOUNDARY, not at
            # `provisioned_at_ms`. Approval proves the anchor is active
            # when the migration observes it; it says nothing about when
            # the approval happened, and a device is often provisioned
            # long before it is approved. Starting the interval at
            # provisioning would vouch for evidence produced in between,
            # which is precisely the window nobody can account for.
            if state == "active":
                conn.execute(
                    """
                    INSERT INTO firmware_anchor_transitions
                        (device_id, transition, from_epoch_id, to_epoch_id,
                         key_epoch_id, actor, reason, occurred_at_ms)
                    VALUES (?, 'promoted', NULL, ?, ?, 'migration', ?, ?)
                    """,
                    (
                        row["device_id"],
                        aid,
                        kid,
                        _MIGRATION_ACTIVATION_START_UNKNOWN,
                        migration_at_ms,
                    ),
                )

    def _backfill_firmware_confirmation_obligations_on_conn(
        self, conn: sqlite3.Connection
    ) -> None:
        """Give every active anchor without an obligation a fail-closed one.

        Cross-store confirmation was introduced after devices had already
        been approved. Those anchors are active in the runtime store but
        have no ``firmware_confirmation_outbox`` row, so the command and
        evidence gates — which treat a missing row as *not confirmed* —
        would refuse them, while the coordinator's resolve update, finding
        no row to update, would change nothing yet report success. Neither
        state is trustworthy.

        The safe reconciliation is to enrol each active anchor as
        ``confirmation_pending``, exactly as a fresh approval would. The
        obligation is then visible to the reconciliation path and becomes
        effective only once the evidence store confirms the identical
        epoch. Failing closed here means a legacy device pauses until it is
        confirmed, never that it operates on authority the evidence store
        cannot back.

        Only ``active`` anchors are enrolled: a pending, superseded, or
        revoked anchor asserts no current authority to confirm. Idempotent
        via ``ON CONFLICT DO NOTHING`` — a device already carrying an
        obligation (including a ``confirmed`` or ``quarantined`` one) keeps
        it untouched, so reopening a database backfills nothing and never
        reopens a resolved obligation.
        """
        created_at_ms = now_ms()
        conn.execute(
            """
            INSERT INTO firmware_confirmation_outbox
                (device_id, anchor_epoch_id, status, attempt_count,
                 created_at_ms)
            SELECT a.device_id, a.anchor_epoch_id, 'confirmation_pending', 0, ?
              FROM firmware_device_anchors a
             WHERE a.state = 'active'
            ON CONFLICT (device_id, anchor_epoch_id) DO NOTHING
            """,
            (created_at_ms,),
        )

    def _complete_backfilled_activation_history_on_conn(
        self, conn: sqlite3.Connection
    ) -> None:
        """Finish the activation history of rows an earlier release already
        backfilled.

        The first lifecycle release gave pre-lifecycle rows an anchor and a
        generic ``registered`` transition. Those identities therefore have
        an anchor row, so the backfill above — which only fires when there
        is none — never revisits them, and they would keep an activation
        history that says an approved device was never active.

        The transition log is append-only, so nothing here rewrites the
        earlier entry; this appends what was missing.

        Idempotent: each branch first checks whether its entry is already
        present, so reopening a database adds nothing.
        """
        migration_at_ms = now_ms()

        rows = conn.execute(
            """
            SELECT a.device_id, a.anchor_epoch_id, a.key_epoch_id, a.state,
                   a.created_at_ms,
                   (SELECT MIN(t.id) FROM firmware_anchor_transitions t
                     WHERE t.device_id = a.device_id
                       AND t.actor = 'migration'
                       AND t.reason = ?
                       AND t.to_epoch_id = a.anchor_epoch_id) AS backfill_id
              FROM firmware_device_anchors a
             WHERE backfill_id IS NOT NULL
            """,
            (_MIGRATION_BACKFILL_REASON,),
        ).fetchall()

        for row in rows:
            aid = row["anchor_epoch_id"]

            already_repaired = conn.execute(
                """
                SELECT 1 FROM firmware_anchor_transitions
                 WHERE device_id = ? AND actor = 'migration' AND reason IN (?, ?)
                 LIMIT 1
                """,
                (
                    row["device_id"],
                    _MIGRATION_ACTIVATION_START_UNKNOWN,
                    _MIGRATION_ACTIVATION_UNRECONSTRUCTABLE,
                ),
            ).fetchone()
            if already_repaired is not None:
                continue

            # The earlier release wrote the same generic reason whichever
            # state it chose, so the log does not say directly whether this
            # anchor was backfilled `active` or `pending`. The first
            # transition to touch the anchor afterwards does say.
            #
            # An anchor backfilled PENDING leaves that state one of two
            # ways, and both are provable:
            #   `promoted to=A`    a real, recorded first activation
            #   `discarded from=A` replaced as a candidate. Only a PENDING
            #                      anchor is ever discarded, so this proves
            #                      it was never active.
            #
            # An anchor backfilled ACTIVE must first LEAVE active, so its
            # first subsequent mention carries it in from_epoch_id
            # (`revoked from=A`, or `promoted from=A` when another anchor
            # superseded it). Its pre-migration activation was never
            # recorded, and a later re-promotion does not make that earlier
            # interval provable.
            first_after = conn.execute(
                """
                SELECT transition, from_epoch_id, to_epoch_id
                  FROM firmware_anchor_transitions
                 WHERE device_id = ? AND id > ?
                   AND (from_epoch_id = ? OR to_epoch_id = ?)
                 ORDER BY id ASC LIMIT 1
                """,
                (row["device_id"], row["backfill_id"], aid, aid),
            ).fetchone()

            if first_after is not None:
                if (
                    first_after["transition"] == "promoted"
                    and first_after["to_epoch_id"] == aid
                ):
                    # Backfilled pending, then genuinely promoted. Nothing
                    # is missing and nothing is uncertain.
                    continue
                if (
                    first_after["transition"] == "discarded"
                    and first_after["from_epoch_id"] == aid
                ):
                    # Backfilled pending, then replaced as a candidate.
                    # Provably never active, which is a stronger answer
                    # than "cannot say" — marking it unprovable would
                    # discard a fact the log does establish.
                    continue
                # Backfilled active. Fall through to the marker below: the
                # promotion that would have to be reconstructed sits before
                # entries already in the log, and an append cannot express
                # that without misordering the interval.
                row = dict(row)
                row["state"] = "_was_active_before_migration"

            if row["state"] == "active":
                # It is active now, so it is known active from this
                # boundary onward. When it BECAME active is unknown, and
                # `created_at_ms` is the backfill's own timestamp rather
                # than an approval, so the interval opens here and not
                # there. Nothing closes it, so appending cannot misorder.
                conn.execute(
                    """
                    INSERT INTO firmware_anchor_transitions
                        (device_id, transition, from_epoch_id, to_epoch_id,
                         key_epoch_id, actor, reason, occurred_at_ms)
                    VALUES (?, 'promoted', NULL, ?, ?, 'migration', ?, ?)
                    """,
                    (
                        row["device_id"],
                        aid,
                        row["key_epoch_id"],
                        _MIGRATION_ACTIVATION_START_UNKNOWN,
                        migration_at_ms,
                    ),
                )
                continue

            if row["state"] == "pending":
                # Provably never promoted: the earlier backfill only chose
                # `pending` for a row that was never approved.
                continue

            # `revoked`, an anchor that was active before the migration, or
            # `superseded`/`discarded` reached by later activity. None of
            # these can say when — or whether — the anchor was active
            # before the upgrade, so all fail closed.
            conn.execute(
                """
                INSERT INTO firmware_anchor_transitions
                    (device_id, transition, from_epoch_id, to_epoch_id,
                     key_epoch_id, actor, reason, occurred_at_ms)
                VALUES (?, 'registered', NULL, ?, ?, 'migration', ?, ?)
                """,
                (
                    row["device_id"],
                    aid,
                    row["key_epoch_id"],
                    _MIGRATION_ACTIVATION_UNRECONSTRUCTABLE,
                    migration_at_ms,
                ),
            )

    @staticmethod
    def _key_firmware_fault_events_by_epoch(conn: sqlite3.Connection) -> None:
        """Rebuild a pre-epoch fault table under the epoch key, every row and id kept."""
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(firmware_fault_events)")
        }
        if "key_epoch_id" in columns:
            return
        kept = (
            "id, device_id, boot_id, seq, grade, posture, capability_hash, code, "
            "subject, detail, device_uptime_ms, received_at_ms, fault_json"
        )
        conn.commit()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "ALTER TABLE firmware_fault_events "
                "RENAME TO _firmware_fault_events_unkeyed"
            )
            conn.execute(_FIRMWARE_FAULT_EVENTS_DDL)
            conn.execute(
                f"INSERT INTO firmware_fault_events ({kept}, key_epoch_id) "
                f"SELECT {kept}, '' FROM _firmware_fault_events_unkeyed"
            )
            # AUTOINCREMENT never reissues an id the old table spent.
            spent = conn.execute(
                "SELECT seq FROM sqlite_sequence "
                "WHERE name = '_firmware_fault_events_unkeyed'"
            ).fetchone()
            if spent is not None:
                conn.execute(
                    "DELETE FROM sqlite_sequence WHERE name = 'firmware_fault_events'"
                )
                conn.execute(
                    "INSERT INTO sqlite_sequence (name, seq) "
                    "VALUES ('firmware_fault_events', ?)",
                    (int(spent[0]),),
                )
            conn.execute("DROP TABLE _firmware_fault_events_unkeyed")
            conn.commit()
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

    @staticmethod
    def _add_history_producer_time(conn: sqlite3.Connection) -> None:
        """producer_time on raw history, every row kept and read as unknown.

        Checked again inside the IMMEDIATE transaction, so a concurrent opener
        finds it added rather than adding it twice. A release that predates the
        column inserts without it and its rows take the default, unknown.
        """
        if "producer_time" in _table_columns(conn, "sensor_history"):
            return
        conn.commit()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if "producer_time" not in _table_columns(conn, "sensor_history"):
                conn.execute(
                    "ALTER TABLE sensor_history ADD COLUMN producer_time TEXT "
                    "NOT NULL DEFAULT 'unknown' CHECK "
                    "(producer_time IN ('reported', 'not_reported', 'unknown'))"
                )
            conn.commit()
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

    def _refuse_unreceipted_history_unless_allowed(self) -> None:
        """Raise before any write when the store needs the rebuild and this opener may not do it."""
        if self._allow_history_rebuild or self._db_path == ":memory:":
            return
        path = Path(self._db_path)
        if not path.is_file():
            return
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            missing, counts = _unreceipted_history(conn)
        finally:
            conn.close()
        if missing:
            raise HistoryReceiptMigrationRequiredError(
                f"history tables {', '.join(missing)} predate the receipt column; "
                f"migrating rebuilds them and discards {sum(counts.values())} rows "
                f"({counts}). Nothing was changed. Start the runtime under this "
                "release to migrate; a read-only tool does not."
            )

    def _rebuild_history_schema_if_unreceipted(self, conn: sqlite3.Connection) -> None:
        """Discard history rows that carry no receipt; the loss is logged, never silent.

        A row written before the store recorded receipts has only the producer's
        clock, and copying that into the receipt would rank the store's history
        on the very value this schema exists to keep out of rankings. The
        rebuild is one transaction: a failure leaves the old tables and rows.
        """
        missing, counts = _unreceipted_history(conn)
        if not missing:
            return
        if not self._allow_history_rebuild:
            raise HistoryReceiptMigrationRequiredError(
                f"history tables {', '.join(missing)} predate the receipt column; "
                f"migrating rebuilds them and discards {sum(counts.values())} rows "
                f"({counts}). Nothing was changed. Start the runtime under this "
                "release to migrate; a read-only tool does not."
            )
        conn.commit()
        try:
            conn.execute("BEGIN IMMEDIATE")
            for statement in _history_rebuild_statements():
                conn.execute(statement)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        logger.warning(
            "[store] history tables predate the receipt column (%s); rebuilt "
            "them and discarded %d rows (%s). Rows without a receipt cannot be "
            "ranked as current or aged, so they are not carried forward.",
            ", ".join(missing),
            sum(counts.values()),
            counts,
        )

    def _migrate_alert_outbox_receipt(self, conn: sqlite3.Connection) -> None:
        """Queue order is arrival; rows from before the column get the migration moment."""
        if "queued_at_ms" not in _table_columns(conn, "alert_outbox"):
            self._add_column_if_missing_on_conn(
                conn, "alert_outbox", "queued_at_ms", "INTEGER NOT NULL DEFAULT 0"
            )
        conn.execute(
            "UPDATE alert_outbox SET queued_at_ms = ? WHERE queued_at_ms <= 0",
            (now_ms(),),
        )
        for name in _LEGACY_OUTBOX_INDEXES:
            conn.execute(f"DROP INDEX IF EXISTS {name}")
        conn.commit()

    def _add_action_record_kind(self, conn: sqlite3.Connection) -> None:
        """record_kind on an action log, held on every open, not only the first.

        A joined row records a request that performed nothing, so it is a
        contributor; one the previous release wrote has no holder link, and
        nothing is invented to make one. This runs on every open because a
        rolled-back release keeps writing joined rows as ordinary ones, and a
        roll-forward must reclassify those too. A legacy row still awaiting
        attestation is settled refused as history, not reported as corrupt.
        Added columns cannot carry the table's CHECKs, so the writer and the
        readers hold the shape on such a database.
        """
        self._add_column_if_missing_on_conn(
            conn, "action_log", "record_kind", "TEXT NOT NULL DEFAULT 'dispatch'"
        )
        self._add_column_if_missing_on_conn(
            conn, "action_log", "record_key", "TEXT NOT NULL DEFAULT ''"
        )
        self._add_column_if_missing_on_conn(
            conn, "action_log", "contributed_to", "TEXT"
        )
        conn.execute(
            "UPDATE action_log SET record_kind = 'contributor_legacy'"
            " WHERE action_taken = 'coalesced' AND record_kind = 'dispatch'"
        )
        # Any other row whose fields disagree with its kind, which only a table
        # without the CHECKs can hold, is rewritten to what every reader reads
        # it as (_action_record_members), so attestation, the summary and the
        # exports agree. It is never attested once rewritten.
        rows = conn.execute(
            "SELECT id, record_kind, record_key, contributed_to, action_taken,"
            " executed, attestation_status FROM action_log"
            f" WHERE {_ACTION_RECORD_CANDIDATES}"
        ).fetchall()
        rewritten: list[tuple[str, int]] = []
        for row in rows:
            read = _action_record_members(row)
            if (row["record_kind"], row["contributed_to"]) == (
                read["record_kind"],
                read["contributed_to"],
            ):
                continue
            conn.execute(
                "UPDATE action_log SET record_kind = ?, contributed_to = NULL,"
                " attestation_status = CASE WHEN attestation_status IN"
                " ('pending', 'failed') THEN 'refused' ELSE attestation_status END,"
                " attestation_reason = CASE WHEN attestation_status IN"
                " ('pending', 'failed') THEN 'reclassified_record'"
                " ELSE attestation_reason END"
                " WHERE id = ?",
                (read["record_kind"], int(row["id"])),
            )
            rewritten.append((read["record_kind"], int(row["id"])))
        if rewritten:
            logger.critical(
                "[action_log] %d rows' fields disagreed with their record kind and "
                "are recorded as every reader reads them, never attested: %s",
                len(rewritten),
                rewritten[:20],
            )
        conn.execute(
            "UPDATE action_log SET attestation_status = 'refused',"
            " attestation_reason = 'legacy_contributor'"
            " WHERE record_kind = 'contributor_legacy'"
            " AND attestation_status IN ('pending', 'failed')"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_action_log_record_key"
            " ON action_log(record_key)"
        )
        # A key names one row. Rows a rolled-back release wrote carry the
        # default '' and stay outside the constraint. Keys already duplicated
        # are reported, not a reason to refuse the store: Tier D does not wait
        # on evidence, and the unresolved count treats such a key as no link.
        # Every later write is still held to one row per key, by triggers
        # where the index cannot be built.
        try:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_action_log_record_key_unique"
                " ON action_log(record_key) WHERE record_key <> ''"
            )
        except sqlite3.IntegrityError:
            logger.critical(
                "[action_log] record keys are duplicated, so a contributor's link "
                "cannot name one holder row; those links are counted unresolved "
                "until the rows are repaired, and no new key may reuse one"
            )
            for statement in _RECORD_KEY_UNIQUE_TRIGGERS:
                conn.execute(statement)
        else:
            for name in _RECORD_KEY_UNIQUE_TRIGGER_NAMES:
                conn.execute(f"DROP TRIGGER IF EXISTS {name}")

    def _rebuild_proof_observation_if_legacy(self, conn: sqlite3.Connection) -> bool:
        """Rebuild a legacy proof table, or finish one a crash left; whether it did.

        One transaction, so a failure leaves the store as it was. A store an
        earlier, non-atomic rebuild stranded holds the old rows under
        `_commissioning_proof_observation_legacy`: they are carried into the
        table now, every observation it does not already hold, matched by its
        consent rather than its id, and the legacy table dropped.
        """
        legacy = "_commissioning_proof_observation_legacy"
        stranded = (
            conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (legacy,),
            ).fetchone()
            is not None
        )
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(commissioning_proof_observation)"
            )
        }
        if "executed" not in columns and not stranded:
            return False
        if "executed" in columns and stranded:
            raise sqlite3.DatabaseError(
                "the commissioning proof table and its legacy copy both hold "
                "the old schema; the store needs repair before it can open"
            )
        if conn.in_transaction:
            # Earlier steps' implicit transaction: committed here, as the
            # schema script this replaced did, so the rebuild is its own step.
            conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        try:
            if "executed" in columns:
                conn.execute(
                    f"ALTER TABLE commissioning_proof_observation RENAME TO {legacy}"
                )
                conn.execute(_PROOF_OBSERVATION_DDL)
            # A row is the same observation by its consent, never by its id:
            # rows written after an earlier rebuild stranded these reuse the
            # ids, the legacy table having taken the id sequence with it.
            # Rows whose id is free keep it; the rest take fresh ids after.
            for ids in ("keep", "fresh"):
                conn.execute(
                    f"""
                    INSERT INTO commissioning_proof_observation
                        (id, binding_hash, zone_id, gpio_pin, active_high, outcome,
                         coil_state_commanded, level_driven, consent_nonce,
                         consented_at_ms, commanded_at_ms, command_issued,
                         effect_verified, operator_attestation, release_requested,
                         held_ms, observation_json, outcome_note)
                    SELECT {"old.id" if ids == "keep" else "NULL"},
                           old.binding_hash, old.zone_id, old.gpio_pin,
                           old.active_high, old.outcome, old.coil_state_commanded,
                           old.level_driven, old.consent_nonce, old.consented_at_ms,
                           old.commanded_at_ms, old.executed, 0, NULL, 0, 0,
                           old.observation_json, old.outcome_note
                      FROM {legacy} AS old
                     WHERE NOT EXISTS (
                             SELECT 1 FROM commissioning_proof_observation AS cur
                              WHERE cur.binding_hash = old.binding_hash
                                AND cur.consent_nonce = old.consent_nonce
                                AND cur.consented_at_ms = old.consented_at_ms)
                       AND old.id {"NOT IN" if ids == "keep" else "IN"}
                           (SELECT id FROM commissioning_proof_observation)
                     ORDER BY old.id
                    """  # noqa: S608 - fixed names
                )
            conn.execute(f"DROP TABLE {legacy}")
            conn.commit()
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise
        return True

    def _add_column_if_missing_on_conn(
        self,
        conn: sqlite3.Connection,
        table: str,
        column: str,
        typedef: str,
    ) -> None:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {typedef}")
        except sqlite3.OperationalError as exc:
            msg = str(exc).lower()
            if "duplicate column name" in msg:
                return
            raise
