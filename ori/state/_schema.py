# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The store's DDL and the history tables it names."""

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

-- What the commissioning proof operation did, one row per command. The consent
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
