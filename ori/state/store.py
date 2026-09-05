# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import datetime
import hashlib
import json
import os
import sqlite3
from typing import Any, Callable, Concatenate, Optional, ParamSpec, TypeVar
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ori.network.events import ActionResult, OriEvent, ReasoningResult, SensorReading
from ori.utils.time_utils import now_ms

_P = ParamSpec("_P")
_T = TypeVar("_T")

_INPUT_ATTESTATION_GRADES = frozenset({"attested", "attested_dev", "unattested"})
_INPUT_POSTURES = frozenset({"development", "sealed_flash", "hardware_key"})


def _normalise_input_attestation_grade(value: Any) -> str:
    grade = str(value or "").strip().lower()
    return grade if grade in _INPUT_ATTESTATION_GRADES else "unattested"


def _normalise_input_evidence(grade_value: Any, posture_value: Any) -> tuple[str, str]:
    grade = _normalise_input_attestation_grade(grade_value)
    posture = str(posture_value or "").strip().lower()
    if grade == "unattested":
        return "unattested", ""
    if grade == "attested_dev":
        if posture == "development":
            return "attested_dev", "development"
        return "unattested", ""
    if posture in _INPUT_POSTURES - {"development"}:
        return "attested", posture
    return "unattested", ""


_DDL = """
CREATE TABLE IF NOT EXISTS sensor_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id   TEXT    NOT NULL,
    sensor_type TEXT    NOT NULL,
    value       REAL    NOT NULL,
    unit        TEXT    NOT NULL,
    timestamp   INTEGER NOT NULL,
    quality     REAL    NOT NULL,
    metadata    TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_sensor_history_sensor_id_ts
    ON sensor_history (sensor_id, timestamp DESC);

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
    timestamp         INTEGER NOT NULL
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
    reading_timestamp        INTEGER,
    history_window_json      TEXT    NOT NULL DEFAULT 'null',
    skill_name               TEXT    NOT NULL DEFAULT '',
    trigger_name             TEXT    NOT NULL DEFAULT '',
    proposed_action          TEXT    NOT NULL DEFAULT '',
    confidence               REAL    NOT NULL DEFAULT 0,
    reasoning_tier           TEXT    NOT NULL DEFAULT '',
    reasoning_model          TEXT    NOT NULL DEFAULT '',
    prompt_context_summary   TEXT    NOT NULL DEFAULT '',
    operator_decision        TEXT    NOT NULL DEFAULT '', -- 'approved' | 'rejected' | 'timeout'
    operator_response        TEXT,
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
    action_tier     TEXT    NOT NULL,   -- 'A' | 'B' | 'C' | 'D'
    trigger_name    TEXT    NOT NULL DEFAULT '',
    original_ts     INTEGER NOT NULL,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    last_attempt_ts INTEGER,
    status          TEXT    NOT NULL DEFAULT 'pending' -- 'pending' | 'failed' | 'delivered' | 'abandoned'
);

CREATE INDEX IF NOT EXISTS idx_alert_outbox_status_tier_ts
    ON alert_outbox (status, action_tier, original_ts ASC);

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

CREATE TABLE IF NOT EXISTS sensor_history_5min (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    bucket_ms INTEGER NOT NULL,
    avg_value REAL NOT NULL,
    unit TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    UNIQUE(sensor_id, bucket_ms)
);

CREATE TABLE IF NOT EXISTS sensor_history_hourly (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    bucket_ms INTEGER NOT NULL,
    avg_value REAL NOT NULL,
    unit TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    UNIQUE(sensor_id, bucket_ms)
);

CREATE TABLE IF NOT EXISTS sensor_history_daily (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    bucket_ms INTEGER NOT NULL,
    avg_value REAL NOT NULL,
    unit TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    UNIQUE(sensor_id, bucket_ms)
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

CREATE TABLE IF NOT EXISTS firmware_fault_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id         TEXT    NOT NULL,
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
    UNIQUE(device_id, boot_id, seq)
);

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


#: The oldest SQLite this store's queries are known to run on.
#:
#: The sensor-history averages and the compaction read path use a ``HAVING``
#: clause on an aggregate query that has no ``GROUP BY``. SQLite refused that
#: form with ``a GROUP BY clause is required before HAVING`` until it was
#: allowed on any aggregate query, so on an older library those reads fail at
#: query time rather than at startup. An operator meets that as a skill that
#: stopped working, which is the wrong place to learn the platform is
#: unsupported.
#:
#: Measured rather than inferred from release notes. 3.34.1 (Debian Bullseye)
#: and 3.37.2 (Ubuntu 22.04) refuse the form; 3.40.1 (Debian Bookworm) and
#: 3.46.1 (Debian Trixie) accept it, which bounds the floor to this release.
#:
#: ``sqlite3`` binds to whatever library the host supplies, so this is the one
#: dependency the hash-locked wheelhouse cannot pin. The stock distribution
#: tuples this runtime is tested on clear the floor with their own libraries:
#: Debian Bookworm 3.40.1, Ubuntu 24.04 3.45.1, Debian Trixie 3.46.1.
#:
#: Clearing the interpreter floor does not imply clearing this one, and the two
#: must not be conflated. A newer Python built by hand on an older
#: distribution -- the trusted-symlink shape the installer admits by design --
#: satisfies the interpreter requirement while the host library stays where the
#: distribution left it. That combination is what this refusal exists to
#: catch.
MINIMUM_SQLITE_VERSION = (3, 39, 0)


class UnsupportedSQLiteError(RuntimeError):
    """The host's SQLite library is too old for this store's queries."""


def require_supported_sqlite() -> None:
    """Refuse a SQLite that cannot run the queries this store issues.

    Compared as a tuple of integers. Comparing the version *strings* would
    order ``"3.9"`` after ``"3.40"``, so a lexical check would admit exactly
    the old libraries this exists to refuse.
    """
    if sqlite3.sqlite_version_info >= MINIMUM_SQLITE_VERSION:
        return
    required = ".".join(str(part) for part in MINIMUM_SQLITE_VERSION)
    raise UnsupportedSQLiteError(
        f"SQLite {sqlite3.sqlite_version} is too old for this runtime; "
        f"{required} or newer is required. Python's `sqlite3` uses the library "
        f"the host supplies, so this is a property of the platform rather than "
        f"of the installed dependencies -- upgrade the distribution, or build "
        f"the interpreter against a newer SQLite."
    )


class StateStore:
    """Async-safe SQLite state store.

    All blocking SQLite calls are dispatched to a thread-pool executor so the
    asyncio event loop is never blocked.
    """

    def __init__(self, db_path: str = "ori_state.db") -> None:
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._write_lock = asyncio.Lock()
        self._lifecycle_lock = asyncio.Lock()

    # ─── Lifecycle ────────────────────────────────────────────────────────────

    async def open(self) -> None:
        """Open the database connection and apply DDL migrations."""
        async with self._lifecycle_lock:
            if self._conn is not None:
                return
            conn = await asyncio.to_thread(self._open_sync)
            self._conn = conn

    def _open_sync(self) -> sqlite3.Connection:
        # Refuse here rather than at import, so a tool that merely imports this
        # module on an unsupported host still runs. Opening the store is the
        # first moment the requirement is real.
        #
        # Checking only here is complete rather than merely convenient. The
        # read path in `_open_read_conn_sync` is what actually issues the
        # query this floor exists for, and it is reachable only through an
        # opened store -- but the reason one check suffices is that
        # `sqlite3.sqlite_version_info` is fixed for the life of the process.
        # It cannot become false after this returns, so re-checking per
        # connection would cost a comparison on every read to re-establish
        # something already known.
        require_supported_sqlite()
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._restrict_db_file_permissions()
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        self._migrate_sync(conn)
        return conn

    def _restrict_db_file_permissions(self) -> None:
        """Keep local SQLite state readable/writable only by the runtime user."""
        if self._db_path == ":memory:":
            return
        try:
            os.chmod(self._db_path, 0o600)
        except FileNotFoundError:
            return
        except PermissionError:
            return

    async def close(self) -> None:
        async with self._lifecycle_lock:
            async with self._write_lock:
                conn = self._conn
                self._conn = None
            if conn is not None:
                await asyncio.to_thread(conn.close)

    def _migrate_sync(self, conn: sqlite3.Connection) -> None:
        conn.executescript(_DDL)
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
        # A bench device commissioned on an earlier build of this branch holds
        # the proof table with `executed` and none of the facts that replaced
        # it. `CREATE TABLE IF NOT EXISTS` leaves such a row set untouched, and
        # adding the new columns is not enough on its own: the legacy
        # `executed` is NOT NULL with no default, so every later insert fails.
        # The table is rebuilt instead, carrying the recorded commands across.
        legacy = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(commissioning_proof_observation)"
            )
        }
        if "executed" in legacy:
            conn.execute(
                "ALTER TABLE commissioning_proof_observation RENAME TO "
                "_commissioning_proof_observation_legacy"
            )
            conn.executescript(_DDL)
            conn.execute(
                """
                INSERT INTO commissioning_proof_observation
                    (id, binding_hash, zone_id, gpio_pin, active_high, outcome,
                     coil_state_commanded, level_driven, consent_nonce,
                     consented_at_ms, commanded_at_ms, command_issued,
                     effect_verified, operator_attestation, release_requested,
                     held_ms, observation_json, outcome_note)
                SELECT id, binding_hash, zone_id, gpio_pin, active_high, outcome,
                       coil_state_commanded, level_driven, consent_nonce,
                       consented_at_ms, commanded_at_ms, executed,
                       0, NULL, 0, 0, observation_json, outcome_note
                  FROM _commissioning_proof_observation_legacy
                """
            )
            conn.execute("DROP TABLE _commissioning_proof_observation_legacy")
            conn.commit()
        else:
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
        self._add_column_if_missing_on_conn(
            conn,
            "tier_c_decision_log",
            "proposal_id",
            "TEXT    NOT NULL DEFAULT ''",
        )
        self._add_column_if_missing_on_conn(
            conn,
            "remote_command_log",
            "from_number",
            "TEXT    NOT NULL DEFAULT ''",
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

    async def _run_write(
        self, fn: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs
    ) -> _T:
        """Run a synchronous write callable in the executor under write lock."""
        async with self._write_lock:
            return await asyncio.to_thread(fn, *args, **kwargs)

    async def _run_read(
        self,
        fn: Callable[Concatenate[sqlite3.Connection, _P], _T],
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> _T:
        """Run a synchronous read callable in the executor without write lock."""
        if self._db_path == ":memory:":
            # In-memory SQLite cannot be shared with short-lived read
            # connections, so route reads through the primary connection
            # under the write lock to avoid cross-thread misuse.
            def call_primary() -> _T:
                return self._run_read_on_primary_conn(fn, *args, **kwargs)

            return await self._run_write(call_primary)

        def call_with_conn() -> _T:
            return self._run_read_with_conn(fn, *args, **kwargs)

        return await asyncio.to_thread(call_with_conn)

    def _run_read_on_primary_conn(
        self,
        fn: Callable[Concatenate[sqlite3.Connection, _P], _T],
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> _T:
        assert self._conn is not None
        return fn(self._conn, *args, **kwargs)

    def _run_read_with_conn(
        self,
        fn: Callable[Concatenate[sqlite3.Connection, _P], _T],
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> _T:
        conn, close_when_done = self._open_read_conn_sync()
        try:
            return fn(conn, *args, **kwargs)
        finally:
            if close_when_done:
                conn.close()

    def _open_read_conn_sync(self) -> tuple[sqlite3.Connection, bool]:
        """Open a short-lived read connection safe for concurrent executor threads."""
        if self._db_path == ":memory:":
            assert self._conn is not None
            return self._conn, False

        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn, True

    async def _run(self, fn, *args):
        """Backward-compatible wrapper for legacy callers/tests."""
        return await self._run_write(fn, *args)

    # ─── sensor_history ───────────────────────────────────────────────────────

    async def compact_history(self, max_backward_skew_ms: int = 3600000) -> None:
        """Compact raw sensor history into time-bucketed averages.

        Call from runtime.py via asyncio.create_task() on a 5-minute
        schedule using asyncio periodic task pattern.
        """
        current_ms = now_ms()
        cutoffs = {
            "raw": current_ms - (48 * 3600 * 1000),  # 48 hours
            "5min": current_ms - (30 * 86400 * 1000),  # 30 days
            "hourly": current_ms - (365 * 86400 * 1000),  # 1 year
        }
        await self._run_write(
            self._compact_sync,
            cutoffs,
            current_ms,
            max_backward_skew_ms,
        )

    def _compact_sync(
        self,
        cutoffs: dict,
        now_ms: int,
        max_backward_skew_ms: int = 3600000,
    ) -> None:
        if self._conn is None:
            raise RuntimeError("StateStore is not open")

        if max_backward_skew_ms < 0:
            raise RuntimeError("Invalid compaction skew threshold: must be >= 0")

        if not (cutoffs["hourly"] < cutoffs["5min"] < cutoffs["raw"] < now_ms):
            raise RuntimeError(
                "Invalid compaction cutoffs: must be strictly ordered in the past"
            )

        row = self._conn.execute(
            """
            SELECT MAX(t) as max_ts FROM (
                SELECT MAX(timestamp) as t FROM sensor_history
                UNION ALL
                SELECT MAX(bucket_ms) as t FROM sensor_history_5min
                UNION ALL
                SELECT MAX(bucket_ms) as t FROM sensor_history_hourly
                UNION ALL
                SELECT MAX(bucket_ms) as t FROM sensor_history_daily
            )
            """
        ).fetchone()

        if row and row["max_ts"] is not None:
            db_max_ts = row["max_ts"]
            if now_ms + max_backward_skew_ms < db_max_ts:
                raise RuntimeError(
                    f"Clock skew detected: now_ms ({now_ms}) is behind db_max_ts ({db_max_ts}) by more than {max_backward_skew_ms}ms"
                )

        # 1. Aggregate raw → 5-minute buckets older than 48h
        self._conn.execute(
            """
            INSERT OR IGNORE INTO sensor_history_5min
            (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count)
            SELECT sensor_id, sensor_type,
                   (timestamp / 300000) * 300000 AS bucket_ms,
                   AVG(value), unit, COUNT(*)
            FROM sensor_history
            WHERE timestamp < ?
            GROUP BY sensor_id, (timestamp / 300000)
        """,
            (cutoffs["raw"],),
        )

        # 2. Delete raw rows older than 48h
        self._conn.execute(
            "DELETE FROM sensor_history WHERE timestamp < ?", (cutoffs["raw"],)
        )

        # 3. Aggregate 5-min → hourly buckets older than 30d
        self._conn.execute(
            """
            INSERT OR IGNORE INTO sensor_history_hourly
            (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count)
            SELECT sensor_id, sensor_type,
                   (bucket_ms / 3600000) * 3600000,
                   SUM(avg_value * sample_count) / SUM(sample_count), unit, SUM(sample_count)
            FROM sensor_history_5min
            WHERE bucket_ms < ?
            GROUP BY sensor_id, (bucket_ms / 3600000)
        """,
            (cutoffs["5min"],),
        )
        self._conn.execute(
            "DELETE FROM sensor_history_5min WHERE bucket_ms < ?", (cutoffs["5min"],)
        )

        # 4. Aggregate hourly → daily buckets older than 1 year
        self._conn.execute(
            """
            INSERT OR IGNORE INTO sensor_history_daily
            (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count)
            SELECT sensor_id, sensor_type,
                   (bucket_ms / 86400000) * 86400000,
                   SUM(avg_value * sample_count) / SUM(sample_count), unit, SUM(sample_count)
            FROM sensor_history_hourly
            WHERE bucket_ms < ?
            GROUP BY sensor_id, (bucket_ms / 86400000)
        """,
            (cutoffs["hourly"],),
        )
        self._conn.execute(
            "DELETE FROM sensor_history_hourly WHERE bucket_ms < ?",
            (cutoffs["hourly"],),
        )

        self._conn.commit()

    async def append_history(self, event: OriEvent) -> None:
        """Persist a sensor reading from an OriEvent."""
        if event.reading is None:
            return
        r = event.reading
        await self._run_write(self._insert_reading_sync, r)

    def _insert_reading_sync(self, r: SensorReading) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO sensor_history
                (sensor_id, sensor_type, value, unit, timestamp, quality, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                r.sensor_id,
                r.sensor_type,
                r.value,
                r.unit,
                r.timestamp,
                r.quality,
                json.dumps(r.metadata),
            ),
        )
        self._conn.commit()

    async def get_history(
        self, sensor_id: str, limit: int = 100
    ) -> list[SensorReading]:
        return await self._run_read(self._get_history_sync, sensor_id, limit)

    def hooks_get_history(
        self, sensor_id: str, limit: int = 100
    ) -> list[SensorReading]:
        """Stable sync facade for hook history lookups."""
        return self._run_read_with_conn(self._get_history_sync, sensor_id, limit)

    def _get_history_sync(
        self, conn: sqlite3.Connection, sensor_id: str, limit: int
    ) -> list[SensorReading]:
        rows = conn.execute(
            """
            SELECT sensor_id, sensor_type, value, unit, timestamp, quality, metadata
            FROM sensor_history
            WHERE sensor_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (sensor_id, limit),
        ).fetchall()
        return [
            SensorReading(
                sensor_id=row["sensor_id"],
                sensor_type=row["sensor_type"],
                value=row["value"],
                unit=row["unit"],
                timestamp=row["timestamp"],
                quality=row["quality"],
                metadata=json.loads(row["metadata"]),
            )
            for row in rows
        ]

    async def avg_last_n(self, sensor_id: str, n: int) -> Optional[float]:
        """Average of the n most-recent readings for a sensor."""
        return await self._run_read(self._avg_last_n_sync, sensor_id, n)

    def hooks_avg_last_n(self, sensor_id: str, n: int) -> Optional[float]:
        """Stable sync facade for hook rolling-N average lookups."""
        return self._run_read_with_conn(self._avg_last_n_sync, sensor_id, n)

    def _avg_last_n_sync(
        self, conn: sqlite3.Connection, sensor_id: str, n: int
    ) -> Optional[float]:
        row = conn.execute(
            """
            SELECT AVG(value) AS avg_val
            FROM (
                SELECT value
                FROM sensor_history
                WHERE sensor_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            )
            """,
            (sensor_id, n),
        ).fetchone()
        return row["avg_val"] if row else None

    async def avg_last_hours(self, sensor_id: str, hours: int) -> Optional[float]:
        """Average of all readings within the last *hours* hours."""
        return await self._run_read(self._avg_last_hours_sync, sensor_id, hours)

    def hooks_avg_last_hours(self, sensor_id: str, hours: int) -> Optional[float]:
        """Stable sync facade for hook average-over-hours lookups."""
        return self._run_read_with_conn(self._avg_last_hours_sync, sensor_id, hours)

    def _avg_last_hours_sync(
        self, conn: sqlite3.Connection, sensor_id: str, hours: int
    ) -> Optional[float]:
        cutoff_ms = now_ms() - hours * 3_600_000

        # Weighted average across all tiers to seamlessly span compaction boundaries
        row = conn.execute(
            """
            SELECT SUM(val * cnt) / SUM(cnt) AS avg_val
            FROM (
                SELECT value AS val, 1 AS cnt
                FROM sensor_history
                WHERE sensor_id = ? AND timestamp >= ?
                UNION ALL
                SELECT avg_value AS val, sample_count AS cnt
                FROM sensor_history_5min
                WHERE sensor_id = ? AND bucket_ms >= ?
                UNION ALL
                SELECT avg_value AS val, sample_count AS cnt
                FROM sensor_history_hourly
                WHERE sensor_id = ? AND bucket_ms >= ?
                UNION ALL
                SELECT avg_value AS val, sample_count AS cnt
                FROM sensor_history_daily
                WHERE sensor_id = ? AND bucket_ms >= ?
            )
            HAVING SUM(cnt) > 0
            """,
            (
                sensor_id,
                cutoff_ms,
                sensor_id,
                cutoff_ms,
                sensor_id,
                cutoff_ms,
                sensor_id,
                cutoff_ms,
            ),
        ).fetchone()
        return row["avg_val"] if row and row["avg_val"] is not None else None

    async def time_of_week_baseline(
        self,
        *,
        sensor_id: str,
        reference_timestamp_ms: int,
        timezone: str = "UTC",
        lookback_weeks: int = 8,
        min_weeks: int = 3,
    ) -> dict[str, Any]:
        """Return a site-local same-weekday/hour baseline from hourly history."""
        return await self._run_read(
            self._time_of_week_baseline_sync,
            sensor_id,
            reference_timestamp_ms,
            timezone,
            lookback_weeks,
            min_weeks,
        )

    def hooks_time_of_week_baseline(
        self,
        sensor_id: str,
        reference_timestamp_ms: int,
        timezone: str = "UTC",
        lookback_weeks: int = 8,
        min_weeks: int = 3,
    ) -> dict[str, Any]:
        """Stable sync facade for hook site-local baseline lookups."""
        return self._run_read_with_conn(
            self._time_of_week_baseline_sync,
            sensor_id,
            reference_timestamp_ms,
            timezone,
            lookback_weeks,
            min_weeks,
        )

    def _time_of_week_baseline_sync(
        self,
        conn: sqlite3.Connection,
        sensor_id: str,
        reference_timestamp_ms: int,
        timezone: str,
        lookback_weeks: int,
        min_weeks: int,
    ) -> dict[str, Any]:
        lookback = max(1, min(int(lookback_weeks), 52))
        min_required_weeks = max(1, min(int(min_weeks), lookback))
        reference_ms = int(reference_timestamp_ms)
        tz_name = str(timezone or "UTC").strip() or "UTC"
        try:
            tz = ZoneInfo(tz_name)
        except ZoneInfoNotFoundError:
            tz_name = "UTC"
            tz = ZoneInfo("UTC")

        reference_dt = datetime.datetime.fromtimestamp(reference_ms / 1000.0, tz=tz)
        target_weekday = int(reference_dt.weekday())
        target_hour = int(reference_dt.hour)
        start_ms = reference_ms - (lookback * 7 * 24 * 3_600_000)

        rows = conn.execute(
            """
            SELECT bucket_ms, avg_value, sample_count, unit
            FROM sensor_history_hourly
            WHERE sensor_id = ?
              AND bucket_ms >= ?
              AND bucket_ms < ?
            ORDER BY bucket_ms ASC
            """,
            (str(sensor_id), int(start_ms), reference_ms),
        ).fetchall()

        total = 0.0
        sample_count = 0
        covered_weeks: set[tuple[int, int]] = set()
        unit = ""
        for row in rows:
            bucket_ms = int(row["bucket_ms"])
            local_dt = datetime.datetime.fromtimestamp(bucket_ms / 1000.0, tz=tz)
            if local_dt.weekday() != target_weekday or local_dt.hour != target_hour:
                continue
            count = max(0, int(row["sample_count"] or 0))
            if count <= 0:
                continue
            value = float(row["avg_value"])
            total += value * count
            sample_count += count
            iso = local_dt.isocalendar()
            covered_weeks.add((int(iso.year), int(iso.week)))
            unit = str(row["unit"] or unit)

        covered_week_count = len(covered_weeks)
        avg_value = (total / sample_count) if sample_count > 0 else None
        usable = sample_count > 0 and covered_week_count >= min_required_weeks
        if sample_count <= 0:
            reason = "no_history"
        elif not usable:
            reason = "low_coverage"
        else:
            reason = "ok"

        return {
            "sensor_id": str(sensor_id),
            "reference_timestamp_ms": reference_ms,
            "timezone": tz_name,
            "target_weekday": target_weekday,
            "target_hour": target_hour,
            "lookback_weeks": lookback,
            "min_weeks": min_required_weeks,
            "avg_value": avg_value,
            "unit": unit,
            "sample_count": sample_count,
            "covered_weeks": covered_week_count,
            "usable": usable,
            "reason": reason,
            "tier": "hourly",
        }

    async def get_latest_readings_snapshot(
        self,
        exclude_sensor_id: str,
        since_ms: int,
        max_entries: int,
    ) -> list[SensorReading]:
        """Return the most-recent reading per sensor_id fresher than since_ms.

        The triggering sensor (exclude_sensor_id) is always excluded.
        Results are bounded to max_entries, ordered by sensor_id for
        deterministic prompt output across calls.
        """
        return await self._run_read(
            self._get_latest_readings_snapshot_sync,
            exclude_sensor_id,
            since_ms,
            max_entries,
        )

    def _get_latest_readings_snapshot_sync(
        self,
        conn: sqlite3.Connection,
        exclude_sensor_id: str,
        since_ms: int,
        max_entries: int,
    ) -> list[SensorReading]:
        # Uses a derived-table join rather than a correlated subquery so the
        # planner resolves each sensor's MAX(timestamp) in a single index pass
        # over (sensor_id, timestamp DESC) before joining back to the full row.
        # The correlated-subquery form re-executes the inner SELECT for every
        # outer candidate row — O(N_candidates × log N_table) vs O(N_candidates).
        rows = conn.execute(
            """
            SELECT h.sensor_id, h.sensor_type, h.value, h.unit,
                   h.timestamp, h.quality, h.metadata
            FROM sensor_history AS h
            INNER JOIN (
                SELECT sensor_id, MAX(timestamp) AS max_ts
                FROM sensor_history
                WHERE sensor_id != ?
                  AND timestamp >= ?
                GROUP BY sensor_id
            ) AS latest
              ON h.sensor_id = latest.sensor_id
             AND h.timestamp = latest.max_ts
            ORDER BY h.sensor_id
            LIMIT ?
            """,
            (exclude_sensor_id, since_ms, max(1, max_entries)),
        ).fetchall()
        return [
            SensorReading(
                sensor_id=row["sensor_id"],
                sensor_type=row["sensor_type"],
                value=row["value"],
                unit=row["unit"],
                timestamp=row["timestamp"],
                quality=row["quality"],
                metadata=json.loads(row["metadata"]),
            )
            for row in rows
        ]

    async def get_timeseries(
        self, sensor_id: str, start_ms: int, end_ms: int
    ) -> list[tuple[int, float]]:
        """Fetch chart data from the appropriate compaction tier."""
        return await self._run_read(
            self._get_timeseries_sync, sensor_id, start_ms, end_ms
        )

    def _get_timeseries_sync(
        self, conn: sqlite3.Connection, sensor_id: str, start_ms: int, end_ms: int
    ) -> list[tuple[int, float]]:
        duration_ms = end_ms - start_ms

        # Choose tier based on requested range
        if duration_ms <= 48 * 3600 * 1000:
            table, time_col, val_col = "sensor_history", "timestamp", "value"
        elif duration_ms <= 30 * 86400 * 1000:
            table, time_col, val_col = "sensor_history_5min", "bucket_ms", "avg_value"
        elif duration_ms <= 365 * 86400 * 1000:
            table, time_col, val_col = "sensor_history_hourly", "bucket_ms", "avg_value"
        else:
            table, time_col, val_col = "sensor_history_daily", "bucket_ms", "avg_value"

        rows = conn.execute(
            f"""
            SELECT {time_col} AS ts, {val_col} AS val
            FROM {table}
            WHERE sensor_id = ? AND {time_col} BETWEEN ? AND ?
            ORDER BY {time_col} ASC
            """,
            (sensor_id, start_ms, end_ms),
        ).fetchall()
        return [(row["ts"], row["val"]) for row in rows]

    async def export_sensor_history(
        self,
        *,
        sensor_id: str,
        start_ms: int,
        end_ms: int,
        limit: int = 10_000,
    ) -> list[dict]:
        """Return bounded sensor history across raw and compacted tiers.

        The gateway/reporting layer should use this method instead of reaching
        into SQLite table names. Rows are ordered oldest-first and include the
        compaction tier so report generators can decide how to aggregate.
        """
        return await self._run_read(
            self._export_sensor_history_sync,
            sensor_id,
            start_ms,
            end_ms,
            limit,
        )

    def _export_sensor_history_sync(
        self,
        conn: sqlite3.Connection,
        sensor_id: str,
        start_ms: int,
        end_ms: int,
        limit: int,
    ) -> list[dict]:
        if int(end_ms) < int(start_ms):
            return []

        capped_limit = max(1, min(int(limit), 10_000))
        params: tuple[Any, ...] = (
            str(sensor_id),
            int(start_ms),
            int(end_ms),
            str(sensor_id),
            int(start_ms),
            int(end_ms),
            str(sensor_id),
            int(start_ms),
            int(end_ms),
            str(sensor_id),
            int(start_ms),
            int(end_ms),
            capped_limit,
        )
        rows = conn.execute(
            """
            SELECT *
            FROM (
                SELECT
                    sensor_id,
                    sensor_type,
                    timestamp AS timestamp,
                    value AS value,
                    unit,
                    quality,
                    1 AS sample_count,
                    'raw' AS tier
                FROM sensor_history
                WHERE sensor_id = ? AND timestamp BETWEEN ? AND ?
                UNION ALL
                SELECT
                    sensor_id,
                    sensor_type,
                    bucket_ms AS timestamp,
                    avg_value AS value,
                    unit,
                    NULL AS quality,
                    sample_count,
                    '5min' AS tier
                FROM sensor_history_5min
                WHERE sensor_id = ? AND bucket_ms BETWEEN ? AND ?
                UNION ALL
                SELECT
                    sensor_id,
                    sensor_type,
                    bucket_ms AS timestamp,
                    avg_value AS value,
                    unit,
                    NULL AS quality,
                    sample_count,
                    'hourly' AS tier
                FROM sensor_history_hourly
                WHERE sensor_id = ? AND bucket_ms BETWEEN ? AND ?
                UNION ALL
                SELECT
                    sensor_id,
                    sensor_type,
                    bucket_ms AS timestamp,
                    avg_value AS value,
                    unit,
                    NULL AS quality,
                    sample_count,
                    'daily' AS tier
                FROM sensor_history_daily
                WHERE sensor_id = ? AND bucket_ms BETWEEN ? AND ?
            )
            ORDER BY timestamp ASC
            LIMIT ?
            """,
            params,
        ).fetchall()
        return [
            {
                "sensor_id": row["sensor_id"],
                "sensor_type": row["sensor_type"],
                "timestamp": row["timestamp"],
                "value": row["value"],
                "unit": row["unit"],
                "quality": row["quality"],
                "sample_count": row["sample_count"],
                "tier": row["tier"],
            }
            for row in rows
        ]

    # ─── action_log ───────────────────────────────────────────────────────────

    async def log_action(
        self,
        result: ActionResult,
        trigger_name: str,
        *,
        attestation_pending: bool = False,
    ) -> int:
        return await self._run_write(
            self._log_action_sync,
            result,
            trigger_name,
            {"attestation_pending": attestation_pending}
            if attestation_pending
            else None,
        )

    async def log_action_for_event(
        self,
        result: ActionResult,
        *,
        trigger_name: str,
        device_id: str = "",
        sensor_id: str = "",
        sensor_type: str = "",
        input_attestation_grade: str = "unattested",
        input_posture: str = "",
        input_firmware_device_id: str = "",
        input_firmware_boot_id: int = 0,
        input_firmware_seq: int = 0,
        input_firmware_registration: str = "",
        attestation_pending: bool = False,
        binding_seq: int | None = None,
    ) -> int:
        """Persist action result with sensor/device context for reporting.

        ``input_firmware_registration`` is the provisioning snapshot with
        approval provenance, stored in the SAME insert as the action row so
        a crash cannot leave a pending action whose provenance was to be
        written by a later transaction.
        """
        return await self._run_write(
            self._log_action_sync,
            result,
            trigger_name,
            {
                "device_id": device_id,
                "sensor_id": sensor_id,
                "sensor_type": sensor_type,
                "input_attestation_grade": input_attestation_grade,
                "input_posture": input_posture,
                "input_firmware_device_id": input_firmware_device_id,
                "input_firmware_boot_id": input_firmware_boot_id,
                "input_firmware_seq": input_firmware_seq,
                "input_firmware_registration": input_firmware_registration,
                "attestation_pending": attestation_pending,
                "binding_seq": binding_seq,
            },
        )

    def _log_action_sync(
        self,
        result: ActionResult,
        trigger_name: str,
        context_fields: dict | None = None,
    ) -> int:
        assert self._conn is not None
        context_fields = context_fields or {}
        approved_int: Optional[int] = None
        if result.approved is not None:
            approved_int = 1 if result.approved else 0
        attestation_status = (
            "pending" if context_fields.get("attestation_pending") else ""
        )
        input_grade, input_posture = _normalise_input_evidence(
            context_fields.get("input_attestation_grade", "unattested"),
            context_fields.get("input_posture", ""),
        )
        cursor = self._conn.execute(
            """
            INSERT INTO action_log
                (action_name, tier, executed, approved, action_taken,
                 operator_response, proposal_id, safe_default_used, device_id,
                 sensor_id, sensor_type, input_attestation_grade, input_posture,
                 input_firmware_device_id, input_firmware_boot_id, input_firmware_seq,
                 input_firmware_registration,
                 correlation_id, trigger_name, timestamp, attestation_status,
                 binding_seq)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.action_name,
                result.tier,
                1 if result.executed else 0,
                approved_int,
                result.action_taken,
                result.operator_response,
                result.proposal_id or "",
                1 if result.safe_default_used else 0,
                str(context_fields.get("device_id", "") or ""),
                str(context_fields.get("sensor_id", "") or ""),
                str(context_fields.get("sensor_type", "") or ""),
                input_grade,
                input_posture,
                str(context_fields.get("input_firmware_device_id", "") or ""),
                int(context_fields.get("input_firmware_boot_id", 0) or 0),
                int(context_fields.get("input_firmware_seq", 0) or 0),
                str(context_fields.get("input_firmware_registration", "") or ""),
                result.correlation_id,
                trigger_name,
                result.timestamp,
                attestation_status,
                (
                    int(context_fields["binding_seq"])
                    if context_fields.get("binding_seq") is not None
                    else None
                ),
            ),
        )
        self._conn.commit()
        return int(cursor.lastrowid or 0)

    async def set_action_attestation(
        self,
        action_id: int,
        *,
        status: str,
        attestation_seq: int | None = None,
    ) -> None:
        """Record the evidence-signing outcome for one action_log row."""
        await self._run_write(
            self._set_action_attestation_sync, action_id, status, attestation_seq
        )

    def _set_action_attestation_sync(
        self,
        action_id: int,
        status: str,
        attestation_seq: int | None,
    ) -> None:
        assert self._conn is not None
        if status not in {"pending", "signed", "failed", "reconciled"}:
            raise ValueError(f"invalid attestation status: {status!r}")
        self._conn.execute(
            "UPDATE action_log SET attestation_status = ?, attestation_seq = ? "
            "WHERE id = ?",
            (status, attestation_seq, action_id),
        )
        self._conn.commit()

    async def get_actions_needing_attestation(self, limit: int = 500) -> list[dict]:
        """Rows whose evidence signing did not complete (pending/failed)."""
        return await self._run_read(self._get_actions_needing_attestation_sync, limit)

    def _get_actions_needing_attestation_sync(
        self, conn: sqlite3.Connection, limit: int
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT id, action_name, tier, executed, approved, action_taken,
                   proposal_id, safe_default_used, device_id, sensor_id,
                   sensor_type, input_attestation_grade, input_posture, correlation_id,
                   input_firmware_device_id, input_firmware_boot_id, input_firmware_seq,
                   input_firmware_registration,
                   trigger_name, timestamp, attestation_status
            FROM action_log
            WHERE attestation_status IN ('pending', 'failed')
            ORDER BY id
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
        out: list[dict] = []
        for row in rows:
            d = dict(row)
            # Restore the persisted registration snapshot so reconciliation
            # has the same durable provenance the original attestation did.
            raw = d.pop("input_firmware_registration", "") or ""
            d["input_firmware_registration"] = json.loads(raw) if raw else None
            out.append(d)
        return out

    async def get_attestation_summary(self) -> dict:
        """Aggregate evidence-signing state for health snapshots."""
        return await self._run_read(self._get_attestation_summary_sync)

    def _get_attestation_summary_sync(self, conn: sqlite3.Connection) -> dict:
        status_rows = conn.execute(
            """
            SELECT attestation_status, COUNT(*) AS n
            FROM action_log
            WHERE attestation_status != ''
            GROUP BY attestation_status
            """
        ).fetchall()
        status_counts = {str(row[0]): int(row[1]) for row in status_rows}
        last_attested = conn.execute(
            """
            SELECT MAX(id) FROM action_log
            WHERE attestation_status IN ('signed', 'reconciled')
            """
        ).fetchone()
        gap_count = int(
            status_counts.get("pending", 0) + status_counts.get("failed", 0)
        )
        return {
            "status_counts": status_counts,
            "last_attested_action_id": (
                int(last_attested[0]) if last_attested and last_attested[0] else None
            ),
            "attestation_gap_count": gap_count,
        }

    async def get_action_log(self, limit: int = 50) -> list[dict]:
        return await self._run_read(self._get_action_log_sync, limit)

    def _get_action_log_sync(self, conn: sqlite3.Connection, limit: int) -> list[dict]:
        rows = conn.execute(
            """
            SELECT action_name, tier, executed, approved, action_taken,
                   operator_response, proposal_id, safe_default_used, device_id,
                   sensor_id, sensor_type, input_attestation_grade, input_posture,
                   input_firmware_device_id, input_firmware_boot_id, input_firmware_seq,
                   correlation_id,
                   trigger_name, timestamp, attestation_status, attestation_seq
            FROM action_log
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            approved_val: Optional[bool] = None
            if row["approved"] is not None:
                approved_val = bool(row["approved"])
            result.append(
                {
                    "action_name": row["action_name"],
                    "tier": row["tier"],
                    "executed": bool(row["executed"]),
                    "approved": approved_val,
                    "action_taken": row["action_taken"],
                    "operator_response": row["operator_response"],
                    "proposal_id": row["proposal_id"],
                    "safe_default_used": bool(row["safe_default_used"]),
                    "device_id": row["device_id"],
                    "sensor_id": row["sensor_id"],
                    "sensor_type": row["sensor_type"],
                    "input_attestation_grade": row["input_attestation_grade"],
                    "input_posture": row["input_posture"],
                    "input_firmware_device_id": row["input_firmware_device_id"],
                    "input_firmware_boot_id": row["input_firmware_boot_id"],
                    "input_firmware_seq": row["input_firmware_seq"],
                    "correlation_id": row["correlation_id"],
                    "trigger_name": row["trigger_name"],
                    "timestamp": row["timestamp"],
                    "attestation_status": row["attestation_status"],
                    "attestation_seq": row["attestation_seq"],
                }
            )
        return result

    async def export_action_log(
        self,
        *,
        device_id: str | None = None,
        since_ms: int | None = None,
        until_ms: int | None = None,
        tier: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return a bounded action-log export for gateway/reporting sync."""
        return await self._run_read(
            self._export_action_log_sync,
            device_id,
            since_ms,
            until_ms,
            tier,
            limit,
        )

    def _export_action_log_sync(
        self,
        conn: sqlite3.Connection,
        device_id: str | None,
        since_ms: int | None,
        until_ms: int | None,
        tier: str | None,
        limit: int,
    ) -> list[dict]:
        where = []
        params: list[Any] = []
        if device_id:
            where.append("device_id = ?")
            params.append(str(device_id))
        if since_ms is not None:
            where.append("timestamp >= ?")
            params.append(int(since_ms))
        if until_ms is not None:
            where.append("timestamp <= ?")
            params.append(int(until_ms))
        if tier:
            where.append("tier = ?")
            params.append(str(tier).upper())
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        params.append(max(1, min(int(limit), 1000)))
        query = (
            """
            SELECT action_name, tier, executed, approved, action_taken,
                   operator_response, proposal_id, safe_default_used, device_id,
                   sensor_id, sensor_type, input_attestation_grade, input_posture,
                   input_firmware_device_id, input_firmware_boot_id, input_firmware_seq,
                   correlation_id,
                   trigger_name, timestamp, attestation_status, attestation_seq
            FROM action_log
            """
            + where_sql
            + """
            ORDER BY timestamp DESC
            LIMIT ?
            """
        )
        rows = conn.execute(query, tuple(params)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["executed"] = bool(item["executed"])
            item["approved"] = (
                bool(item["approved"]) if item["approved"] is not None else None
            )
            item["safe_default_used"] = bool(item["safe_default_used"])
            result.append(item)
        return result

    # ─── tier_c_decision_log ───────────────────────────────────────────────────

    async def log_tier_c_decision(self, **fields) -> None:
        """Persist a full Tier C proposal/decision record for analytics.

        This table is intentionally richer than ``action_log``.  It captures the
        sensor context, reasoning proposal, operator decision, latency, and final
        action outcome needed for future approval/rejection learning.
        """
        await self._run_write(self._log_tier_c_decision_sync, fields)

    def _log_tier_c_decision_sync(self, fields: dict) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO tier_c_decision_log
                (device_id, site_type, location, timezone, sensor_id, sensor_type,
                 reading_value, reading_unit, reading_timestamp, history_window_json,
                 skill_name, trigger_name, proposed_action, confidence,
                 reasoning_tier, reasoning_model, prompt_context_summary,
                 operator_decision, operator_response, decision_latency_ms,
                 approval_timeout_seconds, safe_default_action, safe_default_used,
                 action_taken, action_executed, final_action_result_json,
                 later_outcome_json, proposal_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(fields.get("device_id", "") or ""),
                str(fields.get("site_type", "") or ""),
                str(fields.get("location", "") or ""),
                str(fields.get("timezone", "") or ""),
                str(fields.get("sensor_id", "") or ""),
                str(fields.get("sensor_type", "") or ""),
                fields.get("reading_value"),
                str(fields.get("reading_unit", "") or ""),
                fields.get("reading_timestamp"),
                json.dumps(fields.get("history_window"), sort_keys=True),
                str(fields.get("skill_name", "") or ""),
                str(fields.get("trigger_name", "") or ""),
                str(fields.get("proposed_action", "") or ""),
                float(fields.get("confidence", 0.0) or 0.0),
                str(fields.get("reasoning_tier", "") or ""),
                str(fields.get("reasoning_model", "") or ""),
                str(fields.get("prompt_context_summary", "") or ""),
                str(fields.get("operator_decision", "") or ""),
                fields.get("operator_response"),
                int(fields.get("decision_latency_ms", 0) or 0),
                int(fields.get("approval_timeout_seconds", 0) or 0),
                str(fields.get("safe_default_action", "") or ""),
                1 if fields.get("safe_default_used") else 0,
                str(fields.get("action_taken", "") or ""),
                1 if fields.get("action_executed") else 0,
                json.dumps(fields.get("final_action_result", {}), sort_keys=True),
                json.dumps(fields.get("later_outcome"), sort_keys=True),
                str(fields.get("proposal_id", "") or ""),
                int(fields.get("created_at") or now_ms()),
            ),
        )
        self._conn.commit()

    async def get_tier_c_decision_log(self, limit: int = 50) -> list[dict]:
        return await self._run_read(self._get_tier_c_decision_log_sync, limit)

    def _get_tier_c_decision_log_sync(
        self, conn: sqlite3.Connection, limit: int
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT *
            FROM tier_c_decision_log
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            result.append(self._decode_tier_c_decision_row(row))
        return result

    async def export_tier_c_decision_log(
        self,
        *,
        device_id: str | None = None,
        since_ms: int | None = None,
        until_ms: int | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return a bounded Tier C decision-log export for cloud sync."""
        return await self._run_read(
            self._export_tier_c_decision_log_sync,
            device_id,
            since_ms,
            until_ms,
            limit,
        )

    def _export_tier_c_decision_log_sync(
        self,
        conn: sqlite3.Connection,
        device_id: str | None,
        since_ms: int | None,
        until_ms: int | None,
        limit: int,
    ) -> list[dict]:
        where = []
        params: list[Any] = []
        if device_id:
            where.append("device_id = ?")
            params.append(str(device_id))
        if since_ms is not None:
            where.append("created_at >= ?")
            params.append(int(since_ms))
        if until_ms is not None:
            where.append("created_at <= ?")
            params.append(int(until_ms))
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        params.append(max(1, min(int(limit), 1000)))
        query = (
            """
            SELECT *
            FROM tier_c_decision_log
            """
            + where_sql
            + """
            ORDER BY created_at DESC
            LIMIT ?
            """
        )
        rows = conn.execute(query, tuple(params)).fetchall()
        return [self._decode_tier_c_decision_row(row) for row in rows]

    @staticmethod
    def _decode_tier_c_decision_row(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["history_window"] = json.loads(item.pop("history_window_json"))
        item["safe_default_used"] = bool(item["safe_default_used"])
        item["action_executed"] = bool(item["action_executed"])
        item["final_action_result"] = json.loads(item.pop("final_action_result_json"))
        item["later_outcome"] = json.loads(item.pop("later_outcome_json"))
        return item

    # ─── inbound_messages ─────────────────────────────────────────────────────

    async def store_incoming_message(
        self,
        channel: str,
        from_number: str,
        message: str,
        received_at_ms: int | None = None,
    ) -> None:
        await self._run_write(
            self._store_incoming_message_sync,
            channel,
            from_number,
            message,
            received_at_ms if received_at_ms is not None else now_ms(),
        )

    def _store_incoming_message_sync(
        self,
        channel: str,
        from_number: str,
        message: str,
        received_at_ms: int,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO inbound_messages
                (channel, from_number, message, received_at, consumed_at)
            VALUES (?, ?, ?, ?, NULL)
            """,
            (channel, from_number, message, received_at_ms),
        )
        self._conn.commit()

    async def consume_incoming_message(
        self,
        channel: str,
        from_number: str,
        since_ms: int,
    ) -> Optional[str]:
        return await self._run_write(
            self._consume_incoming_message_sync, channel, from_number, since_ms
        )

    def _consume_incoming_message_sync(
        self,
        channel: str,
        from_number: str,
        since_ms: int,
    ) -> Optional[str]:
        assert self._conn is not None
        row = self._conn.execute(
            """
            SELECT id, message
            FROM inbound_messages
            WHERE channel = ?
              AND from_number = ?
              AND received_at >= ?
              AND consumed_at IS NULL
            ORDER BY received_at ASC, id ASC
            LIMIT 1
            """,
            (channel, from_number, since_ms),
        ).fetchone()
        if row is None:
            return None

        self._conn.execute(
            """
            UPDATE inbound_messages
            SET consumed_at = ?
            WHERE id = ? AND consumed_at IS NULL
            """,
            (now_ms(), row["id"]),
        )
        self._conn.commit()
        return str(row["message"])

    # ─── webhook_replay_log ───────────────────────────────────────────────────

    async def record_webhook_nonce(
        self,
        *,
        source: str,
        nonce: str,
        received_at_ms: int,
        expires_at_ms: int,
    ) -> bool:
        """Record a webhook nonce and return False when it is a replay."""
        return await self._run_write(
            self._record_webhook_nonce_sync,
            source,
            nonce,
            received_at_ms,
            expires_at_ms,
        )

    def _record_webhook_nonce_sync(
        self,
        source: str,
        nonce: str,
        received_at_ms: int,
        expires_at_ms: int,
    ) -> bool:
        assert self._conn is not None
        self._conn.execute(
            "DELETE FROM webhook_replay_log WHERE expires_at_ms <= ?",
            (int(received_at_ms),),
        )
        cursor = self._conn.execute(
            """
            INSERT OR IGNORE INTO webhook_replay_log
                (source, nonce, received_at_ms, expires_at_ms)
            VALUES (?, ?, ?, ?)
            """,
            (
                str(source or ""),
                str(nonce or ""),
                int(received_at_ms),
                int(expires_at_ms),
            ),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    # ─── remote_command_log ───────────────────────────────────────────────────

    async def has_remote_command(self, command_id: str) -> bool:
        return await self._run_read(self._has_remote_command_sync, command_id)

    def _has_remote_command_sync(
        self, conn: sqlite3.Connection, command_id: str
    ) -> bool:
        row = conn.execute(
            """
            SELECT 1
            FROM remote_command_log
            WHERE command_id = ? AND accepted = 1
            LIMIT 1
            """,
            (str(command_id or ""),),
        ).fetchone()
        return row is not None

    async def log_remote_command_attempt(
        self,
        *,
        command_id: str,
        channel: str,
        from_number: str = "",
        command: str,
        accepted: bool,
        reason: str,
        issued_at_ms: int | None = None,
        received_at_ms: int | None = None,
    ) -> None:
        await self._run_write(
            self._log_remote_command_attempt_sync,
            command_id,
            channel,
            from_number,
            command,
            accepted,
            reason,
            issued_at_ms,
            received_at_ms if received_at_ms is not None else now_ms(),
        )

    def _log_remote_command_attempt_sync(
        self,
        command_id: str,
        channel: str,
        from_number: str,
        command: str,
        accepted: bool,
        reason: str,
        issued_at_ms: int | None,
        received_at_ms: int,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO remote_command_log
                (command_id, channel, from_number, command, accepted, reason, issued_at_ms, received_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(command_id or ""),
                str(channel or ""),
                str(from_number or ""),
                str(command or ""),
                1 if accepted else 0,
                str(reason or ""),
                issued_at_ms,
                received_at_ms,
            ),
        )
        self._conn.commit()

    async def get_remote_command_log(self, limit: int = 50) -> list[dict]:
        return await self._run_read(self._get_remote_command_log_sync, limit)

    def _get_remote_command_log_sync(
        self, conn: sqlite3.Connection, limit: int
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT command_id, channel, from_number, command, accepted, reason, issued_at_ms, received_at_ms
            FROM remote_command_log
            ORDER BY received_at_ms DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["accepted"] = bool(item["accepted"])
            result.append(item)
        return result

    async def count_recent_remote_command_rejections(
        self,
        *,
        channel: str,
        from_number: str,
        since_ms: int,
    ) -> int:
        return await self._run_read(
            self._count_recent_remote_command_rejections_sync,
            channel,
            from_number,
            since_ms,
        )

    def _count_recent_remote_command_rejections_sync(
        self,
        conn: sqlite3.Connection,
        channel: str,
        from_number: str,
        since_ms: int,
    ) -> int:
        row = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM remote_command_log
            WHERE channel = ?
              AND from_number = ?
              AND accepted = 0
              AND received_at_ms >= ?
            """,
            (str(channel or ""), str(from_number or ""), int(since_ms)),
        ).fetchone()
        return int(row["n"] if row is not None else 0)

    async def log_remote_command_security_incident(
        self,
        *,
        incident_id: str,
        channel: str,
        from_number: str,
        reason: str,
        rejection_count: int,
        threshold: int,
        window_ms: int,
        created_at_ms: int | None = None,
    ) -> bool:
        return await self._run_write(
            self._log_remote_command_security_incident_sync,
            incident_id,
            channel,
            from_number,
            reason,
            rejection_count,
            threshold,
            window_ms,
            created_at_ms if created_at_ms is not None else now_ms(),
        )

    def _log_remote_command_security_incident_sync(
        self,
        incident_id: str,
        channel: str,
        from_number: str,
        reason: str,
        rejection_count: int,
        threshold: int,
        window_ms: int,
        created_at_ms: int,
    ) -> bool:
        assert self._conn is not None
        cursor = self._conn.execute(
            """
            INSERT OR IGNORE INTO remote_command_security_incident_log
                (incident_id, channel, from_number, reason, rejection_count,
                 threshold, window_ms, created_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(incident_id or ""),
                str(channel or ""),
                str(from_number or ""),
                str(reason or ""),
                int(rejection_count),
                int(threshold),
                int(window_ms),
                int(created_at_ms),
            ),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    async def get_remote_command_security_incidents(
        self,
        limit: int = 50,
    ) -> list[dict]:
        return await self._run_read(
            self._get_remote_command_security_incidents_sync,
            limit,
        )

    def _get_remote_command_security_incidents_sync(
        self,
        conn: sqlite3.Connection,
        limit: int,
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT incident_id, channel, from_number, reason, rejection_count,
                   threshold, window_ms, created_at_ms
            FROM remote_command_security_incident_log
            ORDER BY created_at_ms DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    async def count_recent_remote_command_security_incidents(
        self,
        *,
        channel: str,
        from_number: str,
        since_ms: int,
    ) -> int:
        return await self._run_read(
            self._count_recent_remote_command_security_incidents_sync,
            channel,
            from_number,
            since_ms,
        )

    def _count_recent_remote_command_security_incidents_sync(
        self,
        conn: sqlite3.Connection,
        channel: str,
        from_number: str,
        since_ms: int,
    ) -> int:
        row = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM remote_command_security_incident_log
            WHERE channel = ?
              AND from_number = ?
              AND created_at_ms >= ?
            """,
            (str(channel or ""), str(from_number or ""), int(since_ms)),
        ).fetchone()
        return int(row["n"] if row is not None else 0)

    async def get_recent_remote_command_incident_senders(
        self,
        *,
        since_ms: int,
        limit: int = 50,
    ) -> list[dict]:
        return await self._run_read(
            self._get_recent_remote_command_incident_senders_sync,
            since_ms,
            limit,
        )

    def _get_recent_remote_command_incident_senders_sync(
        self,
        conn: sqlite3.Connection,
        since_ms: int,
        limit: int,
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT channel, from_number, MAX(created_at_ms) AS last_incident_at_ms,
                   COUNT(*) AS incident_count
            FROM remote_command_security_incident_log
            WHERE created_at_ms >= ?
            GROUP BY channel, from_number
            ORDER BY last_incident_at_ms DESC
            LIMIT ?
            """,
            (int(since_ms), max(1, int(limit))),
        ).fetchall()
        return [dict(row) for row in rows]

    async def log_remote_command_execution(
        self,
        *,
        command_id: str,
        channel: str,
        command: str,
        status: str,
        detail: str,
        executed: bool,
        executed_at_ms: int | None = None,
    ) -> None:
        await self._run_write(
            self._log_remote_command_execution_sync,
            command_id,
            channel,
            command,
            status,
            detail,
            executed,
            executed_at_ms if executed_at_ms is not None else now_ms(),
        )

    def _log_remote_command_execution_sync(
        self,
        command_id: str,
        channel: str,
        command: str,
        status: str,
        detail: str,
        executed: bool,
        executed_at_ms: int,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO remote_command_execution_log
                (command_id, channel, command, status, detail, executed, executed_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(command_id or ""),
                str(channel or ""),
                str(command or ""),
                str(status or ""),
                str(detail or ""),
                1 if executed else 0,
                executed_at_ms,
            ),
        )
        self._conn.commit()

    async def get_remote_command_execution_log(self, limit: int = 50) -> list[dict]:
        return await self._run_read(self._get_remote_command_execution_log_sync, limit)

    def _get_remote_command_execution_log_sync(
        self, conn: sqlite3.Connection, limit: int
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT command_id, channel, command, status, detail, executed, executed_at_ms
            FROM remote_command_execution_log
            ORDER BY executed_at_ms DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["executed"] = bool(item["executed"])
            result.append(item)
        return result

    # ─── alert_outbox ─────────────────────────────────────────────────────────

    async def enqueue_alert(
        self,
        *,
        alert_id: str,
        channel: str,
        recipient: str,
        message: str,
        action_tier: str,
        trigger_name: str,
        original_ts: int,
    ) -> bool:
        """Insert an outbound alert row into alert_outbox.

        Returns:
            True if a new row was inserted, False if a row with alert_id already
            exists (deduplicated by UNIQUE constraint).
        """
        return await self._run_write(
            self._enqueue_alert_sync,
            alert_id,
            channel,
            recipient,
            message,
            action_tier,
            trigger_name,
            original_ts,
        )

    def _enqueue_alert_sync(
        self,
        alert_id: str,
        channel: str,
        recipient: str,
        message: str,
        action_tier: str,
        trigger_name: str,
        original_ts: int,
    ) -> bool:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            INSERT INTO alert_outbox
                (alert_id, channel, recipient, message, action_tier, trigger_name, original_ts, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
            ON CONFLICT(alert_id) DO NOTHING
            """,
            (
                alert_id,
                channel,
                recipient,
                message,
                action_tier,
                trigger_name,
                original_ts,
            ),
        )
        self._conn.commit()
        return int(cur.rowcount) > 0

    async def get_retryable_alerts(self, limit: int = 50) -> list[dict]:
        """Fetch pending/failed outbox alerts in oldest-first order."""
        return await self._run_read(self._get_retryable_alerts_sync, limit)

    def _get_retryable_alerts_sync(
        self,
        conn: sqlite3.Connection,
        limit: int,
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT alert_id, channel, recipient, message, action_tier,
                   trigger_name, original_ts, attempt_count, last_attempt_ts, status
            FROM alert_outbox
            WHERE status IN ('pending', 'failed')
            ORDER BY original_ts ASC, id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    async def get_alert_outbox_summary(self) -> dict[str, int | None]:
        """Return a bounded health summary for pending/failed outbound alerts."""
        return await self._run_read(self._get_alert_outbox_summary_sync)

    def _get_alert_outbox_summary_sync(
        self,
        conn: sqlite3.Connection,
    ) -> dict[str, int | None]:
        row = conn.execute(
            """
            SELECT COUNT(*) AS backlog_count,
                   MIN(original_ts) AS oldest_queued_original_ts
            FROM alert_outbox
            WHERE status IN ('pending', 'failed')
            """
        ).fetchone()
        backlog_count = int(row["backlog_count"] or 0)
        oldest_ts = (
            int(row["oldest_queued_original_ts"])
            if row["oldest_queued_original_ts"] is not None
            else None
        )
        return {
            "backlog_count": backlog_count,
            "oldest_queued_original_ts": oldest_ts,
        }

    async def mark_alert_delivered(
        self, alert_id: str, delivered_ts_ms: int | None = None
    ) -> None:
        await self._run_write(
            self._mark_alert_delivered_sync,
            alert_id,
            delivered_ts_ms if delivered_ts_ms is not None else now_ms(),
        )

    def _mark_alert_delivered_sync(self, alert_id: str, delivered_ts_ms: int) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            UPDATE alert_outbox
            SET status = 'delivered',
                last_attempt_ts = ?
            WHERE alert_id = ?
            """,
            (delivered_ts_ms, alert_id),
        )
        self._conn.commit()

    async def mark_alert_attempt_failed(
        self, alert_id: str, failed_ts_ms: int | None = None
    ) -> None:
        await self._run_write(
            self._mark_alert_attempt_failed_sync,
            alert_id,
            failed_ts_ms if failed_ts_ms is not None else now_ms(),
        )

    def _mark_alert_attempt_failed_sync(self, alert_id: str, failed_ts_ms: int) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            UPDATE alert_outbox
            SET attempt_count = attempt_count + 1,
                last_attempt_ts = ?,
                status = 'failed'
            WHERE alert_id = ?
            """,
            (failed_ts_ms, alert_id),
        )
        self._conn.commit()

    async def mark_alert_abandoned(
        self, alert_id: str, abandoned_ts_ms: int | None = None
    ) -> None:
        await self._run_write(
            self._mark_alert_abandoned_sync,
            alert_id,
            abandoned_ts_ms if abandoned_ts_ms is not None else now_ms(),
        )

    def _mark_alert_abandoned_sync(self, alert_id: str, abandoned_ts_ms: int) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            UPDATE alert_outbox
            SET status = 'abandoned',
                last_attempt_ts = ?
            WHERE alert_id = ?
            """,
            (abandoned_ts_ms, alert_id),
        )
        self._conn.commit()

    # ─── offline_token_consumption / offline_token_audit ─────────────────────

    async def claim_offline_token(
        self,
        *,
        token_id: str,
        device_id: str,
        action: str,
        consumed_at_ms: int | None = None,
    ) -> bool:
        return await self._run_write(
            self._claim_offline_token_sync,
            token_id,
            device_id,
            action,
            consumed_at_ms if consumed_at_ms is not None else now_ms(),
        )

    def _claim_offline_token_sync(
        self,
        token_id: str,
        device_id: str,
        action: str,
        consumed_at_ms: int,
    ) -> bool:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            INSERT INTO offline_token_consumption (token_id, device_id, action, consumed_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(token_id) DO NOTHING
            """,
            (token_id, device_id, action, consumed_at_ms),
        )
        self._conn.commit()
        return int(cur.rowcount) > 0

    async def log_offline_token_attempt(
        self,
        *,
        token_id: str,
        device_id: str,
        action: str,
        approved: bool,
        reason: str,
        attempted_at_ms: int | None = None,
    ) -> None:
        await self._run_write(
            self._log_offline_token_attempt_sync,
            token_id,
            device_id,
            action,
            approved,
            reason,
            attempted_at_ms if attempted_at_ms is not None else now_ms(),
        )

    def _log_offline_token_attempt_sync(
        self,
        token_id: str,
        device_id: str,
        action: str,
        approved: bool,
        reason: str,
        attempted_at_ms: int,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO offline_token_audit
                (token_id, device_id, action, approved, reason, attempted_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (token_id, device_id, action, int(bool(approved)), reason, attempted_at_ms),
        )
        self._conn.commit()

    # ─── firmware_device_registry ────────────────────────────────────────────

    async def upsert_firmware_device_anchor(
        self,
        *,
        device_id: str,
        public_key_b64: str,
        posture: str,
        capability_hash: str,
        manifest_json: str,
        channel_map_json: str,
        board_profile: str = "",
        provisioned_at_ms: int | None = None,
    ) -> str:
        """Register a provisioning anchor, per the lifecycle in
        ori-specs/device-provisioning/v1.md.

        Returns an outcome code rather than silently overwriting:

        ``registered``
            No prior anchor; stored unapproved.
        ``unchanged``
            The anchor already matches exactly. Idempotent no-op — nothing
            is touched, including approval and freshness.
        ``pending_manifest_epoch``
            Same key, new capability hash. Stored as a PENDING candidate
            beside the still-active anchor, which is untouched. Nothing is
            accepted against it until it is promoted.
        ``refused_revoked``
            The identity is revoked. Revocation belongs to the identity
            and is never cleared by registration.
        ``refused_key_change``
            The device key differs. A changed key through ordinary
            registration is indistinguishable from a takeover attempt and
            requires an explicit re-provisioning transaction.

        The decision is made inside the write transaction so a concurrent
        revocation cannot be raced.
        """
        return await self._run_write(
            self._upsert_firmware_device_anchor_sync,
            device_id,
            public_key_b64,
            posture,
            capability_hash,
            manifest_json,
            channel_map_json,
            board_profile,
            provisioned_at_ms if provisioned_at_ms is not None else now_ms(),
        )

    def _upsert_firmware_device_anchor_sync(  # noqa: PLR0913
        self,
        device_id: str,
        public_key_b64: str,
        posture: str,
        capability_hash: str,
        manifest_json: str,
        channel_map_json: str,
        board_profile: str,
        provisioned_at_ms: int,
    ) -> str:
        assert self._conn is not None
        from ori.security.firmware.telemetry import (
            anchor_epoch_id as _anchor_epoch_id,
        )
        from ori.security.firmware.telemetry import (
            key_epoch_id as _key_epoch_id,
        )

        kid = _key_epoch_id(device_id=device_id, public_key_b64=public_key_b64)
        aid = _anchor_epoch_id(
            device_id=device_id,
            public_key_b64=public_key_b64,
            posture=posture,
            capability_hash=capability_hash,
        )

        # Decide inside the transaction: a read-then-write in the caller
        # could be raced by a concurrent revocation.
        row = self._conn.execute(
            """
            SELECT public_key_b64, posture, capability_hash, revoked,
                   anchor_epoch_id, key_epoch_id
              FROM firmware_device_registry
             WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()

        def _record_anchor(state: str) -> None:
            self._conn.execute(  # type: ignore[union-attr]
                """
                INSERT OR REPLACE INTO firmware_device_anchors
                    (anchor_epoch_id, device_id, key_epoch_id, public_key_b64,
                     posture, capability_hash, manifest_json, channel_map_json,
                     board_profile, state, created_at_ms, state_changed_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    aid,
                    device_id,
                    kid,
                    public_key_b64,
                    posture,
                    capability_hash,
                    manifest_json,
                    channel_map_json,
                    board_profile,
                    state,
                    provisioned_at_ms,
                    provisioned_at_ms,
                ),
            )

        def _record_transition(
            transition: str, from_epoch: str | None, to_epoch: str | None
        ) -> None:
            self._conn.execute(  # type: ignore[union-attr]
                """
                INSERT INTO firmware_anchor_transitions
                    (device_id, transition, from_epoch_id, to_epoch_id,
                     key_epoch_id, actor, reason, occurred_at_ms)
                VALUES (?, ?, ?, ?, ?, '', '', ?)
                """,
                (device_id, transition, from_epoch, to_epoch, kid, provisioned_at_ms),
            )

        if row is None:
            self._conn.execute(
                """
                INSERT INTO firmware_device_registry
                    (device_id, public_key_b64, posture, capability_hash,
                     manifest_json, channel_map_json, board_profile,
                     approved, provisioned_at_ms, last_boot_id, last_seq,
                     revoked, revoked_at_ms, anchor_epoch_id, key_epoch_id)
                -- anchor_epoch_id stays empty until promotion: it names the
                -- ACTIVE anchor, and nothing is active yet.
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 0, 0, 0, NULL, '', ?)
                """,
                (
                    device_id,
                    public_key_b64,
                    posture,
                    capability_hash,
                    manifest_json,
                    channel_map_json,
                    board_profile,
                    provisioned_at_ms,
                    kid,
                ),
            )
            _record_anchor("pending")
            _record_transition("registered", None, aid)
            self._conn.commit()
            return "registered"

        # Revocation belongs to the identity. It is never cleared as a
        # side effect of a device re-publishing its manifest.
        if row["revoked"]:
            return "refused_revoked"

        # A changed key through ordinary registration is indistinguishable
        # from an attacker presenting a key they control for an identity
        # they do not own: the manifest is self-signed, so verifying it
        # against the key inside it proves consistency, never provenance.
        if row["public_key_b64"] != public_key_b64:
            return "refused_key_change"

        # Authoritative: the anchors table, not the registry pointer. For
        # an identity with no active anchor the registry tracks the pending
        # candidate, so consulting it alone would call a superseded or
        # discarded anchor "unchanged".
        existing_anchor = self._conn.execute(
            "SELECT state FROM firmware_device_anchors WHERE anchor_epoch_id = ?",
            (aid,),
        ).fetchone()
        if existing_anchor is not None and existing_anchor["state"] in (
            "active",
            "pending",
        ):
            # Exact match against the live anchor: idempotent. Touch
            # nothing — not approval, not freshness, not
            # provisioned_at_ms. Re-publishing a manifest is not an event.
            return "unchanged"

        # Same key, new manifest or posture: a PENDING candidate beside
        # the still-active anchor. The active anchor is deliberately
        # untouched — overwriting it would let a device replace its own
        # accepted capability surface by publishing, and would reset a
        # replay window that never left its key epoch.
        existing_pending = self._conn.execute(
            """
            SELECT anchor_epoch_id FROM firmware_device_anchors
             WHERE device_id = ? AND state = 'pending'
            """,
            (device_id,),
        ).fetchone()
        if existing_pending is not None:
            if existing_pending["anchor_epoch_id"] == aid:
                return "unchanged"
            # A pending anchor grants nothing, so replacing one loses no
            # authority; refusing would strand a device whose earlier
            # manifest nobody promoted.
            self._conn.execute(
                """
                UPDATE firmware_device_anchors
                   SET state = 'discarded', state_changed_at_ms = ?
                 WHERE anchor_epoch_id = ?
                """,
                (provisioned_at_ms, existing_pending["anchor_epoch_id"]),
            )
            _record_transition("discarded", existing_pending["anchor_epoch_id"], aid)

        _record_anchor("pending")
        _record_transition("registered", row["anchor_epoch_id"] or None, aid)

        has_active = self._conn.execute(
            "SELECT 1 FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'active'",
            (device_id,),
        ).fetchone()
        if has_active is None:
            # Nothing is active, so the registry row is the identity's
            # description of its only candidate. Point it at the new one —
            # otherwise it would still describe the anchor just discarded,
            # and promotion would activate the wrong manifest.
            self._conn.execute(
                """
                UPDATE firmware_device_registry
                   SET posture = ?, capability_hash = ?, manifest_json = ?,
                       channel_map_json = ?, board_profile = ?,
                       provisioned_at_ms = ?
                 WHERE device_id = ?
                """,
                (
                    posture,
                    capability_hash,
                    manifest_json,
                    channel_map_json,
                    board_profile,
                    provisioned_at_ms,
                    device_id,
                ),
            )
        self._conn.commit()
        return "pending_manifest_epoch"

    async def get_pending_firmware_anchor(self, device_id: str) -> dict | None:
        """The pending candidate for a device, if one is awaiting
        promotion. A pending anchor grants nothing."""
        return await self._run_read(self._get_pending_firmware_anchor_sync, device_id)

    def _get_pending_firmware_anchor_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> dict | None:
        row = conn.execute(
            """
            SELECT * FROM firmware_device_anchors
             WHERE device_id = ? AND state = 'pending'
            """,
            (device_id,),
        ).fetchone()
        return dict(row) if row is not None else None

    async def list_firmware_anchor_history(self, device_id: str) -> list[dict]:
        """Every anchor this identity has held, newest first.

        Append-only: evidence outlives the anchor that authorised it, so
        superseded and discarded anchors are retained rather than
        overwritten.
        """
        return await self._run_read(self._list_firmware_anchor_history_sync, device_id)

    def _list_firmware_anchor_history_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT * FROM firmware_device_anchors
             WHERE device_id = ?
             ORDER BY state_changed_at_ms DESC, rowid DESC
            """,
            (device_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── cross-store confirmation outbox ──────────────────────────────

    async def get_firmware_confirmation_status(
        self, device_id: str, anchor_epoch_id: str
    ) -> str | None:
        """The confirmation status of one approved epoch, or ``None`` if no
        obligation was recorded for it.

        The publish gate reads this: a grant may reach firmware only when
        its active anchor's epoch is ``confirmed``.
        """
        return await self._run_read(
            self._get_firmware_confirmation_status_sync, device_id, anchor_epoch_id
        )

    def _get_firmware_confirmation_status_sync(
        self, conn: sqlite3.Connection, device_id: str, anchor_epoch_id: str
    ) -> str | None:
        row = conn.execute(
            "SELECT status FROM firmware_confirmation_outbox "
            "WHERE device_id = ? AND anchor_epoch_id = ?",
            (device_id, anchor_epoch_id),
        ).fetchone()
        return str(row[0]) if row is not None else None

    async def list_pending_firmware_confirmations(self, limit: int = 100) -> list[dict]:
        """Obligations still awaiting the evidence store's confirmation, oldest first.

        The reconciliation worker drains this. `quarantined` and `confirmed`
        rows are terminal and never returned — a quarantine is resolved by
        an operator, not a retry.
        """
        return await self._run_read(
            self._list_pending_firmware_confirmations_sync, limit
        )

    def _list_pending_firmware_confirmations_sync(
        self, conn: sqlite3.Connection, limit: int
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT device_id, anchor_epoch_id, attempt_count, created_at_ms,
                   last_attempt_ms
              FROM firmware_confirmation_outbox
             WHERE status = 'confirmation_pending'
             ORDER BY created_at_ms ASC, device_id ASC
             LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
        return [dict(r) for r in rows]

    async def record_firmware_confirmation_attempt(
        self, device_id: str, anchor_epoch_id: str, at_ms: int
    ) -> None:
        """Bump the attempt counter for a still-pending obligation.

        Recorded even when the attempt did not resolve (evidence store unreachable),
        so a stuck grant is visibly being worked rather than silently idle.
        """
        await self._run_write(
            self._record_firmware_confirmation_attempt_sync,
            device_id,
            anchor_epoch_id,
            at_ms,
        )

    def _record_firmware_confirmation_attempt_sync(
        self, device_id: str, anchor_epoch_id: str, at_ms: int
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            UPDATE firmware_confirmation_outbox
               SET attempt_count = attempt_count + 1, last_attempt_ms = ?
             WHERE device_id = ? AND anchor_epoch_id = ?
               AND status = 'confirmation_pending'
            """,
            (at_ms, device_id, anchor_epoch_id),
        )
        self._conn.commit()

    async def resolve_firmware_confirmation(
        self, device_id: str, anchor_epoch_id: str, *, status: str, at_ms: int
    ) -> None:
        """Move an obligation to a terminal state: ``confirmed`` or
        ``quarantined``.

        Only a `confirmation_pending` row is resolved, so a late or
        duplicate attempt cannot move a `quarantined` grant to `confirmed`
        or re-resolve one — the reconciliation is idempotent.
        """
        if status not in ("confirmed", "quarantined"):
            raise ValueError(f"invalid confirmation resolution: {status!r}")
        await self._run_write(
            self._resolve_firmware_confirmation_sync,
            device_id,
            anchor_epoch_id,
            status,
            at_ms,
        )

    def _resolve_firmware_confirmation_sync(
        self, device_id: str, anchor_epoch_id: str, status: str, at_ms: int
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            UPDATE firmware_confirmation_outbox
               SET status = ?, resolved_at_ms = ?,
                   attempt_count = attempt_count + 1, last_attempt_ms = ?
             WHERE device_id = ? AND anchor_epoch_id = ?
               AND status = 'confirmation_pending'
            """,
            (status, at_ms, at_ms, device_id, anchor_epoch_id),
        )
        self._conn.commit()

    async def get_firmware_confirmation_summary(self, now_ms_value: int) -> dict:
        """Counts and oldest-pending age for the health snapshot.

        `oldest_pending_age_ms` is derived from the receiver-recorded
        `created_at_ms`, so a stuck grant's age is measured from when this
        store recorded the obligation, not any device-reported time.
        """
        return await self._run_read(
            self._get_firmware_confirmation_summary_sync, now_ms_value
        )

    def _get_firmware_confirmation_summary_sync(
        self, conn: sqlite3.Connection, now_ms_value: int
    ) -> dict:
        row = conn.execute(
            """
            SELECT
              SUM(CASE WHEN status = 'confirmation_pending' THEN 1 ELSE 0 END),
              SUM(CASE WHEN status = 'quarantined' THEN 1 ELSE 0 END),
              MIN(CASE WHEN status = 'confirmation_pending'
                       THEN created_at_ms END)
            FROM firmware_confirmation_outbox
            """,
        ).fetchone()
        pending = int(row[0] or 0)
        quarantined = int(row[1] or 0)
        oldest_created = row[2]
        return {
            "confirmation_pending_count": pending,
            "quarantined_count": quarantined,
            "oldest_pending_age_ms": (
                max(0, now_ms_value - int(oldest_created))
                if oldest_created is not None
                else None
            ),
        }

    async def list_firmware_anchor_transitions(self, device_id: str) -> list[dict]:
        """The audited trust transitions for an identity, oldest first."""
        return await self._run_read(
            self._list_firmware_anchor_transitions_sync, device_id
        )

    async def firmware_active_promotion_attribution(
        self, device_id: str
    ) -> dict | None:
        """The actor and reason of the promotion that made the CURRENT
        active anchor active.

        This is the provenance the coordinating evidence store must
        record when it mirrors the approval: the same operator decision,
        not a fresh or generic one. It is resolved precisely -- the latest
        ``promoted`` transition whose ``to_epoch_id`` is the registry's
        currently active ``anchor_epoch_id`` -- so a later re-provisioning
        or an unrelated promotion cannot be mistaken for it.

        ``None`` if the device is unknown, not approved, or has no such
        promotion (e.g. a legacy row whose activation was inferred by the
        migration -- that attribution is ``migration``, which is returned
        as recorded rather than hidden).
        """
        return await self._run_read(
            self._firmware_active_promotion_attribution_sync, device_id
        )

    def _firmware_active_promotion_attribution_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> dict | None:
        row = conn.execute(
            """
            SELECT t.actor, t.reason, t.occurred_at_ms, t.to_epoch_id
              FROM firmware_anchor_transitions t
              JOIN firmware_device_registry r
                ON r.device_id = t.device_id
               AND r.anchor_epoch_id = t.to_epoch_id
             WHERE t.device_id = ?
               AND t.transition = 'promoted'
               AND r.approved = 1
               AND r.revoked = 0
             -- The transition id is this store's append order: the
             -- receiver-anchored ordering. occurred_at_ms is a recorded
             -- wall-clock that can regress or collide, so it must not
             -- decide which promotion is latest.
             ORDER BY t.id DESC
             LIMIT 1
            """,
            (device_id,),
        ).fetchone()
        return dict(row) if row is not None else None

    def _list_firmware_anchor_transitions_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT * FROM firmware_anchor_transitions
             WHERE device_id = ?
             ORDER BY occurred_at_ms ASC, id ASC
            """,
            (device_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    async def firmware_anchor_activation_intervals(
        self, device_id: str, anchor_epoch_id: str
    ) -> list[dict]:
        """Every interval during which an anchor epoch was active.

        ori-specs/device-provisioning/v1.md requires implementations to be
        able to determine, for any anchor epoch, whether it was ever
        active and over which intervals.

        The anchor's ``state`` column cannot answer this. An anchor that
        was active, was superseded, and has since been re-registered
        reads ``pending`` today, because an anchor epoch has exactly one
        record whose state is its *current* state. Evidence produced
        while it was active is still legitimately attributed to it, so a
        consumer reading only the current state would treat correctly
        signed history as never having been authorised.

        The transition log is the append-only record, and this derives
        the intervals from it rather than storing them, so there is one
        source of truth.

        Ordering is receiver-anchored: ``seq`` is the log's own append
        order and ``at_ms`` is assigned by this store when the transition
        is recorded. Device wall-clock time is never consulted — a device
        supplying its own timestamps could otherwise place its evidence
        inside an interval when its anchor was active, which is the very
        question being decided.

        An interval with ``deactivated_seq`` of ``None`` is still open:
        the anchor is active now.
        """
        return await self._run_read(
            self._firmware_anchor_activation_intervals_sync,
            device_id,
            anchor_epoch_id,
        )

    def _firmware_anchor_activation_intervals_sync(
        self, conn: sqlite3.Connection, device_id: str, anchor_epoch_id: str
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT id, transition, from_epoch_id, to_epoch_id, occurred_at_ms
              FROM firmware_anchor_transitions
             WHERE device_id = ?
             ORDER BY id ASC
            """,
            (device_id,),
        ).fetchall()

        intervals: list[dict] = []
        open_interval: dict | None = None

        for r in rows:
            # Promotion is the only thing that makes an anchor active, so
            # it is the only thing that opens an interval.
            if r["transition"] == "promoted" and r["to_epoch_id"] == anchor_epoch_id:
                if open_interval is None:
                    open_interval = {
                        "activated_seq": int(r["id"]),
                        "activated_at_ms": int(r["occurred_at_ms"]),
                        "deactivated_seq": None,
                        "deactivated_at_ms": None,
                    }
                    intervals.append(open_interval)
                continue

            # Two things end an interval: another anchor being promoted
            # over this one, and the identity being revoked.
            #
            # `reprovisioned` deliberately does NOT, even though it also
            # carries this anchor in from_epoch_id: re-provisioning stores
            # the new key as PENDING and leaves the current anchor active
            # until it is promoted. Treating it as a deactivation would
            # report a gap in which the device was in fact still trusted.
            ends = r["transition"] in ("promoted", "revoked")
            if ends and r["from_epoch_id"] == anchor_epoch_id:
                if open_interval is not None:
                    open_interval["deactivated_seq"] = int(r["id"])
                    open_interval["deactivated_at_ms"] = int(r["occurred_at_ms"])
                    open_interval = None

        return intervals

    async def firmware_anchor_was_active_at(
        self, device_id: str, anchor_epoch_id: str, *, at_ms: int
    ) -> bool:
        """Whether this anchor was *known* active at a receiver-anchored
        instant.

        ``at_ms`` MUST be a time this receiver assigned — its record of
        when evidence arrived, or a position derived from the evidence
        store's chain. It must never be a device-reported timestamp: a device
        choosing its own would place its evidence inside an interval when
        its anchor was active, which is the question being decided.

        Returns ``False`` outside every known interval. For a migrated
        identity that means anything before the migration boundary is
        refused, because when its approval originally happened was never
        recorded — see ``firmware_activation_history_is_provable``.
        """
        intervals = await self.firmware_anchor_activation_intervals(
            device_id, anchor_epoch_id
        )
        for iv in intervals:
            if at_ms < iv["activated_at_ms"]:
                continue
            if iv["deactivated_at_ms"] is None or at_ms < iv["deactivated_at_ms"]:
                return True
        return False

    async def firmware_activation_history_is_provable(self, device_id: str) -> bool:
        """Whether this identity's activation history can be trusted as
        complete.

        ``False`` for an identity migrated from a pre-lifecycle database
        while revoked. Revocation sets ``approved = 0``, so such a row is
        identical whether it was revoked after being promoted or before
        ever being promoted, and the migration refuses to guess.

        Also ``False`` for an identity this store has never heard of.
        Absence of a marker is not evidence of a complete history when
        there is no history at all, and a caller asking about an unknown
        device must not be told its records are trustworthy.

        Callers deciding historical authorisation MUST treat ``False`` as
        "unknown", not as "never active", and fail closed. An empty
        interval list means *provably never promoted* only when this
        returns ``True``.
        """
        return await self._run_read(
            self._firmware_activation_history_is_provable_sync, device_id
        )

    def _firmware_activation_history_is_provable_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> bool:
        known = conn.execute(
            "SELECT 1 FROM firmware_device_registry WHERE device_id = ? LIMIT 1",
            (device_id,),
        ).fetchone()
        if known is None:
            return False

        row = conn.execute(
            """
            SELECT 1 FROM firmware_anchor_transitions
             WHERE device_id = ? AND actor = 'migration' AND reason IN (?, ?, ?)
             LIMIT 1
            """,
            (
                device_id,
                _MIGRATION_ACTIVATION_UNPROVABLE,
                _MIGRATION_ACTIVATION_UNRECONSTRUCTABLE,
                _MIGRATION_ACTIVATION_START_UNKNOWN,
            ),
        ).fetchone()
        return row is None

    async def firmware_anchor_was_ever_active(
        self, device_id: str, anchor_epoch_id: str
    ) -> bool:
        """Whether this anchor epoch is *known* to have been active.

        Distinct from ``state == 'active'``, which is only true right
        now, and from ``state == 'superseded'``, which a re-registration
        clears. Evidence resolution needs this question, not that one.

        ``False`` means "no recorded activation", which is not the same
        as "never active" for an identity migrated while revoked — see
        ``firmware_activation_history_is_provable``.
        """
        intervals = await self.firmware_anchor_activation_intervals(
            device_id, anchor_epoch_id
        )
        return bool(intervals)

    async def get_firmware_device(self, device_id: str) -> dict | None:
        return await self._run_read(self._get_firmware_device_sync, device_id)

    def _get_firmware_device_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> dict | None:
        row = conn.execute(
            """
            SELECT device_id, public_key_b64, alg, posture, capability_hash,
                   manifest_json, channel_map_json, board_profile, approved,
                   provisioned_at_ms, last_boot_id, last_seq, last_provision_seq,
                   revoked, revoked_at_ms, anchor_epoch_id, key_epoch_id
            FROM firmware_device_registry WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "device_id": row[0],
            "public_key_b64": row[1],
            "alg": row[2],
            "posture": row[3],
            "capability_hash": row[4],
            "manifest": json.loads(row[5]),
            "channel_map": json.loads(row[6]),
            "board_profile": row[7],
            "approved": bool(row[8]),
            "provisioned_at_ms": int(row[9]),
            "last_boot_id": int(row[10]),
            "last_seq": int(row[11]),
            "last_provision_seq": int(row[12]),
            "revoked": bool(row[13]),
            "revoked_at_ms": int(row[14]) if row[14] is not None else None,
            "anchor_epoch_id": row[15],
            "key_epoch_id": row[16],
        }

    async def approve_firmware_device(
        self,
        device_id: str,
        *,
        actor: str,
        reason: str,
        occurred_at_ms: int | None = None,
    ) -> bool:
        """Promote the pending anchor to active (ori-specs
        device-provisioning/v1.md). Promotion is the only path to active.

        `actor` and `reason` are REQUIRED and recorded in the transition
        log. Promotion is a trust transition; an unattributed one is
        indistinguishable from a compromise after the fact.
        """
        return await self._run_write(
            self._approve_firmware_device_sync,
            device_id,
            actor,
            reason,
            occurred_at_ms if occurred_at_ms is not None else now_ms(),
        )

    def _approve_firmware_device_sync(
        self, device_id: str, actor: str, reason: str, occurred_at_ms: int
    ) -> bool:
        """Promotion: the ONLY path an anchor becomes active.

        Moves the pending candidate to `active`, the previously active
        anchor to `superseded`, and points the registry at the promoted
        anchor — all in one transaction, so the registry and the anchor
        history cannot disagree about which anchor is trusted.
        """
        assert self._conn is not None
        _require_attribution("promotion", actor, reason)
        registry = self._conn.execute(
            "SELECT revoked, anchor_epoch_id, key_epoch_id "
            "FROM firmware_device_registry "
            "WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if registry is None or registry["revoked"]:
            return False

        pending = self._conn.execute(
            "SELECT * FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'pending'",
            (device_id,),
        ).fetchone()
        if pending is None:
            # Nothing to promote. An already-active anchor is not
            # re-promoted, and inventing one here would be the implicit
            # transition this model exists to remove.
            return False

        # A quarantined epoch is a cross-store disagreement awaiting
        # explicit operator resolution. Re-approving it must NOT silently
        # clear the quarantine, so the promotion is refused here rather
        # than proceeding and re-opening the obligation below. Returning
        # nothing changes state: the operator must resolve the quarantine
        # first (ori-specs/device-provisioning/v1.md).
        quarantined = self._conn.execute(
            "SELECT 1 FROM firmware_confirmation_outbox "
            "WHERE device_id = ? AND anchor_epoch_id = ? AND status = 'quarantined'",
            (device_id, pending["anchor_epoch_id"]),
        ).fetchone()
        if quarantined is not None:
            return False

        previous = self._conn.execute(
            "SELECT anchor_epoch_id FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'active'",
            (device_id,),
        ).fetchone()
        if previous is not None:
            self._conn.execute(
                "UPDATE firmware_device_anchors SET state = 'superseded', "
                "state_changed_at_ms = ? WHERE anchor_epoch_id = ?",
                (occurred_at_ms, previous["anchor_epoch_id"]),
            )

        self._conn.execute(
            "UPDATE firmware_device_anchors SET state = 'active', "
            "state_changed_at_ms = ? WHERE anchor_epoch_id = ?",
            (occurred_at_ms, pending["anchor_epoch_id"]),
        )

        # Telemetry replay state is scoped to the KEY epoch. Promoting
        # within one key epoch must not re-open a closed replay window, so
        # freshness is preserved. Promoting a NEW key epoch — only
        # reachable through re-provisioning — starts a fresh window,
        # because a re-keyed device restarts its counters and would
        # otherwise be refused as a replay against its predecessor's
        # high-water mark. The old epoch's counters remain historical and
        # unusable, since they belong to a key no longer active.
        #
        # last_cmd_seq is deliberately NOT reset: the command mark is per
        # device, not per key, and must continue across rotation
        # (ori-specs/firmware-commands/v1.md).
        key_epoch_changed = pending["key_epoch_id"] != registry["key_epoch_id"]
        self._conn.execute(
            """
            UPDATE firmware_device_registry
               SET approved = 1,
                   public_key_b64 = ?,
                   posture = ?,
                   capability_hash = ?,
                   manifest_json = ?,
                   channel_map_json = ?,
                   board_profile = ?,
                   anchor_epoch_id = ?,
                   key_epoch_id = ?,
                   last_boot_id = CASE WHEN ? THEN 0 ELSE last_boot_id END,
                   last_seq = CASE WHEN ? THEN 0 ELSE last_seq END
             WHERE device_id = ? AND revoked = 0
            """,
            (
                pending["public_key_b64"],
                pending["posture"],
                pending["capability_hash"],
                pending["manifest_json"],
                pending["channel_map_json"],
                pending["board_profile"],
                pending["anchor_epoch_id"],
                pending["key_epoch_id"],
                1 if key_epoch_changed else 0,
                1 if key_epoch_changed else 0,
                device_id,
            ),
        )
        self._conn.execute(
            """
            INSERT INTO firmware_anchor_transitions
                (device_id, transition, from_epoch_id, to_epoch_id,
                 key_epoch_id, actor, reason, occurred_at_ms)
            VALUES (?, 'promoted', ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                previous["anchor_epoch_id"] if previous is not None else None,
                pending["anchor_epoch_id"],
                pending["key_epoch_id"],
                actor,
                reason,
                occurred_at_ms,
            ),
        )
        # Record the cross-store confirmation obligation in the SAME
        # transaction as the promotion, so a crash cannot leave an anchor
        # active locally with no record that the evidence store must still confirm it.
        #
        # A promotion always re-opens confirmation, even for an epoch this
        # identity held before. The only way the same epoch is promoted
        # twice is revoke -> reinstate -> approve, and by then the earlier
        # revocation may have propagated to the evidence store, so the grant genuinely
        # needs re-confirming. The row is reused (the transition log, not
        # this outbox, is the history), with a fresh age and attempt count.
        self._conn.execute(
            """
            INSERT INTO firmware_confirmation_outbox
                (device_id, anchor_epoch_id, status, created_at_ms)
            VALUES (?, ?, 'confirmation_pending', ?)
            ON CONFLICT(device_id, anchor_epoch_id) DO UPDATE SET
                status = 'confirmation_pending',
                attempt_count = 0,
                created_at_ms = excluded.created_at_ms,
                last_attempt_ms = NULL,
                resolved_at_ms = NULL
              WHERE firmware_confirmation_outbox.status != 'quarantined'
            """,
            (device_id, pending["anchor_epoch_id"], occurred_at_ms),
        )
        self._conn.commit()
        return True

    async def revoke_firmware_device(
        self,
        device_id: str,
        *,
        revoked_at_ms: int | None = None,
        actor: str,
        reason: str,
    ) -> bool:
        """Take an identity out of service: the active anchor is retained
        as `revoked`, any pending candidate is discarded, and the
        transition is recorded."""
        return await self._run_write(
            self._revoke_firmware_device_sync,
            device_id,
            revoked_at_ms if revoked_at_ms is not None else now_ms(),
            actor,
            reason,
        )

    def _revoke_firmware_device_sync(
        self, device_id: str, revoked_at_ms: int, actor: str, reason: str
    ) -> bool:
        """Takes an identity out of service, in one transaction.

        The active anchor is retained as `revoked` so reinstatement has
        something to return to, and any pending candidate is discarded —
        an unpromoted candidate must not survive a revocation and become
        promotable later.
        """
        assert self._conn is not None
        _require_attribution("revocation", actor, reason)
        cur = self._conn.execute(
            """
            UPDATE firmware_device_registry
            SET revoked = 1, approved = 0, revoked_at_ms = ?
            WHERE device_id = ?
            """,
            (revoked_at_ms, device_id),
        )
        if cur.rowcount == 0:
            return False

        active = self._conn.execute(
            "SELECT anchor_epoch_id, key_epoch_id FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'active'",
            (device_id,),
        ).fetchone()
        if active is not None:
            self._conn.execute(
                "UPDATE firmware_device_anchors SET state = 'revoked', "
                "state_changed_at_ms = ? WHERE anchor_epoch_id = ?",
                (revoked_at_ms, active["anchor_epoch_id"]),
            )
        pending = self._conn.execute(
            "SELECT anchor_epoch_id FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'pending'",
            (device_id,),
        ).fetchone()
        if pending is not None:
            self._conn.execute(
                "UPDATE firmware_device_anchors SET state = 'discarded', "
                "state_changed_at_ms = ? WHERE anchor_epoch_id = ?",
                (revoked_at_ms, pending["anchor_epoch_id"]),
            )
        self._conn.execute(
            """
            INSERT INTO firmware_anchor_transitions
                (device_id, transition, from_epoch_id, to_epoch_id,
                 key_epoch_id, actor, reason, occurred_at_ms)
            VALUES (?, 'revoked', ?, NULL, ?, ?, ?, ?)
            """,
            (
                device_id,
                active["anchor_epoch_id"] if active is not None else None,
                active["key_epoch_id"] if active is not None else "",
                actor,
                reason,
                revoked_at_ms,
            ),
        )
        self._conn.commit()
        return True

    async def reinstate_firmware_device(
        self,
        device_id: str,
        *,
        actor: str,
        reason: str,
        occurred_at_ms: int | None = None,
    ) -> bool:
        """Return a revoked identity to service.

        Clears the identity's revoked flag and moves the retained
        ``revoked`` anchor back to **pending** — never to active.
        Promotion remains the only path to active, so the operator's next
        act is an explicit, separately audited promotion.
        """
        return await self._run_write(
            self._reinstate_firmware_device_sync,
            device_id,
            actor,
            reason,
            occurred_at_ms if occurred_at_ms is not None else now_ms(),
        )

    def _reinstate_firmware_device_sync(
        self, device_id: str, actor: str, reason: str, occurred_at_ms: int
    ) -> bool:
        assert self._conn is not None
        _require_attribution("reinstatement", actor, reason)
        row = self._conn.execute(
            "SELECT revoked FROM firmware_device_registry WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if row is None or not row["revoked"]:
            # Nothing to reinstate. Clearing a flag that is not set would
            # write an audit row describing an event that did not happen.
            return False

        retained = self._conn.execute(
            "SELECT anchor_epoch_id, key_epoch_id FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'revoked'",
            (device_id,),
        ).fetchone()

        self._conn.execute(
            """
            UPDATE firmware_device_registry
               SET revoked = 0, revoked_at_ms = NULL, approved = 0
             WHERE device_id = ?
            """,
            (device_id,),
        )
        to_epoch = None
        key_epoch = ""
        if retained is not None:
            # Back to pending, not active: promotion is a separate act.
            self._conn.execute(
                "UPDATE firmware_device_anchors SET state = 'pending', "
                "state_changed_at_ms = ? WHERE anchor_epoch_id = ?",
                (occurred_at_ms, retained["anchor_epoch_id"]),
            )
            to_epoch = retained["anchor_epoch_id"]
            key_epoch = retained["key_epoch_id"]
        self._conn.execute(
            """
            INSERT INTO firmware_anchor_transitions
                (device_id, transition, from_epoch_id, to_epoch_id,
                 key_epoch_id, actor, reason, occurred_at_ms)
            VALUES (?, 'reinstated', ?, ?, ?, ?, ?, ?)
            """,
            (device_id, to_epoch, to_epoch, key_epoch, actor, reason, occurred_at_ms),
        )
        self._conn.commit()
        return True

    async def reprovision_firmware_device(
        self,
        *,
        device_id: str,
        public_key_b64: str,
        posture: str,
        capability_hash: str,
        manifest_json: str,
        channel_map_json: str,
        board_profile: str = "",
        actor: str,
        reason: str,
        occurred_at_ms: int | None = None,
    ) -> str:
        """Replace an identity's key: an explicit, audited transaction.

        Ordinary registration refuses a changed key, because a self-signed
        manifest proves consistency and never provenance. This is the path
        that accepts one, and it exists so that acceptance is a deliberate
        operator act with independent identity confirmation behind it.

        The new-key anchor is stored **pending**; the previously active
        anchor stays active until promotion. Historical anchors are
        retained, and the command sequence is untouched — it is per device,
        not per key, so rotation must not reset it.

        Returns ``reprovisioned``, or a refusal: ``unknown_device``,
        ``revoked``, ``refused_same_key`` (the submitted key is the
        current one, so nothing is being replaced), or
        ``refused_key_reuse`` (this identity has used that key before).
        """
        return await self._run_write(
            self._reprovision_firmware_device_sync,
            device_id,
            public_key_b64,
            posture,
            capability_hash,
            manifest_json,
            channel_map_json,
            board_profile,
            actor,
            reason,
            occurred_at_ms if occurred_at_ms is not None else now_ms(),
        )

    def _reprovision_firmware_device_sync(  # noqa: PLR0913
        self,
        device_id: str,
        public_key_b64: str,
        posture: str,
        capability_hash: str,
        manifest_json: str,
        channel_map_json: str,
        board_profile: str,
        actor: str,
        reason: str,
        occurred_at_ms: int,
    ) -> str:
        assert self._conn is not None
        _require_attribution("re-provisioning", actor, reason)
        from ori.security.firmware.telemetry import (
            anchor_epoch_id as _anchor_epoch_id,
        )
        from ori.security.firmware.telemetry import (
            key_epoch_id as _key_epoch_id,
        )

        row = self._conn.execute(
            "SELECT revoked, anchor_epoch_id FROM firmware_device_registry "
            "WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if row is None:
            return "unknown_device"
        if row["revoked"]:
            # Reinstate first: re-provisioning a revoked identity would
            # return it to service without ever saying so.
            return "revoked"

        kid = _key_epoch_id(device_id=device_id, public_key_b64=public_key_b64)
        aid = _anchor_epoch_id(
            device_id=device_id,
            public_key_b64=public_key_b64,
            posture=posture,
            capability_hash=capability_hash,
        )

        # Re-provisioning means REPLACING the key. Submitting the current
        # key is not a key change: with INSERT OR REPLACE it would have
        # overwritten the active anchor row with a pending one while the
        # registry still said approved — a split-brain, and a violation of
        # append-only history.
        current_key_epoch = self._conn.execute(
            "SELECT key_epoch_id FROM firmware_device_registry WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if current_key_epoch is not None and current_key_epoch["key_epoch_id"] == kid:
            return "refused_same_key"

        # Nor may a key this identity has used before come back. An old key
        # may be exactly the one that was rotated away from because it was
        # compromised; allowing its return would make rotation reversible
        # by whoever holds it.
        reused = self._conn.execute(
            "SELECT 1 FROM firmware_device_anchors "
            "WHERE device_id = ? AND key_epoch_id = ?",
            (device_id, kid),
        ).fetchone()
        if reused is not None:
            return "refused_key_reuse"

        # Any existing candidate is superseded by this one.
        existing = self._conn.execute(
            "SELECT anchor_epoch_id FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'pending'",
            (device_id,),
        ).fetchone()
        if existing is not None and existing["anchor_epoch_id"] != aid:
            self._conn.execute(
                "UPDATE firmware_device_anchors SET state = 'discarded', "
                "state_changed_at_ms = ? WHERE anchor_epoch_id = ?",
                (occurred_at_ms, existing["anchor_epoch_id"]),
            )

        self._conn.execute(
            """
            INSERT INTO firmware_device_anchors
                (anchor_epoch_id, device_id, key_epoch_id, public_key_b64,
                 posture, capability_hash, manifest_json, channel_map_json,
                 board_profile, state, created_at_ms, state_changed_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            """,
            (
                aid,
                device_id,
                kid,
                public_key_b64,
                posture,
                capability_hash,
                manifest_json,
                channel_map_json,
                board_profile,
                occurred_at_ms,
                occurred_at_ms,
            ),
        )
        self._conn.execute(
            """
            INSERT INTO firmware_anchor_transitions
                (device_id, transition, from_epoch_id, to_epoch_id,
                 key_epoch_id, actor, reason, occurred_at_ms)
            VALUES (?, 'reprovisioned', ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                row["anchor_epoch_id"] or None,
                aid,
                kid,
                actor,
                reason,
                occurred_at_ms,
            ),
        )
        self._conn.commit()
        return "reprovisioned"

    async def allocate_firmware_runtime_seq(self, device_id: str) -> int:
        """Allocate the next strictly increasing runtime-liveness sequence
        for a device (firmware-commands/v1 runtime liveness).

        Durability here is load-bearing, and for a different reason than
        ``cmd_seq``. A device holds the last accepted value for its CURRENT
        boot, so a runtime that restarted with an in-memory counter would
        have every subsequent message rejected and could not recover while
        that device stayed booted — the device would report a healthy
        runtime unreachable and keep doing so. Recovery would need a device
        reboot, which is not something a runtime restart may require.

        Raises KeyError for unknown devices.
        """
        return await self._run_write(
            self._allocate_firmware_runtime_seq_sync, device_id
        )

    def _allocate_firmware_runtime_seq_sync(self, device_id: str) -> int:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            UPDATE firmware_device_registry
               SET last_runtime_seq = last_runtime_seq + 1
             WHERE device_id = ?
               AND last_runtime_seq < 9007199254740991
            """,
            (device_id,),
        )
        if cur.rowcount != 1:
            self._conn.rollback()
            # The UPDATE misses for two different reasons and they are not
            # the same failure: an unknown device is a caller error, an
            # exhausted counter is the end of the sequence space.
            exists = self._conn.execute(
                "SELECT 1 FROM firmware_device_registry WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if exists is None:
                raise KeyError(f"unknown firmware device: {device_id!r}")
            raise ValueError(
                f"runtime_seq exhausted for {device_id!r}; "
                "the device cannot accept a higher value in this boot"
            )
        row = self._conn.execute(
            "SELECT last_runtime_seq FROM firmware_device_registry WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        assert row is not None
        # Commit before returning. _run_write provides locking and thread
        # dispatch, not a transaction boundary. Without this the allocation
        # is only in the connection's open transaction: a process restart
        # rolls it back, the device then rejects every message from the
        # restarted runtime for the rest of its current boot, and whether
        # it survives at all depends on some unrelated later write
        # happening to commit it.
        self._conn.commit()
        return int(row[0])

    async def allocate_firmware_command_seq(self, device_id: str) -> int:
        """Allocate the next strictly increasing command sequence for a
        provisioned device (firmware-commands contract: one strictly
        increasing cmd_seq per device, continuing across command-key
        rotation and never reused — including for retries of lost
        commands). Raises KeyError for unknown devices."""
        return await self._run_write(
            self._allocate_firmware_command_seq_sync, device_id
        )

    def _allocate_firmware_command_seq_sync(self, device_id: str) -> int:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            UPDATE firmware_device_registry
            SET last_cmd_seq = last_cmd_seq + 1
            WHERE device_id = ?
            """,
            (device_id,),
        )
        if cur.rowcount != 1:
            self._conn.rollback()
            raise KeyError(f"unknown firmware device: {device_id!r}")
        row = self._conn.execute(
            "SELECT last_cmd_seq FROM firmware_device_registry WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        self._conn.commit()
        return int(row[0])

    async def allocate_firmware_provision_seq(
        self,
        device_id: str,
        *,
        expected_anchor_epoch_id: str,
        allow_revoked: bool,
    ) -> int:
        """Allocate the independent firmware transport-provisioning sequence.

        The counter belongs to the stable device identity and is never reset by
        anchor, command-key, certificate, or revocation transitions.
        """
        return await self._run_write(
            self._allocate_firmware_provision_seq_sync,
            device_id,
            expected_anchor_epoch_id,
            allow_revoked,
        )

    def _allocate_firmware_provision_seq_sync(
        self,
        device_id: str,
        expected_anchor_epoch_id: str,
        allow_revoked: bool,
    ) -> int:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            UPDATE firmware_device_registry
               SET last_provision_seq = last_provision_seq + 1
             WHERE device_id = ?
               AND anchor_epoch_id = ?
               AND last_provision_seq < 9007199254740991
               AND (
                    (? = 1 AND revoked = 1)
                    OR
                    (revoked = 0 AND approved = 1 AND EXISTS (
                        SELECT 1 FROM firmware_confirmation_outbox c
                         WHERE c.device_id = firmware_device_registry.device_id
                           AND c.anchor_epoch_id =
                               firmware_device_registry.anchor_epoch_id
                           AND c.status = 'confirmed'
                    ))
               )
            """,
            (device_id, expected_anchor_epoch_id, int(allow_revoked)),
        )
        if cur.rowcount != 1:
            row = self._conn.execute(
                "SELECT last_provision_seq FROM firmware_device_registry "
                "WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            self._conn.rollback()
            if row is None:
                raise KeyError(f"unknown firmware device: {device_id!r}")
            if int(row[0]) < 9007199254740991:
                raise PermissionError(
                    "firmware provisioning authority changed before allocation"
                )
            raise OverflowError("firmware provision_seq exhausted")
        row = self._conn.execute(
            "SELECT last_provision_seq FROM firmware_device_registry "
            "WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        self._conn.commit()
        return int(row[0])

    async def append_firmware_mqtt_provisioning_audit(
        self,
        *,
        device_id: str,
        event_kind: str,
        operation_kind: str,
        provision_seq: int | None,
        request_id: str,
        anchor_epoch_id: str,
        actor: str,
        reason: str,
        request_sha256: str,
        verdict: str,
        certificate_sha256: str,
        broker_uri: str,
        payload_sha256: str,
        occurred_at_ms: int,
    ) -> int:
        """Append one immutable provisioning request or verified response."""
        return await self._run_write(
            self._append_firmware_mqtt_provisioning_audit_sync,
            device_id,
            event_kind,
            operation_kind,
            provision_seq,
            request_id,
            anchor_epoch_id,
            actor,
            reason,
            request_sha256,
            verdict,
            certificate_sha256,
            broker_uri,
            payload_sha256,
            occurred_at_ms,
        )

    def _append_firmware_mqtt_provisioning_audit_sync(
        self,
        device_id: str,
        event_kind: str,
        operation_kind: str,
        provision_seq: int | None,
        request_id: str,
        anchor_epoch_id: str,
        actor: str,
        reason: str,
        request_sha256: str,
        verdict: str,
        certificate_sha256: str,
        broker_uri: str,
        payload_sha256: str,
        occurred_at_ms: int,
    ) -> int:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            INSERT INTO firmware_mqtt_provisioning_audit
                (device_id, event_kind, operation_kind, provision_seq,
                 request_id, anchor_epoch_id, actor, reason, request_sha256,
                 verdict, certificate_sha256, broker_uri, payload_sha256,
                 occurred_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                event_kind,
                operation_kind,
                provision_seq,
                request_id,
                anchor_epoch_id,
                actor,
                reason,
                request_sha256,
                verdict,
                certificate_sha256,
                broker_uri,
                payload_sha256,
                occurred_at_ms,
            ),
        )
        self._conn.commit()
        if cur.lastrowid is None:
            raise RuntimeError("firmware MQTT provisioning audit insert returned no id")
        return cur.lastrowid

    async def list_firmware_mqtt_provisioning_audit(self, device_id: str) -> list[dict]:
        """Return provisioning audit facts in receiver append order."""
        return await self._run_read(
            self._list_firmware_mqtt_provisioning_audit_sync, device_id
        )

    def _list_firmware_mqtt_provisioning_audit_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> list[dict]:
        rows = conn.execute(
            "SELECT * FROM firmware_mqtt_provisioning_audit "
            "WHERE device_id = ? ORDER BY id ASC",
            (device_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    async def save_firmware_mqtt_operator_request(
        self,
        *,
        correlation_id: str,
        parent_correlation_id: str,
        operation_kind: str,
        message: bytes,
        request: bytes,
        device_id: str,
        anchor_epoch_id: str,
        provision_seq: int | None,
        request_id: str,
        actor: str,
        reason: str,
        request_sha256: str,
        certificate_sha256: str,
        broker_uri: str,
        audit_id: int,
        certificate_serial: str,
        not_valid_before: str,
        not_valid_after: str,
        created_at_ms: int,
        completed_parent_correlation_id: str = "",
        parent_response_verdict: str = "",
        parent_response_payload_sha256: str = "",
        parent_completed_at_ms: int = 0,
    ) -> None:
        """Persist one immutable, public operator correlation record."""
        if completed_parent_correlation_id:
            if completed_parent_correlation_id != parent_correlation_id:
                raise ValueError(
                    "completed parent must match the request parent correlation"
                )
            if (
                not parent_response_verdict
                or not parent_response_payload_sha256
                or parent_completed_at_ms <= 0
            ):
                raise ValueError("completed parent response facts are required")
        await self._run_write(
            self._save_firmware_mqtt_operator_request_sync,
            correlation_id,
            parent_correlation_id,
            operation_kind,
            message,
            request,
            device_id,
            anchor_epoch_id,
            provision_seq,
            request_id,
            actor,
            reason,
            request_sha256,
            certificate_sha256,
            broker_uri,
            audit_id,
            certificate_serial,
            not_valid_before,
            not_valid_after,
            created_at_ms,
            completed_parent_correlation_id,
            parent_response_verdict,
            parent_response_payload_sha256,
            parent_completed_at_ms,
        )

    def _save_firmware_mqtt_operator_request_sync(
        self,
        correlation_id: str,
        parent_correlation_id: str,
        operation_kind: str,
        message: bytes,
        request: bytes,
        device_id: str,
        anchor_epoch_id: str,
        provision_seq: int | None,
        request_id: str,
        actor: str,
        reason: str,
        request_sha256: str,
        certificate_sha256: str,
        broker_uri: str,
        audit_id: int,
        certificate_serial: str,
        not_valid_before: str,
        not_valid_after: str,
        created_at_ms: int,
        completed_parent_correlation_id: str,
        parent_response_verdict: str,
        parent_response_payload_sha256: str,
        parent_completed_at_ms: int,
    ) -> None:
        assert self._conn is not None
        try:
            self._insert_firmware_mqtt_operator_request_on_conn(
                self._conn,
                correlation_id=correlation_id,
                parent_correlation_id=parent_correlation_id,
                operation_kind=operation_kind,
                message=message,
                request=request,
                device_id=device_id,
                anchor_epoch_id=anchor_epoch_id,
                provision_seq=provision_seq,
                request_id=request_id,
                actor=actor,
                reason=reason,
                request_sha256=request_sha256,
                certificate_sha256=certificate_sha256,
                broker_uri=broker_uri,
                audit_id=audit_id,
                certificate_serial=certificate_serial,
                not_valid_before=not_valid_before,
                not_valid_after=not_valid_after,
                created_at_ms=created_at_ms,
            )
            if completed_parent_correlation_id:
                self._conn.execute(
                    """
                    INSERT INTO firmware_mqtt_operator_responses
                        (correlation_id, verdict, payload_sha256, completed_at_ms)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        completed_parent_correlation_id,
                        parent_response_verdict,
                        parent_response_payload_sha256,
                        parent_completed_at_ms,
                    ),
                )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def _insert_firmware_mqtt_operator_request_on_conn(
        self,
        conn: sqlite3.Connection,
        *,
        correlation_id: str,
        parent_correlation_id: str,
        operation_kind: str,
        message: bytes,
        request: bytes,
        device_id: str,
        anchor_epoch_id: str,
        provision_seq: int | None,
        request_id: str,
        actor: str,
        reason: str,
        request_sha256: str,
        certificate_sha256: str,
        broker_uri: str,
        audit_id: int,
        certificate_serial: str,
        not_valid_before: str,
        not_valid_after: str,
        created_at_ms: int,
    ) -> None:
        conn.execute(
            """
            INSERT INTO firmware_mqtt_operator_requests
                (correlation_id, parent_correlation_id, operation_kind,
                 message, request, device_id, anchor_epoch_id, provision_seq,
                 request_id, actor, reason, request_sha256,
                 certificate_sha256, broker_uri, audit_id,
                 certificate_serial, not_valid_before, not_valid_after,
                 created_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                correlation_id,
                parent_correlation_id,
                operation_kind,
                sqlite3.Binary(message),
                sqlite3.Binary(request),
                device_id,
                anchor_epoch_id,
                provision_seq,
                request_id,
                actor,
                reason,
                request_sha256,
                certificate_sha256,
                broker_uri,
                audit_id,
                certificate_serial,
                not_valid_before,
                not_valid_after,
                created_at_ms,
            ),
        )

    async def get_firmware_mqtt_operator_request(
        self, correlation_id: str
    ) -> dict | None:
        """Load a public request and its completion state."""
        return await self._run_read(
            self._get_firmware_mqtt_operator_request_sync,
            correlation_id,
        )

    def _get_firmware_mqtt_operator_request_sync(
        self,
        conn: sqlite3.Connection,
        correlation_id: str,
    ) -> dict | None:
        row = conn.execute(
            """
            SELECT r.*, p.verdict AS response_verdict,
                   p.payload_sha256 AS response_payload_sha256,
                   p.completed_at_ms
              FROM firmware_mqtt_operator_requests r
              LEFT JOIN firmware_mqtt_operator_responses p
                ON p.correlation_id = r.correlation_id
             WHERE r.correlation_id = ?
            """,
            (correlation_id,),
        ).fetchone()
        return dict(row) if row is not None else None

    async def complete_firmware_mqtt_operator_request(
        self,
        *,
        correlation_id: str,
        verdict: str,
        payload_sha256: str,
        completed_at_ms: int,
    ) -> None:
        """Append the one terminal response fact for a correlation."""
        await self._run_write(
            self._complete_firmware_mqtt_operator_request_sync,
            correlation_id,
            verdict,
            payload_sha256,
            completed_at_ms,
        )

    def _complete_firmware_mqtt_operator_request_sync(
        self,
        correlation_id: str,
        verdict: str,
        payload_sha256: str,
        completed_at_ms: int,
    ) -> None:
        assert self._conn is not None
        try:
            self._conn.execute(
                """
                INSERT INTO firmware_mqtt_operator_responses
                    (correlation_id, verdict, payload_sha256, completed_at_ms)
                VALUES (?, ?, ?, ?)
                """,
                (correlation_id, verdict, payload_sha256, completed_at_ms),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    async def advance_firmware_freshness(
        self, device_id: str, *, boot_id: int, seq: int
    ) -> bool:
        """Advance the replay high-water mark, strictly monotonically.

        The WHERE clause is the atomicity guarantee: a concurrent or
        replayed writer whose (boot_id, seq) does not strictly advance
        the stored mark updates zero rows, and the caller must treat
        that as a replay."""
        return await self._run_write(
            self._advance_firmware_freshness_sync, device_id, boot_id, seq
        )

    def _advance_firmware_freshness_sync(
        self, device_id: str, boot_id: int, seq: int
    ) -> bool:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            UPDATE firmware_device_registry
            SET last_boot_id = ?, last_seq = ?
            WHERE device_id = ? AND revoked = 0 AND approved = 1
              AND ? >= last_boot_id AND ? > last_seq
            """,
            (boot_id, seq, device_id, boot_id, seq),
        )
        self._conn.commit()
        return cur.rowcount > 0

    async def append_firmware_fault_event(
        self,
        *,
        device_id: str,
        boot_id: int,
        seq: int,
        grade: str,
        posture: str,
        capability_hash: str,
        code: str,
        subject: str,
        detail: str,
        device_uptime_ms: int,
        received_at_ms: int,
        fault_json: str,
    ) -> bool:
        """Record an accepted signed firmware fault event.

        Faults are Layer 1 evidence about device-side refusals and
        protections. They must be durable, but they must never flow into
        the sensor event bus as readings.
        """
        return await self._run_write(
            self._append_firmware_fault_event_sync,
            device_id,
            boot_id,
            seq,
            grade,
            posture,
            capability_hash,
            code,
            subject,
            detail,
            device_uptime_ms,
            received_at_ms,
            fault_json,
        )

    def _append_firmware_fault_event_sync(
        self,
        device_id: str,
        boot_id: int,
        seq: int,
        grade: str,
        posture: str,
        capability_hash: str,
        code: str,
        subject: str,
        detail: str,
        device_uptime_ms: int,
        received_at_ms: int,
        fault_json: str,
    ) -> bool:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            INSERT OR IGNORE INTO firmware_fault_events
                (device_id, boot_id, seq, grade, posture, capability_hash,
                 code, subject, detail, device_uptime_ms, received_at_ms, fault_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                boot_id,
                seq,
                grade,
                posture,
                capability_hash,
                code,
                subject,
                detail,
                device_uptime_ms,
                received_at_ms,
                fault_json,
            ),
        )
        self._conn.commit()
        return cur.rowcount > 0

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

    async def upsert_device_policy_cache(
        self,
        *,
        policy_version: int,
        tier: str,
        relay_b_enabled: bool,
        relay_c_enabled: bool,
        cloud_llm_enabled: bool,
        valid_until: int,
        issued_at: int,
        signature: str,
        raw_payload: str,
        cached_at_ms: int | None = None,
    ) -> None:
        await self._run_write(
            self._upsert_device_policy_cache_sync,
            policy_version,
            tier,
            relay_b_enabled,
            relay_c_enabled,
            cloud_llm_enabled,
            valid_until,
            issued_at,
            signature,
            raw_payload,
            cached_at_ms if cached_at_ms is not None else now_ms(),
        )

    def _upsert_device_policy_cache_sync(
        self,
        policy_version: int,
        tier: str,
        relay_b_enabled: bool,
        relay_c_enabled: bool,
        cloud_llm_enabled: bool,
        valid_until: int,
        issued_at: int,
        signature: str,
        raw_payload: str,
        cached_at_ms: int,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO device_policy_cache
                (policy_version, tier, relay_b_enabled, relay_c_enabled, cloud_llm_enabled,
                 valid_until, issued_at, signature, raw_payload, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(policy_version) DO UPDATE SET
                tier = excluded.tier,
                relay_b_enabled = excluded.relay_b_enabled,
                relay_c_enabled = excluded.relay_c_enabled,
                cloud_llm_enabled = excluded.cloud_llm_enabled,
                valid_until = excluded.valid_until,
                issued_at = excluded.issued_at,
                signature = excluded.signature,
                raw_payload = excluded.raw_payload,
                cached_at = excluded.cached_at
            """,
            (
                int(policy_version),
                tier,
                1 if relay_b_enabled else 0,
                1 if relay_c_enabled else 0,
                1 if cloud_llm_enabled else 0,
                int(valid_until),
                int(issued_at),
                signature,
                raw_payload,
                int(cached_at_ms),
            ),
        )
        self._conn.commit()

    async def get_latest_device_policy_cache(self) -> dict | None:
        return await self._run_read(self._get_latest_device_policy_cache_sync)

    def _get_latest_device_policy_cache_sync(
        self,
        conn: sqlite3.Connection,
    ) -> dict | None:
        row = conn.execute(
            """
            SELECT policy_version, tier, relay_b_enabled, relay_c_enabled,
                   cloud_llm_enabled, valid_until, issued_at, signature,
                   raw_payload, cached_at
            FROM device_policy_cache
            ORDER BY policy_version DESC, cached_at DESC, id DESC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return None
        return {
            "policy_version": int(row["policy_version"]),
            "tier": str(row["tier"]),
            "relay_b_enabled": bool(row["relay_b_enabled"]),
            "relay_c_enabled": bool(row["relay_c_enabled"]),
            "cloud_llm_enabled": bool(row["cloud_llm_enabled"]),
            "valid_until": int(row["valid_until"]),
            "issued_at": int(row["issued_at"]),
            "signature": str(row["signature"]),
            "raw_payload": str(row["raw_payload"]),
            "cached_at": int(row["cached_at"]),
        }

    # ─── reasoning_log ───────────────────────────────────────────────────────

    async def log_reasoning(
        self,
        result: ReasoningResult,
        trigger_name: str,
        device_id: str,
    ) -> None:
        """Persist a :class:`~ori.network.events.ReasoningResult` to reasoning_log."""
        await self._run_write(self._log_reasoning_sync, result, trigger_name, device_id)

    def _log_reasoning_sync(
        self,
        result: ReasoningResult,
        trigger_name: str,
        device_id: str,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO reasoning_log
                (trigger_name, tier_used, prompt, response, confidence,
                 action_tier, device_id, model, tokens_used, latency_ms,
                 proposed_action, reasoning_status, correlation_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trigger_name,
                result.tier,
                result.prompt,
                result.text,
                result.confidence,
                result.action_tier,
                device_id,
                result.model,
                result.tokens_used,
                result.latency_ms,
                result.proposed_action,
                result.reasoning_status,
                result.correlation_id,
                now_ms(),
            ),
        )
        self._conn.commit()

    async def export_reasoning_log(
        self,
        *,
        device_id: str | None = None,
        since_ms: int | None = None,
        until_ms: int | None = None,
        tier_used: str | None = None,
        action_tier: str | None = None,
        reasoning_status: str | None = None,
        correlation_id: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return a bounded reasoning-log export for gateway/cloud sync."""
        return await self._run_read(
            self._export_reasoning_log_sync,
            device_id,
            since_ms,
            until_ms,
            tier_used,
            action_tier,
            reasoning_status,
            correlation_id,
            limit,
        )

    def _export_reasoning_log_sync(
        self,
        conn: sqlite3.Connection,
        device_id: str | None,
        since_ms: int | None,
        until_ms: int | None,
        tier_used: str | None,
        action_tier: str | None,
        reasoning_status: str | None,
        correlation_id: str | None,
        limit: int,
    ) -> list[dict]:
        where = []
        params: list[Any] = []
        if device_id:
            where.append("device_id = ?")
            params.append(str(device_id))
        if since_ms is not None:
            where.append("timestamp >= ?")
            params.append(int(since_ms))
        if until_ms is not None:
            where.append("timestamp <= ?")
            params.append(int(until_ms))
        if tier_used:
            where.append("tier_used = ?")
            params.append(str(tier_used))
        if action_tier:
            where.append("action_tier = ?")
            params.append(str(action_tier).upper())
        if reasoning_status:
            where.append("reasoning_status = ?")
            params.append(str(reasoning_status))
        if correlation_id:
            where.append("correlation_id = ?")
            params.append(str(correlation_id))
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        params.append(max(1, min(int(limit), 1000)))
        query = (
            """
            SELECT trigger_name, tier_used, prompt, response, confidence,
                   action_tier, device_id, model, tokens_used, latency_ms,
                   proposed_action, reasoning_status, correlation_id, timestamp
            FROM reasoning_log
            """
            + where_sql
            + """
            ORDER BY timestamp DESC
            LIMIT ?
            """
        )
        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    # ─── override_log ─────────────────────────────────────────────────────────

    async def log_override(
        self,
        trigger_name: str,
        action: str,
        reason: str,
        operator_response: Optional[str],
        override_type: str,
        device_id: str,
    ) -> None:
        """Persist an operator rejection or autonomous Tier D override."""
        await self._run_write(
            self._log_override_sync,
            trigger_name,
            action,
            reason,
            operator_response,
            override_type,
            device_id,
        )

    def _log_override_sync(
        self,
        trigger_name: str,
        action: str,
        reason: str,
        operator_response: Optional[str],
        override_type: str,
        device_id: str,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO override_log
                (trigger_name, action, reason, operator_response,
                 override_type, device_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trigger_name,
                action,
                reason,
                operator_response,
                override_type,
                device_id,
                now_ms(),
            ),
        )
        self._conn.commit()

    # ─── causal_memory ────────────────────────────────────────────────────────

    async def lookup_causal_memory(self, pattern_key: str) -> Optional[str]:
        # Intentional write-path lock: lookup also updates hit_count/last_seen
        # in the same transaction for causal-memory ranking.
        return await self._run_write(self._lookup_causal_sync, pattern_key)

    def _lookup_causal_sync(self, pattern_key: str) -> Optional[str]:
        assert self._conn is not None
        row = self._conn.execute(
            """
            SELECT resolution FROM causal_memory WHERE pattern_key = ?
            """,
            (pattern_key,),
        ).fetchone()
        if row is None:
            return None
        # Increment hit_count and update last_seen in the same transaction
        self._conn.execute(
            """
            UPDATE causal_memory
            SET hit_count = hit_count + 1, last_seen = ?
            WHERE pattern_key = ?
            """,
            (now_ms(), pattern_key),
        )
        self._conn.commit()
        return str(row["resolution"])

    async def store_causal_memory(
        self, pattern_key: str, resolution: str, confidence: float
    ) -> None:
        await self._run_write(
            self._store_causal_sync, pattern_key, resolution, confidence
        )

    def _store_causal_sync(
        self, pattern_key: str, resolution: str, confidence: float
    ) -> None:
        assert self._conn is not None
        now = now_ms()
        self._conn.execute(
            """
            INSERT INTO causal_memory
                (pattern_key, resolution, confidence, created_at, last_seen, hit_count)
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(pattern_key) DO UPDATE SET
                resolution = excluded.resolution,
                confidence = excluded.confidence,
                last_seen  = excluded.last_seen,
                hit_count  = hit_count + 1
            """,
            (pattern_key, resolution, confidence, now, now),
        )
        self._conn.commit()

    # ─── causal_memory_rejections ────────────────────────────────────────────

    async def store_rejection(
        self,
        pattern_key: str,
        trigger_name: str,
        proposed_action: str,
        operator_response: str | None,
        device_id: str,
        sensor_type: str,
        value_bucket: float,
        time_of_day_hour: int,
        day_of_week: int,
        expiry_days: int = 30,
    ) -> None:
        await self._run_write(
            self._store_rejection_sync,
            pattern_key,
            trigger_name,
            proposed_action,
            operator_response,
            device_id,
            sensor_type,
            value_bucket,
            time_of_day_hour,
            day_of_week,
            expiry_days,
        )

    def _store_rejection_sync(
        self,
        pattern_key: str,
        trigger_name: str,
        proposed_action: str,
        operator_response: str | None,
        device_id: str,
        sensor_type: str,
        value_bucket: float,
        time_of_day_hour: int,
        day_of_week: int,
        expiry_days: int,
    ) -> None:
        assert self._conn is not None
        rejected_at = now_ms()
        expiry_ms: int | None = None
        if expiry_days > 0:
            expiry_ms = int(expiry_days * 86_400_000)
        self._conn.execute(
            """
            INSERT INTO causal_memory_rejections
                (pattern_key, trigger_name, proposed_action, operator_response,
                 device_id, sensor_type, value_bucket, time_of_day_hour,
                 day_of_week, rejected_at, expiry_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(pattern_key, proposed_action) DO UPDATE SET
                trigger_name = excluded.trigger_name,
                operator_response = excluded.operator_response,
                device_id = excluded.device_id,
                sensor_type = excluded.sensor_type,
                value_bucket = excluded.value_bucket,
                time_of_day_hour = excluded.time_of_day_hour,
                day_of_week = excluded.day_of_week,
                rejected_at = excluded.rejected_at,
                expiry_ms = excluded.expiry_ms
            """,
            (
                pattern_key,
                trigger_name,
                proposed_action,
                operator_response,
                device_id,
                sensor_type,
                value_bucket,
                time_of_day_hour,
                day_of_week,
                rejected_at,
                expiry_ms,
            ),
        )
        self._conn.commit()

    async def lookup_rejection(self, pattern_key: str) -> Optional[dict]:
        return await self._run_read(self._lookup_rejection_sync, pattern_key)

    def _lookup_rejection_sync(
        self, conn: sqlite3.Connection, pattern_key: str
    ) -> Optional[dict]:
        row = conn.execute(
            """
            SELECT id, pattern_key, trigger_name, proposed_action, operator_response,
                   device_id, sensor_type, value_bucket, time_of_day_hour,
                   day_of_week, rejected_at, expiry_ms
            FROM causal_memory_rejections
            WHERE pattern_key = ?
            ORDER BY rejected_at DESC
            LIMIT 1
            """,
            (pattern_key,),
        ).fetchone()
        if row is None:
            return None

        expiry_ms = row["expiry_ms"]
        if expiry_ms is not None:
            expires_at = int(row["rejected_at"]) + int(expiry_ms)
            if expires_at < now_ms():
                return None

        return dict(row)

    @staticmethod
    def _build_rejection_pattern_key(
        sensor_type: str,
        trigger_name: str,
        proposed_action: str,
        value: float,
        timestamp_ms: int,
    ) -> str:
        value_bucket = round(float(value) * 2.0) / 2.0
        dt = datetime.datetime.fromtimestamp(
            timestamp_ms / 1000.0, tz=datetime.timezone.utc
        )
        two_hour_bucket = (dt.hour // 2) * 2
        day_of_week = dt.weekday()
        raw = (
            f"{sensor_type}|{trigger_name}|{proposed_action}|"
            f"{value_bucket:.1f}|{two_hour_bucket}|{day_of_week}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    # ─── skill_state ──────────────────────────────────────────────────────────

    async def get_measurement_degradation(self) -> dict[str, bool]:
        """Degraded sensors, mapped to whether the operator has been told.

        Restored at startup so a crash-looping runtime does not re-send the
        same warning on every restart, and so one whose warning never got out
        still sends it.
        """
        return await self._run_read(self._get_measurement_degradation_sync)

    def _get_measurement_degradation_sync(
        self, conn: sqlite3.Connection
    ) -> dict[str, bool]:
        rows = conn.execute(
            "SELECT sensor_id, notified_at FROM sensor_measurement_state "
            "WHERE degraded = 1"
        ).fetchall()
        return {str(row[0]): row[1] is not None for row in rows}

    async def get_measurement_notice_schedule(self) -> dict[str, tuple[int, int]]:
        """Per degraded sensor, when it began and which notice stage it reached.

        Restored at startup so the escalation schedule survives a restart: the
        clock is not reset, and a stage already delivered is not repeated.
        """
        return await self._run_read(self._get_measurement_notice_schedule_sync)

    def _get_measurement_notice_schedule_sync(
        self, conn: sqlite3.Connection
    ) -> dict[str, tuple[int, int]]:
        rows = conn.execute(
            "SELECT sensor_id, degraded_since, updated_at, notice_stage "
            "FROM sensor_measurement_state WHERE degraded = 1"
        ).fetchall()
        # `degraded_since` is absent on a row written before this column
        # existed. Falling back to `updated_at` dates the degradation to the
        # last write rather than inventing "now", so an upgrade does not
        # restart the schedule from zero for a sensor already long degraded.
        return {
            str(row[0]): (
                int(row[1] if row[1] is not None else row[2]),
                int(row[3] or 0),
            )
            for row in rows
        }

    async def set_measurement_notice_stage(self, sensor_id: str, stage: int) -> None:
        """Record the highest notification stage this degradation has reached."""
        await self._run_write(self._set_measurement_notice_stage_sync, sensor_id, stage)

    def _set_measurement_notice_stage_sync(self, sensor_id: str, stage: int) -> None:
        assert self._conn is not None
        self._conn.execute(
            "UPDATE sensor_measurement_state SET notice_stage = ?, updated_at = ? "
            "WHERE sensor_id = ?",
            (int(stage), now_ms(), sensor_id),
        )
        self._conn.commit()

    async def record_measurement_notice_delivered(
        self, sensor_id: str, stage: int, *, degraded_since: int
    ) -> None:
        """Record a delivered notice: the degradation, the stage, and that it went.

        One statement, one commit. Written separately, a crash between them
        leaves the disk saying a later stage was sent while still saying
        nobody was notified, and the next start sends the notice for the
        transition all over again — which is the duplicate message this state
        exists to prevent.

        An upsert rather than an update, because the row may not exist. The
        write that records the degradation can itself fail — the store is
        allowed to be transiently unavailable, and a failure there is logged
        and does not stop polling — so a later escalation can be the first
        write that lands. An `UPDATE` would match nothing, raise nothing, and
        leave the runtime believing the operator had been told about a
        degradation the disk has no record of at all: the next start would
        find no degraded sensor and forget the measurement loss entirely.

        `degraded_since` comes from the runtime's in-memory value so a
        reconstructed row carries the real start of the loss rather than the
        moment the disk caught up, and the schedule does not restart. Where
        the row already exists, its own start and `notified_at` are kept: the
        latter marks *that* the operator has been told, not when they were
        last told, and the stage carries the schedule's own position.
        """
        await self._run_write(
            self._record_measurement_notice_delivered_sync,
            sensor_id,
            stage,
            degraded_since,
        )

    def _record_measurement_notice_delivered_sync(
        self, sensor_id: str, stage: int, degraded_since: int
    ) -> None:
        assert self._conn is not None
        now = now_ms()
        cursor = self._conn.execute(
            """
            INSERT INTO sensor_measurement_state
                (sensor_id, degraded, notified_at, degraded_since,
                 notice_stage, updated_at)
            VALUES (?, 1, ?, ?, ?, ?)
            ON CONFLICT(sensor_id) DO UPDATE SET
                degraded = 1,
                notified_at = COALESCE(
                    sensor_measurement_state.notified_at, excluded.notified_at
                ),
                degraded_since = COALESCE(
                    sensor_measurement_state.degraded_since, excluded.degraded_since
                ),
                notice_stage = excluded.notice_stage,
                updated_at = excluded.updated_at
            """,
            (sensor_id, now, int(degraded_since), int(stage), now),
        )
        if cursor.rowcount != 1:
            # Unreachable while the statement above is an upsert, which always
            # affects exactly one row. It is here so that a return to a plain
            # `UPDATE` fails closed rather than silently: that statement
            # matches nothing when the row is absent, raises nothing, and the
            # caller would mark an operator as told about a degradation the
            # disk has no record of. Nothing written means nothing recorded,
            # and the caller keeps the obligation.
            self._conn.rollback()
            raise RuntimeError(f"measurement notice for {sensor_id!r} was not recorded")
        self._conn.commit()

    async def set_measurement_degraded(self, sensor_id: str, *, notified: bool) -> None:
        """Record a degradation, and separately whether it has been reported."""
        await self._run_write(self._set_measurement_degraded_sync, sensor_id, notified)

    def _set_measurement_degraded_sync(self, sensor_id: str, notified: bool) -> None:
        assert self._conn is not None
        now = now_ms()
        self._conn.execute(
            """
            INSERT INTO sensor_measurement_state
                (sensor_id, degraded, notified_at, degraded_since, updated_at)
            VALUES (?, 1, ?, ?, ?)
            ON CONFLICT(sensor_id) DO UPDATE SET
                degraded = 1,
                -- The start of the degradation, not of the latest write: the
                -- escalation schedule is measured from when measurement was
                -- lost, so a second write must not move it forward.
                degraded_since = COALESCE(
                    sensor_measurement_state.degraded_since, excluded.degraded_since
                ),
                -- Once reported, stays reported. A later write that has not
                -- itself notified must not reopen the alert.
                notified_at = COALESCE(
                    sensor_measurement_state.notified_at, excluded.notified_at
                ),
                updated_at = excluded.updated_at
            """,
            (sensor_id, now if notified else None, now, now),
        )
        self._conn.commit()

    async def clear_measurement_degraded(self, sensor_id: str) -> None:
        """Record that a sensor is measuring again."""
        await self._run_write(self._clear_measurement_degraded_sync, sensor_id)

    def _clear_measurement_degraded_sync(self, sensor_id: str) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO sensor_measurement_state
                (sensor_id, degraded, notified_at, degraded_since, updated_at)
            VALUES (?, 0, NULL, NULL, ?)
            ON CONFLICT(sensor_id) DO UPDATE SET
                degraded = 0,
                notified_at = NULL,
                degraded_since = NULL,
                notice_stage = 0,
                updated_at = excluded.updated_at
            """,
            (sensor_id, now_ms()),
        )
        self._conn.commit()

    async def get_skill_state(self, skill_name: str, key: str) -> Optional[str]:
        return await self._run_read(self._get_skill_state_sync, skill_name, key)

    def hooks_get_skill_state(self, skill_name: str, key: str) -> Optional[str]:
        """Stable sync facade for hook skill-state reads."""
        return self._run_read_with_conn(self._get_skill_state_sync, skill_name, key)

    def _get_skill_state_sync(
        self, conn: sqlite3.Connection, skill_name: str, key: str
    ) -> Optional[str]:
        row = conn.execute(
            """
            SELECT value FROM skill_state
            WHERE skill_name = ? AND key = ?
            """,
            (skill_name, key),
        ).fetchone()
        return row["value"] if row else None

    async def set_skill_state(self, skill_name: str, key: str, value: str) -> None:
        await self._run_write(self._set_skill_state_sync, skill_name, key, value)

    def hooks_set_skill_state(self, skill_name: str, key: str, value: str) -> None:
        """Stable sync facade for hook skill-state writes."""
        self._set_skill_state_sync(skill_name, key, value)

    def _set_skill_state_sync(self, skill_name: str, key: str, value: str) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO skill_state (skill_name, key, value, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(skill_name, key) DO UPDATE SET
                value      = excluded.value,
                updated_at = excluded.updated_at
            """,
            (skill_name, key, value, now_ms()),
        )
        self._conn.commit()


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
