# Ori Runtime — Unreleased

Changes merged to `main` after `v2.5.0` are collected here until the next
release is cut.

## Upgrade notes

- A deployment's `skills[]` entry in `ori.yaml` now accepts only `name` and
  `version`, and a skill's `skill.yaml` accepts only the trigger and action
  keys the loader reads. A configuration or skill that carries any other key
  is refused at load; see Changed below for where each setting lives.
- The Tier C authority snapshot no longer includes a deployment approval
  timeout, so its policy digest changes on upgrade. A Tier C proposal open
  across the upgrade is closed with its safe default, as at every restart,
  and is not approved under the new digest; the next trigger raises a new
  proposal.
- An MQTT-family sensor whose `topic`, or a Victron sensor whose
  `portal_id`, contains the wildcard `+` or `#` is now refused at config
  load, so a runtime carrying one no longer starts. Before, it started and
  that sensor silently never read. Before restarting on this release,
  replace each wildcard with one sensor per concrete topic.
- An MQTT-family sensor whose `clean_session` or `mqtt_clean_session` is set
  to anything but `true` is refused at config load, so a deployment that
  asked for a persistent session no longer starts. Remove the setting, or set
  it to `true`, before upgrading.
- `gateway.firmware_commands.publish_timeout_s` must be finite. A value such
  as `.inf` loaded before and is now refused at config load; set a finite
  number of seconds before upgrading.

## Added

- `ori skills validate <path>` loads one skill directory, or every skill in a
  parent directory, through the runtime's own loader and reports the first
  problem in each. It exits 0 when every skill is valid, 1 when any is
  invalid and 2 when the path cannot be read, and `--json` writes one
  document.
- Firmware fault events are verified under their own fault version. A fault
  at `v` 2 (`firmware-telemetry/v2`, a draft) may carry `command_rejected` /
  `rate_limited`, the edge firmware's signed refusal of a command that
  arrived sooner than its release-owned actuation rate policy allows. The
  refusal is recorded in `firmware_fault_events` and never as an execution,
  and the runtime does not reissue the command. At `v` 1 the same token is
  refused, as is any `v` other than the integer 1 or 2. Faults still never
  reach readings, skills, dispatch or Tier D.

## Changed

- A skill's triggers and `actions.available` entries accept only the keys
  the loader reads. Any other key, including a misspelling such as
  `Requires_Approval`, is refused at load with an error naming the skill,
  the trigger or action, and the key, so a mistyped safety setting fails
  closed instead of being ignored.
- A deployment's `skills[]` entry in `ori.yaml` is closed to `name` and
  `version`, and its `config` mapping is refused: no key in it reached a
  skill. `approval_timeout_seconds`, the one key the runtime parsed, governed
  nothing — a Tier C proposal's lifetime is its trigger's, from `skill.yaml`,
  bounded by the release maximum. A refused key is named with where its
  setting actually lives: the trigger in `skill.yaml` for
  `safe_default_action`, `action_tier`, `requires_approval` and
  `approval_timeout_seconds`, and `actions.secondary_contact` for
  `secondary_contact_number`. The shipped example configurations no longer
  carry skill settings.
- The Android payload is documented as a lab and contingency profile, not a
  deployment shape: it serves demonstrations, installer diagnostics,
  supervised advisory runs and short data collection where no edge host is
  available. A release claims no actuation, Tier C or Tier D authority,
  continuous operation or protection for it. A site's runtime runs on a
  Linux edge host. The phone guides no longer promise an upgrade path from a
  phone to an edge node.

## Fixed

- An admitted firmware fault event is durable. The fault row and the device's
  freshness advance commit in one transaction, so a failure between them
  leaves neither written and the same signed fault can be redelivered; before,
  the mark moved first and a lost fault row made every redelivery a
  `sequence_replay`. Fault rows are keyed by `(device_id, key_epoch_id,
  boot_id, seq)`, the epoch being the anchor the fault was verified against:
  a re-keyed device restarts its counters, and a fault reusing a `(boot_id,
  seq)` recorded under its earlier key was silently dropped after the advance.
  A store created before this change has its `firmware_fault_events` table
  rebuilt at the next runtime start in one transaction, every row and id kept
  and earlier rows carrying an empty `key_epoch_id`; a read-only open does not
  migrate.
- A cached sensor no longer serves a value its source has moved past. In
  every MQTT-family adapter, HTTP and CoAP, a payload refused for a sensor
  withdraws that sensor's cached value, so reads refuse and name the refusal
  until an accepted payload arrives.
- A sensor source that has not yet published, or whose last payload was
  refused, no longer counts against the circuit breaker, and a fresh value
  closes an open breaker, so a Tier D source that starts late is observed
  within one poll. HTTP and CoAP probe an open breaker every poll interval.
- An MQTT-family sensor adapter reconnects to a broker that drops, with
  jittered back-off up to 60 seconds, and resubscribes; reads are refused
  from the drop until a value arrives on the new connection. A connection
  that drops within 30 seconds does not reset the back-off, and a connect
  the broker never answers is closed rather than left open. A broker that
  hangs without closing the connection is still noticed only after twice the
  keepalive.
- A retained MQTT message is never taken as a reading. The on-change
  adapters (Victron, LoRaWAN, Zigbee) stay without a value, reads refused,
  until a live publication arrives, which can take hours. Sensors always
  connect with a clean session, and a sensor's `clean_session` or
  `mqtt_clean_session` set to anything but `true` is refused at config load.
- An MQTT-family sensor whose `topic` (or a Victron sensor whose `portal_id`)
  contains the wildcard `+` or `#` is refused at config load, naming the
  sensor and the key. Such a sensor loaded and subscribed but never read,
  because a value is cached under the topic of the message that carried it
  and read under the configured one. The adapters refuse it too, before
  dialling the broker. One sensor reads one concrete topic.
- `aiomqtt` is in the runtime lock, so the MQTT perception adapters install
  from the release bundle. Connecting one on a Raspberry Pi is not yet
  observed.
- A request that joins an act another dispatch already holds on the same
  resource is recorded in the action log as a contributor, not as an act of
  its own. Its row has `record_kind = 'contributor'`, `executed = 0`, no
  approval, no authority snapshot and no attestation, and `contributed_to`
  names the holder's `record_key`. Only dispatch rows are attested. A joiner
  no longer waits on the holder's outcome, and a joined Tier B post-action
  trigger is no longer reported as a failed act. Rows an earlier release
  recorded as `coalesced` become `contributor_legacy` on every open of the
  store, with no link invented. The gateway and bridge action-log exports do
  not yet carry the record kind, so they still show a contributor as an act.
- A host-state approval that fails or is cancelled after its act still
  records its decision, through the same ordered writer as the act, or
  counts it lost when it cannot be queued. The action row records the act
  that ran rather than a blank result.
- The courier's answer on a sealed evidence envelope has its own ledger
  column, `courier_answer` (`queued`, `queue_full`, `refused`), beside
  `last_failure`, the transport outcome of the last publish. A publish that
  completed after the courier answered no longer erased the answer, so a
  refused or deferred envelope is no longer reported as having no failure
  and a republish no longer opens a new refusal record. Answers are ordered
  by the courier's signed time, so a delayed older answer never replaces a
  newer one. The shared gateway envelope verifier accepts `signed_at_ms`
  only as a JSON integer. A rollback to `v2.5.0` is not lossless: that
  release does not record `queued`.
- Firmware telemetry is held to `firmware-telemetry/v1` where the runtime
  accepted more. A signed manifest with an unknown or missing root field, an
  action other than exactly `action`, `channel` and `authority`, or an
  interlock other than exactly `name`, `channel` and `action` is refused
  `invalid_envelope`, and `v` must be the integer 1. Telemetry or a fault
  whose `device_uptime_ms` goes back within one `boot_id` is refused
  `uptime_regression`. A message that loses the store's atomic advance is
  refused under the reason that applies (`device_revoked`,
  `device_not_approved`, `boot_rollback`, `uptime_regression` or
  `sequence_replay`) instead of always `sequence_replay`.
- `gateway.firmware_commands.publish_timeout_s` must be a finite number
  greater than zero, and an exhausted `cmd_seq` counter is a refusal.

## Security

- Every Ed25519 public key the runtime admits is refused when it is of small
  order, non-canonical, off the curve or carries an invalid sign bit, before
  any verifier is built. Under such a key a signature can verify without a
  private key. One admission applies this to firmware device keys, MQTT
  provisioning responses, commissioning bindings, anchors and firmware
  profiles, signed configuration, community skills, offline tokens, release
  bundles and their key registry, Android payloads, evidence ingest and
  firmware commands; the Android runtime and the host release-evidence
  harness apply the same refusal. A configured anchor of this kind is
  refused where it loads.
- An Ed25519 key of mixed order — a valid key shifted by a point of small
  order — is refused as well, and every check that recognises a key by its
  bytes now compares its identity, so a key and its negation are one key.
  Before this, a published test key, a rotated-away device key or a
  colliding anchor could pass those checks in either shifted or negated
  form. The checks covered are the published-test-key refusal, anchor
  collision and rotation, re-provisioning's refusal of an earlier device
  key, the authority key registry's one-purpose-per-key rule, and the
  commissioning binding and profile collision checks.
- Firmware trust decisions hold where they are committed. Telemetry and
  fault freshness advance only while the registry still holds the anchor
  the message was verified against, so a message verified under a key
  before an approved rotation is no longer accepted after it; a message
  whose anchor keeps moving is refused `anchor_unstable`. Command sequence
  and liveness allocation, and the retained provisioning approval, recheck
  revocation, approval, cross-store confirmation and anchor at the commit,
  so a revocation that lands after the signer's reads stops the command,
  the approval and liveness. After an upgrade, liveness for an anchor the
  upgrade backfill marked pending stops until it is confirmed.
- The firmware command publisher no longer delivers a command, approval or
  liveness message after reporting it failed. It hands nothing to a
  disconnected client, retires any client whose publication failed, timed
  out or was cancelled by shutting its socket first, and its clients never
  reconnect on their own. Bytes written to the socket before a failure was
  reported may still reach the broker, and a message the broker already
  holds, including a retained approval, is outside the runtime's reach.
- `multidict` is updated to 6.9.1 for CVE-2026-104874.
