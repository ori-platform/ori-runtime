# Ori Runtime — Unreleased

Changes merged to `main` after `v2.5.0` are collected here until the next
release is cut.

## Upgrade notes

- Every `skill.yaml` value the loader reads, apart from the skill's own
  `config` values, now has one YAML type, checked before any is used:
  strings for names, conditions, tiers and policies, integers for
  `cooldown_seconds` and `approval_timeout_seconds`, YAML booleans for
  `bypass_llm` and `requires_approval`, lists for `triggers`,
  `sensors_required`, `actions.available` and each `actions.defaults` entry,
  and mappings for `actions`, `prompts` and `config`. A value of another type
  refuses the skill with the field and the type it received, including
  `null` (an empty `prompts:`, `reasoning_policy:` or `sensors_required:`)
  and a float where an integer is expected (`cooldown_seconds: 10.0`). Before,
  a quoted number such as `cooldown_seconds: "10"` was converted, a float was
  truncated, an empty value read as none, and `bypass_llm: "no"` read as true.
  An action's `tier`, when present, must be a tier letter, in either case as
  before; any other value, `tier: ""` included, is refused rather than read
  as Tier A or as omitted. A condition longer than 4,096 characters is
  refused at load and by the engine. A negative
  `cooldown_seconds` is refused, and a trigger whose condition the rule engine
  cannot evaluate, or a Tier D trigger with no condition, refuses the skill.
  Write each value in its own type.
- `skills:` in `ori.yaml` is now the list of skills that run. Each name
  resolves to the skill of that name that ships with the runtime, or to that
  directory under `skills_dir` (default: `skills` beside `ori.yaml`). A
  directory under `skills_dir` that no entry names is no longer loaded, and
  is named in a WARNING at load. A name that resolves to neither, or to both,
  or to a skill whose `skill.yaml` declares another name, or whose `version`
  differs from the entry's, refuses the start; on a reload it keeps the
  running skills. A listed skill that ships with the runtime and fails to load
  also refuses the start. Before upgrading, list every skill the device should
  run, and correct or drop each `version` that does not match the skill's own:
  `ori.yaml.example` shipped `energy-anomaly-detector` pinned at `0.2.1`, which
  the skill has never been, so a configuration copied from it refuses the start
  until the pin is `0.1.0` or removed. This includes a source checkout, or a
  `skills_dir` pointed at the packaged directory, which used to load every
  packaged skill; each one `skills:` leaves out is named in the WARNING, and an
  empty `skills:` is warned about too. `skills[].name` must be a skill
  directory name, named once in any letter case.
- Firmware commands and runtime liveness are now signed in separate signing
  domains (`firmware-commands/v2` Signing Domains): a command over
  `ori.firmware_command.v2`, a NUL and its object bytes, liveness over
  `ori.firmware_liveness.v2`, a NUL and its object bytes. Nothing the runtime
  command key signs is over the bare bytes any longer, so a device whose
  firmware verifies the earlier form refuses every command this release signs
  and every liveness message it publishes. The runtime signs for a device only
  while its accepted manifest declares `runtime_key_domains:
  "firmware-commands/v2"` (`firmware-telemetry/v2` Runtime Key Domains); for any
  other device it signs nothing, logs a WARNING when it accepts the manifest and
  at each start over one it already holds, and its `runtime_commanded` actions
  are unavailable. Upgrade device firmware to a release that verifies in the
  domains and declares the member before relying on runtime commands or
  liveness. A manifest whose `runtime_key_domains` is anything but that exact
  string is refused at registration with `invalid_runtime_key_domains`.
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
- A firmware capability manifest whose `device_mode` is not one of
  `sensor_node`, `bridge_node`, `actuator_node` or `mixed`, or is not the mode
  its `channels` and `actions` determine, is now refused at registration with
  `invalid_device_mode`. A manifest with no channel is refused with
  `no_channels`, as it was before under `invalid_envelope`. A device
  registered before this release is checked against the same rules: if its
  stored manifest fails them, its telemetry and faults are refused with that
  code and its pending anchor is not approved. Re-register it from a manifest
  that follows `firmware-telemetry/v2`.
- A firmware manifest's bridged channel (`source: foreign_device`) must now
  name its controller profile in `controller_profile`, and must be on
  `modbus_rtu`; `controller_alarm_word` and `bitmask` are refused anywhere
  but a bridged alarm word. A device registered with a bridged channel before
  this release has its telemetry and faults refused until it re-registers
  from a manifest that names its profiles, which needs edge firmware that
  signs them.
- Firmware telemetry is now judged in `firmware-telemetry/v1`'s order of
  steps: an envelope's signature is verified before its version, posture,
  counters or readings. A tampered envelope that also carries a bad field
  is refused `signature_verification_failed` where it was refused for the
  field. An envelope whose `v` is not the integer 1 or 2 is refused
  `unsupported_version`, which was `invalid_envelope`.
- Liveness is published at `v` 2 alone (`firmware-commands/v2`, Which `v`
  the runtime publishes): one message per interval to every supervised device
  whose manifest declares `runtime_key_domains`, never at `v` 1. Before, it
  was published at `v` 1. A device that does not declare the domains is sent
  none, as before. An interval whose nonce, signature or publish fails sends
  nothing in its place. A device on firmware that accepts liveness only at
  `v` 1 stops being supervised by this runtime, including one that declares
  the domains: `ori-edge-firmware` builds after `a2c528f` and before `ee35e34`
  declare them and accept only `v` 1. The runtime cannot tell, since a refused
  liveness message answers nothing, so reflash such a device. Current
  reference firmware accepts `v` 2 and keeps it out of command capacity. Any
  `gateway.firmware_commands.publish_liveness_v2` key is refused at config
  load: remove it.
- A LoRaWAN, Zigbee or MQTT perception reading's `timestamp` is now when the
  value reached the runtime. Before, it was a time copied from the payload,
  such as a network server's `received_at`, a coordinator's `last_seen` or a
  perception payload's `timestamp_ms`, none of which a protocol the runtime
  reads declares to be when the value was measured; that time is now in
  `metadata.payload_time`. History stored before this release keeps its
  stored times and reads as of unknown basis.
- A Tier C approval message for a reading the runtime did not request, such
  as an MQTT, Victron, LoRaWAN or Zigbee reading, now reads
  `Measured: not reported by device` rather than the time it arrived.
- The first start on this release adds a column to raw history, keeping
  every row, and compacts into new tables from then on; the compacted tables
  an earlier release wrote are kept as they are, so rolling back leaves that
  release recording and compacting as before. Until the first start has run,
  `ori state history` and
  `ori state action-log`, which open the store read-only and never migrate
  it, refuse a store an earlier release wrote with `state_migration_required`
  and change nothing.
- `device.id` must now match `^[A-Za-z0-9._-]{1,128}$`, runtime-config/v2's
  pattern, which `gateway-api/v2` sizes every topic by. Before, only a space
  was refused, so an id carrying any other character, such as `/`, `+`, a
  non-ASCII letter, or an unexpanded `${...}` placeholder, loaded; it is now
  refused at config load. Rename the device before upgrading; its evidence
  identity and gateway topics follow the new id.
- A gateway export request is now answered only when its `request_id` is 1
  to 128 characters from `A-Z`, `a-z`, `0-9`, `.`, `_` and `-`. A request
  that is not a JSON object, or names any other `request_id`, is refused
  unanswered, where it was answered on `.../export/response/invalid`. An
  export error's `error` is now fixed text of at most 128 characters, a
  reason token and never the request's content or an exception's text, and its
  `export_type` is `unknown` unless the runtime serves the one requested.

## Added

- Health names the devices this runtime signs nothing for:
  `firmware_liveness.undeclared_device_ids` lists every held device whose
  accepted manifest does not declare `runtime_key_domains`, re-read from the
  registry for every snapshot, so a device enters the set when its manifest is
  accepted and leaves it when a declaring one is, with no restart. Such a
  device is never counted in `supervised_devices` or listed in
  `expiring_device_ids`, and a non-empty set degrades `status`. The
  `firmware_signing_domains_undeclared` token is not named yet: a gateway
  refuses a heartbeat carrying a token outside its vocabulary, so it waits for
  gateways that accept it (runtime-health/v4). Manifests that cannot be listed
  make `firmware_liveness.state` `unavailable` and `status` critical, never an
  empty set. The block also carries `state` (`disabled`, `starting`,
  `unavailable` or `available`). A liveness loop not yet started is `starting`
  and degrades `status`; one still not started 300 seconds after the process
  started is `unavailable` and makes it critical, so a hung start is never
  reported healthy.
- Health reports `mqtt_ingress`: for each gateway-to-runtime route the runtime
  built, how many messages it refused for size (`payload_too_large`), dropped
  for volume (`volume_dropped`: past the family's rate or its work in flight)
  and refused under the Payload Member Rule (`member_refused`), since the
  process started. A message left for the broker to redeliver is not counted:
  inbound evidence past its rate or its work in flight is left that way,
  so it is never `volume_dropped`.
  The block is `disabled` with no gateway configured and contributes no
  condition (runtime-health/v4).

- The Tier C approver registry, built against the `tier-c-approvers/v1`
  draft: the runtime-owned record of who may approve a Tier C action, bound to
  the device, a verified `device.site_id` and an identity epoch the runtime
  mints. Its local operations (challenge, recover, local seed, enrol, revoke
  and the binding readback) are on the operator socket, built against the
  `operator-socket/v3` draft; conformance to either is not yet assessed. This
  release enrols LAN keys only: no phone ingress reaches the registry, so an
  SMS candidate is refused `channel_unauthenticated`, and no Tier C reply is
  yet admitted against it.
- `device.site_id` (optional, `^[A-Za-z0-9._-]{1,64}$`). The registry is
  available only with a verified value: from a signed configuration, or the
  configuration's own value in unsigned development posture. A registry
  created under another `device.id` refuses every operation as
  `device_binding_mismatch`, recovery included, until the original identity is
  restored, as a changed site refuses as `site_binding_mismatch`. Any legal
  `device.id`, up to 128 characters, can hold a registry.
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
- Firmware Controller Profiles (`firmware-telemetry/v2`). Registration
  applies the four new refusals and the one-profile rule. Profile documents
  are held from `gateway.firmware_telemetry.controller_profiles_dir`, by
  digest, and only when their bytes are canonical and valid. A bridged
  measurement outside its document's range is refused as a producer defect,
  and a bridged reading carries the profile and qualification of the manifest
  it was accepted under in its metadata. A foreign controller's alarm word
  never becomes a reading: health's `firmware_controller_profiles` shows each
  alarm channel as unknown or as of the reading it came from, by key epoch
  and `(boot_id, seq)`. That state becomes unknown on silence
  (`3 x poll_interval_ms + 30000` on a clock that counts suspend), a
  `sensor_fault` for the channel, any promotion, rotation or revocation, and
  a restart.

- Firmware reading envelopes at `v` 2, and how old a firmware reading is
  (`firmware-telemetry/v2`, `firmware-commands/v2`). An envelope may carry
  `liveness_nonce`, the nonce of the last `v` 2 liveness message the device
  accepted before the measurement began. The runtime signs that nonce into
  each interval's liveness message
  and records, in memory only, when it began signing it, on a clock that counts suspended time. A reading whose
  nonce this process signed for the same device, boot and manifest within an
  hour was polled no more than `now - signing start` ago. Health's new
  `firmware_reading_age` shows each device's latest reading with that bound
  as "polled no more than A ago, as of T", or `unbounded`; alarm snapshots in
  `firmware_controller_profiles` carry the same. A restart empties the table,
  so no reading read back from storage has a bound, and only the runtime that
  signed the nonce computes one. The bound dates the device's poll, not the
  measured quantity, and is not a safety input. The three contract corpora
  are vendored and driven.
- Health reports the evidence envelopes a courier holds that the authority
  has not receipted, as `evidence.awaiting_receipt_count` and
  `evidence.oldest_awaiting_receipt_age_ms`, so a receipt that was refused or
  lost is visible without querying the ledger. The age is the greater of the
  time since the courier says it took custody and the time since this runtime
  recorded it, so a courier clock running ahead cannot make an envelope look
  fresher than its arrival. The runtime's record is the first one and is
  final: a redelivered acknowledgement does not move it. Custody recorded
  before this release is aged by the courier's account alone. Both are `null` when the ledger cannot be read,
  and neither affects `status`.

## Changed

- The gateway `health` export no longer carries device identifiers from
  `firmware_liveness`: `expiring_device_ids` is exported as
  `expiring_device_count`, and `undeclared_device_ids` as
  `undeclared_device_count` (runtime-health/v4 keeps both sets on the device),
  and its free-text `last_error` is no longer exported. The local health
  socket still serves all three.

- A firmware manifest may declare `command_results:
  "firmware-command-result/v1"` (`firmware-telemetry/v2` Command Results); any
  other value is refused at registration with `invalid_command_results`. A
  `v` 2 `storage_degraded` fault may carry `command_record_write_failed`. The
  runtime does not yet consume command results: a `command_result` payload, like
  a `maintenance_event` or `result` payload, is not acted on and supervises
  nothing (ori-runtime#482 adopts it).
- A firmware telemetry payload must carry exactly one Layer 1 family key beside
  its `signature` (`firmware-telemetry/v2` Layer 1 evidence families). One with
  two family keys, or any other top-level key, is refused on its keys alone,
  before any inner object is read: by the subscriber, with a coalesced WARNING,
  and again by the envelope and fault verifiers, as `invalid_envelope` once
  the device's anchor checks pass. Before, the route took the first key it
  recognised and the verifiers accepted other keys beside theirs.
- The operator socket is built against the `operator-socket/v3` draft, with no
  conformance claimed: a request is one JSON object
  and one LF, at most 16,384 bytes (up from 8,192, a limit v2 never stated),
  counted before anything is parsed and refused `payload_too_large`, for
  `reconcile_tier_c` and `evidence_commission` as for the registry operations.
  A registry operation that holds a string with no UTF-8 form, nests deeper
  than 32 levels or names a member twice is `invalid_arguments`;
  `reconcile_tier_c` and `evidence_commission` keep their v2 rules.
- Every sensor reading records what its `timestamp` is, as `gateway-api/v2`
  Producer Time defines it: `reported` for a read the runtime requested,
  `not_reported` for a value pushed to it, timed by its arrival, and `unknown`
  for history stored before this release. The `sensor_history` export and
  the Tier 3 reasoning request carry it as `producer_time`, and a bucket
  holding readings of more than one basis is exported as one row for each.
  A gateway that ignores the member keeps working, and may receive more rows
  for such a bucket than before.
- `ori state action-log` and the gateway `action_log` export carry
  `record_kind`, `record_key` and `contributed_to`, so a reader can tell a
  request that joined another's act from an act, and find the act it joined.

- The Android payload accepts `--progress`, which prints one line per poll on
  stderr naming the poll, how many sensors it read and failed, and whether it
  attempted an upload or a status snapshot. Without the flag its output is
  unchanged. The delivery tests use it to wait for the polls they assert on
  rather than for a stretch of wall-clock time.

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
- The health snapshot always carries `critical`, `true` exactly when
  `status` is `critical`. A firmware liveness loop that stopped, a tick older
  than the expiry window, a loop running that long without one successful
  tick, or an expired device is now `status: critical`; over-capacity and
  failing ticks alone are `degraded` with `critical: false`, and a loop
  stopped in an orderly shutdown holds none of them. `ori doctor` and the
  installer's health gate fail on a critical snapshot, so both now fail on a
  lost decision record, which they passed before, and no longer fail on
  liveness over capacity or failing ticks alone.
- The state store is split by domain. `ori/state/store.py` composes
  `StateStore` from one class per domain (history, action log, Tier C,
  remote commands, alert outbox, firmware, commissioning, device policy,
  reasoning, measurement and skill state), each in a private module under
  `ori/state/`, with the DDL in `_migrations.py`. The methods moved unchanged:
  the schema, the migrations and every behaviour are the same, and
  `ori.state.store` still exports every name imported from it. Tests hold
  every module under `ori/` to 1,500 lines and every function to 150, and
  those already over either limit to their current size.
- The runtime is split by concern. `OriRuntime.start()` runs nineteen
  ordered stages over one startup context, in the order and with the
  constraints `docs/STARTUP_STAGES.md` records and three tests hold, instead of
  one 1,257-line method. `ori/runtime.py` is now the package `ori/runtime/`:
  `OriRuntime` is composed from one class per domain (startup, shutdown,
  health, alerts, remote commands, sensors, measurement, evidence, firmware,
  device policy and the rest), and the module-level helpers live in private
  modules by concern. The code moved unchanged and every behaviour is the same.
  `ori.runtime` exports its interface only (`OriRuntime`, `main` and the
  constants and helpers other modules read), listed in its `__all__`; a script
  that imported a private name from it imports it from the module that defines
  it. `python -m ori.runtime` and the `ori-runtime` command start the runtime
  as before. Under `python -m`, log records are now named `ori.runtime`, as
  they already were under the `ori-runtime` command, and `--help` names the
  program `ori-runtime`.
- The configuration loader is split by section. `ori/config.py` is now the
  package `ori/config/`, with one private module per top-level section of
  `ori.yaml` (device, sensors, skills, reasoning, gateway, actions, hal,
  state, security, evidence and the rest), document admission in
  `_document.py`, `Config` in `_config.py` and production posture in
  `_posture.py`. The code moved unchanged: every section is parsed and
  refused as before, and log records still carry the `ori.config` logger name.
  `ori.config` now exports its interface only: `Config`, each section's
  dataclass, `ConfigValidationError`, and the functions and constants other
  modules read (`anchor_to_config`, `config_env_placeholders`,
  `hardened_posture_declared`, `read_config_document`,
  `requires_production_posture`, `SKILL_NAME_RE`, `MAX_SKILL_NAME_LENGTH`,
  `RESERVED_SENSOR_METADATA_KEYS`), listed in its `__all__`. Its private
  helpers and the names it happened to import are no longer reachable through
  it; a script that read one imports it from the section module that defines
  it.
- The skill loader is split by concern. `ori/skills/loader.py` now only
  re-exports its interface, and the code runs in modules beside it:
  `_manifest.py` (the data model, the manifest grammar and the workload
  budgets), `_provenance.py` (which skills ship with the runtime, and the
  community trust anchor), `_validation.py`, `_registration.py` (handler
  registration, hook loading and the cooldown tracker) and `_loader.py`
  (`SkillLoader`). The code moved unchanged: every skill is loaded and refused
  as before, and log records still carry the `ori.skills.loader` logger name.
  `ori.skills.loader` exports `SkillLoader`, `Skill`, `Trigger`,
  `SkillValidationError`, `SkillSelectionError`, `CommunitySkillAdmission`,
  `first_party_skill_roots` and `MAX_TOTAL_SUBSCRIPTIONS`, listed in its
  `__all__`; a script that read a private name through it imports it from the
  module that defines it.
- The modules beside the configuration loader moved into it:
  `ori.config_fields` is now `ori.config._fields`, `ori.config_skill_entry` is
  `ori.config._skill_entry`, and the signed config installer is
  `ori.config.installer`. The `ori-config-install` command is unchanged; a
  script importing one of the old module paths must use the new one.

## Fixed

- The skill loader no longer crashes on, or admits, a manifest value of the
  wrong type. `action_tier: [D]`, a list in `actions.defaults` or a
  non-numeric `cooldown_seconds` raised a `TypeError` or `ValueError` (a
  traceback from `ori skills validate`, and the skill silently dropped by a
  full load); `condition: ["value > 1"]` loaded, so a Tier D trigger's
  protective condition could never fire; a list or number as a
  `safe_default_action` or an action's `tier` was read as its text. Each is
  now a refusal naming the skill, the trigger or action, the field and the
  type received. A condition the rule engine cannot evaluate, a blank one, an
  unknown or misused `history` helper, one longer than 4,096 characters, and
  text the parser cannot take included, is refused at load by the engine's
  own complete check, and a Tier D trigger must have a condition. Before, one such condition anywhere in a
  skill made the engine raise for every trigger of that skill, so its Tier D
  triggers were suspended along with it. Every refusal is bounded to 1,000
  characters, keeping its start and its end, whatever the manifest put in it. A condition that parses but compares a
  reading with text is still found only when it is evaluated.

- A sensor whose source cannot be reached when the runtime starts is no
  longer skipped until a restart. An OPC-UA server, a serial or USB-serial
  device (one to auto-detect included), or an I2C device that is not there
  yet is connected again in the background, under the same bounded, jittered
  back-off as a dropped MQTT broker, with a fresh adapter each attempt; the
  sensor stays unconnected, and health degraded, until its first reading is
  accepted, and the operator is told when it is. Whether a failure is retried
  is decided by what caused it: a device absent or busy, a host refusing or
  unreachable, or a timeout is retried; a permission error, a malformed value
  or a refused login is final, as before, and if a retry meets one the
  operator and the safety registry are told that the sensor is no longer
  being read. HTTP, CoAP, Growatt and Solarman sensors recover their data on
  their own, since their connect does not reach the source, but while such a
  source is down at start health reads it as connected (ori-runtime#958).

- A cancelled dispatch now hands the cancellation back to whoever cancelled
  it, once the attempt is recorded. Before, the dispatcher recorded the
  attempt and returned normally, so a shutdown or a superseding task could not
  tell it had been honoured. Recording is unchanged: an approval workflow
  still finishes its decision record and the act's row, approval and proposal
  included, and a failed Tier D act still sends its emergency notice, before
  the cancellation is handed back. A Tier D act whose shielded executor is
  still driving still answers with its uncertain result, and one that had
  finished when the cancellation arrived is now recorded as it ran rather
  than as not executed. Three handlers of the same kind no longer misread a
  cancellation: a Tier D executor task that ends cancelled, as a loop-wide
  cancel can leave one before it runs, while the resource gate holds its
  command as uncertain now releases it as not accepted (it stayed uncertain
  until shutdown, refusing the opposite command), a cancelled safety-trip
  intent append is logged as a failed append and the trip command still
  proceeds, and the deadline callback for that append no longer logs a
  cancellation as an error.

- Every action-log row carries a `record_key`. A refusal for an unrecognised
  tier, a relay action suppressed by policy, a Tier D action from a skill
  without first-party provenance, and an action below its minimum tier were
  written with an empty key, so nothing could name or resolve them, and
  `gateway-api/v2` refuses an empty `record_key` on export. The store now
  refuses a new row without one.
- The gateway `action_log` export carries only tiers `A` to `D`, as
  `gateway-api/v2` now states. A refusal of an unknown tier
  (`refused_unknown_tier`, not executed) records no act and is omitted before
  paging. Any other row stored with a tier outside `A` to `D` was written by a
  release up to v2.3.0, which ran an unknown or lower-case tier as Tier A, and
  exports as `A`; a `tier` filter selects by the exported tier. The store and
  `state action-log` keep what was recorded.
- A skill can no longer declare an action, or a `safe_default_action`, named
  as the runtime records an action not taken: `coalesced`, `suppressed`,
  `no_executor`, `not_performed`, `proposal_not_committed`, a Tier C decision
  state such as `dispatch_outcome_unknown`, a name starting `refused_` or
  ending `_unrecorded`, in any letter case. Its row would have read as the runtime's
  own decision, and `coalesced` marks a contributor to a consumer that predates
  `record_kind`. The loader refuses such a skill, naming it. A safe default
  that raises after a failed approval, or whose intent another attempt already
  made, is recorded as not taken, rather than under its own name.
- The signed config installer judged loopback for `--allow-insecure-loopback`
  with its own fixed set (`localhost`, `127.0.0.1`, `::1`). It now uses the
  same helper as the configuration and the runtime, so any loopback address,
  `127.0.0.2` or a bracketed `[::1]` among them, is admitted, and a hostname
  that only resembles one, such as `127.0.0.1.nip.io`, is still refused.
- A `skills:` entry naming a skill that ships with the runtime loads it on an
  installed runtime. Before, the loader read only `skills` beside `ori.yaml`,
  which an installed runtime does not populate, so the runtime started with no
  skills and no error unless `skills_dir` pointed at the packaged directory.
- The rebuild of a commissioning proof table from an earlier build is one
  transaction. A failure partway leaves the store as it was. A store that an
  earlier, non-atomic rebuild left with its rows stranded in
  `_commissioning_proof_observation_legacy` has them carried over on open.
  Each observation is carried once, matched by its consent rather than its
  id, so a row written since under a reused id is kept beside it. Before, the
  next open left them behind, and with them the audit of the consents and
  coil commands they recorded. A store holding the old schema under both
  names refuses to open until repaired; no released build can produce one.
- A connection whose open fails after the connect is closed at once, not left
  for the collector. That covers the state store's writer, whose failed
  migration could hold a write lock other writers waited on, its short-lived
  read connections, and the gateway signing clock, which retries a failed open
  every second and leaked one connection per attempt.
- A state store write whose commit failed no longer stays pending on the
  shared writer connection, or on a skill hook's connection, for the next
  unrelated write to commit. Whatever a write did not commit is rolled back
  when it returns or raises.
- No gateway route on the event loop Tier D runs on waits for the replay
  store any more. An admission holds the replay cache's lock across its store
  transaction, which can wait out the store's busy timeout at its start and
  again at its commit.
  - The export, inbound evidence and outbound acknowledgement routes took
    that lock on the loop to authenticate. With a store, their replay work
    now runs on the cache's own replay thread, never on the loop or its
    default executor, which Tier A notices share.
  - Past 64 waiting checks, or once the cache has closed, new work is refused
    as `replay_store_busy`.
  - A reasoning round trip no longer holds a lock across an answer's record.
    When it ends it still waits for a record already in progress, so nothing
    is recorded after it ends, but neither the event loop nor any shared
    thread waits with it. A cancellation waits for that record and for the
    client's stop and disconnect before it propagates. Those two run as one
    call on a thread of their own, so even an event loop shutting down still
    disconnects the client.
  - A response refused below the replay floor is logged as such, not as a
    replay.
- The health socket compares a request's bytes exactly. A request is the
  bytes up to and including its first line feed, or up to the end of the
  stream; what follows the line feed is discarded, not judged, so a request
  is the same however the transport splits it. The socket answers
  `GET_HEALTH` and the empty request, each optionally ended by its line
  feed, and refuses everything else as `unsupported_request`. Before this,
  only the first read was judged, invalid UTF-8 was dropped and surrounding
  whitespace was stripped as Python defines it, which includes the
  separators `\x1c` to `\x1f`, NEL, NBSP and U+2028, so requests such as
  `GET_\xffHEALTH` were answered. A request longer than 1024 bytes is
  `request_too_large` however it arrives. A request not completed within 5
  seconds is refused as `unsupported_request` and its connection released,
  where an idle client could previously hold a connection open
  indefinitely; a bare `GET_HEALTH` sent with neither a line feed nor a
  half-close now waits for that bound and is refused. A client that hangs
  up before reading the answer no longer logs an unhandled-exception
  traceback. `ori-cli`, the CLI bridge and the Python SDK already send an
  accepted form and end it.
- The Tier C approval request no longer presents a firmware reading's receipt
  time as its measurement time. The device reports none, so the "Measured"
  line reads "not reported by device", followed by "polled no more than A
  ago, as of T" when this runtime can bound the reading's age. "Detected"
  remains the receipt time. The Tier C decision log's `reading_timestamp` is
  documented as the receipt time for a firmware reading.
- `scripts/refresh-evidence-vectors.sh` no longer reports a vector set's own
  glob as removed when it vendors that set for the first time.

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
- An MQTT-family sensor whose broker is unavailable when the runtime starts is
  no longer skipped until a restart. At start, a broker that cannot be
  reached, refuses the connection (bad credentials included) or a
  subscription, fails the TLS handshake, or gives no answer within the timeout
  is retried; anything else fails the connect. The retry uses the same
  back-off as after a drop, and a refused subscription is logged at every
  attempt with its topic and code. Until its first accepted reading the sensor reports
  `connected: false`, health is degraded, its reads are refused, and the
  registry or the operator is told at start, as for a sensor that failed to
  connect. When a notice was sent at start, the first accepted reading sends
  one more, saying the sensor is now read.
  An MQTT-family adapter's `health_check()` is true only while its broker
  link is up with every subscription granted and its listener alive, so it is
  false while the adapter retries, at start or after a drop. Closing an
  MQTT-family adapter while a connect attempt is in progress no longer leaves
  that attempt's connection open. The close waits up to 6 seconds for the
  connect threads it abandoned to settle, closing each socket on the event
  loop; a thread still running after that is logged. A socket such a thread
  opens is closed only where nothing its attempt queued on the event loop can
  still run: by the loop, or off it once the loop is closed. The thread never
  waits for that: a background thread owns the socket from then, and if the
  loop has neither run nor closed within 60 seconds it ends the broker
  connection, with a warning. The descriptor is closed when the loop resumes
  or closes; only an owner that does neither, for the life of the process,
  holds it. The 6 seconds bound only that settling: a close issued during the
  adapter's first connect first waits for that connect to return (#920).
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
- An MQTT-family sensor adapter no longer takes a subscription the broker
  refused as a subscription. A broker that refuses a subscription at
  SUBSCRIBE, as mosquitto's dynamic-security plugin does, keeps the
  connection up; the adapter read the link as up and reads said no data was
  cached yet, indefinitely. Such a refusal now keeps the link down, naming
  the topic and the broker's code. At start and on a reconnect alike, the
  refusal is logged at each attempt, reads stay refused, and the adapter
  keeps retrying under the same back-off; a sensor refused at start is
  reported unconnected until its first accepted reading. Mosquitto's
  `acl_file` grants the subscription and withholds delivery instead, which
  this check cannot see (#855).
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
- A health condition evaluated later no longer overwrites a more severe one.
  A lost decision record beside a commissioning problem or an active
  unprotected safety zone reported `degraded`; `status` is now the most severe
  condition that holds, whatever order they are evaluated in.
- The node heartbeat no longer publishes `healthy` for a health snapshot it
  cannot read. A snapshot whose `status` is not one the runtime produces, or
  whose `critical` is not a boolean agreeing with it, publishes `degraded`
  with no triggers, reasons or evidence taken from it. So does a value of
  the wrong type: nothing is rounded, parsed or read as truthy into a value
  gateway-api/v2 admits. A snapshot provider
  that raises, or a value the heartbeat cannot convert, does the same, and a
  publish that fails is logged and retried on the next interval; neither
  stops the heartbeat for the life of the process any longer. A local `critical`
  publishes `degraded`, which a lost decision record previously published as
  `healthy`, until a gateway claims the `gateway-api/v2` heartbeat rules.
- The node heartbeat no longer publishes a `last_seen_ms` the gateway must
  refuse. A wall clock at or before the epoch, or past 2^53-1 ms, used to be
  published as is, so the gateway dropped every heartbeat and the node went
  stale with nothing on the device saying why. Such a tick now publishes
  nothing, on the ordinary and the degraded path alike, and is neither
  clamped nor signed: a WARNING names the value, at most once a minute with
  the count since, and health reports `degraded` until a tick's clock is
  back in range (#922).

## Security

- Authenticated inbound input now binds exactly what was received. Before, a
  remote command's HMAC was computed over normalised fields: `command_id` and
  `device_id` were stripped of Unicode whitespace and `command` was stripped
  and upper-cased, so one tag verified many wire payloads (`ſet_threshold`
  read as `SET_THRESHOLD`). No authority was gained, but the signed command
  and the one received could differ. Now:
  - a remote command's `command_id` is 1 to 128 of `[A-Za-z0-9._-]`, its
    `command` an ASCII upper-case name compared case-sensitively,
    `issued_at_ms` a JSON integer and `args` an object (signed, as before, as
    canonical JSON); any other value is refused before verification. A
    producer that sent a lower-case `command`, a string timestamp or a null
    `args` must send the exact form;
  - inbound sender identities fold ASCII only, so a non-ASCII digit no longer
    survives into the identity used for allowlisting and lockout.
    `actions.operator_contact`, `actions.secondary_contact` and
    `security.remote_commands.allowed_senders` may still contain spaces of any
    kind, which are removed at load so every provider call receives the
    number the allowlist matches (an alert already queued with spaces in its
    recipient has them removed when it is sent), but one holding any other non-ASCII
    character now refuses the start;
  - the SMS webhook compares its token as bytes in constant time and refuses
    headers that are not UTF-8, a non-ASCII header name, whitespace before a
    colon, a folded header line, a repeated authentication or framing header,
    `Transfer-Encoding`, bytes past `Content-Length`, and a `Content-Length`
    that is empty or not ASCII digits. Its HMAC is verified over the timestamp
    and nonce text exactly as sent, so a signing bridge must send the text it
    signed; the timestamp is 1 to 16 ASCII digits and the nonce visible ASCII
    without spaces;
  - a Tier C approval reply is case-folded and trimmed in ASCII only, so a
    look-alike letter in its yes/no word or proposal id no longer reads as an
    approval. Every ASCII reply is classified as before; a reply that opens
    with non-ASCII whitespace, such as a non-breaking space, is now invalid,
    and SMS ingress keeps that character rather than trimming it away.

- A `skills` directory beside the installed `ori` package is no longer
  first-party. On a wheel install that directory is `site-packages/skills`,
  where any distribution can install files, and a skill there loaded with
  first-party provenance, Tier D triggers and hooks included. That root now
  counts only for a source checkout, decided from the runtime's own
  installation record rather than any file beside the package: a wheel whose
  RECORD lists the running module, judged by the file each entry names and
  not by its spelling, case or Unicode form, has no checkout, whatever other
  records say; an editable install counts only the directory it names; and an
  uninstalled tree must declare `ori-runtime` in its own `pyproject.toml`. The record is read once per process, so an
  installation changed in place takes effect at the next start. An installed
  runtime's packaged skills are under `share/ori-runtime/skills`.
- Whether a listed skill ships with the runtime is decided once, when its
  name resolves. A packaged directory replaced between resolution and load,
  by a symlink to other content for example, refuses the start, or keeps the
  running skills on a reload, instead of counting as a community skill that
  was not admitted and dropping its triggers.
- The gateway replay store no longer falls back to memory when it fails.
  Under gateway-api/v2 as amended, a store that cannot be read or written, at
  the start or later, refuses every gateway envelope that passes the freshness
  checks as `before_replay_floor`. It drops no key and writes no floor, and is
  tried again every 5 seconds off the receiving path until it answers. A
  floor raise the store cannot take keeps its key held, and a key it cannot
  store is refused. With `gateway.auth.persistent_replay_cache: false`, a floor
  an earlier run stored is read at the start and every 5 seconds, and never
  written. Before, a failed store degraded to memory protection that a
  restart forgets, and persistence off ignored the stored floor.
- Every gateway payload the runtime receives is admitted under gateway-api/v2's
  Payload Member Rule before any member is read or its envelope verified:
  gateway heartbeats, reasoning responses, export requests, outbound evidence
  acknowledgements and inbound evidence. `GatewayMessageEncryptor.decrypt`
  admits its plaintext under the same rule. A payload is refused, unanswered
  and changing nothing, when it:
  - is not valid UTF-8 (`invalid_unicode`), or holds a lone surrogate escape;
  - is not one JSON value (`malformed_json`), `NaN` and `Infinity` included;
  - nests deeper than 32 (`nesting_too_deep`);
  - carries anything after its value (`trailing_data`);
  - repeats a member (`duplicate_member`);
  - holds two names, or a name and a member the contract defines, that differ
    only in case or by the closed fold (`case_variant_member`);
  - is not an object (`not_an_object`).

  Before, the runtime kept the last of two repeated members, and accepted
  `NaN`, a byte order mark and members that differed only in case, so a gateway
  and the runtime could read one signed payload two ways. The inbound route's
  `unparseable` refusal is now one of these reasons. Each refusal is counted
  and logged with its reason through the family's ingress record, at most one
  line a second per reason. The scan is linear in the payload whatever its
  shape, and inbound evidence is scanned off the event loop.
  A decrypted export response also defines the health reading's member names,
  such as `status`, `critical` and `projection`, for the objects that are
  elements of its root `items` array, and only for those: a case variant of
  one there is refused as `case_variant_member`.
- Every runtime reader of signed, authenticated or operator-supplied JSON
  refuses a repeated member through one shared hook
  (`ori/utils/strict_json.py`): device-signed firmware telemetry, remote
  commands, the SMS webhook body, fetched and cached device policy, the
  shipped safety profile set, the evidence chain's signed envelopes, and
  operator-supplied manifest and evidence files, alongside the readers that
  already refused one. A guard over all of `ori/` requires the hook at every
  JSON decode, or an exemption that says why a repeat is harmless there.

- With `gateway.auth.enabled: true`, a gateway reasoning response whose
  envelope fails verification, or that replays one already received, is
  dropped and logged. The Tier 3 request goes on waiting for an authentic
  answer until `gateway.reasoning.timeout_ms`. Before, it ended the request as
  failed, so any broker client that knew a request ID could force the runtime
  off gateway reasoning (gateway-api/v2 Reasoning Auth Envelope: verification
  precedes every side effect). Dropped responses are logged once per kind
  when the first arrives, and summed when the request ends.
- Gateway-facing receivers log a refused message at most once a minute per
  reason, with the count since the last line: unverified gateway heartbeats,
  unauthenticated export requests, refused outbound evidence
  acknowledgements and inbound transport refusals. Before, each wrote one
  warning per message, so anything that could publish on a topic could fill
  the log at that topic's ingress rate.
- Inbound SMS approval replies are bounded at the runtime, whatever the bridge
  in front of it does (`docs/SMS_WEBHOOK_SECURITY.md`).
  - **Allowlist:** with neither `actions.operator_contact` nor
    `actions.secondary_contact` set, no reply is accepted from anyone. Before,
    an empty allowlist admitted every sender, and their replies were stored
    and never read, so a flood filled the store. An unlisted sender's plain
    reply is refused before it is stored. A command-shaped message still goes
    through remote-command verification first, as before, under that policy's
    own throttle: it records the attempt, may send the sender a rejection SMS,
    and past the rejection limit records an incident and alerts the operator.
  - **Rate:** each configured number may leave 10 replies a minute, and all of
    them together 30. A refused sender spends none of that. Before, one limit
    of 20 requests a minute per peer address was shared by every sender
    through the bridge's one address. That limit is now 600 a minute, a CPU
    backstop only. A flood from many senders through one bridge can still
    reach it and refuse the operator's reply, until the bridge limits senders
    (ori-gateway#138).
  - **Storage:** a reply over 480 characters is refused. Each number keeps
    its 16 newest unread replies. Replies older than the longest approval
    window plus ten minutes are removed.
  - **Hardened posture:** staging, production, or
    `security.enforce_production_posture: true`, with SMS or WhatsApp enabled,
    refuses to start unless `operator_contact` is a phone number. Before, it
    only warned, and every Tier C proposal fell to its safe default with no
    operator asked.
  - **Refusal counts** are logged by reason, at most one line a minute per
    reason. runtime-health names no field for them yet.
- An SMS webhook nonce is kept until the request's signing time plus
  `max_skew_seconds`, not only for `replay_ttl_seconds` from receipt. Before,
  a request signed ahead of the receiver's clock could be replayed after its
  nonce expired. Both settings are now capped at 2^53 ms.

- Every gateway-to-runtime MQTT family is bounded before anything is
  parsed, decoded or verified (`gateway-api/v2` Payload Size and Payload
  Volume). A payload over its topic's maximum is refused and changes no
  state; past a runtime-owned rate per family, a message is dropped unread.
  Before, 200 authenticated export requests in a burst made the runtime read
  2,000,000 history rows. An oversized inbound evidence message is released
  at the broker so it is not redelivered without end, and one past the rate
  is left with the broker for redelivery. Refusals are logged by topic
  family, reason and size class, never by contents or device, and counted in
  health's `mqtt_ingress`. As a producer, the runtime never
  publishes a reasoning request over its maximum, fits each export page and
  runtime heartbeat to its topic's maximum (ending an export with
  `item_exceeds_payload_maximum` where one item cannot fit alone), and lists
  at most 64 `active_triggers`.
- The gateway export responder answers at most four requests at once; past
  that, a request is dropped unread and counted. An outbound evidence
  acknowledgement for an envelope the runtime sealed but never handed to the
  broker is refused, where before it was applied: the runtime now records an
  envelope's handoff before publishing it, so an answer that overtakes the
  publish still applies. An acknowledgement that answers nothing this device
  sent no longer records a
  replay key, nor does an inbound evidence message refused before ingest.
- A gateway replay key is now kept for `gateway.auth.replay_ttl_ms` from
  receipt, as before, and also until its envelope turns stale (one
  millisecond past its signing time plus `gateway.auth.max_clock_skew_ms`),
  whichever is later. Before, at the default of 300000, an envelope a gateway
  signed with its clock running ahead could be replayed after its key
  expired. Keys a previous release stored are extended the same way when this
  release loads them, never shortened.
- Gateway envelopes are checked in gateway-api/v2's order: the signature and
  topic-device check first, then freshness, then the replay floor, then held
  keys. Before, freshness came first. A dropped or evicted key raises a replay
  floor past its signing time, stored with the held keys; each start takes
  the greater of the stored floor and its own clock. An envelope signed below
  the floor is refused as `before_replay_floor`, so a raised skew, a clock
  stepped back, or a restart no longer reopens keys already dropped. Expect a
  `before_replay_floor` refusal for an envelope in flight across a runtime
  start, and for a gateway whose clock runs behind the runtime's, for that
  lag after each start; a warning names the floor and the clock on each
  such refusal. No secret rotation lowers the floor
  or drops a held key, so a secret brought back readmits nothing it signed; a
  floor ahead of the clock clears as the clock passes it. `gateway.auth.max_clock_skew_ms` is bounded at 2^53, as the cache
  always was, so an envelope signed beyond that is refused as future.
- `database.path: ":memory:"` is no durable store for gateway signing: a
  staging or production configuration with `gateway.auth.enabled` and an
  in-memory database is refused at start; a development one runs with a
  warning that signing times can repeat across a restart.
- The runtime signs every gateway envelope (node heartbeat, reasoning
  requests, export responses, inbound acknowledgements) from one signing
  clock that never repeats a `signed_at_ms`, across a restart too. It claims
  values ahead in the state database, off the signing path: a tenth of
  `gateway.auth.max_clock_skew_ms`, between one and thirty seconds and never
  more than half the skew. No signing time is issued more than a reservation
  ahead of the wall clock as it reads at that moment, so every one passes a
  receiver under the same skew. Restarts faster than the clock moves, or a
  clock stepped back, live or across a start, refuse signing until the wall
  clock catches up. A skew below twenty seconds shrinks the reservation, and
  the database sees a claim more often: about every 250 ms at a 1000 ms skew. While nothing signs, the database
  sees one claim per reservation (about every thirty seconds at the default
  skew); a database that fails is retried once a second. It signs only within
  what it has claimed; while the database stalls past that, it refuses to
  sign, logs a warning, and health reads degraded.
- The runtime keeps one gateway replay cache, shared by every gateway route.
  With a state database, it owns the database's replay tables alone, through
  an exclusive lock named by the database file's device and inode
  (`.ori-gateway-replay-<device>-<inode>.lock`, in the database's directory).
  A second cache, in this process or another, through any name for that file
  (the same path, a symlink, a case variant, a second mount of the directory)
  is refused at construction rather than sharing them; a hard-linked database
  is refused outright, and a lock that cannot be taken refuses the cache
  rather than running it alone. Replacing the lock file, or the database
  itself, while a runtime holds it needs write access to the state directory,
  which already reaches the store; neither is guarded beyond that. Each admission is one transaction against the store, and when the
  store cannot be written the cache decides from its own memory, which as sole
  owner is the whole history.
  It holds every message the gateway families can admit in the longer of
  `replay_ttl_ms` and twice the skew, up to 131072 entries (tens of
  megabytes).
  Before, each route held its own, each at most 4096, and a full cache
  refused an authentic message as a replay; at the default window the
  admitted rates exceed 4096. A window of about 51 minutes or longer, from
  either setting, still reaches the ceiling at full gateway rates; a full
  cache then evicts the key with the smallest signing time and raises the
  replay floor past it, so senders whose clocks run behind that envelope are
  refused until their clocks pass it. Expired keys are pruned in expiry
  order and, when persisted, deleted by key rather than by a scan. The
  evidence ledger finds an acknowledged envelope by index.
- The gateway export responder no longer answers a request whose envelope
  fails verification. Before, with `gateway.auth.enabled: true`, it published
  a signed `auth_failed` error on the response topic the request named, so
  anything on the site network could have the runtime sign replies for it.
  The inbound evidence route already refused such a message silently.
- An inbound evidence message the evidence worker is too busy to take is
  left undecided, as a store fault is: it is released at the broker with no
  acknowledgement, and its replay key stays recorded, since receivers do not
  relax replay protection to accommodate redelivery (`gateway-api/v2`). The
  courier redelivers it in a newly signed envelope, which is admitted. Before,
  it was left with the broker, whose redelivery of the identical bytes replay
  protection refused.
- A persisted gateway replay key is written to SQLite on a worker thread,
  and awaited before the message is acted on, on the inbound evidence route,
  outbound acknowledgements and export requests. Before, each authenticated
  message cost one SQLite commit on the event loop. A recorded key is never
  unrecorded: a route cancelled once its key is written, as every route is at
  shutdown, leaves it recorded, and the courier's newly signed redelivery is
  admitted.
- `gateway.reasoning.timeout_ms` is kept to a day at most, and a
  `gateway.node_heartbeat.interval_seconds` that is not finite means the
  default, also capped at a day, so every value the configuration admits
  schedules a wait the runtime can run.

- No validating pattern in the runtime accepts a trailing newline. A pattern
  ending in `$` also matches before a final newline, so thirteen validators
  that used `match` accepted one, among them the firmware liveness and
  command builders, which could then sign a raw control character into JSON
  bytes, and the evidence, commissioning and Tier C admission digest checks.
  Every pattern now ends in `\Z`, and a test refuses a new one ending in `$`.

- The three RFC 8032 section 7.1 test keys, and the signer key of the
  `ed25519-verification/v1` corpus, are refused as trust anchors and as
  signing seeds, with the other keys whose private seeds this repository
  publishes. Their seeds are vendored in the verification corpus, so anyone
  can sign under them.
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
