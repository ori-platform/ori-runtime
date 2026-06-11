# Ori Runtime Design Decisions

This file records security- and architecture-relevant decisions that future
contributors must preserve unless a superseding decision is explicitly added.

## 2026-06-01 — Runtime Exposes Data, Gateway Owns Cloud (AI) SDKs

**Status:** Accepted

Cloud SDKs like Gemini belong in the gateway and product layer, not in the
safety-critical runtime.

Rules:

- The runtime must not depend on cloud SDKs.
- `ori.yaml.example` must not contain cloud API configuration.
- Gateway/product services own cloud API keys, weekly report
  generation, and Tier C proposal enrichment.
- Runtime responsibility is to expose bounded, provider-neutral export
  primitives: Tier C decision log, action log, reasoning log, sensor history,
  and health status.
- Gateway export transport uses MQTT request/response on
  `ori/{device_id}/export/request` and
  `ori/{device_id}/export/response/{request_id}`. HTTP export endpoints are not
  part of the runtime boundary.
- Export methods must be bounded by time/window and/or `limit` so product-layer
  sync cannot accidentally dump unbounded SQLite state.
- Reasoning-log exports must include structured `reasoning_status` and
  `correlation_id` fields so gateway/cloud sync can join Tier B action results
  with post-action reasoning enrichment without reading SQLite directly.
- Bulk exports must support pagination. Sensor-history exports may use
  `bucket_ms` aggregation so weekly report generation does not require raw
  per-reading transfer.

Rationale:

- Weekly reports and Tier C decision enrichment via cloud AI are
  customer-visible, auditable, and naturally network-dependent.
- Keeping cloud SDKs out of runtime preserves offline-first operation and avoids
  coupling physical safety paths to a cloud provider.
- MQTT keeps gateway integration aligned with the existing LAN broker
  architecture and remains viable when one gateway aggregates multiple edge
  runtimes.

---

## 2026-06-05 — Cloud Reasoning Is a Gateway Backend

**Status:** Accepted

The runtime Intelligence Elevator has three reasoning tiers: rule engine, local
SLM, and gateway reasoning. Cloud reasoning is not a runtime-owned tier.

Rules:

- Runtime reasoning tiers are `rule`, `local_slm`, and `gateway`.
- Skill triggers must not declare `escalate_to: cloud`; they use
  `escalate_to: gateway` when higher reasoning is required.
- The gateway decides whether a gateway reasoning request is answered by a LAN
  model, a cloud provider, or a hybrid provider router.
- The runtime must not depend on cloud provider SDKs by default.
- If direct runtime cloud reasoning is ever needed for a special deployment, it
  must be exposed as an explicit optional extra, not as a default dependency.

Rationale:

- The runtime only sends MQTT reasoning requests and receives provider-neutral
  structured responses. It does not need to know whether the gateway used
  Claude, Gemini, OpenAI, llama.cpp, or another backend.
- Removing runtime-owned cloud reasoning keeps the edge node offline-first,
  provider-neutral, and smaller for Pi and phone deployments.
- Safety properties remain local: Tier D is rule-only, Tier C is
  approval-gated, and gateway availability affects explanation quality, not
  safety authority.

---

## 2026-06-06 — Runtime-Gateway MQTT Envelopes Are Authenticated

**Status:** Accepted

Runtime-gateway MQTT messages must support payload-level HMAC authentication
with timestamp skew checks and short-lived replay protection. Broker ACLs and
TLS remain important deployment hardening, but message authenticity is enforced
at the JSON envelope layer so a misconfigured broker or leaked MQTT credential
does not automatically grant message-forgery authority.

Rules:

- Authenticated deployments configure `gateway.auth.enabled: true` and store only
  the env-var name in `ori.yaml`; the shared secret value lives in the runtime
  environment.
- The gateway MQTT shared secret is separate from remote-command secrets. A
  compromise of SMS/WhatsApp command auth must not compromise site-local gateway
  traffic, and vice versa.
- Runtime reasoning requests, gateway reasoning responses, gateway export
  requests, and runtime export responses use an `auth` envelope containing
  `scheme`, `signed_at_ms`, and `signature`.
- MQTT gateway heartbeat authentication uses `GatewayMessageAuthenticator.verify_broadcast`
  when `gateway.auth.enabled: true` (the production recommendation). The
  heartbeat payload carries no `device_id` and uses a LAN-broadcast topic;
  `verify_broadcast` omits device binding but retains HMAC, timestamp skew, and
  replay-TTL protection. When `gateway.auth.enabled: false` (a convenience
  default for initial LAN setup only), unsigned heartbeats are accepted; the
  security guarantee is then conditional on correct broker ACL configuration.
  See the 2026-06-10 entry for the full authentication and routing rationale.
- Replay protection for gateway MQTT messages is in-memory and TTL-bounded.
  Remote commands remain durably audited in SQLite because they are rare and
  state-mutating; gateway messages are short-lived and higher frequency.
- MQTT messages remain read-only for runtime export paths and provider-neutral
  for reasoning paths. They must never mutate runtime config, policy, update
  intent, relay state, or actuator settings outside the separate authenticated
  remote-command path.

Rationale:

- HMAC protects the message even when transport security or broker ACLs are
  imperfect.
- Timestamp and replay checks reduce spoofing and repeated-message risk without
  adding SQLite write pressure to the reasoning/export hot path.
- Verifying gateway-bound requests before provider invocation prevents
  cost-amplification attacks against cloud-backed gateway reasoning.

---

## 2026-06-06 — Runtime-Gateway MQTT TLS Is Transport Defense-in-Depth

**Status:** Accepted

Runtime-gateway MQTT clients support TLS via `mqtts://` broker URLs and the
`gateway.tls` config block. TLS protects transport confidentiality on the site
LAN, but it does not replace broker ACLs or HMAC envelope authentication.

Rules:

- `mqtts://` defaults to port `8883`; `mqtt://` and `tcp://` default to `1883`.
- TLS certificate paths may be configured under `gateway.tls`.
- Private-key passwords are read from the environment variable named by
  `gateway.tls.keyfile_password_env`; the password value itself must not appear
  in `ori.yaml`.
- The runtime does not expose an `insecure_skip_verify` production config flag
  for gateway transport.

Rationale:

- TLS prevents passive LAN sniffing of gateway reasoning/export traffic.
- HMAC remains the message authenticity and replay boundary.
- Avoiding an insecure verification toggle prevents accidental permanent test
  settings on safety-critical deployments.

---

## 2026-06-04 — Local SLM Confidence Is Non-Authoritative

**Status:** Accepted

The local SLM does not provide a trustworthy confidence signal. Base completion
models do not expose calibrated epistemic uncertainty, and the runtime must not
depend on model honesty for safety or escalation decisions.

Rules:

- Local SLM confidence may be used only as an advisory telemetry signal.
- Gateway escalation is governed by deterministic escalation policy, not by
  model-reported confidence.
- Deterministic escalation signals are evaluated before local SLM inference.
- Signals include: matched trigger declares `escalate_to: gateway`, no baseline
  is available, sensor history query fails, a reading is outside calibrated
  sensor range, or related sensor readings conflict beyond configured
  tolerance.
- For matched triggers, action tier remains trigger-authoritative. The model
  cannot escalate its own physical action authority beyond the tier declared in
  skill YAML.
- If gateway reasoning is invoked when no deterministic trigger matched, the
  gateway response may supply an action tier, but Tier C still requires the
  approval workflow and Tier D remains unreachable through LLM reasoning. Skills
  must not rely on unmatched gateway reasoning for autonomous physical actions.
- Tier D bypasses LLM entirely.
- Gateway escalation uses MQTT request/response on
  `ori/{device_id}/reasoning/request` and
  `ori/{device_id}/reasoning/response`. Non-explicit deterministic signals may
  fall back to local reasoning when gateway transport is unavailable; triggers
  that explicitly declare `escalate_to: gateway` return a gateway-unavailable
  stub instead of silently downgrading to local SLM.
- `gateway.reasoning.timeout_ms` is a per-phase MQTT timeout: one budget for
  connect/subscribe readiness and one budget for the correlated response after
  publish. The worst-case elapsed time may therefore approach 2x the configured
  value.

Rationale:

- Safety properties must not depend on model self-assessment.
- Observable runtime conditions are better escalation inputs than generated
  confidence values.
- Evaluating deterministic escalation before local inference avoids wasting
  edge resources on inputs already known to need gateway reasoning.

---

## 2026-06-04 — Tier B Post-Action Reasoning Policy

**Status:** Accepted

Tier B soft-physical actions are deterministic actions with physical
consequences. They must not wait on local SLM explanation generation unless a
skill author explicitly chooses an approval workflow.

Rules:

- `bypass_llm: true` remains exclusively reserved for Tier D safety-critical
  triggers.
- Physical Tier B triggers must declare either `requires_approval: true` or
  `reasoning_policy: post_action`.
- `reasoning_policy: post_action` is valid only for Tier B triggers.
- With `post_action`, the runtime dispatches deterministic Tier B default
  actions before invoking local or gateway reasoning.
- `post_action` Tier B triggers must include at least one Tier A default action
  so the runtime has a declared operator follow-up path for successful or
  incomplete explanations.
- Post-action reasoning enriches operator text and audit logs only. It must not
  alter, retry, roll back, or obscure the already-recorded action result.
- If post-action reasoning fails, times out, or no reasoner is available, the
  reasoning audit record must contain `reasoning_status: incomplete` and the
  operator-facing fallback is "Action executed. Explanation unavailable."
- If the Tier B physical action fails, post-action reasoning is skipped, the
  action failure remains in `action_log`, and the reasoning audit record
  contains `reasoning_status: skipped`.
- Tier C and Tier D behavior is unchanged.

Rationale:

- Tier B physical response latency should not depend on LLM latency or model
  availability.
- Tier B needs explicit semantics separate from Tier D's safety bypass.
- Audit records must distinguish "action executed but explanation incomplete"
  from a missing enrichment record.

Cloud sync contract:

- Tier B `action_log` and `reasoning_log` records generated from the same
  event carry the same `correlation_id`. Gateway and ori-cloud sync must use
  this structured ID rather than timestamp proximity matching when joining
  action execution and reasoning enrichment records.

---

## 2026-06-01 — Approval Replies Are Not Remote Commands

**Status:** Accepted

Inbound text channels carry two different kinds of operator input: Tier C
approval replies and authenticated remote runtime commands. These must stay
separate because approval replies answer an already-created proposal, while
remote commands attempt to mutate runtime state.

Rules:

- Plain approval replies such as `YES`, `NO`, and equivalent approval tokens
  may remain unauthenticated because they are scoped to the pending Tier C
  proposal.
- Tier C approval messages must include a short `proposal_id`. Scoped replies
  such as `YES-AB12CD34` and `NO-AB12CD34` are valid only when the suffix
  matches the active proposal. Bare `YES`/`NO` remains accepted for the active
  pending proposal for operator usability.
- Offline local-console `TOKEN:<value>` approvals remain allowed, but must pass
  the offline token verifier before approving Tier C.
- Structured remote command payloads (`ORI_COMMAND {json}` or raw JSON objects
  containing the remote-command field set) must never be stored or returned as
  approval replies.
- SMS and WhatsApp ingress must route structured commands through
  `RemoteCommandVerifier` and `remote_command_policy` before any runtime side
  effect.
- The local-console approval channel is not a remote command ingress. Structured
  commands found there must be consumed, durably audited, and ignored for
  approval purposes.
- Local-console approval input is strict: `YES`, `NO`, scoped `YES-<proposal_id>`,
  scoped `NO-<proposal_id>`, and `TOKEN:<value>` are the only valid forms.
  Unrecognised input must be logged and ignored until the proposal times out.

Rationale:

- A command payload must not be able to masquerade as an approval reply and
  accidentally approve a Tier C physical action.
- Proposal IDs reduce the chance that delayed replies intended for one Tier C
  proposal affect another proposal.
- Keeping local-console approval narrow preserves the offline recovery path
  without creating a second unauthenticated command channel.
- The boundary supports Ori Energy and Ori Guard deployments where SMS,
  WhatsApp, and local fallback may all be active under degraded connectivity.

---

## 2026-06-01 — Tier C Decisions Must Carry Dataset-Ready Context

**Status:** Accepted

Tier C approval records are a safety audit trail and a future supervised
learning dataset. The runtime must therefore populate them from the real
reasoning and approval flow, not only from direct dispatcher tests.

Rules:

- Elevator dispatch must attach a bounded recent `history_window` to event
  context before Tier C approval logging.
- Runtime sensor events must carry device `site_type`, `location`, and
  `device_timezone` context.
- `ActionDispatcher` remains responsible for writing the Tier C decision row,
  including skill name, trigger name, proposed action, confidence, operator
  decision, latency, safe-default usage, and final action result.
- Tier C export queries must be bounded by `limit` and support optional
  `device_id`, `since_ms`, and `until_ms` filters for future cloud sync.

Rationale:

- Ori Energy and Ori Guard need evidence-quality records of operator decisions,
  not just action outcomes.
- Capturing history and site context at runtime avoids fragile reconstruction
  later in the product layer.
- A bounded export primitive prepares cloud/reporting sync without giving the
  product layer direct database access.

---

## 2026-06-01 — Remote Commands Are Bound To Approved Senders

**Status:** Accepted

Remote command authentication requires both a valid command signature and an
approved ingress sender identity. A leaked HMAC secret must not be sufficient to
execute runtime commands from an arbitrary phone number or WhatsApp sender.

Rules:

- `security.remote_commands.allowed_senders` defines approved senders by channel.
- SMS sender identities are normalized to digits and `+`.
- WhatsApp sender identities are lowercased and whitespace-stripped.
- When remote commands are enabled and `allow_unlisted_senders=false`, commands
  from senders outside the channel allowlist must be rejected and audited as
  `sender_not_allowed`.
- Missing allowlists fail closed at verification time. Operators may explicitly
  set `allow_unlisted_senders=true` only for test deployments.
- Sender identity comes from ingress metadata, not from the signed payload body.
- The sender allowlist check fires AFTER HMAC verification, not before. Only a
  caller who already holds the valid shared secret can learn their sender is not
  on the allowlist. Callers without the secret receive a signature-related
  rejection regardless of allowlist status, preventing sender enumeration.

Rationale:

- HMAC verifies command authorship but not operator-channel legitimacy.
- Binding signatures to ingress sender identity limits blast radius if a shared
  secret leaks.
- Fail-closed sender binding is safer for physical actuation commands than
  silently accepting signed commands from unknown phones.

---

## 2026-06-01 — Remote Command Dry Run Is Verified And Audited

**Status:** Accepted

Authenticated executable remote commands may request `args.dry_run=true` to test
operator tooling and runtime preconditions without mutating runtime state. Dry
run is an execution mode, not a verifier bypass.

Rules:

- Dry-run commands must pass the same HMAC verification, timestamp validation,
  replay protection, and attempt audit as normal commands.
- Dry-run execution is allowed only after the command is classified executable
  and command-specific preconditions pass.
- Dry-run execution must not fetch/apply DevicePolicy bundles, refresh remote
  policy, mutate skill config, or write any action-state side effect beyond the
  normal execution audit row.
- Execution audit rows use status `dry_run` and `executed=false`.
- Operator feedback must explicitly say `DRY RUN`.
- Audit-only and unsupported commands do not become executable through dry run.

Rationale:

- Operators need a safe way to test command signing, routing, and runtime
  readiness before sending state-changing maintenance commands.
- Keeping dry run behind the full verifier preserves replay and audit
  guarantees.
- Logging dry run as its own status makes it distinguishable from failed,
  unsupported, and executed commands during incident review.

---

## 2026-06-01 — Remote Command Lockout Tuning Is Configurable, Enforcement Is Not

**Status:** Accepted

Operators may tune advisory remote command lockout risk windows and thresholds
through `security.remote_commands.lockout`, but remote command lockout remains
diagnostic-only. The config exists to adapt health-snapshot sensitivity across
deployment environments without prematurely introducing command blocking.

Rules:

- `security.remote_commands.lockout.risk_window_ms` controls the rejection and
  incident lookback window used for sender risk calculation.
- `state_stale_after_ms` controls when cached sender risk is labelled stale in
  health snapshots.
- `incident_sender_limit` bounds how many recent incident senders are rebuilt
  into runtime health state at startup.
- Incident and rejection thresholds may be tuned, but critical thresholds must
  not be lower than their corresponding elevated thresholds.
- `enforcement_enabled` is accepted only as an explicit no-op. Runtime health
  must report `remote_command_lockout.enforcement_enabled=false` regardless of
  YAML until a future recovery-safe enforcement decision exists.
- Invalid lockout config must fail config validation rather than silently using
  unsafe values.

Rationale:

- Different deployments may need different advisory sensitivity, especially
  when SMS delivery quality or operator phone number rotation varies.
- Tuning diagnostic thresholds does not carry the same safety risk as active
  lockout.
- Keeping enforcement hard-disabled prevents a config-only change from blocking
  the only available recovery channel.

---

## 2026-06-01 — Remote Command Lockout Health Rebuilds From Persisted Incidents

**Status:** Accepted

Advisory remote command lockout state is cached in memory for health snapshots,
but the source of truth for abuse history is the persisted
`remote_command_security_incident_log`. On runtime startup, recent persisted
incident senders must be reloaded and re-evaluated so diagnostics survive
process restarts.

Rules:

- Runtime startup rebuilds `_remote_command_lockout_states` after `StateStore`
  opens and before health snapshots are served.
- Only recent incident senders within the advisory lockout risk window are
  reloaded.
- Rebuilt states remain advisory. Enforcement stays disabled.
- Rebuild failures must not prevent runtime startup.
- Health freshness metadata still applies to rebuilt sender states.

Rationale:

- Losing advisory abuse state on restart makes diagnostics misleading after a
  crash, power loss, or operator-initiated restart.
- The persisted incident log already contains the sender identities needed to
  rebuild risk without scanning every remote command attempt.
- Keeping the rebuild bounded to recent incidents avoids unbounded health
  snapshot growth.

---

## 2026-06-01 — Remote Command Lockout Health State Can Be Stale

**Status:** Accepted

Advisory remote command lockout state is updated when abuse incidents fire, not
on every inbound command. Health snapshots must therefore label sender risk
entries as fresh or stale instead of implying that a cached state is current
forever.

Rules:

- Runtime health snapshots include `remote_command_lockout.stale_after_ms`.
- Each sender entry includes `stale`.
- Stale sender entries remain visible for diagnostics.
- Stale advisory risk must not be used for enforcement.
- Enforcement remains disabled until a future recovery-safe lockout decision
  defines active re-evaluation, expiry, and recovery behavior.

Rationale:

- Re-evaluating lockout risk on every command would add database work to the
  common path before enforcement exists.
- Keeping stale entries visible helps operators understand recent abuse history.
- Explicit freshness metadata prevents health consumers from treating cached
  advisory risk as a live enforcement signal.

---

## 2026-06-01 — Remote Command Lockout Is Advisory Until Recovery Is Designed

**Status:** Accepted

Remote command abuse incidents now feed a sender risk calculation, but the
runtime must not enforce command lockout yet. The runtime exposes risk levels so
operators and local diagnostics can see when a sender is dangerous, while valid
signed commands remain usable for recovery and maintenance.

Rules:

- Sender lockout risk is calculated from recent rejected command volume and
  recent `remote_command_security_incident_log` entries.
- Risk levels are `normal`, `elevated`, and `critical`.
- `critical` risk does not currently block authenticated commands.
- `remote_command_lockout.enforcement_enabled` must remain `false` until a
  future decision defines recovery commands, expiry behavior, operator override,
  and safe handling when the locked sender is the only available operator path.
- Runtime health snapshots must expose the current advisory sender risk state.
- Any future enforcement must preserve Tier D safety and must not prevent
  authenticated recovery commands from restoring safe operation.

Rationale:

- Locking out the only reachable operator channel can turn an abuse response into
  an availability or safety failure.
- Visibility can ship before enforcement. Operators get diagnostic signal now
  without losing remote recovery access.
- Enforcement needs a separate safety review because remote commands can update
  policies and thresholds that may be required to restore safe behavior.

---

## 2026-06-01 — Remote Command Abuse Incidents Escalate Separately From Throttling

**Status:** Accepted

Remote command rejection-feedback throttling is an abuse signal, not only a
transport concern. When the threshold is crossed for a sender/window, the runtime
must record a durable security incident and, when runtime alerting is available,
emit a Tier A operator alert.

Rules:

- `remote_command_log` remains the complete per-attempt audit trail.
- `remote_command_security_incident_log` records first suppression per
  `channel`/`from_number`/time-window bucket. Duplicate suppressed attempts in
  the same bucket must not create duplicate incidents.
- Incident logging is best-effort and must not block command verification,
  attempt audit, accepted command execution, or Tier C approval replies.
- Incident escalation must not lock out valid signed commands. Lockout policy is
  a separate future decision with a higher safety bar.
- Runtime operator alerting is Tier A. It warns the operator that remote command
  feedback was throttled because repeated rejected commands were detected.
- If runtime alerting is unavailable, the durable incident log is still the
  authoritative escalation record.

Rationale:

- Repeated rejected remote commands may indicate operator misconfiguration,
  credential probing, or active abuse.
- Separating per-attempt logs from incident logs avoids alert fatigue while
  preserving forensic detail.
- Valid signed commands must remain possible during an incident unless a future
  lockout policy explicitly defines safe recovery behavior.

---

## 2026-06-01 — Remote Command Rejection Feedback Is Throttled

**Status:** Accepted

Remote command ingress must continue auditing every accepted and rejected command
attempt, but SMS and WhatsApp should suppress repeated generic rejection replies
from the same sender once the sender crosses the abuse threshold.

Rules:

- Audit remains authoritative. Every structured remote command attempt is logged
  to `remote_command_log`, including rejected attempts.
- Sender identity is part of the audit key: `channel` plus `from_number`.
- Generic rejection feedback is sent for the first 5 rejected remote commands
  from the same `channel`/`from_number` within 10 minutes.
- Once the threshold is crossed, additional generic rejection feedback is
  suppressed for that sender/window while audit logging continues.
- Accepted commands, execution feedback, and plain Tier C approval replies
  (`YES`/`NO`) are not throttled by this rejection-feedback guard.
- Throttle lookup failures fail open for feedback only. They must not prevent
  verification, audit logging, or command execution policy evaluation.

Rationale:

- Rejected remote commands can otherwise become an SMS/WhatsApp spam vector or a
  low-grade verifier oracle.
- The operator still receives initial rejection feedback for honest mistakes.
- The audit trail remains complete for incident review and future lockout policy.

---

## 2026-06-01 — Remote Command Execution Feedback Is Best-Effort

**Status:** Accepted

After an authenticated remote command is handed to the runtime execution policy,
SMS and WhatsApp ingress should send a concise operator-facing response that
states whether the command executed, failed preconditions, failed execution,
is unsupported, or remains audit-only.

Rules:

- Execution/audit state is authoritative in `remote_command_execution_log`.
- Feedback delivery is best-effort and must not change the command execution
  result.
- Authentication failures receive only a generic rejection response. Channel
  responses must not reveal exact verifier reasons such as `missing_signature`,
  `invalid_signature`, or `replay_detected`.
- Plain Tier C approval replies (`YES`/`NO`) must remain unaffected.
- Response messages must be short enough for SMS transport and safe for
  WhatsApp reuse.

Rationale:

- Operators need closure for state-changing remote commands.
- A failed notification must not cause a successfully executed command to be
  marked failed.
- Generic rejection responses avoid giving attackers an oracle for verifier
  internals.

---

## 2026-05-31 — SET_THRESHOLD Remote Command Handler Spec

**Status:** Accepted

`SET_THRESHOLD` allows an authenticated operator to adjust a numeric skill
configuration key at runtime without restarting the device. The change takes
effect on the next rule evaluation for that skill.

**Command args:**

- `skill_name` (string, required): name of the skill that owns the key
  (e.g. `"energy-anomaly-detector"`).
- `threshold_key` (string, required): the config key to modify (e.g.
  `"dangerous_overcurrent_threshold"`). The key must already exist in the skill's
  config at startup; new keys may not be created remotely.
- `value` (number, required): new numeric value. Must be a positive, finite number.

**Tier D key identification:**
Any skill config key whose name appears as a bare variable reference in a Tier D
trigger condition (`action_tier: D`) is a Tier D threshold key. Detection uses
AST Name-node extraction on the condition string. Example: the condition
`"value > dangerous_overcurrent_threshold"` makes `dangerous_overcurrent_threshold`
a Tier D key.

**Tier D startup-sensitivity invariant (AGENTS.md §13):**
For Tier D threshold keys, the new value must not make the Tier D trigger less
sensitive than the value present in the skill config when the skill was first
loaded at runtime startup. The startup value is captured once at first skill load
and is immutable thereafter. This guard applies regardless of whether a Tier D
condition is currently active.

Examples:

- `value > dangerous_overcurrent_threshold`: the remote value must not be higher
  than startup.
- `value < low_voltage_threshold`: the remote value must not be lower than
  startup.
- Complex Tier D expressions whose sensitivity direction cannot be proven are
  rejected for remote changes. Those changes require local config or a signed
  maintenance workflow.

**Active suppression invariant (AGENTS.md §13):**
If the new value is greater than the current runtime value (raising the threshold)
and any recent sensor reading associated with the skill falls in the range
`(current_value, new_value]`, the change would suppress an active or borderline
Tier D condition and must be rejected. The check uses the most recent reading from
each sensor whose type matches the skill's `sensors_required`.

**Non-Tier-D keys:**
Keys that do not appear in any Tier D trigger condition may be changed to any
positive finite number. No Tier D startup-sensitivity guard and no active
suppression check apply.

**Atomicity:**
The change is applied in-place to the `Skill.config` dict in memory. There is no
on-disk write and no config file reload. The startup-captured values remain
unchanged as the Tier D startup-safety baseline.

**Precondition rejections (all logged and audited):**

- runtime config or loaded skills unavailable
- `skill_name` not found in loaded skills
- `threshold_key` not present in skill config
- `value` is not a positive finite number
- value would make a Tier D key less sensitive than startup config
- the runtime cannot prove a Tier D key's safe sensitivity direction
- change would suppress an active or borderline Tier D condition

---

## 2026-05-31 — Remote APPLY_POLICY Uses Fetch-Then-Verify

**Status:** Accepted

Remote `APPLY_POLICY` must not carry an inline DevicePolicy bundle as the command
payload. The remote command may carry only a reference to the policy bundle, such
as a fetch URL and expected content hash. The runtime must fetch the bundle,
verify that the fetched bytes match the expected hash, and then pass the bundle
through the existing signed DevicePolicy verification chain before applying it.

Rationale:

- SMS payload size limits make inline policy delivery impractical for real
  DevicePolicy bundles.
- Remote command channels should remain authenticated triggers, not privileged
  data carriers.
- Fetch-then-verify reuses the existing policy path: HTTPS transport, device
  authentication, Ed25519 signature verification, timestamp skew checks, and
  monotonic policy-version protection.
- Inline policy application would create a second policy injection surface and
  increase the chance of bypassing existing verification invariants.

Implementation:

- `APPLY_POLICY` may execute only when the authenticated command supplies
  `args.url` and `args.sha256`.
- The URL must use HTTPS.
- The fetched bytes must match the supplied SHA-256 digest before JSON parsing.
- The decoded bundle must then pass the same signed DevicePolicy verification
  chain used by remote policy refresh before the runtime applies it.
- Rejections keep the current policy in place and are audited.
- The device's policy bearer token is forwarded to the reference URL. The URL
  must be within the operator's trust boundary. If the HMAC shared secret is
  ever compromised, an attacker could direct the device to exfiltrate the
  bearer token by supplying a URL they control.

---

## 2026-06-06 — Sensitive MQTT Export Payloads Are Encrypted Above Broker Layer

**Status:** Accepted

Runtime-gateway export responses that carry historical or audit data must be
optionally encrypted at the application layer before publishing to MQTT.

Rules:

- `gateway.encryption.enabled` requires `gateway.auth.enabled`. Encryption
  without authenticated, replay-checked envelopes is not a supported runtime
  posture.
- Sensitive export responses are `sensor_history`, `action_log`,
  `reasoning_log`, and `tier_c_decision_log`.
- Sensitive export payloads are encrypted with AES-GCM before the HMAC envelope
  is applied. The broker sees routing metadata and ciphertext, not `items` or
  audit rows.
- The AES-GCM key is derived from the gateway shared secret using HKDF domain
  separation. The raw HMAC key is not reused directly as the encryption key.
- Health export responses may remain plaintext operational posture.
- Gateway support must decrypt the encrypted response envelope before this is
  enabled in production deployments.

Rationale:

TLS protects the network pipe, but a broker or broker credential compromise can
still expose plaintext JSON routed through MQTT. HMAC proves authenticity and
freshness, but does not hide data. Application-layer encryption protects
historical sensor readings, action logs, reasoning logs, and Tier C approval
audit rows from broker-side plaintext exposure while keeping the runtime-gateway
contract provider-neutral and LAN-compatible.

---

## 2026-06-08 — Alert Outbox Health Is Runtime Health

**Status:** Accepted

Failed operator notifications are queued locally and retried by the runtime.
The retry policy and backlog state are part of runtime health because delayed
alerts affect operator visibility even when physical safety actions remain
local and deterministic.

Rules:

- `actions.alert_outbox` owns retry interval, retry batch size, non-Tier-D
  abandonment threshold, and Tier D critical warning threshold.
- Runtime health snapshots expose retry policy, pending/failed backlog count,
  oldest queued alert timestamp, and oldest queued alert age.
- Empty outbox snapshots report zero backlog and `null` oldest age/timestamp.
- Tier D action execution never depends on notification delivery. Tier D alerts
  keep retrying and log critical warnings after the configured threshold.
- Non-Tier-D alerts may be abandoned after the configured failed-attempt limit.

Rationale:

Internet reachability affects operator visibility, not action authority. The
gateway needs a structured health signal to surface degraded notification
delivery at site level without inferring it from logs or reading SQLite
directly.

---

## 2026-06-08 — Context-Aware Suppression Uses Deterministic History

**Status:** Accepted

Ori may suppress or soften false-positive anomaly reasoning when a reading
matches the site's historical rhythm for the same local weekday and hour. This
is implemented as a bounded StateStore history primitive, not as an NN
classifier, LLM confidence signal, or cloud reasoning call.

Rules:

- Same-weekday/hour baselines use site-local timezone semantics, not UTC
  SQLite bucketing.
- Multi-week comparisons use the hourly compaction tier. Raw history is too
  short-lived and daily compaction is too coarse for hour-of-day patterns.
- Baseline results include `usable`, `covered_weeks`, and `sample_count` so
  skills fail closed when coverage is weak.
- Compaction from 5-minute to hourly and hourly to daily must use weighted
  averages: `SUM(avg_value * sample_count) / SUM(sample_count)`.
- The weighted compaction fix applies to future compaction runs only; the
  runtime does not retroactively recompute existing compacted rows.
- Tier D safety cutoffs are never suppressed by contextual baselines.

Rationale:

The product claim that Ori learns a site's rhythm should be backed by cheap,
explainable local history. A recurring Monday-morning AC load can be treated
differently from the same draw at an unusual time without asking an LLM to
guess or trusting model-reported confidence.

---

## 2026-06-08 — Retail Occupancy Optimizer Uses Occupancy-Gated Actuation

**Status:** Accepted

Retail energy optimisation combines occupancy and total-power context before
requesting or executing physical energy actions. The runtime treats occupancy
as an actuation guard, not as a safety override.

Rules:

- Business-hours empty/high-load conditions are Tier C. The runtime requests
  operator approval before eco-mode or similar hard physical changes.
- Off-hours empty/high-load conditions may be Tier B with
  `reasoning_policy: post_action`. The deterministic load-shed action executes
  first and reasoning enriches the operator/audit message after execution.
- The Tier B path must include a Tier A follow-up notification default.
- Missing occupancy state, stale power state, or missing power baseline history
  fails closed and does not trigger physical actuation.
- Deployment-specific physical actions such as HVAC eco mode or non-critical
  load shedding are explicit skill capabilities and must be mapped to real
  executors in site configuration before production use.
- Tier D safety remains unrelated and cannot be suppressed by occupancy context.

Rationale:

The skill makes Ori commercially useful for SMEs by reducing wasted overnight
energy while preserving actuation trust during business hours, where occupancy
sensors can be wrong and customers may still be using the space.

---

## 2026-06-08 — ContextEnricher Enriches Prompts, Not Safety Decisions

**Status:** Accepted

The runtime ContextEnricher appends a bounded snapshot of recent peer-sensor
readings to prompts before local SLM or gateway inference. It improves
reasoning quality by giving the model cross-sensor context, but it must never
influence safety decisions or Tier D behaviour.

Rules:

- `reasoning.context_enricher.enabled` defaults to `false`. Enrichment is
  opt-in per deployment.
- Staleness is evaluated at prompt-build time, not at sensor-event-emit time.
  A reading that was fresh when it fired may be stale by the time the prompt
  is assembled; `staleness_window_ms` enforces the freshness window at the
  moment the LLM is called.
- The snapshot is bounded by `max_entries` (1–20, default 5). The DB query
  returns at most `max_entries` rows ordered by `sensor_id` for deterministic
  prompt output.
- `include_sources` is applied in Python after the DB query. An empty list
  admits all sources; a non-empty list admits only the named adapter sources.
  This avoids JSON extraction in SQLite and keeps the query consistent with
  existing `metadata` handling.
- All injected field values (sensor_id, sensor_type, value, unit, quality)
  are sanitised with `re.sub(r"[^\w\s\-\./°%]", "", ...)` before insertion,
  matching the sanitisation applied to triggering-event fields in
  `_build_prompt`.
- Enrichment failure is unconditionally silent: any exception logs a WARNING
  and returns the original prompt. The runtime must never halt or degrade
  safety behaviour because a snapshot query failed.
- Tier D triggers exit the rule engine with `bypass_llm: true` before
  `_build_prompt` is called. The enricher is therefore never invoked on
  safety-critical paths by construction, not by an explicit guard.
- The enricher does not fetch internet data, does not call any LLM, and does
  not add cloud SDK dependencies to the runtime.

Rationale:

- A multi-sensor site (current + voltage + temperature) yields better
  reasoning when the model knows all three values, not just the one that
  triggered the event. Cross-sensor snapshots give the SLM and gateway
  reasoner context comparable to what a human operator would consider.
- Prompt-build-time freshness is the correct semantic: a stale peer reading
  could mislead the model into reasoning about a state that no longer exists.
  Event-emit-time freshness would allow arbitrarily old readings into the
  prompt if the event loop is busy.
- Bounded, deterministic output (ORDER BY sensor_id, LIMIT max_entries)
  prevents prompt length from growing unboundedly as a deployment adds sensors.

---

## 2026-06-10 — Gateway Heartbeat MQTT Subscription and Auth

**Status:** Accepted

Rules:

- `MqttGatewayHeartbeatSubscriber` subscribes to `ori/gateway/health` and
  calls `CapabilityPostureTracker.record_gateway_heartbeat(timestamp_ms)`
  directly via `loop.call_soon_threadsafe` for each valid heartbeat received.
  The sensor `EventBus` is not used; the heartbeat is an infrastructure liveness
  signal, not sensor data.
- When `gateway.auth.enabled: true`, each heartbeat payload is verified by
  `GatewayMessageAuthenticator.verify_broadcast` before posture is updated.
  Heartbeats that fail HMAC verification, timestamp skew, or replay checks are
  discarded with a WARNING.
- `gateway.auth.enabled: true` is the production recommendation. When enabled,
  unsigned heartbeats are rejected in code regardless of broker configuration.
- When `gateway.auth.enabled: false` (the default for initial LAN setup),
  unsigned heartbeats are accepted. The security guarantee is then conditional
  on the broker ACL being correctly configured to restrict `topic write
  ori/gateway/health` to the gateway's MQTT user only (see
  `docs/MQTT_SECURITY.md`). A misconfigured or absent ACL allows any LAN client
  to spoof a heartbeat and cause reasoning-quality degradation (gateway escalation
  times out, falls back to local SLM). This is not a safety failure — Tier D and
  action tier authority are unaffected — but `auth.enabled: false` is a
  convenience default, not a production-endorsed posture.
- `verify_broadcast` uses the same shared secret as `verify` but omits
  `device_id` binding. Replay key: `message_type + signed_at_ms + signature`.
  Device binding is not required on a site-wide broadcast topic: the threat is
  stale replay (making the runtime believe the gateway is alive when it is not),
  which is addressed by timestamp skew and replay TTL.
- Rejection tests for unsigned, stale, and replayed heartbeats are in
  `tests/test_gateway_heartbeat.py`.

Rationale:

- Gateway liveness is tracked via TTL-based `_is_gateway_reachable`: the
  runtime does not initiate any probe to verify gateway health. The heartbeat
  subscription is the only signal path for `gateway_reachable` in
  `CapabilityPosture`. Without it, the elevator silently misroutes Tier 3
  escalations on idle sites — the TTL expires with no implicit liveness signal.
- The gateway is a separate process on a separate machine. The heartbeat is a
  cross-process infrastructure signal; routing it through the sensor `EventBus`
  would conflate two semantically different event streams and expose it to
  wildcard skill subscribers that assume `event.reading` is set. The direct call
  to `record_gateway_heartbeat` is the correct interface — the heartbeat module
  is in the gateway package and knows exactly what it is updating.
- `verify_broadcast` is a distinct method from `verify` because the two
  verification paths have different trust models: per-device reasoning and export
  envelopes bind to `device_id` to prevent cross-device replay; a site-wide
  broadcast does not require device scoping. Both methods share the same HMAC
  key and replay cache, so a compromise of one does not require changes to the
  other.

Security posture when `gateway.auth.enabled: false` (not recommended for production):

- A spoofed heartbeat corrupts `_last_gateway_heartbeat_ms` and makes the
  elevator treat the gateway as reachable when it is not. The elevator then
  attempts Tier 3 escalation, burns the full reasoning timeout budget, and
  falls back to local SLM. This is a functional attack on reasoning quality:
  gateway escalation exists precisely to improve reasoning; the only acceptable
  cause of escalation failure is genuine gateway unavailability within timeout
  limits, not a forged liveness signal.
- Tier D is unaffected by gateway availability by construction; physical safety
  is not compromised. But reasoning quality is the operational value of Tier 3,
  and corrupting gateway liveness state undermines it in a way that is
  indistinguishable from a real outage.
- `auth.enabled: false` is only appropriate for controlled initial setup on a
  site where broker ACL correctness is guaranteed and the gateway is not yet
  configured to sign heartbeats. Any deployment where gateway reasoning quality
  matters must enable auth.

---

## 2026-06-11 — Runtime Node Heartbeat Is Gateway Infrastructure, Not Sensor Data

**Status:** Accepted

Rules:

- The gateway heartbeat (`ori/gateway/health`) tells each runtime whether the
  gateway is reachable.
- The runtime node heartbeat (`ori/{device_id}/runtime/heartbeat`) tells the
  gateway whether a runtime node is alive.
- Runtime node heartbeat payloads are device-scoped and include `device_id`,
  `status`, `last_seen_ms`, `gateway_seen_ms`, and `active_triggers`.
  `gateway_seen_ms` is set to `0` by the runtime and stamped by the gateway when
  it receives the payload.
- Runtime node heartbeat is not routed through the sensor `EventBus`. It is
  gateway infrastructure, not skill input or sensor data.
- When `gateway.auth.enabled: true`, runtime node heartbeat payloads are signed
  with the regular device-bound gateway HMAC envelope using message type
  `runtime.heartbeat`.
- Heartbeat publishes must use `retain=false`; a retained node heartbeat can
  make the gateway believe a disconnected runtime is still alive.

Rationale:

Gateway reachability and runtime liveness are opposite directions of the same
site-health relationship, but they are not the same signal. Keeping them on
separate MQTT topics avoids conflating posture consumed by the runtime with node
state consumed by the gateway. Keeping both out of the sensor EventBus preserves
the sensor/skill boundary and avoids wildcard skill handlers seeing
infrastructure-only payloads.
