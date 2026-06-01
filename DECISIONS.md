# Ori Runtime Design Decisions

This file records security- and architecture-relevant decisions that future
contributors must preserve unless a superseding decision is explicitly added.

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
