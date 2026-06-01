# Ori Runtime Design Decisions

This file records security- and architecture-relevant decisions that future
contributors must preserve unless a superseding decision is explicitly added.

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
