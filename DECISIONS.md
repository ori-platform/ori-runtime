# Ori Runtime Design Decisions

This file records security- and architecture-relevant decisions that future
contributors must preserve unless a superseding decision is explicitly added.

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
