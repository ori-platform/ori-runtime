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

Implication:

- `APPLY_POLICY` remains audit-only until the fetch URL, expected hash, and
  signed bundle verification flow are implemented and tested.
