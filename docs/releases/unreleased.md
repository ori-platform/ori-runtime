# Ori Runtime — Unreleased

Changes merged to `main` since `v2.0.0`, collected here until the next
release is cut.

## Breaking Changes — Device Provisioning Attribution

Implements the anchor lifecycle in
[`ori-specs/device-provisioning/v1.md`](https://github.com/ori-platform/ori-specs/blob/main/device-provisioning/v1.md).
The contract requires every operator decision that changes what a receiver
will accept to be attributed, so the APIs that perform those decisions can
no longer be called without attribution.

- **`FirmwareTelemetryGate.approve_device()` and `revoke_device()` now
  require `actor` and `reason` keyword arguments.** The same applies to the
  store-level `approve_firmware_device()` and `revoke_firmware_device()`.
  Calls without them raise `TypeError`; blank or whitespace-only values
  raise `ValueError` before any state changes.
- **`ori-firmware-provisioner approve` now requires `--reason`.**
- **`ori-firmware-provisioner approve` no longer accepts `--actor`.** The
  actor is derived from the authenticated OS principal (the real UID via the
  passwd database) rather than supplied on the command line. A typed name is
  an assertion anyone can make; it is not attribution. An optional
  `--actor-label` annotates the record but never replaces the principal. On
  a platform with no real UID the operation is refused rather than audited
  to a placeholder.

Only device-initiated registration and the replacement of a pending
candidate may be unattributed, because they grant nothing.

### Migration

Add `actor` and `reason` at every call site:

```python
await gate.approve_device(device_id, actor="alice@ops", reason="bench bring-up")
await gate.revoke_device(device_id, actor="alice@ops", reason="key compromised")
```

```sh
# before
ori-firmware-provisioner approve --db … --device-id … --confirm-device-key … --actor alice
# after
ori-firmware-provisioner approve --db … --device-id … --confirm-device-key … \
    --reason "bench bring-up" [--actor-label alice]
```

## Behaviour Changes — Registration

Registration is now a decision rather than an overwrite, and refuses where
it previously accepted:

- **A revoked identity is refused** (`device_revoked`). Revocation belongs to
  the identity and is never cleared as a side effect of a device
  re-publishing its manifest. Returning one to service is `reinstate`.
- **A changed device key is refused** (`key_change_requires_reprovisioning`).
  A self-signed manifest proves internal consistency, never provenance, so
  accepting a new key on that basis would let anyone able to publish take
  over an identity. Use `reprovision`.
- **A same-key manifest change becomes a pending candidate** beside the
  still-active anchor rather than replacing it. Nothing is accepted against
  the candidate until it is promoted, so a device cannot grant itself a new
  capability surface by publishing.

## Added — Lifecycle Operations

`ori-firmware-provisioner` gains two commands, and the gate gains the
matching methods:

- **`reinstate`** — returns a revoked identity to service. Clears the revoked
  flag and moves the retained anchor back to *pending*; it activates
  nothing, because promotion is the only path to active.
- **`reprovision`** — accepts a new device key as a pending anchor, with the
  new key confirmed against the device itself. The previously active anchor
  stays active until promotion.

Both require `--reason` and record the authenticated principal.

`reprovision` refuses a key that is not genuinely new:

- **`same_key_not_a_rotation`** — the submitted key is the current one, so
  nothing is being replaced.
- **`key_epoch_reused`** — this identity has used that key before. An old key
  may be exactly the one rotated away from because it was compromised, so
  returning to it would make rotation reversible by whoever still holds it.

Neither code appears in `ori-specs/device-provisioning/v1.md` yet; the
contract's error table should adopt them.

## Added — Anchor History and Audit

- `firmware_device_anchors`: append-only, every anchor an identity has held
  (`pending`, `active`, `superseded`, `discarded`, `revoked`). Evidence
  outlives the anchor that authorised it, so nothing is deleted. At most one
  active and one pending per identity, enforced by partial unique indexes.
- `firmware_anchor_transitions`: append-only audit of every trust
  transition, with actor, reason, and the epoch either side.
- `key_epoch_id` and `anchor_epoch_id` on the registry, derived
  deterministically so independent stores compute the same value without
  coordinating.

## Freshness Semantics

- A **manifest-only change does not reset telemetry freshness** — the key
  epoch is unchanged, so the replay window stays closed.
- **Promoting a new key epoch does start a fresh window.** A re-keyed device
  restarts its counters and would otherwise be refused as a replay against
  its predecessor's high-water mark. The previous epoch's counters remain
  historical and unusable.
- **`cmd_seq` is never reset.** The command mark is per device, not per key,
  and continues across rotation
  (`ori-specs/firmware-commands/v1.md`).

## Upgrade Notes

Existing databases migrate automatically on open. Rows predating the
lifecycle gain their epoch identifiers and an anchor-history entry: an
approved, unrevoked row becomes `active`; a **revoked** row becomes
`revoked`, never `pending`, so a revoked identity does not acquire a
promotable anchor; anything else becomes `pending`. Approval and freshness
are preserved.
