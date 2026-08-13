# Ori Runtime — Stable Release Notes

## Versioned Notes

- [`v2.3.1`](v2.3.1.md) — bootstrap portability and entry-point repair
- [`v2.3.0`](v2.3.0.md) — authenticated signed release installation for Linux
- [`v2.2.0`](v2.2.0.md) — signed runtime liveness for supervised firmware devices
- [`v2.1.0`](v2.1.0.md) — Layer 1 firmware trust, evidence provenance, and authenticated MQTT provisioning
- [`v2.0.0`](v2.0.0.md) — hardened runtime: fail-closed production security posture
- [`v1.0.0`](v1.0.0.md) — first stable runtime release

## Version

`v2.3.1`

## Stable Scope

Guaranteed by the runtime v1/v2 line:

- Tier A/B/C/D action authority invariants
- deterministic Tier D rule-only safety behavior
- Tier C approval-gated hard physical actions
- explicit Tier B approval/post-action policy requirement
- runtime-owned MQTT gateway reasoning/export/heartbeat contracts
- typed `ori.integration` rule-evaluation boundary for demos and product tests
- release wheel smoke verification for packaged bundled skills

Companion repos (`ori-gateway`, product provisioning, `ori-sdk-python`, `ori-cloud`) may
continue iterating while consuming these runtime contracts.
