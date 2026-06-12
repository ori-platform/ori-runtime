# Ori Runtime — Stable Release Notes

## Versioned Notes

- [`v1.0.0`](v1.0.0.md) — first stable runtime release

## Version

`v1.0.0`

## Stable Scope

Guaranteed by the runtime v1 line:

- Tier A/B/C/D action authority invariants
- deterministic Tier D rule-only safety behavior
- Tier C approval-gated hard physical actions
- explicit Tier B approval/post-action policy requirement
- runtime-owned MQTT gateway reasoning/export/heartbeat contracts
- typed `ori.integration` rule-evaluation boundary for demos and product tests
- release wheel smoke verification for packaged bundled skills

Companion repos (`ori-gateway`, `ori-energy`, `ori-sdk-python`, `ori-cloud`) may
continue iterating while consuming these runtime contracts.
