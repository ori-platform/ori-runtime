# Ori Runtime — Alpha Release Notes

## Version

`v0.1.0-alpha` (or current `0.1.x` alpha tag)

## Summary

Ori Runtime is now publicly available as an alpha release.

This release focuses on the runtime foundation:

- Deterministic + tiered reasoning/action architecture
- Tier enforcement invariants for physical actuation trust
- Strict skill validation and sandbox boundaries
- Hardware adapter resilience with circuit-breaker protections
- SMS/WhatsApp alert and approval workflow integration
- Broad protocol support including GPIO/I2C/Serial/MQTT/OPC-UA/SolarmanV5/HTTP

## Safety and Security

- Tier guard regressions are blocked by CI invariants.
- Skill capability strictness is CI-enforced.
- Community skill hooks are sandboxed.
- Tier C approval workflow remains mandatory.
- Tier D safety path remains autonomous and non-LLM.

See `SECURITY.md` for vulnerability reporting.

## Alpha Scope

Recommended:

- PoCs
- Pilot rollouts
- Controlled production-adjacent trials

Not yet guaranteed:

- Full backward compatibility across alpha minors
- Stable SDK/CLI contracts across every alpha update

## Repository Topology

- Runtime: `ori-platform/ori-runtime`
- Skills registry: `ori-platform/ori-skills`
- CLI: `ori-platform/ori-cli`
- Gateway: `ori-platform/ori-gateway`
- SDK: `ori-platform/ori-sdk-python`
- Dashboard: `ori-platform/ori-dashboard`
- Specs: `ori-platform/ori-specs`

## Suggested GitHub Release Description

```markdown
Ori Runtime is now public in **alpha**.

This release establishes the core runtime needed for physically trustworthy edge agents:

- Tiered reasoning + action authority framework
- Strict safety invariants with CI enforcement
- Community-skill safety boundaries (validation + sandboxing)
- Non-blocking async runtime with hardware circuit-breaker protection

This is an alpha channel focused on pilots and controlled deployments.
Expect iterative changes while companion repos (`ori-skills`, `ori-cli`, `ori-gateway`, `ori-sdk-python`, `ori-dashboard`) continue shipping.
```
