# Inverter Read And Control Ladder

This document defines Ori's posture for inverter telemetry and future inverter
commands.

Ori currently reads broadly and advises only. It does not write inverter
registers, change work modes, alter charge current, alter export limits, or
send vendor control commands.

## Authority Ladder

| Status | Meaning | Runtime authority |
| :-- | :-- | :-- |
| `candidate` | Brand/model is a known target, but no bundled profile or validated transport exists. | No inverter reads. Use USB/PZEM fallback or vendor app manually. |
| `read_profile_implemented` | A bundled profile or dedicated adapter exists and passes decode fixtures. | Read telemetry only. No physical authority. |
| `read_qualified` | A real unit has field evidence for exact model/firmware/logger. | Read telemetry may support higher-confidence dashboards and advisories. |
| `advisory_qualified` | Telemetry, tariff/export-cap policy, and site context are good enough for Tier A recommendations. | Tier A alerts/logs only. No writes. |
| `write_candidate` | A control register/API is known from a source, but not qualified on a real unit. | No writes. Documentation and lab planning only. |
| `write_field_qualified` | A bounded write path has been proven on an exact unit with read-back, reversibility, and failure behavior evidence. | Still no autonomous control unless policy enables it. |
| `control_enabled_by_policy` | Operator/site policy explicitly enables a bounded control action. | Possible Tier B/C action through `ActionDispatcher` only. |

## Non-Negotiable Rules

- HAL adapters are read-only. Inverter writes must never be added to
  `ori/hal/*` adapter read paths.
- Unqualified profiles may support Tier A advisory text only.
- LLM output never grants write authority.
- Any inverter command is a physical action and must flow through
  `ActionDispatcher`.
- Tier B/C command paths require explicit device policy, bounds checks,
  audit logging, and read-back confirmation.
- Export-cap rules are deterministic bounds. If Ori ever controls export, the
  configured cap is a hard limit, not an LLM suggestion.
- A failed read-back or ambiguous inverter response must fail closed and notify
  the operator.

## Read Qualification Evidence

A profile becomes `read_qualified` only after evidence for the exact unit:

- brand, model, firmware, and logger serial;
- transport proof from the same device class that will run Ori;
- raw register dump;
- same-minute inverter LCD, vendor app, or PZEM/clamp reference;
- samples for every profile metric;
- import/export sign validation for grid power where applicable.

`ori-inverter-profile-doctor` checks whether a local evidence bundle is
complete enough for maintainer review. It does not promote profile status.

## Write Qualification Evidence

Future write qualification needs a separate evidence packet:

- exact register/API source and license;
- lower and upper command bounds;
- operator-approved test plan;
- pre-write state snapshot;
- write request payload;
- read-back confirmation;
- reversibility proof;
- timeout/fault behavior;
- rollback or safe-default behavior;
- audit trail linking command, approval, read-back, and final state.

Until that exists, Ori's inverter posture remains:

> Read broadly, advise intelligently, control narrowly only after explicit
> qualification and policy approval.
