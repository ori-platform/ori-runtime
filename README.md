<div align="center">

  <img src="/docs/ori-runtime-logo.png" alt="Ori Logo" width="500"/>

  <h3><strong>Give your devices a brain.</strong></h3>

[![License](https://img.shields.io/badge/license-Apache%202.0-1E6B4A?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-1E6B4A?style=flat-square)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-790%2B%20passing-1E6B4A?style=flat-square)](#testing)
[![Release](https://img.shields.io/badge/release-alpha-C8A951?style=flat-square)](#release-status)
[![Platform](https://img.shields.io/badge/runs%20on-Raspberry%20Pi%20·%20Linux%20·%20macOS-C8A951?style=flat-square)](#)

</div>

---

# Ori — Agentic IoT Runtime

> **IoT devices do not need more data. They need to reason about that data — and act on it.**

Ori is an open-source **agentic IoT runtime** that gives physical devices **tiered autonomous reasoning** — from deterministic safety rules to local SLMs. This reasoning is governed by a **[Physical Actuation Trust](PRINCIPLES.md)** framework that defines exactly what an AI agent is permitted to do in the physical world, at what consequence level, and with what human oversight. Offline-first. No cloud required. Runs on a $55 Raspberry Pi.

## Release Status

**Current channel: Alpha (`0.1.x`)**

- Runtime core is functional and publicly testable.
- Safety invariants (tier guards, strict skill validation, sandbox boundaries) are CI-enforced on every PR.
- APIs/config may still evolve between minor alpha releases.
- Recommended use today: pilots, PoCs, and controlled deployments.

Related repos in the org:

- Runtime: `ori-platform/ori-runtime` (this repo)
- Skills registry: `ori-platform/ori-skills`
- CLI: `ori-platform/ori-cli`
- Gateway: `ori-platform/ori-gateway`
- SDK (Python): `ori-platform/ori-sdk-python`
- Dashboard: `ori-platform/ori-dashboard`
- Specs/RFCs: `ori-platform/ori-specs`

---

## The Difference

Every existing IoT platform does the same thing: collect data, apply a threshold, fire an alert, wait for a human. Sensors report numbers. Ori reasons about them — and acts.

```text
❌ Traditional IoT: "Current draw: 8.2A"
❌ Traditional IoT: "ALERT: threshold exceeded. Please investigate."

✅ Ori (Tier A): "Your AC unit has drawn 40% above baseline for three afternoons.
        Pattern: refrigerant depletion, not usage change.
        Estimated failure: 2 weeks.
        I've sent a service reminder to your WhatsApp."

         — sent autonomously, from a $55 Pi, with no internet

✅ Ori (Tier B): "Grid voltage dropped to 174V. I have switched to
inverter power automatically." ← Acted. Then told you.

✅ Ori (Tier C): "Critical fault detected on main circuit. I am
proposing to trip the breaker. Reply YES to approve
or NO to cancel. Auto-cancel in 5 minutes."
← Reasoned. Proposed. Awaiting you.

✅ Ori (Tier D): [Relay trips immediately]
"Dangerous overcurrent (52A on 10A circuit). Emergency
cutoff executed at 14:32." ← Safety. No waiting.
```

Ori is not a monitoring system with a language model attached. It is an agent that reasons and acts — and trust is won by proving that human correction permanently alters the machine's future behaviour.

---

## What Ori Is Not

- Not a monitoring dashboard like Grafana — Ori acts, not just displays
- Not a cloud IoT platform like AWS IoT Core — Ori runs fully offline
- Not a notification system — alerts are Tier A, the least of what Ori does
- Not just a rules engine — Ori pairs deterministic safety rules with LLM reasoning

---

## Architecture

![Ori Runtime Architecture](/docs/architecture.svg)

```text
┌──────────────────────────────────────────────────────────────┐
│  Layer 6  Business       ori-cloud · dashboard · fleet       │
├──────────────────────────────────────────────────────────────┤
│  Layer 5  Application    Skills · Skills Hub · SDK           │
├──────────────────────────────────────────────────────────────┤
│  Layer 4  Reasoning+Action  Intelligence Elevator            │
│                             + Action Tier Framework          │
├──────────────────────────────────────────────────────────────┤
│  Layer 3  Middleware      Runtime · Event Loop · Dispatcher  │
├──────────────────────────────────────────────────────────────┤
│  Layer 2  Network         EventBus · Protocol Normaliser     │
├──────────────────────────────────────────────────────────────┤
│  Layer 1  Perception      HAL · GPIO · I2C · RS485 · psutil  │
└──────────────────────────────────────────────────────────────┘
```

Layers 1–4 run on the device. **Layers 3 and 4 are inseparable** — the runtime always pairs a reasoning decision with an action decision. Layer 5 is the community. Layer 6 is the business.

For the full architectural specification, read [`CLAUDE.md`](CLAUDE.md). For the design philosophy, read [`PRINCIPLES.md`](PRINCIPLES.md).

---

## Hardware Support

| Protocol             | Status | Coverage                                                                |
| -------------------- | ------ | ----------------------------------------------------------------------- |
| GPIO (Raspberry Pi)  | ✅     | Wired sensors and relay control                                         |
| I2C / SPI            | ✅     | Precision sensors: BME280, ADS1115, SCD40                               |
| Modbus RTU (RS485)   | ✅     | Industrial energy meters, PLCs, motor drives                            |
| psutil               | ✅     | PC and server health monitoring (any laptop)                            |
| MQTT                 | ✅     | WiFi-connected sensors/devices via an MQTT broker (commonly Mosquitto). |
| OPC-UA               | ✅     | Industrial PLCs (IEC 62541)                                             |
| SolarmanV5 (Growatt) | ✅     | Smart inverter integration                                              |
| Zigbee / LoRaWAN     | 🗓️     | Smart home and rural long-range sensors                                 |

✅ = Implemented &nbsp;&nbsp; 🗓️ = Roadmap

All adapters include a **hardware circuit breaker** that auto-isolates failing buses to protect the rest of the system.

---

## How It Works

Ori runs a paired decision system on every sensor event:

### The Intelligence Elevator — _What does this mean?_

```text
Tier 1  RULE ENGINE    microseconds · always available · safety triggers
Tier 2  LOCAL SLM      3-8 seconds  · fully offline    · everyday reasoning
Tier 3  GATEWAY LLM    1-3 seconds  · LAN only         · cross-device reasoning
Tier 4  CLOUD LLM      2-5 seconds  · internet         · deep analysis + reports
```

### The Action Tier Framework — _What should I do about it?_

```text
Tier A  INFORMATIONAL       Always autonomous
        Alerts, logs, reports — the agent acts without asking

Tier B  SOFT PHYSICAL        Autonomous by default, configurable
        Power source switching, thermostat adjustments, irrigation valves
        The agent acts and tells you what it did

Tier C  HARD PHYSICAL        Approval workflow — always
        Breaker trips, equipment shutdown, high-consequence control
        The agent reasons, proposes, and waits for your YES or NO

Tier D  SAFETY-CRITICAL      Always autonomous, cannot be overridden
        Dangerous overcurrent, thermal runaway, hazardous gas
        The agent acts first, notifies you immediately
```

The runtime picks the cheapest reasoning tier that can answer. The action tier determines whether it acts, asks, or moves immediately.

---

## Safety Architecture

Ori is designed for [physical actuation trust](PRINCIPLES.md). The safety architecture enforces invariants at every layer:

- **Tier D rules fire before any LLM** — deterministic, microsecond-latency cutoffs that cannot be disabled or overridden
- **AST whitelist validation** — skill condition expressions are parsed into abstract syntax trees and only safe constructs are permitted (comparisons, arithmetic, `history.method()` calls). No string-pattern blacklist that can be bypassed
- **Sandboxed skill hooks** — community skills cannot import arbitrary modules. The sandbox enforces an explicit allowlist at import time
- **Hardware circuit breakers** — failing sensor buses are auto-isolated using a three-state (CLOSED → OPEN → HALF_OPEN) circuit breaker so one bad sensor doesn't crash the runtime
- **Approval workflows for hard physical actions** — Tier C actions always require operator approval via WhatsApp/SMS. No config flag to skip it

For the full set of security invariants, see [`AGENTS.md`](AGENTS.md#security-invariants--never-violate-these).

---

## Skills

Everything Ori does is a skill. A skill is a packaged agent behaviour with explicit action authority declarations written in YAML.

```yaml
# skills/energy-anomaly-detector/skill.yaml
triggers:
  - name: anomalous_draw
    condition: "load_current > (history.avg_24h('load_current') * 1.4)"
    action_tier: A # → autonomous WhatsApp with reasoning

  - name: grid_instability
    condition: "grid_voltage < 180 and inverter_battery > 0.4"
    action_tier: B # → switches source, tells you after

  - name: critical_fault
    condition: "load_current > rated_capacity * 3.0"
    action_tier: C # → "Trip breaker? Reply YES/NO"

  - name: dangerous_overcurrent
    condition: "load_current > rated_capacity * 5.0"
    bypass_llm: true
    action_tier: D # → cuts power. no waiting.
```

Bundled skills: **pc-system-health** (runs on any laptop) and **energy-anomaly-detector**. More are coming — including HVAC refrigerant monitoring.

Community skills live at **[ori-platform/ori-skills](https://github.com/ori-platform/ori-skills)** — verified by Ed25519 signature and VirusTotal before installation.

---

## The Tier C Approval Workflow

When Ori proposes a hard physical action, this is what the operator receives:

```text
ORI ALERT — Action Required
Device: energy-monitor-ikeja-office-01
Time: Wednesday 14:32

OBSERVATION:
Load current has reached 38.4A — 3.8x the rated 10A capacity.
Sustained for 45 seconds and climbing.

REASONING:
Pattern consistent with a short circuit, not a temporary surge.
Active fault propagation detected.

PROPOSED ACTION:
Trip the main circuit breaker to prevent equipment damage or fire.

CONFIDENCE: 94%

Reply YES to approve  |  Reply NO to cancel
Auto-cancel in 5 minutes if no response.
```

The agent does the diagnosis. The operator approves or rejects a specific, fully-reasoned proposal.

---

## Quick Start — No Hardware Needed

Ori's **pc-system-health** skill runs on any laptop using `psutil`. No Raspberry Pi, no sensors, no wiring.

```bash
# Clone and install
git clone https://github.com/ori-platform/ori-runtime.git
cd ori-runtime
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip          # required: old pip (<22) can't handle pyproject.toml editable installs
pip install -e ".[dev]"

# Verify everything works (660+ tests)
pytest tests/ -v

# Validate a skill loads cleanly
python -c "
import asyncio
from ori.skills.loader import SkillLoader
skill = asyncio.run(SkillLoader().load_one('skills/pc-system-health'))
print(f'Loaded: {skill.name} v{skill.version}')
for t in skill.triggers:
    print(f'  Trigger: {t.name} tier={t.action_tier}')
"
```

---

## Testing

```bash
pytest tests/ -v                              # Full suite
pytest tests/test_rule_engine.py -v           # Specific module
pytest tests/ --cov=ori --cov-report=term-missing  # With coverage
```

The test suite covers all layers — HAL adapters, event bus, rule engine (with AST safety validation), action dispatcher (all four tiers), skill loader, state store, and runtime. 790+ tests passing, 5 skipped (hardware-only).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting, supported versions, and disclosure policy.

---

## Roadmap

| Phase  | Status         | Milestone                                                                   |
| ------ | -------------- | --------------------------------------------------------------------------- |
| Core   | ✅ Complete    | Full runtime with 6-layer architecture, 4-tier action framework, 660+ tests |
| PoC    | 🔨 In Progress | Energy skill deployed in Lagos. HVAC refrigerant monitor. Demo video.       |
| Launch | 🗓️ Planned     | Skills Hub. CLI tooling. Phone-as-gateway deployment model.                 |
| Growth | 🗓️ Planned     | Rust HAL rewrite. 500+ skills. ori-cloud. Enterprise pilots.                |

---

## Contributing

We welcome contributions! Start here:

1. **Read the design philosophy:** [`PRINCIPLES.md`](PRINCIPLES.md)
2. **Read the contributor guide:** [`CONTRIBUTING.md`](CONTRIBUTING.md)
3. **Understand the extension points:** [`AGENTS.md`](AGENTS.md)

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

First PR suggestions: new `psutil` sensor types — testable on any laptop, no hardware required.

---

<div align="center">

**Apache 2.0. Forever free.**

ori-cloud — the managed service — is how the project sustains itself.

[Contributing](CONTRIBUTING.md) · [Architecture](CLAUDE.md) · [Design Principles](PRINCIPLES.md) · [Issues](https://github.com/ori-platform/ori-runtime/issues)

**Ori Nexus Systems LTD** · Lagos, Nigeria · 2026

</div>
