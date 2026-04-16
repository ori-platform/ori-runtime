<div align="center">

  <img src="/docs/ori-runtime-logo.png" alt="Ori Logo" width="500"/>

  <h3><strong>Give your devices a brain.</strong></h3>

[![License](https://img.shields.io/badge/license-Apache%202.0-1E6B4A?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-1E6B4A?style=flat-square)](https://python.org)
[![CI](https://github.com/ori-platform/ori-runtime/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ori-platform/ori-runtime/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-alpha-C8A951?style=flat-square)](#release-status)
[![Platform](https://img.shields.io/badge/runs%20on-Raspberry%20Pi%20·%20Linux%20·%20macOS-C8A951?style=flat-square)](#)

</div>

---

# Ori — Agentic IoT Runtime

> **IoT devices do not need more data. They need to reason about that data — and act on it.**

Ori is an open-source **agentic IoT runtime** that gives physical devices **tiered autonomous reasoning** — from deterministic safety rules to local SLMs. This reasoning is governed by a **[Physical Actuation Trust](PRINCIPLES.md)** framework that defines exactly what an AI agent is permitted to do in the physical world, at what consequence level, and with what human oversight. Offline-first with an offline-capable safety core; gateway/cloud escalation is optional. Runs on a $55 Raspberry Pi.

Built for the world's majority condition — unreliable power, intermittent connectivity, constrained hardware. Systems designed for constraint work everywhere.

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

         — sent autonomously from a $55 Pi, without requiring cloud inference for safety decisions

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
- Not a cloud IoT platform like AWS IoT Core — Ori keeps an offline-capable safety core (Tier 1 + local Tier 2), with optional gateway/cloud escalation when connected
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

| Protocol             | Status | Coverage                                                               |
| -------------------- | ------ | ---------------------------------------------------------------------- |
| GPIO (Raspberry Pi)  | ✅     | Wired sensors and relay control                                        |
| I2C / SPI            | ✅     | Precision sensors: BME280, ADS1115, SCD40                              |
| Modbus RTU (RS485)   | ✅     | Industrial energy meters, PLCs, motor drives                           |
| psutil               | ✅     | PC and server health monitoring (any laptop)                           |
| MQTT                 | ✅     | WiFi-connected sensors/devices via an MQTT broker (commonly Mosquitto) |
| CoAP (actuation)     | ✅     | Constrained-device command path for low-overhead control endpoints     |
| OPC-UA               | ✅     | Industrial PLCs (IEC 62541)                                            |
| SolarmanV5 (Growatt) | ✅     | Smart inverter integration                                             |
| Zigbee               | ✅     | Smart-home sensors via MQTT bridge (for example zigbee2mqtt)           |
| LoRaWAN              | ✅     | Rural long-range uplink sensors via MQTT brokers (TTN/ChirpStack)      |

✅ = Implemented

All adapters include a **hardware circuit breaker** that auto-isolates failing buses to protect the rest of the system.

---

## Hardware Requirements

| Configuration             | Hardware                       | RAM  | Notes                                         |
| ------------------------- | ------------------------------ | ---- | --------------------------------------------- |
| Rule engine only (Tier 1) | Raspberry Pi 3B+ or equivalent | 1GB  | No local SLM. Full safety framework active.   |
| Full stack with local SLM | Raspberry Pi 4 4GB             | 4GB  | Validated reference hardware. 3–8s inference. |
| Development / laptop      | Any modern machine             | 4GB+ | psutil adapter. No Pi required.               |

The model file (Qwen2.5-0.5B Q4) is 500MB. The SQLite state store stays bounded under 80MB via the compaction pyramid regardless of deployment duration.

---

## How It Works

Ori runs a paired decision system on every sensor event:

### The Intelligence Elevator — _What does this mean?_

```text
Tier 1  RULE ENGINE    microseconds · always available  · safety triggers
Tier 2  LOCAL SLM      3-8 seconds  · offline-capable   · everyday reasoning
Tier 3  GATEWAY LLM    1-3 seconds  · LAN only          · cross-device reasoning
Tier 4  CLOUD LLM      2-5 seconds  · internet          · deep analysis + reports
```

- Tier 1 (Rule Engine) and Tier 2 (Local SLM) are fully implemented and available offline.
- Tier 3 (Gateway LLM) and Tier 4 (Cloud LLM) are defined in the architecture and reserved in the elevator — implementation is coming in the gateway milestone.
- The runtime is correctly described as an offline-capable safety runtime. Tier 1 and Tier D safety paths are available with zero network dependency.

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
- **Alert transport failover** — approval requests use the configured primary channel first, then fail over to the secondary channel if delivery fails

For constrained deployments, a common pattern is MQTT for continuous telemetry plus CoAP for low-overhead command delivery.

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

Bundled skills: **pc-system-health** (runs on any laptop), **energy-anomaly-detector**, **hvac-refrigerant-monitor**, and **site-safety-ppe**.

Community skills live at **[ori-platform/ori-skills](https://github.com/ori-platform/ori-skills)**. The runtime enforces strict skill validation and sandboxed hook loading for community-installed skills.

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

# Verify everything works
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

### Quick Local SLM Setup (Qwen GGUF)

```bash
# 1) Activate your venv
source .venv/bin/activate

# 2) Install llama-cpp-python (CPU path; stable across laptops)
pip install --no-cache-dir llama-cpp-python

# 3) Download a local GGUF model
mkdir -p ~/models
curl -L https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf \
  -o ~/models/qwen2.5-0.5b-instruct-q4_k_m.gguf

# 4) Point your config to the local model
# reasoning:
#   default_tier: local
#   local_model: qwen2.5-0.5b-instruct-q4_k_m
#   model_path: /Users/<you>/models
#   offline_fallback: local_slm

# 5) Optional dev convenience: auto-load .env before config parse
export ORI_AUTOLOAD_DOTENV=true

# 6) Start runtime
python -m ori.runtime --config ori.local.yaml
```

### Smoke Tests

```bash
# Full runtime smoke test (requires ori.local.yaml configured)
bash scripts/smoke-runtime-local.sh

# Force pretty console output
ORI_PRETTY_LOGS=true bash scripts/smoke-runtime-local.sh

# Disable ANSI colors (CI/plain terminals)
ORI_PRETTY_LOGS=false bash scripts/smoke-runtime-local.sh

# Live host-health report (real psutil readings + skill trigger evaluation)
ORI_PRETTY_LOGS=true .venv/bin/python scripts/pc_health_report.py

# Local SLM quality smoke test (without starting full runtime)
python - <<'PY'
import asyncio
from ori.reasoning.local_llm import LocalLLM

async def main():
    llm = LocalLLM(
        model_path="/Users/<you>/models/qwen2.5-0.5b-instruct-q4_k_m.gguf",
        context_window=2048,
    )
    result = await llm.reason("CPU at 96% for 10 minutes. Give 2 short operator actions.")
    print(result.tier, result.model)
    print(result.text)

asyncio.run(main())
PY
```

Troubleshooting:

- `ori-runtime: command not found`:
  - install entrypoint into the active venv: `python -m pip install -e .`
  - or run directly: `python -m ori.runtime --config ori.local.yaml`
- Config fails with `Environment variable not set: ${...}`:
  - export required vars into shell or set `ORI_AUTOLOAD_DOTENV=true` with a valid `.env` file
- `Failed to create llama_context` on macOS:
  - reinstall `llama-cpp-python` without Metal (CPU path), then retry
- VS Code uses wrong interpreter:
  - select `${workspaceFolder}/.venv/bin/python` via `Python: Select Interpreter`

---

## Testing

```bash
pytest tests/ -v                              # Full suite
pytest tests/test_rule_engine.py -v           # Specific module
pytest tests/ --cov=ori --cov-report=term-missing  # With coverage
```

The test suite covers all layers — HAL adapters, event bus, rule engine (with AST safety validation), action dispatcher (all four tiers), skill loader, state store, and runtime.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting, supported versions, and disclosure policy.

---

## Roadmap

| Phase  | Status          | Milestone                                                             |
| ------ | --------------- | --------------------------------------------------------------------- |
| Core   | ✅ Active Alpha | Core runtime with 6-layer architecture and 4-tier action framework    |
| PoC    | 🔨 In Progress  | Energy skill deployed in Lagos. HVAC refrigerant monitor. Demo video. |
| Launch | 🔨 In Progress  | Skills Hub. CLI tooling. Phone-as-gateway (Termux path live).         |
| Growth | 🗓️ Planned      | Rust HAL rewrite. 500+ skills. ori-cloud. Enterprise pilots.          |

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
