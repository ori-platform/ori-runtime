<div align="center">

  <img src="/docs/ori-runtime-logo.png" alt="Ori Logo" width="500"/>

  <h3><strong>Give your devices a brain.</strong></h3>

[![License](https://img.shields.io/badge/license-Apache%202.0-1E6B4A?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-1E6B4A?style=flat-square)](https://python.org)
[![CI](https://github.com/ori-platform/ori-runtime/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ori-platform/ori-runtime/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-v2.4.0-1E6B4A?style=flat-square)](#release-status)
[![Platform](https://img.shields.io/badge/runs%20on-Raspberry%20Pi%20·%20Linux%20·%20macOS-C8A951?style=flat-square)](#)

</div>

---

# Ori — Agentic IoT Runtime

> **IoT devices do not need more data. They need to reason about that data — and act on it.**

Ori is an open-source **agentic IoT runtime** that gives physical devices **tiered autonomous reasoning** — from deterministic safety rules to local SLMs. This reasoning is governed by a **[Physical Actuation Trust](PRINCIPLES.md)** framework that defines exactly what an AI agent is permitted to do in the physical world, at what consequence level, and with what human oversight. Offline-first with an offline-capable safety core; gateway escalation is optional. Runs on a $55 Raspberry Pi.

Built for the world's majority condition — unreliable power, intermittent connectivity, constrained hardware. Systems designed for constraint work everywhere.

## Release Status

**Current channel: Stable (`2.3.x`)**

- Runtime core is stable for PoC, demo API, and controlled field deployment,
  with a fail-closed production security posture: staging/production configs
  must meet the hardened gateway, remote-command, webhook, skill-signing,
  state-encryption, and signed-config requirements or the runtime refuses to
  start. Development-profile deployments remain warning-only.
- High-authority action evidence is implemented behind `evidence.enabled`:
  Tier C/D dispatch records can be signed through a privately supplied evidence
  artifact, reconciled after restart, and surfaced through runtime health and
  gateway heartbeat evidence. Device-origin telemetry is now consumed by the
  runtime verification gate: firmware signs readings at the physical edge, the
  runtime verifies and trust-grades them, and the private evidence artifact
  verifies the shared golden bytes/signatures without owning firmware
  canonicalization.
- Safety invariants (tier guards, the runtime action registry, strict skill validation, skill provenance) are CI-enforced on every PR.
- Public runtime contracts used by companion repos are the MQTT gateway/export contracts and the typed `ori.integration` rule-evaluation boundary — unchanged from v1.0.0.
- Recommended use today: pilots, PoCs, controlled deployments, product provisioning, and downstream demo/API integration.
- Release notes: [`docs/releases/v2.4.0.md`](docs/releases/v2.4.0.md)

Related public repos in the org:

- Runtime: `ori-platform/ori-runtime` (this repo)
- Skills registry: `ori-platform/ori-skills-hub`
- CLI: `ori-platform/ori-cli`
- Gateway: `ori-platform/ori-gateway`
- SDK (Python): `ori-platform/ori-sdk-python`
- Specs/RFCs: `ori-platform/ori-specs`

Private evidence-chain and edge-firmware artifacts integrate through the public
contracts in `ori-specs`; their source coordinates are intentionally not part of
this public runtime repository.

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
proposing to open the protected-load safety circuit. Reply YES-AB12CD34
to approve or NO-AB12CD34 to cancel. Auto-cancel in 5 minutes."
← Reasoned. Proposed. Awaiting you.

✅ Ori (Tier D): [Installer-wired relay/contactor opens immediately]
"Dangerous overcurrent (52A on 10A circuit). Emergency
cutoff executed at 14:32." ← Safety. No waiting.
```

Ori is not a monitoring system with a language model attached. It is an agent that reasons and acts — and trust is won by proving that human correction permanently alters the machine's future behaviour.

---

## What Ori Is Not

- Not a monitoring dashboard like Grafana — Ori acts, not just displays
- Not a cloud IoT platform like AWS IoT Core — Ori keeps an offline-capable safety core (Tier 1 + local Tier 2), with optional gateway escalation when connected
- Not a notification system — alerts are Tier A, the least of what Ori does
- Not just a rules engine — Ori pairs deterministic safety rules with LLM reasoning

---

## Architecture

![Ori Runtime Architecture](/docs/architecture.svg)

```text
┌──────────────────────────────────────────────────────────────┐
│  Runtime L6  Business     ori-cloud · dashboard · fleet      │
├──────────────────────────────────────────────────────────────┤
│  Runtime L5  Application  Skills · Skills Hub · SDK          │
├──────────────────────────────────────────────────────────────┤
│  Runtime L4  Reasoning+Action  Intelligence Elevator         │
│                                + Action Tier Framework       │
├──────────────────────────────────────────────────────────────┤
│  Runtime L3  Middleware   Runtime · Event Loop · Dispatcher  │
├──────────────────────────────────────────────────────────────┤
│  Runtime L2  Network      EventBus · Protocol Normaliser     │
├──────────────────────────────────────────────────────────────┤
│  Runtime L1  Perception   HAL · GPIO · I2C · RS485 · psutil  │
└──────────────────────────────────────────────────────────────┘
```

These are **runtime architecture layers**, not evidence protocol layers. Runtime
Layers 1–4 run on the device. **Runtime Layers 3 and 4 are inseparable** — the
runtime always pairs a reasoning decision with an action decision. Runtime Layer
5 is the community. Runtime Layer 6 is the business.

`ori-edge-firmware` is a Layer 1 companion, not a second runtime. Firmware nodes
are **evidence Layer 1** producers: they sign sensor-origin telemetry at the
point of measurement. This runtime verifies and normalises those readings,
reasons over them, acts through the Action Tier Framework, and records Tier C/D
action evidence through the private evidence artifact as **evidence Layer 2**.

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

The model file (Qwen2.5-0.5B Q4) is 500MB. The SQLite state store stays bounded under 80MB via the compaction pyramid regardless of deployment duration. Production/staging deployments must place the SQLite state path on an encrypted filesystem or mount and declare that posture under `state.encryption`; the runtime uses standard `sqlite3`, not SQLCipher.

---

## How It Works

Ori runs a paired decision system on every sensor event:

### The Intelligence Elevator — _What does this mean?_

```text
Tier 1  RULE ENGINE    microseconds · always available  · safety triggers
Tier 2  LOCAL SLM      3-8 seconds  · offline-capable   · everyday reasoning
Tier 3  GATEWAY LLM    1-3 seconds  · LAN only          · cross-device or cloud-backed reasoning
```

- Tier 1 (Rule Engine) and Tier 2 (Local SLM) are fully implemented and available offline.
- Tier 3 (Gateway LLM) is implemented over MQTT request/response and remains optional.
- Cloud reasoning, when used, is a gateway backend, not a runtime dependency.
- Production runtime-gateway MQTT deployments should follow
  [`docs/MQTT_SECURITY.md`](docs/MQTT_SECURITY.md) for broker ACLs, network
  isolation, and HMAC envelope configuration.
- Public SMS webhook deployments should follow
  [`docs/SMS_WEBHOOK_SECURITY.md`](docs/SMS_WEBHOOK_SECURITY.md). Runtime
  sender allowlisting is necessary, but carrier-level sender spoofing requires
  deployment controls such as a signing bridge, source CIDR allowlisting, or a
  trusted reverse proxy.
- The runtime is correctly described as an offline-capable safety runtime. Tier 1 and Tier D safety paths are available with zero network dependency.

### The Action Tier Framework — _What should I do about it?_

```text
Tier A  INFORMATIONAL       Always autonomous
        Alerts, logs, reports — the agent acts without asking

Tier B  SOFT PHYSICAL        Explicit approval or post-action policy
        Power source switching, thermostat adjustments, irrigation valves
        The agent either asks first or acts first and explains after

Tier C  HARD PHYSICAL        Approval workflow — always
        Relay/contactor-controlled shutdown, high-consequence control
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
- **Runtime-owned action floors** — the minimum tier an action may be dispatched at comes from the runtime's own action registry, not from the skill file. A skill may raise an action's tier, never lower it, and only non-actuating actions may be a Tier C safe default
- **Tier D is granted by provenance, not claimed** — Tier D is the one tier that removes the operator, so it is accepted only from skills shipped with the runtime. A signature proves who wrote a skill, not that it holds autonomous safety authority
- **Community hooks do not execute** — the in-process hook sandbox was removed rather than hardened, because it could be escaped and half of it was inert on Python 3.12. There is no in-process fallback; isolated execution is being specified before it is built. First-party skills packaged with the runtime are unaffected
- **Hardware circuit breakers** — failing sensor buses are auto-isolated using a three-state (CLOSED → OPEN → HALF_OPEN) circuit breaker so one bad sensor doesn't crash the runtime
- **Approval workflows for hard physical actions** — Tier C actions always require operator approval via WhatsApp/SMS. No config flag to skip it
- **Alert transport failover** — approval requests use the configured primary channel first, then fail over to the secondary channel if delivery fails
- **Evidence chain for high-authority actions** — when configured, a private
  evidence artifact signs Tier C/D dispatch records and exposes chain head, gap
  count, artifact version, and selected action-event vocabulary in health. This
  is runtime action evidence; device-origin telemetry attestation is the
  firmware/Layer 1 contract.

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
    action_tier: B
    reasoning_policy: post_action # → switches source, explains after

  - name: critical_fault
    condition: "load_current > rated_capacity * 3.0"
    action_tier: C # → "Open protected load safety circuit? Reply YES-<proposal_id>/NO-<proposal_id>"

  - name: dangerous_overcurrent
    condition: "load_current > rated_capacity * 5.0"
    bypass_llm: true
    action_tier: D # → cuts power. no waiting.
```

Bundled skills: **pc-system-health** (runs on any laptop), **pc-network-threat-monitor**, **energy-anomaly-detector**, **prosumer-energy-advisor**, **retail-occupancy-optimizer**, **solar-performance-monitor**, **battery-lifecycle-observer**, **hvac-refrigerant-monitor**, and **site-safety-ppe**.

Community skills live at **[ori-platform/ori-skills](https://github.com/ori-platform/ori-skills)**. The runtime enforces strict skill validation and verified Ed25519 signatures for skills that do not ship with it. Community `hooks.py` execution is disabled pending the isolated-worker contract, so community skills are YAML-only in this release.

---

## The Tier C Approval Workflow

When Ori proposes a hard physical action, this is what the operator receives:

```text
ORI ALERT — Action Required
Device: energy-monitor-ikeja-office-01
Proposal ID: AB12CD34
Time: Wednesday 14:32

OBSERVATION:
Load current has reached 38.4A — 3.8x the rated 10A capacity.
Sustained for 45 seconds and climbing.

REASONING:
Pattern consistent with a short circuit, not a temporary surge.
Active fault propagation detected.

PROPOSED ACTION:
Open the installer-wired safety circuit to cut power to the protected load.

CONFIDENCE: 94%

Reply YES-AB12CD34 to approve  |  Reply NO-AB12CD34 to cancel
Auto-cancel in 5 minutes if no response.
```

The message is delivered over SMS (primary for Nigeria deployments) with automatic
failover to WhatsApp when SMS is unavailable, or WhatsApp-first when configured.
The same message format is used on both channels.

The agent does the diagnosis. The operator approves or rejects a specific, fully-reasoned proposal.

---

## Quick Start — No Hardware Needed

Ori's **pc-system-health** skill runs on any laptop using `psutil`. No Raspberry Pi, no sensors, no wiring.

> **Linux users:** To deploy a signed release as a service, see [docs/linux-install.md](docs/linux-install.md). To run from source for development, see [docs/linux-setup.md](docs/linux-setup.md) for a step-by-step setup guide, including a minimal validated config (`ori.linux.yaml.example`), Linux model paths, and troubleshooting for common Linux-specific issues.

```bash
# Clone and install
git clone https://github.com/ori-platform/ori-runtime.git
cd ori-runtime
python3 -m venv .venv
source .venv/bin/activate

# One-command dev bootstrap (deps + hooks + formatting baseline)
bash scripts/bootstrap.sh

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

## Install Targets

> **Deploying to a Linux device?** Use the signed release installer — see
> [docs/linux-install.md](docs/linux-install.md). It verifies a KMS-signed
> bundle before anything is unpacked, installs the runtime as a managed
> systemd service, and rolls back automatically if the new release is not
> healthy. The install shapes below are for development and downstream
> consumers, not for field deployment.

`ori-runtime` has two intentionally different install shapes:

```bash
# Product/demo consumers: typed rule-evaluation boundary only.
# This is what downstream FastAPI product/demo services should use for proof evaluation.
python -m pip install "ori-runtime[eval] @ git+https://github.com/ori-platform/ori-runtime.git@<commit-or-tag>"

# Runtime/device development: full transport, security, provider, and HAL deps.
python -m pip install -e ".[runtime,dev]"

# Edge deployment still uses the signed wheelhouse / hash-locked requirements path.
bash scripts/build-wheelhouse.sh
```

The base package deliberately installs only the dependency needed by
`ori.integration` (`PyYAML`) plus the packaged bundled skills. MQTT, SMS,
WhatsApp, OPC-UA, HTTP adapters, crypto transports, and hardware/provider
libraries live behind extras or the deployment wheelhouse. This keeps
product/demo consumers from inheriting the full device
runtime dependency surface while still using the real rule engine.

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
#   model_path: /Users/<you>/models       # macOS
#   # model_path: /home/<you>/models     # Linux

# 5) Optional dev convenience: auto-load .env before config parse
export ORI_AUTOLOAD_DOTENV=true

# 6) Start runtime
python -m ori.runtime --config ori.local.yaml

# 7) Optional: hot-reload skills without restart (Unix only)
# Reload applies to new events only; in-flight actions keep previous skill config.
kill -HUP "$(pgrep -f 'python -m ori.runtime' | head -n 1)"
```

### Smoke Tests

```bash
# Full runtime smoke test (auto-selects config by platform if arg #1 is omitted)
bash scripts/smoke-runtime-local.sh

# Linux explicit config (recommended)
bash scripts/smoke-runtime-local.sh ori.yaml

# Force pretty console output
ORI_PRETTY_LOGS=true bash scripts/smoke-runtime-local.sh

# Disable ANSI colors (CI/plain terminals)
ORI_PRETTY_LOGS=false bash scripts/smoke-runtime-local.sh

# Live host-health report (real psutil readings + skill trigger evaluation)
ORI_PRETTY_LOGS=true .venv/bin/python scripts/pc_health_report.py

# Release wheel smoke test
# Builds the wheel, installs it into a clean venv, verifies PEP 561 typing,
# bundled skill packaging, and a real Tier D rule evaluation through
# ori.integration.
bash scripts/smoke-release-wheel.sh

# Local SLM quality smoke test (without starting full runtime)
python - <<'PY'
import asyncio
from ori.reasoning.local_llm import LocalLLM

async def main():
    llm = LocalLLM(
        model_path="/Users/<you>/models/qwen2.5-0.5b-instruct-q4_k_m.gguf",  # macOS
        # model_path="/home/<you>/models/qwen2.5-0.5b-instruct-q4_k_m.gguf",  # Linux
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
bash scripts/typecheck-boundaries.sh          # Scoped mypy gate for public/runtime contracts
bash scripts/smoke-release-wheel.sh           # Installed-wheel release readiness smoke
```

The test suite covers all layers — HAL adapters, event bus, rule engine (with AST safety validation), action dispatcher (all four tiers), skill loader, state store, and runtime.

Run `scripts/smoke-release-wheel.sh` before tagging a runtime release. It is
deliberately stricter than an editable install: it builds the wheel, verifies
the wheel metadata keeps the base install slim for product/demo consumers,
installs runtime dependencies from hash-locked requirements, installs the wheel
with `--no-deps`, then verifies the public `ori.integration` rule-evaluation
boundary is typed (`ori/py.typed`) and can resolve bundled skill data from the
installed artifact. This protects downstream product/demo API paths from
type-checker ignores, accidental dependency bloat, and source-checkout-only
packaging mistakes.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting, supported versions, and disclosure policy.

---

## Roadmap

| Phase             | Status           | Milestone                                                                 |
| ----------------- | ---------------- | ------------------------------------------------------------------------- |
| Runtime core      | ✅ Stable v2.2    | Production posture, typed integration boundary, and evidence Layer 2 hooks |
| Product wedge     | ✅ Shipping       | Ori Energy demo/API integration, private APK path, and Phone Starter flows |
| Evidence hardware | 🔨 In Progress   | Evidence Layer 1 contract and `ori-edge-firmware` bootstrap                |
| Safety kernel     | 🗓️ Planned       | Rust-owned Tier D kernel after shadow-mode evidence, not a broad rewrite   |
| Growth            | 🗓️ Planned       | Skills Hub, Edge Node hardware, ori-cloud, and enterprise pilots           |

---

## Contributing

We welcome contributions! Start here:

1. **Read the design philosophy:** [`PRINCIPLES.md`](PRINCIPLES.md)
2. **Read the contributor guide:** [`CONTRIBUTING.md`](CONTRIBUTING.md)
3. **Understand the extension points:** [`AGENTS.md`](AGENTS.md)

```bash
pip install -e ".[runtime,dev]"
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
