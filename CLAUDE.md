# CLAUDE.md — Ori Runtime: AI Developer Context

This file is read automatically by Claude Code at the start of every session.
Read it completely before writing any code. It contains every architectural
decision that has been made. Do not relitigate them.

---

## What Ori Is

Ori is an open-source, offline-first **agentic** IoT runtime. It gives physical
devices the ability to reason about sensor data AND take autonomous physical
actions based on that reasoning. It is the production implementation of the
Agents of Things (AoT) concept from the 2013 IEEE paper by Mzahm, Ahmad, and Tang.

**Critical framing:** Ori is not a monitoring and alerting system. A monitoring
system detects and reports. An agent detects, reasons, and acts. Every design
decision must preserve and reinforce Ori's agency — the ability to take
physical actions autonomously when configured to do so.

**The distinction that matters:**

- Traditional IoT: "Current draw is 8.2A. ALERT: threshold exceeded."
- Ori: "Your AC unit has been drawing 40% above baseline for three afternoons.
  Pattern suggests refrigerant depletion. Estimated failure: 2 weeks.
  I have sent a service reminder to your maintenance contact."
  OR: "Dangerous overcurrent detected. I have tripped the safety relay."

**Elevator pitch:** Ori is to IoT what Grafana was to observability — an
open-source runtime that becomes the intelligence and action layer every
physical system runs on, monetised through ori-cloud and enterprise features.

**The design philosophy governing every architectural decision in this codebase is documented in PRINCIPLES.md. Read it before making any structural change.**

---

## Architecture: Six Layers

```text
Layer 6  Business      ori-cloud · ori-dashboard · fleet management
Layer 5  Application   Skills · Skills Hub · Skills SDK
Layer 4  Reasoning + Action  Intelligence Elevator + Action Tier Framework
Layer 3  Middleware     Ori Runtime (event loop, skill loader, action dispatcher)
Layer 2  Network        EventBus · ProtocolNormaliser · Deduplicator
Layer 1  Perception     Sensor HAL (GPIO, I2C, Serial, MQTT, psutil)
```

Layers 1–4 run on the device. Layer 5 is the community. Layer 6 is the business.
**Layers 3 and 4 are paired systems** — reasoning and action are inseparable.
Every reasoning result carries an action tier. Every action tier determines
the approval model before execution.

---

## The Intelligence Elevator (Layer 4) — Reasoning

```text
Tier 1  RULE ENGINE    microseconds  always available  safety-critical + Tier D actions
Tier 2  LOCAL SLM      3-8 seconds   offline-capable   most everyday reasoning
Tier 3  GATEWAY LLM    1-3 seconds   LAN required      cross-device or cloud-backed reasoning
```

The runtime selects the cheapest tier that can answer the question.
Tier 1 is always evaluated first. Gateway reasoning is reached only through
deterministic escalation policy or an explicit trigger floor. Cloud reasoning,
when used, is a gateway backend, not a runtime dependency. The reasoning tier
and action tier are selected together — they are not independent decisions.

Runtime-gateway MQTT envelopes are optionally HMAC-authenticated. Production
sites set `gateway.auth.enabled: true` and provide the shared secret through the
environment variable named by `gateway.auth.shared_secret_env`. The gateway
secret is separate from remote-command secrets. Authenticated deployments sign
runtime reasoning requests and export responses, and verify gateway reasoning
responses and export requests before using them.

---

## The Action Tier Framework (Layer 4) — The Agent's Authority

This is the architectural concept that makes Ori genuinely agentic rather than
a glorified dashboard. Every action the runtime can take is classified into one
of four tiers. The tier determines whether the action fires autonomously, whether
it requires operator approval, and whether it can be overridden.

```text
Tier A  INFORMATIONAL        Always autonomous. No approval. No override.
        WhatsApp alerts, SMS, dashboard logs, reasoning logs.
        These ARE agent actions. When Ori sends a reasoned WhatsApp message,
        no human approved it first. The agent reasoned and acted.

Tier B  SOFT PHYSICAL        Explicit approval or post-action policy.
        Switching power sources, adjusting thermostat setpoints,
        opening irrigation valves, dimming lights.
        Reversible, low-consequence. Use requires_approval: true or
        reasoning_policy: post_action on physical Tier B triggers.

Tier C  HARD PHYSICAL        Approval workflow. Always. No exception.
        Opening relay/contactor-controlled safety circuits,
        high-pressure valve control.
        Ori reasons → proposes action via WhatsApp → operator replies YES/NO
        → action executes or is cancelled.
        The agent does the diagnosis. The human approves the surgery.

Tier D  SAFETY-CRITICAL      Always autonomous. Highest priority. Overrides all.
        Cannot be disabled. Cannot be overridden. Fires before any LLM.
        Dangerous overcurrent, temperature above safe limit, hazardous gas.
        bypass_llm: true is set automatically for all Tier D triggers.
```

**The complete decision tree:**

```text
Sensor reading arrives
    │
    ▼
RULE ENGINE — First: Is this Tier D?
    YES → Execute Tier D action immediately. No LLM. Full stop.
    NO  → Evaluate normal rules
          Rule matched, bypass_llm: true → Execute Tier D action, return
          Rule matched, bypass_llm: false → Escalate to SLM with tier hint
          No rule matched → Escalate to LOCAL SLM
    │
    ▼
LOCAL SLM — Returns: reasoning text, confidence, recommended action tier
    │
    ▼
ACTION DISPATCHER
    Tier A → Execute informational action immediately
    Tier B → Execute soft physical action before explanation when
             reasoning_policy: post_action, or use approval workflow
    Tier C → Run approval workflow. Send WhatsApp. Wait for YES/NO.
    Tier D → Already handled above. Never reaches dispatcher.
```

---

## Canonical Data Types

Every function that touches sensor data uses one of these. Never bypass them.

```python
# ori/network/events.py

from dataclasses import dataclass, field
from typing import Optional
import uuid

@dataclass
class SensorReading:
    sensor_id:   str
    sensor_type: str        # 'temperature' | 'current' | 'voltage' | 'humidity' etc.
    value:       float
    unit:        str        # 'celsius' | 'ampere' | 'volt' | 'percent' etc.
    timestamp:   int        # unix milliseconds, always UTC
    quality:     float      # 0.0 to 1.0
    metadata:    dict = field(default_factory=dict)
    raw:         Optional[bytes] = None

@dataclass
class OriEvent:
    event_id:    str
    event_type:  str        # 'sensor.reading' | 'device.heartbeat' | 'skill.trigger'
    device_id:   str
    sensor_id:   str
    timestamp:   int        # unix milliseconds, always UTC
    reading:     Optional[SensorReading]
    context:     dict = field(default_factory=dict)
    source:      str = ''   # 'gpio' | 'i2c' | 'serial' | 'mqtt' | 'sysfs' | 'psutil'
    fingerprint: str = ''

    @classmethod
    def from_reading(cls, reading: SensorReading, device_id: str) -> 'OriEvent':
        return cls(
            event_id=str(uuid.uuid4()),
            event_type='sensor.reading',
            device_id=device_id,
            sensor_id=reading.sensor_id,
            timestamp=reading.timestamp,
            reading=reading,
            source=reading.metadata.get('source', ''),
        )

@dataclass
class ActionResult:
    """Returned by ActionDispatcher after every action attempt."""
    action_name:   str
    tier:          str          # 'A' | 'B' | 'C' | 'D'
    executed:      bool
    approved:      bool | None  # None for Tiers A/B/D (no approval step)
    action_taken:  str          # actual action executed (may be safe_default)
    timestamp:     int
    operator_response: str | None = None

@dataclass
class ReasoningResult:
    """Returned by the Intelligence Elevator after every reasoning call."""
    text:          str
    tier:          str          # 'rule' | 'local_slm' | 'gateway'
    model:         str
    tokens_used:   int
    latency_ms:    int
    confidence:    float = 0.0
    action_tier:   str = 'A'   # Default: informational only
    proposed_action: str | None = None
```

---

## Directory Structure

```bash
ori/
├── AGENTS.md
├── CLAUDE.md
├── PRINCIPLES.md
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
├── pyproject.toml
├── requirements.in
├── requirements.txt
├── requirements-dev.in
├── requirements-dev.txt
├── ori.yaml.example
├── ori.linux.yaml.example
├── ori.yaml.phone.example
│
├── docs/
│   ├── CAPABILITY_MATRIX.md
│   ├── linux-setup.md
│   └── releases/
│
├── scripts/
│   └── guard-capability-matrix.sh
│
├── ori/
│   ├── __init__.py
│   ├── runtime.py             ← main event loop — build last
│   ├── config.py              ← ori.yaml loader and validator
│   │
│   ├── utils/
│   │   ├── bool_utils.py
│   │   └── time_utils.py
│   │
│   ├── gateway/
│   │   ├── export.py          ← MQTT export responder for gateway data requests
│   │   └── reasoning.py       ← MQTT request/response client for Tier 3 reasoning
│   │
│   ├── hal/                   ← Hardware Abstraction Layer (Layer 1)
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── i2c_adapter.py
│   │   ├── serial_adapter.py
│   │   ├── mqtt_adapter.py    ← Generic MQTT telemetry adapter
│   │   ├── psutil_adapter.py  ← PC-Ori, no hardware needed
│   │   ├── smart_adapter.py
│   │   ├── http_adapter.py
│   │   ├── opcua_adapter.py
│   │   ├── victron_adapter.py
│   │   ├── growatt_adapter.py
│   │   └── ... (LoRaWAN, Zigbee, USB-Serial, MQTT perception adapters)
│   │
│   ├── network/               ← Network Layer (Layer 2)
│   │   ├── __init__.py
│   │   ├── events.py          ← OriEvent + SensorReading + ActionResult — BUILD FIRST
│   │   ├── event_bus.py
│   │   ├── deduplicator.py
│   │   └── sms_webhook.py
│   │
│   ├── reasoning/             ← Intelligence Elevator + Action Tiers (Layer 4)
│   │   ├── __init__.py
│   │   ├── elevator.py        ← tier selector
│   │   ├── rule_engine.py     ← deterministic rules — BUILD BEFORE LLM
│   │   ├── local_llm.py       ← llama-cpp-python wrapper
│   │   ├── causal_memory.py   ← SQLite pattern cache
│   │   ├── capability_posture.py
│   │   └── action_dispatcher.py ← ACTION TIER ROUTER — the agent's executor
│   │
│   ├── hardware/
│   │   ├── __init__.py
│   │   └── led_indicator.py
│   │
│   ├── policy/
│   │   ├── device_policy.py
│   │   └── remote_fetch.py
│   │
│   ├── security/
│   │   ├── __init__.py
│   │   └── offline_tokens.py
│   │
│   ├── skills/                ← Skills loader (Layer 5)
│   │   ├── __init__.py
│   │   ├── loader.py
│   │   ├── hooks_api.py
│   │   ├── sandbox.py
│   │   └── signing.py
│   │
│   ├── actions/               ← Action executors (called by action_dispatcher)
│   │   ├── __init__.py
│   │   ├── whatsapp.py        ← Twilio / WhatsApp Cloud API
│   │   ├── sms.py             ← Africa's Talking (PRIMARY for Nigeria)
│   │   ├── relay.py           ← Physical relay control (GPIO output)
│   │   ├── alert_failover.py  ← Failover alert transport wrapper
│   │   ├── coap.py            ← CoAP action executor for constrained devices
│   │   ├── process_manager.py
│   │   ├── system_control.py
│   │   └── logger.py
│   │
│   └── state/
│       ├── __init__.py
│       └── store.py
│
├── skills/
│   ├── template/
│   │   ├── skill.yaml
│   │   └── hooks.py
│   ├── energy-anomaly-detector/
│   │   ├── skill.yaml
│   │   └── hooks.py
│   ├── hvac-refrigerant-monitor/
│   │   ├── skill.yaml
│   │   └── hooks.py
│   ├── pc-network-threat-monitor/
│   │   ├── skill.yaml
│   │   └── hooks.py
│   ├── site-safety-ppe/
│   │   ├── skill.yaml
│   │   └── hooks.py
│   └── pc-system-health/
│       ├── skill.yaml
│       └── hooks.py           ← uses HookContext dynamic API
│
└── tests/
    ├── __init__.py
    ├── test_action_dispatcher.py
    ├── test_config.py
    ├── test_elevator.py
    ├── test_led_indicator.py
    ├── test_remote_policy_fetch.py
    ├── test_offline_tokens.py
    └── ... (full suite in tests/)
```

---

## Build Order

Follow this sequence exactly. Each module depends on the previous.

```text
Step 1   ori/network/events.py          ← SensorReading, OriEvent, ActionResult, ReasoningResult
Step 2   ori/config.py                  ← ori.yaml loader with action_tier support
Step 3   ori/state/store.py             ← SQLite wrapper + action_log table
Step 4   ori/hal/base.py                ← BaseAdapter interface
Step 5   ori/hal/psutil_adapter.py      ← testable on any laptop, no hardware
Step 6   ori/network/deduplicator.py
Step 7   ori/network/event_bus.py
Step 8   ori/reasoning/rule_engine.py   ← includes bypass_llm + action_tier on rules
Step 9   ori/hal/i2c_adapter.py         ← requires Pi
Step 10  ori/hal/serial_adapter.py      ← requires energy meter
Step 11  ori/reasoning/local_llm.py
Step 12  ori/reasoning/elevator.py
Step 13  ori/reasoning/causal_memory.py
Step 14  ori/skills/loader.py
Step 15  ori/reasoning/action_dispatcher.py  ← THE ACTION ENGINE
Step 16  ori/actions/whatsapp.py        ← includes approval_workflow response listener
Step 17  ori/actions/sms.py             ← Africa's Talking primary channel
Step 18  ori/actions/relay.py           ← GPIO output for physical control
Step 19  ori/actions/logger.py
Step 20  ori/runtime.py                 ← ties everything together
```

**Current build state:** All 20 steps complete. Runtime is operational.

---

## The Action Dispatcher — Key Implementation Details

```python
# ori/reasoning/action_dispatcher.py

class ActionTier:
    INFORMATIONAL   = 'A'
    SOFT_PHYSICAL   = 'B'
    HARD_PHYSICAL   = 'C'
    SAFETY_CRITICAL = 'D'

class ActionDispatcher:
    async def dispatch(self, action: str, tier: str,
                       context: SkillContext,
                       result: ReasoningResult) -> ActionResult:

        if tier == ActionTier.SAFETY_CRITICAL:
            return await self._execute_immediately(action, context)

        if tier == ActionTier.INFORMATIONAL:
            return await self._execute_immediately(action, context)

        if tier == ActionTier.SOFT_PHYSICAL:
            if context.skill_config.get('requires_approval', False):
                return await self._approval_workflow(action, context, result)
            return await self._execute_immediately(action, context)

        if tier == ActionTier.HARD_PHYSICAL:
            # Always approval workflow. No exception.
            return await self._approval_workflow(action, context, result)

    async def _approval_workflow(self, action, context, result) -> ActionResult:
        # 1. Send WhatsApp/SMS with reasoning + proposed action via AlertFailoverSender
        #    (tries primary channel first, falls back to secondary on failure)
        # 2. Wait for YES/NO within approval_timeout_seconds (default: 300)
        # 3. YES → execute action
        # 4. NO or timeout → execute safe_default_action, log override
        # 5. No response after 2x timeout → escalate to secondary_contact
        ...
```

The approval message template that appears on the operator's WhatsApp:

```text
ORI ALERT — Action Required
Device: {device_id}
Time: {day_name} {HH:MM}   ← local time in device.timezone (default: Africa/Lagos)

OBSERVATION:
{result.text}

REASONING:
{result.reasoning if set, else result.text}

PROPOSED ACTION:
{action_description}

CONFIDENCE: {result.confidence:.0%}

Reply YES to approve  |  Reply NO to cancel
Auto-cancel in {timeout} seconds if no response.
```

---

## The Skill YAML Format — Full with Action Tiers

```yaml
name: energy-anomaly-detector
version: 0.2.1
author: wasiubakare
license: MIT
signature: ed25519:...

sensors_required:
  - type: current_clamp
  - type: voltage

# Each trigger declares its action_tier explicitly
triggers:
  # Tier A: Informational — always autonomous
  - name: anomalous_draw
    condition: "load_current > (history.avg_24h('load_current') * 1.4)"
    cooldown_seconds: 300
    escalate_to: local_slm
    action_tier: A

  # Tier B: Soft physical — switch source, explain after action
  - name: source_switch_recommended
    condition: "grid_voltage < 180 and inverter_battery > 0.4"
    cooldown_seconds: 60
    escalate_to: rule
    action_tier: B
    reasoning_policy: post_action

  # Tier C: Hard physical — propose relay/contactor-controlled shutdown, await approval
  - name: critical_fault
    condition: "load_current > rated_capacity * 3.0"
    cooldown_seconds: 0
    escalate_to: rule
    action_tier: C
    approval_timeout_seconds: 300
    safe_default_action: log_to_dashboard

  # Tier D: Safety-critical — immediate autonomous cutoff
  - name: dangerous_overcurrent
    condition: "load_current > rated_capacity * 5.0"
    bypass_llm: true
    action_tier: D
    cooldown_seconds: 0

prompts:
  anomalous_draw: |
    Current load: {load_current}A
    24-hour average: {history.avg_24h('load_current')}A
    Recent history: {history.last_n('load_current', 6)}
    Time: {time} on {day_of_week}
    Grid: {grid_voltage}V

    Is this anomalous? Most likely cause? What should the owner do?
    Answer in plain English, 2-3 sentences, no jargon.

actions:
  available:
    - name: alert_whatsapp
      tier: A

    - name: alert_sms
      tier: A

    - name: log_to_dashboard
      tier: A

    - name: switch_power_source
      tier: B
      requires_approval: false # true = operator must approve each switch

    - name: open_safety_circuit
      tier: C
      approval_message: |
        PROPOSED: Open the installer-wired safety circuit.
        REASON: {result.text}
        Reply YES to approve or NO to cancel.

    - name: emergency_cutoff
      tier: D

  defaults:
    anomalous_draw: [alert_whatsapp, log_to_dashboard]
    source_switch_recommended: [switch_power_source, alert_sms]
    critical_fault: [open_safety_circuit]
    dangerous_overcurrent: [emergency_cutoff]
    daily_report: [alert_whatsapp]
```

---

## The ori.yaml Format — Device Configuration

```yaml
device:
  id: energy-monitor-ikeja-01
  name: Ikeja Office Energy Monitor
  location: Lagos, Nigeria
  rated_capacity_amps: 10.0 # Used in Tier D threshold calculations

sensors:
  - id: load-current
    type: current_clamp
    protocol: i2c
    address: 0x48
    channel: 0
    poll_interval_ms: 1000

  - id: grid-voltage
    type: voltage
    protocol: i2c
    address: 0x48
    channel: 1
    poll_interval_ms: 2000

skills:
  - name: energy-anomaly-detector
    version: "0.2.1"
    config:
      energy_cost_naira: 225
      requires_approval_for_soft_actions: false
      approval_timeout_seconds: 300
      safe_default_action: log_to_dashboard
      secondary_contact_number: ${SECONDARY_WHATSAPP}

reasoning:
  default_tier: local
  local_model: qwen2.5-0.5b-instruct-q4_k_m
  model_path: /home/pi/models/
  offline_fallback: rule

gateway:
  enabled: false
  broker_url: mqtt://192.168.1.10:1883
  auth:
    enabled: false
    shared_secret_env: GATEWAY_SHARED_SECRET
    max_clock_skew_ms: 300000
    replay_ttl_ms: 300000
  reasoning:
    enabled: true
    timeout_ms: 10000

actions:
  primary_alert_channel: sms # 'sms' | 'whatsapp' — use sms for Nigeria
  whatsapp:
    enabled: true
    to_number: "${OWNER_WHATSAPP_NUMBER}"
  sms:
    enabled: true # Africa's Talking — primary for Nigeria
    to_number: "${OWNER_PHONE_NUMBER}"
  relay:
    enabled: false # true when physical relay is wired
    gpio_pin: 26
  coap:
    enabled: false
    timeout_s: 2.0
    retries: 1
    allowed_hosts: ["192.168.1.70"]
    commands:
      open_bypass_valve:
        uri: "coap://192.168.1.70/actuators/bypass"
        method: POST
        payload: '{"state":"open"}'

logging:
  level: INFO
  file: ori.log
```

---

## Coding Conventions

**Language:** Python 3.11+ with asyncio throughout. Type hints on every function.

**Naming:**

- Files: `snake_case`
- Classes: `PascalCase`
- Functions/variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Action tiers: always single uppercase letter `'A'`, `'B'`, `'C'`, `'D'`
- Sensor types: lowercase strings `'temperature'`, `'current'`
- Event types: dot-separated strings `'sensor.reading'`, `'skill.trigger'`

**Every new Python file must start with these two lines before any imports:**

```text
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
```

Run `ruff check --fix` on every file you create before finishing.

**Error handling:**

- HAL adapters raise `AdapterConnectionError` or `AdapterTimeoutError`
- Action dispatcher catches all action errors — a failed action MUST NOT crash
  the runtime. Log the failure, continue.
- Approval workflow timeouts are handled gracefully — always execute
  `safe_default_action` on timeout, never leave a Tier C action unresolved.

**Async patterns:**

```python
# CORRECT
await asyncio.sleep(1)           # never time.sleep()
async with aiofiles.open(...)    # never open() for file I/O in async context
asyncio.create_task(fn())        # for background tasks

# WRONG — never block the event loop
time.sleep(1)
requests.get(url)                # use httpx or aiohttp
```

**Action dispatcher is fire-and-track:**
The dispatcher is called after every reasoning result. It MUST:

1. Never block the event loop while waiting for operator approval
2. Use asyncio.wait_for() with timeout for approval responses
3. Always produce an ActionResult, even on failure
4. Log every action attempt to the action_log table in SQLite

**SQLite tables (add to store.py):**

```sql
-- In addition to existing tables from V1.0:
CREATE TABLE IF NOT EXISTS action_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_name TEXT NOT NULL,
    tier TEXT NOT NULL,
    executed INTEGER NOT NULL,  -- 0 or 1
    approved INTEGER,           -- NULL for A/B/D, 0/1 for C
    action_taken TEXT NOT NULL,
    operator_response TEXT,
    trigger_name TEXT,
    timestamp INTEGER NOT NULL
);
```

---

## Platform and Hardware Notes

**HAL adapters degrade gracefully on non-Pi hardware.**

On non-Pi platforms (developer laptops, CI, cloud servers), hardware
libraries like `gpiozero`, `smbus2`, and `RPi.bme280` are unavailable.
Every HAL adapter guards its imports with `try/except ImportError` and
enters simulation mode when the library is missing:

- `connect()` succeeds and logs a WARNING
- `read()` returns simulated or cached values
- No hardware is touched

This is intentional. It allows the full reasoning pipeline, EventBus,
StateStore, and action dispatcher to be exercised in tests and on
developer machines without a Pi. The 5 skipped tests in the suite
require a real Pi with `gpiozero` installed.

**On non-Pi hardware, I2C and serial adapters run in simulation mode.**
If `protocol: i2c` or `protocol: serial` appears in ori.yaml on a
machine without the Pi hardware libraries, `_make_adapter()` returns
the adapter successfully, `connect()` logs a WARNING and sets
`_simulated = True`, and all subsequent `read()` calls return
simulated values. This is not a bug — it is the same path used in
all HAL tests.

**The supported protocols on a production Pi are:**

- `psutil` — system metrics, no additional hardware required
- `i2c` — requires `smbus2`, `gpiozero`, and sensor-specific libraries
- `serial` — requires `pyserial` and a connected RS485/Modbus device

Any other protocol in ori.yaml raises `ConfigValidationError` at
startup before the event loop begins.

**Relay wiring safety:**
Always use Normally Closed (NC) relay terminals. NC wiring means the
load is disconnected when the relay is de-energised. Power loss or
an Ori crash defaults the system to the safe state without software
intervention. Never use Normally Open (NO) terminals for any load
that must be de-energised on failure.

---

## What NOT To Do

- **No monitoring-only mindset.** Never describe Ori as "monitoring and alerting."
  Ori is an agent that acts. Monitoring is a side effect of its sensor layer.
- **No flat action lists.** Every action in a skill YAML must declare its tier.
  An action with no tier is a configuration error.
- **No approval bypass for Tier C.** The approval workflow for hard physical
  actions cannot be skipped, disabled, or made optional in config. If a skill
  defines a Tier C action, the approval workflow runs. No exceptions.
- **No LLM for Tier D.** Safety-critical actions fire from the rule engine.
  `bypass_llm: true` is set automatically for any trigger with `action_tier: D`.
- **No microservices at device layer.** Modular monolith only.
- **No ORM.** Direct sqlite3 with parameterised queries.
- **No global state.** All state passes explicitly.
- **No synchronous blocking calls.** Everything is async.
- **No circuit breaker bypass**. Every adapter subclass must initialize `self._breaker = HardwareCircuitBreaker(adapter_name, config)` and securely wrap its physical I/O tasks within the asynchronous `async with self._breaker:` context manager to effortlessly provide hardware recovery.

---

## Testing the Action Dispatcher

```python
# tests/test_action_dispatcher.py

# Test Tier A: informational action fires immediately
async def test_tier_a_fires_immediately():
    ...

# Test Tier B post-action: soft physical executes before reasoning
async def test_tier_b_post_action_dispatches_before_reasoning():
    ...

# Test Tier B configured: soft physical requests approval when requires_approval: true
async def test_tier_b_approval_when_configured():
    ...

# Test Tier C: hard physical always waits for approval
async def test_tier_c_sends_approval_request():
    ...

# Test Tier C approval YES: action executes after YES response
async def test_tier_c_executes_on_yes():
    ...

# Test Tier C approval NO: safe_default executes after NO response
async def test_tier_c_safe_default_on_no():
    ...

# Test Tier C timeout: safe_default executes after timeout
async def test_tier_c_safe_default_on_timeout():
    ...

# Test Tier D: fires immediately, bypasses dispatcher routing
async def test_tier_d_bypasses_dispatcher():
    ...
```

---

## Environment Variables

```bash
# Alert delivery
OWNER_WHATSAPP_NUMBER=whatsapp:+234XXXXXXXXXX
OWNER_PHONE_NUMBER=+234XXXXXXXXXX
SECONDARY_WHATSAPP=whatsapp:+234XXXXXXXXXX  # Escalation contact for Tier C no-response

# WhatsApp (Twilio or WhatsApp Cloud API)
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_WHATSAPP_FROM=whatsapp:+14155238886

# Africa's Talking (PRIMARY for Nigeria)
AT_API_KEY=
AT_USERNAME=
AT_SENDER_ID=ORI

# Cloud provider keys belong in the gateway/product environment, not runtime.
GATEWAY_SHARED_SECRET=  # Site-local MQTT envelope HMAC secret.

# Relay control (if physical relay wired)
RELAY_GPIO_PIN=26
```

---
