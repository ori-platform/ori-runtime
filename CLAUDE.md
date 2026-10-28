# CLAUDE.md — Ori Runtime: AI Developer Context

Read automatically at the start of every session. It holds the architectural
decisions; do not relitigate them. The design philosophy is in `PRINCIPLES.md`;
read it before any structural change. Navigation and extension recipes are in
`AGENTS.md`; the reasoning behind each decision is in `DECISIONS.md`.

This file states rules and points to where their detail lives. Do not copy code,
schemas or examples into it: name the file instead.

---

## What Ori Is

Ori is an open-source, offline-first **agentic** IoT runtime: devices reason
about sensor data and take autonomous physical actions on that reasoning. It is
the production implementation of Agents of Things (Mzahm, Ahmad and Tang, IEEE
2013).

Ori is not a monitoring and alerting system. A monitor detects and reports; an
agent detects, reasons and acts ("Overcurrent detected. I have tripped the
safety relay."). Every design decision must preserve that agency.

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

Layers 1–4 run on the device. Layers 3 and 4 are paired: every reasoning result
carries an action tier, and the tier decides the approval model.

---

## The Intelligence Elevator (Layer 4)

```text
Tier 1  RULE ENGINE   microseconds  always available  safety-critical + Tier D
Tier 2  LOCAL SLM     3-8 seconds   offline-capable   most everyday reasoning
Tier 3  GATEWAY LLM   1-3 seconds   LAN required      cross-device or cloud-backed
```

The runtime selects the cheapest tier that can answer, evaluating Tier 1 first.

- **Escalation is deterministic.** The gateway is reached only by signals
  evaluated before local inference: explicit `escalate_to: gateway`, a missing
  baseline, a history query failure, a calibrated range breach or a
  related-sensor conflict. Local SLM confidence is telemetry only (currently 0.0
  for base completion backends) and is never the sole reason to stay on-device
  or escalate.
- **Gateway reasoning is MQTT request/response** on
  `ori/{device_id}/reasoning/request` and `ori/{device_id}/reasoning/response`,
  provider-neutral. Cloud reasoning is a gateway backend: no cloud SDK enters
  the runtime.
- **Reasoning grants no authority.** For a matched trigger the trigger's tier
  is authoritative. Unmatched gateway reasoning never creates physical action
  authority: a proposal above Tier A is dropped to `log_to_dashboard`.

**Gateway transport security** (`docs/MQTT_SECURITY.md`):

- Runtime-gateway MQTT envelopes are HMAC-authenticated with the secret named by
  `gateway.auth.shared_secret_env`, separate from remote-command secrets.
  `previous_shared_secret_env` is verify-only during rotation.
- `gateway.encryption.enabled` encrypts the `sensor_history`, `action_log`,
  `reasoning_log` and `tier_c_decision_log` export responses with an
  HKDF-derived AES-GCM key. It requires authenticated envelopes.
- TLS (`mqtts://`, `gateway.tls`) is defense-in-depth and replaces neither HMAC
  nor payload encryption.
- Staging and production require auth and encryption on every enabled gateway
  broker, loopback included, plus TLS, credentials and declared broker posture
  for non-loopback brokers, at config load. Development logs one WARNING.
- Production brokers disable anonymous access, use separate runtime and gateway
  users, and apply per-device topic ACLs.

**SMS webhook ingress** (`docs/SMS_WEBHOOK_SECURITY.md`): a sender allowlist
cannot prove carrier origin. Internet-exposed Africa's Talking ingress needs
source CIDR allowlisting plus an HMAC signing bridge.

**Remote command lockout:** with
`security.remote_commands.lockout.enforcement_enabled: true`, critical-risk
senders are blocked before a command can mutate state. Production requires it
when remote commands are enabled.

---

## The Action Tier Framework (Layer 4)

```text
Tier A  INFORMATIONAL    Always autonomous. Alerts, SMS, logs. These are agent acts.
Tier B  SOFT PHYSICAL    Reversible, low consequence. requires_approval: true, or
                         reasoning_policy: post_action (never both).
Tier C  HARD PHYSICAL    Approval workflow, always: propose, operator replies
                         YES/NO, then execute or cancel.
Tier D  SAFETY-CRITICAL  Always autonomous, attempted before lower work, before any
                         LLM; cannot be disabled or overridden. bypass_llm is set
                         automatically.
```

**The letter is two axes, not a severity scale.** Treating A→D as rising
severity has produced defects three times.

- **Consequence class** (`informational`, `soft`, `hard`): what the act does to
  the world. Whether opening a circuit is reversible is a fact about site
  wiring, established per channel at commissioning, so the runtime registry
  owns it.
- **Authority basis** (`autonomous`, `operator_approval`, `safety_condition`):
  what licenses one dispatch.

So A is informational/autonomous; B is soft, autonomous or approved per
deployment; C is hard/approved; D is hard under a release-owned safety
condition. Consequences:

- A and D are both autonomous. A notice accompanying a trip never inherits the
  trip's authority; any rule taking a maximum over tiers exempts informational
  actions.
- `requires_approval` moves a Tier B action along the authority axis without
  changing its letter.
- A Tier D floor is a category error: `trip_relay` is registered at a hard floor
  and reaches D only through a safety condition.

`skills-package/v3.md` (ori-specs) carries the reasoning; `evidence/v2.md`
records the authority basis on every attested action.

**The runtime owns the floor, and owns Tier D outright.** `skill.yaml` is
untrusted input.

- **Minimum tier, runtime-owned.** `ori/reasoning/action_registry.py` records,
  per executable action, its minimum tier, whether it actuates, and whether it
  may be a Tier C safe default. A skill may raise a tier, never lower it.
- **Tier D, by provenance only.** Tier D triggers are accepted only from skills
  that ship with the runtime (`Skill.first_party`, set by the loader, never read
  from YAML). Escalation into D from `actions.available` is capped at C.
- **A capability grant governs Tier A to C only and never confers D.**
  `device_policy.py` returns for Tier D before it consults expiry
  (`device-policy/v2.md`). Safety authority must not go stale.
- **The end state is `safety-profile/v1.md`:** release-owned typed conditions
  bound to a commissioned zone, with the safety registry (`ori/safety/`) as the
  sole Tier D path once #324 lands. Every packaged `action_tier: D` is legacy
  against it. Nothing deployment-supplied reaches a profile: no config value,
  remote command, DevicePolicy or entitlement alters a condition, multiplier,
  threshold or outcome. A capacity arrives only through the commissioned
  binding.

**Every layer fails closed on its own.** The floor is enforced at skill load,
at dispatch and again in `_execute_immediately`. The trigger tier clamp is
reapplied after every extension boundary. The reading names (`value`,
`sensor_id`, `sensor_type`, `unit`, `quality`) are reserved at load, stripped
where hook output merges, and assigned unconditionally in the rule engine. A
check that holds only because an earlier check held is not a boundary.
`register_executor()` refuses an action with no registry entry; add the entry in
the same change.

**Skill provenance is positive.** A skill is first-party because it ships inside
the package (`_is_core_bundled_skill`), never because its path failed to match
another directory. Everything else must carry a verified signature. Community
hooks do not execute: a non-first-party skill carrying `hooks.py` is refused,
and isolated execution is being specified in ori-specs first.

**Dispatch order** (`docs/DISPATCH_PLAN.md` holds the full tree and reasoning):

1. **Discovery barrier.** One event, every skill that declares the reading's
   sensor type, every matching trigger collected before any reasoning is
   scheduled. Declaration order decides nothing. Tier D conditions read only the
   reading and the skill's configuration (the loader refuses anything else), so
   they are decided before any hook runs or history is read. No cooldown or
   in-flight hold reads or charges against a Tier D attempt: a plan granting
   Tier D dispatches it on every matching reading, only the plan's other
   actions wait, and cooldown is charged against their outcome.
2. **The plan.** Each action at its own authority: informational → A; the
   licensed protective outcome with every clause of the grant → D; otherwise
   `min(C, max(registry floor, declared tier))`. An ungoverned action, or one
   needing a commissioned zone that has none, is refused here.
3. **Tier D first,** across the whole discovery set, before any reasoning task.
   Tier A notices still run, and an opposing act already running is not
   interrupted. Foreclosure belongs to the event: its lower-authority opposite is refused for
   that event even after the act completes; a later event's trip is never
   absorbed and a failed act is never joined.
4. **Local SLM** for what remains.
5. **Dispatcher** admits against the resource an action drives, never its name:
   the same outcome coalesces, the opposite conflicts. Then A executes; B
   executes (post_action) or asks; C asks for a scoped `YES-<proposal_id>` /
   `NO-<proposal_id>`; D executes.

---

## The Action Dispatcher

`ori/reasoning/action_dispatcher.py`. Tier B approval is decided by the matched
trigger's `requires_approval` (`skill.config` only when no trigger matches
`context.trigger_name`). The approval message template is built there and in
`ori/actions/whatsapp.py`; its
`Measured:` line is the reading's own time as the device reported it, and
`Detected:` the runtime's clock, both in `device.timezone`.

**Host-state approval workflow** (Tier C host actions, Tier B with approval):
send through `AlertFailoverSender`, wait for the scoped reply within
`approval_timeout_seconds` (default 300). YES executes; NO, an invalid reply or
timeout executes `safe_default_action`. A timeout also notifies
`actions.secondary_contact` once; that notice carries no approval authority and
nothing re-asks.

**Governed approval** (a physical Tier C action on a commissioned zone,
`tier-c-approval/v1`):

- The proposal row (zone, binding digest, authority snapshot, monotonic
  deadline) commits before anyone is asked.
- A reply is an approval only inside one store transaction that matches binding
  and authority bytes, finds no unresolved dispatch of the same outcome on the
  zone, reserves a terminal record, and claims any v2 token.
- Dispatch follows at once with nothing written ahead of the executor; the
  marker lands beside it and the outcome after it.
- Expired, rejected, blocked or changed: one non-actuating safe-default intent,
  the operator told why. A decision that precedes no act is written before it
  is reported, in one transaction with that intent; the intent is an
  obligation retried while pending, never a receipt.
- A physical Tier C action with no commissioned zone, and `coap_command` at
  Tier C, are refused as proposals.

**Restart and reconciliation.** A restart replays nothing. An open proposal
closes `proposal_aborted_restart` with its safe default; marker without outcome
is `dispatch_outcome_unknown`; neither is `dispatch_not_proven`, because an
absent marker proves nothing. Both raise a CRITICAL operator and audit event. A
graceful stop closes open proposals the same way. Nothing is written between
the approval commit and the executor, so `approval_aborted_undispatched` is
unreachable here. A store unreadable at recovery fails Tier C closed and nothing
else: start completes, Tier D runs, health degrades. An uncertain dispatch
blocks only its outcome on its zone until an authenticated operator observation
(`evidence reconcile-tier-c`) or commissioned feedback reconciles it. Tier D
consults none of this. Health carries `evidence.action_records`. A v1 offline token approves no physical action and no
Tier C action; a v2 token binds one proposal.

**Fire-and-track.** The dispatcher never blocks the loop while waiting, uses
`asyncio.wait_for` for replies, always returns an `ActionResult`, and never lets
a failed action crash the runtime. Every attempt is logged to `action_log`
after the act, never ahead of it, through one ordered, bounded writer; a record
past the ceiling, refused, or unwritten at shutdown is counted lost and
reported (`docs/DISPATCH_PLAN.md`).

---

## Skills

The format is `skills-package/v3` (ori-specs); `skills/template/skill.yaml` and
`skills/energy-anomaly-detector/skill.yaml` are worked examples. Rules:

- Every action declares its tier. An action with no tier, or an unknown tier, is
  refused, never treated as A.
- **An action declared above Tier A must exist in the action registry,**
  checked at skill load. Tier A is exempt: a skill may name its own
  informational action.
- **Physical capability is an outcome on a zone, never a name.** No new physical
  action name is added to the registry; a new capability arrives as an outcome
  defined in ori-specs and bound to a resource by the commissioned binding. The
  three legacy actuator names (`trip_relay`, `close_gas_valve`,
  `release_relay`) resolve to `open_protected_circuit` /
  `close_protected_circuit` through the zone's mapping. Every physical registry
  entry has an executor the runtime registers, and the registry is owned by the
  release; nothing at deployment adds to it.
- **A package holds no Tier D action.** A Tier D trigger's protective outcome
  comes from a safety profile once migrated; until then it observes and
  notifies.
- **A skill whose physical action is not yet bound ships its notifications
  only.** It alerts what should happen and never declares that it happened.
- **There is no deployment override of a skill's actions.** A `skills:` entry in
  `ori.yaml` carries `name` and `version` only. Binding a protective action is a
  runtime change plus a commissioned binding; any text suggesting a config route
  to actuation is wrong.

`same_weekday_hour_baseline(sensor_id, lookback_weeks=8, min_weeks=3)` gives a
bounded site-local baseline for anomaly suppression, never for Tier D cutoffs or
as a confidence proxy.

---

## Configuration

`ori.yaml.example` (Pi), `ori.linux.yaml.example` and `ori.yaml.phone.example`
are the annotated references; `.env.example` lists the environment variables.
`device.deployment_profile` is `development | staging | production`; staging and
production enforce hardened posture and cannot opt out. Non-packaged skills
always require an ed25519 signature; `security.skills.require_signed: true` also
binds packaged ones. `ori.yaml` is never committed (it is gitignored). Use SMS as the primary alert channel in
Nigeria.

---

## Coding Conventions

- Python 3.11+, asyncio throughout, type hints on every function. No
  `time.sleep`, no blocking I/O, no `requests`: use `asyncio.sleep`,
  `aiofiles`, `httpx`/`aiohttp`.
- Files and functions `snake_case`, classes `PascalCase`, constants
  `UPPER_SNAKE_CASE`. Tiers are single uppercase letters; sensor types are
  lowercase strings; event types are dotted (`sensor.reading`).
- Canonical types are in `ori/network/events.py` (`SensorReading`, `OriEvent`,
  `ActionResult`, `ReasoningResult`): timestamps are unix milliseconds UTC,
  quality is 0.0–1.0. Never bypass them.
- Every new Python file starts with:

  ```text
  # Copyright 2026 Ori Nexus Systems LTD
  # SPDX-License-Identifier: Apache-2.0
  ```

- Run `ruff check --fix` on every file you create. `mypy ori/` and pyright are
  gated at zero.
- **Comments and docstrings:** a docstring states the contract (what it returns
  or refuses, the invariant a caller relies on) in a few lines. A comment
  explains a non-obvious why in one to three lines. Longer reasoning goes in the
  commit, the PR body or `docs/`. Never record history in code.
- Modules stay under 1,500 lines and functions under 150, comments included
  (`tests/test_module_size.py`, `tests/test_function_size.py`).
- HAL adapters raise `AdapterConnectionError` or `AdapterTimeoutError`, and
  every adapter wraps physical I/O in `async with self._breaker:`
  (`HardwareCircuitBreaker`).
- SQLite schema lives in `ori/state/_migrations.py`. Direct `sqlite3` with
  parameterised queries; no ORM.
- Modular monolith; no microservices on the device; no global state.

---

## Platform and Hardware

**Simulation is for development only.** Off a Pi, HAL adapters guard hardware
imports and enter simulation (connect succeeds with a WARNING, reads return
simulated values). Staging, production, and development with
`security.enforce_production_posture: true` fail before opening the store when a
configured GPIO relay or status signal lacks `gpiozero`, a CoAP action or sensor
lacks `aiocoap`, or local reasoning lacks `llama-cpp-python` or a readable GGUF
model. I2C and serial simulation remain adapter behaviour. A protocol not in
`ori/hal/protocol_registry.py` is refused at startup.

`actions.relay.enabled` gates Tier B/C use only; a present `gpio_pin` declares
the Tier D path and requires real GPIO even when disabled, so omit the pin when
no relay is wired. Local inference is requested by
`reasoning.default_tier: local` only.

**Relay wiring.** Never derive a coil state or circuit outcome from contact type
(NC/NO); the downstream wiring decides. Controller loss is not one condition:
losing coil power de-energises the coil, but a killed process may leave the
output at its last commanded state (measured on a Pi 4, `docs/evidence/`). Only
the per-mode observation at commissioning licenses calling a state safe.

**The relay is driven only through the commissioned binding**
(`commissioning/binding.json`, `docs/COMMISSIONING.md`). Polarity is refused
from `ori.yaml`. Startup commands the coil `de_energised` through the zone's
polarity. A declared pin with no accepted zone is not driven and its relay
actions are not registered.

---

## What Not To Do

- No monitoring-only framing: Ori is an agent that acts.
- No approval bypass for Tier C, by config or otherwise. Bare `YES`/`NO` never
  approves Tier C unless a legacy or test deployment disables scoped replies.
  Nothing actuates on a reply the store did not commit, and a restart never
  replays an approval.
- No LLM before Tier D.
- No trusting a skill's tier: a registry entry for every executable action; a
  safe default is non-actuating.
- No in-process execution of community hooks, and no filtered-builtins or
  import-hook "sandbox": that approach fails open and was removed.
- No circuit-breaker bypass in any adapter.
