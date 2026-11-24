# CLAUDE.md — Ori Runtime

Architectural rules; do not relitigate them. Philosophy: `PRINCIPLES.md` (read
before any structural change). Navigation and recipes: `AGENTS.md`. Reasoning:
`DECISIONS.md`. State rules and point to detail; never copy code or schemas here.

## What Ori Is

An open-source, offline-first **agentic** IoT runtime (Agents of Things, Mzahm,
Ahmad and Tang, IEEE 2013): devices reason about sensor data and act physically.
Not a monitor: "Overcurrent detected. I have tripped the safety relay." Every
design decision preserves that agency.

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

## The Intelligence Elevator (Layer 4)

```text
Tier 1  RULE ENGINE   microseconds  always available  safety-critical + Tier D
Tier 2  LOCAL SLM     3-8 seconds   offline-capable   most everyday reasoning
Tier 3  GATEWAY LLM   1-3 seconds   LAN required      cross-device or cloud-backed
```

The runtime selects the cheapest tier that can answer, Tier 1 first.

- Escalation is deterministic, decided before local inference
  (`ori/reasoning/escalation_policy.py`); local SLM confidence is telemetry only
  and never decides it.
- Gateway reasoning is provider-neutral MQTT request/response; no cloud SDK
  enters the runtime.
- Reasoning grants no authority: a matched trigger's tier is authoritative;
  unmatched gateway reasoning above Tier A drops to `log_to_dashboard`.

Gateway, SMS-ingress and remote-command security: `AGENTS.md` ("Security
invariants"), `docs/MQTT_SECURITY.md`, `docs/SMS_WEBHOOK_SECURITY.md`.

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

**The letter is two axes, not a severity scale** (treating A→D as rising
severity has produced defects three times): consequence class (`informational`,
`soft`, `hard`; registry-owned, as reversibility is a site-wiring fact) and
authority basis (`autonomous`, `operator_approval`, `safety_condition`).

- A and D are both autonomous; a notice beside a trip never inherits its
  authority, and any max over tiers exempts informational actions.
- `requires_approval` moves Tier B along the authority axis, not its letter.
- A Tier D floor is a category error: `trip_relay` sits at a hard floor and
  reaches D only through a safety condition.

Reasoning: `skills-package/v3.md`; attested authority basis: `evidence/v2.md`.

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
- **The end state is `safety-profile/v1.md`:** release-owned conditions on a
  commissioned zone; `ori/safety/` becomes the sole Tier D path once #324 lands.
  Nothing deployment-supplied (config, remote command, DevicePolicy,
  entitlement) alters a profile.

**Every layer fails closed on its own:** the floor is enforced at skill load,
at dispatch and in `_execute_immediately`; the trigger tier clamp is reapplied
after every extension boundary. A check that holds only because an earlier
check held is not a boundary. `register_executor()` refuses an action with no
registry entry; add the entry in the same change.

**Skill provenance is positive:** first-party only because it ships in the
package (`_is_core_bundled_skill`); everything else needs a verified signature,
and its `hooks.py` is refused.

**Dispatch order** (detail and reasoning: `docs/DISPATCH_PLAN.md`):

1. Discovery barrier: every matching trigger for the event is collected before
   any reasoning. Tier D conditions read only the reading and skill config.
2. The plan: each action at its own authority; an ungoverned action is refused
   here.
3. Tier D first, before any reasoning task; no cooldown or hold applies to it.
4. Local SLM for what remains.
5. Dispatcher admits by resource, not name; then A executes, B executes or
   asks, C asks for `YES-<proposal_id>` / `NO-<proposal_id>`, D executes.

## The Action Dispatcher

`ori/reasoning/action_dispatcher.py`. Approval workflows, governed Tier C
approval, restart and reconciliation: `docs/DISPATCH_PLAN.md` ("Dispatch order
and the approval workflow in brief").

- Fire-and-track: never block the loop while waiting (`asyncio.wait_for` for
  replies); always return an `ActionResult`; a failed action never crashes the
  runtime.
- Every attempt is logged to `action_log` after the act, never ahead of it.
- A restart replays nothing; nothing actuates on a reply the store did not
  commit.

## Skills

The format is `skills-package/v3` (ori-specs); `skills/template/skill.yaml` and
`skills/energy-anomaly-detector/skill.yaml` are worked examples. Rules:

- Every action declares its tier. An action with no tier, or an unknown tier, is
  refused, never treated as A.
- **An action declared above Tier A must exist in the action registry,**
  checked at skill load. Tier A is exempt: a skill may name its own
  informational action.
- **Physical capability is an outcome on a zone, never a name.** No new physical
  action name enters the registry; a new capability is an outcome defined in
  ori-specs and bound by the commissioned binding (legacy names: `AGENTS.md`).
- **A package holds no Tier D action.** A Tier D trigger's protective outcome
  comes from a safety profile once migrated; until then it observes and
  notifies.
- **A skill whose physical action is not yet bound ships its notifications
  only.** It alerts what should happen and never declares that it happened.
- **No deployment override of a skill's actions:** a `skills:` entry in
  `ori.yaml` carries `name` and `version` only; no config route leads to actuation.

## Configuration

`ori.yaml.example` (Pi), `ori.linux.yaml.example` and `ori.yaml.phone.example`
are the annotated references; `.env.example` lists the environment variables.
`device.deployment_profile` is `development | staging | production`; staging and
production enforce hardened posture and cannot opt out. Non-packaged skills
always require an ed25519 signature; `security.skills.require_signed: true` also
binds packaged ones. `ori.yaml` is never committed (it is gitignored). Use SMS as the primary alert channel in
Nigeria.

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
- Docstrings state the contract in a few lines; comments explain a non-obvious
  why in one to three. Longer reasoning goes in the commit, PR body or `docs/`;
  never record history in code.
- Modules stay under 1,500 lines and functions under 150, comments included
  (`tests/test_module_size.py`, `tests/test_function_size.py`).
- HAL adapters raise `AdapterConnectionError` or `AdapterTimeoutError`, and
  every adapter wraps physical I/O in `async with self._breaker:`
  (`HardwareCircuitBreaker`).
- SQLite schema lives in `ori/state/_migrations.py`. Direct `sqlite3` with
  parameterised queries; no ORM.
- Modular monolith; no microservices on the device; no global state.

## Platform and Hardware

Detail: `docs/RASPBERRY_PI_SUPPORT.md` ("Simulation, the relay pin and relay
wiring").

- Simulation is for development only; staging and production fail at startup
  when a configured adapter's hardware library or the local model is missing.
- Never derive a coil state or circuit outcome from contact type (NC/NO); only
  the commissioning observation licenses calling a state safe.
- The relay is driven only through the commissioned binding
  (`docs/COMMISSIONING.md`); polarity is refused from `ori.yaml`.

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
