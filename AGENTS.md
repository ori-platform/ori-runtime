# AGENTS.md — Ori Codebase Guide for AI Coding Agents

This file is for any AI coding agent working on this repository:
Claude Code, Cursor, Codex, Gemini, Copilot, or any other tool.

For Claude Code specifically: `CLAUDE.md` contains the full architectural
specification including all data types, build order, and design decisions.
Read `CLAUDE.md` before writing any implementation code.

This file covers how to navigate and extend the codebase once you understand
the architecture.

---

## What this project is

Ori is an agentic IoT runtime. It reads physical sensor data and takes
autonomous actions based on LLM reasoning. It has an offline-capable safety
core and runs on a Raspberry Pi.

The key concept that every contributor must understand before touching code:

```text
Ori is NOT a monitoring system.
Ori is an agent that reasons about physical signals and acts on them.

Tier A actions  — always autonomous (alerts, logs)
Tier B actions  — autonomous by default (source switching, valve control)
Tier C actions  — approval required (relay/contactor-controlled shutdowns)
Tier D actions  — always autonomous, highest priority (safety cutoffs)
```

Every function, class, and test must be written with this framing in mind.
If you are writing code that makes Ori more passive, you are going in the
wrong direction.

---

## Repository layout

```text
ori/                    Python package — the runtime
├── hal/                Layer 1: hardware adapters
├── network/            Layer 2: event bus, deduplication, data types
├── reasoning/          Layer 4: LLM tiers + action dispatcher
├── skills/             Layer 5: skill loader and sandbox
├── actions/            Action executors called by the dispatcher
├── state/              SQLite state store
├── config.py           ori.yaml loader
└── runtime.py          Main event loop — ties everything together

skills/                 Bundled skills (YAML + Python hooks)
tests/                  pytest test suite
```

---

## The five extension points

When someone asks you to add something new to Ori, it almost always fits into
one of these five patterns. Identify the pattern first, then implement.

---

### 1. Adding a new HAL adapter

**When:** A new sensor protocol or hardware type needs support.
**Where:** `ori/hal/new_adapter.py`
**Pattern:**

```python
from ori.hal.base import BaseAdapter, AdapterConnectionError, AdapterTimeoutError
from ori.network.events import SensorReading
import time

class NewProtocolAdapter(BaseAdapter):

    def __init__(self):
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self, config: dict) -> None:
        # config keys come from ori.yaml sensors[n] block
        # Raise AdapterConnectionError if connection fails
        try:
            # initialise hardware connection here
            self._connected = True
        except Exception as e:
            raise AdapterConnectionError(f"Failed to connect: {e}") from e

    async def read(self, sensor_id: str) -> SensorReading:
        # Must complete within config['read_timeout_ms'] or raise AdapterTimeoutError
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type='temperature',   # match what ori.yaml declares
            value=0.0,
            unit='celsius',
            timestamp=int(time.time() * 1000),
            quality=1.0,
            metadata={'source': 'new_protocol'}
        )

    async def close(self) -> None:
        self._connected = False
```

**Rules:**

- Wrap all hardware imports in `try/except ImportError` so the adapter
  fails gracefully on platforms where the library is unavailable
- Never raise anything except `AdapterConnectionError` or `AdapterTimeoutError`
- Always set `metadata['source']` to the protocol name
- Add `@pytest.mark.skipif` to all tests that require real hardware:

  ```python
  skip_if_no_hardware = pytest.mark.skipif(
      not os.path.exists('/dev/i2c-1'),
      reason="Hardware not available"
  )
  ```

- Register the adapter in `ori/config.py` protocol map so ori.yaml can
  reference it by name

SHARED HARDWARE RESOURCES:
If your adapter accesses a hardware bus that can be shared across
multiple sensor instances (I2C, SPI), use the reference-counted
singleton pattern established in ori/hal/i2c_adapter.py.

Module-level dicts for hardware singletons are a permitted exception
to the no-global-state rule — hardware pins are physical singletons.
The singleton must:

- Use a threading.Lock for all cache operations
- Increment a ref count on connect()
- Decrement and conditionally evict on close()
- Never call deinit() during eviction if other refs may exist
- Stay isolated to the adapter module — never expose the cache
  to layers above the HAL

CIRCUIT BREAKER REQUIREMENT:
Every adapter that polls hardware must utilize the hardware circuit breaker gracefully:

```py
    from ori.hal.base import HardwareCircuitBreaker

    def __init__(self, adapter_name: str, config: dict):
        self._breaker = HardwareCircuitBreaker(adapter_name, config)

    async def read(self, sensor_id):
        async with self._breaker:
            return await self._do_read(sensor_id)
```

---

### 2. Adding a new skill

**When:** A new use case needs agent behaviour (agriculture, cold chain, HVAC…)
**Where:** `skills/skill-name/skill.yaml` and optionally `hooks.py`
**Pattern:**

```yaml
name: your-skill-name
version: 0.1.0
author: your-github-handle
license: Apache-2.0
signature: bundled # use 'bundled' for repo-bundled skills; use ed25519:<sig> for community distribution

sensors_required:
  - type: temperature # sensor types this skill needs

triggers:
  - name: your_trigger_name
    condition: "value > 30.0"
    cooldown_seconds: 300
    escalate_to: local_slm # rule | local_slm | gateway | cloud
    action_tier: A # A | B | C | D — REQUIRED, no default

prompts:
  your_trigger_name: |
    Current reading: {value}{unit}
    History (last 6): {history.last_n('sensor_id', 6)}
    Is this abnormal? What should the operator do?
    Answer in 2-3 plain sentences.

actions:
  available:
    - name: alert_whatsapp
      tier: A
  defaults:
    your_trigger_name: [alert_whatsapp]
```

**Rules:**

- `action_tier` is REQUIRED on every trigger. Missing tier = validation error.
- `bypass_llm: true` MUST be paired with `action_tier: D`. Never one without
  the other.
- Tier C triggers MUST declare `safe_default_action`.
- Prompts must be in plain language — no technical jargon in the output.
  The end user is a Lagos SME owner, not a systems engineer.
- `hooks.py` is optional. Only add it for calculations that cannot be
  expressed in YAML (cost estimates, custom formatting, external API calls).

```python
# hooks.py — optional, only when YAML is insufficient
def post_reasoning(result, context):
    """Called after LLM reasoning, before action dispatch."""
    # result: ReasoningResult
    # context: HookContext with .readings, .history, .state, .timestamp, .derived
    return result  # always return result (modified or unchanged)
```

**HookContext API** (`ori/skills/hooks_api.py`):

The `context` object passed to hooks is a `HookContext` instance built
by the runtime. It provides dynamic, sandboxed access to sensor data
and persistent state. **Never** access the StateStore or database
directly from hooks — always go through these adapters.

| Property               | Type                 | Description                               |
| ---------------------- | -------------------- | ----------------------------------------- |
| `context.readings`     | `dict[str, Any]`     | Current sensor values keyed by sensor_id  |
| `context.history`      | `HookHistoryAdapter` | Parameterised history queries (see below) |
| `context.state`        | `HookStateAdapter`   | Skill-isolated key-value persistence      |
| `context.timestamp`    | `int`                | Event timestamp (unix milliseconds)       |
| `context.derived`      | `dict[str, Any]`     | Writable dict for computed values         |
| `context.trigger_name` | `str`                | Name of the trigger that fired            |

**HookHistoryAdapter methods:**

```python
context.history.avg_hours(sensor_id, hours)   # -> float | None
context.history.avg_last_n(sensor_id, count)  # -> float | None
context.history.last_value(sensor_id)         # -> float | None
context.history.last_timestamp(sensor_id)     # -> int | None
context.history.fetch_history(sensor_id, limit=1)  # -> list[dict]
```

**HookStateAdapter methods** (state is isolated per skill — no cross-skill leakage):

```python
context.state.get(key)          # -> str | None
context.state.set(key, value)   # -> None (persists to SQLite)
```

---

### 3. Adding a new action executor

**When:** Ori needs to take a new kind of action (push notification, relay
variant, database write, REST webhook…)
**Where:** `ori/actions/new_action.py`
**Pattern:**

```python
from ori.network.events import ActionResult
import time
import logging

logger = logging.getLogger(__name__)

class NewAction:

    def __init__(self, config: dict):
        # config from ori.yaml actions.new_action block
        self._enabled = config.get('enabled', False)

    async def execute(self, message: str, context) -> bool:
        """
        Execute the action. Returns True on success, False on failure.
        NEVER raises — always returns bool.
        A failed action must not crash the runtime.
        """
        if not self._enabled:
            logger.debug("NewAction is disabled")
            return False
        try:
            # perform the action
            return True
        except Exception as e:
            logger.error(f"NewAction failed: {e}")
            return False
```

**Rules:**

- Action executors NEVER raise exceptions. They return `False` on failure.
- All network calls must use `asyncio`-compatible libraries (`httpx`, `aiohttp`).
  Never `requests`.
- Always set a timeout on outbound network calls (2–3 seconds maximum).
- Graceful degradation: if credentials/config are missing, log a warning and
  return False. Never crash the runtime because an action is misconfigured.
- Register the executor in `ori/reasoning/action_dispatcher.py` so it can be
  referenced by name in skill YAML.

---

### 4. Adding a new reasoning tier

**When:** A new LLM backend needs to be supported.
**Where:** `ori/reasoning/elevator.py` — add a new tier handler.
**Pattern:** The elevator's `reason()` method delegates to the appropriate
backend. Add a new method and register it in the tier selection logic.
The interface contract is fixed: accept a prompt string, return a
`ReasoningResult`. The backend is an implementation detail.

---

### 5. Modifying the runtime event loop

**Where:** `ori/runtime.py`
**When:** Adding a new background task (health check, sync job, cron handler).

```python
async def run_loop(hal, event_bus, db, config, dispatcher):
    tasks = [
        asyncio.create_task(poll_sensor(s, hal, event_bus, db, deduplicator))
        for s in config.sensors
    ]
    tasks += [
        asyncio.create_task(cron_scheduler(skill, event_bus))
        for skill in skills if skill.has_cron_trigger
    ]
    tasks.append(asyncio.create_task(heartbeat_loop(config, db)))
    # Add new background tasks here:
    # tasks.append(asyncio.create_task(your_new_task(...)))
    await asyncio.gather(*tasks)
```

**Rules:**

- Every background task must handle its own exceptions. An unhandled exception in a gathered task kills the entire runtime.
- Use `asyncio.create_task()` for concurrent work. Never `asyncio.run()` inside a running loop.
- The runtime must log a clear startup message for each task it starts.

---

## Testing conventions

```bash
# Run everything
pytest tests/ -v

# Run a specific module
pytest tests/test_events.py -v

# Run with coverage
pytest tests/ --cov=ori --cov-report=term-missing

# Skip hardware tests (default on non-Pi platforms)
pytest tests/ -v -m "not hardware"
```

**Test file naming:** `tests/test_{module_name}.py` mirroring `ori/{module}.py`.

**Async tests:**

```python
import pytest

@pytest.mark.asyncio
async def test_something_async():
    result = await some_async_function()
    assert result is not None
```

**Hardware skip pattern:**

```python
import os
import pytest

skip_if_no_pi = pytest.mark.skipif(
    not os.path.exists('/dev/gpiomem'),
    reason="Raspberry Pi GPIO not available"
)

skip_if_no_i2c = pytest.mark.skipif(
    not os.path.exists('/dev/i2c-1'),
    reason="I2C bus not available"
)

@skip_if_no_pi
async def test_gpio_adapter():
    ...
```

**Mocking hardware in unit tests:**

```python
from unittest.mock import AsyncMock, patch

async def test_adapter_without_hardware():
    with patch('ori.hal.i2c_adapter.smbus2') as mock_smbus:
        mock_smbus.SMBus.return_value.read_i2c_block_data.return_value = [0x60, 0x00]
        adapter = I2CAdapter()
        await adapter.connect({'address': 0x48, 'channel': 0, 'sensor_type': 'ads1115_current'})
        reading = await adapter.read('test-sensor')
        assert reading.sensor_type == 'current_clamp'
```

---

## Critical constraints — never violate these

These come from the architecture. Violating them breaks the system in ways
that are hard to debug.

```text
1. SensorReading and OriEvent are the only allowed data types for sensor data.
   Never pass raw dicts or primitives between modules.

2. Every trigger in a skill YAML must declare action_tier.
   The skill loader raises SkillValidationError if it is missing.

3. Tier C actions ALWAYS run the approval workflow.
   There is no config flag to skip it. If you find yourself writing code
   to bypass Tier C approval, you are implementing this wrong.

4. Tier D actions NEVER invoke an LLM.
   bypass_llm: true is set automatically. Do not add LLM calls to Tier D paths.

5. Action executors never raise exceptions.
   They return False. The runtime must survive a failed action.

6. The event loop is never blocked.
   time.sleep(), requests.get(), and any synchronous I/O are forbidden
   in async code paths.

7. SQLite queries are always parameterised.
   f-string or .format() SQL is a security and correctness error.

8. ori.yaml is never committed to the repository.
   It is in .gitignore. The example file is ori.yaml.example.
```

---

## Common mistakes and how to fix them

**"I added a sensor type but it's not appearing in readings"**
→ Check that the new sensor type is registered in the adapter's
`SUPPORTED_SENSOR_TYPES` dict and that ori.yaml uses the exact string key.

**"The skill loads but no triggers fire"**
→ The condition expression failed silently. Check `RuleEngineSafetyError`
logs and verify the condition only uses allowed builtins.

**"Tier C action executed without waiting for approval"**
→ The action was incorrectly declared as Tier B in skill.yaml. Check the
`action_tier` field on the trigger.

**"The runtime crashes when an action fails"**
→ The action executor is raising an exception instead of returning False.
Wrap the executor body in `try/except Exception`.

**"Tests pass locally but fail in CI"**
→ A hardware-dependent test is missing its `@skip_if_no_hardware` decorator.
Add the appropriate skip mark.

**"Import error on non-Pi platform"**
→ A hardware library import (`gpiozero`, `smbus2`, `RPi.GPIO`) is at module
level instead of inside a `try/except ImportError` block.

---

## Before submitting a PR

```bash
# 1. Tests pass
pytest tests/ -v

# 2. No import errors on a standard laptop (no Pi required)
python -c "import ori; print('imports ok')"

# 3. If you added a skill, validate it loads cleanly
python -c "
import asyncio
from ori.skills.loader import SkillLoader
skills = asyncio.run(SkillLoader().load_one('skills/your-skill-name'))
print(f'Loaded: {skills.name} v{skills.version}')
"

# 4. If you added an adapter, confirm it handles the no-hardware case
python -c "from ori.hal.your_adapter import YourAdapter; print('graceful import ok')"

# 5. Verify the license header is present on every new Python file
grep -rL "SPDX-License-Identifier: Apache-2.0" ori/ tests/ --include="*.py"
# Output should be empty. Any file listed is missing the header.
```

---

## Security Invariants — Never Violate These

The security invariants below flow directly from the principles in PRINCIPLES.md — specifically Principle 1 (The Lens of Actuation Trust) and Principle 3 (The Lens of Inviolable Safety). Understanding the principles explains why the invariants exist.

These rules apply to any AI coding agent modifying this codebase.
Violating them creates vulnerabilities that affect physical hardware.

1. Never load community skill hooks with raw importlib.
   Always use `ori.skills.sandbox.load_hooks_restricted()`.
   Only use `_load_hooks_direct()` for bundled skills in `skills/`.

2. Never add new modules to `_ALLOWED_IMPORTS` in `sandbox.py`
   without opening a GitHub issue and getting maintainer approval.

3. Never use string-based pattern matching to validate skill
   condition expressions. The rule engine uses AST whitelist
   validation (`_check_safety_ast`) that parses conditions into
   an abstract syntax tree and rejects any node type not in the
   explicit allowlist. Only comparisons, boolean ops, arithmetic,
   names, constants, and `history.method()` calls are permitted.

4. Never interpolate untrusted input (skill names, sensor IDs,
   operator replies) into LLM prompts without sanitisation.

5. Never store credentials in code, comments, or git-tracked
   files. All secrets go in .env (gitignored).

6. Never add a GitHub Actions workflow that processes untrusted
   input (issue titles, PR comments) with shell access.

7. Never add postinstall scripts to pyproject.toml that
   fetch from external URLs.
8. If `_validate_sensor_value` raises `RuleEngineSafetyError`, the
   calling code must fire a Tier A alert to the operator.
   A suspended Tier D path is a safety event requiring human
   awareness. It must never fail silently.
9. relay.py is intentionally tier-agnostic. `RelayAction.trigger()` and
   `RelayAction.release()` must only be called through `ActionDispatcher`,
   never directly from skills, hooks, or any other layer. The Tier D
   CRITICAL escalation and emergency SMS path in `_execute_immediately()`
   depends on this contract — direct relay calls bypass it entirely.

10. DevicePolicy.permits_action() and relay.enabled in ori.yaml govern Tier B and Tier C
    relay actuation only. Tier D relay paths must:
    (a) be initialised at boot regardless of relay.enabled or DevicePolicy state,
    (b) bypass all DevicePolicy checks at dispatch time unconditionally.
    A DevicePolicy enforcement mechanism that prevents Tier D actuation is a safety
    failure, not a billing control. This invariant is verified by a test matrix covering:
    - test_tier_d_relay_fires_when_policy_expired()
    - test_tier_d_relay_fires_when_policy_missing()
    - test_tier_d_relay_fires_when_policy_parse_fails()
    - test_tier_d_relay_fires_when_policy_refresh_fails()

11. Remote DevicePolicy payloads from ori-cloud must be verified for integrity before
    any policy is applied. The runtime must verify:
    (a) HTTPS transport,
    (b) device authentication on the request (API key or JWT),
    (c) policy version is not a downgrade (monotonically increasing),
    (d) response timestamp is within 5 minutes of current device time,
    (e) payload Ed25519 signature is valid against the stored ori-cloud public key.
    A policy payload that fails any of these checks must be REJECTED.
    Rejection behaviour: keep current policy, log at WARNING with audit trail.
    NEVER reject silently. NEVER fail open by applying an unverified policy.
    The phrase 'reject silently' must not appear in any policy enforcement code path.

12. Database compaction logic must always query the physical tables to check for backwards clock skew
    before deleting history. Relying on host clock calculations (`now_ms - 48h < now_ms - 1h`) is a
    tautology and will blindly destroy data if the host clock jumps backward.

13. Remote commands that change configuration, policy, update intent, relay state,
    or any other actuator-affecting setting must be authenticated before execution.
    SMS, WhatsApp, and cloud-originated commands require HMAC, signature, offline
    token, or an equivalent replay-resistant check. Tier D evaluation and
    execution paths must not be disableable by any remote command, including SMS,
    WhatsApp, or cloud API.
    All remote command handlers must call `RemoteCommandVerifier` before executing
    or queueing any state-changing command.
    Remote command authentication must be bound to the ingress sender. When
    remote commands are enabled, `security.remote_commands.allowed_senders`
    must define the approved SMS/WhatsApp sender identities, or
    `allow_unlisted_senders: true` must be explicitly set for test deployments.
    A valid signature from an unapproved sender must be rejected and audited as
    `sender_not_allowed`.
    Verification does not imply execution permission. Authenticated remote commands
    must pass through `ori.security.remote_command_policy` before any runtime side
    effect is allowed.
    `SET_THRESHOLD` must never make a Tier D trigger less sensitive than the
    value configured in `ori.yaml`. For upper-bound conditions such as
    `value > threshold`, raising the threshold above startup is forbidden. For
    lower-bound conditions such as `value < threshold`, lowering the threshold
    below startup is forbidden. If the runtime cannot prove the direction of a
    Tier D threshold safely, the remote change must be rejected. After any
    threshold change, the runtime must immediately re-evaluate active Tier D
    conditions. A threshold change that would suppress an active Tier D
    condition must be rejected.
    Relay fail-safe direction configured in `ori.yaml` is immutable by remote
    command. `SET_RELAY_MODE` must never change normally-closed to normally-open,
    or perform any equivalent fail-safe inversion, regardless of authentication.
    Tier C approval replies and remote commands are separate input classes.
    Approval messages must carry a short `proposal_id`; scoped replies such as
    `YES-<proposal_id>` and `NO-<proposal_id>` must match the active proposal
    before approving or rejecting it. Structured remote command payloads
    (`ORI_COMMAND {json}` or raw JSON with the remote-command field set) must
    never be treated as approval replies. The local-console approval channel is
    not a remote command ingress; structured commands there must be consumed,
    durably audited, and ignored for approval purposes. Unrecognised
    local-console approval input must be logged and ignored until timeout, not
    silently converted to NO.

---

## Supply Chain Security Invariants

These rules apply to every AI coding agent modifying this repository. Violating
these rules can compromise the runtime that controls physical hardware.

1. Never add `pull_request_target` workflows that checkout or execute untrusted
   PR code. Use `pull_request` for fork PR workflows.

2. Every GitHub Actions workflow must declare explicit least-privilege
   permissions. Normal CI uses `contents: read` and `id-token: none`.

3. `id-token: write` is allowed only in a dedicated release job in `release.yml`.
   It must never appear in `ci.yml`.

4. Release jobs must never restore dependency caches (`actions/cache`, package
   manager caches, or setup action cache flags). Cache poisoning was a key part
   of the TanStack May 2026 supply-chain attack.

5. GitHub Actions must be pinned to full commit SHAs. Mutable tags such as
   `@v4`, `@v5`, `@main`, and `@master` are forbidden. Add a human-readable
   version comment next to each SHA.

6. Never download and execute remote scripts in CI without hash or signature
   verification. `curl URL | bash`, `curl URL -o script.py && python script.py`,
   and equivalent patterns are forbidden.

7. Python installs in CI must use hash-locked requirements files with
   `--require-hashes`. Do not use `pip install -e '.[dev]'` to resolve
   dependencies in CI.

8. Device deployment to Pi or phone must install from signed artifacts or a
   signed wheelhouse. Production deployment must not resolve dependencies live
   from public package registries.

9. Valid provenance does not imply safe code. The TanStack May 2026 incident
   produced malicious packages through legitimate CI/OIDC pathways. For Ori,
   Tier C/D skill review gates and runtime sandboxing remain mandatory
   regardless of provenance or author reputation.

10. Run `scripts/check_workflows.py` before merging workflow or pre-commit
    configuration changes. The script fails on `pull_request_target`, mutable
    action refs, unauthorized `id-token: write`, remote script execution
    patterns, and remote pre-commit hooks that are not pinned to full commit
    SHAs.

11. Ed25519 signing implementations that must interoperate with the runtime use
    `cryptography`, not PyNaCl. `ori-skills-hub` must use `cryptography` for Hub
    root signing because the runtime verifies community skill signatures with
    `cryptography`.

## Where to find things

| I want to...                          | Look in...                           |
| ------------------------------------- | ------------------------------------ |
| Add support for a new sensor          | `ori/hal/`                           |
| Change how events are structured      | `ori/network/events.py`              |
| Change how events are deduplicated    | `ori/network/deduplicator.py`        |
| Change reasoning tier selection logic | `ori/reasoning/elevator.py`          |
| Change how actions are routed by tier | `ori/reasoning/action_dispatcher.py` |
| Add a new action type                 | `ori/actions/`                       |
| Change skill loading and validation   | `ori/skills/loader.py`               |
| Change what gets persisted to SQLite  | `ori/state/store.py`                 |
| Change device configuration format    | `ori/config.py` + `ori.yaml.example` |
| Change the main event loop            | `ori/runtime.py`                     |
| Add a bundled skill                   | `skills/`                            |
| Understand a design decision          | `CLAUDE.md`                          |
| Understand the business context       | `CONTRIBUTING.md`                    |
