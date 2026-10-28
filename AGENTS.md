# AGENTS.md — Ori Codebase Guide for AI Coding Agents

For every AI coding agent working here (Claude Code, Codex, Cursor, Gemini,
Copilot). **Read `CLAUDE.md` first:** it holds the architecture and its rules,
including the action tiers, which this file does not repeat. This file covers
extending the codebase and the security invariants. `PRINCIPLES.md` explains
why the invariants exist.

Ori is an agent that reasons about physical signals and acts on them, not a
monitoring system. Code that makes it more passive is going the wrong way.

---

## Where things live

| I want to... | Look in... |
| --- | --- |
| Add a sensor protocol | `ori/hal/` and `ori/hal/protocol_registry.py` |
| Change event structure | `ori/network/events.py` |
| Change deduplication | `ori/network/deduplicator.py` |
| Change reasoning tier selection | `ori/reasoning/elevator.py` |
| Change tier routing and approval | `ori/reasoning/action_dispatcher.py`, `docs/DISPATCH_PLAN.md` |
| Add an action | `ori/actions/`, `ori/reasoning/action_registry.py` |
| Change skill loading | `ori/skills/` (one module per concern) |
| Change persisted state | `ori/state/` (one module per domain; DDL in `_migrations.py`) |
| Change device configuration | `ori/config/` (one module per section) and `ori.yaml.example` |
| Change the event loop | `ori/runtime/` (one module per domain) |
| Add a bundled skill | `skills/` |
| Understand a design decision | `DECISIONS.md` |
| See what is real versus planned | `docs/CAPABILITY_MATRIX.md` |

---

## Extension points

### A HAL adapter

Model it on `ori/hal/http_adapter.py`: a `BaseAdapter` subclass, a closed
`CONFIG_SCHEMA` and `CALIBRATION_SCHEMAS` beside it (validated by
`ori/hal/config_schema.py` at config load), and registration in
`ori/hal/protocol_registry.py`.

- Guard hardware imports with `try/except ImportError`; simulate only in
  development posture (see `CLAUDE.md`, Platform and Hardware).
- Raise only `AdapterConnectionError`, `AdapterTimeoutError` or their
  subclasses (`AdapterUnavailableError` for a source that is absent and worth
  retrying).
- Initialise `self._breaker = HardwareCircuitBreaker(...)` and wrap all physical
  I/O in `async with self._breaker:`.
- A bus shared across sensors (I2C, SPI) uses the reference-counted singleton
  in `ori/hal/i2c_adapter.py`: a lock around the cache, ref count on connect,
  evict on the last close, never `deinit()` while refs remain, never exposed
  above the HAL. This is the one permitted module-level state.
- Set `metadata['source']` on every reading to the protocol name.
- Mark hardware-only tests `@pytest.mark.hardware` with a `skipif` on the device
  path.

### A skill

Copy `skills/template/`. The format is `skills-package/v3` (ori-specs) and the
rules are in `CLAUDE.md` (Skills). In addition:

- `bypass_llm: true` pairs only with `action_tier: D`.
- `requires_approval` is a YAML boolean on the trigger, never on an
  `actions.available` entry.
- Tier C triggers declare a non-actuating `safe_default_action`.
- A `post_action` trigger includes a Tier A default for the follow-up notice.
  If enrichment fails or no reasoner is available, the audit records
  `reasoning_status: incomplete`; if the physical action failed, reasoning is
  skipped and recorded `skipped`. The executed action is never rolled back or
  retried.
- Prompts are plain language for a Lagos SME owner, not an engineer.
- `hooks.py` runs only for first-party skills. Its API is
  `ori/skills/hooks_api.py` (`HookContext`); hooks never touch the StateStore
  directly, and history baselines never suppress Tier D.

### An action executor

Add the registry entry in `ori/reasoning/action_registry.py` first, then
register an async `execute(action, context)` with
`dispatcher.register_executor()` (see `ori/runtime/_startup_foundation.py`).
Registration without a registry entry raises. A physical action arrives as a
commissioned outcome, never a new name (`CLAUDE.md`, Skills).

- An executor never raises: it catches its own errors, logs the failure, and
  the runtime continues.
- Network calls use `httpx`/`aiohttp`, never `requests`, with a timeout of 2–3
  seconds at most on every outbound call.
- Missing credentials or config: log a warning and fail the action, never the
  runtime.

### A reasoning backend

Add it behind `ori/reasoning/elevator.py`'s tier selection: it accepts a prompt
and returns a `ReasoningResult`. Cloud backends belong to the gateway, never the
runtime.

### A background task

Start it from `ori/runtime/_startup.py` and put its loop in
`ori/runtime/_loops.py`. Every task handles its own exceptions (an unhandled
one in a gathered task kills the runtime), uses `asyncio.create_task()` and
never `asyncio.run()` inside the running loop, and logs a clear start message.

---

## Testing

- `pytest tests/ -q -n auto -m "not hardware"` runs the suite; `asyncio_mode` is
  `auto`, so async tests need no marker.
- While editing, run only the tests for what you changed. CI runs the full gate,
  type checks (`mypy ori/`, pyright, both at zero) and the drift checks;
  `scripts/ci_local.sh` reproduces it.
- Mock hardware at the library boundary (for example `ori.hal.i2c_adapter.smbus2`).

Before a PR: the license header is on every new Python file (`grep -rL
"SPDX-License-Identifier: Apache-2.0" ori/ tests/ --include="*.py"` prints
nothing), and a new skill loads with `SkillLoader().load_one(...)`.

---

## Security invariants — never violate these

1. **No community hook code runs in-process.** `load_hooks_restricted()`
   always refuses; do not add a fallback or an import-filtering "sandbox".
2. **Skill conditions are validated by AST allowlist** (`_check_safety_ast` in
   `ori/reasoning/rule_engine.py`): comparisons, boolean ops, arithmetic, names,
   constants and `history.method()` calls only. Never validate them by string
   matching.
3. **Untrusted input** (skill names, sensor IDs, operator replies) is never
   interpolated into an LLM prompt without sanitisation.
4. **No secrets in tracked files.** They go in `.env` (see `.env.example`).
   `ori.yaml` is never committed; it is gitignored.
5. **SQL is always parameterised;** never f-string or `.format()` SQL.
6. **Production posture** (`device.deployment_profile: staging|production`, or
   `security.enforce_production_posture: true`) fails config load on unsafe
   settings: gateway auth and encryption on every enabled broker (plus TLS,
   credentials, declared anonymous-off and ACL posture off loopback); public SMS
   ingress in HMAC mode with source CIDR allowlisting; no unlisted
   remote-command senders, and lockout enforcement on; Ed25519 signatures on
   non-core skills; and the state database under a declared encrypted
   filesystem (`state.encryption.mode: filesystem_required`). Encryption at rest
   is an operator attestation; do not add SQLCipher or row encryption without a
   design review.
7. **A suspended Tier D path is a safety event.** When `_validate_sensor_value`
   raises `RuleEngineSafetyError`, a Tier A alert goes to the operator.
8. **Relay actuation goes through the dispatcher only.** `RelayAction.trigger()`
   and `release()` are never called from skills, hooks or other layers; the
   Tier D escalation and emergency SMS path depends on it.
9. **Tier D is never gated by entitlement.** `DevicePolicy.permits_action()` and
   `actions.relay.enabled` govern Tier B and C only. Tier D relay paths
   initialise at boot regardless and bypass DevicePolicy at dispatch
   (`device-policy/v2.md`; `tests/test_tier_d_relay_bypass.py`).
10. **Remote DevicePolicy payloads are verified before use:** HTTPS, device
    authentication, no version downgrade, timestamp within 5 minutes, Ed25519
    signature against the stored ori-cloud key, and no repeated member names
    (`ori/utils/strict_json.py`). A failing payload is rejected, never silently:
    keep the current policy and log a WARNING with an audit trail.
11. **History compaction checks the physical tables for backward clock skew**
    before deleting (`ori/state/_history.py`); a host-clock calculation alone is
    a tautology.
12. **Remote commands** that affect configuration, policy, updates or actuators
    are authenticated (`RemoteCommandVerifier`), bound to an approved sender
    (`security.remote_commands.allowed_senders`, or an explicit
    `allow_unlisted_senders: true` for tests; an unapproved sender is audited as
    `sender_not_allowed`), and then pass `ori.security.remote_commands.policy`.
    - No remote command can disable Tier D evaluation or execution.
    - `SET_THRESHOLD` never makes a Tier D trigger less sensitive than its
      configured value, is refused when the direction cannot be proven,
      re-evaluates active Tier D conditions at once, and is refused if it would
      suppress one.
    - Relay polarity and coil mapping come only from the commissioned binding;
      `SET_RELAY_MODE` is audit-only.
    - Previous HMAC secrets are verify-only, and a command accepted under one is
      audited distinctly.
13. **Approval replies are not remote commands.** A Tier C reply must match the
    active `proposal_id` (`YES-<id>` / `NO-<id>`); bare `YES`/`NO` approves
    nothing unless `actions.approval_require_scoped_replies: false`. A structured
    command payload is never an approval. Unrecognised local-console input is
    logged and ignored until timeout, never converted to NO.
14. **Gateway MQTT** is authenticated with its own secret, never a
    remote-command secret. Replay protection is gateway-api/v2 Envelope
    Freshness and Replay (`ori/security/gateway_messages.py`), and every signer
    takes its time from `ori/security/signing_clock.py`, never the wall clock.
    The runtime signs reasoning requests, export responses and its node
    heartbeat, and verifies reasoning responses, export requests and gateway
    heartbeats. Sensitive exports are encrypted before HMAC signing; health
    exports may stay plaintext. A gateway message never
    mutates config, policy, update intent or actuator state.
15. **SMS webhook ingress** uses token-only mode only on loopback or trusted
    provider paths. Internet-exposed ingress sets `allowed_source_cidrs` and
    `signature.mode: token_and_hmac` or `hmac_required`, verifying HMAC over the
    raw body before parsing, with nonce replay recorded in the StateStore
    (`docs/SMS_WEBHOOK_SECURITY.md`).

## Supply-chain invariants

1. No `pull_request_target` workflow that checks out or runs PR code.
2. Every workflow declares least-privilege permissions; CI uses
   `contents: read`. `id-token: write` appears only in the release job of
   `release.yml`.
3. Release jobs never restore dependency caches.
4. Actions are pinned to full commit SHAs with a version comment.
5. No remote script execution without hash or signature verification.
6. CI installs from hash-locked requirements with `--require-hashes`, never
   `pip install -e '.[dev]'`.
7. Devices install from signed artifacts or a signed wheelhouse, never live
   registries.
8. Provenance is not safety: Tier C/D review gates hold regardless of author.
9. Run `scripts/check_workflows.py` before merging workflow or pre-commit
   changes.
10. No postinstall step in `pyproject.toml` fetches from a URL, and no workflow
    gives shell access to untrusted input such as issue titles or comments.
11. Ed25519 signing that must interoperate with the runtime uses
    `cryptography`, not PyNaCl (this binds `ori-skills-hub`'s root signing).

---

## Review before handoff

Self-review is required and never sufficient proof. State plainly what remains
unverified: what was simulated, deferred, host-only, or dependent on another
repository or hardware. It does not replace independent review for shared
contracts, Tier D or physical-authority changes, release and install work, or
any claim of HIL proof. The method is the `ori-rigorous-review` skill in
ori-specs `agent-skills/`, installed with ori-specs
`scripts/install-agent-skills`.
