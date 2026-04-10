# Contributing to Ori

Thank you for your interest in contributing to Ori — an open-source, offline-first
**agentic IoT runtime** that gives physical devices the ability to reason about
sensor data and take autonomous physical actions.

Before writing any code, please read **PRINCIPLES.md**. Every contribution is
evaluated through the six design lenses defined there. The most important one:

> **Ori is NOT a monitoring system.** It is an agent that detects, reasons, and acts.
> If your contribution makes Ori more passive, it is going in the wrong direction.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Architecture Overview](#architecture-overview)
- [AI-Assisted Development](#ai-assisted-development)
- [Contributor Boundaries](#contributor-boundaries)
- [How to Contribute](#how-to-contribute)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Safety Invariants](#safety-invariants)
- [Commit Messages](#commit-messages)
- [Signed Commits (Required)](#signed-commits-required)
- [Pull Request Process](#pull-request-process)
- [Types of Contributions Welcome](#types-of-contributions-welcome)
- [Security](#security)
- [Community Guidelines](#community-guidelines)

---

## Getting Started

1. **Read the design principles:** [`PRINCIPLES.md`](PRINCIPLES.md)
2. **Understand the architecture:** [`CLAUDE.md`](CLAUDE.md) — full architectural specification
3. **Learn the extension points:** [`AGENTS.md`](AGENTS.md) — practical patterns for adding features
4. **Set up your environment** (see below)
5. **Pick an issue** or open a discussion

---

## Development Setup

### Prerequisites

- **Python 3.11+**
- **Git**
- A laptop running macOS or Linux (no Raspberry Pi required for development)

### Installation

```bash
# Clone the repository
git clone https://github.com/ori-platform/ori-runtime.git
cd ori-runtime

# Create a virtual environment (Python 3.11+ required)
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip first (required — old system pip can't handle pyproject.toml editable installs)
pip install --upgrade pip

# Option A — hash-locked install (recommended, matches what CI uses)
pip install --require-hashes -r requirements-dev.txt
pip install -e . --no-deps

# Option B — editable install for active development (resolves latest compatible versions)
pip install -e ".[dev]"

# Verify everything works
pytest tests/ -v
python -c "import ori; print('imports ok')"
```

### Dependency Model

Dependencies are managed with [pip-tools](https://github.com/jazzband/pip-tools):

| File                   | Purpose                                   | Edit?                  |
| ---------------------- | ----------------------------------------- | ---------------------- |
| `requirements.in`      | Human-readable runtime constraints (`>=`) | ✅ Edit this           |
| `requirements-dev.in`  | Human-readable dev constraints            | ✅ Edit this           |
| `requirements.txt`     | Compiled + SHA256-hashed runtime deps     | ❌ Never edit manually |
| `requirements-dev.txt` | Compiled + SHA256-hashed dev deps         | ❌ Never edit manually |

**To update or add a dependency:**

```bash
pip install pip-tools

# Edit requirements.in or requirements-dev.in, then recompile:
pip-compile requirements.in --generate-hashes --annotate -o requirements.txt
pip-compile requirements-dev.in --generate-hashes --annotate --constraint requirements.txt -o requirements-dev.txt

# Verify the new hashes install cleanly
python -m venv /tmp/ori_verify && /tmp/ori_verify/bin/pip install --require-hashes -r requirements-dev.txt
/tmp/ori_verify/bin/pip install -e . --no-deps
/tmp/ori_verify/bin/pytest tests/ -v
rm -rf /tmp/ori_verify
```

Never edit `requirements.txt` or `requirements-dev.txt` by hand — they are
generated files. PRs that modify them without a corresponding change to the
corresponding `.in` file will be rejected.

### Hardware-Optional Development

Ori is designed so the full reasoning pipeline, EventBus, StateStore, and
action dispatcher can be tested on any laptop without a Raspberry Pi.
Hardware-dependent tests are automatically skipped on non-Pi platforms
(look for `@pytest.mark.skipif` decorators).

The `psutil` adapter runs on all platforms — no special hardware needed.

---

## Architecture Overview

```text
Layer 6  Business      ori-cloud · ori-dashboard · fleet management
Layer 5  Application   Skills · Skills Hub · Skills SDK
Layer 4  Reasoning     Intelligence Elevator + Action Tier Framework
Layer 3  Middleware     Ori Runtime (event loop, skill loader, action dispatch)
Layer 2  Network       EventBus · ProtocolNormaliser · Deduplicator
Layer 1  Perception    Sensor HAL (GPIO, I2C, Serial, MQTT, psutil)
```

The **Action Tier Framework** is what makes Ori genuinely agentic:

| Tier  | Name            | Autonomy                            | Example                           |
| ----- | --------------- | ----------------------------------- | --------------------------------- |
| **A** | Informational   | Always autonomous                   | WhatsApp alerts, logs             |
| **B** | Soft Physical   | Autonomous by default               | Source switching, valve control   |
| **C** | Hard Physical   | Approval required                   | Breaker trips, equipment shutdown |
| **D** | Safety-Critical | Always autonomous, highest priority | Emergency cutoffs                 |

For the complete architecture, read [`CLAUDE.md`](CLAUDE.md).

---

## AI-Assisted Development

AI-assisted development is **welcome and expected** on this project. The
maintainers use AI tools daily. This is not an anti-AI stance.

The rule is simple: **if you submit AI-generated code, you must be able to
explain every line and defend every decision in a review conversation.**
If you cannot explain it, do not submit it.

This is not about policing your tools. It is about ensuring that every
contributor understands the code they are signing off on — because this
codebase controls physical hardware.

**What this means in practice:**

- Generated code that you understand and can defend: ✅ welcome
- Copy-pasted output you have not read: ❌ will be rejected
- Generated tests with no understanding of what they cover: ❌ will be rejected
- AI-assisted refactors where you can walk through the change: ✅ welcome

---

## Contributor Boundaries

Ori has a clear separation between bundled skills and community skills. Understanding this is essential before contributing.

### The two-tier skill model

```text
┌─────────────────────────────────────────────────────────────┐
│  BUNDLED SKILLS  /skills/ in this repo                      │
│  Loaded via _load_hooks_direct() — sandbox bypassed         │
│  Shipped with the runtime. Implicitly trusted.              │
│  Requires core maintainer review. Ed25519 not required.     │
├─────────────────────────────────────────────────────────────┤
│  COMMUNITY SKILLS  ~/.ori/skills/ on device                 │
│  Loaded via load_hooks_restricted() — sandboxed             │
│  Installed from the Skills Hub. Never in this repo.         │
│  Verified: Ed25519 signature + VirusTotal scan before load  │
└─────────────────────────────────────────────────────────────┘
```

### `/skills/` in this repo — bundled skills (maintainer review required)

**These are first-party skills that ship with the runtime.** Because they use
`_load_hooks_direct()`, their `hooks.py` bypasses the import sandbox entirely.
A malicious or broken bundled skill can access any Python module on the system.

**Submitting a bundled skill PR:**

- Open an issue first and get maintainer approval before writing code
- The skill must be genuinely useful across a broad deployment context
- `hooks.py` must be clean and minimal — no external API calls without explicit discussion
- All triggers must declare `action_tier`
- Tier C and D triggers require maintainer sign-off on the design
- Expect thorough review — bundled skills have the same trust level as core runtime

### Community skills — [ori-platform/ori-skills](https://github.com/ori-platform/ori-skills)

**Community skill contributions do not go here.** They go to the
[ori-skills repository](https://github.com/ori-platform/ori-skills), where they go through:

1. **Ed25519 signature verification** — every skill is signed by its author;
   the runtime verifies the signature before loading
2. **VirusTotal scan** — automated malware scan before Hub listing
3. **Sandbox enforcement** — loaded via `load_hooks_restricted()` with an
   explicit import allowlist; `hooks.py` cannot import arbitrary modules
4. **Hub review** — community maintainer review for quality and safety

The operator installs only the skills they explicitly want. The runtime
never auto-loads from the Hub — explicit selection is the model.

### `/ori/` — Core runtime (maintainer review required)

Changes here affect physical hardware. Every core runtime PR requires:

- An issue opened and discussed **before** writing code
- Maintainer review via CODEOWNERS — PRs cannot be merged without approval
- 100% test coverage on every Tier D code path
- No new dependencies without prior discussion in an issue

If you want to change something in `/ori/` that would be a meaningful
improvement, the right first step is always to open an issue.

---

## How to Contribute

### 1. Find or Create an Issue

- Browse [open issues](https://github.com/ori-platform/ori-runtime/issues)
- Good first issues are labelled `good-first-issue`
- For larger features, open a discussion first

### 2. Fork and Branch

```bash
git checkout -b feature/your-feature-name
```

Branch naming conventions:

- `feature/description` — new functionality
- `fix/description` — bug fixes
- `docs/description` — documentation updates
- `skill/skill-name` — new bundled skill

### 3. Implement Your Change

Identify which [extension point](AGENTS.md) your change fits into:

| I want to...          | Pattern             | Reference      |
| --------------------- | ------------------- | -------------- |
| Add a sensor protocol | New HAL adapter     | `AGENTS.md` §1 |
| Add agent behaviour   | New skill           | `AGENTS.md` §2 |
| Add an action type    | New action executor | `AGENTS.md` §3 |
| Add an LLM backend    | New reasoning tier  | `AGENTS.md` §4 |
| Add a background task | Runtime event loop  | `AGENTS.md` §5 |

### 4. Write Tests and Submit

```bash
# Run tests
pytest tests/ -v

# Lint
ruff check --fix ori/ tests/

# Verify clean import on laptop
python -c "import ori; print('imports ok')"
```

Then open a pull request.

---

## Code Standards

### Language and Style

- **Python 3.11+** with `asyncio` throughout
- **Type hints** on every function signature
- **Naming:** files `snake_case`, classes `PascalCase`, constants `UPPER_SNAKE_CASE`
- **Line length:** 88 characters (enforced by `ruff`)
- **Linter:** `ruff check --fix` on every file before committing

### Copyright Header

Every new Python file **must** begin with:

```python
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
```

### Async Patterns

```python
# ✅ CORRECT
await asyncio.sleep(1)
async with aiofiles.open(...)
asyncio.create_task(fn())

# ❌ WRONG — never block the event loop
time.sleep(1)
requests.get(url)  # use httpx or aiohttp
```

### Error Handling

- **HAL adapters** raise only `AdapterConnectionError` or `AdapterTimeoutError`
- **Action executors** never raise — they return `False` on failure
- **The runtime must survive** any single component failure gracefully

---

## Testing

### Running Tests

```bash
# Full suite
pytest tests/ -v

# Specific module
pytest tests/test_rule_engine.py -v

# With coverage
pytest tests/ --cov=ori --cov-report=term-missing

# Skip hardware tests (automatic on non-Pi)
pytest tests/ -v -m "not hardware"
```

### Test Requirements

- Every new module needs a corresponding `tests/test_{module}.py`
- Test both **happy path** and **negative/edge cases**
- Use `@pytest.mark.asyncio` for async tests
- Mock hardware — tests must pass on a standard laptop
- Guard hardware-dependent tests with `@pytest.mark.skipif`

### Writing Good Tests

Follow the existing test patterns. Ori's test suite is comprehensive:

```python
# Happy path
def test_condition_true_returns_match():
    ...

# Negative path
def test_unsafe_condition_raises():
    ...

# Edge case
def test_broken_condition_is_skipped():
    ...

# Integration
async def test_psutil_adapter_integration():
    ...
```

The test suite currently has **790+ tests** covering all layers.
Every PR must maintain or increase this count.

---

## Safety Invariants

These rules are **inviolable**. They exist because Ori controls physical
hardware. Violating them creates vulnerabilities that affect the real world.

1. **Never bypass Tier C approval.** Hard physical actions always require
   operator approval. There is no config flag to skip it.

2. **Never add LLM calls to Tier D paths.** Safety-critical actions fire
   from the deterministic rule engine. `bypass_llm: true` is automatic.

3. **Never use string-pattern matching for condition validation.** The rule
   engine uses AST whitelist validation (`_check_safety_ast`). Only
   comparisons, boolean ops, arithmetic, names, constants, and
   `history.method()` calls are permitted.

4. **Never load community skill hooks with raw `importlib`.** Always use
   the sandboxed loader in `ori/skills/sandbox.py`.

5. **Never call relay.py directly.** `RelayAction.trigger()` and
   `RelayAction.release()` must only be called through `ActionDispatcher`.

6. **Never store credentials in code.** All secrets go in `.env` (gitignored).

7. **Action executors never raise exceptions.** They return `False`.
   The runtime must survive a failed action.

8. **SQLite queries are always parameterised.** No f-string SQL. Ever.

If you're unsure whether your change violates a safety invariant, open a
discussion before submitting. We'd rather review a question than revert a PR.

---

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(hal): add GrowattAdapter for SolarmanV5 protocol
fix(rule-engine): handle NaN sensor values before evaluation
docs(agents): update circuit breaker instructions
test(hooks): add HookStateAdapter isolation tests
skill(hvac): add hvac-refrigerant-monitor skill
refactor(elevator): extract battery throttle into method
security(sandbox): restrict allowed imports for community hooks
```

Prefix with `security` for any change touching safety invariants.

---

## Signed Commits (Required)

This repository enforces **verified signed commits** on protected branches.
Unsigned commits will block merge.

### Recommended setup: SSH signing (no GPG binary required)

```bash
# Use SSH signatures for commits
git config --global gpg.format ssh
git config --global commit.gpgsign true
git config --global user.signingkey ~/.ssh/id_ed25519.pub
```

If your key path differs, replace `~/.ssh/id_ed25519.pub`.

### GitHub account setup

In **GitHub → Settings → SSH and GPG keys**:

1. Add your public key as an **Authentication key** (normal git access)
2. Add the same public key again as a **Signing Key**

Without step 2, commits may still show as unverified.

### Verify before pushing

```bash
git log --format='%h %G? %ae %s' origin/main..HEAD
```

`%G?` should show `G` for each commit.

### If your branch already has unsigned commits

```bash
# Re-sign each commit on your feature branch
git rebase -i origin/main --exec "git commit --amend -S --no-edit"

# Push rewritten branch history
git push --force-with-lease
```

Force-push here is expected only for your feature branch after re-signing.
Direct pushes to `main` remain blocked by branch protection.

### Optional local verification fix

If git shows `gpg.ssh.allowedSignersFile needs to be configured...`:

```bash
printf "%s %s\n" "$(git config user.email)" "$(cat ~/.ssh/id_ed25519.pub)" > ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

---

## Pull Request Process

1. **All tests pass** — `pytest tests/ -v` must show 0 failures
2. **No lint errors** — `ruff check ori/ tests/` must be clean
3. **Clean laptop import** — `python -c "import ori"` must not error
4. **Copyright headers present** — on every new `.py` file
5. **Description explains WHY** — not just what changed
6. **One concern per PR** — don't bundle unrelated changes

### For New Skills

```bash
# Validate skill loads cleanly
python -c "
import asyncio
from ori.skills.loader import SkillLoader
skill = asyncio.run(SkillLoader().load_one('skills/your-skill-name'))
print(f'Loaded: {skill.name} v{skill.version}')
"
```

### For New Adapters

```bash
# Verify graceful import on non-Pi hardware
python -c "from ori.hal.your_adapter import YourAdapter; print('ok')"
```

---

## Types of Contributions Welcome

### 🔌 New HAL Adapters

Expand the sensors Ori can read — industrial protocols (Modbus, OPC-UA),
smart inverter protocols (SolarmanV5, VenusOS MQTT), environmental sensors.

### 🧠 New Skills

**Community skills** — agriculture, cold chain, HVAC, water quality, solar energy
and more — go to **[ori-platform/ori-skills](https://github.com/ori-platform/ori-skills)**.
They are verified with Ed25519 signatures and VirusTotal scans before being listed.

**Bundled skills** (additions to `/skills/` in this repo) are first-party only.
Open an issue first to discuss whether a skill belongs in the core bundle.

### 🔧 Action Executors

New ways for Ori to act on its reasoning — webhook integrations,
MQTT commands, Modbus writes, push notifications.

### 📝 Documentation

Improve guides, add tutorials, translate documentation for accessibility
across regions where Ori deploys (West Africa, South Asia, Latin America).

### 🧪 Tests

Fill coverage gaps, add edge-case tests, improve test infrastructure.

### 🐛 Bug Reports

File detailed bug reports with steps to reproduce. Include hardware
details if the bug involves a specific sensor or adapter.

---

## Community Guidelines

### Be Respectful

This project serves operators in Lagos, Nairobi, Mumbai, and São Paulo.
Contributions that improve accessibility, reduce hardware requirements,
or work better with unreliable infrastructure are deeply valued.

### Ask Questions

If something in the architecture is unclear, open a discussion. The
codebase is complex for good reasons — we're happy to explain.

### Think Physically

Every line of code potentially affects physical hardware. A bug in a
monitoring dashboard shows wrong numbers. A bug in Ori could trip a
circuit breaker. Code with that awareness.

---

## Security

See [`SECURITY.md`](SECURITY.md) for the current vulnerability reporting
process, response timelines, disclosure policy, and security scope.

---

## Relevant Reading

- [**PRINCIPLES.md**](PRINCIPLES.md) — The six design lenses
- [**CLAUDE.md**](CLAUDE.md) — Full architectural specification
- [**AGENTS.md**](AGENTS.md) — Extension patterns for AI coding agents and contributors
- [**LICENSE**](LICENSE) — Apache 2.0

---

<div align="center">
  <strong>Ori Nexus Systems LTD</strong> · Lagos, Nigeria · 2026
  <br/>
  <em>Give your devices a brain.</em>
</div>
