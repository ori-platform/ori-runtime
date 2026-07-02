# Ori Design Principles

The design philosophy governing every architectural decision in this codebase is documented below. Every line of code, architectural design, and feature proposal in this repository must be evaluated through these **seven lenses**.

When you write code or review a pull request, ask yourself if it survives these lenses:

## 1. The Lens of Actuation Trust

_Physical trust is earned, not assumed._

This codebase implements a **Physical Actuation Trust** framework. This is what makes Ori categorically different from every existing IoT platform and LLM agent framework. An AI agent acting in the physical world must earn the authority to act progressively. Ori's Action Tier Framework — Informational (Tier A) → Soft Physical (Tier B) → Hard Physical (Tier C) → Safety-Critical (Tier D) — is not a safety bolt-on. It is the fundamental model through which the runtime demonstrates trustworthiness.

Furthermore, trust requires **Continuous Humility**. The operator's context always supersedes the agent's generalization. When an operator rejects a Tier C proposal, Ori explicitly logs that rejection to causal memory. Trust is won by proving that human correction permanently alters the machine's future behaviour.

See also: The Lens of Explicit Authority Boundaries — which governs how learned behaviour interacts with actuation permissions.

## 2. The Lens of Constraint

_Designed for the world's majority condition._

Ori was designed for the world's majority condition, not its exception. Unreliable power, intermittent connectivity, constrained hardware budgets, and limited cloud access describe the majority of the world's physical infrastructure — including industrial sites in Europe and the United States.

Systems designed for abundance fail in constraint. Systems designed for constraint work everywhere. This means we optimize for the $55 Raspberry Pi (or repurposed Android phone), not the $500 industrial edge server. We embrace the realities of intermittent power supplies and unreliable network interfaces.

## 3. The Lens of Inviolable Safety

_The deterministic layer is absolute._

The Tier D deterministic rule engine fires before any LLM is consulted. It cannot be disabled. It cannot be overridden by an external skill. It cannot be bypassed by a misconfigured action tier. This is not a configuration option — it is an architectural invariant enforced at every layer of the system. An LLM that hallucinates cannot cause a physical safety failure, because it never reaches the physical control layer without passing through deterministic validation first.

## 4. The Lens of Assumed Failure

_Hardware lies. Software freezes. Power dies._

Traditional IoT assumes perfect conditions and throws a fatal stack trace when hardware disconnects. Ori is built on the assumption that the physical world is hostile. Systems must degrade gracefully, not fail categorically. When the power supply drops, Ori throttles its intelligence — disabling LLMs but keeping safety rules alive. When an I2C sensor wire shorts, the HAL circuit breaker isolates the fault so the other sensors survive. Ori expects failure, and is engineered to survive it autonomously.

## 5. The Lens of Offline-First

_Offline-first is the requirement, not a feature._

Most of the world's physical infrastructure does not have reliable internet connectivity. Building an agent runtime that requires the cloud for continuous reasoning is building for the wrong world. The runtime Intelligence Elevator keeps an offline-capable safety core through Tier 1 deterministic rules, local Tier 2 reasoning, and optional Tier 3 LAN gateway reasoning. Cloud reasoning, when used, is a gateway backend, not a runtime tier or dependency. Every safety-critical function must execute cleanly at 2:00 AM during a power and internet outage.

## 6. The Lens of Explicit Capability

_The skill is the atomic unit of trust._

Every autonomous capability Ori possesses is declared, versioned, signed, and auditable. A skill that is not declared cannot execute. An action that is not in the skill's capability declaration cannot be taken. The sandbox enforces this at the import level. The action tier framework enforces this at the execution level. Community skills are cryptographically signed. The trust model is explicit and machine-verifiable.

## 7. The Lens of Explicit Authority Boundaries

_Learning improves reasoning. It never grants permissions._

Learning is allowed to improve recommendations, context, deduplication, and prioritization. Learning is not allowed to silently grant new actuation authority.

- Causal memory may influence reasoning text, alert suppression, and escalation hints.
- Causal memory must never auto-promote action permissions (e.g., Tier C → Tier B) without explicit operator policy change.
- Any permission-affecting change must be versioned, auditable, and human-approved.
- Safety and approval invariants remain authoritative over all learned behaviour.
