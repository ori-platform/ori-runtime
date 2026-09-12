# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Runtime-owned action capability registry.

Skill YAML declares which tier it *believes* an action belongs to. That
declaration is untrusted input: it arrives in the same file the runtime is
meant to be constraining. Before this registry existed, a skill could declare
``trip_relay`` as Tier A and reach immediate autonomous execution without ever
passing through the Tier C approval workflow.

This module is the authority the skill cannot edit. For every action the
runtime is capable of actually executing, it records:

- the **minimum tier** the action may be dispatched at,
- whether the action drives **physical** actuation,
- whether the action is eligible to be a **safe default** — the fallback that
  runs when a Tier C approval is refused or times out.

Two rules follow, enforced independently at both boundaries (skill load and
action dispatch), because authority must not depend on a single check:

1. A declaration below an action's minimum tier is rejected at load and raised
   to the minimum at dispatch. The registry may raise a tier, never lower one.
2. Only safe-default-eligible actions may be named as a safe default.

**Scope.** The registry governs actions the runtime can execute — those with a
registered executor. An action name with no executor cannot actuate anything;
dispatch logs the intent and moves on.

The two cannot drift.
:meth:`~ori.reasoning.action_dispatcher.ActionDispatcher.register_executor`
refuses an action with no entry here, so an action becomes capable of actuation
and becomes governed in the same change — registering an executor without adding
a capability raises rather than silently producing an ungoverned physical
action. A test additionally parses ``runtime.py`` and asserts every executor it
registers appears below.
"""

from dataclasses import dataclass

# Tier ordering. A through C rank by consequence class — how much of the world
# the action changes, and how reversibly — which is what a floor compares
# against. D is not a fourth consequence class: it is Tier C's consequence under
# a different licence, and it ranks above C only so that a declaration of D
# satisfies a floor of C. Reading this as "higher rank means more operator
# authority" is false at exactly one point, and it is the point that matters:
# Tier D removes the operator entirely. No entry may hold a D floor, for the
# reason recorded below.
_TIER_ORDER: dict[str, int] = {"A": 1, "B": 2, "C": 3, "D": 4}


@dataclass(frozen=True)
class ActionCapability:
    """What the runtime knows about an action, independent of any skill.

    Args:
        minimum_tier: Lowest tier this action may be dispatched at.
        physical: Whether the action drives physical actuation.
        safe_default_eligible: Whether the action may serve as the Tier C
            fallback. Only non-actuating actions qualify — a "safe" default
            that operates a contactor is not a safe default.
        summary: Human-readable note used in validation errors.
    """

    minimum_tier: str
    physical: bool
    safe_default_eligible: bool
    summary: str


# The registry itself. Every action with an executor registered in
# `OriRuntime.start()` appears here.
ACTION_REGISTRY: dict[str, ActionCapability] = {
    # ── Informational (Tier A) ────────────────────────────────────────────
    # Reasoned messages the agent sends on its own authority. They inform;
    # they do not actuate, so they are the only valid safe defaults.
    "alert_whatsapp": ActionCapability(
        minimum_tier="A",
        physical=False,
        safe_default_eligible=True,
        summary="sends a WhatsApp message",
    ),
    "alert_sms": ActionCapability(
        minimum_tier="A",
        physical=False,
        safe_default_eligible=True,
        summary="sends an SMS message",
    ),
    "log_to_dashboard": ActionCapability(
        minimum_tier="A",
        physical=False,
        safe_default_eligible=True,
        summary="records the decision to the action log",
    ),
    # ── Soft actions (Tier B) ─────────────────────────────────────────────
    # Reversible and low-consequence, but they change host or device state,
    # so they are never a silent fallback.
    "terminate_process": ActionCapability(
        minimum_tier="B",
        physical=False,
        safe_default_eligible=False,
        summary="terminates a running process",
    ),
    "reset_kernel_subsystem": ActionCapability(
        minimum_tier="B",
        physical=False,
        safe_default_eligible=False,
        summary="resets a kernel subsystem",
    ),
    "coap_command": ActionCapability(
        minimum_tier="B",
        physical=True,
        safe_default_eligible=False,
        summary="commands an actuator on a constrained device",
    ),
    # ── Hard physical (Tier C floor) ──────────────────────────────────────
    # The three actuator-specific names the runtime registers, each resolving
    # to exactly one protected-circuit outcome through the zone's commissioned
    # mapping. `safety-profile/v1` carries this set as normative legacy
    # vocabulary; the names survive the profile migration only as internal
    # executor names behind the outcome resolver. The floor is C rather than
    # an exact match because a skill may propose these for approval, and never
    # below the workflow.
    "trip_relay": ActionCapability(
        minimum_tier="C",
        physical=True,
        safe_default_eligible=False,
        summary="operates the safety relay",
    ),
    "release_relay": ActionCapability(
        minimum_tier="C",
        physical=True,
        safe_default_eligible=False,
        summary="de-energises the safety relay, restoring the load circuit",
    ),
    "close_gas_valve": ActionCapability(
        minimum_tier="C",
        physical=True,
        safe_default_eligible=False,
        summary="closes the fail-safe gas valve",
    ),
}

# No entry may set a Tier D floor. The registry exists to add operator
# authority, and Tier D is the one tier that removes it — an action raised to
# Tier D fires immediately with no approval. A floor of C sends an understated
# declaration into the approval workflow; a floor of D would send it straight
# past. Tier D is reached only through a licensed protective outcome on a
# commissioned zone. `trip_relay` is registered at C for exactly this reason:
# a skill may propose it for approval, and it reaches D only when a safety
# condition licenses the outcome it resolves to.
#
# Every physical entry below has an executor the runtime registers when a
# commissioned zone is accepted. A name governed here with nothing behind it
# is a capability the runtime advertises and does not have: a skill declares
# it, passes load-time validation, reaches dispatch, and nothing happens. New
# physical capability is not added here as a name — it arrives as an outcome on
# a zone, defined in the specs first, which is what keeps commissioning a site
# from requiring a runtime release.
# Checked with a raise rather than `assert`, which `python -O` removes.
_TIER_D_FLOORS = sorted(
    name for name, entry in ACTION_REGISTRY.items() if entry.minimum_tier == "D"
)
if _TIER_D_FLOORS:
    raise RuntimeError(
        f"action registry entries {_TIER_D_FLOORS} declare a Tier D floor; "
        "raising an action to Tier D would escalate it past the approval "
        "workflow rather than into it"
    )


def tier_rank(tier: str) -> int:
    """Rank a tier for comparison. Unknown tiers rank 0."""
    return _TIER_ORDER.get(str(tier).upper(), 0)


def is_valid_tier(tier: str) -> bool:
    """Whether *tier* is one of the four defined tiers."""
    return str(tier).upper() in _TIER_ORDER


def capability(action: str) -> ActionCapability | None:
    """Return the registered capability for *action*, or None if ungoverned."""
    return ACTION_REGISTRY.get(str(action))


def minimum_tier(action: str) -> str | None:
    """Lowest tier *action* may be dispatched at, or None if ungoverned."""
    entry = capability(action)
    return entry.minimum_tier if entry is not None else None


def enforce_minimum_tier(action: str, tier: str) -> str:
    """Raise *tier* to the action's minimum. Never lowers it.

    An ungoverned action keeps the requested tier: with no executor it cannot
    actuate, and dispatch records the intent without effect.
    """
    floor = minimum_tier(action)
    if floor is None:
        return tier
    return floor if tier_rank(floor) > tier_rank(tier) else tier


def is_safe_default_eligible(action: str) -> bool:
    """Whether *action* may be used as a Tier C safe default.

    Ungoverned actions are eligible: without an executor they cannot actuate,
    and rejecting them would break skills whose fallback is a custom
    informational action. Every action that *can* actuate is registered, so
    every action that could do harm here is decided by the registry.
    """
    entry = capability(action)
    return True if entry is None else entry.safe_default_eligible


def is_physical(action: str) -> bool:
    """Whether *action* is known to drive physical actuation."""
    entry = capability(action)
    return entry is not None and entry.physical
