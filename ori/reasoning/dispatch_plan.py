# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""What a matched trigger licenses, and at what authority each of its actions runs.

The tier letter folds two independent decisions together. *Consequence class* —
informational, soft, hard — is what an action does to the world, and the runtime
registry owns it because reversibility is a fact about site wiring established
at commissioning. *Authority basis* — autonomous, operator approval, or a
release-owned safety condition — is what licenses one dispatch. A is
informational and autonomous; D is hard under a safety condition. They share an
authority basis while sitting at opposite ends of the letter ordering, which is
why every rule here that takes a maximum over tiers exempts informational
actions.

``docs/DISPATCH_PLAN.md`` is the contract this module implements.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ori.reasoning.action_registry import (
    capability,
    enforce_minimum_tier,
    tier_rank,
)

logger = logging.getLogger(__name__)

OPEN_PROTECTED_CIRCUIT = "open_protected_circuit"
CLOSE_PROTECTED_CIRCUIT = "close_protected_circuit"

# Which commissioned outcome each actuator-driving action resolves to. Two names
# can be one act: `trip_relay` and `close_gas_valve` both isolate the load and
# share a single executor, so on one zone they are the same act. `release_relay`
# is the same resource with the opposite outcome.
_COMMISSIONED_OUTCOMES: dict[str, str] = {
    "trip_relay": OPEN_PROTECTED_CIRCUIT,
    "close_gas_valve": OPEN_PROTECTED_CIRCUIT,
    "release_relay": CLOSE_PROTECTED_CIRCUIT,
}

# This map is the registry's physical set, and it grows only when the specs
# add an outcome. A name here with no executor behind it would let an action
# that drives nothing reach Tier D, so the two must stay identical.

# Actions that change host state and resolve through no commissioned zone. They
# take their registry floor and are unaffected by the binding rules below.
_HOST_SCOPED_ACTIONS: frozenset[str] = frozenset(
    {"terminate_process", "reset_kernel_subsystem"}
)

# The outcome a safety condition licenses. A condition protects by isolating;
# nothing in the current vocabulary protects by reconnecting.
PROTECTIVE_OUTCOME = OPEN_PROTECTED_CIRCUIT


class DispatchOutcome:
    """What a trigger's action actually reached, for cooldown accounting."""

    # Not one of the six outcomes: it marks an action the plan has not yet
    # resolved. Anything still carrying it when the event is done reached
    # nothing, and is recorded as `fully_refused` rather than left ambiguous.
    PENDING = ""

    ATTEMPTED = "attempted"
    JOINED_ATTEMPT = "joined_attempt"
    PROPOSAL_OPENED = "proposal_opened"
    PREEMPTED = "preempted"
    FULLY_REFUSED = "fully_refused"
    CONDITION_FALSE = "condition_false"


# Ordered strongest first. `attempted` outranks `proposal_opened` because
# something happened rather than was asked about; the ordering is written down
# so two implementations cannot disagree about a trigger that both acted and
# proposed.
_OUTCOME_ORDER: tuple[str, ...] = (
    DispatchOutcome.ATTEMPTED,
    DispatchOutcome.JOINED_ATTEMPT,
    DispatchOutcome.PROPOSAL_OPENED,
    DispatchOutcome.PREEMPTED,
    DispatchOutcome.FULLY_REFUSED,
    DispatchOutcome.CONDITION_FALSE,
)

_CONSUMING_OUTCOMES: frozenset[str] = frozenset(
    {
        DispatchOutcome.ATTEMPTED,
        DispatchOutcome.JOINED_ATTEMPT,
        DispatchOutcome.PROPOSAL_OPENED,
    }
)


def strongest_outcome(outcomes: list[str]) -> str:
    """The strongest outcome in *outcomes*.

    An unresolved action contributes nothing; a trigger whose actions all went
    unresolved reached nothing and is `fully_refused`, which consumes no
    cooldown.
    """
    for candidate in _OUTCOME_ORDER:
        if candidate in outcomes:
            return candidate
    return DispatchOutcome.FULLY_REFUSED


def consumes_cooldown(outcome: str) -> bool:
    """Whether *outcome* spends the trigger's cooldown."""
    return outcome in _CONSUMING_OUTCOMES


def is_informational(action: str) -> bool:
    """Whether the runtime's own registry proves *action* inert.

    True only for an entry with an A floor that is not physical. The skill's
    declaration does not decide it, and an action with no registry entry is
    never informational — the runtime cannot prove that something it does not
    govern is inert.
    """
    entry = capability(action)
    return entry is not None and entry.minimum_tier == "A" and not entry.physical


def requires_commissioned_binding(action: str) -> bool:
    """Whether *action* drives a commissioned actuator and needs a zone to mean anything."""
    return action in _COMMISSIONED_OUTCOMES


def commissioned_outcome(action: str) -> str | None:
    """The commissioned outcome *action* resolves to, or None if it drives no actuator."""
    return _COMMISSIONED_OUTCOMES.get(action)


@dataclass(frozen=True)
class ResourceIdentity:
    """What an action drives, and what it does to it.

    The resource and the outcome are separate fields, and conflating them
    defeats the purpose: if the outcome were part of the identity, opening and
    closing a circuit would carry different identities and would never be seen
    to conflict, which is the one collision the gate exists to catch.
    """

    resource_key: tuple[str, ...]
    desired_outcome: str
    # Everything else that would make two contributors different acts. A CoAP
    # command to one URI with a different payload is not the same act.
    join_parameters: tuple[tuple[str, str], ...] = ()

    @property
    def join_key(self) -> tuple[Any, ...]:
        return (self.resource_key, self.desired_outcome, self.join_parameters)


def resource_identity(
    action: str,
    *,
    zone_identity_key: tuple[str, str] | None = None,
    binding_revision: str = "",
    target: str = "",
    coap_uri: str = "",
    coap_parameters: tuple[tuple[str, str], ...] = (),
) -> ResourceIdentity | None:
    """The resource *action* drives, or None when it holds none.

    Informational actions hold no resource and are never admitted against one.
    """
    if is_informational(action):
        return None

    outcome = _COMMISSIONED_OUTCOMES.get(action)
    if outcome is not None:
        if zone_identity_key is None:
            return None
        return ResourceIdentity(
            resource_key=tuple(zone_identity_key),
            desired_outcome=outcome,
            join_parameters=(("binding_revision", binding_revision),),
        )

    if action == "coap_command":
        if not coap_uri:
            return None
        return ResourceIdentity(
            resource_key=("coap", coap_uri),
            desired_outcome=action,
            join_parameters=coap_parameters,
        )

    if action in _HOST_SCOPED_ACTIONS:
        # The outcome is the action itself, so two of the same coalesce and
        # there is no opposite to conflict with. An unresolved target is not a
        # shared resource: keying two unrelated terminations on one empty string
        # would coalesce them into a single act.
        if not target:
            return None
        return ResourceIdentity(
            resource_key=("host", action, target),
            desired_outcome=action,
        )

    entry = capability(action)
    if entry is None or not entry.physical:
        return None
    return ResourceIdentity(resource_key=("action", action), desired_outcome=action)


def opposes(left: ResourceIdentity, right: ResourceIdentity) -> bool:
    """Whether two admitted identities are opposite acts on one resource."""
    if left.resource_key != right.resource_key:
        return False
    opposed = {OPEN_PROTECTED_CIRCUIT, CLOSE_PROTECTED_CIRCUIT}
    return (
        left.desired_outcome != right.desired_outcome
        and left.desired_outcome in opposed
        and right.desired_outcome in opposed
    )


@dataclass(frozen=True)
class BindingView:
    """What the commissioned binding establishes for this device.

    ``consequence_by_outcome`` carries the class the zone's mapping resolves an
    outcome to. Absent, the action is not dispatched at all: the runtime has no
    basis to say what driving that actuator would do here.
    """

    zone_identity_key: tuple[str, str] | None = None
    binding_revision: str = ""
    consequence_by_outcome: dict[str, str] = field(default_factory=dict)

    def consequence_for(self, outcome: str) -> str | None:
        return self.consequence_by_outcome.get(outcome)


_CONSEQUENCE_FLOOR: dict[str, str] = {"informational": "A", "soft": "B", "hard": "C"}


def effective_floor(action: str, binding: BindingView | None) -> str | None:
    """The floor the registry and the binding compose into, or None to refuse dispatch.

    The binding may raise and may never lower. A registry floor of B on a zone
    whose mapping makes the act irreversible resolves to hard and dispatches at
    C. The converse is refused rather than applied: a registry floor of C is
    never lowered because a binding calls the act reversible, since the floor is
    the runtime's own reviewed judgement and a binding is site data.
    """
    entry = capability(action)
    registry_floor = entry.minimum_tier if entry is not None else "A"

    outcome = _COMMISSIONED_OUTCOMES.get(action)
    if outcome is None:
        return registry_floor

    if binding is None or binding.zone_identity_key is None:
        return None

    resolved = binding.consequence_for(outcome)
    if resolved is None:
        return None

    binding_floor = _CONSEQUENCE_FLOOR.get(resolved)
    if binding_floor is None:
        logger.warning(
            "dispatch plan: binding resolves %r to unknown consequence %r; "
            "keeping the registry floor",
            action,
            resolved,
        )
        return registry_floor

    if tier_rank(binding_floor) < tier_rank(registry_floor):
        logger.warning(
            "dispatch plan: binding resolves %r to %r, below the registry floor "
            "%s; keeping the floor and reporting the disagreement",
            action,
            resolved,
            registry_floor,
        )
        return registry_floor

    return binding_floor


@dataclass(frozen=True)
class TierDGrant:
    """Whether the safety condition licenses this exact action, and why not."""

    granted: bool
    refusal: str = ""


def tier_d_grant(
    *,
    action: str,
    incident_tier: str,
    bypass_llm: bool,
    first_party: bool,
    declared_actions: tuple[str, ...],
    binding: BindingView | None,
    has_executor: bool,
) -> TierDGrant:
    """Whether every clause of the Tier D grant holds for *action*.

    Tier D removes the operator, so it is granted rather than declared, and it
    is granted to one commissioned outcome on one resource rather than to an
    action name or a plan.

    There is no separate clause excluding informational actions: no action is
    both registered inert and mapped to a commissioned outcome, so the outcome
    clause already refuses every one of them. The guarantee that an
    informational action never rises above Tier A is enforced in
    :func:`assign_action_tier`, before this function is consulted at all.
    """
    if str(incident_tier).upper() != "D":
        return TierDGrant(False, "incident is not Tier D")
    if not bypass_llm:
        return TierDGrant(False, "Tier D trigger does not bypass the model")
    if not first_party:
        return TierDGrant(False, "trigger does not belong to a first-party skill")

    outcome = _COMMISSIONED_OUTCOMES.get(action)
    if outcome is None:
        return TierDGrant(False, "action resolves to no commissioned outcome")
    if outcome != PROTECTIVE_OUTCOME:
        return TierDGrant(
            False,
            f"{outcome} is not the protective outcome for a safety condition",
        )
    if binding is None or binding.zone_identity_key is None:
        return TierDGrant(False, "no commissioned zone covers this action")
    if binding.consequence_for(outcome) is None:
        return TierDGrant(False, "the zone establishes no meaning for this outcome")

    # The defaults list narrows and never grants: it can only select from what
    # the licensed outcome already covers.
    if action not in declared_actions:
        return TierDGrant(False, "action is not named in the trigger's defaults")

    if not has_executor:
        return TierDGrant(False, "no registered executor to attach the authority to")

    return TierDGrant(True)


UNGOVERNED_ACTION = "ungoverned_action"
UNBOUND_ACTUATOR = "unbound_actuator"


@dataclass
class PlannedAction:
    """One action of one matched trigger, with the authority it will run under."""

    action: str
    dispatch_tier: str
    identity: ResourceIdentity | None
    tier_d_granted: bool
    refusal: str = ""
    outcome: str = DispatchOutcome.PENDING

    @property
    def admitted(self) -> bool:
        return not self.refusal

    @property
    def informational(self) -> bool:
        return is_informational(self.action)


def assign_action_tier(
    *,
    action: str,
    incident_tier: str,
    declared_tier: str,
    bypass_llm: bool,
    first_party: bool,
    declared_actions: tuple[str, ...],
    binding: BindingView | None,
    has_executor: bool,
    zone_identity_key: tuple[str, str] | None = None,
    binding_revision: str = "",
    target: str = "",
    coap_uri: str = "",
    coap_parameters: tuple[tuple[str, str], ...] = (),
) -> PlannedAction:
    """Decide the authority one action runs under.

    Nothing inherits authority from the incident. An ancillary action in a Tier
    D plan runs at its own authority, capped at C, or is refused. A notification
    in a Tier C plan is Tier A.
    """
    if capability(action) is None:
        # `register_executor()` already refuses a name with no registry entry, so
        # such an action can never actuate. Letting it travel as far as dispatch
        # turns a declaration error into a runtime one, and at Tier D that is the
        # worst possible place to discover it.
        return PlannedAction(
            action=action,
            dispatch_tier="A",
            identity=None,
            tier_d_granted=False,
            refusal=UNGOVERNED_ACTION,
        )

    if is_informational(action):
        return PlannedAction(
            action=action,
            dispatch_tier="A",
            identity=None,
            tier_d_granted=False,
        )

    grant = tier_d_grant(
        action=action,
        incident_tier=incident_tier,
        bypass_llm=bypass_llm,
        first_party=first_party,
        declared_actions=declared_actions,
        binding=binding,
        has_executor=has_executor,
    )

    identity = resource_identity(
        action,
        zone_identity_key=zone_identity_key,
        binding_revision=binding_revision,
        target=target,
        coap_uri=coap_uri,
        coap_parameters=coap_parameters,
    )

    if grant.granted:
        return PlannedAction(
            action=action,
            dispatch_tier="D",
            identity=identity,
            tier_d_granted=True,
        )

    floor = effective_floor(action, binding)
    if floor is None:
        # The action drives a commissioned actuator and no zone covers it. The
        # runtime has no basis to say what it would do.
        return PlannedAction(
            action=action,
            dispatch_tier="A",
            identity=identity,
            tier_d_granted=False,
            refusal=UNBOUND_ACTUATOR,
        )

    ordinary = enforce_minimum_tier(action, str(declared_tier or floor).upper())
    if tier_rank(floor) > tier_rank(ordinary):
        ordinary = floor
    # Capped at C: an action reaches D through the licensed-outcome branch or
    # not at all. This is the same rule the loader applies to a package's list.
    if tier_rank(ordinary) > tier_rank("C"):
        ordinary = "C"

    return PlannedAction(
        action=action,
        dispatch_tier=ordinary,
        identity=identity,
        tier_d_granted=False,
    )


@dataclass
class TriggerPlan:
    """One matched trigger and the actions its defaults name."""

    skill_name: str
    trigger_name: str
    incident_tier: str
    bypass_llm: bool
    first_party: bool
    actions: list[PlannedAction] = field(default_factory=list)
    cooldown_seconds: int = 0
    # The match this plan was built from, carried so the reasoning path uses it
    # rather than evaluating the same rules again against state the plan has
    # since changed.
    rule_result: Any = None
    # Whether a reasoning task was scheduled for this trigger. Such a plan is
    # charged when that task settles rather than when it is scheduled.
    scheduled: bool = False

    @property
    def outcome(self) -> str:
        return strongest_outcome([a.outcome for a in self.actions])

    @property
    def is_tier_d_incident(self) -> bool:
        return str(self.incident_tier).upper() == "D"

    @property
    def grants_tier_d(self) -> bool:
        return any(a.tier_d_granted for a in self.actions)


@dataclass
class DispatchPlan:
    """Every trigger that matched for one event, across one skill."""

    skill_name: str
    correlation_id: str
    triggers: list[TriggerPlan] = field(default_factory=list)

    @property
    def tier_d_triggers(self) -> list[TriggerPlan]:
        return [t for t in self.triggers if t.grants_tier_d]
