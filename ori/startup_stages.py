# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The order `OriRuntime.start()` runs its stages in, as data.

Each stage is a method `OriRuntime._stage_<name>(context)`. The tuple is the
order, the constraint table says which orderings exist and why, and the
checkpoint set names the stages after which startup stops if a signal asked
it to. `docs/STARTUP_STAGES.md` carries the design;
`tests/test_startup_stages.py` holds the order, the context flow and each
stage's runtime surface to this module and to the code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from ori.actions.alert_failover import AlertFailoverSender
    from ori.actions.coap import CoAPAction
    from ori.actions.logger import LoggerAction
    from ori.actions.process_manager import ProcessManagerAction
    from ori.actions.relay import RelayAction
    from ori.actions.sms import SMSAction
    from ori.actions.system_control import SystemControlAction
    from ori.actions.whatsapp import WhatsAppAction
    from ori.config import Config
    from ori.gateway.envelope_auth import GatewayEnvelopeState
    from ori.hardware.led_indicator import LEDIndicator
    from ori.network.event_bus import EventBus
    from ori.reasoning.action_dispatcher import ActionDispatcher
    from ori.reasoning.capability_posture import CapabilityPostureTracker
    from ori.reasoning.elevator import IntelligenceElevator
    from ori.reasoning.local_llm import LocalLLM
    from ori.security.commissioning.anchors import CommissioningAnchors
    from ori.security.evidence.first_party import FirstPartyEvidenceAttestor


class StartupContext:
    """The values one startup stage hands to a later one, and nothing else.

    A field is unset until the stage that sets it has run, and reading it
    earlier raises `AttributeError`. A value the runtime keeps is stored on the
    runtime, not here.
    """

    __slots__ = (
        "config",
        "commissioning_anchors",
        "status_cfg",
        "status_indicator",
        "whatsapp_action",
        "sms_action",
        "coap_action",
        "logger_action",
        "process_manager_action",
        "system_control_action",
        "has_relay_config",
        "relay_action",
        "relay_enabled",
        "operator_contact",
        "secondary_contact",
        "primary_alert_channel",
        "rejection_expiry_days",
        "alert_sender",
        "evidence_attestor",
        "dispatcher",
        "posture_cfg",
        "posture_tracker",
        "local_llm",
        "gateway_envelope_state",
        "elevator",
        "event_bus",
    )

    config: Config
    commissioning_anchors: CommissioningAnchors
    status_cfg: dict[str, Any]
    status_indicator: LEDIndicator | None
    whatsapp_action: WhatsAppAction
    sms_action: SMSAction
    coap_action: CoAPAction
    logger_action: LoggerAction
    process_manager_action: ProcessManagerAction
    system_control_action: SystemControlAction
    has_relay_config: bool
    relay_action: RelayAction | None
    relay_enabled: bool
    operator_contact: str
    secondary_contact: str
    primary_alert_channel: str
    rejection_expiry_days: int
    alert_sender: AlertFailoverSender
    evidence_attestor: FirstPartyEvidenceAttestor | None
    dispatcher: ActionDispatcher
    posture_cfg: dict[str, Any]
    posture_tracker: CapabilityPostureTracker | None
    local_llm: LocalLLM | None
    gateway_envelope_state: GatewayEnvelopeState | None
    elevator: IntelligenceElevator
    event_bus: EventBus


class Stage(NamedTuple):
    """One stage, with the context fields it reads and the ones it sets."""

    name: str
    reads: frozenset[str] = frozenset()
    sets: frozenset[str] = frozenset()


def _fields(*names: str) -> frozenset[str]:
    return frozenset(names)


STARTUP_STAGES: tuple[Stage, ...] = (
    Stage(
        "configuration",
        sets=_fields(
            "config", "commissioning_anchors", "status_cfg", "status_indicator"
        ),
    ),
    Stage("store", reads=_fields("config")),
    Stage(
        "actions",
        reads=_fields("config"),
        sets=_fields(
            "whatsapp_action",
            "sms_action",
            "coap_action",
            "logger_action",
            "process_manager_action",
            "system_control_action",
            "has_relay_config",
            "relay_action",
            "relay_enabled",
        ),
    ),
    Stage(
        "safety_envelope",
        reads=_fields(
            "config", "commissioning_anchors", "has_relay_config", "relay_action"
        ),
        sets=_fields("has_relay_config", "relay_action"),
    ),
    Stage(
        "alerting",
        reads=_fields("config", "relay_enabled", "sms_action", "whatsapp_action"),
        sets=_fields(
            "operator_contact",
            "secondary_contact",
            "primary_alert_channel",
            "alert_sender",
            "rejection_expiry_days",
        ),
    ),
    Stage("evidence", reads=_fields("config"), sets=_fields("evidence_attestor")),
    Stage(
        "dispatcher",
        reads=_fields(
            "config",
            "status_indicator",
            "sms_action",
            "coap_action",
            "logger_action",
            "process_manager_action",
            "system_control_action",
            "relay_action",
            "relay_enabled",
            "operator_contact",
            "secondary_contact",
            "primary_alert_channel",
            "rejection_expiry_days",
            "alert_sender",
            "evidence_attestor",
        ),
        sets=_fields("dispatcher"),
    ),
    Stage(
        "reasoning",
        reads=_fields("config"),
        sets=_fields(
            "posture_cfg",
            "posture_tracker",
            "local_llm",
            "gateway_envelope_state",
            "elevator",
        ),
    ),
    Stage(
        "event_path",
        reads=_fields(
            "config",
            "status_indicator",
            "relay_action",
            "alert_sender",
            "dispatcher",
            "elevator",
            "local_llm",
            "posture_tracker",
        ),
        sets=_fields("event_bus"),
    ),
    Stage("skills", reads=_fields("config", "dispatcher", "elevator")),
    Stage("signals"),
    Stage("sensor_state", reads=_fields("config")),
    Stage("tier_c_recovery", reads=_fields("dispatcher")),
    Stage("sensors", reads=_fields("config", "event_bus")),
    Stage(
        "loops",
        reads=_fields(
            "config",
            "status_cfg",
            "status_indicator",
            "relay_action",
            "alert_sender",
            "dispatcher",
            "elevator",
            "local_llm",
            "posture_cfg",
            "posture_tracker",
        ),
    ),
    Stage(
        "services",
        reads=_fields(
            "config",
            "event_bus",
            "evidence_attestor",
            "posture_tracker",
            "gateway_envelope_state",
        ),
    ),
    Stage("operator_services", reads=_fields("config", "gateway_envelope_state")),
    Stage("health_and_reconciliation", reads=_fields("config", "status_indicator")),
    Stage("announce", reads=_fields("config", "alert_sender")),
)

#: Stages after which startup stops if a signal asked it to during startup.
STARTUP_CHECKPOINTS: frozenset[str] = frozenset(
    {"loops", "services", "operator_services", "health_and_reconciliation"}
)


class Constraint(NamedTuple):
    """`later` runs after `earlier`, for `reason`."""

    later: str
    earlier: str
    reason: str
    safety: bool


STARTUP_CONSTRAINTS: tuple[Constraint, ...] = (
    Constraint(
        "safety_envelope",
        "configuration",
        "the commissioning anchors are compared with the provisioning anchor "
        "before any binding is read; a binding verified under the provisioning "
        "key would license actuation from it",
        safety=True,
    ),
    Constraint(
        "evidence",
        "safety_envelope",
        "evidence never gates safety: the attestor starts after the registry, "
        "and evidence trust that cannot be established fails closed for evidence "
        "only",
        safety=True,
    ),
    Constraint(
        "dispatcher",
        "safety_envelope",
        "relay-backed executors are registered only when a commissioned actuator "
        "is in force, so the actuator must be decided first",
        safety=True,
    ),
    Constraint(
        "skills",
        "dispatcher",
        "a skill declaring an action above Tier A is checked at load against the "
        "executors the dispatcher holds",
        safety=True,
    ),
    Constraint(
        "tier_c_recovery",
        "dispatcher",
        "proposals a previous process left are closed with their safe default, "
        "which needs every executor registered",
        safety=True,
    ),
    Constraint(
        "sensors",
        "tier_c_recovery",
        "no governed Tier C proposal is raised over proposals this process never "
        "settled, so recovery precedes any sensor loop",
        safety=True,
    ),
    Constraint(
        "sensors",
        "safety_envelope",
        "the registry starts before any reading can arrive, and a sensor that "
        "fails to connect is reported to it at the moment it fails",
        safety=True,
    ),
    Constraint(
        "actions",
        "store",
        "the actions, the journal, the outbox and the lockout state live in the store",
        safety=False,
    ),
    Constraint(
        "safety_envelope",
        "actions",
        "the envelope reads the relay decision the actions stage initialises, and "
        "a configuration that cannot build an action aborts before any pin is "
        "considered",
        safety=False,
    ),
    Constraint(
        "dispatcher",
        "alerting",
        "the dispatcher and its executors send through the failover sender",
        safety=False,
    ),
    Constraint(
        "dispatcher",
        "evidence",
        "the dispatcher attests actions through the attestor",
        safety=False,
    ),
    Constraint(
        "services",
        "reasoning",
        "every gateway route shares the one envelope state built with the "
        "gateway reasoner",
        safety=False,
    ),
    Constraint(
        "services",
        "dispatcher",
        "the firmware liveness stack reads the reading-age table built before "
        "the dispatcher",
        safety=False,
    ),
    Constraint(
        "sensors",
        "signals",
        "a device that cannot be stopped for the whole of startup is worse than "
        "one that stops untidily, and adapter connects can block on hardware",
        safety=False,
    ),
    Constraint(
        "sensors",
        "event_path",
        "poll tasks publish onto the event bus, and the first posture snapshot "
        "precedes any event",
        safety=False,
    ),
    Constraint(
        "health_and_reconciliation",
        "services",
        "pending attestations reconcile after the services are up",
        safety=False,
    ),
    Constraint(
        "health_and_reconciliation",
        "tier_c_recovery",
        "the operator socket serves reconciliation of an uncertain Tier C "
        "dispatch, which recovery records; before it, a dispatch a previous "
        "process left mid-way is still dispatch_started and the store refuses "
        "the reconciliation not_uncertain. The store decides which states admit "
        "one, so this order spares a refused attempt and is not a safety boundary",
        safety=False,
    ),
    Constraint(
        "announce",
        "health_and_reconciliation",
        "the setup notification is last, after the indicator reports NORMAL and "
        "the final checkpoint, so a device told to stop never announces itself",
        safety=False,
    ),
)
