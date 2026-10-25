# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The startup stages that lay the foundation, from configuration to the dispatcher."""

import functools
import logging
import os
from typing import Any

from ori.actions.alert_failover import AlertFailoverSender
from ori.actions.coap import CoAPAction
from ori.actions.commissioned_actuator import CommissionedActuator
from ori.actions.executor_targets import (
    kernel_subsystem_from_context as _kernel_subsystem_from_context,
)
from ori.actions.executor_targets import (
    process_target_from_context as _process_target_from_context,
)
from ori.actions.logger import LoggerAction
from ori.actions.process_manager import ProcessManagerAction
from ori.actions.relay import RelayAction, gpio_backend_importable
from ori.actions.sms import SMSAction
from ori.actions.system_control import SystemControlAction
from ori.actions.whatsapp import TwilioProvider, WhatsAppAction
from ori.config import (
    Config,
    ConfigValidationError,
    config_env_placeholders,
    requires_production_posture,
)
from ori.hardware.led_indicator import (
    LEDIndicator,
    PolicyLEDState,
    RuntimeHealthState,
    StatusSignalingConfig,
)
from ori.network.events import event_received_at_ms
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.action_taken import NOT_PERFORMED
from ori.reasoning.elevator import SkillContext
from ori.runtime._alert_text import (
    message_from_context,
    resolve_action_declared_tier,
    resolve_original_ts,
    resolve_skill_identity,
    resolve_trigger_name,
)
from ori.runtime._capabilities import validate_required_runtime_capabilities
from ori.runtime._commissioning import Commissioning
from ori.runtime._device_io import coap_command_from_context
from ori.runtime._evidence_wiring import (
    build_evidence_attestor,
    evidence_posture_problems,
)
from ori.runtime._firmware_wiring import firmware_reading_age, provisioning_anchor_bytes
from ori.runtime._remote_command_wiring import (
    build_offline_token_verifier,
    build_remote_command_verifier,
    build_sms_allowed_senders,
    remote_command_lockout_config,
)
from ori.runtime._remote_commands import RemoteCommands
from ori.runtime._safety_wiring import SafetyAlertAdapter, refuse_unbound_active_zones
from ori.safety.commander import ActuatorOutcomeCommander
from ori.safety.registry import SafetyRegistry
from ori.security.commissioning.anchors import (
    AnchorError,
    anchor_collision,
    load_commissioning_anchors,
)
from ori.security.commissioning.profiles import load_shipped_profile_set
from ori.security.firmware.confirmation import FirmwareConfirmationCoordinator
from ori.security.firmware.reading_age import measured_statement
from ori.security.firmware.reconciliation import (
    DEFAULT_INTERVAL_S as CONFIRMATION_RETRY_INTERVAL_S,
)
from ori.security.firmware.reconciliation import FirmwareConfirmationReconciler
from ori.startup_stages import StartupContext
from ori.state.store import StateStore, TripJournal
from ori.utils.path_utils import shown
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.runtime")


class StartupFoundation(Commissioning, RemoteCommands):
    """Configuration, the store, actions, the safety envelope, alerting, evidence and the dispatcher."""

    async def _stage_configuration(self, context: StartupContext) -> None:
        try:
            context.config = Config.load(self._config_path)
            # The autoload had to decide before this document could be read, so
            # its answer is confirmed against the posture the document turns
            # out to declare. This closes a document whose posture is itself
            # expanded, and one replaced between the two reads.
            if self._dotenv_variables is not None and requires_production_posture(
                device=context.config.device, security=context.config.security
            ):
                raise ConfigValidationError(
                    "a .env was loaded through ORI_AUTOLOAD_DOTENV before this "
                    "configuration declared hardened posture; its values may "
                    "have supplied signed fields. Use the unit's EnvironmentFile."
                )
            validate_required_runtime_capabilities(context.config, self._config_path)
            self._config_env_placeholders = config_env_placeholders(self._config_path)
        except ConfigValidationError:
            logger.exception("[runtime] config validation failed — aborting")
            raise
        self._config = context.config
        # Anchors are compared as key material at configuration load, before
        # any binding is seen: if a commissioning anchor is the provisioning
        # anchor, the separation the binding contract rests on does not exist.
        try:
            context.commissioning_anchors = load_commissioning_anchors()
        except AnchorError as exc:
            logger.error("[commissioning] %s — aborting", exc)
            raise ConfigValidationError(f"commissioning anchors: {exc}") from exc
        if anchor_collision(
            context.commissioning_anchors, provisioning_anchor_bytes(context.config)
        ):
            logger.error(
                "[commissioning] anchor_collision: a commissioning anchor is the "
                "provisioning anchor — aborting"
            )
            raise ConfigValidationError(
                "anchor_collision: a commissioning anchor and the provisioning "
                "anchor are the same key material"
            )

        from logging.handlers import RotatingFileHandler

        root_logger = logging.getLogger()
        root_logger.setLevel(
            getattr(logging, context.config.logging.level, logging.INFO)
        )

        # Prevent duplicate file handlers when start() is called multiple times.
        target_log_file = os.path.abspath(context.config.logging.file)
        for handler in list(root_logger.handlers):
            if (
                isinstance(handler, RotatingFileHandler)
                and os.path.abspath(getattr(handler, "baseFilename", ""))
                == target_log_file
            ):
                root_logger.removeHandler(handler)
                try:
                    handler.close()
                except Exception:
                    logger.debug(
                        "[runtime] failed to close stale rotating handler: %r",
                        handler,
                    )

        file_handler = RotatingFileHandler(
            context.config.logging.file,
            maxBytes=context.config.logging.max_bytes,
            backupCount=context.config.logging.backup_count,
        )
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        root_logger.addHandler(file_handler)

        logger.info(
            "[runtime] config loaded — device=%s location=%s deployment=%s",
            shown(context.config.device.id),
            shown(context.config.device.location),
            shown(context.config.device.deployment_type),
        )
        self._device_id = str(context.config.device.id)
        self._device_location = str(context.config.device.location or "site")
        self._device_timezone = str(context.config.device.timezone or "UTC")
        self._runtime_started_at_ms = now_ms()
        self._device_policy_enabled = bool(
            (context.config.device_policy or {}).get("enabled", False)
        )
        self._remote_command_lockout_config = remote_command_lockout_config(
            context.config
        )

        context.status_cfg = (
            context.config.hal.status_signaling
            if isinstance(context.config.hal.status_signaling, dict)
            else {}
        )
        context.status_indicator = None
        if bool(context.status_cfg.get("enabled", False)):
            context.status_indicator = LEDIndicator(
                StatusSignalingConfig(
                    power_led_pin=int(context.status_cfg.get("power_led_pin", 17)),
                    relay_led_pin=int(context.status_cfg.get("relay_led_pin", 27)),
                    network_led_pin=int(context.status_cfg.get("network_led_pin", 22)),
                    health_led_pin=int(context.status_cfg.get("health_led_pin", 23)),
                    buzzer_pin=int(context.status_cfg.get("buzzer_pin", 24)),
                ),
                tick_ms=int(context.status_cfg.get("tick_ms", 100)),
            )
            await context.status_indicator.connect()
            context.status_indicator.set_runtime_state(RuntimeHealthState.STARTING)
            context.status_indicator.set_policy_state(PolicyLEDState.NORMAL)
            self._status_indicator = context.status_indicator

    async def _stage_store(self, context: StartupContext) -> None:
        # Startup is the one opener allowed to rebuild pre-receipt history,
        # because it is the moment the device is being upgraded on purpose.
        self._state_store = StateStore(
            db_path=context.config.database_path, allow_history_rebuild=True
        )
        await self._state_store.open()
        await self._load_remote_command_lockout_state()

    async def _stage_actions(self, context: StartupContext) -> None:
        remote_command_verifier = build_remote_command_verifier(context.config)
        context.whatsapp_action = WhatsAppAction(
            provider=TwilioProvider(),
            templates=context.config.actions.whatsapp.get("templates") or {},
            state_store=self._state_store,
            remote_command_verifier=remote_command_verifier,
            remote_command_handler=self._handle_remote_command,
            remote_command_incident_handler=self._handle_remote_command_incident,
        )
        context.sms_action = SMSAction(
            state_store=self._state_store,
            config=context.config.actions.sms,
            remote_command_verifier=remote_command_verifier,
            remote_command_handler=self._handle_remote_command,
            remote_command_incident_handler=self._handle_remote_command_incident,
            allowed_senders=build_sms_allowed_senders(context.config),
        )
        context.coap_action = CoAPAction(config=context.config.actions.coap)
        self._sms_action = context.sms_action
        context.logger_action = LoggerAction()
        context.process_manager_action = ProcessManagerAction()
        context.system_control_action = SystemControlAction()

        context.relay_action = None
        context.has_relay_config = "gpio_pin" in context.config.actions.relay
        context.relay_enabled = bool(context.config.actions.relay.get("enabled", False))

        if (
            context.config.device.deployment_type == "phone"
            and context.has_relay_config
        ):
            logger.warning(
                "[runtime] deployment_type=phone with relay configured; skipping relay initialization "
                "(phone gateway supports Tier A/B software actions only)."
            )
            context.has_relay_config = False
            # Effective relay permission must be false on phone deployments
            # because no GPIO relay executor is initialized on this target.
            context.relay_enabled = False

    async def _stage_safety_envelope(self, context: StartupContext) -> None:
        # The binding is loaded before any pin is driven: the pin's polarity
        # and what its coil states do are commissioned facts, and the relay is
        # connected only under an accepted zone for its pin.
        await self._load_commissioning(context.config, context.commissioning_anchors)
        commissioning_state = self._commissioning_state
        zone = (
            commissioning_state.zone_for_local_gpio(
                int(context.config.actions.relay["gpio_pin"])
            )
            if context.has_relay_config
            and commissioning_state is not None
            and commissioning_state.actuation_licensed
            else None
        )
        if context.has_relay_config and zone is not None and not zone.in_force_eligible:
            zone = None
        # The safety registry activates release-shipped profiles on the
        # in-force zones before any pin is driven, and its refusals gate a
        # hardened start exactly as a missing hardware backend does.
        in_force_zones = (
            commissioning_state.in_force.zones
            if commissioning_state is not None
            and commissioning_state.actuation_licensed
            and commissioning_state.in_force is not None
            else ()
        )
        assert self._state_store is not None
        self._safety_commander = ActuatorOutcomeCommander()
        self._safety_alert_sink = SafetyAlertAdapter(self)
        shipped_profiles = load_shipped_profile_set()
        # The digest a governed Tier C proposal binds as the profile in force.
        self._shipped_profile_digest = str(shipped_profiles.digest or "")
        self._safety_registry = SafetyRegistry(
            shipped_profiles,
            in_force_zones,
            TripJournal(self._state_store),
            self._safety_commander,
            alert_sink=self._safety_alert_sink,
            poll_intervals_ms={
                str(sensor.id): int(sensor.poll_interval_ms)
                for sensor in context.config.sensors
            },
            binding_seq=(
                commissioning_state.in_force.binding_seq
                if commissioning_state is not None
                and commissioning_state.in_force is not None
                else 0
            ),
        )
        safety_verdict = self._safety_registry.startup_verdict(
            hardened=requires_production_posture(
                device=context.config.device, security=context.config.security
            )
        )
        if safety_verdict == "refuse":
            refusals = ", ".join(
                f"{r.zone_id}/{r.profile_id}: {r.reason}"
                for r in self._safety_registry.activation.refused
            )
            raise ConfigValidationError(
                "hardened posture refuses to start with refused safety-profile "
                f"activations: {refusals}"
            )
        if safety_verdict == "start_degraded":
            logger.warning(
                "[safety] starting degraded: refused activations %s; those zones "
                "are not protected by their profiles",
                [
                    (r.zone_id, r.profile_id, r.reason)
                    for r in self._safety_registry.activation.refused
                ],
            )
        if context.has_relay_config and zone is None:
            logger.warning(
                "[runtime] relay on GPIO pin %s is declared but has no zone in force "
                "with both proof legs; the pin is not driven, relay actions are "
                "refused, and the zone is reported unprotected",
                context.config.actions.relay.get("gpio_pin"),
            )
            context.has_relay_config = False
        if self._safety_registry is not None:
            prospective_bound = (
                frozenset({zone.zone_id})
                if context.has_relay_config and zone is not None
                else frozenset()
            )
            refuse_unbound_active_zones(
                sorted(
                    self._safety_registry.zones_with_active_pairs - prospective_bound
                ),
                hardened=requires_production_posture(
                    device=context.config.device, security=context.config.security
                ),
            )
        defer_line_acquisition = (
            zone is not None
            and self._safety_registry is not None
            and zone.zone_id in self._safety_registry.zones_with_active_pairs
            and zone.mapping.get("de_energised_terminal_state") == "closed"
        )
        if (
            context.has_relay_config
            and zone is not None
            and commissioning_state is not None
            and defer_line_acquisition
        ):
            # Connecting acquires the line de-energised, which on this zone
            # closes the protected circuit — the act the registry defers
            # until the first credible reading. The line stays untouched;
            # the registry's first command is the acquisition.
            context.relay_action = RelayAction()
            if not gpio_backend_importable() and requires_production_posture(
                device=context.config.device, security=context.config.security
            ):
                raise ConfigValidationError(
                    "production posture requires a real GPIO backend for the "
                    f"deferred-acquisition relay on pin {context.config.actions.relay['gpio_pin']}"
                )
        elif (
            context.has_relay_config
            and zone is not None
            and commissioning_state is not None
        ):
            context.relay_action = RelayAction()
            gpio_pin: int = context.config.actions.relay["gpio_pin"]
            try:
                await context.relay_action.connect(
                    gpio_pin=gpio_pin,
                    active_high=bool(zone.identity["active_high"]),
                    tolerate_missing_backend=not requires_production_posture(
                        device=context.config.device,
                        security=context.config.security,
                    ),
                )
                logger.info(
                    "[runtime] relay connected on GPIO pin %d (active_high=%s, zone %s, binding %d)",
                    gpio_pin,
                    bool(zone.identity["active_high"]),
                    zone.zone_id,
                    commissioning_state.in_force.binding_seq
                    if commissioning_state.in_force
                    else 0,
                )
            except Exception as exc:
                logger.exception(
                    "[runtime] relay connect failed on pin %d",
                    gpio_pin,
                )
                if requires_production_posture(
                    device=context.config.device,
                    security=context.config.security,
                ):
                    raise ConfigValidationError(
                        "production posture requires configured GPIO relay control "
                        f"to initialise successfully on pin {gpio_pin}: {exc}"
                    ) from exc
                context.relay_action = None
        if (
            context.relay_action is not None
            and zone is not None
            and zone.in_force_eligible
            and commissioning_state is not None
            and commissioning_state.in_force is not None
        ):
            actuator = CommissionedActuator(
                driver=context.relay_action,
                zone=zone,
                binding_seq=commissioning_state.in_force.binding_seq,
            )
            self._commissioned_actuator = actuator
            if self._safety_commander is not None:
                self._safety_commander.bind(
                    zone.zone_id, actuator, defer_acquisition=defer_line_acquisition
                )
            if (
                self._safety_registry is None
                or zone.zone_id not in self._safety_registry.zones_with_active_pairs
            ):
                # Startup commands the coil, it does not assume it:
                # de_energised through the commissioned polarity, whatever
                # the platform default. A zone with an active profile gets
                # the terminal-state-conditioned command from the registry
                # instead, which also honours a durable latch.
                await actuator.command_coil("de_energised", reason="startup")
        if self._safety_registry is not None:
            await self._safety_registry.start()

    async def _stage_alerting(self, context: StartupContext) -> None:
        # operator_contact is a first-class config field, not assembled from sub-dicts
        context.operator_contact = context.config.actions.operator_contact or ""
        if not context.operator_contact:
            logger.warning(
                "[runtime] operator_contact is not configured — "
                "Tier C approval requests and emergency SMS will not reach the operator. "
                "Set actions.operator_contact in ori.yaml."
            )
        context.secondary_contact = context.config.actions.secondary_contact or ""

        # The deployment settings that can change Tier C admission, bound into
        # every proposal's authority snapshot through its policy digest. A
        # proposal's lifetime is its trigger's, from skill.yaml, bounded by the
        # release maximum; no deployment setting shortens it today.
        self._tier_c_deployment_inputs = {
            "relay_enabled": bool(context.relay_enabled),
        }

        context.primary_alert_channel = context.config.actions.primary_alert_channel
        self._primary_alert_channel = context.primary_alert_channel
        self._operator_contact = context.operator_contact
        self._secondary_contact = context.secondary_contact
        self._configure_alert_outbox(context.config.actions.alert_outbox)
        context.alert_sender = AlertFailoverSender(
            primary_channel=context.primary_alert_channel,
            sms_sender=context.sms_action,
            whatsapp_sender=context.whatsapp_action,
        )
        self._alert_sender = context.alert_sender
        if self._safety_alert_sink is not None:
            self._safety_alert_sink.sender = context.alert_sender
        causal_cfg = (
            context.config.reasoning.causal_memory
            if isinstance(context.config.reasoning.causal_memory, dict)
            else {}
        )
        context.rejection_expiry_days = int(causal_cfg.get("rejection_expiry_days", 30))

    async def _stage_evidence(self, context: StartupContext) -> None:
        context.evidence_attestor = build_evidence_attestor(context.config)
        if context.evidence_attestor is not None:
            await context.evidence_attestor.start()
            # Evidence trust that cannot be established fails closed for
            # evidence — ingest refuses, health reports the posture — and
            # never for the runtime: Tier D is never gated on evidence, so the
            # deterministic safety path starts regardless of profile.
            self._evidence_posture_problems = evidence_posture_problems(
                context.config, context.evidence_attestor
            )
            for problem in self._evidence_posture_problems:
                if requires_production_posture(
                    device=context.config.device, security=context.config.security
                ):
                    logger.error(
                        "[evidence] hardened posture cannot establish evidence "
                        "trust (%s); evidence is recorded locally and reported "
                        "degraded, and Tier C/D actions are unaffected",
                        problem,
                    )
                else:
                    logger.warning(
                        "[evidence] evidence trust is not established (%s); "
                        "receipts and custody will be refused until it is",
                        problem,
                    )
        self._evidence_attestor = context.evidence_attestor

        # The confirmation coordinator reconciles a locally-approved anchor
        # with the evidence store before its authority is treated as
        # effective. It is runtime-owned and reaches evidence state only
        # through the attestor's executor-bound backend, so the thread-bound
        # SQLite connections stay on the thread that opened them.
        if (
            context.evidence_attestor is not None
            and self._state_store is not None
            and context.evidence_attestor.available
        ):
            confirmation_chain = context.evidence_attestor.confirmation_backend()
            if confirmation_chain is not None:
                coordinator = FirmwareConfirmationCoordinator(
                    store=self._state_store, chain=confirmation_chain
                )
                self._firmware_confirmation_coordinator = coordinator
                # Approval alone cannot reach the evidence store, and a
                # confirmation that arrives later has nothing re-examining
                # the obligation. This is that missing layer.
                firmware_cfg = (
                    context.config.gateway.firmware_commands
                    if isinstance(context.config.gateway.firmware_commands, dict)
                    else {}
                )
                # Config bounds the interval by the backoff ceiling, so the
                # default maximum always admits it and no compensation is
                # needed here. An interval already at the ceiling simply has
                # nowhere to back off to.
                self._firmware_confirmation_reconciler = FirmwareConfirmationReconciler(
                    store=self._state_store,
                    coordinator=coordinator,
                    interval_s=float(
                        firmware_cfg.get(
                            "confirmation_retry_interval_s",
                            CONFIRMATION_RETRY_INTERVAL_S,
                        )
                    ),
                )

    async def _stage_dispatcher(self, context: StartupContext) -> None:
        # Built before the dispatcher, which reads reading-age bounds when it
        # composes an operator message, and fresh on every start: the table
        # and the signing starts it matches are memory only.
        self._firmware_reading_age = firmware_reading_age(context.config)
        reading_age = self._firmware_reading_age
        context.dispatcher = ActionDispatcher(
            # What Measured may say is decided here, off the action path: the
            # dispatcher composes the line and never reads a reading's provenance.
            measured_time=(
                None
                if reading_age is None
                else functools.partial(measured_statement, reading_age)
            ),
            state_store=self._state_store,
            alert_sender=context.alert_sender,
            emergency_sms_sender=context.sms_action,
            offline_token_verifier=build_offline_token_verifier(context.config.actions),
            status_indicator=context.status_indicator,
            evidence_attestor=context.evidence_attestor,
            binding_seq_in_force=self._binding_seq_in_force,
            authority_facts=self._tier_c_authority_facts,
            config={
                "operator_contact": context.operator_contact,
                "secondary_contact": context.secondary_contact,
                "primary_alert_channel": context.primary_alert_channel,
                "device_timezone": context.config.device.timezone,
                "device_location": context.config.device.location,
                "log_action_decisions": context.config.logging.log_action_decisions,
                "log_approval_workflow": context.config.logging.log_approval_workflow,
                "relay_enabled": context.relay_enabled,
                "rejection_expiry_days": context.rejection_expiry_days,
                "approval_require_scoped_replies": (
                    context.config.actions.approval_require_scoped_replies
                ),
                "local_console_enabled": bool(
                    context.config.actions.local_console.get("enabled", False)
                ),
                "local_console_poll_interval_ms": int(
                    context.config.actions.local_console.get("poll_interval_ms", 1000)
                ),
                "local_console_channel_id": str(
                    context.config.actions.local_console.get(
                        "approval_channel_id", "local_console"
                    )
                ),
            },
        )
        self._dispatcher = context.dispatcher
        await self._load_cached_device_policy(context.config, context.dispatcher)
        await self._maybe_refresh_remote_device_policy_once(
            context.config, context.dispatcher
        )

        # alert_whatsapp executor
        async def _exec_alert_whatsapp(action: str, ctx: SkillContext) -> bool | str:
            msg = message_from_context(ctx, action, channel="whatsapp")
            action_tier = resolve_action_declared_tier(ctx, action)
            trigger_name = resolve_trigger_name(ctx)
            skill_name, first_party = resolve_skill_identity(ctx)
            original_ts = resolve_original_ts(ctx)
            return await self._send_or_queue_alert(
                channel="whatsapp",
                skill_name=skill_name,
                skill_is_first_party=first_party,
                message=msg,
                recipient=context.operator_contact,
                action_tier=action_tier,
                trigger_name=trigger_name,
                original_ts=original_ts,
                received_at_ms=event_received_at_ms(ctx.event if ctx else None),
                alert_sender=context.alert_sender,
            )

        context.dispatcher.register_executor("alert_whatsapp", _exec_alert_whatsapp)

        # alert_sms executor
        async def _exec_alert_sms(action: str, ctx: SkillContext) -> bool | str:
            msg = message_from_context(ctx, action, channel="sms")
            action_tier = resolve_action_declared_tier(ctx, action)
            trigger_name = resolve_trigger_name(ctx)
            skill_name, first_party = resolve_skill_identity(ctx)
            original_ts = resolve_original_ts(ctx)
            return await self._send_or_queue_alert(
                channel="sms",
                skill_name=skill_name,
                skill_is_first_party=first_party,
                message=msg,
                recipient=context.operator_contact,
                action_tier=action_tier,
                trigger_name=trigger_name,
                original_ts=original_ts,
                received_at_ms=event_received_at_ms(ctx.event if ctx else None),
                alert_sender=context.alert_sender,
            )

        context.dispatcher.register_executor("alert_sms", _exec_alert_sms)

        async def _exec_terminate_process(action: str, ctx: SkillContext) -> bool:
            pid, name = _process_target_from_context(ctx)
            if pid is None or not name:
                logger.warning(
                    "[runtime] terminate_process requested but no unambiguous process target is available"
                )
                return False
            ok = await context.process_manager_action.terminate_process(
                pid=pid, name=name
            )
            if not ok:
                logger.warning(
                    "[runtime] terminate_process failed for pid=%s name=%r",
                    pid,
                    name,
                )
            return ok

        context.dispatcher.register_executor(
            "terminate_process", _exec_terminate_process
        )

        def _process_resource(ctx: SkillContext) -> dict[str, Any]:
            """The process this dispatch will terminate, not the sensor that reported."""
            pid, name = _process_target_from_context(ctx)
            if pid is None or not name:
                return {}
            return {"target": f"{pid}:{name}"}

        context.dispatcher.register_resource_resolver(
            "terminate_process", _process_resource
        )

        async def _exec_reset_kernel_subsystem(action: str, ctx: SkillContext) -> bool:
            subsystem = _kernel_subsystem_from_context(ctx)
            if not subsystem:
                logger.warning(
                    "[runtime] reset_kernel_subsystem requested but no target subsystem was provided"
                )
                return False
            ok = await context.system_control_action.reset_kernel_subsystem(
                subsystem=subsystem
            )
            if not ok:
                logger.warning(
                    "[runtime] reset_kernel_subsystem failed for subsystem=%r",
                    subsystem,
                )
            return ok

        context.dispatcher.register_executor(
            "reset_kernel_subsystem", _exec_reset_kernel_subsystem
        )

        def _subsystem_resource(ctx: SkillContext) -> dict[str, Any]:
            """The subsystem this dispatch will reset."""
            subsystem = _kernel_subsystem_from_context(ctx)
            return {"target": subsystem} if subsystem else {}

        context.dispatcher.register_resource_resolver(
            "reset_kernel_subsystem", _subsystem_resource
        )

        async def _exec_coap_command(action: str, ctx: SkillContext) -> bool:
            command_name, payload_override = coap_command_from_context(ctx)
            if not command_name:
                logger.warning(
                    "[runtime] coap_command requested but no command was resolved from trigger=%r "
                    "(expected skill.config.coap.trigger_commands or event metadata coap_command)",
                    getattr(ctx, "trigger_name", ""),
                )
                return False
            ok = await context.coap_action.execute_command(
                command_name=command_name,
                payload_override=payload_override,
            )
            if not ok:
                logger.warning(
                    "[runtime] coap_command execution failed for command=%r",
                    command_name,
                )
            return ok

        context.dispatcher.register_executor("coap_command", _exec_coap_command)

        def _coap_resource(ctx: SkillContext) -> dict[str, Any]:
            """The URI and payload this dispatch will actually command.

            Resolved through the same function the executor uses, so the act
            that is admitted is the act that runs. A resolver reading a static
            configuration key instead made every configured command one act on
            one resource, and the second of two different commands coalesced
            into the first.
            """
            command_name, payload_override = coap_command_from_context(ctx)
            if not command_name:
                return {}
            command = (context.config.actions.coap.get("commands") or {}).get(
                command_name
            )
            if not isinstance(command, dict):
                return {}
            uri = str(command.get("uri", "") or "")
            if not uri:
                return {}
            payload = (
                payload_override
                if payload_override is not None
                else str(command.get("payload", "") or "")
            )
            return {
                "coap_uri": uri,
                "coap_parameters": (
                    ("method", str(command.get("method", "POST"))),
                    ("payload", str(payload)),
                ),
            }

        context.dispatcher.register_resource_resolver("coap_command", _coap_resource)

        # log_to_dashboard — override built-in with device_id from config
        async def _exec_log_to_dashboard(action: str, *_: Any) -> None:
            context.logger_action.log_override(
                action=action,
                override_type="safe_default",
                device_id=context.config.device.id,
            )

        context.dispatcher.register_executor("log_to_dashboard", _exec_log_to_dashboard)

        # Relay-backed safety executors — only if relay successfully connected.
        # Semantic safety actions such as close_gas_valve still resolve through
        # the physical relay path; commissioning must wire the relay output to
        # the named fail-safe valve/contactor before that semantic action is
        # safety-creditable.
        actuator_in_force = self._commissioned_actuator
        if context.relay_action is not None and actuator_in_force is not None:
            actuator_bound = actuator_in_force
            relay_action_bound = context.relay_action

            def _reported(executed: bool) -> bool | str:
                # A driver that refused because it was never connected drove
                # nothing: the one refusal an approved dispatch may record as
                # failed rather than unknown. A failure on a connected line is
                # unknown, since the coil may have moved before it was reported.
                if not executed and not relay_action_bound.connected:
                    return NOT_PERFORMED
                return executed

            async def _exec_trip_relay(*_: Any) -> bool | str:
                # `trip_relay` and `close_gas_valve` name one outcome: isolate
                # the load. The zone's mapping decides the coil state.
                executed = await actuator_bound.command("open_protected_circuit")
                if context.status_indicator is not None:
                    context.status_indicator.set_relay_energized(
                        actuator_bound.coil_energised
                    )
                return _reported(executed)

            async def _exec_release_relay(*_: Any) -> bool | str:
                executed = await actuator_bound.command("close_protected_circuit")
                if context.status_indicator is not None:
                    context.status_indicator.set_relay_energized(
                        actuator_bound.coil_energised
                    )
                return _reported(executed)

            context.dispatcher.register_executor("trip_relay", _exec_trip_relay)
            context.dispatcher.register_executor("release_relay", _exec_release_relay)
            context.dispatcher.register_executor("close_gas_valve", _exec_trip_relay)
