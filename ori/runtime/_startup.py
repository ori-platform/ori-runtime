# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The later startup stages, from reasoning to the announcement, and ``start()``."""

import asyncio
import functools
import logging
import signal
from typing import Any

from ori.config import ConfigValidationError, requires_production_posture
from ori.gateway.envelope_auth import (
    build_gateway_envelope_state as _build_gateway_envelope_state,
)
from ori.hal.base import AdapterUnavailableError, BaseAdapter
from ori.hal.mqtt_base import reconnect_delay
from ori.hal.protocol_registry import UnknownProtocolError, make_adapter
from ori.hardware.led_indicator import RuntimeHealthState
from ori.network.deduplicator import EventDeduplicator
from ori.network.event_bus import EventBus
from ori.reasoning.capability_posture import CapabilityPostureTracker
from ori.reasoning.dispatch_coordinator import DispatchCoordinator
from ori.reasoning.elevator import IntelligenceElevator
from ori.reasoning.resource_gate import ResourceGate
from ori.runtime._capabilities import (
    build_local_llm,
    is_local_slm_available,
    local_llm_requested,
)
from ori.runtime._constants import (
    CAPABILITY_POSTURE_UPDATE_INTERVAL_S,
    DEVICE_POLICY_REFRESH_DEFAULT_S,
    EXTERNAL_WATCHDOG_GPIO,
    EXTERNAL_WATCHDOG_PING_S,
    STALE_SENSOR_MAX_CHECK_INTERVAL_S,
    STALE_SENSOR_MIN_CHECK_INTERVAL_S,
)
from ori.runtime._device_io import (
    adapter_connect_config,
    sync_network_state_from_posture,
)
from ori.runtime._evidence_wiring import (
    build_evidence_inbound_subscriber,
    build_evidence_outbound_publisher,
)
from ori.runtime._firmware_wiring import (
    build_firmware_liveness_stack,
    firmware_profile_library,
    firmware_telemetry_config,
)
from ori.runtime._gateway_wiring import (
    build_context_enricher,
    build_gateway_heartbeat_subscriber,
    build_gateway_reasoner,
    build_runtime_node_heartbeat_publisher,
    warn_gateway_security_posture,
)
from ori.runtime._loops import BackgroundLoops
from ori.runtime._remote_command_wiring import warn_sms_webhook_security_posture
from ori.runtime._remote_commands import RemoteCommands
from ori.runtime._sensors import SensorPolling
from ori.runtime._services import OperatorServices
from ori.runtime._shutdown import Shutdown
from ori.security.firmware.controller_profiles import ControllerAlarmTracker
from ori.security.firmware.reading_age import liveness_bound
from ori.sensor_connection import note_unconnected_sensor
from ori.skills.loader import SkillLoader
from ori.skills.selection import log_tier_configuration, skills_dir_for
from ori.startup_stages import STARTUP_CHECKPOINTS, STARTUP_STAGES, StartupContext
from ori.utils.bool_utils import is_truthy
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.runtime")


class StartupStages(
    Shutdown, OperatorServices, RemoteCommands, SensorPolling, BackgroundLoops
):
    """``start()`` and the stages that wire reasoning, skills, sensors, loops and services."""

    async def start(self) -> None:
        """Full startup sequence. Blocks until a shutdown signal is received.

        Runs the stages of `STARTUP_STAGES` in order, and stops at a
        checkpoint after any stage in `STARTUP_CHECKPOINTS` if a signal asked
        for it; see docs/STARTUP_STAGES.md.
        """
        context = StartupContext()
        for stage in STARTUP_STAGES:
            await getattr(self, f"_stage_{stage.name}")(context)
            if (
                stage.name in STARTUP_CHECKPOINTS
                and await self._stop_if_requested_during_startup()
            ):
                return

    async def _stage_reasoning(self, context: StartupContext) -> None:
        context.posture_cfg = (
            context.config.reasoning.capability_posture
            if isinstance(context.config.reasoning.capability_posture, dict)
            else {}
        )
        posture_enabled = bool(context.posture_cfg.get("enabled", True))
        context.posture_tracker = None
        if posture_enabled:
            context.posture_tracker = CapabilityPostureTracker(
                probe_interval_seconds=int(
                    context.posture_cfg.get("probe_interval_seconds", 30)
                ),
                gateway_heartbeat_ttl_seconds=int(
                    context.posture_cfg.get("gateway_heartbeat_ttl_seconds", 30)
                ),
                internet_probe_host=str(
                    context.posture_cfg.get("internet_probe_host", "one.one.one.one")
                ),
                internet_probe_port=int(
                    context.posture_cfg.get("internet_probe_port", 53)
                ),
                internet_probe_timeout_ms=int(
                    context.posture_cfg.get("internet_probe_timeout_ms", 1000)
                ),
            )
            self._capability_posture_tracker = context.posture_tracker

        context.local_llm = build_local_llm(
            context.config.reasoning,
            self._config_path,
            required=bool(
                requires_production_posture(
                    device=context.config.device,
                    security=context.config.security,
                )
                and local_llm_requested(context.config.reasoning)
            ),
        )
        # One envelope state for every gateway route; see
        # _build_gateway_envelope_state. It raises only when another runtime
        # owns this state database's replay store, which refuses the start.
        context.gateway_envelope_state = _build_gateway_envelope_state(context.config)
        self._gateway_envelope_state = context.gateway_envelope_state
        gateway_reasoner = build_gateway_reasoner(
            context.config, context.gateway_envelope_state
        )
        if gateway_reasoner is not None:
            self._gateway_ingress.add(gateway_reasoner.ingress)
        context.elevator = IntelligenceElevator(
            local_llm=context.local_llm,
            gateway_reasoner=gateway_reasoner,
            config=context.config.reasoning,
            context_enricher=build_context_enricher(context.config),
            # Set by the dispatcher stage; a prompt's {time} names a firmware
            # reading's liveness bound only where this process signed it.
            liveness_bound=(
                None
                if self._firmware_reading_age is None
                else functools.partial(liveness_bound, self._firmware_reading_age)
            ),
        )

    async def _stage_event_path(self, context: StartupContext) -> None:
        context.event_bus = EventBus()
        context.elevator.attach_event_bus(context.event_bus)
        self._event_bus = context.event_bus
        self._elevator = context.elevator
        if context.posture_tracker is not None:
            # Build an initial posture snapshot before processing events.
            posture = await context.posture_tracker.refresh(
                sms_available=is_truthy(
                    context.config.actions.sms.get("enabled", False)
                ),
                whatsapp_available=is_truthy(
                    context.config.actions.whatsapp.get("enabled", False)
                ),
                local_slm_loaded=is_local_slm_available(context.local_llm),
                relay_connected=context.relay_action is not None,
            )
            context.elevator.update_capability_posture(posture)
            context.dispatcher.update_capability_posture(posture)
            context.alert_sender.update_capability_posture(posture)
            if context.status_indicator is not None:
                sync_network_state_from_posture(context.status_indicator, posture)

        self._skill_reload_lock = asyncio.Lock()
        self._deduplicator = EventDeduplicator()

    async def _stage_skills(self, context: StartupContext) -> None:
        declared = context.config.raw.get("skills_dir")
        self._skills_dir = skills_dir_for(
            None if declared is None else str(declared), self._config_path
        )
        self._skill_selection = tuple(
            (entry.name, entry.version) for entry in context.config.skills
        )
        skills_security = context.config.security.get("skills")
        skills_require_signed = is_truthy(
            skills_security.get("require_signed", False)
            if isinstance(skills_security, dict)
            else False
        )
        # One admission point for physical acts, and one discovery barrier for
        # events. The gate is handed to the dispatcher rather than consulted
        # here, so an action is admitted at the last point before an executor
        # runs whichever caller reached it.
        binding_view = self._binding_view()
        gate = ResourceGate()
        context.dispatcher.bind_resource_gate(gate, binding_view)
        dispatch_coordinator = DispatchCoordinator(
            elevator=context.elevator,
            dispatcher=context.dispatcher,
            state_store=self._state_store,
            gate=gate,
        )
        dispatch_coordinator.set_binding(binding_view)
        self._dispatch_coordinator = dispatch_coordinator

        loader = SkillLoader(
            elevator=context.elevator,
            state_store=self._state_store,
            dispatcher=context.dispatcher,
            os_sandbox_config=context.config.os_sandbox,
            require_signed=skills_require_signed,
            coordinator=dispatch_coordinator,
        )
        self._skill_loader = loader
        await self.reload_skills(refuse_unresolved=True)

        log_tier_configuration(self._loaded_skills)

        logger.info(
            "[runtime] event loop ready — device=%s skills=%d triggers=%d",
            context.config.device.id,
            len(self._loaded_skills),
            sum(len(s.triggers) for s in self._loaded_skills),
        )

    async def _stage_signals(self, context: StartupContext) -> None:
        # Registered here rather than at the end of startup, because a device
        # that cannot be stopped for the whole of startup is worse than one
        # that stops untidily, and startup includes adapter connects that can
        # block on hardware. What the handler does depends on how far startup
        # has got: see `_request_stop`.
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, self._request_stop)
        loop.add_signal_handler(signal.SIGINT, self._request_stop)
        if hasattr(signal, "SIGHUP"):
            loop.add_signal_handler(
                signal.SIGHUP, lambda: asyncio.create_task(self.reload_skills())
            )
            logger.info(
                "[runtime] SIGHUP handler active — reload applies to new events only; in-flight tasks keep previous skill config"
            )

    async def _stage_sensor_state(self, context: StartupContext) -> None:
        self._configured_sensors = list(context.config.sensors)
        self._unconnected_sensors = set()
        self._retrying_sensors_announced = set()
        self._connected_sensor_ids = set()
        self._sensor_poll_interval_ms = {}
        self._sensor_last_seen_ms = {}
        self._stale_sensor_active = set()
        self._read_failure_logged_at = {}
        self._measurement_refusals = {}
        self._measurement_valid_streak = {}
        self._measurement_refusal_reason = {}
        await self._restore_measurement_state()
        self._last_alert_timestamps_by_channel = {}
        self._last_alert_timestamps_by_trigger = {}

    async def _stage_tier_c_recovery(self, context: StartupContext) -> None:
        if self._state_store is not None:
            # Proposals a previous process left: an open one is closed with its
            # safe default, an approval without an outcome is recorded
            # uncertain, and none is replayed. After every executor is
            # registered, so the safe default can run, and before any sensor
            # loop can raise a new proposal. A store that cannot be read here
            # fails Tier C closed, not the start: no governed proposal is raised
            # over proposals this process never settled, and Tier D, which
            # consults none of this, still starts.
            try:
                recovered = await context.dispatcher.recover_tier_c_at_start(
                    self._state_store
                )
            except Exception as exc:
                logger.critical(
                    "[runtime] Tier C recovery at start failed: %s; Tier C proposals "
                    "are refused until a start settles them, Tier D is unaffected",
                    exc,
                )
                context.dispatcher.mark_tier_c_recovery_failed(
                    f"{type(exc).__name__}: {exc}"
                )
            else:
                if any(recovered.values()):
                    logger.warning(
                        "[runtime] Tier C proposals settled at start: %s", recovered
                    )

    async def _stage_sensors(self, context: StartupContext) -> None:
        for sensor_cfg in context.config.sensors:
            try:
                adapter = make_adapter(sensor_cfg.protocol)
            except UnknownProtocolError as exc:
                raise ConfigValidationError(str(exc)) from exc
            connect_cfg = adapter_connect_config(sensor_cfg, context.config)
            connected = True
            unavailable = False
            try:
                await adapter.connect(connect_cfg)
            except AdapterUnavailableError as exc:
                logger.warning(
                    "[runtime] sensor_id=%s source not reached at start (%s)",
                    sensor_cfg.id,
                    exc,
                )
                connected = False
                unavailable = True
            except Exception:
                logger.exception(
                    "[runtime] failed to connect adapter for sensor_id=%s — skipping",
                    sensor_cfg.id,
                )
                connected = False
            retrying = unavailable or (connected and adapter.connection_retrying)
            if connected:
                # Before any await, so a stop during the notice still closes it.
                self._adapters.append(adapter)
            if connected or unavailable:
                self._sensor_poll_interval_ms[sensor_cfg.id] = (
                    sensor_cfg.poll_interval_ms
                )
            if not connected or retrying:
                await note_unconnected_sensor(
                    str(sensor_cfg.id),
                    retrying=retrying,
                    unconnected=self._unconnected_sensors,
                    announced=self._retrying_sensors_announced,
                    registry=self._safety_registry,
                    send=self._safety_notice_sender(),
                )
            if unavailable:
                self._background_tasks.append(
                    asyncio.create_task(
                        self._connect_when_available(sensor_cfg, connect_cfg, context),
                        name=f"connect:{sensor_cfg.id}",
                    )
                )
            if not connected:
                continue
            if not retrying:
                self._connected_sensor_ids.add(sensor_cfg.id)
                self._sensor_last_seen_ms[sensor_cfg.id] = now_ms()
                logger.info(
                    "[runtime] adapter=%s sensor_id=%s connected",
                    adapter.adapter_name,
                    sensor_cfg.id,
                )
            self._start_polling(adapter, sensor_cfg, context)

    async def _connect_when_available(
        self, sensor_cfg: Any, connect_cfg: dict[str, Any], context: StartupContext
    ) -> None:
        """Retry a source not there at start until it answers, then poll it.

        A fresh adapter per attempt, under the reconnect back-off a dropped
        broker gets, until a stop cancels this task. The sensor stays
        unconnected, and health degraded, until its first accepted reading. An
        error that does not say the source is absent ends the retries and is
        reported as the start would have reported it.
        """
        attempt = 0
        last_reason = ""
        while True:
            await asyncio.sleep(reconnect_delay(attempt))
            attempt += 1
            adapter = make_adapter(sensor_cfg.protocol)
            # Held, and the connect shielded, before the await: a stop cancels
            # this task, never the connect, so the adapter's own close at
            # shutdown waits for it and gives back whatever it opened.
            self._adapters.append(adapter)
            try:
                await asyncio.shield(adapter.connect(connect_cfg))
            except AdapterUnavailableError as exc:
                self._adapters.remove(adapter)
                if str(exc) != last_reason:
                    last_reason = str(exc)
                    logger.warning(
                        "[runtime] sensor_id=%s still not reached (attempt %d): %s",
                        sensor_cfg.id,
                        attempt,
                        exc,
                    )
                continue
            except Exception:
                self._adapters.remove(adapter)
                logger.exception(
                    "[runtime] sensor_id=%s can no longer be connected; not retried",
                    sensor_cfg.id,
                )
                self._retrying_sensors_announced.discard(str(sensor_cfg.id))
                await note_unconnected_sensor(
                    str(sensor_cfg.id),
                    retrying=False,
                    unconnected=self._unconnected_sensors,
                    announced=self._retrying_sensors_announced,
                    registry=self._safety_registry,
                    send=self._safety_notice_sender(),
                )
                return
            logger.info(
                "[runtime] sensor_id=%s source reached after %d attempt(s)",
                sensor_cfg.id,
                attempt,
            )
            self._start_polling(adapter, sensor_cfg, context)
            return

    def _start_polling(
        self, adapter: BaseAdapter, sensor_cfg: Any, context: StartupContext
    ) -> None:
        task = asyncio.create_task(
            self._poll_sensor(
                adapter,
                sensor_cfg,
                context.event_bus,
                context.config.device.id,
                self._deduplicator,
                context.config.device.timezone,
                context.config.device.country_code,
                context.config.device.location,
                context.config.device.site_type,
            ),
            name=f"poll:{sensor_cfg.id}",
        )
        self._background_tasks.append(task)

    async def _stage_loops(self, context: StartupContext) -> None:
        if self._sensor_poll_interval_ms:
            min_poll_ms = min(self._sensor_poll_interval_ms.values())
            stale_check_interval_s = min(
                STALE_SENSOR_MAX_CHECK_INTERVAL_S,
                max(STALE_SENSOR_MIN_CHECK_INTERVAL_S, (min_poll_ms / 1000.0) / 2.0),
            )
            self._background_tasks.append(
                asyncio.create_task(
                    self._sensor_staleness_loop(
                        alert_sender=context.alert_sender,
                        check_interval_s=stale_check_interval_s,
                    ),
                    name="sensor-staleness",
                )
            )

        self._background_tasks.append(
            asyncio.create_task(self._watchdog_loop(), name="watchdog")
        )
        external_wd = (
            context.config.hal.external_watchdog
            if isinstance(context.config.hal.external_watchdog, dict)
            else {}
        )
        if bool(external_wd.get("enabled", False)):
            if context.config.device.deployment_type == "phone":
                logger.warning(
                    "[runtime] external watchdog requested on phone deployment; skipping "
                    "(requires Raspberry Pi GPIO)."
                )
            else:
                gpio_pin = int(external_wd.get("gpio_pin", EXTERNAL_WATCHDOG_GPIO))
                ping_interval_s = float(
                    external_wd.get("ping_interval_s", EXTERNAL_WATCHDOG_PING_S)
                )
                self._background_tasks.append(
                    asyncio.create_task(
                        self._external_watchdog_loop(gpio_pin, ping_interval_s),
                        name="external-watchdog",
                    )
                )
        self._background_tasks.append(
            asyncio.create_task(
                self._heartbeat_loop(context.config.device.id), name="heartbeat"
            )
        )
        self._background_tasks.append(
            asyncio.create_task(
                self._compaction_loop(
                    self._deduplicator,
                    max_backward_skew_ms=context.config.state.compaction.max_backward_skew_ms,
                ),
                name="compaction",
            )
        )
        self._background_tasks.append(
            asyncio.create_task(
                self._alert_delivery_loop(context.alert_sender),
                name="alert-outbox",
            )
        )
        policy_cfg = (
            context.config.device_policy
            if isinstance(context.config.device_policy, dict)
            else {}
        )
        if bool(policy_cfg.get("enabled", False)) and bool(
            policy_cfg.get("refresh_enabled", False)
        ):
            refresh_interval_s = float(
                policy_cfg.get("refresh_interval_s", DEVICE_POLICY_REFRESH_DEFAULT_S)
            )
            self._background_tasks.append(
                asyncio.create_task(
                    self._device_policy_refresh_loop(
                        config=context.config,
                        dispatcher=context.dispatcher,
                        refresh_interval_s=refresh_interval_s,
                    ),
                    name="device-policy-refresh",
                )
            )
        if context.posture_tracker is not None:
            posture_interval_s = float(
                context.posture_cfg.get(
                    "probe_interval_seconds",
                    CAPABILITY_POSTURE_UPDATE_INTERVAL_S,
                )
            )
            self._background_tasks.append(
                asyncio.create_task(
                    self._capability_posture_loop(
                        tracker=context.posture_tracker,
                        elevator=context.elevator,
                        sms_enabled=is_truthy(
                            context.config.actions.sms.get("enabled", False)
                        ),
                        whatsapp_enabled=is_truthy(
                            context.config.actions.whatsapp.get("enabled", False)
                        ),
                        local_llm=context.local_llm,
                        relay_connected=context.relay_action is not None,
                        update_interval_s=posture_interval_s,
                    ),
                    name="capability-posture",
                )
            )
        if context.status_indicator is not None:
            status_tick_ms = int(context.status_cfg.get("tick_ms", 100))
            self._background_tasks.append(
                asyncio.create_task(
                    self._status_signaling_loop(
                        indicator=context.status_indicator,
                        tick_ms=status_tick_ms,
                    ),
                    name="status-signaling",
                )
            )

    async def _stage_services(self, context: StartupContext) -> None:
        webhook_task = await self._start_sms_webhook_if_enabled(context.config)
        if webhook_task is not None:
            self._background_tasks.append(webhook_task)

        telemetry_export_task = self._start_telemetry_export_if_enabled(
            context.config,
            context.event_bus,
        )
        if telemetry_export_task is not None:
            self._background_tasks.append(telemetry_export_task)

        warn_gateway_security_posture(context.config)
        warn_sms_webhook_security_posture(context.config)

        gateway_export_task = self._start_gateway_export_responder_if_enabled(
            context.config, context.gateway_envelope_state
        )
        if gateway_export_task is not None:
            self._background_tasks.append(gateway_export_task)

        hb_subscriber = (
            build_gateway_heartbeat_subscriber(
                context.config, context.posture_tracker, context.gateway_envelope_state
            )
            if context.posture_tracker is not None
            else None
        )
        if hb_subscriber is not None:
            self._gateway_ingress.add(hb_subscriber.ingress)
            self._background_tasks.append(
                asyncio.create_task(
                    hb_subscriber.serve_until(self._shutdown_event),
                    name="gateway-heartbeat",
                )
            )

        evidence_inbound_subscriber = build_evidence_inbound_subscriber(
            context.config, context.evidence_attestor, context.gateway_envelope_state
        )
        self._evidence_inbound_subscriber = evidence_inbound_subscriber
        if evidence_inbound_subscriber is not None:
            self._gateway_ingress.add(evidence_inbound_subscriber.ingress)
            self._background_tasks.append(
                asyncio.create_task(
                    evidence_inbound_subscriber.serve_until(self._shutdown_event),
                    name="evidence-inbound",
                )
            )

        if (
            context.evidence_attestor is not None
            and context.evidence_attestor.available
            and self._state_store is not None
        ):
            # Independent of the courier: a registration is sealed and held
            # whether or not a gateway is configured to carry it.
            self._background_tasks.append(
                asyncio.create_task(
                    self._evidence_registration_loop(context.evidence_attestor),
                    name="evidence-registration",
                )
            )
            logger.info("[runtime] evidence anchor registration reconciler started")

        self._start_evidence_outbound(context)

        # Built here, not read back from the subscriber, so health reaches the
        # documents and alarm snapshots without holding anything of the stack.
        firmware_telemetry_cfg = firmware_telemetry_config(context.config)
        if firmware_telemetry_cfg is not None:
            self._firmware_profile_library = firmware_profile_library(
                firmware_telemetry_cfg
            )
            self._firmware_alarm_tracker = ControllerAlarmTracker()
        (
            self._firmware_liveness_supervisor,
            firmware_telemetry_subscriber,
            firmware_command_pair,
            firmware_liveness_scheduler,
        ) = build_firmware_liveness_stack(
            context.config,
            context.event_bus,
            self._state_store,  # type: ignore[arg-type]
            self._deduplicator,
            # Late-bound: the callback reads the reconciler when a reconnect
            # happens, so no construction order between the two matters.
            self._nudge_firmware_confirmations,
            profiles=self._firmware_profile_library,
            alarms=self._firmware_alarm_tracker,
            reading_age=self._firmware_reading_age,
        )
        if firmware_telemetry_subscriber is not None:
            self._background_tasks.append(
                asyncio.create_task(
                    firmware_telemetry_subscriber.serve_until(self._shutdown_event),
                    name="firmware-telemetry",
                )
            )

        if firmware_command_pair is not None:
            publisher, service = firmware_command_pair
            # Held before connect() so health reports the loop `starting`, under
            # the startup deadline, rather than disabled while egress connects.
            self._firmware_liveness_scheduler = firmware_liveness_scheduler
            try:
                await publisher.connect()
            except Exception:
                logger.exception("[runtime] failed to connect firmware command MQTT")
                raise
            self._firmware_command_publisher = publisher
            self._firmware_command_service = service
            logger.info("[runtime] MQTT firmware command egress enabled")
            # A manifest stored before this runtime adopted the signing
            # domains is reported at its first start, not when it is next
            # republished or first needed.
            await service.report_undeclared_devices()

            # Started only after connect(): the first tick would otherwise
            # sign a message, spend a sequence number, and fail to publish
            # it. Sequence gaps are legal, but burning them on a race is
            # not a cost to accept when ordering is free.
            if firmware_liveness_scheduler is not None:
                self._background_tasks.append(
                    asyncio.create_task(
                        firmware_liveness_scheduler.serve_until(self._shutdown_event),
                        name="firmware-liveness",
                    )
                )

    def _start_evidence_outbound(self, context: StartupContext) -> None:
        """Build the outbound evidence route, and serve it when evidence is on."""
        evidence_outbound_publisher = build_evidence_outbound_publisher(
            context.config, context.evidence_attestor, context.gateway_envelope_state
        )
        self._evidence_outbound_publisher = evidence_outbound_publisher
        if (
            evidence_outbound_publisher is not None
            and context.evidence_attestor is not None
        ):
            self._gateway_ingress.add(evidence_outbound_publisher.ingress)
            context.evidence_attestor.set_sealed_listener(
                evidence_outbound_publisher.nudge
            )
            self._background_tasks.append(
                asyncio.create_task(
                    evidence_outbound_publisher.serve_until(self._shutdown_event),
                    name="evidence-outbound",
                )
            )
            self._background_tasks.append(
                asyncio.create_task(
                    self._evidence_checkpoint_loop(context.evidence_attestor),
                    name="evidence-checkpoint",
                )
            )

    async def _stage_operator_services(self, context: StartupContext) -> None:
        await self._start_firmware_mqtt_operator_if_enabled(context.config)

        node_heartbeat = build_runtime_node_heartbeat_publisher(
            context.config,
            self._build_health_snapshot,
            context.gateway_envelope_state,
        )
        if node_heartbeat is not None:
            self._runtime_node_heartbeat_publisher = node_heartbeat
            self._background_tasks.append(
                asyncio.create_task(
                    node_heartbeat.serve_until(self._shutdown_event),
                    name="runtime-node-heartbeat",
                )
            )

    async def _stage_health_and_reconciliation(self, context: StartupContext) -> None:
        await self._start_health_socket_if_enabled(context.config)
        await self._start_operator_socket(str(context.config.device.deployment_profile))

        await self._drain_pending_firmware_confirmations()
        if self._firmware_confirmation_reconciler is not None:
            self._background_tasks.append(
                asyncio.create_task(
                    self._firmware_confirmation_reconciler.serve_until(
                        self._shutdown_event
                    ),
                    name="firmware-confirmation-reconciler",
                )
            )
        await self._reconcile_pending_attestations()

        if context.status_indicator is not None:
            context.status_indicator.set_runtime_state(RuntimeHealthState.NORMAL)

    async def _stage_announce(self, context: StartupContext) -> None:
        await self._send_setup_success_notifications(
            context.config, context.alert_sender
        )

        # Block here until stop() sets the shutdown event
        if self._safety_registry is not None:
            self._background_tasks.append(
                asyncio.create_task(
                    self._safety_registry.run_retry_loop(self._shutdown_event)
                )
            )
        if await self._complete_startup():
            await self.stop()
            return

        await self._shutdown_event.wait()

    async def _complete_startup(self) -> bool:
        """Hand the stop signal from startup's checkpoints to the handler.

        Returns True when a request arrived during startup and is this
        caller's to honour.

        The flag is raised before the request is read, so a signal landing
        between the two is taken by the handler rather than falling into an
        instant that neither path owns. Reading first and raising after would
        leave exactly that gap, and a stop dropped there is a device that
        ignores its operator once per boot.
        """
        self._startup_complete = True
        return self._stop_requested_during_startup and not self._shutdown_event.is_set()
