# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Ori Runtime — main entry point.

Wires every component built into a running system:

    runtime = OriRuntime(config_path="ori.yaml")
    asyncio.run(runtime.start())

Or via the CLI entry point::

    ori-runtime --config /path/to/ori.yaml
"""

import asyncio
import hashlib
import json
import logging
import os
import signal
from pathlib import Path
from typing import Any

from ori.actions.alert_failover import AlertFailoverSender
from ori.actions.coap import CoAPAction
from ori.actions.logger import LoggerAction
from ori.actions.process_manager import ProcessManagerAction
from ori.actions.relay import RelayAction
from ori.actions.sms import SMSAction
from ori.actions.system_control import SystemControlAction
from ori.actions.whatsapp import TwilioProvider, WhatsAppAction
from ori.bool_utils import is_truthy
from ori.config import Config, ConfigValidationError
from ori.hal.base import AdapterReadError, BaseAdapter
from ori.hal.protocol_registry import UnknownProtocolError, make_adapter
from ori.hardware.led_indicator import (
    LEDIndicator,
    NetworkState,
    PolicyLEDState,
    PowerState,
    RuntimeHealthState,
    StatusSignalingConfig,
)
from ori.network.deduplicator import EventDeduplicator
from ori.network.event_bus import EventBus
from ori.network.events import OriEvent, SensorReading, compute_fingerprint
from ori.network.sms_webhook import SMSWebhookServer
from ori.policy.remote_fetch import (
    RemotePolicyFetchError,
    device_policy_from_payload,
    fetch_remote_device_policy_bundle,
    fetch_remote_device_policy_bundle_by_reference,
)
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.capability_posture import CapabilityPosture, CapabilityPostureTracker
from ori.reasoning.elevator import IntelligenceElevator, SkillContext
from ori.reasoning.local_llm import LocalLLM
from ori.runtime_health_socket import RuntimeHealthSocketServer
from ori.security.offline_tokens import OfflineTierCTokenVerifier
from ori.security.remote_command_lockout import (
    default_remote_command_lockout_config,
    evaluate_remote_command_lockout,
    remote_command_sender_key,
)
from ori.security.remote_command_policy import (
    STATUS_AUDIT_ONLY,
    STATUS_EXECUTED,
    STATUS_FAILED,
    STATUS_PRECONDITION_FAILED,
    STATUS_UNSUPPORTED,
    RemoteCommandExecutionResult,
    classify_remote_command,
    command_result,
)
from ori.security.remote_command_throttle import RemoteCommandThrottleDecision
from ori.security.remote_commands import RemoteCommand, RemoteCommandVerifier
from ori.security.threshold_guard import (
    all_trigger_condition_refs,
    check_tier_d_condition_suppression,
    check_tier_d_startup_sensitivity,
    tier_d_config_keys,
)
from ori.skills.loader import SkillLoader
from ori.skills.signing import verify_signed_payload
from ori.state.store import StateStore
from ori.time_utils import now_ms

logger = logging.getLogger(__name__)

WATCHDOG_DEVICE = "/dev/watchdog"
WATCHDOG_PING_INTERVAL = 10  # seconds — kernel expects a ping at least this often
WATCHDOG_TIMEOUT = 60  # seconds — kernel reboots if no ping within this window
EXTERNAL_WATCHDOG_GPIO = 17  # BCM pin for optional external watchdog heartbeat
EXTERNAL_WATCHDOG_PING_S = 30  # heartbeat interval for external watchdog devices
TIER_D_DRAIN_TIMEOUT = 5.0  # seconds — wait for in-flight Tier D tasks on shutdown
ALERT_OUTBOX_RETRY_INTERVAL_S = 30.0
ALERT_OUTBOX_BATCH_SIZE = 50
ALERT_OUTBOX_MAX_ATTEMPTS_NON_TIER_D = 10
ALERT_OUTBOX_TIER_D_CRITICAL_THRESHOLD = 3
CAPABILITY_POSTURE_UPDATE_INTERVAL_S = 30.0
DEVICE_POLICY_REFRESH_DEFAULT_S = 21600.0
DEVICE_POLICY_TRANSIENT_AUDIT_SUPPRESS_MS = 900_000
STALE_SENSOR_MIN_CHECK_INTERVAL_S = 1.0
STALE_SENSOR_MAX_CHECK_INTERVAL_S = 30.0
HEALTH_SOCKET_DEFAULT_PATH = "/run/ori/health.sock"


def _resolve_dispatcher_approval_timeout(
    skills_cfg: list[Any],
    default_timeout_s: int = 300,
) -> int:
    """Choose dispatcher fallback timeout deterministically across all skills."""
    resolved = int(default_timeout_s)
    for sc in skills_cfg:
        raw = getattr(sc, "config", {}).get("approval_timeout_seconds")
        if raw is None:
            continue
        try:
            candidate = int(raw)
        except (TypeError, ValueError):
            continue
        if candidate > resolved:
            resolved = candidate
    return max(1, resolved)


class OriRuntime:
    """Main runtime class. Wires all Ori components and manages the event loop.

    Args:
        config_path: Path to ``ori.yaml``. Defaults to ``"ori.yaml"`` in the
            current working directory.
    """

    def __init__(self, config_path: str = "ori.yaml") -> None:
        self._config_path = config_path
        self._config: Config | None = None
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._adapters: list[BaseAdapter] = []
        self._startup_skill_configs: dict[str, dict] = {}
        self._state_store: StateStore | None = None
        self._background_tasks: list[asyncio.Task] = []
        self._sms_action: SMSAction | None = None
        self._alert_sender: AlertFailoverSender | None = None
        self._sms_webhook_server: SMSWebhookServer | None = None
        self._dispatcher: ActionDispatcher | None = None
        self._event_bus: EventBus | None = None
        self._skill_loader: SkillLoader | None = None
        self._skills_dir: str | None = None
        self._loaded_skills: list[Any] = []
        self._skill_subscriptions: list[tuple[str, Any]] = []
        self._skill_reload_lock: asyncio.Lock | None = None
        self._deduplicator: EventDeduplicator | None = None
        self._capability_posture_tracker: CapabilityPostureTracker | None = None
        self._status_indicator: LEDIndicator | None = None
        self._faulted_sensors: set[str] = set()
        self._last_policy_refresh_transient_audit_ms: dict[str, int] = {}
        self._primary_alert_channel: str = "sms"
        self._operator_contact: str = ""
        self._sensor_poll_interval_ms: dict[str, int] = {}
        self._sensor_last_seen_ms: dict[str, int] = {}
        self._stale_sensor_active: set[str] = set()
        self._runtime_started_at_ms: int = 0
        self._configured_sensors: list[Any] = []
        self._connected_sensor_ids: set[str] = set()
        self._last_alert_timestamps_by_channel: dict[str, int] = {}
        self._last_alert_timestamps_by_trigger: dict[str, int] = {}
        self._health_socket_server: RuntimeHealthSocketServer | None = None
        self._health_socket_path: str = ""
        self._device_policy_enabled: bool = False
        self._device_id: str = ""
        self._remote_command_lockout_states: dict[str, dict[str, Any]] = {}
        self._remote_command_lockout_config: dict[str, Any] = (
            default_remote_command_lockout_config()
        )

    # ── Public API ────────────────────────────────────────────────────────────

    async def reload_skills(self) -> bool:
        """Reload skills from ``skills_dir`` without restarting the runtime.

        This method preserves the same validation and sandbox rules as startup:
        it reuses :class:`ori.skills.loader.SkillLoader` and only swaps handlers
        after the new skill set has been loaded successfully.

        Semantics:
        - Reload affects **new events only** after handler swap.
        - In-flight ``reason_and_dispatch`` tasks continue under the skill/config
          snapshot they started with. This avoids mutating active Tier C/Tier D
          flows mid-execution.
        """
        if self._skill_reload_lock is None:
            self._skill_reload_lock = asyncio.Lock()

        async with self._skill_reload_lock:
            if self._event_bus is None or self._skill_loader is None:
                logger.warning(
                    "[runtime] skill reload requested before startup completed"
                )
                return False

            skills_dir = self._skills_dir or str(
                Path(self._config_path).parent / "skills"
            )
            loaded = self._skill_loader.load_all(skills_dir)

            # Safety-first fallback: do not replace a working handler graph
            # with an empty one due to a transient load issue.
            if not loaded and self._loaded_skills:
                logger.warning(
                    "[runtime] skill reload found 0 valid skills in %s — keeping existing handlers",
                    skills_dir,
                )
                return False

            self._unregister_skill_handlers()
            for skill in loaded:
                subscriptions = self._skill_loader.register(skill, self._event_bus)
                self._skill_subscriptions.extend(subscriptions)

            self._loaded_skills = loaded
            for skill in loaded:
                self._startup_skill_configs.setdefault(skill.name, dict(skill.config))
            logger.info(
                "[runtime] skills reloaded — skills=%d triggers=%d source=%s",
                len(self._loaded_skills),
                sum(len(s.triggers) for s in self._loaded_skills),
                skills_dir,
            )
            return True

    async def start(self) -> None:
        """Full startup sequence. Blocks until a shutdown signal is received."""

        # ── Step A: Load and validate config ─────────────────────────────────
        try:
            config = Config.load(self._config_path)
        except ConfigValidationError:
            logger.exception("[runtime] config validation failed — aborting")
            raise
        self._config = config

        from logging.handlers import RotatingFileHandler

        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, config.logging.level, logging.INFO))

        # Prevent duplicate file handlers when start() is called multiple times.
        target_log_file = os.path.abspath(config.logging.file)
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
            config.logging.file,
            maxBytes=config.logging.max_bytes,
            backupCount=config.logging.backup_count,
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
            config.device.id,
            config.device.location,
            config.device.deployment_type,
        )
        self._device_id = str(config.device.id)
        self._runtime_started_at_ms = now_ms()
        self._device_policy_enabled = bool(
            (config.device_policy or {}).get("enabled", False)
        )
        self._remote_command_lockout_config = _remote_command_lockout_config(config)

        status_cfg = (
            config.hal.status_signaling
            if isinstance(config.hal.status_signaling, dict)
            else {}
        )
        status_indicator: LEDIndicator | None = None
        if bool(status_cfg.get("enabled", False)):
            status_indicator = LEDIndicator(
                StatusSignalingConfig(
                    power_led_pin=int(status_cfg.get("power_led_pin", 17)),
                    relay_led_pin=int(status_cfg.get("relay_led_pin", 27)),
                    network_led_pin=int(status_cfg.get("network_led_pin", 22)),
                    health_led_pin=int(status_cfg.get("health_led_pin", 23)),
                    buzzer_pin=int(status_cfg.get("buzzer_pin", 24)),
                ),
                tick_ms=int(status_cfg.get("tick_ms", 100)),
            )
            await status_indicator.connect()
            status_indicator.set_runtime_state(RuntimeHealthState.STARTING)
            status_indicator.set_policy_state(PolicyLEDState.NORMAL)
            self._status_indicator = status_indicator

        # ── Step B: Open StateStore ───────────────────────────────────────────
        db_path: str = config.raw.get("database", {}).get("path", "ori_state.db")
        self._state_store = StateStore(db_path=db_path)
        await self._state_store.open()
        await self._load_remote_command_lockout_state()

        # ── Step C: Instantiate action executors and ActionDispatcher ─────────
        remote_command_verifier = _build_remote_command_verifier(config)
        whatsapp_action = WhatsAppAction(
            provider=TwilioProvider(),
            state_store=self._state_store,
            remote_command_verifier=remote_command_verifier,
            remote_command_handler=self._handle_remote_command,
            remote_command_incident_handler=self._handle_remote_command_incident,
        )
        sms_action = SMSAction(
            state_store=self._state_store,
            config=config.actions.sms,
            remote_command_verifier=remote_command_verifier,
            remote_command_handler=self._handle_remote_command,
            remote_command_incident_handler=self._handle_remote_command_incident,
        )
        coap_action = CoAPAction(config=config.actions.coap)
        self._sms_action = sms_action
        logger_action = LoggerAction()
        process_manager_action = ProcessManagerAction()
        system_control_action = SystemControlAction()

        relay_action: RelayAction | None = None
        has_relay_config = "gpio_pin" in config.actions.relay
        relay_enabled = bool(config.actions.relay.get("enabled", False))

        if config.device.deployment_type == "phone" and has_relay_config:
            logger.warning(
                "[runtime] deployment_type=phone with relay configured; skipping relay initialization "
                "(phone gateway supports Tier A/B software actions only)."
            )
            has_relay_config = False
            # Effective relay permission must be false on phone deployments
            # because no GPIO relay executor is initialized on this target.
            relay_enabled = False

        if has_relay_config:
            relay_action = RelayAction()
            gpio_pin: int = config.actions.relay["gpio_pin"]
            try:
                await relay_action.connect(gpio_pin=gpio_pin)
                logger.info("[runtime] relay connected on GPIO pin %d", gpio_pin)
            except Exception:
                logger.exception(
                    "[runtime] relay connect failed on pin %d",
                    gpio_pin,
                )
                relay_action = None

        # operator_contact is a first-class config field, not assembled from sub-dicts
        _operator_contact: str = config.actions.operator_contact or ""
        if not _operator_contact:
            logger.warning(
                "[runtime] operator_contact is not configured — "
                "Tier C approval requests and emergency SMS will not reach the operator. "
                "Set actions.operator_contact in ori.yaml."
            )
        _secondary_contact: str = config.actions.secondary_contact or ""

        # Dispatcher-level fallback timeout (used only when trigger-level timeout
        # is unavailable): select the maximum declared skill timeout.
        _approval_timeout = _resolve_dispatcher_approval_timeout(config.skills, 300)

        primary_alert_channel = config.actions.primary_alert_channel
        self._primary_alert_channel = primary_alert_channel
        self._operator_contact = _operator_contact
        alert_sender = AlertFailoverSender(
            primary_channel=primary_alert_channel,
            sms_sender=sms_action,
            whatsapp_sender=whatsapp_action,
        )
        self._alert_sender = alert_sender
        causal_cfg = (
            config.reasoning.causal_memory
            if isinstance(config.reasoning.causal_memory, dict)
            else {}
        )
        rejection_expiry_days = int(causal_cfg.get("rejection_expiry_days", 30))

        dispatcher = ActionDispatcher(
            state_store=self._state_store,
            alert_sender=alert_sender,
            emergency_sms_sender=sms_action,
            offline_token_verifier=_build_offline_token_verifier(config.actions),
            status_indicator=status_indicator,
            config={
                "operator_contact": _operator_contact,
                "secondary_contact": _secondary_contact,
                "approval_timeout_seconds": _approval_timeout,
                "primary_alert_channel": primary_alert_channel,
                "device_timezone": config.device.timezone,
                "log_action_decisions": config.logging.log_action_decisions,
                "log_approval_workflow": config.logging.log_approval_workflow,
                "relay_enabled": relay_enabled,
                "rejection_expiry_days": rejection_expiry_days,
                "local_console_enabled": bool(
                    config.actions.local_console.get("enabled", False)
                ),
                "local_console_poll_interval_ms": int(
                    config.actions.local_console.get("poll_interval_ms", 1000)
                ),
                "local_console_channel_id": str(
                    config.actions.local_console.get(
                        "approval_channel_id", "local_console"
                    )
                ),
            },
        )
        self._dispatcher = dispatcher
        await self._load_cached_device_policy(config, dispatcher)
        await self._maybe_refresh_remote_device_policy_once(config, dispatcher)

        # alert_whatsapp executor
        async def _exec_alert_whatsapp(action: str, ctx: SkillContext) -> bool:
            msg = _message_from_context(ctx, action, channel="whatsapp")
            action_tier = _resolve_action_declared_tier(ctx, action)
            trigger_name = _resolve_trigger_name(ctx)
            original_ts = _resolve_original_ts(ctx)
            return await self._send_or_queue_alert(
                channel="whatsapp",
                message=msg,
                recipient=_operator_contact,
                action_tier=action_tier,
                trigger_name=trigger_name,
                original_ts=original_ts,
                alert_sender=alert_sender,
            )

        dispatcher.register_executor("alert_whatsapp", _exec_alert_whatsapp)

        # alert_sms executor
        async def _exec_alert_sms(action: str, ctx: SkillContext) -> bool:
            msg = _message_from_context(ctx, action, channel="sms")
            action_tier = _resolve_action_declared_tier(ctx, action)
            trigger_name = _resolve_trigger_name(ctx)
            original_ts = _resolve_original_ts(ctx)
            return await self._send_or_queue_alert(
                channel="sms",
                message=msg,
                recipient=_operator_contact,
                action_tier=action_tier,
                trigger_name=trigger_name,
                original_ts=original_ts,
                alert_sender=alert_sender,
            )

        dispatcher.register_executor("alert_sms", _exec_alert_sms)

        async def _exec_terminate_process(action: str, ctx: SkillContext) -> bool:
            pid, name = _process_target_from_context(ctx)
            if pid is None or not name:
                logger.warning(
                    "[runtime] terminate_process requested but no unambiguous process target is available"
                )
                return False
            ok = await process_manager_action.terminate_process(pid=pid, name=name)
            if not ok:
                logger.warning(
                    "[runtime] terminate_process failed for pid=%s name=%r",
                    pid,
                    name,
                )
            return ok

        dispatcher.register_executor("terminate_process", _exec_terminate_process)

        async def _exec_reset_kernel_subsystem(action: str, ctx: SkillContext) -> bool:
            subsystem = _kernel_subsystem_from_context(ctx)
            if not subsystem:
                logger.warning(
                    "[runtime] reset_kernel_subsystem requested but no target subsystem was provided"
                )
                return False
            ok = await system_control_action.reset_kernel_subsystem(subsystem=subsystem)
            if not ok:
                logger.warning(
                    "[runtime] reset_kernel_subsystem failed for subsystem=%r",
                    subsystem,
                )
            return ok

        dispatcher.register_executor(
            "reset_kernel_subsystem", _exec_reset_kernel_subsystem
        )

        async def _exec_coap_command(action: str, ctx: SkillContext) -> bool:
            command_name, payload_override = _coap_command_from_context(ctx)
            if not command_name:
                logger.warning(
                    "[runtime] coap_command requested but no command was resolved from trigger=%r "
                    "(expected skill.config.coap.trigger_commands or event metadata coap_command)",
                    getattr(ctx, "trigger_name", ""),
                )
                return False
            ok = await coap_action.execute_command(
                command_name=command_name,
                payload_override=payload_override,
            )
            if not ok:
                logger.warning(
                    "[runtime] coap_command execution failed for command=%r",
                    command_name,
                )
            return ok

        dispatcher.register_executor("coap_command", _exec_coap_command)

        # log_to_dashboard — override built-in with device_id from config
        async def _exec_log_to_dashboard(action: str, *_: Any) -> None:
            logger_action.log_override(
                action=action,
                override_type="safe_default",
                device_id=config.device.id,
            )

        dispatcher.register_executor("log_to_dashboard", _exec_log_to_dashboard)

        # Relay executors — only if relay successfully connected
        if relay_action is not None:

            async def _exec_trip_relay(*_: Any) -> None:
                await relay_action.trigger(duration_seconds=None)  # type: ignore[union-attr]
                if status_indicator is not None:
                    status_indicator.set_relay_energized(True)

            async def _exec_release_relay(*_: Any) -> None:
                await relay_action.release()  # type: ignore[union-attr]
                if status_indicator is not None:
                    status_indicator.set_relay_energized(False)

            dispatcher.register_executor("trip_relay", _exec_trip_relay)
            dispatcher.register_executor("release_relay", _exec_release_relay)

        # ── Step D: Capability posture tracker + IntelligenceElevator ─────────
        posture_cfg = (
            config.reasoning.capability_posture
            if isinstance(config.reasoning.capability_posture, dict)
            else {}
        )
        posture_enabled = bool(posture_cfg.get("enabled", True))
        posture_tracker: CapabilityPostureTracker | None = None
        if posture_enabled:
            posture_tracker = CapabilityPostureTracker(
                probe_interval_seconds=int(
                    posture_cfg.get("probe_interval_seconds", 30)
                ),
                gateway_heartbeat_ttl_seconds=int(
                    posture_cfg.get("gateway_heartbeat_ttl_seconds", 30)
                ),
                internet_probe_host=str(
                    posture_cfg.get("internet_probe_host", "one.one.one.one")
                ),
                internet_probe_port=int(posture_cfg.get("internet_probe_port", 53)),
                internet_probe_timeout_ms=int(
                    posture_cfg.get("internet_probe_timeout_ms", 1000)
                ),
            )
            self._capability_posture_tracker = posture_tracker

        local_llm = _build_local_llm(config.reasoning, self._config_path)
        elevator = IntelligenceElevator(local_llm=local_llm, config=config.reasoning)

        # ── Step E: EventBus ──────────────────────────────────────────────────
        event_bus = EventBus()
        elevator.attach_event_bus(event_bus)
        self._event_bus = event_bus
        if posture_tracker is not None:

            async def _on_gateway_health(event: OriEvent) -> None:
                posture_tracker.record_gateway_heartbeat(event.timestamp)

            event_bus.subscribe("ori/gateway/health", _on_gateway_health)

            # Build an initial posture snapshot before processing events.
            posture = await posture_tracker.refresh(
                sms_available=is_truthy(config.actions.sms.get("enabled", False)),
                whatsapp_available=is_truthy(
                    config.actions.whatsapp.get("enabled", False)
                ),
                local_slm_loaded=_is_local_slm_available(local_llm),
                relay_connected=relay_action is not None,
            )
            elevator.update_capability_posture(posture)
            dispatcher.update_capability_posture(posture)
            alert_sender.update_capability_posture(posture)
            if status_indicator is not None:
                _sync_network_state_from_posture(status_indicator, posture)

        self._skill_reload_lock = asyncio.Lock()
        self._deduplicator = EventDeduplicator()

        # ── Step F: Load skills and register handlers ─────────────────────────
        skills_dir: str = config.raw.get(
            "skills_dir",
            str(Path(self._config_path).parent / "skills"),
        )
        self._skills_dir = skills_dir
        loader = SkillLoader(
            elevator=elevator,
            state_store=self._state_store,
            dispatcher=dispatcher,
            os_sandbox_config=config.os_sandbox,
        )
        self._skill_loader = loader
        await self.reload_skills()

        # ── Step G: Log startup tier configuration ────────────────────────────
        for skill in self._loaded_skills:
            logger.info("[skill] %s v%s loaded", skill.name, skill.version)
            for trigger in skill.triggers:
                escalation = "bypass_llm" if trigger.bypass_llm else trigger.escalate_to
                logger.info(
                    "  trigger: %s → Tier %s → %s",
                    trigger.name,
                    trigger.action_tier,
                    escalation,
                )

        logger.info(
            "[runtime] event loop ready — device=%s skills=%d triggers=%d",
            config.device.id,
            len(self._loaded_skills),
            sum(len(s.triggers) for s in self._loaded_skills),
        )

        # ── Register signal handlers ──────────────────────────────────────────
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(
            signal.SIGTERM, lambda: asyncio.create_task(self.stop())
        )
        loop.add_signal_handler(signal.SIGINT, lambda: asyncio.create_task(self.stop()))
        if hasattr(signal, "SIGHUP"):
            loop.add_signal_handler(
                signal.SIGHUP, lambda: asyncio.create_task(self.reload_skills())
            )
            logger.info(
                "[runtime] SIGHUP handler active — reload applies to new events only; in-flight tasks keep previous skill config"
            )

        # ── Start background tasks ────────────────────────────────────────────
        self._configured_sensors = list(config.sensors)
        self._connected_sensor_ids = set()
        self._sensor_poll_interval_ms = {}
        self._sensor_last_seen_ms = {}
        self._stale_sensor_active = set()
        self._last_alert_timestamps_by_channel = {}
        self._last_alert_timestamps_by_trigger = {}

        for sensor_cfg in config.sensors:
            try:
                adapter = make_adapter(sensor_cfg.protocol)
            except UnknownProtocolError as exc:
                raise ConfigValidationError(str(exc)) from exc
            connect_cfg = {
                "sensor_id": sensor_cfg.id,
                "sensor_type": sensor_cfg.type,
                "circuit_breaker": config.hal.circuit_breaker,
                **sensor_cfg.metadata,
            }
            if sensor_cfg.protocol == "coap":
                coap_cfg = (
                    config.actions.coap if isinstance(config.actions.coap, dict) else {}
                )
                connect_cfg.setdefault(
                    "allowed_hosts", coap_cfg.get("allowed_hosts", [])
                )
                connect_cfg.setdefault("timeout_s", coap_cfg.get("timeout_s", 2.0))
            try:
                await adapter.connect(connect_cfg)
                self._adapters.append(adapter)
                self._connected_sensor_ids.add(sensor_cfg.id)
                self._sensor_poll_interval_ms[sensor_cfg.id] = int(
                    sensor_cfg.poll_interval_ms
                )
                self._sensor_last_seen_ms[sensor_cfg.id] = now_ms()
                logger.info(
                    "[runtime] adapter=%s sensor_id=%s connected",
                    adapter.adapter_name,
                    sensor_cfg.id,
                )
            except Exception:
                logger.exception(
                    "[runtime] failed to connect adapter for sensor_id=%s — skipping",
                    sensor_cfg.id,
                )
                continue

            task = asyncio.create_task(
                self._poll_sensor(
                    adapter,
                    sensor_cfg,
                    event_bus,
                    config.device.id,
                    self._deduplicator,
                    config.device.timezone,
                    config.device.country_code,
                ),
                name=f"poll:{sensor_cfg.id}",
            )
            self._background_tasks.append(task)

        if self._sensor_poll_interval_ms:
            min_poll_ms = min(self._sensor_poll_interval_ms.values())
            stale_check_interval_s = min(
                STALE_SENSOR_MAX_CHECK_INTERVAL_S,
                max(STALE_SENSOR_MIN_CHECK_INTERVAL_S, (min_poll_ms / 1000.0) / 2.0),
            )
            self._background_tasks.append(
                asyncio.create_task(
                    self._sensor_staleness_loop(
                        alert_sender=alert_sender,
                        check_interval_s=stale_check_interval_s,
                    ),
                    name="sensor-staleness",
                )
            )

        self._background_tasks.append(
            asyncio.create_task(self._watchdog_loop(), name="watchdog")
        )
        external_wd = (
            config.hal.external_watchdog
            if isinstance(config.hal.external_watchdog, dict)
            else {}
        )
        if bool(external_wd.get("enabled", False)):
            if config.device.deployment_type == "phone":
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
                self._heartbeat_loop(config.device.id), name="heartbeat"
            )
        )
        self._background_tasks.append(
            asyncio.create_task(
                self._compaction_loop(
                    self._deduplicator,
                    max_backward_skew_ms=config.state.compaction.max_backward_skew_ms,
                ),
                name="compaction",
            )
        )
        self._background_tasks.append(
            asyncio.create_task(
                self._alert_delivery_loop(alert_sender),
                name="alert-outbox",
            )
        )
        policy_cfg = (
            config.device_policy if isinstance(config.device_policy, dict) else {}
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
                        config=config,
                        dispatcher=dispatcher,
                        refresh_interval_s=refresh_interval_s,
                    ),
                    name="device-policy-refresh",
                )
            )
        if posture_tracker is not None:
            posture_interval_s = float(
                posture_cfg.get(
                    "probe_interval_seconds",
                    CAPABILITY_POSTURE_UPDATE_INTERVAL_S,
                )
            )
            self._background_tasks.append(
                asyncio.create_task(
                    self._capability_posture_loop(
                        tracker=posture_tracker,
                        elevator=elevator,
                        sms_enabled=is_truthy(config.actions.sms.get("enabled", False)),
                        whatsapp_enabled=is_truthy(
                            config.actions.whatsapp.get("enabled", False)
                        ),
                        local_llm=local_llm,
                        relay_connected=relay_action is not None,
                        update_interval_s=posture_interval_s,
                    ),
                    name="capability-posture",
                )
            )
        if status_indicator is not None:
            status_tick_ms = int(status_cfg.get("tick_ms", 100))
            self._background_tasks.append(
                asyncio.create_task(
                    self._status_signaling_loop(
                        indicator=status_indicator,
                        tick_ms=status_tick_ms,
                    ),
                    name="status-signaling",
                )
            )
        webhook_task = await self._start_sms_webhook_if_enabled(config)
        if webhook_task is not None:
            self._background_tasks.append(webhook_task)

        await self._start_health_socket_if_enabled(config)

        if status_indicator is not None:
            status_indicator.set_runtime_state(RuntimeHealthState.NORMAL)

        # Block here until stop() sets the shutdown event
        await self._shutdown_event.wait()

    async def stop(self) -> None:
        """Graceful shutdown. Called by SIGTERM/SIGINT signal handlers."""
        if self._shutdown_event.is_set():
            return
        logger.info("[runtime] shutdown initiated")
        self._shutdown_event.set()
        if self._status_indicator is not None:
            self._status_indicator.set_runtime_state(RuntimeHealthState.DEGRADED)

        # 1. Drain in-flight Tier D tasks before cancelling anything else.
        tier_d_tasks: list[asyncio.Task] = []
        if self._dispatcher is not None and hasattr(
            self._dispatcher, "get_inflight_tier_d_tasks"
        ):
            tier_d_tasks.extend(self._dispatcher.get_inflight_tier_d_tasks())

        # Backward-compatible fallback: if any legacy Tier D task tags exist,
        # still honour them during shutdown drain.
        for task in asyncio.all_tasks():
            if task.done():
                continue
            if getattr(task, "_is_tier_d", False) and task not in tier_d_tasks:
                tier_d_tasks.append(task)

        if tier_d_tasks:
            logger.warning(
                "[shutdown] waiting up to %.1fs for %d Tier D task(s)",
                TIER_D_DRAIN_TIMEOUT,
                len(tier_d_tasks),
            )
            await asyncio.wait(tier_d_tasks, timeout=TIER_D_DRAIN_TIMEOUT)

        # 2. Cancel tracked background tasks only — never cancel the task
        #    running start() itself, which returns naturally once the shutdown
        #    event is set.
        tasks = [t for t in self._background_tasks if not t.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # 2b. Stop local health socket service.
        if self._health_socket_server is not None:
            try:
                await self._health_socket_server.close()
            except Exception:
                logger.exception("[shutdown] error closing health socket")
            self._health_socket_server = None
            self._health_socket_path = ""

        # 3. Close HAL adapters
        for adapter in self._adapters:
            try:
                await adapter.close()
            except Exception:
                logger.exception("[shutdown] error closing adapter")

        # 4. Close StateStore
        if self._state_store is not None:
            await self._state_store.close()

        self._unregister_skill_handlers()
        self._loaded_skills = []

        logger.info("[runtime] shutdown complete")

    async def ingest_sms_webhook(self, payload: dict[str, Any]) -> bool:
        """Store one inbound SMS webhook payload for approval workflows."""
        if self._sms_action is None:
            logger.warning("[runtime] SMSAction is not initialised")
            return False
        return await self._sms_action.ingest_incoming_webhook(payload)

    async def _handle_remote_command(
        self, command: RemoteCommand
    ) -> RemoteCommandExecutionResult:
        """Apply runtime-owned execution policy for an authenticated command."""
        try:
            result = await self._execute_remote_command(command)
        except Exception:
            logger.exception(
                "[runtime] remote command execution failed unexpectedly command_id=%s command=%s",
                command.command_id,
                command.command,
            )
            result = command_result(
                command,
                status=STATUS_FAILED,
                detail="unexpected execution error",
                executed=False,
            )

        await self._log_remote_command_execution_result(result)
        return result

    async def _execute_remote_command(
        self, command: RemoteCommand
    ) -> RemoteCommandExecutionResult:
        policy_status = classify_remote_command(command)
        if policy_status == STATUS_AUDIT_ONLY:
            return command_result(
                command,
                status=STATUS_AUDIT_ONLY,
                detail="authenticated command accepted but handler is not enabled",
                executed=False,
            )
        if policy_status == STATUS_UNSUPPORTED:
            return command_result(
                command,
                status=STATUS_UNSUPPORTED,
                detail="authenticated command is not supported by this runtime",
                executed=False,
            )

        if command.command == "REFRESH_POLICY":
            if self._config is None or self._dispatcher is None:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="runtime config or dispatcher is unavailable",
                    executed=False,
                )
            policy_cfg = (
                self._config.device_policy
                if isinstance(self._config.device_policy, dict)
                else {}
            )
            if not bool(policy_cfg.get("enabled", False)):
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="device_policy is not enabled",
                    executed=False,
                )

            refreshed = await self._refresh_remote_device_policy_once(
                config=self._config,
                dispatcher=self._dispatcher,
                suppress_transient_audit=False,
            )
            if refreshed:
                return command_result(
                    command,
                    status=STATUS_EXECUTED,
                    detail="remote DevicePolicy refresh completed",
                    executed=True,
                )
            return command_result(
                command,
                status=STATUS_FAILED,
                detail="remote DevicePolicy refresh failed or was rejected",
                executed=False,
            )

        if command.command == "APPLY_POLICY":
            if self._config is None or self._dispatcher is None:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="runtime config or dispatcher is unavailable",
                    executed=False,
                )
            policy_cfg = (
                self._config.device_policy
                if isinstance(self._config.device_policy, dict)
                else {}
            )
            if not bool(policy_cfg.get("enabled", False)):
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="device_policy is not enabled",
                    executed=False,
                )

            reference_url = str(command.args.get("url", "") or "").strip()
            expected_sha256 = str(command.args.get("sha256") or "").strip()
            if not reference_url or not expected_sha256:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="APPLY_POLICY requires args.url and args.sha256",
                    executed=False,
                )

            try:
                fetched = await fetch_remote_device_policy_bundle_by_reference(
                    policy_cfg,
                    url=reference_url,
                    expected_sha256=expected_sha256,
                    current_policy_version=self._dispatcher.current_policy_version(),
                )
                await self._apply_fetched_remote_device_policy(
                    config=self._config,
                    fetched=fetched,
                    dispatcher=self._dispatcher,
                )
                return command_result(
                    command,
                    status=STATUS_EXECUTED,
                    detail="referenced DevicePolicy applied",
                    executed=True,
                )
            except RemotePolicyFetchError as exc:
                await self._audit_policy_rejection(
                    device_id=self._config.device.id,
                    reason_code=exc.code,
                    detail=str(exc),
                    policy_version=exc.policy_version,
                    payload_timestamp=exc.payload_timestamp,
                )
                return command_result(
                    command,
                    status=STATUS_FAILED,
                    detail=f"referenced DevicePolicy rejected: {exc.code}",
                    executed=False,
                )

        if command.command == "SET_THRESHOLD":
            return await self._execute_set_threshold(command)

        logger.error(
            "[runtime] remote command policy/handler mismatch command_id=%s command=%s policy_status=%s",
            command.command_id,
            command.command,
            policy_status,
        )
        return command_result(
            command,
            status=STATUS_UNSUPPORTED,
            detail="execution policy marks command executable but no runtime handler is registered",
            executed=False,
        )

    async def _execute_set_threshold(
        self, command: RemoteCommand
    ) -> RemoteCommandExecutionResult:
        import math

        skill_name = str(command.args.get("skill_name", "") or "").strip()
        threshold_key = str(command.args.get("threshold_key", "") or "").strip()
        raw_value = command.args.get("value")

        if not skill_name or not threshold_key or raw_value is None:
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail="SET_THRESHOLD requires args.skill_name, args.threshold_key, and args.value",
                executed=False,
            )

        try:
            new_value = float(raw_value)
        except (TypeError, ValueError):
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail="args.value must be a number",
                executed=False,
            )

        if not math.isfinite(new_value) or new_value <= 0:
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail="args.value must be a positive finite number",
                executed=False,
            )

        skill = next((s for s in self._loaded_skills if s.name == skill_name), None)
        if skill is None:
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail=f"skill {skill_name!r} is not loaded",
                executed=False,
            )

        if threshold_key not in skill.config:
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail=f"threshold key {threshold_key!r} does not exist in skill {skill_name!r} config",
                executed=False,
            )

        old_value = skill.config[threshold_key]

        if not isinstance(old_value, (int, float)) or not math.isfinite(
            float(old_value)
        ):
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail=f"threshold key {threshold_key!r} in skill {skill_name!r} is not numeric",
                executed=False,
            )

        if threshold_key not in all_trigger_condition_refs(skill):
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail=f"threshold key {threshold_key!r} is not referenced by any trigger condition in skill {skill_name!r}",
                executed=False,
            )

        if threshold_key in tier_d_config_keys(skill):
            readings = await self._latest_readings_for_skill(skill)
            if readings is None:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="SET_THRESHOLD for a Tier D key requires StateStore to verify no active condition is suppressed",
                    executed=False,
                )
            startup_value = self._startup_skill_configs.get(skill_name, {}).get(
                threshold_key
            )
            ok, detail = check_tier_d_startup_sensitivity(
                skill,
                threshold_key=threshold_key,
                new_value=new_value,
                startup_value=startup_value,
            )
            if not ok:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail=detail,
                    executed=False,
                )
            old_config = dict(skill.config)
            new_config = {**skill.config, threshold_key: new_value}
            ok, detail = check_tier_d_condition_suppression(
                skill, threshold_key, old_config, new_config, readings
            )
            if not ok:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail=detail,
                    executed=False,
                )

        skill.config[threshold_key] = new_value
        logger.info(
            "[runtime] SET_THRESHOLD applied skill=%s key=%s old=%s new=%s command_id=%s",
            skill_name,
            threshold_key,
            old_value,
            new_value,
            command.command_id,
        )
        return command_result(
            command,
            status=STATUS_EXECUTED,
            detail=f"{threshold_key} updated {old_value} -> {new_value} in skill {skill_name!r}",
            executed=True,
        )

    def _sensor_ids_for_skill(self, skill: Any) -> list[str]:
        """Return config sensor IDs whose type matches any of the skill's sensors_required."""
        if self._config is None:
            return []
        required_types = {
            str(sr.get("type", "") or "").lower()
            for sr in (getattr(skill, "sensors_required", None) or [])
            if sr.get("type")
        }
        return [
            cfg.id
            for cfg in self._config.sensors
            if str(cfg.type or "").lower() in required_types
        ]

    async def _latest_readings_for_skill(
        self, skill: Any
    ) -> list[SensorReading] | None:
        """Return the most recent SensorReading for each skill-associated sensor.

        Returns ``None`` when StateStore is unavailable. Callers performing
        Tier D suppression checks must treat ``None`` as a precondition failure
        (fail-closed) rather than assuming no condition is active.
        """
        if self._state_store is None:
            return None
        readings: list[SensorReading] = []
        for sensor_id in self._sensor_ids_for_skill(skill):
            history = await self._state_store.get_history(sensor_id, limit=1)
            if history:
                readings.append(history[0])
        return readings

    async def _log_remote_command_execution_result(
        self, result: RemoteCommandExecutionResult
    ) -> None:
        if self._state_store is None or not hasattr(
            self._state_store, "log_remote_command_execution"
        ):
            return
        await self._state_store.log_remote_command_execution(
            command_id=result.command_id,
            channel=result.channel,
            command=result.command,
            status=result.status,
            detail=result.detail,
            executed=result.executed,
            executed_at_ms=result.executed_at_ms,
        )

    async def _handle_remote_command_incident(
        self,
        decision: RemoteCommandThrottleDecision,
    ) -> None:
        """Emit a Tier A operator alert for first-seen remote command abuse."""
        logger.warning(
            "[runtime] remote command abuse incident id=%s channel=%s sender=%r count=%d threshold=%d",
            decision.incident_id,
            decision.channel,
            decision.from_number,
            decision.rejection_count,
            decision.threshold,
        )
        try:
            lockout_state = await self._evaluate_lockout_for_sender(
                channel=decision.channel,
                from_number=decision.from_number,
            )
            self._remote_command_lockout_states[
                remote_command_sender_key(
                    channel=decision.channel,
                    from_number=decision.from_number,
                )
            ] = lockout_state.as_dict()
        except Exception:
            logger.exception(
                "[runtime] remote command lockout risk evaluation failed for channel=%s sender=%r",
                decision.channel,
                decision.from_number,
            )
        if self._alert_sender is None:
            return
        message = (
            "ORI SECURITY ALERT: repeated rejected remote commands detected "
            f"from {decision.channel} sender {decision.from_number}. "
            f"{decision.rejection_count} rejected attempts in "
            f"{decision.window_ms // 1000}s. Command feedback has been throttled; "
            "valid signed commands remain allowed."
        )
        await self._send_or_queue_alert(
            channel=self._primary_alert_channel,
            message=message,
            recipient=self._operator_contact,
            action_tier="A",
            trigger_name="remote_command_abuse",
            original_ts=now_ms(),
            alert_sender=self._alert_sender,
        )

    async def _load_remote_command_lockout_state(self) -> None:
        """Rebuild advisory sender risk from persisted incident history."""
        self._remote_command_lockout_states.clear()
        if self._state_store is None or not hasattr(
            self._state_store,
            "get_recent_remote_command_incident_senders",
        ):
            return

        now = now_ms()
        lockout_cfg = self._remote_command_lockout_config
        since_ms = now - int(lockout_cfg["state_stale_after_ms"])
        try:
            senders = (
                await self._state_store.get_recent_remote_command_incident_senders(
                    since_ms=since_ms,
                    limit=int(lockout_cfg["incident_sender_limit"]),
                )
            )
        except Exception:
            logger.exception(
                "[runtime] failed to load remote command lockout state from incidents"
            )
            return

        for sender in senders:
            channel = str(sender.get("channel", "") or "")
            from_number = str(sender.get("from_number", "") or "")
            if not channel or not from_number:
                continue
            try:
                lockout_state = await self._evaluate_lockout_for_sender(
                    channel=channel,
                    from_number=from_number,
                    now_ms_value=now,
                )
            except Exception:
                logger.exception(
                    "[runtime] remote command lockout risk bootstrap failed for channel=%s sender=%r",
                    channel,
                    from_number,
                )
                continue
            self._remote_command_lockout_states[
                remote_command_sender_key(
                    channel=channel,
                    from_number=from_number,
                )
            ] = lockout_state.as_dict()

    async def _evaluate_lockout_for_sender(
        self,
        *,
        channel: str,
        from_number: str,
        now_ms_value: int | None = None,
    ):
        """Evaluate advisory sender risk with the runtime's normalized config."""
        cfg = self._remote_command_lockout_config
        return await evaluate_remote_command_lockout(
            state_store=self._state_store,
            channel=channel,
            from_number=from_number,
            window_ms=int(cfg["risk_window_ms"]),
            enforcement_enabled=False,
            elevated_incident_threshold=int(cfg["elevated_incident_threshold"]),
            critical_incident_threshold=int(cfg["critical_incident_threshold"]),
            elevated_rejection_threshold=int(cfg["elevated_rejection_threshold"]),
            critical_rejection_threshold=int(cfg["critical_rejection_threshold"]),
            now_ms_value=now_ms_value,
        )

    async def _start_sms_webhook_if_enabled(
        self, config: Config
    ) -> asyncio.Task | None:
        sms_cfg = config.actions.sms if isinstance(config.actions.sms, dict) else {}
        webhook_cfg = sms_cfg.get("incoming_webhook", {})
        if not isinstance(webhook_cfg, dict):
            return None

        enabled = is_truthy(webhook_cfg.get("enabled", False))
        if not enabled:
            return None

        if self._sms_action is None:
            logger.warning("[runtime] SMS webhook enabled but SMSAction is unavailable")
            return None

        token = str(webhook_cfg.get("token", "") or "").strip()
        if not token:
            logger.warning(
                "[runtime] SMS webhook enabled but incoming_webhook.token is empty; "
                "refusing to start unauthenticated public ingress"
            )
            return None

        host = str(webhook_cfg.get("host", "127.0.0.1"))
        port = int(webhook_cfg.get("port", 8080))
        path = str(webhook_cfg.get("path", "/webhooks/sms/africastalking"))

        self._sms_webhook_server = SMSWebhookServer(
            sms_action=self._sms_action,
            host=host,
            port=port,
            path=path,
            token=token,
        )
        return asyncio.create_task(
            self._sms_webhook_server.serve_until(self._shutdown_event),
            name="sms-webhook",
        )

    async def _start_health_socket_if_enabled(self, config: Config) -> None:
        cfg = config.health_socket if isinstance(config.health_socket, dict) else {}
        if not bool(cfg.get("enabled", True)):
            return

        socket_path = str(cfg.get("path", HEALTH_SOCKET_DEFAULT_PATH)).strip()
        mode = int(cfg.get("mode", 0o660))
        if not socket_path:
            logger.warning("[runtime] health socket path is empty; skipping startup")
            return

        server = RuntimeHealthSocketServer(
            socket_path=socket_path,
            mode=mode,
            snapshot_provider=self._build_health_snapshot,
        )
        try:
            bound_path = await server.start()
        except Exception:
            logger.exception("[runtime] failed to start health socket service")
            return

        self._health_socket_server = server
        self._health_socket_path = bound_path
        logger.info("[runtime] health socket ready at %s", bound_path)

    def _build_health_snapshot(self) -> dict[str, Any]:
        now = now_ms()
        uptime_s = (
            max(0.0, (now - self._runtime_started_at_ms) / 1000.0)
            if self._runtime_started_at_ms > 0
            else 0.0
        )

        posture = (
            vars(self._capability_posture_tracker.get_snapshot())
            if self._capability_posture_tracker is not None
            else None
        )
        if posture is None:
            capability_posture = {
                "available": False,
                "sms_available": False,
                "whatsapp_available": False,
                "gateway_reachable": False,
                "local_slm_loaded": False,
                "relay_connected": False,
                "internet_available": False,
                "checked_at_ms": 0,
                "expires_at_ms": 0,
                "gateway_last_heartbeat_ms": None,
            }
        else:
            capability_posture = {
                "available": True,
                "sms_available": bool(posture["sms_available"]),
                "whatsapp_available": bool(posture["whatsapp_available"]),
                "gateway_reachable": bool(posture["gateway_reachable"]),
                "local_slm_loaded": bool(posture["local_slm_loaded"]),
                "relay_connected": bool(posture["relay_connected"]),
                "internet_available": bool(posture["internet_available"]),
                "checked_at_ms": int(posture["checked_at_ms"]),
                "expires_at_ms": int(posture["expires_at_ms"]),
                "gateway_last_heartbeat_ms": posture["gateway_last_heartbeat_ms"],
            }

        sensors: list[dict[str, Any]] = []
        for sensor_cfg in self._configured_sensors:
            sensor_id = str(sensor_cfg.id)
            poll_ms = int(sensor_cfg.poll_interval_ms)
            last_seen_ms = self._sensor_last_seen_ms.get(sensor_id)
            stale = False
            if last_seen_ms is not None:
                stale = (now - int(last_seen_ms)) > max(2 * poll_ms, 200)
            sensors.append(
                {
                    "id": sensor_id,
                    "type": str(sensor_cfg.type),
                    "protocol": str(sensor_cfg.protocol),
                    "poll_interval_ms": poll_ms,
                    "connected": sensor_id in self._connected_sensor_ids,
                    "last_seen_ms": int(last_seen_ms)
                    if last_seen_ms is not None
                    else None,
                    "stale": bool(stale),
                }
            )

        device_policy_state: dict[str, Any]
        if self._dispatcher is not None:
            device_policy_state = self._dispatcher.get_policy_state_snapshot()
        else:
            device_policy_state = {
                "available": False,
                "policy_version": None,
                "tier": None,
                "relay_b_enabled": None,
                "relay_c_enabled": None,
                "cloud_llm_enabled": None,
                "valid_until": None,
                "issued_at": None,
                "is_expired": None,
            }
        device_policy_state["enabled"] = self._device_policy_enabled
        lockout_stale_after_ms = int(
            self._remote_command_lockout_config["state_stale_after_ms"]
        )
        remote_command_lockout_senders: list[dict[str, Any]] = []
        for state in self._remote_command_lockout_states.values():
            item = dict(state)
            checked_at_ms = int(item.get("checked_at_ms") or 0)
            item["stale"] = checked_at_ms <= 0 or (
                now - checked_at_ms > lockout_stale_after_ms
            )
            remote_command_lockout_senders.append(item)

        return {
            "device_id": self._device_id,
            "uptime_s": uptime_s,
            "health_socket_path": self._health_socket_path,
            "capability_posture": capability_posture,
            "sensors": sensors,
            "last_alert_timestamps": {
                "by_channel": dict(self._last_alert_timestamps_by_channel),
                "by_trigger": dict(self._last_alert_timestamps_by_trigger),
            },
            "device_policy": device_policy_state,
            "remote_command_lockout": {
                "enforcement_enabled": False,
                "risk_window_ms": int(
                    self._remote_command_lockout_config["risk_window_ms"]
                ),
                "stale_after_ms": lockout_stale_after_ms,
                "incident_sender_limit": int(
                    self._remote_command_lockout_config["incident_sender_limit"]
                ),
                "senders": remote_command_lockout_senders,
            },
        }

    def _unregister_skill_handlers(self) -> None:
        if self._event_bus is None:
            self._skill_subscriptions.clear()
            return
        for sensor_type, handler in self._skill_subscriptions:
            self._event_bus.unsubscribe(sensor_type, handler)
        self._skill_subscriptions.clear()

    # ── Background tasks ──────────────────────────────────────────────────────

    async def _poll_sensor(
        self,
        adapter: BaseAdapter,
        sensor_cfg: Any,
        event_bus: EventBus,
        device_id: str,
        deduplicator: EventDeduplicator | None = None,
        device_timezone: str = "",
        device_country_code: str = "",
    ) -> None:
        """Read *adapter* at the configured poll interval and publish to *event_bus*."""
        if self._state_store is None:
            logger.error(
                "[runtime] state_store unavailable for sensor poll task sensor_id=%s; stopping poll loop",
                sensor_cfg.id,
            )
            return
        while not self._shutdown_event.is_set():
            try:
                reading = await adapter.read(sensor_cfg.id)
                self._sensor_last_seen_ms[sensor_cfg.id] = now_ms()
                if sensor_cfg.id in self._stale_sensor_active:
                    self._stale_sensor_active.discard(sensor_cfg.id)
                    logger.info(
                        "[runtime] sensor recovered from stale state sensor_id=%s",
                        sensor_cfg.id,
                    )
                if sensor_cfg.id in self._faulted_sensors:
                    self._faulted_sensors.discard(sensor_cfg.id)
                    if self._status_indicator is not None and not self._faulted_sensors:
                        self._status_indicator.set_hardware_fault(False)
                event = OriEvent.from_reading(reading, device_id)
                event.event_type = f"sensor.{reading.sensor_type}"
                if not isinstance(event.context, dict):
                    event.context = {}
                event.context["device_timezone"] = device_timezone
                event.context["device_country_code"] = (
                    str(device_country_code or "").strip().upper()
                )
                # Keep source explicit in the poll path; adapters must publish
                # protocol provenance through reading.metadata["source"].
                event.source = reading.metadata.get("source", "")
                event.fingerprint = compute_fingerprint(reading, event.device_id)
                await self._state_store.append_history(event)
                if event.reading is not None and deduplicator is not None:
                    if deduplicator.process(event) is None:
                        logger.debug(
                            "Deduplicator suppressed duplicate event for sensor %s "
                            "(fingerprint %s...)",
                            event.sensor_id,
                            event.fingerprint[:8],
                        )
                        continue
                await event_bus.publish(event)
                if self._status_indicator is not None:
                    _sync_power_state_from_reading(self._status_indicator, reading)
            except AdapterReadError as exc:
                logger.warning("[sensor] %s read failed: %s", sensor_cfg.id, exc)
                if self._status_indicator is not None and "circuit breaker OPEN" in str(
                    exc
                ):
                    self._faulted_sensors.add(sensor_cfg.id)
                    self._status_indicator.set_hardware_fault(True)
            except Exception:
                logger.exception("[sensor] unexpected error polling %s", sensor_cfg.id)
            await asyncio.sleep(sensor_cfg.poll_interval_ms / 1000)

    async def _sensor_staleness_loop(
        self,
        *,
        alert_sender: AlertFailoverSender,
        check_interval_s: float,
    ) -> None:
        """Emit Tier A warnings when sensors go silent past 2x poll interval."""
        interval = max(STALE_SENSOR_MIN_CHECK_INTERVAL_S, float(check_interval_s))
        while not self._shutdown_event.is_set():
            now = now_ms()
            for sensor_id, poll_ms in self._sensor_poll_interval_ms.items():
                last_seen = self._sensor_last_seen_ms.get(sensor_id)
                if last_seen is None:
                    continue
                stale_after_ms = max(2 * int(poll_ms), 200)
                stale_duration_ms = now - int(last_seen)
                is_stale = stale_duration_ms > stale_after_ms
                if is_stale and sensor_id not in self._stale_sensor_active:
                    self._stale_sensor_active.add(sensor_id)
                    logger.warning(
                        "[runtime] stale sensor warning sensor_id=%s stale_for_ms=%d threshold_ms=%d",
                        sensor_id,
                        stale_duration_ms,
                        stale_after_ms,
                    )
                    await self._emit_stale_sensor_warning(
                        alert_sender=alert_sender,
                        sensor_id=sensor_id,
                        stale_duration_ms=stale_duration_ms,
                        stale_after_ms=stale_after_ms,
                    )

            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass

    async def _emit_stale_sensor_warning(
        self,
        *,
        alert_sender: AlertFailoverSender,
        sensor_id: str,
        stale_duration_ms: int,
        stale_after_ms: int,
    ) -> None:
        """Send or queue a stale-sensor Tier A notification."""
        if not self._operator_contact:
            logger.warning(
                "[runtime] stale sensor warning not sent: operator_contact is not configured"
            )
            return
        minutes = max(stale_duration_ms // 60_000, 1)
        threshold_seconds = max(stale_after_ms // 1000, 1)
        message = (
            f"Sensor {sensor_id} has not reported for about {minutes} minute(s). "
            f"This exceeded the stale threshold of {threshold_seconds}s."
        )
        await self._send_or_queue_alert(
            channel=self._primary_alert_channel,
            message=message,
            recipient=self._operator_contact,
            action_tier="A",
            trigger_name="sensor_stale_warning",
            original_ts=now_ms(),
            alert_sender=alert_sender,
        )

    async def _maybe_refresh_remote_device_policy_once(
        self,
        config: Config,
        dispatcher: ActionDispatcher,
    ) -> None:
        """Optionally fetch and apply a verified remote DevicePolicy once at startup."""
        policy_cfg = (
            config.device_policy if isinstance(config.device_policy, dict) else {}
        )
        if not bool(policy_cfg.get("enabled", False)):
            return

        await self._refresh_remote_device_policy_once(
            config=config,
            dispatcher=dispatcher,
            suppress_transient_audit=False,
        )

    async def _refresh_remote_device_policy_once(
        self,
        *,
        config: Config,
        dispatcher: ActionDispatcher,
        suppress_transient_audit: bool,
    ) -> bool:
        current_version = dispatcher.current_policy_version()
        try:
            fetched = await fetch_remote_device_policy_bundle(
                config.device_policy,
                current_policy_version=current_version,
            )
            await self._apply_fetched_remote_device_policy(
                config=config,
                fetched=fetched,
                dispatcher=dispatcher,
            )
            return True
        except RemotePolicyFetchError as exc:
            logger.warning(
                "[runtime] remote DevicePolicy rejected code=%s detail=%s",
                exc.code,
                str(exc),
            )
            if (
                suppress_transient_audit
                and self._should_suppress_transient_policy_audit(
                    reason_code=exc.code,
                    detail=str(exc),
                )
            ):
                return False
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code=exc.code,
                detail=str(exc),
                policy_version=exc.policy_version,
                payload_timestamp=exc.payload_timestamp,
            )
            return False
        except Exception:
            logger.exception("[runtime] unexpected remote DevicePolicy fetch error")
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code="unexpected_error",
                detail="unexpected exception during remote policy fetch",
                policy_version=None,
                payload_timestamp=None,
            )
            return False

    async def _apply_fetched_remote_device_policy(
        self,
        *,
        config: Config,
        fetched: Any,
        dispatcher: ActionDispatcher,
    ) -> None:
        """Apply a previously verified remote DevicePolicy and cache it."""
        dispatcher.update_policy(fetched.policy)
        logger.info(
            "[runtime] remote DevicePolicy applied — version=%s tier=%s valid_until=%s",
            fetched.policy.policy_version,
            fetched.policy.tier,
            fetched.policy.valid_until,
        )
        if self._state_store is None:
            return
        try:
            await self._state_store.upsert_device_policy_cache(
                policy_version=fetched.policy.policy_version,
                tier=fetched.policy.tier,
                relay_b_enabled=fetched.policy.relay_b_enabled,
                relay_c_enabled=fetched.policy.relay_c_enabled,
                cloud_llm_enabled=fetched.policy.cloud_llm_enabled,
                valid_until=fetched.policy.valid_until,
                issued_at=fetched.policy.issued_at,
                signature=fetched.policy.signature,
                raw_payload=fetched.raw_payload,
            )
        except Exception:
            logger.exception("[runtime] failed to persist verified DevicePolicy cache")
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code="cache_write_failed",
                detail="verified policy applied but cache persistence failed",
                policy_version=fetched.policy.policy_version,
                payload_timestamp=int(fetched.payload.get("timestamp", 0)),
            )

    async def _device_policy_refresh_loop(
        self,
        *,
        config: Config,
        dispatcher: ActionDispatcher,
        refresh_interval_s: float,
    ) -> None:
        """Periodically refresh and apply remote DevicePolicy while runtime is running."""
        interval = max(1.0, float(refresh_interval_s))
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass
            await self._refresh_remote_device_policy_once(
                config=config,
                dispatcher=dispatcher,
                suppress_transient_audit=True,
            )

    def _should_suppress_transient_policy_audit(
        self,
        *,
        reason_code: str,
        detail: str,
    ) -> bool:
        """Deduplicate repeated transient network policy-refresh audit rows."""
        if reason_code not in {"network_error", "network_timeout"}:
            return False
        key = f"{reason_code}:{detail}"
        now = now_ms()
        last = self._last_policy_refresh_transient_audit_ms.get(key)
        if (
            last is not None
            and (now - last) < DEVICE_POLICY_TRANSIENT_AUDIT_SUPPRESS_MS
        ):
            return True
        self._last_policy_refresh_transient_audit_ms[key] = now
        return False

    async def _load_cached_device_policy(
        self,
        config: Config,
        dispatcher: ActionDispatcher,
    ) -> None:
        """Load and verify cached DevicePolicy from SQLite before remote fetch."""
        if self._state_store is None:
            return
        try:
            cached = await self._state_store.get_latest_device_policy_cache()
        except Exception:
            logger.exception("[runtime] failed to read cached DevicePolicy")
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code="cache_read_failed",
                detail="failed to read device_policy_cache row",
                policy_version=None,
                payload_timestamp=None,
            )
            return
        if not cached:
            return

        policy_cfg = (
            config.device_policy if isinstance(config.device_policy, dict) else {}
        )
        public_key_b64 = str(policy_cfg.get("public_key_b64", "")).strip()
        if not public_key_b64:
            logger.warning(
                "[runtime] cached DevicePolicy exists but device_policy.public_key_b64 is not configured"
            )
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code="cache_verification_unavailable",
                detail="missing device_policy.public_key_b64 for cached policy verification",
                policy_version=int(cached.get("policy_version", 0)),
                payload_timestamp=None,
            )
            return

        raw_payload = str(cached.get("raw_payload", "") or "")
        if not raw_payload:
            logger.warning("[runtime] cached DevicePolicy missing raw_payload")
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code="cache_missing_raw_payload",
                detail="device_policy_cache row has empty raw_payload",
                policy_version=int(cached.get("policy_version", 0)),
                payload_timestamp=None,
            )
            return

        try:
            parsed_payload = json.loads(raw_payload)
            if not isinstance(parsed_payload, dict):
                raise ValueError("cached raw payload is not a JSON object")
            verify_signed_payload(
                parsed_payload,
                public_key_b64,
                context_label="cached device policy payload",
            )
            cached_policy = device_policy_from_payload(
                parsed_payload,
                context_label="cached device policy payload",
            )
        except Exception as exc:
            logger.warning("[runtime] cached DevicePolicy rejected: %s", exc)
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code="cache_invalid_payload",
                detail=str(exc),
                policy_version=int(cached.get("policy_version", 0)),
                payload_timestamp=None,
            )
            return

        dispatcher.update_policy(cached_policy)
        logger.info(
            "[runtime] cached DevicePolicy applied — version=%s tier=%s valid_until=%s",
            cached_policy.policy_version,
            cached_policy.tier,
            cached_policy.valid_until,
        )

    async def _audit_policy_rejection(
        self,
        *,
        device_id: str,
        reason_code: str,
        detail: str,
        policy_version: int | None,
        payload_timestamp: int | None,
    ) -> None:
        if self._state_store is None:
            return
        audit_reason = json.dumps(
            {
                "code": reason_code,
                "detail": detail,
                "policy_version": policy_version,
                "payload_timestamp": payload_timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        try:
            await self._state_store.log_override(
                trigger_name="device_policy_refresh",
                action="refresh_device_policy",
                reason=audit_reason,
                operator_response=None,
                override_type="policy_rejection",
                device_id=device_id,
            )
        except Exception:
            logger.exception("[runtime] failed to persist policy rejection audit trail")

    async def _watchdog_loop(self) -> None:
        """Ping /dev/watchdog every WATCHDOG_PING_INTERVAL seconds."""
        if not os.path.exists(WATCHDOG_DEVICE):
            logger.warning(
                "Watchdog: %s not found. "
                "Run: echo bcm2835_wdt | sudo tee -a /etc/modules",
                WATCHDOG_DEVICE,
            )
            return
        try:
            with open(WATCHDOG_DEVICE, "wb", buffering=0) as wd:
                logger.info(
                    "Watchdog: active on %s — timeout %ds",
                    WATCHDOG_DEVICE,
                    WATCHDOG_TIMEOUT,
                )
                try:
                    while not self._shutdown_event.is_set():
                        wd.write(b"1")
                        wd.flush()
                        try:
                            # Immediate wake on shutdown instead of sleeping blindly
                            await asyncio.wait_for(
                                self._shutdown_event.wait(),
                                timeout=WATCHDOG_PING_INTERVAL,
                            )
                        except asyncio.TimeoutError:
                            pass
                finally:
                    # Clean shutdown — magic V tells the kernel this was intentional
                    # Runs even if the task is cancelled (CancelledError)
                    wd.write(b"V")
                    wd.flush()
                    logger.info("Watchdog: closed cleanly (magic V written)")
        except PermissionError:
            logger.warning(
                "Watchdog: cannot open %s — permission denied. "
                "Run Ori with sudo or add user to watchdog group.",
                WATCHDOG_DEVICE,
            )
        except Exception:
            logger.exception("Watchdog loop failed — reboot may follow")

    async def _external_watchdog_loop(
        self,
        gpio_pin: int = EXTERNAL_WATCHDOG_GPIO,
        ping_interval_s: float = EXTERNAL_WATCHDOG_PING_S,
    ) -> None:
        """Pulse a GPIO pin for optional external watchdog hardware."""
        try:
            import importlib

            gpiozero = importlib.import_module("gpiozero")
        except ImportError:
            # Optional hardware feature; silently skip on non-Pi systems.
            return

        pin = None
        try:
            pin = gpiozero.DigitalOutputDevice(gpio_pin)
            logger.info("External GPIO watchdog active on BCM%d", gpio_pin)
            while not self._shutdown_event.is_set():
                pin.on()
                await asyncio.sleep(0.1)
                pin.off()
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=ping_interval_s,
                    )
                except asyncio.TimeoutError:
                    pass
        except Exception:
            logger.exception("[runtime] external watchdog loop failed")
        finally:
            if pin is not None:
                try:
                    pin.off()
                except Exception:
                    pass
                if hasattr(pin, "close"):
                    try:
                        pin.close()
                    except Exception:
                        pass

    async def _heartbeat_loop(self, device_id: str) -> None:
        """Log a heartbeat every 5 minutes to confirm the runtime is alive.

        The heartbeat reports:
        - managed runtime background tasks (pollers/watchdog/compaction/etc.)
        - pending reasoning tasks
        - pending approval-wait tasks
        - total active asyncio tasks
        """
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=300.0,
                )
                break  # shutdown was signalled during the wait — exit cleanly
            except asyncio.TimeoutError:
                pass  # 5 minutes elapsed normally — log heartbeat
            active = [t for t in asyncio.all_tasks() if not t.done()]
            managed = [t for t in self._background_tasks if not t.done()]
            reasoning_pending = 0
            approval_pending = 0
            for task in active:
                name = task.get_name()
                if name.startswith("reason:"):
                    reasoning_pending += 1
                elif name.startswith("approval:"):
                    approval_pending += 1
            logger.info(
                "[heartbeat] device=%s managed_tasks=%d reasoning_pending=%d "
                "approval_pending=%d active_tasks=%d",
                device_id,
                len(managed),
                reasoning_pending,
                approval_pending,
                len(active),
            )
        logger.debug("[heartbeat] loop exited cleanly")

    async def _compaction_loop(
        self,
        deduplicator: EventDeduplicator | None = None,
        max_backward_skew_ms: int = 3600000,
    ) -> None:
        """Run the SQLite Compaction Pyramid every 5 minutes."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=300.0,
                )
                break  # shutdown was signalled
            except asyncio.TimeoutError:
                pass
            if self._state_store is not None:
                try:
                    await self._state_store.compact_history(
                        max_backward_skew_ms=max_backward_skew_ms
                    )
                    logger.debug("[compaction] history compaction complete")
                except Exception:
                    logger.exception(
                        "[compaction] history compaction failed — will retry"
                    )
            if deduplicator is not None:
                try:
                    deduplicator.cleanup()
                    logger.debug("[compaction] deduplicator cleanup complete")
                except Exception:
                    logger.exception(
                        "[compaction] deduplicator cleanup failed — will retry"
                    )

    async def _capability_posture_loop(
        self,
        *,
        tracker: CapabilityPostureTracker,
        elevator: IntelligenceElevator,
        sms_enabled: bool,
        whatsapp_enabled: bool,
        local_llm: LocalLLM | None,
        relay_connected: bool,
        update_interval_s: float,
    ) -> None:
        """Periodically refresh capability posture and feed it into the elevator."""
        interval = max(update_interval_s, 1.0)
        while not self._shutdown_event.is_set():
            try:
                posture = await tracker.refresh(
                    sms_available=sms_enabled,
                    whatsapp_available=whatsapp_enabled,
                    local_slm_loaded=_is_local_slm_available(local_llm),
                    relay_connected=relay_connected,
                )
                elevator.update_capability_posture(posture)
                if self._dispatcher is not None:
                    self._dispatcher.update_capability_posture(posture)
                if self._alert_sender is not None:
                    self._alert_sender.update_capability_posture(posture)
                if self._status_indicator is not None:
                    _sync_network_state_from_posture(self._status_indicator, posture)
            except Exception:
                logger.exception("[runtime] capability posture refresh failed")

            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass

    async def _status_signaling_loop(
        self,
        *,
        indicator: LEDIndicator,
        tick_ms: int,
    ) -> None:
        interval = max(int(tick_ms), 50) / 1000.0
        while not self._shutdown_event.is_set():
            try:
                indicator.tick()
            except Exception:
                logger.exception("[runtime] status signaling tick failed")
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
        await indicator.close()

    async def _send_or_queue_alert(
        self,
        *,
        channel: str,
        message: str,
        recipient: str,
        action_tier: str,
        trigger_name: str,
        original_ts: int,
        alert_sender: AlertFailoverSender,
    ) -> bool:
        """Attempt immediate delivery; enqueue on failure.

        Returns True if delivered immediately or queued successfully.
        Returns False only if queueing also fails.
        """
        alert_ts = now_ms()
        self._last_alert_timestamps_by_channel[channel] = alert_ts
        if trigger_name:
            self._last_alert_timestamps_by_trigger[trigger_name] = alert_ts

        if not recipient:
            logger.warning(
                "[runtime] %s alert skipped: operator_contact not configured", channel
            )
            return False

        delivered = False
        try:
            delivered = await alert_sender.send(
                message=message,
                to_number=recipient,
                preferred_channel=channel,
            )
        except Exception:
            logger.exception(
                "[runtime] unexpected %s send failure; falling back to outbox queue",
                channel,
            )
            delivered = False

        if delivered:
            return True

        if self._state_store is None:
            logger.error(
                "[runtime] alert delivery failed and StateStore is unavailable; dropping alert"
            )
            return False

        alert_id = _build_alert_id(
            channel=channel,
            recipient=recipient,
            message=message,
            action_tier=action_tier,
            trigger_name=trigger_name,
            original_ts=original_ts,
        )
        inserted = await self._state_store.enqueue_alert(
            alert_id=alert_id,
            channel=channel,
            recipient=recipient,
            message=message,
            action_tier=action_tier,
            trigger_name=trigger_name,
            original_ts=original_ts,
        )
        if inserted:
            logger.info(
                "[runtime] queued failed %s alert id=%s tier=%s trigger=%s original_ts=%d",
                channel,
                alert_id,
                action_tier,
                trigger_name,
                original_ts,
            )
        else:
            logger.debug(
                "[runtime] alert already queued id=%s channel=%s", alert_id, channel
            )
        return True

    async def _alert_delivery_loop(
        self,
        alert_sender: AlertFailoverSender,
    ) -> None:
        """Retry queued outbound alerts until delivered (or abandoned for non-Tier D)."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=ALERT_OUTBOX_RETRY_INTERVAL_S,
                )
                break
            except asyncio.TimeoutError:
                pass

            if self._state_store is None:
                continue

            try:
                pending = await self._state_store.get_retryable_alerts(
                    ALERT_OUTBOX_BATCH_SIZE
                )
            except Exception:
                logger.exception("[runtime] alert outbox fetch failed")
                continue

            for alert in pending:
                try:
                    channel = str(alert["channel"])
                    message = str(alert["message"])
                    recipient = str(alert["recipient"])
                    action_tier = str(alert["action_tier"]).upper()
                    trigger_name = str(alert.get("trigger_name", "") or "")
                    attempt_count = int(alert.get("attempt_count", 0))
                    alert_id = str(alert["alert_id"])
                except Exception:
                    logger.exception("[runtime] malformed outbox row: %r", alert)
                    continue

                delivered = False
                try:
                    preferred_channel = channel
                    if channel not in {"sms", "whatsapp"}:
                        logger.error(
                            "[runtime] alert outbox has unknown channel=%r id=%s",
                            channel,
                            alert_id,
                        )
                        preferred_channel = "sms"
                    elif attempt_count >= 1:
                        # On retries, switch first attempt preference to the other
                        # channel so a persistent single-channel outage does not
                        # stall notification delivery.
                        preferred_channel = "whatsapp" if channel == "sms" else "sms"

                    delivered = await alert_sender.send(
                        message=message,
                        to_number=recipient,
                        preferred_channel=preferred_channel,
                    )
                except Exception:
                    logger.exception(
                        "[runtime] alert outbox send failed for id=%s channel=%s",
                        alert_id,
                        channel,
                    )

                if delivered:
                    delivered_ts = now_ms()
                    self._last_alert_timestamps_by_channel[channel] = delivered_ts
                    if trigger_name:
                        self._last_alert_timestamps_by_trigger[trigger_name] = (
                            delivered_ts
                        )
                    await self._state_store.mark_alert_delivered(alert_id)
                    logger.info(
                        "[runtime] delivered queued alert id=%s channel=%s after %d attempt(s)",
                        alert_id,
                        channel,
                        attempt_count + 1,
                    )
                    continue

                await self._state_store.mark_alert_attempt_failed(alert_id)
                failed_ts = now_ms()
                self._last_alert_timestamps_by_channel[channel] = failed_ts
                if trigger_name:
                    self._last_alert_timestamps_by_trigger[trigger_name] = failed_ts
                attempts_after = attempt_count + 1
                logger.warning(
                    "[runtime] retry failed for queued alert id=%s channel=%s tier=%s attempt=%d",
                    alert_id,
                    channel,
                    action_tier,
                    attempts_after,
                )

                if action_tier == "D":
                    if attempts_after >= ALERT_OUTBOX_TIER_D_CRITICAL_THRESHOLD:
                        logger.critical(
                            "[runtime] Tier D notification delivery still failing id=%s "
                            "channel=%s attempts=%d (will keep retrying)",
                            alert_id,
                            channel,
                            attempts_after,
                        )
                    continue

                if attempts_after >= ALERT_OUTBOX_MAX_ATTEMPTS_NON_TIER_D:
                    await self._state_store.mark_alert_abandoned(alert_id)
                    logger.warning(
                        "[runtime] abandoning queued alert id=%s channel=%s after %d attempts",
                        alert_id,
                        channel,
                        attempts_after,
                    )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _cap_sms_message(message: str, limit: int = 160) -> str:
    compact = " ".join(message.split())
    if len(compact) <= limit:
        return compact
    return compact[: max(limit - 3, 0)].rstrip() + "..."


def _message_from_context(
    ctx: SkillContext,
    fallback: str,
    channel: str = "sms",
) -> str:
    """Build a channel-aware alert message string from a SkillContext."""
    event_ctx = (
        ctx.event.context if ctx.event and isinstance(ctx.event.context, dict) else {}
    )
    channel_key = str(channel or "").strip().lower()

    msg = ""
    channel_messages = event_ctx.get("channel_messages")
    if isinstance(channel_messages, dict):
        raw_channel = channel_messages.get(channel_key) or channel_messages.get(
            "default"
        )
        if isinstance(raw_channel, str) and raw_channel.strip():
            msg = raw_channel.strip()
    if not msg:
        raw_operator = event_ctx.get("operator_message")
        if isinstance(raw_operator, str) and raw_operator.strip():
            msg = raw_operator.strip()

    # Fallback for raw sensor alerts that did not pass through a skill composer.
    if not msg and ctx.event and ctx.event.reading:
        r = ctx.event.reading
        if channel_key == "whatsapp":
            msg = (
                f"[{ctx.event.device_id}] {r.sensor_id} ({r.sensor_type})\n"
                f"Value: {r.value} {r.unit}"
            )
        else:
            msg = f"[{ctx.event.device_id}] {r.sensor_id} ({r.sensor_type}): {r.value} {r.unit}"

    if not msg:
        msg = str(fallback)

    if channel_key == "sms":
        return _cap_sms_message(msg)
    return msg


def _resolve_trigger_name(ctx: SkillContext) -> str:
    if ctx and isinstance(getattr(ctx, "trigger_name", ""), str):
        trigger_name = ctx.trigger_name.strip()
        if trigger_name:
            return trigger_name
    if ctx and ctx.event and isinstance(getattr(ctx.event, "sensor_id", ""), str):
        return ctx.event.sensor_id
    return ""


def _resolve_original_ts(ctx: SkillContext) -> int:
    if ctx and ctx.event:
        try:
            return int(ctx.event.timestamp)
        except Exception:
            pass
    return now_ms()


def _resolve_action_declared_tier(ctx: SkillContext, action_name: str) -> str:
    """Resolve declared tier for an action from skill capability metadata."""
    if ctx and hasattr(ctx, "skill") and hasattr(ctx.skill, "actions"):
        available = None
        if isinstance(ctx.skill.actions, dict):
            available = ctx.skill.actions.get("available")
        if isinstance(available, list):
            for item in available:
                if not isinstance(item, dict):
                    continue
                if str(item.get("name", "")) != action_name:
                    continue
                tier = str(item.get("tier", "")).upper().strip()
                if tier in {"A", "B", "C", "D"}:
                    return tier
    return "A"


def _build_alert_id(
    *,
    channel: str,
    recipient: str,
    message: str,
    action_tier: str,
    trigger_name: str,
    original_ts: int,
) -> str:
    raw = f"{channel}|{recipient}|{action_tier}|{trigger_name}|{original_ts}|{message}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _build_offline_token_verifier(actions_cfg: Any) -> OfflineTierCTokenVerifier | None:
    offline_cfg = {}
    if actions_cfg is not None and hasattr(actions_cfg, "offline_tokens"):
        candidate = getattr(actions_cfg, "offline_tokens", {}) or {}
        if isinstance(candidate, dict):
            offline_cfg = candidate
    if not is_truthy(offline_cfg.get("enabled", False)):
        return None
    return OfflineTierCTokenVerifier(
        public_key_b64=str(offline_cfg.get("public_key_b64", "")),
        max_clock_skew_s=int(offline_cfg.get("max_clock_skew_s", 300)),
    )


def _build_remote_command_verifier(config: Config) -> RemoteCommandVerifier | None:
    security_cfg = config.security if isinstance(config.security, dict) else {}
    remote_cfg = security_cfg.get("remote_commands") or {}
    if not isinstance(remote_cfg, dict):
        return None
    if not is_truthy(remote_cfg.get("enabled", False)):
        return None

    secret_env = str(
        remote_cfg.get("hmac_secret_env", "ORI_REMOTE_COMMAND_HMAC_SECRET")
    ).strip()
    shared_secret = os.environ.get(secret_env, "")
    if not shared_secret:
        logger.warning(
            "[runtime] remote commands enabled but %s is not set; commands will fail closed.",
            secret_env,
        )
    max_skew_ms = int(remote_cfg.get("max_skew_seconds", 300)) * 1000
    return RemoteCommandVerifier(
        device_id=str(config.device.id),
        shared_secret=shared_secret,
        max_skew_ms=max_skew_ms,
    )


def _remote_command_lockout_config(config: Config | None) -> dict[str, Any]:
    if config is None or not isinstance(config.security, dict):
        return default_remote_command_lockout_config()
    remote_cfg = config.security.get("remote_commands") or {}
    if not isinstance(remote_cfg, dict):
        return default_remote_command_lockout_config()
    lockout_cfg = remote_cfg.get("lockout")
    if not isinstance(lockout_cfg, dict):
        return default_remote_command_lockout_config()
    return {**default_remote_command_lockout_config(), **lockout_cfg}


def _is_local_slm_available(local_llm: Any) -> bool:
    """Safely resolve local SLM availability from any LocalLLM-like object."""
    if local_llm is None:
        return False
    return bool(getattr(local_llm, "is_available", False))


def _sync_network_state_from_posture(
    indicator: LEDIndicator, posture: CapabilityPosture
) -> None:
    if posture.internet_available:
        indicator.set_network_state(NetworkState.INTERNET)
        return
    if posture.sms_available:
        indicator.set_network_state(NetworkState.GSM_ONLY)
        return
    indicator.set_network_state(NetworkState.NONE)


def _sync_power_state_from_reading(indicator: LEDIndicator, reading: Any) -> None:
    sensor_type = str(getattr(reading, "sensor_type", ""))
    if sensor_type not in {"battery_percent", "growatt_battery_soc"}:
        return
    try:
        value = float(getattr(reading, "value", 0.0))
    except (TypeError, ValueError):
        return
    if value < 10.0:
        indicator.set_power_state(PowerState.BATTERY_CRITICAL)
    elif value < 20.0:
        indicator.set_power_state(PowerState.BATTERY_LOW)
    else:
        indicator.set_power_state(PowerState.MAINS)


def _maybe_autoload_dotenv(config_path: str) -> None:
    """Load .env when explicitly enabled via ORI_AUTOLOAD_DOTENV=true.

    This is a development convenience toggle. Production remains explicit-env
    by default (no implicit .env loading).
    """
    if not is_truthy(os.environ.get("ORI_AUTOLOAD_DOTENV", "")):
        return

    try:
        from dotenv import load_dotenv  # type: ignore[import-not-found]
    except ImportError:
        logger.warning(
            "[runtime] ORI_AUTOLOAD_DOTENV is enabled but python-dotenv is not installed"
        )
        return

    config_dir = Path(config_path).resolve().parent
    candidates = [config_dir / ".env", Path.cwd() / ".env"]
    loaded_any = False
    seen: set[str] = set()

    for candidate in candidates:
        key = str(candidate.resolve())
        if key in seen:
            continue
        seen.add(key)
        if candidate.is_file():
            load_dotenv(dotenv_path=candidate, override=False)
            loaded_any = True
            logger.info("[runtime] loaded environment from %s", candidate)

    if not loaded_any:
        logger.info(
            "[runtime] ORI_AUTOLOAD_DOTENV enabled but no .env file found near config/cwd"
        )


def _resolve_local_model_file(
    local_model: str,
    model_path: str,
    config_path: str,
) -> str | None:
    """Resolve local model config to an existing GGUF file path.

    Resolution supports:
    - `local_model` as an absolute/relative file path (with or without `.gguf`)
    - `model_path` as a directory containing `local_model` (with optional `.gguf`)
    - `model_path` itself as a direct model file path
    """
    config_dir = Path(config_path).resolve().parent
    local_model = (local_model or "").strip()
    model_path = (model_path or "").strip()

    candidates: list[Path] = []

    def _to_abs(path_text: str) -> Path:
        p = Path(path_text)
        return p if p.is_absolute() else (config_dir / p)

    if local_model:
        local_model_path = _to_abs(local_model)
        candidates.append(local_model_path)
        if local_model_path.suffix.lower() != ".gguf":
            candidates.append(local_model_path.with_suffix(".gguf"))

        if model_path:
            model_base = _to_abs(model_path)
            local_name = Path(local_model).name
            candidates.append(model_base / local_name)
            if not local_name.endswith(".gguf"):
                candidates.append(model_base / f"{local_name}.gguf")
    elif model_path:
        candidates.append(_to_abs(model_path))

    deduped: list[Path] = []
    seen: set[str] = set()
    for c in candidates:
        key = str(c.resolve(strict=False))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)

    for candidate in deduped:
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def _build_local_llm(reasoning_cfg: Any, config_path: str) -> LocalLLM | None:
    """Instantiate LocalLLM from config when a valid local model is available."""
    local_model = str(getattr(reasoning_cfg, "local_model", "") or "")
    model_path = str(getattr(reasoning_cfg, "model_path", "") or "")
    context_window = int(getattr(reasoning_cfg, "local_context_window", 2048) or 2048)

    model_file = _resolve_local_model_file(local_model, model_path, config_path)
    if model_file is None:
        logger.warning(
            "[runtime] local SLM disabled — could not resolve a model file from "
            "reasoning.local_model=%r and reasoning.model_path=%r",
            local_model,
            model_path,
        )
        return None

    local_llm = LocalLLM(model_path=model_file, context_window=context_window)
    if not local_llm.is_available:
        logger.warning(
            "[runtime] local SLM unavailable for model=%s. Ensure llama-cpp-python "
            "is installed and model file is accessible.",
            model_file,
        )
        return None

    logger.info(
        "[runtime] local SLM enabled — model=%s n_ctx=%d",
        model_file,
        context_window,
    )
    return local_llm


def _process_target_from_context(ctx: SkillContext) -> tuple[int | None, str]:
    """Resolve a single process target for `terminate_process`.

    Resolution order:
    1. Explicit event context override: `event.context["terminate_process"]`
       with `{pid, name}`.
    2. Exactly one process in `event.reading.metadata["processes"]`.
    """
    if not ctx or not ctx.event:
        return None, ""

    terminate_ctx = ctx.event.context.get("terminate_process", {})
    if isinstance(terminate_ctx, dict):
        pid = terminate_ctx.get("pid")
        name = terminate_ctx.get("name")
        if isinstance(pid, int) and isinstance(name, str) and name.strip():
            return pid, name.strip()
        if (
            isinstance(pid, str)
            and pid.isdigit()
            and isinstance(name, str)
            and name.strip()
        ):
            return int(pid), name.strip()

    reading = ctx.event.reading
    if reading is None:
        return None, ""

    processes = reading.metadata.get("processes", [])
    if not isinstance(processes, list):
        processes = []

    recommended = reading.metadata.get("recommended_process")
    if isinstance(recommended, dict):
        pid = recommended.get("pid")
        name = recommended.get("name")
        if isinstance(pid, int) and isinstance(name, str) and name.strip():
            return pid, name.strip()
        if (
            isinstance(pid, str)
            and pid.isdigit()
            and isinstance(name, str)
            and name.strip()
        ):
            return int(pid), name.strip()

    valid: list[tuple[int, str]] = []
    for proc in processes:
        if not isinstance(proc, dict):
            continue
        pid = proc.get("pid")
        name = proc.get("name")
        if isinstance(pid, int) and isinstance(name, str) and name.strip():
            valid.append((pid, name.strip()))
        elif (
            isinstance(pid, str)
            and pid.isdigit()
            and isinstance(name, str)
            and name.strip()
        ):
            valid.append((int(pid), name.strip()))

    if len(valid) == 1:
        return valid[0]

    return None, ""


def _kernel_subsystem_from_context(ctx: SkillContext) -> str:
    """Resolve subsystem target for `reset_kernel_subsystem`.

    Resolution order:
    1. Explicit event context override:
       `event.context["reset_kernel_subsystem"]` as either
       `{"subsystem": "<name>"}` or `"<name>"`.
    2. Reading metadata keys: `kernel_subsystem` then `subsystem`.
    """
    if not ctx or not ctx.event:
        return ""

    raw = ctx.event.context.get("reset_kernel_subsystem", "")
    if isinstance(raw, dict):
        subsystem = raw.get("subsystem")
        if isinstance(subsystem, str) and subsystem.strip():
            return subsystem.strip()
    elif isinstance(raw, str) and raw.strip():
        return raw.strip()

    reading = ctx.event.reading
    if reading is None:
        return ""

    for key in ("kernel_subsystem", "subsystem"):
        value = reading.metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _coap_command_from_context(ctx: SkillContext) -> tuple[str, str | None]:
    """Resolve CoAP command from event metadata and skill config.

    Resolution order:
    1. event.context["coap_command"] / ["coap_payload"]
    2. reading.metadata["coap_command"] / ["coap_payload"]
    3. skill.config.coap.trigger_commands[trigger_name]
    4. skill.config.coap.default_command
    """
    if not ctx or not ctx.event:
        return "", None

    command_name = ""
    payload_override: str | None = None

    event_ctx = ctx.event.context if isinstance(ctx.event.context, dict) else {}
    if isinstance(event_ctx.get("coap_command"), str):
        command_name = str(event_ctx["coap_command"]).strip()
    if event_ctx.get("coap_payload") is not None:
        payload_override = str(event_ctx.get("coap_payload"))

    reading = ctx.event.reading
    metadata = reading.metadata if reading is not None else {}
    if not command_name and isinstance(metadata.get("coap_command"), str):
        command_name = str(metadata["coap_command"]).strip()
    if payload_override is None and metadata.get("coap_payload") is not None:
        payload_override = str(metadata.get("coap_payload"))

    skill_cfg = getattr(getattr(ctx, "skill", None), "config", {}) or {}
    if isinstance(skill_cfg, dict):
        coap_cfg = skill_cfg.get("coap") or {}
        if isinstance(coap_cfg, dict):
            trigger_commands = coap_cfg.get("trigger_commands") or {}
            if (
                not command_name
                and isinstance(trigger_commands, dict)
                and isinstance(getattr(ctx, "trigger_name", ""), str)
            ):
                trigger_name = ctx.trigger_name.strip()
                mapped = trigger_commands.get(trigger_name)
                if isinstance(mapped, str) and mapped.strip():
                    command_name = mapped.strip()
            if not command_name:
                default_command = coap_cfg.get("default_command")
                if isinstance(default_command, str) and default_command.strip():
                    command_name = default_command.strip()

    return command_name, payload_override


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Ori Runtime")
    parser.add_argument(
        "--config",
        default="ori.yaml",
        help="Path to ori.yaml config file",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    _maybe_autoload_dotenv(args.config)

    runtime = OriRuntime(config_path=args.config)
    asyncio.run(runtime.start())


if __name__ == "__main__":
    main()
