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
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import signal
import stat
from collections.abc import Awaitable, Callable
from importlib import resources
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from ori.actions.alert_failover import AlertFailoverSender
from ori.actions.coap import CoAPAction, coap_backend_available
from ori.actions.commissioned_actuator import CommissionedActuator
from ori.actions.logger import LoggerAction
from ori.actions.process_manager import ProcessManagerAction
from ori.actions.relay import (
    RelayAction,
    gpio_backend_arbitrated,
    gpio_backend_importable,
    resolved_pin_factory_name,
)
from ori.actions.sms import SMSAction
from ori.actions.system_control import SystemControlAction
from ori.actions.whatsapp import TwilioProvider, WhatsAppAction
from ori.config import (
    Config,
    ConfigValidationError,
    SensorConfig,
    requires_production_posture,
)
from ori.firmware_mqtt_operator import (
    FirmwareMqttOperatorController,
    FirmwareMqttOperatorServer,
)
from ori.gateway.evidence_inbound import (
    EvidenceInboundRouter,
    MqttEvidenceInboundSubscriber,
)
from ori.gateway.evidence_outbound import (
    EvidenceOutboundAckRouter,
    MqttEvidenceOutboundPublisher,
)
from ori.gateway.export import GatewayExportResponder, MqttGatewayExportServer
from ori.gateway.firmware_commands import (
    FirmwareCommandService,
    MqttFirmwareCommandPublisher,
    load_raw_ed25519_seed_from_env,
)
from ori.gateway.firmware_liveness_publisher import FirmwareLivenessScheduler
from ori.gateway.firmware_telemetry import MqttFirmwareTelemetrySubscriber
from ori.gateway.heartbeat import MqttGatewayHeartbeatSubscriber
from ori.gateway.node_heartbeat import (
    DEGRADATION_REASON_FIRMWARE_LIVENESS,
    MqttRuntimeNodeHeartbeatPublisher,
)
from ori.gateway.reasoning import MqttGatewayReasoner
from ori.hal.base import AdapterReadError, BaseAdapter, MeasurementRefusedError
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
from ori.policy.alert_classes import alert_class_for_trigger
from ori.policy.remote_fetch import (
    RemotePolicyFetchError,
    device_policy_from_payload,
    fetch_remote_device_policy_bundle,
    fetch_remote_device_policy_bundle_by_reference,
)
from ori.reasoning.action_dispatcher import ALERT_SUPPRESSED, ActionDispatcher
from ori.reasoning.capability_posture import CapabilityPosture, CapabilityPostureTracker
from ori.reasoning.context_enricher import ContextEnricher, ContextEnricherConfig
from ori.reasoning.elevator import IntelligenceElevator, SkillContext
from ori.reasoning.local_llm import LocalLLM, local_llm_backend_available
from ori.runtime_health_socket import RuntimeHealthSocketServer
from ori.safety.commander import ActuatorOutcomeCommander
from ori.safety.registry import SafetyRegistry
from ori.security.commissioning.anchors import (
    AnchorError,
    CommissioningAnchors,
    anchor_collision,
    load_commissioning_anchors,
    provisioning_anchor,
)
from ori.security.commissioning.loader import (
    CommissioningState,
    DeclaredInventory,
    load_commissioning_state,
)
from ori.security.commissioning.profiles import (
    ProfileSetError,
    load_shipped_profile_set,
)
from ori.security.evidence.authority_keys import load_authority_key_registry
from ori.security.evidence.chain import SCHEMA_VERSION as EVIDENCE_SCHEMA_VERSION
from ori.security.evidence.custody_keys import (
    CustodyKeyRegistry,
    CustodyKeyRegistryError,
)
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.security.evidence.ledger import DEFAULT_CHECKPOINT_INTERVAL_S
from ori.security.firmware.confirmation import (
    CONFIRMED as _FIRMWARE_CONFIRMED,
)
from ori.security.firmware.confirmation import (
    FirmwareConfirmationCoordinator,
)
from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.liveness import (
    LIVENESS_PUBLISH_INTERVAL_S,
    FirmwareLivenessSupervisor,
)
from ori.security.firmware.mqtt_certificate import FirmwareMqttCertificateAuthority
from ori.security.firmware.mqtt_provisioning import FirmwareMqttProvisioningService
from ori.security.firmware.mqtt_workflow import FirmwareMqttProvisioningWorkflow
from ori.security.firmware.reconciliation import (
    DEFAULT_INTERVAL_S as CONFIRMATION_RETRY_INTERVAL_S,
)
from ori.security.firmware.reconciliation import (
    FirmwareConfirmationReconciler,
)
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
    GatewayMessageEncryptionConfig,
    GatewayMessageEncryptor,
    GatewayReplayCache,
)
from ori.security.offline_tokens import OfflineTierCTokenVerifier
from ori.security.remote_commands.commands import RemoteCommand, RemoteCommandVerifier
from ori.security.remote_commands.lockout import (
    default_remote_command_lockout_config,
    evaluate_remote_command_lockout,
    remote_command_sender_key,
)
from ori.security.remote_commands.policy import (
    STATUS_AUDIT_ONLY,
    STATUS_DRY_RUN,
    STATUS_EXECUTED,
    STATUS_FAILED,
    STATUS_PRECONDITION_FAILED,
    STATUS_UNSUPPORTED,
    RemoteCommandExecutionResult,
    classify_remote_command,
    command_requests_dry_run,
    command_result,
)
from ori.security.remote_commands.throttle import RemoteCommandThrottleDecision
from ori.security.threshold_guard import (
    all_trigger_condition_refs,
    check_tier_d_condition_suppression,
    check_tier_d_startup_sensitivity,
    tier_d_config_keys,
)
from ori.security.webhook_signatures import (
    WebhookSignatureConfig,
    WebhookSignatureVerifier,
)
from ori.skills.loader import (
    MAX_TOTAL_SUBSCRIPTIONS as SKILL_SUBSCRIPTION_BUDGET,
)
from ori.skills.loader import (
    SkillLoader,
)
from ori.skills.signing import verify_signed_payload
from ori.state.store import StateStore, TripJournal
from ori.telemetry.http_export import HttpTelemetryExporter
from ori.utils.bool_utils import is_truthy
from ori.utils.net_utils import is_loopback_host
from ori.utils.path_utils import path_is_relative_to
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)


class _SafetyAlertAdapter:
    """The registry's alert sink: straight to the runtime's deliver-or-queue
    path, never the dispatcher, never anything DevicePolicy can gate. The
    sender arrives late in startup; a notice raised before then is refused
    and the registry logs it."""

    def __init__(self, runtime: "OriRuntime") -> None:
        self._runtime = runtime
        self.sender: AlertFailoverSender | None = None

    async def send(
        self, *, kind: str, zone_id: str, profile_id: str, message: str
    ) -> bool:
        if self.sender is None:
            return False
        return await self._runtime._send_or_queue_safety_alert(
            message=f"SAFETY {kind}: {message}",
            trigger_name=f"safety_{kind}",
            alert_sender=self.sender,
        )


def _refuse_unbound_active_zones(unbound: list[str], *, hardened: bool) -> None:
    """Active protection needs a physical executor. A zone with an active
    profile and no bound actuator refuses a hardened start; a development
    start degrades it explicitly rather than reporting protection."""
    if not unbound:
        return
    if hardened:
        raise ConfigValidationError(
            "hardened posture refuses to start: zones with active safety "
            f"profiles have no bound executor: {', '.join(unbound)}"
        )
    logger.warning(
        "[safety] starting degraded: zones %s have active profiles and no "
        "bound executor; their profiles cannot actuate",
        unbound,
    )


WATCHDOG_DEVICE = "/dev/watchdog"
WATCHDOG_PING_INTERVAL = 10  # seconds — kernel expects a ping at least this often
WATCHDOG_TIMEOUT = 60  # seconds — kernel reboots if no ping within this window
EXTERNAL_WATCHDOG_GPIO = 17  # BCM pin for optional external watchdog heartbeat
EXTERNAL_WATCHDOG_PING_S = 30  # heartbeat interval for external watchdog devices
TIER_D_DRAIN_TIMEOUT = 5.0  # seconds — wait for in-flight Tier D tasks on shutdown
EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S = 5.0
ALERT_OUTBOX_RETRY_INTERVAL_S = 30.0
ALERT_OUTBOX_BATCH_SIZE = 50
ALERT_OUTBOX_MAX_ATTEMPTS_NON_TIER_D = 10
ALERT_OUTBOX_TIER_D_CRITICAL_THRESHOLD = 3
SETUP_NOTIFICATION_MAX_CHARS = 320
CAPABILITY_POSTURE_UPDATE_INTERVAL_S = 30.0
DEVICE_POLICY_REFRESH_DEFAULT_S = 21600.0
DEVICE_POLICY_TRANSIENT_AUDIT_SUPPRESS_MS = 900_000
STALE_SENSOR_MIN_CHECK_INTERVAL_S = 1.0

# How many consecutive refused measurement windows mark a sensor degraded. One
# refusal is a transient the poll cadence will retry; a run of them means the
# signal, the wiring or the timing has changed and the reading is not coming
# back on its own.
MEASUREMENT_REFUSALS_BEFORE_DEGRADED = 3

# And how many consecutive good windows clear it. Recovery is deliberately
# slower than failure: a measurement path that alternates is not trustworthy,
# and flapping between degraded and healthy would produce an alert stream that
# operators learn to ignore.
MEASUREMENT_WINDOWS_TO_RECOVER = 5

# How many times a degradation warning is retried when it could not be
# delivered or durably queued. Paced by the poll interval, and bounded so a
# broken alert path does not retry forever on every refused window.
MEASUREMENT_NOTIFY_MAX_ATTEMPTS = 5

# The escalation schedule for a measurement loss that does not resolve, in
# elapsed milliseconds since the degradation began.
#
# A device that cannot establish a trustworthy measurement said so once and
# then waited indefinitely for a person. The first notice is not the problem;
# the silence after it is, because a channel that is not being measured is a
# channel nothing is protecting, and the operator has no reminder that it is
# still in that state.
#
#   immediate   the primary contact, on the transition into degraded
#   6 hours     the primary contact again
#   12 hours    the secondary contact, or the primary where none is configured
#   daily       the same escalation contact, indefinitely
#
# **There is no give-up.** A still-unprotected channel must not become
# permanently silent, so nothing here stops on a message count or a delivery
# cost. It stops when the sensor produces credible measurements again. Two
# further stop conditions are sanctioned and neither is implemented: removal
# of the affected safety pair, which belongs with the active-pair supervision
# design, and a locally audited maintenance acknowledgement with a short
# expiry, which needs an inbound, audited authority surface of its own. Until
# they exist, recovery is the only way this stops, and an operator who has
# accepted the fault keeps being reminded of it.
#
# Release-owned rather than site-configurable, deliberately. A setting here
# would let a deployment configure a persistent measurement loss into silence,
# which is the condition this schedule exists to prevent. Measure real pilot
# message volume first; any later configuration must be a surface that cannot
# disable, indefinitely defer, or remove the escalation.
#
# The cadence keeps message volume to two primary messages and then one daily
# escalation, rather than repeating to everybody every day.
MEASUREMENT_REMINDER_AFTER_MS = 6 * 60 * 60 * 1000
MEASUREMENT_ESCALATE_AFTER_MS = 12 * 60 * 60 * 1000
MEASUREMENT_ESCALATION_REPEAT_MS = 24 * 60 * 60 * 1000


def measurement_notice_stage_due(elapsed_ms: int) -> int:
    """Which notice the schedule owes at this point in a degradation.

    Stage 0 is the notice sent on the transition itself. The schedule is a
    function of elapsed time alone, never of what was delivered, so a reminder
    that could not be sent is superseded by the next stage rather than
    cancelling it.
    """
    if elapsed_ms < MEASUREMENT_REMINDER_AFTER_MS:
        return 0
    if elapsed_ms < MEASUREMENT_ESCALATE_AFTER_MS:
        return 1
    repeats = (elapsed_ms - MEASUREMENT_ESCALATE_AFTER_MS) // (
        MEASUREMENT_ESCALATION_REPEAT_MS
    )
    return 2 + int(repeats)


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


def adapter_connect_config(sensor_cfg: SensorConfig, config: Config) -> dict[str, Any]:
    """Build the dict handed to an adapter's ``connect()``.

    Metadata is spread first and the runtime's own values are applied over it,
    never the reverse. Config load already refuses a sensor that names one of
    these, and this ordering means the boundary does not depend on that check
    having run: a metadata key reaching here cannot displace the sensor's
    declared identity or the circuit breaker, which would make hardware
    recovery settable per sensor.

    Extracted from ``start()`` so the boundary is a unit a test can drive with
    a real adapter, rather than ten lines inside an eight-hundred-line method.
    """
    connect_cfg: dict[str, Any] = {
        **sensor_cfg.metadata,
        "sensor_id": sensor_cfg.id,
        "sensor_type": sensor_cfg.type,
        "circuit_breaker": config.hal.circuit_breaker,
        # Adapters that run their own poll loop refresh a cache the runtime then
        # reads on the same schedule. Without this the cache refreshed at the
        # adapter's default while the runtime read at the operator's rate,
        # serving one stale reading repeatedly as though it were fresh.
        "poll_interval_ms": sensor_cfg.poll_interval_ms,
        # Calibration is passed as its own block rather than flattened into the
        # same namespace. Flattening is what let a documented `sensitivity` sit
        # unread beside the adapter's own default.
        "calibration": dict(sensor_cfg.calibration),
    }
    return connect_cfg


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
        self._secondary_contact: str = ""
        self._sensor_poll_interval_ms: dict[str, int] = {}
        self._sensor_last_seen_ms: dict[str, int] = {}
        self._stale_sensor_active: set[str] = set()
        # A refused measurement window is not a failed read. The sensor is
        # present and answering; what it returned was not a measurement.
        self._measurement_refusals: dict[str, int] = {}
        self._measurement_valid_streak: dict[str, int] = {}
        self._measurement_degraded: set[str] = set()
        # Configured sensors whose adapter never connected. Distinct from a
        # sensor that connected and went quiet: that one is late and the
        # staleness watch sees it, this one is absent and nothing else does.
        self._unconnected_sensors: set[str] = set()
        self._measurement_unnotified: set[str] = set()
        self._measurement_notify_attempts: dict[str, int] = {}
        self._measurement_degraded_since: dict[str, int] = {}
        self._measurement_notice_stage: dict[str, int] = {}
        self._runtime_started_at_ms: int = 0
        self._configured_sensors: list[Any] = []
        self._connected_sensor_ids: set[str] = set()
        self._last_alert_timestamps_by_channel: dict[str, int] = {}
        self._last_alert_timestamps_by_trigger: dict[str, int] = {}
        self._health_socket_server: RuntimeHealthSocketServer | None = None
        self._firmware_mqtt_operator_server: FirmwareMqttOperatorServer | None = None
        self._gateway_export_server: MqttGatewayExportServer | None = None
        self._runtime_node_heartbeat_publisher: (
            MqttRuntimeNodeHeartbeatPublisher | None
        ) = None
        self._firmware_command_publisher: MqttFirmwareCommandPublisher | None = None
        self._firmware_command_service: FirmwareCommandService | None = None
        self._firmware_liveness_scheduler: FirmwareLivenessScheduler | None = None
        self._telemetry_exporter: HttpTelemetryExporter | None = None
        self._evidence_attestor: FirstPartyEvidenceAttestor | None = None
        self._evidence_inbound_subscriber: MqttEvidenceInboundSubscriber | None = None
        self._evidence_outbound_publisher: MqttEvidenceOutboundPublisher | None = None
        self._evidence_posture_problems: list[str] = []
        self._commissioning_state: CommissioningState | None = None
        self._safety_registry: SafetyRegistry | None = None
        self._safety_commander: ActuatorOutcomeCommander | None = None
        self._safety_alert_sink: _SafetyAlertAdapter | None = None
        self._commissioned_actuator: CommissionedActuator | None = None
        self._firmware_confirmation_coordinator: (
            FirmwareConfirmationCoordinator | None
        ) = None
        self._firmware_confirmation_reconciler: (
            FirmwareConfirmationReconciler | None
        ) = None
        self._health_socket_path: str = ""
        self._firmware_mqtt_operator_socket_path: str = ""
        self._device_policy_enabled: bool = False
        self._device_id: str = ""
        self._remote_command_lockout_states: dict[str, dict[str, Any]] = {}
        self._remote_command_lockout_config: dict[str, Any] = (
            default_remote_command_lockout_config()
        )
        self._alert_outbox_retry_interval_s: float = ALERT_OUTBOX_RETRY_INTERVAL_S
        self._alert_outbox_batch_size: int = ALERT_OUTBOX_BATCH_SIZE
        self._alert_outbox_max_non_tier_d_attempts: int = (
            ALERT_OUTBOX_MAX_ATTEMPTS_NON_TIER_D
        )
        self._alert_outbox_tier_d_critical_threshold: int = (
            ALERT_OUTBOX_TIER_D_CRITICAL_THRESHOLD
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

            # Check the whole plan before removing anything. Registration is
            # what enforces the subscription budget, so discovering mid-way
            # that the new set does not fit would leave the runtime with the
            # old handlers already gone and only some replacements installed —
            # including, potentially, missing Tier D coverage.
            planned = self._skill_loader.planned_subscription_cost(loaded)
            if planned > SKILL_SUBSCRIPTION_BUDGET:
                logger.error(
                    "[runtime] skill reload rejected — %d handlers exceeds the "
                    "budget of %d; keeping the existing handler graph",
                    planned,
                    SKILL_SUBSCRIPTION_BUDGET,
                )
                return False

            self._unregister_skill_handlers()
            try:
                for skill in loaded:
                    subscriptions = self._skill_loader.register(skill, self._event_bus)
                    self._skill_subscriptions.extend(subscriptions)
            except Exception:
                # The old graph is already gone. Report at CRITICAL rather than
                # letting a partially registered runtime look healthy.
                logger.critical(
                    "[runtime] skill registration failed mid-reload — the "
                    "handler graph is incomplete and safety triggers may be "
                    "missing. Restart the runtime.",
                    exc_info=True,
                )
                raise

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

    async def approve_firmware_commands(self, device_id: str) -> bytes:
        """Publish the retained provisioning approval for one firmware device."""
        if self._firmware_command_service is None:
            raise RuntimeError("firmware command egress is not enabled")
        return await self._firmware_command_service.publish_provisioning_approval(
            device_id
        )

    async def publish_firmware_command(
        self,
        *,
        device_id: str,
        action: str,
        channel: str,
    ) -> bytes:
        """Sign and publish one non-retained firmware command."""
        if self._firmware_command_service is None:
            raise RuntimeError("firmware command egress is not enabled")
        return await self._firmware_command_service.publish_command(
            device_id=device_id,
            action=action,
            channel=channel,
        )

    async def start(self) -> None:
        """Full startup sequence. Blocks until a shutdown signal is received."""

        # ── Step A: Load and validate config ─────────────────────────────────
        try:
            config = Config.load(self._config_path)
            _validate_required_runtime_capabilities(config, self._config_path)
        except ConfigValidationError:
            logger.exception("[runtime] config validation failed — aborting")
            raise
        self._config = config
        # Anchors are compared as key material at configuration load, before
        # any binding is seen: if a commissioning anchor is the provisioning
        # anchor, the separation the binding contract rests on does not exist.
        try:
            commissioning_anchors = load_commissioning_anchors()
        except AnchorError as exc:
            logger.error("[commissioning] %s — aborting", exc)
            raise ConfigValidationError(f"commissioning anchors: {exc}") from exc
        if anchor_collision(commissioning_anchors, _provisioning_anchor_bytes(config)):
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
            allowed_senders=_build_sms_allowed_senders(config),
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

        # The binding is loaded before any pin is driven: the pin's polarity
        # and what its coil states do are commissioned facts, and the relay is
        # connected only under an accepted zone for its pin.
        await self._load_commissioning(config, commissioning_anchors)
        commissioning_state = self._commissioning_state
        zone = (
            commissioning_state.zone_for_local_gpio(
                int(config.actions.relay["gpio_pin"])
            )
            if has_relay_config
            and commissioning_state is not None
            and commissioning_state.actuation_licensed
            else None
        )
        if has_relay_config and zone is not None and not zone.in_force_eligible:
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
        self._safety_alert_sink = _SafetyAlertAdapter(self)
        self._safety_registry = SafetyRegistry(
            load_shipped_profile_set(),
            in_force_zones,
            TripJournal(self._state_store),
            self._safety_commander,
            alert_sink=self._safety_alert_sink,
            poll_intervals_ms={
                str(sensor.id): int(sensor.poll_interval_ms)
                for sensor in config.sensors
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
                device=config.device, security=config.security
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
        if has_relay_config and zone is None:
            logger.warning(
                "[runtime] relay on GPIO pin %s is declared but has no zone in force "
                "with both proof legs; the pin is not driven, relay actions are "
                "refused, and the zone is reported unprotected",
                config.actions.relay.get("gpio_pin"),
            )
            has_relay_config = False
        if self._safety_registry is not None:
            prospective_bound = (
                frozenset({zone.zone_id})
                if has_relay_config and zone is not None
                else frozenset()
            )
            _refuse_unbound_active_zones(
                sorted(
                    self._safety_registry.zones_with_active_pairs - prospective_bound
                ),
                hardened=requires_production_posture(
                    device=config.device, security=config.security
                ),
            )
        defer_line_acquisition = (
            zone is not None
            and self._safety_registry is not None
            and zone.zone_id in self._safety_registry.zones_with_active_pairs
            and zone.mapping.get("de_energised_terminal_state") == "closed"
        )
        if (
            has_relay_config
            and zone is not None
            and commissioning_state is not None
            and defer_line_acquisition
        ):
            # Connecting acquires the line de-energised, which on this zone
            # closes the protected circuit — the act the registry defers
            # until the first credible reading. The line stays untouched;
            # the registry's first command is the acquisition.
            relay_action = RelayAction()
            if not gpio_backend_importable() and requires_production_posture(
                device=config.device, security=config.security
            ):
                raise ConfigValidationError(
                    "production posture requires a real GPIO backend for the "
                    f"deferred-acquisition relay on pin {config.actions.relay['gpio_pin']}"
                )
        elif has_relay_config and zone is not None and commissioning_state is not None:
            relay_action = RelayAction()
            gpio_pin: int = config.actions.relay["gpio_pin"]
            try:
                await relay_action.connect(
                    gpio_pin=gpio_pin,
                    active_high=bool(zone.identity["active_high"]),
                    tolerate_missing_backend=not requires_production_posture(
                        device=config.device,
                        security=config.security,
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
                    device=config.device,
                    security=config.security,
                ):
                    raise ConfigValidationError(
                        "production posture requires configured GPIO relay control "
                        f"to initialise successfully on pin {gpio_pin}: {exc}"
                    ) from exc
                relay_action = None
        if (
            relay_action is not None
            and zone is not None
            and zone.in_force_eligible
            and commissioning_state is not None
            and commissioning_state.in_force is not None
        ):
            actuator = CommissionedActuator(
                driver=relay_action,
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
        self._secondary_contact = _secondary_contact
        self._configure_alert_outbox(config.actions.alert_outbox)
        alert_sender = AlertFailoverSender(
            primary_channel=primary_alert_channel,
            sms_sender=sms_action,
            whatsapp_sender=whatsapp_action,
        )
        self._alert_sender = alert_sender
        if self._safety_alert_sink is not None:
            self._safety_alert_sink.sender = alert_sender
        causal_cfg = (
            config.reasoning.causal_memory
            if isinstance(config.reasoning.causal_memory, dict)
            else {}
        )
        rejection_expiry_days = int(causal_cfg.get("rejection_expiry_days", 30))

        evidence_attestor = _build_evidence_attestor(config)
        if evidence_attestor is not None:
            await evidence_attestor.start()
            # Evidence trust that cannot be established fails closed for
            # evidence — ingest refuses, health reports the posture — and
            # never for the runtime: Tier D is never gated on evidence, so the
            # deterministic safety path starts regardless of profile.
            self._evidence_posture_problems = _evidence_posture_problems(
                config, evidence_attestor
            )
            for problem in self._evidence_posture_problems:
                if requires_production_posture(
                    device=config.device, security=config.security
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
        self._evidence_attestor = evidence_attestor

        # The confirmation coordinator reconciles a locally-approved anchor
        # with the evidence store before its authority is treated as
        # effective. It is runtime-owned and reaches evidence state only
        # through the attestor's executor-bound backend, so the thread-bound
        # SQLite connections stay on the thread that opened them.
        if (
            evidence_attestor is not None
            and self._state_store is not None
            and evidence_attestor.available
        ):
            confirmation_chain = evidence_attestor.confirmation_backend()
            if confirmation_chain is not None:
                coordinator = FirmwareConfirmationCoordinator(
                    store=self._state_store, chain=confirmation_chain
                )
                self._firmware_confirmation_coordinator = coordinator
                # Approval alone cannot reach the evidence store, and a
                # confirmation that arrives later has nothing re-examining
                # the obligation. This is that missing layer.
                firmware_cfg = (
                    config.gateway.firmware_commands
                    if isinstance(config.gateway.firmware_commands, dict)
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

        dispatcher = ActionDispatcher(
            state_store=self._state_store,
            alert_sender=alert_sender,
            emergency_sms_sender=sms_action,
            offline_token_verifier=_build_offline_token_verifier(config.actions),
            status_indicator=status_indicator,
            evidence_attestor=evidence_attestor,
            binding_seq_in_force=self._binding_seq_in_force,
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
                "approval_require_scoped_replies": (
                    config.actions.approval_require_scoped_replies
                ),
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
        async def _exec_alert_whatsapp(action: str, ctx: SkillContext) -> bool | str:
            msg = _message_from_context(ctx, action, channel="whatsapp")
            action_tier = _resolve_action_declared_tier(ctx, action)
            trigger_name = _resolve_trigger_name(ctx)
            skill_name, first_party = _resolve_skill_identity(ctx)
            original_ts = _resolve_original_ts(ctx)
            return await self._send_or_queue_alert(
                channel="whatsapp",
                skill_name=skill_name,
                skill_is_first_party=first_party,
                message=msg,
                recipient=_operator_contact,
                action_tier=action_tier,
                trigger_name=trigger_name,
                original_ts=original_ts,
                alert_sender=alert_sender,
            )

        dispatcher.register_executor("alert_whatsapp", _exec_alert_whatsapp)

        # alert_sms executor
        async def _exec_alert_sms(action: str, ctx: SkillContext) -> bool | str:
            msg = _message_from_context(ctx, action, channel="sms")
            action_tier = _resolve_action_declared_tier(ctx, action)
            trigger_name = _resolve_trigger_name(ctx)
            skill_name, first_party = _resolve_skill_identity(ctx)
            original_ts = _resolve_original_ts(ctx)
            return await self._send_or_queue_alert(
                channel="sms",
                skill_name=skill_name,
                skill_is_first_party=first_party,
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

        # Relay-backed safety executors — only if relay successfully connected.
        # Semantic safety actions such as close_gas_valve still resolve through
        # the physical relay path; commissioning must wire the relay output to
        # the named fail-safe valve/contactor before that semantic action is
        # safety-creditable.
        actuator_in_force = self._commissioned_actuator
        if relay_action is not None and actuator_in_force is not None:
            actuator_bound = actuator_in_force

            async def _exec_trip_relay(*_: Any) -> bool:
                # `trip_relay` and `close_gas_valve` name one outcome: isolate
                # the load. The zone's mapping decides the coil state.
                executed = await actuator_bound.command("open_protected_circuit")
                if status_indicator is not None:
                    status_indicator.set_relay_energized(actuator_bound.coil_energised)
                return executed

            async def _exec_release_relay(*_: Any) -> bool:
                executed = await actuator_bound.command("close_protected_circuit")
                if status_indicator is not None:
                    status_indicator.set_relay_energized(actuator_bound.coil_energised)
                return executed

            dispatcher.register_executor("trip_relay", _exec_trip_relay)
            dispatcher.register_executor("release_relay", _exec_release_relay)
            dispatcher.register_executor("close_gas_valve", _exec_trip_relay)

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

        local_llm = _build_local_llm(
            config.reasoning,
            self._config_path,
            required=bool(
                requires_production_posture(
                    device=config.device,
                    security=config.security,
                )
                and _local_llm_requested(config.reasoning)
            ),
        )
        gateway_reasoner = _build_gateway_reasoner(config)
        elevator = IntelligenceElevator(
            local_llm=local_llm,
            gateway_reasoner=gateway_reasoner,
            config=config.reasoning,
            context_enricher=_build_context_enricher(config),
        )

        # ── Step E: EventBus ──────────────────────────────────────────────────
        event_bus = EventBus()
        elevator.attach_event_bus(event_bus)
        self._event_bus = event_bus
        if posture_tracker is not None:
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
        skills_security = config.security.get("skills")
        skills_require_signed = is_truthy(
            skills_security.get("require_signed", False)
            if isinstance(skills_security, dict)
            else False
        )
        loader = SkillLoader(
            elevator=elevator,
            state_store=self._state_store,
            dispatcher=dispatcher,
            os_sandbox_config=config.os_sandbox,
            require_signed=skills_require_signed,
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
        self._unconnected_sensors = set()
        self._connected_sensor_ids = set()
        self._sensor_poll_interval_ms = {}
        self._sensor_last_seen_ms = {}
        self._stale_sensor_active = set()
        self._measurement_refusals = {}
        self._measurement_valid_streak = {}
        await self._restore_measurement_state()
        self._last_alert_timestamps_by_channel = {}
        self._last_alert_timestamps_by_trigger = {}

        for sensor_cfg in config.sensors:
            try:
                adapter = make_adapter(sensor_cfg.protocol)
            except UnknownProtocolError as exc:
                raise ConfigValidationError(str(exc)) from exc
            connect_cfg = adapter_connect_config(sensor_cfg, config)
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
                # Skipped, and said out loud. The staleness watch cannot cover
                # this: it runs from the poll intervals of sensors that
                # connected, so one that never did is not late, it is absent.
                self._unconnected_sensors.add(str(sensor_cfg.id))
                # The registry must not wait out its loss bound for a fact the
                # runtime already holds. Until a pair is told, it is an active
                # pair with no record that its measurement is unavailable.
                told_a_pair = False
                if self._safety_registry is not None:
                    told_a_pair = await self._safety_registry.note_sensor_unavailable(
                        str(sensor_cfg.id), "could not be connected"
                    )
                if not told_a_pair:
                    # A pair notice already names the sensor, its zone and its
                    # profile, so sending this as well would be two messages
                    # for one event, and one per pair where several depend on
                    # the sensor. Decided on whether a pair was actually told,
                    # not on whether a registry exists: candidate, pending and
                    # refused profiles produce no pair notice at all.
                    await self._emit_unconnected_sensor_warning(
                        sensor_id=str(sensor_cfg.id)
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
                    config.device.location,
                    config.device.site_type,
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

        telemetry_export_task = self._start_telemetry_export_if_enabled(
            config,
            event_bus,
        )
        if telemetry_export_task is not None:
            self._background_tasks.append(telemetry_export_task)

        _warn_gateway_security_posture(config)
        _warn_sms_webhook_security_posture(config)

        gateway_export_task = self._start_gateway_export_responder_if_enabled(config)
        if gateway_export_task is not None:
            self._background_tasks.append(gateway_export_task)

        hb_subscriber = (
            _build_gateway_heartbeat_subscriber(config, posture_tracker)
            if posture_tracker is not None
            else None
        )
        if hb_subscriber is not None:
            self._background_tasks.append(
                asyncio.create_task(
                    hb_subscriber.serve_until(self._shutdown_event),
                    name="gateway-heartbeat",
                )
            )

        evidence_inbound_subscriber = _build_evidence_inbound_subscriber(
            config, evidence_attestor
        )
        self._evidence_inbound_subscriber = evidence_inbound_subscriber
        if evidence_inbound_subscriber is not None:
            self._background_tasks.append(
                asyncio.create_task(
                    evidence_inbound_subscriber.serve_until(self._shutdown_event),
                    name="evidence-inbound",
                )
            )

        evidence_outbound_publisher = _build_evidence_outbound_publisher(
            config, evidence_attestor
        )
        self._evidence_outbound_publisher = evidence_outbound_publisher
        if evidence_outbound_publisher is not None and evidence_attestor is not None:
            evidence_attestor.set_sealed_listener(evidence_outbound_publisher.nudge)
            self._background_tasks.append(
                asyncio.create_task(
                    evidence_outbound_publisher.serve_until(self._shutdown_event),
                    name="evidence-outbound",
                )
            )
            self._background_tasks.append(
                asyncio.create_task(
                    self._evidence_checkpoint_loop(evidence_attestor),
                    name="evidence-checkpoint",
                )
            )

        (
            self._firmware_liveness_supervisor,
            firmware_telemetry_subscriber,
            firmware_command_pair,
            firmware_liveness_scheduler,
        ) = _build_firmware_liveness_stack(
            config,
            event_bus,
            self._state_store,
            self._deduplicator,
            # Late-bound on purpose: the subscriber is built before the
            # evidence attestor decides whether a reconciler exists at all,
            # so the callback reads it when a reconnect actually happens.
            self._nudge_firmware_confirmations,
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
            try:
                await publisher.connect()
            except Exception:
                logger.exception("[runtime] failed to connect firmware command MQTT")
                raise
            self._firmware_command_publisher = publisher
            self._firmware_command_service = service
            logger.info("[runtime] MQTT firmware command egress enabled")

            # Started only after connect(): the first tick would otherwise
            # sign a message, spend a sequence number, and fail to publish
            # it. Sequence gaps are legal, but burning them on a race is
            # not a cost to accept when ordering is free.
            if firmware_liveness_scheduler is not None:
                self._firmware_liveness_scheduler = firmware_liveness_scheduler
                self._background_tasks.append(
                    asyncio.create_task(
                        firmware_liveness_scheduler.serve_until(self._shutdown_event),
                        name="firmware-liveness",
                    )
                )

        await self._start_firmware_mqtt_operator_if_enabled(config)

        node_heartbeat = _build_runtime_node_heartbeat_publisher(
            config,
            self._build_health_snapshot,
        )
        if node_heartbeat is not None:
            self._runtime_node_heartbeat_publisher = node_heartbeat
            self._background_tasks.append(
                asyncio.create_task(
                    node_heartbeat.serve_until(self._shutdown_event),
                    name="runtime-node-heartbeat",
                )
            )

        await self._start_health_socket_if_enabled(config)

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

        if status_indicator is not None:
            status_indicator.set_runtime_state(RuntimeHealthState.NORMAL)

        await self._send_setup_success_notifications(config, alert_sender)

        # Block here until stop() sets the shutdown event
        if self._safety_registry is not None:
            self._background_tasks.append(
                asyncio.create_task(
                    self._safety_registry.run_retry_loop(self._shutdown_event)
                )
            )
        await self._shutdown_event.wait()

    async def stop(self) -> None:
        """Graceful shutdown. Called by SIGTERM/SIGINT signal handlers."""
        if self._shutdown_event.is_set():
            return
        logger.info("[runtime] shutdown initiated")
        # Retain a shutdown checkpoint and hand the courier what it can take
        # while the routes are still up: setting the shutdown event is what
        # tears them down, so this has to come first or the flush finds a
        # closed route and the checkpoint waits for the next start.
        await self._issue_shutdown_checkpoint()
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

        # 2b. Stop gateway export responder.
        if self._gateway_export_server is not None:
            try:
                await self._gateway_export_server.close()
            except Exception:
                logger.exception("[shutdown] error closing gateway export responder")
            self._gateway_export_server = None

        # 2c. Stop runtime node heartbeat publisher.
        if self._runtime_node_heartbeat_publisher is not None:
            try:
                await self._runtime_node_heartbeat_publisher.close()
            except Exception:
                logger.exception("[shutdown] error closing runtime node heartbeat")
            self._runtime_node_heartbeat_publisher = None

        # 2d. Stop firmware command egress.
        if self._firmware_command_publisher is not None:
            try:
                await self._firmware_command_publisher.close()
            except Exception:
                logger.exception("[shutdown] error closing firmware command publisher")
            self._firmware_command_publisher = None
            self._firmware_command_service = None
            self._firmware_liveness_scheduler = None

        # 2e. Stop local health socket service.
        if self._health_socket_server is not None:
            try:
                await self._health_socket_server.close()
            except Exception:
                logger.exception("[shutdown] error closing health socket")
            self._health_socket_server = None
            self._health_socket_path = ""

        # 2f. Stop the authenticated firmware MQTT operator service.
        if self._firmware_mqtt_operator_server is not None:
            try:
                await self._firmware_mqtt_operator_server.close()
            except Exception:
                logger.exception(
                    "[shutdown] error closing firmware MQTT operator socket"
                )
            self._firmware_mqtt_operator_server = None
            self._firmware_mqtt_operator_socket_path = ""

        # 2g. Stop the evidence executor; the shutdown checkpoint is already
        #     retained (1b).
        if self._evidence_attestor is not None:
            self._evidence_attestor.set_sealed_listener(None)
            try:
                self._evidence_attestor.close()
            except Exception:
                logger.exception("[shutdown] error closing evidence attestor")
            self._evidence_attestor = None

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
            lockout_result = await self._remote_command_lockout_precheck(command)
            if lockout_result is not None:
                result = lockout_result
            else:
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

    async def _remote_command_lockout_precheck(
        self, command: RemoteCommand
    ) -> RemoteCommandExecutionResult | None:
        """Return a blocking result when sender lockout enforcement applies."""
        cfg = self._remote_command_lockout_config
        enforcement_enabled = is_truthy(cfg.get("enforcement_enabled", False))
        try:
            lockout_state = await self._evaluate_lockout_for_sender(
                channel=command.channel,
                from_number=command.from_number,
            )
        except Exception:
            logger.exception(
                "[runtime] remote command lockout evaluation failed command_id=%s channel=%s sender=%r",
                command.command_id,
                command.channel,
                command.from_number,
            )
            if enforcement_enabled:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="remote command lockout evaluation unavailable",
                    executed=False,
                )
            return None

        self._remote_command_lockout_states[
            remote_command_sender_key(
                channel=command.channel,
                from_number=command.from_number,
            )
        ] = lockout_state.as_dict()
        if lockout_state.locked_out:
            logger.warning(
                "[runtime] remote command blocked by lockout command_id=%s channel=%s sender=%r reason=%s",
                command.command_id,
                command.channel,
                command.from_number,
                lockout_state.reason,
            )
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail=f"remote command sender locked out: {lockout_state.reason}",
                executed=False,
            )
        return None

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

            if command_requests_dry_run(command):
                return command_result(
                    command,
                    status=STATUS_DRY_RUN,
                    detail="would refresh remote DevicePolicy using the existing verified fetch path",
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
            reference_error = _validate_remote_policy_reference_args(
                reference_url,
                expected_sha256,
            )
            if reference_error is not None:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail=reference_error,
                    executed=False,
                )

            if command_requests_dry_run(command):
                return command_result(
                    command,
                    status=STATUS_DRY_RUN,
                    detail="would fetch, hash-check, signature-verify, and apply referenced DevicePolicy",
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

        if command_requests_dry_run(command):
            return command_result(
                command,
                status=STATUS_DRY_RUN,
                detail=f"would update {threshold_key} {old_value} -> {new_value} in skill {skill_name!r}",
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
            enforcement_enabled=is_truthy(cfg.get("enforcement_enabled", False)),
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

        host = str(webhook_cfg.get("host", "127.0.0.1"))
        port = int(webhook_cfg.get("port", 8080))
        path = str(webhook_cfg.get("path", "/webhooks/sms/africastalking"))
        signature_cfg = webhook_cfg.get("signature") or {}
        signature_mode = (
            str(signature_cfg.get("mode", "token_only") or "token_only").lower()
            if isinstance(signature_cfg, dict)
            else "token_only"
        )
        token = str(webhook_cfg.get("token", "") or "").strip()
        if signature_mode != "hmac_required" and not token:
            logger.warning(
                "[runtime] SMS webhook enabled but incoming_webhook.token is empty; "
                "refusing to start unauthenticated public ingress"
            )
            return None

        signature_verifier = self._build_sms_webhook_signature_verifier(webhook_cfg)
        if signature_mode != "token_only" and signature_verifier is None:
            logger.warning(
                "[runtime] SMS webhook signature mode=%s is configured but verifier "
                "could not be built; refusing to start public ingress",
                signature_mode,
            )
            return None

        self._sms_webhook_server = SMSWebhookServer(
            sms_action=self._sms_action,
            host=host,
            port=port,
            path=path,
            token=token,
            signature_verifier=signature_verifier,
            state_store=self._state_store,
            allowed_source_cidrs=list(webhook_cfg.get("allowed_source_cidrs") or []),
        )
        return asyncio.create_task(
            self._sms_webhook_server.serve_until(self._shutdown_event),
            name="sms-webhook",
        )

    def _build_sms_webhook_signature_verifier(
        self, webhook_cfg: dict[str, Any]
    ) -> WebhookSignatureVerifier | None:
        signature_cfg = webhook_cfg.get("signature") or {}
        if not isinstance(signature_cfg, dict):
            return None
        mode = str(signature_cfg.get("mode", "token_only") or "token_only").lower()
        if mode == "token_only":
            return None
        try:
            config = WebhookSignatureConfig(
                mode=mode,
                shared_secret=str(signature_cfg.get("shared_secret", "") or ""),
                previous_shared_secret=str(
                    signature_cfg.get("previous_shared_secret", "") or ""
                ),
                signature_header=str(
                    signature_cfg.get("signature_header", "x-ori-webhook-signature")
                    or "x-ori-webhook-signature"
                ),
                timestamp_header=str(
                    signature_cfg.get("timestamp_header", "x-ori-webhook-timestamp")
                    or "x-ori-webhook-timestamp"
                ),
                nonce_header=str(
                    signature_cfg.get("nonce_header", "x-ori-webhook-nonce")
                    or "x-ori-webhook-nonce"
                ),
                max_skew_ms=int(signature_cfg.get("max_skew_seconds", 300)) * 1000,
                replay_ttl_ms=int(signature_cfg.get("replay_ttl_seconds", 300)) * 1000,
                require_nonce=is_truthy(signature_cfg.get("require_nonce", True)),
            )
            return WebhookSignatureVerifier(config)
        except Exception:
            logger.exception(
                "[runtime] invalid SMS webhook signature configuration; refusing to "
                "start signed webhook ingress"
            )
            return None

    def _start_gateway_export_responder_if_enabled(
        self, config: Config
    ) -> asyncio.Task[None] | None:
        if not bool(config.gateway.enabled):
            return None
        if self._state_store is None:
            logger.warning(
                "[gateway-export] state store unavailable; skipping MQTT export responder"
            )
            return None
        try:
            responder = GatewayExportResponder(
                device_id=config.device.id,
                state_store=self._state_store,
                health_snapshot_provider=self._build_health_snapshot,
                message_auth=_build_gateway_message_auth(config),
                message_encryptor=_build_gateway_message_encryptor(config),
            )
            server = MqttGatewayExportServer(
                broker_url=config.gateway.broker_url,
                responder=responder,
                tls_config=getattr(config.gateway, "tls", {}),
            )
        except Exception:
            logger.exception("[gateway-export] invalid responder configuration")
            return None
        self._gateway_export_server = server
        return asyncio.create_task(
            server.serve_until(self._shutdown_event),
            name="gateway-export-responder",
        )

    def _start_telemetry_export_if_enabled(
        self,
        config: Config,
        event_bus: EventBus,
    ) -> asyncio.Task[None] | None:
        export_cfg = config.telemetry_export
        if not export_cfg.enabled:
            return None
        exporter = HttpTelemetryExporter(
            device_id=config.device.id,
            config=export_cfg,
        )
        self._telemetry_exporter = exporter
        event_bus.subscribe("*", exporter.handle_event)
        return asyncio.create_task(
            exporter.serve_until(self._shutdown_event),
            name="telemetry-export",
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

    async def _start_firmware_mqtt_operator_if_enabled(
        self,
        config: Config,
    ) -> None:
        cfg = (
            config.firmware_mqtt_provisioning
            if isinstance(config.firmware_mqtt_provisioning, dict)
            else {}
        )
        if not bool(cfg.get("enabled", False)):
            return
        if self._state_store is None:
            raise RuntimeError(
                "firmware MQTT operator service requires the runtime state store"
            )

        provisioner_key = load_raw_ed25519_seed_from_env(
            str(cfg["provisioner_key_env"]),
            label="firmware MQTT provisioner key",
        )
        command_cfg = (
            config.gateway.firmware_commands
            if isinstance(getattr(config.gateway, "firmware_commands", {}), dict)
            else {}
        )
        if bool(command_cfg.get("enabled", False)):
            command_provisioner_key = load_raw_ed25519_seed_from_env(
                str(command_cfg.get("provisioner_key_env", "")),
                label="firmware command provisioner key",
            )
            if not hmac.compare_digest(provisioner_key, command_provisioner_key):
                raise RuntimeError(
                    "firmware MQTT and command provisioning-authority keys differ"
                )
        (
            ca_certificate_pem,
            ca_private_key_pem,
            broker_ca_certificate_pem,
        ) = await asyncio.gather(
            asyncio.to_thread(_read_public_pem_file, str(cfg["client_ca_certfile"])),
            asyncio.to_thread(
                _read_private_key_file,
                str(cfg["client_ca_keyfile"]),
            ),
            asyncio.to_thread(_read_public_pem_file, str(cfg["broker_ca_certfile"])),
        )
        password_env = str(cfg.get("client_ca_key_password_env", "")).strip()
        ca_password: bytes | None = None
        if password_env:
            password = os.environ.get(password_env)
            if password is None or not password:
                raise RuntimeError(
                    "firmware MQTT client CA key password environment variable is unset"
                )
            ca_password = password.encode("utf-8")

        service = FirmwareMqttProvisioningService(
            store=self._state_store,
            provisioner_key_bytes=provisioner_key,
        )
        certificate_authority = FirmwareMqttCertificateAuthority(
            ca_certificate_pem=ca_certificate_pem,
            ca_private_key_pem=ca_private_key_pem,
            ca_private_key_password=ca_password,
            validity_days=int(cfg["certificate_validity_days"]),
        )
        workflow = FirmwareMqttProvisioningWorkflow(
            service=service,
            certificate_authority=certificate_authority,
            broker_ca_certificate_pem=broker_ca_certificate_pem,
        )
        controller = FirmwareMqttOperatorController(
            workflow=workflow,
            store=self._state_store,
            broker_uri=str(cfg["broker_uri"]),
            time_server=str(cfg["time_server"]),
        )
        server = FirmwareMqttOperatorServer(
            socket_path=str(cfg["socket_path"]),
            mode=int(cfg["socket_mode"]),
            allowed_uids={int(uid) for uid in cfg.get("allowed_uids", [])},
            controller=controller,
        )
        try:
            bound_path = await server.start()
        except Exception:
            await server.close()
            raise
        self._firmware_mqtt_operator_server = server
        self._firmware_mqtt_operator_socket_path = bound_path
        logger.info("[runtime] firmware MQTT operator service ready at %s", bound_path)

    def _configure_alert_outbox(self, alert_outbox_cfg: dict[str, Any]) -> None:
        cfg = alert_outbox_cfg if isinstance(alert_outbox_cfg, dict) else {}
        self._alert_outbox_retry_interval_s = (
            float(cfg.get("retry_interval_minutes", 0.5)) * 60.0
        )
        self._alert_outbox_batch_size = int(cfg.get("batch_size", 50))
        self._alert_outbox_max_non_tier_d_attempts = int(
            cfg.get("max_non_tier_d_attempts", 10)
        )
        self._alert_outbox_tier_d_critical_threshold = int(
            cfg.get("tier_d_critical_warning_threshold", 3)
        )

    async def _evidence_checkpoint_loop(
        self, attestor: FirstPartyEvidenceAttestor
    ) -> None:
        """Retain a signed checkpoint every interval. The cadence is release-owned."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(), timeout=DEFAULT_CHECKPOINT_INTERVAL_S
                )
                return
            except asyncio.TimeoutError:
                pass
            await attestor.issue_checkpoint()

    async def _issue_shutdown_checkpoint(self) -> None:
        attestor = self._evidence_attestor
        if attestor is None or not attestor.available:
            return
        await attestor.issue_checkpoint()
        publisher = self._evidence_outbound_publisher
        if publisher is not None:
            await publisher.flush(EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S)

    async def _reconcile_pending_attestations(self) -> None:
        """Repair evidence gaps left by crashes or signing outages.

        Option B append-after-log (DECISIONS.md 2026-07-10): rows stuck in
        ``pending``/``failed`` are re-signed with their original timestamps
        (the chain records write time separately, so late signing is
        transparent) and marked ``reconciled``. Rows that still cannot be
        signed stay ``failed`` and remain visible as gaps — never fabricated.
        """
        if self._evidence_attestor is None or self._state_store is None:
            return
        if not hasattr(self._state_store, "get_actions_needing_attestation"):
            return
        try:
            rows = await self._state_store.get_actions_needing_attestation()
        except Exception:
            logger.warning("[evidence] reconciliation scan failed")
            return
        if not rows:
            return
        repaired = 0
        for row in rows:
            # Cross-store confirmation gate: firmware-sourced evidence is
            # accepted only once the source device's active epoch is
            # confirmed in the evidence store. The coordinator reconciles the
            # two stores and returns the stored status; anything short of
            # confirmed leaves the row pending (fail closed) rather than
            # signing under authority the evidence store cannot back. The
            # local approved flag is deliberately NOT the gate here.
            if not await self._firmware_source_confirmed(row):
                continue
            # reconciled=True stamps the signed payload as late evidence —
            # a verifier must never mistake it for emission-time signing.
            seq = await self._evidence_attestor.attest_action(
                dict(row), reconciled=True
            )
            status = "reconciled" if seq is not None else "failed"
            try:
                await self._state_store.set_action_attestation(
                    int(row["id"]), status=status, attestation_seq=seq
                )
            except Exception:
                logger.warning(
                    "[evidence] failed to record reconciliation for action id=%s",
                    row.get("id"),
                )
                continue
            if seq is not None:
                repaired += 1
        remaining = len(rows) - repaired
        logger.warning(
            "[evidence] startup reconciliation: %d repaired, %d still unsigned",
            repaired,
            remaining,
        )

    def _nudge_firmware_confirmations(self) -> None:
        """Reconcile outstanding obligations now, because a link came back.

        A restored transport is the most likely moment for a pending
        confirmation to resolve, so waiting out the remaining backoff would be
        the wrong response to the one event suggesting a retry will work.
        """
        reconciler = self._firmware_confirmation_reconciler
        if reconciler is not None:
            reconciler.nudge()

    async def _drain_pending_firmware_confirmations(self) -> None:
        """Reconcile every outstanding confirmation obligation once, now.

        Approval records a durable confirmation_pending obligation but cannot
        itself reach the evidence store (the provisioner is offline). At the
        runtime's earliest opportunity, drain every pending obligation through
        the coordinator, so a normally-approved device -- one with no firmware
        action waiting -- still gets its epoch confirmed and can publish
        approvals and receive commands.

        Recurring retries are the reconciler's `serve_until`, started as a
        background task. This drives the same worker once, so startup does not
        wait out an interval before doing what it can immediately.
        """
        reconciler = self._firmware_confirmation_reconciler
        if reconciler is None:
            # The coordinator is what decides whether draining is possible;
            # the reconciler only schedules around it. Building a transient
            # one here keeps a caller that has a coordinator from getting a
            # silent no-op because scheduling was not set up.
            coordinator = self._firmware_confirmation_coordinator
            if coordinator is None or self._state_store is None:
                return
            reconciler = FirmwareConfirmationReconciler(
                store=self._state_store, coordinator=coordinator
            )
        confirmed, seen = await reconciler.reconcile_once()
        if seen:
            logger.info(
                "[confirmation] startup drain: %d of %d devices confirmed",
                confirmed,
                seen,
            )

    async def _firmware_source_confirmed(self, row: dict) -> bool:
        """Whether a firmware-sourced action may be signed yet.

        A row with no firmware source device is not gated -- there is no
        cross-store anchor to confirm. For a firmware-sourced row, the
        coordinator reconciles the runtime and evidence stores and returns
        the source device's stored confirmation status; only ``confirmed``
        permits signing. A firmware-sourced row with no coordinator
        available fails closed.
        """
        source_device_id = str(row.get("input_firmware_device_id", "") or "").strip()
        if not source_device_id:
            return True
        coordinator = self._firmware_confirmation_coordinator
        if coordinator is None:
            logger.warning(
                "[confirmation] no coordinator available; leaving firmware "
                "evidence for %s pending",
                source_device_id,
            )
            return False
        try:
            status = await coordinator.confirm(source_device_id)
        except Exception:
            logger.warning(
                "[confirmation] reconciling %s failed; leaving evidence pending",
                source_device_id,
            )
            return False
        return status == _FIRMWARE_CONFIRMED

    def _binding_seq_in_force(self) -> int | None:
        state = self._commissioning_state
        if state is None or state.in_force is None:
            return None
        return state.in_force.binding_seq

    def _commissioning_health(self) -> dict[str, Any]:
        state = self._commissioning_state
        if state is None:
            health: dict[str, Any] = {
                "binding_seq": 0,
                "binding_hash": None,
                "anchors_configured": False,
                "zones": [],
                "last_verdict": None,
                "actuation_licensed": False,
            }
        else:
            health = state.health()
        actuator = self._commissioned_actuator
        health["actuator"] = actuator.health() if actuator is not None else None
        return health

    async def _load_commissioning(
        self, config: Config, anchors: CommissioningAnchors
    ) -> None:
        """Load the binding in force and decide what startup may claim.

        The profile set ships with the release and is refused in every posture
        when it cannot load. Declared actuating hardware with no accepted
        binding refuses a hardened start and degrades a development one; it
        never licenses actuation through the commissioned seam either way.
        """
        assert self._state_store is not None
        try:
            profiles = load_shipped_profile_set()
        except ProfileSetError as exc:
            logger.error("[commissioning] %s — aborting", exc)
            raise ConfigValidationError(str(exc)) from exc
        hardened = requires_production_posture(
            device=config.device, security=config.security
        )
        relay_pin = config.actions.relay.get("gpio_pin")
        inventory = DeclaredInventory.from_config(
            [str(sensor.id) for sensor in config.sensors],
            int(relay_pin) if relay_pin is not None else None,
        )
        state = await load_commissioning_state(
            data_path=Path(self._config_path).resolve().parent,
            device_id=str(config.device.id),
            anchors=anchors,
            provisioning_anchor=_provisioning_anchor_bytes(config),
            inventory=inventory,
            posture="production" if hardened else "development",
            profiles=profiles,
            store=self._state_store,
        )
        self._commissioning_state = state
        if inventory.actuators and not state.actuation_licensed:
            if state.provisional is not None:
                detail = (
                    f"binding {state.provisional.binding_seq} is provisional: "
                    "a proof leg is unproven"
                )
            elif state.last_verdict is not None:
                detail = (
                    f"binding verdict {state.last_verdict.stage}:"
                    f"{state.last_verdict.reason}"
                )
            else:
                detail = "no binding presented"
            if hardened:
                logger.error(
                    "[commissioning] declared actuating hardware has no binding in "
                    "force (%s) — aborting under hardened posture",
                    detail,
                )
                raise ConfigValidationError(
                    "commissioning: declared actuating hardware has no binding in "
                    f"force ({detail}); a hardened runtime does not start "
                    "unprotected, and commissioning precedes hardening"
                )
            if "binding_missing" not in state.problems:
                state.problems.append("binding_missing")
            logger.warning(
                "[commissioning] declared actuating hardware has no binding in force "
                "(%s); starting degraded with no protection claim, no actuation "
                "through the commissioned seam, and no coil command",
                detail,
            )
        elif state.in_force is not None:
            logger.info(
                "[commissioning] binding %d in force: %d zone(s), actuation %s",
                state.in_force.binding_seq,
                len(state.in_force.zones),
                "licensed" if state.actuation_licensed else "withheld",
            )

    async def _evidence_health(self) -> dict[str, Any]:
        attestor = self._evidence_attestor
        enabled = bool(
            self._config is not None
            and getattr(self._config, "evidence", None) is not None
            and self._config.evidence.enabled
        )
        health: dict[str, Any] = {
            "enabled": enabled,
            "available": bool(attestor is not None and attestor.available),
            # This device's own anchor, which is its own property to report.
            "public_key_hex": attestor.public_key_hex if attestor else "",
            # `artifact_version` is deliberately absent: ori-specs
            # runtime-health/v2 removes it. The private component's version is
            # implementation metadata an operator has no part in, and
            # `available` with `protocol_version` already answer whether this
            # device can sign and against which public contract.
            #
            # It was briefly removed during the disclosure audit and restored,
            # because v1 still required it and a published contract is not a
            # runtime's to change unilaterally. v2 is what licenses this.
            "protocol_version": (
                EVIDENCE_SCHEMA_VERSION
                if attestor is not None and attestor.available
                else ""
            ),
            # Vocabulary the device will emit for new Tier C/D attestations.
            # Only meaningful while signing is available; '' otherwise, so a
            # mixed-fleet rollout can be confirmed per device before the
            # first Tier C/D action fires.
            "action_event_type": (
                attestor.action_event_type
                if attestor is not None and attestor.available
                else ""
            ),
            "chain_head_hash": None,
            "pending_export_count": None,
            # Whether inbound authority artifacts can currently arrive. A route
            # that is down stalls delivery without stalling anything else, so
            # nothing on the device would otherwise show it.
            "inbound_route_connected": (
                self._evidence_inbound_subscriber.connected
                if self._evidence_inbound_subscriber is not None
                else False
            ),
            "last_attested_action_id": None,
            "attestation_gap_count": 0,
            "status_counts": {},
            # Authority artifacts ingest refused, retained by the ledger so a
            # refused receipt is distinguishable from one that never arrived.
            "ingest_refusal_count": None,
            "last_ingest_refusal": None,
            # Why evidence trust is not established, from a closed vocabulary;
            # empty when it is. Signing can be available while trust is not.
            "posture_problems": list(getattr(self, "_evidence_posture_problems", ())),
        }
        if attestor is not None and attestor.available:
            health["chain_head_hash"] = await attestor.chain_head_hash()
            health["pending_export_count"] = await attestor.pending_export_count()
            refusals = await attestor.ingest_refusal_summary()
            if refusals is not None:
                health["ingest_refusal_count"] = refusals["count"]
                health["last_ingest_refusal"] = refusals["last"]
        if (
            enabled
            and self._state_store is not None
            and hasattr(self._state_store, "get_attestation_summary")
        ):
            try:
                summary = await self._state_store.get_attestation_summary()
                health["last_attested_action_id"] = summary["last_attested_action_id"]
                health["attestation_gap_count"] = summary["attestation_gap_count"]
                health["status_counts"] = summary["status_counts"]
            except Exception:
                logger.warning("[evidence] attestation summary read failed")
        return health

    def _telemetry_export_health(self) -> dict[str, Any]:
        """Report export state. It never contributes to `status` or `critical`.

        Export suspension is driven by product-side account state. Letting it
        degrade the device's health verdict would put billing state on a path
        that reaches protection decisions, which is the boundary this must not
        cross.
        """
        exporter = self._telemetry_exporter
        if exporter is None:
            return {"enabled": False}
        snapshot = exporter.status_snapshot()
        snapshot["enabled"] = True
        return snapshot

    async def _build_health_snapshot(self) -> dict[str, Any]:
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
                    "measurement_degraded": sensor_id in self._measurement_degraded,
                    "consecutive_refusals": self._measurement_refusals.get(
                        sensor_id, 0
                    ),
                    "last_seen_ms": int(last_seen_ms)
                    if last_seen_ms is not None
                    else None,
                    "stale": bool(stale),
                }
            )

        safety_state: dict[str, Any] | None = (
            self._safety_registry.health_snapshot()
            if self._safety_registry is not None
            else None
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

        alert_outbox = await self._build_alert_outbox_health(now)
        firmware_liveness_health = self._firmware_liveness_health()

        snapshot: dict[str, Any] = {
            "device_id": self._device_id,
            "uptime_s": uptime_s,
            "health_socket_path": self._health_socket_path,
            "firmware_mqtt_operator": {
                "available": self._firmware_mqtt_operator_server is not None,
                "socket_path": self._firmware_mqtt_operator_socket_path,
                "contract": "ori.runtime.firmware-mqtt-operator",
                "schema_version": 1,
            },
            "capability_posture": capability_posture,
            "gateway_broker_posture": self._gateway_broker_posture_health(),
            "state_store_encryption": self._state_store_encryption_health(),
            "sensors": sensors,
            "safety": safety_state,
            "last_alert_timestamps": {
                "by_channel": dict(self._last_alert_timestamps_by_channel),
                "by_trigger": dict(self._last_alert_timestamps_by_trigger),
            },
            "alert_outbox": alert_outbox,
            "device_policy": device_policy_state,
            "remote_command_lockout": {
                "enforcement_enabled": is_truthy(
                    self._remote_command_lockout_config.get(
                        "enforcement_enabled", False
                    )
                ),
                "risk_window_ms": int(
                    self._remote_command_lockout_config["risk_window_ms"]
                ),
                "stale_after_ms": lockout_stale_after_ms,
                "incident_sender_limit": int(
                    self._remote_command_lockout_config["incident_sender_limit"]
                ),
                "senders": remote_command_lockout_senders,
            },
            "evidence": await self._evidence_health(),
            "commissioning": self._commissioning_health(),
            "firmware_liveness": firmware_liveness_health,
            "telemetry_export": self._telemetry_export_health(),
        }
        # `runtime-health/v2` types this as an array and reads absence as
        # unknown, so a device with no registry omits the key entirely rather
        # than carrying a null a consumer would iterate.
        safety_zones: list[dict[str, Any]] = []
        if self._safety_registry is not None:
            safety_zones = self._safety_registry.safety_zones()
            snapshot["safety_zones"] = safety_zones
        if firmware_liveness_health["degraded"]:
            # A stopped or stalled liveness loop puts timely publication at
            # risk for one or more supervised devices while the rest of the
            # runtime looks healthy. Contributed rather than assigned, so this
            # never clears a critical condition another subsystem has raised.
            snapshot["critical"] = True
            snapshot["status"] = "degraded"
        if self._unconnected_sensors:
            # A configured sensor that never connected is not a healthy
            # runtime: something it was told to measure is not being measured.
            # Degraded rather than critical, and it names no token in
            # `degradation_reasons` because that vocabulary is closed and
            # carries none for this (ori-platform/ori-specs#171); the sensor
            # itself reports `connected: false` in the meantime.
            snapshot["status"] = "degraded"
        if getattr(self, "_evidence_posture_problems", ()):
            # Evidence trust not established is degraded, not critical: the
            # safety path is unaffected, and what is at risk is the record.
            snapshot["status"] = "degraded"
        commissioning = getattr(self, "_commissioning_state", None)
        if commissioning is not None and commissioning.problems:
            # Declared actuating hardware with no accepted binding is a device
            # that cannot claim protection; it must not read as healthy.
            snapshot["status"] = "degraded"
        if any(
            zone.get("activation") == "active"
            and zone.get("protection_claim") == "unprotected"
            for zone in safety_zones
        ):
            # An active pair is one the device has undertaken to protect, and
            # `unprotected` says it is not doing so. `runtime-health/v2` does
            # not require this, so it is a decision rather than a conformance
            # gap: a fleet view aggregating `status` would otherwise show
            # nothing wrong while a zone the device claims to protect is not
            # being protected. Commissioning problems already degrade for the
            # same class of fact, one step earlier.
            #
            # Only `active` pairs count. A pair held for ratification or
            # refused reports `unprotected` too, and correctly — the device
            # never undertook to protect it, and degrading on those would make
            # every device carrying a candidate profile permanently degraded.
            #
            # Degraded, never critical, and it changes nothing about Tier D:
            # this is a report, and the protection path neither reads it nor
            # is gated by it.
            #
            # The consequence to expect: `_backend_drivable` is a constant
            # `False` until the non-actuating drivability member on #482, so
            # the first ratified profile makes every device carrying one
            # permanently degraded on a fully commissioned zone with nothing
            # wrong. That is the honest report — the producer cannot establish
            # protection — but it is a fleet-wide change the day ratification
            # lands, and `degradation_reasons` carries no token for it
            # (ori-platform/ori-specs#171), so the reason will not be nameable
            # until that closes.
            snapshot["status"] = "degraded"

        # Named reasons for the site view. The rich diagnostics above stay
        # local: fleet counts reveal deployment topology and per-device
        # identity is a disclosure this contract does not make. Only closed,
        # non-sensitive tokens cross the boundary.
        snapshot["degradation_reasons"] = _degradation_reasons(
            firmware_liveness_degraded=bool(firmware_liveness_health["degraded"]),
        )
        return snapshot

    def _firmware_liveness_health(self) -> dict[str, Any]:
        scheduler = self._firmware_liveness_scheduler
        if scheduler is None:
            # Not configured is not degraded: no command egress means this
            # runtime is not the authority for any device, so there is no
            # obligation to be failing.
            return {
                "enabled": False,
                "running": False,
                "degraded": False,
            }
        health = dict(scheduler.health())
        health["enabled"] = True
        return health

    def _gateway_broker_posture_health(self) -> dict[str, Any]:
        if self._config is None:
            return {
                "available": False,
                "gateway_enabled": False,
                "deployment_check": "unknown",
                "anonymous_access": "unknown",
                "acl_policy": "unknown",
                "require_credentials": False,
                "credentials_configured": False,
                "requires_acl_hardening": True,
            }
        broker_posture = self._config.gateway.broker_posture
        broker_url = str(self._config.gateway.broker_url or "").strip()
        parsed = urlparse(broker_url if "://" in broker_url else f"mqtt://{broker_url}")
        credentials_configured = bool(parsed.username and parsed.password)
        hardened = (
            broker_posture.get("deployment_check") == "required"
            and broker_posture.get("anonymous_access") == "disabled"
            and broker_posture.get("acl_policy") == "per_device_required"
            and is_truthy(broker_posture.get("require_credentials", False))
            and credentials_configured
        )
        return {
            "available": True,
            "gateway_enabled": bool(self._config.gateway.enabled),
            "deployment_check": str(broker_posture.get("deployment_check", "warning")),
            "anonymous_access": str(broker_posture.get("anonymous_access", "unknown")),
            "acl_policy": str(broker_posture.get("acl_policy", "unknown")),
            "require_credentials": is_truthy(
                broker_posture.get("require_credentials", False)
            ),
            "credentials_configured": credentials_configured,
            "requires_acl_hardening": bool(self._config.gateway.enabled)
            and not hardened,
        }

    def _state_store_encryption_health(self) -> dict[str, Any]:
        if self._config is None:
            return {
                "available": False,
                "mode": "unknown",
                "satisfied": False,
                "marker_configured": False,
                "path_prefix_configured": False,
            }

        encryption = self._config.state.encryption
        marker_ok = bool(
            encryption.marker_file
            and Path(encryption.marker_file).expanduser().is_file()
        )
        db_path = Path(self._config.database_path).expanduser().resolve(strict=False)
        prefix_ok = any(
            path_is_relative_to(
                db_path,
                Path(prefix).expanduser().resolve(strict=False),
            )
            for prefix in encryption.encrypted_path_prefixes
        )
        return {
            "available": True,
            "mode": encryption.mode,
            "satisfied": bool(encryption.mode == "filesystem_required")
            and (marker_ok or prefix_ok),
            "marker_configured": bool(encryption.marker_file),
            "path_prefix_configured": bool(encryption.encrypted_path_prefixes),
        }

    async def _build_alert_outbox_health(self, now: int) -> dict[str, Any]:
        summary = {
            "backlog_count": 0,
            "oldest_queued_original_ts": None,
            "oldest_queued_age_ms": None,
        }
        if self._state_store is not None:
            try:
                raw_summary = await self._state_store.get_alert_outbox_summary()
                oldest_ts = raw_summary.get("oldest_queued_original_ts")
                summary = {
                    "backlog_count": int(raw_summary.get("backlog_count") or 0),
                    "oldest_queued_original_ts": int(oldest_ts)
                    if oldest_ts is not None
                    else None,
                    "oldest_queued_age_ms": max(0, now - int(oldest_ts))
                    if oldest_ts is not None
                    else None,
                }
            except Exception:
                logger.exception("[runtime] alert outbox health summary failed")

        return {
            **summary,
            "retry_interval_minutes": self._alert_outbox_retry_interval_s / 60.0,
            "max_non_tier_d_attempts": self._alert_outbox_max_non_tier_d_attempts,
            "tier_d_critical_warning_threshold": self._alert_outbox_tier_d_critical_threshold,
            "batch_size": self._alert_outbox_batch_size,
        }

    def _unregister_skill_handlers(self) -> None:
        # Routed through the loader so the subscription budget is credited
        # back. Unsubscribing directly from the bus removes the handlers but
        # leaves the loader believing they are still registered, which made a
        # long-running runtime exhaust its budget through ordinary reloads.
        loader = getattr(self, "_skill_loader", None)
        if loader is not None:
            loader.unregister(self._skill_subscriptions, self._event_bus)
        elif self._event_bus is not None:
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
        device_location: str = "",
        device_site_type: str = "",
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
                # The safety registry consumes every reading synchronously,
                # before deduplication, history, the EventBus, or any skill:
                # a duplicate is irrelevant to skills and still matters to
                # credible-reading freshness and a latched trip.
                if self._safety_registry is not None:
                    for decision in await self._safety_registry.observe_reading(
                        reading.sensor_id,
                        reading.value,
                        reading.unit,
                        reading.quality,
                    ):
                        if decision.tripped:
                            logger.critical(
                                "[safety] TRIP zone=%s profile=%s driver_accepted=%s",
                                decision.pair[0],
                                decision.pair[1],
                                decision.driver_accepted,
                            )
                self._sensor_last_seen_ms[sensor_cfg.id] = now_ms()
                await self._note_measurement_accepted(str(sensor_cfg.id))
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
                event.context["location"] = str(device_location or "")
                event.context["site_type"] = str(device_site_type or "")
                event.context["device_country_code"] = (
                    str(device_country_code or "").strip().upper()
                )
                calibration = getattr(sensor_cfg, "calibration", None)
                if isinstance(calibration, dict) and calibration:
                    event.context["sensor_calibration"] = dict(calibration)
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
                if isinstance(exc, MeasurementRefusedError):
                    await self._note_measurement_refusal(
                        sensor_id=str(sensor_cfg.id),
                        detail=str(exc),
                    )
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

            await self._escalate_persistent_measurement_loss()

            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass

    async def _restore_measurement_state(self) -> None:
        """Rebuild every measurement-degradation fact from the state store.

        Restored rather than cleared. The notice fires on the transition into
        degradation, so an in-memory set emptied by every start would make a
        crash-looping runtime re-send the same warning after each restart, and
        a schedule reset by every start would postpone every escalation
        forever on the same device.

        One seam, called at startup and driven directly by the tests that
        prove a restart behaves, so the durable join cannot drift from what
        startup actually does.
        """
        restored = (
            await self._state_store.get_measurement_degradation()
            if self._state_store is not None
            else {}
        )
        schedule = (
            await self._state_store.get_measurement_notice_schedule()
            if self._state_store is not None
            else {}
        )
        self._measurement_degraded = set(restored)
        self._measurement_degraded_since = {
            sensor_id: since for sensor_id, (since, _) in schedule.items()
        }
        self._measurement_notice_stage = {
            sensor_id: stage for sensor_id, (_, stage) in schedule.items()
        }
        # A degradation whose notice never got out is still owed one. Losing
        # that distinction would make the crash that prevented the alert the
        # reason it is never sent.
        self._measurement_unnotified = {
            sensor_id for sensor_id, notified in restored.items() if not notified
        }
        self._measurement_notify_attempts = {}

    async def _escalate_persistent_measurement_loss(self) -> None:
        """Re-notify, and escalate, while a measurement loss persists.

        The first notice fires on the transition and is not repeated, so a
        device that cannot establish a trustworthy measurement said so once
        and then waited indefinitely for a person. This is what keeps saying
        it.

        It restores nothing. A channel that is not being measured is not being
        protected, and telling somebody about it does not change that; the
        notice exists so an operator can act, not so the device can claim to
        have handled it.
        """
        now = now_ms()
        for sensor_id in sorted(self._measurement_degraded):
            since = self._measurement_degraded_since.get(sensor_id)
            if since is None:
                # Degraded with no recorded start. Anchor it here rather than
                # treating it as owed every stage at once.
                self._measurement_degraded_since[sensor_id] = now
                continue
            due = measurement_notice_stage_due(now - since)
            if due <= self._measurement_notice_stage.get(sensor_id, 0):
                continue
            await self._send_measurement_escalation(
                sensor_id=sensor_id,
                stage=due,
                elapsed_ms=now - since,
                first_notice_delivered=sensor_id not in self._measurement_unnotified,
            )

    def _measurement_escalation_recipient(self, stage: int) -> str:
        """Who a given stage is addressed to.

        Stages 0 and 1 are the primary contact; from stage 2 the escalation
        goes to the secondary contact, and to the primary again only where no
        secondary is configured. A device with one contact is not left silent
        because it has nobody to escalate to.
        """
        if stage >= 2 and self._secondary_contact:
            return self._secondary_contact
        return self._operator_contact

    async def _send_measurement_escalation(
        self,
        *,
        sensor_id: str,
        stage: int,
        elapsed_ms: int,
        first_notice_delivered: bool,
    ) -> None:
        """Send one scheduled stage, and record it only if it got out.

        The escalation runs whether or not the notice on the transition ever
        reached anybody. An undelivered first notice is the case where an
        operator knows least, so blocking the schedule on it would silence the
        device precisely when its contact is unreachable — and the initial
        notice's own retries are bounded, so the block would be permanent.
        What changes is the wording: a stage that cannot assume the first
        notice arrived states the fault rather than recalling one.
        """
        recipient = self._measurement_escalation_recipient(stage)
        if self._alert_sender is None or not recipient:
            logger.warning(
                "[sensor] measurement escalation for %s not sent: "
                "no alert sender or no recipient for stage %d",
                sensor_id,
                stage,
            )
            return
        hours = elapsed_ms // (60 * 60 * 1000)
        opening = (
            f"Sensor {sensor_id} has still not produced a valid measurement "
            f"after {hours} hours."
            if first_notice_delivered
            else (
                f"Sensor {sensor_id} has not produced a valid measurement for "
                f"{hours} hours. An earlier notice about it could not be "
                "delivered."
            )
        )
        message = (
            f"{opening} Readings are not being published for it, and any "
            "protection depending on them is not running. Nothing has been "
            "restored. Check the sensor wiring and signal."
        )
        # Structural rather than policy-gated, for the same reason as the
        # notice on the transition, and addressed to the escalation contact.
        delivered = await self._send_or_queue_safety_alert(
            message=message,
            trigger_name=f"measurement_degraded_persists:{sensor_id}",
            alert_sender=self._alert_sender,
            recipient=recipient,
        )
        if not delivered:
            # Left un-recorded so this stage is retried on the next pass, and
            # superseded without ceremony when the next stage falls due. A
            # reminder that could not be sent never cancels the escalation
            # after it.
            return
        # Advanced in memory whether or not the write below lands, so a store
        # that is failing does not turn every pass of the loop into another
        # message. A restart then repeats at most this one stage.
        self._measurement_notice_stage[sensor_id] = stage
        recorded = True
        if self._state_store is not None:
            try:
                # One write, not two, and an upsert rather than an update.
                # Recording only the stage would leave the disk saying a later
                # stage was sent while still saying nobody was notified, so
                # the next start would send the notice for the transition all
                # over again. And the row may not exist at all: the write that
                # records the degradation is allowed to fail transiently, so
                # an escalation can be the first one to land. It carries the
                # in-memory start so a reconstructed row dates the loss to
                # when it happened rather than to when the disk caught up.
                await self._state_store.record_measurement_notice_delivered(
                    sensor_id,
                    stage,
                    degraded_since=self._measurement_degraded_since.get(
                        sensor_id, now_ms()
                    ),
                )
            except Exception:
                recorded = False
                logger.exception(
                    "[sensor] could not persist notice stage %d for %s; "
                    "a restart may repeat this reminder",
                    stage,
                    sensor_id,
                )
        if recorded:
            # Cleared only once the disk agrees. Clearing it on a failed write
            # would leave memory saying the operator has been told and disk
            # saying they have not, and the restart would resolve that
            # disagreement by messaging them again.
            self._measurement_unnotified.discard(sensor_id)
            self._measurement_notify_attempts.pop(sensor_id, None)
        logger.warning(
            "[sensor] measurement loss for %s persists after %d hours; "
            "stage %d notice sent",
            sensor_id,
            hours,
            stage,
        )

    async def _note_measurement_accepted(self, sensor_id: str) -> None:
        """A window that was a measurement. Counts toward clearing degradation."""
        if sensor_id not in self._measurement_degraded:
            self._measurement_refusals.pop(sensor_id, None)
            return
        streak = self._measurement_valid_streak.get(sensor_id, 0) + 1
        self._measurement_valid_streak[sensor_id] = streak
        if streak < MEASUREMENT_WINDOWS_TO_RECOVER:
            return
        # Persisted before the in-memory state is cleared. The other order
        # would let a store failure leave a sensor healthy in memory and
        # degraded on disk, so the next restart resurrects a resolved fault.
        if not await self._clear_measurement_state(sensor_id):
            return
        self._measurement_degraded.discard(sensor_id)
        self._measurement_unnotified.discard(sensor_id)
        self._measurement_notify_attempts.pop(sensor_id, None)
        self._measurement_refusals.pop(sensor_id, None)
        self._measurement_valid_streak.pop(sensor_id, None)
        self._measurement_degraded_since.pop(sensor_id, None)
        self._measurement_notice_stage.pop(sensor_id, None)
        logger.info(
            "[sensor] %s measurement recovered after %d consecutive valid windows",
            sensor_id,
            streak,
        )

    async def _note_measurement_refusal(self, *, sensor_id: str, detail: str) -> None:
        """A window that was not a measurement.

        No reading was published, so nothing downstream saw a value. What the
        operator must not be left with is silence: a sensor that has quietly
        stopped measuring looks identical to one measuring zero.
        """
        # Any refusal breaks a recovery run. Alternating windows are not a
        # measurement path coming back.
        self._measurement_valid_streak.pop(sensor_id, None)
        refusals = self._measurement_refusals.get(sensor_id, 0) + 1
        self._measurement_refusals[sensor_id] = refusals
        if refusals < MEASUREMENT_REFUSALS_BEFORE_DEGRADED:
            return
        if sensor_id in self._measurement_degraded:
            if sensor_id not in self._measurement_unnotified:
                # Already reported. The alert fires on the transition, not per
                # window, so a persistent fault does not become a message flood.
                return
            # Degraded, but the operator was never actually reached — no sender,
            # no contact, or send and durable queueing both failed. Retry on
            # this refusal rather than treating the failure as delivery.
            attempts = self._measurement_notify_attempts.get(sensor_id, 0)
            if attempts >= MEASUREMENT_NOTIFY_MAX_ATTEMPTS:
                return
            self._measurement_notify_attempts[sensor_id] = attempts + 1
            await self._deliver_measurement_warning(
                sensor_id=sensor_id, refusals=refusals
            )
            return
        self._measurement_degraded.add(sensor_id)
        self._measurement_unnotified.add(sensor_id)
        self._measurement_degraded_since.setdefault(sensor_id, now_ms())
        self._measurement_notice_stage[sensor_id] = 0
        # Recorded before the alert is attempted, and without letting a store
        # failure escape the poll loop: this runs inside an `except` clause, so
        # an exception here would not be caught by the handler below it and
        # would end polling for this sensor entirely.
        await self._persist_measurement_state(sensor_id, notified=False)
        logger.warning(
            "[sensor] %s measurement degraded after %d consecutive refused windows: %s",
            sensor_id,
            refusals,
            detail,
        )
        self._measurement_notify_attempts[sensor_id] = 1
        await self._deliver_measurement_warning(sensor_id=sensor_id, refusals=refusals)

    async def _deliver_measurement_warning(
        self, *, sensor_id: str, refusals: int
    ) -> None:
        """Try to reach the operator, and record it only if that succeeded."""
        if not await self._emit_measurement_degraded_warning(
            sensor_id=sensor_id, refusals=refusals
        ):
            return
        # Delivered or durably queued. Only now is the operator owed nothing
        # further, so only now may a restart stay quiet.
        self._measurement_unnotified.discard(sensor_id)
        self._measurement_notify_attempts.pop(sensor_id, None)
        await self._persist_measurement_state(sensor_id, notified=True)

    async def _persist_measurement_state(
        self, sensor_id: str, *, notified: bool
    ) -> None:
        """Record degradation durably. A store failure must not stop polling."""
        if self._state_store is None:
            return
        try:
            await self._state_store.set_measurement_degraded(
                sensor_id, notified=notified
            )
        except Exception:
            logger.exception(
                "[sensor] could not persist measurement degradation for %s; "
                "the alert still fires, but a restart may repeat it",
                sensor_id,
            )

    async def _clear_measurement_state(self, sensor_id: str) -> bool:
        """Record recovery durably. Returns False when it could not be written."""
        if self._state_store is None:
            return True
        try:
            await self._state_store.clear_measurement_degraded(sensor_id)
        except Exception:
            logger.exception(
                "[sensor] could not persist measurement recovery for %s; "
                "leaving it degraded rather than diverging from disk",
                sensor_id,
            )
            return False
        return True

    async def _emit_measurement_degraded_warning(
        self, *, sensor_id: str, refusals: int
    ) -> bool:
        """Send or queue the Tier A notice that a sensor stopped measuring.

        Returns whether the operator is owed nothing further — delivered, or
        durably queued for delivery. A False answer leaves the notification
        pending so a later poll or a restart tries again.
        """
        if self._alert_sender is None:
            logger.warning(
                "[runtime] measurement degraded warning not sent: no alert sender"
            )
            return False
        if not self._operator_contact:
            logger.warning(
                "[runtime] measurement degraded warning not sent: "
                "operator_contact is not configured"
            )
            return False
        message = (
            f"Sensor {sensor_id} has stopped producing valid measurements after "
            f"{refusals} consecutive refused windows. Readings are not being "
            "published for it, and any protection depending on them is not "
            "running. Check the sensor wiring and signal."
        )
        # Structural rather than policy-gated. A notice that a protection is
        # absent must not be suppressed by an entitlement cap: suppressing it
        # leaves an operator believing a measurement is being taken that is
        # not, which is the fact this notice exists to carry.
        return bool(
            await self._send_or_queue_safety_alert(
                message=message,
                trigger_name=f"measurement_degraded:{sensor_id}",
                alert_sender=self._alert_sender,
            )
        )

    async def _emit_unconnected_sensor_warning(self, *, sensor_id: str) -> None:
        """A configured sensor that never connected, as a Tier A notice.

        Health already reports it unconnected, and on a headless device
        nothing carries a log line to an operator. It never aborts startup:
        a runtime that refuses to run has removed the agent, and the sensor
        that failed may not be the one protecting anything.

        Sent through the structural path rather than the ordinary one, so it
        is delivered or durably queued rather than dropped. An entitlement cap
        that suppressed it would leave an operator believing a measurement is
        being taken that is not, which is the fact this notice exists to carry.
        """
        if self._alert_sender is None:
            logger.warning(
                "[runtime] unconnected sensor warning not sent for %s: "
                "no alert sender is configured",
                sensor_id,
            )
            return
        await self._send_or_queue_safety_alert(
            message=(
                f"Sensor {sensor_id} could not be connected at startup and is "
                "not being read. The rest of the runtime is running."
            ),
            trigger_name="sensor_unconnected_warning",
            alert_sender=self._alert_sender,
        )

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
        allow_failover: bool = True,
        skill_name: str = "",
        skill_is_first_party: bool = False,
    ) -> bool | str:
        """Attempt immediate delivery; enqueue on failure.

        True when delivered immediately or queued successfully, False when
        queueing also fails, and `ALERT_SUPPRESSED` when a customer preference
        withheld the notice -- a deliberate non-action, which `action_log` must
        not record as an attempt that failed.
        """
        if not self._policy_permits_alert_class(
            skill_name,
            trigger_name,
            action_tier=action_tier,
            first_party=skill_is_first_party,
        ):
            logger.info(
                "[runtime] %s alert suppressed by customer preference "
                "skill=%s trigger=%s class=%s",
                channel,
                skill_name,
                trigger_name,
                alert_class_for_trigger(
                    skill_name, trigger_name, first_party=skill_is_first_party
                ),
            )
            await self._record_preference_disabled_alert(
                channel=channel,
                alert_class=alert_class_for_trigger(
                    skill_name, trigger_name, first_party=skill_is_first_party
                ),
                trigger_name=trigger_name,
                action_tier=action_tier,
                original_ts=original_ts,
            )
            return ALERT_SUPPRESSED

        if not recipient:
            # Checked after the preference, because a notice the customer
            # switched off was not going to be sent to anyone. Reporting it as
            # a missing recipient would record a configuration fault the
            # deployment does not have.
            logger.warning(
                "[runtime] %s alert skipped: operator_contact not configured", channel
            )
            return False

        if not await self._policy_permits_external_alert(
            channel=channel,
            action_tier=action_tier,
        ):
            logger.info(
                "[runtime] %s alert suppressed by DevicePolicy monthly cap tier=%s trigger=%s",
                channel,
                action_tier,
                trigger_name,
            )
            return False

        # Stamped only once a send is actually attempted. These timestamps are
        # published in the health snapshot, and a customer preference or a cap
        # that stopped the alert would otherwise report activity that never
        # happened.
        alert_ts = now_ms()
        self._last_alert_timestamps_by_channel[channel] = alert_ts
        if trigger_name:
            self._last_alert_timestamps_by_trigger[trigger_name] = alert_ts

        delivered = False
        try:
            if allow_failover:
                delivered = await alert_sender.send(
                    message=message,
                    to_number=recipient,
                    preferred_channel=channel,
                )
            else:
                exact_sender = getattr(alert_sender, "send_exact", None)
                if callable(exact_sender):
                    # `callable()` narrows to a callable returning `object`,
                    # which is not awaitable. The cast names the contract a
                    # duck-typed sender must satisfy; the guard is unchanged,
                    # so a non-callable attribute still falls through to
                    # `send()` rather than being invoked.
                    send_exact = cast("Callable[..., Awaitable[bool]]", exact_sender)
                    delivered = await send_exact(
                        message=message,
                        to_number=recipient,
                        channel=channel,
                    )
                else:
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
            await self._record_policy_counted_alert(channel, action_tier=action_tier)
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
            await self._record_policy_counted_alert(channel, action_tier=action_tier)
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

    async def _send_or_queue_safety_alert(
        self,
        *,
        message: str,
        trigger_name: str,
        alert_sender: AlertFailoverSender,
        recipient: str = "",
    ) -> bool:
        """Mandatory notices: delivery or durable queue, structurally outside
        DevicePolicy — no external-alert gate is consulted and no
        policy-counted counter moves.

        Two callers, admitted by one rule: a notice that a protection is
        absent or failed must not be suppressed by an entitlement cap, because
        suppressing it leaves an operator believing something is being watched
        that is not. The safety registry's sink is one. A configured sensor
        that never connected is the other, and it qualifies for the same
        reason — the runtime cannot measure what it was told to measure. A
        persistent measurement loss is the third, and its escalation is why
        `recipient` exists: from the second stage the notice is addressed to
        the secondary contact, and it must stay on this route to get there.
        An entitlement cap that silenced the escalation would leave exactly
        the operator who has not acted still not knowing.
        Never reachable from skills or ordinary action execution."""
        recipient = recipient or self._operator_contact
        if not recipient:
            logger.warning(
                "[safety] notice not sent: operator_contact is not configured"
            )
            return False
        channel = self._primary_alert_channel
        alert_ts = now_ms()
        self._last_alert_timestamps_by_channel[channel] = alert_ts
        self._last_alert_timestamps_by_trigger[trigger_name] = alert_ts
        delivered = False
        try:
            delivered = await alert_sender.send(
                message=message,
                to_number=recipient,
                preferred_channel=channel,
            )
        except Exception:
            logger.exception(
                "[safety] %s notice send failed; falling back to outbox", channel
            )
        if delivered:
            return True
        if self._state_store is None:
            logger.error(
                "[safety] notice delivery failed and StateStore is unavailable"
            )
            return False
        alert_id = _build_alert_id(
            channel=channel,
            recipient=recipient,
            message=message,
            action_tier="A",
            trigger_name=trigger_name,
            original_ts=alert_ts,
        )
        return await self._state_store.enqueue_alert(
            alert_id=alert_id,
            channel=channel,
            recipient=recipient,
            message=message,
            action_tier="A",
            trigger_name=trigger_name,
            original_ts=alert_ts,
        )

    def _policy_permits_alert_class(
        self,
        skill_name: str,
        trigger_name: str,
        *,
        action_tier: str = "A",
        first_party: bool = False,
    ) -> bool:
        """Whether a customer preference leaves this trigger's notice on.

        Reached only from `_send_or_queue_alert`. Mandatory notices travel
        `_send_or_queue_safety_alert`, which does not call this and must not.
        No policy means no preference, so the notice stands.
        """
        if str(action_tier).upper() == "D":
            return True
        alert_class = alert_class_for_trigger(
            skill_name, trigger_name, first_party=first_party
        )
        if alert_class is None:
            return True
        if self._dispatcher is None:
            return True
        return self._dispatcher.permits_alert_class(
            alert_class, action_tier=action_tier
        )

    async def _record_preference_disabled_alert(
        self,
        *,
        channel: str,
        alert_class: str | None,
        trigger_name: str,
        action_tier: str,
        original_ts: int,
    ) -> None:
        """Record that a notice was withheld by preference, and send nothing.

        Bounded to one row per channel, class and month, like the cap counter
        beside it. Keying by event timestamp instead would add a row per
        suppression, and a class with no cooldown suppressing at the poll rate
        would grow the state store without limit for a record nothing reads
        back yet.
        """
        if self._state_store is None:
            return
        key = _preference_disabled_key(channel, alert_class, original_ts)
        try:
            raw = await self._state_store.get_skill_state(
                "__runtime_alert_preferences__", key
            )
            try:
                previous = json.loads(raw) if raw else {}
            except ValueError:
                previous = {}
            count = int(previous.get("count", 0) or 0) + 1
            await self._state_store.set_skill_state(
                "__runtime_alert_preferences__",
                key,
                json.dumps(
                    {
                        "outcome": "disabled",
                        "reason": "customer_preference",
                        "channel": channel,
                        "alert_class": alert_class,
                        "action_tier": action_tier,
                        "count": count,
                        "last_trigger_name": trigger_name,
                        "last_suppressed_ms": now_ms(),
                    },
                    sort_keys=True,
                ),
            )
        except Exception:
            logger.exception(
                "[runtime] failed to record a preference-disabled alert outcome"
            )

    async def _policy_permits_external_alert(
        self,
        *,
        channel: str,
        action_tier: str,
    ) -> bool:
        if str(action_tier).upper() == "D":
            return True
        if self._dispatcher is None or self._state_store is None:
            return True
        count = await self._current_policy_counted_alerts(channel)
        return self._dispatcher.permits_external_alert(
            channel=channel,
            action_tier=action_tier,
            current_month_count=count,
        )

    async def _current_policy_counted_alerts(self, channel: str) -> int:
        if self._state_store is None:
            return 0
        raw = await self._state_store.get_skill_state(
            "__runtime_alert_policy__",
            _alert_policy_count_key(channel, now_ms()),
        )
        try:
            return max(0, int(raw or "0"))
        except (TypeError, ValueError):
            return 0

    async def _record_policy_counted_alert(
        self,
        channel: str,
        *,
        action_tier: str,
    ) -> None:
        if str(action_tier).upper() == "D":
            return
        if self._state_store is None:
            return
        try:
            key = _alert_policy_count_key(channel, now_ms())
            current = await self._current_policy_counted_alerts(channel)
            await self._state_store.set_skill_state(
                "__runtime_alert_policy__",
                key,
                str(current + 1),
            )
        except Exception:
            logger.warning(
                "[runtime] failed to persist %s alert policy count; delivered alert remains valid",
                channel,
                exc_info=True,
            )

    async def _send_setup_success_notifications(
        self,
        config: Config,
        alert_sender: AlertFailoverSender,
    ) -> None:
        setup_cfg = (
            config.actions.setup_notifications
            if isinstance(config.actions.setup_notifications, dict)
            else {}
        )
        if not is_truthy(setup_cfg.get("enabled", False)):
            return

        if not self._operator_contact:
            logger.warning(
                "[runtime] setup notification skipped: operator_contact not configured"
            )
            return

        channels = _resolve_setup_notification_channels(
            setup_cfg.get("channels", ["primary"]),
            config.actions.primary_alert_channel,
        )
        if not channels:
            logger.warning("[runtime] setup notification skipped: no valid channels")
            return

        channel_enabled = {
            "sms": is_truthy(config.actions.sms.get("enabled", False)),
            "whatsapp": is_truthy(config.actions.whatsapp.get("enabled", False)),
        }
        message = _setup_success_message(
            config=config,
            connected_sensor_count=len(self._connected_sensor_ids),
            active_trigger_count=_count_active_triggers(
                configured_sensors=config.sensors,
                connected_sensor_ids=self._connected_sensor_ids,
                loaded_skills=self._loaded_skills,
            ),
        )
        original_ts = self._runtime_started_at_ms or now_ms()
        for channel in channels:
            if not channel_enabled.get(channel, False):
                logger.info(
                    "[runtime] setup notification skipped for disabled channel=%s",
                    channel,
                )
                continue
            try:
                await self._send_or_queue_alert(
                    channel=channel,
                    message=message,
                    recipient=self._operator_contact,
                    action_tier="A",
                    trigger_name="runtime_setup_complete",
                    original_ts=original_ts,
                    alert_sender=alert_sender,
                    allow_failover=False,
                )
            except Exception:
                logger.exception(
                    "[runtime] setup notification failed unexpectedly on channel=%s",
                    channel,
                )

    async def _alert_delivery_loop(
        self,
        alert_sender: AlertFailoverSender,
    ) -> None:
        """Retry queued outbound alerts until delivered (or abandoned for non-Tier D)."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self._alert_outbox_retry_interval_s,
                )
                break
            except asyncio.TimeoutError:
                pass

            if self._state_store is None:
                continue

            try:
                pending = await self._state_store.get_retryable_alerts(
                    self._alert_outbox_batch_size
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
                    if attempts_after >= self._alert_outbox_tier_d_critical_threshold:
                        logger.critical(
                            "[runtime] Tier D notification delivery still failing id=%s "
                            "channel=%s attempts=%d (will keep retrying)",
                            alert_id,
                            channel,
                            attempts_after,
                        )
                    continue

                if attempts_after >= self._alert_outbox_max_non_tier_d_attempts:
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


def _resolve_setup_notification_channels(
    raw_channels: Any,
    primary_alert_channel: str,
) -> list[str]:
    if isinstance(raw_channels, str):
        candidates = [raw_channels]
    elif isinstance(raw_channels, list):
        candidates = raw_channels
    else:
        candidates = ["primary"]

    primary = str(primary_alert_channel or "sms").strip().lower()
    if primary not in {"sms", "whatsapp"}:
        primary = "sms"

    resolved: list[str] = []
    for raw in candidates:
        channel = str(raw).strip().lower()
        if channel == "primary":
            channel = primary
        if channel in {"sms", "whatsapp"} and channel not in resolved:
            resolved.append(channel)
    return resolved


def _setup_success_message(
    *,
    config: Config,
    connected_sensor_count: int,
    active_trigger_count: int,
) -> str:
    """Describe only the notification posture established at startup.

    The safety disclaimer is fixed text and must never be removed by a generic
    tail truncation.  ``device.location`` is operator-controlled and unbounded
    by the config schema, so only that field is compacted and shortened to fit.
    """
    location = " ".join(str(config.device.location or "").split()) or "site"
    sensor_label = "sensor" if connected_sensor_count == 1 else "sensors"
    rule_label = "rule" if active_trigger_count == 1 else "rules"
    prefix = "Ori is online at "
    suffix = (
        f": {connected_sensor_count} {sensor_label} connected and "
        f"{active_trigger_count} {rule_label} active. "
        "Ori will notify you when it detects a configured risk. "
        "No safety cutoff is commissioned, so Ori can warn but cannot intervene."
    )
    location_budget = max(
        SETUP_NOTIFICATION_MAX_CHARS - len(prefix) - len(suffix),
        0,
    )
    if len(location) > location_budget:
        if location_budget <= 3:
            location = "." * location_budget
        else:
            location = location[: location_budget - 3].rstrip() + "..."
    return prefix + location + suffix


def _count_active_triggers(
    *,
    configured_sensors: list[Any],
    connected_sensor_ids: set[str],
    loaded_skills: list[Any],
) -> int:
    """Count registered rules with at least one connected declared input.

    A skill's triggers are registered for every type in ``sensors_required``.
    Matching more than one connected type therefore makes a trigger reachable
    through more than one subscription, but it remains one rule and is counted
    once.  Skills without a declared type are excluded conservatively: a
    wildcard subscription is not a declared operator-facing input contract.
    """
    connected_types: set[str] = set()
    for sensor in configured_sensors:
        sensor_id = str(getattr(sensor, "id", ""))
        sensor_type = getattr(sensor, "type", "")
        if (
            sensor_id in connected_sensor_ids
            and isinstance(sensor_type, str)
            and sensor_type
        ):
            connected_types.add(sensor_type)

    active_count = 0
    for skill in loaded_skills:
        required = getattr(skill, "sensors_required", [])
        if not isinstance(required, list):
            continue
        declared_types: set[str] = set()
        for item in required:
            if not isinstance(item, dict):
                continue
            sensor_type = item.get("type")
            if isinstance(sensor_type, str) and sensor_type:
                declared_types.add(sensor_type)
        if not connected_types.intersection(declared_types):
            continue
        triggers = getattr(skill, "triggers", [])
        if isinstance(triggers, list):
            active_count += len(triggers)
    return active_count


def _resolve_skill_identity(ctx: SkillContext) -> tuple[str, bool]:
    """The skill's name and whether the loader marked it first-party.

    `first_party` is set by the loader from the packaged roots and never read
    from `skill.yaml`, so a skill cannot claim it. Anything that cannot be
    resolved reads as community, which resolves to no class.
    """
    skill = getattr(ctx, "skill", None) if ctx else None
    name = getattr(skill, "name", "") if skill is not None else ""
    first_party = bool(getattr(skill, "first_party", False))
    return (str(name or "").strip(), first_party)


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


def _preference_disabled_key(
    channel: str, alert_class: str | None, timestamp_ms: int
) -> str:
    month = dt.datetime.fromtimestamp(
        max(0, int(timestamp_ms)) / 1000,
        tz=dt.UTC,
    ).strftime("%Y-%m")
    normalized = str(channel or "").strip().lower() or "unknown"
    return f"disabled:{normalized}:{alert_class or 'unclassified'}:{month}"


def _alert_policy_count_key(channel: str, timestamp_ms: int) -> str:
    month = dt.datetime.fromtimestamp(
        max(0, int(timestamp_ms)) / 1000,
        tz=dt.UTC,
    ).strftime("%Y-%m")
    normalized = str(channel or "").strip().lower() or "unknown"
    return f"external_alert_count:{normalized}:{month}"


def _validate_remote_policy_reference_args(
    reference_url: str,
    expected_sha256: str,
) -> str | None:
    """Return a precondition error for invalid APPLY_POLICY reference args."""
    if not str(reference_url or "").strip().startswith("https://"):
        return "policy reference URL must start with https://"
    digest = str(expected_sha256 or "").strip().lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        return "policy reference sha256 must be a 64-character hex digest"
    return None


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
            "[runtime] remote commands enabled but configured HMAC secret "
            "environment variable is not set; commands will fail closed."
        )
    previous_secret_env = str(remote_cfg.get("previous_hmac_secret_env", "") or "")
    previous_shared_secret = (
        os.environ.get(previous_secret_env, "") if previous_secret_env else ""
    )
    if previous_secret_env and not previous_shared_secret:
        logger.warning(
            "[runtime] remote command previous HMAC secret environment variable "
            "is configured but empty; previous-secret verification disabled."
        )
    max_skew_ms = int(remote_cfg.get("max_skew_seconds", 300)) * 1000
    return RemoteCommandVerifier(
        device_id=str(config.device.id),
        shared_secret=shared_secret,
        previous_shared_secret=previous_shared_secret,
        max_skew_ms=max_skew_ms,
        allowed_senders=remote_cfg.get("allowed_senders"),
        allow_unlisted_senders=is_truthy(
            remote_cfg.get("allow_unlisted_senders", False)
        ),
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
        from dotenv import load_dotenv
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


def _local_llm_requested(reasoning_cfg: Any) -> bool:
    """Return whether configuration asks this runtime to provide local inference."""
    return (
        str(getattr(reasoning_cfg, "default_tier", "") or "").strip().lower() == "local"
    )


def _validate_required_runtime_capabilities(
    config: Config,
    config_path: str,
) -> None:
    """Fail before host mutation when hardened configuration cannot be served.

    Development deliberately retains simulation and graceful degradation for
    laptops and CI. Staging, production, and explicit posture enforcement must
    never report a healthy runtime while a requested physical/protocol/reasoning
    backend is absent.
    """
    if not requires_production_posture(
        device=config.device,
        security=config.security,
    ):
        return

    missing: list[str] = []
    status_cfg = (
        config.hal.status_signaling
        if isinstance(config.hal.status_signaling, dict)
        else {}
    )
    relay_requested = bool(
        config.device.deployment_type != "phone" and "gpio_pin" in config.actions.relay
    )
    status_signaling_requested = is_truthy(status_cfg.get("enabled", False))
    if relay_requested or status_signaling_requested:
        requested_by = (
            "relay control and status signaling"
            if relay_requested and status_signaling_requested
            else "relay control"
            if relay_requested
            else "status signaling"
        )
        if not gpio_backend_importable():
            missing.append(f"gpiozero is unavailable but {requested_by} is configured")
        elif not gpio_backend_arbitrated():
            # The dependency is present and pins would move, so the import check
            # passes. gpiozero fell back to a factory that drives /dev/gpiomem
            # without claiming the line, so the kernel refuses no second writer.
            # A hardened runtime must not report a physical capability it cannot
            # hold exclusively.
            factory = resolved_pin_factory_name() or "none"
            missing.append(
                f"{requested_by} is configured but the resolved GPIO backend "
                f"({factory}) does not claim its lines through the kernel"
            )

    coap_requested = is_truthy(config.actions.coap.get("enabled", False)) or any(
        sensor.protocol == "coap" for sensor in config.sensors
    )
    if coap_requested and not coap_backend_available():
        missing.append(
            "aiocoap is unavailable but a CoAP action or sensor is configured"
        )

    if _local_llm_requested(config.reasoning):
        if not local_llm_backend_available():
            missing.append(
                "llama-cpp-python is unavailable but local reasoning is configured"
            )
        if (
            _resolve_local_model_file(
                str(config.reasoning.local_model or ""),
                str(config.reasoning.model_path or ""),
                config_path,
            )
            is None
        ):
            missing.append(
                "a readable GGUF model file could not be resolved for local reasoning"
            )

    if missing:
        raise ConfigValidationError(
            "production posture requires every configured host capability to be "
            "available; "
            + "; ".join(missing)
            + ". Install the required signed runtime target/dependencies or disable "
            "the capability explicitly before startup."
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


def _build_local_llm(
    reasoning_cfg: Any,
    config_path: str,
    *,
    required: bool = False,
) -> LocalLLM | None:
    """Instantiate LocalLLM from config when a valid local model is available."""
    local_model = str(getattr(reasoning_cfg, "local_model", "") or "")
    model_path = str(getattr(reasoning_cfg, "model_path", "") or "")
    context_window = int(getattr(reasoning_cfg, "local_context_window", 2048) or 2048)

    model_file = _resolve_local_model_file(local_model, model_path, config_path)
    if model_file is None:
        if required:
            raise ConfigValidationError(
                "production posture requires a readable GGUF model file when "
                "local reasoning is configured"
            )
        logger.warning(
            "[runtime] local SLM disabled — could not resolve a model file from "
            "reasoning.local_model=%r and reasoning.model_path=%r",
            local_model,
            model_path,
        )
        return None

    local_llm = LocalLLM(model_path=model_file, context_window=context_window)
    if not local_llm.is_available:
        if required:
            raise ConfigValidationError(
                "production posture requires llama-cpp-python and an accessible "
                f"local model file; local reasoning is unavailable for {model_file}"
            )
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


def _build_gateway_reasoner(config: Config) -> MqttGatewayReasoner | None:
    """Instantiate the MQTT Tier 3 gateway reasoner when configured."""
    if not bool(config.gateway.enabled):
        return None
    reasoning_cfg = (
        config.gateway.reasoning if isinstance(config.gateway.reasoning, dict) else {}
    )
    if not bool(reasoning_cfg.get("enabled", True)):
        return None
    try:
        reasoner = MqttGatewayReasoner(
            broker_url=config.gateway.broker_url,
            device_id=config.device.id,
            timeout_ms=int(reasoning_cfg.get("timeout_ms", 10_000)),
            tls_config=getattr(config.gateway, "tls", {}),
            message_auth=_build_gateway_message_auth(config),
        )
    except Exception:
        logger.exception("[runtime] invalid gateway reasoning configuration")
        return None
    logger.info(
        "[runtime] MQTT gateway reasoning enabled on ori/%s/reasoning/request",
        config.device.id,
    )
    return reasoner


def _build_evidence_attestor(config: Config) -> FirstPartyEvidenceAttestor | None:
    """Build the optional Tier C/D evidence attestor.

    Evidence signing is opt-in via ``evidence.enabled``. A configured but
    missing device secret fails startup loudly -- a silently unkeyed evidence
    chain would defeat the point of enabling it.

    The epoch and key selector are not read from configuration. They are derived
    from the device identity and the evidence key once that key exists, because
    they are sealed into immutable envelopes and recomputed by the evidence
    authority: a configured value would eventually be set wrongly on some device
    and could not be corrected afterwards.
    """
    evidence = getattr(config, "evidence", None)
    if evidence is None or not bool(evidence.enabled):
        return None
    secret = os.environ.get(evidence.device_secret_env, "")
    if not secret:
        raise ValueError(
            "evidence signing is enabled but the configured device-secret "
            f"environment variable ({evidence.device_secret_env}) is empty; "
            "provision a random install secret (not just the device serial)"
        )
    return FirstPartyEvidenceAttestor(
        db_path=evidence.db_path,
        key_path=evidence.key_path,
        device_secret=secret,
        device_id=config.device.id,
        custody_keys=_custody_key_registry(config),
        authority_keys=_load_authority_keys(),
    )


#: Closed vocabulary for `evidence.posture_problems` in runtime health.
EVIDENCE_POSTURE_SIGNING_UNAVAILABLE = "signing_unavailable"
EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING = "authority_keys_missing"
EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED = "custody_unconfigured"


def _evidence_posture_problems(
    config: Config, attestor: FirstPartyEvidenceAttestor
) -> list[str]:
    """What stops evidence trust being established, from local, knowable facts.

    The ledger and device key opened, the signed release shipped an
    authority-key registry, and custody can be verified when a gateway carries
    evidence. Each missing piece is reported, never used to refuse startup:
    evidence records what happened and must not decide whether the runtime may
    run. With any of these missing, ingest refuses what it cannot verify and
    health says why.
    """
    problems: list[str] = []
    if not attestor.available:
        problems.append(EVIDENCE_POSTURE_SIGNING_UNAVAILABLE)
    if attestor.authority_key_count == 0:
        problems.append(EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING)
    if bool(config.gateway.enabled) and not attestor.custody_configured:
        problems.append(EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED)
    return problems


def _load_authority_keys() -> dict:
    """Resolve the authority key registry from the signed release.

    Packaged inside the wheel, so it is covered by the release signature and
    arrives only through an activated release -- the same path the installer
    already uses for release keys. It is deliberately not a configurable path:
    an operator who could point the runtime at a registry of their choosing
    could make arbitrary receipts and epoch confirmations trusted, which is the
    entire property this registry exists to provide.

    A release that ships none yields an empty registry, so inbound receipts and
    epoch confirmations are refused as unknown-key rather than accepted
    unverified. A registry that is present but unreadable is fatal, because that
    is a deployment claiming a verification it cannot perform.
    """
    resource = resources.files("ori.security").joinpath("evidence-authority-keys.json")
    try:
        with resources.as_file(resource) as path:
            if not path.exists():
                return {}
            return load_authority_key_registry(path)
    except (FileNotFoundError, ModuleNotFoundError):
        return {}


def _envelope_secrets(config: Config) -> tuple[str, ...]:
    """Every runtime-gateway envelope secret currently resolvable.

    Handed to the custody registry so reuse is refused on the bytes. Two
    environment variables can hold the same value, so comparing the names an
    operator wrote would report that configuration as correct.

    Each value is contributed both as provisioned and stripped of surrounding
    whitespace. A custody secret differing from an envelope secret only by a
    trailing newline is the same secret to any peer that trims one of them, and
    treating those as distinct key material would let a stray keystroke defeat
    the separation rather than report it.
    """
    raw_auth = getattr(config.gateway, "auth", {})
    auth_cfg = raw_auth if isinstance(raw_auth, dict) else {}
    names = (
        str(auth_cfg.get("shared_secret_env", "") or "").strip(),
        str(auth_cfg.get("previous_shared_secret_env", "") or "").strip(),
    )
    resolved: list[str] = []
    for name in names:
        if not name:
            continue
        value = os.environ.get(name, "")
        for candidate in (value, value.strip()):
            if candidate and candidate not in resolved:
                resolved.append(candidate)
    return tuple(resolved)


def _custody_key_registry(config: Config) -> CustodyKeyRegistry | None:
    """The custody generations acknowledgements are verified against.

    Built from `gateway.custody`, which is a **different secret** from
    `gateway.auth.shared_secret_env`. Custody previously read the envelope
    secret here, which every conformance test contradicted and no running
    system exercised, because nothing routes an acknowledgement inbound yet.

    None when no custody secret is configured. Custody is then refused at
    ingest rather than accepted unauthenticated, since an unauthenticated
    acknowledgement is forgeable by anything on the site network and the
    runtime uses custody state to manage its queue.
    """
    raw = getattr(config.gateway, "custody", {})
    custody_cfg = raw if isinstance(raw, dict) else {}
    env_name = str(custody_cfg.get("secret_env", "") or "").strip()

    # Not configured at all is a choice; configured and empty is a broken
    # credential. Collapsing the second into the first would report a
    # deployment whose custody secret never reached the process as one that
    # deliberately runs without custody, and the operator would see a healthy
    # runtime silently refusing every acknowledgement.
    if not env_name:
        return None
    # Read exactly as provisioned. The custody MAC keys from these bytes, so
    # trimming would key from bytes the operator did not set; the registry
    # refuses surrounding whitespace instead of silently deriving a different
    # identifier from the one the gateway holds.
    active = os.environ.get(env_name, "")
    if not active:
        raise ValueError(
            f"gateway.custody.secret_env names {env_name}, but that environment "
            "variable is empty or unset; provision the custody secret or remove "
            "the setting to run without custody verification"
        )

    previous_env = str(custody_cfg.get("previous_secret_env", "") or "").strip()
    previous = ""
    if previous_env:
        previous = os.environ.get(previous_env, "")
        if not previous:
            raise ValueError(
                f"gateway.custody.previous_secret_env names {previous_env}, but "
                "that environment variable is empty or unset; a rotation window "
                "needs the outgoing secret, so remove the setting to close it"
            )

    retired = tuple(str(v) for v in (custody_cfg.get("retired_key_ids") or ()))
    try:
        return CustodyKeyRegistry(
            active_secret=active,
            previous_secret=previous or None,
            retired_key_ids=retired,
            forbidden_secrets=_envelope_secrets(config),
        )
    except CustodyKeyRegistryError as exc:
        # Fail closed and loudly. A registry that cannot be built is a
        # misconfiguration an operator must fix, and silently continuing
        # without custody verification would look like a working deployment.
        raise ValueError(f"gateway.custody is misconfigured: {exc}") from exc


def _build_gateway_message_auth(config: Config) -> GatewayMessageAuthenticator | None:
    """Build optional HMAC auth for runtime-gateway MQTT envelopes."""
    raw_auth = getattr(config.gateway, "auth", {})
    auth_cfg = raw_auth if isinstance(raw_auth, dict) else {}
    if not bool(auth_cfg.get("enabled", False)):
        return None
    env_name = str(auth_cfg.get("shared_secret_env", "") or "").strip()
    secret = os.environ.get(env_name, "") if env_name else ""
    if not secret:
        raise ValueError(
            "gateway auth is enabled but configured shared-secret environment "
            "variable is empty"
        )
    previous_env_name = str(
        auth_cfg.get("previous_shared_secret_env", "") or ""
    ).strip()
    previous_secret = os.environ.get(previous_env_name, "") if previous_env_name else ""
    if previous_env_name and not previous_secret:
        logger.warning(
            "[runtime] gateway auth previous shared-secret environment variable "
            "is configured but empty; previous-secret verification disabled."
        )
    replay_ttl_ms = int(auth_cfg.get("replay_ttl_ms", 300_000))
    replay_cache = None
    if is_truthy(auth_cfg.get("persistent_replay_cache", True)):
        # A restart is attacker-influenceable on a physically accessible
        # device (pulling power is enough), so seen keys persist to the
        # state database to keep the replay window closed across restarts.
        replay_cache = GatewayReplayCache(
            ttl_ms=replay_ttl_ms,
            db_path=str(getattr(config, "database_path", "") or ""),
        )
        if not replay_cache.persistent:
            logger.warning(
                "[runtime] gateway replay cache persistence unavailable; "
                "replay protection is in-memory only until the next restart."
            )
    return GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret=secret,
            previous_shared_secret=previous_secret,
            max_skew_ms=int(auth_cfg.get("max_clock_skew_ms", 300_000)),
            replay_ttl_ms=replay_ttl_ms,
        ),
        replay_cache=replay_cache,
    )


def _build_gateway_message_encryptor(config: Config) -> GatewayMessageEncryptor | None:
    """Build optional AES-GCM encryption for sensitive export payloads."""
    raw_encryption = getattr(config.gateway, "encryption", {})
    encryption_cfg = raw_encryption if isinstance(raw_encryption, dict) else {}
    if not bool(encryption_cfg.get("enabled", False)):
        return None
    raw_auth = getattr(config.gateway, "auth", {})
    auth_cfg = raw_auth if isinstance(raw_auth, dict) else {}
    if not bool(auth_cfg.get("enabled", False)):
        raise ValueError("gateway encryption requires gateway auth")
    env_name = str(auth_cfg.get("shared_secret_env", "") or "").strip()
    secret = os.environ.get(env_name, "") if env_name else ""
    if not secret:
        raise ValueError(
            "gateway encryption is enabled but configured shared-secret "
            "environment variable is empty"
        )
    return GatewayMessageEncryptor(GatewayMessageEncryptionConfig(shared_secret=secret))


def _build_gateway_heartbeat_subscriber(
    config: Config,
    posture_tracker: CapabilityPostureTracker,
) -> MqttGatewayHeartbeatSubscriber | None:
    """Instantiate the MQTT gateway heartbeat subscriber when configured."""
    if not bool(config.gateway.enabled):
        return None
    auth_cfg = getattr(config.gateway, "auth", {}) or {}
    auth_enabled = bool(auth_cfg.get("enabled", False))
    if not auth_enabled:
        logger.warning(
            "[gateway-heartbeat] gateway.auth.enabled is false — heartbeat "
            "payloads are accepted without HMAC verification. A spoofed "
            "heartbeat can corrupt gateway liveness state and cause the "
            "elevator to burn escalation timeout budget on a non-existent "
            "gateway. Enable gateway.auth for all production deployments."
        )
    try:
        subscriber = MqttGatewayHeartbeatSubscriber(
            broker_url=config.gateway.broker_url,
            posture_tracker=posture_tracker,
            device_id=config.device.id,
            tls_config=getattr(config.gateway, "tls", {}),
            authenticator=_build_gateway_message_auth(config),
        )
    except Exception:
        logger.exception("[runtime] invalid gateway heartbeat configuration")
        return None
    logger.info(
        "[runtime] MQTT gateway heartbeat subscriber enabled on %s (auth=%s)",
        "ori/gateway/health",
        "enabled" if auth_enabled else "disabled",
    )
    return subscriber


def _build_evidence_inbound_subscriber(
    config: Config,
    attestor: FirstPartyEvidenceAttestor | None,
) -> MqttEvidenceInboundSubscriber | None:
    """Instantiate the inbound authority-artifact route when configured.

    Requires a gateway and a started attestor. Without the attestor there is no
    ledger to apply anything to, and subscribing anyway would leave a runtime
    acknowledging receipt of artifacts it cannot record -- which is worse than
    not listening, because the gateway would stop retrying.

    Envelope authentication is defense in depth rather than the proof. Every
    artifact carries its own authenticator, verified under key material this
    transport never sees: custody under the dedicated custody secret, receipts
    and epoch confirmations under authority keys from the signed release. An
    unauthenticated envelope therefore degrades the route rather than opening
    it, which is why development may run without one while staging and
    production reject an auth-disabled gateway broker at config load.
    """
    if not bool(config.gateway.enabled):
        return None
    if attestor is None or not attestor.available:
        return None
    ingest = attestor.ingest
    if ingest is None:
        return None

    auth_cfg = getattr(config.gateway, "auth", {}) or {}
    auth_enabled = bool(auth_cfg.get("enabled", False))
    if not auth_enabled:
        logger.warning(
            "[evidence-inbound] gateway.auth.enabled is false — inbound "
            "authority artifacts are accepted without envelope verification. "
            "Each artifact is still verified under its own key material, so "
            "nothing is trusted on arrival, but anything on the site network "
            "can then spend this runtime's ingest path. Enable gateway.auth "
            "for all production deployments."
        )
    try:
        router = EvidenceInboundRouter(
            device_id=config.device.id,
            ingest=ingest,
            message_auth=_build_gateway_message_auth(config),
        )
        subscriber = MqttEvidenceInboundSubscriber(
            broker_url=config.gateway.broker_url,
            router=router,
            device_id=config.device.id,
            tls_config=getattr(config.gateway, "tls", {}),
        )
    except Exception:
        logger.exception("[runtime] invalid inbound evidence route configuration")
        return None
    logger.info(
        "[runtime] inbound evidence route enabled on %s (envelope auth=%s)",
        subscriber.topic,
        "enabled" if auth_enabled else "disabled",
    )
    return subscriber


def _build_evidence_outbound_publisher(
    config: Config,
    attestor: FirstPartyEvidenceAttestor | None,
) -> MqttEvidenceOutboundPublisher | None:
    """Instantiate the outbound carriage route when configured.

    Requires a gateway and a started attestor: without a ledger there is
    nothing to carry. Envelope authentication covers the courier's
    acknowledgements only; the artifacts themselves are device-signed end to
    end, so an unauthenticated development gateway degrades what a queued
    acknowledgement is worth rather than what the courier receives.
    """
    if not bool(config.gateway.enabled):
        return None
    if attestor is None or not attestor.available:
        return None
    outbox = attestor.outbound
    if outbox is None:
        return None
    auth_cfg = getattr(config.gateway, "auth", {}) or {}
    auth_enabled = bool(auth_cfg.get("enabled", False))
    if not auth_enabled:
        logger.warning(
            "[evidence-outbound] gateway.auth.enabled is false — courier "
            "acknowledgements are applied without envelope verification, so "
            "anything on the site network can retire a queued checkpoint. "
            "Enable gateway.auth for all production deployments."
        )
    try:
        router = EvidenceOutboundAckRouter(
            device_id=config.device.id,
            outbox=outbox,
            message_auth=_build_gateway_message_auth(config),
        )
        publisher = MqttEvidenceOutboundPublisher(
            broker_url=config.gateway.broker_url,
            router=router,
            device_id=config.device.id,
            outbox=outbox,
            tls_config=getattr(config.gateway, "tls", {}),
        )
    except Exception:
        logger.exception("[runtime] invalid outbound evidence route configuration")
        return None
    logger.info(
        "[runtime] outbound evidence route enabled on %s (envelope auth=%s)",
        publisher.topic,
        "enabled" if auth_enabled else "disabled",
    )
    return publisher


def _build_firmware_telemetry_subscriber(
    config: Config,
    event_bus: EventBus,
    state_store: StateStore,
    deduplicator: EventDeduplicator | None,
    liveness_supervisor: FirmwareLivenessSupervisor,
    on_connected: Callable[[], None] | None = None,
) -> MqttFirmwareTelemetrySubscriber | None:
    """Instantiate the signed firmware telemetry subscriber when configured."""
    if not bool(config.gateway.enabled):
        return None
    firmware_cfg = (
        config.gateway.firmware_telemetry
        if isinstance(getattr(config.gateway, "firmware_telemetry", {}), dict)
        else {}
    )
    if not bool(firmware_cfg.get("enabled", False)):
        return None
    try:
        subscriber = MqttFirmwareTelemetrySubscriber(
            broker_url=config.gateway.broker_url,
            telemetry_gate=FirmwareTelemetryGate(state_store),
            event_bus=event_bus,
            state_store=state_store,
            runtime_device_id=config.device.id,
            topic=str(firmware_cfg.get("topic", "ori/fw/+/telemetry")),
            qos=int(firmware_cfg.get("qos", 1)),
            tls_config=getattr(config.gateway, "tls", {}),
            deduplicator=deduplicator,
            liveness_supervisor=liveness_supervisor,
            on_connected=on_connected,
        )
    except Exception:
        logger.exception("[runtime] invalid firmware telemetry MQTT configuration")
        return None
    logger.info(
        "[runtime] MQTT firmware telemetry subscriber enabled on %s",
        firmware_cfg.get("topic", "ori/fw/+/telemetry"),
    )
    return subscriber


def _build_firmware_command_service(
    config: Config,
    state_store: StateStore,
    liveness_supervisor: FirmwareLivenessSupervisor,
) -> tuple[MqttFirmwareCommandPublisher, FirmwareCommandService] | None:
    """Instantiate firmware command egress when explicitly configured."""
    if not bool(config.gateway.enabled):
        return None
    command_cfg = (
        config.gateway.firmware_commands
        if isinstance(getattr(config.gateway, "firmware_commands", {}), dict)
        else {}
    )
    if not bool(command_cfg.get("enabled", False)):
        return None
    try:
        runtime_key = load_raw_ed25519_seed_from_env(
            str(command_cfg.get("runtime_command_key_env", "")),
            label="runtime command key",
        )
        provisioner_key = load_raw_ed25519_seed_from_env(
            str(command_cfg.get("provisioner_key_env", "")),
            label="firmware provisioner key",
        )
        publisher = MqttFirmwareCommandPublisher(
            broker_url=config.gateway.broker_url,
            runtime_device_id=config.device.id,
            qos=int(command_cfg.get("qos", 1)),
            tls_config=getattr(config.gateway, "tls", {}),
            publish_timeout_s=float(command_cfg.get("publish_timeout_s", 10.0)),
        )
        service = FirmwareCommandService(
            store=state_store,
            publisher=publisher,
            runtime_command_key_bytes=runtime_key,
            provisioner_key_bytes=provisioner_key,
            liveness_supervisor=liveness_supervisor,
        )
    except Exception:
        logger.exception("[runtime] invalid firmware command egress configuration")
        raise
    return publisher, service


def _provisioning_anchor_bytes(config: Config) -> bytes | None:
    """The provisioning anchor as raw key material, from the environment it names.

    The reading lives with the other anchors so the CLI bridge resolves the
    same value from the same document; two readings of one anchor is one
    reading too many.
    """
    return provisioning_anchor(config.security)


def _degradation_reasons(*, firmware_liveness_degraded: bool) -> list[str]:
    """Named degradation reasons for the node heartbeat.

    Returns an empty list when nothing is degraded; the heartbeat omits the
    field entirely in that case. An empty array on the wire is malformed —
    absent and present-empty are different states, and encoding one as the
    other is the ambiguity the contract exists to remove.

    The vocabulary is owned by ``ori.gateway.node_heartbeat``, the wire
    boundary that enforces it, so a token cannot be named here without also
    being publishable there.
    """
    reasons: list[str] = []
    if firmware_liveness_degraded:
        reasons.append(DEGRADATION_REASON_FIRMWARE_LIVENESS)
    return sorted(set(reasons))


def _build_firmware_liveness_stack(
    config: Config,
    event_bus: EventBus,
    state_store: StateStore,
    deduplicator: EventDeduplicator | None,
    on_telemetry_connected: Callable[[], None] | None = None,
) -> tuple[
    FirmwareLivenessSupervisor,
    MqttFirmwareTelemetrySubscriber | None,
    tuple[MqttFirmwareCommandPublisher, FirmwareCommandService] | None,
    FirmwareLivenessScheduler | None,
]:
    """Compose both firmware liveness halves around ONE supervisor.

    The telemetry subscriber is the only thing that can establish
    supervision and the command service is the only thing that can act on
    it, so they must hold the same object. Two instances leave the service
    refusing every device forever while the subscriber records into a map
    nobody reads — production indistinguishable from the feature being
    absent, with every unit test still green.

    This exists as a function rather than as three statements inside
    ``start`` because that is what makes the shared instance assertable.
    Wiring each half correctly while connecting neither to the other is a
    mistake no unit test can see; with exactly one construction site and one
    name to pass, it has nowhere to happen.
    """
    supervisor = FirmwareLivenessSupervisor()
    subscriber = _build_firmware_telemetry_subscriber(
        config,
        event_bus,
        state_store,
        deduplicator,
        supervisor,
        on_connected=on_telemetry_connected,
    )
    command_pair = _build_firmware_command_service(
        config,
        state_store,
        supervisor,
    )

    # The scheduler is composed here rather than in ``start`` for the same
    # reason as the rest: it must drive the command SERVICE, whose signing
    # refusal is the supervision obligation, and never the transport
    # publisher beside it. Building it next to both makes the wrong one
    # visibly wrong.
    scheduler = None
    if command_pair is not None:
        command_cfg = (
            config.gateway.firmware_commands
            if isinstance(getattr(config.gateway, "firmware_commands", {}), dict)
            else {}
        )
        # No separate enable flag: command authority and its supervision
        # assertion are one operational posture, not two switches. A runtime
        # that commands a device but never asserts it is watching is the
        # exact condition this signal exists to make visible.
        #
        # It does not by itself orphan anything. A device is orphaned only
        # when neither the runtime nor a gateway is reachable, and firmware
        # today still derives runtime_reachable from broker connectivity —
        # so an expired assertion changes nothing until that switchover
        # lands (ori-edge-firmware#68).
        scheduler = FirmwareLivenessScheduler(
            command_pair[1],
            interval_s=float(
                command_cfg.get("liveness_interval_s", LIVENESS_PUBLISH_INTERVAL_S)
            ),
        )
    return supervisor, subscriber, command_pair, scheduler


def _read_private_key_file(path: str) -> bytes:
    """Read one root/runtime-owned private-key file without following symlinks."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("secure private-key file opening is unsupported")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("cannot open firmware MQTT client CA private key") from exc
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise RuntimeError(
                "firmware MQTT client CA private key must be a regular file"
            )
        if file_stat.st_uid not in {0, os.geteuid()}:
            raise RuntimeError(
                "firmware MQTT client CA private key has an invalid owner"
            )
        if file_stat.st_mode & 0o077:
            raise RuntimeError(
                "firmware MQTT client CA private key must have mode 0o600 or stricter"
            )
        with os.fdopen(fd, "rb", closefd=False) as handle:
            value = handle.read(64 * 1024 + 1)
    finally:
        os.close(fd)
    if not value or len(value) > 64 * 1024:
        raise RuntimeError("firmware MQTT client CA private key size is invalid")
    return value


def _read_public_pem_file(path: str) -> bytes:
    """Read bounded public PEM material without accepting a private key."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("secure certificate file opening is unsupported")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("cannot open firmware MQTT public certificate file") from exc
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise RuntimeError(
                "firmware MQTT public certificate must be a regular file"
            )
        with os.fdopen(fd, "rb", closefd=False) as handle:
            value = handle.read(64 * 1024 + 1)
    finally:
        os.close(fd)
    if not value or len(value) > 64 * 1024 or b"PRIVATE KEY" in value.upper():
        raise RuntimeError("firmware MQTT public certificate material is invalid")
    return value


def _build_runtime_node_heartbeat_publisher(
    config: Config,
    health_snapshot_provider: Callable[[], dict[str, Any] | Awaitable[dict[str, Any]]],
) -> MqttRuntimeNodeHeartbeatPublisher | None:
    """Instantiate the runtime-to-gateway node heartbeat publisher when configured."""
    if not bool(config.gateway.enabled):
        return None
    heartbeat_cfg = (
        config.gateway.node_heartbeat
        if isinstance(getattr(config.gateway, "node_heartbeat", {}), dict)
        else {}
    )
    if not bool(heartbeat_cfg.get("enabled", True)):
        return None
    auth_cfg = getattr(config.gateway, "auth", {}) or {}
    auth_enabled = bool(auth_cfg.get("enabled", False))
    if not auth_enabled:
        logger.warning(
            "[runtime-heartbeat] gateway.auth.enabled is false — node heartbeat "
            "payloads are published without HMAC. Enable gateway.auth for "
            "production deployments."
        )
    try:
        publisher = MqttRuntimeNodeHeartbeatPublisher(
            broker_url=config.gateway.broker_url,
            device_id=config.device.id,
            health_snapshot_provider=health_snapshot_provider,
            interval_seconds=float(heartbeat_cfg.get("interval_seconds", 30)),
            tls_config=getattr(config.gateway, "tls", {}),
            authenticator=_build_gateway_message_auth(config),
        )
    except Exception:
        logger.exception("[runtime] invalid runtime node heartbeat configuration")
        return None
    logger.info(
        "[runtime] MQTT runtime node heartbeat publisher enabled on ori/%s/runtime/heartbeat (auth=%s)",
        config.device.id,
        "enabled" if auth_enabled else "disabled",
    )
    return publisher


def _build_context_enricher(config: Config) -> ContextEnricher | None:
    """Build ContextEnricher from reasoning.context_enricher config block."""
    enricher_raw = getattr(config.reasoning, "context_enricher", {}) or {}
    if not bool(enricher_raw.get("enabled", False)):
        return None
    try:
        cfg = ContextEnricherConfig(
            enabled=True,
            staleness_window_ms=int(enricher_raw.get("staleness_window_ms", 60_000)),
            max_entries=int(enricher_raw.get("max_entries", 5)),
            include_sources=list(enricher_raw.get("include_sources") or []),
        )
        return ContextEnricher(cfg)
    except Exception:
        logger.exception(
            "[runtime] failed to construct ContextEnricher — enrichment disabled"
        )
        return None


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


def _build_sms_allowed_senders(config: Config) -> set[str]:
    """Return the normalized set of phone numbers permitted to send inbound SMS.

    Built from ``actions.operator_contact`` and ``actions.secondary_contact``.
    An empty set means no allowlist is enforced (open to any sender).
    """
    senders: set[str] = set()
    for raw in (config.actions.operator_contact, config.actions.secondary_contact):
        normalized = "".join(ch for ch in str(raw or "") if ch.isdigit() or ch == "+")
        if normalized:
            senders.add(normalized)
    return senders


def _warn_gateway_security_posture(config: Config) -> None:
    """Emit startup warnings for gateway security posture gaps.

    Called once during runtime startup after all gateway components are built.
    Does not raise — posture issues are warnings, not startup failures, because
    loopback-only sites are intentionally configured without TLS or auth.
    """
    if not bool(config.gateway.enabled):
        return

    auth_cfg = getattr(config.gateway, "auth", {}) or {}
    tls_cfg = getattr(config.gateway, "tls", {}) or {}
    broker_url = str(getattr(config.gateway, "broker_url", "") or "")

    auth_enabled = bool(auth_cfg.get("enabled", False))
    tls_enabled = bool(tls_cfg.get("enabled", False))
    # Parse the host out rather than prefix-matching the URL. Production
    # posture requires broker credentials, so the very configuration this
    # runtime asks for — `mqtt://user:pass@127.0.0.1:1883` — carries userinfo
    # ahead of the host and matches no prefix. Classifying that as a public
    # broker made the runtime log, at ERROR, that traffic was unauthenticated
    # while it was in fact authenticated. A security channel that cries wolf
    # is worse than a silent one: the operator either acts on a false alarm or
    # learns to ignore it.
    parsed = urlparse(broker_url if "://" in broker_url else f"mqtt://{broker_url}")
    is_loopback = is_loopback_host(parsed.hostname)

    if not auth_enabled:
        if not is_loopback:
            logger.error(
                "[runtime-security] GATEWAY: gateway.auth.enabled is false and broker "
                "is not loopback — MQTT traffic is unauthenticated. "
                "Set gateway.auth.enabled: true and provide GATEWAY_SHARED_SECRET."
            )
        else:
            logger.warning(
                "[runtime-security] gateway.auth.enabled is false — HMAC envelope "
                "authentication disabled. Acceptable for loopback-only deployments only."
            )

    if not tls_enabled and not is_loopback:
        logger.warning(
            "[runtime-security] GATEWAY: gateway.tls.enabled is false and broker is "
            "not loopback — MQTT payloads are unencrypted on the network. "
            "Enable TLS for any non-loopback gateway deployment."
        )

    if auth_enabled and not tls_enabled and not is_loopback:
        logger.warning(
            "[runtime-security] GATEWAY: HMAC auth is enabled but TLS is not. "
            "Payloads are authenticated but visible in transit on the LAN. "
            "Enable gateway.tls for defense-in-depth."
        )


def _warn_sms_webhook_security_posture(config: Config) -> None:
    """Emit startup warnings for public SMS webhook ingress gaps.

    Production/staging posture fails config load for these conditions. This
    warning path exists for development configs that bind the webhook on a
    non-loopback interface before production posture is enabled.
    """
    sms_cfg = config.actions.sms if isinstance(config.actions.sms, dict) else {}
    webhook_cfg = sms_cfg.get("incoming_webhook") or {}
    if not isinstance(webhook_cfg, dict):
        return
    if not is_truthy(webhook_cfg.get("enabled", False)):
        return

    host = str(webhook_cfg.get("host", "127.0.0.1") or "").strip()
    if is_loopback_host(host):
        return

    signature_cfg = webhook_cfg.get("signature") or {}
    signature_mode = (
        str(signature_cfg.get("mode", "token_only") or "token_only").strip().lower()
        if isinstance(signature_cfg, dict)
        else "token_only"
    )
    if signature_mode == "token_only":
        logger.error(
            "[runtime-security] SMS_WEBHOOK: incoming_webhook.host=%r is not "
            "loopback and signature.mode=token_only. Public SMS webhook ingress "
            "must be fronted by a signing bridge or configured with "
            "signature.mode=token_and_hmac/hmac_required.",
            host,
        )

    source_cidrs = webhook_cfg.get("allowed_source_cidrs") or []
    if not source_cidrs:
        logger.warning(
            "[runtime-security] SMS_WEBHOOK: incoming_webhook.host=%r is not "
            "loopback and allowed_source_cidrs is empty. Restrict ingress to "
            "Africa's Talking provider IP ranges or a trusted reverse proxy.",
            host,
        )


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
