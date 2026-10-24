# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The state every runtime domain shares: ``OriRuntime.__init__``."""

import asyncio
import logging
from typing import Any

from ori.actions.alert_failover import AlertFailoverSender
from ori.actions.commissioned_actuator import CommissionedActuator
from ori.actions.sms import SMSAction
from ori.config import Config
from ori.firmware_mqtt_operator import FirmwareMqttOperatorServer
from ori.gateway.evidence_inbound import MqttEvidenceInboundSubscriber
from ori.gateway.evidence_outbound import MqttEvidenceOutboundPublisher
from ori.gateway.export import MqttGatewayExportServer
from ori.gateway.firmware_commands import (
    FirmwareCommandService,
    MqttFirmwareCommandPublisher,
)
from ori.gateway.firmware_liveness_publisher import FirmwareLivenessScheduler
from ori.gateway.node_heartbeat import MqttRuntimeNodeHeartbeatPublisher
from ori.hal.base import BaseAdapter
from ori.hardware.led_indicator import LEDIndicator
from ori.network.deduplicator import EventDeduplicator
from ori.network.event_bus import EventBus
from ori.network.sms_webhook import SMSWebhookServer
from ori.operator_socket import OperatorSocketServer
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.capability_posture import CapabilityPostureTracker
from ori.reasoning.dispatch_coordinator import DispatchCoordinator
from ori.reasoning.elevator import IntelligenceElevator
from ori.runtime._constants import (
    ALERT_OUTBOX_BATCH_SIZE,
    ALERT_OUTBOX_MAX_ATTEMPTS_NON_TIER_D,
    ALERT_OUTBOX_RETRY_INTERVAL_S,
    ALERT_OUTBOX_TIER_D_CRITICAL_THRESHOLD,
)
from ori.runtime._measurement_policy import MEASUREMENT_WRITER_CEILING
from ori.runtime._safety_wiring import SafetyAlertAdapter
from ori.runtime_health_socket import RuntimeHealthSocketServer
from ori.safety.commander import ActuatorOutcomeCommander
from ori.safety.registry import SafetyRegistry
from ori.security.commissioning.loader import CommissioningState
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.security.firmware.confirmation import FirmwareConfirmationCoordinator
from ori.security.firmware.controller_profiles import (
    ControllerAlarmTracker,
    ControllerProfileLibrary,
)
from ori.security.firmware.reading_age import ReadingAgeTracker
from ori.security.firmware.reconciliation import FirmwareConfirmationReconciler
from ori.security.gateway_messages import GatewayEnvelopeState
from ori.security.remote_commands.lockout import default_remote_command_lockout_config
from ori.skills.loader import SkillLoader
from ori.state.deferred_writer import DeferredWriter
from ori.state.store import StateStore
from ori.telemetry.http_export import HttpTelemetryExporter


class RuntimeCore:
    """Every attribute the runtime holds, set before any domain runs."""

    def __init__(
        self,
        config_path: str = "ori.yaml",
        *,
        dotenv_variables: frozenset[str] | None = None,
    ) -> None:
        self._config_path = config_path
        #: What a `.env` autoloaded before this configuration could be read, or
        #: ``None`` if none was. The decision had to be made first; startup
        #: confirms it against the posture the document turns out to declare.
        self._dotenv_variables = dotenv_variables
        #: Which variables the document's values name, read once after it is
        #: loaded. ``None`` until then, and read as unknown, because a report
        #: cannot say a file supplied nothing while it does not know what the
        #: document asks for.
        self._config_env_placeholders: frozenset[str] | None = None
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
        self._elevator: IntelligenceElevator | None = None
        self._skill_loader: SkillLoader | None = None
        self._skills_dir: str | None = None
        self._skill_selection: tuple[tuple[str, str], ...] = ()
        self._loaded_skills: list[Any] = []
        self._skill_subscriptions: list[tuple[str, Any]] = []
        self._dispatch_coordinator: DispatchCoordinator | None = None
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
        self._read_failure_logged_at: dict[str, float] = {}
        # A refused measurement window is not a failed read. The sensor is
        # present and answering; what it returned was not a measurement.
        self._measurement_refusals: dict[str, int] = {}
        self._measurement_valid_streak: dict[str, int] = {}
        # Why the current run of refusals was refused, for the health snapshot.
        self._measurement_refusal_reason: dict[str, str] = {}
        self._measurement_degraded: set[str] = set()
        # Configured sensors whose adapter never connected. Distinct from a
        # sensor that connected and went quiet: that one is late and the
        # staleness watch sees it, this one is absent and nothing else does.
        self._unconnected_sensors: set[str] = set()
        self._retrying_sensors_announced: set[str] = set()
        self._measurement_unnotified: set[str] = set()
        self._measurement_notify_attempts: dict[str, int] = {}
        self._measurement_degraded_since: dict[str, int] = {}
        self._measurement_notice_stage: dict[str, int] = {}
        # Recovery is recorded beside the reading, never ahead of it, by one
        # ordered writer. A sensor has at most one reconciliation pending, and
        # one whose disk says recovered while it is still degraded is owed a
        # restore until the disk agrees.
        self._measurement_writer = DeferredWriter(
            "measurement",
            ceiling=MEASUREMENT_WRITER_CEILING,
            loss_level=logging.WARNING,
        )
        self._measurement_reconciling: set[str] = set()
        self._measurement_disk_recovered: set[str] = set()
        self._runtime_started_at_ms: int = 0
        self._configured_sensors: list[Any] = []
        self._connected_sensor_ids: set[str] = set()
        self._last_alert_timestamps_by_channel: dict[str, int] = {}
        self._last_alert_timestamps_by_trigger: dict[str, int] = {}
        self._health_socket_server: RuntimeHealthSocketServer | None = None
        self._operator_socket_server: OperatorSocketServer | None = None
        self._firmware_mqtt_operator_server: FirmwareMqttOperatorServer | None = None
        self._gateway_export_server: MqttGatewayExportServer | None = None
        self._runtime_node_heartbeat_publisher: (
            MqttRuntimeNodeHeartbeatPublisher | None
        ) = None
        self._gateway_envelope_state: GatewayEnvelopeState | None = None
        self._firmware_command_publisher: MqttFirmwareCommandPublisher | None = None
        self._firmware_command_service: FirmwareCommandService | None = None
        self._firmware_liveness_scheduler: FirmwareLivenessScheduler | None = None
        self._firmware_reading_age: ReadingAgeTracker | None = None
        self._firmware_profile_library: ControllerProfileLibrary | None = None
        self._firmware_alarm_tracker: ControllerAlarmTracker | None = None
        self._telemetry_exporter: HttpTelemetryExporter | None = None
        # Startup and stop must not run at once; these order them.
        self._startup_complete = False
        self._stop_requested_during_startup = False
        self._evidence_attestor: FirstPartyEvidenceAttestor | None = None
        self._evidence_inbound_subscriber: MqttEvidenceInboundSubscriber | None = None
        self._evidence_outbound_publisher: MqttEvidenceOutboundPublisher | None = None
        self._evidence_posture_problems: list[str] = []
        self._commissioning_state: CommissioningState | None = None
        self._safety_registry: SafetyRegistry | None = None
        self._safety_commander: ActuatorOutcomeCommander | None = None
        self._safety_alert_sink: SafetyAlertAdapter | None = None
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
        self._device_location: str = "site"
        self._device_timezone: str = "UTC"
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
