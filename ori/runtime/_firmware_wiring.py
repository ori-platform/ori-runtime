# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Builders for firmware telemetry, commands, reading age and liveness."""

import logging
import math
from collections.abc import Callable
from typing import Any

from ori.config import Config
from ori.gateway.firmware_commands import (
    FirmwareCommandService,
    MqttFirmwareCommandPublisher,
    load_raw_ed25519_seed_from_env,
)
from ori.gateway.firmware_liveness_publisher import (
    MIN_LIVENESS_PUBLISH_INTERVAL_S,
    FirmwareLivenessScheduler,
)
from ori.gateway.firmware_telemetry import MqttFirmwareTelemetrySubscriber
from ori.network.deduplicator import EventDeduplicator
from ori.network.event_bus import EventBus
from ori.security.commissioning.anchors import provisioning_anchor
from ori.security.firmware.controller_profiles import (
    ControllerAlarmTracker,
    ControllerProfileLibrary,
)
from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.liveness import (
    LIVENESS_PUBLISH_INTERVAL_S,
    FirmwareLivenessSupervisor,
)
from ori.security.firmware.reading_age import (
    DEFAULT_TOTAL_BOUND,
    LivenessTable,
    ReadingAgeTracker,
    default_per_device_bound,
)
from ori.state.store import StateStore

logger = logging.getLogger("ori.runtime")


def firmware_telemetry_config(config: Config) -> dict[str, Any] | None:
    """The firmware telemetry section when the subscriber is enabled, else None."""
    if not bool(config.gateway.enabled):
        return None
    firmware_cfg = (
        config.gateway.firmware_telemetry
        if isinstance(getattr(config.gateway, "firmware_telemetry", {}), dict)
        else {}
    )
    if not bool(firmware_cfg.get("enabled", False)):
        return None
    return firmware_cfg


def firmware_profile_library(
    firmware_cfg: dict[str, Any],
) -> ControllerProfileLibrary:
    """The controller profile documents held, read once at start."""
    return ControllerProfileLibrary.from_directory(
        str(firmware_cfg.get("controller_profiles_dir", "") or "") or None
    )


def _build_firmware_telemetry_subscriber(
    config: Config,
    event_bus: EventBus,
    state_store: StateStore,
    deduplicator: EventDeduplicator | None,
    liveness_supervisor: FirmwareLivenessSupervisor,
    on_connected: Callable[[], None] | None = None,
    profiles: ControllerProfileLibrary | None = None,
    alarms: ControllerAlarmTracker | None = None,
    reading_age: ReadingAgeTracker | None = None,
) -> MqttFirmwareTelemetrySubscriber | None:
    """Instantiate the signed firmware telemetry subscriber when configured."""
    firmware_cfg = firmware_telemetry_config(config)
    if firmware_cfg is None:
        return None
    if profiles is None:
        profiles = firmware_profile_library(firmware_cfg)
    try:
        subscriber = MqttFirmwareTelemetrySubscriber(
            broker_url=config.gateway.broker_url,
            telemetry_gate=FirmwareTelemetryGate(
                state_store, profiles=profiles, alarms=alarms, reading_age=reading_age
            ),
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


def firmware_reading_age(config: Config) -> ReadingAgeTracker | None:
    """The reading-age tracker, with a liveness table only where this runtime signs liveness.

    None when no firmware telemetry is accepted. The per-device bound holds an
    hour of a device's ``v`` 2 messages at the configured interval
    (firmware-telemetry/v2 The bound); the total bound is fixed, so a short
    interval cannot grow the table without limit.
    """
    if firmware_telemetry_config(config) is None:
        return None
    command_cfg = (
        config.gateway.firmware_commands
        if isinstance(getattr(config.gateway, "firmware_commands", {}), dict)
        else {}
    )
    if not (bool(config.gateway.enabled) and bool(command_cfg.get("enabled", False))):
        # No v 2 nonce is signed, so nothing could match a table.
        return ReadingAgeTracker(None)
    interval = command_cfg.get("liveness_interval_s", LIVENESS_PUBLISH_INTERVAL_S)
    if (
        isinstance(interval, bool)
        or not isinstance(interval, (int, float))
        or not math.isfinite(interval)
        or interval < MIN_LIVENESS_PUBLISH_INTERVAL_S
    ):
        # The scheduler refuses this interval itself; the table still needs a size.
        interval = LIVENESS_PUBLISH_INTERVAL_S
    per_device = default_per_device_bound(float(interval))
    return ReadingAgeTracker(
        LivenessTable(
            per_device_bound=per_device,
            total_bound=max(per_device, DEFAULT_TOTAL_BOUND),
        )
    )


def _build_firmware_command_service(
    config: Config,
    state_store: StateStore,
    liveness_supervisor: FirmwareLivenessSupervisor,
    liveness_table: LivenessTable | None = None,
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
            liveness_table=liveness_table,
        )
    except Exception:
        logger.exception("[runtime] invalid firmware command egress configuration")
        raise
    return publisher, service


def provisioning_anchor_bytes(config: Config) -> bytes | None:
    """The provisioning anchor as raw key material, from the environment it names.

    The reading lives with the other anchors so the CLI bridge resolves the
    same value from the same document; two readings of one anchor is one
    reading too many.
    """
    return provisioning_anchor(config.security)


def build_firmware_liveness_stack(
    config: Config,
    event_bus: EventBus,
    state_store: StateStore,
    deduplicator: EventDeduplicator | None,
    on_telemetry_connected: Callable[[], None] | None = None,
    profiles: ControllerProfileLibrary | None = None,
    alarms: ControllerAlarmTracker | None = None,
    reading_age: ReadingAgeTracker | None = None,
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
        profiles=profiles,
        alarms=alarms,
        reading_age=reading_age,
    )
    # The same table the gate matches nonces against, for the same reason as
    # the shared supervisor: a second one would bound nothing.
    command_pair = _build_firmware_command_service(
        config,
        state_store,
        supervisor,
        None if reading_age is None else reading_age.table,
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
        # so an expired assertion changes nothing until the edge firmware
        # derives reachability from the liveness assertion instead.
        scheduler = FirmwareLivenessScheduler(
            command_pair[1],
            interval_s=float(
                command_cfg.get("liveness_interval_s", LIVENESS_PUBLISH_INTERVAL_S)
            ),
        )
    return supervisor, subscriber, command_pair, scheduler
