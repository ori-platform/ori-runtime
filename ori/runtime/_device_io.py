# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""What the runtime hands to devices: an adapter's connect configuration, a
CoAP command resolved from a skill context, and the status indicator's state."""

from typing import Any

from ori.config import Config, SensorConfig
from ori.hardware.led_indicator import LEDIndicator, NetworkState, PowerState
from ori.reasoning.capability_posture import CapabilityPosture
from ori.reasoning.elevator import SkillContext


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


def sync_network_state_from_posture(
    indicator: LEDIndicator, posture: CapabilityPosture
) -> None:
    if posture.internet_available:
        indicator.set_network_state(NetworkState.INTERNET)
        return
    if posture.sms_available:
        indicator.set_network_state(NetworkState.GSM_ONLY)
        return
    indicator.set_network_state(NetworkState.NONE)


def sync_power_state_from_reading(indicator: LEDIndicator, reading: Any) -> None:
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


def coap_command_from_context(ctx: SkillContext) -> tuple[str, str | None]:
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
