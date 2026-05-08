# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import yaml

from ori.hal.protocol_registry import SUPPORTED_SENSOR_PROTOCOLS

logger = logging.getLogger(__name__)

_VALID_ACTION_TIERS = {"A", "B", "C", "D"}
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

# BCM GPIO pins valid for relay use on Raspberry Pi 4 and CM4 (both BCM2711).
# Mirrors ori/actions/relay.py::_VALID_BCM_PINS — kept here to avoid a
# config → actions import. If the range ever changes, update both.
# If Ori is ported to a non-Broadcom SoC, replace this with a hardware-profile
# abstraction rather than removing startup pin validation.
_VALID_BCM_PINS: frozenset[int] = frozenset(range(2, 28))


class ConfigValidationError(Exception):
    pass


# ─── Dataclasses ──────────────────────────────────────────────────────────────


@dataclass
class DeviceConfig:
    id: str
    name: str
    location: str
    rated_capacity_amps: float = 10.0
    timezone: str = "Africa/Lagos"
    country_code: str = ""
    deployment_type: str = "pi"  # 'pi' | 'phone' | 'server'


@dataclass
class SensorConfig:
    id: str
    type: str
    protocol: str
    poll_interval_ms: int
    metadata: dict = field(default_factory=dict)
    calibration: dict = field(default_factory=dict)


@dataclass
class SkillConfig:
    name: str
    version: str
    config: dict = field(default_factory=dict)


@dataclass
class ReasoningConfig:
    default_tier: str
    local_model: str
    model_path: str
    offline_fallback: str
    escalation_threshold: float = 0.70
    energy_aware_reasoning: dict = field(default_factory=dict)
    capability_posture: dict = field(default_factory=dict)
    causal_memory: dict = field(default_factory=dict)


@dataclass
class GatewayConfig:
    enabled: bool
    broker_url: str


@dataclass
class ActionChannelConfig:
    primary_alert_channel: str  # 'sms' | 'whatsapp'
    operator_contact: str = ""  # phone number for Tier C approvals and emergency SMS
    secondary_contact: str = ""  # escalation contact if operator doesn't respond
    whatsapp: dict = field(default_factory=dict)
    sms: dict = field(default_factory=dict)
    relay: dict = field(default_factory=dict)
    coap: dict = field(default_factory=dict)
    local_console: dict = field(default_factory=dict)
    offline_tokens: dict = field(default_factory=dict)


@dataclass
class HalConfig:
    circuit_breaker: dict = field(default_factory=dict)
    external_watchdog: dict = field(default_factory=dict)
    status_signaling: dict = field(default_factory=dict)


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: str = "ori.log"
    max_bytes: int = 10485760
    backup_count: int = 3
    log_action_decisions: bool = True
    log_approval_workflow: bool = True


@dataclass
class Config:
    device: DeviceConfig
    sensors: list[SensorConfig]
    skills: list[SkillConfig]
    reasoning: ReasoningConfig
    gateway: GatewayConfig
    actions: ActionChannelConfig
    hal: HalConfig
    logging: LoggingConfig
    device_policy: dict = field(default_factory=dict)
    health_socket: dict = field(default_factory=dict)
    os_sandbox: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, path: str) -> "Config":
        try:
            with open(path) as fh:
                raw_text = fh.read()
        except OSError as exc:
            raise ConfigValidationError(
                f"Cannot read config file '{path}': {exc}"
            ) from exc

        expanded = _expand_env_vars(raw_text)

        try:
            data: dict[str, Any] = yaml.safe_load(expanded)
        except yaml.YAMLError as exc:
            raise ConfigValidationError(f"YAML parse error in '{path}': {exc}") from exc

        if not isinstance(data, dict):
            raise ConfigValidationError(
                "Config file must be a YAML mapping at the top level."
            )

        device = _parse_device(data.get("device", {}))
        sensors = _parse_sensors(data.get("sensors", []))
        skills = _parse_skills(data.get("skills", []))
        reasoning = _parse_reasoning(data.get("reasoning", {}))
        gateway = _parse_gateway(data.get("gateway", {}))
        actions = _parse_actions(data.get("actions", {}))
        hal = _parse_hal(data.get("hal"))
        device_policy = _parse_device_policy(data.get("device_policy"))
        health_socket = _parse_health_socket(data.get("health_socket"))
        os_sandbox = _parse_os_sandbox(data.get("os_sandbox"))
        logging_cfg = _parse_logging(data.get("logging"))
        _validate_coap_sensor_allowlist(sensors, actions.coap)

        if not actions.operator_contact or "${" in actions.operator_contact:
            logger.warning(
                "[config] actions.operator_contact is missing or not properly interpolated. Tier C emergency actions will fail."
            )
        if actions.secondary_contact and "${" in actions.secondary_contact:
            logger.warning(
                "[config] actions.secondary_contact contains uninterpolated variable. Escalations may fail."
            )

        whatsapp_enabled = (
            str(actions.whatsapp.get("enabled", "")).lower() == "true"
            or actions.whatsapp.get("enabled") is True
        )
        if whatsapp_enabled:
            for v in (
                "TWILIO_ACCOUNT_SID",
                "TWILIO_AUTH_TOKEN",
                "TWILIO_WHATSAPP_FROM",
            ):
                val = str(actions.whatsapp.get(v, ""))
                if not val or "${" in val:
                    resolved_value = actions.whatsapp.get(v, "")
                    raise ConfigValidationError(
                        f"Environment variable not set: {resolved_value}. "
                        f"Set it in your .env file before starting Ori."
                    )

        sms_enabled = (
            str(actions.sms.get("enabled", "")).lower() == "true"
            or actions.sms.get("enabled") is True
        )
        if sms_enabled:
            sms_transport = str(actions.sms.get("transport", "hybrid")).strip().lower()
            if sms_transport not in {"ip", "gsm", "hybrid"}:
                raise ConfigValidationError(
                    "actions.sms.transport must be one of: ip, gsm, hybrid."
                )

            at_api_key = str(actions.sms.get("AT_API_KEY", ""))
            at_username = str(actions.sms.get("AT_USERNAME", ""))
            ip_configured = bool(
                at_api_key
                and "${" not in at_api_key
                and at_username
                and "${" not in at_username
            )

            gsm_cfg = actions.sms.get("gsm") or {}
            if gsm_cfg and not isinstance(gsm_cfg, dict):
                raise ConfigValidationError("actions.sms.gsm must be a mapping.")
            if not isinstance(gsm_cfg, dict):
                gsm_cfg = {}

            gsm_enabled = (
                str(gsm_cfg.get("enabled", "")).lower() == "true"
                or gsm_cfg.get("enabled") is True
            )
            gsm_port = str(gsm_cfg.get("port", "")).strip()
            if gsm_enabled and not gsm_port:
                raise ConfigValidationError(
                    "actions.sms.gsm.port is required when actions.sms.gsm.enabled=true."
                )

            if gsm_enabled:
                try:
                    baud = int(gsm_cfg.get("baud", 115200))
                except (TypeError, ValueError) as exc:
                    raise ConfigValidationError(
                        "actions.sms.gsm.baud must be a valid integer."
                    ) from exc
                if baud <= 0:
                    raise ConfigValidationError("actions.sms.gsm.baud must be > 0.")
            gsm_configured = bool(gsm_enabled and gsm_port)

            if sms_transport == "ip":
                for v in ("AT_API_KEY", "AT_USERNAME"):
                    val = str(actions.sms.get(v, ""))
                    if not val or "${" in val:
                        resolved_value = actions.sms.get(v, "")
                        raise ConfigValidationError(
                            f"Environment variable not set: {resolved_value}. "
                            f"Set it in your .env file before starting Ori."
                        )

            if sms_transport == "gsm" and not gsm_configured:
                raise ConfigValidationError(
                    "actions.sms.transport=gsm requires actions.sms.gsm.enabled=true and actions.sms.gsm.port."
                )

            if sms_transport == "hybrid":
                # If hybrid explicitly includes AT fields, validate them
                # instead of collapsing to a generic "no path configured" error.
                for v in ("AT_API_KEY", "AT_USERNAME"):
                    if v in actions.sms:
                        val = str(actions.sms.get(v, ""))
                        if not val or "${" in val:
                            resolved_value = actions.sms.get(v, "")
                            raise ConfigValidationError(
                                f"Environment variable not set: {resolved_value}. "
                                f"Set it in your .env file before starting Ori."
                            )

            if sms_transport == "hybrid" and not (ip_configured or gsm_configured):
                raise ConfigValidationError(
                    "actions.sms.transport=hybrid requires at least one configured transport path (IP credentials or GSM modem config)."
                )

            incoming = actions.sms.get("incoming_webhook") or {}
            if isinstance(incoming, dict):
                webhook_enabled = (
                    str(incoming.get("enabled", "")).lower() == "true"
                    or incoming.get("enabled") is True
                )
                if webhook_enabled:
                    token = str(incoming.get("token", ""))
                    if not token or "${" in token:
                        resolved_value = incoming.get("token", "")
                        raise ConfigValidationError(
                            f"Environment variable not set: {resolved_value}. "
                            f"Set it in your .env file before starting Ori."
                        )

        if device.deployment_type == "phone":
            logger.info(
                "[config] phone deployment mode enabled — no GPIO/relay hardware path is expected on this target."
            )
            if bool(actions.relay.get("enabled", False)):
                logger.warning(
                    "[config] deployment_type=phone with actions.relay.enabled=true. "
                    "Relay actions are not supported on phone gateways."
                )

        status_cfg = (
            hal.status_signaling if isinstance(hal.status_signaling, dict) else {}
        )
        if bool(status_cfg.get("enabled", False)):
            relay_pin = actions.relay.get("gpio_pin")
            if relay_pin is not None and int(
                status_cfg.get("relay_led_pin", 27)
            ) == int(relay_pin):
                raise ConfigValidationError(
                    "hal.status_signaling.relay_led_pin conflicts with actions.relay.gpio_pin."
                )

        return cls(
            device=device,
            sensors=sensors,
            skills=skills,
            reasoning=reasoning,
            gateway=gateway,
            actions=actions,
            hal=hal,
            device_policy=device_policy,
            health_socket=health_socket,
            os_sandbox=os_sandbox,
            logging=logging_cfg,
            raw=data,
        )


# ─── Environment variable expansion ───────────────────────────────────────────


def _expand_env_vars(text: str) -> str:
    """Replace ${VAR_NAME} with the environment variable value, or leave as-is."""

    def _replace(match: re.Match) -> str:
        var = match.group(1)
        return os.environ.get(var, match.group(0))

    return _ENV_VAR_RE.sub(_replace, text)


# ─── Section parsers ──────────────────────────────────────────────────────────


def _parse_device(data: Any) -> DeviceConfig:
    if not isinstance(data, dict):
        raise ConfigValidationError("'device' section must be a mapping.")

    device_id = _require_str(data, "id", "device")
    if " " in device_id:
        raise ConfigValidationError(
            f"device.id must not contain spaces, got: '{device_id}'"
        )

    deployment_type = str(data.get("deployment_type", "pi")).strip().lower()
    if deployment_type not in {"pi", "phone", "server"}:
        raise ConfigValidationError(
            "device.deployment_type must be one of ['phone', 'pi', 'server']."
        )
    country_code = str(data.get("country_code", "")).strip().upper()
    if country_code and (len(country_code) != 2 or not country_code.isalpha()):
        raise ConfigValidationError(
            "device.country_code must be a 2-letter ISO country code (e.g. NG, US, KE)."
        )

    return DeviceConfig(
        id=device_id,
        name=_require_str(data, "name", "device"),
        location=_require_str(data, "location", "device"),
        rated_capacity_amps=float(data.get("rated_capacity_amps", 10.0)),
        timezone=str(data.get("timezone", "Africa/Lagos")),
        country_code=country_code,
        deployment_type=deployment_type,
    )


def _parse_sensors(data: Any) -> list[SensorConfig]:
    if not isinstance(data, list):
        raise ConfigValidationError("'sensors' must be a list.")

    sensors = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ConfigValidationError(f"sensors[{i}] must be a mapping.")

        sensor_id = _require_str(item, "id", f"sensors[{i}]")
        protocol = _require_str(item, "protocol", f"sensors[{i}]")
        poll_ms = int(item.get("poll_interval_ms", 1000))

        if not (100 <= poll_ms <= 60_000):
            raise ConfigValidationError(
                f"sensors[{i}] (id={sensor_id!r}): poll_interval_ms must be "
                f"100–60000, got {poll_ms}."
            )
        if protocol not in SUPPORTED_SENSOR_PROTOCOLS:
            raise ConfigValidationError(
                f"sensors[{i}] (id={sensor_id!r}): unknown protocol {protocol!r}. "
                f"Supported protocols: {sorted(SUPPORTED_SENSOR_PROTOCOLS)}."
            )

        # Fields not in the first-class set go into metadata
        known = {"id", "type", "protocol", "poll_interval_ms", "calibration"}
        metadata = {k: v for k, v in item.items() if k not in known}
        if protocol == "coap":
            _validate_coap_sensor_metadata(metadata, f"sensors[{i}]")

        sensors.append(
            SensorConfig(
                id=sensor_id,
                type=_require_str(item, "type", f"sensors[{i}]"),
                protocol=protocol,
                poll_interval_ms=poll_ms,
                metadata=metadata,
                calibration=item.get("calibration") or {},
            )
        )
    return sensors


def _validate_coap_sensor_metadata(metadata: dict[str, Any], section: str) -> None:
    uri = str(metadata.get("uri", "")).strip()
    if not uri:
        raise ConfigValidationError(f"{section}: coap sensors require 'uri'.")
    parsed = urlparse(uri)
    if parsed.scheme not in {"coap", "coaps"}:
        raise ConfigValidationError(
            f"{section}: coap sensor uri must start with coap:// or coaps://."
        )
    if not (parsed.hostname or "").strip():
        raise ConfigValidationError(f"{section}: coap sensor uri host is required.")

    json_path = str(metadata.get("json_path", "")).strip()
    if not json_path:
        raise ConfigValidationError(f"{section}: coap sensors require 'json_path'.")

    method = str(metadata.get("method", "GET")).strip().upper()
    if method not in {"GET", "POST", "PUT", "DELETE"}:
        raise ConfigValidationError(
            f"{section}: coap sensor method must be one of GET/POST/PUT/DELETE."
        )

    if "timeout_s" in metadata:
        try:
            timeout_s = float(metadata.get("timeout_s"))
        except (TypeError, ValueError) as exc:
            raise ConfigValidationError(
                f"{section}: coap sensor timeout_s must be numeric."
            ) from exc
        if timeout_s <= 0:
            raise ConfigValidationError(
                f"{section}: coap sensor timeout_s must be > 0."
            )

    if "allowed_hosts" in metadata:
        sensor_allow = metadata.get("allowed_hosts")
        if not isinstance(sensor_allow, list) or not all(
            isinstance(host, str) and host.strip() for host in sensor_allow
        ):
            raise ConfigValidationError(
                f"{section}: coap sensor allowed_hosts must be a list of non-empty strings."
            )


def _validate_coap_sensor_allowlist(
    sensors: list[SensorConfig], coap_actions_cfg: dict[str, Any]
) -> None:
    coap_sensors = [sensor for sensor in sensors if sensor.protocol == "coap"]
    if not coap_sensors:
        return

    global_allow = coap_actions_cfg.get("allowed_hosts") if coap_actions_cfg else None
    if not isinstance(global_allow, list) or not all(
        isinstance(host, str) and host.strip() for host in global_allow
    ):
        raise ConfigValidationError(
            "actions.coap.allowed_hosts must be configured as a non-empty list "
            "when using protocol=coap sensors."
        )
    global_allow_set = {str(host).strip().lower() for host in global_allow}
    if not global_allow_set:
        raise ConfigValidationError(
            "actions.coap.allowed_hosts must be non-empty when using protocol=coap sensors."
        )

    for sensor in coap_sensors:
        uri = str(sensor.metadata.get("uri", "")).strip()
        host = (urlparse(uri).hostname or "").strip().lower()
        if host and host not in global_allow_set:
            raise ConfigValidationError(
                f"sensors[{sensor.id!r}]: coap uri host {host!r} is not listed in actions.coap.allowed_hosts."
            )


def _parse_skills(data: Any) -> list[SkillConfig]:
    if not isinstance(data, list):
        raise ConfigValidationError("'skills' must be a list.")

    skills = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ConfigValidationError(f"skills[{i}] must be a mapping.")

        skill_cfg: dict = item.get("config") or {}
        _validate_skill_config(skill_cfg, f"skills[{i}]")

        skills.append(
            SkillConfig(
                name=_require_str(item, "name", f"skills[{i}]"),
                version=str(item.get("version", "")),
                config=skill_cfg,
            )
        )
    return skills


def _validate_skill_config(cfg: dict, context: str) -> None:
    """Recursively validate action_tier values within a skill config dict."""
    if not isinstance(cfg, dict):
        return

    for key, value in cfg.items():
        if key == "action_tier":
            if value not in _VALID_ACTION_TIERS:
                raise ConfigValidationError(
                    f"{context}.config.action_tier must be one of "
                    f"{sorted(_VALID_ACTION_TIERS)}, got: {value!r}"
                )
        if isinstance(value, dict):
            _validate_skill_config(value, f"{context}.config.{key}")
        if isinstance(value, list):
            for j, entry in enumerate(value):
                if isinstance(entry, dict):
                    _validate_skill_config(entry, f"{context}.config.{key}[{j}]")


def _parse_reasoning(data: Any) -> ReasoningConfig:
    if not isinstance(data, dict):
        raise ConfigValidationError("'reasoning' section must be a mapping.")

    energy_aware = data.get("energy_aware_reasoning") or {}
    if not isinstance(energy_aware, dict):
        raise ConfigValidationError(
            "'reasoning.energy_aware_reasoning' must be a mapping when provided."
        )
    causal_memory = data.get("causal_memory") or {}
    if not isinstance(causal_memory, dict):
        raise ConfigValidationError(
            "'reasoning.causal_memory' must be a mapping when provided."
        )
    capability_posture = data.get("capability_posture") or {}
    if not isinstance(capability_posture, dict):
        raise ConfigValidationError(
            "'reasoning.capability_posture' must be a mapping when provided."
        )

    try:
        probe_interval_seconds = int(
            capability_posture.get("probe_interval_seconds", 30)
        )
        gateway_heartbeat_ttl_seconds = int(
            capability_posture.get("gateway_heartbeat_ttl_seconds", 30)
        )
        internet_probe_timeout_ms = int(
            capability_posture.get("internet_probe_timeout_ms", 1000)
        )
        internet_probe_port = int(capability_posture.get("internet_probe_port", 53))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "reasoning.capability_posture numeric fields must be valid integers."
        ) from exc

    if not (1 <= probe_interval_seconds <= 30):
        raise ConfigValidationError(
            "reasoning.capability_posture.probe_interval_seconds must be between 1 and 30."
        )
    if gateway_heartbeat_ttl_seconds < 1:
        raise ConfigValidationError(
            "reasoning.capability_posture.gateway_heartbeat_ttl_seconds must be >= 1."
        )
    if internet_probe_timeout_ms < 100:
        raise ConfigValidationError(
            "reasoning.capability_posture.internet_probe_timeout_ms must be >= 100."
        )
    if not (1 <= internet_probe_port <= 65535):
        raise ConfigValidationError(
            "reasoning.capability_posture.internet_probe_port must be between 1 and 65535."
        )
    internet_probe_host = str(
        capability_posture.get("internet_probe_host", "one.one.one.one")
    ).strip()
    if not internet_probe_host:
        raise ConfigValidationError(
            "reasoning.capability_posture.internet_probe_host must not be empty."
        )

    capability_posture_cfg = {
        "enabled": (
            str(capability_posture.get("enabled", "true")).strip().lower() == "true"
            or capability_posture.get("enabled") is True
        ),
        "probe_interval_seconds": probe_interval_seconds,
        "gateway_heartbeat_ttl_seconds": gateway_heartbeat_ttl_seconds,
        "internet_probe_timeout_ms": internet_probe_timeout_ms,
        "internet_probe_port": internet_probe_port,
        "internet_probe_host": internet_probe_host,
    }

    return ReasoningConfig(
        default_tier=str(data.get("default_tier", "local")),
        local_model=str(data.get("local_model", "")),
        model_path=str(data.get("model_path", "")),
        offline_fallback=str(data.get("offline_fallback", "rule")),
        escalation_threshold=float(data.get("escalation_threshold", 0.70)),
        energy_aware_reasoning=energy_aware,
        capability_posture=capability_posture_cfg,
        causal_memory=causal_memory,
    )


def _parse_gateway(data: Any) -> GatewayConfig:
    if not isinstance(data, dict):
        raise ConfigValidationError("'gateway' section must be a mapping.")

    return GatewayConfig(
        enabled=bool(data.get("enabled", False)),
        broker_url=str(data.get("broker_url", "")),
    )


def _parse_actions(data: Any) -> ActionChannelConfig:
    if not isinstance(data, dict):
        raise ConfigValidationError("'actions' section must be a mapping.")

    primary = str(data.get("primary_alert_channel", "sms"))
    if primary not in {"sms", "whatsapp"}:
        raise ConfigValidationError(
            f"actions.primary_alert_channel must be 'sms' or 'whatsapp', "
            f"got: {primary!r}"
        )

    relay_raw: dict = data.get("relay") or {}
    relay: dict = dict(relay_raw)

    relay_enabled = (
        str(relay.get("enabled", "")).lower() == "true" or relay.get("enabled") is True
    )

    if relay_enabled and "gpio_pin" not in relay:
        raise ConfigValidationError(
            "actions.relay.enabled is true but no 'gpio_pin' is configured. "
            "A valid BCM gpio_pin must be provided to use relay actions."
        )

    if "gpio_pin" in relay:
        relay["gpio_pin"] = int(relay["gpio_pin"])
        if relay["gpio_pin"] not in _VALID_BCM_PINS:
            raise ConfigValidationError(
                f"actions.relay.gpio_pin={relay['gpio_pin']} is outside the "
                f"valid BCM range (2-27) for Raspberry Pi 4. "
                f"Misconfigured pins must be caught at startup, not during "
                f"a safety action. Check ori.yaml."
            )

    coap_raw = data.get("coap") or {}
    if not isinstance(coap_raw, dict):
        raise ConfigValidationError("'actions.coap' must be a mapping when provided.")
    coap = dict(coap_raw)

    coap_enabled = (
        str(coap.get("enabled", "")).lower() == "true" or coap.get("enabled") is True
    )
    if coap_enabled:
        commands = coap.get("commands") or {}
        if not isinstance(commands, dict):
            raise ConfigValidationError(
                "actions.coap.commands must be a mapping when coap is enabled."
            )
        for command_name, spec in commands.items():
            if not isinstance(spec, dict):
                raise ConfigValidationError(
                    f"actions.coap.commands.{command_name} must be a mapping."
                )
            uri = str(spec.get("uri", "")).strip()
            method = str(spec.get("method", "POST")).strip().upper()
            if not uri:
                raise ConfigValidationError(
                    f"actions.coap.commands.{command_name}.uri is required."
                )
            if not uri.startswith(("coap://", "coaps://")):
                raise ConfigValidationError(
                    f"actions.coap.commands.{command_name}.uri must start with coap:// or coaps://."
                )
            if method not in {"GET", "POST", "PUT", "DELETE"}:
                raise ConfigValidationError(
                    f"actions.coap.commands.{command_name}.method must be one of GET/POST/PUT/DELETE."
                )

        allowed_hosts = coap.get("allowed_hosts") or []
        if (
            not isinstance(allowed_hosts, list)
            or len(allowed_hosts) == 0
            or not all(isinstance(host, str) and host.strip() for host in allowed_hosts)
        ):
            raise ConfigValidationError(
                "actions.coap.allowed_hosts must be a non-empty list of hostnames/IPs when coap is enabled."
            )

    local_console_raw = data.get("local_console") or {}
    if not isinstance(local_console_raw, dict):
        raise ConfigValidationError(
            "'actions.local_console' must be a mapping when provided."
        )
    local_console = {
        "enabled": bool(local_console_raw.get("enabled", False)),
        "poll_interval_ms": int(local_console_raw.get("poll_interval_ms", 1000)),
        "approval_channel_id": str(
            local_console_raw.get("approval_channel_id", "local_console")
        ),
    }
    if local_console["poll_interval_ms"] < 100:
        raise ConfigValidationError(
            "actions.local_console.poll_interval_ms must be >= 100."
        )

    offline_tokens_raw = data.get("offline_tokens") or {}
    if not isinstance(offline_tokens_raw, dict):
        raise ConfigValidationError(
            "'actions.offline_tokens' must be a mapping when provided."
        )
    offline_tokens = {
        "enabled": bool(offline_tokens_raw.get("enabled", False)),
        "public_key_b64": str(offline_tokens_raw.get("public_key_b64", "")),
        "max_clock_skew_s": int(offline_tokens_raw.get("max_clock_skew_s", 300)),
    }
    if offline_tokens["max_clock_skew_s"] < 0:
        raise ConfigValidationError(
            "actions.offline_tokens.max_clock_skew_s must be >= 0."
        )
    if offline_tokens["enabled"]:
        public_key = offline_tokens["public_key_b64"]
        if not public_key or "${" in public_key:
            raise ConfigValidationError(
                "actions.offline_tokens.enabled=true requires actions.offline_tokens.public_key_b64."
            )

    return ActionChannelConfig(
        primary_alert_channel=primary,
        operator_contact=str(data.get("operator_contact") or ""),
        secondary_contact=str(data.get("secondary_contact") or ""),
        whatsapp=data.get("whatsapp") or {},
        sms=data.get("sms") or {},
        relay=relay,
        coap=coap,
        local_console=local_console,
        offline_tokens=offline_tokens,
    )


def _parse_hal(data: Any) -> HalConfig:
    """Parse the HAL block gracefully, enforcing safe defaults on failure."""
    default_cb = {
        "failure_threshold": 5,
        "recovery_timeout_s": 300,
        "success_threshold": 2,
    }
    default_external_watchdog = {
        "enabled": False,
        "gpio_pin": 17,
        "ping_interval_s": 30,
    }
    default_status_signaling = {
        "enabled": False,
        "power_led_pin": 17,
        "relay_led_pin": 27,
        "network_led_pin": 22,
        "health_led_pin": 23,
        "buzzer_pin": 24,
        "tick_ms": 100,
    }

    if not isinstance(data, dict):
        if data is not None:
            logger.warning(
                "[config] 'hal' config missing or not a dict. Falling back to default circuit breaker."
            )
        return HalConfig(
            circuit_breaker=default_cb,
            external_watchdog=default_external_watchdog,
            status_signaling=default_status_signaling,
        )

    cb_data = data.get("circuit_breaker")
    if not isinstance(cb_data, dict):
        if cb_data is not None:
            logger.warning(
                "[config] 'hal.circuit_breaker' missing or not a dict. Falling back to default circuit breaker."
            )
        cb_out = default_cb
    else:
        try:
            cb_out = {
                "failure_threshold": int(cb_data.get("failure_threshold", 5)),
                "recovery_timeout_s": int(cb_data.get("recovery_timeout_s", 300)),
                "success_threshold": int(cb_data.get("success_threshold", 2)),
            }
        except (ValueError, TypeError):
            logger.warning(
                "[config] 'hal.circuit_breaker' has invalid types. Falling back to default circuit breaker."
            )
            cb_out = default_cb
        else:
            if cb_out["failure_threshold"] < 1:
                raise ConfigValidationError(
                    "hal.circuit_breaker.failure_threshold must be >= 1."
                )
            if cb_out["recovery_timeout_s"] < 1:
                raise ConfigValidationError(
                    "hal.circuit_breaker.recovery_timeout_s must be >= 1."
                )
            if cb_out["success_threshold"] < 1:
                raise ConfigValidationError(
                    "hal.circuit_breaker.success_threshold must be >= 1."
                )

    ew_data = data.get("external_watchdog")
    if ew_data is None:
        ew_out = default_external_watchdog
    elif not isinstance(ew_data, dict):
        logger.warning(
            "[config] 'hal.external_watchdog' is not a mapping. Falling back to defaults."
        )
        ew_out = default_external_watchdog
    else:
        try:
            ew_out = {
                "enabled": bool(ew_data.get("enabled", False)),
                "gpio_pin": int(ew_data.get("gpio_pin", 17)),
                "ping_interval_s": int(ew_data.get("ping_interval_s", 30)),
            }
        except (TypeError, ValueError):
            logger.warning(
                "[config] 'hal.external_watchdog' has invalid types. Falling back to defaults."
            )
            ew_out = default_external_watchdog

    if ew_out["gpio_pin"] not in _VALID_BCM_PINS:
        raise ConfigValidationError(
            f"hal.external_watchdog.gpio_pin={ew_out['gpio_pin']} is outside the "
            "valid BCM range (2-27) for Raspberry Pi 4."
        )
    if ew_out["ping_interval_s"] < 1:
        raise ConfigValidationError(
            "hal.external_watchdog.ping_interval_s must be >= 1."
        )

    ss_data = data.get("status_signaling")
    if ss_data is None:
        ss_out = default_status_signaling
    elif not isinstance(ss_data, dict):
        logger.warning(
            "[config] 'hal.status_signaling' is not a mapping. Falling back to defaults."
        )
        ss_out = default_status_signaling
    else:
        try:
            ss_out = {
                "enabled": bool(ss_data.get("enabled", False)),
                "power_led_pin": int(ss_data.get("power_led_pin", 17)),
                "relay_led_pin": int(ss_data.get("relay_led_pin", 27)),
                "network_led_pin": int(ss_data.get("network_led_pin", 22)),
                "health_led_pin": int(ss_data.get("health_led_pin", 23)),
                "buzzer_pin": int(ss_data.get("buzzer_pin", 24)),
                "tick_ms": int(ss_data.get("tick_ms", 100)),
            }
        except (TypeError, ValueError):
            logger.warning(
                "[config] 'hal.status_signaling' has invalid types. Falling back to defaults."
            )
            ss_out = default_status_signaling

    for key in (
        "power_led_pin",
        "relay_led_pin",
        "network_led_pin",
        "health_led_pin",
        "buzzer_pin",
    ):
        pin = int(ss_out[key])
        if pin not in _VALID_BCM_PINS:
            raise ConfigValidationError(
                f"hal.status_signaling.{key}={pin} is outside the valid BCM range (2-27) for Raspberry Pi 4."
            )

    ss_pins = [
        int(ss_out["power_led_pin"]),
        int(ss_out["relay_led_pin"]),
        int(ss_out["network_led_pin"]),
        int(ss_out["health_led_pin"]),
        int(ss_out["buzzer_pin"]),
    ]
    if len(set(ss_pins)) != len(ss_pins):
        raise ConfigValidationError(
            "hal.status_signaling pins must be unique (no duplicate BCM pin assignments)."
        )
    if int(ss_out["tick_ms"]) < 50:
        raise ConfigValidationError("hal.status_signaling.tick_ms must be >= 50.")

    if bool(ss_out.get("enabled")) and bool(ew_out.get("enabled")):
        ew_pin = int(ew_out["gpio_pin"])
        for key in (
            "power_led_pin",
            "relay_led_pin",
            "network_led_pin",
            "health_led_pin",
            "buzzer_pin",
        ):
            if int(ss_out[key]) == ew_pin:
                raise ConfigValidationError(
                    f"hal.status_signaling.{key} conflicts with hal.external_watchdog.gpio_pin."
                )

    return HalConfig(
        circuit_breaker=cb_out,
        external_watchdog=ew_out,
        status_signaling=ss_out,
    )


def _parse_device_policy(data: Any) -> dict:
    """Parse remote DevicePolicy fetch settings."""
    default_policy = {
        "enabled": False,
        "url": "",
        "auth_token": "",
        "public_key_b64": "",
        "request_timeout_ms": 3000,
        "max_clock_skew_s": 300,
        "refresh_enabled": False,
        "refresh_interval_s": 21600,
    }

    if data is None:
        return default_policy

    if not isinstance(data, dict):
        logger.warning(
            "[config] 'device_policy' is not a mapping. Falling back to defaults."
        )
        return default_policy

    try:
        out = {
            "enabled": bool(data.get("enabled", False)),
            "url": str(data.get("url", "") or "").strip(),
            "auth_token": str(data.get("auth_token", "") or "").strip(),
            "public_key_b64": str(data.get("public_key_b64", "") or "").strip(),
            "request_timeout_ms": int(data.get("request_timeout_ms", 3000)),
            "max_clock_skew_s": int(data.get("max_clock_skew_s", 300)),
            "refresh_enabled": bool(data.get("refresh_enabled", False)),
            "refresh_interval_s": int(data.get("refresh_interval_s", 21600)),
        }
    except (TypeError, ValueError):
        logger.warning(
            "[config] 'device_policy' has invalid types. Falling back to defaults."
        )
        return default_policy

    if out["request_timeout_ms"] < 100:
        raise ConfigValidationError("device_policy.request_timeout_ms must be >= 100.")
    if out["max_clock_skew_s"] < 1:
        raise ConfigValidationError("device_policy.max_clock_skew_s must be >= 1.")
    if out["refresh_interval_s"] < 60:
        raise ConfigValidationError("device_policy.refresh_interval_s must be >= 60.")

    if out["enabled"]:
        if not out["url"]:
            raise ConfigValidationError(
                "device_policy.enabled is true but 'url' is empty."
            )
        if not out["url"].startswith("https://"):
            raise ConfigValidationError(
                "device_policy.url must start with https:// when enabled."
            )
        if not out["auth_token"] or "${" in out["auth_token"]:
            raise ConfigValidationError(
                "device_policy.auth_token is missing or not properly interpolated."
            )
        if not out["public_key_b64"] or "${" in out["public_key_b64"]:
            raise ConfigValidationError(
                "device_policy.public_key_b64 is missing or not properly interpolated."
            )

    return out


def _parse_health_socket(data: Any) -> dict:
    """Parse local read-only health socket configuration."""
    default_socket = {
        "enabled": True,
        "path": "/run/ori/health.sock",
        "mode": 0o660,
    }

    if data is None:
        return default_socket

    if not isinstance(data, dict):
        logger.warning(
            "[config] 'health_socket' is not a mapping. Falling back to defaults."
        )
        return default_socket

    out = dict(default_socket)
    out["enabled"] = bool(data.get("enabled", default_socket["enabled"]))

    path = str(data.get("path", default_socket["path"]) or "").strip()
    if not path:
        raise ConfigValidationError("health_socket.path must not be empty.")
    if "\x00" in path:
        raise ConfigValidationError("health_socket.path contains invalid null bytes.")
    out["path"] = path

    raw_mode = data.get("mode", default_socket["mode"])
    try:
        if isinstance(raw_mode, str):
            mode = int(raw_mode, 0)
        else:
            mode = int(raw_mode)
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "health_socket.mode must be a valid integer (e.g. 0o660)."
        ) from exc
    if mode < 0 or mode > 0o777:
        raise ConfigValidationError("health_socket.mode must be between 0 and 0o777.")
    out["mode"] = mode

    return out


def _parse_os_sandbox(data: Any) -> dict:
    """Parse community skill OS sandbox settings."""
    defaults = {
        "enabled": True,
        "require_for_community": False,
        "exec_timeout_ms": 2000,
        "max_output_bytes": 65536,
    }
    if data is None:
        return defaults
    if not isinstance(data, dict):
        logger.warning(
            "[config] 'os_sandbox' is not a mapping. Falling back to defaults."
        )
        return defaults

    out = dict(defaults)
    out["enabled"] = bool(data.get("enabled", True))
    out["require_for_community"] = bool(data.get("require_for_community", False))
    try:
        out["exec_timeout_ms"] = int(data.get("exec_timeout_ms", 2000))
        out["max_output_bytes"] = int(data.get("max_output_bytes", 65536))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "os_sandbox.exec_timeout_ms and os_sandbox.max_output_bytes must be integers."
        ) from exc
    if out["exec_timeout_ms"] < 100:
        raise ConfigValidationError("os_sandbox.exec_timeout_ms must be >= 100.")
    if out["max_output_bytes"] < 4096:
        raise ConfigValidationError("os_sandbox.max_output_bytes must be >= 4096.")
    return out


def _parse_logging(data: Any) -> LoggingConfig:
    if not isinstance(data, dict):
        if data is not None:
            logger.warning(
                "[config] 'logging' section is not a mapping. Using defaults."
            )
        return LoggingConfig()

    try:
        max_bytes = int(data.get("max_bytes", 10485760))
        backup_count = int(data.get("backup_count", 3))
    except (ValueError, TypeError):
        max_bytes = 10485760
        backup_count = 3

    return LoggingConfig(
        level=str(data.get("level", "INFO")),
        file=str(data.get("file", "ori.log")),
        max_bytes=max_bytes,
        backup_count=backup_count,
        log_action_decisions=bool(data.get("log_action_decisions", True)),
        log_approval_workflow=bool(data.get("log_approval_workflow", True)),
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _require_str(data: dict, key: str, context: str) -> str:
    value = data.get(key)
    if value is None:
        raise ConfigValidationError(f"'{context}.{key}' is required but missing.")
    return str(value)
