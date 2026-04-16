# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from ori.hal.protocol_registry import SUPPORTED_SENSOR_PROTOCOLS

logger = logging.getLogger(__name__)

_VALID_ACTION_TIERS = {"A", "B", "C", "D"}
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

# BCM GPIO pins valid for relay use on Raspberry Pi 4.
# Mirrors ori/actions/relay.py::_VALID_BCM_PINS — kept here to avoid a
# config → actions import.  If the range ever changes, update both.
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


@dataclass
class HalConfig:
    circuit_breaker: dict = field(default_factory=dict)
    external_watchdog: dict = field(default_factory=dict)


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
        logging_cfg = _parse_logging(data.get("logging"))

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
            for v in ("AT_API_KEY", "AT_USERNAME"):
                val = str(actions.sms.get(v, ""))
                if not val or "${" in val:
                    resolved_value = actions.sms.get(v, "")
                    raise ConfigValidationError(
                        f"Environment variable not set: {resolved_value}. "
                        f"Set it in your .env file before starting Ori."
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

        return cls(
            device=device,
            sensors=sensors,
            skills=skills,
            reasoning=reasoning,
            gateway=gateway,
            actions=actions,
            hal=hal,
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

    return DeviceConfig(
        id=device_id,
        name=_require_str(data, "name", "device"),
        location=_require_str(data, "location", "device"),
        rated_capacity_amps=float(data.get("rated_capacity_amps", 10.0)),
        timezone=str(data.get("timezone", "Africa/Lagos")),
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

    return ReasoningConfig(
        default_tier=str(data.get("default_tier", "local")),
        local_model=str(data.get("local_model", "")),
        model_path=str(data.get("model_path", "")),
        offline_fallback=str(data.get("offline_fallback", "rule")),
        escalation_threshold=float(data.get("escalation_threshold", 0.70)),
        energy_aware_reasoning=energy_aware,
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

    return ActionChannelConfig(
        primary_alert_channel=primary,
        operator_contact=str(data.get("operator_contact") or ""),
        secondary_contact=str(data.get("secondary_contact") or ""),
        whatsapp=data.get("whatsapp") or {},
        sms=data.get("sms") or {},
        relay=relay,
        coap=coap,
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

    if not isinstance(data, dict):
        if data is not None:
            logger.warning(
                "[config] 'hal' config missing or not a dict. Falling back to default circuit breaker."
            )
        return HalConfig(
            circuit_breaker=default_cb,
            external_watchdog=default_external_watchdog,
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

    return HalConfig(circuit_breaker=cb_out, external_watchdog=ew_out)


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
