# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_VALID_ACTION_TIERS = {"A", "B", "C", "D"}
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigValidationError(Exception):
    pass


# ─── Dataclasses ──────────────────────────────────────────────────────────────


@dataclass
class DeviceConfig:
    id: str
    name: str
    location: str
    rated_capacity_amps: float = 10.0


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


@dataclass
class GatewayConfig:
    enabled: bool
    broker_url: str


@dataclass
class ActionChannelConfig:
    primary_alert_channel: str  # 'sms' | 'whatsapp'
    whatsapp: dict = field(default_factory=dict)
    sms: dict = field(default_factory=dict)
    relay: dict = field(default_factory=dict)


@dataclass
class Config:
    device: DeviceConfig
    sensors: list[SensorConfig]
    skills: list[SkillConfig]
    reasoning: ReasoningConfig
    gateway: GatewayConfig
    actions: ActionChannelConfig
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

        whatsapp_enabled = (
            str(actions.whatsapp.get("enabled", "")).lower() == "true"
            or actions.whatsapp.get("enabled") is True
        )
        if whatsapp_enabled:
            for v in (
                "TWILIO_ACCOUNT_SID",
                "TWILIO_AUTH_TOKEN",
                "TWILIO_WHATSAPP_FROM",
                "OWNER_WHATSAPP_NUMBER",
            ):
                val = str(actions.whatsapp.get(v, ""))
                if not val or "${" in val:
                    resolved_value = actions.whatsapp.get(v, "")
                    raise ConfigValidationError(
                        f"Environment variable not set: {resolved_value}. "
                        f"Set it in your .env file before starting Ori."
                    )

        sec_whatsapp = str(actions.whatsapp.get("SECONDARY_WHATSAPP", ""))
        if "${" in sec_whatsapp:
            logger.warning(
                "SECONDARY_WHATSAPP missing. Tier C escalation will not function if operator does not respond."
            )

        sms_enabled = (
            str(actions.sms.get("enabled", "")).lower() == "true"
            or actions.sms.get("enabled") is True
        )
        if sms_enabled:
            for v in ("AT_API_KEY", "AT_USERNAME", "OWNER_PHONE_NUMBER"):
                val = str(actions.sms.get(v, ""))
                if not val or "${" in val:
                    resolved_value = actions.sms.get(v, "")
                    raise ConfigValidationError(
                        f"Environment variable not set: {resolved_value}. "
                        f"Set it in your .env file before starting Ori."
                    )

        return cls(
            device=device,
            sensors=sensors,
            skills=skills,
            reasoning=reasoning,
            gateway=gateway,
            actions=actions,
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

    return DeviceConfig(
        id=device_id,
        name=_require_str(data, "name", "device"),
        location=_require_str(data, "location", "device"),
        rated_capacity_amps=float(data.get("rated_capacity_amps", 10.0)),
    )


def _parse_sensors(data: Any) -> list[SensorConfig]:
    if not isinstance(data, list):
        raise ConfigValidationError("'sensors' must be a list.")

    sensors = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ConfigValidationError(f"sensors[{i}] must be a mapping.")

        sensor_id = _require_str(item, "id", f"sensors[{i}]")
        poll_ms = int(item.get("poll_interval_ms", 1000))

        if not (100 <= poll_ms <= 60_000):
            raise ConfigValidationError(
                f"sensors[{i}] (id={sensor_id!r}): poll_interval_ms must be "
                f"100–60000, got {poll_ms}."
            )

        # Fields not in the first-class set go into metadata
        known = {"id", "type", "protocol", "poll_interval_ms", "calibration"}
        metadata = {k: v for k, v in item.items() if k not in known}

        sensors.append(
            SensorConfig(
                id=sensor_id,
                type=_require_str(item, "type", f"sensors[{i}]"),
                protocol=_require_str(item, "protocol", f"sensors[{i}]"),
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

    return ReasoningConfig(
        default_tier=str(data.get("default_tier", "local")),
        local_model=str(data.get("local_model", "")),
        model_path=str(data.get("model_path", "")),
        offline_fallback=str(data.get("offline_fallback", "rule")),
        escalation_threshold=float(data.get("escalation_threshold", 0.70)),
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

    return ActionChannelConfig(
        primary_alert_channel=primary,
        whatsapp=data.get("whatsapp") or {},
        sms=data.get("sms") or {},
        relay=relay,
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _require_str(data: dict, key: str, context: str) -> str:
    value = data.get(key)
    if value is None:
        raise ConfigValidationError(f"'{context}.{key}' is required but missing.")
    return str(value)
