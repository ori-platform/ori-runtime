# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_network
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from ori.hal.protocol_registry import SUPPORTED_SENSOR_PROTOCOLS
from ori.security.config_signatures import (
    CONFIG_REQUIRE_SIGNED_ENV,
    DEFAULT_CONFIG_TRUST_ANCHOR_ENV,
    ConfigSignatureError,
    config_signature_policy_from_raw_config,
    verify_config_signature_if_needed,
)
from ori.security.remote_command_lockout import normalize_remote_command_lockout_config
from ori.security.remote_commands import normalize_remote_command_sender
from ori.utils.bool_utils import is_truthy
from ori.utils.path_utils import path_is_relative_to

logger = logging.getLogger(__name__)

_VALID_ACTION_TIERS = {"A", "B", "C", "D"}
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# BCM GPIO pins valid for relay use on Raspberry Pi 4 and CM4 (both BCM2711).
# Mirrors ori/actions/relay.py::_VALID_BCM_PINS — kept here to avoid a
# config → actions import. If the range ever changes, update both.
# If Ori is ported to a non-Broadcom SoC, replace this with a hardware-profile
# abstraction rather than removing startup pin validation.
_VALID_BCM_PINS: frozenset[int] = frozenset(range(2, 28))


class ConfigValidationError(Exception):
    pass


def _validate_iana_timezone(tz_name: str) -> bool:
    try:
        ZoneInfo(tz_name)
        return True
    except ZoneInfoNotFoundError:
        return False


def _detect_host_timezone() -> str | None:
    """Best-effort host timezone detection using IANA names only."""
    tz_env = str(os.environ.get("TZ", "")).strip()
    if tz_env and _validate_iana_timezone(tz_env):
        return tz_env

    local_tz = datetime.now().astimezone().tzinfo
    key = str(getattr(local_tz, "key", "") or "").strip()
    if key and _validate_iana_timezone(key):
        return key
    return None


def _resolve_device_timezone(raw_value: Any) -> str:
    """Resolve runtime timezone: config value -> host timezone -> UTC."""
    configured = str(raw_value or "").strip()
    if configured:
        if _validate_iana_timezone(configured):
            return configured
        logger.warning(
            "[config] device.timezone=%r is invalid; attempting host timezone fallback.",
            configured,
        )

    host_tz = _detect_host_timezone()
    if host_tz:
        logger.info("[config] using host timezone fallback: %s", host_tz)
        return host_tz

    logger.warning(
        "[config] unable to resolve device timezone from config/host; falling back to UTC."
    )
    return str(timezone.utc)


# ─── Dataclasses ──────────────────────────────────────────────────────────────


@dataclass
class DeviceConfig:
    id: str
    name: str
    location: str
    rated_capacity_amps: float = 10.0
    timezone: str = "Africa/Lagos"
    country_code: str = ""
    deployment_type: str = "pi"  # 'pi' | 'phone' | 'edge_node' | 'server'
    deployment_profile: str = "development"  # 'development' | 'staging' | 'production'
    site_type: str = ""  # business/site context, e.g. pharmacy | office | factory


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
    escalation_threshold: float = 0.70
    energy_aware_reasoning: dict = field(default_factory=dict)
    capability_posture: dict = field(default_factory=dict)
    causal_memory: dict = field(default_factory=dict)
    context_enricher: dict = field(default_factory=dict)


@dataclass
class GatewayConfig:
    enabled: bool
    broker_url: str
    reasoning: dict = field(default_factory=dict)
    node_heartbeat: dict = field(default_factory=dict)
    auth: dict = field(default_factory=dict)
    tls: dict = field(default_factory=dict)
    encryption: dict = field(default_factory=dict)
    broker_posture: dict = field(default_factory=dict)


@dataclass
class TelemetryExportConfig:
    enabled: bool = False
    endpoint: str = ""
    api_key_env: str = ""
    flush_interval_s: float = 30.0
    batch_size: int = 50
    timeout_ms: int = 3000
    max_queue_size: int = 1000


@dataclass
class ActionChannelConfig:
    primary_alert_channel: str  # 'sms' | 'whatsapp'
    operator_contact: str = ""  # phone number for Tier C approvals and emergency SMS
    secondary_contact: str = ""  # escalation contact if operator doesn't respond
    approval_require_scoped_replies: bool = True
    whatsapp: dict = field(default_factory=dict)
    sms: dict = field(default_factory=dict)
    relay: dict = field(default_factory=dict)
    coap: dict = field(default_factory=dict)
    local_console: dict = field(default_factory=dict)
    offline_tokens: dict = field(default_factory=dict)
    alert_outbox: dict = field(default_factory=dict)
    setup_notifications: dict = field(default_factory=dict)


@dataclass
class HalConfig:
    circuit_breaker: dict = field(default_factory=dict)
    external_watchdog: dict = field(default_factory=dict)
    status_signaling: dict = field(default_factory=dict)


@dataclass
class CompactionConfig:
    max_backward_skew_ms: int = 3600000


@dataclass
class StateEncryptionConfig:
    mode: str = "disabled"
    encrypted_path_prefixes: list[str] = field(default_factory=list)
    marker_file: str = ""


@dataclass
class StateConfig:
    compaction: CompactionConfig = field(default_factory=CompactionConfig)
    encryption: StateEncryptionConfig = field(default_factory=StateEncryptionConfig)


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: str = "ori.log"
    max_bytes: int = 10485760
    backup_count: int = 3
    log_action_decisions: bool = True
    log_approval_workflow: bool = True


@dataclass
class EvidenceConfig:
    """On-device evidence signing (Verity chain) configuration."""

    enabled: bool = False
    db_path: str = "ori_verity.db"
    key_path: str = "ori_verity.key"
    device_secret_env: str = "ORI_EVIDENCE_DEVICE_SECRET"


@dataclass
class Config:
    device: DeviceConfig
    sensors: list[SensorConfig]
    skills: list[SkillConfig]
    reasoning: ReasoningConfig
    gateway: GatewayConfig
    telemetry_export: TelemetryExportConfig
    actions: ActionChannelConfig
    hal: HalConfig
    logging: LoggingConfig
    database_path: str = "ori_state.db"
    device_policy: dict = field(default_factory=dict)
    security: dict = field(default_factory=dict)
    health_socket: dict = field(default_factory=dict)
    os_sandbox: dict = field(default_factory=dict)
    state: StateConfig = field(default_factory=StateConfig)
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)
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

        try:
            raw_unexpanded = yaml.safe_load(raw_text)
        except yaml.YAMLError as exc:
            raise ConfigValidationError(f"YAML parse error in '{path}': {exc}") from exc

        if not isinstance(raw_unexpanded, dict):
            raise ConfigValidationError(
                "Config file must be a YAML mapping at the top level."
            )

        try:
            config_signature_policy = config_signature_policy_from_raw_config(
                raw_unexpanded
            )
            config_signature_verification = verify_config_signature_if_needed(
                raw_unexpanded,
                config_signature_policy,
            )
        except ConfigSignatureError as exc:
            raise ConfigValidationError(str(exc)) from exc

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
        telemetry_export = _parse_telemetry_export(data.get("telemetry_export"))
        actions = _parse_actions(data.get("actions", {}))
        hal = _parse_hal(data.get("hal"))
        device_policy = _parse_device_policy(data.get("device_policy"))
        security = _parse_security(data.get("security"))
        security["config_signature"]["verified"] = (
            config_signature_verification.verified
        )
        security["config_signature"]["required"] = (
            config_signature_verification.required
        )
        security["config_signature"]["trust_anchor_env"] = (
            config_signature_verification.trust_anchor_env
        )
        security["config_signature"]["signer_id"] = (
            config_signature_verification.signer_id
        )
        security["config_signature"]["signed_at_ms"] = (
            config_signature_verification.signed_at_ms
        )
        health_socket = _parse_health_socket(data.get("health_socket"))
        os_sandbox = _parse_os_sandbox(data.get("os_sandbox"))
        state_cfg = _parse_state(data.get("state"))
        evidence_cfg = _parse_evidence(data.get("evidence"))
        database_path = _parse_database_path(data.get("database"))
        logging_cfg = _parse_logging(data.get("logging"))
        _validate_coap_sensor_allowlist(sensors, actions.coap)
        _warn_gateway_network_posture(gateway)
        _validate_production_security_posture(
            device=device,
            gateway=gateway,
            actions=actions,
            security=security,
            state=state_cfg,
            database_path=database_path,
            config_signature_verified=config_signature_verification.verified,
        )

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
            twilio_from = str(actions.whatsapp.get("TWILIO_WHATSAPP_FROM", "")).strip()
            if not twilio_from.lower().startswith("whatsapp:+"):
                raise ConfigValidationError(
                    "actions.whatsapp.TWILIO_WHATSAPP_FROM must start with 'whatsapp:+' "
                    "(example: 'whatsapp:+14155238886')."
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
                    _validate_sms_webhook_source_cidrs(
                        incoming.get("allowed_source_cidrs")
                    )
                    signature_cfg = incoming.get("signature") or {}
                    if signature_cfg and not isinstance(signature_cfg, dict):
                        raise ConfigValidationError(
                            "actions.sms.incoming_webhook.signature must be a mapping."
                        )
                    mode = "token_only"
                    if isinstance(signature_cfg, dict):
                        mode = (
                            str(signature_cfg.get("mode", "token_only")).strip().lower()
                        )
                        if mode not in {
                            "token_only",
                            "hmac_required",
                            "token_and_hmac",
                        }:
                            raise ConfigValidationError(
                                "actions.sms.incoming_webhook.signature.mode must be one of: "
                                "token_only, hmac_required, token_and_hmac."
                            )
                    token = str(incoming.get("token", ""))
                    if mode != "hmac_required" and (not token or "${" in token):
                        resolved_value = incoming.get("token", "")
                        raise ConfigValidationError(
                            f"Environment variable not set: {resolved_value}. "
                            f"Set it in your .env file before starting Ori."
                        )
                    if isinstance(signature_cfg, dict):
                        if mode != "token_only":
                            secret = str(signature_cfg.get("shared_secret", ""))
                            if not secret or "${" in secret:
                                resolved_value = signature_cfg.get("shared_secret", "")
                                raise ConfigValidationError(
                                    f"Environment variable not set: {resolved_value}. "
                                    f"Set it in your .env file before starting Ori."
                                )
                            previous_secret = str(
                                signature_cfg.get("previous_shared_secret", "")
                            )
                            if previous_secret and "${" in previous_secret:
                                resolved_value = signature_cfg.get(
                                    "previous_shared_secret", ""
                                )
                                raise ConfigValidationError(
                                    f"Environment variable not set: {resolved_value}. "
                                    f"Set it in your .env file before starting Ori."
                                )
                            if previous_secret and previous_secret == secret:
                                raise ConfigValidationError(
                                    "actions.sms.incoming_webhook.signature.previous_shared_secret "
                                    "must differ from shared_secret"
                                )
                        for key in ("max_skew_seconds", "replay_ttl_seconds"):
                            if key in signature_cfg:
                                try:
                                    value = int(signature_cfg[key])
                                except (TypeError, ValueError) as exc:
                                    raise ConfigValidationError(
                                        f"actions.sms.incoming_webhook.signature.{key} must be an integer."
                                    ) from exc
                                if value < 0:
                                    raise ConfigValidationError(
                                        f"actions.sms.incoming_webhook.signature.{key} must be >= 0."
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
            telemetry_export=telemetry_export,
            actions=actions,
            hal=hal,
            device_policy=device_policy,
            security=security,
            health_socket=health_socket,
            os_sandbox=os_sandbox,
            state=state_cfg,
            evidence=evidence_cfg,
            logging=logging_cfg,
            database_path=database_path,
            raw=data,
        )


# ─── Environment variable expansion ───────────────────────────────────────────


def _expand_env_vars(text: str) -> str:
    """Replace ${VAR_NAME} with the environment variable value, or leave as-is."""

    def _replace(match: re.Match[str]) -> str:
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
    if deployment_type not in {"pi", "phone", "edge_node", "server"}:
        raise ConfigValidationError(
            "device.deployment_type must be one of "
            "['phone', 'pi', 'edge_node', 'server']."
        )
    deployment_profile = (
        str(data.get("deployment_profile", "development")).strip().lower()
    )
    if deployment_profile not in {"development", "staging", "production"}:
        raise ConfigValidationError(
            "device.deployment_profile must be one of "
            "['development', 'staging', 'production']."
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
        timezone=_resolve_device_timezone(data.get("timezone", "")),
        country_code=country_code,
        deployment_type=deployment_type,
        deployment_profile=deployment_profile,
        site_type=str(data.get("site_type", "") or "").strip(),
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
            timeout_s = float(metadata["timeout_s"])
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

    default_tier = str(data.get("default_tier", "local")).strip().lower()
    if default_tier not in {"rule", "local"}:
        raise ConfigValidationError(
            "reasoning.default_tier must be one of: rule, local. "
            "gateway is selected by escalation policy; cloud is a gateway backend."
        )

    context_enricher = data.get("context_enricher") or {}
    if not isinstance(context_enricher, dict):
        raise ConfigValidationError(
            "'reasoning.context_enricher' must be a mapping when provided."
        )
    if context_enricher:
        try:
            ce_staleness = int(context_enricher.get("staleness_window_ms", 60_000))
            ce_max_entries = int(context_enricher.get("max_entries", 5))
        except (TypeError, ValueError) as exc:
            raise ConfigValidationError(
                "reasoning.context_enricher numeric fields must be valid integers."
            ) from exc
        if ce_staleness < 100:
            raise ConfigValidationError(
                "reasoning.context_enricher.staleness_window_ms must be >= 100."
            )
        if not (1 <= ce_max_entries <= 20):
            raise ConfigValidationError(
                "reasoning.context_enricher.max_entries must be between 1 and 20."
            )
        ce_sources = context_enricher.get("include_sources") or []
        if not isinstance(ce_sources, list) or not all(
            isinstance(s, str) for s in ce_sources
        ):
            raise ConfigValidationError(
                "reasoning.context_enricher.include_sources must be a list of strings."
            )
        context_enricher = {
            "enabled": (
                str(context_enricher.get("enabled", "false")).strip().lower() == "true"
                or context_enricher.get("enabled") is True
            ),
            "staleness_window_ms": ce_staleness,
            "max_entries": ce_max_entries,
            "include_sources": list(ce_sources),
        }

    return ReasoningConfig(
        default_tier=default_tier,
        local_model=str(data.get("local_model", "")),
        model_path=str(data.get("model_path", "")),
        escalation_threshold=float(data.get("escalation_threshold", 0.70)),
        energy_aware_reasoning=energy_aware,
        capability_posture=capability_posture_cfg,
        causal_memory=causal_memory,
        context_enricher=context_enricher,
    )


def _parse_gateway(data: Any) -> GatewayConfig:
    if not isinstance(data, dict):
        raise ConfigValidationError("'gateway' section must be a mapping.")
    node_heartbeat_raw = data.get("node_heartbeat") or {}
    if not isinstance(node_heartbeat_raw, dict):
        raise ConfigValidationError(
            "'gateway.node_heartbeat' section must be a mapping."
        )
    node_heartbeat = dict(node_heartbeat_raw)
    node_heartbeat["enabled"] = (
        str(node_heartbeat.get("enabled", "true")).strip().lower() == "true"
        or node_heartbeat.get("enabled") is True
    )
    try:
        interval_seconds = float(node_heartbeat.get("interval_seconds", 30))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "gateway.node_heartbeat.interval_seconds must be a number"
        ) from exc
    if interval_seconds < 1:
        raise ConfigValidationError(
            "gateway.node_heartbeat.interval_seconds must be >= 1"
        )
    node_heartbeat["interval_seconds"] = interval_seconds

    reasoning_raw = data.get("reasoning") or {}
    if not isinstance(reasoning_raw, dict):
        raise ConfigValidationError("'gateway.reasoning' section must be a mapping.")
    reasoning = dict(reasoning_raw)
    reasoning["enabled"] = (
        str(reasoning.get("enabled", "true")).strip().lower() == "true"
        or reasoning.get("enabled") is True
    )
    try:
        timeout_ms = int(reasoning.get("timeout_ms", 10_000))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "gateway.reasoning.timeout_ms must be an integer"
        ) from exc
    if timeout_ms < 100:
        raise ConfigValidationError("gateway.reasoning.timeout_ms must be >= 100")
    reasoning["timeout_ms"] = timeout_ms

    auth_raw = data.get("auth") or {}
    if not isinstance(auth_raw, dict):
        raise ConfigValidationError("'gateway.auth' section must be a mapping.")
    auth = dict(auth_raw)
    auth["enabled"] = (
        str(auth.get("enabled", "false")).strip().lower() == "true"
        or auth.get("enabled") is True
    )
    shared_secret_env = str(auth.get("shared_secret_env", "") or "").strip()
    if auth["enabled"] and not shared_secret_env:
        raise ConfigValidationError(
            "gateway.auth.shared_secret_env is required when gateway.auth.enabled is true"
        )
    auth["shared_secret_env"] = shared_secret_env
    previous_shared_secret_env = str(
        auth.get("previous_shared_secret_env", "") or ""
    ).strip()
    if (
        auth["enabled"]
        and previous_shared_secret_env
        and previous_shared_secret_env == shared_secret_env
    ):
        raise ConfigValidationError(
            "gateway.auth.previous_shared_secret_env must differ from shared_secret_env"
        )
    auth["previous_shared_secret_env"] = previous_shared_secret_env
    try:
        max_clock_skew_ms = int(auth.get("max_clock_skew_ms", 300_000))
        replay_ttl_ms = int(auth.get("replay_ttl_ms", 300_000))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "gateway.auth.max_clock_skew_ms and gateway.auth.replay_ttl_ms must be integers"
        ) from exc
    if max_clock_skew_ms < 1_000:
        raise ConfigValidationError("gateway.auth.max_clock_skew_ms must be >= 1000")
    if replay_ttl_ms < 1_000:
        raise ConfigValidationError("gateway.auth.replay_ttl_ms must be >= 1000")
    auth["max_clock_skew_ms"] = max_clock_skew_ms
    auth["replay_ttl_ms"] = replay_ttl_ms
    auth["persistent_replay_cache"] = is_truthy(
        auth.get("persistent_replay_cache", True)
    )

    tls_raw = data.get("tls") or {}
    if not isinstance(tls_raw, dict):
        raise ConfigValidationError("'gateway.tls' section must be a mapping.")
    tls = dict(tls_raw)
    if "insecure_skip_verify" in tls or "insecure" in tls:
        raise ConfigValidationError(
            "gateway.tls.insecure_skip_verify is not supported; configure ca_certfile for self-signed brokers"
        )
    tls["enabled"] = (
        str(tls.get("enabled", "false")).strip().lower() == "true"
        or tls.get("enabled") is True
    )
    for key in ("ca_certfile", "certfile", "keyfile", "keyfile_password_env"):
        tls[key] = str(tls.get(key, "") or "").strip()
    if tls["keyfile"] and not tls["certfile"]:
        raise ConfigValidationError(
            "gateway.tls.certfile is required when gateway.tls.keyfile is set"
        )
    if tls["keyfile_password_env"] and not tls["keyfile"]:
        raise ConfigValidationError(
            "gateway.tls.keyfile is required when gateway.tls.keyfile_password_env is set"
        )

    encryption_raw = data.get("encryption") or {}
    if not isinstance(encryption_raw, dict):
        raise ConfigValidationError("'gateway.encryption' section must be a mapping.")
    encryption = dict(encryption_raw)
    encryption["enabled"] = (
        str(encryption.get("enabled", "false")).strip().lower() == "true"
        or encryption.get("enabled") is True
    )
    if encryption["enabled"] and not auth["enabled"]:
        raise ConfigValidationError(
            "gateway.encryption.enabled requires gateway.auth.enabled"
        )

    broker_posture = _parse_gateway_broker_posture(data.get("broker_posture"))

    return GatewayConfig(
        enabled=bool(data.get("enabled", False)),
        broker_url=str(data.get("broker_url", "")),
        reasoning=reasoning,
        node_heartbeat=node_heartbeat,
        auth=auth,
        tls=tls,
        encryption=encryption,
        broker_posture=broker_posture,
    )


def _parse_gateway_broker_posture(data: Any) -> dict[str, Any]:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigValidationError(
            "'gateway.broker_posture' section must be a mapping."
        )

    deployment_check = str(data.get("deployment_check", "warning")).strip().lower()
    if deployment_check not in {"warning", "required"}:
        raise ConfigValidationError(
            "gateway.broker_posture.deployment_check must be 'warning' or 'required'."
        )
    anonymous_access = str(data.get("anonymous_access", "unknown")).strip().lower()
    if anonymous_access not in {"unknown", "disabled"}:
        raise ConfigValidationError(
            "gateway.broker_posture.anonymous_access must be 'unknown' or 'disabled'."
        )
    acl_policy = str(data.get("acl_policy", "unknown")).strip().lower()
    if acl_policy not in {"unknown", "per_device_required"}:
        raise ConfigValidationError(
            "gateway.broker_posture.acl_policy must be 'unknown' or 'per_device_required'."
        )

    return {
        **data,
        "deployment_check": deployment_check,
        "anonymous_access": anonymous_access,
        "acl_policy": acl_policy,
        "require_credentials": is_truthy(data.get("require_credentials", False)),
    }


def _warn_gateway_network_posture(gateway: GatewayConfig) -> None:
    """Warn about weak non-loopback gateway broker posture in development.

    Staging and production profiles fail closed on the same conditions in
    ``_validate_production_security_posture``; development deployments get a
    single consolidated WARNING instead so LAN testing stays possible.
    """
    if not bool(gateway.enabled):
        return

    broker_url = str(gateway.broker_url or "").strip()
    if not broker_url:
        return
    parsed = urlparse(broker_url if "://" in broker_url else f"mqtt://{broker_url}")
    if parsed.hostname is None or _is_loopback_host(parsed.hostname):
        return

    missing: list[str] = []
    if parsed.scheme.lower() != "mqtts" and not is_truthy(
        gateway.tls.get("enabled", False)
    ):
        missing.append("gateway TLS (mqtts:// or gateway.tls.enabled: true)")
    if not is_truthy(gateway.auth.get("enabled", False)):
        missing.append("gateway.auth.enabled: true")
    if not is_truthy(gateway.encryption.get("enabled", False)):
        missing.append("gateway.encryption.enabled: true")

    broker_posture = gateway.broker_posture
    if broker_posture.get("deployment_check") != "required":
        missing.append("gateway.broker_posture.deployment_check: required")
    if broker_posture.get("anonymous_access") != "disabled":
        missing.append("gateway.broker_posture.anonymous_access: disabled")
    if broker_posture.get("acl_policy") != "per_device_required":
        missing.append("gateway.broker_posture.acl_policy: per_device_required")
    if not is_truthy(broker_posture.get("require_credentials", False)):
        missing.append("gateway.broker_posture.require_credentials: true")
    if not (parsed.username and parsed.password):
        missing.append("MQTT username and password in gateway.broker_url")

    if missing:
        logger.warning(
            "[config] non-loopback gateway broker is missing hardening that "
            "staging/production posture requires: %s",
            "; ".join(missing),
        )


def _parse_telemetry_export(data: Any) -> TelemetryExportConfig:
    if data is None:
        return TelemetryExportConfig()
    if not isinstance(data, dict):
        raise ConfigValidationError("'telemetry_export' section must be a mapping.")

    enabled = is_truthy(data.get("enabled", False))
    endpoint = str(data.get("endpoint", "") or "").strip()
    api_key_env = str(data.get("api_key_env", "") or "").strip()

    try:
        flush_interval_s = float(data.get("flush_interval_s", 30.0))
        batch_size = int(data.get("batch_size", 50))
        timeout_ms = int(data.get("timeout_ms", 3000))
        max_queue_size = int(data.get("max_queue_size", 1000))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "telemetry_export.flush_interval_s, batch_size, timeout_ms, and "
            "max_queue_size must be numeric."
        ) from exc

    if flush_interval_s < 1.0 or flush_interval_s > 300.0:
        raise ConfigValidationError(
            "telemetry_export.flush_interval_s must be between 1 and 300 seconds."
        )
    if batch_size < 1 or batch_size > 500:
        raise ConfigValidationError(
            "telemetry_export.batch_size must be between 1 and 500."
        )
    if timeout_ms < 100 or timeout_ms > 30_000:
        raise ConfigValidationError(
            "telemetry_export.timeout_ms must be between 100 and 30000."
        )
    if max_queue_size < batch_size:
        raise ConfigValidationError(
            "telemetry_export.max_queue_size must be greater than or equal to "
            "telemetry_export.batch_size."
        )

    if enabled:
        if not endpoint:
            raise ConfigValidationError(
                "telemetry_export.endpoint is required when telemetry_export.enabled=true."
            )
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ConfigValidationError(
                "telemetry_export.endpoint must be an absolute http(s) URL."
            )
        if parsed.scheme != "https" and not _is_loopback_host(parsed.hostname):
            raise ConfigValidationError(
                "telemetry_export.endpoint must use https:// unless it targets "
                "localhost or 127.0.0.1."
            )
        if not api_key_env:
            raise ConfigValidationError(
                "telemetry_export.api_key_env is required when "
                "telemetry_export.enabled=true."
            )
        if not _ENV_NAME_RE.match(api_key_env):
            raise ConfigValidationError(
                "telemetry_export.api_key_env must be an environment variable name."
            )

    return TelemetryExportConfig(
        enabled=enabled,
        endpoint=endpoint,
        api_key_env=api_key_env,
        flush_interval_s=flush_interval_s,
        batch_size=batch_size,
        timeout_ms=timeout_ms,
        max_queue_size=max_queue_size,
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
    local_console_enabled = bool(local_console_raw.get("enabled", False))
    local_console_poll_interval_ms = int(
        local_console_raw.get("poll_interval_ms", 1000)
    )
    local_console_approval_channel_id = str(
        local_console_raw.get("approval_channel_id", "local_console")
    )
    if local_console_poll_interval_ms < 100:
        raise ConfigValidationError(
            "actions.local_console.poll_interval_ms must be >= 100."
        )
    local_console: dict[str, Any] = {
        "enabled": local_console_enabled,
        "poll_interval_ms": local_console_poll_interval_ms,
        "approval_channel_id": local_console_approval_channel_id,
    }

    offline_tokens_raw = data.get("offline_tokens") or {}
    if not isinstance(offline_tokens_raw, dict):
        raise ConfigValidationError(
            "'actions.offline_tokens' must be a mapping when provided."
        )
    offline_tokens_enabled = bool(offline_tokens_raw.get("enabled", False))
    offline_tokens_public_key_b64 = str(offline_tokens_raw.get("public_key_b64", ""))
    offline_tokens_max_clock_skew_s = int(
        offline_tokens_raw.get("max_clock_skew_s", 300)
    )
    if offline_tokens_max_clock_skew_s < 0:
        raise ConfigValidationError(
            "actions.offline_tokens.max_clock_skew_s must be >= 0."
        )
    if offline_tokens_enabled:
        if not offline_tokens_public_key_b64 or "${" in offline_tokens_public_key_b64:
            raise ConfigValidationError(
                "actions.offline_tokens.enabled=true requires actions.offline_tokens.public_key_b64."
            )
    offline_tokens: dict[str, Any] = {
        "enabled": offline_tokens_enabled,
        "public_key_b64": offline_tokens_public_key_b64,
        "max_clock_skew_s": offline_tokens_max_clock_skew_s,
    }

    setup_notifications_raw = data.get("setup_notifications") or {}
    if not isinstance(setup_notifications_raw, dict):
        raise ConfigValidationError(
            "'actions.setup_notifications' must be a mapping when provided."
        )
    setup_channels_raw = setup_notifications_raw.get("channels", ["primary"])
    if isinstance(setup_channels_raw, str):
        setup_channels_raw = [setup_channels_raw]
    if not isinstance(setup_channels_raw, list):
        raise ConfigValidationError(
            "actions.setup_notifications.channels must be a list of sms/whatsapp/primary."
        )
    setup_channels: list[str] = []
    for raw_channel in setup_channels_raw:
        channel = str(raw_channel).strip().lower()
        if channel not in {"sms", "whatsapp", "primary"}:
            raise ConfigValidationError(
                "actions.setup_notifications.channels entries must be sms, whatsapp, or primary."
            )
        if channel not in setup_channels:
            setup_channels.append(channel)
    setup_notifications = {
        "enabled": is_truthy(setup_notifications_raw.get("enabled", False)),
        "channels": setup_channels,
    }

    alert_outbox_raw = data.get("alert_outbox") or {}
    if not isinstance(alert_outbox_raw, dict):
        raise ConfigValidationError(
            "'actions.alert_outbox' must be a mapping when provided."
        )
    try:
        retry_interval_minutes = float(
            alert_outbox_raw.get("retry_interval_minutes", 0.5)
        )
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "actions.alert_outbox.retry_interval_minutes must be a number."
        ) from exc
    try:
        max_non_tier_d_attempts = int(
            alert_outbox_raw.get("max_non_tier_d_attempts", 10)
        )
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "actions.alert_outbox.max_non_tier_d_attempts must be an integer."
        ) from exc
    try:
        tier_d_critical_warning_threshold = int(
            alert_outbox_raw.get("tier_d_critical_warning_threshold", 3)
        )
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "actions.alert_outbox.tier_d_critical_warning_threshold must be an integer."
        ) from exc
    try:
        batch_size = int(alert_outbox_raw.get("batch_size", 50))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "actions.alert_outbox.batch_size must be an integer."
        ) from exc

    alert_outbox = {
        "retry_interval_minutes": retry_interval_minutes,
        "max_non_tier_d_attempts": max_non_tier_d_attempts,
        "tier_d_critical_warning_threshold": tier_d_critical_warning_threshold,
        "batch_size": batch_size,
    }
    if alert_outbox["retry_interval_minutes"] <= 0:
        raise ConfigValidationError(
            "actions.alert_outbox.retry_interval_minutes must be > 0."
        )
    if alert_outbox["max_non_tier_d_attempts"] < 1:
        raise ConfigValidationError(
            "actions.alert_outbox.max_non_tier_d_attempts must be >= 1."
        )
    if alert_outbox["tier_d_critical_warning_threshold"] < 1:
        raise ConfigValidationError(
            "actions.alert_outbox.tier_d_critical_warning_threshold must be >= 1."
        )
    if not 1 <= alert_outbox["batch_size"] <= 1000:
        raise ConfigValidationError(
            "actions.alert_outbox.batch_size must be between 1 and 1000."
        )

    approval_require_scoped_replies = is_truthy(
        data.get("approval_require_scoped_replies", True)
    )

    return ActionChannelConfig(
        primary_alert_channel=primary,
        operator_contact=str(data.get("operator_contact") or ""),
        secondary_contact=str(data.get("secondary_contact") or ""),
        approval_require_scoped_replies=approval_require_scoped_replies,
        whatsapp=data.get("whatsapp") or {},
        sms=data.get("sms") or {},
        relay=relay,
        coap=coap,
        local_console=local_console,
        offline_tokens=offline_tokens,
        alert_outbox=alert_outbox,
        setup_notifications=setup_notifications,
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
        enabled = bool(data.get("enabled", False))
        url = str(data.get("url", "") or "").strip()
        auth_token = str(data.get("auth_token", "") or "").strip()
        public_key_b64 = str(data.get("public_key_b64", "") or "").strip()
        request_timeout_ms = int(data.get("request_timeout_ms", 3000))
        max_clock_skew_s = int(data.get("max_clock_skew_s", 300))
        refresh_enabled = bool(data.get("refresh_enabled", False))
        refresh_interval_s = int(data.get("refresh_interval_s", 21600))
    except (TypeError, ValueError):
        logger.warning(
            "[config] 'device_policy' has invalid types. Falling back to defaults."
        )
        return default_policy

    if request_timeout_ms < 100:
        raise ConfigValidationError("device_policy.request_timeout_ms must be >= 100.")
    if max_clock_skew_s < 1:
        raise ConfigValidationError("device_policy.max_clock_skew_s must be >= 1.")
    if refresh_interval_s < 60:
        raise ConfigValidationError("device_policy.refresh_interval_s must be >= 60.")

    if enabled:
        if not url:
            raise ConfigValidationError(
                "device_policy.enabled is true but 'url' is empty."
            )
        if not url.startswith("https://"):
            raise ConfigValidationError(
                "device_policy.url must start with https:// when enabled."
            )
        if not auth_token or "${" in auth_token:
            raise ConfigValidationError(
                "device_policy.auth_token is missing or not properly interpolated."
            )
        if not public_key_b64 or "${" in public_key_b64:
            raise ConfigValidationError(
                "device_policy.public_key_b64 is missing or not properly interpolated."
            )

    out: dict[str, Any] = {
        "enabled": enabled,
        "url": url,
        "auth_token": auth_token,
        "public_key_b64": public_key_b64,
        "request_timeout_ms": request_timeout_ms,
        "max_clock_skew_s": max_clock_skew_s,
        "refresh_enabled": refresh_enabled,
        "refresh_interval_s": refresh_interval_s,
    }
    return out


def _parse_security(data: Any) -> dict:
    """Parse security controls that are not tied to one action channel."""
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigValidationError("'security' must be a mapping.")

    out = dict(data)
    remote = out.get("remote_commands") or {}
    if not isinstance(remote, dict):
        raise ConfigValidationError("security.remote_commands must be a mapping.")

    try:
        max_skew_seconds = int(remote.get("max_skew_seconds", 300))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "security.remote_commands.max_skew_seconds must be an integer."
        ) from exc
    if max_skew_seconds < 0:
        raise ConfigValidationError(
            "security.remote_commands.max_skew_seconds must be >= 0."
        )

    enabled = (
        str(remote.get("enabled", "")).strip().lower() == "true"
        or remote.get("enabled") is True
    )
    hmac_secret_env = str(
        remote.get("hmac_secret_env", "ORI_REMOTE_COMMAND_HMAC_SECRET")
    ).strip()
    if enabled and not hmac_secret_env:
        raise ConfigValidationError(
            "security.remote_commands.hmac_secret_env is required when enabled."
        )
    previous_hmac_secret_env = str(
        remote.get("previous_hmac_secret_env", "") or ""
    ).strip()
    if (
        enabled
        and previous_hmac_secret_env
        and previous_hmac_secret_env == hmac_secret_env
    ):
        raise ConfigValidationError(
            "security.remote_commands.previous_hmac_secret_env must differ from hmac_secret_env."
        )

    allowed_senders = _parse_remote_command_allowed_senders(
        remote.get("allowed_senders")
    )
    allow_unlisted_senders = (
        str(remote.get("allow_unlisted_senders", "")).strip().lower() == "true"
        or remote.get("allow_unlisted_senders") is True
    )
    if enabled and not allow_unlisted_senders and not any(allowed_senders.values()):
        logger.warning(
            "[config] remote commands are enabled without allowed_senders; "
            "all remote command senders will be rejected."
        )

    try:
        lockout = normalize_remote_command_lockout_config(remote.get("lockout"))
    except ValueError as exc:
        raise ConfigValidationError(str(exc)) from exc

    out["remote_commands"] = {
        **remote,
        "enabled": enabled,
        "hmac_secret_env": hmac_secret_env,
        "previous_hmac_secret_env": previous_hmac_secret_env,
        "max_skew_seconds": max_skew_seconds,
        "allowed_senders": allowed_senders,
        "allow_unlisted_senders": allow_unlisted_senders,
        "lockout": lockout,
    }

    skills_security = out.get("skills") or {}
    if not isinstance(skills_security, dict):
        raise ConfigValidationError("security.skills must be a mapping.")
    out["skills"] = {
        **skills_security,
        "require_signed": is_truthy(skills_security.get("require_signed", False)),
    }
    config_signature = out.get("config_signature") or {}
    if not isinstance(config_signature, dict):
        raise ConfigValidationError("security.config_signature must be a mapping.")
    trust_anchor_env = str(
        os.environ.get("ORI_CONFIG_TRUST_ANCHOR_ENV")
        or config_signature.get("trust_anchor_env")
        or DEFAULT_CONFIG_TRUST_ANCHOR_ENV
    ).strip()
    if not trust_anchor_env or not _ENV_NAME_RE.fullmatch(trust_anchor_env):
        raise ConfigValidationError(
            "security.config_signature.trust_anchor_env must be a valid "
            "environment variable name."
        )
    out["config_signature"] = {
        **config_signature,
        "require_signed": is_truthy(config_signature.get("require_signed", False))
        or is_truthy(os.environ.get(CONFIG_REQUIRE_SIGNED_ENV, "")),
        "trust_anchor_env": trust_anchor_env,
        "verified": False,
        "required": False,
        "signer_id": "",
        "signed_at_ms": None,
    }
    out["enforce_production_posture"] = is_truthy(
        out.get("enforce_production_posture", False)
    )
    return out


def _validate_production_security_posture(
    *,
    device: DeviceConfig,
    gateway: GatewayConfig,
    actions: ActionChannelConfig,
    security: dict[str, Any],
    state: StateConfig,
    database_path: str,
    config_signature_verified: bool,
) -> None:
    """Fail closed on unsafe production posture.

    Development and loopback deployments may intentionally use weaker local
    settings. Production posture is opt-in by ``security`` or implied by
    ``device.deployment_profile: staging|production``. An explicit false
    ``security.enforce_production_posture`` does not override those profiles.
    """
    enforce = bool(
        device.deployment_profile in {"staging", "production"}
        or security.get("enforce_production_posture") is True
    )
    if not enforce:
        return

    skills_security = security.get("skills") or {}
    if not isinstance(skills_security, dict) or not is_truthy(
        skills_security.get("require_signed", False)
    ):
        raise ConfigValidationError(
            "production posture requires security.skills.require_signed: true"
        )

    remote = security.get("remote_commands") or {}
    if isinstance(remote, dict) and is_truthy(remote.get("enabled", False)):
        if is_truthy(remote.get("allow_unlisted_senders", False)):
            raise ConfigValidationError(
                "production posture forbids "
                "security.remote_commands.allow_unlisted_senders: true"
            )
        allowed_senders = remote.get("allowed_senders")
        if not isinstance(allowed_senders, dict) or not any(
            bool(v) for v in allowed_senders.values()
        ):
            raise ConfigValidationError(
                "production posture requires "
                "security.remote_commands.allowed_senders when remote commands are enabled"
            )
        lockout = (
            remote.get("lockout") if isinstance(remote.get("lockout"), dict) else {}
        )
        if not is_truthy(lockout.get("enforcement_enabled", False)):
            raise ConfigValidationError(
                "production posture requires "
                "security.remote_commands.lockout.enforcement_enabled: true "
                "when remote commands are enabled"
            )

    if gateway.enabled:
        broker_url = str(gateway.broker_url or "").strip()
        if not broker_url:
            raise ConfigValidationError(
                "production posture requires gateway.broker_url when gateway is enabled"
            )
        parsed = urlparse(broker_url if "://" in broker_url else f"mqtt://{broker_url}")
        scheme = parsed.scheme.lower()
        if parsed.hostname is None:
            raise ConfigValidationError(
                "production posture requires gateway.broker_url to include a hostname"
            )
        # Payload-level protections do not depend on network position: a
        # loopback broker is still reachable by other local processes, so
        # HMAC auth and export encryption are required for every broker.
        if not is_truthy(gateway.auth.get("enabled", False)):
            raise ConfigValidationError(
                "production posture requires gateway.auth.enabled: true "
                "when gateway is enabled"
            )
        if not is_truthy(gateway.encryption.get("enabled", False)):
            raise ConfigValidationError(
                "production posture requires gateway.encryption.enabled: true "
                "when gateway is enabled"
            )
        non_loopback = not _is_loopback_host(parsed.hostname)
        if non_loopback:
            if scheme != "mqtts" and not is_truthy(gateway.tls.get("enabled", False)):
                raise ConfigValidationError(
                    "production posture requires gateway TLS for non-loopback brokers "
                    "(use mqtts:// or gateway.tls.enabled: true)"
                )
            broker_posture = gateway.broker_posture
            if broker_posture.get("deployment_check") != "required":
                raise ConfigValidationError(
                    "production posture requires "
                    "gateway.broker_posture.deployment_check: required "
                    "for non-loopback brokers"
                )
            if broker_posture.get("anonymous_access") != "disabled":
                raise ConfigValidationError(
                    "production posture requires "
                    "gateway.broker_posture.anonymous_access: disabled "
                    "for non-loopback brokers"
                )
            if broker_posture.get("acl_policy") != "per_device_required":
                raise ConfigValidationError(
                    "production posture requires "
                    "gateway.broker_posture.acl_policy: per_device_required "
                    "for non-loopback brokers"
                )
            if not is_truthy(broker_posture.get("require_credentials", False)):
                raise ConfigValidationError(
                    "production posture requires "
                    "gateway.broker_posture.require_credentials: true "
                    "for non-loopback brokers"
                )
            if not parsed.username or not parsed.password:
                raise ConfigValidationError(
                    "production posture requires gateway.broker_url to include "
                    "MQTT username and password for non-loopback brokers"
                )

    sms_cfg = actions.sms if isinstance(actions.sms, dict) else {}
    incoming = sms_cfg.get("incoming_webhook") or {}
    if isinstance(incoming, dict) and is_truthy(incoming.get("enabled", False)):
        host = str(incoming.get("host", "127.0.0.1") or "").strip()
        if not _is_loopback_host(host):
            allowed_source_cidrs = incoming.get("allowed_source_cidrs")
            if not _sms_webhook_source_cidrs_present(allowed_source_cidrs):
                raise ConfigValidationError(
                    "production posture requires "
                    "actions.sms.incoming_webhook.allowed_source_cidrs for public "
                    "SMS webhook ingress"
                )
            signature = incoming.get("signature") or {}
            mode = (
                str(signature.get("mode", "token_only")).strip().lower()
                if isinstance(signature, dict)
                else "token_only"
            )
            if mode == "token_only":
                raise ConfigValidationError(
                    "production posture forbids public SMS webhook token_only mode; "
                    "use token_and_hmac or hmac_required"
                )

    _validate_state_store_encryption_posture(
        state=state,
        database_path=database_path,
    )

    config_signature = security.get("config_signature") or {}
    if not isinstance(config_signature, dict) or not is_truthy(
        config_signature.get("require_signed", False)
    ):
        raise ConfigValidationError(
            "production posture requires security.config_signature.require_signed: "
            f"true or {CONFIG_REQUIRE_SIGNED_ENV}=true"
        )
    if not config_signature_verified:
        raise ConfigValidationError(
            "production posture requires a verified config_signature block"
        )


def _is_loopback_host(host: str | None) -> bool:
    value = str(host or "").strip().lower()
    return value in {"localhost", "::1"} or value.startswith("127.")


def _validate_state_store_encryption_posture(
    *,
    state: StateConfig,
    database_path: str,
) -> None:
    encryption = state.encryption
    if encryption.mode != "filesystem_required":
        raise ConfigValidationError(
            "production posture requires state.encryption.mode: filesystem_required"
        )

    marker_ok = False
    if encryption.marker_file:
        marker_path = Path(encryption.marker_file).expanduser()
        if not marker_path.is_file():
            raise ConfigValidationError(
                "state.encryption.marker_file must point to an existing file "
                "when configured."
            )
        marker_ok = True

    db_path = Path(database_path).expanduser().resolve(strict=False)
    prefix_ok = any(
        path_is_relative_to(
            db_path,
            Path(prefix).expanduser().resolve(strict=False),
        )
        for prefix in encryption.encrypted_path_prefixes
    )
    if not (marker_ok or prefix_ok):
        raise ConfigValidationError(
            "production posture requires database.path to live under one of "
            "state.encryption.encrypted_path_prefixes or a valid "
            "state.encryption.marker_file."
        )


def _validate_sms_webhook_source_cidrs(data: Any) -> None:
    """Validate optional SMS webhook source CIDR allowlist."""
    if data is None:
        return
    if not isinstance(data, list):
        raise ConfigValidationError(
            "actions.sms.incoming_webhook.allowed_source_cidrs must be a list."
        )
    for index, item in enumerate(data):
        cidr = str(item).strip()
        if not cidr:
            raise ConfigValidationError(
                "actions.sms.incoming_webhook.allowed_source_cidrs entries "
                "must not be empty."
            )
        try:
            network = ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ConfigValidationError(
                "actions.sms.incoming_webhook.allowed_source_cidrs "
                f"entry {index} is not a valid IP/CIDR: {cidr!r}"
            ) from exc
        if network.prefixlen == 0:
            raise ConfigValidationError(
                "actions.sms.incoming_webhook.allowed_source_cidrs must not "
                "contain a catch-all network."
            )


def _sms_webhook_source_cidrs_present(data: Any) -> bool:
    if not isinstance(data, list):
        return False
    return any(str(item).strip() for item in data)


def _parse_remote_command_allowed_senders(data: Any) -> dict[str, list[str]]:
    """Parse remote command sender allowlist by ingress channel."""
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigValidationError(
            "security.remote_commands.allowed_senders must be a mapping."
        )
    result: dict[str, list[str]] = {"sms": [], "whatsapp": []}
    for channel, raw_senders in data.items():
        normalized_channel = str(channel or "").strip().lower()
        if not normalized_channel:
            continue
        if not isinstance(raw_senders, list):
            raise ConfigValidationError(
                f"security.remote_commands.allowed_senders.{normalized_channel} must be a list."
            )
        seen: set[str] = set()
        normalized: list[str] = []
        for sender in raw_senders:
            value = normalize_remote_command_sender(normalized_channel, sender)
            if value and value not in seen:
                seen.add(value)
                normalized.append(value)
        result[normalized_channel] = normalized
    return result


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


def _parse_evidence(data: Any) -> EvidenceConfig:
    if data is None:
        return EvidenceConfig()
    if not isinstance(data, dict):
        raise ConfigValidationError("'evidence' section must be a mapping.")
    enabled = is_truthy(data.get("enabled", False))
    db_path = str(data.get("db_path", "ori_verity.db") or "").strip()
    key_path = str(data.get("key_path", "ori_verity.key") or "").strip()
    device_secret_env = str(
        data.get("device_secret_env", "ORI_EVIDENCE_DEVICE_SECRET") or ""
    ).strip()
    if enabled:
        if not db_path:
            raise ConfigValidationError(
                "evidence.db_path is required when evidence.enabled is true"
            )
        if not key_path:
            raise ConfigValidationError(
                "evidence.key_path is required when evidence.enabled is true"
            )
        if not _ENV_NAME_RE.match(device_secret_env):
            raise ConfigValidationError(
                "evidence.device_secret_env must be a valid environment variable name"
            )
        if db_path == key_path:
            raise ConfigValidationError(
                "evidence.db_path and evidence.key_path must differ"
            )
    return EvidenceConfig(
        enabled=enabled,
        db_path=db_path,
        key_path=key_path,
        device_secret_env=device_secret_env,
    )


def _parse_state(data: Any) -> StateConfig:
    if not isinstance(data, dict):
        return StateConfig()
    comp_data = data.get("compaction", {})
    if not isinstance(comp_data, dict):
        comp_data = {}
    encryption_data = data.get("encryption", {})
    if not isinstance(encryption_data, dict):
        raise ConfigValidationError("state.encryption must be a mapping.")

    try:
        max_skew = int(comp_data.get("max_backward_skew_ms", 3600000))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "state.compaction.max_backward_skew_ms must be an integer."
        ) from exc

    if max_skew < 60000:
        raise ConfigValidationError(
            "state.compaction.max_backward_skew_ms must be >= 60000."
        )

    encryption = _parse_state_encryption(encryption_data)

    return StateConfig(
        compaction=CompactionConfig(max_backward_skew_ms=max_skew),
        encryption=encryption,
    )


def _parse_state_encryption(data: dict[str, Any]) -> StateEncryptionConfig:
    mode = str(data.get("mode", "disabled") or "disabled").strip().lower()
    if mode not in {"disabled", "filesystem_required"}:
        raise ConfigValidationError(
            "state.encryption.mode must be one of: disabled, filesystem_required."
        )

    prefixes_raw = data.get("encrypted_path_prefixes", [])
    if prefixes_raw is None:
        prefixes_raw = []
    if not isinstance(prefixes_raw, list):
        raise ConfigValidationError(
            "state.encryption.encrypted_path_prefixes must be a list."
        )
    prefixes = [str(item).strip() for item in prefixes_raw if str(item).strip()]
    for prefix in prefixes:
        prefix_path = Path(prefix).expanduser()
        if not prefix_path.is_absolute():
            raise ConfigValidationError(
                "state.encryption.encrypted_path_prefixes entries must be absolute paths."
            )
        resolved_prefix = prefix_path.resolve(strict=False)
        if str(resolved_prefix) == resolved_prefix.anchor:
            raise ConfigValidationError(
                "state.encryption.encrypted_path_prefixes must not contain a root path."
            )
    marker_file = str(data.get("marker_file", "") or "").strip()
    if marker_file and not Path(marker_file).expanduser().is_absolute():
        raise ConfigValidationError(
            "state.encryption.marker_file must be an absolute path."
        )

    if mode == "filesystem_required" and not prefixes and not marker_file:
        raise ConfigValidationError(
            "state.encryption.mode=filesystem_required requires "
            "encrypted_path_prefixes or marker_file."
        )

    return StateEncryptionConfig(
        mode=mode,
        encrypted_path_prefixes=prefixes,
        marker_file=marker_file,
    )


def _parse_database_path(data: Any) -> str:
    if data is None:
        return "ori_state.db"
    if not isinstance(data, dict):
        raise ConfigValidationError("'database' section must be a mapping.")
    path = str(data.get("path", "ori_state.db") or "").strip()
    if not path:
        raise ConfigValidationError("database.path must not be empty.")
    return path


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
