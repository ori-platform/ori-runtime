# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""``Config``: the parsed device configuration and the loader that builds it."""

import logging
import re
from dataclasses import dataclass, field, replace

from ori.config._actions import ActionChannelConfig, parse_actions
from ori.config._database import (
    anchor_to_config,
    parse_database_path,
    resolve_database_path,
)
from ori.config._device import DeviceConfig, parse_device
from ori.config._device_policy import parse_device_policy
from ori.config._document import _load_config_document, _read_config_text
from ori.config._evidence import EvidenceConfig, parse_evidence
from ori.config._fields import ConfigValidationError
from ori.config._fields import checked_device_endpoint as _checked_device_endpoint
from ori.config._firmware_mqtt_provisioning import parse_firmware_mqtt_provisioning
from ori.config._gateway import (
    GatewayConfig,
    parse_gateway,
    warn_gateway_network_posture,
)
from ori.config._hal import HalConfig, parse_hal
from ori.config._health_socket import parse_health_socket
from ori.config._logging import LoggingConfig, parse_logging
from ori.config._os_sandbox import parse_os_sandbox
from ori.config._posture import validate_production_security_posture
from ori.config._reasoning import ReasoningConfig, parse_reasoning
from ori.config._security import parse_security, validate_sms_webhook_source_cidrs
from ori.config._sensors import (
    SensorConfig,
    parse_sensors,
    refuse_persistent_mqtt_session,
    refuse_wildcard_mqtt_topic,
    validate_coap_sensor_allowlist,
)
from ori.config._skills import SkillConfig, parse_skills
from ori.config._state import StateConfig, parse_state
from ori.config._telemetry_export import TelemetryExportConfig, parse_telemetry_export
from ori.hal.protocol_registry import MQTT_FAMILY_PROTOCOLS
from ori.security.config_signatures import (
    ConfigSignatureError,
    config_signature_policy_from_raw_config,
    verify_config_signature_if_needed,
)
from ori.utils.path_utils import shown

logger = logging.getLogger("ori.config")


_TWILIO_CONTENT_SID_RE = re.compile(r"^HX[0-9a-fA-F]{32}\Z")
_WHATSAPP_TEMPLATE_INTENTS = (
    "startup",
    "tier_a_alert",
    "tier_c_approval",
    "tier_c_escalation",
)


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
    firmware_mqtt_provisioning: dict = field(default_factory=dict)
    os_sandbox: dict = field(default_factory=dict)
    state: StateConfig = field(default_factory=StateConfig)
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, path: str) -> "Config":
        """Load and validate a device configuration.

        Every failure is a ``ConfigValidationError``. Classifying the parse
        step alone is not enough: interpreting the parsed document converts
        values, and a conversion refuses in its own vocabulary. ``float()`` on
        a 309-digit integer raises ``OverflowError``, on a string
        ``ValueError``, on a list ``TypeError``, and
        ``device.rated_capacity_amps`` — the Tier D threshold input — is the
        first field to reach one. Neither `Config.load`'s callers in
        `ori/runtime/` nor `ori/config/installer.py` catch those, so each
        would leave startup as an interpreter traceback and a restart loop.

        A defect in a section parser is classified here too. That is the
        deliberate cost: the exception type and the original traceback are
        both preserved through the chained cause, and a loader whose contract
        is refusal must not have a second, unclassified way to fail.

        The file is admitted before it is parsed: opened with ``O_NOFOLLOW``
        and ``O_NONBLOCK``, refused unless ``fstat`` on that descriptor says it
        is a regular file, and read no further than one byte past a 1 MiB cap.
        A FIFO, a device, a directory and a symlinked path are all refused
        rather than blocking or being followed.
        """
        try:
            return cls._interpret(path)
        except ConfigValidationError:
            raise
        except Exception as exc:
            raise ConfigValidationError(
                f"Config file {shown(path)} could not be interpreted: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    @classmethod
    def _interpret(cls, path: str) -> "Config":
        raw_text = _read_config_text(path)

        raw_unexpanded = _load_config_document(raw_text, path)

        if not isinstance(raw_unexpanded, dict):
            raise ConfigValidationError(
                f"Config file {shown(path)} must be a YAML mapping at the top level."
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

        # The same bytes are parsed again rather than a substituted copy of
        # them, so the document the runtime uses has, by construction, the
        # structure the signature covered. Environment values reach individual
        # scalar *values*; a key is never expanded, so one cannot name a key.
        # This is the same in every deployment, signed or not — there is one
        # loader, and a signature changes what is checked, not what is read.
        data = _load_config_document(raw_text, path, expand_env=True)

        if not isinstance(data, dict):
            raise ConfigValidationError(
                f"Config file {shown(path)} must be a YAML mapping at the top level."
            )

        device = parse_device(data.get("device", {}))
        actions = parse_actions(data.get("actions", {}))
        sensor_external = dict(data)
        sensor_external["actions"] = {"coap": actions.coap}
        sensors = parse_sensors(data.get("sensors", []), external=sensor_external)
        skills = parse_skills(data.get("skills", []))
        reasoning = parse_reasoning(data.get("reasoning", {}))
        gateway = parse_gateway(data.get("gateway", {}))
        telemetry_export = parse_telemetry_export(data.get("telemetry_export"))
        hal = parse_hal(data.get("hal"))
        device_policy = parse_device_policy(data.get("device_policy"))
        security = parse_security(data.get("security"))
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
        health_socket = parse_health_socket(data.get("health_socket"))
        firmware_mqtt_provisioning = parse_firmware_mqtt_provisioning(
            data.get("firmware_mqtt_provisioning")
        )
        os_sandbox = parse_os_sandbox(data.get("os_sandbox"))
        state_cfg = parse_state(data.get("state"))
        evidence_cfg = parse_evidence(data.get("evidence"))
        database_path = resolve_database_path(
            parse_database_path(data.get("database")), path
        )
        logging_cfg = parse_logging(data.get("logging"))
        # The runtime writes these, so where they land must be the installation
        # the configuration describes rather than wherever it was started. The
        # evidence key is sealed on first use, so a second working directory
        # would seal a second device identity for one device.
        logging_cfg = replace(
            logging_cfg, file=anchor_to_config(logging_cfg.file, path)
        )
        evidence_cfg = replace(
            evidence_cfg,
            db_path=anchor_to_config(evidence_cfg.db_path, path),
            key_path=anchor_to_config(evidence_cfg.key_path, path),
        )
        reasoning = replace(
            reasoning, model_path=anchor_to_config(reasoning.model_path, path)
        )
        for section, keys in (
            (health_socket, ("path",)),
            (gateway.tls, ("ca_certfile", "certfile", "keyfile")),
            (gateway.firmware_telemetry, ("controller_profiles_dir",)),
        ):
            if not isinstance(section, dict):
                continue
            for key in keys:
                declared = section.get(key)
                if isinstance(declared, str):
                    # An empty value means unset, and the anchor returns it
                    # unchanged rather than resolving to the config directory.
                    section[key] = anchor_to_config(declared, path)

        # A sensor carries its own transport material and device endpoint.
        # The schema canonicalises every deprecated TLS spelling into
        # `mqtt.tls.*` before this runs, so anchoring the canonical name covers
        # each of them; a sweep over the aliases as well anchored nothing.
        for sensor in sensors:
            mqtt_cfg = sensor.metadata.get("mqtt")
            if sensor.protocol in MQTT_FAMILY_PROTOCOLS:
                refuse_persistent_mqtt_session(sensor.id, sensor.metadata)
                refuse_wildcard_mqtt_topic(sensor.id, sensor.metadata)
            tls = mqtt_cfg.get("tls") if isinstance(mqtt_cfg, dict) else None
            if isinstance(tls, dict):
                for key in ("ca_certfile", "certfile", "keyfile"):
                    declared = tls.get(key)
                    if isinstance(declared, str):
                        tls[key] = anchor_to_config(declared, path)

            # `usb_serial` opens a URL through `serial_for_url`; `serial` does
            # not, so what each may name is checked against its own consumer.
            endpoint = {
                "serial": "port",
                "usb_serial": "device_path",
                # Passed verbatim as an argv element to `smartctl`, which takes
                # a device path and no URL form. Requiring it absolute also
                # keeps a value that begins with `-` from arriving as an option.
                "smart": "device",
            }.get(sensor.protocol)
            declared = sensor.metadata.get(endpoint) if endpoint else None
            if endpoint and isinstance(declared, str):
                sensor.metadata[endpoint] = _checked_device_endpoint(
                    declared,
                    f"sensors[{sensor.id}].{endpoint}",
                    urls_supported=sensor.protocol == "usb_serial",
                )

        gsm = actions.sms.get("gsm") if isinstance(actions.sms, dict) else None
        if isinstance(gsm, dict) and isinstance(gsm.get("port"), str):
            # The modem is opened with `Serial()`, which takes a port name.
            gsm["port"] = _checked_device_endpoint(
                gsm["port"], "actions.sms.gsm.port", urls_supported=False
            )
        validate_coap_sensor_allowlist(sensors, actions.coap)
        warn_gateway_network_posture(gateway)
        validate_production_security_posture(
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
            templates = actions.whatsapp.get("templates")
            if not isinstance(templates, dict):
                raise ConfigValidationError(
                    "actions.whatsapp.templates must configure approved Content SIDs "
                    "for startup, tier_a_alert, tier_c_approval, and tier_c_escalation."
                )
            for intent in _WHATSAPP_TEMPLATE_INTENTS:
                content_sid = str(templates.get(intent, "") or "").strip()
                if not _TWILIO_CONTENT_SID_RE.fullmatch(content_sid):
                    raise ConfigValidationError(
                        f"actions.whatsapp.templates.{intent} must be an approved "
                        "Twilio Content SID in the form HX followed by 32 hexadecimal "
                        "characters."
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
                    validate_sms_webhook_source_cidrs(
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
            firmware_mqtt_provisioning=firmware_mqtt_provisioning,
            os_sandbox=os_sandbox,
            state=state_cfg,
            evidence=evidence_cfg,
            logging=logging_cfg,
            database_path=database_path,
            raw=data,
        )
