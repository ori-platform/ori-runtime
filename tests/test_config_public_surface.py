# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""``ori.config`` binds the same names it bound as a single module.

The configuration is defined one module per section under ``ori/config/``, and
``ori.config`` re-exports all of it. An importer, a test or an operator script
that reached a name through ``ori.config`` keeps reaching it, private names and
the module's own imports included, so no caller depends on where a section
lives.
"""

import types

import ori.config

#: Every name ``ori.config`` bound at a8d41fd2, when it was the single module
#: ``ori/config.py``. Generated once, in a checkout of that commit, with
#: ``python -c 'import ori.config as c; print(sorted(n for n in vars(c) if not
#: n.startswith("__")))'``. A name is added or removed here only as a deliberate
#: change to the surface, never to make a move pass.
MAIN_NAMESPACE: frozenset[str] = frozenset(
    {
        "ActionChannelConfig",
        "Any",
        "CONFIG_REQUIRE_SIGNED_ENV",
        "CompactionConfig",
        "Config",
        "ConfigSignatureError",
        "ConfigValidationError",
        "DEFAULT_CONFIG_TRUST_ANCHOR_ENV",
        "DeviceConfig",
        "DocumentError",
        "EvidenceConfig",
        "GatewayConfig",
        "HalConfig",
        "LoggingConfig",
        "MAX_SKILL_NAME_LENGTH",
        "MQTT_FAMILY_PROTOCOLS",
        "Path",
        "RESERVED_SENSOR_METADATA_KEYS",
        "ReasoningConfig",
        "SKILL_NAME_RE",
        "SUPPORTED_SENSOR_PROTOCOLS",
        "SchemaError",
        "SensorConfig",
        "SkillConfig",
        "StateConfig",
        "StateEncryptionConfig",
        "TelemetryExportConfig",
        "ZoneInfo",
        "ZoneInfoNotFoundError",
        "_BoundedConfigSafeLoader",
        "_CLEAN_SESSION_SPELLINGS",
        "_CONFIG_READ_CHUNK",
        "_ConfigDocumentLimitError",
        "_ENV_NAME_RE",
        "_ENV_VAR_RE",
        "_ExpandingConfigSafeLoader",
        "_IN_MEMORY_STORE",
        "_MAX_CONFIG_BYTES",
        "_MQTT_TOPIC_KEYS",
        "_SENSOR_ENVELOPE_SCHEMA",
        "_SKILL_ENTRY_KEYS",
        "_TWILIO_CONTENT_SID_RE",
        "_VALID_BCM_PINS",
        "_WHATSAPP_TEMPLATE_INTENTS",
        "_checked_device_endpoint",
        "_detect_host_timezone",
        "_expand_env_vars",
        "_load_config_document",
        "_parse_actions",
        "_parse_database_path",
        "_parse_device",
        "_parse_device_policy",
        "_parse_evidence",
        "_parse_firmware_mqtt_provisioning",
        "_parse_gateway",
        "_parse_gateway_broker_posture",
        "_parse_hal",
        "_parse_health_socket",
        "_parse_logging",
        "_parse_os_sandbox",
        "_parse_reasoning",
        "_parse_remote_command_allowed_senders",
        "_parse_security",
        "_parse_sensors",
        "_parse_skills",
        "_parse_state",
        "_parse_state_encryption",
        "_parse_telemetry_export",
        "_read_config_text",
        "_refuse_persistent_mqtt_session",
        "_refuse_reserved_sensor_metadata",
        "_refuse_skill_config",
        "_refuse_wildcard_mqtt_topic",
        "_require_optional_str",
        "_require_str",
        "_resolve_database_path",
        "_resolve_device_timezone",
        "_sms_webhook_source_cidrs_present",
        "_validate_coap_sensor_allowlist",
        "_validate_coap_sensor_metadata",
        "_validate_iana_timezone",
        "_validate_production_security_posture",
        "_validate_sms_webhook_source_cidrs",
        "_validate_state_store_encryption_posture",
        "_warn_gateway_network_posture",
        "anchor_to_config",
        "checked_device_id",
        "checked_site_id",
        "config_env_placeholders",
        "config_signature_policy_from_raw_config",
        "dataclass",
        "datetime",
        "errno",
        "field",
        "hardened_posture_declared",
        "ip_network",
        "is_loopback_host",
        "is_truthy",
        "logger",
        "logging",
        "math",
        "normalize_remote_command_lockout_config",
        "normalize_remote_command_sender",
        "os",
        "path_is_relative_to",
        "protocol_schemas",
        "re",
        "read_config_bytes",
        "read_config_document",
        "replace",
        "requires_production_posture",
        "shown",
        "stat",
        "timezone",
        "topic_wildcards",
        "urlparse",
        "validate_document",
        "validate_schema",
        "verify_config_signature_if_needed",
        "yaml",
    }
)


def _namespace() -> set[str]:
    """Names ``ori.config`` binds, less the package's own section modules."""
    return {
        name
        for name, value in vars(ori.config).items()
        if not name.startswith("__")
        and not (
            isinstance(value, types.ModuleType)
            and value.__name__.startswith("ori.config.")
        )
    }


def test_ori_config_binds_exactly_main_s_names() -> None:
    names = _namespace()
    assert len(MAIN_NAMESPACE) == 120
    assert names - MAIN_NAMESPACE == set(), "names added to ori.config"
    assert MAIN_NAMESPACE - names == set(), "names ori.config no longer binds"
