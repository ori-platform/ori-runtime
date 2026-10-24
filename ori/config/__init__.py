# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The device configuration: ``ori.yaml`` loaded, validated and typed.

``Config`` and the section dataclasses are defined one module per top-level
section under ``ori/config/``, with document admission in ``_document``, the
loader in ``_config`` and production posture in ``_posture``. This module
re-exports every name ``ori.config`` has always bound, the imports included, so
no importer depends on that layout; ``tests/test_config_public_surface.py``
holds the set.
"""

import errno as errno
import logging as logging
import math as math
import os as os
import re as re
import stat as stat
from dataclasses import dataclass as dataclass
from dataclasses import field as field
from dataclasses import replace as replace
from datetime import datetime as datetime
from datetime import timezone as timezone
from ipaddress import ip_network as ip_network
from pathlib import Path as Path
from typing import Any as Any
from urllib.parse import urlparse as urlparse
from zoneinfo import ZoneInfo as ZoneInfo
from zoneinfo import ZoneInfoNotFoundError as ZoneInfoNotFoundError

import yaml as yaml

from ori.config import _actions as _actions
from ori.config import _database as _database
from ori.config import _device as _device
from ori.config import _device_policy as _device_policy
from ori.config import _env as _env
from ori.config import _evidence as _evidence
from ori.config import _firmware_mqtt_provisioning as _firmware_mqtt_provisioning
from ori.config import _gateway as _gateway
from ori.config import _hal as _hal
from ori.config import _health_socket as _health_socket
from ori.config import _logging as _logging
from ori.config import _os_sandbox as _os_sandbox
from ori.config import _posture as _posture
from ori.config import _reasoning as _reasoning
from ori.config import _security as _security
from ori.config import _sensors as _sensors
from ori.config import _skills as _skills
from ori.config import _state as _state
from ori.config import _telemetry_export as _telemetry_export
from ori.config._actions import _VALID_BCM_PINS as _VALID_BCM_PINS
from ori.config._actions import ActionChannelConfig as ActionChannelConfig
from ori.config._config import _TWILIO_CONTENT_SID_RE as _TWILIO_CONTENT_SID_RE
from ori.config._config import _WHATSAPP_TEMPLATE_INTENTS as _WHATSAPP_TEMPLATE_INTENTS
from ori.config._config import Config as Config
from ori.config._config import _checked_device_endpoint as _checked_device_endpoint
from ori.config._database import _IN_MEMORY_STORE as _IN_MEMORY_STORE
from ori.config._database import anchor_to_config as anchor_to_config
from ori.config._device import DeviceConfig as DeviceConfig
from ori.config._device import _detect_host_timezone as _detect_host_timezone
from ori.config._device import _require_str as _require_str
from ori.config._device import _resolve_device_timezone as _resolve_device_timezone
from ori.config._device import _validate_iana_timezone as _validate_iana_timezone
from ori.config._document import _CONFIG_READ_CHUNK as _CONFIG_READ_CHUNK
from ori.config._document import _MAX_CONFIG_BYTES as _MAX_CONFIG_BYTES
from ori.config._document import _BoundedConfigSafeLoader as _BoundedConfigSafeLoader
from ori.config._document import _ConfigDocumentLimitError as _ConfigDocumentLimitError
from ori.config._document import (
    _ExpandingConfigSafeLoader as _ExpandingConfigSafeLoader,
)
from ori.config._document import _load_config_document as _load_config_document
from ori.config._document import _read_config_text as _read_config_text
from ori.config._document import config_env_placeholders as config_env_placeholders
from ori.config._document import read_config_bytes as read_config_bytes
from ori.config._document import read_config_document as read_config_document
from ori.config._env import _ENV_VAR_RE as _ENV_VAR_RE
from ori.config._evidence import EvidenceConfig as EvidenceConfig
from ori.config._fields import MAX_SKILL_NAME_LENGTH as MAX_SKILL_NAME_LENGTH
from ori.config._fields import SKILL_NAME_RE as SKILL_NAME_RE
from ori.config._fields import ConfigValidationError as ConfigValidationError
from ori.config._fields import checked_device_id as checked_device_id
from ori.config._fields import checked_site_id as checked_site_id
from ori.config._gateway import GatewayConfig as GatewayConfig
from ori.config._gateway import (
    _parse_gateway_broker_posture as _parse_gateway_broker_posture,
)
from ori.config._hal import HalConfig as HalConfig
from ori.config._logging import LoggingConfig as LoggingConfig
from ori.config._posture import (
    _validate_state_store_encryption_posture as _validate_state_store_encryption_posture,
)
from ori.config._posture import hardened_posture_declared as hardened_posture_declared
from ori.config._posture import (
    requires_production_posture as requires_production_posture,
)
from ori.config._reasoning import ReasoningConfig as ReasoningConfig
from ori.config._security import (
    _parse_remote_command_allowed_senders as _parse_remote_command_allowed_senders,
)
from ori.config._sensors import _CLEAN_SESSION_SPELLINGS as _CLEAN_SESSION_SPELLINGS
from ori.config._sensors import _MQTT_TOPIC_KEYS as _MQTT_TOPIC_KEYS
from ori.config._sensors import _SENSOR_ENVELOPE_SCHEMA as _SENSOR_ENVELOPE_SCHEMA
from ori.config._sensors import (
    RESERVED_SENSOR_METADATA_KEYS as RESERVED_SENSOR_METADATA_KEYS,
)
from ori.config._sensors import SensorConfig as SensorConfig
from ori.config._sensors import (
    _refuse_reserved_sensor_metadata as _refuse_reserved_sensor_metadata,
)
from ori.config._sensors import (
    _validate_coap_sensor_metadata as _validate_coap_sensor_metadata,
)
from ori.config._skills import _SKILL_ENTRY_KEYS as _SKILL_ENTRY_KEYS
from ori.config._skills import SkillConfig as SkillConfig
from ori.config._skills import _refuse_skill_config as _refuse_skill_config
from ori.config._skills import _require_optional_str as _require_optional_str
from ori.config._state import CompactionConfig as CompactionConfig
from ori.config._state import StateConfig as StateConfig
from ori.config._state import StateEncryptionConfig as StateEncryptionConfig
from ori.config._state import _parse_state_encryption as _parse_state_encryption
from ori.config._telemetry_export import TelemetryExportConfig as TelemetryExportConfig
from ori.hal.config_schema import DocumentError as DocumentError
from ori.hal.config_schema import SchemaError as SchemaError
from ori.hal.config_schema import validate_document as validate_document
from ori.hal.config_schema import validate_schema as validate_schema
from ori.hal.mqtt_base import topic_wildcards as topic_wildcards
from ori.hal.protocol_registry import MQTT_FAMILY_PROTOCOLS as MQTT_FAMILY_PROTOCOLS
from ori.hal.protocol_registry import (
    SUPPORTED_SENSOR_PROTOCOLS as SUPPORTED_SENSOR_PROTOCOLS,
)
from ori.hal.protocol_registry import protocol_schemas as protocol_schemas
from ori.security.config_signatures import (
    CONFIG_REQUIRE_SIGNED_ENV as CONFIG_REQUIRE_SIGNED_ENV,
)
from ori.security.config_signatures import (
    DEFAULT_CONFIG_TRUST_ANCHOR_ENV as DEFAULT_CONFIG_TRUST_ANCHOR_ENV,
)
from ori.security.config_signatures import ConfigSignatureError as ConfigSignatureError
from ori.security.config_signatures import (
    config_signature_policy_from_raw_config as config_signature_policy_from_raw_config,
)
from ori.security.config_signatures import (
    verify_config_signature_if_needed as verify_config_signature_if_needed,
)
from ori.security.remote_commands.commands import (
    normalize_remote_command_sender as normalize_remote_command_sender,
)
from ori.security.remote_commands.lockout import (
    normalize_remote_command_lockout_config as normalize_remote_command_lockout_config,
)
from ori.utils.bool_utils import is_truthy as is_truthy
from ori.utils.net_utils import is_loopback_host as is_loopback_host
from ori.utils.path_utils import path_is_relative_to as path_is_relative_to
from ori.utils.path_utils import shown as shown

logger = logging.getLogger(__name__)

# Helpers one section module calls in another are defined without the
# underscore; the package keeps the names it has always bound.

_ENV_NAME_RE = _env.ENV_NAME_RE
_expand_env_vars = _env.expand_env_vars
_parse_actions = _actions.parse_actions
_parse_database_path = _database.parse_database_path
_parse_device = _device.parse_device
_parse_device_policy = _device_policy.parse_device_policy
_parse_evidence = _evidence.parse_evidence
_parse_firmware_mqtt_provisioning = (
    _firmware_mqtt_provisioning.parse_firmware_mqtt_provisioning
)
_parse_gateway = _gateway.parse_gateway
_parse_hal = _hal.parse_hal
_parse_health_socket = _health_socket.parse_health_socket
_parse_logging = _logging.parse_logging
_parse_os_sandbox = _os_sandbox.parse_os_sandbox
_parse_reasoning = _reasoning.parse_reasoning
_parse_security = _security.parse_security
_parse_sensors = _sensors.parse_sensors
_parse_skills = _skills.parse_skills
_parse_state = _state.parse_state
_parse_telemetry_export = _telemetry_export.parse_telemetry_export
_refuse_persistent_mqtt_session = _sensors.refuse_persistent_mqtt_session
_refuse_wildcard_mqtt_topic = _sensors.refuse_wildcard_mqtt_topic
_resolve_database_path = _database.resolve_database_path
_sms_webhook_source_cidrs_present = _security.sms_webhook_source_cidrs_present
_validate_coap_sensor_allowlist = _sensors.validate_coap_sensor_allowlist
_validate_production_security_posture = _posture.validate_production_security_posture
_validate_sms_webhook_source_cidrs = _security.validate_sms_webhook_source_cidrs
_warn_gateway_network_posture = _gateway.warn_gateway_network_posture
