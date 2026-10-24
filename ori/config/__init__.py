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

from ori.config._actions import _VALID_BCM_PINS as _VALID_BCM_PINS
from ori.config._actions import ActionChannelConfig as ActionChannelConfig
from ori.config._actions import _parse_actions as _parse_actions
from ori.config._config import _TWILIO_CONTENT_SID_RE as _TWILIO_CONTENT_SID_RE
from ori.config._config import _WHATSAPP_TEMPLATE_INTENTS as _WHATSAPP_TEMPLATE_INTENTS
from ori.config._config import Config as Config
from ori.config._config import _checked_device_endpoint as _checked_device_endpoint
from ori.config._database import _IN_MEMORY_STORE as _IN_MEMORY_STORE
from ori.config._database import _parse_database_path as _parse_database_path
from ori.config._database import _resolve_database_path as _resolve_database_path
from ori.config._database import anchor_to_config as anchor_to_config
from ori.config._device import DeviceConfig as DeviceConfig
from ori.config._device import _detect_host_timezone as _detect_host_timezone
from ori.config._device import _parse_device as _parse_device
from ori.config._device import _require_str as _require_str
from ori.config._device import _resolve_device_timezone as _resolve_device_timezone
from ori.config._device import _validate_iana_timezone as _validate_iana_timezone
from ori.config._device_policy import _parse_device_policy as _parse_device_policy
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
from ori.config._env import _ENV_NAME_RE as _ENV_NAME_RE
from ori.config._env import _ENV_VAR_RE as _ENV_VAR_RE
from ori.config._env import _expand_env_vars as _expand_env_vars
from ori.config._evidence import EvidenceConfig as EvidenceConfig
from ori.config._evidence import _parse_evidence as _parse_evidence
from ori.config._firmware_mqtt_provisioning import (
    _parse_firmware_mqtt_provisioning as _parse_firmware_mqtt_provisioning,
)
from ori.config._gateway import GatewayConfig as GatewayConfig
from ori.config._gateway import _parse_gateway as _parse_gateway
from ori.config._gateway import (
    _parse_gateway_broker_posture as _parse_gateway_broker_posture,
)
from ori.config._gateway import (
    _warn_gateway_network_posture as _warn_gateway_network_posture,
)
from ori.config._hal import HalConfig as HalConfig
from ori.config._hal import _parse_hal as _parse_hal
from ori.config._health_socket import _parse_health_socket as _parse_health_socket
from ori.config._logging import LoggingConfig as LoggingConfig
from ori.config._logging import _parse_logging as _parse_logging
from ori.config._os_sandbox import _parse_os_sandbox as _parse_os_sandbox
from ori.config._posture import (
    _validate_production_security_posture as _validate_production_security_posture,
)
from ori.config._posture import (
    _validate_state_store_encryption_posture as _validate_state_store_encryption_posture,
)
from ori.config._posture import hardened_posture_declared as hardened_posture_declared
from ori.config._posture import (
    requires_production_posture as requires_production_posture,
)
from ori.config._reasoning import ReasoningConfig as ReasoningConfig
from ori.config._reasoning import _parse_reasoning as _parse_reasoning
from ori.config._security import (
    _parse_remote_command_allowed_senders as _parse_remote_command_allowed_senders,
)
from ori.config._security import _parse_security as _parse_security
from ori.config._security import (
    _sms_webhook_source_cidrs_present as _sms_webhook_source_cidrs_present,
)
from ori.config._security import (
    _validate_sms_webhook_source_cidrs as _validate_sms_webhook_source_cidrs,
)
from ori.config._sensors import _CLEAN_SESSION_SPELLINGS as _CLEAN_SESSION_SPELLINGS
from ori.config._sensors import _MQTT_TOPIC_KEYS as _MQTT_TOPIC_KEYS
from ori.config._sensors import _SENSOR_ENVELOPE_SCHEMA as _SENSOR_ENVELOPE_SCHEMA
from ori.config._sensors import (
    RESERVED_SENSOR_METADATA_KEYS as RESERVED_SENSOR_METADATA_KEYS,
)
from ori.config._sensors import SensorConfig as SensorConfig
from ori.config._sensors import _parse_sensors as _parse_sensors
from ori.config._sensors import (
    _refuse_persistent_mqtt_session as _refuse_persistent_mqtt_session,
)
from ori.config._sensors import (
    _refuse_reserved_sensor_metadata as _refuse_reserved_sensor_metadata,
)
from ori.config._sensors import (
    _refuse_wildcard_mqtt_topic as _refuse_wildcard_mqtt_topic,
)
from ori.config._sensors import (
    _validate_coap_sensor_allowlist as _validate_coap_sensor_allowlist,
)
from ori.config._sensors import (
    _validate_coap_sensor_metadata as _validate_coap_sensor_metadata,
)
from ori.config._skills import _SKILL_ENTRY_KEYS as _SKILL_ENTRY_KEYS
from ori.config._skills import SkillConfig as SkillConfig
from ori.config._skills import _parse_skills as _parse_skills
from ori.config._skills import _refuse_skill_config as _refuse_skill_config
from ori.config._skills import _require_optional_str as _require_optional_str
from ori.config._state import CompactionConfig as CompactionConfig
from ori.config._state import StateConfig as StateConfig
from ori.config._state import StateEncryptionConfig as StateEncryptionConfig
from ori.config._state import _parse_state as _parse_state
from ori.config._state import _parse_state_encryption as _parse_state_encryption
from ori.config._telemetry_export import TelemetryExportConfig as TelemetryExportConfig
from ori.config._telemetry_export import (
    _parse_telemetry_export as _parse_telemetry_export,
)
from ori.config_fields import MAX_SKILL_NAME_LENGTH as MAX_SKILL_NAME_LENGTH
from ori.config_fields import SKILL_NAME_RE as SKILL_NAME_RE
from ori.config_fields import ConfigValidationError as ConfigValidationError
from ori.config_fields import checked_device_id as checked_device_id
from ori.config_fields import checked_site_id as checked_site_id
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
