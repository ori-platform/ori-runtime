# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The device configuration: ``ori.yaml`` loaded, validated and typed.

``Config`` and the section dataclasses are defined one module per top-level
section under ``ori/config/``, with document admission in ``_document``, the
loader in ``_config`` and production posture in ``_posture``. This module is
the configuration's interface: ``Config``, the dataclass of each section it
holds, its error, and the functions and constants other code reads from it.
Everything else is private to the module that defines it;
``tests/test_config_public_surface.py`` holds the set.
"""

from ori.config._actions import ActionChannelConfig
from ori.config._config import Config
from ori.config._database import anchor_to_config
from ori.config._device import DeviceConfig
from ori.config._document import config_env_placeholders, read_config_document
from ori.config._evidence import EvidenceConfig
from ori.config._fields import (
    MAX_SKILL_NAME_LENGTH,
    SKILL_NAME_RE,
    ConfigValidationError,
)
from ori.config._gateway import GatewayConfig
from ori.config._hal import HalConfig
from ori.config._logging import LoggingConfig
from ori.config._posture import hardened_posture_declared, requires_production_posture
from ori.config._reasoning import ReasoningConfig
from ori.config._sensors import RESERVED_SENSOR_METADATA_KEYS, SensorConfig
from ori.config._skills import SkillConfig
from ori.config._state import CompactionConfig, StateConfig, StateEncryptionConfig
from ori.config._telemetry_export import TelemetryExportConfig

__all__ = [
    "MAX_SKILL_NAME_LENGTH",
    "RESERVED_SENSOR_METADATA_KEYS",
    "SKILL_NAME_RE",
    "ActionChannelConfig",
    "CompactionConfig",
    "Config",
    "ConfigValidationError",
    "DeviceConfig",
    "EvidenceConfig",
    "GatewayConfig",
    "HalConfig",
    "LoggingConfig",
    "ReasoningConfig",
    "SensorConfig",
    "SkillConfig",
    "StateConfig",
    "StateEncryptionConfig",
    "TelemetryExportConfig",
    "anchor_to_config",
    "config_env_placeholders",
    "hardened_posture_declared",
    "read_config_document",
    "requires_production_posture",
]
