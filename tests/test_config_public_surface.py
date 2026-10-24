# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""``ori.config`` exports its interface and nothing else.

The configuration is defined one module per section under ``ori/config/``.
``ori.config`` exports ``Config``, the dataclass of each section it holds, its
error, and the functions and constants other code reads from it. As a single
module it also exposed every private helper and every name it imported; those
are not re-exported, because nothing outside the configuration read them, and a
re-export kept for no reader is a shim. A test that needs a private name
imports it from the section module that defines it.
"""

import types

import ori.config

#: The interface. A name is added here only when code outside ``ori/config/``
#: reads it, or it is the type of a ``Config`` field.
INTERFACE: frozenset[str] = frozenset(
    {
        "ActionChannelConfig",
        "CompactionConfig",
        "Config",
        "ConfigValidationError",
        "DeviceConfig",
        "EvidenceConfig",
        "GatewayConfig",
        "HalConfig",
        "LoggingConfig",
        "MAX_SKILL_NAME_LENGTH",
        "RESERVED_SENSOR_METADATA_KEYS",
        "ReasoningConfig",
        "SKILL_NAME_RE",
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


def test_ori_config_binds_exactly_its_interface() -> None:
    names = _namespace()
    assert names - INTERFACE == set(), "names added to ori.config"
    assert INTERFACE - names == set(), "names ori.config no longer binds"


def test_all_lists_the_interface() -> None:
    assert set(ori.config.__all__) == INTERFACE
    assert len(ori.config.__all__) == len(INTERFACE)


def test_every_config_field_type_is_exported() -> None:
    """A section's dataclass is part of the interface wherever ``Config`` holds one."""
    import typing

    def section_types(annotation: object) -> set[type]:
        found = {annotation} if isinstance(annotation, type) else set()
        for argument in typing.get_args(annotation):
            found |= section_types(argument)
        return {t for t in found if t.__module__.startswith("ori.config.")}

    held = set()
    for annotation in typing.get_type_hints(ori.config.Config).values():
        held |= section_types(annotation)
    assert {"SensorConfig", "SkillConfig", "GatewayConfig"} <= {
        t.__name__ for t in held
    }
    for section in held:
        assert section.__name__ in INTERFACE, f"Config holds {section.__name__}"
        assert getattr(ori.config, section.__name__) is section
