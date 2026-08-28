# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for the protocol definition boundary, before schema activation."""

from __future__ import annotations

from importlib import import_module
from unittest.mock import patch

import pytest

from ori.hal.protocol_registry import (
    PROTOCOL_DEFINITIONS,
    SUPPORTED_SENSOR_PROTOCOLS,
    UnknownProtocolError,
    make_adapter,
    protocol_definition,
)


def test_supported_protocols_are_derived_from_the_definitions() -> None:
    assert SUPPORTED_SENSOR_PROTOCOLS == frozenset(PROTOCOL_DEFINITIONS)


def test_protocol_definitions_cannot_be_mutated_after_import() -> None:
    with pytest.raises(TypeError):
        PROTOCOL_DEFINITIONS["test"] = PROTOCOL_DEFINITIONS["i2c"]  # type: ignore[index]


def test_definition_names_module_and_class_without_importing_or_constructing() -> None:
    with patch("ori.hal.protocol_registry.import_module") as imported:
        definition = protocol_definition("i2c")

    assert definition.module == "ori.hal.i2c_adapter"
    assert definition.class_name == "I2CAdapter"
    imported.assert_not_called()


def test_every_definition_resolves_its_adapter_class_without_constructing_it() -> None:
    for definition in PROTOCOL_DEFINITIONS.values():
        module = import_module(definition.module)
        assert isinstance(getattr(module, definition.class_name), type)


def test_factory_imports_only_the_adapter_selected_by_protocol() -> None:
    class Adapter:
        pass

    with patch("ori.hal.protocol_registry.import_module") as imported:
        imported.return_value.PsutilAdapter = Adapter
        adapter = make_adapter("psutil")

    imported.assert_called_once_with("ori.hal.psutil_adapter")
    assert isinstance(adapter, Adapter)


def test_unknown_protocol_uses_the_existing_operator_facing_refusal() -> None:
    with pytest.raises(UnknownProtocolError, match="Unknown sensor protocol 'unknown'"):
        protocol_definition("unknown")
