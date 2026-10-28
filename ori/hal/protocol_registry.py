# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The one authoritative definition of supported sensor protocols.

The registry intentionally names adapters without importing them at module load:
configuration may need to inspect a protocol before hardware dependencies are
available, and importing an optional adapter has no reason to construct it.
The forthcoming schema-resolution path will use the same definitions to find
each module's declarations; adding another hand-maintained protocol list would
make the two surfaces drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from types import MappingProxyType
from typing import Any, Callable, Mapping

from ori.hal.base import BaseAdapter
from ori.hal.config_schema import ValidatedSchema, validate_schema


@dataclass(frozen=True)
class ProtocolDefinition:
    """An adapter's import location, never an adapter instance."""

    module: str
    class_name: str


PROTOCOL_DEFINITIONS: Mapping[str, ProtocolDefinition] = MappingProxyType(
    {
        "psutil": ProtocolDefinition("ori.hal.psutil_adapter", "PsutilAdapter"),
        "i2c": ProtocolDefinition("ori.hal.i2c_adapter", "I2CAdapter"),
        "serial": ProtocolDefinition("ori.hal.serial_adapter", "SerialAdapter"),
        "solarman_modbus": ProtocolDefinition(
            "ori.hal.solarman_modbus_adapter", "SolarmanModbusAdapter"
        ),
        "growatt": ProtocolDefinition("ori.hal.growatt_adapter", "GrowattAdapter"),
        "victron": ProtocolDefinition("ori.hal.victron_adapter", "VictronAdapter"),
        "zigbee": ProtocolDefinition("ori.hal.zigbee_adapter", "ZigbeeAdapter"),
        "lorawan": ProtocolDefinition("ori.hal.lorawan_adapter", "LoraWanAdapter"),
        "mqtt": ProtocolDefinition("ori.hal.mqtt_adapter", "MqttAdapter"),
        "mqtt_perception": ProtocolDefinition(
            "ori.hal.mqtt_perception_adapter", "MqttPerceptionAdapter"
        ),
        "usb_serial": ProtocolDefinition(
            "ori.hal.usb_serial_adapter", "UsbSerialAdapter"
        ),
        "http": ProtocolDefinition("ori.hal.http_adapter", "HttpAdapter"),
        "coap": ProtocolDefinition("ori.hal.coap_adapter", "CoapAdapter"),
        "opcua": ProtocolDefinition("ori.hal.opcua_adapter", "OpcUaAdapter"),
        "smart": ProtocolDefinition("ori.hal.smart_adapter", "SmartAdapter"),
    }
)

# Derived rather than maintained beside PROTOCOL_DEFINITIONS. Config loading
# uses this name, so retain the stable public surface while removing the second
# source of truth.
SUPPORTED_SENSOR_PROTOCOLS: frozenset[str] = frozenset(PROTOCOL_DEFINITIONS)

# Sensors served by an MqttCachedAdapter subclass; a test holds this equal to
# the registry's classes so a new MQTT adapter cannot miss the session rule.
MQTT_FAMILY_PROTOCOLS: frozenset[str] = frozenset(
    {"mqtt", "mqtt_perception", "victron", "lorawan", "zigbee"}
)


class UnknownProtocolError(ValueError):
    """Raised when a sensor protocol is not registered in the runtime."""


def protocol_definition(protocol: str) -> ProtocolDefinition:
    """Return the definition for an operator-written protocol name."""
    try:
        return PROTOCOL_DEFINITIONS[protocol]
    except KeyError as exc:
        raise UnknownProtocolError(
            f"Unknown sensor protocol '{protocol}'. "
            f"Supported: {sorted(SUPPORTED_SENSOR_PROTOCOLS)}. "
            "Check ori.yaml sensors configuration."
        ) from exc


def make_adapter(protocol: str) -> BaseAdapter:
    """Instantiate the adapter named by *protocol*.

    This is intentionally the only operation that constructs an adapter. Code
    resolving declarations must use :func:`protocol_definition` and import the
    module itself rather than calling this factory.
    """
    definition = protocol_definition(protocol)
    module = import_module(definition.module)
    adapter_class = getattr(module, definition.class_name)
    return adapter_class()


def protocol_schemas(
    protocol: str,
) -> tuple[ValidatedSchema, dict[str, ValidatedSchema]]:
    """Load one protocol's declarations without constructing its adapter.

    A missing mapping is a release-author error, but it must be surfaced while
    loading configuration because that is the first point an operator selects a
    protocol.  Never default an absent mapping to an open schema: that would
    make an adapter whose surface nobody declared accept arbitrary metadata.
    """
    definition = protocol_definition(protocol)
    module = import_module(definition.module)
    missing = [
        name
        for name in ("CONFIG_SCHEMA", "CALIBRATION_SCHEMAS")
        if not hasattr(module, name)
    ]
    if missing:
        raise ValueError(
            f"protocol {protocol!r} module {definition.module!r} is missing "
            f"{', '.join(missing)}"
        )

    config_schema = getattr(module, "CONFIG_SCHEMA")
    calibration_schemas: Any = getattr(module, "CALIBRATION_SCHEMAS")
    if not isinstance(calibration_schemas, dict):
        raise ValueError(
            f"protocol {protocol!r} module {definition.module!r}: "
            "CALIBRATION_SCHEMAS must be a mapping"
        )
    if not all(isinstance(sensor_type, str) for sensor_type in calibration_schemas):
        raise ValueError(
            f"protocol {protocol!r} module {definition.module!r}: "
            "CALIBRATION_SCHEMAS keys must be strings"
        )

    validated_calibrations = {
        sensor_type: validate_schema(
            schema, name=f"{protocol}.{sensor_type}.calibration"
        )
        for sensor_type, schema in calibration_schemas.items()
    }
    return (
        validate_schema(config_schema, name=f"{protocol}.CONFIG_SCHEMA"),
        validated_calibrations,
    )


def connect_config(
    metadata: Mapping[str, Any],
    *,
    sensor_id: str,
    sensor_type: str,
    poll_interval_ms: int,
    calibration: Mapping[str, Any],
) -> dict[str, Any]:
    """The mapping an adapter connects with, short of ``circuit_breaker``.

    Metadata first and the runtime's values over it, never the reverse, so a
    metadata key cannot displace the sensor's declared identity.
    """
    return {
        **metadata,
        "sensor_id": sensor_id,
        "sensor_type": sensor_type,
        # Adapters that run their own poll loop refresh a cache the runtime
        # reads on this schedule; at their own default they would serve one
        # stale reading repeatedly as though it were fresh.
        "poll_interval_ms": poll_interval_ms,
        # Its own block, not flattened: flattening let a documented
        # `sensitivity` sit unread beside the adapter's own default.
        "calibration": dict(calibration),
    }


# The function every adapter module exposes for the checks its connect() makes
# from the configuration alone, so config load runs the same ones.
CONFIG_CHECK_NAME = "refuse_unusable_config"


def protocol_config_check(protocol: str) -> Callable[[dict[str, Any]], object]:
    """Return the protocol's configuration check without constructing its adapter.

    The check takes the mapping ``connect()`` receives and raises
    ``AdapterConnectionError`` for a value connect would refuse. A module
    without one is refused here, never treated as having nothing to check.
    """
    definition = protocol_definition(protocol)
    module = import_module(definition.module)
    check = getattr(module, CONFIG_CHECK_NAME, None)
    if not callable(check):
        raise ValueError(
            f"protocol {protocol!r} module {definition.module!r} is missing "
            f"{CONFIG_CHECK_NAME}"
        )
    return check
