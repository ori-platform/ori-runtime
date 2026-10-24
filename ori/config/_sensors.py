# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``sensors`` section."""

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ori.config._fields import ConfigValidationError
from ori.hal.config_schema import (
    DocumentError,
    SchemaError,
    validate_document,
    validate_schema,
)
from ori.hal.mqtt_base import topic_wildcards
from ori.hal.protocol_registry import (
    SUPPORTED_SENSOR_PROTOCOLS,
    protocol_schemas,
)

_SENSOR_ENVELOPE_SCHEMA = validate_schema(
    {
        "id": {"type": "string", "required": True},
        "type": {"type": "string", "required": True},
        "protocol": {"type": "string", "required": True},
        "poll_interval_ms": {
            "type": "integer",
            "default": 1000,
            "minimum": 100,
            "maximum": 60_000,
        },
    },
    name="sensors[] envelope",
)

# Supplied by runtime.py when it assembles an adapter's connect() config, and
# therefore not settable on a sensor. `calibration` is absent because it is
# already a first-class sensor key and never reaches metadata.
RESERVED_SENSOR_METADATA_KEYS = frozenset(
    {"sensor_id", "sensor_type", "circuit_breaker"}
)


@dataclass
class SensorConfig:
    id: str
    type: str
    protocol: str
    poll_interval_ms: int
    metadata: dict = field(default_factory=dict)
    calibration: dict = field(default_factory=dict)


def parse_sensors(
    data: Any, *, external: dict[str, Any] | None = None
) -> list[SensorConfig]:
    if not isinstance(data, list):
        raise ConfigValidationError("'sensors' must be a list.")

    sensors = []
    seen_ids: dict[str, int] = {}
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ConfigValidationError(f"sensors[{i}] must be a mapping.")

        section = f"sensors[{i}]"
        canonical = {
            key: item[key]
            for key in ("id", "type", "protocol", "poll_interval_ms")
            if key in item
        }
        try:
            envelope = validate_document(
                canonical, _SENSOR_ENVELOPE_SCHEMA, context=section
            )
        except DocumentError as exc:
            raise ConfigValidationError(str(exc)) from exc

        sensor_id = envelope["id"].strip()
        sensor_type = envelope["type"].strip()
        protocol = envelope["protocol"].strip()
        poll_ms = envelope["poll_interval_ms"]
        if not sensor_id:
            raise ConfigValidationError(
                f"{section}.id: must be non-empty after trimming."
            )
        if not sensor_type:
            raise ConfigValidationError(
                f"{section}.type: must be non-empty after trimming."
            )
        if not protocol:
            raise ConfigValidationError(
                f"{section}.protocol: must be non-empty after trimming."
            )
        if protocol not in SUPPORTED_SENSOR_PROTOCOLS:
            raise ConfigValidationError(
                f"sensors[{i}] (id={sensor_id!r}): unknown protocol {protocol!r}. "
                f"Supported protocols: {sorted(SUPPORTED_SENSOR_PROTOCOLS)}."
            )
        if sensor_id in seen_ids:
            raise ConfigValidationError(
                f"{section}.id: {sensor_id!r} is already used by "
                f"sensors[{seen_ids[sensor_id]}]. Per-sensor state is keyed by "
                f"id, so two entries sharing one do not produce two sensors."
            )
        seen_ids[sensor_id] = i

        # Everything outside the canonical envelope is protocol configuration.
        # It is closed by the declaration selected above; forwarding a key that
        # no adapter claims is the configuration defect this boundary ends.
        known = {"id", "type", "protocol", "poll_interval_ms", "calibration"}
        protocol_config = {k: v for k, v in item.items() if k not in known}
        _refuse_reserved_sensor_metadata(protocol_config, section, sensor_id)
        try:
            protocol_schema, calibration_schemas = protocol_schemas(protocol)
            metadata = validate_document(
                protocol_config,
                protocol_schema,
                context=f"{section} (protocol={protocol!r})",
                external=external,
            )
            if protocol == "coap":
                _validate_coap_sensor_metadata(metadata, section)
            calibration = item.get("calibration", {})
            if not isinstance(calibration, dict):
                raise ConfigValidationError(
                    f"{section}.calibration: expected object, got {type(calibration).__name__}."
                )
            calibration_schema = calibration_schemas.get(sensor_type)
            if calibration_schema is None:
                if calibration:
                    raise ConfigValidationError(
                        f"{section}.calibration: protocol {protocol!r} and type "
                        f"{sensor_type!r} declare no calibration schema."
                    )
            else:
                calibration = validate_document(
                    calibration,
                    calibration_schema,
                    context=f"{section}.calibration (protocol={protocol!r}, type={sensor_type!r})",
                    external=external,
                )
        except (DocumentError, SchemaError, ValueError) as exc:
            raise ConfigValidationError(str(exc)) from exc

        sensors.append(
            SensorConfig(
                id=sensor_id,
                type=sensor_type,
                protocol=protocol,
                poll_interval_ms=poll_ms,
                metadata=metadata,
                calibration=calibration,
            )
        )
    return sensors


def _refuse_reserved_sensor_metadata(
    metadata: dict[str, Any], section: str, sensor_id: str
) -> None:
    """Refuse a sensor key that would displace a value the runtime supplies.

    `runtime.py` builds the adapter's config by injecting the sensor's identity
    and the HAL circuit-breaker settings, then spreading metadata over the top.
    Metadata therefore wins, and these three names are not in the first-class
    set, so a sensor entry could set them.

    Both consequences are severe enough to refuse rather than resolve by
    precedence. `circuit_breaker` makes hardware recovery configurable per
    sensor, which is the bypass the HAL rules forbid. `sensor_type` decides what
    the adapter reads and in what unit, so a sensor declared one way reaches its
    adapter as another, and the reading is produced under an identity the
    operator did not declare.

    An operator who wrote one of these meant something by it, and silently
    preferring the runtime's value would be the same defect one level down.
    """
    reserved = sorted(RESERVED_SENSOR_METADATA_KEYS & set(metadata))
    if reserved:
        raise ConfigValidationError(
            f"{section} (id={sensor_id!r}): {', '.join(repr(k) for k in reserved)} "
            f"{'is' if len(reserved) == 1 else 'are'} supplied by the runtime and "
            f"cannot be set on a sensor. Use 'id' and 'type' for sensor identity, "
            f"and 'hal.circuit_breaker' for breaker settings."
        )


def validate_coap_sensor_allowlist(
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
        if not host:
            raise ConfigValidationError(
                f"sensors[{sensor.id!r}]: coap uri must include a host."
            )
        if host not in global_allow_set:
            raise ConfigValidationError(
                f"sensors[{sensor.id!r}]: coap uri host {host!r} is not listed in actions.coap.allowed_hosts."
            )


def _validate_coap_sensor_metadata(metadata: dict[str, Any], section: str) -> None:
    """Enforce URI semantics that the declarative grammar cannot express.

    The schema owns field presence and scalar types.  URI scheme/host validity
    and a strictly positive request timeout are security constraints: a value
    accepted here reaches the CoAP allowlist and adapter unchanged.
    """
    uri = str(metadata.get("uri", "")).strip()
    parsed = urlparse(uri)
    if not parsed.hostname:
        raise ConfigValidationError(f"{section}.uri: host is required.")
    if parsed.scheme not in {"coap", "coaps"}:
        raise ConfigValidationError(
            f"{section}.uri: must start with coap:// or coaps://."
        )
    if float(metadata.get("timeout_s", 0)) <= 0:
        raise ConfigValidationError(f"{section}.timeout_s: must be > 0.")


_CLEAN_SESSION_SPELLINGS = ("clean_session", "mqtt_clean_session")


def refuse_persistent_mqtt_session(sensor_id: str, metadata: dict[str, Any]) -> None:
    """A sensor's MQTT session is clean; a persistent one is refused by name."""
    mqtt_cfg = metadata.get("mqtt")
    places: list[tuple[str, Any]] = [
        (key, metadata[key]) for key in _CLEAN_SESSION_SPELLINGS if key in metadata
    ]
    if isinstance(mqtt_cfg, dict):
        places += [
            (f"mqtt.{key}", mqtt_cfg[key])
            for key in _CLEAN_SESSION_SPELLINGS
            if key in mqtt_cfg
        ]
    for key, value in places:
        if value is not True:
            raise ConfigValidationError(
                f"sensors[{sensor_id}].{key}: {value!r} is refused; an MQTT sensor "
                "uses a clean session. A broker queues messages for a persistent "
                "session and delivers them on reconnect, and the freshness bound "
                "cannot time a queued message from its publication."
            )


# The sensor keys an MQTT-family adapter builds its subscription from.
_MQTT_TOPIC_KEYS = ("topic", "portal_id")


def refuse_wildcard_mqtt_topic(sensor_id: str, metadata: dict[str, Any]) -> None:
    """A sensor reads one concrete topic; a wildcard is refused by name."""
    for key in _MQTT_TOPIC_KEYS:
        value = metadata.get(key)
        if not isinstance(value, str):
            continue
        wildcards = topic_wildcards(value)
        if wildcards:
            raise ConfigValidationError(
                f"sensors[{sensor_id}].{key}: {value!r} is refused; it carries "
                f"the MQTT wildcard {' and '.join(repr(w) for w in wildcards)}. "
                "A value is cached under the topic of the message that carried "
                "it and read under the configured one, so a sensor on a wildcard "
                "subscription never reads. Name one concrete topic per sensor."
            )
