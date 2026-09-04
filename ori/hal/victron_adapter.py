# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
)
from ori.hal.mqtt_base import MQTT_CONNECTION_SCHEMA, MqttCachedAdapter
from ori.network.events import SensorReading

_DEFAULT_PORT = 1883

# Mapping: sensor_type -> (topic_suffix, unit)
_SENSOR_MAP: dict[str, tuple[str, str]] = {
    "victron_battery_soc": ("battery/276/Soc", "percent"),
    "victron_battery_voltage": ("battery/276/Voltage", "volt"),
    "victron_battery_power": ("battery/276/Power", "watt"),
    "victron_pv_power": ("system/0/Dc/Pv/Power", "watt"),
    "victron_grid_power": ("system/0/Ac/Grid/L1/Power", "watt"),
    "victron_load_power": ("system/0/Ac/Loads/L1/Power", "watt"),
}
_SUPPORTED = frozenset(_SENSOR_MAP)

CONFIG_SCHEMA = {
    **MQTT_CONNECTION_SCHEMA,
    "portal_id": {"type": "string", "required": True},
}
CALIBRATION_SCHEMAS: dict[str, dict] = {}


class VictronAdapter(MqttCachedAdapter):
    """Victron VenusOS MQTT adapter (subscribe + cache)."""

    def __init__(self) -> None:
        super().__init__()
        self._sensor_type: str = ""
        self._portal_id: str = ""

    async def connect(self, config: dict) -> None:
        sensor_type = str(config.get("sensor_type", "")).strip()
        if sensor_type not in _SUPPORTED:
            raise AdapterConnectionError(
                f"VictronAdapter: unsupported sensor_type '{sensor_type}'. "
                f"Supported: {sorted(_SUPPORTED)}"
            )

        portal_id = str(config.get("portal_id", "")).strip()
        if not portal_id:
            raise AdapterConnectionError(
                "VictronAdapter: 'portal_id' is required in sensor config."
            )

        async with self._connecting(f"portal '{portal_id}'", release=self._close_mqtt):
            self._sensor_type = sensor_type
            self._portal_id = portal_id
            topics = [self._topic_for_sensor(sensor) for sensor in sorted(_SUPPORTED)]
            await self._connect_mqtt(
                config=config,
                topics=topics,
                default_port=_DEFAULT_PORT,
                listener_name=f"victron-listener:{portal_id}",
            )

    async def _handle_message(self, topic: str, payload: Any) -> None:
        value, raw_payload = self.parse_numeric_payload(payload)
        self._cache_value(topic, value, raw_payload)

    async def read(self, sensor_id: str) -> SensorReading:
        self._ensure_aiomqtt_available()
        if not self._connected:
            raise AdapterReadError(
                "VictronAdapter: not connected — call connect() first"
            )
        if self._breaker is None:
            raise AdapterReadError("VictronAdapter: circuit breaker is not initialized")

        topic = self._topic_for_sensor(self._sensor_type)
        _suffix, unit = _SENSOR_MAP[self._sensor_type]

        async with self._breaker:
            cached = self._cache.get(topic)
            if cached is None:
                raise AdapterReadError(
                    "VictronAdapter: no MQTT data cached yet for "
                    f"sensor_type='{self._sensor_type}'"
                )
            value, timestamp_ms, raw_payload = cached

            return SensorReading(
                sensor_id=sensor_id,
                sensor_type=self._sensor_type,
                value=value,
                unit=unit,
                timestamp=timestamp_ms,
                quality=1.0,
                metadata={
                    "source": "victron",
                    "broker_host": self._broker_host,
                    "port": self._port,
                    "portal_id": self._portal_id,
                    "topic": topic,
                    "raw_payload": raw_payload,
                },
            )

    def _topic_for_sensor(self, sensor_type: str) -> str:
        suffix, _unit = _SENSOR_MAP[sensor_type]
        return f"N/{self._portal_id}/{suffix}"
