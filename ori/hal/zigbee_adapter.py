# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json
from typing import Any

from ori.hal.base import AdapterConnectionError, AdapterReadError
from ori.hal.mqtt_base import MqttCachedAdapter
from ori.network.events import SensorReading
from ori.time_utils import now_ms

_DEFAULT_PORT = 1883

# Common zigbee2mqtt fields for smart-home sensors.
_SENSOR_MAP: dict[str, tuple[str, str]] = {
    "temperature": ("temperature", "celsius"),
    "humidity": ("humidity", "percent"),
    "illuminance": ("illuminance", "lux"),
    "battery_percent": ("battery", "percent"),
    "power_watt": ("power", "watt"),
    "energy_kwh": ("energy", "kilowatt_hour"),
    "motion": ("occupancy", "ratio"),
    "contact": ("contact", "ratio"),
    "water_leak": ("water_leak", "ratio"),
}


def _clamp_quality(value: float) -> float:
    return max(0.0, min(1.0, value))


def _extract_path(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            if part not in current:
                raise AdapterReadError(
                    f"ZigbeeAdapter: path '{path}' not found in payload"
                )
            current = current[part]
            continue
        if isinstance(current, list):
            try:
                index = int(part)
            except ValueError as exc:
                raise AdapterReadError(
                    f"ZigbeeAdapter: path '{path}' expects numeric list index, got '{part}'"
                ) from exc
            if index < 0 or index >= len(current):
                raise AdapterReadError(
                    f"ZigbeeAdapter: list index {index} out of range for path '{path}'"
                )
            current = current[index]
            continue
        raise AdapterReadError(
            f"ZigbeeAdapter: cannot traverse path '{path}' through {type(current).__name__}"
        )
    return current


def _coerce_value(value: Any) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        token = value.strip().lower()
        if token in {"true", "on", "open", "detected", "yes", "wet"}:
            return 1.0
        if token in {"false", "off", "closed", "clear", "no", "dry"}:
            return 0.0
        try:
            return float(token)
        except ValueError as exc:
            raise AdapterReadError(
                f"ZigbeeAdapter: value is not numeric/boolean: {value!r}"
            ) from exc
    raise AdapterReadError(
        f"ZigbeeAdapter: unsupported value type {type(value).__name__} in payload"
    )


class ZigbeeAdapter(MqttCachedAdapter):
    """Zigbee sensor adapter via MQTT bridge (zigbee2mqtt or equivalent)."""

    def __init__(self) -> None:
        super().__init__()
        self._sensor_type: str = ""
        self._topic: str = ""
        self._value_path: str = ""
        self._quality_path: str = ""
        self._unit: str = ""

    async def connect(self, config: dict) -> None:
        sensor_type = str(config.get("sensor_type", "")).strip()
        if not sensor_type:
            raise AdapterConnectionError("ZigbeeAdapter: 'sensor_type' is required")

        default_path, default_unit = _SENSOR_MAP.get(sensor_type, ("", ""))
        value_path = str(config.get("value_path", default_path)).strip()
        unit = str(config.get("unit", default_unit)).strip()
        if not value_path:
            raise AdapterConnectionError(
                "ZigbeeAdapter: unsupported sensor_type without value_path override. "
                f"Known sensor types: {sorted(_SENSOR_MAP)}"
            )

        topic = str(config.get("topic", "")).strip()
        if not topic:
            raise AdapterConnectionError(
                "ZigbeeAdapter: 'topic' is required (e.g. zigbee2mqtt/living-room)"
            )

        self._sensor_type = sensor_type
        self._topic = topic
        self._value_path = value_path
        self._quality_path = str(config.get("quality_path", "")).strip()
        self._unit = unit

        await self._connect_mqtt(
            config=config,
            topics=[topic],
            default_port=_DEFAULT_PORT,
            listener_name=f"zigbee-listener:{topic}",
        )

    async def _handle_message(self, topic: str, payload: Any) -> None:
        parsed = self._parse_payload(payload)
        raw_value = _extract_path(parsed, self._value_path)
        value = _coerce_value(raw_value)

        quality = 1.0
        if self._quality_path:
            raw_quality = _extract_path(parsed, self._quality_path)
            quality = _clamp_quality(float(_coerce_value(raw_quality)))

        payload_ts_ms = now_ms()
        for path in ("timestamp_ms", "metadata.timestamp_ms", "last_seen"):
            try:
                ts_value = _extract_path(parsed, path)
            except AdapterReadError:
                continue
            if isinstance(ts_value, (int, float)):
                ts_int = int(ts_value)
                payload_ts_ms = ts_int * 1000 if ts_int < 10_000_000_000 else ts_int
                break

        self._cache_value(
            topic,
            value,
            {
                "payload": parsed,
                "quality": quality,
                "timestamp_ms": payload_ts_ms,
            },
        )

    async def read(self, sensor_id: str) -> SensorReading:
        self._ensure_aiomqtt_available()
        if not self._connected:
            raise AdapterReadError(
                "ZigbeeAdapter: not connected — call connect() first"
            )
        if self._breaker is None:
            raise AdapterReadError("ZigbeeAdapter: circuit breaker is not initialized")

        async with self._breaker:
            cached = self._cache.get(self._topic)
            if cached is None:
                raise AdapterReadError("ZigbeeAdapter: no MQTT data cached yet")

            value, timestamp_ms, raw_payload = cached
            quality = 1.0
            payload = raw_payload
            if isinstance(raw_payload, dict):
                payload = raw_payload.get("payload", raw_payload)
                quality = _clamp_quality(float(raw_payload.get("quality", 1.0)))
                ts = raw_payload.get("timestamp_ms")
                if isinstance(ts, (int, float)):
                    timestamp_ms = int(ts)

            return SensorReading(
                sensor_id=sensor_id,
                sensor_type=self._sensor_type,
                value=float(value),
                unit=self._unit,
                timestamp=timestamp_ms,
                quality=quality,
                metadata={
                    "source": "zigbee",
                    "topic": self._topic,
                    "value_path": self._value_path,
                    "broker_host": self._broker_host,
                    "port": self._port,
                    "raw_payload": payload,
                },
            )

    async def close(self) -> None:
        await self._close_mqtt()

    @staticmethod
    def _parse_payload(payload: Any) -> dict[str, Any]:
        if isinstance(payload, (bytes, bytearray)):
            text = bytes(payload).decode("utf-8", errors="replace").strip()
        else:
            text = str(payload).strip()
        if not text:
            raise AdapterReadError("ZigbeeAdapter: empty MQTT payload")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AdapterReadError(
                f"ZigbeeAdapter: payload is not valid JSON: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise AdapterReadError("ZigbeeAdapter: payload must be a JSON object")
        return parsed
