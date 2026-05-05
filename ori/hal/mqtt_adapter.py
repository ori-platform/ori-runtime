# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Generic MQTT telemetry adapter (subscribe + cache read pattern)."""

from __future__ import annotations

import json
from typing import Any

from ori.hal.base import AdapterConnectionError, AdapterReadError
from ori.hal.mqtt_base import MqttCachedAdapter
from ori.network.events import SensorReading
from ori.time_utils import now_ms

_DEFAULT_PORT = 1883


def _extract_path(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            if part not in current:
                raise AdapterReadError(
                    f"MqttAdapter: path '{path}' not found in payload"
                )
            current = current[part]
            continue
        if isinstance(current, list):
            try:
                idx = int(part)
            except ValueError as exc:
                raise AdapterReadError(
                    f"MqttAdapter: path '{path}' expects numeric list index at '{part}'"
                ) from exc
            if idx < 0 or idx >= len(current):
                raise AdapterReadError(
                    f"MqttAdapter: list index {idx} out of range for '{path}'"
                )
            current = current[idx]
            continue
        raise AdapterReadError(
            f"MqttAdapter: cannot traverse path '{path}' through {type(current).__name__}"
        )
    return current


def _coerce_float(value: Any) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    token = str(value).strip()
    if not token:
        raise AdapterReadError("MqttAdapter: empty value")
    try:
        return float(token)
    except ValueError as exc:
        raise AdapterReadError(f"MqttAdapter: value is not numeric: {value!r}") from exc


def _clamp_quality(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


class MqttAdapter(MqttCachedAdapter):
    """Subscribe to one MQTT topic and return cached numeric sensor readings."""

    def __init__(self) -> None:
        super().__init__()
        self._sensor_type: str = ""
        self._topic: str = ""
        self._value_path: str = "value"
        self._quality_path: str = ""
        self._unit: str = ""

    async def connect(self, config: dict) -> None:
        sensor_type = str(config.get("sensor_type", "")).strip()
        if not sensor_type:
            raise AdapterConnectionError("MqttAdapter: 'sensor_type' is required")

        topic = str(config.get("topic", "")).strip()
        if not topic:
            raise AdapterConnectionError("MqttAdapter: 'topic' is required")

        self._sensor_type = sensor_type
        self._topic = topic
        self._value_path = str(config.get("value_path", "value")).strip()
        self._quality_path = str(config.get("quality_path", "")).strip()
        self._unit = str(config.get("unit", "")).strip()

        await self._connect_mqtt(
            config=config,
            topics=[topic],
            default_port=_DEFAULT_PORT,
            listener_name=f"mqtt-listener:{topic}",
        )

    async def _handle_message(self, topic: str, payload: Any) -> None:
        parsed = self._parse_payload(payload)
        raw_value = _extract_path(parsed, self._value_path)
        value = _coerce_float(raw_value)

        quality = 1.0
        if self._quality_path:
            raw_quality = _extract_path(parsed, self._quality_path)
            quality = _clamp_quality(_coerce_float(raw_quality))

        timestamp_ms = now_ms()
        self._cache_value(
            topic,
            value,
            {
                "payload": parsed,
                "quality": quality,
                "timestamp_ms": timestamp_ms,
            },
        )

    async def read(self, sensor_id: str) -> SensorReading:
        self._ensure_aiomqtt_available()
        if not self._connected:
            raise AdapterReadError("MqttAdapter: not connected — call connect() first")
        if self._breaker is None:
            raise AdapterReadError("MqttAdapter: circuit breaker is not initialized")

        async with self._breaker:
            cached = self._cache.get(self._topic)
            if cached is None:
                raise AdapterReadError("MqttAdapter: no MQTT data cached yet")

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
                    "source": "mqtt",
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
            raise AdapterReadError("MqttAdapter: empty MQTT payload")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AdapterReadError(
                f"MqttAdapter: payload is not valid JSON: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise AdapterReadError("MqttAdapter: payload must be a JSON object")
        return parsed
