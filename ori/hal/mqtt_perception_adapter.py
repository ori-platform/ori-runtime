# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json
from typing import Any

from ori.hal.base import AdapterConnectionError, AdapterReadError
from ori.hal.mqtt_base import MqttCachedAdapter
from ori.network.events import SensorReading
from ori.utils.time_utils import now_ms

_DEFAULT_PORT = 1883
_CONTRACT_VERSION = "ori.perception.v1"
_SUPPORTED_SENSOR_TYPES = frozenset(
    {
        "ppe_hardhat_violation_score",
        "ppe_vest_violation_score",
    }
)


def _clamp_quality(value: float) -> float:
    return max(0.0, min(1.0, value))


class MqttPerceptionAdapter(MqttCachedAdapter):
    """MQTT adapter for external perception streams using ori.perception.v1."""

    def __init__(self) -> None:
        super().__init__()
        self._sensor_type: str = ""
        self._topic: str = ""

    async def connect(self, config: dict) -> None:
        sensor_type = str(config.get("sensor_type", "")).strip()
        if sensor_type not in _SUPPORTED_SENSOR_TYPES:
            raise AdapterConnectionError(
                f"MqttPerceptionAdapter: unsupported sensor_type '{sensor_type}'. "
                f"Supported: {sorted(_SUPPORTED_SENSOR_TYPES)}"
            )
        topic = str(config.get("topic", "")).strip()
        if not topic:
            raise AdapterConnectionError(
                "MqttPerceptionAdapter: 'topic' is required in sensor config."
            )

        self._sensor_type = sensor_type
        self._topic = topic

        await self._connect_mqtt(
            config=config,
            topics=[topic],
            default_port=_DEFAULT_PORT,
            listener_name=f"perception-listener:{topic}",
        )

    async def _handle_message(self, topic: str, payload: Any) -> None:
        parsed = self._parse_payload(payload)
        payload_sensor_type = str(parsed.get("sensor_type", "")).strip()
        if payload_sensor_type != self._sensor_type:
            return

        value = float(parsed["value"])
        self._cache_value(topic, value, parsed)

    async def read(self, sensor_id: str) -> SensorReading:
        self._ensure_aiomqtt_available()
        if not self._connected:
            raise AdapterReadError(
                "MqttPerceptionAdapter: not connected — call connect() first"
            )
        if self._breaker is None:
            raise AdapterReadError(
                "MqttPerceptionAdapter: circuit breaker is not initialized"
            )

        async with self._breaker:
            cached = self._cache.get(self._topic)
            if cached is None:
                raise AdapterReadError(
                    "MqttPerceptionAdapter: no perception message cached yet"
                )

            value, timestamp_ms, raw_payload = cached
            payload = raw_payload if isinstance(raw_payload, dict) else {}
            confidence = _clamp_quality(float(payload.get("confidence", 0.0)))
            payload_ts = payload.get("timestamp_ms")
            if isinstance(payload_ts, (int, float)):
                timestamp_ms = int(payload_ts)
            meta = payload.get("metadata", {})
            metadata = meta if isinstance(meta, dict) else {}

            return SensorReading(
                sensor_id=sensor_id,
                sensor_type=self._sensor_type,
                value=float(value),
                unit="score",
                timestamp=timestamp_ms,
                quality=confidence,
                metadata={
                    **metadata,
                    "source": "mqtt_perception",
                    "schema": _CONTRACT_VERSION,
                    "topic": self._topic,
                    "broker_host": self._broker_host,
                    "port": self._port,
                },
            )

    async def close(self) -> None:
        await self._close_mqtt()

    def _parse_payload(self, payload: Any) -> dict[str, Any]:
        if isinstance(payload, (bytes, bytearray)):
            text = bytes(payload).decode("utf-8", errors="replace").strip()
        else:
            text = str(payload).strip()
        if not text:
            raise AdapterReadError("Perception payload is empty")

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AdapterReadError(
                f"Perception payload is not valid JSON: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise AdapterReadError("Perception payload must be a JSON object")

        schema = str(parsed.get("schema", "")).strip()
        if schema != _CONTRACT_VERSION:
            raise AdapterReadError(
                f"Perception payload schema must be '{_CONTRACT_VERSION}'"
            )

        sensor_type = str(parsed.get("sensor_type", "")).strip()
        if sensor_type not in _SUPPORTED_SENSOR_TYPES:
            raise AdapterReadError(
                f"Perception payload has unsupported sensor_type '{sensor_type}'"
            )

        value = parsed.get("value", parsed.get("violation_score"))
        if not isinstance(value, (int, float)):
            raise AdapterReadError("Perception payload field 'value' must be numeric")
        if float(value) < 0.0 or float(value) > 1.0:
            raise AdapterReadError("Perception payload 'value' must be within 0.0..1.0")
        parsed["value"] = float(value)

        confidence = parsed.get("confidence")
        if not isinstance(confidence, (int, float)):
            raise AdapterReadError(
                "Perception payload field 'confidence' must be numeric"
            )
        if float(confidence) < 0.0 or float(confidence) > 1.0:
            raise AdapterReadError(
                "Perception payload 'confidence' must be within 0.0..1.0"
            )
        parsed["confidence"] = float(confidence)

        if "timestamp_ms" not in parsed:
            parsed["timestamp_ms"] = now_ms()
        elif not isinstance(parsed.get("timestamp_ms"), (int, float)):
            raise AdapterReadError(
                "Perception payload field 'timestamp_ms' must be numeric"
            )

        metadata = parsed.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            raise AdapterReadError(
                "Perception payload field 'metadata' must be a mapping"
            )
        if metadata is None:
            parsed["metadata"] = {}

        return parsed
