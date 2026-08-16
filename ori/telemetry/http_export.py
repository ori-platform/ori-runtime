# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""HTTP telemetry export for phone and lightweight provisioned deployments."""

import asyncio
import json
import logging
import os
from dataclasses import asdict
from typing import Any

from ori.config import TelemetryExportConfig
from ori.network.events import OriEvent, SensorReading
from ori.telemetry.canonical import canonical_telemetry_bytes, telemetry_hmac_sha256
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

# Annotated Any so the fallback assignment below needs no ignore: an ignore
# here would be reported unused in whichever environment does not match it.
_httpx: Any
try:
    import httpx as _httpx

    _HTTPX_AVAILABLE = True
except ImportError:
    _httpx = None
    _HTTPX_AVAILABLE = False

SCHEMA_VERSION = "runtime.telemetry.v1"


class HttpTelemetryExporter:
    """Bounded, non-authoritative HTTP telemetry exporter.

    The exporter is intentionally outside the actuation path. It mirrors real
    runtime events to a provisioned telemetry endpoint, but endpoint
    availability must never influence Tier B/C/D action authority.
    """

    def __init__(
        self,
        *,
        device_id: str,
        config: TelemetryExportConfig,
    ) -> None:
        self._device_id = device_id
        self._config = config
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=config.max_queue_size
        )
        self._sequence = 0
        self._dropped_events = 0

    @property
    def dropped_events(self) -> int:
        return self._dropped_events

    async def handle_event(self, event: OriEvent) -> None:
        """Queue one event without blocking EventBus delivery."""
        if event.event_type != "sensor.reading" or event.reading is None:
            return
        try:
            self._queue.put_nowait(_serialize_event(event))
        except asyncio.QueueFull:
            self._dropped_events += 1
            logger.warning(
                "[telemetry-export] queue full; dropped event_id=%s total_dropped=%d",
                event.event_id,
                self._dropped_events,
            )

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        if not _HTTPX_AVAILABLE or _httpx is None:
            logger.warning(
                "[telemetry-export] httpx is unavailable; telemetry export disabled"
            )
            return

        logger.info(
            "[telemetry-export] enabled endpoint=%s batch_size=%d flush_interval=%.1fs",
            self._config.endpoint,
            self._config.batch_size,
            self._config.flush_interval_s,
        )
        while not shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    shutdown_event.wait(),
                    timeout=self._config.flush_interval_s,
                )
                break
            except asyncio.TimeoutError:
                pass
            try:
                await self.flush_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("[telemetry-export] flush loop failed")

        try:
            await self.flush_once()
        except Exception:
            logger.exception("[telemetry-export] final flush failed")

    async def flush_once(self) -> int:
        batch = self._drain_batch()
        if not batch:
            return 0

        api_key = os.environ.get(self._config.api_key_env, "").strip()
        if not api_key:
            logger.warning(
                "[telemetry-export] configured API key environment variable is not set; "
                "telemetry batch retained in memory"
            )
            self._requeue(batch)
            return 0

        try:
            await self._post_batch(batch, api_key)
        except Exception as exc:
            logger.warning(
                "[telemetry-export] POST failed; retaining batch in memory: %s",
                exc,
            )
            self._requeue(batch)
            return 0
        return len(batch)

    def _drain_batch(self) -> list[dict[str, Any]]:
        batch: list[dict[str, Any]] = []
        while len(batch) < self._config.batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch

    def _requeue(self, batch: list[dict[str, Any]]) -> None:
        for item in batch:
            try:
                self._queue.put_nowait(item)
            except asyncio.QueueFull:
                self._dropped_events += 1
                logger.warning(
                    "[telemetry-export] queue full while retaining failed batch; "
                    "dropped telemetry item total_dropped=%d",
                    self._dropped_events,
                )

    async def _post_batch(self, batch: list[dict[str, Any]], api_key: str) -> None:
        self._sequence += 1
        payload = {
            "schema_version": SCHEMA_VERSION,
            "device_id": self._device_id,
            "sequence": self._sequence,
            "sent_at_ms": now_ms(),
            "events": batch,
        }
        body = canonical_telemetry_bytes(payload)
        timestamp_ms = str(now_ms())
        signature = telemetry_hmac_sha256(api_key, timestamp_ms, body)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "X-Ori-Device-Id": self._device_id,
            "X-Ori-Timestamp-Ms": timestamp_ms,
            "X-Ori-Signature": f"v1={signature}",
        }
        timeout_s = self._config.timeout_ms / 1000.0
        async with _httpx.AsyncClient(timeout=timeout_s) as client:
            response = await client.post(
                self._config.endpoint,
                content=body,
                headers=headers,
            )
            raise_for_status = getattr(response, "raise_for_status", None)
            if callable(raise_for_status):
                raise_for_status()


def _serialize_event(event: OriEvent) -> dict[str, Any]:
    reading = event.reading
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "device_id": event.device_id,
        "sensor_id": event.sensor_id,
        "timestamp": event.timestamp,
        "source": event.source,
        "fingerprint": event.fingerprint,
        "context": _json_safe(event.context),
        "reading": _serialize_reading(reading) if reading is not None else None,
    }


def _serialize_reading(reading: SensorReading) -> dict[str, Any]:
    data = asdict(reading)
    data.pop("raw", None)
    # _json_safe is Any-in/Any-out by design; a dict in yields a dict out.
    safe: dict[str, Any] = _json_safe(data)
    return safe


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, dict):
            return {str(k): _json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_json_safe(item) for item in value]
        return str(value)
