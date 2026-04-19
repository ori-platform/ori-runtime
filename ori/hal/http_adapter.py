# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import time
from typing import Any

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    BaseAdapter,
    HardwareCircuitBreaker,
)
from ori.network.events import SensorReading

logger = logging.getLogger(__name__)

try:
    import httpx as _httpx  # type: ignore[import-untyped]

    _HTTPX_AVAILABLE = True
except ImportError:
    _httpx = None
    _HTTPX_AVAILABLE = False

_DEFAULT_POLL_INTERVAL_MS = 10_000
_DEFAULT_TIMEOUT_S = 5.0


def _now_ms() -> int:
    return int(time.time() * 1000)


class HttpAdapter(BaseAdapter):
    """Virtual sensor adapter that polls JSON-over-HTTP endpoints."""

    def __init__(self) -> None:
        self._connected = False
        self._sensor_id: str = ""
        self._sensor_type: str = ""
        self._unit: str = ""
        self._url: str = ""
        self._json_path: str = ""
        self._poll_interval_ms: int = _DEFAULT_POLL_INTERVAL_MS
        self._timeout_s: float = _DEFAULT_TIMEOUT_S
        self._cached_reading: SensorReading | None = None
        self._poll_task: asyncio.Task[None] | None = None
        self._breaker: HardwareCircuitBreaker | None = None

    @property
    def is_connected(self) -> bool:
        return self._connected and _HTTPX_AVAILABLE

    async def connect(self, config: dict) -> None:
        if not _HTTPX_AVAILABLE or _httpx is None:
            raise AdapterConnectionError(
                "HttpAdapter: 'httpx' is not installed. Run: pip install httpx"
            )

        self._sensor_id = str(config.get("sensor_id", "")).strip()
        self._sensor_type = str(config.get("sensor_type", "")).strip()
        self._url = str(config.get("url", "")).strip()
        self._json_path = str(config.get("json_path", "")).strip()
        self._unit = str(config.get("unit", "")).strip()
        self._poll_interval_ms = int(
            config.get("poll_interval_ms", _DEFAULT_POLL_INTERVAL_MS)
        )
        self._timeout_s = float(config.get("timeout_s", _DEFAULT_TIMEOUT_S))
        self._breaker = HardwareCircuitBreaker(self.adapter_name, config)

        if not self._sensor_type:
            raise AdapterConnectionError("HttpAdapter: 'sensor_type' is required")
        if not self._url:
            raise AdapterConnectionError("HttpAdapter: 'url' is required")
        if not self._json_path:
            raise AdapterConnectionError("HttpAdapter: 'json_path' is required")
        if self._poll_interval_ms < 100:
            raise AdapterConnectionError("HttpAdapter: poll_interval_ms must be >= 100")
        if self._timeout_s <= 0:
            raise AdapterConnectionError("HttpAdapter: timeout_s must be > 0")

        self._connected = True
        self._poll_task = asyncio.create_task(
            self._poll_loop(),
            name=f"http-poll:{self._sensor_id or self._sensor_type}",
        )

    async def read(self, sensor_id: str) -> SensorReading:
        if not self._connected:
            raise AdapterReadError("HttpAdapter: not connected — call connect() first")
        if self._cached_reading is None:
            raise AdapterReadError(
                "HttpAdapter: no data available yet (polling in progress)"
            )
        reading = self._cached_reading
        if reading.sensor_id == sensor_id:
            return reading
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type=reading.sensor_type,
            value=reading.value,
            unit=reading.unit,
            timestamp=reading.timestamp,
            quality=reading.quality,
            metadata=dict(reading.metadata),
            raw=reading.raw,
        )

    async def close(self) -> None:
        task = self._poll_task
        self._poll_task = None
        self._connected = False
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def _poll_loop(self) -> None:
        while self._connected:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                break
            except AdapterReadError as exc:
                # Keep last cached value if available.
                logger.warning(
                    "HttpAdapter: poll failed for url=%s json_path=%s: %s",
                    self._url,
                    self._json_path,
                    exc,
                )
            except Exception:
                logger.exception(
                    "HttpAdapter: unexpected poll-loop error for url=%s", self._url
                )
            try:
                await asyncio.sleep(self._poll_interval_ms / 1000.0)
            except asyncio.CancelledError:
                break

    async def _poll_once(self) -> None:
        if self._breaker is None:
            raise AdapterReadError("HttpAdapter: circuit breaker is not initialized")
        if not _HTTPX_AVAILABLE or _httpx is None:
            raise AdapterReadError(
                "HttpAdapter: 'httpx' is not installed. Run: pip install httpx"
            )

        async with self._breaker:
            try:
                async with _httpx.AsyncClient(timeout=self._timeout_s) as client:
                    response = await client.get(self._url)
                    raise_for_status = getattr(response, "raise_for_status", None)
                    if callable(raise_for_status):
                        raise_for_status()
                    payload = response.json()
                value = self._extract(payload, self._json_path)
            except AdapterReadError:
                raise
            except Exception as exc:
                raise AdapterReadError(
                    f"HttpAdapter: HTTP poll failed for url={self._url}: {exc}"
                ) from exc

            self._cached_reading = SensorReading(
                sensor_id=self._sensor_id or self._sensor_type,
                sensor_type=self._sensor_type,
                value=value,
                unit=self._unit,
                timestamp=_now_ms(),
                quality=1.0,
                metadata={
                    "source": "http",
                    "url": self._url,
                    "json_path": self._json_path,
                },
            )

    @staticmethod
    def _extract(data: dict[str, Any], json_path: str) -> float:
        current: Any = data
        for part in json_path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                raise AdapterReadError(
                    f"HttpAdapter: json_path '{json_path}' not found in response"
                )
        try:
            return float(current)
        except (TypeError, ValueError) as exc:
            raise AdapterReadError(
                f"HttpAdapter: extracted value at '{json_path}' is not numeric"
            ) from exc
