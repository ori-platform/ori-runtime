# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""CoAP telemetry adapter with cached polling semantics."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from urllib.parse import urlparse

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    AdapterTimeoutError,
    BaseAdapter,
    HardwareCircuitBreaker,
)
from ori.network.events import SensorReading
from ori.time_utils import now_ms

logger = logging.getLogger(__name__)

try:
    import aiocoap as _aiocoap  # type: ignore[import-untyped]

    _AIOCOAP_AVAILABLE = True
except ImportError:
    _aiocoap = None
    _AIOCOAP_AVAILABLE = False

_DEFAULT_POLL_INTERVAL_MS = 10_000
_DEFAULT_TIMEOUT_S = 2.0
_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "DELETE"})


class CoapAdapter(BaseAdapter):
    """Virtual sensor adapter that polls CoAP endpoints and caches latest value."""

    def __init__(self) -> None:
        self._connected = False
        self._sensor_id: str = ""
        self._sensor_type: str = ""
        self._unit: str = ""
        self._uri: str = ""
        self._method: str = "GET"
        self._payload: bytes = b""
        self._json_path: str = ""
        self._poll_interval_ms: int = _DEFAULT_POLL_INTERVAL_MS
        self._timeout_s: float = _DEFAULT_TIMEOUT_S
        self._allowed_hosts: set[str] = set()
        self._cached_reading: SensorReading | None = None
        self._poll_task: asyncio.Task[None] | None = None
        self._breaker: HardwareCircuitBreaker | None = None
        self._context: Any = None

    @property
    def is_connected(self) -> bool:
        return self._connected and _AIOCOAP_AVAILABLE

    async def connect(self, config: dict) -> None:
        if not _AIOCOAP_AVAILABLE or _aiocoap is None:
            raise AdapterConnectionError(
                "CoapAdapter: 'aiocoap' is not installed. Run: pip install aiocoap"
            )

        self._sensor_id = str(config.get("sensor_id", "")).strip()
        self._sensor_type = str(config.get("sensor_type", "")).strip()
        self._uri = str(config.get("uri", "")).strip()
        self._method = str(config.get("method", "GET")).strip().upper()
        self._json_path = str(config.get("json_path", "")).strip()
        self._unit = str(config.get("unit", "")).strip()
        self._poll_interval_ms = int(
            config.get("poll_interval_ms", _DEFAULT_POLL_INTERVAL_MS)
        )
        self._timeout_s = float(config.get("timeout_s", _DEFAULT_TIMEOUT_S))
        self._payload = self._encode_payload(config.get("payload", ""))
        self._breaker = HardwareCircuitBreaker(self.adapter_name, config)

        allowed_hosts = config.get("allowed_hosts", []) or []
        self._allowed_hosts = {
            str(host).strip().lower() for host in allowed_hosts if str(host).strip()
        }

        if not self._sensor_type:
            raise AdapterConnectionError("CoapAdapter: 'sensor_type' is required")
        if not self._uri:
            raise AdapterConnectionError("CoapAdapter: 'uri' is required")
        if not self._json_path:
            raise AdapterConnectionError("CoapAdapter: 'json_path' is required")
        if self._method not in _ALLOWED_METHODS:
            raise AdapterConnectionError(
                f"CoapAdapter: method must be one of {sorted(_ALLOWED_METHODS)}"
            )
        if self._poll_interval_ms < 100:
            raise AdapterConnectionError("CoapAdapter: poll_interval_ms must be >= 100")
        if self._timeout_s <= 0:
            raise AdapterConnectionError("CoapAdapter: timeout_s must be > 0")
        self._validate_target()

        try:
            self._context = await _aiocoap.Context.create_client_context()
        except Exception as exc:
            raise AdapterConnectionError(
                f"CoapAdapter: failed to create aiocoap client context: {exc}"
            ) from exc

        self._connected = True
        self._poll_task = asyncio.create_task(
            self._poll_loop(),
            name=f"coap-poll:{self._sensor_id or self._sensor_type}",
        )

    async def read(self, sensor_id: str) -> SensorReading:
        if not self._connected:
            raise AdapterReadError("CoapAdapter: not connected — call connect() first")
        if self._cached_reading is None:
            raise AdapterReadError(
                "CoapAdapter: no data available yet (polling in progress)"
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
        await self._shutdown_context()

    async def _poll_loop(self) -> None:
        while self._connected:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                break
            except (AdapterReadError, AdapterTimeoutError) as exc:
                logger.warning(
                    "CoapAdapter: poll failed for uri=%s json_path=%s: %s",
                    self._uri,
                    self._json_path,
                    exc,
                )
            except Exception:
                logger.exception(
                    "CoapAdapter: unexpected poll-loop error for uri=%s", self._uri
                )
            try:
                await asyncio.sleep(self._poll_interval_ms / 1000.0)
            except asyncio.CancelledError:
                break

    async def _poll_once(self) -> None:
        if self._breaker is None:
            raise AdapterReadError("CoapAdapter: circuit breaker is not initialized")
        if not _AIOCOAP_AVAILABLE or _aiocoap is None:
            raise AdapterReadError(
                "CoapAdapter: 'aiocoap' is not installed. Run: pip install aiocoap"
            )
        if self._context is None:
            raise AdapterReadError("CoapAdapter: aiocoap context is not initialized")

        async with self._breaker:
            code = getattr(_aiocoap, self._method, None)
            if code is None:
                raise AdapterReadError(
                    f"CoapAdapter: method constant missing for {self._method!r}"
                )
            request = _aiocoap.Message(code=code, uri=self._uri, payload=self._payload)

            try:
                response = await asyncio.wait_for(
                    self._context.request(request).response,
                    timeout=self._timeout_s,
                )
            except asyncio.TimeoutError as exc:
                raise AdapterTimeoutError(
                    f"CoapAdapter: timeout polling uri={self._uri}"
                ) from exc
            except Exception as exc:
                raise AdapterReadError(
                    f"CoapAdapter: request failed for uri={self._uri}: {exc}"
                ) from exc

            payload = self._decode_payload(response.payload)
            value = self._extract(payload, self._json_path)
            self._cached_reading = SensorReading(
                sensor_id=self._sensor_id or self._sensor_type,
                sensor_type=self._sensor_type,
                value=value,
                unit=self._unit,
                timestamp=now_ms(),
                quality=1.0,
                metadata={
                    "source": "coap",
                    "uri": self._uri,
                    "json_path": self._json_path,
                    "method": self._method,
                },
                raw=bytes(response.payload),
            )

    async def _shutdown_context(self) -> None:
        context = self._context
        self._context = None
        if context is None:
            return
        try:
            await context.shutdown()
        except Exception:
            logger.debug("CoapAdapter: context shutdown failed", exc_info=True)

    def _validate_target(self) -> None:
        parsed = urlparse(self._uri)
        if parsed.scheme not in {"coap", "coaps"}:
            raise AdapterConnectionError("CoapAdapter: uri must use coap/coaps scheme")

        host = (parsed.hostname or "").strip().lower()
        if not host:
            raise AdapterConnectionError("CoapAdapter: uri host is required")

        if not self._allowed_hosts:
            raise AdapterConnectionError(
                "CoapAdapter: allowed_hosts is required and must be non-empty"
            )
        if host not in self._allowed_hosts:
            raise AdapterConnectionError(
                f"CoapAdapter: host {host!r} is not in allowed_hosts"
            )

    @staticmethod
    def _encode_payload(payload: object) -> bytes:
        if payload is None:
            return b""
        if isinstance(payload, (bytes, bytearray)):
            return bytes(payload)
        if isinstance(payload, (dict, list)):
            return json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )
        return str(payload).encode("utf-8")

    @staticmethod
    def _decode_payload(payload: bytes) -> dict[str, Any]:
        try:
            raw = payload.decode("utf-8")
        except Exception as exc:
            raise AdapterReadError("CoapAdapter: payload is not valid UTF-8") from exc

        try:
            parsed = json.loads(raw)
        except Exception as exc:
            raise AdapterReadError("CoapAdapter: payload is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise AdapterReadError("CoapAdapter: payload JSON must be an object")
        return parsed

    @staticmethod
    def _extract(data: dict[str, Any], json_path: str) -> float:
        current: Any = data
        for part in json_path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                raise AdapterReadError(
                    f"CoapAdapter: json_path '{json_path}' not found in response"
                )
        try:
            return float(current)
        except (TypeError, ValueError) as exc:
            raise AdapterReadError(
                f"CoapAdapter: extracted value at '{json_path}' is not numeric"
            ) from exc
