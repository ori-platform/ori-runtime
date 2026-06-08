# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""MQTT export responder for gateway-owned reporting and sync.

The gateway asks for runtime-owned data over MQTT instead of reading SQLite
files directly. This module keeps the boundary read-only and provider-neutral:
requests are bounded, device-scoped, and routed through StateStore export APIs.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from ori.gateway.mqtt_security import apply_tls_context, parse_gateway_broker_url
from ori.security.gateway_messages import (
    GatewayMessageAuthenticator,
    GatewayMessageAuthError,
    GatewayMessageEncryptor,
)

try:
    import paho.mqtt.client as mqtt

    _PAHO_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by monkeypatch in tests
    mqtt = None  # type: ignore[assignment]
    _PAHO_AVAILABLE = False

logger = logging.getLogger(__name__)

EXPORT_REQUEST_TOPIC_TEMPLATE = "ori/{device_id}/export/request"
EXPORT_RESPONSE_TOPIC_TEMPLATE = "ori/{device_id}/export/response/{request_id}"
SUPPORTED_EXPORT_TYPES = {
    "health",
    "sensor_history",
    "action_log",
    "reasoning_log",
    "tier_c_decision_log",
}
SENSITIVE_EXPORT_TYPES = {
    "sensor_history",
    "action_log",
    "reasoning_log",
    "tier_c_decision_log",
}
MAX_EXPORT_LIMIT = 1000
MAX_SENSOR_HISTORY_SOURCE_ROWS = 10_000
DEFAULT_SENSOR_BUCKET_MS = 0


@dataclass(frozen=True)
class ExportResponse:
    request_id: str
    export_type: str
    device_id: str
    items: list[dict[str, Any]] = field(default_factory=list)
    next_page_token: str = ""
    complete: bool = True
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "export_type": self.export_type,
            "device_id": self.device_id,
            "items": self.items,
            "next_page_token": self.next_page_token,
            "complete": self.complete,
            "error": self.error,
        }

    def to_json_bytes(
        self,
        message_auth: GatewayMessageAuthenticator | None = None,
        message_encryptor: GatewayMessageEncryptor | None = None,
    ) -> bytes:
        payload = self.as_dict()
        if message_encryptor is not None and self.export_type in SENSITIVE_EXPORT_TYPES:
            if message_auth is None:
                raise ValueError("gateway export encryption requires message_auth")
            payload = message_encryptor.encrypt(
                payload,
                message_type="export_response",
            )
        if message_auth is not None:
            payload = message_auth.sign(payload, message_type="export_response")
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )


class GatewayExportResponder:
    """Validate gateway export requests and return bounded runtime data."""

    def __init__(
        self,
        *,
        device_id: str,
        state_store: Any,
        health_snapshot_provider: Callable[[], dict[str, Any]],
        message_auth: GatewayMessageAuthenticator | None = None,
        message_encryptor: GatewayMessageEncryptor | None = None,
    ) -> None:
        if message_encryptor is not None and message_auth is None:
            raise ValueError("gateway export encryption requires message_auth")
        self._device_id = str(device_id)
        self._state_store = state_store
        self._health_snapshot_provider = health_snapshot_provider
        self._message_auth = message_auth
        self._message_encryptor = message_encryptor

    @property
    def request_topic(self) -> str:
        return EXPORT_REQUEST_TOPIC_TEMPLATE.format(device_id=self._device_id)

    def response_topic(self, request_id: str) -> str:
        safe_request_id = _safe_topic_segment(str(request_id).strip()) or "invalid"
        return EXPORT_RESPONSE_TOPIC_TEMPLATE.format(
            device_id=self._device_id,
            request_id=safe_request_id,
        )

    async def handle_payload(
        self, payload: bytes | str | dict[str, Any]
    ) -> ExportResponse:
        try:
            request = self._decode_payload(payload)
            if self._message_auth is not None:
                expected_request_id = str(request.get("request_id", "") or "")
                request = self._message_auth.verify(
                    request,
                    message_type="export_request",
                    expected_device_id=self._device_id,
                    expected_request_id=expected_request_id or None,
                )
            return await self.handle_request(request)
        except GatewayMessageAuthError as exc:
            request = self._decode_payload_for_error(payload)
            return self._error_response(
                request_id=str(request.get("request_id", "invalid") or "invalid"),
                export_type=str(request.get("export_type", "unknown") or "unknown"),
                error=f"auth_failed: {exc}",
            )
        except _ExportRequestError as exc:
            return self._error_response(
                request_id=exc.request_id,
                export_type=exc.export_type,
                error=exc.message,
            )
        except Exception as exc:
            logger.exception("[gateway-export] unhandled request failure")
            return self._error_response(
                request_id="invalid",
                export_type="unknown",
                error=f"internal_error: {exc}",
            )

    async def handle_request(self, request: dict[str, Any]) -> ExportResponse:
        try:
            return await self._handle_request(request)
        except _ExportRequestError as exc:
            return self._error_response(
                request_id=exc.request_id,
                export_type=exc.export_type,
                error=exc.message,
            )
        except Exception as exc:
            logger.exception("[gateway-export] unhandled request failure")
            request_id = str(request.get("request_id", "invalid") or "invalid")
            export_type = str(request.get("export_type", "unknown") or "unknown")
            return self._error_response(
                request_id=request_id,
                export_type=export_type,
                error=f"internal_error: {exc}",
            )

    async def _handle_request(self, request: dict[str, Any]) -> ExportResponse:
        request_id = _required_text(request, "request_id")
        if _safe_topic_segment(request_id) != request_id:
            raise _ExportRequestError(
                "request_id must not contain MQTT separators or wildcards",
                request_id="invalid",
                export_type=str(request.get("export_type", "unknown") or "unknown"),
            )
        export_type = _required_text(request, "export_type")
        if export_type not in SUPPORTED_EXPORT_TYPES:
            raise _ExportRequestError(
                f"unsupported export_type: {export_type}",
                request_id=request_id,
                export_type=export_type,
            )

        requested_device_id = _required_text(request, "device_id")
        if requested_device_id != self._device_id:
            raise _ExportRequestError(
                "device_id does not match this runtime",
                request_id=request_id,
                export_type=export_type,
            )

        try:
            limit = _bounded_limit(request.get("limit", 100))
            offset = _page_offset(request.get("page_token", ""))
            since_ms = _optional_int(request.get("since_ms"), "since_ms")
            until_ms = _optional_int(request.get("until_ms"), "until_ms")
        except _ExportRequestError as exc:
            raise _ExportRequestError(
                exc.message,
                request_id=request_id,
                export_type=export_type,
            ) from exc
        if since_ms is not None and until_ms is not None and until_ms < since_ms:
            raise _ExportRequestError(
                "until_ms must be >= since_ms",
                request_id=request_id,
                export_type=export_type,
            )
        params = request.get("params") or {}
        if not isinstance(params, dict):
            raise _ExportRequestError(
                "params must be an object",
                request_id=request_id,
                export_type=export_type,
            )

        if export_type == "health":
            items = [dict(self._health_snapshot_provider())]
            return ExportResponse(
                request_id=request_id,
                export_type=export_type,
                device_id=self._device_id,
                items=items,
            )

        if export_type == "sensor_history":
            return await self._sensor_history_response(
                request_id=request_id,
                export_type=export_type,
                params=params,
                since_ms=since_ms,
                until_ms=until_ms,
                limit=limit,
                offset=offset,
            )

        if export_type == "action_log":
            rows = await self._state_store.export_action_log(
                device_id=self._device_id,
                since_ms=since_ms,
                until_ms=until_ms,
                tier=str(params.get("tier", "") or "") or None,
                limit=min(MAX_EXPORT_LIMIT, limit + offset + 1),
            )
            return self._paged_response(request_id, export_type, rows, limit, offset)

        if export_type == "reasoning_log":
            rows = await self._state_store.export_reasoning_log(
                device_id=self._device_id,
                since_ms=since_ms,
                until_ms=until_ms,
                tier_used=str(params.get("tier_used", "") or "") or None,
                action_tier=str(params.get("action_tier", "") or "") or None,
                reasoning_status=str(params.get("reasoning_status", "") or "") or None,
                correlation_id=str(params.get("correlation_id", "") or "") or None,
                limit=min(MAX_EXPORT_LIMIT, limit + offset + 1),
            )
            return self._paged_response(request_id, export_type, rows, limit, offset)

        rows = await self._state_store.export_tier_c_decision_log(
            device_id=self._device_id,
            since_ms=since_ms,
            until_ms=until_ms,
            limit=min(MAX_EXPORT_LIMIT, limit + offset + 1),
        )
        return self._paged_response(request_id, export_type, rows, limit, offset)

    async def _sensor_history_response(
        self,
        *,
        request_id: str,
        export_type: str,
        params: dict[str, Any],
        since_ms: int | None,
        until_ms: int | None,
        limit: int,
        offset: int,
    ) -> ExportResponse:
        sensor_id = str(params.get("sensor_id", "") or "").strip()
        if not sensor_id:
            raise _ExportRequestError(
                "params.sensor_id is required",
                request_id=request_id,
                export_type=export_type,
            )
        start_ms = since_ms
        end_ms = until_ms
        if start_ms is None or end_ms is None:
            raise _ExportRequestError(
                "since_ms and until_ms are required for sensor_history",
                request_id=request_id,
                export_type=export_type,
            )
        try:
            bucket_ms = _optional_int(
                params.get("bucket_ms", DEFAULT_SENSOR_BUCKET_MS), "params.bucket_ms"
            )
        except _ExportRequestError as exc:
            raise _ExportRequestError(
                exc.message,
                request_id=request_id,
                export_type=export_type,
            ) from exc
        bucket_ms = int(bucket_ms or 0)
        if bucket_ms < 0:
            raise _ExportRequestError(
                "params.bucket_ms must be >= 0",
                request_id=request_id,
                export_type=export_type,
            )

        source_limit = MAX_SENSOR_HISTORY_SOURCE_ROWS
        rows = await self._state_store.export_sensor_history(
            sensor_id=sensor_id,
            start_ms=start_ms,
            end_ms=end_ms,
            limit=source_limit,
        )
        items = _bucket_sensor_rows(rows, bucket_ms) if bucket_ms else list(rows)
        return self._paged_response(request_id, export_type, items, limit, offset)

    def _paged_response(
        self,
        request_id: str,
        export_type: str,
        rows: list[dict[str, Any]],
        limit: int,
        offset: int,
    ) -> ExportResponse:
        page = rows[offset : offset + limit]
        next_offset = offset + len(page)
        more_rows_known = next_offset < len(rows)
        maybe_truncated_at_source_limit = len(
            rows
        ) >= MAX_EXPORT_LIMIT and next_offset == len(rows)
        next_page_token = (
            str(next_offset)
            if more_rows_known or maybe_truncated_at_source_limit
            else ""
        )
        return ExportResponse(
            request_id=request_id,
            export_type=export_type,
            device_id=self._device_id,
            items=page,
            next_page_token=next_page_token,
            complete=not bool(next_page_token),
        )

    def _decode_payload(self, payload: bytes | str | dict[str, Any]) -> dict[str, Any]:
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, bytes):
            text = payload.decode("utf-8")
        else:
            text = str(payload)
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError as exc:
            raise _ExportRequestError("request payload must be JSON") from exc
        if not isinstance(decoded, dict):
            raise _ExportRequestError("request payload must be a JSON object")
        return decoded

    def _decode_payload_for_error(
        self, payload: bytes | str | dict[str, Any]
    ) -> dict[str, Any]:
        try:
            return self._decode_payload(payload)
        except Exception:
            return {}

    def _error_response(
        self,
        *,
        request_id: str,
        export_type: str,
        error: str,
    ) -> ExportResponse:
        return ExportResponse(
            request_id=request_id or "invalid",
            export_type=export_type or "unknown",
            device_id=self._device_id,
            items=[],
            next_page_token="",
            complete=True,
            error=error,
        )


class MqttGatewayExportServer:
    """Paho-backed MQTT transport for :class:`GatewayExportResponder`."""

    def __init__(
        self,
        *,
        broker_url: str,
        responder: GatewayExportResponder,
        tls_config: dict[str, Any] | None = None,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        if not _PAHO_AVAILABLE or mqtt is None:
            raise RuntimeError("paho-mqtt is not installed")
        self._broker = parse_gateway_broker_url(broker_url, tls_config=tls_config)
        self._responder = responder
        self._client_factory = client_factory or _default_client_factory
        self._client: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        self._loop = asyncio.get_running_loop()
        client = self._client_factory(
            client_id=f"ori-export-{self._responder._device_id}"
        )
        self._client = client
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        try:
            username = self._broker.username
            password = self._broker.password
            if username:
                client.username_pw_set(username, password)
            apply_tls_context(client, self._broker)
            await asyncio.to_thread(
                client.connect,
                self._broker.host,
                int(self._broker.port),
                60,
            )
            await asyncio.to_thread(client.loop_start)
            logger.info(
                "[gateway-export] MQTT responder listening on %s via %s:%s",
                self._responder.request_topic,
                self._broker.host,
                self._broker.port,
            )
            await shutdown_event.wait()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("[gateway-export] MQTT responder stopped unexpectedly")
        finally:
            await self.close()

    async def close(self) -> None:
        client = self._client
        self._client = None
        if client is None:
            return
        try:
            await asyncio.to_thread(client.loop_stop)
        except Exception:
            logger.warning("[gateway-export] failed to stop MQTT loop")
        try:
            await asyncio.to_thread(client.disconnect)
        except Exception:
            logger.warning("[gateway-export] failed to disconnect MQTT client")

    def _on_connect(
        self, client: Any, _userdata: Any, _flags: Any, rc: Any, *_: Any
    ) -> None:
        if int(getattr(rc, "value", rc)) != 0:
            logger.warning("[gateway-export] MQTT connect failed rc=%s", rc)
            return
        client.subscribe(self._responder.request_topic)

    def _on_message(self, client: Any, _userdata: Any, message: Any) -> None:
        loop = self._loop
        if loop is None:
            logger.warning("[gateway-export] message received before event loop ready")
            return
        payload = getattr(message, "payload", b"")
        future = asyncio.run_coroutine_threadsafe(
            self._publish_response(client, payload), loop
        )
        future.add_done_callback(_log_future_failure)

    async def _publish_response(self, client: Any, payload: bytes) -> None:
        response = await self._responder.handle_payload(payload)
        topic = self._responder.response_topic(response.request_id)
        await asyncio.to_thread(
            client.publish,
            topic,
            response.to_json_bytes(
                self._responder._message_auth,
                self._responder._message_encryptor,
            ),
            qos=1,
        )


class _ExportRequestError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        request_id: str = "invalid",
        export_type: str = "unknown",
    ) -> None:
        super().__init__(message)
        self.message = message
        self.request_id = request_id or "invalid"
        self.export_type = export_type or "unknown"


def _default_client_factory(*, client_id: str) -> Any:
    if mqtt is None:
        raise RuntimeError("paho-mqtt is not installed")
    kwargs: dict[str, Any] = {"client_id": client_id}
    if hasattr(mqtt, "CallbackAPIVersion"):
        kwargs["callback_api_version"] = mqtt.CallbackAPIVersion.VERSION2
    try:
        return mqtt.Client(**kwargs)
    except TypeError:
        kwargs.pop("callback_api_version", None)
        return mqtt.Client(**kwargs)


def _required_text(request: dict[str, Any], key: str) -> str:
    value = str(request.get(key, "") or "").strip()
    if not value:
        raise _ExportRequestError(f"{key} is required")
    if len(value) > 128:
        raise _ExportRequestError(f"{key} is too long")
    return value


def _safe_topic_segment(value: str) -> str:
    value = str(value or "").strip()
    if not value or len(value) > 128:
        return ""
    if any(ch in value for ch in "/+#"):
        return ""
    return value


def _optional_int(value: Any, name: str) -> int | None:
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise _ExportRequestError(f"{name} must be an integer") from exc
    if parsed < 0:
        raise _ExportRequestError(f"{name} must be >= 0")
    return parsed


def _bounded_limit(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise _ExportRequestError("limit must be an integer") from exc
    if parsed < 1:
        raise _ExportRequestError("limit must be >= 1")
    return min(parsed, MAX_EXPORT_LIMIT)


def _page_offset(value: Any) -> int:
    if value in (None, ""):
        return 0
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise _ExportRequestError("page_token must be an integer offset") from exc
    if parsed < 0:
        raise _ExportRequestError("page_token must be >= 0")
    return parsed


def _bucket_sensor_rows(
    rows: list[dict[str, Any]], bucket_ms: int
) -> list[dict[str, Any]]:
    if bucket_ms <= 0:
        return list(rows)

    buckets: dict[int, dict[str, Any]] = {}
    for row in rows:
        timestamp = int(row.get("timestamp") or 0)
        value = float(row.get("value") or 0.0)
        sample_count = max(1, int(row.get("sample_count") or 1))
        bucket_start = (timestamp // bucket_ms) * bucket_ms
        bucket = buckets.setdefault(
            bucket_start,
            {
                "sensor_id": row.get("sensor_id", ""),
                "sensor_type": row.get("sensor_type", ""),
                "timestamp": bucket_start,
                "start_ms": bucket_start,
                "end_ms": bucket_start + bucket_ms,
                "value": 0.0,
                "avg_value": 0.0,
                "min_value": value,
                "max_value": value,
                "unit": row.get("unit", ""),
                "quality": None,
                "sample_count": 0,
                "bucket_ms": bucket_ms,
                "tier": "bucketed",
                "_weighted_total": 0.0,
            },
        )
        bucket["sample_count"] += sample_count
        bucket["_weighted_total"] += value * sample_count
        bucket["min_value"] = min(float(bucket["min_value"]), value)
        bucket["max_value"] = max(float(bucket["max_value"]), value)

    result = []
    for bucket_start in sorted(buckets):
        bucket = buckets[bucket_start]
        count = max(1, int(bucket["sample_count"]))
        avg = float(bucket.pop("_weighted_total")) / count
        bucket["value"] = avg
        bucket["avg_value"] = avg
        result.append(bucket)
    return result


def _log_future_failure(future: Any) -> None:
    try:
        future.result()
    except Exception:
        logger.exception("[gateway-export] failed to publish MQTT export response")
