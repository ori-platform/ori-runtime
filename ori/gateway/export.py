# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""MQTT export responder for gateway-owned reporting and sync.

The gateway asks for runtime-owned data over MQTT instead of reading SQLite
files directly. This module keeps the boundary read-only and provider-neutral:
requests are bounded, device-scoped, and routed through StateStore export APIs.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from dataclasses import dataclass, field, replace
from typing import Any, Awaitable, Callable, cast

from ori.gateway import export_paging
from ori.gateway.mqtt_retry import (
    MqttSession,
    serve_with_reconnect,
    start_mqtt_client,
)
from ori.gateway.mqtt_security import parse_gateway_broker_url
from ori.gateway.payload_bounds import (
    EXPORT_REQUEST,
    EXPORT_RESPONSE,
    IN_FLIGHT_EXCEEDED,
    IngressBound,
    bounded_error,
    fits,
    fitting_count,
    routing_id,
)
from ori.gateway.route_io import Slots
from ori.security.gateway_messages import (
    GatewayMessageAuthenticator,
    GatewayMessageAuthError,
    GatewayMessageEncryptor,
)
from ori.security.payload_members import (
    EXPORT_REQUEST_MEMBERS,
    PayloadMemberError,
    admitted_text,
)
from ori.utils.coalesced_log import CoalescedWarning

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
DEFAULT_SENSOR_BUCKET_MS = 0
ITEM_EXCEEDS_PAYLOAD_MAXIMUM = "item_exceeds_payload_maximum"
#: Export requests being answered at once. A stalled store would otherwise
#: let requests the rate admits wait without limit; past it one is dropped.
EXPORT_IN_FLIGHT_BOUND = 4


@dataclass(frozen=True)
class ExportResponse:
    request_id: str
    export_type: str
    device_id: str
    items: list[dict[str, Any]] = field(default_factory=list)
    next_page_token: str = ""
    complete: bool = True
    error: str | None = None
    #: The token that continues after each item, so a page cut to fit
    #: continues from the last item it holds. Not on the wire.
    item_tokens: tuple[str, ...] = ()

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
        health_snapshot_provider: Callable[
            [], dict[str, Any] | Awaitable[dict[str, Any]]
        ],
        message_auth: GatewayMessageAuthenticator | None = None,
        message_encryptor: GatewayMessageEncryptor | None = None,
    ) -> None:
        if message_encryptor is not None and message_auth is None:
            raise ValueError("gateway export encryption requires message_auth")
        self._device_id = str(device_id)
        # Page tokens verify only under this responder's key, so a token built
        # from the public inputs, or one from before a restart, is refused.
        self._page_key = export_paging.new_key()
        self._state_store = state_store
        self._health_snapshot_provider = health_snapshot_provider
        self._message_auth = message_auth
        self._message_encryptor = message_encryptor
        #: Records a request refused under the Payload Member Rule; the
        #: subscriber sets its family's ingress counter here.
        self.refusal_recorder: Callable[[str], None] | None = None
        self._refusal_log = CoalescedWarning(logger)

    @property
    def request_topic(self) -> str:
        return EXPORT_REQUEST_TOPIC_TEMPLATE.format(device_id=self._device_id)

    def response_topic(self, request_id: str) -> str:
        if not routing_id(request_id):
            raise ValueError("request_id is outside gateway-api/v2's routing form")
        return EXPORT_RESPONSE_TOPIC_TEMPLATE.format(
            device_id=self._device_id, request_id=request_id
        )

    async def handle_payload(
        self, payload: bytes | str | dict[str, Any]
    ) -> ExportResponse | None:
        """The response to *payload*, or None when it is refused unanswered.

        A request whose `request_id` is not JSON text in gateway-api/v2's
        routing form names no response topic that can be relied on, so it is
        not answered, as an oversized payload is not. Nor is one whose
        envelope does not verify, as the inbound evidence route does not
        answer one.
        """
        request = self._decode_payload(payload)
        if request is None or not routing_id(request.get("request_id")):
            return None
        request_id = str(request["request_id"])
        if self._message_auth is not None:
            try:
                request = await self._message_auth.verify_async(
                    request,
                    message_type="export_request",
                    expected_device_id=self._device_id,
                    expected_request_id=request_id,
                )
            except GatewayMessageAuthError as exc:
                # Not answered: a signed reply to an unauthenticated request
                # would hand anything on the site network a signing oracle.
                self._refusal_log.warn(
                    "unauthenticated",
                    "[gateway-export] unauthenticated request dropped: %s",
                    exc,
                )
                return None
            except Exception:
                logger.exception("[gateway-export] verifying a request failed")
                return None
        return await self.handle_request(request)

    async def handle_request(self, request: dict[str, Any]) -> ExportResponse | None:
        if not routing_id(request.get("request_id")):
            return None
        request_id = str(request["request_id"])
        try:
            return await self._handle_request(request, request_id)
        except _ExportRequestError as exc:
            return self._error_response(
                request_id=request_id,
                export_type=_echoed_export_type(request),
                error=exc.message,
            )
        except Exception:
            logger.exception("[gateway-export] unhandled request failure")
            return self._error_response(
                request_id=request_id,
                export_type=_echoed_export_type(request),
                error="internal_error",
            )

    async def _handle_request(
        self, request: dict[str, Any], request_id: str
    ) -> ExportResponse:
        export_type = _required_text(request, "export_type")
        if export_type not in SUPPORTED_EXPORT_TYPES:
            raise _ExportRequestError("unsupported export_type")

        requested_device_id = _required_text(request, "device_id")
        if requested_device_id != self._device_id:
            raise _ExportRequestError("device_id does not match this runtime")

        limit = _bounded_limit(request.get("limit", 100))
        since_ms = _optional_int(request.get("since_ms"), "since_ms")
        until_ms = _optional_int(request.get("until_ms"), "until_ms")
        if since_ms is not None and until_ms is not None and until_ms < since_ms:
            raise _ExportRequestError("until_ms must be >= since_ms")
        params = request.get("params") or {}
        if not isinstance(params, dict):
            raise _ExportRequestError("params must be an object")

        if export_type == "health":
            snapshot = self._health_snapshot_provider()
            if inspect.isawaitable(snapshot):
                snapshot = await snapshot
            items = [dict(snapshot)]
            return ExportResponse(
                request_id=request_id,
                export_type=export_type,
                device_id=self._device_id,
                items=items,
            )

        digest = export_paging.filter_digest(export_type, since_ms, until_ms, params)
        page = _Page(request_id, export_type, limit, digest)
        if export_type == "sensor_history":
            return await self._sensor_history_response(
                page, request.get("page_token", ""), params, since_ms, until_ms
            )
        after = self._position(request.get("page_token", ""), digest, 2)

        if export_type == "action_log":
            rows = await self._state_store.export_action_log(
                device_id=self._device_id,
                since_ms=since_ms,
                until_ms=until_ms,
                tier=str(params.get("tier", "") or "") or None,
                limit=limit + 1,
                after=_pair(after),
                positioned=True,
            )
            return self._paged_response(page, rows)

        if export_type == "reasoning_log":
            rows = await self._state_store.export_reasoning_log(
                device_id=self._device_id,
                since_ms=since_ms,
                until_ms=until_ms,
                tier_used=str(params.get("tier_used", "") or "") or None,
                action_tier=str(params.get("action_tier", "") or "") or None,
                reasoning_status=str(params.get("reasoning_status", "") or "") or None,
                correlation_id=str(params.get("correlation_id", "") or "") or None,
                limit=limit + 1,
                after=_pair(after),
                positioned=True,
            )
            return self._paged_response(page, rows)

        rows = await self._state_store.export_tier_c_decision_log(
            device_id=self._device_id,
            since_ms=since_ms,
            until_ms=until_ms,
            limit=limit + 1,
            after=_pair(after),
            positioned=True,
        )
        return self._paged_response(page, rows)

    def _position(self, token: Any, digest: str, arity: int) -> tuple[int, ...] | None:
        try:
            return export_paging.read(
                token,
                key=self._page_key,
                device_id=self._device_id,
                digest=digest,
                arity=arity,
            )
        except export_paging.PageTokenInvalidError:
            raise _ExportRequestError(export_paging.PAGE_TOKEN_INVALID) from None

    async def _sensor_history_response(
        self,
        page: _Page,
        token: Any,
        params: dict[str, Any],
        since_ms: int | None,
        until_ms: int | None,
    ) -> ExportResponse:
        sensor_id = str(params.get("sensor_id", "") or "").strip()
        if not sensor_id:
            raise _ExportRequestError("params.sensor_id is required")
        start_ms = since_ms
        end_ms = until_ms
        if start_ms is None or end_ms is None:
            raise _ExportRequestError(
                "since_ms and until_ms are required for sensor_history"
            )
        bucket_ms = _optional_int(
            params.get("bucket_ms", DEFAULT_SENSOR_BUCKET_MS), "params.bucket_ms"
        )
        bucket_ms = int(bucket_ms or 0)
        if bucket_ms < 0:
            raise _ExportRequestError("params.bucket_ms must be >= 0")

        if bucket_ms:
            bucket_after = self._position(token, page.digest, 2)
            rows = await self._state_store.export_sensor_buckets(
                sensor_id=sensor_id,
                start_ms=start_ms,
                end_ms=end_ms,
                bucket_ms=bucket_ms,
                limit=page.limit + 1,
                after=_pair(bucket_after),
            )
            return self._paged_response(page, rows)
        row_after = self._position(token, page.digest, 5)
        rows = await self._state_store.export_sensor_history(
            sensor_id=sensor_id,
            start_ms=start_ms,
            end_ms=end_ms,
            limit=page.limit + 1,
            after=cast("tuple[int, int, int, int, int] | None", row_after),
            positioned=True,
        )
        return self._paged_response(page, rows)

    def _paged_response(
        self, page: _Page, rows: list[dict[str, Any]]
    ) -> ExportResponse:
        """One page of *rows*, which holds at most one row past the page.

        Each item's continuation token names its position; the page continues
        after its last item exactly when a further row was found.
        """
        positions = [row.pop("_position") for row in rows]
        kept = rows[: page.limit]
        tokens = tuple(
            export_paging.issue(
                self._page_key, self._device_id, page.digest, tuple(position)
            )
            for position in positions[: page.limit]
        )
        more = len(rows) > page.limit
        return ExportResponse(
            request_id=page.request_id,
            export_type=page.export_type,
            device_id=self._device_id,
            items=kept,
            next_page_token=tokens[-1] if more and tokens else "",
            complete=not more,
            item_tokens=tokens,
        )

    def encode(self, response: ExportResponse) -> bytes:
        """*response* as published, its page cut to its topic's maximum.

        A page holds as many items as fit after encryption, encoding and
        `auth`, and its `next_page_token` continues from the first it no longer
        holds. An item that does not fit by itself ends the export with
        `item_exceeds_payload_maximum` (gateway-api/v2 Payload Size).
        """
        body = self._encode(response)
        if fits(EXPORT_RESPONSE, body):
            return body
        count = fitting_count(
            len(response.items),
            lambda n: fits(EXPORT_RESPONSE, self._encode(_first_items(response, n))),
        )
        if count == 0:
            return self._encode(
                self._error_response(
                    request_id=response.request_id,
                    export_type=response.export_type,
                    error=ITEM_EXCEEDS_PAYLOAD_MAXIMUM,
                )
            )
        return self._encode(_first_items(response, count))

    def _encode(self, response: ExportResponse) -> bytes:
        return response.to_json_bytes(self._message_auth, self._message_encryptor)

    def _decode_payload(
        self, payload: bytes | str | dict[str, Any]
    ) -> dict[str, Any] | None:
        """The request object, or None for a payload that is not one."""
        if isinstance(payload, dict):
            return payload
        # gateway-api/v2 Payload Member Rule, before any member is read: a
        # refused request is not answered, since none of it can be relied on.
        try:
            return admitted_text(payload, defined=EXPORT_REQUEST_MEMBERS)
        except PayloadMemberError as exc:
            if self.refusal_recorder is not None:
                self.refusal_recorder(exc.reason)
            return None

    def _error_response(
        self,
        *,
        request_id: str,
        export_type: str,
        error: str,
    ) -> ExportResponse:
        return ExportResponse(
            request_id=request_id,
            export_type=export_type,
            device_id=self._device_id,
            items=[],
            next_page_token="",
            complete=True,
            error=bounded_error(error),
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
        self._ingress = IngressBound(EXPORT_REQUEST)
        responder.refusal_recorder = self._ingress.refuse
        # Taken in the client's callback thread before anything is scheduled,
        # and held until the response is published or has failed.
        self._slots = Slots(EXPORT_IN_FLIGHT_BOUND)

    @property
    def ingress(self) -> IngressBound:
        """This route's size and rate bound, whose counts health reports."""
        return self._ingress

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        self._loop = asyncio.get_running_loop()
        await serve_with_reconnect(
            shutdown_event,
            connect=self._connect,
            close=self.close,
            log=logger,
            service="gateway-export",
        )

    async def _connect(self, session: MqttSession) -> Any:
        client = self._client_factory(
            client_id=f"ori-export-{self._responder._device_id}"
        )
        self._client = client
        session.bind(
            client,
            subscribe=(self._responder.request_topic, 0),
            on_message=self._on_message,
        )
        await start_mqtt_client(client, self._broker)
        logger.info(
            "[gateway-export] connecting to subscribe to %s via %s:%s",
            self._responder.request_topic,
            self._broker.host,
            self._broker.port,
        )
        return client

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

    def _on_message(self, client: Any, _userdata: Any, message: Any) -> None:
        loop = self._loop
        if loop is None:
            logger.warning("[gateway-export] message received before event loop ready")
            return
        payload = getattr(message, "payload", b"")
        if self._ingress.admit(payload) is not None:
            return
        if not self._slots.try_take():
            self._ingress.refuse(IN_FLIGHT_EXCEEDED)
            return
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._publish_response(client, payload), loop
            )
        except Exception:
            self._slots.give_back()
            raise
        future.add_done_callback(self._settled)

    def _settled(self, future: Any) -> None:
        self._slots.give_back()
        _log_future_failure(future)

    async def _publish_response(self, client: Any, payload: bytes) -> None:
        response = await self._responder.handle_payload(payload)
        if response is None:
            return
        topic = self._responder.response_topic(response.request_id)
        # Off the loop: fitting a page re-encodes, encrypts and signs it.
        body = await asyncio.to_thread(self._responder.encode, response)
        await asyncio.to_thread(client.publish, topic, body, qos=1)


@dataclass(frozen=True)
class _Page:
    """What a page is built for: its request, size and token binding."""

    request_id: str
    export_type: str
    limit: int
    digest: str


def _pair(position: tuple[int, ...] | None) -> tuple[int, int] | None:
    """A two-part position, as the log exports and buckets order by."""
    return None if position is None else (position[0], position[1])


class _ExportRequestError(ValueError):
    """A request answered with an error; *message* is fixed text, never input."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _echoed_export_type(request: dict[str, Any]) -> str:
    """The request's `export_type` if the runtime serves it, else `unknown`.

    Echoing an unsupported one would carry gateway text into a reply that must
    fit the 4096-byte floor.
    """
    export_type = request.get("export_type")
    if isinstance(export_type, str) and export_type in SUPPORTED_EXPORT_TYPES:
        return export_type
    return "unknown"


def _first_items(response: ExportResponse, count: int) -> ExportResponse:
    return replace(
        response,
        items=response.items[:count],
        # A health export is not paged, so it carries no tokens.
        next_page_token=(
            response.item_tokens[count - 1]
            if 0 < count <= len(response.item_tokens)
            else ""
        ),
        complete=False,
        item_tokens=response.item_tokens[:count],
    )


def _default_client_factory(*, client_id: str) -> Any:
    if mqtt is None:
        raise RuntimeError("paho-mqtt is not installed")
    kwargs: dict[str, Any] = {"client_id": client_id}
    callback_api_version = getattr(mqtt, "CallbackAPIVersion", None)
    if callback_api_version is not None:
        kwargs["callback_api_version"] = callback_api_version.VERSION2
    try:
        return mqtt.Client(**kwargs)
    except TypeError:
        kwargs.pop("callback_api_version", None)
        return mqtt.Client(**kwargs)


def _required_text(request: dict[str, Any], key: str) -> str:
    raw = request.get(key, "")
    if not isinstance(raw, str):
        # Taken only as text: str() of a value nested past the recursion
        # limit raises, and of a list or object names no export.
        raise _ExportRequestError(f"{key} must be text")
    value = raw.strip()
    if not value:
        raise _ExportRequestError(f"{key} is required")
    if len(value) > 128:
        raise _ExportRequestError(f"{key} is too long")
    return value


_INT64_MAX = 2**63 - 1


def _optional_int(value: Any, name: str) -> int | None:
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise _ExportRequestError(f"{name} must be an integer") from exc
    if parsed < 0:
        raise _ExportRequestError(f"{name} must be >= 0")
    if parsed > _INT64_MAX:
        raise _ExportRequestError(f"{name} is out of range")
    return parsed


def _bounded_limit(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise _ExportRequestError("limit must be an integer") from exc
    if parsed < 1:
        raise _ExportRequestError("limit must be >= 1")
    return min(parsed, MAX_EXPORT_LIMIT)


def _log_future_failure(future: Any) -> None:
    if future.cancelled():
        # Cancelled at shutdown: nothing failed.
        return
    try:
        future.result()
    except Exception:
        logger.exception("[gateway-export] failed to publish MQTT export response")
