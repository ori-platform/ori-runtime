# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""MQTT request/response client for Tier 3 gateway reasoning."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse

from ori.network.events import OriEvent, ReasoningResult
from ori.utils.time_utils import now_ms

try:
    import paho.mqtt.client as mqtt

    _PAHO_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by monkeypatch in tests
    mqtt = None  # type: ignore[assignment]
    _PAHO_AVAILABLE = False

logger = logging.getLogger(__name__)

REASONING_REQUEST_TOPIC_TEMPLATE = "ori/{device_id}/reasoning/request"
REASONING_RESPONSE_TOPIC_TEMPLATE = "ori/{device_id}/reasoning/response"
DEFAULT_GATEWAY_REASONING_TIMEOUT_MS = 10_000
MAX_CONTEXT_HISTORY_POINTS = 10
_VALID_ACTION_TIERS = {"A", "B", "C", "D"}


class GatewayReasoningError(RuntimeError):
    """Raised when a gateway reasoning request cannot produce a valid result."""


@dataclass(frozen=True)
class GatewayReasoningRequest:
    request_id: str
    device_id: str
    sensor_type: str
    trigger_name: str
    prompt: str
    context: dict[str, Any]
    action_tier_hint: str
    timeout_ms: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "device_id": self.device_id,
            "sensor_type": self.sensor_type,
            "trigger_name": self.trigger_name,
            "prompt": self.prompt,
            "context": self.context,
            "action_tier_hint": self.action_tier_hint,
            "timeout_ms": self.timeout_ms,
        }

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.as_dict(), separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )


class MqttGatewayReasoner:
    """Paho-backed Tier 3 reasoner used by :class:`IntelligenceElevator`.

    The client is intentionally request-scoped: each ``reason()`` call connects,
    subscribes, publishes one request, waits for the matching response, then
    closes. Gateway escalation is infrequent and this avoids a long-lived MQTT
    client hidden inside the reasoning path.
    """

    def __init__(
        self,
        *,
        broker_url: str,
        device_id: str,
        timeout_ms: int = DEFAULT_GATEWAY_REASONING_TIMEOUT_MS,
        client_factory: Callable[..., Any] | None = None,
        request_id_factory: Callable[[], str] | None = None,
    ) -> None:
        if not _PAHO_AVAILABLE or mqtt is None:
            raise RuntimeError("paho-mqtt is not installed")
        self._broker = _parse_broker_url(broker_url)
        self._device_id = _validate_topic_segment(
            device_id,
            "device_id",
            strict_ascii=False,
        )
        self._timeout_ms = max(1, int(timeout_ms))
        self._client_factory = client_factory or _default_client_factory
        self._request_id_factory = request_id_factory or (lambda: uuid.uuid4().hex)

    @property
    def request_topic(self) -> str:
        return REASONING_REQUEST_TOPIC_TEMPLATE.format(device_id=self._device_id)

    @property
    def response_topic(self) -> str:
        return REASONING_RESPONSE_TOPIC_TEMPLATE.format(device_id=self._device_id)

    async def reason(
        self,
        prompt: str,
        *,
        event: OriEvent | None = None,
        rule_result: Any = None,
        state_store: Any = None,
    ) -> ReasoningResult:
        request = await self._build_request(
            prompt=prompt,
            event=event,
            rule_result=rule_result,
            state_store=state_store,
        )
        response = await self._round_trip(request)
        return _reasoning_result_from_response(response)

    async def _build_request(
        self,
        *,
        prompt: str,
        event: OriEvent | None,
        rule_result: Any,
        state_store: Any,
    ) -> GatewayReasoningRequest:
        request_id = _validate_topic_segment(
            str(self._request_id_factory() or ""),
            "request_id",
            allow_hyphen=True,
            allow_underscore=True,
        )
        action_tier_hint = str(getattr(rule_result, "action_tier", "A") or "A")
        if action_tier_hint not in _VALID_ACTION_TIERS:
            action_tier_hint = "A"

        reading = event.reading if event is not None else None
        context = {
            "value": float(getattr(reading, "value", 0.0) or 0.0),
            "unit": str(getattr(reading, "unit", "") or ""),
            "timestamp": int(
                getattr(reading, "timestamp", None)
                or getattr(event, "timestamp", None)
                or now_ms()
            ),
            "history": await _history_points(event, state_store),
        }
        return GatewayReasoningRequest(
            request_id=request_id,
            device_id=self._device_id,
            sensor_type=str(getattr(reading, "sensor_type", "") or ""),
            trigger_name=str(getattr(rule_result, "rule_name", "") or ""),
            prompt=str(prompt or ""),
            context=context,
            action_tier_hint=action_tier_hint,
            timeout_ms=self._timeout_ms,
        )

    async def _round_trip(self, request: GatewayReasoningRequest) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        connected = loop.create_future()
        response = loop.create_future()
        client = self._client_factory(client_id=f"ori-reasoning-{self._device_id}")

        def _set_future_result(future: asyncio.Future, value: Any) -> None:
            if not future.done():
                future.set_result(value)

        def _set_future_exception(future: asyncio.Future, exc: BaseException) -> None:
            if not future.done():
                future.set_exception(exc)

        def _on_connect(
            connected_client: Any, _userdata: Any, _flags: Any, rc: Any, *_: Any
        ) -> None:
            rc_value = int(getattr(rc, "value", rc))
            if rc_value != 0:
                loop.call_soon_threadsafe(
                    _set_future_exception,
                    connected,
                    GatewayReasoningError(f"gateway MQTT connect failed rc={rc}"),
                )
                return
            connected_client.subscribe(self.response_topic)
            loop.call_soon_threadsafe(_set_future_result, connected, True)

        def _on_message(_client: Any, _userdata: Any, message: Any) -> None:
            try:
                payload = json.loads(getattr(message, "payload", b"").decode("utf-8"))
            except Exception:
                logger.warning(
                    "[gateway-reasoning] ignoring malformed response payload"
                )
                return
            if not isinstance(payload, dict):
                logger.warning("[gateway-reasoning] ignoring non-object response")
                return
            if str(payload.get("request_id", "")) != request.request_id:
                return
            loop.call_soon_threadsafe(_set_future_result, response, payload)

        client.on_connect = _on_connect
        client.on_message = _on_message

        try:
            username = self._broker.get("username")
            password = self._broker.get("password")
            if username:
                client.username_pw_set(username, password)
            await asyncio.to_thread(
                client.connect,
                self._broker["host"],
                int(self._broker["port"]),
                60,
            )
            await asyncio.to_thread(client.loop_start)
            await asyncio.wait_for(connected, timeout=self._timeout_ms / 1000.0)
            publish_info = await asyncio.to_thread(
                client.publish,
                self.request_topic,
                request.to_json_bytes(),
                1,
                False,
            )
            publish_rc = getattr(publish_info, "rc", 0)
            if int(publish_rc or 0) != 0:
                raise GatewayReasoningError(
                    f"gateway MQTT publish failed rc={publish_rc}"
                )
            return await asyncio.wait_for(response, timeout=self._timeout_ms / 1000.0)
        except asyncio.TimeoutError as exc:
            raise GatewayReasoningError("gateway reasoning response timeout") from exc
        finally:
            try:
                await asyncio.to_thread(client.loop_stop)
            except Exception:
                logger.warning("[gateway-reasoning] failed to stop MQTT loop")
            try:
                await asyncio.to_thread(client.disconnect)
            except Exception:
                logger.warning("[gateway-reasoning] failed to disconnect MQTT client")


async def _history_points(
    event: OriEvent | None,
    state_store: Any,
) -> list[dict[str, Any]]:
    from_context = _history_points_from_context(event)
    if from_context:
        return from_context[:MAX_CONTEXT_HISTORY_POINTS]
    if event is None or event.reading is None or state_store is None:
        return []
    if not hasattr(state_store, "get_history"):
        return []
    try:
        rows = await state_store.get_history(
            event.reading.sensor_id,
            limit=MAX_CONTEXT_HISTORY_POINTS,
        )
    except Exception:
        logger.debug(
            "[gateway-reasoning] failed to load context history for %s",
            event.reading.sensor_id,
        )
        return []
    points = []
    for row in rows[:MAX_CONTEXT_HISTORY_POINTS]:
        points.append(
            {
                "value": float(getattr(row, "value", 0.0) or 0.0),
                "timestamp": int(getattr(row, "timestamp", 0) or 0),
            }
        )
    return points


def _history_points_from_context(event: OriEvent | None) -> list[dict[str, Any]]:
    if event is None or not isinstance(getattr(event, "context", None), dict):
        return []
    raw = event.context.get("history_window")
    if not isinstance(raw, list):
        return []
    points: list[dict[str, Any]] = []
    for row in raw:
        if not isinstance(row, dict):
            continue
        try:
            points.append(
                {
                    "value": float(row.get("value", 0.0) or 0.0),
                    "timestamp": int(
                        row.get("timestamp")
                        or row.get("timestamp_ms")
                        or row.get("reading_timestamp")
                        or 0
                    ),
                }
            )
        except (TypeError, ValueError):
            continue
    return points


def _reasoning_result_from_response(payload: dict[str, Any]) -> ReasoningResult:
    error = payload.get("error")
    if error:
        raise GatewayReasoningError(f"gateway provider error: {error}")
    action_tier = str(payload.get("action_tier", "") or "")
    if action_tier not in _VALID_ACTION_TIERS:
        raise GatewayReasoningError("gateway response action_tier is invalid")
    proposed_action = payload.get("proposed_action")
    if proposed_action is not None:
        proposed_action = str(proposed_action)
    return ReasoningResult(
        text=str(payload.get("text", "") or ""),
        tier="gateway",
        model=str(payload.get("model", "") or "gateway"),
        tokens_used=int(payload.get("tokens_used", 0) or 0),
        latency_ms=int(payload.get("latency_ms", 0) or 0),
        confidence=float(payload.get("confidence", 0.0) or 0.0),
        action_tier=action_tier,
        proposed_action=proposed_action,
    )


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


def _parse_broker_url(broker_url: str) -> dict[str, Any]:
    raw = str(broker_url or "").strip()
    if not raw:
        raise ValueError(
            "gateway.broker_url is required when gateway reasoning is enabled"
        )
    parsed = urlparse(raw if "://" in raw else f"mqtt://{raw}")
    if parsed.scheme not in {"mqtt", "tcp"}:
        raise ValueError("gateway.broker_url must use mqtt:// or tcp://")
    if not parsed.hostname:
        raise ValueError("gateway.broker_url must include a broker host")
    return {
        "host": parsed.hostname,
        "port": parsed.port or 1883,
        "username": parsed.username or "",
        "password": parsed.password or "",
    }


def _validate_topic_segment(
    value: str,
    name: str,
    *,
    allow_hyphen: bool = False,
    allow_underscore: bool = False,
    strict_ascii: bool = True,
) -> str:
    raw = str(value or "")
    value = raw.strip()
    if not value:
        raise ValueError(f"{name} must not be empty")
    if value != raw:
        raise ValueError(f"{name} must not contain leading or trailing whitespace")
    if any(ch in value for ch in "/+#"):
        raise ValueError(f"{name} must not contain MQTT separators or wildcards")
    if not strict_ascii:
        return value
    for ch in value:
        if ch.isascii() and ch.isalnum():
            continue
        if allow_hyphen and ch == "-":
            continue
        if allow_underscore and ch == "_":
            continue
        raise ValueError(
            f"{name} must contain only ASCII letters, digits"
            + (", hyphen" if allow_hyphen else "")
            + (", or underscore" if allow_underscore else "")
        )
    return value
