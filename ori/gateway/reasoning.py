# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""MQTT request/response client for Tier 3 gateway reasoning."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from ori.gateway.mqtt_retry import reason_code_value
from ori.gateway.mqtt_security import apply_tls_context, parse_gateway_broker_url
from ori.gateway.payload_bounds import (
    REASONING_REQUEST,
    REASONING_RESPONSE,
    IngressBound,
    fits,
    routing_id,
)
from ori.network.events import OriEvent, ReasoningResult, history_as_of
from ori.network.producer_time import NOT_REPORTED, UNKNOWN, read_producer_time
from ori.security.gateway_messages import (
    GatewayMessageAuthenticator,
    GatewayMessageAuthError,
)
from ori.security.payload_members import (
    REASONING_RESPONSE_MEMBERS,
    PayloadMemberError,
    admitted_text,
)
from ori.utils.mqtt_suback import subscription_refusal
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
MAX_GATEWAY_REASONING_TIMEOUT_MS = 86_400_000
MAX_CONTEXT_HISTORY_POINTS = 10
_VALID_ACTION_TIERS = {"A", "B", "C", "D"}
# The greatest receipt gateway-api/v2 admits: an integer a JSON double holds exactly.
_MAX_SAFE_INTEGER = 2**53 - 1


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

    def to_json_bytes(
        self, message_auth: GatewayMessageAuthenticator | None = None
    ) -> bytes:
        payload = self.as_dict()
        if message_auth is not None:
            payload = message_auth.sign(payload, message_type="reasoning_request")
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )


#: How an unanswered response is named in the log, by why it was dropped.
#: A response below the replay floor is not shown to be a replay.
_DROP_LABELS = {
    "unverified": "an unverified",
    "replayed": "a replayed",
    "below_floor": "a below-the-replay-floor",
}


def _refusal_kind(exc: GatewayMessageAuthError) -> str:
    reason = str(exc)
    if reason == "replay_detected":
        return "replayed"
    if reason == "before_replay_floor":
        return "below_floor"
    return "unverified"


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
        tls_config: dict[str, Any] | None = None,
        client_factory: Callable[..., Any] | None = None,
        request_id_factory: Callable[[], str] | None = None,
        message_auth: GatewayMessageAuthenticator | None = None,
    ) -> None:
        if not _PAHO_AVAILABLE or mqtt is None:
            raise RuntimeError("paho-mqtt is not installed")
        self._broker = parse_gateway_broker_url(broker_url, tls_config=tls_config)
        if not routing_id(device_id):
            raise ValueError("device_id is outside gateway-api/v2's routing form")
        self._device_id = device_id
        # Any integer runtime-config/v2 admits, kept to a wait the loop can
        # schedule and the gateway can read: a day at most.
        self._timeout_ms = max(
            1, min(int(timeout_ms), MAX_GATEWAY_REASONING_TIMEOUT_MS)
        )
        self._client_factory = client_factory or _default_client_factory
        self._request_id_factory = request_id_factory or (lambda: uuid.uuid4().hex)
        self._message_auth = message_auth
        self._ingress = IngressBound(REASONING_RESPONSE)

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
        request_id = self._request_id_factory()
        if not routing_id(request_id):
            raise ValueError("request_id is outside gateway-api/v2's routing form")
        action_tier_hint = str(getattr(rule_result, "action_tier", "A") or "A")
        if action_tier_hint not in _VALID_ACTION_TIERS:
            action_tier_hint = "A"

        reading = event.reading if event is not None else None
        context = {
            "value": float(getattr(reading, "value", 0.0) or 0.0),
            "unit": str(getattr(reading, "unit", "") or ""),
            # A reading's own time, as stored, under its own basis; a substitute
            # is sent only when there is no reading, whose basis is then unknown.
            "timestamp": int(reading.timestamp)
            if reading is not None
            else int(getattr(event, "timestamp", None) or now_ms()),
            # With no reading, `timestamp` is not a reading's time.
            "producer_time": read_producer_time(
                getattr(reading, "producer_time", None)
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
        body = request.to_json_bytes(self._message_auth)
        if not fits(REASONING_REQUEST, body):
            # Never published: the escalation is unavailable now, not after
            # waiting out a timeout for an answer that cannot come.
            raise GatewayReasoningError(
                "gateway reasoning request exceeds its payload maximum"
            )
        loop = asyncio.get_running_loop()
        connected = loop.create_future()
        response = loop.create_future()
        client = self._client_factory(client_id=f"ori-reasoning-{self._device_id}")

        def _set_future_result(future: asyncio.Future, value: Any) -> None:
            if not future.done():
                future.set_result(value)

        def _call_on_loop(callback: Callable[..., None], *args: Any) -> None:
            # A late answer can finish after the loop has closed.
            try:
                loop.call_soon_threadsafe(callback, *args)
            except RuntimeError:
                pass  # the loop has closed; nothing waits for this any more

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
            # Sending SUBSCRIBE is not being subscribed: the request is
            # published only once SUBACK grants the response topic.
            result = connected_client.subscribe(self.response_topic)
            sent = result[0] if isinstance(result, tuple) else result
            if sent is not None and reason_code_value(sent) != 0:
                loop.call_soon_threadsafe(
                    _set_future_exception,
                    connected,
                    GatewayReasoningError(
                        f"could not send subscribe for {self.response_topic} rc={sent}"
                    ),
                )

        def _on_subscribe(
            _client: Any, _userdata: Any, _mid: Any, reason_codes: Any, *_: Any
        ) -> None:
            refused = subscription_refusal(reason_codes)
            if refused is not None:
                loop.call_soon_threadsafe(
                    _set_future_exception,
                    connected,
                    GatewayReasoningError(
                        f"broker refused subscription to {self.response_topic} "
                        f"({refused})"
                    ),
                )
                return
            loop.call_soon_threadsafe(_set_future_result, connected, True)

        # Set on this client's network thread once the request is answered:
        # a later answer, authentic or not, is read no further and records
        # nothing (gateway-api/v2 Payload Volume).
        answered = threading.Event()
        # Guards `answered`, `recording` and `waiters`, and is never held across
        # I/O: an answer's record can wait on the replay store, and the event
        # loop takes this lock when the round trip ends.
        settling = threading.Lock()
        # Records begun while the request was pending and not yet finished;
        # the round trip ends only once there are none, so nothing is recorded
        # for a request that has ended (gateway-api/v2 Payload Volume).
        recording = [0]
        # The loop's futures waiting for `recording` to reach zero.
        waiters: list[asyncio.Future[None]] = []
        # Unanswered responses dropped this round trip: the first of each kind
        # is logged at once, the rest summed when it ends, so a flood across a
        # long wait writes at most two lines per kind, not one per message.
        dropped = dict.fromkeys(_DROP_LABELS, 0)

        def _drop(kind: str, detail: object) -> None:
            with settling:
                dropped[kind] += 1
                first = dropped[kind] == 1
            if first:
                logger.warning(
                    "[gateway-reasoning] dropped %s response for %s: %s",
                    _DROP_LABELS[kind],
                    request.request_id,
                    detail,
                )

        def _on_message(_client: Any, _userdata: Any, message: Any) -> None:
            raw = getattr(message, "payload", b"")
            if self._ingress.admit(raw) is not None:
                return
            if answered.is_set():
                # Answered already: not even decoded, authentic or not.
                return
            # gateway-api/v2 Payload Member Rule, before any member is read.
            try:
                payload = admitted_text(raw, defined=REASONING_RESPONSE_MEMBERS)
            except PayloadMemberError as exc:
                self._ingress.refuse(exc.reason)
                return
            # Compared as it arrived: str() of a value nested past the
            # recursion limit raises on this paho thread.
            if payload.get("request_id") != request.request_id:
                return
            if self._message_auth is None and payload.get("device_id") != (
                self._device_id
            ):
                # Authenticated, verification binds the device; unauthenticated,
                # the body must still name the device its topic does.
                answered.set()
                loop.call_soon_threadsafe(
                    _set_future_exception,
                    response,
                    GatewayReasoningError("gateway response names another device"),
                )
                return
            if answered.is_set():
                # Answered already: read no further, authentic or not.
                return
            claim = None
            if self._message_auth is not None:
                try:
                    claim = self._message_auth.authenticate(
                        payload,
                        message_type="reasoning_response",
                        expected_device_id=self._device_id,
                        expected_request_id=request.request_id,
                    )
                except GatewayMessageAuthError as exc:
                    # Verification precedes every side effect (gateway-api/v2
                    # Reasoning Auth Envelope): an unverified answer ends
                    # nothing, and the request waits for an authentic one.
                    # A replay is refused here too, before it is recorded.
                    _drop(_refusal_kind(exc), exc)
                    return
            with settling:
                if answered.is_set():
                    return
                recording[0] += 1
            replay: GatewayMessageAuthError | None = None
            won = False
            try:
                if claim is not None:
                    try:
                        self._message_auth.commit(claim)  # type: ignore[union-attr]
                    except GatewayMessageAuthError as exc:
                        # A replay is no answer either.
                        replay = exc
                    else:
                        payload = claim.payload
            finally:
                with settling:
                    recording[0] -= 1
                    if replay is None and not answered.is_set():
                        answered.set()
                        won = True
                    woken = waiters[:] if recording[0] == 0 else []
                    if woken:
                        waiters.clear()
                for waiter in woken:
                    _call_on_loop(_set_future_result, waiter, None)
            if replay is not None:
                _drop(_refusal_kind(replay), replay)
                return
            if won:
                _call_on_loop(_set_future_result, response, payload)

        client.on_connect = _on_connect
        client.on_subscribe = _on_subscribe
        client.on_message = _on_message

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
            await asyncio.wait_for(connected, timeout=self._timeout_ms / 1000.0)
            publish_info = await asyncio.to_thread(
                client.publish,
                self.request_topic,
                body,
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
            # Over, however it ended: an answer arriving from here is for
            # nothing pending. A record already begun is waited for, off the
            # lock and without blocking the loop, and a cancellation does not
            # cut that wait or the client's teardown short.
            cancelled = False
            while True:
                with settling:
                    answered.set()
                    if recording[0] == 0:
                        summary = dict(dropped)
                        break
                    waiter: asyncio.Future[None] = loop.create_future()
                    waiters.append(waiter)
                try:
                    await asyncio.shield(waiter)
                except asyncio.CancelledError:
                    cancelled = True
            for kind, count in summary.items():
                if count > 1:
                    logger.warning(
                        "[gateway-reasoning] dropped %d %s responses for %s in all",
                        count,
                        _DROP_LABELS[kind].split(" ", 1)[1],
                        request.request_id,
                    )
            teardown = _teardown(client)
            while not teardown.done():
                try:
                    await asyncio.shield(teardown)
                except asyncio.CancelledError:
                    cancelled = True
            if cancelled:
                raise asyncio.CancelledError


def _stop_and_disconnect(client: Any) -> None:
    """Stop the client's network thread, then disconnect it, each attempted."""
    try:
        client.loop_stop()
    except Exception:
        logger.warning("[gateway-reasoning] failed to stop MQTT loop")
    try:
        client.disconnect()
    except Exception:
        logger.warning("[gateway-reasoning] failed to disconnect MQTT client")


def _teardown(client: Any) -> asyncio.Future[None]:
    """Run `_stop_and_disconnect` on a thread of its own; its completion.

    `loop_stop` joins the client's network thread, which may still be in a
    replay check, so it occupies no thread other work shares. One callable
    on one thread runs both calls whatever happens to the awaiting task, and
    the thread is not a daemon, so even a loop shutting down does not cut it
    short.
    """
    loop = asyncio.get_running_loop()
    done: asyncio.Future[None] = loop.create_future()

    def finished() -> None:
        if not done.done():
            done.set_result(None)

    def run() -> None:
        try:
            _stop_and_disconnect(client)
        finally:
            try:
                loop.call_soon_threadsafe(finished)
            except RuntimeError:
                pass  # the loop has closed; nothing awaits this any more

    threading.Thread(target=run, name="ori-gateway-reasoning-teardown").start()
    return done


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
            **history_as_of(event),
        )
    except Exception:
        logger.debug(
            "[gateway-reasoning] failed to load context history for %s",
            event.reading.sensor_id,
        )
        return []
    return [
        _history_point(
            getattr(row, "value", 0.0),
            getattr(row, "timestamp", 0),
            getattr(row, "received_at_ms", None),
            getattr(row, "producer_time", None),
        )
        for row in rows[:MAX_CONTEXT_HISTORY_POINTS]
    ]


def _history_point(
    value: Any, timestamp: Any, received: Any, producer_time: Any
) -> dict[str, Any]:
    """One history point, its basis read as unknown when it is not one of the three.

    A not_reported point carries its receipt, under gateway-api/v2's export row
    checks; one without a valid receipt states no basis instead.
    """
    point: dict[str, Any] = {
        "value": float(value or 0.0),
        "timestamp": int(timestamp or 0),
    }
    if _valid_receipt(received):
        point["received_at_ms"] = int(received)
    basis = read_producer_time(producer_time)
    if basis == NOT_REPORTED and "received_at_ms" not in point:
        basis = UNKNOWN
    point["producer_time"] = basis
    return point


def _valid_receipt(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= _MAX_SAFE_INTEGER
    )


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
                _history_point(
                    row.get("value", 0.0),
                    row.get("timestamp")
                    or row.get("timestamp_ms")
                    or row.get("reading_timestamp")
                    or 0,
                    row.get("received_at_ms"),
                    row.get("producer_time"),
                )
            )
        except (TypeError, ValueError):
            continue
    return points


def _reasoning_result_from_response(payload: dict[str, Any]) -> ReasoningResult:
    """The response held to the contract's JSON types; anything else is the
    gateway's error, refused here rather than left to a caller's fallback."""
    if "error" in payload:
        error = payload["error"]
        if not isinstance(error, str):
            raise GatewayReasoningError("gateway response error is not text")
        if error:
            raise GatewayReasoningError(f"gateway provider error: {error}")
    action_tier = payload.get("action_tier")
    if not isinstance(action_tier, str) or action_tier not in _VALID_ACTION_TIERS:
        raise GatewayReasoningError("gateway response action_tier is invalid")
    text = payload.get("text", "")
    model = payload.get("model", "")
    proposed_action = payload.get("proposed_action")
    tokens_used = payload.get("tokens_used", 0)
    latency_ms = payload.get("latency_ms", 0)
    confidence = payload.get("confidence", 0.0)
    if not (
        isinstance(text, str)
        and isinstance(model, str)
        and (proposed_action is None or isinstance(proposed_action, str))
        and _count(tokens_used)
        and _count(latency_ms)
    ):
        raise GatewayReasoningError("gateway response field is malformed")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise GatewayReasoningError("gateway response confidence is not finite")
    try:
        confidence = float(confidence)
    except OverflowError:
        raise GatewayReasoningError(
            "gateway response confidence is not finite"
        ) from None
    if not math.isfinite(confidence):
        raise GatewayReasoningError("gateway response confidence is not finite")
    return ReasoningResult(
        text=text,
        tier="gateway",
        model=model or "gateway",
        tokens_used=tokens_used,
        latency_ms=latency_ms,
        confidence=confidence,
        action_tier=action_tier,
        proposed_action=proposed_action,
    )


def _count(value: object) -> bool:
    """A non-negative JSON integer inside the integer zone."""
    return type(value) is int and 0 <= value <= 2**53 - 1


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
