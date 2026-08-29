# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The route carrying this device's evidence artifacts to the gateway courier.

Outbound carriage per `gateway-api/v1`: the exact signed bytes of a delivery
envelope, checkpoint or anchor registration travel Base64-encoded on
`ori/{device_id}/evidence/outbound`, and the gateway answers on the `ack`
topic with an authenticated transport decision. That acknowledgement is a
statement about the courier's queue, never about the evidence: a `queued`
envelope stays awaiting custody until the separately authenticated custody
acknowledgement arrives through the inbound route, while a `queued`
checkpoint or registration is retired because the gateway's durable queue now
owns retry.

Nothing here is authenticated by the carriage itself. Every artifact carries
its own device signature end to end, so a carriage HMAC would prove nothing a
gateway holding that key could not forge.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable

from ori.gateway.mqtt_security import apply_tls_context, parse_gateway_broker_url
from ori.security.evidence.bound import BoundOutboundQueue
from ori.security.evidence.ledger import (
    OUTBOX_ARTIFACT_TYPES,
    RETIRE_QUEUED,
    RETIRE_REFUSED,
)
from ori.security.gateway_messages import (
    GatewayMessageAuthenticator,
    GatewayMessageAuthError,
)
from ori.utils.time_utils import now_ms

try:
    import paho.mqtt.client as mqtt

    _PAHO_AVAILABLE = True
except ImportError:  # pragma: no cover — paho is always installed in production
    mqtt = None  # type: ignore[assignment]
    _PAHO_AVAILABLE = False

logger = logging.getLogger(__name__)

EVIDENCE_OUTBOUND_TOPIC_TEMPLATE = "ori/{device_id}/evidence/outbound"
EVIDENCE_OUTBOUND_ACK_TOPIC_TEMPLATE = "ori/{device_id}/evidence/outbound/ack"
EVIDENCE_OUTBOUND_ACK_MESSAGE_TYPE = "evidence_outbound_ack"

ARTIFACT_DELIVERY_ENVELOPE = "delivery_envelope"
OUTBOUND_ARTIFACT_TYPES = (
    frozenset({ARTIFACT_DELIVERY_ENVELOPE}) | OUTBOX_ARTIFACT_TYPES
)

ACK_QUEUED = "queued"
ACK_REFUSED = "refused"
#: The courier's closed transport refusal vocabulary. `queue_full` is the one
#: that is retriable; the other two mean the bytes this device sealed were
#: refused, which no retry will change.
ACK_REASON_QUEUE_FULL = "queue_full"
ACK_REFUSAL_REASONS = frozenset(
    {"malformed", "binding_mismatch", ACK_REASON_QUEUE_FULL}
)

#: Transport vocabulary for what this route did with an acknowledgement.
ROUTED_APPLIED = "applied"
ROUTED_IGNORED = "ignored"
ROUTED_REFUSED = "refused"

RETRY_INTERVAL_S = 30.0
RETRY_BACKOFF_MAX_S = 900.0
DRAIN_BATCH = 50
_RECONNECT_MIN_S = 5.0
_RECONNECT_MAX_S = 300.0
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def artifact_digest(wire: bytes) -> str:
    """SHA-256 over the exact artifact bytes, as the courier computes it."""
    return "sha256:" + hashlib.sha256(wire).hexdigest()


def carriage_payload(device_id: str, artifact_type: str, wire: bytes) -> bytes:
    """The outbound carriage for one artifact's exact signed bytes."""
    if artifact_type not in OUTBOUND_ARTIFACT_TYPES:
        raise ValueError(f"{artifact_type!r} is not an outbound artifact type")
    return json.dumps(
        {
            "device_id": device_id,
            "artifact_type": artifact_type,
            "artifact_b64": base64.b64encode(wire).decode("ascii"),
        },
        separators=(",", ":"),
    ).encode("utf-8")


def retry_due(attempts: int, last_attempt_ms: int | None, *, at_ms: int) -> bool:
    """Whether an artifact's next attempt is due under exponential backoff."""
    if attempts <= 0 or last_attempt_ms is None:
        return True
    delay_s = min(RETRY_INTERVAL_S * 2.0 ** (attempts - 1), RETRY_BACKOFF_MAX_S)
    return at_ms - int(last_attempt_ms) >= delay_s * 1000.0


@dataclass(frozen=True)
class AckRouted:
    """What this route did with one acknowledgement, and why."""

    outcome: str
    reason: str = ""
    artifact_type: str = ""
    artifact_digest: str = ""


class EvidenceOutboundAckRouter:
    """Verifies one courier acknowledgement and applies it to the ledger."""

    def __init__(
        self,
        *,
        device_id: str,
        outbox: BoundOutboundQueue,
        message_auth: GatewayMessageAuthenticator | None = None,
        now: Callable[[], int] = now_ms,
    ) -> None:
        self._device_id = str(device_id)
        self._outbox = outbox
        self._message_auth = message_auth
        self._now = now

    @property
    def envelope_authenticated(self) -> bool:
        return self._message_auth is not None

    async def handle_ack(self, payload: bytes | str | dict[str, Any]) -> AckRouted:
        """Apply one acknowledgement. Never raises for a bad message."""
        if isinstance(payload, dict):
            decoded: Any = dict(payload)
        else:
            try:
                decoded = json.loads(payload)
            except Exception as exc:
                return AckRouted(ROUTED_REFUSED, f"payload is not JSON: {exc}")
        if not isinstance(decoded, dict):
            return AckRouted(ROUTED_REFUSED, "payload is not an object")

        if self._message_auth is not None:
            try:
                decoded = self._message_auth.verify(
                    decoded,
                    message_type=EVIDENCE_OUTBOUND_ACK_MESSAGE_TYPE,
                    expected_device_id=self._device_id,
                    now_ms_value=self._now(),
                )
            except GatewayMessageAuthError as exc:
                return AckRouted(ROUTED_REFUSED, f"envelope unauthenticated: {exc}")
        elif str(decoded.get("device_id", "")) != self._device_id:
            return AckRouted(ROUTED_REFUSED, "acknowledgement names another device")

        artifact_type = str(decoded.get("artifact_type", "") or "")
        digest = str(decoded.get("artifact_digest", "") or "")
        outcome = str(decoded.get("outcome", "") or "")
        reason = str(decoded.get("reason", "") or "")
        if artifact_type not in OUTBOUND_ARTIFACT_TYPES:
            return AckRouted(ROUTED_REFUSED, f"unknown artifact_type {artifact_type!r}")
        if not _DIGEST.match(digest):
            return AckRouted(ROUTED_REFUSED, "artifact_digest is not sha256 hex")
        if outcome == ACK_QUEUED:
            if reason:
                return AckRouted(
                    ROUTED_REFUSED, "a queued acknowledgement carries no reason"
                )
        elif outcome == ACK_REFUSED:
            if reason not in ACK_REFUSAL_REASONS:
                return AckRouted(ROUTED_REFUSED, f"unknown refusal reason {reason!r}")
        else:
            return AckRouted(ROUTED_REFUSED, f"unknown outcome {outcome!r}")

        at_ms = self._now()
        if artifact_type == ARTIFACT_DELIVERY_ENVELOPE:
            return await self._apply_to_envelope(digest, outcome, reason, at_ms)
        return await self._apply_to_artifact(
            artifact_type, digest, outcome, reason, at_ms
        )

    async def _apply_to_envelope(
        self, digest: str, outcome: str, reason: str, at_ms: int
    ) -> AckRouted:
        row = await self._outbox.find_envelope(digest)
        if row is None:
            logger.warning(
                "[evidence-outbound] acknowledgement names an envelope this device "
                "never sealed; ignored"
            )
            return AckRouted(
                ROUTED_IGNORED, "unknown envelope", ARTIFACT_DELIVERY_ENVELOPE, digest
            )
        local_seq = int(row["local_seq"])
        if outcome == ACK_QUEUED:
            # Custody is claimed only by the custody acknowledgement, which
            # arrives through the inbound route under its own key.
            return AckRouted(ROUTED_APPLIED, "", ARTIFACT_DELIVERY_ENVELOPE, digest)
        if reason == ACK_REASON_QUEUE_FULL:
            await self._outbox.record_attempt(local_seq, at_ms=at_ms, failure=reason)
            return AckRouted(ROUTED_APPLIED, reason, ARTIFACT_DELIVERY_ENVELOPE, digest)
        logger.error(
            "[evidence-outbound] the courier refused sealed envelope local_seq=%s (%s)",
            local_seq,
            reason,
        )
        # One failure row per refusal episode: the envelope keeps being
        # republished at the backoff cap, and a courier that refuses the same
        # bytes indefinitely must not grow the record by one row per attempt.
        if row["last_failure"] != "refused":
            await self._outbox.record_delivery_failure(
                local_seq, reason="refused", observed_at_ms=at_ms
            )
        await self._outbox.record_attempt(local_seq, at_ms=at_ms, failure="refused")
        return AckRouted(ROUTED_APPLIED, reason, ARTIFACT_DELIVERY_ENVELOPE, digest)

    async def _apply_to_artifact(
        self, artifact_type: str, digest: str, outcome: str, reason: str, at_ms: int
    ) -> AckRouted:
        row = await self._outbox.find_artifact(digest)
        if row is None or str(row["artifact_type"]) != artifact_type:
            logger.warning(
                "[evidence-outbound] acknowledgement names a %s this device never "
                "queued; ignored",
                artifact_type,
            )
            return AckRouted(ROUTED_IGNORED, "unknown artifact", artifact_type, digest)
        if outcome == ACK_QUEUED:
            await self._outbox.retire_artifact(
                digest, outcome=RETIRE_QUEUED, at_ms=at_ms
            )
            return AckRouted(ROUTED_APPLIED, "", artifact_type, digest)
        if reason == ACK_REASON_QUEUE_FULL:
            await self._outbox.note_artifact_attempt(digest, at_ms=at_ms)
            return AckRouted(ROUTED_APPLIED, reason, artifact_type, digest)
        logger.error(
            "[evidence-outbound] the courier refused a signed %s (%s)",
            artifact_type,
            reason,
        )
        await self._outbox.retire_artifact(digest, outcome=RETIRE_REFUSED, at_ms=at_ms)
        return AckRouted(ROUTED_APPLIED, reason, artifact_type, digest)


class MqttEvidenceOutboundPublisher:
    """Persistent MQTT session carrying retained artifacts to the courier.

    Publishes whatever the ledger still holds, on a retry cadence with
    per-artifact backoff, and applies the courier's acknowledgements. Retention
    is decided by the ledger alone: this publisher never retires anything on
    PUBACK.
    """

    def __init__(
        self,
        *,
        broker_url: str,
        router: EvidenceOutboundAckRouter,
        device_id: str,
        outbox: BoundOutboundQueue,
        tls_config: dict[str, Any] | None = None,
        client_factory: Callable[..., Any] | None = None,
        retry_interval_s: float = RETRY_INTERVAL_S,
        now: Callable[[], int] = now_ms,
    ) -> None:
        if not _PAHO_AVAILABLE or mqtt is None:
            raise RuntimeError("paho-mqtt is not installed")
        self._broker = parse_gateway_broker_url(broker_url, tls_config=tls_config)
        self._router = router
        self._device_id = str(device_id)
        self._outbox = outbox
        self._client_factory = client_factory or _default_client_factory
        self._retry_interval_s = max(1.0, float(retry_interval_s))
        self._now = now
        self._client: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._connected = False
        self._lost: asyncio.Event | None = None
        self._granted: asyncio.Event | None = None
        self._wake: asyncio.Event | None = None
        self._drain_lock = asyncio.Lock()

    @property
    def topic(self) -> str:
        return EVIDENCE_OUTBOUND_TOPIC_TEMPLATE.format(device_id=self._device_id)

    @property
    def ack_topic(self) -> str:
        return EVIDENCE_OUTBOUND_ACK_TOPIC_TEMPLATE.format(device_id=self._device_id)

    @property
    def connected(self) -> bool:
        """Whether the broker has granted the acknowledgement subscription."""
        return self._connected

    def nudge(self) -> None:
        """Drain now rather than at the next interval. Safe from any thread."""
        loop = self._loop
        wake = self._wake
        if loop is None or wake is None:
            return
        loop.call_soon_threadsafe(wake.set)

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        """Connect, subscribe, and carry until *shutdown_event* fires."""
        self._loop = asyncio.get_running_loop()
        self._lost = asyncio.Event()
        self._granted = asyncio.Event()
        self._wake = asyncio.Event()
        delay = _RECONNECT_MIN_S
        while not shutdown_event.is_set():
            try:
                await self._connect_and_serve(shutdown_event)
                delay = _RECONNECT_MIN_S
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._connected = False
                logger.warning(
                    "[evidence-outbound] route down (%s); retrying in %.0fs",
                    exc,
                    delay,
                )
            finally:
                await self.close()
            if shutdown_event.is_set():
                return
            try:
                await asyncio.wait_for(shutdown_event.wait(), timeout=delay)
                return
            except asyncio.TimeoutError:
                delay = min(delay * 2, _RECONNECT_MAX_S)

    async def _connect_and_serve(self, shutdown_event: asyncio.Event) -> None:
        lost = self._lost
        granted = self._granted
        wake = self._wake
        assert lost is not None and granted is not None and wake is not None
        lost.clear()
        granted.clear()
        client = self._client_factory(client_id=f"ori-evidence-out-{self._device_id}")
        self._client = client
        client.on_connect = self._on_connect
        client.on_subscribe = self._on_subscribe
        client.on_disconnect = self._on_disconnect
        client.on_message = self._on_message
        if self._broker.username:
            client.username_pw_set(self._broker.username, self._broker.password)
        apply_tls_context(client, self._broker)
        await asyncio.to_thread(
            client.connect, self._broker.host, int(self._broker.port), 60
        )
        await asyncio.to_thread(client.loop_start)
        await _wait_first(shutdown_event, lost, granted)
        while not shutdown_event.is_set() and not lost.is_set():
            wake.clear()
            await self.drain()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(
                    _wait_first(shutdown_event, lost, wake),
                    timeout=self._retry_interval_s,
                )
        if not shutdown_event.is_set():
            raise ConnectionError("subscription lost")
        # Shutting down with the session still granted: carry what was retained
        # since the last drain before the route is closed.
        await self.drain()

    async def drain(self) -> int:
        """Publish every retained artifact whose retry is due. Returns the count."""
        # One drain at a time: a nudge and a shutdown flush that overlap would
        # both read the same undue rows and carry each artifact twice.
        async with self._drain_lock:
            return await self._drain()

    async def _drain(self) -> int:
        if not self._connected or self._client is None:
            return 0
        published = 0
        at_ms = self._now()
        for row in await self._outbox.awaiting_custody(DRAIN_BATCH):
            if not retry_due(int(row["attempts"]), row["last_attempt_ms"], at_ms=at_ms):
                continue
            wire = str(row["envelope_json"]).encode("utf-8")
            sent = await self._publish(ARTIFACT_DELIVERY_ENVELOPE, wire)
            await self._outbox.record_attempt(
                int(row["local_seq"]),
                at_ms=at_ms,
                failure=None if sent else "unreachable",
            )
            if not sent:
                return published
            published += 1
        for row in await self._outbox.pending_artifacts(DRAIN_BATCH):
            if not retry_due(int(row["attempts"]), row["last_attempt_ms"], at_ms=at_ms):
                continue
            wire = str(row["artifact_json"]).encode("utf-8")
            sent = await self._publish(str(row["artifact_type"]), wire)
            await self._outbox.note_artifact_attempt(
                str(row["artifact_digest"]), at_ms=at_ms
            )
            if not sent:
                return published
            published += 1
        return published

    async def flush(self, timeout_s: float) -> int:
        """Drain once, bounded, for a clean shutdown. Returns the count."""
        try:
            return await asyncio.wait_for(self.drain(), timeout=timeout_s)
        except asyncio.TimeoutError:
            logger.warning("[evidence-outbound] shutdown flush timed out")
            return 0

    async def _publish(self, artifact_type: str, wire: bytes) -> bool:
        client = self._client
        if client is None:
            return False
        try:
            payload = carriage_payload(self._device_id, artifact_type, wire)
            await asyncio.to_thread(client.publish, self.topic, payload, 1)
        except Exception:
            logger.warning("[evidence-outbound] failed to publish a %s", artifact_type)
            return False
        return True

    async def close(self) -> None:
        client = self._client
        self._client = None
        self._connected = False
        if client is None:
            return
        try:
            await asyncio.to_thread(client.loop_stop)
        except Exception:
            logger.warning("[evidence-outbound] failed to stop MQTT loop")
        try:
            await asyncio.to_thread(client.disconnect)
        except Exception:
            logger.warning("[evidence-outbound] failed to disconnect cleanly")

    # ── paho callbacks ────────────────────────────────────────────────────────

    def _on_connect(
        self, client: Any, _userdata: Any, _flags: Any, rc: Any, *_: Any
    ) -> None:
        if _rc_value(rc) != 0:
            logger.warning("[evidence-outbound] MQTT connect failed rc=%s", rc)
            self._signal(self._lost)
            return
        result = client.subscribe(self.ack_topic, qos=1)
        code = result[0] if isinstance(result, tuple) else result
        if _rc_value(code) != 0:
            logger.warning(
                "[evidence-outbound] could not send subscribe for %s rc=%s",
                self.ack_topic,
                code,
            )
            self._signal(self._lost)

    def _on_subscribe(
        self, _client: Any, _userdata: Any, _mid: Any, reason_codes: Any, *_: Any
    ) -> None:
        codes = (
            reason_codes if isinstance(reason_codes, (list, tuple)) else [reason_codes]
        )
        refused = [code for code in codes if _rc_value(code) >= 0x80]
        if refused or not codes:
            logger.warning(
                "[evidence-outbound] broker refused subscription to %s (%s)",
                self.ack_topic,
                refused or "no granted QoS",
            )
            self._connected = False
            self._signal(self._lost)
            return
        self._connected = True
        logger.info(
            "[evidence-outbound] carrying on %s via %s:%s (envelope auth=%s)",
            self.topic,
            self._broker.host,
            self._broker.port,
            "enabled" if self._router.envelope_authenticated else "disabled",
        )
        self._signal(self._granted)

    def _on_disconnect(self, _client: Any, _userdata: Any, *args: Any) -> None:
        self._connected = False
        logger.warning("[evidence-outbound] disconnected from broker")
        self._signal(self._lost)

    def _signal(self, event: asyncio.Event | None) -> None:
        loop = self._loop
        if loop is None or event is None:
            return
        loop.call_soon_threadsafe(event.set)

    def _on_message(self, _client: Any, _userdata: Any, message: Any) -> None:
        loop = self._loop
        if loop is None:
            logger.warning(
                "[evidence-outbound] acknowledgement received before event loop ready"
            )
            return
        payload = getattr(message, "payload", b"") or b""
        future = asyncio.run_coroutine_threadsafe(self._route_ack(payload), loop)
        future.add_done_callback(_log_future_failure)

    async def _route_ack(self, payload: bytes) -> None:
        routed = await self._router.handle_ack(payload)
        if routed.outcome == ROUTED_REFUSED:
            logger.warning(
                "[evidence-outbound] acknowledgement refused: %s", routed.reason
            )
        elif routed.reason:
            logger.warning(
                "[evidence-outbound] courier %s a %s: %s",
                "deferred" if routed.reason == ACK_REASON_QUEUE_FULL else "refused",
                routed.artifact_type,
                routed.reason,
            )
        else:
            logger.info(
                "[evidence-outbound] courier %s a %s",
                routed.outcome,
                routed.artifact_type,
            )


def _rc_value(code: Any) -> int:
    value = getattr(code, "value", code)
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


async def _wait_first(*events: asyncio.Event) -> None:
    waiters = [asyncio.ensure_future(event.wait()) for event in events]
    try:
        await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for waiter in waiters:
            waiter.cancel()


def _log_future_failure(future: Any) -> None:
    try:
        future.result()
    except Exception:
        logger.exception("[evidence-outbound] routing an acknowledgement failed")


def _default_client_factory(*, client_id: str) -> Any:
    if mqtt is None:
        raise RuntimeError("paho-mqtt is not installed")
    # Persistent, per gateway-api/v1: an acknowledgement published while the
    # runtime restarts must still arrive, or the artifact is republished and
    # the courier answers again.
    kwargs: dict[str, Any] = {"client_id": client_id, "clean_session": False}
    callback_api_version = getattr(mqtt, "CallbackAPIVersion", None)
    if callback_api_version is not None:
        kwargs["callback_api_version"] = callback_api_version.VERSION2
    try:
        return mqtt.Client(**kwargs)
    except TypeError:
        kwargs.pop("callback_api_version", None)
        return mqtt.Client(**kwargs)
