# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The route carrying inbound authority artifacts into evidence ingest.

`EvidenceIngestService` verifies custody acknowledgements, delivery receipts
and epoch confirmations, and `BoundIngestService` marshals each onto the
evidence worker thread. Nothing called them, so an artifact delivered to this
device had no destination.

The transport decides whether a *message* is worth handing to ingest; ingest
decides whether an *artifact* proves out. This module refuses a message with
`InboundRefusal` and never borrows a reason from the contract's closed set --
`bad_authenticator` means a forgery, and reusing it for a stale MQTT envelope
would bury the genuine case among ordinary clock skew.

Nothing here decides an artifact is true. Only a verified receipt advances
delivery state, and only a verified epoch confirmation activates an epoch.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any, Callable

from ori.gateway.mqtt_security import apply_tls_context, parse_gateway_broker_url
from ori.security.evidence_bound import BoundIngestService
from ori.security.evidence_canonical import canonical_json
from ori.security.evidence_ingest_service import IngestOutcome
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

EVIDENCE_INBOUND_TOPIC_TEMPLATE = "ori/{device_id}/evidence/inbound"
EVIDENCE_INBOUND_ACK_TOPIC_TEMPLATE = "ori/{device_id}/evidence/inbound/ack"

_RECONNECT_MIN_S = 5.0
_RECONNECT_MAX_S = 300.0

#: Distinct from every other runtime-gateway message type, so an envelope
#: authenticating another exchange cannot be replayed onto this one.
EVIDENCE_INBOUND_MESSAGE_TYPE = "evidence_inbound"
EVIDENCE_INBOUND_ACK_MESSAGE_TYPE = "evidence_inbound_ack"

#: The sender names the artifact. The three have disjoint field sets, but
#: inferring the type from which verifier succeeds is trial verification by
#: another name.
ARTIFACT_CUSTODY = "custody_acknowledgement"
ARTIFACT_RECEIPT = "delivery_receipt"
ARTIFACT_EPOCH = "epoch_confirmation"
ARTIFACT_TYPES = frozenset({ARTIFACT_CUSTODY, ARTIFACT_RECEIPT, ARTIFACT_EPOCH})

#: Transport vocabulary, kept disjoint from the contract's rejection reasons.
REFUSE_UNPARSEABLE = "unparseable"
REFUSE_NOT_AN_OBJECT = "not_an_object"
REFUSE_ENVELOPE_UNAUTHENTICATED = "envelope_unauthenticated"
REFUSE_UNKNOWN_ARTIFACT_TYPE = "unknown_artifact_type"
REFUSE_MISSING_ARTIFACT = "missing_artifact"
REFUSE_INGEST_UNAVAILABLE = "ingest_unavailable"


@dataclass(frozen=True)
class Routed:
    """What happened to one message, and what to tell the courier about it."""

    outcome: IngestOutcome | InboundRefusal
    acknowledgement: dict[str, Any] | None = None


@dataclass(frozen=True)
class InboundRefusal:
    """A message refused by the transport, before any artifact was read."""

    reason: str
    detail: str

    @property
    def accepted(self) -> bool:
        return False


class EvidenceInboundRouter:
    """Authenticates one inbound message and hands its artifact to ingest."""

    def __init__(
        self,
        *,
        device_id: str,
        ingest: BoundIngestService | None,
        message_auth: GatewayMessageAuthenticator | None = None,
    ) -> None:
        # Checked, not merely annotated. `EvidenceIngestService` satisfies any
        # structural protocol describing these three methods, so a type hint
        # would let the raw service through -- and it raises
        # `sqlite3.ProgrammingError` only once a gateway actually delivers
        # something, which no offline test reaches.
        if ingest is not None and not isinstance(ingest, BoundIngestService):
            raise TypeError(
                "inbound evidence must be applied through BoundIngestService; "
                f"{type(ingest).__name__} would be called on this thread"
            )
        self._device_id = str(device_id)
        self._ingest = ingest
        self._message_auth = message_auth

    @property
    def topic(self) -> str:
        return EVIDENCE_INBOUND_TOPIC_TEMPLATE.format(device_id=self._device_id)

    @property
    def envelope_authenticated(self) -> bool:
        return self._message_auth is not None

    @property
    def ack_topic(self) -> str:
        return EVIDENCE_INBOUND_ACK_TOPIC_TEMPLATE.format(device_id=self._device_id)

    def handle_payload(self, payload: bytes | str | dict[str, Any]) -> Routed:
        """Route one message, returning what happened and what to acknowledge.

        Never raises for a bad message: a refusal is a value, not an exception
        for some handler up the stack to interpret.

        An acknowledgement accompanies only an outcome ingest actually reached.
        A transport refusal produces none: it is not a statement about an
        artifact, and answering an unauthenticated message with a signed reply
        would hand anything on the site network a signing oracle.
        """
        decoded = _decode(payload)
        if isinstance(decoded, InboundRefusal):
            return Routed(decoded)

        if self._message_auth is not None:
            try:
                decoded = self._message_auth.verify(
                    decoded,
                    message_type=EVIDENCE_INBOUND_MESSAGE_TYPE,
                    expected_device_id=self._device_id,
                )
            except GatewayMessageAuthError as exc:
                return Routed(InboundRefusal(REFUSE_ENVELOPE_UNAUTHENTICATED, str(exc)))

        artifact_type = str(decoded.get("artifact_type", "") or "")
        if artifact_type not in ARTIFACT_TYPES:
            return Routed(
                InboundRefusal(
                    REFUSE_UNKNOWN_ARTIFACT_TYPE,
                    f"artifact_type {artifact_type!r} is not one this route accepts",
                )
            )

        artifact = decoded.get("artifact")
        if not isinstance(artifact, dict):
            return Routed(
                InboundRefusal(
                    REFUSE_MISSING_ARTIFACT,
                    f"the {artifact_type} carries no artifact object",
                )
            )

        # Reported after the message is understood, so an operator reads "a real
        # artifact arrived with nowhere to go" rather than "malformed".
        if self._ingest is None:
            return Routed(
                InboundRefusal(
                    REFUSE_INGEST_UNAVAILABLE,
                    "evidence ingest is not available on this runtime",
                )
            )

        if artifact_type == ARTIFACT_CUSTODY:
            outcome = self._ingest.accept_custody(artifact)
        elif artifact_type == ARTIFACT_RECEIPT:
            outcome = self._ingest.accept_receipt(artifact)
        else:
            outcome = self._ingest.accept_epoch_confirmation(artifact)
        return Routed(outcome, self._acknowledgement(artifact_type, artifact, outcome))

    def _acknowledgement(
        self, artifact_type: str, artifact: dict[str, Any], outcome: IngestOutcome
    ) -> dict[str, Any]:
        """The courier's retirement signal for one artifact.

        Identified by a digest over the artifact's canonical bytes rather than
        a correlation identifier: the artifact already carries its identity in
        the bytes the authority signed, and a transport identifier would be a
        second name the two sides could disagree about.

        It reports that this receiver decided, never that the artifact was
        true.
        """
        digest = hashlib.sha256(canonical_json(artifact)).hexdigest()
        payload: dict[str, Any] = {
            "device_id": self._device_id,
            "artifact_type": artifact_type,
            "artifact_digest": f"sha256:{digest}",
            "outcome": "applied" if outcome.accepted else "refused",
            "reason": "" if outcome.accepted else str(outcome.reason or ""),
            "acknowledged_at_ms": now_ms(),
        }
        if self._message_auth is None:
            return payload
        return self._message_auth.sign(
            payload, message_type=EVIDENCE_INBOUND_ACK_MESSAGE_TYPE
        )


def _decode(
    payload: bytes | str | dict[str, Any],
) -> dict[str, Any] | InboundRefusal:
    if isinstance(payload, dict):
        return dict(payload)
    try:
        parsed = json.loads(payload)
    except Exception as exc:
        return InboundRefusal(REFUSE_UNPARSEABLE, f"payload is not JSON: {exc}")
    if not isinstance(parsed, dict):
        return InboundRefusal(
            REFUSE_NOT_AN_OBJECT, f"payload decoded to {type(parsed).__name__}"
        )
    return parsed


class MqttEvidenceInboundSubscriber:
    """Persistent MQTT subscription feeding the inbound evidence route.

    Routing runs in a worker thread. It blocks -- `BoundIngestService` waits on
    the evidence worker -- so the event loop would stall behind a SQLite write,
    and paho's network thread would stall the MQTT keepalive behind one.
    """

    def __init__(
        self,
        *,
        broker_url: str,
        router: EvidenceInboundRouter,
        device_id: str,
        tls_config: dict[str, Any] | None = None,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        if not _PAHO_AVAILABLE or mqtt is None:
            raise RuntimeError("paho-mqtt is not installed")
        self._broker = parse_gateway_broker_url(broker_url, tls_config=tls_config)
        self._router = router
        self._device_id = str(device_id)
        self._client_factory = client_factory or _default_client_factory
        self._client: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._connected = False
        self._lost: asyncio.Event | None = None

    @property
    def topic(self) -> str:
        return self._router.topic

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        """Connect, subscribe, and serve until *shutdown_event* fires.

        Retries for the life of the runtime. A single attempt would let one
        broker outage remove the inbound route until the next restart, and
        nothing would report it: the runtime would stay healthy while the
        gateway retried deliveries that could no longer land.
        """
        self._loop = asyncio.get_running_loop()
        self._lost = asyncio.Event()
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
                    "[evidence-inbound] route down (%s); retrying in %.0fs",
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

    @property
    def connected(self) -> bool:
        """Whether the broker has granted this route's subscription.

        Reported in runtime health. A route that is down is a delivery stall
        rather than a runtime fault, and nothing else on the device can
        observe it: evidence simply stops arriving.
        """
        return self._connected

    async def _connect_and_serve(self, shutdown_event: asyncio.Event) -> None:
        lost = self._lost
        assert lost is not None
        lost.clear()
        client = self._client_factory(client_id=f"ori-evidence-in-{self._device_id}")
        self._client = client
        client.on_connect = self._on_connect
        client.on_subscribe = self._on_subscribe
        client.on_disconnect = self._on_disconnect
        client.on_message = self._on_message
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
        # Either end of the route can fail: the broker may refuse the
        # subscription, or drop a session it had granted. Both must reconnect
        # rather than leave a task parked on a route that no longer carries
        # anything.
        await _wait_first(shutdown_event, lost)
        if not shutdown_event.is_set():
            raise ConnectionError("subscription lost")

    async def close(self) -> None:
        """Stop the paho network loop and disconnect cleanly."""
        client = self._client
        self._client = None
        self._connected = False
        if client is None:
            return
        try:
            await asyncio.to_thread(client.loop_stop)
        except Exception:
            logger.warning("[evidence-inbound] failed to stop MQTT loop")
        try:
            await asyncio.to_thread(client.disconnect)
        except Exception:
            logger.warning("[evidence-inbound] failed to disconnect cleanly")

    # ── paho callbacks ────────────────────────────────────────────────────────

    def _on_connect(
        self, client: Any, _userdata: Any, _flags: Any, rc: Any, *_: Any
    ) -> None:
        if _rc_value(rc) != 0:
            logger.warning("[evidence-inbound] MQTT connect failed rc=%s", rc)
            self._signal_lost()
            return
        # QoS 1: a dropped authority artifact is not recoverable by asking
        # again, since the runtime does not know it was sent.
        #
        # Sending SUBSCRIBE is not being subscribed. The return value says the
        # packet was queued; the broker's grant or refusal arrives later in
        # SUBACK, so `connected` is decided in _on_subscribe.
        result = client.subscribe(self.topic, qos=1)
        code = result[0] if isinstance(result, tuple) else result
        if _rc_value(code) != 0:
            logger.warning(
                "[evidence-inbound] could not send subscribe for %s rc=%s",
                self.topic,
                code,
            )
            self._signal_lost()

    def _on_subscribe(
        self, _client: Any, _userdata: Any, _mid: Any, reason_codes: Any, *_: Any
    ) -> None:
        """Mark the route up only once the broker has granted the subscription.

        A broker that authenticates the connection and then refuses the topic
        by ACL is the shape this catches. Without it the route reports healthy
        and waits forever for artifacts the broker will never deliver.
        """
        codes = (
            reason_codes if isinstance(reason_codes, (list, tuple)) else [reason_codes]
        )
        refused = [code for code in codes if _rc_value(code) >= 0x80]
        if refused or not codes:
            logger.warning(
                "[evidence-inbound] broker refused subscription to %s (%s)",
                self.topic,
                refused or "no granted QoS",
            )
            self._connected = False
            self._signal_lost()
            return
        self._connected = True
        logger.info(
            "[evidence-inbound] subscribed to %s via %s:%s (envelope auth=%s)",
            self.topic,
            self._broker.host,
            self._broker.port,
            "enabled" if self._router.envelope_authenticated else "disabled",
        )

    def _on_disconnect(self, _client: Any, _userdata: Any, *args: Any) -> None:
        """Drop the route's claim to be up, and reconnect.

        Without this `connected` stays true after the session is gone, which
        would report a working route while nothing could arrive.
        """
        self._connected = False
        logger.warning("[evidence-inbound] disconnected from broker")
        self._signal_lost()

    def _signal_lost(self) -> None:
        """Wake the serve loop from a paho callback thread."""
        loop = self._loop
        lost = self._lost
        if loop is None or lost is None:
            return
        loop.call_soon_threadsafe(lost.set)

    def _on_message(self, _client: Any, _userdata: Any, message: Any) -> None:
        loop = self._loop
        if loop is None:
            logger.warning(
                "[evidence-inbound] message received before event loop ready"
            )
            return
        payload = getattr(message, "payload", b"") or b""
        future = asyncio.run_coroutine_threadsafe(self._route(payload), loop)
        future.add_done_callback(_log_future_failure)

    async def _route(self, payload: bytes) -> None:
        routed = await asyncio.to_thread(self._router.handle_payload, payload)
        _log_result(routed.outcome)
        if routed.acknowledgement is None:
            return
        client = self._client
        if client is None:
            logger.warning(
                "[evidence-inbound] no connection to acknowledge on; the courier "
                "will redeliver"
            )
            return
        try:
            await asyncio.to_thread(
                client.publish,
                self._router.ack_topic,
                json.dumps(routed.acknowledgement).encode(),
                1,
            )
        except Exception:
            # The courier retires an artifact only on an acknowledgement, so a
            # lost one costs a redelivery rather than the evidence.
            logger.warning("[evidence-inbound] failed to publish acknowledgement")


def _rc_value(code: Any) -> int:
    """Numeric value of a paho reason code, whichever API version produced it."""
    value = getattr(code, "value", code)
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


async def _wait_first(*events: asyncio.Event) -> None:
    """Return once any of *events* is set."""
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
        logger.exception("[evidence-inbound] routing an inbound artifact failed")


def _default_client_factory(*, client_id: str) -> Any:
    if mqtt is None:
        raise RuntimeError("paho-mqtt is not installed")
    # A persistent session, per gateway-api/v1. Under a clean session the
    # broker discards this subscription on disconnect, so every artifact
    # published while the runtime restarts is dropped with nothing recording
    # that it existed. The client id is stable for the same reason: a session
    # can only be resumed by the name that created it.
    kwargs: dict[str, Any] = {"client_id": client_id, "clean_session": False}
    callback_api_version = getattr(mqtt, "CallbackAPIVersion", None)
    if callback_api_version is not None:
        kwargs["callback_api_version"] = callback_api_version.VERSION2
    try:
        return mqtt.Client(**kwargs)
    except TypeError:
        kwargs.pop("callback_api_version", None)
        return mqtt.Client(**kwargs)


def _log_result(result: IngestOutcome | InboundRefusal) -> None:
    """Report every result: a refusal and a message that never arrived leave
    identical ledger state, and the difference is only visible here."""
    if isinstance(result, InboundRefusal):
        logger.warning(
            "[evidence-inbound] message refused before ingest: %s (%s)",
            result.reason,
            result.detail,
        )
        return
    if result.accepted:
        logger.info(
            "[evidence-inbound] accepted %s%s",
            result.artifact,
            (
                f" applying {list(result.applied_sequences)}"
                if result.applied_sequences
                else ""
            ),
        )
        return
    logger.warning(
        "[evidence-inbound] ingest refused %s: %s (%s)",
        result.artifact,
        result.reason,
        result.detail,
    )
