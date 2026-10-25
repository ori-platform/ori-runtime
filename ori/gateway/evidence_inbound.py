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
import functools
import hashlib
import json
import logging
import threading
from dataclasses import dataclass
from typing import Any, Callable, cast

from ori.gateway.mqtt_security import apply_tls_context, parse_gateway_broker_url
from ori.gateway.payload_bounds import (
    EVIDENCE_INBOUND,
    PAYLOAD_TOO_LARGE,
    REDELIVERY_DUE,
    IngressBound,
    refill_seconds,
)
from ori.gateway.route_io import RouteIO, Slots
from ori.security.evidence.bound import BoundIngestService
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.executor import EvidenceExecutorSaturatedError
from ori.security.evidence.ingest import REJECT_REASONS
from ori.security.evidence.ingest_service import UNDECIDED, IngestOutcome
from ori.security.gateway_messages import (
    AuthenticatedMessage,
    GatewayMessageAuthenticator,
    GatewayMessageAuthError,
)
from ori.security.payload_members import (
    EVIDENCE_INBOUND_MEMBERS,
    PayloadMemberError,
    admitted_text,
)
from ori.security.payload_members import REASONS as MEMBER_REASONS
from ori.utils.coalesced_log import CoalescedWarning
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
#: Inbound messages being routed at once. Past it a message is left without
#: its MQTT acknowledgement, so the broker keeps it for this session, and the
#: route reconnects once the backlog clears so the broker redelivers it.
INBOUND_IN_FLIGHT_BOUND = 16

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
_INGEST_KIND = {
    ARTIFACT_CUSTODY: "custody",
    ARTIFACT_RECEIPT: "receipt",
    ARTIFACT_EPOCH: "epoch",
}

#: Transport vocabulary, kept disjoint from the contract's rejection reasons.
REFUSE_NOT_AN_OBJECT = "not_an_object"
REFUSE_ENVELOPE_UNAUTHENTICATED = "envelope_unauthenticated"
REFUSE_UNKNOWN_ARTIFACT_TYPE = "unknown_artifact_type"
REFUSE_MISSING_ARTIFACT = "missing_artifact"
REFUSE_INGEST_UNAVAILABLE = "ingest_unavailable"
REFUSE_UNADMISSIBLE = "unadmissible"


#: An admitted message: its artifact type, artifact, where it goes, and its
#: envelope, recorded as seen only once ingest is about to act on it.
_Admitted = tuple[
    str, dict[str, Any], BoundIngestService, "AuthenticatedMessage | None"
]


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
        if ingest is not None and not isinstance(
            cast(object, ingest), BoundIngestService
        ):
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

        Never raises: a refusal is a value, not an exception for some handler
        up the stack to interpret, and a failure inside ingest leaves the
        artifact undecided rather than escaping.

        An acknowledgement accompanies only an outcome ingest actually decided.
        A transport refusal produces none: it is not a statement about an
        artifact, and answering an unauthenticated message with a signed reply
        would hand anything on the site network a signing oracle. An undecided
        artifact produces none either, so the courier delivers it again.

        Blocks the calling thread on the evidence worker; the subscriber uses
        :meth:`route`, which holds no thread while it waits.
        """
        admitted = self._admit_or_refuse(payload)
        if isinstance(admitted, InboundRefusal):
            return Routed(admitted)
        artifact_type, artifact, ingest, claim = admitted
        replayed = self._committed(claim)
        if replayed is not None:
            return Routed(replayed)
        try:
            if artifact_type == ARTIFACT_CUSTODY:
                outcome = ingest.accept_custody(artifact)
            elif artifact_type == ARTIFACT_RECEIPT:
                outcome = ingest.accept_receipt(artifact)
            else:
                outcome = ingest.accept_epoch_confirmation(artifact)
        except Exception:
            outcome = _failed(artifact_type)
        return Routed(outcome, self._acknowledgement(artifact_type, artifact, outcome))

    async def route(self, payload: bytes | str | dict[str, Any]) -> Routed:
        """:meth:`handle_payload`, awaiting the evidence worker on the event loop.

        A persisted replay key is written on the replay thread and awaited before
        ingest. A recorded key is never unrecorded (gateway-api/v2: receivers
        do not relax replay protection to accommodate redelivery): an attempt
        the evidence worker was too busy to take is left undecided, like a
        store fault, with no acknowledgement, and the courier redelivers it in
        a newly signed envelope.
        """
        # A megabyte scanned under the Payload Member Rule is CPU work that
        # would otherwise hold the event loop Tier D runs on.
        try:
            decoded = await asyncio.to_thread(_decode, payload)
        except Exception:
            logger.exception("[evidence-inbound] admitting a message failed")
            return Routed(
                InboundRefusal(REFUSE_UNADMISSIBLE, "the message could not be admitted")
            )
        # Its replay checks wait on the cache's lock, which another thread's
        # store transaction can hold: off the event loop, wherever they wait.
        if self._message_auth is None:
            admitted = self._admit_or_refuse(payload, decoded)
        else:
            try:
                admitted = await self._message_auth.run_off_loop(
                    self._admit_or_refuse, payload, decoded
                )
            except GatewayMessageAuthError as exc:
                admitted = InboundRefusal(REFUSE_ENVELOPE_UNAUTHENTICATED, str(exc))
        if isinstance(admitted, InboundRefusal):
            return Routed(admitted)
        artifact_type, artifact, ingest, claim = admitted
        replayed = await self._committed_async(claim)
        if replayed is not None:
            return Routed(replayed)
        try:
            outcome = await ingest.accept_async(_INGEST_KIND[artifact_type], artifact)
        except EvidenceExecutorSaturatedError:
            outcome = _saturated(artifact_type)
        except Exception:
            outcome = _failed(artifact_type)
        return Routed(outcome, self._acknowledgement(artifact_type, artifact, outcome))

    def _admit_or_refuse(
        self,
        payload: bytes | str | dict[str, Any],
        decoded: dict[str, Any] | InboundRefusal | None = None,
    ) -> InboundRefusal | _Admitted:
        """Admission, never raising: a message it cannot place is refused.

        A transport refusal, so no acknowledgement; the subscriber still
        releases the message. Its envelope is not recorded as seen, since it
        answers nothing (gateway-api/v2 Payload Volume), and a redelivered
        identical one is refused again for the same reason.
        """
        try:
            return self._admit(payload, decoded)
        except Exception:
            logger.exception("[evidence-inbound] admitting a message failed")
            return InboundRefusal(
                REFUSE_UNADMISSIBLE, "the message could not be admitted"
            )

    def _committed(self, claim: AuthenticatedMessage | None) -> InboundRefusal | None:
        """Record *claim* as seen before ingest; the refusal when it was already."""
        if claim is None or self._message_auth is None:
            return None
        try:
            self._message_auth.commit(claim)
        except GatewayMessageAuthError as exc:
            return InboundRefusal(REFUSE_ENVELOPE_UNAUTHENTICATED, str(exc))
        except Exception:
            logger.exception("[evidence-inbound] recording an envelope failed")
            return InboundRefusal(
                REFUSE_UNADMISSIBLE, "the message could not be admitted"
            )
        return None

    async def _committed_async(
        self, claim: AuthenticatedMessage | None
    ) -> InboundRefusal | None:
        """`_committed`, its write off the event loop."""
        if claim is None or self._message_auth is None:
            return None
        try:
            await self._message_auth.commit_async(claim)
        except GatewayMessageAuthError as exc:
            return InboundRefusal(REFUSE_ENVELOPE_UNAUTHENTICATED, str(exc))
        except Exception:
            logger.exception("[evidence-inbound] recording an envelope failed")
            return InboundRefusal(
                REFUSE_UNADMISSIBLE, "the message could not be admitted"
            )
        return None

    def _admit(
        self,
        payload: bytes | str | dict[str, Any],
        decoded: dict[str, Any] | InboundRefusal | None = None,
    ) -> InboundRefusal | _Admitted:
        """The message's artifact and where it goes, or the transport refusal.

        *decoded* is `_decode(payload)` when the caller has already run it.
        """
        if decoded is None:
            decoded = _decode(payload)
        if isinstance(decoded, InboundRefusal):
            return decoded

        claim: AuthenticatedMessage | None = None
        if self._message_auth is not None:
            try:
                claim = self._message_auth.authenticate(
                    decoded,
                    message_type=EVIDENCE_INBOUND_MESSAGE_TYPE,
                    expected_device_id=self._device_id,
                )
            except GatewayMessageAuthError as exc:
                return InboundRefusal(REFUSE_ENVELOPE_UNAUTHENTICATED, str(exc))
            decoded = claim.payload

        raw_type = decoded.get("artifact_type")
        artifact_type = raw_type if isinstance(raw_type, str) else ""
        if artifact_type not in ARTIFACT_TYPES:
            return InboundRefusal(
                REFUSE_UNKNOWN_ARTIFACT_TYPE,
                f"artifact_type {artifact_type!r} is not one this route accepts",
            )

        artifact = decoded.get("artifact")
        if not isinstance(artifact, dict):
            return InboundRefusal(
                REFUSE_MISSING_ARTIFACT,
                f"the {artifact_type} carries no artifact object",
            )

        # Reported after the message is understood, so an operator reads "a real
        # artifact arrived with nowhere to go" rather than "malformed".
        if self._ingest is None:
            return InboundRefusal(
                REFUSE_INGEST_UNAVAILABLE,
                "evidence ingest is not available on this runtime",
            )
        return artifact_type, artifact, self._ingest, claim

    def _acknowledgement(
        self, artifact_type: str, artifact: dict[str, Any], outcome: IngestOutcome
    ) -> dict[str, Any] | None:
        """The courier's retirement signal for one artifact, or None.

        Identified by a digest over the artifact's canonical bytes rather than
        a correlation identifier: the artifact already carries its identity in
        the bytes the authority signed, and a transport identifier would be a
        second name the two sides could disagree about.

        It reports that this receiver decided, never that the artifact was
        true, so an undecided artifact is not acknowledged. Neither is one with
        no canonical bytes, since nothing could name it.
        """
        if not outcome.decided:
            return None
        if outcome.accepted:
            answer, reason = "applied", ""
        elif outcome.reason in REJECT_REASONS:
            answer, reason = "refused", str(outcome.reason)
        else:
            # Unreachable through IngestOutcome, which refuses to be built so;
            # checked again here because this is what leaves the device.
            logger.error(
                "[evidence-inbound] a %s refusal names no receiver rejection "
                "reason; it is not acknowledged",
                artifact_type,
            )
            return None
        try:
            digest = hashlib.sha256(canonical_json(artifact)).hexdigest()
        except Exception:
            logger.warning(
                "[evidence-inbound] a %s with no canonical form cannot be acknowledged",
                artifact_type,
            )
            return None
        payload: dict[str, Any] = {
            "device_id": self._device_id,
            "artifact_type": artifact_type,
            "artifact_digest": f"sha256:{digest}",
            "outcome": answer,
            "reason": reason,
            "acknowledged_at_ms": now_ms(),
        }
        if self._message_auth is None:
            return payload
        try:
            return self._message_auth.sign(
                payload, message_type=EVIDENCE_INBOUND_ACK_MESSAGE_TYPE
            )
        except Exception:
            # The decision stands; only its answer is lost, and the courier
            # delivers the artifact again.
            logger.exception("[evidence-inbound] signing an acknowledgement failed")
            return None


def _saturated(artifact_type: str) -> IngestOutcome:
    """Refused at submission by a full evidence worker: undecided, as a store
    fault is, so the courier redelivers it in a newly signed envelope."""
    return IngestOutcome(
        artifact=artifact_type,
        state=UNDECIDED,
        detail="the evidence worker is saturated",
    )


def _failed(artifact_type: str) -> IngestOutcome:
    """An ingest failure no rule anticipated: logged, undecided, never raised."""
    logger.exception(
        "[evidence-inbound] applying a %s failed; it is left undecided", artifact_type
    )
    return IngestOutcome(
        artifact=artifact_type, state=UNDECIDED, detail="ingest failed unexpectedly"
    )


def _decode(
    payload: bytes | str | dict[str, Any],
) -> dict[str, Any] | InboundRefusal:
    if isinstance(payload, dict):
        return dict(payload)
    # gateway-api/v2 Payload Member Rule, before any member is read or the
    # envelope verified: one reading of the bytes, or none.
    try:
        return admitted_text(payload, defined=EVIDENCE_INBOUND_MEMBERS)
    except PayloadMemberError as exc:
        return InboundRefusal(exc.reason, "refused under the Payload Member Rule")


class _Session:
    """One broker session of the inbound route, and everything it decides.

    A session owns its client, the events that end it, whether it is up, and
    what it owes for redelivery. Callbacks are bound to the session whose
    client they belong to, so a client a close failed to stop can only ever
    reach its own closed session: no state is shared between sessions for a
    late callback, route or signal to reach.
    """

    def __init__(self, client: Any) -> None:
        self.client = client
        self.lock = threading.Lock()
        self.lost = asyncio.Event()
        self.redeliver = asyncio.Event()
        self.open = True
        self.connected = False
        # What the session owes for redelivery, and the episode that will end
        # it: accumulated, so a later rate drop never erases a failure the
        # reconnect has still to back off from.
        self.owed = False
        self.owed_after_failure = False
        self.owed_after_rate = False
        self.redeliver_after_failure = False
        self.redeliver_after_rate = False
        #: A reconnect for redelivery is due; nothing more is routed meanwhile.
        self.pending = False

    def owe(self, *, failed: bool = False, rate: bool = False) -> bool:
        """Mark a redelivery owed; True when this is the first of the episode."""
        with self.lock:
            first = not self.owed
            self.owed = True
            self.owed_after_failure = self.owed_after_failure or failed
            self.owed_after_rate = self.owed_after_rate or rate
            return first

    def redeliver_owed(self, loop: asyncio.AbstractEventLoop) -> None:
        """End this session for what it owes, if it owes anything."""
        with self.lock:
            if not self.owed:
                return
            self.owed = False
            self.redeliver_after_failure = (
                self.redeliver_after_failure or self.owed_after_failure
            )
            self.redeliver_after_rate = (
                self.redeliver_after_rate or self.owed_after_rate
            )
            self.owed_after_failure = self.owed_after_rate = False
            self.pending = True
        loop.call_soon_threadsafe(self.redeliver.set)

    def set_connected(self, connected: bool) -> bool:
        """Report this session up or down, while it is open."""
        with self.lock:
            if not self.open:
                return False
            self.connected = connected
            return True

    def close(self) -> None:
        """Closed with its claim to be up, in one step."""
        with self.lock:
            self.open = False
            self.connected = False

    def ended_for(self) -> tuple[bool, bool]:
        """Why it ended for redelivery: after a failure, after the rate."""
        with self.lock:
            return self.redeliver_after_failure, self.redeliver_after_rate


class MqttEvidenceInboundSubscriber:
    """Persistent MQTT subscription feeding the inbound evidence route.

    Routing awaits the evidence worker from the event loop and holds no thread
    while it waits: a blocked thread per message would let a stalled evidence
    store take every thread a shared executor has. Client calls run on this
    route's own thread. A message past the in-flight bound is left unacknowledged,
    and the broker redelivers it once the route reconnects.

    Each connection is a `_Session` of its own; the slots, the rate and the
    counts are the route's, across sessions.
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
        self._loop: asyncio.AbstractEventLoop | None = None
        self._session: _Session | None = None
        self._io = RouteIO("ori-evidence-in")
        # Taken in the client's callback thread, before anything is scheduled
        # on the event loop, so a flood allocates nothing past the bound.
        self._slots = Slots(INBOUND_IN_FLIGHT_BOUND)
        self._ingress = IngressBound(EVIDENCE_INBOUND)
        self._shed = 0
        self._manual_ack = False
        self._refusal_log = CoalescedWarning(logger)

    @property
    def ingress(self) -> IngressBound:
        """This route's size and rate bound, whose counts health reports."""
        return self._ingress

    @property
    def topic(self) -> str:
        return self._router.topic

    @property
    def shed_count(self) -> int:
        """Messages left unacknowledged at the in-flight bound."""
        return self._shed

    @property
    def _in_flight(self) -> int:
        return self._slots.taken

    @property
    def connected(self) -> bool:
        """Whether the broker has granted the current session's subscription.

        Reported in runtime health. A route that is down is a delivery stall
        rather than a runtime fault, and nothing else on the device can
        observe it: evidence simply stops arriving.
        """
        session = self._session
        return session is not None and session.connected

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        """Connect, subscribe, and serve until *shutdown_event* fires.

        Retries for the life of the runtime. A single attempt would let one
        broker outage remove the inbound route until the next restart, and
        nothing would report it: the runtime would stay healthy while the
        gateway retried deliveries that could no longer land.
        """
        self._loop = asyncio.get_running_loop()
        delay = _RECONNECT_MIN_S
        self._io.open()
        try:
            await self._serve(shutdown_event, delay)
        finally:
            self._io.shutdown()

    async def _serve(self, shutdown_event: asyncio.Event, delay: float) -> None:
        while not shutdown_event.is_set():
            redeliver = False
            errored = False
            session: _Session | None = None
            try:
                session = self._begin_session(
                    self._client_factory(client_id=f"ori-evidence-in-{self._device_id}")
                )
                redeliver = await self._connect_and_serve(session, shutdown_event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                errored = True
                logger.warning(
                    "[evidence-inbound] route down (%s); retrying in %.0fs",
                    exc,
                    delay,
                )
            finally:
                await self.close()
            # Read once the session is closed; nothing can reach it any more.
            failed, rate = session.ended_for() if session else (False, False)
            if not errored and not (redeliver and failed):
                delay = _RECONNECT_MIN_S
            if shutdown_event.is_set():
                return
            if redeliver and not failed:
                if rate:
                    # Past the rate: back once a full burst is admitted again,
                    # never after the doubling backoff of a failed route.
                    try:
                        await asyncio.wait_for(
                            shutdown_event.wait(),
                            timeout=refill_seconds(EVIDENCE_INBOUND),
                        )
                        return
                    except asyncio.TimeoutError:
                        pass
                # Past the bound only: the broker holds what was left, and the
                # route has room for it now.
                continue
            if redeliver:
                logger.warning(
                    "[evidence-inbound] routing failed; reconnecting for "
                    "redelivery in %.0fs",
                    delay,
                )
            try:
                await asyncio.wait_for(shutdown_event.wait(), timeout=delay)
                return
            except asyncio.TimeoutError:
                delay = min(delay * 2, _RECONNECT_MAX_S)

    def _begin_session(self, client: Any) -> _Session:
        """A new session for *client*, its callbacks bound to it alone."""
        session = _Session(client)
        # Acknowledged once routed, never on arrival: a message the route had
        # no room for stays with the broker rather than being taken and lost.
        manual_ack_set = getattr(client, "manual_ack_set", None)
        self._manual_ack = callable(manual_ack_set)
        if callable(manual_ack_set):
            manual_ack_set(True)
        client.on_connect = functools.partial(self._on_connect, session)
        client.on_subscribe = functools.partial(self._on_subscribe, session)
        client.on_disconnect = functools.partial(self._on_disconnect, session)
        client.on_message = functools.partial(self._on_message, session)
        self._session = session
        return session

    async def _connect_and_serve(
        self, session: _Session, shutdown_event: asyncio.Event
    ) -> bool:
        """Serve one session; True when it ended to have the broker redeliver."""
        client = session.client
        username = self._broker.username
        password = self._broker.password
        if username:
            client.username_pw_set(username, password)
        apply_tls_context(client, self._broker)
        await self._io.run(
            client.connect,
            self._broker.host,
            int(self._broker.port),
            60,
        )
        await self._io.run(client.loop_start)
        # Either end of the route can fail: the broker may refuse the
        # subscription, or drop a session it had granted. Both must reconnect
        # rather than leave a task parked on a route that no longer carries
        # anything.
        await _wait_first(shutdown_event, session.lost, session.redeliver)
        if shutdown_event.is_set():
            return False
        if session.redeliver.is_set() and not session.lost.is_set():
            logger.info(
                "[evidence-inbound] reconnecting so the broker redelivers the "
                "messages left unacknowledged"
            )
            return True
        raise ConnectionError("subscription lost")

    async def close(self) -> None:
        """Close the current session, then stop its client."""
        session = self._session
        if session is None or not session.open:
            return
        session.close()
        client = session.client
        try:
            await self._io.run(client.loop_stop)
        except Exception:
            logger.warning("[evidence-inbound] failed to stop MQTT loop")
        try:
            await self._io.run(client.disconnect)
        except Exception:
            logger.warning("[evidence-inbound] failed to disconnect cleanly")

    # ── paho callbacks, each bound to the session whose client it is ────────

    def _on_connect(
        self,
        session: _Session,
        client: Any,
        _userdata: Any,
        _flags: Any,
        rc: Any,
        *_: Any,
    ) -> None:
        if _rc_value(rc) != 0:
            logger.warning("[evidence-inbound] MQTT connect failed rc=%s", rc)
            self._signal_lost(session)
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
            self._signal_lost(session)

    def _on_subscribe(
        self,
        session: _Session,
        _client: Any,
        _userdata: Any,
        _mid: Any,
        reason_codes: Any,
        *_: Any,
    ) -> None:
        """Mark the session up only once the broker has granted the subscription.

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
            session.set_connected(False)
            self._signal_lost(session)
            return
        if not session.set_connected(True):
            return
        logger.info(
            "[evidence-inbound] subscribed to %s via %s:%s (envelope auth=%s)",
            self.topic,
            self._broker.host,
            self._broker.port,
            "enabled" if self._router.envelope_authenticated else "disabled",
        )

    def _on_disconnect(
        self, session: _Session, _client: Any, _userdata: Any, *args: Any
    ) -> None:
        """Drop the session's claim to be up, and reconnect.

        Without this `connected` stays true after the session is gone, which
        would report a working route while nothing could arrive.
        """
        if not session.set_connected(False):
            return
        logger.warning("[evidence-inbound] disconnected from broker")
        self._signal_lost(session)

    def _signal_lost(self, session: _Session) -> None:
        """Wake the serve loop from a paho callback thread to end *session*."""
        loop = self._loop
        if loop is not None:
            loop.call_soon_threadsafe(session.lost.set)

    def _on_message(
        self, session: _Session, client: Any, _userdata: Any, message: Any
    ) -> None:
        loop = self._loop
        if loop is None:
            logger.warning(
                "[evidence-inbound] message received before event loop ready"
            )
            return
        payload = getattr(message, "payload", b"") or b""
        if session.pending or not session.open:
            # A reconnect is due, or this client's session is over: the broker
            # brings this back unread. Still classified and counted.
            if self._ingress.within_size(payload):
                self._ingress.refuse(REDELIVERY_DUE)
            else:
                self._release(client, message)
            return
        refusal = self._ingress.admit(payload, over_rate=REDELIVERY_DUE)
        if refusal == PAYLOAD_TOO_LARGE:
            # Released, never answered: a message refused for its size would
            # be redelivered and refused without end.
            self._release(client, message)
            return
        if refusal is not None:
            # Left with the broker, which redelivers it once the rate has room.
            self._leave_with_broker(session, loop, rate=True)
            return
        if not self._slots.try_take():
            # Nothing is scheduled for it: the message stays with the broker
            # and comes back after the reconnect that follows the backlog.
            self._shed += 1
            self._ingress.refuse(REDELIVERY_DUE)
            if self._leave_with_broker(session, loop):
                logger.warning(
                    "[evidence-inbound] %d messages in flight; further messages "
                    "are left with the broker until they clear",
                    INBOUND_IN_FLIGHT_BOUND,
                )
            return
        ticket = _Ticket(session)
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._routed(
                    ticket,
                    client,
                    payload,
                    getattr(message, "mid", None),
                    getattr(message, "qos", 0),
                ),
                loop,
            )
        except Exception:
            logger.warning("[evidence-inbound] could not schedule a message")
            session.owe(failed=True)
            self._give_back()
            return
        future.add_done_callback(functools.partial(self._settled, ticket))

    def _leave_with_broker(
        self, session: _Session, loop: asyncio.AbstractEventLoop, *, rate: bool = False
    ) -> bool:
        """Owe the broker's redelivery of a message left unacknowledged.

        Owed first, then settled against the slots: once none is taken the
        reconnect is due now, since a slot released between the two found
        nothing owed and will not come back to it. True when this opens the
        episode.
        """
        first = session.owe(rate=rate)
        if self._slots.taken == 0:
            session.redeliver_owed(loop)
        return first

    def _release(self, client: Any, message: Any) -> None:
        """Acknowledge *message* at the broker without routing it."""
        mid = getattr(message, "mid", None)
        if not self._manual_ack or mid is None:
            return
        try:
            code = client.ack(mid, getattr(message, "qos", 0))
        except Exception:
            logger.warning("[evidence-inbound] failed to release a refused message")
            return
        if _rc_value(code) != 0:
            logger.warning("[evidence-inbound] the client refused an ack rc=%s", code)

    def _give_back(self) -> None:
        """Release a slot; once none is taken, the current session reconnects
        for what it owes. The slots are every session's; what is owed is the
        session's own."""
        if self._slots.give_back() > 0:
            return
        session, loop = self._session, self._loop
        if session is not None and loop is not None:
            session.redeliver_owed(loop)

    def _settled(self, ticket: _Ticket, future: Any) -> None:
        # A route cancelled before it started never reached its own release.
        if not ticket.started:
            ticket.session.owe(failed=True)
            self._give_back()
        _log_future_failure(future)

    async def _routed(
        self, ticket: _Ticket, client: Any, payload: bytes, mid: Any, qos: Any
    ) -> None:
        ticket.started = True
        try:
            await self._route(ticket, client, payload, mid, qos)
        finally:
            self._give_back()

    async def _route(
        self, ticket: _Ticket, client: Any, payload: bytes, mid: Any, qos: Any
    ) -> None:
        # Owed to the session that admitted the message, even once it is over:
        # its reconnect redelivered the message, and nothing reads a closed
        # session's debt.
        acknowledged = False
        try:
            await self._route_admitted(payload)
            acknowledged = await self._acknowledge(client, mid, qos)
        finally:
            if not acknowledged and self._manual_ack and mid is not None:
                # Routing failed or was cancelled before the broker released
                # the message: it is still the broker's, and comes back after
                # the reconnect.
                ticket.session.owe(failed=True)

    async def _acknowledge(self, client: Any, mid: Any, qos: Any) -> bool:
        """Release the message at the broker once it has been routed."""
        if not self._manual_ack or mid is None:
            return True
        try:
            code = await self._io.run(client.ack, mid, qos)
        except Exception:
            logger.warning("[evidence-inbound] failed to acknowledge a message")
            return False
        if _rc_value(code) != 0:
            logger.warning("[evidence-inbound] the client refused an ack rc=%s", code)
            return False
        return True

    async def _route_admitted(self, payload: bytes) -> None:
        routed = await self._router.route(payload)
        if (
            isinstance(routed.outcome, InboundRefusal)
            and routed.outcome.reason in MEMBER_REASONS
        ):
            self._ingress.refuse(routed.outcome.reason)
        elif isinstance(routed.outcome, InboundRefusal):
            # A transport refusal is the sender's to repeat, so it is summed.
            self._refusal_log.warn(
                routed.outcome.reason,
                "[evidence-inbound] message refused before ingest: %s (%s)",
                routed.outcome.reason,
                routed.outcome.detail,
            )
        else:
            _log_result(routed.outcome)
        if routed.acknowledgement is None:
            return
        session = self._session
        if session is None or not session.open:
            # Answered only on an open session: a closed one's client may be
            # one a close failed to stop.
            logger.warning(
                "[evidence-inbound] no connection to acknowledge on; the courier "
                "will redeliver"
            )
            return
        try:
            await self._io.run(
                session.client.publish,
                self._router.ack_topic,
                json.dumps(routed.acknowledgement).encode(),
                1,
            )
        except Exception:
            # The courier retires an artifact only on an acknowledgement, so a
            # lost one costs a redelivery rather than the evidence.
            logger.warning("[evidence-inbound] failed to publish acknowledgement")


class _Ticket:
    """Whether one admitted message's route has started, and its session."""

    __slots__ = ("session", "started")

    def __init__(self, session: _Session) -> None:
        self.session = session
        self.started = False


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
    if future.cancelled():
        # Cancelled at shutdown; its message stays the broker's.
        return
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
    if not result.decided:
        logger.warning(
            "[evidence-inbound] %s left undecided (%s); released without an "
            "acknowledgement so the courier delivers it again",
            result.artifact,
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
