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
checkpoint or registration retires its courier handoff copy because the
gateway's durable queue now owns retry. For a registration that retires only
the copy: its confirmation obligation keeps the sealed bytes and re-offers
them until a verified epoch confirmation closes it.

Nothing here is authenticated by the carriage itself. Every artifact carries
its own device signature end to end, so a carriage HMAC would prove nothing a
gateway holding that key could not forge.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import functools
import hashlib
import json
import logging
import re
import threading
from dataclasses import dataclass
from typing import Any, Callable

from ori.gateway.mqtt_security import apply_tls_context, parse_gateway_broker_url
from ori.gateway.payload_bounds import (
    EVIDENCE_OUTBOUND_ACK,
    IN_FLIGHT_EXCEEDED,
    IngressBound,
)
from ori.gateway.route_io import RouteIO, Slots
from ori.security.evidence.bound import BoundOutboundQueue
from ori.security.evidence.executor import EvidenceExecutorSaturatedError
from ori.security.evidence.ledger import (
    FAULT_HOLDER_ENVELOPE,
    FAULT_HOLDER_OBLIGATION,
    FAULT_HOLDER_OUTBOX,
    OUTBOX_ANCHOR_REGISTRATION,
    OUTBOX_ARTIFACT_TYPES,
    OUTBOX_CHECKPOINT,
    RETIRE_QUEUED,
    RETIRE_REFUSED,
    copy_fault,
)
from ori.security.evidence.registration import MAX_DOUBLINGS
from ori.security.gateway_messages import (
    AuthenticatedMessage,
    GatewayMessageAuthenticator,
    GatewayMessageAuthError,
)
from ori.security.payload_members import (
    EVIDENCE_OUTBOUND_ACK_MEMBERS,
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

_JSON_INTEGER_MAX = 2**53 - 1


EVIDENCE_OUTBOUND_TOPIC_TEMPLATE = "ori/{device_id}/evidence/outbound"
EVIDENCE_OUTBOUND_ACK_TOPIC_TEMPLATE = "ori/{device_id}/evidence/outbound/ack"
EVIDENCE_OUTBOUND_ACK_MESSAGE_TYPE = "evidence_outbound_ack"

ARTIFACT_DELIVERY_ENVELOPE = "delivery_envelope"
ARTIFACT_ANCHOR_REGISTRATION = OUTBOX_ANCHOR_REGISTRATION
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
_SHUTDOWN_DRAIN_S = 5.0
#: Acknowledgements being applied at once. Past it one is dropped; the
#: artifact stays retained and its next attempt draws another.
ACK_IN_FLIGHT_BOUND = 16
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}\Z")


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
    # A clock moved back past the last attempt makes it due at once; waiting
    # for the clock to catch up would hold the only copy for the whole step.
    if at_ms < int(last_attempt_ms):
        return True
    # The attempt count is unbounded; the exponent is not.
    doublings = min(int(attempts) - 1, MAX_DOUBLINGS)
    delay_s = min(RETRY_INTERVAL_S * (1 << doublings), RETRY_BACKOFF_MAX_S)
    return at_ms - int(last_attempt_ms) >= delay_s * 1000.0


def _row_due(row: dict[str, Any], at_ms: int, what: str) -> bool:
    """A row whose schedule cannot be computed is due, never a reason the route drops."""
    try:
        return retry_due(int(row["attempts"]), row["last_attempt_ms"], at_ms=at_ms)
    except Exception:
        logger.warning("[evidence-outbound] a %s's retry schedule is unreadable", what)
        return True


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
            # gateway-api/v2 Payload Member Rule, before any member is read.
            try:
                decoded = admitted_text(payload, defined=EVIDENCE_OUTBOUND_ACK_MEMBERS)
            except PayloadMemberError as exc:
                return AckRouted(ROUTED_REFUSED, exc.reason)

        # The courier's own time for this answer, which orders it against the
        # answers before it: the authenticated signing time, and only that.
        auth_block = decoded.get("auth")
        signed_at = (
            auth_block.get("signed_at_ms") if isinstance(auth_block, dict) else None
        )
        # Authenticated now, recorded as seen only once it answers something
        # this device sent: an acknowledgement for nothing held adds no state,
        # replay record included (gateway-api/v2 Payload Volume).
        claim: AuthenticatedMessage | None = None
        if self._message_auth is not None:
            try:
                claim = await self._message_auth.authenticate_async(
                    decoded,
                    message_type=EVIDENCE_OUTBOUND_ACK_MESSAGE_TYPE,
                    expected_device_id=self._device_id,
                    now_ms_value=self._now(),
                )
            except GatewayMessageAuthError as exc:
                return AckRouted(ROUTED_REFUSED, f"envelope unauthenticated: {exc}")
            decoded = claim.payload
        elif decoded.get("device_id") != self._device_id:
            return AckRouted(ROUTED_REFUSED, "acknowledgement names another device")

        # Members are taken only as text, so str() never sees a value nested
        # past the recursion limit, which raises from a route that never raises.
        members = ("artifact_type", "artifact_digest", "outcome", "reason")
        if any(not isinstance(decoded.get(name, ""), str) for name in members):
            return AckRouted(ROUTED_REFUSED, "an acknowledgement member is not text")
        artifact_type: str = decoded.get("artifact_type", "")
        digest: str = decoded.get("artifact_digest", "")
        outcome: str = decoded.get("outcome", "")
        reason: str = decoded.get("reason", "")
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
        answered_at_ms = self._answered_at(signed_at, at_ms)
        if artifact_type == ARTIFACT_DELIVERY_ENVELOPE:
            return await self._apply_to_envelope(
                digest, outcome, reason, at_ms, answered_at_ms, claim
            )
        return await self._apply_to_artifact(
            artifact_type, digest, outcome, reason, at_ms, claim
        )

    async def _replayed(self, claim: AuthenticatedMessage | None) -> AckRouted | None:
        """Record *claim* as seen, off the event loop; the refusal when it was
        already."""
        if claim is None or self._message_auth is None:
            return None
        try:
            await self._message_auth.commit_async(claim)
        except GatewayMessageAuthError as exc:
            return AckRouted(ROUTED_REFUSED, f"envelope unauthenticated: {exc}")
        return None

    def _answered_at(self, signed_at: Any, at_ms: int) -> int:
        """The courier's time for an answer, or the receive time in its place.

        Only an authenticated signing time is the courier's account, and only
        inside the integer zone and no further ahead of receipt than the
        envelope's own clock skew allows. Unauthenticated, anything on the
        site network could pin the ordering time ahead, so receipt stands in.
        """
        if self._message_auth is None:
            return at_ms
        if (
            isinstance(signed_at, int)
            and not isinstance(signed_at, bool)
            and abs(signed_at) <= _JSON_INTEGER_MAX
            and signed_at <= at_ms + self._message_auth.max_skew_ms
        ):
            return int(signed_at)
        return at_ms

    async def _apply_to_envelope(
        self,
        digest: str,
        outcome: str,
        reason: str,
        at_ms: int,
        answered_at_ms: int,
        claim: AuthenticatedMessage | None = None,
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
        # The courier can only answer for bytes it was given: an answer for an
        # envelope never handed off adds nothing, its replay key included.
        if int(row["attempts"]) == 0:
            logger.warning(
                "[evidence-outbound] acknowledgement names an envelope never "
                "handed off; refused"
            )
            return AckRouted(
                ROUTED_REFUSED, "never handed off", ARTIFACT_DELIVERY_ENVELOPE, digest
            )
        replayed = await self._replayed(claim)
        if replayed is not None:
            return replayed
        local_seq = int(row["local_seq"])
        if outcome == ACK_QUEUED:
            # Custody is claimed only by the custody acknowledgement, which
            # arrives through the inbound route under its own key; `queued`
            # ends a refusal episode and nothing more.
            await self._outbox.apply_courier_answer(
                local_seq, answer=ACK_QUEUED, at_ms=at_ms, answered_at_ms=answered_at_ms
            )
            return AckRouted(ROUTED_APPLIED, "", ARTIFACT_DELIVERY_ENVELOPE, digest)
        if reason == ACK_REASON_QUEUE_FULL:
            await self._outbox.apply_courier_answer(
                local_seq,
                answer=ACK_REASON_QUEUE_FULL,
                at_ms=at_ms,
                answered_at_ms=answered_at_ms,
            )
            return AckRouted(ROUTED_APPLIED, reason, ARTIFACT_DELIVERY_ENVELOPE, digest)
        # One failure row per refusal episode, decided in the ledger's own
        # transaction: the envelope keeps being republished at the backoff
        # cap, and a courier refusing the same bytes indefinitely must not
        # grow the record by one row per attempt.
        if await self._outbox.apply_courier_answer(
            local_seq, answer="refused", at_ms=at_ms, answered_at_ms=answered_at_ms
        ):
            logger.error(
                "[evidence-outbound] the courier refused sealed envelope "
                "local_seq=%s (%s)",
                local_seq,
                reason,
            )
        return AckRouted(ROUTED_APPLIED, reason, ARTIFACT_DELIVERY_ENVELOPE, digest)

    async def _apply_to_artifact(
        self,
        artifact_type: str,
        digest: str,
        outcome: str,
        reason: str,
        at_ms: int,
        claim: AuthenticatedMessage | None = None,
    ) -> AckRouted:
        row = await self._outbox.find_artifact(digest)
        if row is None or str(row["artifact_type"]) != artifact_type:
            logger.warning(
                "[evidence-outbound] acknowledgement names a %s this device never "
                "queued; ignored",
                artifact_type,
            )
            return AckRouted(ROUTED_IGNORED, "unknown artifact", artifact_type, digest)
        # The courier can only answer for bytes it was given. An answer for a
        # copy never handed off would retire it, queued or refused, unsent.
        if int(row["attempts"]) == 0:
            logger.warning(
                "[evidence-outbound] acknowledgement names a %s never handed off; "
                "refused",
                artifact_type,
            )
            return AckRouted(ROUTED_REFUSED, "never handed off", artifact_type, digest)
        replayed = await self._replayed(claim)
        if replayed is not None:
            return replayed
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


class _Session:
    """One broker session of the outbound route.

    It owns its client, the events that end it or report its grant, and
    whether it is up. Callbacks are bound to the session whose client they
    belong to, so a client a close failed to stop reaches only its own closed
    session, never the one that replaced it.
    """

    def __init__(self, client: Any) -> None:
        self.client = client
        self.lock = threading.Lock()
        self.lost = asyncio.Event()
        self.granted = asyncio.Event()
        self.open = True
        self.connected = False

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

    @property
    def carrying(self) -> bool:
        """Granted, and so open: what may publish on it."""
        return self.connected


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
        self._loop: asyncio.AbstractEventLoop | None = None
        self._session: _Session | None = None
        self._wake: asyncio.Event | None = None
        self._drain_lock = asyncio.Lock()
        self._published = 0
        self._io = RouteIO("ori-evidence-out")
        # Taken in the client's callback thread, before anything is scheduled.
        self._ack_slots = Slots(ACK_IN_FLIGHT_BOUND)
        self._ingress = IngressBound(EVIDENCE_OUTBOUND_ACK)
        self._acks_shed = 0
        self._refusal_log = CoalescedWarning(logger)

    @property
    def ingress(self) -> IngressBound:
        """This route's size and rate bound, whose counts health reports."""
        return self._ingress

    @property
    def topic(self) -> str:
        return EVIDENCE_OUTBOUND_TOPIC_TEMPLATE.format(device_id=self._device_id)

    @property
    def ack_topic(self) -> str:
        return EVIDENCE_OUTBOUND_ACK_TOPIC_TEMPLATE.format(device_id=self._device_id)

    @property
    def connected(self) -> bool:
        """Whether the broker has granted the current session's subscription."""
        session = self._session
        return session is not None and session.connected

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
        self._wake = asyncio.Event()
        self._io.open()
        try:
            await self._serve(shutdown_event)
        finally:
            self._io.shutdown()

    async def _serve(self, shutdown_event: asyncio.Event) -> None:
        delay = _RECONNECT_MIN_S
        while not shutdown_event.is_set():
            try:
                await self._connect_and_serve(shutdown_event)
                delay = _RECONNECT_MIN_S
            except asyncio.CancelledError:
                raise
            except Exception as exc:
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

    def _begin_session(self, client: Any) -> _Session:
        """A new session for *client*, its callbacks bound to it alone."""
        session = _Session(client)
        client.on_connect = functools.partial(self._on_connect, session)
        client.on_subscribe = functools.partial(self._on_subscribe, session)
        client.on_disconnect = functools.partial(self._on_disconnect, session)
        client.on_message = self._on_message
        self._session = session
        return session

    async def _connect_and_serve(self, shutdown_event: asyncio.Event) -> None:
        wake = self._wake
        assert wake is not None
        client = self._client_factory(client_id=f"ori-evidence-out-{self._device_id}")
        session = self._begin_session(client)
        lost, granted = session.lost, session.granted
        if self._broker.username:
            client.username_pw_set(self._broker.username, self._broker.password)
        apply_tls_context(client, self._broker)
        await self._io.run(
            client.connect, self._broker.host, int(self._broker.port), 60
        )
        await self._io.run(client.loop_start)
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
        # since the last drain before the route is closed, within a bound, so a
        # held evidence store cannot hold the shutdown.
        await self.flush(_SHUTDOWN_DRAIN_S)

    async def drain(self) -> int:
        """Publish every retained artifact whose retry is due. Returns the count."""
        # One drain at a time: a nudge and a shutdown flush that overlap would
        # both read the same undue rows and carry each artifact twice.
        async with self._drain_lock:
            try:
                return await self._drain()
            except EvidenceExecutorSaturatedError:
                # The worker has all the work it admits; the next cycle retries.
                logger.warning(
                    "[evidence-outbound] evidence worker busy; drain deferred"
                )
                return 0

    async def _drain(self) -> int:
        session = self._session
        if session is None or not session.carrying:
            return 0
        at_ms = self._now()
        self._published = 0
        # Each stage returns False when the route failed; the rest wait.
        for stage in (
            self._drain_envelopes,
            self._drain_checkpoint,
            self._drain_registrations,
            self._drain_reoffers,
        ):
            if not await stage(at_ms):
                break
        return self._published

    async def _carriable(
        self, holder: str, holder_id: int, wire: bytes, digest: str, at_ms: int
    ) -> bool:
        """The bytes are what was sealed; if not, the copy leaves the route.

        Its bytes stay where they are and the fault is recorded once, so a
        damaged copy is neither carried nor left to hold anything behind it.
        """
        fault = copy_fault(wire, digest)
        if fault is None:
            return True
        logger.error(
            "[evidence-outbound] a retained %s copy cannot be carried as sealed "
            "(%s); it is kept and taken off the route",
            holder,
            fault,
        )
        await self._outbox.record_artifact_fault(
            holder, holder_id, reason=fault, at_ms=at_ms
        )
        return False

    async def _drain_envelopes(self, at_ms: int) -> bool:
        """Carry due envelopes, reading past any that are not yet due."""
        published = 0
        after = 0
        while published < DRAIN_BATCH:
            rows = await self._outbox.awaiting_custody(DRAIN_BATCH, after_seq=after)
            if not rows:
                break
            for row in rows:
                local_seq = int(row["local_seq"])
                after = local_seq
                if not _row_due(row, at_ms, ARTIFACT_DELIVERY_ENVELOPE):
                    continue
                wire = bytes(row["envelope_bytes"])
                if not await self._carriable(
                    FAULT_HOLDER_ENVELOPE,
                    local_seq,
                    wire,
                    str(row["envelope_digest"]),
                    at_ms,
                ):
                    continue
                # A stop applied since the page was read holds this one too.
                if not await self._outbox.awaiting_custody(1, only_seq=local_seq):
                    continue
                # The attempt is recorded before the bytes leave, so an
                # acknowledgement that overtakes this call still finds the
                # envelope handed off; only its transport outcome follows.
                await self._outbox.record_attempt(local_seq, at_ms=at_ms, failure=None)
                sent = await self._publish(ARTIFACT_DELIVERY_ENVELOPE, wire)
                if not sent:
                    await self._outbox.record_transport_failure(
                        local_seq, failure="unreachable"
                    )
                    return False
                published += 1
                self._published += 1
                if published >= DRAIN_BATCH:
                    break
        return True

    async def _drain_checkpoint(self, at_ms: int) -> bool:
        """Carry the earliest checkpoint still awaiting its acknowledgement.

        Checkpoints leave in production order: a later one is never handed
        off while an earlier one lacks its `queued` acknowledgement, and when
        the earliest is not yet due the later ones wait with it. The earliest
        is selected in SQL, so no number of later checkpoints can crowd
        anything else out. A copy whose bytes are damaged leaves the order.
        """
        # Bounded: each pass either ends the drain or takes one damaged copy
        # off the route, which makes the next checkpoint the earliest.
        for _ in range(DRAIN_BATCH):
            head = await self._outbox.pending_artifacts(
                1, artifact_type=OUTBOX_CHECKPOINT
            )
            if not head:
                return True
            row = head[0]
            wire = bytes(row["artifact_bytes"])
            if not await self._carriable(
                FAULT_HOLDER_OUTBOX,
                int(row["id"]),
                wire,
                str(row["artifact_digest"]),
                at_ms,
            ):
                continue
            if not _row_due(row, at_ms, OUTBOX_CHECKPOINT):
                return True
            return await self._hand_off(row, wire, at_ms)
        return True

    async def _drain_registrations(self, at_ms: int) -> bool:
        """Carry due registration copies; checkpoints never hold them."""
        published = 0
        after = 0
        while published < DRAIN_BATCH:
            rows = await self._outbox.pending_artifacts(
                DRAIN_BATCH, artifact_type=OUTBOX_ANCHOR_REGISTRATION, after_id=after
            )
            if not rows:
                break
            for row in rows:
                after = int(row["id"])
                if not _row_due(row, at_ms, OUTBOX_ANCHOR_REGISTRATION):
                    continue
                wire = bytes(row["artifact_bytes"])
                if not await self._carriable(
                    FAULT_HOLDER_OUTBOX,
                    int(row["id"]),
                    wire,
                    str(row["artifact_digest"]),
                    at_ms,
                ):
                    continue
                before = self._published
                if not await self._hand_off(row, wire, at_ms):
                    return False
                published += self._published - before
                if published >= DRAIN_BATCH:
                    break
        return True

    async def _hand_off(self, row: dict[str, Any], wire: bytes, at_ms: int) -> bool:
        """Publish one outbox copy; False only when the route failed."""
        # A stop applied since the row was read holds it too.
        if not await self._outbox.pending_artifacts(1, only_id=int(row["id"])):
            return True
        # The attempt is recorded before the bytes leave, so an acknowledgement
        # that overtakes this call still finds them handed off.
        await self._outbox.note_artifact_attempt(
            str(row["artifact_digest"]), at_ms=at_ms
        )
        if not await self._publish(str(row["artifact_type"]), wire):
            return False
        self._published += 1
        return True

    async def _drain_reoffers(self, at_ms: int) -> bool:
        """Re-offer unconfirmed registrations from their obligations, byte for byte."""
        for row in await self._outbox.registration_reoffers_due(
            at_ms=at_ms, limit=DRAIN_BATCH
        ):
            wire = bytes(row["artifact_bytes"])
            if not await self._carriable(
                FAULT_HOLDER_OBLIGATION,
                int(row["id"]),
                wire,
                str(row["artifact_digest"]),
                at_ms,
            ):
                continue
            if not await self._outbox.registration_reoffers_due(
                at_ms=at_ms, limit=1, only_id=int(row["id"])
            ):
                continue
            # The attempt is persisted before the bytes leave, as for the
            # courier copy: the next delay runs from every attempted offer,
            # including one the route or the process loses.
            await self._outbox.note_registration_offer(
                str(row["artifact_digest"]), at_ms=at_ms
            )
            if not await self._publish(ARTIFACT_ANCHOR_REGISTRATION, wire):
                return False
            self._published += 1
        return True

    async def flush(self, timeout_s: float) -> int:
        """Drain once, bounded, for a clean shutdown. Returns the count."""
        try:
            return await asyncio.wait_for(self.drain(), timeout=timeout_s)
        except asyncio.TimeoutError:
            logger.warning("[evidence-outbound] shutdown flush timed out")
            return 0

    async def _publish(self, artifact_type: str, wire: bytes) -> bool:
        session = self._session
        # Checked before every artifact, not once per pass: the session can drop
        # between two publishes of one drain, and nothing is carried after it.
        if session is None or not session.carrying:
            return False
        try:
            payload = carriage_payload(self._device_id, artifact_type, wire)
            await self._io.run(session.client.publish, self.topic, payload, 1)
        except Exception:
            logger.warning("[evidence-outbound] failed to publish a %s", artifact_type)
            return False
        return True

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
            logger.warning("[evidence-outbound] failed to stop MQTT loop")
        try:
            await self._io.run(client.disconnect)
        except Exception:
            logger.warning("[evidence-outbound] failed to disconnect cleanly")

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
            logger.warning("[evidence-outbound] MQTT connect failed rc=%s", rc)
            self._signal(session.lost)
            return
        result = client.subscribe(self.ack_topic, qos=1)
        code = result[0] if isinstance(result, tuple) else result
        if _rc_value(code) != 0:
            logger.warning(
                "[evidence-outbound] could not send subscribe for %s rc=%s",
                self.ack_topic,
                code,
            )
            self._signal(session.lost)

    def _on_subscribe(
        self,
        session: _Session,
        _client: Any,
        _userdata: Any,
        _mid: Any,
        reason_codes: Any,
        *_: Any,
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
            session.set_connected(False)
            self._signal(session.lost)
            return
        if not session.set_connected(True):
            return
        logger.info(
            "[evidence-outbound] carrying on %s via %s:%s (envelope auth=%s)",
            self.topic,
            self._broker.host,
            self._broker.port,
            "enabled" if self._router.envelope_authenticated else "disabled",
        )
        self._signal(session.granted)

    def _on_disconnect(
        self, session: _Session, _client: Any, _userdata: Any, *args: Any
    ) -> None:
        if not session.set_connected(False):
            return
        logger.warning("[evidence-outbound] disconnected from broker")
        self._signal(session.lost)

    def _signal(self, event: asyncio.Event) -> None:
        loop = self._loop
        if loop is not None:
            loop.call_soon_threadsafe(event.set)

    def _on_message(self, _client: Any, _userdata: Any, message: Any) -> None:
        loop = self._loop
        if loop is None:
            logger.warning(
                "[evidence-outbound] acknowledgement received before event loop ready"
            )
            return
        payload = getattr(message, "payload", b"") or b""
        if self._ingress.admit(payload) is not None:
            # Dropped unread; the artifact stays retained, as at the bound below.
            return
        if not self._ack_slots.try_take():
            # Dropped before anything is scheduled; the artifact stays retained
            # and its next attempt draws another acknowledgement.
            self._acks_shed += 1
            self._ingress.refuse(IN_FLIGHT_EXCEEDED)
            return
        started = [False]
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._route_ack(payload, started), loop
            )
        except Exception:
            logger.warning("[evidence-outbound] could not schedule an acknowledgement")
            self._ack_slots.give_back()
            return

        def settled(done: Any) -> None:
            if not started[0]:
                self._ack_slots.give_back()
            _log_future_failure(done)

        future.add_done_callback(settled)

    @property
    def acks_shed(self) -> int:
        """Acknowledgements dropped at the in-flight bound."""
        return self._acks_shed

    @property
    def _acks_in_flight(self) -> int:
        return self._ack_slots.taken

    async def _route_ack(self, payload: bytes, started: list[bool]) -> None:
        started[0] = True
        try:
            await self._apply_ack(payload)
        finally:
            self._ack_slots.give_back()

    async def _apply_ack(self, payload: bytes) -> None:
        routed = await self._router.handle_ack(payload)
        if routed.outcome == ROUTED_REFUSED and routed.reason in MEMBER_REASONS:
            self._ingress.refuse(routed.reason)
        elif routed.outcome == ROUTED_REFUSED:
            self._refusal_log.warn(
                "refused",
                "[evidence-outbound] acknowledgement refused: %s",
                routed.reason,
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
    if future.cancelled():
        # Cancelled at shutdown: nothing failed.
        return
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
