# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""HTTP telemetry export for phone and lightweight provisioned deployments.

Delivery follows `runtime-telemetry/v2`: a batch is delivered only when the
receiver's answer says its events are held, a batch that is not delivered is
retained under its own identity and re-sent unchanged, and a transport failure
never stops the exporter. How an answer is read lives in `delivery.py` so the
Android payload can reach the same verdict from the same bytes.
"""

import asyncio
import hmac
import json
import logging
import os
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import asdict, dataclass, field
from typing import Any

from ori.config import TelemetryExportConfig
from ori.network.events import OriEvent, SensorReading
from ori.telemetry.canonical import (
    TelemetryCanonicalizationError,
    canonical_telemetry_bytes,
    telemetry_hmac_sha256,
)
from ori.telemetry.delivery import (
    MAX_RESPONSE_BYTES,
    TERMINAL_REFUSAL_STATUSES,
    TERMINAL_REFUSALS,
    DeliveryOutcome,
    DeliveryVerdict,
    body_is_wanted,
    read_answer,
    read_batch_response,
)
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

# Annotated Any so the fallback assignment below needs no ignore: an ignore
# here would be reported unused in whichever environment does not match it.
_httpx: Any
try:
    import httpx as _httpx

    _HTTPX_AVAILABLE = True
except ImportError:
    _httpx = None
    _HTTPX_AVAILABLE = False

SCHEMA_VERSION = "runtime.telemetry.v1"

# TERMINAL_REFUSALS and the rule that reads an answer live in delivery.py, so
# the same bytes reach the same verdict here and in the Android payload. They
# are re-exported because the runtime and its tests import them from this
# module.
__all__ = [
    "HttpTelemetryExporter",
    "TERMINAL_REFUSALS",
    "TERMINAL_REFUSAL_STATUSES",
]


@dataclass
class _PendingBatch:
    """A batch and the identity it keeps across every attempt.

    `runtime-telemetry/v2` re-sends a retained batch as the same batch: the same
    events in the same order under the same `sequence`. Only `sent_at_ms` and
    the signature are recomputed, so the batch has to outlive the attempt that
    failed -- which is why events are held here rather than pushed back onto the
    queue, where a later drain would merge them with newer readings under a new
    sequence.
    """

    sequence: int
    events: list[dict[str, Any]] = field(default_factory=list)
    # Attempts the receiver's application answered without confirming. Such an
    # answer is deterministic, so after MAX_UNCONFIRMED_ATTEMPTS the batch is
    # abandoned and counted rather than held at the head of the queue for good.
    unconfirmed_attempts: int = 0


# Enough attempts to ride out a receiver mid-deploy answering inconsistently,
# few enough that one batch a receiver will never confirm cannot hold the head
# of the queue indefinitely. The Android payload holds the same number.
MAX_UNCONFIRMED_ATTEMPTS = 5


class HttpTelemetryExporter:
    """Bounded, non-authoritative HTTP telemetry exporter.

    The exporter is intentionally outside the actuation path. It mirrors real
    runtime events to a provisioned telemetry endpoint, but endpoint
    availability must never influence Tier B/C/D action authority.
    """

    def __init__(
        self,
        *,
        device_id: str,
        config: TelemetryExportConfig,
    ) -> None:
        self._device_id = device_id
        self._config = config
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=config.max_queue_size
        )
        # Batches the receiver has not confirmed, oldest first. Capacity is
        # shared with the queue so retention cannot grow past the bound the
        # deployment set for in-memory telemetry.
        self._retained: deque[_PendingBatch] = deque()
        self._retained_events = 0
        self._in_flight_events = 0
        self._sequence = 0
        self._dropped_events = 0
        self._refused_events = 0
        self._declined_events = 0
        self._duplicate_events = 0
        self._unconfirmed_events = 0
        self._unreadable_responses = 0
        self._nonconformant_responses = 0
        self._refusal_status: int | None = None
        self._refusal_detail: str | None = None
        self._refused_credential: str | None = None
        self._refused_at_ms: int | None = None

    @property
    def dropped_events(self) -> int:
        """Events discarded because the in-memory queue was full."""
        return self._dropped_events

    @property
    def refused_events(self) -> int:
        """Events discarded because export is suspended by a terminal refusal."""
        return self._refused_events

    @property
    def declined_events(self) -> int:
        """Events the receiver reported as rejected.

        Counted apart from `dropped_events` and `refused_events` because the
        contract requires the three to be distinguishable: one is this
        exporter's own overflow, one is a suspended credential, and this one is
        the receiver declining a reading it was sent. None of them is an export.
        """
        return self._declined_events

    @property
    def duplicate_events(self) -> int:
        """Events the receiver reported it already held. Delivered, not lost."""
        return self._duplicate_events

    @property
    def unconfirmed_events(self) -> int:
        """Events abandoned after the receiver answered without confirming them.

        The receiver spoke and did not account for the batch, repeatedly. That is
        not this exporter's overflow, not a suspension and not a named decline,
        so it is counted on its own and never as exported.
        """
        return self._unconfirmed_events

    @property
    def retained_events(self) -> int:
        """Events held in batches the receiver has not confirmed."""
        return self._retained_events

    @property
    def export_suspended(self) -> bool:
        """True while a terminal refusal is stopping export for this credential."""
        return self._refusal_status is not None

    def status_snapshot(self) -> dict[str, Any]:
        """Reportable export state. Carries no credential material.

        `transport_available` is reported separately from `enabled` because a
        configured exporter with no HTTP client posts nothing while looking
        configured, and a runtime must not report a capability as present
        while it is unavailable.
        """
        return {
            "transport_available": _HTTPX_AVAILABLE,
            "suspended": self.export_suspended,
            "refusal_status": self._refusal_status,
            "refusal_detail": self._refusal_detail,
            "refused_at_ms": self._refused_at_ms,
            "refused_events": self._refused_events,
            "dropped_events": self._dropped_events,
            "declined_events": self._declined_events,
            "duplicate_events": self._duplicate_events,
            "unconfirmed_events": self._unconfirmed_events,
            "queued_events": self._queue.qsize(),
            "retained_events": self._retained_events,
            "unreadable_responses": self._unreadable_responses,
            "nonconformant_responses": self._nonconformant_responses,
        }

    async def handle_event(self, event: OriEvent) -> None:
        """Queue one event without blocking EventBus delivery."""
        if event.event_type != "sensor.reading" or event.reading is None:
            return
        if self.export_suspended:
            self._refused_events += 1
            return
        if self._in_memory_events() >= self._config.max_queue_size:
            self._drop_new(event.event_id)
            return
        try:
            self._queue.put_nowait(_serialize_event(event))
        except asyncio.QueueFull:
            self._drop_new(event.event_id)

    def _in_memory_events(self) -> int:
        """Events this exporter is holding: queued, retained, and in flight.

        The batch being posted is counted because it is still held in memory and
        will be retained if the post fails. Leaving it out made the real ceiling
        `max_queue_size + batch_size`, which is neither the bound this file
        documents nor the one a deployment set.
        """
        return self._queue.qsize() + self._retained_events + self._in_flight_events

    def _drop_new(self, event_id: str) -> None:
        """Overflow discards the newest telemetry, per the contract.

        The newest is dropped rather than the oldest retained batch because a
        retained batch is already a delivery the receiver has not confirmed, and
        discarding it would lose a reading that may be the only record of an
        interval.
        """
        self._dropped_events += 1
        logger.warning(
            "[telemetry-export] in-memory telemetry is full; dropped event_id=%s "
            "queued=%d retained=%d total_dropped=%d",
            event_id,
            self._queue.qsize(),
            self._retained_events,
            self._dropped_events,
        )

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        if not _HTTPX_AVAILABLE or _httpx is None:
            logger.warning(
                "[telemetry-export] httpx is unavailable; telemetry export disabled"
            )
            return

        logger.info(
            "[telemetry-export] enabled endpoint=%s batch_size=%d flush_interval=%.1fs",
            self._config.endpoint,
            self._config.batch_size,
            self._config.flush_interval_s,
        )
        while not shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    shutdown_event.wait(),
                    timeout=self._config.flush_interval_s,
                )
                break
            except asyncio.TimeoutError:
                pass
            try:
                await self.flush_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("[telemetry-export] flush loop failed")

        try:
            await self.flush_once()
        except Exception:
            logger.exception("[telemetry-export] final flush failed")

    async def flush_once(self) -> int:
        """Send what is pending. Returns the number of events the receiver holds.

        "Exported" means stored. An event the receiver declined is counted under
        `declined_events` and never included here, and a batch whose answer could
        not be read counts as nothing sent rather than as a delivery.
        """
        api_key = os.environ.get(self._config.api_key_env, "").strip()
        if self._refusal_status is not None:
            if api_key and not self._credential_matches_refusal(api_key):
                self._resume_after_credential_change()
            else:
                self._discard_queued_while_suspended()
                return 0

        pending = self._take_pending()
        if not pending:
            return 0

        if not api_key:
            logger.warning(
                "[telemetry-export] configured API key environment variable is not set; "
                "telemetry batches retained in memory"
            )
            self._in_flight_events = 0
            self._retain(pending)
            return 0

        delivered = 0
        resolved = 0
        try:
            for index, batch in enumerate(pending):
                verdict = await self._send(batch, api_key)
                self._in_flight_events -= len(batch.events)
                resolved = index + 1
                if verdict is None:
                    continue

                if verdict.outcome is DeliveryOutcome.SUSPEND:
                    # The verdict counts this batch; the rest are refused without
                    # being attempted, because the credential they would present
                    # is the one that was refused.
                    refused = verdict.refused_events + sum(
                        len(item.events) for item in pending[index + 1 :]
                    )
                    resolved = len(pending)
                    self._suspend_on_terminal_refusal(verdict, api_key, refused)
                    return delivered

                if verdict.outcome is DeliveryOutcome.RETAIN:
                    if verdict.receiver_answered:
                        batch.unconfirmed_attempts += 1
                        if batch.unconfirmed_attempts >= MAX_UNCONFIRMED_ATTEMPTS:
                            # The receiver's own answer, repeated, does not account
                            # for this batch and will not start to. Abandoning it is
                            # what lets newer readings through; against a receiver
                            # still keying batches on `sequence` it bounds the loss a
                            # restart causes to what that receiver discards anyway,
                            # and counts it, instead of making it permanent.
                            self._unconfirmed_events += len(batch.events)
                            logger.error(
                                "[telemetry-export] batch sequence=%d abandoned after %d "
                                "answers that did not confirm it (%s); "
                                "unconfirmed_events=%d",
                                batch.sequence,
                                batch.unconfirmed_attempts,
                                verdict.reason,
                                self._unconfirmed_events,
                            )
                            continue
                    logger.warning(
                        "[telemetry-export] batch sequence=%d not confirmed (%s); "
                        "retained in memory",
                        batch.sequence,
                        verdict.reason,
                    )
                    # Stop here rather than trying the rest. Retained batches go
                    # ahead of newer ones in the order first attempted, and sending
                    # a later batch now would break that order for no gain against
                    # an endpoint that has just failed.
                    self._in_flight_events = 0
                    self._retain(pending[index:])
                    resolved = len(pending)
                    return delivered

                self._duplicate_events += verdict.duplicate_events
                if verdict.declined_events:
                    self._declined_events += verdict.declined_events
                    logger.warning(
                        "[telemetry-export] receiver declined %d of %d events in "
                        "sequence=%d; they are not retried. event_ids=%s",
                        verdict.declined_events,
                        len(batch.events),
                        batch.sequence,
                        ",".join(verdict.declined_event_ids),
                    )
                if verdict.nonconformant_body:
                    self._nonconformant_responses += 1
                    logger.warning(
                        "[telemetry-export] receiver answered sequence=%d without every "
                        "required response member; each absent member read as zero",
                        batch.sequence,
                    )
                delivered += len(batch.events) - verdict.declined_events
        finally:
            # Whatever ends the loop -- including cancellation at shutdown -- no
            # batch stays counted as in flight, and one that was drained and not
            # resolved is held rather than lost from every counter.
            self._in_flight_events = 0
            if resolved < len(pending):
                self._retain(pending[resolved:])

        return delivered

    def _take_pending(self) -> list[_PendingBatch]:
        """Retained batches oldest first, then at most one newly formed batch."""
        pending = list(self._retained)
        self._retained.clear()
        self._retained_events = 0

        events = self._drain_batch()
        if events:
            self._sequence += 1
            pending.append(_PendingBatch(sequence=self._sequence, events=events))
        self._in_flight_events = sum(len(batch.events) for batch in pending)
        return pending

    def _retain(self, batches: list[_PendingBatch]) -> None:
        """Hold batches for a later attempt, oldest first, within the bound."""
        for batch in reversed(batches):
            self._retained.appendleft(batch)
            self._retained_events += len(batch.events)

        # Retention shares the deployment's bound with the queue. When the two
        # together exceed it the *newest* retained batch goes, which is the same
        # priority `_drop_new` applies to a new reading: a retained batch is
        # already a delivery the receiver has not confirmed, and the oldest of
        # them records the start of the outage an operator is trying to explain.
        # Dropping from the other end kept the newest and discarded exactly
        # that.
        while self._retained and self._in_memory_events() > self._config.max_queue_size:
            stale = self._retained.pop()
            self._retained_events -= len(stale.events)
            self._dropped_events += len(stale.events)
            logger.warning(
                "[telemetry-export] in-memory telemetry is full; dropped retained "
                "batch sequence=%d events=%d total_dropped=%d",
                stale.sequence,
                len(stale.events),
                self._dropped_events,
            )

    async def _send(self, batch: _PendingBatch, api_key: str) -> DeliveryVerdict | None:
        """Post one batch and read the answer. Never raises for a send failure.

        Returns None when this exporter cannot send the batch at all, which is
        its own loss rather than anything the receiver said: the batch is
        already dropped and counted by the time None comes back.
        """
        try:
            body = self._canonical_body(batch)
        except TelemetryCanonicalizationError as exc:
            # A batch that cannot be represented will not become representable
            # on a later attempt, so retrying it is a loop with no exit. It is
            # dropped and counted as this exporter's own loss.
            self._dropped_events += len(batch.events)
            logger.error(
                "[telemetry-export] batch sequence=%d cannot be canonicalised and is "
                "discarded: %s. total_dropped=%d",
                batch.sequence,
                exc,
                self._dropped_events,
            )
            return None

        timestamp_ms = str(now_ms())
        signature = telemetry_hmac_sha256(api_key, timestamp_ms, body)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            # No coding is accepted, and none is decoded below: the size ceiling
            # then bounds the bytes that actually arrive.
            "Accept-Encoding": "identity",
            "X-Ori-Device-Id": self._device_id,
            "X-Ori-Timestamp-Ms": timestamp_ms,
            "X-Ori-Signature": f"v1={signature}",
        }
        timeout_s = self._config.timeout_ms / 1000.0
        try:
            async with _httpx.AsyncClient(timeout=timeout_s) as client:
                async with client.stream(
                    "POST",
                    self._config.endpoint,
                    content=body,
                    headers=headers,
                ) as response:
                    status = response.status_code
                    fields = _raw_header_fields(response.headers)
                    if body_is_wanted(fields):
                        answer = await _read_bounded(response)
                    else:
                        logger.warning(
                            "[telemetry-export] response body not read: its header "
                            "section is not readable alike, it is content-coded, or "
                            "it declares more than the %d-byte ceiling; batch retained",
                            MAX_RESPONSE_BYTES,
                        )
                        answer = None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("[telemetry-export] POST failed: %s", exc)
            return read_batch_response(status=None, batch_events=len(batch.events))

        return self._verdict(status, fields, answer, len(batch.events))

    def _canonical_body(self, batch: _PendingBatch) -> bytes:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "device_id": self._device_id,
            "sequence": batch.sequence,
            "sent_at_ms": now_ms(),
            "events": batch.events,
        }
        return canonical_telemetry_bytes(payload)

    def _verdict(
        self,
        status: object,
        fields: list[tuple[bytes, bytes]],
        answer: bytes | None,
        batch_events: int,
    ) -> DeliveryVerdict:
        """Read the answer, and count one that could not be read."""
        verdict = read_answer(
            status=status if isinstance(status, int) else None,
            fields=fields,
            body=answer,
            batch_events=batch_events,
        )
        # Counted from the verdict's own flag rather than from whether the status
        # was a success. A 2xx that was read and reported counts that were not
        # summable is not an unreadable answer.
        if verdict.body_unreadable:
            self._unreadable_responses += 1
        return verdict

    def _credential_matches_refusal(self, api_key: str) -> bool:
        """Whether this is the credential the endpoint refused.

        The refused credential is held as itself and compared in constant time.
        Deriving a tag from it would be the weaker choice here, not the safer
        one: the process already holds the credential in the environment it
        reads every flush and in the header of every request, so a comparison
        copy adds no exposure, while a digest of a credential invites being
        treated -- and scanned -- as a password hash, which this is not.

        It is never serialised and never enters `status_snapshot`, and it is
        released as soon as a different credential resumes export, so a rotated
        credential is not retained past the rotation.
        """
        recorded = self._refused_credential
        if recorded is None:
            return False
        # Compared as bytes. `compare_digest` on `str` raises for any non-ASCII
        # character, and this is the line a credential rotation runs: a device
        # whose key carried one would raise out of every flush, be logged as
        # "flush loop failed", and never resume -- with the rotation meant to
        # recover it as the thing that could not run.
        return hmac.compare_digest(recorded.encode("utf-8"), api_key.encode("utf-8"))

    def _suspend_on_terminal_refusal(
        self,
        verdict: DeliveryVerdict,
        api_key: str,
        batch_size: int,
    ) -> None:
        # The verdict carries which recorded refusal was satisfied, and both
        # values came from the enumeration rather than from the response, so
        # nothing a response said reaches the health report. Recovering the
        # status by taking an arbitrary element of the set was correct only
        # while the set held one entry.
        status = verdict.refusal_status
        if status is None or status not in TERMINAL_REFUSAL_STATUSES:
            status = next(iter(TERMINAL_REFUSAL_STATUSES))
        self._refusal_status = status
        self._refusal_detail = TERMINAL_REFUSALS[status]
        self._refused_credential = api_key
        self._refused_at_ms = now_ms()
        self._refused_events += batch_size
        logger.error(
            "[telemetry-export] endpoint refused this device with HTTP %d (%s); "
            "telemetry export suspended until the credential changes or the "
            "runtime restarts. Actions and safety are unaffected. "
            "refused_events=%d",
            status,
            self._refusal_detail or "no detail",
            self._refused_events,
        )
        self._discard_queued_while_suspended()

    def _resume_after_credential_change(self) -> None:
        logger.info(
            "[telemetry-export] telemetry credential changed after an HTTP %s "
            "refusal; resuming export",
            self._refusal_status,
        )
        self._refusal_status = None
        self._refusal_detail = None
        self._refused_credential = None
        self._refused_at_ms = None

    def _discard_queued_while_suspended(self) -> None:
        """Nothing survives a suspension, retained batches included.

        A retained batch would otherwise sit through the suspension and be sent
        the moment a new credential resumed export, delivering readings under a
        credential that never sent them and past the interval they describe.
        Both paths count as refused rather than dropped, because the reason is
        the endpoint's refusal and not this exporter's own capacity.
        """
        while self._retained:
            batch = self._retained.popleft()
            self._retained_events -= len(batch.events)
            self._refused_events += len(batch.events)
        while True:
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            self._refused_events += 1

    def _drain_batch(self) -> list[dict[str, Any]]:
        batch: list[dict[str, Any]] = []
        while len(batch) < self._config.batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch


async def _read_bounded(response: Any) -> bytes | None:
    """The response body, or None when it exceeds the ceiling.

    Read incrementally and abandoned one chunk past the ceiling, so the bound
    holds on this process's memory and not only on what is parsed. This process
    holds the reasoning loop and the action dispatcher, and a receiver -- or a
    captive portal in front of one -- answering with megabytes must not be able
    to grow it. A coded body and a declared length past the ceiling are refused
    before this is called. An oversized body is unreadable, never a truncated
    prefix parsed as if it were the answer.
    """
    received = bytearray()
    if getattr(response, "is_stream_consumed", False):
        # A response httpx built in memory is read when it is constructed and
        # cannot be streamed again. Its bytes are already held, so there is
        # nothing left to bound, and a coded body was refused above.
        chunks: Any = _single_chunk(response.content)
    else:
        # Raw bytes, never decoded: a decoding iterator inflates a whole
        # compressed chunk before this loop can count it.
        chunks = response.aiter_raw()
    async for chunk in chunks:
        received += chunk
        if len(received) > MAX_RESPONSE_BYTES:
            logger.warning(
                "[telemetry-export] response body passed the %d-byte ceiling; "
                "batch retained",
                MAX_RESPONSE_BYTES,
            )
            return None
    return bytes(received)


def _raw_header_fields(headers: Any) -> list[tuple[bytes, bytes]]:
    """Every header field as the parser produced it, names and values as bytes.

    httpx keeps h11's parsed fields in `raw`. A test double's plain mapping is
    encoded as latin-1, which is how HTTP carries field bytes.
    """
    raw = getattr(headers, "raw", None)
    if raw is not None:
        return [(bytes(name), bytes(value)) for name, value in raw]
    return [
        (str(name).encode("latin-1"), str(value).encode("latin-1"))
        for name, value in headers.items()
    ]


async def _single_chunk(content: bytes) -> AsyncIterator[bytes]:
    yield content


def _serialize_event(event: OriEvent) -> dict[str, Any]:
    reading = event.reading
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "device_id": event.device_id,
        "sensor_id": event.sensor_id,
        "timestamp": event.timestamp,
        "source": event.source,
        "fingerprint": event.fingerprint,
        "context": _json_safe(event.context),
        "reading": _serialize_reading(reading) if reading is not None else None,
    }


def _serialize_reading(reading: SensorReading) -> dict[str, Any]:
    data = asdict(reading)
    data.pop("raw", None)
    # _json_safe is Any-in/Any-out by design; a dict in yields a dict out.
    safe: dict[str, Any] = _json_safe(data)
    return safe


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, dict):
            return {str(k): _json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_json_safe(item) for item in value]
        return str(value)
