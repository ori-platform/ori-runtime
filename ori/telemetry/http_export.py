# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""HTTP telemetry export for phone and lightweight provisioned deployments."""

import asyncio
import hmac
import json
import logging
import os
from dataclasses import asdict
from typing import Any

from ori.config import TelemetryExportConfig
from ori.network.events import OriEvent, SensorReading
from ori.telemetry.canonical import canonical_telemetry_bytes, telemetry_hmac_sha256
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

# The refusals the endpoint repeats for as long as this credential is
# presented, as the (status, detail) pairs the contract states them in.
# 403 alone: 401 is re-issuable, and 415/422 describe the request rather than
# the credential, so retrying them keeps a serialisation bug visible instead of
# silencing export on one. 404 and 410 are retried for the same reason -- the
# contract records no case for them, so nothing here may claim to know one.
# The detail is half the identity: a status alone is what any intermediary can
# produce. tests/vectors/telemetry_refusals pins both halves.
TERMINAL_REFUSALS = {403: "device is suspended"}
TERMINAL_REFUSAL_STATUSES = frozenset(TERMINAL_REFUSALS)


class TelemetryExportRefusedError(Exception):
    """A refusal that the endpoint will repeat for the credential in use."""

    def __init__(self, status: int, detail: str | None) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status
        self.detail = detail


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
        self._sequence = 0
        self._dropped_events = 0
        self._refused_events = 0
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
        }

    async def handle_event(self, event: OriEvent) -> None:
        """Queue one event without blocking EventBus delivery."""
        if event.event_type != "sensor.reading" or event.reading is None:
            return
        if self.export_suspended:
            self._refused_events += 1
            return
        try:
            self._queue.put_nowait(_serialize_event(event))
        except asyncio.QueueFull:
            self._dropped_events += 1
            logger.warning(
                "[telemetry-export] queue full; dropped event_id=%s total_dropped=%d",
                event.event_id,
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
        api_key = os.environ.get(self._config.api_key_env, "").strip()
        if self._refusal_status is not None:
            if api_key and not self._credential_matches_refusal(api_key):
                self._resume_after_credential_change()
            else:
                self._discard_queued_while_suspended()
                return 0

        batch = self._drain_batch()
        if not batch:
            return 0

        if not api_key:
            logger.warning(
                "[telemetry-export] configured API key environment variable is not set; "
                "telemetry batch retained in memory"
            )
            self._requeue(batch)
            return 0

        try:
            await self._post_batch(batch, api_key)
        except TelemetryExportRefusedError as exc:
            self._suspend_on_terminal_refusal(exc, api_key, len(batch))
            return 0
        except Exception as exc:
            logger.warning(
                "[telemetry-export] POST failed; retaining batch in memory: %s",
                exc,
            )
            self._requeue(batch)
            return 0
        return len(batch)

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
        return hmac.compare_digest(recorded, api_key)

    def _suspend_on_terminal_refusal(
        self,
        refusal: TelemetryExportRefusedError,
        api_key: str,
        batch_size: int,
    ) -> None:
        self._refusal_status = refusal.status
        self._refusal_detail = refusal.detail
        self._refused_credential = api_key
        self._refused_at_ms = now_ms()
        self._refused_events += batch_size
        logger.error(
            "[telemetry-export] endpoint refused this device with HTTP %d (%s); "
            "telemetry export suspended until the credential changes or the "
            "runtime restarts. Actions and safety are unaffected. "
            "refused_events=%d",
            refusal.status,
            refusal.detail or "no detail",
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

    def _requeue(self, batch: list[dict[str, Any]]) -> None:
        for item in batch:
            try:
                self._queue.put_nowait(item)
            except asyncio.QueueFull:
                self._dropped_events += 1
                logger.warning(
                    "[telemetry-export] queue full while retaining failed batch; "
                    "dropped telemetry item total_dropped=%d",
                    self._dropped_events,
                )

    async def _post_batch(self, batch: list[dict[str, Any]], api_key: str) -> None:
        self._sequence += 1
        payload = {
            "schema_version": SCHEMA_VERSION,
            "device_id": self._device_id,
            "sequence": self._sequence,
            "sent_at_ms": now_ms(),
            "events": batch,
        }
        body = canonical_telemetry_bytes(payload)
        timestamp_ms = str(now_ms())
        signature = telemetry_hmac_sha256(api_key, timestamp_ms, body)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "X-Ori-Device-Id": self._device_id,
            "X-Ori-Timestamp-Ms": timestamp_ms,
            "X-Ori-Signature": f"v1={signature}",
        }
        timeout_s = self._config.timeout_ms / 1000.0
        async with _httpx.AsyncClient(timeout=timeout_s) as client:
            response = await client.post(
                self._config.endpoint,
                content=body,
                headers=headers,
            )
            status = getattr(response, "status_code", None)
            if isinstance(status, int) and _is_terminal_refusal(status, response):
                raise TelemetryExportRefusedError(status, TERMINAL_REFUSALS[status])
            raise_for_status = getattr(response, "raise_for_status", None)
            if callable(raise_for_status):
                raise_for_status()


def _is_terminal_refusal(status: int, response: Any) -> bool:
    """Whether this response is the endpoint refusing this device for good.

    Suspension is irreversible for the process, so it needs positive evidence
    that the endpoint answered, not merely that nothing contradicted it. Any
    intermediary can return a bare 403 -- a proxy or WAF does so without a
    challenge and with an HTML body -- and an absent header proves nothing
    about origin.

    So every recorded property of the terminal case must hold: the status, no
    authentication challenge, a JSON media type, and the exact `detail` the
    contract records for that status. A proxy answering `{"detail": "access
    denied"}` satisfies every other property, so requiring only that a detail
    is present leaves the class open. Anything else is retried, because
    retrying a genuine suspension costs bandwidth while suspending on an
    intermediary costs the telemetry outright.

    The comparison is exact, so an upstream rewording fails toward retry
    rather than toward suspension, and `contract_version` is what catches the
    meaning moving.

    This remains a content check, not proof of origin: an intermediary that
    reproduced the recorded body would still pass. Only an authenticated
    response could settle that, which needs a contract the endpoint does not
    yet offer.
    """
    if status not in TERMINAL_REFUSAL_STATUSES:
        return False
    headers = getattr(response, "headers", None)
    if headers is None:
        return False
    try:
        challenge = headers.get("WWW-Authenticate")
        content_type = headers.get("Content-Type") or ""
    except Exception:
        return False
    if challenge:
        return False
    media_type = str(content_type).split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        return False
    return _refusal_detail(response) == TERMINAL_REFUSALS[status]


def _refusal_detail(response: Any) -> str | None:
    """The response's `detail` string, or None when the body is not readable.

    Only ever compared against a recorded value and discarded. What is retained
    on a suspension is that recorded value, so no response text reaches the
    health report.
    """
    try:
        body = response.json()
    except Exception:
        return None
    if isinstance(body, dict):
        detail = body.get("detail")
        if isinstance(detail, str):
            return detail
    return None


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
