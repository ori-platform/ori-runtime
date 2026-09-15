# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest

from ori.config import TelemetryExportConfig
from ori.network.events import OriEvent, SensorReading
from ori.telemetry import http_export
from ori.telemetry.canonical import (
    TelemetryCanonicalizationError,
    canonical_telemetry_bytes,
    telemetry_hmac_sha256,
)
from ori.telemetry.http_export import HttpTelemetryExporter

GOLDEN_BODY = (
    '{"device_id":"phone-gateway-ikeja-01","events":[{"context":{"location":"Ìkẹjà"},'
    '"device_id":"phone-gateway-ikeja-01","event_id":"00000000-0000-4000-8000-000000000001",'
    '"event_type":"sensor.reading","fingerprint":"","reading":{"metadata":{"label":"Mains – east"},'
    '"quality":1.0,"sensor_id":"phone-main-power","sensor_type":"usb_power",'
    '"timestamp":1719000000000,"unit":"watt","value":1240.5},"sensor_id":"phone-main-power",'
    '"source":"usb_serial","timestamp":1719000000000}],"schema_version":"runtime.telemetry.v1",'
    '"sent_at_ms":1719000000000,"sequence":1}'
).encode("utf-8")


def _event(value: float = 1250.0) -> OriEvent:
    return OriEvent.from_reading(
        SensorReading(
            sensor_id="phone-main-power",
            sensor_type="usb_power",
            value=value,
            unit="watt",
            timestamp=1_000,
            quality=0.99,
            metadata={"source": "usb_serial", "site": {"name": b"ikeja"}},
            raw=b"\x01\x02",
        ),
        device_id="phone-01",
    )


def _config(**overrides) -> TelemetryExportConfig:
    values = {
        "enabled": True,
        "endpoint": "https://api.example.test/runtime/telemetry",
        "api_key_env": "ORI_DEVICE_API_KEY",
        "flush_interval_s": 30.0,
        "batch_size": 2,
        "timeout_ms": 3000,
        "max_queue_size": 3,
    }
    values.update(overrides)
    return TelemetryExportConfig(**values)


class _FakeResponse:
    """What a client returns: a status, headers and bytes, streamed in chunks."""

    def __init__(self, status_code=200, headers=None, content=b"", chunk=65536):
        self.status_code = status_code
        self.headers = headers if headers is not None else {}
        self.content = content
        self.chunk = chunk
        self.bytes_read = 0

    async def aiter_raw(self):
        for start in range(0, len(self.content), self.chunk):
            piece = self.content[start : start + self.chunk]
            self.bytes_read += len(piece)
            yield piece


class _Streamed:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return None


def _accepted(events: int, duplicate: int = 0, rejected=None) -> _FakeResponse:
    """A conformant receiver's answer to a batch of `events` events."""
    rejected = rejected or []
    status = "accepted"
    if rejected:
        status = "partial"
    elif duplicate and not events - duplicate:
        status = "duplicate"
    return _FakeResponse(
        200,
        {"Content-Type": "application/json"},
        json.dumps(
            {
                "status": status,
                "accepted_events": events - duplicate - len(rejected),
                "duplicate_events": duplicate,
                "rejected_events": rejected,
            }
        ).encode(),
    )


class _FakeAsyncClient:
    requests: list[dict] = []
    fail: bool = False
    # Answers popped in order; exhausting the list falls back to accepting
    # whatever was sent, so a test only lists the answers it cares about.
    responses: list = []

    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def stream(self, method, endpoint, *, content, headers):
        assert method == "POST"
        self.requests.append(
            {
                "endpoint": endpoint,
                "content": content,
                "headers": headers,
                "timeout": self.timeout,
            }
        )
        if self.fail:
            raise RuntimeError("network down")
        if _FakeAsyncClient.responses:
            return _Streamed(_FakeAsyncClient.responses.pop(0))
        sent = len(json.loads(content)["events"])
        return _Streamed(_accepted(sent))


@pytest.mark.asyncio
async def test_handle_event_queues_sensor_reading_without_raw_bytes():
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())

    await exporter.handle_event(_event())

    queued = exporter._drain_batch()
    assert len(queued) == 1
    assert queued[0]["event_type"] == "sensor.reading"
    assert queued[0]["reading"]["sensor_type"] == "usb_power"
    assert "raw" not in queued[0]["reading"]
    assert queued[0]["reading"]["metadata"]["site"]["name"] == "b'ikeja'"


@pytest.mark.asyncio
async def test_handle_event_drops_when_queue_is_full():
    exporter = HttpTelemetryExporter(
        device_id="phone-01",
        config=_config(batch_size=1, max_queue_size=1),
    )

    await exporter.handle_event(_event(1.0))
    await exporter.handle_event(_event(2.0))

    assert exporter.dropped_events == 1
    assert len(exporter._drain_batch()) == 1


@pytest.mark.asyncio
async def test_flush_once_posts_hmac_signed_batch(monkeypatch):
    monkeypatch.setenv("ORI_DEVICE_API_KEY", "device-secret")
    _FakeAsyncClient.requests = []
    _FakeAsyncClient.fail = False
    monkeypatch.setattr(
        http_export,
        "_httpx",
        SimpleNamespace(AsyncClient=_FakeAsyncClient),
    )
    monkeypatch.setattr(http_export, "_HTTPX_AVAILABLE", True)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    sent = await exporter.flush_once()

    assert sent == 1
    request = _FakeAsyncClient.requests[0]
    assert request["endpoint"] == "https://api.example.test/runtime/telemetry"
    assert request["timeout"] == 3.0
    headers = request["headers"]
    assert headers["Authorization"] == "Bearer device-secret"
    assert headers["X-Ori-Device-Id"] == "phone-01"
    body = request["content"]
    payload = json.loads(body)
    assert payload["schema_version"] == "runtime.telemetry.v1"
    assert payload["device_id"] == "phone-01"
    signed = headers["X-Ori-Timestamp-Ms"].encode("utf-8") + b"." + body
    expected = hmac.new(
        b"device-secret",
        signed,
        hashlib.sha256,
    ).hexdigest()
    assert headers["X-Ori-Signature"] == f"v1={expected}"


def test_runtime_telemetry_golden_body_and_hmac() -> None:
    payload = json.loads(GOLDEN_BODY)

    assert canonical_telemetry_bytes(payload) == GOLDEN_BODY
    assert hashlib.sha256(GOLDEN_BODY).hexdigest() == (
        "51e7a268d28c96f7ba516593b7d4ca160848ff641888ce1b3b513f2bbf2370ea"
    )
    assert (
        telemetry_hmac_sha256(
            "test-runtime-telemetry-key", 1_719_000_000_123, GOLDEN_BODY
        )
        == "5ed66b6fc38a5d68e8c0c16bf18ade62968549432fb52baeb8b56625927dba79"
    )
    assert "Ìkẹjà".encode("utf-8") in GOLDEN_BODY
    assert b"\\u" not in GOLDEN_BODY


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), 1e-5])
def test_runtime_telemetry_rejects_noncanonical_numbers(value: float) -> None:
    with pytest.raises(TelemetryCanonicalizationError):
        canonical_telemetry_bytes({"value": value})


@pytest.mark.asyncio
async def test_flush_once_requeues_when_post_fails(monkeypatch):
    monkeypatch.setenv("ORI_DEVICE_API_KEY", "device-secret")
    _FakeAsyncClient.requests = []
    _FakeAsyncClient.fail = True
    monkeypatch.setattr(
        http_export,
        "_httpx",
        SimpleNamespace(AsyncClient=_FakeAsyncClient),
    )
    monkeypatch.setattr(http_export, "_HTTPX_AVAILABLE", True)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    sent = await exporter.flush_once()

    assert sent == 0
    assert exporter.retained_events == 1
    assert exporter.dropped_events == 0


@pytest.mark.asyncio
async def test_flush_once_requeues_when_api_key_missing(monkeypatch, caplog):
    monkeypatch.delenv("ORI_DEVICE_API_KEY", raising=False)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    sent = await exporter.flush_once()

    assert sent == 0
    assert exporter.retained_events == 1
    assert "ORI_DEVICE_API_KEY" not in caplog.text
    assert "configured API key environment variable is not set" in caplog.text


@pytest.mark.asyncio
async def test_serve_until_noops_when_httpx_missing(monkeypatch):
    monkeypatch.setattr(http_export, "_httpx", None)
    monkeypatch.setattr(http_export, "_HTTPX_AVAILABLE", False)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    shutdown = asyncio.Event()

    await exporter.serve_until(shutdown)

    assert exporter.dropped_events == 0


def _install(monkeypatch, responses=None, fail=False):
    _FakeAsyncClient.requests = []
    _FakeAsyncClient.fail = fail
    _FakeAsyncClient.responses = list(responses or [])
    monkeypatch.setenv("ORI_DEVICE_API_KEY", "device-secret")
    monkeypatch.setattr(
        http_export, "_httpx", SimpleNamespace(AsyncClient=_FakeAsyncClient)
    )
    monkeypatch.setattr(http_export, "_HTTPX_AVAILABLE", True)


def _sequences() -> list[int]:
    return [json.loads(r["content"])["sequence"] for r in _FakeAsyncClient.requests]


def _event_ids(request) -> list[str]:
    return [e["event_id"] for e in json.loads(request["content"])["events"]]


@pytest.mark.asyncio
async def test_a_retried_batch_keeps_its_sequence_and_its_events(monkeypatch):
    """The defect: a retry that merged newer readings in under a new sequence.

    A batch that was not confirmed is re-sent as the same batch. Were the events
    pushed back onto the queue instead, the next drain would carry the reading
    enqueued during the failure and the receiver would key the whole thing on a
    sequence it had never seen.
    """
    _install(monkeypatch, responses=[_FakeResponse(503, {}, b"unavailable")])
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event(100.0))

    assert await exporter.flush_once() == 0
    first_ids = _event_ids(_FakeAsyncClient.requests[0])

    # A reading taken while the batch was undelivered.
    await exporter.handle_event(_event(200.0))
    # Both go out: the retained batch first, then the newer reading as its own.
    assert await exporter.flush_once() == 2

    assert _sequences() == [1, 1, 2], "the retry reused its own sequence"
    assert _event_ids(_FakeAsyncClient.requests[1]) == first_ids, (
        "the retry carried the same events, not the newer reading"
    )
    assert _event_ids(_FakeAsyncClient.requests[2]) != first_ids, (
        "the newer reading travelled under its own sequence, not merged in"
    )


@pytest.mark.asyncio
async def test_retained_batches_go_ahead_of_newer_ones_in_attempt_order(monkeypatch):
    """Order first attempted, so sequence arrives monotonically within a run."""
    _install(
        monkeypatch,
        responses=[
            _FakeResponse(503, {}, b"x"),  # sequence 1 fails
            _FakeResponse(503, {}, b"x"),  # sequence 1 fails again
        ],
    )
    exporter = HttpTelemetryExporter(
        device_id="phone-01", config=_config(batch_size=1, max_queue_size=10)
    )
    await exporter.handle_event(_event(1.0))
    await exporter.flush_once()
    await exporter.handle_event(_event(2.0))
    await exporter.flush_once()

    # Two batches are now outstanding; the endpoint starts accepting.
    await exporter.flush_once()

    assert _sequences() == [1, 1, 1, 2], (
        "the older batch was re-sent before the newer one"
    )


@pytest.mark.asyncio
async def test_a_duplicate_answer_is_delivered_and_not_retried(monkeypatch):
    """Every event already held. Nothing stored, nothing lost, nothing retried."""
    _install(monkeypatch, responses=[_accepted(1, duplicate=1)])
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event())

    assert await exporter.flush_once() == 1
    assert exporter.retained_events == 0
    assert exporter.declined_events == 0
    assert await exporter.flush_once() == 0
    assert len(_FakeAsyncClient.requests) == 1


@pytest.mark.asyncio
async def test_declined_events_are_counted_and_never_reported_as_exported(monkeypatch):
    """A declined event is permanently refused: counted, discarded, not retried."""
    _install(monkeypatch, responses=None)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=2))
    await exporter.handle_event(_event(1.0))
    await exporter.handle_event(_event(2.0))

    # The answer names one of the two events the exporter actually sent.
    _FakeAsyncClient.responses = []
    sent_ids: list[str] = []

    def stream(self, method, endpoint, *, content, headers):
        _FakeAsyncClient.requests.append({"endpoint": endpoint, "content": content})
        ids = [e["event_id"] for e in json.loads(content)["events"]]
        sent_ids.extend(ids)
        return _Streamed(
            _accepted(
                len(ids),
                rejected=[{"event_id": ids[0], "reason": "sensor_not_registered"}],
            )
        )

    monkeypatch.setattr(_FakeAsyncClient, "stream", stream)

    delivered = await exporter.flush_once()

    assert delivered == 1, "the declined event is not counted as exported"
    assert exporter.declined_events == 1
    assert exporter.retained_events == 0, "a declined event is not retried"
    assert exporter.status_snapshot()["declined_events"] == 1


@pytest.mark.asyncio
async def test_an_unreadable_success_is_retained_rather_than_assumed_delivered(
    monkeypatch,
):
    """A 200 whose body says nothing is the shape that hid the original loss."""
    _install(monkeypatch, responses=[_FakeResponse(200, {}, b"OK")])
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event())

    assert await exporter.flush_once() == 0
    assert exporter.retained_events == 1
    assert exporter.status_snapshot()["unreadable_responses"] == 1


@pytest.mark.asyncio
async def test_counts_that_do_not_sum_to_the_batch_are_not_a_delivery(monkeypatch):
    """The invariant is the whole value of the response body."""
    body = json.dumps(
        {
            "status": "accepted",
            "accepted_events": 1,
            "duplicate_events": 0,
            "rejected_events": [],
        }
    ).encode()
    _install(
        monkeypatch,
        responses=[_FakeResponse(200, {"Content-Type": "application/json"}, body)],
    )
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=2))
    await exporter.handle_event(_event(1.0))
    await exporter.handle_event(_event(2.0))

    assert await exporter.flush_once() == 0
    assert exporter.retained_events == 2


@pytest.mark.asyncio
async def test_a_body_missing_tolerated_members_delivers_and_is_reported(monkeypatch):
    """A receiver mid-migration: delivered, but recorded as non-conformant."""
    body = json.dumps({"status": "accepted", "accepted_events": 1}).encode()
    _install(
        monkeypatch,
        responses=[_FakeResponse(200, {"Content-Type": "application/json"}, body)],
    )
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event())

    assert await exporter.flush_once() == 1
    assert exporter.retained_events == 0
    assert exporter.status_snapshot()["nonconformant_responses"] == 1


@pytest.mark.asyncio
async def test_retention_and_the_queue_share_the_configured_bound(monkeypatch):
    """Held batches count against max_queue_size, so memory stays bounded.

    Without the shared bound a retained batch would be invisible to the queue's
    own limit and the exporter could hold twice what the deployment allowed.
    """
    _install(monkeypatch, responses=[_FakeResponse(503, {}, b"x")] * 8)
    exporter = HttpTelemetryExporter(
        device_id="phone-01", config=_config(batch_size=1, max_queue_size=2)
    )
    for value in (1.0, 2.0, 3.0, 4.0):
        await exporter.handle_event(_event(value))
        await exporter.flush_once()

    assert exporter.retained_events + exporter._queue.qsize() <= 2
    assert exporter.dropped_events > 0


@pytest.mark.asyncio
async def test_a_reading_is_refused_when_retained_batches_already_fill_the_bound(
    monkeypatch,
):
    """The shared bound, pinned at the enqueue point on its own.

    The queue's own `maxsize` refuses a put when the queue alone is full, so a
    test that only fills the queue passes whether or not retained batches are
    counted. Here the queue is empty and retention alone fills the bound, which
    is the one state where the shared check is the only thing that refuses.
    """
    _install(monkeypatch, responses=[_FakeResponse(503, {}, b"x")] * 4)
    exporter = HttpTelemetryExporter(
        device_id="phone-01", config=_config(batch_size=2, max_queue_size=2)
    )
    await exporter.handle_event(_event(1.0))
    await exporter.handle_event(_event(2.0))
    await exporter.flush_once()
    assert exporter.retained_events == 2
    assert exporter._queue.qsize() == 0

    await exporter.handle_event(_event(3.0))

    assert exporter._queue.qsize() == 0, "retention already filled the bound"
    assert exporter.dropped_events == 1


@pytest.mark.asyncio
async def test_a_suspension_discards_retained_batches_too(monkeypatch):
    """A retained batch must not outlive the suspension and post on a new key.

    Otherwise a credential change would deliver readings the refused credential
    had collected, under a key that never sent them and past the interval they
    describe.
    """
    refusal = _FakeResponse(
        403,
        {"Content-Type": "application/json"},
        b'{"detail":"device is suspended"}',
    )
    _install(monkeypatch, responses=[_FakeResponse(503, {}, b"x"), refusal])
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event(1.0))
    await exporter.flush_once()
    assert exporter.retained_events == 1

    await exporter.handle_event(_event(2.0))
    await exporter.flush_once()

    assert exporter.export_suspended is True
    assert exporter.retained_events == 0
    # Exact: the refused batch and the newer one behind it that was never
    # attempted. A lower bound on this counter asserts less than its name.
    assert exporter.refused_events == 2
    assert exporter.declined_events == 0, "a refusal is not a decline"


@pytest.mark.asyncio
async def test_a_batch_that_cannot_be_canonicalised_is_dropped_not_retried(monkeypatch):
    """An unrepresentable batch will not become representable, so retrying loops."""
    _install(monkeypatch)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event())

    def explode(_payload):
        raise TelemetryCanonicalizationError("float outside the agreement zone")

    monkeypatch.setattr(http_export, "canonical_telemetry_bytes", explode)

    # The return is the number of events the receiver holds, and a batch this
    # exporter destroyed is not one of them.
    assert await exporter.flush_once() == 0

    assert exporter.retained_events == 0
    assert exporter.dropped_events == 1
    assert _FakeAsyncClient.requests == [], "nothing was posted"


class _GatedResponse(_FakeResponse):
    """A response whose body does not arrive until the test releases it."""

    def __init__(self, gate, **kwargs):
        super().__init__(**kwargs)
        self.gate = gate

    async def aiter_raw(self):
        await self.gate.wait()
        async for piece in super().aiter_raw():
            yield piece


def _gated_accept(gate, events):
    accepted = _accepted(events)
    return _GatedResponse(
        gate,
        status_code=accepted.status_code,
        headers=accepted.headers,
        content=accepted.content,
    )


@pytest.mark.asyncio
async def test_a_batch_in_flight_counts_against_the_bound(monkeypatch):
    """While a batch is being posted it is still held, so it fills the bound.

    Without counting it the exporter holds max_queue_size plus a batch, which is
    neither the bound it documents nor the one the deployment set.
    """
    gate = asyncio.Event()
    _install(monkeypatch, responses=[_gated_accept(gate, 2)])
    exporter = HttpTelemetryExporter(
        device_id="phone-01", config=_config(batch_size=2, max_queue_size=2)
    )
    await exporter.handle_event(_event(1.0))
    await exporter.handle_event(_event(2.0))

    flush = asyncio.create_task(exporter.flush_once())
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    await exporter.handle_event(_event(3.0))
    assert exporter.dropped_events == 1, (
        "two readings were in flight and the bound is two"
    )

    gate.set()
    assert await flush == 2


@pytest.mark.asyncio
async def test_a_delivered_batch_stops_counting_against_the_bound(monkeypatch):
    """After a success nothing is left counted as in flight.

    Were it left, every reading until the next flush would be dropped whenever
    the batch size equals the bound.
    """
    _install(monkeypatch)
    exporter = HttpTelemetryExporter(
        device_id="phone-01", config=_config(batch_size=2, max_queue_size=2)
    )
    await exporter.handle_event(_event(1.0))
    await exporter.handle_event(_event(2.0))
    assert await exporter.flush_once() == 2

    await exporter.handle_event(_event(3.0))
    await exporter.handle_event(_event(4.0))

    assert exporter.dropped_events == 0
    assert exporter._queue.qsize() == 2


@pytest.mark.asyncio
async def test_a_cancelled_flush_retains_the_batch_and_releases_the_bound(monkeypatch):
    """Cancellation at shutdown neither loses the drained batch nor leaks it."""
    gate = asyncio.Event()
    _install(monkeypatch, responses=[_gated_accept(gate, 2)])
    exporter = HttpTelemetryExporter(
        device_id="phone-01", config=_config(batch_size=2, max_queue_size=4)
    )
    await exporter.handle_event(_event(1.0))
    await exporter.handle_event(_event(2.0))

    flush = asyncio.create_task(exporter.flush_once())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    flush.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(flush, timeout=5)

    assert exporter.retained_events == 2, "the drained batch is held, not lost"
    assert exporter._in_flight_events == 0
    await exporter.handle_event(_event(3.0))
    await exporter.handle_event(_event(4.0))
    assert exporter.dropped_events == 0, "the bound is released"


@pytest.mark.asyncio
async def test_a_response_body_past_the_ceiling_is_not_read_past_it(monkeypatch):
    """The ceiling bounds memory, not only parsing.

    The body is streamed and abandoned a chunk past the ceiling, and the answer
    is counted as unreadable with its batch retained.
    """
    huge = _FakeResponse(
        200, {"Content-Type": "application/json"}, b"x" * (4 * 1024 * 1024), chunk=4096
    )
    _install(monkeypatch, responses=[huge])
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event())

    assert await exporter.flush_once() == 0

    assert huge.bytes_read <= http_export.MAX_RESPONSE_BYTES + huge.chunk
    assert exporter.retained_events == 1
    assert exporter.status_snapshot()["unreadable_responses"] == 1


@pytest.mark.asyncio
async def test_a_declared_length_past_the_ceiling_is_refused_unread(monkeypatch):
    big = _FakeResponse(
        200,
        {"Content-Type": "application/json", "Content-Length": str(10 * 1024 * 1024)},
        b"x" * 1024,
    )
    _install(monkeypatch, responses=[big])
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event())

    assert await exporter.flush_once() == 0
    assert big.bytes_read == 0
    assert exporter.retained_events == 1


@pytest.mark.asyncio
async def test_a_readable_answer_that_does_not_sum_is_not_counted_unreadable(
    monkeypatch,
):
    """The unreadable counter means the answer could not be read, nothing else."""
    body = json.dumps(
        {
            "status": "accepted",
            "accepted_events": 0,
            "duplicate_events": 0,
            "rejected_events": [],
        }
    ).encode()
    _install(
        monkeypatch,
        responses=[_FakeResponse(200, {"Content-Type": "application/json"}, body)],
    )
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event())

    assert await exporter.flush_once() == 0
    assert exporter.retained_events == 1
    assert exporter.status_snapshot()["unreadable_responses"] == 0


@pytest.mark.asyncio
async def test_a_deeply_nested_answer_cannot_escape_the_flush(monkeypatch):
    """A body inside the size ceiling that would exhaust a recursive parser.

    It once raised out of the flush loop, dropping a drained batch from every
    counter and leaving it counted as in flight.
    """
    deep = b"[" * 30000 + b"]" * 30000
    _install(
        monkeypatch,
        responses=[_FakeResponse(200, {"Content-Type": "application/json"}, deep)],
    )
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=2))
    await exporter.handle_event(_event(1.0))
    await exporter.handle_event(_event(2.0))

    assert await exporter.flush_once() == 0

    assert exporter.retained_events == 2
    assert exporter._in_flight_events == 0
    assert exporter.status_snapshot()["unreadable_responses"] == 1


@pytest.mark.asyncio
async def test_a_batch_the_receiver_keeps_answering_without_confirming_is_abandoned(
    monkeypatch,
):
    """Bounded, counted, and the next batch goes through.

    This is the answer a receiver still keying batches on `sequence` gives after a
    restart. Retrying it forever would hold the head of the queue for good; after
    MAX_UNCONFIRMED_ATTEMPTS it is abandoned and counted as unconfirmed.
    """
    unmigrated = _FakeResponse(
        200,
        {"Content-Type": "application/json"},
        b'{"status":"duplicate","accepted_events":0}',
    )
    limit = http_export.MAX_UNCONFIRMED_ATTEMPTS
    _install(monkeypatch, responses=[unmigrated] * limit)
    exporter = HttpTelemetryExporter(
        device_id="phone-01", config=_config(batch_size=1, max_queue_size=10)
    )
    await exporter.handle_event(_event(1.0))

    for _ in range(limit - 1):
        assert await exporter.flush_once() == 0
        assert exporter.retained_events == 1, "retained while attempts remain"

    await exporter.handle_event(_event(2.0))
    delivered = await exporter.flush_once()

    assert exporter.unconfirmed_events == 1
    assert exporter.status_snapshot()["unconfirmed_events"] == 1
    assert delivered == 1, "the newer batch went through behind it"
    assert exporter.retained_events == 0
    assert exporter.dropped_events == 0, "abandonment is not overflow"


@pytest.mark.asyncio
async def test_an_unreadable_answer_never_abandons_a_batch(monkeypatch):
    """A captive portal's 200 is not the receiver speaking, so it is retried."""
    portal = _FakeResponse(200, {"Content-Type": "text/html"}, b"<html>sign in</html>")
    limit = http_export.MAX_UNCONFIRMED_ATTEMPTS
    _install(monkeypatch, responses=[portal] * (limit * 2))
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event())

    for _ in range(limit * 2):
        await exporter.flush_once()

    assert exporter.unconfirmed_events == 0
    assert exporter.retained_events == 1


@pytest.mark.asyncio
async def test_a_non_ascii_credential_can_still_be_rotated_after_a_suspension(
    monkeypatch,
):
    """compare_digest on str raises for non-ASCII; the comparison is on bytes.

    The rotation path is the line that raised, so a device holding such a key
    would have logged "flush loop failed" on every flush and never resumed.
    """
    refusal = _FakeResponse(
        403, {"Content-Type": "application/json"}, b'{"detail":"device is suspended"}'
    )
    _install(monkeypatch, responses=[refusal])
    monkeypatch.setenv("ORI_DEVICE_API_KEY", "clé-ancienne")
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event(1.0))
    await exporter.flush_once()
    assert exporter.export_suspended is True

    await exporter.flush_once()  # the same key: stays suspended, raises nothing
    assert exporter.export_suspended is True

    monkeypatch.setenv("ORI_DEVICE_API_KEY", "clé-nouvelle")
    assert await exporter.flush_once() == 0  # the rotation resumes export
    assert exporter.export_suspended is False

    # A reading taken while suspended is refused by design, so delivery resumes
    # with the next one.
    await exporter.handle_event(_event(2.0))
    assert await exporter.flush_once() == 1


@pytest.mark.asyncio
async def test_the_reported_refusal_is_the_one_the_endpoint_gave(monkeypatch):
    """With two recorded refusals, the health report names the one that matched.

    Taking an arbitrary element of the enumeration is indistinguishable while
    it holds one entry, and names the wrong refusal once it holds two.
    """
    from ori.telemetry import delivery

    refusals = {403: "device is suspended", 423: "device is locked"}
    statuses = frozenset(refusals)
    for module in (delivery, http_export):
        monkeypatch.setattr(module, "TERMINAL_REFUSALS", refusals)
        monkeypatch.setattr(module, "TERMINAL_REFUSAL_STATUSES", statuses)

    locked = _FakeResponse(
        423, {"Content-Type": "application/json"}, b'{"detail":"device is locked"}'
    )
    _install(monkeypatch, responses=[locked])
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event())

    await exporter.flush_once()

    snapshot = exporter.status_snapshot()
    assert exporter.export_suspended is True
    assert snapshot["refusal_status"] == 423
    assert snapshot["refusal_detail"] == "device is locked"


class _PerEventReceiver:
    """A receiver keyed per event, as the amended contract requires.

    `lose_next_ack` stores the next batch and then fails the request, which is a
    receiver that committed and whose answer never reached the producer.
    """

    stored: dict[str, dict] = {}
    sequences: list[int] = []
    lose_next_ack: bool = False

    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def stream(self, method, endpoint, *, content, headers):
        body = json.loads(content)
        _PerEventReceiver.sequences.append(body["sequence"])
        new = duplicate = 0
        for event in body["events"]:
            if event["event_id"] in _PerEventReceiver.stored:
                duplicate += 1
            else:
                _PerEventReceiver.stored[event["event_id"]] = event
                new += 1
        if _PerEventReceiver.lose_next_ack:
            _PerEventReceiver.lose_next_ack = False
            raise RuntimeError("connection reset after the receiver committed")
        return _Streamed(_accepted(new + duplicate, duplicate=duplicate))


def _install_per_event_receiver(monkeypatch):
    _PerEventReceiver.stored = {}
    _PerEventReceiver.sequences = []
    _PerEventReceiver.lose_next_ack = False
    monkeypatch.setenv("ORI_DEVICE_API_KEY", "device-secret")
    monkeypatch.setattr(
        http_export, "_httpx", SimpleNamespace(AsyncClient=_PerEventReceiver)
    )
    monkeypatch.setattr(http_export, "_HTTPX_AVAILABLE", True)


@pytest.mark.asyncio
async def test_a_restarted_exporter_loses_no_reading_a_per_event_receiver_stores(
    monkeypatch,
):
    """Every restart reuses sequence 1, and no reading is lost to it.

    The loss this contract removes was a receiver discarding a batch whose
    sequence it had seen before a restart. Three producer lifetimes, each
    starting at sequence 1, store every reading each of them sent.
    """
    _install_per_event_receiver(monkeypatch)
    sent: list[str] = []

    for lifetime in range(3):
        exporter = HttpTelemetryExporter(
            device_id="phone-01", config=_config(batch_size=2, max_queue_size=10)
        )
        for reading in range(4):
            event = _event(1000.0 + lifetime * 10 + reading)
            sent.append(event.event_id)
            await exporter.handle_event(event)
        assert await exporter.flush_once() == 2
        assert await exporter.flush_once() == 2

    assert _PerEventReceiver.sequences == [1, 2, 1, 2, 1, 2], "each lifetime restarts"
    assert sorted(_PerEventReceiver.stored) == sorted(sent), "no reading was lost"


@pytest.mark.asyncio
async def test_a_lost_acknowledgement_then_new_readings_stores_the_new_readings(
    monkeypatch,
):
    """The receiver committed a batch and its answer was lost.

    The batch is re-sent as itself and answered as a duplicate, which is a
    delivery and not a loss; the reading taken meanwhile travels in its own batch
    and is stored.
    """
    _install_per_event_receiver(monkeypatch)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    first = _event(100.0)
    await exporter.handle_event(first)
    _PerEventReceiver.lose_next_ack = True

    assert await exporter.flush_once() == 0, "an unanswered batch is not delivered"
    assert first.event_id in _PerEventReceiver.stored, "though the receiver holds it"

    later = _event(200.0)
    await exporter.handle_event(later)
    assert await exporter.flush_once() == 2

    assert _PerEventReceiver.sequences == [1, 1, 2]
    assert set(_PerEventReceiver.stored) == {first.event_id, later.event_id}
    snapshot = exporter.status_snapshot()
    assert snapshot["declined_events"] == 0, snapshot
    assert snapshot["dropped_events"] == 0, snapshot
    assert snapshot["duplicate_events"] == 1, "the re-sent batch was already held"


def _unmigrated() -> _FakeResponse:
    return _FakeResponse(
        200,
        {"Content-Type": "application/json"},
        b'{"status":"duplicate","accepted_events":0}',
    )


def test_the_attempt_bound_is_the_fifth_unconfirmed_answer() -> None:
    """The contract fixes the number, so two producers count the same loss."""
    assert http_export.MAX_UNCONFIRMED_ATTEMPTS == 5


@pytest.mark.asyncio
async def test_a_transport_failure_between_unconfirmed_answers_does_not_reset_them(
    monkeypatch,
):
    """On a flaky network the count must still reach the bound.

    Resetting it on every failed POST would hold a batch an unmigrated receiver
    will never confirm for as long as the network keeps dropping one attempt in
    two, which is the permanent head-of-line loss the bound exists to end.
    """
    unavailable = _FakeResponse(503, {}, b"unavailable")
    script = []
    for _ in range(4):
        script += [_unmigrated(), unavailable]
    script.append(_unmigrated())
    _install(monkeypatch, responses=script)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event())

    for _ in range(8):
        await exporter.flush_once()
        assert exporter.retained_events == 1, "four unconfirmed answers so far"
    await exporter.flush_once()

    assert exporter.unconfirmed_events == 1, "abandoned on the fifth"
    assert exporter.retained_events == 0


@pytest.mark.asyncio
async def test_each_batch_counts_its_own_unconfirmed_answers(monkeypatch):
    """The batch behind an abandoned one starts at one attempt, not zero or five.

    It is attempted in the flush that abandons the first, and that answer counts.
    """
    _install(monkeypatch, responses=[_unmigrated()] * 10)
    exporter = HttpTelemetryExporter(
        device_id="phone-01", config=_config(batch_size=1, max_queue_size=10)
    )
    await exporter.handle_event(_event(1.0))
    for _ in range(4):
        await exporter.flush_once()
    await exporter.handle_event(_event(2.0))

    await exporter.flush_once()
    assert exporter.unconfirmed_events == 1, "the first batch reached the bound"
    assert exporter.retained_events == 1, "the second was answered once and kept"

    for _ in range(3):
        await exporter.flush_once()
        assert exporter.unconfirmed_events == 1
    await exporter.flush_once()
    assert exporter.unconfirmed_events == 2, "the second reached its own fifth answer"
    assert len(_FakeAsyncClient.requests) == 10


@pytest.mark.asyncio
async def test_a_valid_prefix_of_an_oversized_body_is_not_read(monkeypatch):
    """Exactly the ceiling of conformant JSON, then one more byte.

    The prefix alone would parse and confirm the batch. The body is past the
    ceiling, so it is unreadable, not a delivery.
    """
    answer = json.dumps(
        {
            "status": "accepted",
            "accepted_events": 1,
            "duplicate_events": 0,
            "rejected_events": [],
        }
    ).encode()
    body = answer.ljust(http_export.MAX_RESPONSE_BYTES, b" ") + b" "
    oversized = _FakeResponse(
        200, {"Content-Type": "application/json"}, body, chunk=4096
    )
    _install(monkeypatch, responses=[oversized])
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event())

    assert await exporter.flush_once() == 0
    assert exporter.retained_events == 1


@pytest.mark.asyncio
async def test_a_coded_body_is_refused_unread_and_no_coding_is_requested(monkeypatch):
    """A compressed body is never inflated, so it cannot occupy memory unbounded."""
    coded = _FakeResponse(
        200,
        {"Content-Type": "application/json", "Content-Encoding": "gzip"},
        b"\x1f\x8b" + b"\x00" * 64,
    )
    _install(monkeypatch, responses=[coded])
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config(batch_size=1))
    await exporter.handle_event(_event())

    assert await exporter.flush_once() == 0
    assert coded.bytes_read == 0, "the coded body was not read at all"
    assert exporter.retained_events == 1
    assert exporter.status_snapshot()["unreadable_responses"] == 1
    assert _FakeAsyncClient.requests[0]["headers"]["Accept-Encoding"] == "identity"


def test_raw_header_fields_are_the_parsed_bytes() -> None:
    import httpx

    headers = httpx.Headers(
        [
            (b"Content-Type", b"application/json"),
            (b"WWW-Authenticate", b'Bearer realm="caf\xe9"'),
            (b"X-Empty", b""),
        ]
    )
    assert http_export._raw_header_fields(headers) == [
        (b"Content-Type", b"application/json"),
        (b"WWW-Authenticate", b'Bearer realm="caf\xe9"'),
        (b"X-Empty", b""),
    ]


class _RawSocketReceiver:
    """Answers each connection with the next scripted response bytes, as written."""

    def __init__(self, responses: list[bytes]) -> None:
        self.responses = list(responses)
        self.requests = 0

    async def serve(self, reader, writer) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1])
        await reader.readexactly(length)
        self.requests += 1
        writer.write(self.responses.pop(0) if self.responses else b"")
        await writer.drain()
        writer.close()


def _raw(
    status_line: bytes, fields: list[bytes], body: bytes, *, length: bool = True
) -> bytes:
    if length:
        fields = [*fields, b"Content-Length: %d" % len(body)]
    return (
        status_line + b"\r\n" + b"".join(f + b"\r\n" for f in fields) + b"\r\n" + body
    )


_REFUSAL = b'{"detail":"device is suspended"}'
_CONFIRM_ONE = b'{"status":"accepted","accepted_events":1,"duplicate_events":0,"rejected_events":[]}'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "suspended", "delivered"),
    [
        pytest.param(
            _raw(
                b"HTTP/1.1 403 Forbidden",
                [b"Content-Type: application/json", b"Garbage"],
                _REFUSAL,
            ),
            False,
            0,
            id="line-without-a-colon",
        ),
        pytest.param(
            _raw(
                b"HTTP/1.1 403 Forbidden",
                [b"Content-Type: application/json", b"WWW-Authenticate : Bearer"],
                _REFUSAL,
            ),
            False,
            0,
            id="space-before-the-colon",
        ),
        pytest.param(
            _raw(
                b"HTTP/1.1 403 Forbidden",
                [
                    b"Content-Type: application/json",
                    b"Transfer-Encoding: gzip, chunked",
                ],
                _REFUSAL,
                length=False,
            ),
            False,
            0,
            id="transfer-coding-other-than-chunked",
        ),
        pytest.param(
            _raw(
                b"HTTP/1.1 403 Forbidden",
                [
                    b"Content-Type: application/json",
                    b"Content-Length: 32",
                    b"Content-Length: 33",
                ],
                _REFUSAL,
                length=False,
            ),
            False,
            0,
            id="conflicting-lengths",
        ),
        pytest.param(
            _raw(
                b"HTTP/1.1 403 Forbidden",
                [
                    b"Content-Type: application/json",
                    b'WWW-Authenticate: Bearer realm="caf\xc3\xa9"',
                ],
                _REFUSAL,
            ),
            False,
            0,
            id="non-ascii-challenge",
        ),
        pytest.param(
            b"HTTP/1.1 100 Continue\r\n\r\n"
            + _raw(
                b"HTTP/1.1 403 Forbidden", [b"Content-Type: application/json"], _REFUSAL
            ),
            True,
            0,
            id="refusal-after-100-continue",
        ),
        pytest.param(
            b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
            + _raw(
                b"HTTP/1.1 200 OK", [b"Content-Type: application/json"], _CONFIRM_ONE
            ),
            False,
            1,
            id="confirmation-after-103",
        ),
        pytest.param(
            _raw(
                b"HTTP/1.1 200 OK",
                [
                    b"Content-Type: application/json",
                    b"X-Site: \xc3\x8ck\xe1\xba\xb9j\xc3\xa0",
                ],
                _CONFIRM_ONE,
            ),
            False,
            1,
            id="utf8-in-an-unrelated-header",
        ),
    ],
)
async def test_the_exporter_reads_raw_responses_through_its_real_client(
    monkeypatch, response: bytes, suspended: bool, delivered: int
) -> None:
    """The client and its parser, not a stand-in, against bytes on a socket.

    The shared vectors read these shapes through h11 directly; this pins that
    the exporter's own path does the same, since a parser the exporter does not
    use proves nothing about it.
    """
    receiver = _RawSocketReceiver([response])
    server = await asyncio.start_server(receiver.serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    monkeypatch.setenv("ORI_DEVICE_API_KEY", "device-secret")
    try:
        exporter = HttpTelemetryExporter(
            device_id="phone-01",
            config=_config(
                batch_size=1, endpoint=f"http://127.0.0.1:{port}/runtime/telemetry"
            ),
        )
        await exporter.handle_event(_event())
        assert await exporter.flush_once() == delivered
    finally:
        server.close()
        await server.wait_closed()

    assert receiver.requests == 1
    assert exporter.export_suspended is suspended
