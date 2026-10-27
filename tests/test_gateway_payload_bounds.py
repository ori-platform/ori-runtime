# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""gateway-api/v2 Payload Size and Payload Volume, held by the runtime.

The vendored `payload-size-v2.json` is the conformance test: the size cases go
through the runtime's own bounds, the paging cases through its page fitting,
and the required replies are built by the runtime's own encoders at the bounds
the `replies` cases name, at the 4096-byte floor.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import pathlib
import threading
from types import SimpleNamespace
from typing import Any

import pytest

from ori.gateway.evidence_inbound import (
    ARTIFACT_CUSTODY,
    EvidenceInboundRouter,
    MqttEvidenceInboundSubscriber,
    _Ticket,
)
from ori.gateway.evidence_outbound import (
    EvidenceOutboundAckRouter,
    MqttEvidenceOutboundPublisher,
)
from ori.gateway.export import (
    ITEM_EXCEEDS_PAYLOAD_MAXIMUM,
    ExportResponse,
    GatewayExportResponder,
    MqttGatewayExportServer,
)
from ori.gateway.heartbeat import MqttGatewayHeartbeatSubscriber
from ori.gateway.node_heartbeat import (
    DEGRADATION_REASONS,
    MqttRuntimeNodeHeartbeatPublisher,
)
from ori.gateway.payload_bounds import (
    ACTIVE_TRIGGERS_MAX,
    ALERT_DELIVERY_ACK,
    ENRICHMENT_RESPONSE,
    EVIDENCE_INBOUND,
    EVIDENCE_OUTBOUND_ACK,
    EXPORT_REQUEST,
    EXPORT_RESPONSE,
    GATEWAY_HEALTH,
    IN_FLIGHT_EXCEEDED,
    INGRESS_RATES,
    LAN_DISCLOSURE_REQUEST,
    LAN_REPLY,
    PAYLOAD_FLOOR,
    PAYLOAD_MAXIMA,
    PAYLOAD_TOO_LARGE,
    RATE_EXCEEDED,
    REASONING_RESPONSE,
    REDELIVERY_DUE,
    RUNTIME_HEARTBEAT,
    IngressBound,
    IngressFamilies,
    fits,
    fitting_count,
    refill_seconds,
    replay_capacity,
    size_class,
)
from ori.gateway.reasoning import GatewayReasoningError, MqttGatewayReasoner
from ori.gateway.route_io import Slots
from ori.security.evidence.ingest import REJECT_REASONS
from ori.security.evidence.ingest_service import REJECTED, IngestOutcome
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
    GatewayMessageEncryptionConfig,
    GatewayMessageEncryptor,
    GatewayReplayCache,
)
from ori.security.payload_members import DUPLICATE_MEMBER
from ori.state.store import StateStore
from tests.gateway_auth_helpers import cache_for
from tests.waiting import quiesce, wait_until

CORPUS = json.loads(
    (
        pathlib.Path(__file__).parent
        / "vectors"
        / "gateway_api"
        / "payload-size-v2.json"
    ).read_text(encoding="utf-8")
)
SECRET = "payload-bounds-secret"
LONG_ID = "a" * 128
#: An `error` of 128 U+1F600, the widest the floor must hold once escaped.
WIDE_ERROR = "\U0001f600" * 128
MAX_INT = 2**53 - 1


def _auth() -> GatewayMessageAuthenticator:
    # Started at clock 0, so envelopes signed before it was built still pass.
    return GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret=SECRET),
        replay_cache=GatewayReplayCache(max_skew_ms=300_000, start_ms=0),
    )


def _construct(construction: str, length: int) -> bytes:
    if construction == "json_object":
        return b'{"pad":"' + b"a" * (length - 10) + b'"}'
    assert construction == "invalid_utf8"
    return b"\xff" * length


class _Clock:
    """A monotonic clock that moves only when told to."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# ── the table and the size cases ────────────────────────────────────────────


def test_the_table_is_the_contract_table():
    at_maximum = {
        case["topic"]: case["length"]
        for case in CORPUS["cases"]
        if case["configured_maximum"] is None and case["note"] == "exactly the maximum"
    }
    assert at_maximum == PAYLOAD_MAXIMA


def test_every_case_is_the_bytes_its_construction_gives():
    for case in CORPUS["cases"]:
        body = _construct(case["construction"], case["length"])
        assert hashlib.sha256(body).hexdigest() == case["sha256"], case["name"]


#: Gateway-to-runtime families with no runtime subscriber, so nothing to bound.
_NOT_SUBSCRIBED = {
    ALERT_DELIVERY_ACK,
    ENRICHMENT_RESPONSE,
    LAN_REPLY,
    LAN_DISCLOSURE_REQUEST,
}


@pytest.mark.parametrize(
    "case",
    [c for c in CORPUS["cases"] if c["configured_maximum"] is None],
    ids=lambda c: c["name"],
)
def test_a_size_case_reaches_its_verdict(case):
    body = _construct(case["construction"], case["length"])
    if case["direction"] == "runtime_to_gateway":
        verdict = "admitted" if fits(case["topic"], body) else PAYLOAD_TOO_LARGE
    elif case["topic"] in _NOT_SUBSCRIBED:
        pytest.skip("the runtime does not subscribe to this family")
    else:
        verdict = IngressBound(case["topic"], clock=_Clock()).admit(body) or "admitted"
    assert verdict == case["verdict"]


@pytest.mark.parametrize("case", CORPUS["envelopes"], ids=lambda c: c["name"])
def test_an_evidence_envelope_at_its_bounds_is_judged_as_the_contract_judges_it(case):
    """The inbound message is admitted canonical and refused escaped, which is
    why the gateway publishes it canonical; each side holds the other's form."""
    body = b"{" + b" " * (case["length"] - 2) + b"}"
    if case["topic"] in INGRESS_RATES:
        verdict = IngressBound(case["topic"], clock=_Clock()).admit(body)
    else:
        verdict = None if fits(case["topic"], body) else PAYLOAD_TOO_LARGE
    assert (verdict or "admitted") == case["verdict"]


def test_the_configured_cases_have_no_setting_to_apply_to():
    """The runtime offers no setting for a topic's maximum, so the table is the
    maximum in force and no configured value exists to apply or refuse."""
    configured = [c for c in CORPUS["cases"] if c["configured_maximum"] is not None]
    assert configured
    assert set(INGRESS_RATES) | _NOT_SUBSCRIBED == {
        c["topic"] for c in CORPUS["cases"] if c["direction"] == "gateway_to_runtime"
    }
    assert not set(INGRESS_RATES) & _NOT_SUBSCRIBED


@pytest.mark.parametrize(
    "length, expected", [(0, 1), (1, 1), (2, 2), (3, 4), (16384, 16384), (16385, 32768)]
)
def test_a_size_class_is_the_least_power_of_two_not_below(length, expected):
    assert size_class(length) == expected


# ── paging ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("case", CORPUS["paging"], ids=lambda c: c["name"])
def test_export_pages_fill_as_the_contract_pages_them(case):
    items, maximum = case["item_bytes"], case["maximum"]
    pages, error, offset = [], None, 0
    while offset < len(items):
        count = fitting_count(
            len(items) - offset,
            lambda n: case["fixed_bytes"] + sum(items[offset : offset + n]) <= maximum,
        )
        if count == 0:
            error = {"at": offset, "error": ITEM_EXCEEDS_PAYLOAD_MAXIMUM}
            break
        offset += count
        pages.append({"items": count, "next": offset})
    assert pages == case["pages"]
    assert error == case["error"]


async def _responder(tmp_path, *, encrypted: bool = False, device_id: str = "dev-01"):
    store = StateStore(str(tmp_path / "bounds.db"))
    await store.open()
    responder = GatewayExportResponder(
        device_id=device_id,
        state_store=store,
        health_snapshot_provider=lambda: {"device_id": device_id},
        message_auth=_auth(),
        message_encryptor=GatewayMessageEncryptor(
            GatewayMessageEncryptionConfig(shared_secret=SECRET)
        )
        if encrypted
        else None,
    )
    return responder, store


async def test_an_export_page_holds_only_what_fits_and_continues_from_the_rest(
    tmp_path,
):
    responder, store = await _responder(tmp_path, encrypted=True)
    try:
        items = [{"row": index, "pad": "x" * 600_000} for index in range(12)]
        response = ExportResponse(
            request_id="req-1",
            export_type="action_log",
            device_id="dev-01",
            items=items,
            page_offset=40,
        )
        body = responder.encode(response)
        assert fits(EXPORT_RESPONSE, body)
        plain = _auth().verify(
            json.loads(body),
            message_type="export_response",
            expected_device_id="dev-01",
            expected_request_id="req-1",
        )
        page = GatewayMessageEncryptor(
            GatewayMessageEncryptionConfig(shared_secret=SECRET)
        ).decrypt(plain, message_type="export_response", expected_device_id="dev-01")
        held = len(page["items"])
        assert 1 <= held < len(items)
        assert page["items"] == items[:held]
        assert page["next_page_token"] == str(40 + held)
        assert page["complete"] is False
        # One more item would not have fitted.
        wider = ExportResponse(**{**response.__dict__, "items": items[: held + 1]})
        assert not fits(EXPORT_RESPONSE, responder._encode(wider))
    finally:
        await store.close()


async def test_an_item_too_large_for_a_page_by_itself_ends_the_export(tmp_path):
    responder, store = await _responder(tmp_path)
    try:
        response = ExportResponse(
            request_id="req-1",
            export_type="health",
            device_id="dev-01",
            items=[{"pad": "x" * PAYLOAD_MAXIMA[EXPORT_RESPONSE]}],
        )
        decoded = json.loads(responder.encode(response))
        assert decoded["error"] == ITEM_EXCEEDS_PAYLOAD_MAXIMUM
        assert decoded["items"] == [] and decoded["complete"] is True
        assert decoded["request_id"] == "req-1"
    finally:
        await store.close()


# ── required replies at the floor ───────────────────────────────────────────


def _reply(name: str) -> dict[str, Any]:
    return next(case for case in CORPUS["replies"] if case["name"] == name)


async def test_an_encrypted_export_error_fits_the_floor_at_its_bounds(tmp_path):
    assert _reply("export_error_encrypted")["configured_maximum"] == PAYLOAD_FLOOR
    responder, store = await _responder(tmp_path, encrypted=True, device_id=LONG_ID)
    try:
        longest = max(
            ("sensor_history", "action_log", "reasoning_log", "tier_c_decision_log"),
            key=len,
        )
        response = responder._error_response(
            request_id="r" * 128, export_type=longest, error=WIDE_ERROR + "overflow"
        )
        assert response.error == WIDE_ERROR
        body = responder.encode(response)
        assert json.loads(body)["encrypted"] is True
        assert len(body) <= PAYLOAD_FLOOR
    finally:
        await store.close()


async def test_an_export_error_never_echoes_what_the_gateway_sent(tmp_path):
    responder, store = await _responder(tmp_path, device_id=LONG_ID)
    try:
        wide = "\U0001f600" * 128
        request = {
            "request_id": "r" * 128,
            "export_type": wide,
            "device_id": LONG_ID,
            "auth": {"signature": wide},
        }
        # Unauthenticated, it is not answered at all.
        assert await responder.handle_payload(json.dumps(request).encode()) is None
        request = _auth().sign(request, message_type="export_request")
        response = await responder.handle_payload(json.dumps(request).encode())
        assert response is not None and response.export_type == "unknown"
        assert response.error is not None and wide not in response.error
        assert len(responder.encode(response)) <= PAYLOAD_FLOOR
    finally:
        await store.close()


def _publisher(**kwargs: Any) -> MqttRuntimeNodeHeartbeatPublisher:
    return MqttRuntimeNodeHeartbeatPublisher(
        broker_url="mqtt://localhost",
        device_id=kwargs.pop("device_id", LONG_ID),
        health_snapshot_provider=lambda: {},
        authenticator=_auth(),
        client_factory=lambda **_: None,
    )


def _snapshot(active_triggers: list[str]) -> dict[str, Any]:
    return {
        "status": "critical",
        "critical": True,
        "active_triggers": active_triggers,
        "degradation_reasons": sorted(DEGRADATION_REASONS),
        "evidence": {
            "enabled": True,
            "available": True,
            "chain_head_hash": "f" * 64,
            "attestation_gap_count": MAX_INT,
            "action_event_type": "A" * 64,
        },
    }


def test_a_runtime_heartbeat_with_no_triggers_fits_the_floor_at_its_bounds():
    assert (
        _reply("runtime_heartbeat_no_triggers")["configured_maximum"] == PAYLOAD_FLOOR
    )
    publisher = _publisher()
    payload = publisher._mapped(_snapshot([]), MAX_INT)
    assert payload["evidence"]["action_event_type"] == "A" * 64
    assert payload["degradation_reasons"]
    assert len(publisher._fitted(payload)) <= PAYLOAD_FLOOR


def test_a_heartbeat_lists_only_the_triggers_that_fit_in_the_runtime_order():
    publisher = _publisher()
    names = [f"{index:03d}-" + "t" * 2000 for index in range(100)]
    payload = publisher._mapped(_snapshot(names), MAX_INT)
    assert payload["active_triggers"] == names[:ACTIVE_TRIGGERS_MAX]
    body = publisher._fitted(payload)
    assert fits(RUNTIME_HEARTBEAT, body)
    listed = json.loads(body)["active_triggers"]
    assert listed and listed == names[: len(listed)]
    assert len(listed) < ACTIVE_TRIGGERS_MAX
    # Every other member survived.
    assert json.loads(body)["evidence"]["action_event_type"] == "A" * 64


def test_an_inbound_acknowledgement_fits_the_floor_at_its_bounds():
    router = EvidenceInboundRouter(device_id=LONG_ID, ingest=None, message_auth=_auth())
    reason = max(REJECT_REASONS, key=len)
    ack = router._acknowledgement(
        ARTIFACT_CUSTODY,
        {"v": 1},
        IngestOutcome(artifact=ARTIFACT_CUSTODY, state=REJECTED, reason=reason),
    )
    assert ack is not None and ack["reason"] == reason
    # Encoded as the subscriber publishes it.
    assert len(json.dumps(ack).encode()) <= PAYLOAD_FLOOR


# ── the routing form ────────────────────────────────────────────────────────


def test_the_reasoner_refuses_a_device_or_request_id_outside_the_routing_form():
    with pytest.raises(ValueError, match="device_id"):
        MqttGatewayReasoner(
            broker_url="mqtt://localhost",
            device_id="dév",
            client_factory=lambda **_: None,
        )


# ── refusals through the real entry points ──────────────────────────────────


async def test_a_burst_of_signed_export_requests_is_served_at_the_runtime_rate(
    tmp_path,
):
    """200 authenticated sensor_history requests, as the gateway signs them,
    reach the store only as often as the export rate admits."""
    responder, store = await _responder(tmp_path)
    reads = []
    original = store.export_sensor_history

    async def counted(**kwargs: Any) -> Any:
        reads.append(kwargs)
        return await original(**kwargs)

    store.export_sensor_history = counted  # type: ignore[method-assign]
    published: list[str] = []

    class _Client:
        def publish(self, topic: str, payload: bytes, qos: int = 0) -> None:
            published.append(topic)

    server = MqttGatewayExportServer(
        broker_url="mqtt://localhost",
        responder=responder,
        client_factory=lambda **_: None,
    )
    clock = _Clock()
    server._ingress = IngressBound(EXPORT_REQUEST, clock=clock)
    server._loop = asyncio.get_running_loop()
    gateway = _auth()
    try:
        for index in range(200):
            request = gateway.sign(
                {
                    "request_id": f"req-{index}",
                    "export_type": "sensor_history",
                    "device_id": "dev-01",
                    "since_ms": 0,
                    "until_ms": MAX_INT,
                    "params": {"sensor_id": "main"},
                },
                message_type="export_request",
            )
            message = SimpleNamespace(payload=json.dumps(request).encode())
            await asyncio.to_thread(server._on_message, _Client(), None, message)
            # Each answered before the next, so only the rate refuses here;
            # the in-flight bound has its own test.
            await wait_until(lambda: server._slots.taken == 0, what="the answer")
        burst = INGRESS_RATES[EXPORT_REQUEST].burst
        await wait_until(lambda: len(published) == burst, what="the burst's answers")
        await quiesce(what="the work the message scheduled")
        assert len(reads) == burst
        assert server._ingress.refusals() == {
            PAYLOAD_TOO_LARGE: 0,
            RATE_EXCEEDED: 200 - burst,
        }
        # The rate refills with time, never with anything the gateway sends.
        clock.now += 1.0 / INGRESS_RATES[EXPORT_REQUEST].per_second
        assert server._ingress.admit(b"{}") is None
        assert server._ingress.admit(b"{}") == RATE_EXCEEDED
    finally:
        await store.close()


async def test_an_oversized_export_request_is_refused_before_it_is_read(
    tmp_path, caplog
):
    responder, store = await _responder(tmp_path)
    handled = []

    async def spy(payload: Any) -> None:
        handled.append(payload)

    responder.handle_payload = spy  # type: ignore[method-assign]
    server = MqttGatewayExportServer(
        broker_url="mqtt://localhost",
        responder=responder,
        client_factory=lambda **_: None,
    )
    server._loop = asyncio.get_running_loop()
    secret_marker = b"dev-01-secret-contents"
    payload = b'{"device_id":"' + secret_marker + b'","pad":"' + b"a" * 20_000 + b'"}'
    try:
        with caplog.at_level(logging.WARNING, logger="ori.gateway.payload_bounds"):
            server._on_message(None, None, SimpleNamespace(payload=payload))
            await quiesce(what="the work the message scheduled")
        assert handled == []
        assert server._ingress.refusals()[PAYLOAD_TOO_LARGE] == 1
        logged = caplog.text
        assert EXPORT_REQUEST in logged and "32768" in logged
        assert "secret-contents" not in logged and "dev-01" not in logged
    finally:
        await store.close()


class _Tracker:
    def __init__(self) -> None:
        self.recorded: list[int] = []

    def record_gateway_heartbeat(self, received_at_ms: int) -> None:
        self.recorded.append(received_at_ms)


async def test_the_gateway_heartbeat_is_bounded_in_size_and_rate():
    tracker = _Tracker()
    subscriber = MqttGatewayHeartbeatSubscriber(
        broker_url="mqtt://localhost",
        posture_tracker=tracker,  # type: ignore[arg-type]
        device_id="dev-01",
        client_factory=lambda **_: None,
    )
    subscriber._loop = asyncio.get_running_loop()
    subscriber._ingress = IngressBound(GATEWAY_HEALTH, clock=_Clock())
    maximum = PAYLOAD_MAXIMA[GATEWAY_HEALTH]

    subscriber._on_message(
        None, None, SimpleNamespace(payload=_construct("json_object", maximum + 1))
    )
    await quiesce(what="the work the message scheduled")
    assert tracker.recorded == []

    for _ in range(INGRESS_RATES[GATEWAY_HEALTH].burst + 3):
        subscriber._on_message(
            None, None, SimpleNamespace(payload=_construct("json_object", maximum))
        )
    await quiesce(what="the work the message scheduled")
    assert len(tracker.recorded) == INGRESS_RATES[GATEWAY_HEALTH].burst
    assert subscriber._ingress.refusals() == {PAYLOAD_TOO_LARGE: 1, RATE_EXCEEDED: 3}


class _ReasoningClient:
    """Answers every request with *answer*, on the response topic."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.on_connect: Any = None
        self.on_message: Any = None
        self.on_subscribe: Any = None
        self.published: list[bytes] = []
        self.connected = False

    def connect(self, *_args: Any) -> None:
        self.connected = True

    def loop_start(self) -> None:
        self.on_connect(self, None, None, 0)

    def subscribe(self, _topic: str, qos: int = 0) -> tuple[int, int]:
        if self.on_subscribe is not None:
            self.on_subscribe(self, None, 1, [qos], None)
        return (0, 1)

    def publish(self, _topic: str, payload: bytes, *_args: Any) -> Any:
        self.published.append(payload)
        request = json.loads(payload)
        self.on_message(self, None, SimpleNamespace(payload=self.answer(request)))
        return SimpleNamespace(rc=0)

    def loop_stop(self) -> None:
        pass

    def disconnect(self) -> None:
        pass


@pytest.fixture
def _paho(monkeypatch):
    monkeypatch.setattr("ori.gateway.reasoning._PAHO_AVAILABLE", True)
    monkeypatch.setattr("ori.gateway.reasoning.mqtt", object())


@pytest.mark.usefixtures("_paho")
async def test_an_oversized_reasoning_response_is_never_read():
    """Even one that answers the pending request: its size is all that is read."""

    def answer(request: dict[str, Any]) -> bytes:
        body = json.dumps(
            {
                "request_id": request["request_id"],
                "device_id": "dev-01",
                "action_tier": "A",
                "text": "",
            }
        ).encode()
        return (
            body[:-1] + b',"pad":"' + b"a" * PAYLOAD_MAXIMA[ENRICHMENT_RESPONSE] + b'"}'
        )

    client = _ReasoningClient(answer)
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://localhost",
        device_id="dev-01",
        timeout_ms=100,
        client_factory=lambda **_: client,
    )
    with pytest.raises(GatewayReasoningError, match="timeout"):
        await reasoner.reason("prompt")
    assert reasoner._ingress.refusals()[PAYLOAD_TOO_LARGE] == 1


@pytest.mark.usefixtures("_paho")
async def test_a_reasoning_request_over_its_maximum_is_never_published():
    client = _ReasoningClient(lambda _request: b"{}")
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://localhost",
        device_id="dev-01",
        timeout_ms=60_000,
        client_factory=lambda **_: client,
    )
    with pytest.raises(GatewayReasoningError, match="payload maximum"):
        await reasoner.reason("p" * 262_144)
    assert client.published == [] and client.connected is False


class _AckingClient:
    """A paho client as far as a session needs one: callbacks and manual ack."""

    def __init__(self) -> None:
        self.acked: list[Any] = []
        self.published: list[tuple[str, bytes]] = []
        self.on_connect: Any = None
        self.on_subscribe: Any = None
        self.on_disconnect: Any = None
        self.on_message: Any = None

    def manual_ack_set(self, _on: bool) -> None:
        pass

    def ack(self, mid: Any, _qos: Any) -> int:
        self.acked.append(mid)
        return 0

    def subscribe(self, *_args: Any, **_kwargs: Any) -> tuple[int, int]:
        return (0, 1)

    def publish(self, topic: str, payload: bytes, *_args: Any) -> None:
        self.published.append((topic, payload))


class _AckRouter:
    def __init__(self) -> None:
        self.handled: list[bytes] = []

    async def handle_ack(self, payload: bytes) -> Any:
        self.handled.append(payload)
        return SimpleNamespace(outcome="applied", reason="", artifact_type="checkpoint")


async def test_an_outbound_acknowledgement_past_its_bounds_is_dropped_unread():
    router = _AckRouter()
    publisher = MqttEvidenceOutboundPublisher(
        broker_url="mqtt://localhost",
        router=router,  # type: ignore[arg-type]
        device_id="dev-01",
        outbox=None,  # type: ignore[arg-type]
        client_factory=lambda **_: None,
    )
    publisher._loop = asyncio.get_running_loop()
    publisher._ingress = IngressBound(EVIDENCE_OUTBOUND_ACK, clock=_Clock())
    maximum = PAYLOAD_MAXIMA[EVIDENCE_OUTBOUND_ACK]

    publisher._on_message(
        None, None, SimpleNamespace(payload=_construct("json_object", maximum + 1))
    )
    burst = INGRESS_RATES[EVIDENCE_OUTBOUND_ACK].burst
    # One at a time, so the in-flight bound never sheds what the rate admits.
    for index in range(burst + 2):
        publisher._on_message(
            None, None, SimpleNamespace(payload=_construct("json_object", maximum))
        )
        await wait_until(
            lambda: (
                len(router.handled) == min(index + 1, burst)
                and publisher._acks_in_flight == 0
            ),
            what="the acknowledgement to be routed",
        )
    await quiesce(what="the acknowledgements the route scheduled")

    assert all(len(payload) == maximum for payload in router.handled)
    assert publisher._ingress.refusals() == {PAYLOAD_TOO_LARGE: 1, RATE_EXCEEDED: 2}


# ── review follow-ups ───────────────────────────────────────────────────────


@pytest.mark.parametrize("export_type", [["health"], {"t": "health"}, 7, None, True])
@pytest.mark.parametrize("signed", [False, True])
async def test_a_non_text_export_type_is_answered_as_unknown(
    tmp_path, export_type, signed
):
    """Never hashed, never str()-ed: answered with an error once it verifies,
    and not answered at all unsigned."""
    responder, store = await _responder(tmp_path)
    try:
        request: dict[str, Any] = {
            "request_id": "req-1",
            "export_type": export_type,
            "device_id": "dev-01",
        }
        if signed:
            request = _auth().sign(request, message_type="export_request")
        response = await responder.handle_payload(json.dumps(request).encode())
        if not signed:
            assert response is None
            return
        assert response is not None
        assert response.export_type == "unknown"
        assert response.error
        assert len(responder.encode(response)) <= PAYLOAD_FLOOR
    finally:
        await store.close()


@pytest.mark.parametrize("case", CORPUS["paging"], ids=lambda c: c["name"])
async def test_the_responder_pages_the_corpus_cases(tmp_path, case, monkeypatch):
    """`GatewayExportResponder.encode` itself, under the case's sizes."""
    responder, store = await _responder(tmp_path)
    monkeypatch.setitem(PAYLOAD_MAXIMA, EXPORT_RESPONSE, case["maximum"])
    sizes = case["item_bytes"]

    def modelled(response: ExportResponse) -> bytes:
        summary = json.dumps(
            {
                "items": len(response.items),
                "next": response.next_page_token,
                "error": response.error,
            }
        ).encode()
        length = case["fixed_bytes"] + sum(item["bytes"] for item in response.items)
        return summary.ljust(max(length, len(summary)))

    responder._encode = modelled  # type: ignore[method-assign]
    try:
        pages, error, offset = [], None, 0
        while offset < len(sizes):
            page = ExportResponse(
                request_id="req-1",
                export_type="action_log",
                device_id="dev-01",
                items=[{"bytes": b} for b in sizes[offset:]],
                page_offset=offset,
            )
            published = json.loads(responder.encode(page))
            if published["error"]:
                error = {"at": offset, "error": published["error"]}
                break
            if published["items"] == len(sizes) - offset:
                advanced = len(sizes)
            else:
                advanced = int(published["next"])
            # Every page moves forward, so the export ends.
            assert offset < advanced <= len(sizes), (offset, published)
            offset = advanced
            pages.append({"items": published["items"], "next": offset})
        assert pages == case["pages"]
        assert error == case["error"]
    finally:
        await store.close()


@pytest.mark.usefixtures("_paho")
async def test_reasoning_responses_past_the_rate_are_never_read():
    """A flood of answers to nothing uses up the rate; the real answer is dropped."""
    burst = INGRESS_RATES[REASONING_RESPONSE].burst

    class _Flooding(_ReasoningClient):
        def publish(self, _topic: str, payload: bytes, *_args: Any) -> Any:
            request = json.loads(payload)
            for index in range(burst):
                stray = {"request_id": f"other-{index}", "device_id": "dev-01"}
                self.on_message(
                    self, None, SimpleNamespace(payload=json.dumps(stray).encode())
                )
            answer = {
                "request_id": request["request_id"],
                "device_id": "dev-01",
                "action_tier": "A",
                "text": "late",
            }
            self.on_message(
                self, None, SimpleNamespace(payload=json.dumps(answer).encode())
            )
            return SimpleNamespace(rc=0)

    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://localhost",
        device_id="dev-01",
        timeout_ms=100,
        client_factory=lambda **_: _Flooding(None),
    )
    reasoner._ingress = IngressBound(REASONING_RESPONSE, clock=_Clock())
    with pytest.raises(GatewayReasoningError, match="timeout"):
        await reasoner.reason("prompt")
    assert reasoner._ingress.refusals() == {PAYLOAD_TOO_LARGE: 0, RATE_EXCEEDED: 1}


async def test_every_refusal_reaches_the_log_and_the_tail_within_a_second(caplog):
    """The log is the only report: a coalesced tail is flushed, not held back."""
    bound = IngressBound(EXPORT_REQUEST, clock=_Clock())
    lines: list[tuple[str, int, list[int]]] = []
    write = bound._log

    def recorded(reason: str, count: int, classes: list[int]) -> None:
        write(reason, count, classes)
        if count:
            lines.append((reason, count, classes))

    bound._log = recorded  # type: ignore[method-assign]
    with caplog.at_level(logging.WARNING, logger="ori.gateway.payload_bounds"):
        for _ in range(200):
            bound.admit(b"{}")
        for length in (20_000, 70_000, 20_000):
            bound.admit(b"a" * length)
        dropped = 200 - INGRESS_RATES[EXPORT_REQUEST].burst

        def logged(reason: str) -> int:
            return sum(count for name, count, _ in lines if name == reason)

        await wait_until(
            lambda: logged(RATE_EXCEEDED) == dropped and logged(PAYLOAD_TOO_LARGE) == 3,
            what="every refusal to be logged",
        )
    # The first of each at once, the rest in one flushed line, every class named.
    assert [line for line in lines if line[0] == PAYLOAD_TOO_LARGE] == [
        (PAYLOAD_TOO_LARGE, 1, [32768]),
        (PAYLOAD_TOO_LARGE, 2, [32768, 131072]),
    ]
    assert f"dropped {dropped - 1} message(s)" in caplog.text
    assert bound.refusals() == {PAYLOAD_TOO_LARGE: 3, RATE_EXCEEDED: dropped}


def test_the_replay_cache_holds_every_message_the_families_admit_in_a_window():
    from ori.gateway.payload_bounds import REPLAY_CACHE_CEILING

    for ttl_ms in (1_000, 300_000, 600_001, 2_400_000, 3_600_000):
        admitted = sum(r.per_second for r in INGRESS_RATES.values()) * ttl_ms / 1000
        bursts = sum(r.burst for r in INGRESS_RATES.values())
        needed = admitted + bursts
        assert replay_capacity(ttl_ms) >= min(needed, REPLAY_CACHE_CEILING)
        assert replay_capacity(ttl_ms) >= 4096


def test_the_runtime_sizes_each_gateway_replay_cache_for_the_window(monkeypatch):
    from ori.config import GatewayConfig
    from ori.gateway.envelope_auth import (
        build_gateway_message_auth as _build_gateway_message_auth,
    )

    monkeypatch.setenv("GATEWAY_SHARED_SECRET", SECRET)
    for persistent in (True, False):
        config: Any = SimpleNamespace(
            database_path="",
            gateway=GatewayConfig(
                enabled=True,
                broker_url="mqtt://broker.local",
                auth={
                    "enabled": True,
                    "shared_secret_env": "GATEWAY_SHARED_SECRET",
                    "max_clock_skew_ms": 300_000,
                    "replay_ttl_ms": 600_000,
                    "persistent_replay_cache": persistent,
                },
            ),
        )
        auth = _build_gateway_message_auth(config)
        assert auth is not None
        assert auth._replay_cache._max_entries == replay_capacity(600_001)


def test_any_replay_window_the_contract_admits_is_accepted():
    """runtime-config/v2 bounds it below only; the cache follows it up."""
    from ori.config._gateway import parse_gateway as _parse_gateway

    for ttl_ms in (1_000, 300_000, 86_400_000):
        data = {
            "enabled": False,
            "broker_url": "mqtt://localhost",
            "auth": {"replay_ttl_ms": ttl_ms},
        }
        assert _parse_gateway(data).auth["replay_ttl_ms"] == ttl_ms


def _admit(cache: Any, key: str, at_ms: int) -> str | None:
    return cache.admit(
        key, signed_at_ms=at_ms, received_at_ms=at_ms, now_ms_value=at_ms
    )


def test_the_replay_cache_prunes_in_expiry_order_without_scanning():
    cache = GatewayReplayCache(ttl_ms=100, max_skew_ms=0, max_entries=10, start_ms=0)
    assert _admit(cache, "a", 0) is None  # expires at 100
    assert _admit(cache, "b", 50) is None  # expires at 150
    assert _admit(cache, "c", 99) is None
    assert sorted(cache._held) == ["a", "b", "c"]
    assert _admit(cache, "d", 100) is None
    assert sorted(cache._held) == ["b", "c", "d"] and cache.floor_ms() == 1
    assert _admit(cache, "e", 150) is None
    assert sorted(cache._held) == ["c", "d", "e"] and cache.floor_ms() == 51
    # Every live key has one expiry entry still to come; expired ones are gone.
    assert sorted(cache._expiries) == [(199, "c"), (200, "d"), (250, "e")]
    assert _admit(cache, "f", 10_000) is None
    assert len(cache._expiries) == 1 and list(cache._held) == ["f"]


def test_the_persisted_replay_cache_prunes_by_index(tmp_path):
    import sqlite3

    from ori.security.gateway_messages import GatewayReplayCache

    db = tmp_path / "replay.db"
    GatewayReplayCache(ttl_ms=100, max_skew_ms=0, db_path=str(db))
    with sqlite3.connect(db) as connection:
        # A dropped key is deleted by its own key, never by a scan.
        plan = connection.execute(
            "EXPLAIN QUERY PLAN DELETE FROM gateway_replay_cache WHERE key = ?",
            ("k",),
        ).fetchall()
        # A release before the floor deletes by expiry after a rollback.
        rollback_plan = connection.execute(
            "EXPLAIN QUERY PLAN DELETE FROM gateway_replay_cache WHERE seen_until_ms <= ?",
            (0,),
        ).fetchall()
    assert any("sqlite_autoindex_gateway_replay_cache" in str(row) for row in plan), (
        plan
    )
    assert any("gateway_replay_cache_expiry" in str(row) for row in rollback_plan), (
        rollback_plan
    )


@pytest.mark.parametrize(
    "ttl_ms, skew_ms",
    [(2**63, 300_000), (2**80, 2**80), (10**309, 10**309), (1_000, 300_000)],
)
async def test_any_replay_window_the_contract_admits_starts_and_records(
    tmp_path, monkeypatch, ttl_ms, skew_ms
):
    """Through the runtime's own builder, persistent: the window is decided in
    one place, so no expiry, cache size or SQL bound leaves its range."""
    from ori.config import GatewayConfig
    from ori.gateway.envelope_auth import (
        build_gateway_message_auth as _build_gateway_message_auth,
    )
    from ori.security.gateway_messages import replay_retention_ms, replay_window_ms

    monkeypatch.setenv("GATEWAY_SHARED_SECRET", SECRET)
    config: Any = SimpleNamespace(
        database_path=str(tmp_path / "state.db"),
        gateway=GatewayConfig(
            enabled=True,
            broker_url="mqtt://broker.local",
            auth={
                "enabled": True,
                "shared_secret_env": "GATEWAY_SHARED_SECRET",
                "max_clock_skew_ms": skew_ms,
                "replay_ttl_ms": ttl_ms,
                "persistent_replay_cache": True,
            },
        ),
    )
    auth = _build_gateway_message_auth(config)
    assert auth is not None and auth._replay_cache.persistent
    window = replay_window_ms(skew_ms)
    assert window == min(2 * skew_ms + 1, 2**53)
    assert auth._replay_cache._max_entries == replay_capacity(
        replay_retention_ms(ttl_ms, skew_ms)
    )

    # The durable signing clock issues nothing before its first claim commits.
    await wait_until(
        lambda: bool(auth._signing_clock._ranges), what="the first signing claim"
    )
    signed = auth.sign(
        {"device_id": "dev-01", "request_id": "r1"}, message_type="export_request"
    )
    auth._signing_clock.stop()
    assert auth.verify(
        signed, message_type="export_request", expected_device_id="dev-01"
    )
    with pytest.raises(Exception, match="replay_detected"):
        auth.verify(signed, message_type="export_request", expected_device_id="dev-01")


@pytest.mark.parametrize("ttl_ms", [1_000, 300_000, 3_600_000])
@pytest.mark.parametrize("broadcast", [False, True])
def test_a_replay_is_refused_until_it_is_stale_whatever_the_ttl(ttl_ms, broadcast):
    """Signed at the future edge of the skew and received at once, a replay
    could pass until twice the skew later, inclusive; the key outlives that."""
    skew = 300_000
    auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret=SECRET, max_skew_ms=skew, replay_ttl_ms=ttl_ms
        ),
        replay_cache=GatewayReplayCache(ttl_ms=ttl_ms, max_skew_ms=skew, start_ms=0),
    )
    received = 1_000_000_000
    if broadcast:
        payload = auth.sign(
            {"status": "healthy"},
            message_type="gateway.heartbeat",
            signed_at_ms=received + skew,
        )

        def check(at: int) -> Any:
            return auth.verify_broadcast(
                payload, message_type="gateway.heartbeat", now_ms_value=at
            )

    else:
        payload = auth.sign(
            {"device_id": "dev-01", "request_id": "r1"},
            message_type="export_request",
            signed_at_ms=received + skew,
        )

        def check(at: int) -> Any:
            return auth.verify(
                payload,
                message_type="export_request",
                expected_device_id="dev-01",
                now_ms_value=at,
            )

    assert check(received)
    for replayed_at in (
        received + 1,
        received + min(ttl_ms, 2 * skew),
        received + 2 * skew,
    ):
        with pytest.raises(Exception, match="replay_detected"):
            check(replayed_at)
    with pytest.raises(Exception, match="stale_timestamp"):
        check(received + 2 * skew + 1)


def test_an_infinite_window_in_the_configuration_is_a_configuration_error():
    from ori.config import ConfigValidationError
    from ori.config._gateway import parse_gateway as _parse_gateway

    for key in ("replay_ttl_ms", "max_clock_skew_ms"):
        with pytest.raises(ConfigValidationError, match="must be integers"):
            _parse_gateway(
                {
                    "enabled": False,
                    "broker_url": "mqtt://localhost",
                    "auth": {key: float("inf")},
                }
            )


def test_the_ledger_finds_an_envelope_by_index(tmp_path):
    import sqlite3

    from ori.security.evidence.ledger import _SCHEMA

    with sqlite3.connect(tmp_path / "ledger.db") as connection:
        connection.executescript(_SCHEMA)
        plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM evidence_delivery_ledger "
            "WHERE envelope_digest = ?",
            ("sha256:" + "0" * 64,),
        ).fetchall()
    assert any("idx_evidence_ledger_envelope_digest" in str(row) for row in plan), plan


async def test_an_export_page_is_fitted_off_the_event_loop(tmp_path):
    responder, store = await _responder(tmp_path)
    loop_thread = threading.get_ident()
    encoded_on: list[int] = []
    encode = responder.encode

    def recorded(response: ExportResponse) -> bytes:
        encoded_on.append(threading.get_ident())
        return encode(response)

    responder.encode = recorded  # type: ignore[method-assign]
    published: list[str] = []

    class _Client:
        def publish(self, topic: str, payload: bytes, qos: int = 0) -> None:
            published.append(topic)

    server = MqttGatewayExportServer(
        broker_url="mqtt://localhost",
        responder=responder,
        client_factory=lambda **_: None,
    )
    request = _auth().sign(
        {"request_id": "req-1", "export_type": "health", "device_id": "dev-01"},
        message_type="export_request",
    )
    try:
        await server._publish_response(_Client(), json.dumps(request).encode())
        assert published and encoded_on
        assert loop_thread not in encoded_on
    finally:
        await store.close()


def test_a_refusal_is_logged_at_once_when_no_flush_thread_can_start(
    monkeypatch, caplog
):
    bound = IngressBound(EXPORT_REQUEST, clock=_Clock())

    class _NoThreads(threading.Timer):
        def start(self) -> None:
            raise RuntimeError("can't create new thread at interpreter shutdown")

    with caplog.at_level(logging.WARNING, logger="ori.gateway.payload_bounds"):
        bound.admit(b"a" * 20_000)
        monkeypatch.setattr(threading, "Timer", _NoThreads)
        bound.admit(b"a" * 70_000)
        bound.admit(b"a" * 70_000)
    assert bound._flush[PAYLOAD_TOO_LARGE] is None
    assert caplog.text.count("refused 1 message(s)") == 3


@pytest.mark.parametrize(
    "module, helper",
    [
        ("ori.gateway.evidence_inbound", "_log_future_failure"),
        ("ori.gateway.evidence_outbound", "_log_future_failure"),
        ("ori.gateway.export", "_log_future_failure"),
        ("ori.gateway.firmware_telemetry", "_log_background_failure"),
    ],
)
def test_a_cancelled_background_future_is_not_logged_as_a_failure(
    module, helper, caplog
):
    """`concurrent.futures.CancelledError` is an `Exception`; cancelling at
    shutdown is not a failure, but a failure still is."""
    import concurrent.futures
    import importlib

    log = getattr(importlib.import_module(module), helper)
    cancelled: concurrent.futures.Future[None] = concurrent.futures.Future()
    cancelled.cancel()
    failed: concurrent.futures.Future[None] = concurrent.futures.Future()
    failed.set_exception(RuntimeError("a defect"))
    with caplog.at_level(logging.ERROR, logger=module):
        log(cancelled)
        assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []
        log(failed)
    assert [r.levelno for r in caplog.records] == [logging.ERROR]


async def test_a_stalled_store_bounds_the_export_work_in_flight(tmp_path):
    """Requests the rate admits, arriving while the store is held, never wait
    past the in-flight bound; the rest are dropped unread and counted."""
    from ori.gateway.export import EXPORT_IN_FLIGHT_BOUND

    responder, store = await _responder(tmp_path)
    held = asyncio.Event()
    waiting = 0

    async def stalled(**_kwargs: Any) -> Any:
        nonlocal waiting
        waiting += 1
        await held.wait()
        return []

    store.export_sensor_history = stalled  # type: ignore[method-assign]
    published: list[str] = []

    class _Client:
        def publish(self, topic: str, payload: bytes, qos: int = 0) -> None:
            published.append(topic)

    server = MqttGatewayExportServer(
        broker_url="mqtt://localhost",
        responder=responder,
        client_factory=lambda **_: None,
    )
    clock = _Clock()
    server._ingress = IngressBound(EXPORT_REQUEST, clock=clock)
    server._loop = asyncio.get_running_loop()
    gateway = _auth()
    try:
        for index in range(100):
            clock.now += 1.0  # always within the rate
            request = gateway.sign(
                {
                    "request_id": f"req-{index}",
                    "export_type": "sensor_history",
                    "device_id": "dev-01",
                    "since_ms": 0,
                    "until_ms": MAX_INT,
                    "params": {"sensor_id": "main"},
                },
                message_type="export_request",
            )
            message = SimpleNamespace(payload=json.dumps(request).encode())
            await asyncio.to_thread(server._on_message, _Client(), None, message)
        await wait_until(
            lambda: waiting == EXPORT_IN_FLIGHT_BOUND, what="the store to be waited on"
        )
        assert server._slots.taken == EXPORT_IN_FLIGHT_BOUND
        assert server._ingress.refusals()[RATE_EXCEEDED] == 0
        assert (
            server._ingress.refusals()[IN_FLIGHT_EXCEEDED]
            == 100 - EXPORT_IN_FLIGHT_BOUND
        )
        held.set()
        await wait_until(
            lambda: (
                server._slots.taken == 0 and len(published) == EXPORT_IN_FLIGHT_BOUND
            ),
            what="the held requests to be answered and their slots released",
        )
    finally:
        held.set()
        await store.close()


@pytest.mark.usefixtures("_paho")
async def test_a_reasoning_answer_after_the_first_is_never_recorded():
    """It answers nothing pending, so it records nothing, a replay key included."""

    class _Twice(_ReasoningClient):
        def publish(self, _topic: str, payload: bytes, *_args: Any) -> Any:
            request = json.loads(payload)
            for text in ("first", "second"):
                answer = _auth().sign(
                    {
                        "request_id": request["request_id"],
                        "device_id": "dev-01",
                        "action_tier": "A",
                        "text": text,
                    },
                    message_type="reasoning_response",
                )
                self.on_message(
                    self, None, SimpleNamespace(payload=json.dumps(answer).encode())
                )
            return SimpleNamespace(rc=0)

    auth = _auth()
    verified: list[str] = []
    commit = auth.commit

    def counted(message: Any) -> None:
        verified.append(message.payload["text"])
        commit(message)

    auth.commit = counted  # type: ignore[method-assign]
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://localhost",
        device_id="dev-01",
        timeout_ms=1000,
        client_factory=lambda **_: _Twice(None),
        message_auth=auth,
    )
    result = await reasoner.reason("prompt")
    assert result.text == "first"
    assert verified == ["first"]


@pytest.mark.usefixtures("_paho")
async def test_a_reasoning_answer_after_a_timeout_records_nothing():
    """Delivered while the timed-out request's client stops."""

    class _Late(_ReasoningClient):
        def publish(self, _topic: str, payload: bytes, *_args: Any) -> Any:
            self.request = json.loads(payload)
            return SimpleNamespace(rc=0)

        def loop_stop(self) -> None:
            answer = _auth().sign(
                {
                    "request_id": self.request["request_id"],
                    "device_id": "dev-01",
                    "action_tier": "A",
                    "text": "late",
                },
                message_type="reasoning_response",
            )
            self.on_message(
                self, None, SimpleNamespace(payload=json.dumps(answer).encode())
            )

    auth = _auth()
    verified: list[str] = []
    commit = auth.commit

    def counted(message: Any) -> None:
        verified.append(message.payload["text"])
        commit(message)

    auth.commit = counted  # type: ignore[method-assign]
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://localhost",
        device_id="dev-01",
        timeout_ms=50,
        client_factory=lambda **_: _Late(None),
        message_auth=auth,
    )
    with pytest.raises(GatewayReasoningError, match="timeout"):
        await reasoner.reason("prompt")
    assert verified == []


# ── inbound evidence: each session owns what it decides ─────────────────────


def _inbound(
    *, hold: asyncio.Event | None = None, late_error: BaseException | None = None
):
    """A subscriber whose router records what it routes; `{"first":1}` waits on
    *hold*, then raises *late_error* if one is given."""
    router = EvidenceInboundRouter(
        device_id="dev-01", ingest=None, message_auth=_auth()
    )
    routed: list[bytes] = []

    async def route(payload: bytes) -> Any:
        routed.append(payload)
        if hold is not None and payload == b'{"first":1}':
            await hold.wait()
            if late_error is not None:
                raise late_error
        return SimpleNamespace(outcome=None, acknowledgement=None)

    router.route = route  # type: ignore[method-assign]
    subscriber = MqttEvidenceInboundSubscriber(
        broker_url="mqtt://localhost",
        router=router,
        device_id="dev-01",
        client_factory=lambda **_: _AckingClient(),
    )
    return subscriber, routed


def _message(payload: bytes, mid: int) -> SimpleNamespace:
    return SimpleNamespace(payload=payload, mid=mid, qos=1)


def _exhaust(subscriber: Any) -> None:
    subscriber._ingress = IngressBound(EVIDENCE_INBOUND, clock=_Clock())
    for _ in range(INGRESS_RATES[EVIDENCE_INBOUND].burst):
        assert subscriber._ingress.admit(b"{}") is None


async def test_an_oversized_inbound_message_is_released_and_never_routed():
    subscriber, routed = _inbound()
    subscriber._loop = asyncio.get_running_loop()
    client = _AckingClient()
    session = subscriber._begin_session(client)
    maximum = PAYLOAD_MAXIMA[EVIDENCE_INBOUND]

    client.on_message(client, None, _message(b"\xff" * (maximum + 1), 9))
    await quiesce(what="anything the message scheduled")

    assert routed == [] and client.acked == [9]
    assert subscriber._in_flight == 0
    assert not session.redeliver.is_set() and not session.pending


async def test_an_inbound_message_past_the_rate_is_left_with_the_broker():
    subscriber, routed = _inbound()
    subscriber._loop = asyncio.get_running_loop()
    client = _AckingClient()
    session = subscriber._begin_session(client)
    _exhaust(subscriber)

    client.on_message(client, None, _message(b"{}", 3))
    await wait_until(session.redeliver.is_set, what="the session to end for redelivery")

    assert routed == [] and client.acked == []
    # Owed back once the rate refills, never after a failed route's backoff.
    assert session.ended_for() == (False, True)
    # Left with the broker, so not dropped: health counts it in no family.
    families = IngressFamilies()
    families.add(subscriber.ingress)
    assert families.families()[EVIDENCE_INBOUND]["volume_dropped"] == 0
    assert subscriber.ingress.refusals()[REDELIVERY_DUE] == 1


@pytest.mark.parametrize("first, second", [("failed", "rate"), ("rate", "failed")])
async def test_why_a_session_ends_for_redelivery_accumulates(first, second):
    """A later rate drop never erases a failure the reconnect must back off from."""
    subscriber, _ = _inbound()
    loop = asyncio.get_running_loop()
    session = subscriber._begin_session(_AckingClient())

    session.owe(**{first: True})
    session.redeliver_owed(loop)
    session.owe(**{second: True})
    session.redeliver_owed(loop)

    assert session.ended_for() == (True, True)


async def test_a_rate_drop_redelivers_after_the_refill_not_the_failure_backoff(
    monkeypatch,
):
    """Through `_serve`: every round waits the refill time; the failure backoff
    never starts."""
    from ori.gateway.evidence_inbound import _RECONNECT_MIN_S

    subscriber, _ = _inbound()
    subscriber._loop = asyncio.get_running_loop()
    shutdown = asyncio.Event()
    waits: list[float] = []
    rounds = 0

    async def session_ending_for_rate(session: Any, _shutdown: asyncio.Event) -> bool:
        nonlocal rounds
        rounds += 1
        if rounds > 8:
            shutdown.set()
            return False
        session.owe(rate=True)
        session.redeliver_owed(asyncio.get_running_loop())
        return True

    async def recorded(awaitable: Any, timeout: float) -> Any:
        waits.append(timeout)
        task = asyncio.ensure_future(awaitable)
        task.cancel()
        raise asyncio.TimeoutError

    async def closed() -> None:
        pass

    subscriber._connect_and_serve = session_ending_for_rate  # type: ignore[method-assign]
    subscriber.close = closed  # type: ignore[method-assign]
    monkeypatch.setattr(asyncio, "wait_for", recorded)
    await subscriber._serve(shutdown, _RECONNECT_MIN_S)
    assert waits == [refill_seconds(EVIDENCE_INBOUND)] * 8


async def test_while_a_redelivery_is_due_nothing_is_routed_and_everything_is_counted(
    caplog,
):
    """No rate token is spent; an oversized message is still released."""
    subscriber, routed = _inbound()
    loop = asyncio.get_running_loop()
    subscriber._loop = loop
    client = _AckingClient()
    session = subscriber._begin_session(client)
    session.owe(rate=True)
    session.redeliver_owed(loop)
    subscriber._ingress = IngressBound(EVIDENCE_INBOUND, clock=_Clock())
    tokens = subscriber._ingress._tokens
    maximum = PAYLOAD_MAXIMA[EVIDENCE_INBOUND]

    with caplog.at_level(logging.WARNING, logger="ori.gateway.payload_bounds"):
        for mid in range(10):
            client.on_message(client, None, _message(b"{}", mid))
        client.on_message(client, None, _message(b"\xff" * (maximum + 1), 99))
    await quiesce(what="anything the messages scheduled")

    assert routed == [] and client.acked == [99]
    assert subscriber._ingress._tokens == tokens
    assert subscriber._ingress.refusals() == {
        PAYLOAD_TOO_LARGE: 1,
        RATE_EXCEEDED: 0,
        REDELIVERY_DUE: 10,
    }
    assert "redelivery_due" in caplog.text and "payload_too_large" in caplog.text


async def test_a_replaced_sessions_client_reaches_only_its_own_closed_session():
    """A client a close failed to stop goes on calling back: every callback is
    bound to its own session, so the one that replaced it is untouched."""
    subscriber, routed = _inbound()
    subscriber._loop = asyncio.get_running_loop()
    old, new = _AckingClient(), _AckingClient()
    first = subscriber._begin_session(old)
    first.set_connected(True)
    await subscriber.close()  # its loop_stop "failed": the client keeps running
    second = subscriber._begin_session(new)
    second.set_connected(True)
    _exhaust(subscriber)

    old.on_message(old, None, _message(b"{}", 1))
    old.on_message(old, None, _message(b"\xff" * 2_000_000, 2))
    old.on_subscribe(old, None, 1, [0x80], None)
    old.on_disconnect(old, None, 7)
    old.on_connect(old, None, None, 5)
    await quiesce(what="anything the stale callbacks scheduled")

    assert routed == []
    assert subscriber._session is second and subscriber.connected
    assert not second.lost.is_set() and not second.redeliver.is_set()
    assert not second.pending and not second.owed
    assert first.connected is False


async def test_a_session_freed_of_its_slots_by_an_older_sessions_route_reconnects():
    """The slots are every session's, what is owed is the session's own: the
    last slot released, by any route, fires the current session's debt."""
    subscriber, _ = _inbound()
    subscriber._loop = asyncio.get_running_loop()
    subscriber._slots = Slots(1)
    old_session = subscriber._begin_session(_AckingClient())
    assert subscriber._slots.try_take()  # an old session's route in flight
    ticket = _Ticket(old_session)
    ticket.started = True
    await subscriber.close()
    client = _AckingClient()
    current = subscriber._begin_session(client)

    client.on_message(client, None, _message(b"{}", 1))  # no slot: shed and owed
    assert current.owed and subscriber.shed_count == 1
    subscriber._give_back()  # the old route finishes

    await wait_until(current.redeliver.is_set, what="the current session to reconnect")
    assert not old_session.redeliver.is_set()


async def test_a_route_cancelled_before_it_starts_owes_only_its_own_session():
    import concurrent.futures

    subscriber, _ = _inbound()
    subscriber._loop = asyncio.get_running_loop()
    older = subscriber._begin_session(_AckingClient())
    assert subscriber._slots.try_take()
    ticket = _Ticket(older)
    await subscriber.close()
    current = subscriber._begin_session(_AckingClient())

    cancelled: concurrent.futures.Future[None] = concurrent.futures.Future()
    cancelled.cancel()
    subscriber._settled(ticket, cancelled)

    assert older.owed and not current.owed
    assert subscriber._in_flight == 0


@pytest.mark.parametrize("late", ["ack_fails", "saturated"])
async def test_a_route_outliving_its_session_never_touches_the_next_one(
    monkeypatch, late
):
    """Through `serve_until`: a route still running when the broker drops the
    session finishes in the next one, its late failure owed to its own."""
    from ori.security.evidence.executor import EvidenceExecutorSaturatedError
    from tests.evidence.test_inbound_route import _FakeClient

    class _Client(_FakeClient):
        def __init__(self) -> None:
            super().__init__()
            self.live = True
            self.acked: list[Any] = []

        def manual_ack_set(self, _on: bool) -> None:
            pass

        def ack(self, mid: Any, _qos: Any) -> int:
            self.acked.append(mid)
            return 0 if self.live else 4  # paho's MQTT_ERR_NO_CONN

    monkeypatch.setattr("ori.gateway.evidence_inbound._RECONNECT_MIN_S", 0.05)
    monkeypatch.setattr(
        "ori.gateway.evidence_inbound._log_result", lambda _outcome: None
    )
    held = asyncio.Event()
    subscriber, routed = _inbound(
        hold=held,
        late_error=EvidenceExecutorSaturatedError("the worker is full")
        if late == "saturated"
        else None,
    )
    clients: list[_Client] = []

    def factory(**_kwargs: Any) -> _Client:
        clients.append(_Client())
        return clients[-1]

    subscriber._client_factory = factory
    shutdown = asyncio.Event()
    task = asyncio.create_task(subscriber.serve_until(shutdown))
    try:
        await wait_until(lambda: subscriber.connected, what="the first session")
        first_client = clients[0]
        first = subscriber._session
        assert first_client.on_message is not None
        await asyncio.to_thread(
            first_client.on_message, first_client, None, _message(b'{"first":1}', 1)
        )
        await wait_until(lambda: routed == [b'{"first":1}'], what="the first route")
        first_client.live = False
        first_client.drop_session()
        await wait_until(
            lambda: len(clients) == 2 and subscriber.connected, what="the next session"
        )
        second = subscriber._session
        assert second is not None and second is not first
        held.set()
        await wait_until(lambda: subscriber._in_flight == 0, what="the late route")

        assert first is not None and first.owed
        assert not second.owed and not second.pending
        assert not second.redeliver.is_set() and not second.lost.is_set()
        # And the next session still routes what arrives.
        second_client = clients[1]
        assert second_client.on_message is not None
        await asyncio.to_thread(
            second_client.on_message, second_client, None, _message(b'{"next":2}', 2)
        )
        await wait_until(lambda: b'{"next":2}' in routed, what="the next route")
        assert len(clients) == 2
    finally:
        shutdown.set()
        held.set()
        await asyncio.wait_for(task, timeout=10)


async def test_a_callback_paused_across_a_reconnect_owes_only_its_own_session(
    monkeypatch,
):
    """Through `serve_until`: a message callback paused inside rate admission
    while its session is replaced, its failed close leaving the client running,
    resumes owing the session it was bound to. The replacement stays up."""
    from tests.evidence.test_inbound_route import _FakeClient

    entered, release = threading.Event(), threading.Event()
    clients: list[Any] = []

    class _Client(_FakeClient):
        def manual_ack_set(self, _on: bool) -> None:
            pass

        def ack(self, *_args: Any) -> int:
            return 0

        def loop_stop(self) -> None:
            super().loop_stop()
            if self is clients[0]:
                raise OSError("the loop did not stop")

    class _PausedBound:
        def admit(self, _payload: bytes, *, over_rate: str = RATE_EXCEEDED) -> str:
            entered.set()
            release.wait(5)
            return over_rate

    def factory(**_kwargs: Any) -> _Client:
        clients.append(_Client())
        return clients[-1]

    monkeypatch.setattr("ori.gateway.evidence_inbound._RECONNECT_MIN_S", 0.02)
    subscriber, routed = _inbound()
    subscriber._client_factory = factory
    subscriber._ingress = _PausedBound()  # type: ignore[assignment]
    shutdown = asyncio.Event()
    task = asyncio.create_task(subscriber.serve_until(shutdown))
    paused: threading.Thread | None = None
    try:
        await wait_until(lambda: subscriber.connected, what="the first session")
        old = clients[0]
        first = subscriber._session
        paused = threading.Thread(
            target=old.on_message, args=(old, None, _message(b"{}", 1))
        )
        paused.start()
        await asyncio.to_thread(entered.wait, 5)
        old.drop_session()
        await wait_until(
            lambda: len(clients) == 2 and subscriber.connected, what="the next session"
        )
        current = subscriber._session
        assert current is not None and current is not first
        release.set()
        await asyncio.to_thread(paused.join, 5)
        assert first is not None
        # Decided in the callback's thread: with no slot taken, what it owes
        # is settled on the session it was bound to before the join returns.
        assert first.pending, "the resumed callback owed another session"
        # Long enough for a redelivery the loop was handed to have run.
        await asyncio.sleep(0.1)

        assert subscriber._session is current and subscriber.connected
        assert not current.owed and not current.pending
        assert not current.redeliver.is_set() and not current.lost.is_set()
        assert clients[1].loop_stopped == 0 and len(clients) == 2
        assert routed == []
    finally:
        release.set()
        if paused is not None:
            await asyncio.to_thread(paused.join, 5)
        shutdown.set()
        await asyncio.wait_for(task, timeout=10)


async def test_both_evidence_routes_count_their_in_flight_refusals():
    """The inbound route leaves the message with the broker, so it is owed a
    redelivery; the outbound acknowledgement is dropped."""
    from ori.gateway.evidence_inbound import INBOUND_IN_FLIGHT_BOUND
    from ori.gateway.evidence_outbound import ACK_IN_FLIGHT_BOUND

    subscriber, _ = _inbound()
    subscriber._loop = asyncio.get_running_loop()
    client = _AckingClient()
    subscriber._begin_session(client)
    subscriber._slots = SimpleNamespace(  # type: ignore[assignment]
        try_take=lambda: False, taken=INBOUND_IN_FLIGHT_BOUND
    )
    client.on_message(client, None, _message(b"{}", 1))
    assert client.acked == []
    assert subscriber._ingress.refusals()[REDELIVERY_DUE] == 1
    assert subscriber._ingress.refusals().get(IN_FLIGHT_EXCEEDED, 0) == 0

    publisher = MqttEvidenceOutboundPublisher(
        broker_url="mqtt://localhost",
        router=_AckRouter(),  # type: ignore[arg-type]
        device_id="dev-01",
        outbox=None,  # type: ignore[arg-type]
        client_factory=lambda **_: None,
    )
    publisher._loop = asyncio.get_running_loop()
    publisher._ack_slots = SimpleNamespace(  # type: ignore[assignment]
        try_take=lambda: False, taken=ACK_IN_FLIGHT_BOUND
    )
    publisher._on_message(None, None, SimpleNamespace(payload=b"{}"))
    assert publisher._ingress.refusals()[IN_FLIGHT_EXCEEDED] == 1
    assert publisher.acks_shed == 1


async def test_a_closed_sessions_message_is_left_with_the_broker_even_within_the_rate():
    """Its session decides nothing more: not routed, counted, and redelivered
    by the broker on the session that replaced it."""
    subscriber, routed = _inbound()
    subscriber._loop = asyncio.get_running_loop()
    old = _AckingClient()
    subscriber._begin_session(old)
    await subscriber.close()
    subscriber._begin_session(_AckingClient())

    old.on_message(old, None, _message(b"{}", 1))
    await quiesce(what="anything the message scheduled")

    assert routed == [] and old.acked == []
    assert subscriber._in_flight == 0
    assert subscriber._ingress.refusals()[REDELIVERY_DUE] == 1


async def test_a_shed_message_is_never_stranded_by_a_slot_freed_meanwhile():
    """The last route released its slot between the failed take and the owe:
    that release found nothing owed, so the owe itself settles the reconnect."""
    subscriber, _ = _inbound()
    subscriber._loop = asyncio.get_running_loop()
    subscriber._slots = Slots(1)
    assert subscriber._slots.try_take()
    client = _AckingClient()
    session = subscriber._begin_session(client)
    take = subscriber._slots.try_take

    def full_then_freed() -> bool:
        taken = take()
        subscriber._give_back()  # the last route finishes, owing nothing yet
        return taken

    subscriber._slots.try_take = full_then_freed  # type: ignore[method-assign]
    client.on_message(client, None, _message(b"{}", 1))

    await wait_until(
        session.redeliver.is_set, what="the reconnect for the shed message"
    )
    assert subscriber._in_flight == 0


async def test_an_artifact_is_never_answered_on_a_closed_session():
    subscriber, _ = _inbound()
    subscriber._loop = asyncio.get_running_loop()

    async def answered(_payload: bytes) -> Any:
        return SimpleNamespace(
            outcome=IngestOutcome(artifact=ARTIFACT_CUSTODY, state="accepted"),
            acknowledgement={"outcome": "applied"},
        )

    subscriber._router.route = answered  # type: ignore[method-assign]
    client = _AckingClient()
    subscriber._begin_session(client)
    await subscriber.close()

    await subscriber._route_admitted(b"{}")
    assert client.published == []


async def test_a_cut_export_page_continues_from_where_it_was_cut(tmp_path, monkeypatch):
    """Through `_publish_response`: a page asked for at a non-zero token and cut
    to fit continues from its own first item plus what it held."""
    rows = [{"id": index, "pad": "x" * 400} for index in range(40)]

    class _Store:
        async def export_action_log(self, **kwargs: Any) -> list[dict[str, Any]]:
            return rows[: kwargs["limit"]]

    responder = GatewayExportResponder(
        device_id="dev-01",
        state_store=_Store(),
        health_snapshot_provider=dict,
        message_auth=_auth(),
    )
    monkeypatch.setitem(PAYLOAD_MAXIMA, EXPORT_RESPONSE, 4096)
    published: list[bytes] = []

    class _Client:
        def publish(self, topic: str, payload: bytes, qos: int = 0) -> None:
            published.append(payload)

    server = MqttGatewayExportServer(
        broker_url="mqtt://localhost",
        responder=responder,
        client_factory=lambda **_: None,
    )
    request = _auth().sign(
        {
            "request_id": "req-1",
            "export_type": "action_log",
            "device_id": "dev-01",
            "limit": 20,
            "page_token": "5",
        },
        message_type="export_request",
    )
    await server._publish_response(_Client(), json.dumps(request).encode())

    (body,) = published
    assert len(body) <= 4096
    page = json.loads(body)
    held = len(page["items"])
    assert 1 <= held < 20
    assert [item["id"] for item in page["items"]] == list(range(5, 5 + held))
    assert page["next_page_token"] == str(5 + held)
    assert page["complete"] is False


@pytest.mark.usefixtures("_paho")
def test_a_reasoning_timeout_the_contract_admits_is_kept_to_a_day():
    from ori.gateway.reasoning import MAX_GATEWAY_REASONING_TIMEOUT_MS

    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://localhost",
        device_id="dev-01",
        timeout_ms=10**320,
        client_factory=lambda **_: None,
    )
    assert reasoner._timeout_ms == MAX_GATEWAY_REASONING_TIMEOUT_MS
    assert reasoner._timeout_ms / 1000.0 == 86_400.0


@pytest.mark.parametrize(
    "interval, expected",
    [
        (float("inf"), 30.0),
        (float("nan"), 30.0),
        (1e300, 86_400.0),
        (0.5, 1.0),
        (45.0, 45.0),
    ],
)
def test_a_heartbeat_interval_the_contract_admits_always_fires_again(
    interval, expected
):
    publisher = MqttRuntimeNodeHeartbeatPublisher(
        broker_url="mqtt://localhost",
        device_id="dev-01",
        health_snapshot_provider=dict,
        interval_seconds=interval,
        client_factory=lambda **_: None,
    )
    assert publisher._interval_seconds == expected


def test_a_key_a_previous_release_stored_lives_until_its_envelope_is_stale(
    tmp_path, monkeypatch
):
    """Written as receipt plus the old window, which ended before the envelope
    could no longer pass; after the restart its expiry is decided again from
    its own signing time, kept through a second restart."""
    import sqlite3

    from ori.config import GatewayConfig
    from ori.gateway.envelope_auth import (
        build_gateway_message_auth as _build_gateway_message_auth,
    )

    clock = [1_000_000_000]
    monkeypatch.setattr("ori.security.gateway_messages.now_ms", lambda: clock[0])
    skew, received = 300_000, 1_000_000_000
    db = tmp_path / "state.db"
    signer = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret=SECRET),
        replay_cache=cache_for(GatewayMessageAuthConfig(shared_secret=SECRET)),
    )
    payload = signer.sign(
        {"device_id": "dev-01", "request_id": "r1"},
        message_type="export_request",
        signed_at_ms=received + skew,
    )
    # The previous release's row: the key and receipt plus replay_ttl_ms
    # (300000), in the table as it created it.
    key = "\n".join(
        [
            "export_request",
            "dev-01",
            "r1",
            str(received + skew),
            payload["auth"]["signature"],
        ]
    )
    with sqlite3.connect(db) as connection:
        connection.execute(
            "CREATE TABLE gateway_replay_cache ("
            "key TEXT PRIMARY KEY, seen_until_ms INTEGER NOT NULL)"
        )
        connection.execute(
            "INSERT INTO gateway_replay_cache VALUES (?, ?)", (key, received + 300_000)
        )

    monkeypatch.setenv("GATEWAY_SHARED_SECRET", SECRET)
    for _restart in range(2):
        config: Any = SimpleNamespace(
            database_path=str(db),
            gateway=GatewayConfig(
                enabled=True,
                broker_url="mqtt://broker.local",
                auth={
                    "enabled": True,
                    "shared_secret_env": "GATEWAY_SHARED_SECRET",
                    "max_clock_skew_ms": skew,
                    "replay_ttl_ms": 300_000,
                    "persistent_replay_cache": True,
                },
            ),
        )
        auth = _build_gateway_message_auth(config)
        assert auth is not None
        for replayed_at in (received + 300_000, received + 2 * skew):
            with pytest.raises(Exception, match="replay_detected"):
                auth.verify(
                    payload,
                    message_type="export_request",
                    expected_device_id="dev-01",
                    now_ms_value=replayed_at,
                )
        auth._replay_cache.close()
        auth._signing_clock.stop()
    with sqlite3.connect(db) as connection:
        assert connection.execute(
            "SELECT seen_until_ms, signed_at_ms FROM gateway_replay_cache"
        ).fetchone() == (received + 2 * skew + 1, received + skew)


def _restarting_auth(db: Any, *, skew: int, monkeypatch: Any) -> Any:
    from ori.config import GatewayConfig
    from ori.gateway.envelope_auth import (
        build_gateway_message_auth as _build_gateway_message_auth,
    )

    monkeypatch.setenv("GATEWAY_SHARED_SECRET", SECRET)
    config: Any = SimpleNamespace(
        database_path=str(db),
        gateway=GatewayConfig(
            enabled=True,
            broker_url="mqtt://broker.local",
            auth={
                "enabled": True,
                "shared_secret_env": "GATEWAY_SHARED_SECRET",
                "max_clock_skew_ms": skew,
                "replay_ttl_ms": 300_000,
                "persistent_replay_cache": True,
            },
        ),
    )
    auth = _build_gateway_message_auth(config)
    assert auth is not None and auth._replay_cache.persistent
    return auth


@pytest.mark.parametrize("skew", [2**62, 2**80, 10**309])
def test_the_widest_skew_survives_a_restart(tmp_path, monkeypatch, skew):
    """A key re-derived on load is bounded as one recorded live is."""
    from ori.utils.time_utils import now_ms

    db = tmp_path / "state.db"
    first = _restarting_auth(db, skew=skew, monkeypatch=monkeypatch)
    # Signed a millisecond before the restart, whatever the signing clock reads.
    signed = first.sign(
        {"device_id": "dev-01", "request_id": "r1"},
        message_type="export_request",
        signed_at_ms=now_ms() - 1,
    )
    first.verify(signed, message_type="export_request", expected_device_id="dev-01")
    first._replay_cache.close()

    restarted = _restarting_auth(db, skew=skew, monkeypatch=monkeypatch)
    ((expires, _signed),) = restarted._replay_cache._held.values()
    assert expires < 2**63
    # Signed before this start, so the start floor refuses it first.
    with pytest.raises(Exception, match="before_replay_floor"):
        restarted.verify(
            signed,
            message_type="export_request",
            expected_device_id="dev-01",
            now_ms_value=now_ms(),
        )


def test_the_stored_and_the_in_memory_expiry_agree_to_the_millisecond(tmp_path):
    import sqlite3

    from ori.security.gateway_messages import GatewayReplayCache

    db = tmp_path / "replay.db"
    cache = GatewayReplayCache(ttl_ms=100, max_skew_ms=0, db_path=str(db), start_ms=0)
    assert _admit(cache, "k", 0) is None  # expires at 100

    def stored() -> tuple[int, int | None]:
        with sqlite3.connect(db) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM gateway_replay_cache WHERE key = 'k'"
            ).fetchone()[0]
            floor = connection.execute(
                "SELECT floor_ms FROM gateway_replay_floor"
            ).fetchone()
        return count, floor[0] if floor else None

    assert _admit(cache, "a", 99) is None
    assert stored() == (1, None) and cache.check("k", signed_at_ms=0) == (
        "replay_detected"
    )
    assert _admit(cache, "b", 100) is None
    assert stored() == (0, 1) and "k" not in cache._held
    assert cache.floor_ms() == 1


def test_a_loaded_key_with_no_signing_time_keeps_its_stored_expiry(tmp_path):
    import sqlite3

    from ori.security.gateway_messages import GatewayReplayCache

    db = tmp_path / "replay.db"
    GatewayReplayCache(ttl_ms=100, max_skew_ms=50, db_path=str(db))
    with sqlite3.connect(db) as connection:
        connection.execute(
            "INSERT INTO gateway_replay_cache (key, seen_until_ms) VALUES (?, ?)",
            ("foreign-key-without-fields", 12_345),
        )
    loaded = GatewayReplayCache(ttl_ms=100, max_skew_ms=50, db_path=str(db))
    # The latest signing time that expiry allows, so its drop raises the floor
    # at least as far as its real one would.
    assert loaded._held == {"foreign-key-without-fields": (12_345, 12_294)}


def test_the_expiry_heap_never_outgrows_the_live_keys():
    from ori.security.gateway_messages import GatewayReplayCache

    cache = GatewayReplayCache(ttl_ms=10, max_skew_ms=0, max_entries=100, start_ms=0)
    for index in range(20_000):
        assert _admit(cache, f"k{index}", index) is None
        assert len(cache._held) <= 10
        assert len(cache._expiries) <= 2 * len(cache._held) + 64
        assert len(cache._signings) <= 2 * len(cache._held) + 64
    # Full of live keys, it evicts instead: neither heap outgrows it either.
    full = GatewayReplayCache(ttl_ms=10**9, max_skew_ms=0, max_entries=50, start_ms=0)
    for index in range(20_000):
        assert _admit(full, f"k{index}", index) is None
        assert len(full._held) <= 50
        assert len(full._expiries) <= 2 * len(full._held) + 64
        assert len(full._signings) <= 2 * len(full._held) + 64


@pytest.mark.parametrize("broadcast", [False, True])
@pytest.mark.parametrize("own_cache", [False, True])
@pytest.mark.parametrize(
    "ttl_ms, signed_offset, expected_offset",
    [
        # The configured window from receipt, as before: never shorter.
        (300_000, -300_000, 300_000),
        (3_600_000, 0, 3_600_000),
        # Extended until the envelope is stale when that is later.
        (1_000, 300_000, 600_001),
        (300_000, 300_000, 600_001),
    ],
)
def test_a_key_is_kept_as_before_and_until_its_envelope_is_stale(
    tmp_path, monkeypatch, broadcast, own_cache, ttl_ms, signed_offset, expected_offset
):
    skew, received = 300_000, 1_000_000_000
    # Each cache starts at the receiver's clock, before anything is signed.
    monkeypatch.setattr("ori.security.gateway_messages.now_ms", lambda: 0)
    config = GatewayMessageAuthConfig(
        shared_secret=SECRET, max_skew_ms=skew, replay_ttl_ms=ttl_ms
    )
    if own_cache:
        auth = GatewayMessageAuthenticator(config)
    else:
        auth = GatewayMessageAuthenticator(
            config,
            replay_cache=GatewayReplayCache(
                ttl_ms=ttl_ms, max_skew_ms=skew, db_path=str(tmp_path / "replay.db")
            ),
        )
    signed_at = received + signed_offset
    if broadcast:
        payload = auth.sign(
            {"status": "healthy"},
            message_type="gateway.heartbeat",
            signed_at_ms=signed_at,
        )
        auth.verify_broadcast(
            payload, message_type="gateway.heartbeat", now_ms_value=received
        )
    else:
        payload = auth.sign(
            {"device_id": "dev-01", "request_id": "r1"},
            message_type="export_request",
            signed_at_ms=signed_at,
        )
        auth.verify(
            payload,
            message_type="export_request",
            expected_device_id="dev-01",
            now_ms_value=received,
        )
    ((expires, _signed),) = auth._replay_cache._held.values()
    assert expires == received + expected_offset


def test_a_restart_under_the_same_settings_keeps_a_stored_key_as_it_was(tmp_path):
    """Decided again from its stored signing and receipt times."""
    received, skew, ttl = 1_000_000_000, 300_000, 3_600_000
    db = tmp_path / "replay.db"
    first = GatewayReplayCache(
        ttl_ms=ttl, max_skew_ms=skew, db_path=str(db), start_ms=0
    )
    key = f"export_request\ndev-01\nr1\n{received}\nhmac-sha256:{'0' * 64}"
    assert _admit(first, key, received) is None
    first.close()
    loaded = GatewayReplayCache(
        ttl_ms=ttl, max_skew_ms=skew, db_path=str(db), start_ms=0
    )
    assert loaded._held[key] == (received + ttl, received)


def test_a_key_signed_beyond_any_clock_is_refused_as_future(tmp_path, monkeypatch):
    """The skew is bounded where a clock never reaches, so an envelope signed
    past that is refused, and no signing time or floor leaves SQLite's range."""
    db = tmp_path / "state.db"
    first = _restarting_auth(db, skew=2**80, monkeypatch=monkeypatch)
    signed = first.sign(
        {"device_id": "dev-01", "request_id": "far"},
        message_type="export_request",
        signed_at_ms=2**70,
    )
    with pytest.raises(Exception, match="future_timestamp"):
        first.verify(signed, message_type="export_request", expected_device_id="dev-01")
    assert first._replay_cache._held == {}


def test_a_replay_cache_never_grows_past_its_ceiling():
    from ori.gateway.payload_bounds import REPLAY_CACHE_CEILING

    assert replay_capacity(86_400_000) == REPLAY_CACHE_CEILING
    assert replay_capacity(2**53) == REPLAY_CACHE_CEILING
    assert replay_capacity(600_001) < REPLAY_CACHE_CEILING


def test_every_gateway_route_built_by_the_runtime_shares_one_envelope_state():
    """Read from the startup stages themselves: every route builder is handed
    the one replay cache and signing clock, so the table is held once per
    process, not once per route, and one clock signs for every signer."""
    import ast

    from tests.package_layout import runtime_methods, runtime_tree

    builders = {
        "build_gateway_reasoner",
        "_start_gateway_export_responder_if_enabled",
        "build_gateway_heartbeat_subscriber",
        "build_evidence_inbound_subscriber",
        "build_evidence_outbound_publisher",
        "build_runtime_node_heartbeat_publisher",
    }
    # The stages, and any method a stage hands its startup context to.
    stages = [
        node
        for name, node in runtime_methods().items()
        if name.startswith("_stage_")
        or [arg.arg for arg in node.args.args[1:2]] == ["context"]
    ]
    assert stages, "OriRuntime has no startup stages to read"

    def the_envelope_state(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "context"
            and node.attr == "gateway_envelope_state"
        )

    called: dict[str, bool] = {}
    built = []
    for stage in stages:
        for node in ast.walk(stage):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "id", None) or getattr(
                    node.func, "attr", None
                )
                if name in builders:
                    called[name] = called.get(name, True) and any(
                        the_envelope_state(arg)
                        for arg in [*node.args, *(k.value for k in node.keywords)]
                    )
            # Built once: no second cache assigned anywhere in startup.
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and any(
                    the_envelope_state(t)
                    or getattr(t, "id", None) == "gateway_envelope_state"
                    for t in node.targets
                )
            ):
                built.append(node)
    assert called == dict.fromkeys(builders, True)
    assert len(built) == 1
    # And every route builder hands its cache on: no authenticator in the
    # runtime is built without the cache its builder was given.
    for function in ast.walk(runtime_tree()):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Call)
                and getattr(node.func, "id", None) == "_build_gateway_message_auth"
            ):
                forwarded = [*node.args[1:], *(k.value for k in node.keywords)]
                assert any(
                    isinstance(arg, ast.Name) and arg.id == "envelope_state"
                    for arg in forwarded
                ), f"{function.name} builds an authenticator without its cache"


def test_a_route_builder_uses_the_envelope_state_it_is_given(monkeypatch):
    from ori.config import GatewayConfig
    from ori.gateway.envelope_auth import (
        build_gateway_envelope_state as _build_gateway_envelope_state,
    )
    from ori.gateway.envelope_auth import (
        build_gateway_message_auth as _build_gateway_message_auth,
    )

    monkeypatch.setenv("GATEWAY_SHARED_SECRET", SECRET)
    config: Any = SimpleNamespace(
        database_path="",
        gateway=GatewayConfig(
            enabled=True,
            broker_url="mqtt://broker.local",
            auth={
                "enabled": True,
                "shared_secret_env": "GATEWAY_SHARED_SECRET",
                "max_clock_skew_ms": 300_000,
                "replay_ttl_ms": 300_000,
                "persistent_replay_cache": False,
            },
        ),
    )
    shared = _build_gateway_envelope_state(config)
    assert shared is not None
    first = _build_gateway_message_auth(config, shared)
    second = _build_gateway_message_auth(config, shared)
    assert first is not None and second is not None
    assert first._replay_cache is shared.replay_cache
    assert second._replay_cache is shared.replay_cache
    assert first._signing_clock is shared.signing_clock
    assert second._signing_clock is shared.signing_clock


# ── Payload Member Rule refusals are recorded with their reason ────────────

_REPEATED = b'{"request_id":"r","request_id":"r"}'


async def test_a_refused_heartbeat_is_recorded_with_its_reason():
    tracker = _Tracker()
    subscriber = MqttGatewayHeartbeatSubscriber(
        broker_url="mqtt://localhost",
        posture_tracker=tracker,  # type: ignore[arg-type]
        device_id="dev-01",
        client_factory=lambda **_: None,
    )
    subscriber._loop = asyncio.get_running_loop()
    subscriber._on_message(None, None, SimpleNamespace(payload=_REPEATED))
    await quiesce(what="the work the message scheduled")
    assert tracker.recorded == []
    assert subscriber._ingress.refusals()[DUPLICATE_MEMBER] == 1


async def test_a_refused_export_request_is_recorded_with_its_reason():
    responder = GatewayExportResponder(
        device_id="dev-01", state_store=None, health_snapshot_provider=dict
    )
    server = MqttGatewayExportServer(
        broker_url="mqtt://localhost",
        responder=responder,
        client_factory=lambda **_: None,
    )
    server._loop = asyncio.get_running_loop()
    published: list[str] = []

    class _Client:
        def publish(self, topic: str, payload: bytes, qos: int = 0) -> None:
            published.append(topic)

    message = SimpleNamespace(payload=_REPEATED)
    await asyncio.to_thread(server._on_message, _Client(), None, message)
    await wait_until(lambda: server._slots.taken == 0, what="the request to settle")
    assert published == []
    assert server._ingress.refusals()[DUPLICATE_MEMBER] == 1


@pytest.mark.usefixtures("_paho")
async def test_a_refused_reasoning_response_is_recorded_with_its_reason():
    def answer(request: dict[str, Any]) -> bytes:
        return (
            json.dumps(
                {"request_id": request["request_id"], "action_tier": "A", "text": ""}
            ).encode()[:-1]
            + b',"text":"again"}'
        )

    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://localhost",
        device_id="dev-01",
        timeout_ms=100,
        client_factory=lambda **_: _ReasoningClient(answer),
    )
    with pytest.raises(GatewayReasoningError, match="timeout"):
        await reasoner.reason("prompt")
    assert reasoner._ingress.refusals()[DUPLICATE_MEMBER] == 1


async def test_a_refused_outbound_acknowledgement_is_recorded_with_its_reason():
    router = EvidenceOutboundAckRouter(
        device_id="dev-01",
        outbox=None,  # type: ignore[arg-type]
        message_auth=_auth(),
    )
    publisher = MqttEvidenceOutboundPublisher(
        broker_url="mqtt://localhost",
        router=router,
        device_id="dev-01",
        outbox=None,  # type: ignore[arg-type]
        client_factory=lambda **_: None,
    )
    await publisher._apply_ack(_REPEATED)
    assert publisher._ingress.refusals()[DUPLICATE_MEMBER] == 1


async def test_a_refused_inbound_message_is_recorded_with_its_reason():
    subscriber, _ = _inbound()
    subscriber._router = EvidenceInboundRouter(
        device_id="dev-01", ingest=None, message_auth=_auth()
    )
    subscriber._loop = asyncio.get_running_loop()
    await subscriber._route_admitted(_REPEATED)
    assert subscriber._ingress.refusals()[DUPLICATE_MEMBER] == 1
