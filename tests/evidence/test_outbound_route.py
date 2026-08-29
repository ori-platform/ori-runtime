# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The route carrying evidence artifacts to the courier, per gateway-api/v1.

Retention is the property under test. A PUBACK retires nothing; a `queued`
acknowledgement retires a checkpoint but never an envelope; and only bytes the
gateway can verify were signed by this device ever leave.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import pathlib
import threading
from typing import Any, cast

import pytest

from ori.gateway.evidence_outbound import (
    ARTIFACT_DELIVERY_ENVELOPE,
    EVIDENCE_OUTBOUND_ACK_MESSAGE_TYPE,
    RETRY_BACKOFF_MAX_S,
    RETRY_INTERVAL_S,
    ROUTED_APPLIED,
    ROUTED_IGNORED,
    ROUTED_REFUSED,
    EvidenceOutboundAckRouter,
    MqttEvidenceOutboundPublisher,
    artifact_digest,
    carriage_payload,
    retry_due,
)
from ori.security.evidence.bound import BoundOutboundQueue
from ori.security.evidence.chain import EvidenceChain, attestation_event_id
from ori.security.evidence.device_key import EvidenceDeviceKey
from ori.security.evidence.executor import EvidenceExecutor
from ori.security.evidence.ledger import (
    OUTBOX_CHECKPOINT,
    RETIRE_QUEUED,
    RETIRE_REFUSED,
    EvidenceDeliveryLedger,
)
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
)

DEVICE = "energy-monitor-ikeja-01"
ENVELOPE_SECRET = "site-envelope-secret"
VECTOR = (
    pathlib.Path(__file__).resolve().parent.parent
    / "vectors"
    / "gateway_api"
    / "outbound-evidence.json"
)


class Rig:
    """A real ledger on its own thread, reached only through the façade."""

    def __init__(self, tmp_path: pathlib.Path) -> None:
        self.executor = EvidenceExecutor()
        self.key = EvidenceDeviceKey.load_or_create(tmp_path / "k.key", "secret")
        self.chain = EvidenceChain(tmp_path / "chain.db", self.key, DEVICE)
        self.ledger = self.executor.run(
            lambda: EvidenceDeliveryLedger(
                tmp_path / "ledger.db",
                self.key,
                DEVICE,
                anchor_epoch_id="epoch-1",
                key_id="key-1",
            )
        )
        self.outbox = BoundOutboundQueue(self.executor, self.ledger)

    def seal(self, action_log_id: int) -> dict[str, Any]:
        row = self.chain.append(
            event_id=attestation_event_id(DEVICE, action_log_id),
            event_type="SAFETY_ACTION_EXECUTED",
            emitted_at_ms=1751500800000,
            payload={"kind": "runtime_action", "action_log_id": action_log_id},
            created_at_ms=1751500800040,
        )
        return dict(
            self.executor.run(self.ledger.seal, row, sealed_at_ms=1751500800500)
        )

    def queue_checkpoint(self) -> dict[str, Any]:
        return dict(self.executor.run(self.ledger.issue_checkpoint, issued_at_ms=5))

    def envelope(self, local_seq: int) -> dict[str, Any]:
        row = self.executor.run(self.ledger.find_by_local_seq, local_seq)
        assert row is not None
        return dict(row)

    def artifact(self, digest: str) -> dict[str, Any] | None:
        row = self.executor.run(self.ledger.find_artifact, digest)
        return None if row is None else dict(row)

    def failures(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.executor.run(self.ledger.local_failures)]

    def close(self) -> None:
        self.chain.close()
        self.executor.close(teardown=self.ledger.close)


@pytest.fixture
def rig(tmp_path):
    rig = Rig(tmp_path)
    yield rig
    rig.close()


def _auth(secret: str = ENVELOPE_SECRET) -> GatewayMessageAuthenticator:
    return GatewayMessageAuthenticator(GatewayMessageAuthConfig(shared_secret=secret))


def _ack(
    artifact_type: str,
    digest: str,
    *,
    outcome: str = "queued",
    reason: str = "",
    device_id: str = DEVICE,
    secret: str | None = ENVELOPE_SECRET,
    signed_at_ms: int = 1787000003000,
) -> dict[str, Any]:
    payload = {
        "device_id": device_id,
        "artifact_type": artifact_type,
        "artifact_digest": digest,
        "outcome": outcome,
        "reason": reason,
        "acknowledged_at_ms": 1787000003000,
    }
    if secret is None:
        return payload
    return _auth(secret).sign(
        payload,
        message_type=EVIDENCE_OUTBOUND_ACK_MESSAGE_TYPE,
        signed_at_ms=signed_at_ms,
    )


def _router(rig: Rig, *, authenticated: bool = True) -> EvidenceOutboundAckRouter:
    return EvidenceOutboundAckRouter(
        device_id=DEVICE,
        outbox=rig.outbox,
        message_auth=_auth() if authenticated else None,
        now=lambda: 1787000004000,
    )


# --------------------------------------------------------------------------
# Carriage
# --------------------------------------------------------------------------


def test_the_carriage_reproduces_the_published_fixture():
    vector = json.loads(VECTOR.read_text())
    case = next(c for c in vector["cases"] if c["name"] == "checkpoint_carriage")
    wire = bytes.fromhex(case["decoded_artifact_hex"])
    payload = json.loads(carriage_payload(DEVICE, "checkpoint", wire))
    assert payload == case["payload"]
    assert base64.b64decode(payload["artifact_b64"], validate=True) == wire
    assert artifact_digest(wire) == case["artifact_digest"]


def test_the_carriage_refuses_a_type_the_courier_does_not_accept():
    with pytest.raises(ValueError):
        carriage_payload(DEVICE, "commissioning_authorization", b"{}")


def test_retry_backoff_doubles_and_caps():
    assert retry_due(0, None, at_ms=0)
    assert not retry_due(1, 0, at_ms=int(RETRY_INTERVAL_S * 1000) - 1)
    assert retry_due(1, 0, at_ms=int(RETRY_INTERVAL_S * 1000))
    assert not retry_due(2, 0, at_ms=int(RETRY_INTERVAL_S * 2000) - 1)
    assert retry_due(2, 0, at_ms=int(RETRY_INTERVAL_S * 2000))
    assert not retry_due(20, 0, at_ms=int(RETRY_BACKOFF_MAX_S * 1000) - 1)
    assert retry_due(20, 0, at_ms=int(RETRY_BACKOFF_MAX_S * 1000))


# --------------------------------------------------------------------------
# Acknowledgements
# --------------------------------------------------------------------------


async def test_the_published_acknowledgement_retires_the_published_checkpoint(rig):
    """The vendored gateway-api fixture, end to end through the router."""
    vector = json.loads(VECTOR.read_text())
    carriage = next(c for c in vector["cases"] if c["name"] == "checkpoint_carriage")
    ack = next(c for c in vector["cases"] if c["name"] == "queued_acknowledgement")
    wire = bytes.fromhex(carriage["decoded_artifact_hex"])
    queued = rig.executor.run(
        rig.ledger.queue_artifact, OUTBOX_CHECKPOINT, wire, created_at_ms=1
    )
    assert queued["artifact_digest"] == ack["payload"]["artifact_digest"]

    router = EvidenceOutboundAckRouter(
        device_id=DEVICE,
        outbox=rig.outbox,
        message_auth=GatewayMessageAuthenticator(
            GatewayMessageAuthConfig(shared_secret=vector["shared_secret"])
        ),
        now=lambda: ack["signed_at_ms"] + 1,
    )
    routed = await router.handle_ack(json.dumps(ack["payload"]).encode())
    assert routed.outcome == ROUTED_APPLIED, routed
    retired = rig.artifact(queued["artifact_digest"])
    assert retired is not None and retired["retire_outcome"] == RETIRE_QUEUED


async def test_a_queued_acknowledgement_retires_a_checkpoint_once(rig):
    queued = rig.queue_checkpoint()
    router = _router(rig)
    first_ack = _ack("checkpoint", queued["artifact_digest"])
    first = await router.handle_ack(first_ack)
    assert first.outcome == ROUTED_APPLIED
    replayed = await router.handle_ack(first_ack)
    assert replayed.outcome == ROUTED_REFUSED, "a byte-identical replay is refused"
    # A republish draws a newly signed acknowledgement from the courier.
    again = await router.handle_ack(
        _ack("checkpoint", queued["artifact_digest"], signed_at_ms=1787000003500)
    )
    assert again.outcome == ROUTED_APPLIED
    artifact = rig.artifact(queued["artifact_digest"])
    assert artifact is not None
    assert artifact["retired_at_ms"] == 1787000004000
    assert artifact["retire_outcome"] == RETIRE_QUEUED


async def test_a_queued_acknowledgement_never_marks_custody_on_an_envelope(rig):
    sealed = rig.seal(1)
    routed = await _router(rig).handle_ack(
        _ack(ARTIFACT_DELIVERY_ENVELOPE, sealed["envelope_digest"])
    )
    assert routed.outcome == ROUTED_APPLIED
    after = rig.envelope(int(sealed["local_seq"]))
    assert after["custody_state"] == "none"
    assert after["attempts"] == 0
    assert (await rig.outbox.awaiting_custody()) != []


async def test_a_full_queue_defers_without_dropping(rig):
    sealed = rig.seal(1)
    queued = rig.queue_checkpoint()
    router = _router(rig)
    for artifact_type, digest in (
        (ARTIFACT_DELIVERY_ENVELOPE, sealed["envelope_digest"]),
        ("checkpoint", queued["artifact_digest"]),
    ):
        routed = await router.handle_ack(
            _ack(artifact_type, digest, outcome="refused", reason="queue_full")
        )
        assert routed.outcome == ROUTED_APPLIED and routed.reason == "queue_full"
    envelope = rig.envelope(int(sealed["local_seq"]))
    assert envelope["attempts"] == 1 and envelope["last_failure"] == "queue_full"
    assert envelope["custody_state"] == "none"
    artifact = rig.artifact(queued["artifact_digest"])
    assert artifact is not None
    assert artifact["retired_at_ms"] is None and artifact["attempts"] == 1
    assert rig.failures() == []


@pytest.mark.parametrize("reason", ["malformed", "binding_mismatch"])
async def test_a_refused_envelope_is_recorded_as_a_local_delivery_failure(rig, reason):
    sealed = rig.seal(1)
    routed = await _router(rig).handle_ack(
        _ack(
            ARTIFACT_DELIVERY_ENVELOPE,
            sealed["envelope_digest"],
            outcome="refused",
            reason=reason,
        )
    )
    assert routed.outcome == ROUTED_APPLIED
    failures = rig.failures()
    assert [f["local_seq"] for f in failures] == [sealed["local_seq"]]
    assert failures[0]["reason"] == "refused"
    assert rig.envelope(int(sealed["local_seq"]))["custody_state"] == "none"


async def test_a_refusal_episode_is_recorded_once_while_retries_continue(rig):
    sealed = rig.seal(1)
    local_seq = int(sealed["local_seq"])
    router = _router(rig)

    def refusal(signed_at_ms: int) -> dict[str, Any]:
        return _ack(
            ARTIFACT_DELIVERY_ENVELOPE,
            sealed["envelope_digest"],
            outcome="refused",
            reason="malformed",
            signed_at_ms=signed_at_ms,
        )

    await router.handle_ack(refusal(1787000003000))
    await router.handle_ack(refusal(1787000003100))
    await router.handle_ack(refusal(1787000003200))
    assert len(rig.failures()) == 1
    assert rig.envelope(local_seq)["attempts"] == 3
    assert (await rig.outbox.awaiting_custody()) != [], "still retained for retry"

    # A carriage that went out cleanly ends the episode; a later refusal is new.
    await rig.outbox.record_attempt(local_seq, at_ms=1787000003300, failure=None)
    await router.handle_ack(refusal(1787000003400))
    assert len(rig.failures()) == 2


@pytest.mark.parametrize("reason", ["malformed", "binding_mismatch"])
async def test_a_refused_checkpoint_is_retired_as_refused(rig, reason):
    queued = rig.queue_checkpoint()
    await _router(rig).handle_ack(
        _ack("checkpoint", queued["artifact_digest"], outcome="refused", reason=reason)
    )
    artifact = rig.artifact(queued["artifact_digest"])
    assert artifact is not None and artifact["retire_outcome"] == RETIRE_REFUSED


async def test_an_unsigned_acknowledgement_is_refused_when_auth_is_enabled(rig):
    queued = rig.queue_checkpoint()
    routed = await _router(rig).handle_ack(
        _ack("checkpoint", queued["artifact_digest"], secret=None)
    )
    assert routed.outcome == ROUTED_REFUSED
    artifact = rig.artifact(queued["artifact_digest"])
    assert artifact is not None and artifact["retired_at_ms"] is None


async def test_a_forged_acknowledgement_is_refused(rig):
    queued = rig.queue_checkpoint()
    ack = _ack(
        "checkpoint", queued["artifact_digest"], outcome="refused", reason="malformed"
    )
    ack["outcome"] = "queued"
    ack["reason"] = ""
    routed = await _router(rig).handle_ack(json.dumps(ack))
    assert routed.outcome == ROUTED_REFUSED
    artifact = rig.artifact(queued["artifact_digest"])
    assert artifact is not None and artifact["retired_at_ms"] is None


async def test_an_acknowledgement_for_another_device_is_refused(rig):
    queued = rig.queue_checkpoint()
    signed_for_other = _ack(
        "checkpoint", queued["artifact_digest"], device_id="another-device"
    )
    assert (await _router(rig).handle_ack(signed_for_other)).outcome == ROUTED_REFUSED
    unsigned_for_other = _ack(
        "checkpoint", queued["artifact_digest"], device_id="another-device", secret=None
    )
    assert (
        await _router(rig, authenticated=False).handle_ack(unsigned_for_other)
    ).outcome == ROUTED_REFUSED


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (
            lambda a: a.update(artifact_type="commissioning_authorization"),
            ROUTED_REFUSED,
        ),
        (lambda a: a.update(artifact_digest="sha256:short"), ROUTED_REFUSED),
        (lambda a: a.update(outcome="stored"), ROUTED_REFUSED),
        (lambda a: a.update(outcome="refused", reason="disk_on_fire"), ROUTED_REFUSED),
        (lambda a: a.update(reason="queue_full"), ROUTED_REFUSED),
        (lambda a: a.update(artifact_digest="sha256:" + "0" * 64), ROUTED_IGNORED),
    ],
)
async def test_malformed_and_unknown_acknowledgements_change_nothing(
    rig, mutate, expected
):
    queued = rig.queue_checkpoint()
    payload = {
        "device_id": DEVICE,
        "artifact_type": "checkpoint",
        "artifact_digest": queued["artifact_digest"],
        "outcome": "queued",
        "reason": "",
        "acknowledged_at_ms": 1,
    }
    mutate(payload)
    signed = _auth().sign(
        payload,
        message_type=EVIDENCE_OUTBOUND_ACK_MESSAGE_TYPE,
        signed_at_ms=1787000003000,
    )
    routed = await _router(rig).handle_ack(signed)
    assert routed.outcome == expected, routed
    artifact = rig.artifact(queued["artifact_digest"])
    assert artifact is not None and artifact["retired_at_ms"] is None


async def test_an_acknowledgement_naming_the_wrong_type_for_a_digest_is_ignored(rig):
    queued = rig.queue_checkpoint()
    routed = await _router(rig).handle_ack(
        _ack("anchor_registration", queued["artifact_digest"])
    )
    assert routed.outcome == ROUTED_IGNORED
    artifact = rig.artifact(queued["artifact_digest"])
    assert artifact is not None and artifact["retired_at_ms"] is None


@pytest.mark.parametrize("payload", [b"not json", b"[1]", b"null"])
async def test_unparseable_acknowledgements_are_refused(rig, payload):
    assert (await _router(rig).handle_ack(payload)).outcome == ROUTED_REFUSED


# --------------------------------------------------------------------------
# The publisher
# --------------------------------------------------------------------------


class _Message:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload


class _FakeClient:
    def __init__(self, *, granted_qos: int = 1, publish_failures: int = 0) -> None:
        self.on_connect = None
        self.on_subscribe = None
        self.on_disconnect = None
        self.on_message = None
        self.subscriptions: list[tuple[str, int]] = []
        self.published: list[tuple[str, bytes, int]] = []
        self.disconnected = 0
        self._granted_qos = granted_qos
        self._publish_failures = publish_failures

    def username_pw_set(self, *_args, **_kwargs) -> None:
        pass

    def connect(self, *_args, **_kwargs) -> None:
        pass

    def loop_start(self) -> None:
        if self.on_connect is not None:
            self.on_connect(self, None, None, 0)

    def subscribe(self, topic: str, qos: int = 0):
        self.subscriptions.append((topic, qos))
        if self.on_subscribe is not None:
            self.on_subscribe(self, None, 1, [self._granted_qos], None)
        return (0, 1)

    def publish(self, topic, payload, qos=0, retain=False):
        if self._publish_failures > 0:
            self._publish_failures -= 1
            raise OSError("broker gone")
        self.published.append((topic, payload, qos))

    def deliver(self, payload: dict[str, Any]) -> None:
        assert self.on_message is not None
        self.on_message(self, None, _Message(json.dumps(payload).encode()))

    def loop_stop(self) -> None:
        pass

    def disconnect(self) -> None:
        self.disconnected += 1


def _publisher(
    rig: Rig, client: _FakeClient, **kwargs
) -> MqttEvidenceOutboundPublisher:
    return MqttEvidenceOutboundPublisher(
        broker_url="mqtt://localhost:1883",
        router=_router(rig),
        device_id=DEVICE,
        outbox=rig.outbox,
        client_factory=lambda **_kwargs: client,
        retry_interval_s=kwargs.pop("retry_interval_s", 0.05),
        now=kwargs.pop("now", lambda: 1787000004000),
    )


async def _until(predicate, timeout_s: float = 2.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout_s
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.01)


async def _stop(shutdown: asyncio.Event, task: asyncio.Task[None]) -> None:
    shutdown.set()
    await asyncio.wait_for(task, 2.0)


def _carried(client: _FakeClient) -> list[dict[str, Any]]:
    return [
        json.loads(p) for topic, p, _ in client.published if topic.endswith("/outbound")
    ]


async def test_retained_artifacts_are_carried_as_exact_bytes_at_qos_1(rig):
    sealed = rig.seal(1)
    checkpoint = rig.queue_checkpoint()
    client = _FakeClient()
    publisher = _publisher(rig, client)
    shutdown = asyncio.Event()
    task = asyncio.create_task(publisher.serve_until(shutdown))
    try:
        await _until(lambda: len(_carried(client)) == 2)
        assert client.subscriptions == [(f"ori/{DEVICE}/evidence/outbound/ack", 1)]
        assert {qos for _, _, qos in client.published} == {1}
        by_type = {c["artifact_type"]: c for c in _carried(client)}
        envelope_wire = base64.b64decode(by_type["delivery_envelope"]["artifact_b64"])
        assert envelope_wire == sealed["envelope_json"].encode("utf-8")
        assert (
            "sha256:" + hashlib.sha256(envelope_wire).hexdigest()
            == sealed["envelope_digest"]
        )
        checkpoint_wire = base64.b64decode(by_type["checkpoint"]["artifact_b64"])
        assert checkpoint_wire == checkpoint["artifact_json"].encode("utf-8")
        assert all(c["device_id"] == DEVICE for c in _carried(client))
        assert rig.envelope(int(sealed["local_seq"]))["attempts"] == 1
        # Carried is not released: PUBACK retires nothing on either table.
        assert rig.envelope(int(sealed["local_seq"]))["custody_state"] == "none"
        retained = rig.artifact(checkpoint["artifact_digest"])
        assert retained is not None and retained["retired_at_ms"] is None
    finally:
        await _stop(shutdown, task)


async def test_nothing_is_carried_once_the_broker_drops_the_session(rig):
    rig.seal(1)
    client = _FakeClient()
    publisher = _publisher(rig, client, retry_interval_s=60.0)
    shutdown = asyncio.Event()
    task = asyncio.create_task(publisher.serve_until(shutdown))
    try:
        await _until(lambda: len(_carried(client)) == 1)
        rig.seal(2)
        # The state `_on_disconnect` leaves before the serve loop tears the
        # client down: the session is gone but the handle still exists.
        publisher._connected = False
        assert await publisher.flush(1.0) == 0
        assert len(_carried(client)) == 1
    finally:
        await _stop(shutdown, task)


async def test_nothing_is_published_until_the_broker_grants_the_ack_subscription(rig):
    rig.seal(1)
    client = _FakeClient(granted_qos=0x80)
    publisher = _publisher(rig, client)
    shutdown = asyncio.Event()
    task = asyncio.create_task(publisher.serve_until(shutdown))
    try:
        await asyncio.sleep(0.2)
        assert _carried(client) == []
        assert not publisher.connected
    finally:
        await _stop(shutdown, task)


async def test_puback_retires_nothing_and_the_envelope_is_republished_after_backoff(
    rig,
):
    sealed = rig.seal(1)
    clock = {"now": 1787000004000}
    client = _FakeClient()
    publisher = _publisher(rig, client, now=lambda: clock["now"])
    shutdown = asyncio.Event()
    task = asyncio.create_task(publisher.serve_until(shutdown))
    try:
        await _until(lambda: len(_carried(client)) == 1)
        await asyncio.sleep(0.2)
        assert len(_carried(client)) == 1, "republished before backoff elapsed"
        clock["now"] += int(RETRY_INTERVAL_S * 1000)
        publisher.nudge()
        await _until(lambda: len(_carried(client)) == 2)
        assert rig.envelope(int(sealed["local_seq"]))["attempts"] == 2
        assert rig.envelope(int(sealed["local_seq"]))["custody_state"] == "none"
    finally:
        await _stop(shutdown, task)


async def test_a_queued_acknowledgement_arriving_on_the_route_retires_the_checkpoint(
    rig,
):
    checkpoint = rig.queue_checkpoint()
    client = _FakeClient()
    publisher = _publisher(rig, client)
    shutdown = asyncio.Event()
    task = asyncio.create_task(publisher.serve_until(shutdown))
    try:
        await _until(lambda: len(_carried(client)) == 1)
        client.deliver(_ack("checkpoint", checkpoint["artifact_digest"]))
        await _until(
            lambda: (
                (rig.artifact(checkpoint["artifact_digest"]) or {}).get("retired_at_ms")
                is not None
            )
        )
        publisher.nudge()
        await asyncio.sleep(0.2)
        assert len(_carried(client)) == 1, "a retired checkpoint was republished"
    finally:
        await _stop(shutdown, task)


async def test_a_publish_failure_is_recorded_and_the_drain_stops(rig):
    first = rig.seal(1)
    rig.seal(2)
    client = _FakeClient(publish_failures=1)
    publisher = _publisher(rig, client, retry_interval_s=10.0)
    shutdown = asyncio.Event()
    task = asyncio.create_task(publisher.serve_until(shutdown))
    try:
        await _until(lambda: rig.envelope(int(first["local_seq"]))["attempts"] == 1)
        assert rig.envelope(int(first["local_seq"]))["last_failure"] == "unreachable"
        assert rig.envelope(2)["attempts"] == 0
        assert _carried(client) == []
    finally:
        await _stop(shutdown, task)


async def test_flush_carries_what_is_due_and_returns_the_count(rig):
    rig.seal(1)
    rig.queue_checkpoint()
    client = _FakeClient()
    publisher = _publisher(rig, client, retry_interval_s=60.0)
    shutdown = asyncio.Event()
    task = asyncio.create_task(publisher.serve_until(shutdown))
    try:
        await _until(lambda: publisher.connected)
        await _until(lambda: len(_carried(client)) == 2)
        rig.queue_checkpoint()
        assert await publisher.flush(1.0) == 0, (
            "an identical checkpoint is one artifact"
        )
        rig.seal(2)
        assert await publisher.flush(1.0) == 1
    finally:
        await _stop(shutdown, task)
    assert await publisher.flush(1.0) == 0, "nothing is carried once disconnected"


# --------------------------------------------------------------------------
# Runtime wiring
# --------------------------------------------------------------------------


class _Cfg:
    class _Gateway:
        def __init__(self, *, enabled: bool, auth: dict) -> None:
            self.enabled = enabled
            self.broker_url = "mqtt://localhost:1883"
            self.tls: dict = {}
            self.auth = auth

    class _Device:
        id = DEVICE

    def __init__(self, *, enabled: bool = True, auth: dict | None = None) -> None:
        self.gateway = _Cfg._Gateway(enabled=enabled, auth=auth or {})
        self.device = _Cfg._Device()


class _StubAttestor:
    def __init__(self, *, available: bool, outbound: object) -> None:
        self.available = available
        self.outbound = outbound


@pytest.mark.parametrize(
    "name, config, attestor",
    [
        (
            "no gateway",
            _Cfg(enabled=False),
            _StubAttestor(available=True, outbound=object()),
        ),
        ("no attestor", _Cfg(), None),
        (
            "attestor unavailable",
            _Cfg(),
            _StubAttestor(available=False, outbound=object()),
        ),
        (
            "attestor without outbox",
            _Cfg(),
            _StubAttestor(available=True, outbound=None),
        ),
    ],
)
def test_the_route_is_not_built_without_somewhere_to_carry_from(name, config, attestor):
    from ori.runtime import _build_evidence_outbound_publisher

    assert (
        _build_evidence_outbound_publisher(cast(Any, config), cast(Any, attestor))
        is None
    ), name


def test_the_route_is_built_with_envelope_auth_when_configured(monkeypatch):
    from ori.runtime import _build_evidence_outbound_publisher

    monkeypatch.setenv("ORI_TEST_ENVELOPE_SECRET", ENVELOPE_SECRET)
    config = _Cfg(
        auth={"enabled": True, "shared_secret_env": "ORI_TEST_ENVELOPE_SECRET"}
    )
    publisher = _build_evidence_outbound_publisher(
        cast(Any, config), cast(Any, _StubAttestor(available=True, outbound=object()))
    )
    assert publisher is not None
    assert publisher.topic == f"ori/{DEVICE}/evidence/outbound"
    assert publisher.ack_topic == f"ori/{DEVICE}/evidence/outbound/ack"
    assert publisher._router.envelope_authenticated


def test_a_development_runtime_without_gateway_auth_still_carries():
    from ori.runtime import _build_evidence_outbound_publisher

    publisher = _build_evidence_outbound_publisher(
        cast(Any, _Cfg(auth={"enabled": False})),
        cast(Any, _StubAttestor(available=True, outbound=object())),
    )
    assert publisher is not None
    assert not publisher._router.envelope_authenticated


class _RecordingAttestor:
    def __init__(self, *, available: bool = True) -> None:
        self.available = available
        self.checkpoints = 0

    async def issue_checkpoint(self) -> dict[str, Any] | None:
        self.checkpoints += 1
        return {"artifact_type": "checkpoint"}


class _RecordingPublisher:
    def __init__(self) -> None:
        self.flushes: list[float] = []
        self.nudges = 0

    async def flush(self, timeout_s: float) -> int:
        self.flushes.append(timeout_s)
        return 0

    def nudge(self) -> None:
        self.nudges += 1


def _runtime(attestor, publisher):
    from ori.runtime import OriRuntime

    runtime = object.__new__(OriRuntime)
    runtime._evidence_attestor = attestor
    runtime._evidence_outbound_publisher = publisher
    runtime._shutdown_event = asyncio.Event()
    return runtime


async def test_shutdown_retains_a_checkpoint_before_flushing_the_route():
    from ori.runtime import EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S

    attestor = _RecordingAttestor()
    publisher = _RecordingPublisher()
    await _runtime(attestor, publisher)._issue_shutdown_checkpoint()
    assert attestor.checkpoints == 1
    assert publisher.flushes == [EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S]


@pytest.mark.parametrize(
    "attestor",
    [None, _RecordingAttestor(available=False)],
    ids=["absent", "unavailable"],
)
async def test_shutdown_issues_nothing_without_a_usable_attestor(attestor):
    publisher = _RecordingPublisher()
    await _runtime(attestor, publisher)._issue_shutdown_checkpoint()
    assert publisher.flushes == []
    if attestor is not None:
        assert attestor.checkpoints == 0


async def test_shutdown_retains_the_checkpoint_even_without_a_route():
    attestor = _RecordingAttestor()
    await _runtime(attestor, None)._issue_shutdown_checkpoint()
    assert attestor.checkpoints == 1


async def test_the_checkpoint_loop_issues_on_the_release_owned_interval(monkeypatch):
    from ori import runtime as runtime_module

    monkeypatch.setattr(runtime_module, "DEFAULT_CHECKPOINT_INTERVAL_S", 0.02)
    attestor = _RecordingAttestor()
    runtime = _runtime(attestor, None)
    task = asyncio.create_task(runtime._evidence_checkpoint_loop(cast(Any, attestor)))
    await _until(lambda: attestor.checkpoints >= 3)
    runtime._shutdown_event.set()
    await asyncio.wait_for(task, 1.0)


async def test_the_checkpoint_loop_issues_nothing_when_shut_down_first():
    attestor = _RecordingAttestor()
    runtime = _runtime(attestor, None)
    runtime._shutdown_event.set()
    await asyncio.wait_for(runtime._evidence_checkpoint_loop(cast(Any, attestor)), 1.0)
    assert attestor.checkpoints == 0


async def test_shutdown_drains_what_was_retained_before_closing(rig):
    client = _FakeClient()
    publisher = _publisher(rig, client, retry_interval_s=60.0)
    shutdown = asyncio.Event()
    task = asyncio.create_task(publisher.serve_until(shutdown))
    try:
        await _until(lambda: publisher.connected)
        checkpoint = rig.queue_checkpoint()
        assert _carried(client) == []
    finally:
        shutdown.set()
        await asyncio.wait_for(task, 2.0)
    carried = _carried(client)
    assert [c["artifact_type"] for c in carried] == ["checkpoint"]
    assert (
        base64.b64decode(carried[0]["artifact_b64"])
        == checkpoint["artifact_json"].encode()
    )
    assert client.disconnected == 1, "the route was closed after the final drain"


async def test_a_flush_overlapping_a_nudged_drain_carries_each_artifact_once(rig):
    release = threading.Event()
    in_flight = threading.Event()

    class _SlowClient(_FakeClient):
        def publish(self, topic, payload, qos=0, retain=False):
            in_flight.set()
            release.wait(2.0)
            return super().publish(topic, payload, qos, retain)

    client = _SlowClient()
    publisher = _publisher(rig, client, retry_interval_s=60.0)
    shutdown = asyncio.Event()
    task = asyncio.create_task(publisher.serve_until(shutdown))
    try:
        await _until(lambda: publisher.connected)
        rig.queue_checkpoint()
        publisher.nudge()
        await asyncio.to_thread(in_flight.wait, 2.0)
        flush = asyncio.create_task(publisher.flush(2.0))
        await asyncio.sleep(0.05)
        release.set()
        assert await flush == 0
    finally:
        shutdown.set()
        await asyncio.wait_for(task, 2.0)
    assert [c["artifact_type"] for c in _carried(client)] == ["checkpoint"]
    (row,) = rig.executor.run(rig.ledger.pending_artifacts, 10)
    assert int(row["attempts"]) == 1


async def test_stop_flushes_the_shutdown_checkpoint_while_routes_are_up():
    """The shutdown event tears the routes down, so the flush precedes it."""
    from ori.runtime import OriRuntime

    runtime = OriRuntime(config_path="/unused/ori.yaml")
    seen: dict[str, Any] = {}

    class _Attestor:
        available = True

        async def issue_checkpoint(self):
            seen["issued_while_shutting_down"] = runtime._shutdown_event.is_set()
            return {"artifact_type": "checkpoint"}

        def set_sealed_listener(self, listener):
            pass

        def close(self):
            pass

    class _Publisher:
        async def flush(self, timeout_s: float) -> int:
            seen["flushed_while_shutting_down"] = runtime._shutdown_event.is_set()
            return 1

    runtime._evidence_attestor = cast(Any, _Attestor())
    runtime._evidence_outbound_publisher = cast(Any, _Publisher())
    await runtime.stop()
    assert seen == {
        "issued_while_shutting_down": False,
        "flushed_while_shutting_down": False,
    }
    assert runtime._shutdown_event.is_set()
