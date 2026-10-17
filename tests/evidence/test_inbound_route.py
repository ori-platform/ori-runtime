# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The route from the runtime-gateway transport into evidence ingest.

Verification and application were both covered while nothing connected them.
These cover the join.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import pathlib
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest

from ori.gateway.evidence_inbound import (
    ARTIFACT_CUSTODY,
    ARTIFACT_EPOCH,
    ARTIFACT_RECEIPT,
    EVIDENCE_INBOUND_ACK_MESSAGE_TYPE,
    EVIDENCE_INBOUND_MESSAGE_TYPE,
    REFUSE_ENVELOPE_UNAUTHENTICATED,
    REFUSE_INGEST_UNAVAILABLE,
    REFUSE_MISSING_ARTIFACT,
    REFUSE_NOT_AN_OBJECT,
    REFUSE_UNKNOWN_ARTIFACT_TYPE,
    REFUSE_UNPARSEABLE,
    EvidenceInboundRouter,
    InboundRefusal,
    MqttEvidenceInboundSubscriber,
)
from ori.security.evidence.bound import BoundIngestService
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.custody_keys import derive_custody_key_id
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.security.evidence.ingest import REJECT_UNKNOWN_KEY
from ori.security.evidence.ingest_service import IngestOutcome
from ori.security.evidence.ledger import RECEIPT_NONE
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
)
from tests.waiting import wait_until

DEVICE = "energy-monitor-ikeja-01"
ENVELOPE_SECRET = "site-envelope-secret"
CUSTODY_SECRET = "site-custody-secret"
PREVIOUS_CUSTODY_SECRET = "site-custody-secret-previous"
STRANGER_CUSTODY_SECRET = "a-secret-this-runtime-never-shared"

CUSTODY_DOMAIN = b"ori.evidence_custody_ack.v1\x00"


class _RecordingIngest(BoundIngestService):
    """Records which accept_* the route chose, and answers as told.

    A real `BoundIngestService` subclass, because the route refuses anything
    else -- which is the point of that check.
    """

    def __init__(self, outcome: IngestOutcome | None = None) -> None:
        super().__init__(cast(Any, None), cast(Any, None))
        self.calls: list[tuple[str, object]] = []
        self._outcome = outcome or IngestOutcome(artifact="stub", state="accepted")

    def accept_custody(self, artifact: object) -> IngestOutcome:
        self.calls.append((ARTIFACT_CUSTODY, artifact))
        return self._outcome

    def accept_receipt(self, artifact: object) -> IngestOutcome:
        self.calls.append((ARTIFACT_RECEIPT, artifact))
        return self._outcome

    def accept_epoch_confirmation(self, artifact: object) -> IngestOutcome:
        self.calls.append((ARTIFACT_EPOCH, artifact))
        return self._outcome

    async def accept_async(self, artifact_type: str, artifact: object) -> IngestOutcome:
        return {
            "custody": self.accept_custody,
            "receipt": self.accept_receipt,
            "epoch": self.accept_epoch_confirmation,
        }[artifact_type](artifact)


def _authenticator() -> GatewayMessageAuthenticator:
    return GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret=ENVELOPE_SECRET)
    )


def _envelope(artifact_type: str, artifact: dict, *, device_id: str = DEVICE) -> dict:
    return {
        "device_id": device_id,
        "artifact_type": artifact_type,
        "artifact": artifact,
    }


def _signed(envelope: dict) -> bytes:
    payload = _authenticator().sign(
        envelope, message_type=EVIDENCE_INBOUND_MESSAGE_TYPE
    )
    return json.dumps(payload).encode()


def _route_outcome(router, payload):
    return router.handle_payload(payload).outcome


def _mac(artifact: dict, secret: str) -> dict:
    body = {k: v for k, v in artifact.items() if k != "mac"}
    artifact["mac"] = (
        "hmac-sha256:"
        + hmac.new(
            secret.encode(), CUSTODY_DOMAIN + canonical_json(body), hashlib.sha256
        ).hexdigest()
    )
    return artifact


# --------------------------------------------------------------------------
# What the transport refuses before ingest is reached
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload, expected",
    [
        (b"not json at all", REFUSE_UNPARSEABLE),
        (b"[1, 2, 3]", REFUSE_NOT_AN_OBJECT),
        (b'"a string"', REFUSE_NOT_AN_OBJECT),
    ],
)
def test_an_undecodable_message_is_refused(payload, expected):
    ingest = _RecordingIngest()
    router = EvidenceInboundRouter(device_id=DEVICE, ingest=ingest)

    result = router.handle_payload(payload).outcome

    assert isinstance(result, InboundRefusal)
    assert result.reason == expected
    assert ingest.calls == []


def test_an_unknown_artifact_type_is_refused_rather_than_guessed():
    """Inferring the type from which verifier succeeds is trial verification."""
    ingest = _RecordingIngest()
    router = EvidenceInboundRouter(device_id=DEVICE, ingest=ingest)

    result = router.handle_payload(
        json.dumps(_envelope("anchor_quarantine", {"v": 1})).encode()
    ).outcome

    assert isinstance(result, InboundRefusal)
    assert result.reason == REFUSE_UNKNOWN_ARTIFACT_TYPE
    assert ingest.calls == []


@pytest.mark.parametrize("artifact", [None, "a string", 7, ["v", 1]])
def test_a_message_carrying_no_artifact_object_is_refused(artifact):
    ingest = _RecordingIngest()
    router = EvidenceInboundRouter(device_id=DEVICE, ingest=ingest)
    envelope = _envelope(ARTIFACT_CUSTODY, {})
    envelope["artifact"] = artifact

    result = router.handle_payload(json.dumps(envelope).encode()).outcome

    assert isinstance(result, InboundRefusal)
    assert result.reason == REFUSE_MISSING_ARTIFACT
    assert ingest.calls == []


def test_a_runtime_without_ingest_refuses_rather_than_pretending():
    """Absent ingest is a fault on this device, not a malformed message."""
    router = EvidenceInboundRouter(device_id=DEVICE, ingest=None)

    result = router.handle_payload(
        json.dumps(_envelope(ARTIFACT_CUSTODY, {"v": 1})).encode()
    ).outcome

    assert isinstance(result, InboundRefusal)
    assert result.reason == REFUSE_INGEST_UNAVAILABLE


# --------------------------------------------------------------------------
# Envelope authentication happens before the artifact is read
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, mutate",
    [
        ("unsigned", lambda payload: {k: v for k, v in payload.items() if k != "auth"}),
        (
            "signature corrupted",
            lambda payload: {
                **payload,
                "auth": {**payload["auth"], "signature": "hmac-sha256:" + "0" * 64},
            },
        ),
        (
            "signed for another device",
            lambda payload: {**payload, "device_id": "some-other-device"},
        ),
        (
            "replayed from another exchange",
            lambda payload: {**payload, "artifact_type": ARTIFACT_RECEIPT},
        ),
    ],
)
def test_an_unauthenticated_envelope_never_reaches_ingest(name, mutate):
    ingest = _RecordingIngest()
    router = EvidenceInboundRouter(
        device_id=DEVICE, ingest=ingest, message_auth=_authenticator()
    )
    signed = json.loads(_signed(_envelope(ARTIFACT_CUSTODY, {"v": 1})))

    result = router.handle_payload(json.dumps(mutate(signed)).encode()).outcome

    assert isinstance(result, InboundRefusal), name
    assert result.reason == REFUSE_ENVELOPE_UNAUTHENTICATED, name
    # The ordering is the claim: a good artifact in a bad envelope reaches no
    # verifier.
    assert ingest.calls == [], name


def test_a_signed_envelope_reaches_ingest():
    ingest = _RecordingIngest()
    router = EvidenceInboundRouter(
        device_id=DEVICE, ingest=ingest, message_auth=_authenticator()
    )
    artifact = {"v": 1, "local_seq": 4}

    result = router.handle_payload(
        _signed(_envelope(ARTIFACT_CUSTODY, artifact))
    ).outcome

    assert not isinstance(result, InboundRefusal)
    assert ingest.calls == [(ARTIFACT_CUSTODY, artifact)]


# --------------------------------------------------------------------------
# Dispatch, and what comes back
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "artifact_type", [ARTIFACT_CUSTODY, ARTIFACT_RECEIPT, ARTIFACT_EPOCH]
)
def test_each_artifact_reaches_its_own_verifier_and_no_other(artifact_type):
    ingest = _RecordingIngest()
    router = EvidenceInboundRouter(device_id=DEVICE, ingest=ingest)
    artifact = {"v": 1, "marker": artifact_type}

    router.handle_payload(json.dumps(_envelope(artifact_type, artifact)).encode())

    assert ingest.calls == [(artifact_type, artifact)]


def test_an_ingest_rejection_is_returned_rather_than_swallowed():
    """Dropping rejections would make an unknown-key receipt look like none."""
    refused = IngestOutcome(
        artifact="delivery_receipt",
        state="rejected",
        reason=REJECT_UNKNOWN_KEY,
        detail="no key is held for that identifier",
    )
    ingest = _RecordingIngest(refused)
    router = EvidenceInboundRouter(device_id=DEVICE, ingest=ingest)

    result = router.handle_payload(
        json.dumps(_envelope(ARTIFACT_RECEIPT, {"v": 1})).encode()
    ).outcome

    assert result == refused
    assert not result.accepted


def test_the_topic_is_device_scoped():
    router = EvidenceInboundRouter(device_id=DEVICE, ingest=None)
    assert router.topic == f"ori/{DEVICE}/evidence/inbound"


# --------------------------------------------------------------------------
# End to end: a real acknowledgement, through the real thread boundary
# --------------------------------------------------------------------------


@pytest.fixture
def attestor(tmp_path, monkeypatch):
    """A started attestor holding an active and a previous custody generation."""
    monkeypatch.setenv("ORI_TEST_CUSTODY", CUSTODY_SECRET)
    monkeypatch.setenv("ORI_TEST_CUSTODY_PREVIOUS", PREVIOUS_CUSTODY_SECRET)

    from ori.security.evidence.custody_keys import CustodyKeyRegistry

    attestor = FirstPartyEvidenceAttestor(
        db_path=str(tmp_path / "evidence.db"),
        key_path=str(tmp_path / "evidence.key"),
        device_secret="a-random-install-secret",
        device_id=DEVICE,
        custody_keys=CustodyKeyRegistry(
            active_secret=CUSTODY_SECRET,
            previous_secret=PREVIOUS_CUSTODY_SECRET,
        ),
    )
    yield attestor
    attestor.close()


async def _seal_one(attestor: FirstPartyEvidenceAttestor) -> dict:
    """Attest an action so a sealed envelope with local_seq 1 exists."""
    assert await attestor.start()
    seq = await attestor.attest_action(
        {
            "id": 1,
            "action_name": "emergency_cutoff",
            "tier": "D",
            "executed": 1,
            "action_taken": "emergency_cutoff",
            "timestamp": 1787000000000,
            "trigger_name": "dangerous_overcurrent",
            "authority_json": (
                '{"kind":"tier_d_legacy_skill",'
                '"skill_name":"energy-anomaly-detector",'
                '"skill_version":"0.2.1",'
                '"trigger_name":"dangerous_overcurrent"}'
            ),
        }
    )
    assert seq is not None
    ledger = attestor._ledger
    assert ledger is not None
    sealed = attestor._executor.run(ledger.find_by_local_seq, 1)
    assert sealed is not None
    return {
        "v": 1,
        "device_id": DEVICE,
        "local_seq": 1,
        "envelope_digest": str(sealed["envelope_digest"]),
        "custody_at_ms": 1787000000900,
    }


@pytest.mark.parametrize(
    "name, secret, accepted",
    [
        ("the active generation", CUSTODY_SECRET, True),
        ("the previous generation", PREVIOUS_CUSTODY_SECRET, True),
        ("a generation never shared", STRANGER_CUSTODY_SECRET, False),
    ],
)
def test_custody_selects_the_generation_its_key_id_names(
    attestor, name, secret, accepted
):
    """The end-to-end claim: envelope, thread marshalling and key selection.

    Runs against the real `BoundIngestService`. Handing the raw service to the
    route raises `sqlite3.ProgrammingError` here.
    """

    async def scenario() -> IngestOutcome | InboundRefusal:
        artifact = await _seal_one(attestor)
        artifact["key_id"] = derive_custody_key_id(secret)
        router = EvidenceInboundRouter(
            device_id=DEVICE,
            ingest=attestor.ingest,
            message_auth=_authenticator(),
        )
        payload = _signed(_envelope(ARTIFACT_CUSTODY, _mac(artifact, secret)))
        return await asyncio.to_thread(_route_outcome, router, payload)

    result = asyncio.run(scenario())

    assert not isinstance(result, InboundRefusal), name
    assert result.accepted is accepted, name
    if not accepted:
        assert result.reason == REJECT_UNKNOWN_KEY, name


def test_custody_moves_the_public_pending_count_through_the_route(attestor):
    """`pending_export_count` counts envelopes awaiting custody, so it falls."""

    async def scenario() -> tuple[int | None, int | None, bool]:
        artifact = await _seal_one(attestor)
        artifact["key_id"] = derive_custody_key_id(CUSTODY_SECRET)
        before = await attestor.pending_export_count()

        router = EvidenceInboundRouter(
            device_id=DEVICE,
            ingest=attestor.ingest,
            message_auth=_authenticator(),
        )
        payload = _signed(_envelope(ARTIFACT_CUSTODY, _mac(artifact, CUSTODY_SECRET)))
        outcome = await asyncio.to_thread(_route_outcome, router, payload)

        return before, await attestor.pending_export_count(), outcome.accepted

    before, after, accepted = asyncio.run(scenario())
    assert accepted
    assert (before, after) == (1, 0)


def test_custody_does_not_report_the_envelope_delivered(attestor):
    """Custody says a courier holds the bytes; only a receipt is delivery."""

    async def scenario() -> tuple[str, int | None]:
        artifact = await _seal_one(attestor)
        artifact["key_id"] = derive_custody_key_id(CUSTODY_SECRET)
        router = EvidenceInboundRouter(device_id=DEVICE, ingest=attestor.ingest)
        payload = json.dumps(
            _envelope(ARTIFACT_CUSTODY, _mac(artifact, CUSTODY_SECRET))
        ).encode()
        outcome = await asyncio.to_thread(_route_outcome, router, payload)
        assert outcome.accepted

        ledger = attestor._ledger
        assert ledger is not None
        row = attestor._executor.run(ledger.find_by_local_seq, 1)
        awaiting = attestor._executor.run(ledger.awaiting_receipt_count)
        return str(row["receipt_state"]), awaiting

    receipt_state, awaiting_receipt = asyncio.run(scenario())
    assert receipt_state == RECEIPT_NONE
    assert awaiting_receipt == 1


def test_custody_through_the_route_awaits_a_receipt_until_one_verifies(
    attestor, monkeypatch
):
    """A refused receipt leaves the envelope waiting, and health can say so."""
    monkeypatch.setattr(
        "ori.security.evidence.ingest_service.now_ms", lambda: 1787000000400
    )

    async def scenario():
        artifact = await _seal_one(attestor)
        artifact["key_id"] = derive_custody_key_id(CUSTODY_SECRET)
        router = EvidenceInboundRouter(device_id=DEVICE, ingest=attestor.ingest)
        custody = json.dumps(
            _envelope(ARTIFACT_CUSTODY, _mac(artifact, CUSTODY_SECRET))
        ).encode()
        assert (await asyncio.to_thread(_route_outcome, router, custody)).accepted
        held = await attestor.awaiting_receipt(1787000005000)

        forged = json.dumps(_envelope(ARTIFACT_RECEIPT, {"v": 1})).encode()
        refused = await asyncio.to_thread(_route_outcome, router, forged)
        return held, refused, await attestor.awaiting_receipt(1787000006000)

    held, refused, after = asyncio.run(scenario())
    # The courier's clock says 900, ahead of this runtime's 400, so the
    # runtime's own record sets the age.
    assert held == (1, 1787000005000 - 1787000000400)
    assert not isinstance(refused, InboundRefusal) and refused.accepted is False
    assert after == (1, 1787000006000 - 1787000000400)


def test_a_redelivered_custody_does_not_make_the_envelope_newer(attestor, monkeypatch):
    """The first record of custody stands: a replay later is not a later arrival."""
    clock = [1787000000400]
    monkeypatch.setattr("ori.security.evidence.ingest_service.now_ms", lambda: clock[0])

    async def scenario():
        artifact = await _seal_one(attestor)
        artifact["key_id"] = derive_custody_key_id(CUSTODY_SECRET)
        router = EvidenceInboundRouter(device_id=DEVICE, ingest=attestor.ingest)
        custody = json.dumps(
            _envelope(ARTIFACT_CUSTODY, _mac(artifact, CUSTODY_SECRET))
        ).encode()
        assert (await asyncio.to_thread(_route_outcome, router, custody)).accepted
        first = await attestor.awaiting_receipt(1787000005000)
        clock[0] = 1787000004900
        await asyncio.to_thread(_route_outcome, router, custody)
        return first, await attestor.awaiting_receipt(1787000005000)

    first, replayed = asyncio.run(scenario())
    assert first == (1, 1787000005000 - 1787000000400)
    assert replayed == first


def test_the_raw_ingest_service_is_refused_at_construction(attestor):
    """A structural protocol would admit it; it fails only across a thread."""

    async def scenario() -> None:
        assert await attestor.start()

    asyncio.run(scenario())
    bound = attestor.ingest
    assert bound is not None
    raw = bound._service

    with pytest.raises(TypeError, match="BoundIngestService"):
        EvidenceInboundRouter(device_id=DEVICE, ingest=cast(Any, raw))


# --------------------------------------------------------------------------
# What the runtime builds, and when it declines to
# --------------------------------------------------------------------------


class _Cfg:
    """Minimal config shape the builder reads."""

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
    def __init__(self, *, available: bool, ingest: object) -> None:
        self.available = available
        self.ingest = ingest


def test_the_route_is_not_built_without_a_gateway():
    from ori.runtime import _build_evidence_inbound_subscriber

    subscriber = _build_evidence_inbound_subscriber(
        cast(Any, _Cfg(enabled=False)),
        cast(Any, _StubAttestor(available=True, ingest=_RecordingIngest())),
    )
    assert subscriber is None


@pytest.mark.parametrize(
    "name, attestor",
    [
        ("no attestor", None),
        ("attestor unavailable", _StubAttestor(available=False, ingest=object())),
        ("attestor without ingest", _StubAttestor(available=True, ingest=None)),
    ],
)
def test_the_route_is_not_built_without_somewhere_to_apply_artifacts(name, attestor):
    """Consuming what cannot be recorded makes the gateway stop retrying."""
    from ori.runtime import _build_evidence_inbound_subscriber

    built = _build_evidence_inbound_subscriber(cast(Any, _Cfg()), cast(Any, attestor))
    assert built is None, name


def test_the_route_is_built_when_a_gateway_and_ingest_are_both_present(monkeypatch):
    from ori.runtime import _build_evidence_inbound_subscriber

    monkeypatch.setenv("ORI_TEST_ENVELOPE_SECRET", ENVELOPE_SECRET)
    config = _Cfg(
        auth={"enabled": True, "shared_secret_env": "ORI_TEST_ENVELOPE_SECRET"}
    )
    subscriber = _build_evidence_inbound_subscriber(
        cast(Any, config),
        cast(Any, _StubAttestor(available=True, ingest=_RecordingIngest())),
    )

    assert subscriber is not None
    assert subscriber.topic == f"ori/{DEVICE}/evidence/inbound"
    assert subscriber._router.envelope_authenticated


def test_a_development_runtime_without_gateway_auth_still_routes(monkeypatch):
    """Envelope auth is defence in depth; each artifact carries its own."""
    from ori.runtime import _build_evidence_inbound_subscriber

    subscriber = _build_evidence_inbound_subscriber(
        cast(Any, _Cfg(auth={"enabled": False})),
        cast(Any, _StubAttestor(available=True, ingest=_RecordingIngest())),
    )

    assert subscriber is not None
    assert not subscriber._router.envelope_authenticated


# --------------------------------------------------------------------------
# The MQTT subscriber itself
# --------------------------------------------------------------------------


class _FakeClient:
    """Enough paho surface to drive the subscriber's lifecycle.

    `subscribe` returns only that SUBSCRIBE was queued; the broker's grant or
    refusal is delivered separately through `on_subscribe`, as paho does.
    """

    def __init__(
        self,
        *,
        connect_errors: int = 0,
        subscribe_rc: int = 0,
        granted_qos: int = 1,
        suback: bool = True,
    ) -> None:
        self.on_connect = None
        self.on_subscribe = None
        self.on_disconnect = None
        self.on_message = None
        self.subscriptions: list[tuple[str, int]] = []
        self.published: list[tuple[str, bytes, int]] = []
        self.loop_started = 0
        self.loop_stopped = 0
        self.disconnected = 0
        self._connect_errors = connect_errors
        self._subscribe_rc = subscribe_rc
        self._granted_qos = granted_qos
        self._suback = suback
        self.connect_attempts = 0

    def username_pw_set(self, *_args, **_kwargs) -> None:
        pass

    def connect(self, *_args, **_kwargs) -> None:
        self.connect_attempts += 1
        if self._connect_errors > 0:
            self._connect_errors -= 1
            raise OSError("broker unreachable")

    def loop_start(self) -> None:
        self.loop_started += 1
        if self.on_connect is not None:
            self.on_connect(self, None, None, 0)

    def subscribe(self, topic: str, qos: int = 0):
        self.subscriptions.append((topic, qos))
        if self._subscribe_rc == 0 and self._suback and self.on_subscribe is not None:
            self.on_subscribe(self, None, 1, [self._granted_qos], None)
        return (self._subscribe_rc, 1)

    def drop_session(self) -> None:
        """The broker dropping a session it had granted."""
        if self.on_disconnect is not None:
            self.on_disconnect(self, None, 7)

    def publish(self, topic, payload, qos=0, retain=False):
        self.published.append((topic, payload, qos))

    def loop_stop(self) -> None:
        self.loop_stopped += 1

    def disconnect(self) -> None:
        self.disconnected += 1


def _subscriber(client: _FakeClient, ingest=None) -> MqttEvidenceInboundSubscriber:
    router = EvidenceInboundRouter(
        device_id=DEVICE, ingest=ingest, message_auth=_authenticator()
    )
    return MqttEvidenceInboundSubscriber(
        broker_url="mqtt://localhost:1883",
        router=router,
        device_id=DEVICE,
        client_factory=lambda **_kwargs: client,
    )


def test_the_subscriber_subscribes_at_qos_1_and_stops_cleanly():
    """QoS 1: a dropped artifact cannot be re-requested, since the runtime
    does not know it was sent."""
    client = _FakeClient()
    subscriber = _subscriber(client)

    async def scenario() -> None:
        shutdown = asyncio.Event()
        task = asyncio.create_task(subscriber.serve_until(shutdown))
        await wait_until(lambda: subscriber.connected, what="the route to come up")
        assert client.subscriptions == [(f"ori/{DEVICE}/evidence/inbound", 1)]
        shutdown.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())
    assert client.loop_stopped == 1
    assert client.disconnected == 1
    assert not subscriber.connected


@pytest.mark.parametrize(
    "name, client",
    [
        ("subscribe could not be sent", _FakeClient(subscribe_rc=1)),
        ("broker refused the topic", _FakeClient(granted_qos=0x87)),
    ],
)
def test_a_refused_subscription_does_not_report_the_route_up(name, client, monkeypatch):
    """Sending SUBSCRIBE is not being subscribed.

    A broker that authenticates the connection and then refuses the topic by
    ACL answers in SUBACK. Reading the queue result as acceptance would leave
    the route reporting healthy while waiting forever.
    """
    monkeypatch.setattr("ori.gateway.evidence_inbound._RECONNECT_MIN_S", 0.01)
    monkeypatch.setattr("ori.gateway.evidence_inbound._RECONNECT_MAX_S", 0.01)
    subscriber = _subscriber(client)

    async def scenario() -> None:
        shutdown = asyncio.Event()
        task = asyncio.create_task(subscriber.serve_until(shutdown))
        # Refusal must retry rather than park on a route carrying nothing.
        await wait_until(
            lambda: client.connect_attempts > 1,
            what=f"a reconnect after the refusal ({name})",
        )
        assert not subscriber.connected, name
        shutdown.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())


def test_a_queued_subscribe_alone_does_not_report_the_route_up():
    """The broker's grant arrives in SUBACK, not in the subscribe() return.

    This is the case a queue-result check reads as success: SUBSCRIBE was sent
    and the broker has said nothing back.
    """
    client = _FakeClient(suback=False)
    subscriber = _subscriber(client)

    async def scenario() -> None:
        shutdown = asyncio.Event()
        task = asyncio.create_task(subscriber.serve_until(shutdown))
        await wait_until(lambda: client.subscriptions, what="SUBSCRIBE to be sent")
        assert client.subscriptions == [(f"ori/{DEVICE}/evidence/inbound", 1)]
        assert not subscriber.connected
        shutdown.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())


def test_a_dropped_session_reconnects_and_stops_claiming_the_route_is_up(monkeypatch):
    """`connected` must not survive the session it describes."""
    monkeypatch.setattr("ori.gateway.evidence_inbound._RECONNECT_MIN_S", 0.01)
    monkeypatch.setattr("ori.gateway.evidence_inbound._RECONNECT_MAX_S", 0.01)
    client = _FakeClient()
    subscriber = _subscriber(client)

    async def scenario() -> None:
        shutdown = asyncio.Event()
        task = asyncio.create_task(subscriber.serve_until(shutdown))
        await wait_until(lambda: subscriber.connected, what="the route to come up")
        attempts = client.connect_attempts

        await asyncio.to_thread(client.drop_session)
        await wait_until(
            lambda: client.connect_attempts > attempts,
            what="a reconnect after the dropped session",
        )

        shutdown.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())


def test_a_broker_outage_retries_rather_than_ending_the_route(monkeypatch):
    """One outage must not remove inbound evidence for the process lifetime.

    Without a retry the task completes, the runtime stays healthy, and the
    gateway goes on retrying deliveries that can no longer land.
    """
    monkeypatch.setattr("ori.gateway.evidence_inbound._RECONNECT_MIN_S", 0.01)
    monkeypatch.setattr("ori.gateway.evidence_inbound._RECONNECT_MAX_S", 0.01)
    client = _FakeClient(connect_errors=2)
    subscriber = _subscriber(client)

    async def scenario() -> None:
        shutdown = asyncio.Event()
        task = asyncio.create_task(subscriber.serve_until(shutdown))
        await wait_until(
            lambda: subscriber.connected, what="the route to come up after the outage"
        )
        assert client.connect_attempts >= 3
        shutdown.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())


def test_a_message_on_the_wire_reaches_ingest():
    """The callback seam: paho hands bytes over and the artifact is applied."""
    ingest = _RecordingIngest()
    client = _FakeClient()
    subscriber = _subscriber(client, ingest=ingest)
    artifact = {"v": 1, "local_seq": 3}

    async def scenario() -> None:
        shutdown = asyncio.Event()
        task = asyncio.create_task(subscriber.serve_until(shutdown))
        await wait_until(lambda: subscriber.connected, what="the route to come up")

        message = SimpleNamespace(
            payload=_signed(_envelope(ARTIFACT_CUSTODY, artifact))
        )
        assert client.on_message is not None
        await asyncio.to_thread(client.on_message, client, None, message)
        await wait_until(lambda: ingest.calls, what="the artifact to reach ingest")

        shutdown.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())
    assert ingest.calls == [(ARTIFACT_CUSTODY, artifact)]


def test_a_refused_message_is_logged_rather_than_dropped(caplog):
    """A refusal and a message that never arrived leave identical state."""
    ingest = _RecordingIngest()
    client = _FakeClient()
    subscriber = _subscriber(client, ingest=ingest)

    async def scenario() -> None:
        shutdown = asyncio.Event()
        task = asyncio.create_task(subscriber.serve_until(shutdown))
        await wait_until(lambda: subscriber.connected, what="the route to come up")

        message = SimpleNamespace(payload=b"{}")
        assert client.on_message is not None
        with caplog.at_level(logging.WARNING):
            await asyncio.to_thread(client.on_message, client, None, message)
            await wait_until(
                lambda: any(
                    REFUSE_ENVELOPE_UNAUTHENTICATED in record.message
                    for record in caplog.records
                ),
                what="the refusal to be logged",
            )

        shutdown.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())
    assert ingest.calls == []
    assert any(
        REFUSE_ENVELOPE_UNAUTHENTICATED in record.message for record in caplog.records
    )


# --------------------------------------------------------------------------
# The acknowledgement the courier retires on
# --------------------------------------------------------------------------


def test_an_applied_artifact_is_acknowledged_by_digest():
    """The courier retires on this, so it must name the artifact it carried."""
    ingest = _RecordingIngest()
    router = EvidenceInboundRouter(
        device_id=DEVICE, ingest=ingest, message_auth=_authenticator()
    )
    artifact = {"v": 1, "local_seq": 4}

    routed = router.handle_payload(_signed(_envelope(ARTIFACT_CUSTODY, artifact)))
    ack = routed.acknowledgement

    assert ack is not None
    assert ack["outcome"] == "applied"
    assert ack["reason"] == ""
    assert ack["artifact_type"] == ARTIFACT_CUSTODY
    assert ack["artifact_digest"] == (
        "sha256:" + hashlib.sha256(canonical_json(artifact)).hexdigest()
    )
    # Signed under its own message type, so it cannot be replayed as an
    # inbound message.
    verified = _authenticator().verify(
        ack,
        message_type=EVIDENCE_INBOUND_ACK_MESSAGE_TYPE,
        expected_device_id=DEVICE,
    )
    assert verified["artifact_digest"] == ack["artifact_digest"]


def test_a_refused_artifact_is_acknowledged_with_its_reason():
    """A refusal is still a decision, and the courier needs to hear it."""
    refused = IngestOutcome(
        artifact="delivery_receipt",
        state="rejected",
        reason=REJECT_UNKNOWN_KEY,
        detail="no key is held for that identifier",
    )
    router = EvidenceInboundRouter(device_id=DEVICE, ingest=_RecordingIngest(refused))

    routed = router.handle_payload(
        json.dumps(_envelope(ARTIFACT_RECEIPT, {"v": 1})).encode()
    )

    assert routed.acknowledgement is not None
    assert routed.acknowledgement["outcome"] == "refused"
    assert routed.acknowledgement["reason"] == REJECT_UNKNOWN_KEY


@pytest.mark.parametrize(
    "name, payload",
    [
        ("unparseable", b"not json"),
        ("unauthenticated envelope", b'{"device_id":"x","artifact_type":"y"}'),
    ],
)
def test_a_transport_refusal_is_never_acknowledged(name, payload):
    """Answering an unauthenticated message with a signed reply would hand
    anything on the site network a signing oracle."""
    router = EvidenceInboundRouter(
        device_id=DEVICE, ingest=_RecordingIngest(), message_auth=_authenticator()
    )

    routed = router.handle_payload(payload)

    assert isinstance(routed.outcome, InboundRefusal), name
    assert routed.acknowledgement is None, name


def test_the_subscriber_publishes_the_acknowledgement():
    ingest = _RecordingIngest()
    client = _FakeClient()
    subscriber = _subscriber(client, ingest=ingest)
    artifact = {"v": 1, "local_seq": 9}

    async def scenario() -> None:
        shutdown = asyncio.Event()
        task = asyncio.create_task(subscriber.serve_until(shutdown))
        await wait_until(lambda: subscriber.connected, what="the route to come up")
        message = SimpleNamespace(
            payload=_signed(_envelope(ARTIFACT_CUSTODY, artifact))
        )
        assert client.on_message is not None
        await asyncio.to_thread(client.on_message, client, None, message)
        await wait_until(
            lambda: client.published, what="the acknowledgement to be published"
        )
        shutdown.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())

    assert len(client.published) == 1
    topic, payload, qos = client.published[0]
    assert topic == f"ori/{DEVICE}/evidence/inbound/ack"
    assert qos == 1
    assert json.loads(payload)["outcome"] == "applied"


def test_the_default_client_uses_a_persistent_session():
    """A clean session drops the subscription on disconnect, so artifacts
    published while the runtime restarts are lost with no record."""
    from ori.gateway.evidence_inbound import _default_client_factory

    client = _default_client_factory(client_id="ori-evidence-in-test")

    assert client._clean_session is False


def test_redelivery_under_a_fresh_envelope_is_acknowledged_again():
    """A courier retries by re-signing, never by resending the same bytes.

    Replay protection is keyed on the envelope, so a byte-identical
    retransmission is indistinguishable from a captured envelope replayed by an
    attacker. It is refused, and a transport refusal carries no
    acknowledgement -- so a courier retrying that way would wait forever for a
    signal that can never arrive, deadlocking its queue on its own retry.
    """
    auth = _authenticator()
    router = EvidenceInboundRouter(
        device_id=DEVICE, ingest=_RecordingIngest(), message_auth=_authenticator()
    )
    artifact = {"v": 1, "local_seq": 4}
    envelope = _envelope(ARTIFACT_CUSTODY, artifact)

    # Signed once and kept, so the replay attempt below is the same bytes
    # rather than a second signature that merely resembles them.
    delivered = json.dumps(
        auth.sign(envelope, message_type=EVIDENCE_INBOUND_MESSAGE_TYPE)
    )
    first = router.handle_payload(delivered)
    assert first.acknowledgement is not None

    # The same bytes again: refused as a replay, and deliberately not acked.
    replayed = router.handle_payload(delivered)
    assert isinstance(replayed.outcome, InboundRefusal)
    assert replayed.outcome.reason == REFUSE_ENVELOPE_UNAUTHENTICATED
    assert replayed.acknowledgement is None

    # The same artifact under a fresh envelope: acknowledged again, and the
    # digest identifies it as the same artifact across both attempts.
    second = router.handle_payload(
        json.dumps(
            auth.sign(
                envelope,
                message_type=EVIDENCE_INBOUND_MESSAGE_TYPE,
                # A later timestamp, so this is a distinct envelope by the
                # same key the replay cache uses. Reading the clock again
                # would be a coin toss on the millisecond boundary.
                signed_at_ms=json.loads(delivered)["auth"]["signed_at_ms"] + 1000,
            )
        )
    )
    assert second.acknowledgement is not None
    assert (
        second.acknowledgement["artifact_digest"]
        == first.acknowledgement["artifact_digest"]
    )


def test_a_byte_identical_replay_is_refused_and_never_acknowledged():
    """Replay protection must not be relaxed to make redelivery convenient.

    It is what stops a captured custody acknowledgement being replayed to
    misreport a stalled queue, and a receiver cannot tell an honest
    retransmission from a hostile one.
    """
    auth = _authenticator()
    router = EvidenceInboundRouter(
        device_id=DEVICE, ingest=_RecordingIngest(), message_auth=_authenticator()
    )
    payload = json.dumps(
        auth.sign(
            _envelope(ARTIFACT_CUSTODY, {"v": 1}),
            message_type=EVIDENCE_INBOUND_MESSAGE_TYPE,
        )
    ).encode()

    assert router.handle_payload(payload).acknowledgement is not None

    repeated = router.handle_payload(payload)
    assert isinstance(repeated.outcome, InboundRefusal)
    assert repeated.outcome.reason == REFUSE_ENVELOPE_UNAUTHENTICATED
    assert repeated.acknowledgement is None


# --------------------------------------------------------------------------
# The published transport fixture
# --------------------------------------------------------------------------

FIXTURE = json.loads(
    (
        pathlib.Path(__file__).parent.parent
        / "vectors"
        / "gateway_api"
        / "inbound-evidence.json"
    ).read_text()
)


def _fixture_case(name: str) -> dict:
    for case in FIXTURE["cases"]:
        if case["name"] == name:
            return case
    raise AssertionError(f"the fixture no longer carries a {name!r} case")


class _FixtureIngest(BoundIngestService):
    """Accepts whatever it is handed, so the fixture tests the transport."""

    def __init__(self) -> None:
        super().__init__(cast(Any, None), cast(Any, None))

    def accept_custody(self, artifact: object) -> IngestOutcome:
        return IngestOutcome(artifact=ARTIFACT_CUSTODY, state="accepted")

    async def accept_async(self, artifact_type: str, artifact: object) -> IngestOutcome:
        return self.accept_custody(artifact)


def _fixture_router() -> EvidenceInboundRouter:
    secret = FIXTURE["shared_secret"]
    return EvidenceInboundRouter(
        device_id="site-a-edge-01",
        ingest=_FixtureIngest(),
        message_auth=GatewayMessageAuthenticator(
            GatewayMessageAuthConfig(shared_secret=secret)
        ),
    )


def test_the_runtime_verifies_the_published_inbound_fixture():
    """Against published bytes, not against a message this file builds.

    Locally constructed envelopes prove the runtime agrees with itself. The
    fixture is what the gateway implements against, so only this catches the
    two drifting apart while both stay green.
    """
    case = _fixture_case("inbound_custody_acknowledgement")

    with patch(
        "ori.security.gateway_messages.now_ms", return_value=case["signed_at_ms"]
    ):
        routed = _fixture_router().handle_payload(dict(case["payload"]))

    assert not isinstance(routed.outcome, InboundRefusal), routed.outcome
    assert routed.outcome.accepted


def test_the_runtime_reproduces_the_published_acknowledgement_fixture():
    """Byte for byte, `auth` block included, as the contract requires."""
    inbound = _fixture_case("inbound_custody_acknowledgement")
    expected = _fixture_case("ingest_acknowledgement_applied")
    at_ms = expected["signed_at_ms"]

    with (
        patch("ori.security.gateway_messages.now_ms", return_value=at_ms),
        patch("ori.gateway.evidence_inbound.now_ms", return_value=at_ms),
    ):
        routed = _fixture_router().handle_payload(dict(inbound["payload"]))

    assert routed.acknowledgement == expected["payload"]


def test_the_fixture_signing_strings_still_describe_its_signatures():
    """The fixture must stay internally consistent, or it proves nothing.

    A regeneration that updated a payload without its signing string would
    leave a document the two implementations could both fail against for
    different reasons.
    """
    secret = FIXTURE["shared_secret"].encode()
    for case in FIXTURE["cases"]:
        expected = (
            "hmac-sha256:"
            + hmac.new(
                secret, case["signing_string"].encode(), hashlib.sha256
            ).hexdigest()
        )
        assert expected == case["expected_signature"], case["name"]
        assert case["payload"]["auth"]["signature"] == expected, case["name"]

        body = {k: v for k, v in case["payload"].items() if k != "auth"}
        assert (
            canonical_json(body).hex() == case["canonical_payload_without_auth_hex"]
        ), case["name"]


def test_the_vendored_fixture_matches_the_message_types_the_route_uses():
    """A renamed message type on either side breaks the envelope binding."""
    assert (
        _fixture_case("inbound_custody_acknowledgement")["message_type"]
        == EVIDENCE_INBOUND_MESSAGE_TYPE
    )
    assert (
        _fixture_case("ingest_acknowledgement_applied")["message_type"]
        == EVIDENCE_INBOUND_ACK_MESSAGE_TYPE
    )
    router = EvidenceInboundRouter(device_id="site-a-edge-01", ingest=None)
    assert _fixture_case("inbound_custody_acknowledgement")["topic"] == router.topic
    assert _fixture_case("ingest_acknowledgement_applied")["topic"] == router.ack_topic


def _replay_rows(db: pathlib.Path) -> int:
    import sqlite3

    with sqlite3.connect(db) as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM gateway_replay_cache"
        ).fetchone()[0]


def _persisted_router(db: pathlib.Path, ingest=None) -> EvidenceInboundRouter:
    from ori.security.gateway_messages import GatewayReplayCache

    return EvidenceInboundRouter(
        device_id=DEVICE,
        ingest=ingest,
        message_auth=GatewayMessageAuthenticator(
            GatewayMessageAuthConfig(shared_secret=ENVELOPE_SECRET),
            replay_cache=GatewayReplayCache(db_path=str(db)),
        ),
    )


@pytest.mark.parametrize(
    "envelope, reason",
    [
        (_envelope("not_an_artifact", {"v": 1}), REFUSE_UNKNOWN_ARTIFACT_TYPE),
        (
            {"device_id": DEVICE, "artifact_type": ARTIFACT_CUSTODY},
            REFUSE_MISSING_ARTIFACT,
        ),
        (_envelope(ARTIFACT_CUSTODY, {"v": 1}), REFUSE_INGEST_UNAVAILABLE),
    ],
)
def test_an_authenticated_message_refused_in_transport_adds_no_replay_state(
    tmp_path, envelope, reason
):
    """gateway-api/v2 Payload Volume: it answers nothing the device holds."""
    db = tmp_path / "replay.db"
    router = _persisted_router(db)
    payload = _signed(envelope)

    for _ in range(2):
        outcome = _route_outcome(router, payload)
        assert isinstance(outcome, InboundRefusal) and outcome.reason == reason
    assert _replay_rows(db) == 0


def test_an_admitted_message_is_recorded_once_and_its_replay_refused(tmp_path):
    db = tmp_path / "replay.db"
    ingest = _RecordingIngest()
    router = _persisted_router(db, ingest)
    payload = _signed(_envelope(ARTIFACT_CUSTODY, {"v": 1}))

    assert _route_outcome(router, payload).accepted
    assert _replay_rows(db) == 1
    replayed = _route_outcome(router, payload)
    assert isinstance(replayed, InboundRefusal)
    assert replayed.reason == REFUSE_ENVELOPE_UNAUTHENTICATED
    assert len(ingest.calls) == 1


def test_a_message_the_saturated_worker_refused_is_admitted_when_redelivered(tmp_path):
    """Refused at submission, it was never acted on: its key is released, so
    the broker's redelivery of the same bytes is not a replay."""
    from ori.security.evidence.executor import EvidenceExecutorSaturatedError

    db = tmp_path / "replay.db"

    class _Saturating(_RecordingIngest):
        saturated = True

        async def accept_async(
            self, artifact_type: str, artifact: object
        ) -> IngestOutcome:
            if self.saturated:
                raise EvidenceExecutorSaturatedError("the worker is full")
            return await super().accept_async(artifact_type, artifact)

    ingest = _Saturating()
    router = _persisted_router(db, ingest)
    payload = _signed(_envelope(ARTIFACT_CUSTODY, {"v": 1}))

    with pytest.raises(EvidenceExecutorSaturatedError):
        asyncio.run(router.route(payload))
    assert _replay_rows(db) == 0
    ingest.saturated = False
    assert asyncio.run(router.route(payload)).outcome.accepted
    assert _replay_rows(db) == 1


class _HeldIngest(_RecordingIngest):
    """Holds the first route inside ingest until released, then answers or
    reports the worker saturated."""

    def __init__(self) -> None:
        super().__init__()
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.saturate_once = False

    async def accept_async(self, artifact_type: str, artifact: object) -> IngestOutcome:
        from ori.security.evidence.executor import EvidenceExecutorSaturatedError

        if not self.entered.is_set():
            self.entered.set()
            await self.release.wait()
            if self.saturate_once:
                raise EvidenceExecutorSaturatedError("the worker is full")
        return await super().accept_async(artifact_type, artifact)


@pytest.mark.parametrize("original", ["saturated", "accepted"])
def test_a_copy_of_a_message_still_being_routed_is_left_not_refused(tmp_path, original):
    """The broker's copy of a message whose route has not settled is neither
    recorded nor refused as a replay, so the original's release on saturation
    still has a redelivery to admit."""
    from ori.gateway.evidence_inbound import EvidenceInFlightError
    from ori.security.evidence.executor import EvidenceExecutorSaturatedError

    db = tmp_path / "replay.db"
    ingest = _HeldIngest()
    ingest.saturate_once = original == "saturated"
    router = _persisted_router(db, ingest)
    payload = _signed(_envelope(ARTIFACT_CUSTODY, {"v": 1}))

    async def scenario() -> None:
        first = asyncio.create_task(router.route(payload))
        await ingest.entered.wait()
        rows = _replay_rows(db)
        with pytest.raises(EvidenceInFlightError):
            await router.route(payload)
        assert _replay_rows(db) == rows == 1
        ingest.release.set()
        if original == "saturated":
            await asyncio.wait([first])
            assert isinstance(first.exception(), EvidenceExecutorSaturatedError)
            assert _replay_rows(db) == 0
            # The broker's redelivery, after the reconnect, is admitted.
            assert (await router.route(payload)).outcome.accepted
        else:
            assert (await first).outcome.accepted
            replayed = (await router.route(payload)).outcome
            assert isinstance(replayed, InboundRefusal)
            assert replayed.reason == REFUSE_ENVELOPE_UNAUTHENTICATED
        assert _replay_rows(db) == 1
        assert len(ingest.calls) == 1

    asyncio.run(scenario())


def test_the_blocking_route_refuses_a_copy_still_being_routed_unrecorded(tmp_path):
    """The same rule on `handle_payload`: a copy found in flight is refused in
    transport, unrecorded, and the original goes on to settle."""
    import threading

    from ori.gateway.evidence_inbound import REFUSE_IN_FLIGHT

    db = tmp_path / "replay.db"
    ingest = _HeldIngest()
    router = _persisted_router(db, ingest)
    payload = _signed(_envelope(ARTIFACT_CUSTODY, {"v": 1}))
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever)
    thread.start()
    try:
        first = asyncio.run_coroutine_threadsafe(router.route(payload), loop)
        asyncio.run_coroutine_threadsafe(ingest.entered.wait(), loop).result(5)

        copy = router.handle_payload(payload).outcome
        assert isinstance(copy, InboundRefusal) and copy.reason == REFUSE_IN_FLIGHT
        assert _replay_rows(db) == 1

        loop.call_soon_threadsafe(ingest.release.set)
        assert first.result(5).outcome.accepted
        assert len(ingest.calls) == 1
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        loop.close()


def test_the_route_writes_replay_keys_off_the_event_loop(tmp_path, monkeypatch):
    """Each commit and each release is an SQLite commit: on a worker thread,
    and awaited before the message is acted on."""
    import threading

    from ori.security.evidence.executor import EvidenceExecutorSaturatedError
    from ori.security.gateway_messages import GatewayReplayCache

    writes: list[tuple[str, int]] = []
    persist, forget = GatewayReplayCache._persist, GatewayReplayCache.forget

    def recorded_persist(self, *args, **kwargs):
        writes.append(("persist", threading.get_ident()))
        return persist(self, *args, **kwargs)

    def recorded_forget(self, *args, **kwargs):
        writes.append(("forget", threading.get_ident()))
        return forget(self, *args, **kwargs)

    monkeypatch.setattr(GatewayReplayCache, "_persist", recorded_persist)
    monkeypatch.setattr(GatewayReplayCache, "forget", recorded_forget)

    class _SaturatedOnce(_RecordingIngest):
        saturated = True

        async def accept_async(
            self, artifact_type: str, artifact: object
        ) -> IngestOutcome:
            if self.saturated:
                self.saturated = False
                raise EvidenceExecutorSaturatedError("the worker is full")
            return await super().accept_async(artifact_type, artifact)

    router = _persisted_router(tmp_path / "replay.db", _SaturatedOnce())
    payload = _signed(_envelope(ARTIFACT_CUSTODY, {"v": 1}))

    async def scenario() -> int:
        with pytest.raises(EvidenceExecutorSaturatedError):
            await router.route(payload)
        assert (await router.route(payload)).outcome.accepted
        return threading.get_ident()

    loop_thread = asyncio.run(scenario())
    assert [kind for kind, _ in writes] == ["persist", "forget", "persist"]
    assert all(thread != loop_thread for _, thread in writes)


def _held_persist(monkeypatch):
    """Hold every replay-key insert until released; record each undo."""
    import threading

    from ori.security.gateway_messages import GatewayReplayCache

    entered, release, forgotten = (threading.Event() for _ in range(3))
    persist, forget = GatewayReplayCache._persist, GatewayReplayCache.forget

    def held(self, *args, **kwargs):
        entered.set()
        release.wait(5)
        return persist(self, *args, **kwargs)

    def recorded_forget(self, *args, **kwargs):
        result = forget(self, *args, **kwargs)
        forgotten.set()
        return result

    monkeypatch.setattr(GatewayReplayCache, "_persist", held)
    monkeypatch.setattr(GatewayReplayCache, "forget", recorded_forget)
    return entered, release, forgotten, persist


def test_a_key_written_while_the_runtime_shuts_down_is_left_unrecorded(
    tmp_path, monkeypatch
):
    """`asyncio.run` cancels every task at shutdown, the write's included; the
    write still lands on its thread, and is undone there, since nothing was
    ingested and the broker still holds the message."""
    import threading

    from ori.security.gateway_messages import GatewayReplayCache

    entered, release, forgotten, persist = _held_persist(monkeypatch)
    db = tmp_path / "replay.db"
    ingest = _RecordingIngest()
    payload = _signed(_envelope(ARTIFACT_CUSTODY, {"v": 1}))

    async def runtime() -> None:
        router = _persisted_router(db, ingest)
        asyncio.get_running_loop().create_task(router.route(payload))
        await asyncio.to_thread(entered.wait, 5)
        # The write lands only once teardown has begun.
        threading.Timer(0.2, release.set).start()

    asyncio.run(runtime())

    assert forgotten.wait(5), "the landed write was never undone"
    assert ingest.calls == [] and _replay_rows(db) == 0
    monkeypatch.setattr(GatewayReplayCache, "_persist", persist)
    after_restart = _persisted_router(db, ingest)
    assert asyncio.run(after_restart.route(payload)).outcome.accepted


def test_a_copy_arriving_before_a_cancelled_write_lands_is_left_not_refused(
    tmp_path, monkeypatch
):
    """The key stays held until its write is undone, so the copy is left with
    the broker; once undone, its redelivery is admitted."""
    from ori.gateway.evidence_inbound import EvidenceInFlightError
    from ori.security.gateway_messages import GatewayReplayCache

    entered, release, forgotten, persist = _held_persist(monkeypatch)
    db = tmp_path / "replay.db"
    ingest = _RecordingIngest()
    router = _persisted_router(db, ingest)
    payload = _signed(_envelope(ARTIFACT_CUSTODY, {"v": 1}))

    async def scenario() -> None:
        route = asyncio.create_task(router.route(payload))
        await asyncio.to_thread(entered.wait, 5)
        route.cancel()
        await asyncio.wait([route])
        assert route.cancelled()
        with pytest.raises(EvidenceInFlightError):
            await router.route(payload)
        release.set()
        await asyncio.to_thread(forgotten.wait, 5)
        assert forgotten.is_set() and _replay_rows(db) == 0
        monkeypatch.setattr(GatewayReplayCache, "_persist", persist)
        assert (await router.route(payload)).outcome.accepted
        assert len(ingest.calls) == 1

    asyncio.run(scenario())


def test_a_route_cancelled_after_its_write_landed_undoes_it(tmp_path, monkeypatch):
    """The write landed before the route resumed: the route's own abandonment
    undoes it, since nothing was ingested."""
    import threading

    from ori.gateway.evidence_inbound import _KeyWrite
    from ori.security.gateway_messages import GatewayReplayCache

    landed, proceed, undone = threading.Event(), threading.Event(), threading.Event()
    commit, forget = _KeyWrite.commit, GatewayReplayCache.forget
    forgotten_on: list[int] = []

    def recorded_forget(self, *args, **kwargs):
        forgotten_on.append(threading.get_ident())
        result = forget(self, *args, **kwargs)
        undone.set()
        return result

    monkeypatch.setattr(GatewayReplayCache, "forget", recorded_forget)

    def landed_then_parked(self):
        commit(self)
        landed.set()
        proceed.wait(5)

    monkeypatch.setattr(_KeyWrite, "commit", landed_then_parked)
    db = tmp_path / "replay.db"
    ingest = _RecordingIngest()
    router = _persisted_router(db, ingest)
    payload = _signed(_envelope(ARTIFACT_CUSTODY, {"v": 1}))

    async def scenario() -> None:
        route = asyncio.create_task(router.route(payload))
        await asyncio.to_thread(landed.wait, 5)
        assert _replay_rows(db) == 1
        route.cancel()
        await asyncio.wait([route])
        assert route.cancelled()
        proceed.set()
        await asyncio.to_thread(undone.wait, 5)
        assert forgotten_on and threading.get_ident() not in forgotten_on, (
            "the undo wrote on the event loop"
        )
        await wait_until(lambda: not router._in_flight, what="the key unheld")
        assert _replay_rows(db) == 0 and ingest.calls == []
        monkeypatch.setattr(_KeyWrite, "commit", commit)
        assert (await router.route(payload)).outcome.accepted

    asyncio.run(scenario())


@pytest.mark.parametrize("path", ["commit", "release on saturation"])
def test_a_key_write_still_queued_for_a_worker_runs_when_its_route_is_cancelled(
    tmp_path, path
):
    """Every worker busy, the write still waiting when the route is cancelled:
    it runs once a worker frees, so nothing stays recorded or held."""
    import concurrent.futures
    import threading

    from ori.security.evidence.executor import EvidenceExecutorSaturatedError

    db = tmp_path / "replay.db"
    saturating = path != "commit"
    busy, free = threading.Event(), threading.Event()
    saturate = asyncio.Event()

    class _Saturating(_RecordingIngest):
        async def accept_async(
            self, artifact_type: str, artifact: object
        ) -> IngestOutcome:
            await saturate.wait()
            raise EvidenceExecutorSaturatedError("the worker is full")

    ingest = _Saturating() if saturating else _RecordingIngest()
    router = _persisted_router(db, ingest)
    payload = _signed(_envelope(ARTIFACT_CUSTODY, {"v": 1}))

    def occupy() -> None:
        busy.set()
        free.wait(5)

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(1))
        route: asyncio.Task[Any] | None = None
        if saturating:
            # Committed with the worker free; it then waits in ingest.
            route = asyncio.create_task(router.route(payload))
            await wait_until(lambda: _replay_rows(db) == 1, what="the commit")
        blocker = loop.run_in_executor(None, occupy)
        await wait_until(busy.is_set, what="the only worker to be busy")
        if saturating:
            saturate.set()
        else:
            route = asyncio.create_task(router.route(payload))
        assert route is not None
        # The route reaches its write, which queues behind the busy worker.
        for _ in range(5):
            await asyncio.sleep(0)
        route.cancel()
        await asyncio.wait([route])
        assert route.cancelled()
        free.set()
        assert await blocker is None
        await loop.run_in_executor(None, lambda: None)  # the queue has drained
        assert _replay_rows(db) == 0
        assert not router._in_flight, "a key is held with nothing left to release it"

    asyncio.run(scenario())
