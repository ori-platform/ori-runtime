# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
from types import SimpleNamespace

import pytest

import ori.gateway.node_heartbeat as node_heartbeat_module
from ori.gateway.node_heartbeat import (
    RUNTIME_HEARTBEAT_MESSAGE_TYPE,
    RUNTIME_HEARTBEAT_TOPIC_TEMPLATE,
    MqttRuntimeNodeHeartbeatPublisher,
)
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
)


class _FakeClient:
    def __init__(self) -> None:
        self.connected: tuple[str, int, int] | None = None
        self.loop_started = False
        self.loop_stopped = False
        self.disconnected = False
        self.username: tuple[str, str] | None = None
        self.tls_context = None
        self.published: list[tuple[str, bytes, int, bool]] = []

    def username_pw_set(self, username, password):
        self.username = (username, password)

    def tls_set_context(self, context):
        self.tls_context = context

    def connect(self, host, port, keepalive):
        self.connected = (host, port, keepalive)

    def loop_start(self):
        self.loop_started = True

    def loop_stop(self):
        self.loop_stopped = True

    def disconnect(self):
        self.disconnected = True

    def publish(self, topic, payload, qos=0, retain=False):
        self.published.append((topic, payload, qos, retain))
        return SimpleNamespace(rc=0)


def _auth() -> GatewayMessageAuthenticator:
    return GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="site-test-secret",
            max_skew_ms=300_000,
            replay_ttl_ms=300_000,
        )
    )


def _publisher(
    *,
    device_id: str = "dev-01",
    broker_url: str = "mqtt://localhost",
    snapshot=None,
    authenticator=None,
    client=None,
) -> MqttRuntimeNodeHeartbeatPublisher:
    async def _snapshot():
        return snapshot or {"status": "healthy", "active_triggers": ["grid_sag"]}

    return MqttRuntimeNodeHeartbeatPublisher(
        broker_url=broker_url,
        device_id=device_id,
        health_snapshot_provider=_snapshot,
        interval_seconds=30,
        authenticator=authenticator,
        client_factory=lambda **_: client or _FakeClient(),
    )


@pytest.mark.asyncio
async def test_runtime_node_heartbeat_publishes_unsigned_retained_false(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(client=client)

    await publisher._publish_once(client)

    topic, raw_payload, qos, retain = client.published[0]
    payload = json.loads(raw_payload)
    assert topic == RUNTIME_HEARTBEAT_TOPIC_TEMPLATE.format(device_id="dev-01")
    assert qos == 0
    assert retain is False
    assert payload == {
        "active_triggers": ["grid_sag"],
        "device_id": "dev-01",
        "gateway_seen_ms": 0,
        "last_seen_ms": 1_000_000,
        "status": "healthy",
    }


@pytest.mark.asyncio
async def test_runtime_node_heartbeat_signs_payload_when_auth_enabled(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    authenticator = _auth()
    publisher = _publisher(client=client, authenticator=authenticator)

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    verified = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="site-test-secret")
    ).verify(
        payload,
        message_type=RUNTIME_HEARTBEAT_MESSAGE_TYPE,
        expected_device_id="dev-01",
    )
    assert verified["device_id"] == "dev-01"
    assert verified["status"] == "healthy"


@pytest.mark.asyncio
async def test_runtime_node_heartbeat_marks_critical_snapshot_degraded(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={"status": "healthy", "critical": True},
    )

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert payload["status"] == "degraded"


@pytest.mark.asyncio
async def test_runtime_node_heartbeat_serve_until_uses_mqtts_tls(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    shutdown = asyncio.Event()
    shutdown.set()
    publisher = _publisher(
        broker_url="mqtts://operator:secret@broker.local",
        client=client,
    )

    await publisher.serve_until(shutdown)

    assert client.connected == ("broker.local", 8883, 60)
    assert client.username == ("operator", "secret")
    assert client.tls_context is not None
    assert client.loop_started is True
    assert client.loop_stopped is True
    assert client.disconnected is True
    assert len(client.published) == 1


# ── degradation_reasons (gateway-api/v1) ─────────────────────────────


@pytest.mark.asyncio
async def test_degradation_reasons_omitted_when_nothing_is_degraded(monkeypatch):
    """Absent, never an empty array.

    An empty array is malformed under gateway-api/v1: absent and
    present-empty are different states, and a conforming gateway refuses
    the latter with degradation_reasons_length_invalid.
    """
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "healthy",
            "active_triggers": [],
            "degradation_reasons": [],
        },
    )

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert "degradation_reasons" not in payload


@pytest.mark.asyncio
async def test_degradation_reasons_omitted_when_empty_even_if_degraded(monkeypatch):
    """Isolates the emptiness guard from the status guard.

    The healthy-status test above cannot prove this on its own: with a
    healthy status the status check also suppresses the field, so a
    regression that emitted `[]` would still pass. A node degraded for some
    unrelated reason, carrying no named reasons, is the case that separates
    them — and it is a real state, since other subsystems can degrade a node
    without naming anything.
    """
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "degraded",
            "active_triggers": [],
            "degradation_reasons": [],
        },
    )

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert payload["status"] == "degraded"
    assert "degradation_reasons" not in payload


@pytest.mark.asyncio
async def test_degradation_reasons_emitted_on_a_degraded_heartbeat(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "degraded",
            "active_triggers": [],
            "degradation_reasons": ["firmware_liveness_degraded"],
        },
    )

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert payload["status"] == "degraded"
    assert payload["degradation_reasons"] == ["firmware_liveness_degraded"]


@pytest.mark.asyncio
async def test_degradation_reasons_are_unique_and_ordered(monkeypatch):
    """Uniqueness and ordering, without teaching production to emit junk.

    An earlier version of this test used invented tokens and therefore
    asserted that the publisher emits values a conforming gateway is
    required to reject — encoding the opposite of the rollout rule. The
    vocabulary is extended for the duration of the test instead, so the
    ordering behaviour is exercised with tokens the boundary accepts.
    """
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    monkeypatch.setattr(
        node_heartbeat_module,
        "DEGRADATION_REASONS",
        frozenset({"aa_test_only", "zz_test_only"}),
    )
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "degraded",
            "active_triggers": [],
            "degradation_reasons": ["zz_test_only", "aa_test_only", "zz_test_only"],
        },
    )

    await publisher._publish_once(client)

    reasons = json.loads(client.published[0][1])["degradation_reasons"]
    assert reasons == ["aa_test_only", "zz_test_only"]
    assert reasons == sorted(set(reasons))


@pytest.mark.asyncio
async def test_unratified_tokens_are_never_emitted(monkeypatch):
    """A receiver must refuse an unratified token, so never send one.

    Refusing here costs one reason; emitting costs the whole heartbeat.
    """
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "degraded",
            "active_triggers": [],
            "degradation_reasons": ["not_ratified_yet"],
        },
    )

    await publisher._publish_once(client)

    assert "degradation_reasons" not in json.loads(client.published[0][1])


@pytest.mark.asyncio
async def test_ratified_tokens_survive_alongside_unratified_ones(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "degraded",
            "active_triggers": [],
            "degradation_reasons": ["not_ratified_yet", "firmware_liveness_degraded"],
        },
    )

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert payload["degradation_reasons"] == ["firmware_liveness_degraded"]


@pytest.mark.asyncio
async def test_non_string_reasons_are_refused_not_coerced(monkeypatch):
    """str() over an arbitrary object manufactures a plausible token."""
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    for junk in ({"a": 1}, 42, None, ["nested"]):
        client = _FakeClient()
        publisher = _publisher(
            client=client,
            snapshot={
                "status": "degraded",
                "active_triggers": [],
                "degradation_reasons": [junk],
            },
        )
        await publisher._publish_once(client)
        assert "degradation_reasons" not in json.loads(client.published[0][1])


@pytest.mark.asyncio
async def test_over_the_contract_maximum_omits_the_field(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    oversized = frozenset(f"tok_{i:02d}" for i in range(17))
    monkeypatch.setattr(node_heartbeat_module, "DEGRADATION_REASONS", oversized)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "degraded",
            "active_triggers": [],
            "degradation_reasons": sorted(oversized),
        },
    )

    await publisher._publish_once(client)

    assert "degradation_reasons" not in json.loads(client.published[0][1])


@pytest.mark.asyncio
async def test_degradation_reasons_dropped_rather_than_sent_with_healthy_status(
    monkeypatch, caplog
):
    """Reasons imply degraded. Sending both would be malformed on the wire.

    A caller that names a reason has already contributed critical/degraded
    to the snapshot, so this guards a future caller that forgets — and it
    warns rather than failing silently.
    """
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "healthy",
            "active_triggers": [],
            "degradation_reasons": ["firmware_liveness_degraded"],
        },
    )

    with caplog.at_level("WARNING"):
        await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert "degradation_reasons" not in payload
    assert "degradation_reasons" in caplog.text


@pytest.mark.asyncio
async def test_degradation_reasons_are_inside_the_signed_payload(monkeypatch):
    """Signed content, not metadata.

    Tampering after signing must break authentication, which is what makes
    a reordered list a transport failure rather than a semantic one.
    """
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    authenticator = _auth()
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        authenticator=authenticator,
        snapshot={
            "status": "degraded",
            "active_triggers": [],
            "degradation_reasons": ["firmware_liveness_degraded"],
        },
    )

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert payload["degradation_reasons"] == ["firmware_liveness_degraded"]
    assert "auth" in payload

    verifier = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="site-test-secret")
    )
    # Unmodified: authenticates.
    verifier.verify(
        payload,
        message_type=RUNTIME_HEARTBEAT_MESSAGE_TYPE,
        expected_device_id="dev-01",
    )
    # Reordered after signing: the canonical bytes changed, so this must
    # fail authentication rather than reach semantic validation.
    tampered = dict(payload)
    tampered["degradation_reasons"] = ["zz_tampered"]
    with pytest.raises(Exception):
        verifier.verify(
            tampered,
            message_type=RUNTIME_HEARTBEAT_MESSAGE_TYPE,
            expected_device_id="dev-01",
        )


def test_degradation_reasons_helper_omits_and_names():
    from ori.runtime import (
        DEGRADATION_REASON_FIRMWARE_LIVENESS,
        _degradation_reasons,
    )

    assert _degradation_reasons(firmware_liveness_degraded=False) == []
    assert _degradation_reasons(firmware_liveness_degraded=True) == [
        DEGRADATION_REASON_FIRMWARE_LIVENESS
    ]
