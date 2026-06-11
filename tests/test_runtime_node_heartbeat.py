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
