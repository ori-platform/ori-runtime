# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
import logging
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import ori.gateway.heartbeat as heartbeat_module
from ori.gateway.heartbeat import (
    _HEARTBEAT_MESSAGE_TYPE,
    GATEWAY_HEALTH_TOPIC,
    MqttGatewayHeartbeatSubscriber,
)
from ori.network.event_bus import EventBus
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
)
from ori.utils.time_utils import now_ms as _now_ms

# ── helpers ───────────────────────────────────────────────────────────────────


class _CollectingEventBus:
    """Minimal EventBus stand-in that records published events."""

    def __init__(self) -> None:
        self.published: list = []

    async def publish(self, event) -> None:
        self.published.append(event)


def _auth(
    *, max_skew_ms: int = 5_000, replay_ttl_ms: int = 5_000
) -> GatewayMessageAuthenticator:
    return GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="site-test-secret",
            max_skew_ms=max_skew_ms,
            replay_ttl_ms=replay_ttl_ms,
        )
    )


def _subscriber(
    event_bus=None,
    *,
    device_id: str = "dev-01",
    broker_url: str = "mqtt://localhost",
    authenticator=None,
    client_factory=None,
):
    return MqttGatewayHeartbeatSubscriber(
        broker_url=broker_url,
        event_bus=event_bus or _CollectingEventBus(),
        device_id=device_id,
        authenticator=authenticator,
        client_factory=client_factory or (lambda **_: _FakeClient()),
    )


def _heartbeat_payload(
    status="healthy",
    uptime_s=12.5,
    provider="echo",
    sim_available=False,
    timestamp_ms=1_000_000,
) -> bytes:
    return json.dumps(
        {
            "status": status,
            "uptime_s": uptime_s,
            "provider": provider,
            "sim_available": sim_available,
            "timestamp_ms": timestamp_ms,
        }
    ).encode()


def _message(payload: bytes) -> SimpleNamespace:
    return SimpleNamespace(payload=payload)


class _FakeClient:
    """Minimal paho.mqtt.Client stand-in sufficient for heartbeat subscriber tests."""

    def __init__(self):
        self.on_connect = None
        self.on_message = None
        self.subscribed: list[str] = []
        self.connected: tuple | None = None
        self.loop_started = False
        self.loop_stopped = False
        self.disconnected = False
        self._connect_rc = 0

    def username_pw_set(self, username, password):
        pass

    def tls_set_context(self, context):
        pass

    def connect(self, host, port, keepalive):
        self.connected = (host, port, keepalive)
        if self.on_connect is not None:
            self.on_connect(self, None, None, self._connect_rc)

    def subscribe(self, topic):
        self.subscribed.append(topic)

    def loop_start(self):
        self.loop_started = True

    def loop_stop(self):
        self.loop_stopped = True

    def disconnect(self):
        self.disconnected = True


# ── _on_message → EventBus routing tests ─────────────────────────────────────
#
# _on_message posts to the event loop via call_soon_threadsafe + create_task,
# so each test must be async (asyncio_mode = "auto") and await asyncio.sleep(0)
# twice: once to schedule the task, once to execute the coroutine.


async def test_valid_heartbeat_publishes_event_to_event_bus():
    bus = _CollectingEventBus()
    sub = _subscriber(bus)
    sub._loop = asyncio.get_running_loop()

    sub._on_message(None, None, _message(_heartbeat_payload(timestamp_ms=9_876_543)))
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert len(bus.published) == 1
    event = bus.published[0]
    assert event.event_type == GATEWAY_HEALTH_TOPIC
    assert event.timestamp == 9_876_543
    assert event.device_id == "dev-01"
    assert event.reading is None
    assert event.source == "mqtt"


async def test_event_bus_receives_correct_device_id():
    bus = _CollectingEventBus()
    sub = _subscriber(bus, device_id="energy-monitor-ikeja-01")
    sub._loop = asyncio.get_running_loop()

    sub._on_message(None, None, _message(_heartbeat_payload()))
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert bus.published[0].device_id == "energy-monitor-ikeja-01"


async def test_degraded_status_still_publishes():
    """A gateway reporting 'degraded' is still alive — event must be published."""
    bus = _CollectingEventBus()
    sub = _subscriber(bus)
    sub._loop = asyncio.get_running_loop()

    sub._on_message(None, None, _message(_heartbeat_payload(status="degraded")))
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert len(bus.published) == 1


async def test_unknown_status_still_publishes():
    """Forward-compatibility: unknown status values must not suppress event publishing."""
    bus = _CollectingEventBus()
    sub = _subscriber(bus)
    sub._loop = asyncio.get_running_loop()

    payload = json.dumps(
        {"status": "future_unknown_status", "timestamp_ms": 5}
    ).encode()
    sub._on_message(None, None, _message(payload))
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert len(bus.published) == 1
    assert bus.published[0].timestamp == 5


async def test_missing_timestamp_ms_falls_back_to_now(monkeypatch):
    """When timestamp_ms is absent the subscriber uses the local clock."""
    monkeypatch.setattr(heartbeat_module, "now_ms", lambda: 42_000)

    bus = _CollectingEventBus()
    sub = _subscriber(bus)
    sub._loop = asyncio.get_running_loop()

    payload = json.dumps({"status": "healthy", "uptime_s": 1.0}).encode()
    sub._on_message(None, None, _message(payload))
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert bus.published[0].timestamp == 42_000


async def test_non_numeric_timestamp_ms_falls_back_to_now(monkeypatch):
    monkeypatch.setattr(heartbeat_module, "now_ms", lambda: 99_000)

    bus = _CollectingEventBus()
    sub = _subscriber(bus)
    sub._loop = asyncio.get_running_loop()

    payload = json.dumps({"status": "healthy", "timestamp_ms": "not-a-number"}).encode()
    sub._on_message(None, None, _message(payload))
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert bus.published[0].timestamp == 99_000


async def test_malformed_json_silently_discarded():
    bus = _CollectingEventBus()
    sub = _subscriber(bus)
    sub._loop = asyncio.get_running_loop()

    sub._on_message(None, None, _message(b"not json at all {{{"))
    await asyncio.sleep(0)

    assert bus.published == []


async def test_non_dict_json_silently_discarded():
    """A JSON array or scalar must be discarded — only objects are valid."""
    bus = _CollectingEventBus()
    sub = _subscriber(bus)
    sub._loop = asyncio.get_running_loop()

    sub._on_message(None, None, _message(b'["healthy", 12.5]'))
    await asyncio.sleep(0)
    sub._on_message(None, None, _message(b"null"))
    await asyncio.sleep(0)

    assert bus.published == []


async def test_empty_payload_silently_discarded():
    bus = _CollectingEventBus()
    sub = _subscriber(bus)
    sub._loop = asyncio.get_running_loop()

    sub._on_message(None, None, _message(b""))
    await asyncio.sleep(0)

    assert bus.published == []


def test_message_before_loop_set_logs_warning(caplog):
    """Messages received before serve_until() is called must be safely discarded."""
    sub = _subscriber()
    assert sub._loop is None

    with caplog.at_level(logging.WARNING, logger="ori.gateway.heartbeat"):
        sub._on_message(None, None, _message(_heartbeat_payload()))

    assert "before event loop ready" in caplog.text


# ── authentication tests ──────────────────────────────────────────────────────


async def test_auth_disabled_accepts_unsigned_heartbeat():
    """No authenticator set → unsigned heartbeats are accepted without auth block."""
    bus = _CollectingEventBus()
    sub = _subscriber(bus, authenticator=None)
    sub._loop = asyncio.get_running_loop()

    sub._on_message(None, None, _message(_heartbeat_payload()))
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert len(bus.published) == 1


async def test_auth_enabled_accepts_valid_signed_heartbeat():
    """Valid HMAC envelope → heartbeat is accepted and published."""
    authenticator = _auth()
    raw = json.loads(_heartbeat_payload().decode())
    # Sign with the real current timestamp so verify_broadcast skew check passes.
    signed = authenticator.sign(
        raw, message_type=_HEARTBEAT_MESSAGE_TYPE, signed_at_ms=_now_ms()
    )

    bus = _CollectingEventBus()
    sub = _subscriber(bus, authenticator=_auth())
    sub._loop = asyncio.get_running_loop()

    sub._on_message(None, None, _message(json.dumps(signed).encode()))
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert len(bus.published) == 1


async def test_auth_enabled_rejects_unsigned_heartbeat(caplog):
    """Auth enabled but no auth block in payload → discarded with WARNING."""
    bus = _CollectingEventBus()
    sub = _subscriber(bus, authenticator=_auth())
    sub._loop = asyncio.get_running_loop()

    with caplog.at_level(logging.WARNING, logger="ori.gateway.heartbeat"):
        sub._on_message(None, None, _message(_heartbeat_payload()))
        await asyncio.sleep(0)

    assert bus.published == []
    assert "rejected heartbeat" in caplog.text


async def test_auth_enabled_rejects_tampered_payload(caplog):
    """Valid signature over original payload, then field mutated → invalid_signature."""
    authenticator = _auth()
    raw = json.loads(_heartbeat_payload().decode())
    signed = authenticator.sign(
        raw, message_type=_HEARTBEAT_MESSAGE_TYPE, signed_at_ms=10_000
    )
    signed["uptime_s"] = 9999.0  # tamper after signing

    bus = _CollectingEventBus()
    sub = _subscriber(bus, authenticator=_auth())
    sub._loop = asyncio.get_running_loop()

    with caplog.at_level(logging.WARNING, logger="ori.gateway.heartbeat"):
        with patch.object(heartbeat_module, "now_ms", return_value=10_000):
            sub._on_message(None, None, _message(json.dumps(signed).encode()))
            await asyncio.sleep(0)

    assert bus.published == []
    assert "rejected heartbeat" in caplog.text


async def test_auth_enabled_rejects_replayed_heartbeat(caplog):
    """Same signed heartbeat delivered twice → second delivery rejected as replay."""
    authenticator = _auth()
    raw = json.loads(_heartbeat_payload().decode())
    # Sign with real current time so skew check passes for both deliveries.
    signed = authenticator.sign(
        raw, message_type=_HEARTBEAT_MESSAGE_TYPE, signed_at_ms=_now_ms()
    )
    signed_bytes = json.dumps(signed).encode()

    bus = _CollectingEventBus()
    sub = _subscriber(bus, authenticator=authenticator)
    sub._loop = asyncio.get_running_loop()

    sub._on_message(None, None, _message(signed_bytes))
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert len(bus.published) == 1

    with caplog.at_level(logging.WARNING, logger="ori.gateway.heartbeat"):
        sub._on_message(None, None, _message(signed_bytes))
        await asyncio.sleep(0)

    assert len(bus.published) == 1  # second delivery rejected
    assert "rejected heartbeat" in caplog.text


async def test_auth_enabled_rejects_stale_heartbeat(caplog):
    """Heartbeat signed beyond max_skew_ms in the past → stale_timestamp."""
    authenticator = _auth(max_skew_ms=1_000)
    raw = json.loads(_heartbeat_payload().decode())
    signed = authenticator.sign(
        raw, message_type=_HEARTBEAT_MESSAGE_TYPE, signed_at_ms=0
    )

    bus = _CollectingEventBus()
    sub = _subscriber(bus, authenticator=authenticator)
    sub._loop = asyncio.get_running_loop()

    with caplog.at_level(logging.WARNING, logger="ori.gateway.heartbeat"):
        with patch.object(heartbeat_module, "now_ms", return_value=10_000):
            sub._on_message(None, None, _message(json.dumps(signed).encode()))
            await asyncio.sleep(0)

    assert bus.published == []
    assert "rejected heartbeat" in caplog.text


# ── _on_connect unit tests ────────────────────────────────────────────────────


def test_on_connect_zero_rc_subscribes():
    fake = _FakeClient()
    sub = _subscriber(client_factory=lambda **_: fake)

    sub._on_connect(fake, None, None, 0)

    assert fake.subscribed == [GATEWAY_HEALTH_TOPIC]


def test_on_connect_nonzero_rc_does_not_subscribe(caplog):
    fake = _FakeClient()
    sub = _subscriber(client_factory=lambda **_: fake)

    with caplog.at_level(logging.WARNING, logger="ori.gateway.heartbeat"):
        sub._on_connect(fake, None, None, 5)

    assert fake.subscribed == []
    assert "connect failed" in caplog.text


# ── serve_until integration tests ────────────────────────────────────────────


async def test_serve_until_connects_subscribes_and_stops():
    fake = _FakeClient()
    sub = _subscriber(client_factory=lambda **_: fake)
    shutdown = asyncio.Event()

    async def _stop():
        await asyncio.sleep(0)
        shutdown.set()

    await asyncio.gather(sub.serve_until(shutdown), _stop())

    assert fake.connected == ("localhost", 1883, 60)
    assert fake.subscribed == [GATEWAY_HEALTH_TOPIC]
    assert fake.loop_started is True
    assert fake.loop_stopped is True
    assert fake.disconnected is True


async def test_serve_until_tls_applies_context():
    """mqtts:// scheme must trigger TLS context creation on the paho client."""
    fake = _FakeClient()
    tls_contexts: list = []
    original_tls_set = fake.tls_set_context

    def _capture_tls(ctx):
        tls_contexts.append(ctx)
        original_tls_set(ctx)

    fake.tls_set_context = _capture_tls

    sub = MqttGatewayHeartbeatSubscriber(
        broker_url="mqtts://localhost",
        event_bus=_CollectingEventBus(),
        device_id="dev-01",
        client_factory=lambda **_: fake,
    )
    shutdown = asyncio.Event()

    async def _stop():
        await asyncio.sleep(0)
        shutdown.set()

    await asyncio.gather(sub.serve_until(shutdown), _stop())

    assert len(tls_contexts) == 1
    assert tls_contexts[0] is not None


async def test_serve_until_heartbeat_routes_through_real_event_bus():
    """End-to-end: MQTT heartbeat → EventBus → posture tracker."""
    from ori.reasoning.capability_posture import CapabilityPostureTracker

    tracker = CapabilityPostureTracker(gateway_heartbeat_ttl_seconds=60)
    bus = EventBus()

    async def _on_gateway_health(event):
        tracker.record_gateway_heartbeat(event.timestamp)

    bus.subscribe("ori/gateway/health", _on_gateway_health)

    class _ActiveFakeClient(_FakeClient):
        def loop_start(self):
            super().loop_start()
            if self.on_message is not None:
                self.on_message(
                    self, None, _message(_heartbeat_payload(timestamp_ms=3_000_000))
                )

    sub = MqttGatewayHeartbeatSubscriber(
        broker_url="mqtt://localhost",
        event_bus=bus,
        device_id="dev-01",
        client_factory=lambda **_: _ActiveFakeClient(),
    )
    shutdown = asyncio.Event()

    async def _stop():
        # Two yields: one to schedule the task, one to run the coroutine.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        shutdown.set()

    await asyncio.gather(sub.serve_until(shutdown), _stop())

    assert tracker._last_gateway_heartbeat_ms == 3_000_000


# ── paho unavailable guard ────────────────────────────────────────────────────


def test_paho_unavailable_raises():
    with patch.object(heartbeat_module, "_PAHO_AVAILABLE", False):
        with pytest.raises(RuntimeError, match="paho-mqtt is not installed"):
            MqttGatewayHeartbeatSubscriber(
                broker_url="mqtt://localhost",
                event_bus=_CollectingEventBus(),
                device_id="dev-01",
            )
