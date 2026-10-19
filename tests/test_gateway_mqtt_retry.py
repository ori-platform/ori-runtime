# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Host-only recovery checks for the gateway-facing MQTT service loops."""

from __future__ import annotations

import asyncio
import json
import threading
from types import SimpleNamespace
from typing import Any, cast

import pytest

import ori.gateway.export as export_module
import ori.gateway.firmware_telemetry as firmware_module
import ori.gateway.heartbeat as heartbeat_module
import ori.gateway.mqtt_retry as retry_module
import ori.gateway.node_heartbeat as node_module
from ori.network.event_bus import EventBus
from ori.reasoning.capability_posture import CapabilityPostureTracker
from ori.security.firmware.liveness import FirmwareLivenessSupervisor
from tests.waiting import settle, wait_until

SURFACES = ("node", "export", "gateway_heartbeat", "firmware_telemetry")


class _Client:
    def __init__(self, failure: str = "") -> None:
        self.failure = failure
        self.on_connect: Any = None
        self.on_disconnect: Any = None
        self.on_message: Any = None
        self.on_subscribe: Any = None
        self.connect_calls = 0
        self.loop_started = False
        self.loop_stopped = False
        self.disconnected = False
        self.subscribed: list[str] = []
        self.published: list[bytes] = []

    def username_pw_set(self, _username: str, _password: str | None) -> None:
        pass

    def tls_set_context(self, _context: Any) -> None:
        pass

    def connect(self, _host: str, _port: int, _keepalive: int) -> int:
        self.connect_calls += 1
        if self.failure == "raise":
            raise ConnectionRefusedError("broker unavailable")
        if self.failure == "return_code":
            return 5
        self.on_connect(self, None, None, 5 if self.failure == "connack" else 0)
        return 0

    def loop_start(self) -> int:
        self.loop_started = True
        return 0

    def loop_stop(self) -> None:
        self.loop_stopped = True

    def disconnect(self) -> None:
        self.disconnected = True
        if self.on_disconnect is not None:
            self.on_disconnect(self, None, 0)

    def subscribe(self, topic: str, qos: int = 0) -> tuple[int, int]:
        self.subscribed.append(topic)
        if self.failure == "subscribe_not_sent":
            return (4, 1)
        if self.on_subscribe is not None:
            granted = 0x80 if self.failure == "suback" else qos
            self.on_subscribe(self, None, 1, [granted], None)
        return (0, 1)

    def publish(self, _topic: str, body: bytes, **_kwargs: Any) -> Any:
        self.published.append(body)
        return SimpleNamespace(rc=0)


class _DeferredConnectClient(_Client):
    def __init__(self) -> None:
        super().__init__()
        self.connected = False

    def connect(self, _host: str, _port: int, _keepalive: int) -> int:
        self.connect_calls += 1
        return 0

    def complete_connect(self) -> None:
        self.connected = True
        self.on_connect(self, None, None, 0)

    def publish(self, topic: str, body: bytes, **kwargs: Any) -> Any:
        if not self.connected:
            return SimpleNamespace(rc=4)
        return super().publish(topic, body, **kwargs)


class _Gate:
    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []

    async def ingest(self, payload: dict[str, Any]) -> tuple[Any, list[Any]]:
        self.received.append(payload)
        return SimpleNamespace(accepted=False), []


def _service(surface: str, clients: list[_Client]) -> Any:
    def factory(**_kwargs: Any) -> _Client:
        return clients.pop(0)

    if surface == "node":
        return node_module.MqttRuntimeNodeHeartbeatPublisher(
            broker_url="mqtt://localhost",
            device_id="runtime-01",
            health_snapshot_provider=lambda: {
                "critical": False,
                "active_triggers": [],
            },
            client_factory=factory,
        )
    if surface == "export":
        responder = export_module.GatewayExportResponder(
            device_id="runtime-01",
            state_store=object(),
            health_snapshot_provider=lambda: {"device_id": "runtime-01"},
        )
        return export_module.MqttGatewayExportServer(
            broker_url="mqtt://localhost",
            responder=responder,
            client_factory=factory,
        )
    if surface == "gateway_heartbeat":
        return heartbeat_module.MqttGatewayHeartbeatSubscriber(
            broker_url="mqtt://localhost",
            posture_tracker=CapabilityPostureTracker(gateway_heartbeat_ttl_seconds=60),
            device_id="runtime-01",
            client_factory=factory,
        )
    return firmware_module.MqttFirmwareTelemetrySubscriber(
        broker_url="mqtt://localhost",
        telemetry_gate=cast(Any, _Gate()),
        event_bus=EventBus(),
        state_store=cast(Any, object()),
        runtime_device_id="runtime-01",
        liveness_supervisor=FirmwareLivenessSupervisor(),
        client_factory=factory,
    )


def _ready(surface: str, client: _Client) -> bool:
    if not client.loop_started:
        return False
    if surface == "node":
        return bool(client.published)
    return bool(client.subscribed)


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("failure", ("raise", "return_code", "connack"))
async def test_a_refused_first_connection_recovers_without_restart(
    monkeypatch: pytest.MonkeyPatch, surface: str, failure: str
) -> None:
    monkeypatch.setattr(retry_module, "RECONNECT_MIN_S", 0.01)
    first, second = _Client(failure), _Client()
    service = _service(surface, [first, second])
    shutdown = asyncio.Event()
    serving = asyncio.create_task(service.serve_until(shutdown))
    try:
        await wait_until(
            lambda: _ready(surface, second) or serving.done(),
            what=f"{surface} to resume after {failure}",
        )
        assert not serving.done(), f"{surface} stopped instead of retrying"
        assert first.connect_calls == 1
        assert first.loop_stopped and first.disconnected
        assert _ready(surface, second)
    finally:
        shutdown.set()
        await settle([serving], what=f"{surface} to stop after recovery")


@pytest.mark.parametrize("surface", SURFACES)
async def test_delayed_connack_recovers_after_refusal_and_drop(
    monkeypatch: pytest.MonkeyPatch, surface: str
) -> None:
    monkeypatch.setattr(retry_module, "RECONNECT_MIN_S", 0.01)
    first = _Client("raise")
    second, third = _DeferredConnectClient(), _DeferredConnectClient()
    service = _service(surface, [first, second, third])
    if surface == "node":
        service._interval_seconds = 0.01
    shutdown = asyncio.Event()
    serving = asyncio.create_task(service.serve_until(shutdown))
    try:
        await wait_until(
            lambda: second.loop_started or serving.done(),
            what=f"{surface} to start the second network loop",
        )
        assert not serving.done()
        assert not _ready(surface, second), "service became available before CONNACK"
        await asyncio.to_thread(second.complete_connect)
        await wait_until(
            lambda: _ready(surface, second) or serving.done(),
            what=f"{surface} to become available after delayed CONNACK",
        )
        assert not serving.done()
        assert first.loop_stopped and first.disconnected

        await asyncio.to_thread(second.on_disconnect, second, None, 1)
        await wait_until(
            lambda: third.loop_started or serving.done(),
            what=f"{surface} to start a new loop after disconnect",
        )
        assert not serving.done()
        assert second.loop_stopped and second.disconnected
        assert not _ready(surface, third), "replacement session skipped CONNACK"
        await asyncio.to_thread(third.complete_connect)
        await wait_until(
            lambda: _ready(surface, third) or serving.done(),
            what=f"{surface} to recover after the dropped session",
        )
        assert not serving.done()
    finally:
        shutdown.set()
        await settle([serving], what=f"{surface} to stop after delayed recovery")


@pytest.mark.parametrize("surface", SURFACES)
async def test_a_dropped_session_uses_a_fresh_client(
    monkeypatch: pytest.MonkeyPatch, surface: str
) -> None:
    monkeypatch.setattr(retry_module, "RECONNECT_MIN_S", 0.01)
    first, second = _Client(), _Client()
    service = _service(surface, [first, second])
    if surface != "node":

        def unexpected_message(*_args: Any) -> None:
            raise AssertionError("retired client delivered a message")

        service._on_message = unexpected_message
    shutdown = asyncio.Event()
    serving = asyncio.create_task(service.serve_until(shutdown))
    try:
        await wait_until(
            lambda: _ready(surface, first) or serving.done(),
            what=f"{surface} first session to start",
        )
        assert not serving.done()
        first.on_disconnect(first, None, 1)
        await wait_until(
            lambda: _ready(surface, second) or serving.done(),
            what=f"{surface} to reconnect after a dropped session",
        )
        assert not serving.done()
        assert first.loop_stopped and first.disconnected
        previous_subscriptions = list(first.subscribed)
        first.on_connect(first, None, None, 0)
        assert first.subscribed == previous_subscriptions, "retired client resubscribed"
        if first.on_message is not None:
            first.on_message(
                first, None, SimpleNamespace(payload=b'{"status":"healthy"}')
            )
        assert _ready(surface, second)
    finally:
        shutdown.set()
        await settle([serving], what=f"{surface} to stop after reconnection")


@pytest.mark.parametrize(
    "surface", ("export", "gateway_heartbeat", "firmware_telemetry")
)
async def test_a_restored_subscriber_handles_a_message(
    monkeypatch: pytest.MonkeyPatch, surface: str
) -> None:
    monkeypatch.setattr(retry_module, "RECONNECT_MIN_S", 0.01)
    first, second = _Client("raise"), _Client()
    service = _service(surface, [first, second])
    shutdown = asyncio.Event()
    serving = asyncio.create_task(service.serve_until(shutdown))
    try:
        await wait_until(
            lambda: _ready(surface, second) or serving.done(),
            what=f"{surface} to subscribe after recovery",
        )
        assert not serving.done()
        if surface == "export":
            payload = {
                "request_id": "recovered-1",
                "export_type": "health",
                "device_id": "runtime-01",
            }
            second.on_message(
                second, None, SimpleNamespace(payload=json.dumps(payload).encode())
            )
            await wait_until(
                lambda: bool(second.published),
                what="export to answer after recovery",
            )
            assert json.loads(second.published[0])["request_id"] == "recovered-1"
        elif surface == "gateway_heartbeat":
            second.on_message(
                second,
                None,
                SimpleNamespace(payload=b'{"status":"healthy","timestamp_ms":1}'),
            )
            await wait_until(
                lambda: service._posture_tracker._last_gateway_heartbeat_ms is not None,
                what="gateway heartbeat to update posture after recovery",
            )
        else:
            second.on_message(second, None, SimpleNamespace(payload=b'{"envelope":{}}'))
            await wait_until(
                lambda: bool(service._telemetry_gate.received),
                what="firmware telemetry to reach the gate after recovery",
            )
    finally:
        shutdown.set()
        await settle([serving], what=f"{surface} to stop after delivery")


@pytest.mark.parametrize("surface", SURFACES)
async def test_shutdown_interrupts_the_reconnect_wait(
    monkeypatch: pytest.MonkeyPatch, surface: str
) -> None:
    monkeypatch.setattr(retry_module, "RECONNECT_MIN_S", 60.0)
    first = _Client("raise")
    remaining = [first, _Client()]
    service = _service(surface, remaining)
    shutdown = asyncio.Event()
    serving = asyncio.create_task(service.serve_until(shutdown))
    await wait_until(
        lambda: first.disconnected or serving.done(),
        what=f"{surface} failed attempt to be closed",
    )
    assert not serving.done()
    shutdown.set()
    await settle([serving], what=f"{surface} to stop during backoff")
    assert len(remaining) == 1, "a new session started after shutdown"


@pytest.mark.parametrize("surface", SURFACES)
async def test_cancellation_interrupts_the_reconnect_wait(
    monkeypatch: pytest.MonkeyPatch, surface: str
) -> None:
    monkeypatch.setattr(retry_module, "RECONNECT_MIN_S", 60.0)
    first = _Client("raise")
    remaining = [first, _Client()]
    service = _service(surface, remaining)
    serving = asyncio.create_task(service.serve_until(asyncio.Event()))
    await wait_until(
        lambda: first.disconnected or serving.done(),
        what=f"{surface} failed attempt to be closed",
    )
    assert not serving.done()
    serving.cancel()
    with pytest.raises(asyncio.CancelledError):
        await serving
    assert len(remaining) == 1, "a new session started after cancellation"


@pytest.mark.parametrize("surface", SURFACES)
async def test_cancellation_closes_an_active_session(
    surface: str,
) -> None:
    client = _Client()
    service = _service(surface, [client])
    serving = asyncio.create_task(service.serve_until(asyncio.Event()))
    try:
        await wait_until(
            lambda: _ready(surface, client) or serving.done(),
            what=f"{surface} active session to start",
        )
        assert not serving.done()
    finally:
        serving.cancel()
        with pytest.raises(asyncio.CancelledError):
            await serving
    assert client.loop_stopped and client.disconnected


def test_reconnect_delay_has_jitter_and_a_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(retry_module.random, "uniform", lambda _a, _b: 0.8)
    assert retry_module.retry_delay(5.0) == 4.0
    monkeypatch.setattr(retry_module.random, "uniform", lambda _a, _b: 1.2)
    assert retry_module.retry_delay(5.0) == 6.0
    assert retry_module.retry_delay(300.0) == retry_module.RECONNECT_MAX_S


async def test_backoff_doubles_to_the_ceiling_and_restarts_after_a_connected_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shutdown = asyncio.Event()
    delays: list[float] = []
    # Seven refusals, one session that connects and then drops, one refusal.
    script = ["refuse"] * 7 + ["connect", "refuse"]

    async def record(_shutdown: asyncio.Event, base_delay_s: float) -> bool:
        delays.append(base_delay_s)
        if len(delays) == len(script):
            shutdown.set()
            return False
        return True

    async def connect(session: retry_module.MqttSession) -> Any:
        step = script[len(delays)]
        client = _Client()
        session.bind(client)
        if step == "refuse":
            raise ConnectionRefusedError("broker unavailable")
        client.on_connect(client, None, None, 0)
        client.on_disconnect(client, None, 0)
        return client

    async def close() -> None:
        pass

    monkeypatch.setattr(retry_module, "wait_before_retry", record)
    await asyncio.wait_for(
        retry_module.serve_with_reconnect(
            shutdown,
            connect=connect,
            close=close,
            log=retry_module.logging.getLogger("test"),
            service="test",
        ),
        5,
    )
    assert delays == [5.0, 10.0, 20.0, 40.0, 80.0, 160.0, 300.0, 5.0, 10.0]


async def test_each_session_is_retired_and_closed_however_it_ends() -> None:
    shutdown = asyncio.Event()
    sessions: list[retry_module.MqttSession] = []
    closed = 0

    async def connect(session: retry_module.MqttSession) -> Any:
        sessions.append(session)
        shutdown.set()
        raise ConnectionRefusedError("broker unavailable")

    async def close() -> None:
        nonlocal closed
        closed += 1

    await retry_module.serve_with_reconnect(
        shutdown,
        connect=connect,
        close=close,
        log=retry_module.logging.getLogger("test"),
        service="test",
    )
    assert closed == 1
    stale = _Client()
    sessions[0].bind(stale)
    stale.on_disconnect(stale, None, 0)
    await asyncio.sleep(0)
    assert not sessions[0].lost.is_set()


SUBSCRIBERS = ("export", "gateway_heartbeat", "firmware_telemetry")


@pytest.mark.parametrize("surface", SUBSCRIBERS)
@pytest.mark.parametrize("failure", ("suback", "subscribe_not_sent"))
async def test_a_refused_subscription_is_a_failed_session(
    monkeypatch: pytest.MonkeyPatch, surface: str, failure: str
) -> None:
    """A session whose subscription is refused never counts as connected.

    It reconnects, and its back-off keeps growing rather than restarting at the
    minimum, as it would after a session that came up.
    """
    shutdown = asyncio.Event()
    delays: list[float] = []

    async def record(_shutdown: asyncio.Event, base_delay_s: float) -> bool:
        delays.append(base_delay_s)
        if len(delays) == 3:
            shutdown.set()
            return False
        return True

    monkeypatch.setattr(retry_module, "wait_before_retry", record)
    clients = [_Client(failure) for _ in range(3)]
    service = _service(surface, list(clients))
    await asyncio.wait_for(service.serve_until(shutdown), 5)

    assert delays == [5.0, 10.0, 20.0]
    assert all(client.subscribed for client in clients)
    assert all(client.loop_stopped and client.disconnected for client in clients)


async def test_a_grant_for_a_retired_session_reaches_nothing() -> None:
    """A SUBACK from the client of a session already retired is not a grant."""
    hooks: list[int] = []
    session = retry_module.MqttSession(asyncio.get_running_loop())
    client = _Client()
    client.subscribe = lambda *_args, **_kwargs: (0, 1)  # SUBACK held back
    session.bind(client, subscribe=("t", 1), on_subscribed=lambda: hooks.append(1))
    client.on_connect(client, None, None, 0)
    session.retire()
    client.on_subscribe(client, None, 1, [1], None)
    await asyncio.sleep(0)
    assert not session.connected and not session.ever_connected
    assert hooks == []


async def test_only_the_answer_to_this_sessions_subscribe_is_read() -> None:
    """A SUBACK for another message id neither grants nor refuses; a repeat
    grant does not run the hook twice."""
    hooks: list[int] = []
    session = retry_module.MqttSession(asyncio.get_running_loop())
    client = _Client()
    client.subscribe = lambda *_args, **_kwargs: (0, 7)  # SUBACK held back
    session.bind(client, subscribe=("t", 1), on_subscribed=lambda: hooks.append(1))
    client.on_connect(client, None, None, 0)

    client.on_subscribe(client, None, 6, [0x80], None)
    client.on_subscribe(client, None, 8, [1], None)
    await asyncio.sleep(0)
    assert not session.connected and not session.lost.is_set()

    client.on_subscribe(client, None, 7, [1], None)
    client.on_subscribe(client, None, 7, [1], None)
    await asyncio.sleep(0)
    assert session.connected and hooks == [1]


class _NetworkThreadClient(_Client):
    """Answers SUBSCRIBE later, from another thread, as paho's network loop does."""

    def __init__(self, granted: int) -> None:
        super().__init__()
        self.granted = granted
        self.release = threading.Event()

    def subscribe(self, topic: str, qos: int = 0) -> tuple[int, int]:
        self.subscribed.append(topic)

        def answer() -> None:
            self.release.wait(5)
            self.on_subscribe(
                self, None, 1, [self.granted if self.granted else qos], None
            )

        threading.Thread(target=answer, daemon=True).start()
        return (0, 1)


@pytest.mark.parametrize("granted", [0, 0x80])
async def test_a_suback_from_the_network_thread_decides_the_session(
    monkeypatch: pytest.MonkeyPatch, granted: int
) -> None:
    """Nothing counts as subscribed until a SUBACK arrives off the event loop."""
    hooks: list[int] = []
    delays: list[float] = []
    shutdown = asyncio.Event()

    async def record(_shutdown: asyncio.Event, base_delay_s: float) -> bool:
        delays.append(base_delay_s)
        shutdown.set()
        return False

    monkeypatch.setattr(retry_module, "wait_before_retry", record)
    client = _NetworkThreadClient(granted)
    service = _service("firmware_telemetry", [client])
    service._on_connected = lambda: hooks.append(1)
    serving = asyncio.create_task(service.serve_until(shutdown))
    try:
        await wait_until(lambda: bool(client.subscribed), what="SUBSCRIBE to be sent")
        await asyncio.sleep(0.05)
        assert hooks == [] and not serving.done(), "up before any SUBACK"
        client.release.set()
        if granted:
            await asyncio.wait_for(serving, 5)
            assert hooks == [] and delays == [5.0]
        else:
            await wait_until(lambda: hooks == [1], what="the grant to run the hook")
            assert not serving.done()
    finally:
        shutdown.set()
        client.release.set()
        await settle([serving], what="the subscriber to stop")
