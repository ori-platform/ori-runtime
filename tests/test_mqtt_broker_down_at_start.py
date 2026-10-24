# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A broker that is down when the runtime starts is retried, not skipped.

An MQTT-family connect that could not reach its broker used to raise, and the
runtime skipped the sensor for the life of the process: a broker co-located
with the runtime that started after it left the sensor silent until a restart.
The sensor now enters the reconnect back-off a dropped broker uses, reads
refuse until its first value, and it reports unconnected until then.
"""

from __future__ import annotations

import asyncio
import logging
import textwrap
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import aiomqtt
import pytest

from ori.actions.alert_delivery import AlertSendReceipt
from ori.actions.alert_failover import AlertFailoverSender
from ori.hal.base import AdapterConnectionError, AdapterReadError
from ori.hal.mqtt_base import MqttCachedAdapter
from ori.runtime import OriRuntime
from ori.security.commissioning.profiles import load_profile_set
from ori.sensor_connection import (
    announce_late_connection,
    close_adapters,
    connected_late,
)
from tests.commissioning.signing import commission_relay
from tests.package_layout import patch_runtime
from tests.test_mqtt_adapter import _FakeClient
from tests.test_mqtt_subscription_refused import _adapter
from tests.test_mqtt_subscription_refused import _config as family_config
from tests.test_mqtt_wildcard_topic import SENSORS
from tests.test_runtime import _patch_external, _stop_and_join
from tests.waiting import HOLD_S, settle, wait_until

TOPIC = "plant/chiller/supply"
SENSOR_ID = "chiller-temp"


class _Stream:
    """Delivers queued messages; a queued exception ends the stream, as a drop."""

    def __init__(self, queue: asyncio.Queue[Any]) -> None:
        self._queue = queue

    def __aiter__(self) -> _Stream:
        return self

    async def __anext__(self) -> Any:
        item = await self._queue.get()
        if isinstance(item, BaseException):
            raise item
        return item


class _Broker:
    """A broker the test brings up; until then every connect is refused."""

    def __init__(self, error: Exception | None = None) -> None:
        self.up = False
        self.refused = 0
        self.error = error or OSError("[Errno 61] Connection refused")
        # The SUBACK codes, or an exception the client raises on SUBSCRIBE.
        self.suback: Any = (0,)
        self.clients: list[_FakeClient] = []

    def client(self, **kwargs: Any) -> _FakeClient:
        broker = self

        class _Client(_FakeClient):
            async def __aenter__(self) -> Any:
                if not broker.up:
                    broker.refused += 1
                    raise broker.error
                return await super().__aenter__()

            @property
            def messages(self) -> Any:
                return _Stream(self._queue)

            async def subscribe(self, topic: str) -> Any:
                await super().subscribe(topic)
                if isinstance(broker.suback, Exception):
                    raise broker.suback
                return broker.suback

        built = _Client(**kwargs)
        self.clients.append(built)
        return built

    def connected(self) -> list[_FakeClient]:
        return [
            c
            for c in self.clients
            if c.subscriptions and not c.closed and self.suback == (0,)
        ]


def _patched(broker: _Broker, delay: Any) -> tuple[Any, ...]:
    return (
        patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
        patch("ori.hal.mqtt_base._aiomqtt", SimpleNamespace(Client=broker.client)),
        patch("ori.hal.mqtt_base.reconnect_delay", delay),
    )


@pytest.mark.parametrize("protocol", sorted(SENSORS))
async def test_a_broker_down_at_connect_is_retried_until_it_answers(
    protocol: str, caplog: pytest.LogCaptureFixture
) -> None:
    broker = _Broker()
    attempts: list[int] = []

    def delay(attempt: int) -> float:
        attempts.append(attempt)
        return 0.005

    available, module, backoff = _patched(broker, delay)
    with available, module, backoff:
        adapter = _adapter(protocol)
        await adapter.connect(family_config(protocol))
        try:
            assert adapter.is_connected and adapter.connection_retrying
            assert not await adapter.health_check()
            with pytest.raises(AdapterReadError, match="connection is down"):
                await adapter.read("s1")
            await wait_until(lambda: len(attempts) >= 3, what="three retries")
            assert not await adapter.health_check()
            assert attempts[:3] == [0, 1, 2], "not the reconnect back-off"
            assert adapter._client is None and not broker.connected()
            assert "lost the broker" not in caplog.text, "no link was ever up"

            broker.up = True
            await wait_until(lambda: adapter._link_up, what="the broker to be reached")
            assert not adapter.connection_retrying
            client = broker.clients[-1]
            assert adapter._client is client and client.subscriptions
            assert await adapter.health_check()
            with pytest.raises(AdapterReadError) as caught:
                await adapter.read("s1")
            assert "connection is down" not in str(caught.value)

            # A later drop with the broker gone again is unhealthy too.
            broker.up = False
            refused = broker.refused
            await client._queue.put(aiomqtt.MqttError("Disconnected"))
            await wait_until(lambda: broker.refused >= refused + 2, what="retries")
            assert adapter.is_connected and not await adapter.health_check()
            broker.up = True
            await wait_until(lambda: adapter._link_up, what="the second reconnect")
            assert await adapter.health_check()
        finally:
            await adapter.close()
        assert adapter._listener_task is None and adapter._client is None


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(aiomqtt.MqttCodeError(5), id="connack-not-authorised"),
        pytest.param(
            aiomqtt.MqttError("[Errno 8] nodename nor servname provided"),
            id="dns",
        ),
        pytest.param(TimeoutError("timed out"), id="timeout"),
    ],
)
async def test_a_refused_or_unresolved_connect_at_start_is_retried(
    error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    broker = _Broker(error)
    available, module, backoff = _patched(broker, lambda _a: 0.005)
    with available, module, backoff, caplog.at_level(logging.WARNING):
        adapter = _adapter("mqtt")
        await adapter.connect(family_config("mqtt"))
        try:
            assert adapter.connection_retrying
            await wait_until(lambda: broker.refused >= 2, what="a retry")
            assert str(error) in caplog.text
        finally:
            await adapter.close()


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(ValueError("Invalid subscription filter."), id="paho-filter"),
        pytest.param(TypeError("bad argument"), id="type"),
    ],
)
async def test_an_error_that_cannot_succeed_fails_the_connect(
    error: Exception,
) -> None:
    broker = _Broker()
    broker.up = True
    broker.suback = error
    available, module, backoff = _patched(broker, lambda _a: 0.005)
    with available, module, backoff:
        adapter = _adapter("mqtt")
        with pytest.raises(AdapterConnectionError, match=str(error)):
            await adapter.connect(family_config("mqtt"))
    assert adapter._listener_task is None and adapter._client is None
    assert len(broker.clients) == 1 and broker.clients[0].closed


@pytest.mark.parametrize(
    "where",
    [
        pytest.param(lambda v: {"mqtt": {"timeout": v}}, id="mqtt.timeout"),
        pytest.param(lambda v: {"mqtt_timeout_s": v}, id="mqtt_timeout_s"),
        pytest.param(lambda v: {"timeout": v}, id="timeout"),
    ],
)
@pytest.mark.parametrize("value", [0, 0.0, -1, float("nan"), float("inf")])
async def test_a_timeout_that_cannot_wait_fails_the_connect(
    where: Any, value: float
) -> None:
    """A zero timeout would fail every attempt at once and be retried forever."""
    broker = _Broker()
    broker.up = True
    available, module, backoff = _patched(broker, lambda _a: 0.005)
    with available, module, backoff:
        adapter = _adapter("mqtt")
        with pytest.raises(AdapterConnectionError, match="timeout must be"):
            await adapter.connect({**family_config("mqtt"), **where(value)})
    assert not broker.clients and adapter._listener_task is None


async def test_a_close_during_the_start_back_off_ends_it() -> None:
    broker = _Broker()
    available, module, backoff = _patched(broker, lambda _a: 3600.0)
    with available, module, backoff:
        adapter = _adapter("mqtt")
        await adapter.connect(family_config("mqtt"))
        listener = adapter._listener_task
        assert listener is not None and adapter.connection_retrying
        await adapter.close()
    assert listener.done() and adapter._listener_task is None
    assert broker.refused == 1


def _config(
    tmp_path: Path,
    *,
    operator: bool = True,
    sensor_type: str = "temperature",
    unit: str = "celsius",
    relay: str = "enabled: false",
) -> Path:
    contact = 'operator_contact: "+2348000000000"' if operator else ""
    cfg = tmp_path / "ori.yaml"
    cfg.write_text(
        textwrap.dedent(f"""\
            device:
              id: test-device-01
              name: Test Device
              location: Test Lab

            sensors:
              - id: {SENSOR_ID}
                type: {sensor_type}
                unit: {unit}
                protocol: mqtt
                broker_host: 127.0.0.1
                topic: {TOPIC}
                poll_interval_ms: 100

            skills: []

            reasoning:
              default_tier: rule

            gateway:
              enabled: false
              broker_url: ""

            actions:
              primary_alert_channel: sms
              {contact}
              whatsapp:
                enabled: false
              sms:
                enabled: false
              relay:
                {relay}

            skills_dir: {str(tmp_path / "skills")}
            database:
              path: {str(tmp_path / "ori_state.db")}
        """),
        encoding="utf-8",
    )
    (tmp_path / "skills").mkdir()
    return cfg


def _sensor(snapshot: dict[str, Any]) -> dict[str, Any]:
    return next(s for s in snapshot["sensors"] if s["id"] == SENSOR_ID)


async def test_the_runtime_connects_a_sensor_whose_broker_starts_late(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_external(monkeypatch)
    sent: list[str] = []

    async def _send(self: Any, *, alert: Any, to_number: str, **kwargs: Any) -> Any:
        sent.append(alert.sms_body)
        return AlertSendReceipt.accepted_without_provider_receipt(channel="sms")

    monkeypatch.setattr(AlertFailoverSender, "send", _send)
    broker = _Broker()
    available, module, backoff = _patched(broker, lambda _a: 0.005)
    with available, module, backoff:
        runtime = OriRuntime(config_path=str(_config(tmp_path)))
        start_task = asyncio.create_task(runtime.start())
        try:
            await wait_until(
                lambda: (
                    (runtime._adapters and broker.refused >= 3 and sent)
                    or start_task.done()
                ),
                what="the adapter recorded, retried, and the operator told",
            )
            assert not start_task.done(), "startup ended instead of retrying"
            assert runtime._unconnected_sensors == {SENSOR_ID}
            assert any(SENSOR_ID in m and "being retried" in m for m in sent), sent
            snapshot = await runtime._build_health_snapshot()
            assert snapshot["status"] != "healthy"
            assert _sensor(snapshot)["connected"] is False
            assert _sensor(snapshot)["last_seen_ms"] is None
            (adapter,) = runtime._adapters
            assert isinstance(adapter, MqttCachedAdapter)
            with pytest.raises(AdapterReadError, match="connection is down"):
                await adapter.read(SENSOR_ID)

            broker.up = True
            await wait_until(broker.connected, what="the broker to be reached")
            (client,) = broker.connected()
            assert client.subscriptions == [TOPIC]
            with pytest.raises(AdapterReadError, match="no MQTT data cached yet"):
                await adapter.read(SENSOR_ID)
            assert runtime._unconnected_sensors == {SENSOR_ID}

            await client.emit(TOPIC, b'{"value": 21.5}')
            await wait_until(
                lambda: SENSOR_ID in runtime._connected_sensor_ids,
                what="the first reading to connect the sensor",
            )
            assert not runtime._unconnected_sensors
            assert (await adapter.read(SENSOR_ID)).value == pytest.approx(21.5)
            snapshot = await runtime._build_health_snapshot()
            assert _sensor(snapshot)["connected"] is True
            assert _sensor(snapshot)["last_seen_ms"] is not None
        finally:
            await _stop_and_join(runtime, start_task)


async def test_a_stop_during_the_start_back_off_ends_promptly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_external(monkeypatch)
    broker = _Broker()
    available, module, backoff = _patched(broker, lambda _a: 3600.0)
    with available, module, backoff:
        runtime = OriRuntime(config_path=str(_config(tmp_path)))
        start_task = asyncio.create_task(runtime.start())
        try:
            await wait_until(
                lambda: runtime._adapters or start_task.done(),
                what="the adapter to be connected and backing off",
            )
            (adapter,) = runtime._adapters
            assert isinstance(adapter, MqttCachedAdapter)
            listener = adapter._listener_task
            assert listener is not None and adapter.connection_retrying
        finally:
            await _stop_and_join(runtime, start_task)
        assert listener.done()
        assert not [
            task
            for task in asyncio.all_tasks()
            if task.get_name().startswith("mqtt-listener") and not task.done()
        ]
    assert broker.refused == 1


class _Running:
    """A started runtime over a faked broker, with every notice it sends."""

    def __init__(self, runtime: OriRuntime, broker: _Broker) -> None:
        self.runtime = runtime
        self.broker = broker
        self.notices: list[tuple[str, bool]] = []
        self.reads: list[Any] = []

    def sent(self, trigger: str) -> int:
        return sum(1 for name, _ in self.notices if name == trigger)

    def record_reads(self) -> MqttCachedAdapter:
        (adapter,) = self.runtime._adapters
        assert isinstance(adapter, MqttCachedAdapter)
        original = adapter.read

        async def recording(sensor_id: str) -> Any:
            try:
                reading = await original(sensor_id)
            except Exception as exc:
                self.reads.append(exc)
                raise
            self.reads.append(reading.value)
            return reading

        adapter.read = recording  # type: ignore[method-assign]
        return adapter

    async def polls(self, count: int = 2) -> None:
        """Wait for *count* more reads, so the poll that saw a value has finished."""
        target = len(self.reads) + count
        await wait_until(lambda: len(self.reads) >= target, what=f"{count} polls")

    def client(self) -> _FakeClient:
        (client,) = self.broker.connected()
        return client


def _spy_notices(
    monkeypatch: pytest.MonkeyPatch, running: list[_Running], hang: str
) -> None:
    original = OriRuntime._send_or_queue_safety_alert

    async def spy(self: OriRuntime, **kwargs: Any) -> bool:
        if kwargs["trigger_name"] == hang:
            running[0].notices.append((hang, False))
            await asyncio.sleep(HOLD_S)
        told = await original(self, **kwargs)
        running[0].notices.append((kwargs["trigger_name"], told))
        return told

    monkeypatch.setattr(OriRuntime, "_send_or_queue_safety_alert", spy)


async def _start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    broker: _Broker,
    hang: str = "",
    **config: Any,
) -> tuple[_Running, asyncio.Task[Any]]:
    _patch_external(monkeypatch)
    holder: list[_Running] = []
    _spy_notices(monkeypatch, holder, hang)
    runtime = OriRuntime(config_path=str(_config(tmp_path, **config)))
    holder.append(_Running(runtime, broker))
    return holder[0], asyncio.create_task(runtime.start())


async def _wait_retrying(running: _Running, start_task: asyncio.Task[Any]) -> None:
    await wait_until(
        lambda: (
            (running.runtime._adapters and running.runtime._unconnected_sensors)
            or start_task.done()
        ),
        what="the sensor to be retrying",
    )
    assert not start_task.done(), "startup ended instead of retrying"


async def test_one_notice_at_start_and_one_when_the_sensor_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker = _Broker()
    patches = _patched(broker, lambda _a: 0.005)
    with patches[0], patches[1], patches[2]:
        running, start_task = await _start(tmp_path, monkeypatch, broker)
        try:
            await _wait_retrying(running, start_task)
            await wait_until(
                lambda: running.sent("sensor_unconnected_warning"),
                what="the start notice",
            )
            running.record_reads()
            broker.up = True
            await wait_until(broker.connected, what="the broker to be reached")
            await running.client().emit(TOPIC, b'{"value": 21.5}')
            await wait_until(
                lambda: running.sent("sensor_connected_notice"),
                what="the recovery notice",
            )
            await running.client().emit(TOPIC, b'{"value": 22.5}')
            await wait_until(lambda: 22.5 in running.reads, what="a second value")
            await running.polls()
            assert running.notices == [
                ("sensor_unconnected_warning", True),
                ("sensor_connected_notice", True),
            ]
        finally:
            await _stop_and_join(running.runtime, start_task)


async def test_no_recovery_notice_without_a_start_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker = _Broker()
    patches = _patched(broker, lambda _a: 0.005)
    with patches[0], patches[1], patches[2]:
        running, start_task = await _start(
            tmp_path, monkeypatch, broker, operator=False
        )
        try:
            await _wait_retrying(running, start_task)
            await wait_until(
                lambda: running.notices, what="the start notice to be attempted"
            )
            running.record_reads()
            broker.up = True
            await wait_until(broker.connected, what="the broker to be reached")
            await running.client().emit(TOPIC, b'{"value": 21.5}')
            await wait_until(
                lambda: SENSOR_ID in running.runtime._connected_sensor_ids,
                what="the first reading",
            )
            await running.polls()
            assert running.notices == [("sensor_unconnected_warning", False)]
        finally:
            await _stop_and_join(running.runtime, start_task)


@pytest.mark.parametrize("value", ['"abc"', "NaN", "1e400", "null"])
async def test_a_refused_payload_does_not_connect_the_sensor(
    value: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker = _Broker()
    patches = _patched(broker, lambda _a: 0.005)
    with patches[0], patches[1], patches[2]:
        running, start_task = await _start(tmp_path, monkeypatch, broker)
        try:
            await _wait_retrying(running, start_task)
            running.record_reads()
            broker.up = True
            await wait_until(broker.connected, what="the broker to be reached")
            await running.client().emit(TOPIC, f'{{"value": {value}}}'.encode())
            await wait_until(
                lambda: any("refused" in str(r) for r in running.reads),
                what="the payload to be refused",
            )
            await running.polls()
            runtime = running.runtime
            assert runtime._unconnected_sensors == {SENSOR_ID}
            snapshot = await runtime._build_health_snapshot()
            assert _sensor(snapshot)["connected"] is False
            assert _sensor(snapshot)["last_seen_ms"] is None
            assert not running.sent("sensor_connected_notice")
        finally:
            await _stop_and_join(running.runtime, start_task)


async def test_a_subscription_refused_at_start_is_retried_by_the_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    broker = _Broker()
    broker.up = True
    broker.suback = (0x87,)
    patches = _patched(broker, lambda _a: 0.005)
    with (
        patches[0],
        patches[1],
        patches[2],
        caplog.at_level(logging.WARNING, logger="ori.hal.mqtt_base"),
    ):
        running, start_task = await _start(tmp_path, monkeypatch, broker)
        try:
            await _wait_retrying(running, start_task)
            await wait_until(lambda: len(broker.clients) >= 3, what="retries")
            refusals = [
                r.getMessage()
                for r in caplog.records
                if "refused the subscription" in r.getMessage()
            ]
            assert len(refusals) >= 2
            assert all(f"topic={TOPIC!r}" in m and "SUBACK 0x87" in m for m in refusals)
            snapshot = await running.runtime._build_health_snapshot()
            assert snapshot["status"] != "healthy"
            assert _sensor(snapshot)["connected"] is False

            broker.suback = (0,)
            await wait_until(broker.connected, what="the grant")
            await running.client().emit(TOPIC, b'{"value": 21.5}')
            await wait_until(
                lambda: SENSOR_ID in running.runtime._connected_sensor_ids,
                what="the first reading",
            )
        finally:
            await _stop_and_join(running.runtime, start_task)


async def test_a_pair_on_a_retrying_sensor_recovers_on_its_first_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ratified = load_profile_set(
        [
            {
                "v": 1,
                "id": "fixture.overcurrent.v1",
                "status": "ratified",
                "observes": {"quantity": "current", "unit": "ampere"},
                "condition": {
                    "kind": "upper_capacity_multiplier",
                    "capacity_parameter": "rated_capacity_amps",
                    "multiplier": 2.0,
                },
                "outcome": "open_protected_circuit",
            }
        ]
    )
    patch_runtime(monkeypatch, "load_shipped_profile_set", lambda: ratified)
    patch_runtime(monkeypatch, "gpio_backend_importable", lambda: True)
    patch_runtime(monkeypatch, "gpio_backend_arbitrated", lambda: True)
    commission_relay(
        tmp_path / "ori.yaml",
        monkeypatch,
        device_id="test-device-01",
        sensor_id=SENSOR_ID,
        proof_method="actuate_and_observe",
    )
    broker = _Broker()
    patches = _patched(broker, lambda _a: 0.005)
    with patches[0], patches[1], patches[2]:
        running, start_task = await _start(
            tmp_path,
            monkeypatch,
            broker,
            sensor_type="current",
            unit="ampere",
            relay="{enabled: false, gpio_pin: 26}",
        )

        async def zone() -> dict[str, Any]:
            snapshot = await running.runtime._build_health_snapshot()
            zones = snapshot.get("safety_zones")
            assert zones, "no eligible pair was reported"
            return next(z for z in zones if z["zone_id"])

        try:
            await _wait_retrying(running, start_task)
            await wait_until(
                lambda: running.sent("safety_measurement_loss"), what="the pair notice"
            )
            entry = await zone()
            assert entry["activation"] == "active", entry
            assert entry["measurement_degraded"] is True, entry
            assert not running.sent("sensor_unconnected_warning")

            broker.up = True
            await wait_until(broker.connected, what="the broker to be reached")
            await running.client().emit(TOPIC, b'{"value": 0.5}')

            async def recovered() -> bool:
                return (await zone())["measurement_degraded"] is False

            await wait_until(recovered, what="the pair to recover")
            await wait_until(
                lambda: running.sent("sensor_connected_notice"),
                what="the recovery notice",
            )
            assert running.sent("sensor_connected_notice") == 1
        finally:
            await _stop_and_join(running.runtime, start_task)


async def test_a_later_drop_sends_no_second_recovery_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker = _Broker()
    patches = _patched(broker, lambda _a: 0.005)
    with patches[0], patches[1], patches[2]:
        running, start_task = await _start(tmp_path, monkeypatch, broker)
        try:
            await _wait_retrying(running, start_task)
            running.record_reads()
            broker.up = True
            await wait_until(broker.connected, what="the broker to be reached")
            first = running.client()
            await first.emit(TOPIC, b'{"value": 21.5}')
            await wait_until(
                lambda: running.sent("sensor_connected_notice"),
                what="the recovery notice",
            )
            await first._queue.put(aiomqtt.MqttError("Disconnected"))
            await wait_until(
                lambda: broker.connected() and running.client() is not first,
                what="the reconnect",
            )
            await running.client().emit(TOPIC, b'{"value": 23.5}')
            await wait_until(lambda: 23.5 in running.reads, what="a value after it")
            await running.polls()
            assert running.sent("sensor_connected_notice") == 1
            assert [
                task.get_name()
                for task in running.runtime._background_tasks
                if task.get_name().startswith("sensor-connected-notice:")
            ] == [f"sensor-connected-notice:{SENSOR_ID}"]
        finally:
            await _stop_and_join(running.runtime, start_task)


async def test_a_recovery_notice_in_flight_is_cancelled_at_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker = _Broker()
    patches = _patched(broker, lambda _a: 0.005)
    with patches[0], patches[1], patches[2]:
        running, start_task = await _start(
            tmp_path, monkeypatch, broker, hang="sensor_connected_notice"
        )
        try:
            await _wait_retrying(running, start_task)
            broker.up = True
            await wait_until(broker.connected, what="the broker to be reached")
            await running.client().emit(TOPIC, b'{"value": 21.5}')
            await wait_until(
                lambda: running.sent("sensor_connected_notice"),
                what="the recovery notice to be in flight",
            )
            (notice,) = [
                task
                for task in running.runtime._background_tasks
                if task.get_name().startswith("sensor-connected-notice:")
            ]
            assert not notice.done()
        finally:
            await _stop_and_join(running.runtime, start_task)
        assert notice.cancelled()


async def test_a_sensor_is_connected_and_announced_once() -> None:
    unconnected, connected, announced = {"s1"}, set[str](), {"s1"}
    sent: list[str] = []

    async def send(message: str, trigger: str) -> bool:
        sent.append(trigger)
        return True

    assert connected_late("s1", unconnected=unconnected, connected=connected)
    assert not connected_late("s1", unconnected=unconnected, connected=connected)
    assert connected == {"s1"} and not unconnected
    await announce_late_connection("s1", announced=announced, send=send)
    await announce_late_connection("s1", announced=announced, send=send)
    assert sent == ["sensor_connected_notice"] and not announced


class _SlowClose:
    """An adapter whose close is held until the test releases every one."""

    def __init__(self, entered: asyncio.Event, release: asyncio.Event) -> None:
        self.entered = entered
        self.release = release
        self.closed = False

    async def close(self) -> None:
        self.entered.set()
        await self.release.wait()
        self.closed = True


class _FailingClose:
    async def close(self) -> None:
        raise RuntimeError("simulated close failure")


async def test_adapters_close_concurrently_and_a_failure_stops_none() -> None:
    release = asyncio.Event()
    entered = [asyncio.Event() for _ in range(3)]
    slow = [_SlowClose(event, release) for event in entered]
    closing = asyncio.create_task(close_adapters([slow[0], _FailingClose(), *slow[1:]]))
    # Every close is under way at once, before any is allowed to finish.
    await wait_until(
        lambda: all(event.is_set() for event in entered), what="all closes to start"
    )
    assert not any(adapter.closed for adapter in slow)
    release.set()
    await settle({closing}, what="the closes")
    assert closing.exception() is None
    assert all(adapter.closed for adapter in slow)


async def test_a_dead_listener_is_unhealthy_with_the_link_up() -> None:
    broker = _Broker()
    broker.up = True
    available, module, backoff = _patched(broker, lambda _a: 0.005)
    with available, module, backoff:
        adapter = _adapter("mqtt")
        await adapter.connect(family_config("mqtt"))
        try:
            assert await adapter.health_check()
            listener = adapter._listener_task
            assert listener is not None
            listener.cancel()
            await settle({listener}, what="the listener to end")
            assert adapter._link_up and not await adapter.health_check()
        finally:
            await adapter.close()


async def test_a_stop_during_the_start_notice_closes_the_retrying_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The adapter is recorded before the start notice is awaited, so a stop
    while that send is blocked still closes it and its reconnect supervisor."""
    from ori.hal.protocol_registry import make_adapter as real_make

    made: list[Any] = []

    def recording(protocol: str) -> Any:
        adapter = real_make(protocol)
        made.append(adapter)
        return adapter

    patch_runtime(monkeypatch, "make_adapter", recording)
    broker = _Broker()
    patches = _patched(broker, lambda _a: 0.005)
    with patches[0], patches[1], patches[2]:
        running, start_task = await _start(
            tmp_path, monkeypatch, broker, hang="sensor_unconnected_warning"
        )
        try:
            await wait_until(
                lambda: running.sent("sensor_unconnected_warning") or start_task.done(),
                what="the start notice to be held mid-send",
            )
            assert not start_task.done()
        finally:
            await _stop_and_join(running.runtime, start_task)
        (adapter,) = made
        assert not adapter.is_connected, "the retrying adapter was never closed"
        assert adapter._listener_task is None
        assert not [
            task
            for task in asyncio.all_tasks()
            if task.get_name().startswith("mqtt-listener") and not task.done()
        ], "a reconnect supervisor outlived the stop"
