# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A cached sensor is silent once its value outlives the silence bound.

Every adapter that serves a cache — the MQTT family, HTTP and CoAP — used to
serve its last value for as long as its listener or poller lived. The runtime
counted each read as a live reading, so the staleness watch never fired and the
safety registry judged a frozen value as fresh.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, AsyncIterator, Callable
from unittest.mock import AsyncMock, patch

import pytest

import ori.hal.base as hal_base
from ori.hal.base import AdapterReadError, silence_bound_ms
from ori.hal.coap_adapter import CoapAdapter
from ori.hal.http_adapter import HttpAdapter
from ori.hal.lorawan_adapter import LoraWanAdapter
from ori.hal.mqtt_adapter import MqttAdapter
from ori.hal.mqtt_perception_adapter import MqttPerceptionAdapter
from ori.hal.victron_adapter import VictronAdapter
from ori.hal.zigbee_adapter import ZigbeeAdapter
from ori.network.event_bus import EventBus
from ori.runtime import OriRuntime
from ori.state.store import StateStore
from tests.test_lorawan_adapter import _config as lorawan_config
from tests.test_mqtt_adapter import _config as mqtt_config
from tests.test_mqtt_adapter import _FakeClient, _FakeTopic
from tests.test_mqtt_perception_adapter import _config as perception_config
from tests.test_victron_adapter import _config as victron_config
from tests.test_zigbee_adapter import _config as zigbee_config

POLL_MS = 1000
BOUND_MS = silence_bound_ms(POLL_MS)
SENSOR = "main-distribution-current"
DEVICE = "bench-runtime-01"
HAZARD = 25.0  # above the fixture profile's trip point of 2 x 10 A
CLEAR = 5.0


class _Clock:
    def __init__(self) -> None:
        self.now = 5_000.0

    def __call__(self) -> float:
        return self.now

    def advance_ms(self, ms: float) -> None:
        self.now += ms / 1000.0


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr(hal_base, "_arrival_clock", fake)
    return fake


class _RetainedMessage:
    def __init__(self, topic: str, payload: bytes) -> None:
        self.topic = _FakeTopic(topic)
        self.payload = payload
        self.retain = True


async def _settle() -> None:
    for _ in range(5):
        await asyncio.sleep(0)


class _MqttSource:
    """One MQTT-family adapter behind a fake broker."""

    def __init__(
        self,
        adapter_type: type,
        config: dict[str, Any],
        body: Callable[[float, int | None, float], Any],
    ) -> None:
        self.adapter_type = adapter_type
        self.config = {**config, "poll_interval_ms": POLL_MS}
        self.body = body
        self.adapter: Any = None
        self._stack = contextlib.ExitStack()

    @property
    def topic(self) -> str:
        if isinstance(self.adapter, VictronAdapter):
            return self.adapter._topic_for_sensor(self.config["sensor_type"])
        return self.config["topic"]

    async def start(self) -> None:
        self._stack.enter_context(patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True))
        self._stack.enter_context(
            patch("ori.hal.mqtt_base._aiomqtt", SimpleNamespace(Client=_FakeClient))
        )
        self.adapter = self.adapter_type()
        await self.adapter.connect(self.config)

    def _payload(self, value: float, ts: int | None, quality: float) -> bytes:
        return json.dumps(self.body(value, ts, quality)).encode()

    async def send(
        self, value: float, *, ts: int | None = None, quality: float = 1.0
    ) -> None:
        await self.adapter._client.emit(self.topic, self._payload(value, ts, quality))
        await _settle()

    async def replay(self, value: float) -> None:
        """The broker's retained copy, delivered on subscribe."""
        await self.adapter._client._queue.put(
            _RetainedMessage(self.topic, self._payload(value, None, 1.0))
        )
        await _settle()

    async def fail(self) -> None:
        """A silent publisher sends nothing."""

    async def reconnect(self) -> None:
        await self.adapter.close()
        await self.adapter.connect(self.config)

    async def stop(self) -> None:
        with contextlib.suppress(Exception):
            await self.adapter.close()
        self._stack.close()


class _HttpResponse:
    def __init__(self, payload: Any) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        if isinstance(self._payload, Exception):
            raise self._payload

    def json(self) -> Any:
        return self._payload


class _HttpSource:
    def __init__(self) -> None:
        self.responses: list[_HttpResponse] = []
        self.config = {
            "sensor_id": SENSOR,
            "sensor_type": "current",
            "url": "http://meter.local/metrics",
            "json_path": "main.current",
            "unit": "ampere",
            "poll_interval_ms": POLL_MS,
            "timeout_s": 2.0,
            "circuit_breaker": {
                "failure_threshold": 3,
                "recovery_timeout_s": 300,
                "success_threshold": 2,
            },
        }
        self.adapter: Any = None
        self._stack = contextlib.ExitStack()

    async def start(self) -> None:
        responses = self.responses

        class _Client:
            def __init__(self, *, timeout: float) -> None:
                self.timeout = timeout

            async def __aenter__(self) -> Any:
                return self

            async def __aexit__(self, *_exc: Any) -> None:
                return None

            async def get(self, _url: str) -> _HttpResponse:
                return responses.pop(0)

        async def _idle(*_args: Any, **_kwargs: Any) -> None:
            await asyncio.sleep(3600)

        self._stack.enter_context(patch("ori.hal.http_adapter._HTTPX_AVAILABLE", True))
        self._stack.enter_context(
            patch("ori.hal.http_adapter._httpx", SimpleNamespace(AsyncClient=_Client))
        )
        self._stack.enter_context(patch.object(HttpAdapter, "_poll_loop", new=_idle))
        self.adapter = HttpAdapter()
        await self.adapter.connect(self.config)

    async def send(
        self, value: float, *, ts: int | None = None, quality: float = 1.0
    ) -> None:
        body: dict[str, Any] = {"main": {"current": value, "quality": quality}}
        if ts is not None:
            body["timestamp_ms"] = ts
        self.responses.append(_HttpResponse(body))
        await self.adapter._poll_once()

    async def fail(self) -> None:
        self.responses.append(_HttpResponse(RuntimeError("503")))
        with pytest.raises(AdapterReadError):
            await self.adapter._poll_once()

    async def reconnect(self) -> None:
        await self.adapter.close()
        await self.adapter.connect(self.config)

    async def stop(self) -> None:
        with contextlib.suppress(Exception):
            await self.adapter.close()
        self._stack.close()


class _CoapSource:
    def __init__(self) -> None:
        self.futures: list[asyncio.Future[Any]] = []
        self.config = {
            "sensor_id": SENSOR,
            "sensor_type": "current",
            "uri": "coap://192.168.1.70/telemetry/current",
            "method": "GET",
            "json_path": "metrics.current",
            "unit": "ampere",
            "poll_interval_ms": POLL_MS,
            "timeout_s": 0.1,
            "allowed_hosts": ["192.168.1.70"],
            "circuit_breaker": {
                "failure_threshold": 3,
                "recovery_timeout_s": 300,
                "success_threshold": 2,
            },
        }
        self.adapter: Any = None
        self._stack = contextlib.ExitStack()

    async def start(self) -> None:
        futures = self.futures

        class _Context:
            def request(self, _message: Any) -> Any:
                return SimpleNamespace(response=futures.pop(0))

            async def shutdown(self) -> None:
                return None

        async def _create() -> Any:
            return _Context()

        async def _idle(*_args: Any, **_kwargs: Any) -> None:
            await asyncio.sleep(3600)

        fake = SimpleNamespace(
            GET="GET",
            Message=lambda code, uri, payload: SimpleNamespace(
                code=code, uri=uri, payload=payload
            ),
            Context=SimpleNamespace(create_client_context=staticmethod(_create)),
        )
        self._stack.enter_context(
            patch("ori.hal.coap_adapter._AIOCOAP_AVAILABLE", True)
        )
        self._stack.enter_context(patch("ori.hal.coap_adapter._aiocoap", fake))
        self._stack.enter_context(patch.object(CoapAdapter, "_poll_loop", new=_idle))
        self.adapter = CoapAdapter()
        await self.adapter.connect(self.config)

    async def send(
        self, value: float, *, ts: int | None = None, quality: float = 1.0
    ) -> None:
        body: dict[str, Any] = {"metrics": {"current": value, "quality": quality}}
        if ts is not None:
            body["timestamp_ms"] = ts
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        future.set_result(SimpleNamespace(payload=json.dumps(body).encode()))
        self.futures.append(future)
        await self.adapter._poll_once()

    async def fail(self) -> None:
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        future.set_exception(RuntimeError("4.04 not found"))
        self.futures.append(future)
        with pytest.raises(AdapterReadError):
            await self.adapter._poll_once()

    async def reconnect(self) -> None:
        await self.adapter.close()
        await self.adapter.connect(self.config)

    async def stop(self) -> None:
        with contextlib.suppress(Exception):
            await self.adapter.close()
        self._stack.close()


def _mqtt() -> _MqttSource:
    return _MqttSource(
        MqttAdapter,
        {
            **mqtt_config(),
            "sensor_id": SENSOR,
            "sensor_type": "current",
            "unit": "ampere",
        },
        lambda v, ts, q: {
            "reading": {"value": v, "quality": q},
            **({"timestamp_ms": ts} if ts is not None else {}),
        },
    )


def _lorawan() -> _MqttSource:
    return _MqttSource(
        LoraWanAdapter,
        lorawan_config(sensor_type="lorawan_temperature"),
        lambda v, ts, q: {
            "uplink_message": {"decoded_payload": {"temperature": v}},
            **({"timestamp_ms": ts} if ts is not None else {}),
        },
    )


def _zigbee() -> _MqttSource:
    return _MqttSource(
        ZigbeeAdapter,
        zigbee_config(),
        lambda v, ts, q: {
            "temperature": v,
            "quality": q,
            **({"timestamp_ms": ts} if ts is not None else {}),
        },
    )


def _perception() -> _MqttSource:
    return _MqttSource(
        MqttPerceptionAdapter,
        perception_config(),
        lambda v, ts, q: {
            "schema": "ori.perception.v1",
            "sensor_type": "ppe_hardhat_violation_score",
            "value": v / 100.0,
            "confidence": q,
            **({"timestamp_ms": ts} if ts is not None else {}),
        },
    )


def _victron() -> _MqttSource:
    return _MqttSource(
        VictronAdapter,
        victron_config(sensor_type="victron_battery_soc"),
        lambda v, ts, q: {"value": v},
    )


MQTT_FAMILY = [
    pytest.param(_mqtt, id="mqtt"),
    pytest.param(_lorawan, id="lorawan"),
    pytest.param(_zigbee, id="zigbee"),
    pytest.param(_perception, id="mqtt_perception"),
]
ALL_CACHED = [
    *MQTT_FAMILY,
    pytest.param(_HttpSource, id="http"),
    pytest.param(_CoapSource, id="coap"),
]
TIER_D_CAPABLE = [
    pytest.param(_mqtt, id="mqtt"),
    pytest.param(_HttpSource, id="http"),
    pytest.param(_CoapSource, id="coap"),
]


@contextlib.asynccontextmanager
async def _running(factory: Callable[[], Any]) -> AsyncIterator[Any]:
    source = factory()
    await source.start()
    try:
        yield source
    finally:
        await source.stop()


def _value(reading: Any) -> float:
    return float(reading.value)


# ── The adapter boundary ─────────────────────────────────────────────────────


@pytest.mark.parametrize("factory", ALL_CACHED)
async def test_a_value_past_the_silence_bound_is_refused(
    factory: Callable[[], Any], clock: _Clock
) -> None:
    async with _running(factory) as source:
        await source.send(12.0)
        clock.advance_ms(BOUND_MS)
        await source.adapter.read(SENSOR)  # at the bound: still live
        clock.advance_ms(1)
        await source.fail()
        with pytest.raises(AdapterReadError, match="past the silence bound"):
            await source.adapter.read(SENSOR)


@pytest.mark.parametrize("factory", ALL_CACHED)
@pytest.mark.parametrize(
    "producer_ts",
    [
        pytest.param(4_102_444_800_000, id="producer-clock-in-2100"),
        pytest.param(1, id="producer-clock-at-epoch"),
    ],
)
async def test_a_producer_timestamp_does_not_change_the_age(
    factory: Callable[[], Any], clock: _Clock, producer_ts: int
) -> None:
    async with _running(factory) as source:
        await source.send(12.0, ts=producer_ts, quality=1.0)
        clock.advance_ms(BOUND_MS - 1)
        assert _value(await source.adapter.read(SENSOR)) > 0
        clock.advance_ms(2)
        with pytest.raises(AdapterReadError, match="past the silence bound"):
            await source.adapter.read(SENSOR)


@pytest.mark.parametrize("factory", ALL_CACHED)
@pytest.mark.parametrize("wall_step_ms", [-86_400_000, 86_400_000])
async def test_a_wall_clock_step_does_not_change_the_age(
    factory: Callable[[], Any], clock: _Clock, wall_step_ms: int
) -> None:
    import ori.utils.time_utils as time_utils

    async with _running(factory) as source:
        await source.send(12.0)
        stepped = time_utils.time.time() + wall_step_ms / 1000.0
        with patch.object(time_utils, "time", SimpleNamespace(time=lambda: stepped)):
            assert _value(await source.adapter.read(SENSOR)) > 0
            clock.advance_ms(BOUND_MS + 1)
            with pytest.raises(AdapterReadError, match="past the silence bound"):
                await source.adapter.read(SENSOR)


@pytest.mark.parametrize("factory", ALL_CACHED)
async def test_the_bound_follows_the_sensors_own_poll_interval(
    factory: Callable[[], Any], clock: _Clock
) -> None:
    poll_ms = 5000
    source = factory()
    source.config["poll_interval_ms"] = poll_ms
    await source.start()
    try:
        await source.send(12.0)
        clock.advance_ms(silence_bound_ms(poll_ms))
        assert _value(await source.adapter.read(SENSOR)) > 0
        clock.advance_ms(1)
        with pytest.raises(AdapterReadError, match="past the silence bound"):
            await source.adapter.read(SENSOR)
    finally:
        await source.stop()


@pytest.mark.parametrize("factory", ALL_CACHED)
async def test_an_identical_value_that_arrives_again_is_fresh(
    factory: Callable[[], Any], clock: _Clock
) -> None:
    async with _running(factory) as source:
        await source.send(12.0)
        clock.advance_ms(BOUND_MS - 100)
        await source.send(12.0)
        clock.advance_ms(BOUND_MS - 100)
        assert _value(await source.adapter.read(SENSOR)) > 0


@pytest.mark.parametrize("factory", ALL_CACHED)
async def test_a_reconnect_does_not_refresh_an_old_value(
    factory: Callable[[], Any], clock: _Clock
) -> None:
    async with _running(factory) as source:
        await source.send(12.0)
        clock.advance_ms(BOUND_MS + 1)
        await source.reconnect()
        with pytest.raises(AdapterReadError):
            await source.adapter.read(SENSOR)


@pytest.mark.parametrize("factory", MQTT_FAMILY)
async def test_a_retained_replay_is_not_a_reading(
    factory: Callable[[], Any], clock: _Clock
) -> None:
    """The broker replays its retained copy on subscribe; its age is unknowable."""
    async with _running(factory) as source:
        await source.replay(12.0)
        with pytest.raises(AdapterReadError, match="no .* cached"):
            await source.adapter.read(SENSOR)
        await source.send(12.0)
        assert _value(await source.adapter.read(SENSOR)) > 0


@pytest.mark.parametrize("factory", MQTT_FAMILY)
async def test_a_silence_does_not_open_the_breaker(
    factory: Callable[[], Any], clock: _Clock
) -> None:
    """Counted by the breaker, a gap would hold reads refused after it ended."""
    async with _running(factory) as source:
        await source.send(12.0)
        clock.advance_ms(BOUND_MS + 1)
        for _ in range(source.adapter._breaker.failure_threshold + 2):
            with pytest.raises(AdapterReadError, match="past the silence bound"):
                await source.adapter.read(SENSOR)
        await source.send(13.0)
        assert _value(await source.adapter.read(SENSOR)) > 0


def test_the_silence_bound_is_two_intervals_with_a_floor() -> None:
    assert silence_bound_ms(1000) == 2000
    assert silence_bound_ms(60_000) == 120_000
    assert silence_bound_ms(50) == 200


def test_arrival_is_timed_on_the_monotonic_clock() -> None:
    import time

    with patch.object(hal_base.time, "time", lambda: 1e12):
        assert abs(hal_base.cache_arrival() - time.monotonic()) < 1.0


def test_a_cached_value_with_no_arrival_is_refused(clock: _Clock) -> None:
    with pytest.raises(AdapterReadError, match="no arrival time"):
        hal_base.refuse_stale_cache(None, POLL_MS, "Probe")


def test_a_value_that_arrived_after_now_is_refused(clock: _Clock) -> None:
    with pytest.raises(AdapterReadError, match="past the silence bound"):
        hal_base.refuse_stale_cache(clock.now + 1.0, POLL_MS, "Probe")


@pytest.mark.parametrize("raw", [0, -1, True, "1000", 1.5, None])
async def test_an_unusable_poll_interval_refuses_the_mqtt_connect(raw: Any) -> None:
    source = _mqtt()
    source.config["poll_interval_ms"] = raw
    with pytest.raises(Exception, match="poll_interval_ms must be a positive integer"):
        await source.start()
    source._stack.close()


# ── Through the runtime's poll path ──────────────────────────────────────────


class _Harness:
    def __init__(self, runtime: OriRuntime, registry: Any, commander: Any) -> None:
        self.runtime = runtime
        self.registry = registry
        self.commander = commander
        self.observed: list[tuple[str, float]] = []
        self.published: list[Any] = []
        self.bus = EventBus()


@contextlib.asynccontextmanager
async def _runtime(tmp_path: Path) -> AsyncIterator[_Harness]:
    from tests.safety.test_registry import build

    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    registry, commander = build(store)
    await registry.start()
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._safety_registry = registry
    runtime._shutdown_event = asyncio.Event()
    runtime._measurement_refusals = {}
    runtime._measurement_valid_streak = {}
    runtime._measurement_refusal_reason = {}
    runtime._measurement_degraded = set()
    runtime._measurement_unnotified = set()
    runtime._measurement_notify_attempts = {}
    harness = _Harness(runtime, registry, commander)
    real_observe = registry.observe_reading

    async def spy(sensor_id: str, value: float, unit: str, quality: float) -> Any:
        harness.observed.append((sensor_id, value))
        return await real_observe(sensor_id, value, unit, quality)

    registry.observe_reading = spy

    async def _handler(event: Any) -> None:
        harness.published.append(event)

    for sensor_type in ("current", "lorawan_temperature", "temperature"):
        harness.bus.subscribe(sensor_type, _handler)
    try:
        yield harness
    finally:
        await store.close()


async def _poll(harness: _Harness, adapter: Any) -> None:
    """One pass of the runtime's own poll loop against *adapter*."""
    runtime = harness.runtime

    class _OnePass:
        async def read(self, sensor_id: str) -> Any:
            runtime._shutdown_event.set()
            return await adapter.read(sensor_id)

    runtime._shutdown_event.clear()
    sensor_cfg: Any = SimpleNamespace(id=SENSOR, poll_interval_ms=1)
    await runtime._poll_sensor(_OnePass(), sensor_cfg, harness.bus, DEVICE)  # type: ignore[arg-type]


@pytest.mark.parametrize("factory", ALL_CACHED)
async def test_the_runtime_refuses_a_value_past_the_bound(
    factory: Callable[[], Any], clock: _Clock, tmp_path: Path
) -> None:
    async with _runtime(tmp_path) as harness, _running(factory) as source:
        await source.send(12.0)
        await _poll(harness, source.adapter)
        assert len(harness.observed) == 1
        assert SENSOR in harness.runtime._sensor_last_seen_ms

        harness.runtime._sensor_last_seen_ms.pop(SENSOR)
        clock.advance_ms(BOUND_MS + 1)
        await source.fail()
        await _poll(harness, source.adapter)
        assert len(harness.observed) == 1, (
            "the registry observed a value past the silence bound"
        )
        assert SENSOR not in harness.runtime._sensor_last_seen_ms
        assert len(harness.published) <= 1


@pytest.mark.parametrize("factory", TIER_D_CAPABLE)
async def test_a_silent_source_after_a_hazard_is_not_observed_again(
    factory: Callable[[], Any], clock: _Clock, tmp_path: Path
) -> None:
    """The trip fires on the live hazard; the silence that follows is refused."""
    async with _runtime(tmp_path) as harness, _running(factory) as source:
        await source.send(HAZARD)
        await _poll(harness, source.adapter)
        assert harness.observed == [(SENSOR, HAZARD)]
        assert harness.commander.outcome_calls == [
            ("main-distribution", "open_protected_circuit")
        ]

        clock.advance_ms(BOUND_MS + 1)
        for _ in range(5):
            await _poll(harness, source.adapter)
        assert harness.observed == [(SENSOR, HAZARD)]

        # The source resumes: the next live value reaches the registry at once.
        await source.send(CLEAR)
        await _poll(harness, source.adapter)
        assert harness.observed == [(SENSOR, HAZARD), (SENSOR, CLEAR)]


@pytest.mark.parametrize("factory", TIER_D_CAPABLE)
async def test_a_hazard_that_repeats_the_last_value_is_observed(
    factory: Callable[[], Any], clock: _Clock, tmp_path: Path
) -> None:
    async with _runtime(tmp_path) as harness, _running(factory) as source:
        await source.send(HAZARD)
        await _poll(harness, source.adapter)
        clock.advance_ms(BOUND_MS + 1)
        await source.send(HAZARD)
        await _poll(harness, source.adapter)
        assert harness.observed == [(SENSOR, HAZARD), (SENSOR, HAZARD)]
        assert SENSOR in harness.runtime._sensor_last_seen_ms


@pytest.mark.parametrize("poll_ms", [POLL_MS, 5000])
async def test_the_staleness_watch_uses_the_same_silence_bound(poll_ms: int) -> None:
    """The adapter refuses and the watch warns at one bound, so neither lags."""
    from unittest.mock import AsyncMock

    from ori.utils.time_utils import now_ms

    bound = silence_bound_ms(poll_ms)
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._shutdown_event = asyncio.Event()
    runtime._sensor_poll_interval_ms = {"inside": poll_ms, "past": poll_ms}
    now = now_ms()
    runtime._sensor_last_seen_ms = {
        "inside": now - (bound - 500),
        "past": now - (bound + 500),
    }
    runtime._stale_sensor_active = set()
    runtime._send_or_queue_alert = AsyncMock(return_value=True)  # type: ignore[method-assign]

    loop = asyncio.create_task(
        runtime._sensor_staleness_loop(alert_sender=AsyncMock(), check_interval_s=1.0)
    )
    for _ in range(50):
        if runtime._stale_sensor_active:
            break
        await asyncio.sleep(0.01)
    runtime._shutdown_event.set()
    await loop
    assert runtime._stale_sensor_active == {"past"}


@pytest.mark.parametrize("poll_ms", [POLL_MS, 5000])
async def test_the_health_stale_flag_uses_the_same_silence_bound(poll_ms: int) -> None:
    bound = silence_bound_ms(poll_ms)
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._configured_sensors = [
        SimpleNamespace(
            id=name, type="current", protocol="mqtt", poll_interval_ms=poll_ms
        )
        for name in ("inside", "past")
    ]
    seen_at = 1_700_000_000_000
    runtime._sensor_last_seen_ms = {"inside": seen_at + 1, "past": seen_at}
    with patch("ori.runtime.now_ms", return_value=seen_at + bound + 1):
        snapshot = await runtime._build_health_snapshot()
    stale = {s["id"]: s["stale"] for s in snapshot["sensors"]}
    assert stale == {"inside": False, "past": True}


# ── Victron is excluded from the bound ───────────────────────────────────────


def _mqtt_family_classes() -> set[type]:
    from ori.hal.mqtt_base import MqttCachedAdapter

    found: set[type] = set()
    pending = [MqttCachedAdapter]
    while pending:
        for sub in pending.pop().__subclasses__():
            found.add(sub)
            pending.append(sub)
    return found


def test_only_victron_is_excluded_from_the_silence_bound() -> None:
    excluded = {c for c in _mqtt_family_classes() if not c.SILENCE_BOUNDED}
    assert excluded == {VictronAdapter}, (
        "an MQTT adapter left the silence bound; this guard sees only subclasses "
        "of MqttCachedAdapter, not a read() that skips _require_fresh"
    )


async def test_a_silent_victron_source_is_still_served(clock: _Clock) -> None:
    async with _running(_victron) as source:
        await source.send(84.5)
        clock.advance_ms(10 * BOUND_MS)
        assert _value(await source.adapter.read(SENSOR)) == 84.5


async def test_a_victron_retained_replay_is_still_cached(clock: _Clock) -> None:
    async with _running(_victron) as source:
        await source.replay(84.5)
        assert _value(await source.adapter.read(SENSOR)) == 84.5


class _WallClock:
    def __init__(self, clock: _Clock) -> None:
        self._clock = clock

    def __call__(self) -> int:
        return int(self._clock.now * 1000) + 1_700_000_000_000


async def _watch(runtime: OriRuntime) -> None:
    """Run the staleness watch for a few passes."""
    runtime._shutdown_event.clear()
    task = asyncio.create_task(
        runtime._sensor_staleness_loop(alert_sender=AsyncMock(), check_interval_s=0.001)
    )
    await asyncio.sleep(0.02)
    runtime._shutdown_event.set()
    await task


def _alerting(
    harness: _Harness, monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> AsyncMock:
    import ori.runtime as runtime_module

    monkeypatch.setattr(runtime_module, "now_ms", _WallClock(clock))
    monkeypatch.setattr(runtime_module, "STALE_SENSOR_MIN_CHECK_INTERVAL_S", 0.001)
    runtime = harness.runtime
    runtime._operator_contact = "+2340000000000"
    runtime._sensor_poll_interval_ms = {SENSOR: POLL_MS}
    runtime._stale_sensor_active = set()
    sent = AsyncMock(return_value=True)
    runtime._send_or_queue_alert = sent  # type: ignore[method-assign]
    return sent


async def test_a_silent_victron_source_raises_no_stale_alert(
    clock: _Clock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _runtime(tmp_path) as harness, _running(_victron) as source:
        sent = _alerting(harness, monkeypatch, clock)
        await source.send(84.5)
        for _ in range(10):
            clock.advance_ms(BOUND_MS)
            await _poll(harness, source.adapter)
            await _watch(harness.runtime)
        assert len(harness.observed) == 10
        sent.assert_not_awaited()


# ── Alert and log volume under silence ───────────────────────────────────────


async def test_a_long_silence_alerts_once_and_again_after_recovery(
    clock: _Clock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _runtime(tmp_path) as harness, _running(_mqtt) as source:
        sent = _alerting(harness, monkeypatch, clock)
        await source.send(12.0)
        await _poll(harness, source.adapter)
        for _ in range(20):
            clock.advance_ms(POLL_MS)
            await _poll(harness, source.adapter)
            await _watch(harness.runtime)
        assert sent.await_count == 1

        await source.send(12.0)
        await _poll(harness, source.adapter)
        await _watch(harness.runtime)
        assert sent.await_count == 1, "recovery raised a second silence alert"

        for _ in range(20):
            clock.advance_ms(POLL_MS)
            await _poll(harness, source.adapter)
            await _watch(harness.runtime)
        assert sent.await_count == 2


def _read_failures(caplog: pytest.LogCaptureFixture, level: int) -> int:
    return sum(
        1
        for r in caplog.records
        if r.levelno == level and "read failed" in r.getMessage()
    )


async def test_a_long_silence_logs_one_read_warning_per_interval(
    clock: _Clock, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    caplog.set_level(logging.DEBUG, logger="ori.runtime")
    async with _runtime(tmp_path) as harness, _running(_mqtt) as source:
        await source.send(12.0)
        await _poll(harness, source.adapter)
        clock.advance_ms(BOUND_MS + 1)
        for _ in range(30):
            await _poll(harness, source.adapter)
        assert _read_failures(caplog, logging.WARNING) == 1
        assert _read_failures(caplog, logging.DEBUG) == 29

        await source.send(12.0)
        await _poll(harness, source.adapter)
        clock.advance_ms(BOUND_MS + 1)
        await _poll(harness, source.adapter)
        assert _read_failures(caplog, logging.WARNING) == 2


async def test_the_read_warning_interval_is_what_limits_the_log(
    clock: _Clock,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import logging

    import ori.runtime as runtime_module

    monkeypatch.setattr(runtime_module, "READ_FAILURE_LOG_INTERVAL_S", 0.0)
    caplog.set_level(logging.DEBUG, logger="ori.runtime")
    async with _runtime(tmp_path) as harness, _running(_mqtt) as source:
        await source.send(12.0)
        await _poll(harness, source.adapter)
        clock.advance_ms(BOUND_MS + 1)
        for _ in range(5):
            await _poll(harness, source.adapter)
        assert _read_failures(caplog, logging.WARNING) == 5
