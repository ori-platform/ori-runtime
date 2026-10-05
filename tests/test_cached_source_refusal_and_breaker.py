# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A refused payload withdraws the value it would replace, and a late source is read.

Both through the runtime's own poll path and the real safety registry: a
refused payload used to leave the earlier value served as live, and a source
that started late, or an endpoint that answered again, was withheld for the
breaker's recovery window.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest

from ori.hal.base import AdapterReadError, CircuitState
from tests.test_cached_sensor_freshness import (
    ALL_CACHED,
    CLEAR,
    HAZARD,
    POLL_MS,
    SENSOR,
    TIER_D_CAPABLE,
    UNBOUNDED,
    _Clock,
    _CoapSource,
    _HttpResponse,
    _HttpSource,
    _MqttSource,
    _poll,
    _running,
    _runtime,
    _settle,
    _victron,
)

EVERY_CACHED = [*ALL_CACHED, *UNBOUNDED]


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr("ori.hal.base._arrival_clock", fake)
    return fake


async def _refuse(source: Any) -> None:
    """The source answers with a payload this sensor cannot accept."""
    if isinstance(source, _MqttSource):
        await source.adapter._client.emit(source.topic, b'{"unexpected": true}')
        await _settle()
    elif isinstance(source, _HttpSource):
        source.responses.append(_HttpResponse({"main": {}}))
        with pytest.raises(AdapterReadError):
            await source.adapter._poll_once()
    elif isinstance(source, _CoapSource):
        import asyncio
        from types import SimpleNamespace

        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        future.set_result(SimpleNamespace(payload=json.dumps({"metrics": {}}).encode()))
        source.futures.append(future)
        with pytest.raises(AdapterReadError):
            await source.adapter._poll_once()
    else:  # pragma: no cover
        raise AssertionError(type(source))


def _hazard(source: Any) -> float:
    # The fixture profile trips on current; other sensor types only observe.
    return HAZARD


@pytest.mark.parametrize("factory", EVERY_CACHED)
async def test_a_refused_payload_withdraws_the_cached_value(
    factory: Callable[[], Any], clock: Any, tmp_path: Path
) -> None:
    async with _runtime(tmp_path) as harness, _running(factory) as source:
        await source.send(12.0)
        await _poll(harness, source.adapter)
        observed = len(harness.observed)
        assert observed == 1

        harness.runtime._sensor_last_seen_ms.pop(SENSOR)
        await _refuse(source)
        with pytest.raises(AdapterReadError, match="refused"):
            await source.adapter.read(SENSOR)
        await _poll(harness, source.adapter)
        assert len(harness.observed) == observed, "a withdrawn value was observed"
        assert SENSOR not in harness.runtime._sensor_last_seen_ms

        await source.send(13.0)
        await _poll(harness, source.adapter)
        assert len(harness.observed) == observed + 1
        assert SENSOR in harness.runtime._sensor_last_seen_ms


async def test_a_refusal_on_another_topic_leaves_this_value_served(
    clock: Any,
) -> None:
    async with _running(_victron) as source:
        await source.send(84.5)
        other = source.adapter._topic_for_sensor("victron_grid_power")
        assert other != source.topic
        await source.adapter._client.emit(other, b'{"unexpected": true}')
        await _settle()
        assert (await source.adapter.read(SENSOR)).value == pytest.approx(84.5)


@pytest.mark.parametrize("factory", TIER_D_CAPABLE)
async def test_a_late_or_recovered_source_is_observed_within_one_poll(
    factory: Callable[[], Any], clock: Any, tmp_path: Path
) -> None:
    async with _runtime(tmp_path) as harness, _running(factory) as source:
        breaker = source.adapter._breaker
        # Exactly the threshold: an open breaker consumes no further answer.
        for _ in range(breaker.failure_threshold):
            await source.fail()
            await _poll(harness, source.adapter)
        assert harness.observed == []
        if isinstance(source, _MqttSource):
            # Nothing published yet is not a fault: the breaker never opened.
            assert breaker.state == CircuitState.CLOSED
        else:
            assert breaker.state == CircuitState.OPEN
            # The poller's next poll comes one interval later.
            assert breaker.recovery_timeout_s <= POLL_MS / 1000.0
            breaker.opened_at -= POLL_MS / 1000.0

        await source.send(_hazard(source))
        await _poll(harness, source.adapter)
        assert harness.observed == [(SENSOR, HAZARD)]
        assert breaker.state == CircuitState.CLOSED
        assert harness.commander.outcome_calls == [
            ("main-distribution", "open_protected_circuit")
        ]

        await source.send(CLEAR)
        await _poll(harness, source.adapter)
        assert harness.observed[-1] == (SENSOR, CLEAR)


@pytest.mark.parametrize(
    "factory",
    [pytest.param(_HttpSource, id="http"), pytest.param(_CoapSource, id="coap")],
)
async def test_a_failing_endpoint_still_opens_the_breaker(
    factory: Callable[[], Any], clock: Any
) -> None:
    async with _running(factory) as source:
        breaker = source.adapter._breaker
        for _ in range(breaker.failure_threshold):
            await source.fail()
        assert breaker.state == CircuitState.OPEN
        with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
            await source.adapter._poll_once()


async def test_a_coap_value_that_overflows_withdraws_the_cached_value(
    clock: _Clock,
) -> None:
    import asyncio
    from types import SimpleNamespace

    async with _running(_CoapSource) as source:
        await source.send(12.0)
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        future.set_result(
            SimpleNamespace(payload=b'{"metrics":{"current":1' + b"0" * 400 + b"}}")
        )
        source.futures.append(future)
        with pytest.raises(AdapterReadError):
            await source.adapter._poll_once()
        with pytest.raises(AdapterReadError, match="refused"):
            await source.adapter.read(SENSOR)


@pytest.mark.parametrize("factory", UNBOUNDED)
async def test_a_retained_replay_never_reaches_the_safety_registry(
    factory: Callable[[], Any], clock: _Clock, tmp_path: Path
) -> None:
    """An on-change source has no silence bound, so a replay must not be a value."""
    async with _runtime(tmp_path) as harness, _running(factory) as source:
        await source.replay(HAZARD)
        for _ in range(3):
            await _poll(harness, source.adapter)
        assert harness.observed == []
        assert SENSOR not in harness.runtime._sensor_last_seen_ms
        await source.send(CLEAR)
        await _poll(harness, source.adapter)
        assert len(harness.observed) == 1
