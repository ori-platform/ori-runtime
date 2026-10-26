# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A sensor whose source is unreachable at start is retried until it answers.

Through a real `OriRuntime.start()`, with a source the test brings up: an
adapter raising `AdapterUnavailableError` is retried under back-off with a
fresh adapter each attempt, stays unconnected until its first accepted
reading, and is then read. Any other connect error is final, at start or
during the retries, and a stop ends the retries.
"""

from __future__ import annotations

import asyncio
import textwrap
import threading
from pathlib import Path
from typing import Any

import pytest

from ori.hal.base import AdapterConnectionError, AdapterUnavailableError, BaseAdapter
from ori.network.events import SensorReading
from ori.runtime import OriRuntime
from ori.utils.time_utils import now_ms
from tests.package_layout import patch_runtime
from tests.test_runtime import _patch_external, _stop_and_join
from tests.waiting import wait_until

SENSOR_ID = "inverter-temp"


class _Source:
    """The far end: unreachable until the test brings it up."""

    def __init__(self) -> None:
        self.up = False
        self.final: Exception | None = None
        self.attempts = 0
        self.made: list[_LateAdapter] = []
        self.hold: asyncio.Event | None = None
        self.delays: list[int] = []
        self.threaded: threading.Event | None = None
        self.opened: list[_ThreadedAdapter] = []


class _LateAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "late"

    def __init__(self, source: _Source) -> None:
        self._source = source
        self.connected = False
        self.closed = False

    async def connect(self, config: dict) -> None:
        self._source.attempts += 1
        if self._source.hold is not None:
            await self._source.hold.wait()
        if self._source.final is not None:
            raise self._source.final
        if not self._source.up:
            raise AdapterUnavailableError("late: connection refused")
        self.connected = True

    async def read(self, sensor_id: str) -> SensorReading:
        return SensorReading(
            sensor_id=sensor_id,
            sensor_type="temperature",
            value=31.5,
            unit="celsius",
            timestamp=now_ms(),
            quality=1.0,
        )

    async def close(self) -> None:
        self.closed = True
        self.connected = False


class _ThreadedAdapter(BaseAdapter):
    """Connects as the real adapters do: under the lifecycle lock, opening its
    source in a worker thread, giving it back on release and on close."""

    @property
    def adapter_name(self) -> str:
        return "threaded"

    def __init__(self, gate: threading.Event) -> None:
        self._gate = gate
        self.handle: str | None = None

    def _open(self) -> None:
        self._gate.wait(5)
        self.handle = "open"

    async def _release(self) -> None:
        self.handle = None

    async def connect(self, config: dict) -> None:
        async with self._connecting("threaded source", release=self._release):
            await asyncio.to_thread(self._open)

    async def read(self, sensor_id: str) -> SensorReading:
        raise AssertionError("never read")

    async def close(self) -> None:
        async with self._closing():
            self.handle = None


def _config(tmp_path: Path) -> Path:
    cfg = tmp_path / "ori.yaml"
    cfg.write_text(
        textwrap.dedent(f"""\
            device:
              id: test-device-01
              name: Test Device
              location: Test Lab
            sensors:
              - id: {SENSOR_ID}
                type: temperature
                unit: celsius
                protocol: http
                url: http://192.0.2.10/status
                json_path: temperature
                poll_interval_ms: 100
            skills: []
            reasoning:
              default_tier: rule
            gateway:
              enabled: false
              broker_url: ""
            actions:
              primary_alert_channel: sms
              operator_contact: "+2348000000000"
              whatsapp:
                enabled: false
              sms:
                enabled: false
            skills_dir: {tmp_path / "skills"}
            database:
              path: {tmp_path / "ori_state.db"}
        """),
        encoding="utf-8",
    )
    (tmp_path / "skills").mkdir()
    return cfg


def _start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: _Source
) -> tuple[OriRuntime, asyncio.Task[Any]]:
    _patch_external(monkeypatch)

    def make(_protocol: str) -> BaseAdapter:
        if source.threaded is not None:
            threaded = _ThreadedAdapter(source.threaded)
            source.opened.append(threaded)
            return threaded
        adapter = _LateAdapter(source)
        source.made.append(adapter)
        return adapter

    patch_runtime(monkeypatch, "make_adapter", make)

    def delay(attempt: int) -> float:
        source.delays.append(attempt)
        return 0.01

    patch_runtime(monkeypatch, "reconnect_delay", delay)
    notices: list[tuple[str, str]] = []
    original = OriRuntime._send_or_queue_safety_alert

    async def spy(self: OriRuntime, **kwargs: Any) -> bool:
        notices.append((kwargs["trigger_name"], kwargs["message"]))
        return await original(self, **kwargs)

    monkeypatch.setattr(OriRuntime, "_send_or_queue_safety_alert", spy)
    runtime = OriRuntime(config_path=str(_config(tmp_path)))
    runtime.notices = notices  # type: ignore[attr-defined]
    return runtime, asyncio.create_task(runtime.start())


async def test_a_source_that_comes_up_late_is_connected_and_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _Source()
    runtime, start_task = _start(tmp_path, monkeypatch, source)
    try:
        await wait_until(
            lambda: source.attempts >= 3 or start_task.done(),
            what="the source to be retried",
        )
        assert not start_task.done()
        assert SENSOR_ID in runtime._unconnected_sensors
        assert (await runtime._build_health_snapshot())["status"] == "degraded"
        assert all(not adapter.connected for adapter in source.made)
        source.up = True
        await wait_until(
            lambda: SENSOR_ID in runtime._connected_sensor_ids,
            what="the first reading after the source came up",
        )
        assert SENSOR_ID not in runtime._unconnected_sensors
        assert [adapter.connected for adapter in source.made].count(True) == 1
    finally:
        await _stop_and_join(runtime, start_task)
    assert all(not adapter.connected for adapter in source.made)


async def test_a_configuration_error_at_start_is_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _Source()
    source.final = AdapterConnectionError("late: 'url' is required")
    runtime, start_task = _start(tmp_path, monkeypatch, source)
    try:
        await wait_until(
            lambda: SENSOR_ID in runtime._unconnected_sensors or start_task.done(),
            what="the sensor to be skipped",
        )
        await asyncio.sleep(0.1)
        assert source.attempts == 1
        assert not [
            t for t in asyncio.all_tasks() if t.get_name() == f"connect:{SENSOR_ID}"
        ]
    finally:
        await _stop_and_join(runtime, start_task)


async def test_a_configuration_error_during_the_retries_ends_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _Source()
    runtime, start_task = _start(tmp_path, monkeypatch, source)
    try:
        await wait_until(lambda: source.attempts >= 2, what="the source to be retried")
        source.final = AdapterConnectionError("late: refused for good")
        retry = next(
            t for t in asyncio.all_tasks() if t.get_name() == f"connect:{SENSOR_ID}"
        )
        await wait_until(retry.done, what="the retries to end")
        attempts = source.attempts
        await asyncio.sleep(0.1)
        assert source.attempts == attempts
        assert SENSOR_ID in runtime._unconnected_sensors
    finally:
        await _stop_and_join(runtime, start_task)


async def test_a_stop_ends_the_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _Source()
    runtime, start_task = _start(tmp_path, monkeypatch, source)
    await wait_until(lambda: source.attempts >= 2, what="the source to be retried")
    await _stop_and_join(runtime, start_task)
    attempts = source.attempts
    await asyncio.sleep(0.1)
    assert source.attempts == attempts
    assert not [
        t
        for t in asyncio.all_tasks()
        if t.get_name() == f"connect:{SENSOR_ID}" and not t.done()
    ]


async def test_the_retries_back_off_and_keep_no_failed_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _Source()
    runtime, start_task = _start(tmp_path, monkeypatch, source)
    try:
        await wait_until(lambda: source.attempts >= 5, what="five attempts")
        assert source.delays[:4] == [0, 1, 2, 3]
        assert len(runtime._adapters) <= 1
        assert [t for t in asyncio.all_tasks() if t.get_name() == "sensor-staleness"]
        notices = runtime.notices  # type: ignore[attr-defined]
        assert any(
            name == "sensor_unconnected_warning" and "being retried" in message
            for name, message in notices
        )
    finally:
        await _stop_and_join(runtime, start_task)


async def test_retries_ended_by_a_final_error_are_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _Source()
    runtime, start_task = _start(tmp_path, monkeypatch, source)
    try:
        await wait_until(lambda: source.attempts >= 2, what="the source to be retried")
        source.final = AdapterConnectionError("late: refused for good")
        notices = runtime.notices  # type: ignore[attr-defined]
        await wait_until(
            lambda: any("not being read" in message for _, message in notices),
            what="the operator told the retries ended",
        )
        assert SENSOR_ID not in runtime._retrying_sensors_announced
    finally:
        await _stop_and_join(runtime, start_task)


async def test_a_stop_mid_connect_closes_the_adapter_in_flight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _Source()
    runtime, start_task = _start(tmp_path, monkeypatch, source)
    await wait_until(lambda: source.attempts >= 2, what="the source to be retried")
    source.hold = asyncio.Event()
    attempts = source.attempts
    await wait_until(lambda: source.attempts > attempts, what="a connect in flight")
    in_flight = source.made[-1]
    stopping = asyncio.create_task(_stop_and_join(runtime, start_task))
    await asyncio.sleep(0.05)
    source.hold.set()
    await asyncio.wait_for(stopping, timeout=10)
    assert in_flight.closed


async def test_a_stop_never_strands_what_a_threaded_connect_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stop cancels the retry, not the connect: the adapter's close waits for
    the worker thread and gives back what it opened."""
    source = _Source()
    runtime, start_task = _start(tmp_path, monkeypatch, source)
    await wait_until(lambda: source.attempts >= 1, what="the first retry")
    gate = threading.Event()
    source.threaded = gate
    await wait_until(lambda: source.opened, what="a threaded connect in flight")
    stopping = asyncio.create_task(_stop_and_join(runtime, start_task))
    await asyncio.sleep(0.1)
    gate.set()
    await asyncio.wait_for(stopping, timeout=10)
    await asyncio.sleep(0.05)
    assert [adapter.handle for adapter in source.opened] == [None]
