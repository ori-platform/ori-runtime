# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Readings reach HTTP export along the paths that actually publish them.

The exporter is subscribed by the runtime's own wiring and fed by the real poll
loop, the real firmware telemetry subscriber and the real EventBus; what is
asserted is the batch body posted to the receiver.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from ori.network.event_bus import EventBus
from ori.network.events import OriEvent, SensorReading
from ori.runtime import OriRuntime
from ori.state.store import StateStore
from ori.telemetry import http_export
from ori.telemetry.http_export import HttpTelemetryExporter
from tests.test_telemetry_http_export import _config, _FakeAsyncClient

DEVICE = "dev-01"
T0 = int(time.time() * 1000) - 600_000


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


@pytest.fixture
def receiver(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    monkeypatch.setenv("ORI_DEVICE_API_KEY", "device-secret")
    monkeypatch.setattr(
        http_export, "_httpx", SimpleNamespace(AsyncClient=_FakeAsyncClient)
    )
    monkeypatch.setattr(http_export, "_HTTPX_AVAILABLE", True)
    _FakeAsyncClient.requests = []
    _FakeAsyncClient.fail = False
    _FakeAsyncClient.responses = []
    return _FakeAsyncClient.requests


def _posted_events(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event
        for request in requests
        for event in json.loads(request["content"])["events"]
    ]


def _runtime(store: StateStore) -> Any:
    runtime: Any = OriRuntime(config_path="ori.yaml")
    runtime._state_store = store
    runtime._shutdown_event = asyncio.Event()
    runtime._measurement_refusals = {}
    runtime._measurement_valid_streak = {}
    runtime._measurement_refusal_reason = {}
    runtime._measurement_degraded = set()
    runtime._measurement_unnotified = set()
    runtime._measurement_notify_attempts = {}
    return runtime


def _wire_exporter(runtime: Any, bus: EventBus) -> HttpTelemetryExporter:
    """Subscribe through the runtime's own wiring; flushing is driven by the test."""
    config = SimpleNamespace(
        device=SimpleNamespace(id=DEVICE),
        telemetry_export=_config(batch_size=10, max_queue_size=10),
    )
    task = runtime._start_telemetry_export_if_enabled(config, bus)
    assert task is not None
    task.cancel()
    return cast(HttpTelemetryExporter, runtime._telemetry_exporter)


def _reading(
    sensor_id: str, sensor_type: str, unit: str, value: float
) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp=T0,
        quality=1.0,
        metadata={"source": "i2c"},
    )


async def _poll(runtime: Any, bus: EventBus, reading: SensorReading) -> None:
    class _Once:
        async def read(self, sensor_id: str) -> SensorReading:
            runtime._shutdown_event.set()
            return reading

    sensor_cfg: Any = SimpleNamespace(id=reading.sensor_id, poll_interval_ms=1)
    await runtime._poll_sensor(cast(Any, _Once()), sensor_cfg, bus, DEVICE)
    runtime._shutdown_event.clear()


async def test_polled_readings_of_every_type_are_exported(
    store: StateStore, receiver: list[dict[str, Any]]
) -> None:
    runtime = _runtime(store)
    bus = EventBus()
    exporter = _wire_exporter(runtime, bus)

    await _poll(runtime, bus, _reading("load-current", "current", "ampere", 8.2))
    await _poll(runtime, bus, _reading("grid-voltage", "voltage", "volt", 229.0))

    assert await exporter.flush_once() == 2
    events = _posted_events(receiver)
    assert [(e["sensor_id"], e["reading"]["sensor_type"]) for e in events] == [
        ("load-current", "current"),
        ("grid-voltage", "voltage"),
    ]
    # The batch contract admits one event type; the bus type is not the wire's.
    assert {e["event_type"] for e in events} == {"sensor.reading"}
    assert [e["reading"]["value"] for e in events] == [8.2, 229.0]


async def test_a_sensor_typed_reading_is_exported_once_like_any_other(
    store: StateStore, receiver: list[dict[str, Any]]
) -> None:
    runtime = _runtime(store)
    bus = EventBus()
    exporter = _wire_exporter(runtime, bus)

    await _poll(runtime, bus, _reading("odd", "reading", "count", 1.0))

    assert await exporter.flush_once() == 1
    assert [e["sensor_id"] for e in _posted_events(receiver)] == ["odd"]


async def test_a_firmware_node_reading_is_exported(
    store: StateStore, receiver: list[dict[str, Any]]
) -> None:
    from ori.runtime import _build_firmware_telemetry_subscriber
    from ori.security.firmware.liveness import FirmwareLivenessSupervisor
    from tests.firmware.test_liveness_composition import (
        _cfg,
        _provision,
        _telemetry_message,
    )

    runtime = _runtime(store)
    bus = EventBus()
    exporter = _wire_exporter(runtime, bus)
    subscriber = _build_firmware_telemetry_subscriber(
        _cfg(), bus, store, None, FirmwareLivenessSupervisor()
    )
    assert subscriber is not None
    await _provision(store)

    await subscriber._ingest_telemetry(_telemetry_message("telemetry_single_reading"))

    assert await exporter.flush_once() == 1
    events = _posted_events(receiver)
    assert len(events) == 1
    assert events[0]["event_type"] == "sensor.reading"
    assert events[0]["source"] == "firmware"
    assert events[0]["sensor_id"] == "ori-fw-7c9f2b3a:ch0"
    assert events[0]["reading"]["sensor_type"] == "current"
    assert events[0]["reading"]["value"] == 8.21


def _event(event_type: str, reading: SensorReading | None) -> OriEvent:
    return OriEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        device_id=DEVICE,
        sensor_id="load-current",
        timestamp=T0,
        reading=reading,
    )


@pytest.mark.parametrize(
    ("event_type", "with_reading"),
    [
        ("device.heartbeat", False),
        ("skill.trigger", False),
        ("power.low_battery_throttle", False),
        ("sensor.current", False),
        ("sensor.invalid_value", True),
        ("skill.trigger", True),
        ("sensor.voltage", True),
        ("current", True),
    ],
)
async def test_an_event_that_is_not_a_published_reading_is_not_exported(
    store: StateStore,
    receiver: list[dict[str, Any]],
    event_type: str,
    with_reading: bool,
) -> None:
    runtime = _runtime(store)
    bus = EventBus()
    exporter = _wire_exporter(runtime, bus)
    reading = (
        _reading("load-current", "current", "ampere", 8.2) if with_reading else None
    )

    event = _event(event_type, reading)
    await bus.publish(event)
    # Directly as well: the bus logs and swallows a handler that raises.
    await exporter.handle_event(event)

    assert await exporter.flush_once() == 0
    assert receiver == []
    assert exporter.status_snapshot()["queued_events"] == 0


async def test_a_canonical_reading_event_is_exported_once(
    store: StateStore, receiver: list[dict[str, Any]]
) -> None:
    runtime = _runtime(store)
    bus = EventBus()
    exporter = _wire_exporter(runtime, bus)
    event = OriEvent.from_reading(
        _reading("load-current", "current", "ampere", 8.2), DEVICE
    )
    assert event.event_type == "sensor.reading"

    await bus.publish(event)

    assert await exporter.flush_once() == 1
    events = _posted_events(receiver)
    assert [(e["event_id"], e["event_type"]) for e in events] == [
        (event.event_id, "sensor.reading")
    ]
