# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import threading
import time

import pytest

from ori.network.events import OriEvent, SensorReading
from ori.state.store import StateStore
from tests.waiting import wait_until


@pytest.fixture
async def store(tmp_path):
    s = StateStore(db_path=str(tmp_path / "concurrency.db"))
    await s.open()
    yield s
    await s.close()


def _ms() -> int:
    return int(time.time() * 1000)


def _event(sensor_id: str, value: float) -> OriEvent:
    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type="cpu_percent",
        value=value,
        unit="percent",
        timestamp=_ms(),
        quality=1.0,
        metadata={"source": "test"},
    )
    return OriEvent.from_reading(reading, device_id="test-device")


async def test_concurrent_reads(store):
    for idx in range(20):
        await store.append_history(_event("sensor-1", float(idx)))

    results = await asyncio.gather(
        *[store.get_history("sensor-1", limit=5) for _ in range(10)]
    )

    assert len(results) == 10
    assert all(len(rows) == 5 for rows in results)


async def test_write_blocks_other_writes(store, monkeypatch):
    gate = threading.Event()
    entered = threading.Event()
    counters_lock = threading.Lock()
    active_writers = 0
    max_active_writers = 0

    def _blocked_insert(self, _reading):
        nonlocal active_writers, max_active_writers
        with counters_lock:
            active_writers += 1
            max_active_writers = max(max_active_writers, active_writers)
            entered.set()
        gate.wait(timeout=2.0)
        with counters_lock:
            active_writers -= 1

    monkeypatch.setattr(StateStore, "_insert_reading_sync", _blocked_insert)

    first = asyncio.create_task(store.append_history(_event("sensor-1", 1.0)))
    await wait_until(lambda: entered.is_set(), what="entered.is_set()")
    assert entered.is_set(), "First writer did not enter the critical section"

    second = asyncio.create_task(store.append_history(_event("sensor-1", 2.0)))
    await asyncio.sleep(0.05)
    assert not second.done(), "Second write should wait for write lock"

    gate.set()
    await asyncio.gather(first, second)
    assert max_active_writers == 1


async def test_read_during_write(store, monkeypatch):
    await store.append_history(_event("sensor-1", 42.0))

    gate = threading.Event()
    entered = threading.Event()

    def _blocked_insert(self, _reading):
        entered.set()
        gate.wait(timeout=2.0)

    monkeypatch.setattr(StateStore, "_insert_reading_sync", _blocked_insert)

    blocked_write = asyncio.create_task(store.append_history(_event("sensor-1", 99.0)))
    await wait_until(lambda: entered.is_set(), what="entered.is_set()")
    assert entered.is_set(), "Write path did not enter blocked section"

    rows = await asyncio.wait_for(store.get_history("sensor-1", limit=1), timeout=0.5)
    assert len(rows) == 1
    assert rows[0].value == pytest.approx(42.0)

    gate.set()
    await blocked_write
