# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A connected sensor that has delivered no reading, under runtime-health/v4.

`last_seen_ms` is null until a reading is accepted, and `stale` runs from the
connection when there is none, so a source the broker starves (an `acl_file`
that grants the SUBSCRIBE and withholds every message) is told apart from one
that reported and went quiet.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

from ori.runtime import OriRuntime
from ori.utils.time_utils import now_ms

POLL_MS = 1000
BOUND_MS = 2 * POLL_MS


def _runtime(
    *, connected_at: int | None, last_seen: int | None, connected: bool = True
) -> Any:
    runtime: Any = OriRuntime(config_path="ori.yaml")
    runtime._runtime_started_at_ms = now_ms() - 60_000
    runtime._configured_sensors = [
        SimpleNamespace(
            id="s1", type="current", protocol="mqtt", poll_interval_ms=POLL_MS
        )
    ]
    runtime._connected_sensor_ids = {"s1"} if connected else set()
    runtime._sensor_connected_at_ms = (
        {} if connected_at is None else {"s1": connected_at}
    )
    runtime._sensor_last_seen_ms = {} if last_seen is None else {"s1": last_seen}
    return runtime


async def _sensor(runtime: Any) -> dict[str, Any]:
    snapshot = await runtime._build_health_snapshot()
    (sensor,) = snapshot["sensors"]
    return dict(sensor)


async def test_no_reading_within_the_bound_is_not_stale_and_has_no_last_seen() -> None:
    sensor = await _sensor(
        _runtime(connected_at=now_ms() - BOUND_MS // 2, last_seen=None)
    )
    assert sensor["connected"] is True
    assert sensor["last_seen_ms"] is None
    assert sensor["stale"] is False


async def test_no_reading_past_the_bound_since_connecting_is_stale() -> None:
    sensor = await _sensor(
        _runtime(connected_at=now_ms() - BOUND_MS - 500, last_seen=None)
    )
    assert sensor["last_seen_ms"] is None
    assert sensor["stale"] is True


async def test_a_reading_inside_the_bound_wins_over_an_old_connection() -> None:
    now = now_ms()
    sensor = await _sensor(
        _runtime(connected_at=now - 10 * BOUND_MS, last_seen=now - BOUND_MS // 2)
    )
    assert sensor["last_seen_ms"] == now - BOUND_MS // 2
    assert sensor["stale"] is False


async def test_a_sensor_that_never_connected_is_not_stale() -> None:
    sensor = await _sensor(_runtime(connected_at=None, last_seen=None, connected=False))
    assert sensor["last_seen_ms"] is None
    assert sensor["stale"] is False


async def _warning(runtime: Any) -> str:
    runtime._shutdown_event = asyncio.Event()
    runtime._sensor_poll_interval_ms = {"s1": 100}
    runtime._stale_sensor_active = set()
    runtime._primary_alert_channel = "sms"
    runtime._operator_contact = "+2340000000000"
    runtime._send_or_queue_alert = AsyncMock(return_value=True)

    async def stop_once_warned() -> None:
        while runtime._send_or_queue_alert.await_count == 0:
            await asyncio.sleep(0.005)
        runtime._shutdown_event.set()

    await asyncio.wait_for(
        asyncio.gather(
            runtime._sensor_staleness_loop(
                alert_sender=AsyncMock(), check_interval_s=0.01
            ),
            stop_once_warned(),
        ),
        timeout=10,
    )
    runtime._send_or_queue_alert.assert_awaited_once()
    call = runtime._send_or_queue_alert.await_args
    assert call is not None
    return str(call.kwargs["message"])


async def test_the_warning_names_a_sensor_with_no_reading_since_it_connected() -> None:
    message = await _warning(_runtime(connected_at=now_ms() - 5_000, last_seen=None))
    assert "has had no reading accepted since it connected" in message
    assert "has not reported for" not in message


async def test_the_warning_for_a_source_that_went_quiet_is_unchanged() -> None:
    now = now_ms()
    message = await _warning(_runtime(connected_at=now - 60_000, last_seen=now - 5_000))
    assert "has not reported for about" in message
    assert "since it connected" not in message


async def test_no_connection_and_no_reading_raises_no_warning() -> None:
    runtime = _runtime(connected_at=None, last_seen=None, connected=False)
    runtime._shutdown_event = asyncio.Event()
    runtime._sensor_poll_interval_ms = {"s1": 100}
    runtime._stale_sensor_active = set()
    runtime._operator_contact = "+2340000000000"
    runtime._send_or_queue_alert = AsyncMock(return_value=True)
    task = asyncio.create_task(
        runtime._sensor_staleness_loop(alert_sender=AsyncMock(), check_interval_s=0.01)
    )
    await asyncio.sleep(0.1)
    runtime._shutdown_event.set()
    await task
    runtime._send_or_queue_alert.assert_not_awaited()
