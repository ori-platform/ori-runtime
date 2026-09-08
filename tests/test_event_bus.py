# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import time
from typing import Any, cast

import pytest

from ori.network.event_bus import EventBus
from ori.network.events import OriEvent, SensorReading

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _ms() -> int:
    return int(time.time() * 1000)


def _event(
    sensor_type: str = "current_clamp",
    sensor_id: str = "s1",
    device_id: str = "dev-01",
    value: float = 5.0,
) -> OriEvent:
    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit="ampere",
        timestamp=_ms(),
        quality=1.0,
    )
    return OriEvent.from_reading(reading, device_id)


def _heartbeat(device_id: str = "dev-01") -> OriEvent:
    return OriEvent(
        event_id="hb-001",
        event_type="device.heartbeat",
        device_id=device_id,
        sensor_id="",
        timestamp=_ms(),
        reading=None,
    )


async def _noop(event: OriEvent) -> None:
    pass


# ─── subscribe / subscriber_count ─────────────────────────────────────────────


class TestSubscribe:
    def test_subscriber_count_zero_initially(self):
        bus = EventBus()
        assert bus.subscriber_count("current_clamp") == 0

    def test_subscriber_count_after_subscribe(self):
        bus = EventBus()
        bus.subscribe("current_clamp", _noop)
        assert bus.subscriber_count("current_clamp") == 1

    def test_multiple_handlers_same_type(self):
        bus = EventBus()

        async def h1(e): ...
        async def h2(e): ...

        bus.subscribe("current_clamp", h1)
        bus.subscribe("current_clamp", h2)
        assert bus.subscriber_count("current_clamp") == 2

    def test_handlers_for_different_types_are_independent(self):
        bus = EventBus()
        bus.subscribe("current_clamp", _noop)
        assert bus.subscriber_count("voltage") == 0

    def test_wildcard_subscriber_count(self):
        bus = EventBus()
        bus.subscribe("*", _noop)
        assert bus.subscriber_count("*") == 1

    def test_sync_handler_logs_warning(self, caplog):
        import logging

        def sync_handler(event): ...

        bus = EventBus()
        with caplog.at_level(logging.WARNING, logger="ori.network.event_bus"):
            bus.subscribe("current_clamp", cast(Any, sync_handler))

        assert any("not async" in r.message for r in caplog.records)

    def test_async_handler_no_warning(self, caplog):
        import logging

        bus = EventBus()
        with caplog.at_level(logging.WARNING, logger="ori.network.event_bus"):
            bus.subscribe("current_clamp", _noop)

        assert not any("not async" in r.message for r in caplog.records)

    def test_sync_handler_still_registered_despite_warning(self, caplog):
        import logging

        def sync_handler(event): ...

        bus = EventBus()
        with caplog.at_level(logging.WARNING, logger="ori.network.event_bus"):
            bus.subscribe("current_clamp", cast(Any, sync_handler))

        assert bus.subscriber_count("current_clamp") == 1


# ─── unsubscribe ──────────────────────────────────────────────────────────────


class TestUnsubscribe:
    def test_unsubscribe_removes_handler(self):
        bus = EventBus()
        bus.subscribe("current_clamp", _noop)
        bus.unsubscribe("current_clamp", _noop)
        assert bus.subscriber_count("current_clamp") == 0

    def test_unsubscribe_nonexistent_handler_is_silent(self):
        bus = EventBus()
        bus.unsubscribe("current_clamp", _noop)  # must not raise

    def test_unsubscribe_nonexistent_type_is_silent(self):
        bus = EventBus()
        bus.unsubscribe("does_not_exist", _noop)  # must not raise

    def test_unsubscribe_only_removes_specified_handler(self):
        bus = EventBus()

        async def h1(e): ...
        async def h2(e): ...

        bus.subscribe("current_clamp", h1)
        bus.subscribe("current_clamp", h2)
        bus.unsubscribe("current_clamp", h1)
        assert bus.subscriber_count("current_clamp") == 1


# ─── clear ────────────────────────────────────────────────────────────────────


class TestClear:
    def test_clear_removes_all_subscriptions(self):
        bus = EventBus()
        bus.subscribe("current_clamp", _noop)
        bus.subscribe("voltage", _noop)
        bus.subscribe("*", _noop)
        bus.clear()
        assert bus.subscriber_count("current_clamp") == 0
        assert bus.subscriber_count("voltage") == 0
        assert bus.subscriber_count("*") == 0


# ─── publish — delivery ───────────────────────────────────────────────────────


class TestPublishDelivery:
    async def test_handler_receives_event(self):
        bus = EventBus()
        received: list[OriEvent] = []

        async def handler(event: OriEvent) -> None:
            received.append(event)

        bus.subscribe("current_clamp", handler)
        event = _event("current_clamp")
        await bus.publish(event)
        assert received == [event]

    async def test_only_matching_handler_called(self):
        bus = EventBus()
        current_received: list[OriEvent] = []
        voltage_received: list[OriEvent] = []

        async def on_current(e):
            current_received.append(e)

        async def on_voltage(e):
            voltage_received.append(e)

        bus.subscribe("current_clamp", on_current)
        bus.subscribe("voltage", on_voltage)

        await bus.publish(_event("current_clamp"))
        assert len(current_received) == 1
        assert len(voltage_received) == 0

    async def test_wildcard_receives_all_events(self):
        bus = EventBus()
        received: list[OriEvent] = []

        async def wildcard(e):
            received.append(e)

        bus.subscribe("*", wildcard)
        await bus.publish(_event("current_clamp"))
        await bus.publish(_event("voltage"))
        await bus.publish(_event("temperature"))
        assert len(received) == 3

    async def test_specific_and_wildcard_both_called(self):
        bus = EventBus()
        specific_calls: list[OriEvent] = []
        wildcard_calls: list[OriEvent] = []

        async def on_specific(e):
            specific_calls.append(e)

        async def on_wildcard(e):
            wildcard_calls.append(e)

        bus.subscribe("current_clamp", on_specific)
        bus.subscribe("*", on_wildcard)
        event = _event("current_clamp")
        await bus.publish(event)

        assert len(specific_calls) == 1
        assert len(wildcard_calls) == 1

    async def test_wildcard_handler_not_called_twice_when_also_specific(self):
        """A handler registered as both specific and wildcard should not be double-delivered."""
        bus = EventBus()
        call_count = 0

        async def handler(e):
            nonlocal call_count
            call_count += 1

        bus.subscribe("current_clamp", handler)
        bus.subscribe("*", handler)
        await bus.publish(_event("current_clamp"))
        assert call_count == 1

    async def test_multiple_handlers_all_called(self):
        bus = EventBus()
        results: list[int] = []

        async def h1(e):
            results.append(1)

        async def h2(e):
            results.append(2)

        async def h3(e):
            results.append(3)

        bus.subscribe("current_clamp", h1)
        bus.subscribe("current_clamp", h2)
        bus.subscribe("current_clamp", h3)
        await bus.publish(_event("current_clamp"))
        assert results == [1, 2, 3]

    async def test_event_without_reading_routed_by_event_type(self):
        """Heartbeat events (reading=None) are routed by event_type."""
        bus = EventBus()
        received: list[OriEvent] = []

        async def on_heartbeat(e):
            received.append(e)

        bus.subscribe("device.heartbeat", on_heartbeat)
        await bus.publish(_heartbeat())
        assert len(received) == 1


# ─── publish — exception isolation ────────────────────────────────────────────


class TestPublishExceptionIsolation:
    async def test_failing_handler_does_not_stop_delivery(self):
        bus = EventBus()
        delivered: list[int] = []

        async def bad(e):
            raise RuntimeError("boom")

        async def good(e):
            delivered.append(1)

        bus.subscribe("current_clamp", bad)
        bus.subscribe("current_clamp", good)
        await bus.publish(_event("current_clamp"))  # must not raise
        assert delivered == [1]

    async def test_multiple_failing_handlers_all_attempted(self):
        bus = EventBus()
        attempts: list[int] = []

        async def fail1(e):
            attempts.append(1)
            raise ValueError("fail1")

        async def fail2(e):
            attempts.append(2)
            raise ValueError("fail2")

        async def ok(e):
            attempts.append(3)

        bus.subscribe("current_clamp", fail1)
        bus.subscribe("current_clamp", fail2)
        bus.subscribe("current_clamp", ok)
        await bus.publish(_event("current_clamp"))
        assert attempts == [1, 2, 3]

    async def test_exception_is_logged(self, caplog):
        import logging

        bus = EventBus()

        async def bad(e):
            raise RuntimeError("deliberate")

        bus.subscribe("current_clamp", bad)
        with caplog.at_level(logging.ERROR, logger="ori.network.event_bus"):
            await bus.publish(_event("current_clamp"))

        assert any(
            "deliberate" in r.message or "raised" in r.message for r in caplog.records
        )


# ─── publish — no-subscriber warning ─────────────────────────────────────────


class TestNoSubscriberWarning:
    async def test_warning_logged_when_no_subscribers(self, caplog):
        import logging

        bus = EventBus()
        with caplog.at_level(logging.WARNING, logger="ori.network.event_bus"):
            await bus.publish(_event("current_clamp"))

        assert any("no subscribers" in r.message for r in caplog.records)

    async def test_no_warning_when_wildcard_subscribed(self, caplog):
        import logging

        bus = EventBus()
        bus.subscribe("*", _noop)
        with caplog.at_level(logging.WARNING, logger="ori.network.event_bus"):
            await bus.publish(_event("current_clamp"))

        assert not any("no subscribers" in r.message for r in caplog.records)


# ─── publish — timeout / strict mode ──────────────────────────────────────────


class TestPublishTimeoutAndStrict:
    async def test_handler_timeout_logs_and_continues(self, caplog):
        import logging

        bus = EventBus(handler_timeout_s=0.01)
        delivered: list[int] = []

        async def slow(_event):
            await asyncio.sleep(0.05)

        async def good(_event):
            delivered.append(1)

        bus.subscribe("current_clamp", slow)
        bus.subscribe("current_clamp", good)

        with caplog.at_level(logging.ERROR, logger="ori.network.event_bus"):
            await bus.publish(_event("current_clamp"))

        assert delivered == [1]
        assert any("timed out" in r.message for r in caplog.records)

    async def test_handler_timeout_raises_in_strict_mode(self):
        bus = EventBus(handler_timeout_s=0.01, strict_exceptions=True)

        async def slow(_event):
            await asyncio.sleep(0.05)

        bus.subscribe("current_clamp", slow)
        with pytest.raises(asyncio.TimeoutError):
            await bus.publish(_event("current_clamp"))

    async def test_handler_exception_raises_in_strict_mode(self):
        bus = EventBus(strict_exceptions=True)

        async def bad(_event):
            raise RuntimeError("boom")

        bus.subscribe("current_clamp", bad)
        with pytest.raises(RuntimeError, match="boom"):
            await bus.publish(_event("current_clamp"))

    async def test_no_warning_when_specific_subscriber_exists(self, caplog):
        import logging

        bus = EventBus()
        bus.subscribe("current_clamp", _noop)
        with caplog.at_level(logging.WARNING, logger="ori.network.event_bus"):
            await bus.publish(_event("current_clamp"))

        assert not any("no subscribers" in r.message for r in caplog.records)
