# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import time
from unittest.mock import patch

from ori.network.deduplicator import EventDeduplicator, OccurrenceRecord
from ori.network.events import OriEvent, SensorReading

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _ms() -> int:
    return int(time.time() * 1000)


def _reading(
    sensor_id: str = "load-current",
    sensor_type: str = "current_clamp",
    value: float = 5.0,
    unit: str = "ampere",
    timestamp: int | None = None,
) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp=timestamp or _ms(),
        quality=1.0,
    )


def _event(reading: SensorReading, device_id: str = "dev-01") -> OriEvent:
    return OriEvent.from_reading(reading, device_id)


# ─── Basic deduplication ──────────────────────────────────────────────────────


class TestProcessDeduplication:
    def test_first_event_passes_through(self):
        dedup = EventDeduplicator()
        event = _event(_reading())
        assert dedup.process(event) is event

    def test_duplicate_within_window_returns_none(self):
        dedup = EventDeduplicator()
        r = _reading(value=5.0)
        e1 = _event(r)
        e2 = _event(r)  # same reading, same device → same fingerprint
        dedup.process(e1)
        assert dedup.process(e2) is None

    def test_duplicate_within_window_increments_count(self):
        dedup = EventDeduplicator()
        r = _reading(value=5.0)
        dedup.process(_event(r))
        dedup.process(_event(r))
        stats = dedup.get_stats()
        assert stats["total_suppressed"] == 1

    def test_same_reading_after_window_passes_through(self):
        dedup = EventDeduplicator()
        r = _reading(value=5.0)
        now = _ms()
        with patch("ori.network.deduplicator.now_ms", return_value=now):
            dedup.process(_event(r))

        # 5001ms after first_seen — outside the 5-second window
        with patch("ori.network.deduplicator.now_ms", return_value=now + 5_001):
            result = dedup.process(_event(r))
        assert result is not None

    def test_different_values_pass_through(self):
        """Values that round differently produce different fingerprints."""
        dedup = EventDeduplicator()
        dedup.process(_event(_reading(value=5.0)))
        # 5.5 rounds to a different bucket than 5.0
        result = dedup.process(_event(_reading(value=5.5)))
        assert result is not None

    def test_different_sensor_ids_are_independent(self):
        """sensor_id is part of the fingerprint — different sensors never suppress each other."""
        dedup = EventDeduplicator()
        r1 = _reading(sensor_id="s1", sensor_type="current_clamp", value=5.0)
        r2 = _reading(sensor_id="s2", sensor_type="current_clamp", value=5.0)
        dedup.process(_event(r1))
        assert dedup.process(_event(r2)) is not None

    def test_different_sensor_types_are_independent(self):
        dedup = EventDeduplicator()
        dedup.process(_event(_reading(sensor_type="current_clamp", value=5.0)))
        assert (
            dedup.process(_event(_reading(sensor_type="voltage", value=5.0)))
            is not None
        )

    def test_different_sensor_types_are_independent_explicit(self):
        dedup = EventDeduplicator()
        r1 = _reading(sensor_type="current_clamp", value=5.0)
        r2 = _reading(sensor_type="voltage", value=5.0)
        dedup.process(_event(r1))
        assert dedup.process(_event(r2)) is not None

    def test_window_restarts_after_expiry(self):
        """After expiry, forwarded event must restart dedup window from new time."""
        dedup = EventDeduplicator()
        r = _reading(value=5.0)
        start = _ms()
        with patch("ori.network.deduplicator.now_ms", return_value=start):
            assert dedup.process(_event(r)) is not None

        # First event after expiry passes through and starts a new window.
        after_expiry = start + 5_001
        with patch("ori.network.deduplicator.now_ms", return_value=after_expiry):
            assert dedup.process(_event(r)) is not None

        # A millisecond later should be suppressed by the restarted window.
        just_after = after_expiry + 1
        with patch("ori.network.deduplicator.now_ms", return_value=just_after):
            assert dedup.process(_event(r)) is None

    def test_different_devices_are_independent(self):
        dedup = EventDeduplicator()
        r = _reading(value=5.0)
        dedup.process(_event(r, device_id="dev-01"))
        assert dedup.process(_event(r, device_id="dev-02")) is not None

    def test_event_without_reading_uses_event_id(self):
        """Heartbeat events (no reading) must not be suppressed against each other."""
        dedup = EventDeduplicator()
        now = _ms()
        e1 = OriEvent(
            event_id="hb-001",
            event_type="device.heartbeat",
            device_id="dev-01",
            sensor_id="",
            timestamp=now,
            reading=None,
        )
        e2 = OriEvent(
            event_id="hb-002",
            event_type="device.heartbeat",
            device_id="dev-01",
            sensor_id="",
            timestamp=now,
            reading=None,
        )
        dedup.process(e1)
        # Different event_id → different fallback fingerprint → not suppressed
        assert dedup.process(e2) is not None

    def test_exactly_at_window_boundary_is_suppressed(self):
        """An event at exactly _WINDOW_MS − 1 ms after first_seen is still within the window."""
        dedup = EventDeduplicator()
        r = _reading(value=5.0)
        now = _ms()
        with patch("ori.network.deduplicator.now_ms", return_value=now):
            dedup.process(_event(r))

        just_inside = now + 4_999
        with patch("ori.network.deduplicator.now_ms", return_value=just_inside):
            result = dedup.process(_event(r))
        assert result is None

    def test_exactly_at_window_expiry_passes_through(self):
        """An event at exactly _WINDOW_MS ms after first_seen is outside the window."""
        dedup = EventDeduplicator()
        r = _reading(value=5.0)
        now = _ms()
        with patch("ori.network.deduplicator.now_ms", return_value=now):
            dedup.process(_event(r))

        at_expiry = now + 5_000
        with patch("ori.network.deduplicator.now_ms", return_value=at_expiry):
            result = dedup.process(_event(r))
        assert result is not None

    def test_sliding_window_no_boundary_leak(self):
        """Readings at 4999ms and 5001ms after first_seen: first suppressed, second passes.

        This is the boundary-leak regression test. With the old bucket approach
        (timestamp // 5000) two readings could fall in different buckets and
        both pass even though they were only 2ms apart straddling a boundary.
        With first_seen sliding window this cannot happen.
        """
        dedup = EventDeduplicator()
        r = _reading(value=5.0)
        now = _ms()
        with patch("ori.network.deduplicator.now_ms", return_value=now):
            dedup.process(_event(r))

        # 4999ms later — still inside window → suppressed
        with patch("ori.network.deduplicator.now_ms", return_value=now + 4_999):
            assert dedup.process(_event(r)) is None

        # 5001ms after first_seen → outside window → passes through
        with patch("ori.network.deduplicator.now_ms", return_value=now + 5_001):
            assert dedup.process(_event(r)) is not None


# ─── Stats ────────────────────────────────────────────────────────────────────


class TestStats:
    def test_initial_stats_are_zero(self):
        stats = EventDeduplicator().get_stats()
        assert stats == {
            "total_processed": 0,
            "total_suppressed": 0,
            "active_fingerprints": 0,
        }

    def test_processed_counts_every_call(self):
        dedup = EventDeduplicator()
        r = _reading()
        dedup.process(_event(r))
        dedup.process(_event(r))
        dedup.process(_event(r))
        assert dedup.get_stats()["total_processed"] == 3

    def test_suppressed_counts_only_duplicates(self):
        dedup = EventDeduplicator()
        r = _reading()
        dedup.process(_event(r))  # passes → not suppressed
        dedup.process(_event(r))  # suppressed
        dedup.process(_event(r))  # suppressed
        assert dedup.get_stats()["total_suppressed"] == 2

    def test_active_fingerprints_count(self):
        dedup = EventDeduplicator()
        dedup.process(_event(_reading(sensor_id="s1")))
        dedup.process(_event(_reading(sensor_id="s2")))
        assert dedup.get_stats()["active_fingerprints"] == 2


# ─── OccurrenceRecord ─────────────────────────────────────────────────────────


class TestOccurrenceRecord:
    def test_record_created_on_first_event(self):
        dedup = EventDeduplicator()
        r = _reading(value=5.0)
        event = _event(r)
        dedup.process(event)
        assert len(dedup._records) == 1
        rec = next(iter(dedup._records.values()))
        assert isinstance(rec, OccurrenceRecord)
        assert rec.count == 1
        assert rec.event is event

    def test_record_count_increments_on_duplicate(self):
        dedup = EventDeduplicator()
        r = _reading(value=5.0)
        dedup.process(_event(r))
        dedup.process(_event(r))
        rec = next(iter(dedup._records.values()))
        assert rec.count == 2

    def test_first_seen_does_not_change_on_duplicate(self):
        dedup = EventDeduplicator()
        r = _reading(value=5.0)
        now = _ms()
        with patch("ori.network.deduplicator.now_ms", return_value=now):
            dedup.process(_event(r))
        later = now + 1_000
        with patch("ori.network.deduplicator.now_ms", return_value=later):
            dedup.process(_event(r))
        rec = next(iter(dedup._records.values()))
        assert rec.first_seen == now
        assert rec.last_seen == later


# ─── Cleanup ──────────────────────────────────────────────────────────────────


class TestCleanup:
    def test_cleanup_removes_stale_records(self):
        dedup = EventDeduplicator()
        r = _reading()
        now = _ms()
        with patch("ori.network.deduplicator.now_ms", return_value=now):
            dedup.process(_event(r))

        # Advance 31 seconds past the record's last_seen
        future = now + 31_000
        with patch("ori.network.deduplicator.now_ms", return_value=future):
            evicted = dedup.cleanup()

        assert evicted == 1
        assert len(dedup._records) == 0

    def test_cleanup_keeps_fresh_records(self):
        dedup = EventDeduplicator()
        r = _reading()
        now = _ms()
        with patch("ori.network.deduplicator.now_ms", return_value=now):
            dedup.process(_event(r))

        # Only 10 seconds later — within the 30-second TTL
        with patch("ori.network.deduplicator.now_ms", return_value=now + 10_000):
            evicted = dedup.cleanup()

        assert evicted == 0
        assert len(dedup._records) == 1

    def test_cleanup_selectively_removes_old_records(self):
        dedup = EventDeduplicator()
        now = _ms()
        with patch("ori.network.deduplicator.now_ms", return_value=now):
            dedup.process(_event(_reading(sensor_id="s-old")))

        # second sensor seen 20 s later
        with patch("ori.network.deduplicator.now_ms", return_value=now + 20_000):
            dedup.process(_event(_reading(sensor_id="s-fresh")))

        # Cleanup at now+35s — s-old is stale, s-fresh is not
        with patch("ori.network.deduplicator.now_ms", return_value=now + 35_000):
            evicted = dedup.cleanup()

        assert evicted == 1
        assert len(dedup._records) == 1
        remaining = next(iter(dedup._records.values()))
        assert remaining.event.sensor_id == "s-fresh"

    def test_cleanup_returns_zero_when_nothing_to_evict(self):
        dedup = EventDeduplicator()
        assert dedup.cleanup() == 0

    def test_cleanup_after_dedup_window_and_ttl_evicts_old_record(self):
        dedup = EventDeduplicator()
        reading = _reading(sensor_id="cpu", value=11.1)
        now = _ms()

        with patch("ori.network.deduplicator.now_ms", return_value=now):
            dedup.process(_event(reading))

        # Dedup window elapsed; same fingerprint is re-registered.
        with patch("ori.network.deduplicator.now_ms", return_value=now + 6_001):
            dedup.process(_event(reading))

        # Cleanup past TTL should evict the stale entry.
        with patch("ori.network.deduplicator.now_ms", return_value=now + 37_100):
            evicted = dedup.cleanup()

        assert evicted == 1
        assert len(dedup._records) == 0
