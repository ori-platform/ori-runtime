# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import time
from dataclasses import dataclass

from ori.network.events import OriEvent, compute_fingerprint

_WINDOW_MS = 5_000   # suppress duplicates seen within this window
_TTL_MS = 30_000     # evict records older than this from the cache


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class OccurrenceRecord:
    first_seen: int   # unix milliseconds
    last_seen: int    # unix milliseconds
    count: int
    event: OriEvent


class EventDeduplicator:
    """Suppress duplicate sensor readings that arrive within a 5-second window.

    Two events are considered duplicates when they share the same fingerprint
    (device + sensor_id + sensor_type + rounded value), as produced by
    :func:`~ori.network.events.compute_fingerprint`, AND the current time is
    within :data:`_WINDOW_MS` milliseconds of the record's ``first_seen``
    timestamp.  Using ``first_seen`` (not ``last_seen``) gives a true sliding
    window that does not leak at fixed bucket boundaries.

    The deduplicator is intentionally synchronous and has no external
    dependencies — it runs inline in the event loop without blocking.
    """

    def __init__(self) -> None:
        self._records: dict[str, OccurrenceRecord] = {}
        self._total_processed: int = 0
        self._total_suppressed: int = 0

    def process(self, event: OriEvent) -> OriEvent | None:
        """Evaluate *event* and return it if it should be forwarded.

        Returns:
            The original *event* if it is new or outside the dedup window.
            ``None`` if a duplicate was seen within the last
            :data:`_WINDOW_MS` milliseconds.
        """
        self._total_processed += 1

        # Compute fingerprint from the reading if available; fall back to
        # the pre-set fingerprint on the event itself.
        if event.reading is not None:
            fp = compute_fingerprint(event.reading, event.device_id)
        else:
            fp = event.fingerprint or event.event_id  # heartbeats are unique

        now = _now_ms()
        record = self._records.get(fp)

        if record is not None and (now - record.first_seen) < _WINDOW_MS:
            # Duplicate within the window — suppress
            record.last_seen = now
            record.count += 1
            self._total_suppressed += 1
            return None

        # New or expired — forward and (re)register
        self._records[fp] = OccurrenceRecord(
            first_seen=record.first_seen if record is not None else now,
            last_seen=now,
            count=record.count + 1 if record is not None else 1,
            event=event,
        )
        return event

    def cleanup(self) -> int:
        """Remove records that have not been seen for more than 30 seconds.

        Returns:
            Number of records evicted.
        """
        cutoff = _now_ms() - _TTL_MS
        stale = [fp for fp, rec in self._records.items() if rec.last_seen < cutoff]
        for fp in stale:
            del self._records[fp]
        return len(stale)

    def get_stats(self) -> dict:
        """Return running totals for monitoring.

        Returns:
            ``{"total_processed": int, "total_suppressed": int,
            "active_fingerprints": int}``
        """
        return {
            "total_processed": self._total_processed,
            "total_suppressed": self._total_suppressed,
            "active_fingerprints": len(self._records),
        }
