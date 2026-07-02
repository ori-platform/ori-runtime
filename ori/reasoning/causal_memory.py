# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import datetime
import hashlib

from ori.network.events import OriEvent


def generate_key(event: OriEvent, trigger_name: str) -> str:
    """Return a stable SHA-256 hex key for a (sensor_type, trigger, value, weekday) tuple.

    Two events produce the same key when they share:

    - ``sensor_type`` (e.g. ``'current_clamp'``)
    - ``trigger_name`` (the matched rule name from the skill YAML)
    - ``round(value, 0)`` — rounded to the nearest whole unit so minor jitter
      does not fragment the cache
    - ``day_of_week`` (0=Monday … 6=Sunday) — captures weekday/weekend patterns

    Events without a reading fall back to ``event.event_type`` for the
    sensor_type component so heartbeats can still be cached.

    Args:
        event: The sensor event to fingerprint.
        trigger_name: The rule or trigger name that fired.

    Returns:
        64-character lowercase hex string (SHA-256 digest).
    """
    sensor_type = (
        event.reading.sensor_type if event.reading is not None else event.event_type
    )
    value_bucket = str(
        round(event.reading.value, 0) if event.reading is not None else 0
    )
    dt = datetime.datetime.fromtimestamp(
        event.timestamp / 1000.0, tz=datetime.timezone.utc
    )
    day_of_week = str(dt.weekday())  # 0=Monday, 6=Sunday

    raw = sensor_type + trigger_name + value_bucket + day_of_week
    return hashlib.sha256(raw.encode()).hexdigest()


class CausalMemory:
    """Pattern cache that short-circuits LLM inference on known situations.

    On a cache hit, :meth:`lookup` returns the previously stored resolution
    string immediately — no LLM call is made.  The :class:`~ori.state.store.StateStore`
    handles persistence; this class owns key generation and provides the
    domain-level interface consumed by the :class:`~ori.reasoning.elevator.IntelligenceElevator`.

    Args:
        state_store: An open :class:`~ori.state.store.StateStore` instance.
    """

    def __init__(self, state_store: object) -> None:
        self._store = state_store

    # ── Public API ────────────────────────────────────────────────────────────

    async def lookup(self, pattern_key: str) -> str | None:
        """Return the cached resolution for *pattern_key*, or ``None`` on a miss.

        A cache hit also increments the ``hit_count`` and updates ``last_seen``
        in the backing store (handled transparently by
        :meth:`~ori.state.store.StateStore.lookup_causal_memory`).

        Args:
            pattern_key: A key produced by :func:`generate_key`.

        Returns:
            The stored resolution string, or ``None`` if not cached.
        """
        return await self._store.lookup_causal_memory(pattern_key)

    async def store(self, pattern_key: str, resolution: str, confidence: float) -> None:
        """Persist or update a resolution for *pattern_key*.

        If the key already exists the resolution and confidence are updated and
        ``hit_count`` is incremented (upsert semantics from the store layer).

        Args:
            pattern_key: A key produced by :func:`generate_key`.
            resolution: The text to cache (e.g. the LLM's reasoning output).
            confidence: 0.0–1.0 confidence score at the time of storage.
        """
        await self._store.store_causal_memory(pattern_key, resolution, confidence)

    @staticmethod
    def generate_key(event: OriEvent, trigger_name: str) -> str:
        """Convenience alias — delegates to the module-level :func:`generate_key`."""
        return generate_key(event, trigger_name)
