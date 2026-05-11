# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass, field
from typing import Any, Optional

from ori.network.events import OriEvent
from ori.time_utils import now_ms


class HookHistoryAdapter:
    """Synchronous adapter to wrap StateStore for skill hooks."""

    def __init__(self, store: Any):
        self._store = store

    def _read(self, method_name: str, *args: Any) -> Any:
        """Execute a stable StateStore hook-sync method."""
        if not self._store:
            return None
        method = getattr(self._store, method_name, None)
        if callable(method):
            return method(*args)
        return None

    def avg_hours(self, sensor_id: str, hours: int) -> Optional[float]:
        if not self._store:
            return None
        return self._read("hooks_avg_last_hours", sensor_id, hours)

    def avg_last_n(self, sensor_id: str, n: int) -> Optional[float]:
        if not self._store:
            return None
        return self._read("hooks_avg_last_n", sensor_id, n)

    def last_value(self, sensor_id: str) -> Optional[float]:
        if not self._store:
            return None
        history = self._read("hooks_get_history", sensor_id, 1) or []
        if history:
            return history[0].value
        return None

    def last_timestamp(self, sensor_id: str) -> Optional[int]:
        if not self._store:
            return None
        history = self._read("hooks_get_history", sensor_id, 1) or []
        if history:
            return history[0].timestamp
        return None

    def fetch_history(self, sensor_id: str, limit: int = 1) -> list[dict[str, Any]]:
        if not self._store:
            return []
        history = self._read("hooks_get_history", sensor_id, limit) or []
        return [
            {
                "sensor_id": r.sensor_id,
                "sensor_type": r.sensor_type,
                "value": r.value,
                "unit": r.unit,
                "timestamp": r.timestamp,
                "quality": r.quality,
                "metadata": r.metadata,
            }
            for r in history
        ]


class HookStateAdapter:
    """Provides key-value persistence specifically isolated to the active skill."""

    def __init__(self, store: Any, skill_name: str):
        self._store = store
        self._skill_name = skill_name

    def _read(self, method_name: str, *args: Any) -> Any:
        """Execute a stable StateStore hook-sync method."""
        if not self._store:
            return None
        method = getattr(self._store, method_name, None)
        if callable(method):
            return method(*args)
        return None

    def get(self, key: str) -> Optional[str]:
        if not self._store or not self._skill_name:
            return None
        return self._read("hooks_get_skill_state", self._skill_name, key)

    def set(self, key: str, value: str) -> None:
        if not self._store or not self._skill_name:
            return
        fn = getattr(self._store, "hooks_set_skill_state", None)
        if callable(fn):
            fn(self._skill_name, key, value)


@dataclass
class HookContext:
    """Context block provided to synchronous skill hooks."""

    event: OriEvent | None
    trigger_name: str
    readings: dict[str, Any]
    history: HookHistoryAdapter
    state: HookStateAdapter
    timestamp: int
    config: dict[str, Any] = field(default_factory=dict)
    derived: dict[str, Any] = field(default_factory=dict)

    @property
    def reading(self) -> Any:
        """Convenience accessor for hook compatibility."""
        if self.event is None:
            return None
        return self.event.reading

    @classmethod
    def build(
        cls,
        event: OriEvent,
        store: Any,
        skill_name: str,
        skill_config: dict[str, Any] | None = None,
    ) -> "HookContext":
        readings = {}
        if event and event.reading:
            readings[event.reading.sensor_id] = event.reading.value
            # Also spread meta into readings for easy trigger addressing
            if isinstance(event.reading.metadata, dict):
                readings.update(event.reading.metadata)

        return cls(
            event=event,
            trigger_name="",
            readings=readings,
            history=HookHistoryAdapter(store),
            state=HookStateAdapter(store, skill_name),
            timestamp=event.timestamp if event else now_ms(),
            config=skill_config if isinstance(skill_config, dict) else {},
        )
