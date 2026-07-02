# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import time
from unittest.mock import AsyncMock, patch

from ori.network.events import OriEvent, SensorReading
from ori.reasoning.causal_memory import CausalMemory, generate_key

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _ms() -> int:
    return int(time.time() * 1000)


def _reading(
    sensor_type: str = "current_clamp",
    value: float = 5.0,
    sensor_id: str = "load-current",
) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit="ampere",
        timestamp=_ms(),
        quality=1.0,
    )


def _event(sensor_type: str = "current_clamp", value: float = 5.0) -> OriEvent:
    return OriEvent.from_reading(
        _reading(sensor_type=sensor_type, value=value), "dev-01"
    )


def _heartbeat() -> OriEvent:
    return OriEvent(
        event_id="hb-001",
        event_type="device.heartbeat",
        device_id="dev-01",
        sensor_id="",
        timestamp=_ms(),
        reading=None,
    )


def _mock_store() -> AsyncMock:
    store = AsyncMock()
    store.lookup_causal_memory.return_value = None
    store.store_causal_memory.return_value = None
    return store


# ─── generate_key (module-level function) ─────────────────────────────────────


class TestGenerateKey:
    def test_returns_64_char_hex(self):
        key = generate_key(_event(), "anomalous_draw")
        assert len(key) == 64
        int(key, 16)  # raises if not valid hex

    def test_same_inputs_same_key(self):
        event = _event(sensor_type="current_clamp", value=5.0)
        with patch("ori.reasoning.causal_memory.datetime") as mock_dt:
            mock_dt.datetime.fromtimestamp.return_value.weekday.return_value = 0
            k1 = generate_key(event, "trigger_a")
            k2 = generate_key(event, "trigger_a")
        assert k1 == k2

    def test_different_sensor_type_gives_different_key(self):
        with patch("ori.reasoning.causal_memory.datetime") as mock_dt:
            mock_dt.datetime.fromtimestamp.return_value.weekday.return_value = 0
            k1 = generate_key(_event(sensor_type="current_clamp"), "t")
            k2 = generate_key(_event(sensor_type="voltage"), "t")
        assert k1 != k2

    def test_different_trigger_gives_different_key(self):
        event = _event()
        with patch("ori.reasoning.causal_memory.datetime") as mock_dt:
            mock_dt.datetime.fromtimestamp.return_value.weekday.return_value = 0
            k1 = generate_key(event, "trigger_a")
            k2 = generate_key(event, "trigger_b")
        assert k1 != k2

    def test_different_value_bucket_gives_different_key(self):
        with patch("ori.reasoning.causal_memory.datetime") as mock_dt:
            mock_dt.datetime.fromtimestamp.return_value.weekday.return_value = 0
            k1 = generate_key(_event(value=5.0), "t")  # rounds to 5
            k2 = generate_key(_event(value=6.0), "t")  # rounds to 6
        assert k1 != k2

    def test_values_in_same_bucket_give_same_key(self):
        """5.1 and 5.4 both round to 5.0 — same key."""
        with patch("ori.reasoning.causal_memory.datetime") as mock_dt:
            mock_dt.datetime.fromtimestamp.return_value.weekday.return_value = 0
            k1 = generate_key(_event(value=5.1), "t")
            k2 = generate_key(_event(value=5.4), "t")
        assert k1 == k2

    def test_different_day_of_week_gives_different_key(self):
        event = _event()
        with patch("ori.reasoning.causal_memory.datetime") as mock_dt:
            mock_dt.datetime.fromtimestamp.return_value.weekday.return_value = 0
            k_monday = generate_key(event, "t")
        with patch("ori.reasoning.causal_memory.datetime") as mock_dt:
            mock_dt.datetime.fromtimestamp.return_value.weekday.return_value = 6
            k_sunday = generate_key(event, "t")
        assert k_monday != k_sunday

    def test_event_without_reading_uses_event_type(self):
        """Heartbeat events must not crash key generation."""
        event = _heartbeat()
        with patch("ori.reasoning.causal_memory.datetime") as mock_dt:
            mock_dt.datetime.fromtimestamp.return_value.weekday.return_value = 0
            key = generate_key(event, "heartbeat_check")
        assert len(key) == 64


# ─── CausalMemory.lookup ──────────────────────────────────────────────────────


class TestLookup:
    async def test_miss_returns_none(self):
        store = _mock_store()
        cm = CausalMemory(store)
        result = await cm.lookup("nonexistent-key")
        assert result is None
        store.lookup_causal_memory.assert_called_once_with("nonexistent-key")

    async def test_hit_returns_cached_resolution(self):
        store = _mock_store()
        store.lookup_causal_memory.return_value = "AC unit drawing 40% above baseline."
        cm = CausalMemory(store)
        result = await cm.lookup("some-key")
        assert result == "AC unit drawing 40% above baseline."

    async def test_delegates_to_store(self):
        store = _mock_store()
        cm = CausalMemory(store)
        await cm.lookup("key-123")
        store.lookup_causal_memory.assert_called_once_with("key-123")


# ─── CausalMemory.store ───────────────────────────────────────────────────────


class TestStore:
    async def test_delegates_to_store_causal_memory(self):
        store = _mock_store()
        cm = CausalMemory(store)
        await cm.store("key-abc", "resolution text", 0.95)
        store.store_causal_memory.assert_called_once_with(
            "key-abc", "resolution text", 0.95
        )

    async def test_store_then_lookup_roundtrip(self):
        """After store(), a subsequent lookup() returns the same resolution."""
        stored: dict[str, str] = {}

        async def fake_store(key, resolution, confidence):
            stored[key] = resolution

        async def fake_lookup(key):
            return stored.get(key)

        store = AsyncMock()
        store.store_causal_memory.side_effect = fake_store
        store.lookup_causal_memory.side_effect = fake_lookup

        cm = CausalMemory(store)
        await cm.store("k", "cached resolution", 0.8)
        result = await cm.lookup("k")
        assert result == "cached resolution"


# ─── CausalMemory.generate_key (instance method alias) ────────────────────────


class TestInstanceGenerateKey:
    def test_instance_method_matches_module_function(self):
        store = _mock_store()
        cm = CausalMemory(store)
        event = _event()
        with patch("ori.reasoning.causal_memory.datetime") as mock_dt:
            mock_dt.datetime.fromtimestamp.return_value.weekday.return_value = 2
            k_instance = cm.generate_key(event, "trigger")
            k_module = generate_key(event, "trigger")
        assert k_instance == k_module
