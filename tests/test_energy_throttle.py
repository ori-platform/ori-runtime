# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import time
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, patch

import pytest

from ori.network.event_bus import EventBus
from ori.network.events import OriEvent, SensorReading
from ori.reasoning.elevator import IntelligenceElevator


def _ms() -> int:
    return int(time.time() * 1000)


def _reading(
    value: float,
    sensor_id: str,
    sensor_type: str = "current_clamp",
    unit: str = "ampere",
) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp=_ms(),
        quality=1.0,
    )


def _event(value: float = 5.0) -> OriEvent:
    return OriEvent.from_reading(
        _reading(value=value, sensor_id="load-current", sensor_type="current_clamp"),
        device_id="dev-01",
    )


@dataclass
class FakeSkill:
    triggers: list = field(default_factory=list)
    actions: dict = field(default_factory=dict)
    prompts: dict = field(default_factory=dict)
    config: dict = field(default_factory=dict)

    def get_default_actions_for_trigger(self, trigger_name: str) -> list[str]:
        defaults = self.actions.get("defaults", {})
        if isinstance(defaults, dict):
            maybe = defaults.get(trigger_name, [])
            if isinstance(maybe, list):
                return maybe
        return []

    def is_action_declared(self, action_name: str) -> bool:
        available = self.actions.get("available", [])
        for entry in available:
            if isinstance(entry, dict) and entry.get("name") == action_name:
                return True
            if isinstance(entry, str) and entry == action_name:
                return True
        return False


def _skill_tier_a() -> FakeSkill:
    return FakeSkill(
        triggers=[
            {
                "name": "anomaly",
                "condition": "value > 3.0",
                "action_tier": "A",
                "bypass_llm": False,
                "cooldown_seconds": 0,
            }
        ],
        actions={
            "available": [{"name": "alert_whatsapp", "tier": "A"}],
            "defaults": {"anomaly": ["alert_whatsapp"]},
        },
    )


def _skill_tier_d() -> FakeSkill:
    return FakeSkill(
        triggers=[
            {
                "name": "dangerous_overcurrent",
                "condition": "value > 4.0",
                "action_tier": "D",
                "bypass_llm": True,
                "cooldown_seconds": 0,
            }
        ],
        actions={
            "available": [{"name": "open_safety_circuit", "tier": "D"}],
            "defaults": {"dangerous_overcurrent": ["open_safety_circuit"]},
        },
    )


def _cfg(enabled: bool = True) -> object:
    return type(
        "C",
        (object,),
        {
            "offline_fallback": "local_slm",
            "escalation_threshold": 0.70,
            "energy_aware_reasoning": (
                {
                    "enabled": enabled,
                    "throttle_threshold_percent": 20,
                    "critical_threshold_percent": 10,
                    "battery_sensor_id": "inverter-battery",
                    "alert_on_throttle": True,
                }
                if enabled
                else {}
            ),
        },
    )()


def _state_store(
    battery_pct: float | None,
    event_history: list[float] | None = None,
) -> AsyncMock:
    store = AsyncMock()

    async def _get_history(sensor_id: str, limit: int = 10):
        if sensor_id == "inverter-battery":
            if battery_pct is None:
                return []
            return [
                _reading(
                    value=battery_pct,
                    sensor_id="inverter-battery",
                    sensor_type="battery_state",
                    unit="percent",
                )
            ]
        vals = event_history or [5.0, 5.0, 5.0]
        return [_reading(v, sensor_id=sensor_id) for v in vals[:limit]]

    store.get_history.side_effect = _get_history
    store.avg_last_hours.return_value = 5.0
    store.log_reasoning = AsyncMock()
    return store


class TestEnergyAwareThrottle:
    @pytest.mark.asyncio
    async def test_throttle_disabled_by_default(self):
        conf = type(
            "C",
            (object,),
            {"offline_fallback": "local_slm", "escalation_threshold": 0.70},
        )()
        elevator = IntelligenceElevator(config=conf)
        store = _state_store(battery_pct=5.0)
        with patch("ori.reasoning.elevator._is_offline", return_value=False):
            tier = await elevator.select_tier(_event(), _skill_tier_a(), store)
        assert tier == "local_slm"

    @pytest.mark.asyncio
    async def test_battery_above_threshold_normal(self):
        elevator = IntelligenceElevator(config=_cfg(enabled=True))
        store = _state_store(battery_pct=50.0)
        with patch("ori.reasoning.elevator._is_offline", return_value=False):
            tier = await elevator.select_tier(_event(), _skill_tier_a(), store)
        assert tier == "local_slm"

    @pytest.mark.asyncio
    async def test_battery_below_throttle_returns_rule(self):
        elevator = IntelligenceElevator(config=_cfg(enabled=True))
        store = _state_store(battery_pct=15.0)
        with patch.object(elevator, "_emit_power_alert", AsyncMock()) as emit:
            tier = await elevator.select_tier(_event(), _skill_tier_a(), store)
        assert tier == "rule"
        emit.assert_awaited_once()
        assert emit.await_args.kwargs["level"] == "low"

    @pytest.mark.asyncio
    async def test_battery_below_critical_returns_rule(self):
        elevator = IntelligenceElevator(config=_cfg(enabled=True))
        store = _state_store(battery_pct=5.0)
        with patch.object(elevator, "_emit_power_alert", AsyncMock()) as emit:
            tier = await elevator.select_tier(_event(), _skill_tier_a(), store)
        assert tier == "rule"
        emit.assert_awaited_once()
        assert emit.await_args.kwargs["level"] == "critical"

    @pytest.mark.asyncio
    async def test_tier_d_unaffected_by_throttle(self):
        elevator = IntelligenceElevator(config=_cfg(enabled=True))
        dispatcher = AsyncMock()
        store = _state_store(battery_pct=5.0)
        await elevator.reason_and_dispatch(
            _event(value=5.0), _skill_tier_d(), store, dispatcher
        )

        dispatcher.dispatch.assert_called_once()
        kwargs = dispatcher.dispatch.call_args.kwargs
        assert kwargs["action"] == "open_safety_circuit"
        assert kwargs["tier"] == "D"

    @pytest.mark.asyncio
    async def test_alert_emitted_on_throttle(self):
        elevator = IntelligenceElevator(config=_cfg(enabled=True))
        store = _state_store(battery_pct=15.0)
        with patch.object(elevator, "_emit_power_alert", AsyncMock()) as emit:
            tier = await elevator.select_tier(_event(), _skill_tier_a(), store)
        assert tier == "rule"
        emit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_alert_not_spammed(self):
        elevator = IntelligenceElevator(config=_cfg(enabled=True))
        bus = EventBus()
        bus.publish = AsyncMock()  # type: ignore[method-assign]
        elevator.attach_event_bus(bus)
        store = _state_store(battery_pct=15.0)

        tier1 = await elevator.select_tier(_event(), _skill_tier_a(), store)
        tier2 = await elevator.select_tier(_event(), _skill_tier_a(), store)
        assert tier1 == "rule"
        assert tier2 == "rule"
        assert bus.publish.await_count == 1

    @pytest.mark.asyncio
    async def test_no_battery_sensor_proceeds_normally(self):
        cfg = _cfg(enabled=True)
        cfg.energy_aware_reasoning["battery_sensor_id"] = "inverter-battery"
        elevator = IntelligenceElevator(config=cfg)
        store = _state_store(battery_pct=None)
        with patch("ori.reasoning.elevator._is_offline", return_value=False):
            tier = await elevator.select_tier(_event(), _skill_tier_a(), store)
        assert tier == "local_slm"
