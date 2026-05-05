# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from typing import Any, Callable

from ori.time_utils import now_ms

logger = logging.getLogger(__name__)

_VALID_BCM_PINS = frozenset(range(2, 28))


class RuntimeHealthState(str, enum.Enum):
    STARTING = "starting"
    NORMAL = "normal"
    DEGRADED = "degraded"


class PolicyLEDState(str, enum.Enum):
    NORMAL = "normal"
    GRACE = "grace"
    RESTRICTED = "restricted"


class NetworkState(str, enum.Enum):
    INTERNET = "internet"
    GSM_ONLY = "gsm_only"
    NONE = "none"


class PowerState(str, enum.Enum):
    MAINS = "mains"
    BATTERY_LOW = "battery_low"
    BATTERY_CRITICAL = "battery_critical"


@dataclass(frozen=True)
class StatusSignalingConfig:
    power_led_pin: int = 17
    relay_led_pin: int = 27
    network_led_pin: int = 22
    health_led_pin: int = 23
    buzzer_pin: int = 24


class _NullPin:
    def on(self) -> None:
        return

    def off(self) -> None:
        return

    def close(self) -> None:
        return


class LEDIndicator:
    """GPIO status signaling with priority arbitration.

    On non-Pi hosts (gpiozero unavailable), this class degrades to no-op mode.
    """

    def __init__(
        self,
        config: StatusSignalingConfig,
        *,
        tick_ms: int = 100,
        device_factory: Callable[[int], Any] | None = None,
    ) -> None:
        self._validate_pins(config)
        self._cfg = config
        self._tick_ms = max(int(tick_ms), 50)
        self._device_factory = device_factory
        self._available = False

        self._power_led: Any = _NullPin()
        self._relay_led: Any = _NullPin()
        self._network_led: Any = _NullPin()
        self._health_led: Any = _NullPin()
        self._buzzer: Any = _NullPin()

        self._runtime_state = RuntimeHealthState.STARTING
        self._policy_state = PolicyLEDState.NORMAL
        self._network_state = NetworkState.NONE
        self._power_state = PowerState.MAINS
        self._relay_energized = False
        self._hardware_fault = False
        self._tier_c_pending = False
        self._tier_c_has_comms = False
        self._tier_d_firing = False

        self._tier_d_snapshot: dict[str, Any] | None = None

    @property
    def available(self) -> bool:
        return self._available

    def set_runtime_state(self, state: RuntimeHealthState) -> None:
        self._runtime_state = state

    def set_policy_state(self, state: PolicyLEDState | str) -> None:
        self._policy_state = (
            state if isinstance(state, PolicyLEDState) else PolicyLEDState(str(state))
        )

    def set_network_state(self, state: NetworkState | str) -> None:
        self._network_state = (
            state if isinstance(state, NetworkState) else NetworkState(str(state))
        )

    def set_power_state(self, state: PowerState | str) -> None:
        self._power_state = (
            state if isinstance(state, PowerState) else PowerState(str(state))
        )

    def set_hardware_fault(self, active: bool) -> None:
        self._hardware_fault = bool(active)

    def set_relay_energized(self, active: bool) -> None:
        self._relay_energized = bool(active)

    def set_tier_c_pending(self, has_comms: bool) -> None:
        self._tier_c_pending = True
        self._tier_c_has_comms = bool(has_comms)

    def clear_tier_c_pending(self) -> None:
        self._tier_c_pending = False
        self._tier_c_has_comms = False

    def set_tier_d_firing(self) -> None:
        if self._tier_d_firing:
            return
        self._tier_d_snapshot = {
            "runtime_state": self._runtime_state,
            "policy_state": self._policy_state,
            "network_state": self._network_state,
            "power_state": self._power_state,
            "relay_energized": self._relay_energized,
            "hardware_fault": self._hardware_fault,
            "tier_c_pending": self._tier_c_pending,
            "tier_c_has_comms": self._tier_c_has_comms,
        }
        self._tier_d_firing = True

    def clear_tier_d_firing(self) -> None:
        if not self._tier_d_firing:
            return
        self._tier_d_firing = False
        if self._tier_d_snapshot is None:
            return
        self._runtime_state = self._tier_d_snapshot["runtime_state"]
        self._policy_state = self._tier_d_snapshot["policy_state"]
        self._network_state = self._tier_d_snapshot["network_state"]
        self._power_state = self._tier_d_snapshot["power_state"]
        self._relay_energized = self._tier_d_snapshot["relay_energized"]
        self._hardware_fault = self._tier_d_snapshot["hardware_fault"]
        self._tier_c_pending = self._tier_d_snapshot["tier_c_pending"]
        self._tier_c_has_comms = self._tier_d_snapshot["tier_c_has_comms"]
        self._tier_d_snapshot = None

    async def connect(self) -> None:
        factory = self._device_factory
        if factory is None:
            try:
                from gpiozero import DigitalOutputDevice  # type: ignore[import-untyped]

                factory = DigitalOutputDevice
            except ImportError:
                logger.info(
                    "LEDIndicator: gpiozero not available — running in no-op mode"
                )
                return

        self._power_led = factory(self._cfg.power_led_pin)
        self._relay_led = factory(self._cfg.relay_led_pin)
        self._network_led = factory(self._cfg.network_led_pin)
        self._health_led = factory(self._cfg.health_led_pin)
        self._buzzer = factory(self._cfg.buzzer_pin)
        self._available = True

    async def close(self) -> None:
        for pin in (
            self._power_led,
            self._relay_led,
            self._network_led,
            self._health_led,
            self._buzzer,
        ):
            try:
                pin.off()
            except Exception:
                pass
            if hasattr(pin, "close"):
                try:
                    pin.close()
                except Exception:
                    pass
        self._available = False

    def tick(self, now_ms_value: int | None = None) -> None:
        now = now_ms() if now_ms_value is None else int(now_ms_value)
        priority = self._resolve_priority_state()

        power_on = False
        relay_on = False
        network_on = False
        health_on = False
        buzzer_on = False

        if priority == 1:  # Tier D firing
            relay_on = True
            health_on = self._blink(now, period_ms=300)
            buzzer_on = True
        elif priority == 2:  # Hardware fault
            health_on = self._single_slow_blink(now)
        elif priority == 3:  # Battery critical
            power_on = self._blink(now, period_ms=300)
            buzzer_on = self._double_beep(now, cycle_ms=60_000)
        elif priority == 4:  # Tier C pending, no comms
            relay_on = self._blink(now, period_ms=300)
            buzzer_on = self._triple_beep(now, cycle_ms=30_000)
        elif priority == 5:  # Tier C pending, comms
            relay_on = self._blink(now, period_ms=2000)
        elif priority == 6:  # Policy restricted
            health_on = self._triple_pulse(now)
        elif priority == 7:  # Policy grace
            health_on = self._double_pulse(now)
        elif priority == 8:  # Battery low
            power_on = True
        elif priority == 9:  # No connectivity
            network_on = False
        elif priority == 10:  # GSM only
            network_on = self._blink(now, period_ms=2000)
        else:  # 11 - Normal operation
            power_on = True if self._power_state == PowerState.MAINS else False
            network_on = self._network_state == NetworkState.INTERNET
            relay_on = self._relay_energized
            if self._runtime_state == RuntimeHealthState.STARTING:
                health_on = self._blink(now, period_ms=300)
            elif self._runtime_state == RuntimeHealthState.DEGRADED:
                health_on = self._single_slow_blink(now)
            else:
                health_on = True

        self._set_pin(self._power_led, power_on)
        self._set_pin(self._relay_led, relay_on)
        self._set_pin(self._network_led, network_on)
        self._set_pin(self._health_led, health_on)
        self._set_pin(self._buzzer, buzzer_on)

    def _resolve_priority_state(self) -> int:
        if self._tier_d_firing:
            return 1
        if self._hardware_fault:
            return 2
        if self._power_state == PowerState.BATTERY_CRITICAL:
            return 3
        if self._tier_c_pending and not self._tier_c_has_comms:
            return 4
        if self._tier_c_pending and self._tier_c_has_comms:
            return 5
        if self._policy_state == PolicyLEDState.RESTRICTED:
            return 6
        if self._policy_state == PolicyLEDState.GRACE:
            return 7
        if self._power_state == PowerState.BATTERY_LOW:
            return 8
        if self._network_state == NetworkState.NONE:
            return 9
        if self._network_state == NetworkState.GSM_ONLY:
            return 10
        return 11

    @staticmethod
    def _blink(now_ms_value: int, *, period_ms: int) -> bool:
        phase = now_ms_value % max(period_ms, 1)
        return phase < (period_ms // 2)

    @staticmethod
    def _single_slow_blink(now_ms_value: int) -> bool:
        # Collision-safe against double/triple pulse states
        phase = now_ms_value % 2000
        return phase < 500

    @staticmethod
    def _double_pulse(now_ms_value: int) -> bool:
        # Two slow pulses + long pause (priority 7)
        phase = now_ms_value % 5000
        return (0 <= phase < 500) or (1000 <= phase < 1500)

    @staticmethod
    def _triple_pulse(now_ms_value: int) -> bool:
        # Three slow pulses + long pause (priority 6)
        phase = now_ms_value % 5000
        return (0 <= phase < 500) or (1000 <= phase < 1500) or (2000 <= phase < 2500)

    @staticmethod
    def _double_beep(now_ms_value: int, *, cycle_ms: int) -> bool:
        phase = now_ms_value % cycle_ms
        return (0 <= phase < 120) or (250 <= phase < 370)

    @staticmethod
    def _triple_beep(now_ms_value: int, *, cycle_ms: int) -> bool:
        phase = now_ms_value % cycle_ms
        return (0 <= phase < 120) or (250 <= phase < 370) or (500 <= phase < 620)

    @staticmethod
    def _set_pin(pin: Any, state: bool) -> None:
        try:
            if state:
                pin.on()
            else:
                pin.off()
        except Exception:
            pass

    @staticmethod
    def _validate_pins(config: StatusSignalingConfig) -> None:
        pins = [
            config.power_led_pin,
            config.relay_led_pin,
            config.network_led_pin,
            config.health_led_pin,
            config.buzzer_pin,
        ]
        if len(set(pins)) != len(pins):
            raise ValueError("LEDIndicator: status signaling pins must be unique.")
        for pin in pins:
            if pin not in _VALID_BCM_PINS:
                raise ValueError(
                    f"LEDIndicator: BCM pin {pin} is outside the valid range (2-27)."
                )
