# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio

import pytest

from ori.hardware.led_indicator import (
    LEDIndicator,
    NetworkState,
    PolicyLEDState,
    PowerState,
    RuntimeHealthState,
    StatusSignalingConfig,
)


class _FakePin:
    def __init__(self, _pin: int):
        self.is_on = False

    def on(self) -> None:
        self.is_on = True

    def off(self) -> None:
        self.is_on = False

    def close(self) -> None:
        self.is_on = False


@pytest.mark.asyncio
async def test_tier_d_priority_overrides_other_states():
    indicator = LEDIndicator(
        StatusSignalingConfig(),
        device_factory=_FakePin,
    )
    await indicator.connect()

    indicator.set_hardware_fault(True)
    indicator.set_tier_c_pending(has_comms=False)
    indicator.set_tier_d_firing()
    indicator.tick(now_ms_value=0)

    assert indicator._relay_led.is_on is True
    assert indicator._buzzer.is_on is True


@pytest.mark.asyncio
async def test_pattern_collision_fault_vs_policy_states():
    indicator = LEDIndicator(
        StatusSignalingConfig(),
        device_factory=_FakePin,
    )
    await indicator.connect()

    fault_seq = []
    indicator.set_hardware_fault(True)
    for ts in range(0, 5000, 250):
        indicator.tick(now_ms_value=ts)
        fault_seq.append(indicator._health_led.is_on)
    indicator.set_hardware_fault(False)

    grace_seq = []
    indicator.set_policy_state(PolicyLEDState.GRACE)
    for ts in range(0, 5000, 250):
        indicator.tick(now_ms_value=ts)
        grace_seq.append(indicator._health_led.is_on)

    restricted_seq = []
    indicator.set_policy_state(PolicyLEDState.RESTRICTED)
    for ts in range(0, 5000, 250):
        indicator.tick(now_ms_value=ts)
        restricted_seq.append(indicator._health_led.is_on)

    assert fault_seq != grace_seq
    assert fault_seq != restricted_seq
    assert grace_seq != restricted_seq


@pytest.mark.asyncio
async def test_non_pi_noop_mode():
    indicator = LEDIndicator(StatusSignalingConfig())
    await indicator.connect()
    assert indicator.available is False
    indicator.set_runtime_state(RuntimeHealthState.NORMAL)
    indicator.set_network_state(NetworkState.NONE)
    indicator.set_policy_state(PolicyLEDState.NORMAL)
    indicator.set_power_state(PowerState.MAINS)
    indicator.tick(now_ms_value=0)
    await indicator.close()


@pytest.mark.asyncio
async def test_status_loop_ticks_and_closes():
    from ori.runtime import OriRuntime

    indicator = LEDIndicator(
        StatusSignalingConfig(),
        device_factory=_FakePin,
    )
    await indicator.connect()

    runtime = OriRuntime()
    task = asyncio.create_task(
        runtime._status_signaling_loop(indicator=indicator, tick_ms=50)
    )
    await asyncio.sleep(0.12)
    await runtime.stop()
    await task
    assert indicator.available is False
