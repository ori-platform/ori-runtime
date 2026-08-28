# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The suite must not be able to move a physical output.

These assertions only mean something where gpiozero is importable, which is the
platform the runtime ships to and the one where the guard is load-bearing. On a
developer machine they skip, and that is the honest outcome: nothing there can
reach a pin, so nothing there can prove a guard against reaching one.
"""

from __future__ import annotations

import pytest

from ori.actions.relay import RelayAction
from tests.conftest import ALLOW_GPIO_ENV, FakeGPIODevice, _real_gpio_allowed

gpiozero = pytest.importorskip(
    "gpiozero", reason="guard is a no-op without gpiozero; nothing here reaches a pin"
)


def test_output_classes_are_substituted() -> None:
    assert gpiozero.OutputDevice is FakeGPIODevice
    assert gpiozero.DigitalOutputDevice is FakeGPIODevice


def test_the_pin_factory_probe_is_left_alone() -> None:
    """`Device` is deliberately not faked.

    `resolved_pin_factory_name()` asks it which backend would drive a pin, which
    opens the chip and claims no line. Faking it would make the hardened-posture
    check report a capability the host does not have — the opposite defect.
    """
    assert not isinstance(gpiozero.Device, FakeGPIODevice)


@pytest.mark.asyncio
async def test_connecting_a_relay_reaches_no_pin() -> None:
    relay = RelayAction()
    await relay.connect(gpio_pin=26, tolerate_missing_backend=False)

    assert isinstance(relay._device, FakeGPIODevice)
    assert relay._simulated is False, (
        "the relay must still report a real backend: the guard replaces the "
        "device, not the runtime's belief about whether one exists"
    )
    assert relay._device.pin == 26


@pytest.mark.asyncio
async def test_actuating_a_relay_records_instead_of_driving() -> None:
    relay = RelayAction()
    await relay.connect(gpio_pin=26, tolerate_missing_backend=False)

    await relay.trigger()
    assert relay.is_active is True
    await relay.release()
    assert relay.is_active is False
    assert relay._device.history == ["on", "off"]


def test_the_opt_in_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ALLOW_GPIO_ENV, raising=False)
    assert _real_gpio_allowed() is False
    for value in ("1", "true", "YES"):
        monkeypatch.setenv(ALLOW_GPIO_ENV, value)
        assert _real_gpio_allowed() is True
    for value in ("", "0", "no", "maybe"):
        monkeypatch.setenv(ALLOW_GPIO_ENV, value)
        assert _real_gpio_allowed() is False
