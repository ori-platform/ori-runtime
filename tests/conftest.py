# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Test-wide guards.

The suite must not be able to move a physical output. On a developer machine
that is true by accident — gpiozero is absent, so every GPIO path falls back to
simulation. On a Pi it was not true at all: `RelayAction.connect` builds a real
`OutputDevice` whenever gpiozero is importable, so running the suite claimed
BCM 26 and toggled it, and a bench with a relay wired would have actuated.

Safety that depends on a dependency being missing is not safety. The guard here
substitutes gpiozero's output classes with recording fakes, so the tests keep
exercising the real code paths and reach no pin.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

#: Set to run against real hardware. Deliberately awkward: an operator who wants
#: a bench test opts in for that run, and nothing acquires the ability by
#: default because a dependency happened to be installed.
ALLOW_GPIO_ENV = "ORI_TEST_ALLOW_REAL_GPIO"

#: Every gpiozero name the runtime constructs. `Device` is absent on purpose:
#: `resolved_pin_factory_name` calls `Device.ensure_pin_factory()` to learn
#: which backend would drive a pin, which opens the chip and claims no line.
#: That answer is what the hardened-posture check needs, and faking it would
#: report a capability the host does not have.
_OUTPUT_CLASSES = ("OutputDevice", "DigitalOutputDevice", "LED", "Buzzer", "PWMLED")


class FakeGPIODevice:
    """Stands in for a gpiozero output, recording instead of driving."""

    def __init__(self, pin: int | str, *args: Any, **kwargs: Any) -> None:
        self.pin = pin
        self.active_high = bool(kwargs.get("active_high", True))
        self.value = float(bool(kwargs.get("initial_value", False)))
        self.closed = False
        self.history: list[str] = []

    def on(self) -> None:
        self.value = 1.0
        self.history.append("on")

    def off(self) -> None:
        self.value = 0.0
        self.history.append("off")

    def toggle(self) -> None:
        self.value = 0.0 if self.value else 1.0
        self.history.append("toggle")

    def close(self) -> None:
        self.closed = True
        self.history.append("close")

    def __repr__(self) -> str:
        return f"FakeGPIODevice(pin={self.pin!r}, value={self.value})"


def _real_gpio_allowed() -> bool:
    return os.environ.get(ALLOW_GPIO_ENV, "").strip().lower() in {"1", "true", "yes"}


@pytest.fixture(autouse=True)
def no_real_gpio(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse real GPIO for the whole suite unless a run opts in.

    Autouse rather than a marker each hardware test remembers to apply: the
    failure mode is a test that forgets, and a guard you can forget is the one
    already in place — a module-level skip that fires when gpiozero is *absent*,
    which is exactly backwards.
    """
    if _real_gpio_allowed():
        return
    try:
        import gpiozero  # pyright: ignore[reportMissingImports]
    except ImportError:
        return  # Nothing here can reach a pin.

    for name in _OUTPUT_CLASSES:
        if hasattr(gpiozero, name):
            monkeypatch.setattr(gpiozero, name, FakeGPIODevice)
