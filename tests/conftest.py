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

import asyncio
import os
from collections.abc import Callable
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


def _mark_startup_complete(runtime: Any) -> "asyncio.Event":
    """An event set when `start()` finishes its last step.

    `start()` ends by awaiting the shutdown event, and
    `_send_setup_success_notifications` is the last step it takes before doing
    so, which makes wrapping that step an exact marker rather than a guess.
    The shutdown event itself is not one: several background loops await it
    too, so a waiter on it says nothing about whether startup is done.

    If that step is ever renamed this fails loudly with `AttributeError`
    rather than silently going back to racing.
    """
    complete = asyncio.Event()
    original = runtime._send_setup_success_notifications

    async def _marked(*args: Any, **kwargs: Any) -> Any:
        try:
            return await original(*args, **kwargs)
        finally:
            complete.set()

    runtime._send_setup_success_notifications = _marked
    return complete


async def run_runtime_until(
    runtime: Any,
    reached: Callable[[], bool],
    *,
    description: str,
    timeout: float = 15.0,
) -> None:
    """Start a runtime, wait for a state and for startup, then stop it.

    The pattern this replaces slept for a fixed interval and then stopped:

    ```python
    async def _stop():
        await asyncio.sleep(0.1)
        await runtime.stop()

    await asyncio.gather(runtime.start(), _stop())
    ```

    The sleep is a guess that startup got far enough. When it has not — a
    loaded runner, a slower interpreter — the stop tears down a half-built
    runtime, and the failure does not surface at the test that caused it: it
    surfaces wherever startup happened to be, as an assertion inside an
    unrelated component. One of these failed in CI as a bare `AssertionError`
    sixty lines into the state store, from a pull request that does not touch
    the file containing the test.

    **Waiting for the asserted state is not enough on its own.** That state
    becomes true partway through startup, and `start()` still has adapter
    connections, background services, the webhook, the health socket and
    reconciliation ahead of it. Stopping there closes resources those later
    steps are still using — the same race, entered by observation instead of
    by a guess. So this waits for the state, and then for startup to finish,
    and only then stops.

    Both waits earn their place. The state wait is what fails with a useful
    message when the thing the test asserts on never happens; the startup wait
    is what makes the teardown safe. Neither substitutes for the other, and
    the assertions still hold afterwards because what they read — log records,
    recorded calls — persists past the moment it first became true.
    """
    complete = _mark_startup_complete(runtime)

    async def _stop_when_safe() -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while not reached():
            if loop.time() > deadline:
                raise AssertionError(
                    f"startup did not reach {description} within {timeout}s"
                )
            await asyncio.sleep(0.02)
        await asyncio.wait_for(complete.wait(), timeout=timeout)
        await runtime.stop()

    await asyncio.gather(runtime.start(), _stop_when_safe())


def logged(caplog: Any, fragment: str) -> bool:
    """Whether a log record containing `fragment` has been emitted yet."""
    return any(fragment in record.message for record in caplog.records)


async def run_runtime_full_startup(runtime: Any, *, timeout: float = 15.0) -> None:
    """Start a runtime, let startup finish completely, then stop it.

    For tests whose subject is the lifecycle itself, or which assert that
    something did *not* happen: there is no partial state to wait for, and an
    absence cannot be waited for at all.
    """
    await run_runtime_until(
        runtime,
        lambda: True,
        description="the end of startup",
        timeout=timeout,
    )


SLOW_STARTUP_PROBE_ENV = "ORI_SLOW_STARTUP_PROBE"

# Opt-in harness for the fix in ori-platform/ori-runtime#468. A test that waits
# for a state rather than an interval must keep passing when startup is slower
# than the interval it used to guess with, and a run on a fast machine is not
# evidence of that:
#
#     ORI_SLOW_STARTUP_PROBE=1 python3 -m pytest tests/test_runtime.py
#
# It slows an early startup phase and a late one. Slowing only the early phase
# moves every wait later together, so a teardown that fires at a partial state
# still lands before the steps that would notice it; the late delay is what
# puts a stop between the state a test waits for and the startup work that
# follows it.
#
# In-tree and opt-in rather than a recipe in a pull request, so the check can
# be run again by whoever next doubts one of these tests.
if os.environ.get(SLOW_STARTUP_PROBE_ENV) == "1":
    from ori.runtime import OriRuntime as _ProbeRuntime
    from ori.state.store import StateStore as _ProbeStore

    _PROBE_DELAY_S = 0.6
    _probe_original_open = _ProbeStore.open
    _probe_original_health_socket = _ProbeRuntime._start_health_socket_if_enabled

    @pytest.fixture(autouse=True)
    def slow_startup_probe(monkeypatch: pytest.MonkeyPatch) -> None:
        async def _slow_open(self: Any, *args: Any, **kwargs: Any) -> Any:
            result = await _probe_original_open(self, *args, **kwargs)
            await asyncio.sleep(_PROBE_DELAY_S)
            return result

        async def _slow_late(self: Any, *args: Any, **kwargs: Any) -> Any:
            await asyncio.sleep(_PROBE_DELAY_S)
            return await _probe_original_health_socket(self, *args, **kwargs)

        monkeypatch.setattr(_ProbeStore, "open", _slow_open)
        monkeypatch.setattr(
            _ProbeRuntime, "_start_health_socket_if_enabled", _slow_late
        )
