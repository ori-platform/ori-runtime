# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for ori/actions/relay.py.

gpiozero is not available on developer machines or CI.  All tests run
in simulation mode — the skip_if_no_pi fixture gates any future tests
that require real hardware.
"""

import sys
import types

import pytest

from ori.actions import relay as relay_module
from ori.actions.relay import RelayAction

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def skip_if_no_pi():
    """Skip the test if gpiozero is not importable (non-Pi platform)."""
    try:
        import gpiozero  # type: ignore[import-untyped]  # noqa: F401
    except ImportError:
        pytest.skip("gpiozero not available — Pi hardware required")


@pytest.fixture
async def relay() -> RelayAction:
    """A RelayAction already connected in simulation mode."""
    r = RelayAction()
    await r.connect(gpio_pin=26, tolerate_missing_backend=True)
    return r


# ── connect() ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_connect_sets_connected():
    r = RelayAction()
    assert not r._connected
    await r.connect(gpio_pin=26, tolerate_missing_backend=True)
    assert r._connected


@pytest.mark.asyncio
async def test_connect_enters_simulation_mode_without_gpiozero(monkeypatch):
    """Remove gpiozero from sys.modules to force simulation mode."""
    monkeypatch.setitem(sys.modules, "gpiozero", None)
    r = RelayAction()
    await r.connect(gpio_pin=26, tolerate_missing_backend=True)
    assert r._simulated is True
    assert r._device is None


@pytest.mark.asyncio
async def test_connect_is_fail_closed_by_default(monkeypatch):
    monkeypatch.setitem(sys.modules, "gpiozero", None)
    relay = RelayAction()

    with pytest.raises(RuntimeError, match="gpiozero is required"):
        await relay.connect(gpio_pin=26)

    assert relay._connected is False
    assert relay._simulated is False
    assert relay._device is None


@pytest.mark.asyncio
async def test_connect_stores_pin_and_active_high():
    r = RelayAction()
    await r.connect(gpio_pin=17, active_high=False, tolerate_missing_backend=True)
    assert r._pin == 17
    assert r._active_high is False


# ── is_active initial state ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_is_active_false_before_connect():
    r = RelayAction()
    assert r.is_active is False


@pytest.mark.asyncio
async def test_is_active_false_after_connect(relay):
    assert relay.is_active is False


# ── trigger() ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_returns_true(relay):
    ok = await relay.trigger()
    assert ok is True


@pytest.mark.asyncio
async def test_trigger_activates_relay(relay):
    await relay.trigger()
    assert relay.is_active is True


@pytest.mark.asyncio
async def test_trigger_with_duration_releases_relay(relay):
    ok = await relay.trigger(duration_seconds=0.0)
    assert ok is True
    assert relay.is_active is False


@pytest.mark.asyncio
async def test_trigger_latch_stays_active(relay):
    """duration_seconds=None latches the relay — is_active remains True."""
    await relay.trigger(duration_seconds=None)
    assert relay.is_active is True


@pytest.mark.asyncio
async def test_trigger_returns_false_before_connect():
    r = RelayAction()
    ok = await r.trigger()
    assert ok is False


# ── release() ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_release_returns_true(relay):
    await relay.trigger()
    ok = await relay.release()
    assert ok is True


@pytest.mark.asyncio
async def test_release_deactivates_relay(relay):
    await relay.trigger()
    assert relay.is_active is True
    await relay.release()
    assert relay.is_active is False


@pytest.mark.asyncio
async def test_release_returns_false_before_connect():
    r = RelayAction()
    ok = await r.release()
    assert ok is False


@pytest.mark.asyncio
async def test_release_idempotent(relay):
    """Releasing an already-inactive relay must succeed."""
    assert relay.is_active is False
    ok = await relay.release()
    assert ok is True
    assert relay.is_active is False


# ── trigger / release cycle ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_multiple_trigger_release_cycles(relay):
    for _ in range(3):
        await relay.trigger()
        assert relay.is_active is True
        await relay.release()
        assert relay.is_active is False


# ── skip_if_no_pi guard ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_real_gpio_skipped_without_pi(skip_if_no_pi):
    """This test body only runs on a real Pi with gpiozero installed."""
    r = RelayAction()
    await r.connect(gpio_pin=26)
    assert r._simulated is False  # would fail in sim mode — skip guards it


# ── Pin validation ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_connect_rejects_invalid_pin():
    """GPIO pin 45 is outside the BCM 2-27 range — must raise ValueError."""
    r = RelayAction()
    with pytest.raises(ValueError, match="BCM range"):
        await r.connect(gpio_pin=45)


@pytest.mark.asyncio
async def test_connect_rejects_pin_zero():
    """GPIO pin 0 is reserved for I2C ID EEPROM — not valid for relay use."""
    r = RelayAction()
    with pytest.raises(ValueError, match="BCM range"):
        await r.connect(gpio_pin=0)


class TestResolvedPinFactory:
    """What gpiozero loaded, as distinct from what imported.

    gpiozero never raises for a missing backend. It warns and falls back to
    NativeFactory, which drives /dev/gpiomem directly and registers no claim
    with the kernel. Measured on a Pi 4: a line held by the arbitrated factory
    reports `consumer="lg"`, while the same line held by the fallback still
    reads as an unused input. Nothing refuses a second writer.
    """

    def test_no_gpiozero_resolves_to_nothing(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def refuse_gpiozero(name, *args, **kwargs):
            if name == "gpiozero":
                raise ImportError("no gpiozero here")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", refuse_gpiozero)

        assert relay_module.resolved_pin_factory_name() == ""
        assert relay_module.gpio_backend_arbitrated() is False

    def test_a_factory_that_cannot_open_the_chip_resolves_to_nothing(self, monkeypatch):
        """A raise means the same thing as a fallback to the caller: no backend.

        gpiozero raises BadPinFactory when an explicitly requested factory is
        unavailable, and chip-open errors surface here too.
        """
        module = types.ModuleType("gpiozero")

        class _Device:
            pin_factory = None

            @staticmethod
            def ensure_pin_factory():
                raise RuntimeError("could not open /dev/gpiochip0")

        module.Device = _Device  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "gpiozero", module)

        assert relay_module.resolved_pin_factory_name() == ""
        assert relay_module.gpio_backend_arbitrated() is False

    @pytest.mark.parametrize(
        "factory_name, arbitrated",
        [
            ("LGPIOFactory", True),
            ("RPiGPIOFactory", True),
            ("PiGPIOFactory", True),
            ("NativeFactory", False),
        ],
    )
    def test_only_the_unarbitrated_fallback_is_refused(
        self, monkeypatch, factory_name, arbitrated
    ):
        module = types.ModuleType("gpiozero")
        factory = type(factory_name, (), {})()

        class _Device:
            pin_factory = factory

            @staticmethod
            def ensure_pin_factory():
                return None

        module.Device = _Device  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "gpiozero", module)

        assert relay_module.resolved_pin_factory_name() == factory_name
        assert relay_module.gpio_backend_arbitrated() is arbitrated
