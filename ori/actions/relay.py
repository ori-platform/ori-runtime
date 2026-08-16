# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Physical relay control via Raspberry Pi GPIO.

Used for Tier B (soft physical) and Tier D (safety-critical) actions.

.. warning::
    **Safety — read before enabling in production.**

    Relay wiring connects Ori directly to mains voltage or industrial
    control circuits.  Incorrect wiring can cause electric shock, fire,
    equipment damage, or death.  Before setting ``relay.enabled: true``
    in ori.yaml:

    - Wiring must be inspected and approved by a qualified electrician.
    - Verify the relay's rated switching capacity (voltage, current) is
      not exceeded by the connected load.
    - Confirm ``active_high`` matches the relay module's trigger logic
      (most opto-isolated relay boards are ``active_low``).
    - Wire to the Normally Closed (NC) terminal, not Normally Open
      (NO).  NC wiring means power loss or an Ori crash defaults the
      load to the safe state (disconnected) without software
      intervention.
    - Test with the load de-energised before connecting live circuits.
    - Never operate a relay above its rated duty cycle.

    Ori accepts no liability for damage caused by incorrect relay wiring.

Platform guard
--------------
``gpiozero`` is only available on Raspberry Pi. On non-Pi platforms
(developer laptops, CI), callers must explicitly opt into *simulation mode*:
all calls then succeed and are logged at DEBUG level without touching any
hardware. The runtime opts in only for development posture; relay connection is
fail-closed by default and in hardened posture.

Usage
-----
    relay = RelayAction()
    await relay.connect(gpio_pin=26, active_high=True)

    # Pulse for 2 seconds (Tier B: switch power source)
    await relay.trigger(duration_seconds=2.0)

    # Latch open (Tier D: emergency cutoff, held until manual reset)
    await relay.trigger()   # duration_seconds=None → latch on
    await relay.release()   # explicit release
"""

import asyncio
import logging
from typing import Protocol

logger = logging.getLogger(__name__)


class _RelayDevice(Protocol):
    """The gpiozero ``OutputDevice`` surface this module actually uses.

    gpiozero ships no stubs, but that is a reason to describe the three members
    touched here — not to type the handle as ``Any``. This is the boundary that
    energises a physical relay: an invalid call or a missed ``None`` check is
    exactly what should fail type checking rather than at a Tier D dispatch.
    """

    @property
    def value(self) -> float:
        """Current pin value; non-zero while the relay is energised."""

    def on(self) -> None:
        """Energise the pin."""

    def off(self) -> None:
        """De-energise the pin."""


# Valid BCM GPIO pin numbers on Raspberry Pi 4 (pins 0–1 are reserved for
# I2C ID EEPROM; 28–53 are not exposed on the 40-pin header).
_VALID_BCM_PINS: frozenset[int] = frozenset(range(2, 28))


def gpio_backend_importable() -> bool:
    """Return whether gpiozero exposes the required output classes.

    This proves dependency availability only. Real pin-factory initialization in
    :meth:`RelayAction.connect` is the hardware check and may still fail closed.
    """
    try:
        from gpiozero import (  # pyright: ignore[reportMissingImports]
            DigitalOutputDevice,
            OutputDevice,
        )
    except ImportError:
        return False
    return DigitalOutputDevice is not None and OutputDevice is not None


class RelayAction:
    """Controls a single relay output pin via gpiozero.

    One :class:`RelayAction` instance manages one physical relay.
    Instantiate one per relay defined in ori.yaml.

    GPIO initialisation is deferred to :meth:`connect` (rather than
    ``__init__``) so the object can be constructed at runtime startup
    before the event loop is running and before a pin number is known.
    """

    def __init__(self) -> None:
        self._pin: int | None = None
        self._active_high: bool = True
        # The gpiozero OutputDevice, or None in simulation mode.
        self._device: _RelayDevice | None = None
        self._simulated: bool = False
        self._connected: bool = False
        self._sim_state: bool = False  # logical active state used in simulation

    # ── Connection ────────────────────────────────────────────────────────────

    async def connect(
        self,
        gpio_pin: int,
        active_high: bool = True,
        *,
        allow_simulation: bool = False,
    ) -> None:
        """Initialise *gpio_pin* as a relay output.

        The gpiozero constructor is fast (microseconds) and does not need
        to be pushed to an executor.

        Args:
            gpio_pin: BCM GPIO pin number (e.g. ``26`` per CLAUDE.md).
            active_high: ``True`` if the relay activates on a HIGH signal
                (default).  Set ``False`` for opto-isolated relay boards
                that trigger on LOW — verify the relay datasheet.
            allow_simulation: Permit a no-op relay when gpiozero is unavailable.
                This is fail-closed by default; runtime startup opts in only for
                development posture.

        Note:
            When gpiozero is unavailable, simulation occurs only if
            ``allow_simulation`` is explicitly true. Otherwise connection
            raises and no hardware capability is reported.
        """
        if gpio_pin not in _VALID_BCM_PINS:
            raise ValueError(
                f"RelayAction: gpio_pin={gpio_pin} is outside valid BCM "
                f"range (2-27 on Pi 4). Check ori.yaml relay config. "
                f"Misconfigured pins must fail at startup, not during "
                f"a safety action."
            )

        self._pin = gpio_pin
        self._active_high = active_high

        try:
            from gpiozero import (  # pyright: ignore[reportMissingImports]
                OutputDevice,
            )

            # initial_value=False → relay starts de-energised
            self._device = OutputDevice(
                gpio_pin,
                active_high=active_high,
                initial_value=False,
            )
            self._simulated = False
            logger.info(
                "RelayAction: connected to GPIO pin %d (active_high=%s)",
                gpio_pin,
                active_high,
            )
        except ImportError as exc:
            if not allow_simulation:
                self._device = None
                self._simulated = False
                self._connected = False
                raise RuntimeError(
                    "RelayAction: gpiozero is required when relay control is "
                    "configured in staging or production posture."
                ) from exc
            self._device = None
            self._simulated = True
            logger.warning(
                "RelayAction: gpiozero not available — running in simulation "
                "mode on GPIO pin %d.  No hardware will be actuated.",
                gpio_pin,
            )

        self._connected = True

    # ── Control ───────────────────────────────────────────────────────────────

    async def trigger(self, duration_seconds: float | None = None) -> bool:
        """Activate the relay.

        Args:
            duration_seconds: Activate for this many seconds then release
                automatically.  Pass ``None`` to latch the relay on
                indefinitely until :meth:`release` is called explicitly.

        Returns:
            ``True`` on success, ``False`` if not connected or on error.
        """
        if not self._connected:
            logger.error(
                "RelayAction.trigger: called before connect() — pin not initialised."
            )
            return False

        try:
            if self._simulated:
                self._sim_state = True
                logger.debug(
                    "RelayAction.trigger [SIM]: GPIO pin %d activated (duration=%s)",
                    self._pin,
                    f"{duration_seconds}s"
                    if duration_seconds is not None
                    else "latched",
                )
                if duration_seconds is not None:
                    await asyncio.sleep(duration_seconds)
                    self._sim_state = False
                    logger.debug(
                        "RelayAction.trigger [SIM]: GPIO pin %d released after %.2fs",
                        self._pin,
                        duration_seconds,
                    )
                return True

            # Real GPIO
            self._require_device().on()
            logger.info(
                "RelayAction.trigger: GPIO pin %d activated (duration=%s)",
                self._pin,
                f"{duration_seconds}s" if duration_seconds is not None else "latched",
            )
            if duration_seconds is not None:
                await asyncio.sleep(duration_seconds)
                self._require_device().off()
                logger.info(
                    "RelayAction.trigger: GPIO pin %d released after %.2fs",
                    self._pin,
                    duration_seconds,
                )
            return True

        except Exception:
            # Log at exception level and return False.
            # IMPORTANT: Tier D escalation (CRITICAL log + emergency SMS) is
            # the caller's responsibility — ActionDispatcher._execute_immediately()
            # detects executed=False on SAFETY_CRITICAL tier and escalates.
            # relay.py is intentionally tier-agnostic. Never call relay actions
            # directly — always route through ActionDispatcher.
            logger.exception("RelayAction.trigger: error on GPIO pin %d", self._pin)
            return False

    async def release(self) -> bool:
        """Deactivate the relay (open the circuit).

        Returns:
            ``True`` on success, ``False`` if not connected or on error.
        """
        if not self._connected:
            logger.error(
                "RelayAction.release: called before connect() — pin not initialised."
            )
            return False

        try:
            if self._simulated:
                self._sim_state = False
                logger.debug(
                    "RelayAction.release [SIM]: GPIO pin %d deactivated", self._pin
                )
                return True

            self._require_device().off()
            logger.info("RelayAction.release: GPIO pin %d deactivated", self._pin)
            return True

        except Exception:
            # Log at exception level and return False.
            # IMPORTANT: Tier D escalation (CRITICAL log + emergency SMS) is
            # the caller's responsibility — ActionDispatcher._execute_immediately()
            # detects executed=False on SAFETY_CRITICAL tier and escalates.
            # relay.py is intentionally tier-agnostic. Never call relay actions
            # directly — always route through ActionDispatcher.
            logger.exception("RelayAction.release: error on GPIO pin %d", self._pin)
            return False

    def _require_device(self) -> _RelayDevice:
        """Return the GPIO handle, or fail loudly.

        Unreachable by construction: ``connect()`` sets a device unless it fell
        back to simulation, and every caller checks ``_simulated`` first. It
        raises rather than returning None so a broken invariant surfaces as a
        failed action instead of a silently skipped one — ``trigger()`` and
        ``release()`` catch it and return ``False``, which is what they already
        did when this state produced an ``AttributeError``.
        """
        device = self._device
        if device is None:
            raise RuntimeError(
                "RelayAction: GPIO device is unavailable outside simulation mode"
            )
        return device

    # ── State ─────────────────────────────────────────────────────────────────

    @property
    def is_active(self) -> bool:
        """``True`` if the relay is currently energised.

        In simulation mode tracks the logical state set by :meth:`trigger`
        and :meth:`release`.  On real hardware reads the live pin value
        from gpiozero.
        """
        if not self._connected:
            return False
        if self._simulated:
            return self._sim_state
        return bool(self._require_device().value)
