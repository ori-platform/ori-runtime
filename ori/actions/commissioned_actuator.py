# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The commissioned actuation seam: outcomes in, coil states out, levels last.

A safety action names a physical outcome — `open_protected_circuit` or
`close_protected_circuit`. The zone's commissioned mapping resolves it to a coil
state, and the zone's `active_high` resolves the coil state to a level on the
pin. Nothing here derives one from another, and nothing here actuates without
an accepted zone: absence of a mapping is a refusal, never an assumption.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal, Protocol

from ori.security.commissioning.binding import AcceptedZone

logger = logging.getLogger(__name__)

Outcome = Literal["open_protected_circuit", "close_protected_circuit"]
CoilState = Literal["energised", "de_energised"]

OUTCOMES: frozenset[str] = frozenset(
    {"open_protected_circuit", "close_protected_circuit"}
)


class CoilDriver(Protocol):
    """What the seam needs from a relay: energise, de-energise, and say which."""

    async def connect(
        self,
        gpio_pin: int,
        active_high: bool = True,
        *,
        tolerate_missing_backend: bool = False,
        initial_coil_state: str = "de_energised",
    ) -> None:
        """Take the line as an output, at the given coil state."""
        raise NotImplementedError

    async def trigger(self, duration_seconds: float | None = None) -> bool:
        """Energise the coil; True when the driver did."""
        raise NotImplementedError

    async def release(self) -> bool:
        """De-energise the coil; True when the driver did."""
        raise NotImplementedError

    @property
    def is_simulated(self) -> bool:
        """True when no hardware line was taken, so nothing was commanded."""
        raise NotImplementedError

    @property
    def is_active(self) -> bool:
        """Whether the coil is energised, as the driver reads it."""
        raise NotImplementedError


@dataclass(frozen=True)
class Actuation:
    """What one command did, for the log and the health surface."""

    outcome: str
    coil_state: str
    level: str
    binding_seq: int
    executed: bool


class CommissionedActuator:
    """One local-GPIO actuator, driven only through its accepted zone."""

    def __init__(
        self, *, driver: CoilDriver, zone: AcceptedZone, binding_seq: int
    ) -> None:
        if zone.kind != "local_gpio":
            raise ValueError(f"zone {zone.zone_id!r} is not a local GPIO actuator")
        self._driver = driver
        self._zone = zone
        self._binding_seq = binding_seq
        self._last: Actuation | None = None

    @property
    def zone(self) -> AcceptedZone:
        return self._zone

    @property
    def binding_seq(self) -> int:
        return self._binding_seq

    @property
    def active_high(self) -> bool:
        return bool(self._zone.identity["active_high"])

    @property
    def last(self) -> Actuation | None:
        return self._last

    def coil_state_for(self, outcome: str) -> CoilState:
        """The commissioned coil state for an outcome; refuses anything else."""
        if outcome not in OUTCOMES:
            raise ValueError(f"{outcome!r} is not a protected-circuit outcome")
        state = self._zone.mapping[outcome]
        if state not in ("energised", "de_energised"):
            raise ValueError(f"zone {self._zone.zone_id!r} maps {outcome} to {state!r}")
        return state  # type: ignore[return-value]

    def level_for(self, coil_state: str) -> str:
        """The pin level that puts the coil in *coil_state* on this driver stage."""
        energised = coil_state == "energised"
        return "high" if energised == self.active_high else "low"

    async def command_coil(self, coil_state: str, *, reason: str) -> bool:
        """Put the coil in a state directly. Startup uses this: it commands
        `de_energised` rather than assuming the platform default is it."""
        if coil_state == "energised":
            executed = await self._driver.trigger(duration_seconds=None)
        elif coil_state == "de_energised":
            executed = await self._driver.release()
        else:
            raise ValueError(f"{coil_state!r} is not a coil state")
        self._last = Actuation(
            outcome=reason,
            coil_state=coil_state,
            level=self.level_for(coil_state),
            binding_seq=self._binding_seq,
            executed=executed,
        )
        logger.info(
            "[actuator] %s: coil %s (pin %s) under binding %d%s",
            reason,
            coil_state,
            self.level_for(coil_state),
            self._binding_seq,
            "" if executed else " — driver reported failure",
        )
        return executed

    async def command(self, outcome: str) -> bool:
        """Execute a protected-circuit outcome through the commissioned mapping."""
        coil_state = self.coil_state_for(outcome)
        return await self.command_coil(coil_state, reason=outcome)

    async def acquire_commanding(self, outcome: str) -> bool:
        """Take the pin *at* an outcome's coil state, as the single command.

        Taking a line as an output drives it, so a path that connects and then
        commands issues two physical acts for one authorisation: de-energise,
        then the outcome. Where the acquisition is the act being authorised --
        the commissioning proof, which holds one consent for one command -- the
        coil state belongs in the acquisition itself.

        The caller must not follow this with `command`, `command_coil`,
        `trigger` or `release`: the line is already at the commanded state.
        Ordinary runtime startup keeps its explicit `command_coil` path, which
        is a different guarantee -- it commands `de_energised` rather than
        assuming the platform default is it.
        """
        coil_state = self.coil_state_for(outcome)
        await self._driver.connect(
            gpio_pin=int(self._zone.identity["gpio_pin"]),
            active_high=self.active_high,
            initial_coil_state=coil_state,
        )
        # A driver that took no real line commanded nothing, whatever the
        # connect returned. Reported, never assumed.
        executed = not self._driver.is_simulated
        self._last = Actuation(
            outcome=outcome,
            coil_state=coil_state,
            level=self.level_for(coil_state),
            binding_seq=self._binding_seq,
            executed=executed,
        )
        logger.info(
            "[actuator] %s: line taken at coil %s (pin %s) under binding %d%s",
            outcome,
            coil_state,
            self.level_for(coil_state),
            self._binding_seq,
            "" if executed else " — no hardware line was taken",
        )
        return executed

    @property
    def coil_energised(self) -> bool:
        return self._driver.is_active

    def health(self) -> dict[str, object]:
        last = self._last
        return {
            "zone_id": self._zone.zone_id,
            "gpio_pin": self._zone.identity["gpio_pin"],
            "active_high": self.active_high,
            "binding_seq": self._binding_seq,
            "coil": "energised" if self.coil_energised else "de_energised",
            "last_command": (
                {
                    "outcome": last.outcome,
                    "coil_state": last.coil_state,
                    "level": last.level,
                    "executed": last.executed,
                }
                if last
                else None
            ),
        }
