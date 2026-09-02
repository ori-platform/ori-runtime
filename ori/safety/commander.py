# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The registry's actuation seam over the commissioned actuator.

A zone whose line acquisition is deferred — a closed-terminal zone with an
active profile, where the acquisition itself drives the coil — is not
touched until the registry's first command, and that command is the
acquisition, at the licensed coil state, as one physical act. A command for
an unbound zone reports driver refusal rather than raising, so a trip on a
zone whose hardware never initialised latches loudly instead of crashing
the reading path.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class ActuatorOutcomeCommander:
    """OutcomeCommander over CommissionedActuator instances, per zone."""

    def __init__(self) -> None:
        self._actuators: dict[str, Any] = {}
        self._deferred: set[str] = set()

    def bind(
        self, zone_id: str, actuator: Any, *, defer_acquisition: bool = False
    ) -> None:
        self._actuators[zone_id] = actuator
        if defer_acquisition:
            self._deferred.add(zone_id)

    @property
    def bound_zones(self) -> frozenset[str]:
        return frozenset(self._actuators)

    async def command_outcome(self, zone_id: str, outcome: str) -> bool:
        actuator = self._actuators.get(zone_id)
        if actuator is None:
            logger.error(
                "[safety] outcome %s refused: zone %s has no bound actuator",
                outcome,
                zone_id,
            )
            return False
        if zone_id in self._deferred:
            # Deferred state clears only on a successful acquisition: a
            # failed or raising acquire leaves the line untaken, and the
            # next attempt must acquire again, never command an unheld line.
            accepted = bool(await actuator.acquire_commanding(outcome))
            if accepted:
                self._deferred.discard(zone_id)
            return accepted
        return bool(await actuator.command(outcome))

    async def command_startup_de_energised(self, zone_id: str) -> bool:
        actuator = self._actuators.get(zone_id)
        if actuator is None:
            logger.error(
                "[safety] startup de_energised refused: zone %s has no bound actuator",
                zone_id,
            )
            return False
        if zone_id in self._deferred:
            accepted = bool(
                await actuator.acquire_coil("de_energised", reason="safety_startup")
            )
            if accepted:
                self._deferred.discard(zone_id)
            return accepted
        return bool(
            await actuator.command_coil("de_energised", reason="safety_startup")
        )
