# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A sensor not connected at start: who is told, and when it counts as connected.

Every function takes the runtime's state as arguments and holds none of its
own. A sensor whose adapter could not connect is skipped, unless its source was
unreachable (`AdapterUnavailableError`): that one is connected again in the
background, under back-off, with a fresh adapter each attempt. One whose adapter
connected but is still retrying its source (`BaseAdapter.connection_retrying`)
is polled. Either way the sensor stays unconnected until its first accepted
reading.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable
from typing import Protocol

logger = logging.getLogger(__name__)

#: Sends a mandatory Tier A notice (message, trigger name) and returns whether
#: it was delivered or durably queued.
SendNotice = Callable[[str, str], Awaitable[bool]]

UNCONNECTED_TRIGGER = "sensor_unconnected_warning"
CONNECTED_TRIGGER = "sensor_connected_notice"


class UnavailabilityRegistry(Protocol):
    async def note_sensor_unavailable(self, sensor_id: str, reason: str) -> bool:
        """Record *sensor_id* unavailable; whether an affected pair was told."""
        raise NotImplementedError


async def note_unconnected_sensor(
    sensor_id: str,
    *,
    retrying: bool,
    unconnected: set[str],
    announced: set[str],
    registry: UnavailabilityRegistry | None,
    send: SendNotice | None,
) -> None:
    """Record a sensor not connected at start, and tell a pair or the operator.

    A retrying sensor whose start notice reached anyone is added to
    *announced*, so its first reading is announced too.
    """
    unconnected.add(sensor_id)
    if retrying:
        logger.warning(
            "[runtime] sensor_id=%s not reached at start; retrying in the background",
            sensor_id,
        )
    # The registry must not wait out its loss bound for a fact the runtime
    # already holds. Until a pair is told, it is an active pair with no record
    # that its measurement is unavailable.
    told = False
    if registry is not None:
        told = await registry.note_sensor_unavailable(
            sensor_id,
            "could not be connected; retrying"
            if retrying
            else "could not be connected",
        )
    if not told:
        # A pair notice already names the sensor, its zone and its profile, so
        # sending this as well would be two messages for one event. Decided on
        # whether a pair was actually told, not on whether a registry exists:
        # candidate, pending and refused profiles produce no pair notice.
        told = await _warn_unconnected(sensor_id, retrying=retrying, send=send)
    if told and retrying:
        announced.add(sensor_id)


async def _warn_unconnected(
    sensor_id: str, *, retrying: bool, send: SendNotice | None
) -> bool:
    """A configured sensor that never connected, as a Tier A notice.

    Health already reports it unconnected, and on a headless device nothing
    carries a log line to an operator. It never aborts startup: a runtime that
    refuses to run has removed the agent. Sent on the structural path, so an
    entitlement cap cannot leave an operator believing a measurement is being
    taken that is not.
    """
    if send is None:
        logger.warning(
            "[runtime] unconnected sensor warning not sent for %s: "
            "no alert sender is configured",
            sensor_id,
        )
        return False
    if retrying:
        message = (
            f"Sensor {sensor_id} could not be connected at startup. The "
            "connection is being retried and the sensor is not read until it "
            "answers. The rest of the runtime is running."
        )
    else:
        message = (
            f"Sensor {sensor_id} could not be connected at startup and is not "
            "being read. The rest of the runtime is running."
        )
    return await send(message, UNCONNECTED_TRIGGER)


def connected_late(
    sensor_id: str, *, unconnected: set[str], connected: set[str]
) -> bool:
    """Move a sensor unconnected at start to connected on an accepted reading.

    Returns whether it moved, which happens once per sensor.
    """
    if sensor_id not in unconnected:
        return False
    unconnected.discard(sensor_id)
    connected.add(sensor_id)
    logger.info(
        "[runtime] sensor_id=%s connected after start: first reading accepted",
        sensor_id,
    )
    return True


async def announce_late_connection(
    sensor_id: str, *, announced: set[str], send: SendNotice | None
) -> None:
    """Tell the operator a sensor is now read, only if its start notice was sent."""
    if sensor_id not in announced:
        return
    announced.discard(sensor_id)
    if send is None:
        return
    try:
        await send(
            f"Sensor {sensor_id} connected after startup and is now being read.",
            CONNECTED_TRIGGER,
        )
    except Exception:
        logger.exception("[runtime] sensor connected notice failed for %s", sensor_id)


class Closeable(Protocol):
    async def close(self) -> None:
        """Release what the adapter holds."""
        raise NotImplementedError


async def close_adapters(adapters: Iterable[Closeable]) -> None:
    """Close every adapter concurrently; one that fails never stops another.

    An MQTT-family close can wait for a connect thread, and sensors usually
    share one broker, so closing in turn would add those waits together.
    """

    async def close(adapter: Closeable) -> None:
        try:
            await adapter.close()
        except Exception:
            logger.exception("[shutdown] error closing adapter")

    await asyncio.gather(*(close(adapter) for adapter in adapters))
