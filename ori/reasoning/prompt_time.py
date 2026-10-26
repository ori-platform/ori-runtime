# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A prompt's `{time}`: a measurement time only where the producer reported one."""

import datetime
import logging
from typing import Any, Callable, Mapping

from ori.network.producer_time import (
    NOT_REPORTED,
    REPORTED,
    UNKNOWN,
    read_producer_time,
)

logger = logging.getLogger(__name__)


def prompt_time(
    reading: Any,
    liveness_bound: Callable[[Any], Any] | None = None,
) -> str:
    """The reading's time as a prompt may present it (gateway-api/v2 Producer Time).

    A reported time is shown as the measurement. A `not_reported` time is the
    reading's arrival and is named so, after the firmware liveness bound where
    this process holds one; a time of unstated basis is not shown.
    """
    basis = read_producer_time(getattr(reading, "producer_time", None))
    if basis == UNKNOWN:
        return "not stated"
    at = datetime.datetime.fromtimestamp(
        reading.timestamp / 1000, tz=datetime.UTC
    ).strftime("%Y-%m-%d %H:%M:%S UTC")
    if basis == REPORTED:
        return at
    stated = "not reported by device"
    if liveness_bound is not None:
        try:
            bound = liveness_bound(reading)
        except Exception:
            # A bound that cannot be computed is left out, never guessed.
            logger.exception("prompt_time: could not compute the liveness bound")
            bound = None
        if bound is not None:
            stated += f", runtime liveness bound {bound.text()}"
    return f"{stated}; arrived at the runtime at {at}"


def history_time(row: Mapping[str, Any]) -> dict[str, Any]:
    """A history row's time under the name its basis allows, or none if unstated."""
    basis = read_producer_time(row.get("producer_time"))
    if basis == REPORTED:
        return {"measured_at": row.get("timestamp")}
    if basis == NOT_REPORTED:
        return {"arrived_at": row.get("timestamp")}
    return {}


def history_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"value": row.get("value"), **history_time(row)}


def latest_time(rows: list[Any]) -> Any:
    """`history.last_timestamp()`: a measurement as before, an arrival named, else None."""
    if not rows:
        return None
    timed = history_time(rows[0])
    return timed.get("measured_at", timed or None)
