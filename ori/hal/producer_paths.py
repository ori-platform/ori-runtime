# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The basis of each ingest path's `timestamp`, decided where a reading enters.

gateway-api/v2 (Producer Time) leaves the table to the runtime: it is keyed by
the path a reading arrives by and the member `timestamp` is taken from, and it
is closed, so a path missing from it raises instead of defaulting. Only ingest
reads it; nothing past a reading's construction decides on its path.
"""

from types import MappingProxyType
from typing import Mapping

from ori.network.producer_time import NOT_REPORTED, REPORTED, UNKNOWN

#: The runtime's clock at a read it requested itself, which dates that read.
READ_CLOCK = "read_clock"
#: The runtime's clock when a pushed value reached it.
ARRIVAL_CLOCK = "arrival_clock"
#: A time the caller supplied, whose basis the runtime cannot state.
CALLER_TIME = "caller_time"

PRODUCER_PATHS: Mapping[tuple[str, str], str] = MappingProxyType(
    {
        # Requests the runtime makes at the time of the read.
        ("i2c", READ_CLOCK): REPORTED,
        ("serial", READ_CLOCK): REPORTED,
        ("usb_serial", READ_CLOCK): REPORTED,
        ("solarman_modbus", READ_CLOCK): REPORTED,
        ("psutil", READ_CLOCK): REPORTED,
        ("smart", READ_CLOCK): REPORTED,
        ("opcua", READ_CLOCK): REPORTED,
        ("growatt", READ_CLOCK): REPORTED,
        # Polled, then served from a cache that keeps each poll's time and basis.
        ("http", READ_CLOCK): REPORTED,
        ("coap", READ_CLOCK): REPORTED,
        # Pushed values, read later from a subscription cache. A time in the
        # payload is an intermediary's, such as a LoRaWAN network server's or a
        # Zigbee coordinator's, or one no protocol declares a measurement, so
        # it is carried in metadata and never taken.
        ("mqtt", ARRIVAL_CLOCK): NOT_REPORTED,
        ("victron", ARRIVAL_CLOCK): NOT_REPORTED,
        ("lorawan", ARRIVAL_CLOCK): NOT_REPORTED,
        ("zigbee", ARRIVAL_CLOCK): NOT_REPORTED,
        ("mqtt_perception", ARRIVAL_CLOCK): NOT_REPORTED,
        # firmware-telemetry/v2: `emitted_at_ms` is advisory, never taken.
        ("firmware", ARRIVAL_CLOCK): NOT_REPORTED,
        ("rule_evaluation", CALLER_TIME): UNKNOWN,
    }
)


def producer_time_for(path: str, member: str) -> str:
    """The basis of a reading from *path* whose `timestamp` came from *member*."""
    try:
        return PRODUCER_PATHS[(path, member)]
    except KeyError:
        raise KeyError(
            f"no producer-time entry for path={path!r} member={member!r}; "
            "add one to PRODUCER_PATHS"
        ) from None
