# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""What a reading's `timestamp` is: the gateway-api/v2 Producer Time vocabulary.

Which path is which basis is ingest's table, in ori.hal.producer_paths.
"""

from typing import Any

REPORTED = "reported"
NOT_REPORTED = "not_reported"
UNKNOWN = "unknown"

#: In the order a bucket holding several bases exports its rows.
PRODUCER_TIMES: tuple[str, ...] = (REPORTED, NOT_REPORTED, UNKNOWN)


def read_producer_time(value: Any) -> str:
    """A stored or carried marker, read as unknown when absent or not one of the three."""
    return value if isinstance(value, str) and value in PRODUCER_TIMES else UNKNOWN
