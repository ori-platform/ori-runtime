# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
import time


def now_ms() -> int:
    """Return current Unix time in milliseconds."""
    return int(time.time() * 1000)


def monotonic_ms() -> int:
    """Return a monotonic clock in milliseconds, for ages and deadlines only."""
    return int(time.monotonic() * 1000)
