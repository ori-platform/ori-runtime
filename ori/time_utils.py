# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
import time


def now_ms() -> int:
    """Return current Unix time in milliseconds."""
    return int(time.time() * 1000)
