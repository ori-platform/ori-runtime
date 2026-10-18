# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""One warning line per reason per interval, for refusals a sender can repeat.

A receiver that logs every refused message lets anyone who can reach its topic
write the log at the topic's ingress rate, and push earlier lines out of a
rotating file. Each reason is written at once the first time, then at most
once an interval, carrying how many were refused since the last line.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

#: How often one reason may write a line.
DEFAULT_INTERVAL_S = 60.0


class CoalescedWarning:
    """Thread-safe: paho callbacks and the event loop both report through it."""

    def __init__(
        self,
        logger: logging.Logger,
        *,
        interval_s: float = DEFAULT_INTERVAL_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._logger = logger
        self._interval_s = interval_s
        self._clock = clock
        self._lock = threading.Lock()
        self._logged_at: dict[str, float] = {}
        self._unlogged: dict[str, int] = {}

    def warn(self, reason: str, message: str, *args: object) -> None:
        """Count one *reason*; write *message* now if this interval allows.

        The line ends with the count since the last one for that reason, this
        refusal included. Refusals after the last line are carried into the
        next.
        """
        with self._lock:
            count = self._unlogged.get(reason, 0) + 1
            now = self._clock()
            if now - self._logged_at.get(reason, float("-inf")) < self._interval_s:
                self._unlogged[reason] = count
                return
            self._logged_at[reason] = now
            self._unlogged[reason] = 0
        self._logger.warning(message + " (%d since the last report)", *args, count)
