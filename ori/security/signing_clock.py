# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The runtime's signing clock for runtime-gateway HMAC envelopes.

gateway-api/v2 Senders: every envelope is fresh, so `signed_at_ms` never
repeats, across a restart too. A clock issues values only from ranges it has
claimed in the state store: one transaction reads the stored mark, raises it a
reservation ahead and claims everything between, so no value is issued twice,
by this clock, another one on the same store, or a later process.

One writer thread owns the store connection. It keeps the mark a reservation
ahead of the wall clock, claiming again whenever less than half of one is
left, so a signer idle for any length of time still finds a claimed value; it
has at most one claim outstanding, and the mark only ever rises. When the
claimed values run out, because the store stalls or fails, signing is refused
rather than issuing a value no stored mark covers, and never waits for the
store.

The reservation is a tenth of the clock skew, between one and thirty seconds
and never more than half the skew.
No signing time is issued more than a reservation ahead of the wall clock as
it reads at that moment, so every one passes a receiver under the same skew,
the reservation being at most half of it. Restarts faster than the clock
moves, or a clock stepped back, live or across a start, leave the claimed or
issued values further ahead; signing is then refused, never blocked, until the
wall clock catches up, as Senders requires. While nothing signs, the
store sees one claim per reservation, about every thirty seconds at the
default skew; a store that fails is retried once a second.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Callable

from ori.utils.coalesced_log import CoalescedWarning
from ori.utils.path_utils import shown
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

#: The reservation without a skew to size it from.
RESERVATION_MS = 1_000
_MIN_RESERVATION_MS = 1_000
_MAX_RESERVATION_MS = 30_000
#: Claim again once less than this is left ahead of the latest value issued
#: or the wall clock; a claim always reaches twice this past the latest value.
_LOW_WATER_MS = 500
#: How long the writer waits before retrying a store that failed.
_RETRY_S = 1.0
#: The largest mark a 64-bit integer column holds, less the largest reservation.
MARK_CEILING = 2**63 - 1 - _MAX_RESERVATION_MS


#: SQLite's private in-memory database: one connection's memory, gone at the
#: next start, so never a durable store.
IN_MEMORY_STORE = ":memory:"


def durable_store(db_path: str | None) -> bool:
    """Whether *db_path* names a store that outlives the process."""
    path = str(db_path or "").strip()
    return bool(path) and path != IN_MEMORY_STORE


def reservation_for_skew(max_skew_ms: int) -> int:
    """A tenth of *max_skew_ms*, kept between one and thirty seconds, and
    never more than half of it, so a signing time a reservation ahead of the
    wall clock always passes a receiver under the same skew."""
    skew = max(0, int(max_skew_ms))
    floor = min(_MIN_RESERVATION_MS, skew // 2)
    return max(min(max(skew // 10, floor), _MAX_RESERVATION_MS), 1)


class SigningClockUnavailableError(RuntimeError):
    """No claimed value is left for the next signing time; nothing is signed."""


class SigningClock:
    """Issue signing times that never repeat, durably when *db_path* is set.

    Without *db_path* the clock never repeats within the process and keeps
    nothing across a restart; that is for tests and tools, never the runtime.
    """

    def __init__(
        self,
        db_path: str | None = None,
        *,
        clock: Callable[[], int] = now_ms,
        reservation_ms: int = RESERVATION_MS,
    ) -> None:
        self._clock = clock
        self._reservation_ms = max(2, int(reservation_ms))
        self._low_water_ms = min(_LOW_WATER_MS, self._reservation_ms // 2)
        self._lock = threading.Lock()
        self._wake = threading.Condition(self._lock)
        self._last: int | None = None
        # Claimed, inclusive, ascending, none overlapping.
        self._ranges: deque[tuple[int, int]] = deque()
        self._stopped = False
        self._refusing = False
        self._warning = CoalescedWarning(logger)
        self._conn: sqlite3.Connection | None = None
        self._thread: threading.Thread | None = None
        self._path = str(db_path or "").strip()
        self._durable = durable_store(self._path)
        if not self._durable:
            return
        # The store is opened and claimed from on the writer thread only, so
        # a store that is locked or hangs delays no start; nothing is issued
        # until the first claim commits.
        self._thread = threading.Thread(
            target=self._serve, name="ori-signing-clock", daemon=True
        )
        self._thread.start()

    @property
    def durable(self) -> bool:
        return self._durable

    def refusing(self) -> bool:
        """Whether signing is refused now: nothing claimed is left."""
        with self._lock:
            return self._refusing

    def issue(self) -> int:
        """The next signing time; raises `SigningClockUnavailableError`."""
        with self._lock:
            wall = self._clock()
            value = wall if self._last is None else max(wall, self._last + 1)
            if not self._durable:
                self._last = value
                return value
            ranges = self._ranges
            while ranges and value > ranges[0][1]:
                ranges.popleft()
            if not ranges:
                self._refusing = True
                self._wake.notify_all()
                self._warning.warn(
                    "unclaimed",
                    "[gateway-auth] signing refused: no claimed signing time "
                    "is left at %d; waiting on the state store",
                    value,
                )
                raise SigningClockUnavailableError("signing_clock_unavailable")
            value = max(value, ranges[0][0])
            if value > wall + self._reservation_ms:
                # A clock stepped back, live or across a start, under values
                # already claimed or issued: never more than a reservation
                # ahead of it, whatever is claimed.
                self._refusing = True
                self._warning.warn(
                    "ahead",
                    "[gateway-auth] signing refused: the next signing time %d "
                    "is more than a reservation ahead of the wall clock %d",
                    value,
                    wall,
                )
                raise SigningClockUnavailableError("signing_clock_ahead")
            self._last = value
            self._refusing = False
            if self._wanted_mark() is not None:
                self._wake.notify_all()
            return value

    def stop(self, timeout_s: float = 2.0) -> None:
        """Stop the writer. A claim that hangs is left to the daemon thread."""
        with self._lock:
            self._stopped = True
            self._wake.notify_all()
        thread = self._thread
        if thread is not None:
            thread.join(timeout_s)

    def _wanted_mark(self) -> int | None:
        """The mark to claim to once less than the low water is left ahead
        of the wall clock and the latest value issued; else None.

        Reckoned from the wall clock, reaching a short step past the latest
        value only when that is later: a value issued ahead of the wall clock
        never carries a whole reservation further, so restarts in quick
        succession add no lead.
        """
        wall = self._clock()
        last = self._last
        claimed_to = self._ranges[-1][1] if self._ranges else None
        ahead = wall if last is None or last < wall else last
        if claimed_to is not None and claimed_to - ahead >= self._low_water_ms:
            return None
        mark = wall + self._reservation_ms
        if last is not None:
            mark = max(mark, last + 2 * self._low_water_ms)
        return min(mark, MARK_CEILING)

    def _until_low_water_s(self) -> float:
        """How long the writer may sleep before the low water is reached."""
        with self._lock:
            wall = self._clock()
            last = self._last
            claimed_to = self._ranges[-1][1] if self._ranges else wall
            ahead = wall if last is None or last < wall else last
            left_ms = claimed_to - ahead - self._low_water_ms
        return max(left_ms / 1_000, 0.05)

    def _serve(self) -> None:
        try:
            while True:
                with self._lock:
                    if self._stopped:
                        return
                    wanted = self._wanted_mark() if self._conn is not None else None
                if self._conn is None:
                    self._conn = self._open()
                    if self._conn is None:
                        self._pause(_RETRY_S, interruptible=False)
                    continue
                if wanted is None:
                    # Woken by an issue, or in time to claim before the low
                    # water while nothing signs.
                    self._pause(self._until_low_water_s())
                    continue
                claimed = self._claim(wanted)
                if claimed is None:
                    # A store that fails is retried at this pace, however
                    # often signers ask meanwhile.
                    self._pause(_RETRY_S, interruptible=False)
                    continue
                with self._lock:
                    # Above everything claimed before: each claim starts one
                    # past the stored mark, which every earlier claim raised.
                    self._ranges.append(claimed)
        finally:
            conn, self._conn = self._conn, None
            if conn is not None:
                conn.close()

    def _pause(self, seconds: float, *, interruptible: bool = True) -> None:
        """Sleep, woken early by an issue only when *interruptible*; a stop
        always wakes it."""
        with self._lock:
            if interruptible:
                if not self._stopped:
                    self._wake.wait(seconds)
                return
            deadline = time.monotonic() + seconds
            while not self._stopped:
                left = deadline - time.monotonic()
                if left <= 0:
                    return
                self._wake.wait(left)

    def _open(self) -> sqlite3.Connection | None:
        try:
            conn = sqlite3.connect(self._path, isolation_level=None)
            conn.execute("PRAGMA busy_timeout = 5000")
            # A claim counts once its commit returns, so it must be on disk.
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS gateway_signing_clock ("
                "id INTEGER PRIMARY KEY CHECK (id = 1), mark_ms INTEGER NOT NULL)"
            )
        except sqlite3.Error:
            self._warning.warn(
                "open_failed",
                "[gateway-auth] signing clock store at %s cannot be opened; "
                "runtime-gateway envelopes are not signed until it opens",
                shown(self._path),
            )
            return None
        return conn

    def _claim(self, wanted: int) -> tuple[int, int] | None:
        """Raise the stored mark to at least *wanted*; the range claimed."""
        conn = self._conn
        if conn is None:
            return None
        try:
            conn.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                row = conn.execute(
                    "SELECT mark_ms FROM gateway_signing_clock WHERE id = 1"
                ).fetchone()
                if row is not None and type(row[0]) is not int:
                    raise ValueError("stored signing mark is not an integer")
                low = wanted - self._reservation_ms if row is None else row[0] + 1
                wall = self._clock()
                # A claim delayed by a stalled store still reaches a
                # reservation past the clock it lands at.
                wanted = max(wanted, min(wall + self._reservation_ms, MARK_CEILING))
                if low > wall + self._reservation_ms:
                    # Restarts faster than the wall clock moves, or a clock
                    # stepped back: values from here would run further ahead
                    # than a reservation. Refused until the clock catches up,
                    # which no receiver under the same skew would admit sooner.
                    raise ValueError(
                        "stored signing mark is more than a reservation ahead "
                        "of the wall clock"
                    )
                # At least twice the low water past the stored mark, so a
                # mark left ahead of the wall clock still yields values; less
                # than any restart takes, so restarts add no lead.
                high = min(max(wanted, low + 2 * self._low_water_ms - 1), MARK_CEILING)
                if low > high:
                    raise ValueError("stored signing mark is at its ceiling")
                conn.execute(
                    "INSERT INTO gateway_signing_clock (id, mark_ms) VALUES (1, ?) "
                    "ON CONFLICT (id) DO UPDATE SET mark_ms = MAX("
                    "gateway_signing_clock.mark_ms, excluded.mark_ms)",
                    (high,),
                )
                conn.execute("COMMIT")
                committed = True
            finally:
                # Whatever stopped the claim, nothing of it stays open.
                if not committed and conn.in_transaction:
                    conn.execute("ROLLBACK")
        except (sqlite3.Error, ValueError) as exc:
            self._warning.warn(
                "claim_failed",
                "[gateway-auth] signing clock claim failed (%s); retrying",
                exc,
            )
            return None
        return low, high
