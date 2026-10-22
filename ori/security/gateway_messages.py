# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""HMAC authentication for site-local runtime-gateway MQTT envelopes.

Gateway messages have a different trust model from remote commands:

* remote commands are rare, state-mutating, and durably audited in SQLite;
* gateway MQTT messages are site-local, short-lived, and higher frequency.

This module therefore uses the same HMAC/canonical-JSON idea as remote
commands, with a bounded TTL replay cache. The cache is in-memory by
default; when a database path is supplied it also persists seen keys to
SQLite, with the replay floor of gateway-api/v2 Envelope Freshness and
Replay, so neither a restart, a raised skew nor a clock stepped back
reopens the replay window outside that section's stated limits. Restarts
are attacker-influenceable on physically accessible devices (pulling
power is enough), so persistence is the hardened posture. A store that
cannot be read or written refuses every gateway envelope until it answers:
falling back to memory would forget a floor a restart must keep. Tier D and
dispatch never consult the floor.
"""

from __future__ import annotations

import asyncio
import fcntl
import functools
import heapq
import hmac
import json
import logging
import os
import re
import sqlite3
import threading
from base64 import urlsafe_b64decode, urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Mapping, NoReturn, TypeVar

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ori.security.payload_members import (
    EXPORT_RESPONSE_MEMBERS,
    PayloadMemberError,
    admitted_object,
)
from ori.security.signing_clock import SigningClock, durable_store
from ori.utils.coalesced_log import CoalescedWarning
from ori.utils.path_utils import shown
from ori.utils.time_utils import now_ms

AUTH_FIELD = "auth"
AUTH_SCHEME = "hmac-sha256"
SIGNATURE_PREFIX = "hmac-sha256:"
ENCRYPTION_FIELD = "encryption"
ENCRYPTION_SCHEME = "aes-256-gcm"
ENCRYPTION_KEY_INFO = b"ori.gateway-mqtt.export-encryption.v1"
ENCRYPTION_SALT = b"ori-runtime-gateway-mqtt-v1"
DEFAULT_GATEWAY_AUTH_SKEW_MS = 300_000
DEFAULT_GATEWAY_AUTH_REPLAY_TTL_MS = 300_000
_MAX_REPLAY_ENTRIES = 4096
#: A wall clock in milliseconds stays below this for about 285,000 years, so
#: remembering a key any longer is the same as remembering it for ever.
_LONGEST_MEANINGFUL_MS = 2**53
_BELOW_FLOOR = "before_replay_floor"
#: The bounded wait of one atomic step of the replay store; past it, refused.
_STORE_BUSY_TIMEOUT_MS = 5_000
#: How often a store that does not answer is tried again, off the verifying
#: path, and how often a floor an earlier run stored is read again.
_FLOOR_READ_INTERVAL_S = 5.0
#: Replay work admitted to the replay thread and not yet finished. Past it,
#: work is refused rather than queued behind a store that stopped answering.
_REPLAY_WORK_CEILING = 64
_FLOOR_TABLE_DDL = (
    "CREATE TABLE IF NOT EXISTS gateway_replay_floor ("
    "id INTEGER PRIMARY KEY CHECK (id = 1), floor_ms INTEGER)"
)


def replay_window_ms(max_skew_ms: int) -> int:
    """How long after receipt a replay of an envelope could still pass.

    `_verify` accepts an envelope while the clock is within *max_skew_ms* of
    its signing time, both ends inclusive, and it was received no earlier
    than its signing time less the skew: so until twice the skew after
    receipt, and a key pruned at expiry must outlive that by a millisecond.
    Capped where a wall clock in milliseconds never reaches.
    """
    return min(2 * max(0, int(max_skew_ms)) + 1, _LONGEST_MEANINGFUL_MS)


def replay_retention_ms(replay_ttl_ms: int, max_skew_ms: int) -> int:
    """The longest any replay key is kept: the configured window from receipt,
    or until its envelope is stale, whichever is later. What sizes a cache."""
    return max(
        min(max(1, int(replay_ttl_ms)), _LONGEST_MEANINGFUL_MS),
        replay_window_ms(max_skew_ms),
    )


#: The refusals of gateway-api/v2 Envelope Freshness and Replay checks 3 and
#: 4: an envelope already seen, or one signed before what the floor covers.
REPLAY_REFUSALS = frozenset({"before_replay_floor", "replay_detected"})

_T = TypeVar("_T")
_AES_GCM_NONCE_BYTES = 12
logger = logging.getLogger(__name__)


def _signed_at_ms(auth: Mapping[str, Any]) -> int:
    """The signing time exactly as signed: a JSON integer, never a coercible one.

    The auth block is outside the signed bytes, so a string or a float that
    int() would accept verifies all the same, and a consumer ordering on the
    raw value would read a different time than the one verified.
    """
    value = auth.get("signed_at_ms")
    if type(value) is not int:
        raise GatewayMessageAuthError("invalid_signed_at_ms")
    return value


class GatewayMessageAuthError(ValueError):
    """Raised when a runtime-gateway MQTT envelope fails authentication."""


#: What a hostile payload can make signing raise: a value with no JSON form
#: (NaN, a lone surrogate), or one nested past the recursion limit. An
#: authentication error is itself a ValueError, so it is re-raised first.
_UNVERIFIABLE = (ValueError, TypeError, RecursionError)
_SIGNATURE_RE = re.compile(r"\Ahmac-sha256:[0-9a-f]{64}\Z")


class GatewayMessageEncryptionError(ValueError):
    """Raised when a runtime-gateway MQTT envelope cannot be decrypted."""


@dataclass(frozen=True)
class GatewayMessageAuthConfig:
    shared_secret: str
    previous_shared_secret: str = ""
    max_skew_ms: int = DEFAULT_GATEWAY_AUTH_SKEW_MS
    replay_ttl_ms: int = DEFAULT_GATEWAY_AUTH_REPLAY_TTL_MS


@dataclass(frozen=True)
class GatewayMessageEncryptionConfig:
    shared_secret: str


@dataclass(frozen=True)
class AuthenticatedMessage:
    """A message whose envelope verified, its replay key not yet recorded.

    For a receiver that must add no state for a message that answers nothing
    it holds (gateway-api/v2 Payload Volume): it correlates first, then calls
    `GatewayMessageAuthenticator.commit`.
    """

    payload: dict[str, Any]
    replay_key: str
    at_ms: int
    signed_at_ms: int


class ReplayStoreOwnedError(RuntimeError):
    """Another replay cache, in this process or another, owns this store."""


class ReplayWorkRefusedError(RuntimeError):
    """The replay thread holds as much work as it admits, or the cache closed."""


class ReplayStoreAccessError(OSError):
    """The store, or the lock beside it, cannot be opened: a storage fault,
    not another owner. The cache refuses until it can be."""


def _own_replay_store(path: str) -> Any | None:
    """An exclusive, non-blocking lock owning the database at *path*.

    Ownership follows the database file, never the name it was given. The
    lock is named by the file's device and inode, in the file's directory, so
    every name that reaches that file - a symlink, a case variant on a
    case-insensitive filesystem, a second mount of the directory - reaches the
    same lock; a hard link, a second directory entry for the file, is refused.
    flock is per open file, so a second cache in this process is refused as
    surely as one in another. None only where no store can exist, a missing
    directory; any other failure to take ownership raises rather than becoming
    a second, independent receiver.
    """
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        return None
    try:
        # Created here if new, so the lock can be named by the file itself.
        os.close(os.open(path, os.O_RDWR | os.O_CREAT, 0o600))
        identity = os.stat(path)
        lock_path = os.path.join(
            directory,
            f".ori-gateway-replay-{identity.st_dev}-{identity.st_ino}.lock",
        )
        lock = open(lock_path, "a+b")  # noqa: SIM115
    except OSError as exc:
        raise ReplayStoreAccessError(
            exc.errno, f"cannot open {shown(path)} to own it: {exc.strerror}"
        ) from exc
    try:
        if identity.st_nlink != 1:
            raise ReplayStoreOwnedError(
                f"gateway replay store {shown(path)} is hard-linked; ownership "
                "cannot be established"
            )
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            # The lock is the file at its path: one replaced while it was
            # being taken would be a lock nobody else is looking at.
            if os.fstat(lock.fileno()).st_ino != os.stat(lock_path).st_ino:
                raise OSError("lock file replaced while it was taken")
        except OSError as exc:
            raise ReplayStoreOwnedError(
                f"another gateway replay cache owns {shown(path)}"
            ) from exc
    except ReplayStoreOwnedError:
        lock.close()
        raise
    return lock


class GatewayReplayCache:
    """The replay floor and held keys of gateway-api/v2 Envelope Freshness and Replay.

    A held key is dropped once its envelope is stale and *ttl_ms* has passed
    since its receipt, or evicted, smallest signing time first, when the cache
    is full. Either raises the floor to one past the key's signing time in the
    same step, so no check sees the key gone and the floor not raised. The
    floor in force is the greater of that raised floor and the clock when the
    cache was built; only a raised floor is stored, never a clock reading.

    Nothing lowers the stored floor or drops a held key early, a secret
    rotation included. A floor ahead of the clock clears as the clock passes it.

    With *db_path* and *stores*, held keys and the raised floor persist to that
    SQLite file in one transaction per change. With *db_path* alone, a floor an
    earlier run stored there is read at the start and again every
    ``_FLOOR_READ_INTERVAL_S``, and never written.

    A store that exists and cannot be read or written, at the start or later,
    leaves the floor in force unbounded: every envelope reaching checks 3 and 4
    is refused as below the floor, no key is dropped and no floor written, and
    the store is tried again off the verifying path until it answers. A write
    that failed changed nothing, here or in the store. Thread-safe: paho
    callbacks verify on their own threads, and receivers on the event loop
    hand their replay work to the cache's own replay thread.
    """

    def __init__(
        self,
        *,
        ttl_ms: int = DEFAULT_GATEWAY_AUTH_REPLAY_TTL_MS,
        max_skew_ms: int,
        max_entries: int = _MAX_REPLAY_ENTRIES,
        db_path: str | None = None,
        stores: bool = True,
        start_ms: int | None = None,
    ) -> None:
        self._ttl_ms = min(max(1, int(ttl_ms)), _LONGEST_MEANINGFUL_MS)
        self._max_skew_ms = min(max(0, int(max_skew_ms)), _LONGEST_MEANINGFUL_MS)
        self._max_entries = max(1, int(max_entries))
        # key -> (expiry, signing time). Both heaps are lazy: an entry is live
        # while it matches what _held records for its key.
        self._held: dict[str, tuple[int, int]] = {}
        self._expiries: list[tuple[int, str]] = []
        self._signings: list[tuple[int, str]] = []
        self._raised_floor: int | None = None
        self._start_floor = int(start_ms if start_ms is not None else now_ms())
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._ownership: Any = None
        self._unreadable = False
        self._closed = threading.Event()
        # Held by a probe for its whole run, and by close() before it releases
        # the store, so no probe touches the store after it is released.
        self._probing = threading.Lock()
        self._watch: threading.Thread | None = None
        # The replay thread: work an event-loop receiver hands off, so neither
        # the loop nor its default executor, which Tier A notices also use,
        # waits on this cache's lock. The lock serialises the work anyway.
        self._work_lock = threading.Lock()
        self._work_pending = 0
        self._work_executor: ThreadPoolExecutor | None = None
        path = str(db_path or "").strip()
        # SQLite's private in-memory database is one connection's memory: no
        # store to own, and nothing that survives a restart.
        self._path = os.path.realpath(path) if durable_store(path) else ""
        self._stores = bool(self._path) and bool(stores)
        if self._stores:
            # One cache owns a store at a time, in this process or any other:
            # a cache's memory is then the whole of the store's history.
            try:
                self._ownership = _own_replay_store(self._path)
                self._connect()
            except (sqlite3.Error, ReplayStoreAccessError):
                self._enter_unreadable()
        elif self._path and os.path.exists(self._path):
            try:
                self._merge_floor(self._read_earlier_floor())
            except sqlite3.Error:
                self._enter_unreadable()
            self._start_watch()

    @property
    def persistent(self) -> bool:
        """Whether recording a key is a write to the store."""
        return self._stores

    @property
    def unreadable(self) -> bool:
        """Whether the stored floor cannot be read, so every envelope is refused."""
        return self._unreadable

    def close(self) -> None:
        """Release the store: its connection, then its ownership.

        A probe already running finishes first; none starts after.
        """
        self._closed.set()
        with self._work_lock:
            executor, self._work_executor = self._work_executor, None
        if executor is not None:
            # Work already running finishes under the lock below; work still
            # queued is cancelled, never left to run against a released store.
            executor.shutdown(wait=False, cancel_futures=True)
        with self._probing, self._lock:
            conn, self._conn = self._conn, None
            if conn is not None:
                conn.close()
            ownership, self._ownership = self._ownership, None
            if ownership is not None:
                ownership.close()

    async def run_off_loop(
        self, fn: Callable[..., _T], /, *args: Any, **kwargs: Any
    ) -> _T:
        """Run *fn* on the replay thread and await it.

        Refused, rather than queued, past ``_REPLAY_WORK_CEILING`` or once the
        cache has closed.
        """
        with self._work_lock:
            if self._closed.is_set():
                raise ReplayWorkRefusedError("the gateway replay cache is closed")
            if self._work_pending >= _REPLAY_WORK_CEILING:
                raise ReplayWorkRefusedError(
                    f"the replay thread holds {self._work_pending} checks already"
                )
            if self._work_executor is None:
                self._work_executor = ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix="ori-gateway-replay"
                )
            self._work_pending += 1
            future = self._work_executor.submit(functools.partial(fn, *args, **kwargs))
        future.add_done_callback(self._work_finished)
        return await asyncio.wrap_future(future)

    def _work_finished(self, _future: Any) -> None:
        with self._work_lock:
            self._work_pending -= 1

    @property
    def max_skew_ms(self) -> int:
        return self._max_skew_ms

    def floor_ms(self) -> int:
        """The floor this cache keeps, whether or not the store can be read."""
        with self._lock:
            return self._floor()

    def check(self, key: str, *, signed_at_ms: int) -> str | None:
        """Checks 3 and 4 without recording: the refusal reason, or None.

        Nothing is pruned here: a key whose retention ended belongs to a stale
        envelope, which check 1 has already refused.
        """
        with self._lock:
            return self._refusal(key, signed_at_ms)

    def admit(
        self,
        key: str,
        *,
        signed_at_ms: int,
        received_at_ms: int,
        now_ms_value: int | None = None,
    ) -> str | None:
        """Checks 3 and 4 and, when both hold, hold *key*, as one step.

        With a store, the step is one transaction against it, the floor and
        held keys there deciding as well as this cache's own, and a key held
        only once the store has it.
        """
        current_ms = int(now_ms_value if now_ms_value is not None else now_ms())
        with self._lock:
            if self._unreadable:
                return _BELOW_FLOOR
            prior = self._raised_floor
            dropped = self._prune_locked(current_ms)
            reason = self._refusal(key, signed_at_ms)
            if not self._stores:
                if reason is None:
                    while len(self._held) >= self._max_entries:
                        dropped.append(self._evict_locked())
                    self._compact()
                    self._hold(
                        key, self._expiry(signed_at_ms, received_at_ms), signed_at_ms
                    )
                return reason
            if reason is not None and not dropped:
                return reason
            try:
                held = self._transact(
                    lambda conn: self._admit_stored(
                        conn, key, signed_at_ms, received_at_ms, dropped, reason
                    )
                )
            except sqlite3.Error:
                self._restore(dropped, prior)
                self._enter_unreadable()
                return _BELOW_FLOOR
            if isinstance(held, str):
                return held
            if held is not None:
                self._hold(key, held[1], signed_at_ms)
            return reason

    def prune(self, now_ms_value: int | None = None) -> None:
        """Drop every key whose retention has ended."""
        current_ms = int(now_ms_value if now_ms_value is not None else now_ms())
        with self._lock:
            if self._unreadable:
                return
            prior = self._raised_floor
            self._settle(self._prune_locked(current_ms), prior)

    def evict_one(self) -> None:
        """What a full cache does before holding a new key."""
        with self._lock:
            if self._held and not self._unreadable:
                prior = self._raised_floor
                dropped = [self._evict_locked()]
                self._compact()
                self._settle(dropped, prior)

    def refresh(self) -> bool:
        """Read the stored floor again; whether the store answered.

        Run off the verifying path: the store is tried on a connection of its
        own, outside the lock every verification takes, and only an answer is
        applied under it. A storing cache must also commit a write again.
        """
        if not self._path:
            return True
        with self._probing:
            if self._closed.is_set():
                return False
            try:
                floor = self._probe()
            except (sqlite3.Error, OSError):
                with self._lock:
                    self._enter_unreadable()
                return False
            return self._apply_probe(floor)

    def _apply_probe(self, floor: int | None) -> bool:
        with self._lock:
            try:
                if self._stores and self._conn is None:
                    # Under the lock every verification takes: a store taken
                    # again since the probe refuses at once, never waited on.
                    self._connect(wait_ms=0)
                else:
                    self._merge_floor(floor)
            except (sqlite3.Error, OSError, ReplayStoreOwnedError):
                self._enter_unreadable()
                return False
            if self._unreadable:
                self._unreadable = False
                logger.warning(
                    "[gateway-auth] gateway replay store %s answers again; "
                    "the replay floor is %d",
                    shown(self._path),
                    self._floor(),
                )
            return True

    # ─── the store ──────────────────────────────────────────────────────────

    def _connect(self, *, wait_ms: int | None = None) -> None:
        """Connect to the owned store and load it; nothing kept if it fails.

        *wait_ms* bounds each wait for the store while loading it; afterwards
        every step waits at most the store's ordinary bound.
        """
        wait = _STORE_BUSY_TIMEOUT_MS if wait_ms is None else wait_ms
        if self._ownership is None:
            self._ownership = _own_replay_store(self._path)
        if self._ownership is None:
            raise sqlite3.OperationalError("the replay store's directory is missing")
        # Transactions are explicit: every change is one BEGIN IMMEDIATE,
        # written whole or not at all.
        conn = sqlite3.connect(
            self._path,
            check_same_thread=False,
            isolation_level=None,
            timeout=wait / 1000,
        )
        try:
            self._conn = conn
            self._open(conn)
            conn.execute(f"PRAGMA busy_timeout = {int(_STORE_BUSY_TIMEOUT_MS)}")
        except BaseException:
            self._conn = None
            conn.close()
            raise

    def _probe(self) -> int | None:
        """The stored floor, read on a connection of this call's own."""
        if self._stores:
            if not os.path.isdir(os.path.dirname(self._path)):
                raise OSError("the replay store's directory is missing")
            conn = sqlite3.connect(
                self._path, isolation_level=None, timeout=_STORE_BUSY_TIMEOUT_MS / 1000
            )
            try:
                # A committed write, not only the write lock: a full or
                # read-only store takes the lock and fails the write. The row
                # written is the floor as it stands, or none.
                conn.execute("BEGIN IMMEDIATE")
                try:
                    floor = _stored_floor(conn)
                    conn.execute(_FLOOR_TABLE_DDL)
                    conn.execute(
                        "INSERT INTO gateway_replay_floor (id, floor_ms) "
                        "VALUES (1, NULL) ON CONFLICT (id) DO UPDATE SET "
                        "floor_ms = gateway_replay_floor.floor_ms"
                    )
                    conn.execute("COMMIT")
                except BaseException:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise
                return floor
            finally:
                conn.close()
        return self._read_earlier_floor()

    def _read_earlier_floor(self) -> int | None:
        """The floor an earlier, storing run left, read and never written."""
        if not os.path.exists(self._path):
            return None
        conn = sqlite3.connect(
            f"{Path(self._path).as_uri()}?mode=ro",
            uri=True,
            timeout=_STORE_BUSY_TIMEOUT_MS / 1000,
        )
        try:
            return _stored_floor(conn)
        finally:
            conn.close()

    def _merge_floor(self, stored: int | None) -> None:
        if stored is not None and (
            self._raised_floor is None or stored > self._raised_floor
        ):
            self._raised_floor = stored

    def _enter_unreadable(self) -> None:
        if not self._unreadable:
            self._unreadable = True
            logger.error(
                "[gateway-auth] gateway replay store %s cannot be read or "
                "written; every gateway envelope is refused below the replay "
                "floor until it answers",
                shown(self._path),
                exc_info=True,
            )
        if self._stores:
            self._start_watch()

    def _start_watch(self) -> None:
        # Under the lock, or before the cache is shared. The watch clears this
        # itself, under the lock, only once it has seen the store answer.
        if self._watch is not None or self._closed.is_set():
            return
        self._watch = threading.Thread(
            target=self._watch_store, name="ori-gateway-replay-floor", daemon=True
        )
        self._watch.start()

    def _watch_store(self) -> None:
        # A storing cache reads its floor in every admission, so it is watched
        # only while the store refuses; one that only reads an earlier floor is
        # watched for the life of the run.
        while not self._closed.wait(_FLOOR_READ_INTERVAL_S):
            self.refresh()
            if self._stores:
                with self._lock:
                    if not self._unreadable:
                        self._watch = None
                        return

    def _admit_stored(
        self,
        conn: sqlite3.Connection,
        key: str,
        signed_at_ms: int,
        received_at_ms: int,
        dropped: list[tuple[str, int, int]],
        reason: str | None,
    ) -> tuple[str, int, int, int] | str | None:
        """The key to hold once this commits, the refusal, or None for neither."""
        if reason is None:
            self._merge_floor(_stored_floor(conn))
            if signed_at_ms < self._floor():
                reason = _BELOW_FLOOR
            elif conn.execute(
                "SELECT 1 FROM gateway_replay_cache WHERE key = ?", (key,)
            ).fetchone():
                reason = "replay_detected"
        held: tuple[str, int, int, int] | None = None
        if reason is None:
            while len(self._held) >= self._max_entries:
                dropped.append(self._evict_locked())
            self._compact()
            expiry = self._expiry(signed_at_ms, received_at_ms)
            held = (key, expiry, signed_at_ms, received_at_ms)
        self._write_change(conn, [entry[0] for entry in dropped], held)
        return reason if reason is not None else held

    def _settle(self, dropped: list[tuple[str, int, int]], prior: int | None) -> None:
        """Write *dropped* and its raise, or keep every key held if it fails."""
        if not dropped or not self._stores:
            return
        try:
            self._transact(
                lambda conn: self._write_change(
                    conn, [entry[0] for entry in dropped], None
                )
            )
        except sqlite3.Error:
            self._restore(dropped, prior)
            self._enter_unreadable()

    def _restore(self, dropped: list[tuple[str, int, int]], prior: int | None) -> None:
        """Undo drops the store did not take: the keys held, the floor as it was."""
        for key, expiry, signed_at_ms in dropped:
            self._hold(key, expiry, signed_at_ms)
        self._raised_floor = prior

    def _transact(self, change: Callable[[sqlite3.Connection], _T]) -> _T:
        """Run *change* in one BEGIN IMMEDIATE transaction; its result."""
        conn = self._conn
        if conn is None:
            raise sqlite3.OperationalError("the replay store is not open")
        conn.execute("BEGIN IMMEDIATE")
        try:
            result = change(conn)
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        return result

    # ─── memory ─────────────────────────────────────────────────────────────

    def _floor(self) -> int:
        raised = self._raised_floor
        return self._start_floor if raised is None else max(raised, self._start_floor)

    def _refusal(self, key: str, signed_at_ms: int) -> str | None:
        # An unreadable store leaves the floor unbounded: a refusal, never a
        # floor, so it is neither stored nor reported.
        if self._unreadable or signed_at_ms < self._floor():
            return _BELOW_FLOOR
        if key in self._held:
            return "replay_detected"
        return None

    def _expiry(self, signed_at_ms: int, received_at_ms: int) -> int:
        """The first clock reading at which the key may be dropped."""
        return min(
            max(signed_at_ms + self._max_skew_ms + 1, received_at_ms + self._ttl_ms),
            _LONGEST_MEANINGFUL_MS,
        )

    def _hold(self, key: str, expiry: int, signed_at_ms: int) -> None:
        self._held[key] = (expiry, signed_at_ms)
        heapq.heappush(self._expiries, (expiry, key))
        heapq.heappush(self._signings, (signed_at_ms, key))

    def _drop(self, key: str) -> tuple[str, int, int]:
        expiry, signed_at_ms = self._held.pop(key)
        raised = signed_at_ms + 1
        if self._raised_floor is None or raised > self._raised_floor:
            self._raised_floor = raised
        return key, expiry, signed_at_ms

    def _prune_locked(self, current_ms: int) -> list[tuple[str, int, int]]:
        dropped: list[tuple[str, int, int]] = []
        expiries = self._expiries
        while expiries and expiries[0][0] <= current_ms:
            expiry, key = heapq.heappop(expiries)
            entry = self._held.get(key)
            if entry is not None and entry[0] == expiry:
                dropped.append(self._drop(key))
        self._compact()
        return dropped

    def _evict_locked(self) -> tuple[str, int, int]:
        while True:
            signed_at_ms, key = heapq.heappop(self._signings)
            entry = self._held.get(key)
            if entry is not None and entry[1] == signed_at_ms:
                return self._drop(key)

    def _compact(self) -> None:
        # Entries of dropped keys stay in the other heap until they reach its
        # top; rebuilt once they outnumber the live ones, so neither grows
        # past a small multiple of the cache.
        limit = 2 * len(self._held) + 64
        if len(self._signings) > limit:
            self._signings = [(s, k) for k, (_e, s) in self._held.items()]
            heapq.heapify(self._signings)
        if len(self._expiries) > limit:
            self._expiries = [(e, k) for k, (e, _s) in self._held.items()]
            heapq.heapify(self._expiries)

    def _open(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS gateway_replay_cache ("
            "key TEXT PRIMARY KEY, seen_until_ms INTEGER NOT NULL)"
        )
        # Added, never required: a release before the floor writes rows
        # without them after an automatic rollback.
        columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(gateway_replay_cache)")
        }
        for column in ("signed_at_ms", "received_at_ms"):
            if column not in columns:
                conn.execute(
                    f"ALTER TABLE gateway_replay_cache ADD COLUMN {column} INTEGER"
                )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS gateway_replay_cache_expiry "
            "ON gateway_replay_cache (seen_until_ms)"
        )
        conn.execute(_FLOOR_TABLE_DDL)
        floor = _stored_floor(conn)
        rows = conn.execute(
            "SELECT key, seen_until_ms, signed_at_ms, received_at_ms "
            "FROM gateway_replay_cache"
        ).fetchall()
        # Every row is checked before any is held: a store with one it cannot
        # read is unreadable whole.
        for row in rows:
            if not isinstance(row[0], str) or not all(
                _stored_integer(value, nullable=index > 1)
                for index, value in enumerate(row)
                if index > 0
            ):
                raise sqlite3.DatabaseError("a stored replay key cannot be read")
        self._merge_floor(floor)
        rewritten: list[tuple[int, int, str]] = []
        for key, stored_ms, signed_col, received_col in rows:
            signed_at_ms = (
                int(signed_col)
                if signed_col is not None
                else self._stored_signing_time(key, stored_ms)
            )
            if received_col is not None:
                # Decided again under this start's skew and window.
                expiry = self._expiry(signed_at_ms, int(received_col))
            else:
                # Written by a release that kept no receipt time: extended to
                # when the envelope turns stale, never shortened.
                expiry = min(
                    max(stored_ms, signed_at_ms + self._max_skew_ms + 1),
                    _LONGEST_MEANINGFUL_MS,
                )
            self._hold(key, expiry, signed_at_ms)
            if expiry != stored_ms or signed_col is None:
                rewritten.append((expiry, signed_at_ms, key))
        prior = self._raised_floor
        evicted: list[tuple[str, int, int]] = []
        while len(self._held) > self._max_entries:
            evicted.append(self._evict_locked())
        dropped = [entry[0] for entry in evicted]
        kept = [entry for entry in rewritten if entry[2] in self._held]
        if kept or dropped:

            def rewrite(conn: sqlite3.Connection) -> None:
                conn.executemany(
                    "UPDATE gateway_replay_cache SET seen_until_ms = ?, "
                    "signed_at_ms = ? WHERE key = ?",
                    kept,
                )
                self._write_change(conn, dropped, None)

            try:
                self._transact(rewrite)
            except sqlite3.Error:
                # Memory stays what the store holds: the evicted keys held,
                # the floor not raised.
                self._restore(evicted, prior)
                raise

    def _stored_signing_time(self, key: str, stored_ms: int) -> int:
        """A row's signing time from its key, which always ends with it.

        A key of any other shape takes the latest signing time its stored
        expiry allows, so dropping it raises the floor at least as far as
        its real signing time would have.
        """
        fields = key.split("\n")
        try:
            signed_at_ms = int(fields[-2])
        except (IndexError, ValueError):
            return stored_ms - self._max_skew_ms - 1
        if abs(signed_at_ms) > _LONGEST_MEANINGFUL_MS:
            return stored_ms - self._max_skew_ms - 1
        return signed_at_ms

    def _write_change(
        self,
        conn: sqlite3.Connection,
        dropped: list[str],
        held: tuple[str, int, int, int] | None,
    ) -> None:
        if dropped:
            conn.executemany(
                "DELETE FROM gateway_replay_cache WHERE key = ?",
                [(key,) for key in dropped],
            )
            conn.execute(
                "INSERT INTO gateway_replay_floor (id, floor_ms) VALUES (1, ?) "
                "ON CONFLICT (id) DO UPDATE SET floor_ms = MAX("
                "COALESCE(gateway_replay_floor.floor_ms, excluded.floor_ms), "
                "excluded.floor_ms)",
                (self._raised_floor,),
            )
        if held is not None:
            key, expiry, signed_at_ms, received_at_ms = held
            conn.execute(
                "INSERT INTO gateway_replay_cache "
                "(key, seen_until_ms, signed_at_ms, received_at_ms) "
                "VALUES (?, ?, ?, ?)",
                (key, expiry, signed_at_ms, received_at_ms),
            )


def _stored_floor(conn: sqlite3.Connection) -> int | None:
    """The floor stored in *conn*'s database; None when none ever was."""
    if (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'gateway_replay_floor'"
        ).fetchone()
        is None
    ):
        return None
    row = conn.execute(
        "SELECT floor_ms FROM gateway_replay_floor WHERE id = 1"
    ).fetchone()
    if row is None or row[0] is None:
        return None
    if not _stored_integer(row[0], nullable=False):
        raise sqlite3.DatabaseError("the stored replay floor is not an integer")
    return int(row[0])


def _stored_integer(value: object, *, nullable: bool) -> bool:
    """Whether a stored value is SQLite's INTEGER, or NULL where allowed."""
    if value is None:
        return nullable
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class GatewayEnvelopeState:
    """What every gateway route of one runtime shares: one replay cache, and
    one signing clock behind every signer."""

    replay_cache: GatewayReplayCache
    signing_clock: SigningClock

    def close(self) -> None:
        """Stop the clock's writer, then release the store the cache owns.

        Each step is attempted whatever the other did, and none raises.
        """
        for step, what in (
            (self.signing_clock.stop, "stopping the signing clock"),
            (self.replay_cache.close, "closing the gateway replay cache"),
        ):
            try:
                step()
            except Exception:
                logger.exception("[gateway-auth] error %s", what)


class GatewayMessageAuthenticator:
    """Sign and verify runtime-gateway MQTT JSON payloads."""

    def __init__(
        self,
        config: GatewayMessageAuthConfig,
        *,
        replay_cache: GatewayReplayCache | None = None,
        signing_clock: SigningClock | None = None,
    ) -> None:
        secret = str(config.shared_secret or "").strip()
        if not secret:
            raise ValueError("gateway message shared_secret must not be empty")
        self._secret = secret
        previous_secret = str(config.previous_shared_secret or "").strip()
        if previous_secret and hmac.compare_digest(previous_secret, secret):
            raise ValueError(
                "gateway message previous_shared_secret must differ from shared_secret"
            )
        self._previous_secret = previous_secret
        self._max_skew_ms = min(max(0, int(config.max_skew_ms)), _LONGEST_MEANINGFUL_MS)
        self._replay_cache = replay_cache or GatewayReplayCache(
            ttl_ms=config.replay_ttl_ms,
            max_skew_ms=config.max_skew_ms,
        )
        # The cache drops a key once its envelope is stale under its own skew,
        # so one built for a narrower skew would forget envelopes this still
        # admits.
        if self._replay_cache.max_skew_ms != self._max_skew_ms:
            raise ValueError(
                "gateway replay cache skew differs from the authenticator's"
            )
        self._floor_warning = CoalescedWarning(logger)
        # In-process only unless the runtime's durable one is supplied.
        self._signing_clock = signing_clock or SigningClock(clock=_wall_now_ms)

    @property
    def persists_replay_keys(self) -> bool:
        """Whether recording a replay key is an SQLite write."""
        return self._replay_cache.persistent

    @property
    def max_skew_ms(self) -> int:
        """How far a signing time may sit from the receiver's clock."""
        return self._max_skew_ms

    def sign(
        self,
        payload: Mapping[str, Any],
        *,
        message_type: str,
        signed_at_ms: int | None = None,
    ) -> dict[str, Any]:
        """Return a copy of *payload* with an HMAC auth block attached.

        The signing time comes from the signing clock, which never repeats
        one; raises `SigningClockUnavailableError` when it has none to give.
        *signed_at_ms* is for tests and the vectors; no runtime signer passes it.
        """
        signed_payload = _payload_without_auth(payload)
        issued_ms = int(
            signed_at_ms if signed_at_ms is not None else self._signing_clock.issue()
        )
        signature = self._signature(
            payload=signed_payload,
            message_type=message_type,
            signed_at_ms=issued_ms,
        )
        signed_payload[AUTH_FIELD] = {
            "scheme": AUTH_SCHEME,
            "signed_at_ms": issued_ms,
            "signature": signature,
        }
        return signed_payload

    def verify(
        self,
        payload: Mapping[str, Any],
        *,
        message_type: str,
        expected_device_id: str,
        expected_request_id: str | None = None,
        now_ms_value: int | None = None,
    ) -> dict[str, Any]:
        """Verify *payload* and return a copy without the auth block.

        Raises only `GatewayMessageAuthError` for anything a sender can put on
        the wire, so every caller's refusal path is the only path.
        """
        message = self.authenticate(
            payload,
            message_type=message_type,
            expected_device_id=expected_device_id,
            expected_request_id=expected_request_id,
            now_ms_value=now_ms_value,
        )
        self.commit(message, now_ms_value=message.at_ms)
        return message.payload

    def authenticate(
        self,
        payload: Mapping[str, Any],
        *,
        message_type: str,
        expected_device_id: str,
        expected_request_id: str | None = None,
        now_ms_value: int | None = None,
    ) -> AuthenticatedMessage:
        """Verify *payload*'s envelope without recording it as seen.

        Nothing is accepted until `commit` records the replay key; a message
        never committed may arrive again and verify again.
        """
        try:
            return self._verify(
                payload,
                message_type=message_type,
                expected_device_id=expected_device_id,
                expected_request_id=expected_request_id,
                now_ms_value=now_ms_value,
            )
        except GatewayMessageAuthError:
            raise
        except _UNVERIFIABLE as exc:
            raise GatewayMessageAuthError("unverifiable_payload") from exc

    def commit(
        self, message: AuthenticatedMessage, *, now_ms_value: int | None = None
    ) -> None:
        """Record *message* as seen, making checks 3 and 4 again as it does.

        Its receipt time stays the time it was authenticated. Without
        *now_ms_value*, keys are pruned as of that time too: a later prune only
        ever keeps a key longer, and the receiver's own clock decides it.
        """
        current_ms = int(now_ms_value if now_ms_value is not None else message.at_ms)
        reason = self._replay_cache.admit(
            message.replay_key,
            signed_at_ms=message.signed_at_ms,
            received_at_ms=message.at_ms,
            now_ms_value=current_ms,
        )
        if reason is not None:
            self._refuse(reason, current_ms)

    def _replay_checks(
        self, replay_key: str, signed_at_ms: int, current_ms: int
    ) -> None:
        reason = self._replay_cache.check(replay_key, signed_at_ms=signed_at_ms)
        if reason is not None:
            self._refuse(reason, current_ms)

    def _freshness(self, signed_at_ms: int, current_ms: int) -> None:
        if signed_at_ms < current_ms - self._max_skew_ms:
            raise GatewayMessageAuthError("stale_timestamp")
        if signed_at_ms > current_ms + self._max_skew_ms:
            raise GatewayMessageAuthError("future_timestamp")

    def _refuse(self, reason: str, current_ms: int) -> NoReturn:
        if reason == "before_replay_floor" and self._replay_cache.unreadable:
            # No clock passes this one: it ends when the store answers.
            self._floor_warning.warn(
                "replay_store_unreadable",
                "[gateway-auth] envelope refused: the gateway replay store "
                "cannot be read or written, so every envelope is refused until "
                "it answers (clock %d)",
                current_ms,
            )
        elif reason == "before_replay_floor":
            # Check 1 held, so the floor sits above the clock less the skew
            # whenever this refuses: a restart, a clock step or an eviction
            # ahead of the clock, far more often than an attack. Fresh
            # envelopes are refused until the senders' clocks pass the floor.
            self._floor_warning.warn(
                reason,
                "[gateway-auth] envelope refused below the replay floor "
                "%d at clock %d; envelopes signed before the floor are "
                "refused until the senders' clocks pass it",
                self._replay_cache.floor_ms(),
                current_ms,
            )
        raise GatewayMessageAuthError(reason)

    async def run_off_loop(
        self, fn: Callable[..., _T], /, *args: Any, **kwargs: Any
    ) -> _T:
        """Run replay work for a receiver on the event loop, off it.

        With a store, the replay checks wait on the cache's lock, which an
        admission holds across its store transaction; so the work runs on the
        cache's own replay thread, never on the loop Tier D runs on nor on its
        default executor. Without one it never waits, and runs here. Work the
        replay thread refuses is refused as `replay_store_busy`.
        """
        if not self.persists_replay_keys:
            return fn(*args, **kwargs)
        try:
            return await self._replay_cache.run_off_loop(fn, *args, **kwargs)
        except ReplayWorkRefusedError as exc:
            raise GatewayMessageAuthError("replay_store_busy") from exc

    async def authenticate_async(
        self,
        payload: Mapping[str, Any],
        *,
        message_type: str,
        expected_device_id: str,
        expected_request_id: str | None = None,
        now_ms_value: int | None = None,
    ) -> AuthenticatedMessage:
        """`authenticate` for a receiver on the event loop, off it wherever it
        waits. Authenticating records nothing, so a cancelled wait leaves
        nothing behind."""
        return await self.run_off_loop(
            self.authenticate,
            payload,
            message_type=message_type,
            expected_device_id=expected_device_id,
            expected_request_id=expected_request_id,
            now_ms_value=now_ms_value,
        )

    async def verify_async(
        self,
        payload: Mapping[str, Any],
        *,
        message_type: str,
        expected_device_id: str,
        expected_request_id: str | None = None,
    ) -> dict[str, Any]:
        """`verify` for a receiver on the event loop, off it wherever it waits."""
        message = await self.authenticate_async(
            payload,
            message_type=message_type,
            expected_device_id=expected_device_id,
            expected_request_id=expected_request_id,
        )
        await self.commit_async(message)
        return message.payload

    async def commit_async(self, message: AuthenticatedMessage) -> None:
        """`commit` for a receiver on the event loop.

        A persisted key is committed on the replay thread and awaited, so the
        message is still recorded durably before it is acted on.
        """
        await self.run_off_loop(self.commit, message)

    def _verify(
        self,
        payload: Mapping[str, Any],
        *,
        message_type: str,
        expected_device_id: str,
        expected_request_id: str | None,
        now_ms_value: int | None,
    ) -> AuthenticatedMessage:
        auth = payload.get(AUTH_FIELD)
        if not isinstance(auth, Mapping):
            raise GatewayMessageAuthError("missing_auth")
        scheme = str(auth.get("scheme", "") or "")
        if scheme != AUTH_SCHEME:
            raise GatewayMessageAuthError("unsupported_auth_scheme")
        signature = str(auth.get("signature", "") or "")
        if not signature.startswith(SIGNATURE_PREFIX):
            raise GatewayMessageAuthError("missing_signature")
        signed_at_ms = _signed_at_ms(auth)

        unsigned_payload = _payload_without_auth(payload)
        device_id = str(unsigned_payload.get("device_id", "") or "")
        if device_id != str(expected_device_id):
            raise GatewayMessageAuthError("device_mismatch")
        request_id = str(unsigned_payload.get("request_id", "") or "")
        if expected_request_id is not None and request_id != str(expected_request_id):
            raise GatewayMessageAuthError("request_id_mismatch")

        signature_match = self._signature_match(
            signature,
            payload=unsigned_payload,
            message_type=message_type,
            signed_at_ms=signed_at_ms,
        )
        if signature_match == "none":
            raise GatewayMessageAuthError("invalid_signature")
        if signature_match == "previous":
            logger.warning(
                "gateway MQTT envelope accepted with previous HMAC secret: "
                "message_type=%s device_id=%s request_id=%s",
                message_type,
                device_id,
                request_id,
            )

        # Freshness only once the signature and the topic-device check hold.
        current_ms = int(now_ms_value if now_ms_value is not None else now_ms())
        self._freshness(signed_at_ms, current_ms)
        replay_key = "\n".join(
            [message_type, device_id, request_id, str(signed_at_ms), signature]
        )
        self._replay_checks(replay_key, signed_at_ms, current_ms)
        return AuthenticatedMessage(
            unsigned_payload, replay_key, current_ms, signed_at_ms
        )

    def verify_broadcast(
        self,
        payload: Mapping[str, Any],
        *,
        message_type: str,
        now_ms_value: int | None = None,
    ) -> dict[str, Any]:
        """Verify a site-broadcast MQTT payload and return a copy without the auth block.

        Identical to :meth:`verify` except no ``device_id`` or ``request_id``
        binding is performed.  Broadcast messages (e.g. gateway heartbeats) are
        addressed to the entire site, not to a specific runtime.  HMAC correctness,
        timestamp skew, and replay protection are still fully enforced.

        The replay key is ``message_type + signed_at_ms + signature`` — unique per
        signed message without needing per-device scoping.
        """
        try:
            return self._verify_broadcast(
                payload, message_type=message_type, now_ms_value=now_ms_value
            )
        except GatewayMessageAuthError:
            raise
        except _UNVERIFIABLE as exc:
            raise GatewayMessageAuthError("unverifiable_payload") from exc

    def _verify_broadcast(
        self,
        payload: Mapping[str, Any],
        *,
        message_type: str,
        now_ms_value: int | None,
    ) -> dict[str, Any]:
        auth = payload.get(AUTH_FIELD)
        if not isinstance(auth, Mapping):
            raise GatewayMessageAuthError("missing_auth")
        scheme = str(auth.get("scheme", "") or "")
        if scheme != AUTH_SCHEME:
            raise GatewayMessageAuthError("unsupported_auth_scheme")
        signature = str(auth.get("signature", "") or "")
        if not signature.startswith(SIGNATURE_PREFIX):
            raise GatewayMessageAuthError("missing_signature")
        signed_at_ms = _signed_at_ms(auth)

        unsigned_payload = _payload_without_auth(payload)
        signature_match = self._signature_match(
            signature,
            payload=unsigned_payload,
            message_type=message_type,
            signed_at_ms=signed_at_ms,
        )
        if signature_match == "none":
            raise GatewayMessageAuthError("invalid_signature")
        if signature_match == "previous":
            logger.warning(
                "gateway MQTT broadcast accepted with previous HMAC secret: "
                "message_type=%s",
                message_type,
            )

        current_ms = int(now_ms_value if now_ms_value is not None else now_ms())
        self._freshness(signed_at_ms, current_ms)
        replay_key = "\n".join([message_type, str(signed_at_ms), signature])
        reason = self._replay_cache.admit(
            replay_key,
            signed_at_ms=signed_at_ms,
            received_at_ms=current_ms,
            now_ms_value=current_ms,
        )
        if reason is not None:
            self._refuse(reason, current_ms)
        return unsigned_payload

    def _signature(
        self,
        *,
        payload: Mapping[str, Any],
        message_type: str,
        signed_at_ms: int,
    ) -> str:
        return self._signature_with_secret(
            self._secret,
            payload=payload,
            message_type=message_type,
            signed_at_ms=signed_at_ms,
        )

    def _signature_match(
        self,
        signature: str,
        *,
        payload: Mapping[str, Any],
        message_type: str,
        signed_at_ms: int,
    ) -> str:
        # Shape before comparison: compare_digest refuses a non-ASCII string
        # with TypeError, and a signature of another shape matches nothing.
        if not _SIGNATURE_RE.fullmatch(signature):
            raise GatewayMessageAuthError("malformed_signature")
        expected = self._signature(
            payload=payload,
            message_type=message_type,
            signed_at_ms=signed_at_ms,
        )
        if hmac.compare_digest(signature, expected):
            return "current"
        if not self._previous_secret:
            return "none"
        expected_previous = self._signature_with_secret(
            self._previous_secret,
            payload=payload,
            message_type=message_type,
            signed_at_ms=signed_at_ms,
        )
        if hmac.compare_digest(signature, expected_previous):
            return "previous"
        return "none"

    def _signature_with_secret(
        self,
        secret: str,
        *,
        payload: Mapping[str, Any],
        message_type: str,
        signed_at_ms: int,
    ) -> str:
        device_id = str(payload.get("device_id", "") or "")
        request_id = str(payload.get("request_id", "") or "")
        signed = "\n".join(
            [
                str(message_type),
                device_id,
                request_id,
                str(int(signed_at_ms)),
                _canonical_json(payload),
            ]
        )
        digest = hmac.new(
            str(secret).encode("utf-8"),
            signed.encode("utf-8"),
            sha256,
        ).hexdigest()
        return f"{SIGNATURE_PREFIX}{digest}"


class GatewayMessageEncryptor:
    """Encrypt sensitive runtime-gateway MQTT payloads with AES-GCM."""

    def __init__(self, config: GatewayMessageEncryptionConfig) -> None:
        secret = str(config.shared_secret or "").strip()
        if not secret:
            raise ValueError("gateway message shared_secret must not be empty")
        self._key = _derive_encryption_key(secret)

    def encrypt(
        self,
        payload: Mapping[str, Any],
        *,
        message_type: str,
        nonce: bytes | None = None,
    ) -> dict[str, Any]:
        """Return an encrypted envelope for *payload*.

        Routing metadata stays visible so MQTT topics and request correlation do
        not depend on decryption. The original payload is recovered by
        :meth:`decrypt`.
        """
        plaintext_payload = _payload_without_auth(payload)
        metadata = _encryption_metadata(plaintext_payload)
        nonce_bytes = nonce if nonce is not None else os.urandom(_AES_GCM_NONCE_BYTES)
        if len(nonce_bytes) != _AES_GCM_NONCE_BYTES:
            raise GatewayMessageEncryptionError("invalid_nonce_length")
        aad = _encryption_aad(metadata, message_type=message_type)
        ciphertext = AESGCM(self._key).encrypt(
            nonce_bytes,
            _canonical_json(plaintext_payload).encode("utf-8"),
            aad,
        )
        return {
            **metadata,
            "encrypted": True,
            ENCRYPTION_FIELD: {
                "scheme": ENCRYPTION_SCHEME,
                "nonce": _b64encode(nonce_bytes),
                "ciphertext": _b64encode(ciphertext),
            },
        }

    def decrypt(
        self,
        payload: Mapping[str, Any],
        *,
        message_type: str,
        expected_device_id: str,
        expected_request_id: str | None = None,
    ) -> dict[str, Any]:
        """Decrypt *payload* and return the original JSON object."""
        if payload.get("encrypted") is not True:
            raise GatewayMessageEncryptionError("missing_encrypted_flag")
        envelope = payload.get(ENCRYPTION_FIELD)
        if not isinstance(envelope, Mapping):
            raise GatewayMessageEncryptionError("missing_encryption")
        if str(envelope.get("scheme", "") or "") != ENCRYPTION_SCHEME:
            raise GatewayMessageEncryptionError("unsupported_encryption_scheme")

        metadata = _encryption_metadata(payload)
        if metadata["device_id"] != str(expected_device_id):
            raise GatewayMessageEncryptionError("device_mismatch")
        if expected_request_id is not None and metadata["request_id"] != str(
            expected_request_id
        ):
            raise GatewayMessageEncryptionError("request_id_mismatch")

        try:
            nonce = _b64decode(str(envelope.get("nonce", "") or ""))
            ciphertext = _b64decode(str(envelope.get("ciphertext", "") or ""))
            plaintext = AESGCM(self._key).decrypt(
                nonce,
                ciphertext,
                _encryption_aad(metadata, message_type=message_type),
            )
        except Exception as exc:
            raise GatewayMessageEncryptionError("decryption_failed") from exc
        # The plaintext is a JSON text in its own right, admitted under the
        # Payload Member Rule before any member of it is read.
        try:
            decoded = admitted_object(plaintext, defined=EXPORT_RESPONSE_MEMBERS)
        except PayloadMemberError as exc:
            raise GatewayMessageEncryptionError(
                f"invalid_plaintext: {exc.reason}"
            ) from exc
        if _encryption_metadata(decoded) != metadata:
            raise GatewayMessageEncryptionError("metadata_mismatch")
        return decoded


def _wall_now_ms() -> int:
    """This module's wall clock, read when called, so a patch of `now_ms`
    here reaches a default signing clock built before it."""
    return now_ms()


def _payload_without_auth(payload: Mapping[str, Any]) -> dict[str, Any]:
    clean = dict(payload)
    clean.pop(AUTH_FIELD, None)
    return clean


def _canonical_json(value: Any) -> str:
    # allow_nan=False refuses NaN and Infinity, which json.dumps would otherwise
    # emit as bare NaN/Infinity tokens that no conforming JSON parser accepts --
    # the Go gateway rejects them outright, so the message would be unverifiable.
    # This is a validity constraint, not evidence/v3's D-011 agreement zone: gateway
    # MQTT carries operational telemetry whose numeric range is deliberately broader.
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _derive_encryption_key(shared_secret: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ENCRYPTION_SALT,
        info=ENCRYPTION_KEY_INFO,
    ).derive(shared_secret.encode("utf-8"))


def _encryption_metadata(payload: Mapping[str, Any]) -> dict[str, str]:
    metadata = {
        "request_id": str(payload.get("request_id", "") or "").strip(),
        "device_id": str(payload.get("device_id", "") or "").strip(),
        "export_type": str(payload.get("export_type", "") or "").strip(),
    }
    for key, value in metadata.items():
        if not value:
            raise GatewayMessageEncryptionError(f"missing_{key}")
    return metadata


def _encryption_aad(metadata: Mapping[str, str], *, message_type: str) -> bytes:
    return _canonical_json(
        {
            "message_type": str(message_type),
            "request_id": metadata["request_id"],
            "device_id": metadata["device_id"],
            "export_type": metadata["export_type"],
        }
    ).encode("utf-8")


def _b64encode(value: bytes) -> str:
    return urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return urlsafe_b64decode(padded.encode("ascii"))
