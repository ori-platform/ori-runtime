# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""gateway-api/v2 The floor: a store that cannot be read or written refuses.

Every fault here is real: another connection holds the store's lock.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest

from ori.security import gateway_messages
from ori.security.gateway_messages import GatewayReplayCache


@pytest.fixture(autouse=True)
def _short_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway_messages, "_STORE_BUSY_TIMEOUT_MS", 20)


def _cache(db: Path, **kwargs: Any) -> GatewayReplayCache:
    kwargs.setdefault("start_ms", 0)
    return GatewayReplayCache(ttl_ms=1, max_skew_ms=300, db_path=str(db), **kwargs)


def _admit(cache: GatewayReplayCache, key: str, at_ms: int) -> str | None:
    return cache.admit(
        key, signed_at_ms=at_ms, received_at_ms=at_ms, now_ms_value=at_ms
    )


class _Lock:
    def __init__(self, db: Path) -> None:
        self.conn = sqlite3.connect(db, isolation_level=None)
        self.conn.execute("BEGIN EXCLUSIVE")

    def release(self) -> None:
        self.conn.execute("ROLLBACK")
        self.conn.close()


def _stored(db: Path) -> tuple[Any, list[str]]:
    conn = sqlite3.connect(db)
    try:
        floor = conn.execute("SELECT floor_ms FROM gateway_replay_floor").fetchone()
        keys = [row[0] for row in conn.execute("SELECT key FROM gateway_replay_cache")]
    finally:
        conn.close()
    return (None if floor is None else floor[0]), sorted(keys)


def test_a_raise_the_store_cannot_take_keeps_its_key_held(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    cache = _cache(db)
    try:
        assert _admit(cache, "a", 1_000) is None
        lock = _Lock(db)
        try:
            cache.prune(2_000)
            assert cache.unreadable
            assert list(cache._held) == ["a"] and cache.floor_ms() == 0
            assert _admit(cache, "b", 2_000) == "before_replay_floor"
        finally:
            lock.release()
        assert _stored(db) == (None, ["a"])
        assert cache.refresh()
        cache.prune(2_000)
        assert cache.floor_ms() == 1_001 and cache._held == {}
        assert _stored(db) == (1_001, [])
    finally:
        cache.close()


def test_an_eviction_the_store_cannot_take_keeps_its_key_held(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    cache = _cache(db)
    try:
        assert _admit(cache, "a", 1_000) is None
        lock = _Lock(db)
        try:
            cache.evict_one()
        finally:
            lock.release()
        assert cache.unreadable and list(cache._held) == ["a"]
        assert cache.floor_ms() == 0
    finally:
        cache.close()


def test_a_full_cache_whose_eviction_fails_admits_nothing(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    cache = _cache(db, max_entries=1)
    try:
        assert _admit(cache, "a", 1_000) is None
        assert cache._conn is not None
        cache._conn.execute("PRAGMA busy_timeout = 20")
        lock = _Lock(db)
        try:
            assert _admit(cache, "b", 1_100) == "before_replay_floor"
        finally:
            lock.release()
        assert list(cache._held) == ["a"] and cache.floor_ms() == 0
        assert _stored(db) == (None, ["a"])
    finally:
        cache.close()


def test_nothing_reaches_the_store_while_it_cannot_be_read(tmp_path: Path) -> None:
    """The verifying path refuses at once: it never waits on the store."""
    db = tmp_path / "state.db"
    cache = _cache(db)
    try:
        assert _admit(cache, "held", 500) is None
        lock = _Lock(db)
        try:
            assert not cache.refresh()
        finally:
            lock.release()

        def _touched(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("the store was touched")

        class _Untouchable:
            # Every connection entry point the cache uses; none may run.
            execute = executemany = commit = rollback = close = staticmethod(_touched)

            @property
            def in_transaction(self) -> bool:
                raise AssertionError("the store was touched")

        real, cache._conn = cache._conn, _Untouchable()  # type: ignore[assignment]
        try:
            assert _admit(cache, "a", 1_000) == "before_replay_floor"
            assert cache.check("a", signed_at_ms=1_000) == "before_replay_floor"
            cache.prune(10_000)
            cache.evict_one()
            # A prune here would drop "held": nothing is dropped either.
            assert _admit(cache, "b", 10_000) == "before_replay_floor"
            assert list(cache._held) == ["held"] and cache.floor_ms() == 0
        finally:
            cache._conn = real
    finally:
        cache.close()


def test_a_receiver_that_stores_nothing_reads_and_never_writes(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    earlier = _cache(db)
    assert _admit(earlier, "a", 1_000) is None
    earlier.prune(2_000)
    earlier.close()
    before = hashlib.sha256(db.read_bytes()).hexdigest()

    cache = _cache(db, stores=False)
    try:
        assert not cache.persistent and cache.floor_ms() == 1_001
        assert _admit(cache, "b", 1_001) is None
        cache.prune(5_000)
        assert cache.floor_ms() == 1_002
    finally:
        cache.close()
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    assert sorted(p.name for p in tmp_path.iterdir() if "wal" in p.name) == []


def test_a_receiver_that_stores_nothing_creates_no_store(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    cache = _cache(db, stores=False)
    try:
        assert not cache.unreadable and cache.floor_ms() == 0
    finally:
        cache.close()
    assert list(tmp_path.iterdir()) == []


def test_a_store_with_no_floor_table_holds_no_floor(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    sqlite3.connect(db).close()
    cache = _cache(db, stores=False, start_ms=7)
    try:
        assert not cache.unreadable and cache.floor_ms() == 7
    finally:
        cache.close()


def test_a_floor_that_is_not_an_integer_cannot_be_read(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    _cache(db).close()
    conn = sqlite3.connect(db)
    with conn:
        conn.execute("INSERT INTO gateway_replay_floor (id, floor_ms) VALUES (1, 'x')")
    conn.close()
    cache = _cache(db, stores=False)
    try:
        assert cache.unreadable
        assert _admit(cache, "a", 1_000) == "before_replay_floor"
    finally:
        cache.close()


def test_the_store_is_tried_again_off_the_verifying_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gateway_messages, "_FLOOR_READ_INTERVAL_S", 0.01)
    db = tmp_path / "state.db"
    cache = _cache(db)
    try:
        lock = _Lock(db)
        try:
            assert not cache.refresh()
            watch = cache._watch
            assert watch is not None and watch.is_alive()
            assert watch is not threading.current_thread()
            assert cache.unreadable
        finally:
            lock.release()
        watch.join(timeout=5)
        assert not watch.is_alive() and not cache.unreadable
        assert _admit(cache, "a", 1_000) is None
    finally:
        cache.close()


def test_a_store_unreadable_at_the_start_loads_once_it_answers(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    earlier = _cache(db)
    assert _admit(earlier, "a", 1_000) is None
    earlier.close()
    lock = _Lock(db)
    try:
        cache = _cache(db, start_ms=500)
        assert cache.unreadable and cache.floor_ms() == 500
    finally:
        lock.release()
    try:
        assert cache.refresh()
        assert _admit(cache, "a", 1_000) == "replay_detected"
    finally:
        cache.close()


def test_a_refresh_never_lowers_the_floor(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    cache = _cache(db)
    try:
        assert _admit(cache, "a", 1_000) is None
        cache.prune(2_000)
        conn = sqlite3.connect(db)
        with conn:
            conn.execute("UPDATE gateway_replay_floor SET floor_ms = 5")
        conn.close()
        assert cache.refresh()
        assert cache.floor_ms() == 1_001
    finally:
        cache.close()


def test_a_store_that_reads_but_cannot_write_has_not_answered(tmp_path: Path) -> None:
    """A failed raise ends only once the write can succeed too."""
    db = tmp_path / "state.db"
    cache = _cache(db)
    try:
        holder = sqlite3.connect(db, isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")
        try:
            assert sqlite3.connect(db).execute("SELECT 1").fetchone() == (1,)
            assert not cache.refresh()
        finally:
            holder.execute("ROLLBACK")
            holder.close()
        assert cache.refresh()
    finally:
        cache.close()


def test_a_store_that_takes_the_lock_but_not_a_write_has_not_answered(
    tmp_path: Path,
) -> None:
    """A read-only store grants the write lock and fails the write itself."""
    db = tmp_path / "state.db"
    cache = _cache(db)
    try:
        db.chmod(0o444)
        try:
            assert not cache.refresh() and cache.unreadable
        finally:
            db.chmod(0o600)
        assert cache.refresh() and not cache.unreadable
    finally:
        cache.close()


@pytest.mark.parametrize(
    "corrupt",
    [
        "UPDATE gateway_replay_floor SET floor_ms = 'x'",
        "UPDATE gateway_replay_floor SET floor_ms = 1500.5",
        "UPDATE gateway_replay_cache SET seen_until_ms = 'x'",
        "UPDATE gateway_replay_cache SET signed_at_ms = x'00'",
        "UPDATE gateway_replay_cache SET received_at_ms = 2.5",
    ],
)
def test_a_store_holding_a_row_it_cannot_read_is_unreadable_at_the_start(
    tmp_path: Path, corrupt: str
) -> None:
    db = tmp_path / "state.db"
    earlier = _cache(db)
    assert _admit(earlier, "a", 1_000) is None
    assert _admit(earlier, "b", 1_100) is None
    earlier.prune(1_350)  # drops "a", raising the floor; "b" stays stored
    earlier.close()
    conn = sqlite3.connect(db)
    with conn:
        conn.execute(corrupt)
    conn.close()
    cache = _cache(db, start_ms=2_000)
    try:
        assert cache.unreadable and cache._held == {}
        assert _admit(cache, "c", 2_000) == "before_replay_floor"
    finally:
        cache.close()


def test_a_key_is_held_only_once_the_store_has_it(tmp_path: Path) -> None:
    """The store refuses the key inside the transaction, after it began."""
    db = tmp_path / "state.db"
    cache = _cache(db)
    try:
        assert cache._conn is not None
        cache._conn.execute(
            "CREATE TEMP TRIGGER refuse_key BEFORE INSERT ON gateway_replay_cache "
            "BEGIN SELECT RAISE(ABORT, 'disk I/O'); END"
        )
        assert _admit(cache, "a", 1_000) == "before_replay_floor"
        assert cache._held == {} and cache.unreadable
    finally:
        cache.close()


def test_a_refresh_after_close_takes_nothing_back(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    lock = _Lock(db)
    try:
        cache = _cache(db)
        assert cache.unreadable
    finally:
        lock.release()
    cache.close()
    assert not cache.refresh()
    assert cache._conn is None and cache._ownership is None


def test_a_refresh_never_waits_under_the_verifying_lock(tmp_path: Path) -> None:
    """The store taken again between the probe and the load refuses at once."""
    db = tmp_path / "state.db"
    lock = _Lock(db)
    try:
        cache = _cache(db, start_ms=0)
    finally:
        lock.release()
    gateway_messages._STORE_BUSY_TIMEOUT_MS = 2_000  # restored by the fixture
    probe = cache._probe
    taken: list[_Lock] = []

    def probe_then_lose_the_store() -> Any:
        floor = probe()
        taken.append(_Lock(db))
        return floor

    cache._probe = probe_then_lose_the_store  # type: ignore[method-assign]
    connect = sqlite3.connect
    waits: list[float] = []

    def recording_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        waits.append(kwargs.get("timeout", 5.0))
        return connect(*args, **kwargs)

    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(gateway_messages.sqlite3, "connect", recording_connect)
            assert not cache.refresh() and cache.unreadable
        # The probe's own connection, the test's lock, then the load under
        # the lock, which waits for nothing however long the bound.
        assert len(waits) == 3 and waits[-1] == 0.0
        assert cache._conn is None
    finally:
        for held in taken:
            held.release()
        cache.close()


def test_a_failure_as_the_watch_ends_keeps_the_store_watched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An admission that fails after the watch saw the store answer, before
    it ended: the watch stays, so the store is still tried again."""
    monkeypatch.setattr(gateway_messages, "_FLOOR_READ_INTERVAL_S", 1_000.0)
    db = tmp_path / "state.db"
    lock = _Lock(db)
    try:
        cache = _cache(db)
    finally:
        lock.release()
    closed = cache._closed
    try:
        refresh = cache.refresh

        def refresh_then_fail() -> bool:
            answered = refresh()
            blocker = _Lock(db)
            try:
                assert _admit(cache, "a", 1_000) == "before_replay_floor"
            finally:
                blocker.release()
            return answered

        class _OneTick:
            def __init__(self) -> None:
                self.ticks = 0

            def wait(self, _timeout: float) -> bool:
                self.ticks += 1
                return self.ticks > 1

            def is_set(self) -> bool:
                return False

        cache.refresh = refresh_then_fail  # type: ignore[method-assign]
        cache._closed = _OneTick()  # type: ignore[assignment]
        cache._watch_store()
        assert cache.unreadable and cache._watch is not None
    finally:
        cache._closed = closed
        cache.close()


@pytest.mark.parametrize("persistent", [True, False])
def test_the_runtime_builder_reads_a_stored_floor_and_writes_only_when_storing(
    tmp_path: Path, persistent: bool
) -> None:
    from types import SimpleNamespace

    from ori.config import DeviceConfig, GatewayConfig
    from ori.gateway.envelope_auth import build_gateway_envelope_state

    db = tmp_path / "state.db"
    # Ahead of any clock this runs on, so only a read explains the floor.
    ahead = 2**50
    earlier = _cache(db)
    assert _admit(earlier, "a", ahead) is None
    earlier.prune(ahead + 1_000)
    earlier.close()
    config: Any = SimpleNamespace(
        database_path=str(db),
        gateway=GatewayConfig(
            enabled=True,
            broker_url="mqtt://broker.local",
            auth={
                "enabled": True,
                "shared_secret_env": "GATEWAY_SHARED_SECRET",
                "max_clock_skew_ms": 300,
                "persistent_replay_cache": persistent,
            },
        ),
        device=DeviceConfig(
            id="d", name="d", location="l", deployment_profile="development"
        ),
        security={},
    )
    state = build_gateway_envelope_state(config)
    assert state is not None
    cache = state.replay_cache
    try:
        assert cache.persistent is persistent and not cache.unreadable
        assert cache.floor_ms() == ahead + 1
        assert _admit(cache, "b", ahead + 1) is None
    finally:
        state.close()
    floor, keys = _stored(db)
    assert floor == ahead + 1
    assert keys == (["b"] if persistent else [])


def test_a_store_whose_commit_fails_has_not_answered(tmp_path: Path) -> None:
    """A reader's shared lock lets the write lock and the write through and
    refuses only the commit: the probe must commit to see it."""
    db = tmp_path / "state.db"
    cache = _cache(db)
    try:
        reader = sqlite3.connect(db, isolation_level=None)
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM gateway_replay_floor").fetchall()
        try:
            assert not cache.refresh()
        finally:
            reader.execute("ROLLBACK")
            reader.close()
        assert cache.refresh()
    finally:
        cache.close()


def test_a_store_recovered_from_a_start_fault_waits_its_ordinary_bound(
    tmp_path: Path,
) -> None:
    db = tmp_path / "state.db"
    lock = _Lock(db)
    try:
        cache = _cache(db)
    finally:
        lock.release()
    try:
        assert cache.refresh() and cache._conn is not None
        (timeout,) = cache._conn.execute("PRAGMA busy_timeout").fetchone()
        assert timeout == gateway_messages._STORE_BUSY_TIMEOUT_MS
    finally:
        cache.close()


def test_an_unreadable_store_says_so_rather_than_naming_a_clock(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from ori.security.gateway_messages import (
        GatewayMessageAuthConfig,
        GatewayMessageAuthenticator,
        GatewayMessageAuthError,
    )

    db = tmp_path / "state.db"
    lock = _Lock(db)
    cache = _cache(db, start_ms=0)
    try:
        auth = GatewayMessageAuthenticator(
            GatewayMessageAuthConfig(shared_secret="s", max_skew_ms=300),
            replay_cache=cache,
        )
        envelope = auth.sign(
            {"device_id": "d", "request_id": "r"},
            message_type="export_request",
            signed_at_ms=50_000,
        )
        with caplog.at_level("WARNING"), pytest.raises(GatewayMessageAuthError):
            auth.verify(
                envelope,
                message_type="export_request",
                expected_device_id="d",
                now_ms_value=50_000,
            )
    finally:
        lock.release()
        cache.close()
    assert "cannot be read or written" in caplog.text
    assert "clocks pass it" not in caplog.text


def test_a_refresh_after_close_touches_no_store(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    cache = _cache(db)
    cache.close()
    db.unlink()
    assert not cache.refresh()
    assert _admit(cache, "a", 1_000) == "before_replay_floor"
    assert not db.exists() and cache._watch is None


def test_close_waits_for_a_probe_in_flight(tmp_path: Path) -> None:
    """No probe touches the store once close() has released it."""
    db = tmp_path / "state.db"
    cache = _cache(db)
    lock = _Lock(db)
    try:
        assert not cache.refresh()
    finally:
        lock.release()
    entered, proceed = threading.Event(), threading.Event()
    probe = cache._probe
    order: list[str] = []

    def slow_probe() -> Any:
        entered.set()
        proceed.wait(5)
        floor = probe()
        order.append("probe")
        return floor

    cache._probe = slow_probe  # type: ignore[method-assign]
    worker = threading.Thread(target=cache.refresh)
    worker.start()
    assert entered.wait(5)
    closer = threading.Thread(target=lambda: (cache.close(), order.append("close")))
    closer.start()
    closer.join(0.2)
    assert closer.is_alive()  # held back by the probe
    proceed.set()
    worker.join(5)
    closer.join(5)
    assert order == ["probe", "close"]
    assert cache._conn is None and cache._ownership is None


def test_a_failed_startup_eviction_changes_nothing(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    earlier = _cache(db)
    assert _admit(earlier, "a", 1_000) is None
    assert _admit(earlier, "b", 1_100) is None
    earlier.close()
    conn = sqlite3.connect(db)
    with conn:
        conn.execute(
            "CREATE TRIGGER refuse_delete BEFORE DELETE ON gateway_replay_cache "
            "BEGIN SELECT RAISE(ABORT, 'disk I/O'); END"
        )
    conn.close()
    cache = _cache(db, max_entries=1)
    try:
        assert cache.unreadable
        assert sorted(cache._held) == ["a", "b"] and cache.floor_ms() == 0
        assert _stored(db) == (None, ["a", "b"])
    finally:
        cache.close()


def test_a_store_that_cannot_be_opened_is_unreadable_not_owned(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    _cache(db).close()
    db.chmod(0o444)
    try:
        cache = _cache(db)
        try:
            assert cache.unreadable and cache._ownership is None
            assert _admit(cache, "a", 1_000) == "before_replay_floor"
        finally:
            cache.close()
    finally:
        db.chmod(0o600)


def test_another_owner_still_refuses_the_start(tmp_path: Path) -> None:
    from ori.security.gateway_messages import ReplayStoreOwnedError

    db = tmp_path / "state.db"
    owner = _cache(db)
    try:
        with pytest.raises(ReplayStoreOwnedError):
            _cache(db)
    finally:
        owner.close()
