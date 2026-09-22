# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from ori.state.store import StateStore

NOW_MS = 2_000_000_000_000  # Fixed point in time


@pytest.fixture
async def store(tmp_path):
    db_file = tmp_path / "test_compaction.db"
    store = StateStore(str(db_file))
    await store.open()
    try:
        yield store
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_compaction_pyramid(store, monkeypatch):
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW_MS)

    def _insert_raw(ts: int, value: float):
        # Received when measured: the receipt is what retention is decided on.
        store._conn.execute(
            """
            INSERT INTO sensor_history
            (sensor_id, sensor_type, value, unit, timestamp, quality, received_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("s1", "temp", value, "c", ts, 1.0, ts),
        )

    # 1. New data (<48h)
    _insert_raw(NOW_MS - 3600_000, 20.0)
    _insert_raw(NOW_MS - 7200_000, 25.0)

    # 2. 5-min bucket data (>48h, <30d)
    # same 5-minute bucket
    bucket_5m = NOW_MS - 86400_000 * 3
    _insert_raw(bucket_5m, 10.0)
    _insert_raw(bucket_5m + 1000, 20.0)

    # 3. Hourly bucket data (>30d, <1y)
    bucket_1h = NOW_MS - 86400_000 * 40
    _insert_raw(bucket_1h, 100.0)

    # 4. Daily bucket data (>1y)
    bucket_1d = NOW_MS - 86400_000 * 400
    _insert_raw(bucket_1d, 500.0)

    store._conn.commit()

    await store.compact_history()

    # Verify rows in sensor_history
    raw = store._conn.execute("SELECT * FROM sensor_history").fetchall()
    assert len(raw) == 2

    # Verify rows in 5min
    five_min = store._conn.execute("SELECT * FROM sensor_history_5min").fetchall()
    assert len(five_min) == 1
    assert five_min[0]["avg_value"] == 15.0
    assert five_min[0]["sample_count"] == 2

    # Verify rows in hourly
    hourly = store._conn.execute("SELECT * FROM sensor_history_hourly").fetchall()
    assert len(hourly) == 1
    assert hourly[0]["avg_value"] == 100.0

    # Verify rows in daily
    daily = store._conn.execute("SELECT * FROM sensor_history_daily").fetchall()
    assert len(daily) == 1
    assert daily[0]["avg_value"] == 500.0


def _row_count(store, table: str) -> int:
    return store._conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]


def _insert_receipt(store, *, timestamp: int, received_at_ms: int) -> None:
    store._conn.execute(
        """
        INSERT INTO sensor_history
        (sensor_id, sensor_type, value, unit, timestamp, quality, received_at_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        ("s1", "temp", 20.0, "c", timestamp, 1.0, received_at_ms),
    )
    store._conn.commit()


_CUTOFFS = {
    "hourly": NOW_MS - 300_000,
    "5min": NOW_MS - 200_000,
    "raw": NOW_MS - 100_000,
}


@pytest.mark.asyncio
@pytest.mark.parametrize("synchronized", [None, False])
async def test_a_future_receipt_does_not_halt_compaction(store, synchronized):
    """Retention keeps running; the row is kept, since the clock may be wrong."""
    _insert_receipt(store, timestamp=NOW_MS, received_at_ms=NOW_MS + 86_400_000)
    _insert_receipt(store, timestamp=NOW_MS - 150_000, received_at_ms=NOW_MS - 150_000)

    store._compact_sync(_CUTOFFS, NOW_MS, 3_600_000, synchronized)

    remaining = store._conn.execute(
        "SELECT received_at_ms FROM sensor_history"
    ).fetchall()
    assert [row["received_at_ms"] for row in remaining] == [NOW_MS + 86_400_000]
    assert _row_count(store, "sensor_history_5min") == 1


@pytest.mark.asyncio
async def test_a_synchronized_clock_prunes_raw_receipts_beyond_the_skew_bound(store):
    """Only raw rows past the bound go; a receipt inside it is ordinary skew."""
    _insert_receipt(store, timestamp=NOW_MS, received_at_ms=NOW_MS + 3_600_001)
    _insert_receipt(store, timestamp=NOW_MS, received_at_ms=NOW_MS + 3_600_000)
    for table in (
        "sensor_history_5min",
        "sensor_history_hourly",
        "sensor_history_daily",
    ):
        store._conn.execute(
            f"""
            INSERT INTO {table}
            (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count,
             max_received_at_ms)
            VALUES ('s1', 'temp', ?, 20.0, 'c', 1, ?)
            """,
            (NOW_MS, NOW_MS + 86_400_000),
        )
    store._conn.commit()

    store._compact_sync(_CUTOFFS, NOW_MS, 3_600_000, True)

    remaining = store._conn.execute(
        "SELECT received_at_ms FROM sensor_history"
    ).fetchall()
    assert [row["received_at_ms"] for row in remaining] == [NOW_MS + 3_600_000]
    # A bucket's receipt is the greatest of its samples; pruning it would take
    # the ordinary samples merged with the suspect one.
    for table in (
        "sensor_history_5min",
        "sensor_history_hourly",
        "sensor_history_daily",
    ):
        assert _row_count(store, table) == 1, table


@pytest.mark.asyncio
async def test_a_producer_clock_in_the_future_is_not_a_receipt(store):
    """Only a receipt is the host's own clock; a reading's date prunes nothing."""
    _insert_receipt(store, timestamp=NOW_MS + 86_400_000, received_at_ms=NOW_MS)

    store._compact_sync(_CUTOFFS, NOW_MS, 3_600_000, True)

    assert _row_count(store, "sensor_history") == 1


@pytest.mark.asyncio
async def test_unified_read_paths(store, monkeypatch):
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW_MS)

    # Insert raw
    store._conn.execute(
        "INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, timestamp, quality, received_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("s1", "temp", 10.0, "c", NOW_MS - 1000, 1.0, NOW_MS - 1000),
    )
    # Insert 5min
    store._conn.execute(
        "INSERT INTO sensor_history_5min (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count, max_received_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("s1", "temp", NOW_MS - 86400_000 * 3, 20.0, "c", 2, NOW_MS - 86400_000 * 3),
    )
    store._conn.commit()

    # The 7 day average should cover both.
    # Weighted average: (10*1 + 20*2) / (1 + 2) = 50 / 3 = 16.666
    avg = await store.avg_last_hours("s1", 24 * 7)
    assert abs(avg - 16.666) < 0.01

    # Timeseries for 30 days should hit 5min table
    ts = await store.get_timeseries("s1", NOW_MS - 86400_000 * 10, NOW_MS)
    assert len(ts) == 1
    assert ts[0][1] == 20.0


@pytest.mark.asyncio
async def test_compaction_uses_weighted_average_for_hourly(store, monkeypatch):
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW_MS)
    bucket = NOW_MS - 86400_000 * 40
    hour_bucket = (bucket // 3_600_000) * 3_600_000
    store._conn.execute(
        "INSERT INTO sensor_history_5min (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count, max_received_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("s1", "temp", hour_bucket, 10.0, "c", 1, hour_bucket),
    )
    store._conn.execute(
        "INSERT INTO sensor_history_5min (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count, max_received_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("s1", "temp", hour_bucket + 300_000, 20.0, "c", 9, hour_bucket + 300_000),
    )
    store._conn.commit()

    await store.compact_history()

    hourly = store._conn.execute(
        "SELECT avg_value, sample_count FROM sensor_history_hourly WHERE sensor_id = ?",
        ("s1",),
    ).fetchone()
    assert hourly["avg_value"] == pytest.approx(19.0)
    assert hourly["sample_count"] == 10


@pytest.mark.asyncio
async def test_compaction_uses_weighted_average_for_daily(store, monkeypatch):
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW_MS)
    bucket = NOW_MS - 86400_000 * 400
    day_bucket = (bucket // 86_400_000) * 86_400_000
    store._conn.execute(
        "INSERT INTO sensor_history_hourly (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count, max_received_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("s1", "temp", day_bucket, 10.0, "c", 1, day_bucket),
    )
    store._conn.execute(
        "INSERT INTO sensor_history_hourly (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count, max_received_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("s1", "temp", day_bucket + 3_600_000, 20.0, "c", 9, day_bucket + 3_600_000),
    )
    store._conn.commit()

    await store.compact_history()

    daily = store._conn.execute(
        "SELECT avg_value, sample_count FROM sensor_history_daily WHERE sensor_id = ?",
        ("s1",),
    ).fetchone()
    assert daily["avg_value"] == pytest.approx(19.0)
    assert daily["sample_count"] == 10


@pytest.mark.asyncio
async def test_a_bucket_mixing_a_future_receipt_with_ordinary_ones_is_kept(store):
    """Eighteen ordinary samples and one suspect receipt share a bucket."""
    store._conn.execute(
        """
        INSERT INTO sensor_history_5min
        (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count,
         max_received_at_ms)
        VALUES ('s1', 'temp', ?, 20.0, 'c', 18, ?)
        """,
        (NOW_MS - 3 * 86_400_000, NOW_MS + 86_400_000),
    )
    store._conn.commit()

    store._compact_sync(_CUTOFFS, NOW_MS, 3_600_000, True)

    row = store._conn.execute("SELECT sample_count FROM sensor_history_5min").fetchone()
    assert row is not None and row["sample_count"] == 18


@pytest.mark.asyncio
async def test_a_kept_future_receipt_is_reported_on_change_and_daily(store, caplog):
    """A condition that persists is not a warning every five minutes."""
    day = 86_400_000
    _insert_receipt(store, timestamp=NOW_MS, received_at_ms=NOW_MS + 10 * day)
    with caplog.at_level("WARNING", logger="ori.state.store"):
        store._compact_sync(_CUTOFFS, NOW_MS, 3_600_000, None)
        store._compact_sync(_CUTOFFS, NOW_MS + 300_000, 3_600_000, None)
        assert len(caplog.records) == 1
        _insert_receipt(store, timestamp=NOW_MS, received_at_ms=NOW_MS + 11 * day)
        store._compact_sync(_CUTOFFS, NOW_MS + 600_000, 3_600_000, None)
        assert len(caplog.records) == 2
        store._compact_sync(_CUTOFFS, NOW_MS + 600_000 + day, 3_600_000, None)
        assert len(caplog.records) == 3


@pytest.mark.asyncio
async def test_a_future_receipt_is_left_out_of_an_hours_average(store, monkeypatch):
    """Its age is unknown, so it is not inside any window measured from now."""
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW_MS)
    _insert_receipt(store, timestamp=NOW_MS - 60_000, received_at_ms=NOW_MS - 60_000)
    store._conn.execute(
        "UPDATE sensor_history SET value = 10.0 WHERE received_at_ms = ?",
        (NOW_MS - 60_000,),
    )
    _insert_receipt(
        store, timestamp=NOW_MS - 60_000, received_at_ms=NOW_MS + 86_400_000
    )
    store._conn.commit()

    assert await store.avg_last_hours("s1", 1) == pytest.approx(10.0)


@pytest.mark.asyncio
async def test_a_future_receipt_is_not_a_fresh_latest_reading(store, monkeypatch):
    """The sensor's latest arrival carries a receipt the clock has not reached."""
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW_MS)
    _insert_receipt(
        store, timestamp=NOW_MS - 60_000, received_at_ms=NOW_MS + 86_400_000
    )

    snapshot = await store.get_latest_readings_snapshot(
        exclude_sensor_id="other", since_ms=NOW_MS - 3_600_000, max_entries=10
    )

    assert snapshot == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "table", ["sensor_history_5min", "sensor_history_hourly", "sensor_history_daily"]
)
async def test_a_future_bucket_is_left_out_of_an_hours_average(
    store, monkeypatch, table
):
    """The age bound applies to every tier the window reads, not only raw."""
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW_MS)
    _insert_receipt(store, timestamp=NOW_MS - 60_000, received_at_ms=NOW_MS - 60_000)
    store._conn.execute("UPDATE sensor_history SET value = 10.0")
    store._conn.execute(
        f"""
        INSERT INTO {table}
        (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count,
         max_received_at_ms)
        VALUES ('s1', 'temp', ?, 99.0, 'c', 50, ?)
        """,
        (NOW_MS - 600_000, NOW_MS + 86_400_000),
    )
    store._conn.commit()

    assert await store.avg_last_hours("s1", 1) == pytest.approx(10.0)


@pytest.mark.asyncio
@pytest.mark.parametrize(("ahead_ms", "counted"), [(30_000, True), (61_000, False)])
async def test_the_hours_average_tolerates_a_receipt_just_ahead(
    store, monkeypatch, ahead_ms, counted
):
    """Within the read tolerance a receipt counts; beyond it, it does not."""
    from ori.state.store import RECEIPT_READ_TOLERANCE_MS

    assert RECEIPT_READ_TOLERANCE_MS == 60_000
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW_MS)
    _insert_receipt(store, timestamp=NOW_MS - 60_000, received_at_ms=NOW_MS - 60_000)
    store._conn.execute("UPDATE sensor_history SET value = 10.0")
    _insert_receipt(store, timestamp=NOW_MS - 30_000, received_at_ms=NOW_MS + ahead_ms)
    store._conn.execute(
        "UPDATE sensor_history SET value = 30.0 WHERE received_at_ms = ?",
        (NOW_MS + ahead_ms,),
    )
    store._conn.commit()

    expected = 20.0 if counted else 10.0
    assert await store.avg_last_hours("s1", 1) == pytest.approx(expected)


@pytest.mark.asyncio
@pytest.mark.parametrize(("ahead_ms", "counted"), [(30_000, True), (61_000, False)])
async def test_the_latest_snapshot_tolerates_a_receipt_just_ahead(
    store, monkeypatch, ahead_ms, counted
):
    """A small backward clock step must not make a live sensor vanish."""
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW_MS)
    _insert_receipt(store, timestamp=NOW_MS - 30_000, received_at_ms=NOW_MS + ahead_ms)

    snapshot = await store.get_latest_readings_snapshot(
        exclude_sensor_id="other", since_ms=NOW_MS - 3_600_000, max_entries=10
    )

    assert (len(snapshot) == 1) is counted


def test_the_compaction_skew_can_never_fall_below_the_read_tolerance(tmp_path):
    """A prune on a synchronized clock must not delete rows readers still admit."""
    from ori.config import ConfigValidationError, _parse_state
    from ori.state.store import RECEIPT_READ_TOLERANCE_MS

    with pytest.raises(ConfigValidationError, match=str(RECEIPT_READ_TOLERANCE_MS)):
        _parse_state(
            {"compaction": {"max_backward_skew_ms": RECEIPT_READ_TOLERANCE_MS - 1}}
        )


@pytest.mark.asyncio
async def test_a_pruned_row_is_not_reported_as_kept(store, caplog):
    """The warning names what was kept, and a pruned row is not among it."""
    _insert_receipt(store, timestamp=NOW_MS, received_at_ms=NOW_MS + 86_400_000)
    with caplog.at_level("WARNING", logger="ori.state.store"):
        store._compact_sync(_CUTOFFS, NOW_MS, 3_600_000, True)
    messages = [record.getMessage() for record in caplog.records]
    assert any("pruned 1 raw readings" in m for m in messages), messages
    assert not any("is kept" in m for m in messages), messages


@pytest.mark.asyncio
async def test_a_cleared_condition_is_reported_again_when_it_returns(store, caplog):
    """Once nothing is kept, the next future receipt is new, not a repeat."""
    day = 86_400_000
    _insert_receipt(store, timestamp=NOW_MS, received_at_ms=NOW_MS + 10 * day)
    with caplog.at_level("WARNING", logger="ori.state.store"):
        store._compact_sync(_CUTOFFS, NOW_MS, 3_600_000, None)
        store._compact_sync(_CUTOFFS, NOW_MS, 3_600_000, True)
        _insert_receipt(store, timestamp=NOW_MS, received_at_ms=NOW_MS + 10 * day)
        store._compact_sync(_CUTOFFS, NOW_MS + 300_000, 3_600_000, None)
    kept = [r for r in caplog.records if "is kept" in r.getMessage()]
    assert len(kept) == 2
