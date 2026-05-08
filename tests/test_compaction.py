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
        store._conn.execute(
            """
            INSERT INTO sensor_history
            (sensor_id, sensor_type, value, unit, timestamp, quality)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("s1", "temp", value, "c", ts, 1.0),
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


@pytest.mark.asyncio
async def test_clock_skew_guard(store, monkeypatch):
    # Guardrail: if host clock moves backward relative to persisted history,
    # compaction must refuse to delete data.
    now = 2_000_000_000_000
    future_ts = now + 4_000_000
    store._conn.execute(
        """
        INSERT INTO sensor_history
        (sensor_id, sensor_type, value, unit, timestamp, quality)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        ("s1", "temp", 20.0, "c", future_ts, 1.0),
    )
    store._conn.commit()

    cutoffs = {
        "hourly": now - 300_000,
        "5min": now - 200_000,
        "raw": now - 100_000,
    }
    with pytest.raises(RuntimeError, match="Clock skew detected"):
        store._compact_sync(cutoffs, now)


@pytest.mark.asyncio
async def test_unified_read_paths(store, monkeypatch):
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW_MS)

    # Insert raw
    store._conn.execute(
        "INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, timestamp, quality) VALUES (?, ?, ?, ?, ?, ?)",
        ("s1", "temp", 10.0, "c", NOW_MS - 1000, 1.0),
    )
    # Insert 5min
    store._conn.execute(
        "INSERT INTO sensor_history_5min (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count) VALUES (?, ?, ?, ?, ?, ?)",
        ("s1", "temp", NOW_MS - 86400_000 * 3, 20.0, "c", 2),
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
