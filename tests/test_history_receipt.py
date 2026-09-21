# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The store ranks its history on its own receipts, never on a producer's clock.

Five adapters copy a remote node's `timestamp_ms` into a reading unchanged,
which is right: the reading's own time is the only account anyone has of when
the world was measured. What that clock may never do is decide which reading
is current, how fresh the store's picture is, or what compaction keeps. Those
are the store's own facts, established by `received_at_ms` at insert and by
`id`, which is the exact arrival order. The producer time is kept raw, is
shown beside the receipt under its own name, and contributes to an age in one
direction only: it may make a record look older, never fresher.

The inventory at the bottom is the guard for the class rather than the
instance: every SQL clause in the store that orders, aggregates, compares or
buckets on a producer-time column is classified with the reason it is not a
ranking, and an unclassified one fails the suite.
"""

from __future__ import annotations

import ast
import logging
import re
import sqlite3
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from ori.network.events import OriEvent, SensorReading, StoredReading
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.elevator import SkillContext
from ori.skills.loader import SkillLoader, SkillValidationError
from ori.state.store import StateStore
from tests.test_action_dispatcher import FakeSkill, _result

ROOT = Path(__file__).resolve().parents[1]
NOW = 2_000_000_000_000
FAR_FUTURE = 9_007_199_254_740_991
HOUR = 3_600_000


def _reading(
    value: float, timestamp: int = NOW, sensor_id: str = "s1"
) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type="current",
        value=value,
        unit="ampere",
        timestamp=timestamp,
        quality=1.0,
    )


def _event(reading: SensorReading) -> OriEvent:
    return OriEvent.from_reading(reading, "dev-01")


@pytest.fixture
async def store(tmp_path):
    state = StateStore(str(tmp_path / "receipt.db"))
    await state.open()
    try:
        yield state
    finally:
        await state.close()


async def _append_at(
    store: StateStore, monkeypatch, received_at: int, reading: SensorReading
) -> None:
    """Insert with the store's clock pinned, so the receipt is chosen by the test."""
    monkeypatch.setattr("ori.state.store.now_ms", lambda: received_at)
    await store.append_history(_event(reading))


# ─── Rankings ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_far_future_producer_timestamp_never_becomes_current(
    store, monkeypatch
):
    """One poisoned reading followed by honest ones leaves the honest ones on top."""
    await _append_at(store, monkeypatch, NOW, _reading(1000.0, timestamp=FAR_FUTURE))
    for i, value in enumerate((10.0, 11.0, 12.0, 13.0), start=1):
        await _append_at(store, monkeypatch, NOW + i, _reading(value))

    assert await store.avg_last_n("s1", 3) == pytest.approx(12.0)
    latest = await store.get_history("s1", limit=1)
    assert latest[0].value == 13.0
    assert latest[0].timestamp == NOW, "the producer time is kept raw on the row"
    assert isinstance(latest[0], StoredReading) and latest[0].received_at_ms == NOW + 4

    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW + 5)
    await _append_at(store, monkeypatch, NOW + 5, _reading(7.0, sensor_id="other"))
    snapshot = await store.get_latest_readings_snapshot(
        exclude_sensor_id="other", since_ms=NOW, max_entries=10
    )
    assert [(r.sensor_id, r.value) for r in snapshot] == [("s1", 13.0)]


@pytest.mark.asyncio
async def test_latest_is_arrival_order_even_across_a_host_clock_step_back(
    store, monkeypatch
):
    """A host clock stepping back must not hold a stale reading as current.

    Ranking on the receipt time with an id tie-break would present the reading
    received before the step as the latest for as long as the step lasts;
    ranking on arrival order does not.
    """
    await _append_at(store, monkeypatch, NOW, _reading(1.0))
    await _append_at(store, monkeypatch, NOW - 2 * HOUR, _reading(2.0))

    assert (await store.get_history("s1", limit=1))[0].value == 2.0
    assert await store.avg_last_n("s1", 1) == 2.0


@pytest.mark.asyncio
async def test_the_freshness_window_is_an_age_bounded_on_both_clocks(
    store, monkeypatch
):
    """Fresh context was both received and measured inside the window.

    A reading received long ago is stale however recent its clock says it is,
    and a late flush of an old measurement is stale however recently it
    arrived: the producer's clock can make a reading older, never fresher.
    """
    await _append_at(
        store,
        monkeypatch,
        NOW - 10 * HOUR,
        _reading(1.0, timestamp=NOW, sensor_id="old-receipt"),
    )
    await _append_at(
        store,
        monkeypatch,
        NOW,
        _reading(2.0, timestamp=NOW - 10 * HOUR, sensor_id="late-flush"),
    )
    await _append_at(
        store,
        monkeypatch,
        NOW,
        _reading(3.0, timestamp=NOW - HOUR // 2, sensor_id="fresh"),
    )

    snapshot = await store.get_latest_readings_snapshot(
        exclude_sensor_id="none", since_ms=NOW - HOUR, max_entries=10
    )
    assert [r.sensor_id for r in snapshot] == ["fresh"]


@pytest.mark.asyncio
async def test_a_stale_latest_arrival_leaves_the_sensor_absent_not_represented_by_an_older_row(
    store, monkeypatch
):
    """Latest is decided before freshness: a superseded row never stands in.

    An earlier-arriving fresh reading followed by a later-arriving stale one,
    stale by the measured clock on one sensor and by the receipt on another,
    leaves both sensors out of the snapshot rather than resurrecting the
    earlier row as the sensor's current state.
    """
    await _append_at(store, monkeypatch, NOW, _reading(1.0, sensor_id="flushed"))
    await _append_at(
        store,
        monkeypatch,
        NOW + 1,
        _reading(2.0, timestamp=NOW - 10 * HOUR, sensor_id="flushed"),
    )
    await _append_at(store, monkeypatch, NOW, _reading(1.0, sensor_id="stepped"))
    await _append_at(
        store,
        monkeypatch,
        NOW - 10 * HOUR,
        _reading(2.0, timestamp=NOW, sensor_id="stepped"),
    )
    await _append_at(store, monkeypatch, NOW, _reading(9.0, sensor_id="fresh"))

    snapshot = await store.get_latest_readings_snapshot(
        exclude_sensor_id="none", since_ms=NOW - HOUR, max_entries=10
    )
    assert [(r.sensor_id, r.value) for r in snapshot] == [("fresh", 9.0)]


@pytest.mark.asyncio
async def test_within_the_last_hours_is_an_age_bounded_on_both_clocks(
    store, monkeypatch
):
    """A row is inside a window only if it was both received and measured inside it."""
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW)
    inside = _reading(10.0, timestamp=NOW - HOUR)
    late_flush = _reading(
        100.0, timestamp=NOW - 30 * HOUR
    )  # measured yesterday, received now
    await _append_at(store, monkeypatch, NOW - HOUR, inside)
    await _append_at(store, monkeypatch, NOW, late_flush)
    await _append_at(
        store, monkeypatch, NOW - 30 * HOUR, _reading(1000.0, timestamp=NOW)
    )
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW)

    assert await store.avg_last_hours("s1", 24) == pytest.approx(10.0)


@pytest.mark.asyncio
async def test_the_receipt_is_assigned_by_the_store_and_never_by_the_reading(
    store, monkeypatch
):
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW)
    smuggled = StoredReading(
        sensor_id="s1",
        sensor_type="current",
        value=1.0,
        unit="ampere",
        timestamp=NOW,
        quality=1.0,
        received_at_ms=1,
    )
    await store.append_history(_event(smuggled))
    assert (await store.get_history("s1", limit=1))[0].received_at_ms == NOW


@pytest.mark.asyncio
async def test_arrival_order_rankings_need_no_sort_pass(store):
    """The plan for every arrival-order ranking walks an index; no temp B-tree."""
    conn = store._conn
    assert conn is not None
    plans = {
        "history": "SELECT id FROM sensor_history WHERE sensor_id = ? ORDER BY id DESC LIMIT ?",
        "snapshot": (
            "SELECT sensor_id, MAX(id) FROM sensor_history "
            "WHERE sensor_id != ? AND received_at_ms >= ? GROUP BY sensor_id"
        ),
    }
    for name, sql in plans.items():
        plan = " | ".join(
            str(row[3])
            for row in conn.execute(
                f"EXPLAIN QUERY PLAN {sql}",
                ("s1", 0) if name == "snapshot" else ("s1", 5),
            )
        )
        assert "USE TEMP B-TREE FOR ORDER BY" not in plan, f"{name}: {plan}"
        assert "INDEX" in plan, f"{name}: {plan}"


# ─── Compaction ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_compaction_retires_a_poisoned_row_by_receipt_and_never_halts(
    store, monkeypatch
):
    """The row the old skew guard tripped on is now just an old row, and it leaves."""
    await _append_at(
        store, monkeypatch, NOW - 49 * HOUR, _reading(5.0, timestamp=FAR_FUTURE)
    )
    await _append_at(store, monkeypatch, NOW, _reading(6.0))
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW)

    await store.compact_history()
    await (
        store.compact_history()
    )  # a second cycle is where a halted store stayed halted

    raw = store._conn.execute("SELECT value FROM sensor_history").fetchall()
    assert [r["value"] for r in raw] == [6.0]
    bucket = store._conn.execute(
        "SELECT bucket_ms, max_received_at_ms, sample_count FROM sensor_history_5min"
    ).fetchone()
    assert bucket["bucket_ms"] == (FAR_FUTURE // 300_000) * 300_000, (
        "buckets key on measured time"
    )
    assert bucket["max_received_at_ms"] == NOW - 49 * HOUR, "retention keys on receipt"


@pytest.mark.asyncio
async def test_a_producer_timestamp_in_the_future_does_not_trip_the_host_clock_guard(
    store, monkeypatch
):
    await _append_at(store, monkeypatch, NOW, _reading(5.0, timestamp=NOW + 4 * HOUR))
    cutoffs = {"hourly": NOW - 3, "5min": NOW - 2, "raw": NOW - 1}
    await store._run_write(store._compact_sync, cutoffs, NOW, HOUR)  # does not raise


@pytest.mark.asyncio
async def test_compaction_merges_a_bucket_that_gains_samples_across_runs(
    store, monkeypatch
):
    """Two readings in one measured bucket, received across a run boundary, both survive."""
    measured = NOW - 100 * HOUR
    await _append_at(
        store, monkeypatch, NOW - 50 * HOUR, _reading(10.0, timestamp=measured)
    )
    await _append_at(
        store, monkeypatch, NOW - 47 * HOUR, _reading(30.0, timestamp=measured + 1_000)
    )

    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW)
    await store.compact_history()
    first = store._conn.execute(
        "SELECT avg_value, sample_count FROM sensor_history_5min"
    ).fetchone()
    assert (first["avg_value"], first["sample_count"]) == (10.0, 1)

    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW + 4 * HOUR)
    await store.compact_history()
    merged = store._conn.execute(
        "SELECT avg_value, sample_count, max_received_at_ms FROM sensor_history_5min"
    ).fetchall()
    assert len(merged) == 1
    assert (merged[0]["avg_value"], merged[0]["sample_count"]) == (20.0, 2)
    assert merged[0]["max_received_at_ms"] == NOW - 47 * HOUR
    assert store._conn.execute("SELECT COUNT(*) FROM sensor_history").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_every_export_row_carries_the_receipt_beside_the_producer_time(
    store, monkeypatch
):
    await _append_at(store, monkeypatch, NOW, _reading(1.0, timestamp=FAR_FUTURE))
    store._conn.execute(
        "INSERT INTO sensor_history_hourly (sensor_id, sensor_type, bucket_ms, avg_value, unit, "
        "sample_count, max_received_at_ms) VALUES ('s1', 'current', ?, 2.0, 'ampere', 4, ?)",
        (NOW - 5 * HOUR, NOW - 4 * HOUR),
    )
    store._conn.commit()

    rows = await store.export_sensor_history(
        sensor_id="s1", start_ms=0, end_ms=FAR_FUTURE
    )
    assert [(r["tier"], r["timestamp"], r["received_at_ms"]) for r in rows] == [
        ("hourly", NOW - 5 * HOUR, NOW - 4 * HOUR),
        ("raw", FAR_FUTURE, NOW),
    ]


# ─── The alert outbox ────────────────────────────────────────────────────────


async def _enqueue(store: StateStore, alert_id: str, original_ts: int) -> None:
    await store.enqueue_alert(
        alert_id=alert_id,
        channel="sms",
        recipient="+2340000000000",
        message="msg",
        action_tier="A",
        trigger_name="t",
        original_ts=original_ts,
    )


@pytest.mark.asyncio
async def test_alert_retry_order_is_arrival_and_the_summary_carries_the_queue_receipt(
    store, monkeypatch
):
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW)
    await _enqueue(store, "first", FAR_FUTURE)
    await _enqueue(store, "second", 1)

    queue = await store.get_retryable_alerts(limit=10)
    assert [item["alert_id"] for item in queue] == ["first", "second"]
    summary = await store.get_alert_outbox_summary()
    assert summary["oldest_queued_at_ms"] == NOW
    assert summary["oldest_queued_original_ts"] == 1, (
        "the producer's account, beside the receipt"
    )


# ─── Migration ───────────────────────────────────────────────────────────────


_OLD_HISTORY_SCHEMA = """
CREATE TABLE sensor_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, sensor_id TEXT NOT NULL, sensor_type TEXT NOT NULL,
    value REAL NOT NULL, unit TEXT NOT NULL, timestamp INTEGER NOT NULL, quality REAL NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_sensor_history_sensor_id_ts ON sensor_history (sensor_id, timestamp DESC);
CREATE TABLE sensor_history_5min (
    id INTEGER PRIMARY KEY AUTOINCREMENT, sensor_id TEXT NOT NULL, sensor_type TEXT NOT NULL,
    bucket_ms INTEGER NOT NULL, avg_value REAL NOT NULL, unit TEXT NOT NULL,
    sample_count INTEGER NOT NULL, UNIQUE(sensor_id, bucket_ms)
);
INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, timestamp, quality)
    VALUES ('s1', 'current', 1.0, 'ampere', 1, 1.0), ('s1', 'current', 2.0, 'ampere', 2, 1.0),
           ('s1', 'current', 3.0, 'ampere', 3, 1.0);
INSERT INTO sensor_history_5min (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count)
    VALUES ('s1', 'current', 0, 1.0, 'ampere', 2);
CREATE TABLE alert_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL UNIQUE, channel TEXT NOT NULL,
    recipient TEXT NOT NULL, message TEXT NOT NULL, action_tier TEXT NOT NULL,
    original_ts INTEGER NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 0, last_attempt_ts INTEGER,
    status TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX idx_alert_outbox_status_tier_ts ON alert_outbox (status, action_tier, original_ts ASC);
INSERT INTO alert_outbox (alert_id, channel, recipient, message, action_tier, original_ts)
    VALUES ('a', 'sms', '+1', 'm', 'A', 5);
"""


def _old_store(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(_OLD_HISTORY_SCHEMA)
    conn.commit()
    conn.close()


@pytest.mark.asyncio
async def test_opening_an_unreceipted_store_rebuilds_history_and_logs_what_it_discarded(
    tmp_path, caplog, monkeypatch
):
    path = tmp_path / "old.db"
    _old_store(path)
    monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW)

    state = StateStore(str(path), allow_history_rebuild=True)
    with caplog.at_level(logging.WARNING, logger="ori.state.store"):
        await state.open()
    try:
        conn = state._conn
        assert conn is not None
        assert "received_at_ms" in {
            r[1] for r in conn.execute("PRAGMA table_info(sensor_history)")
        }
        assert conn.execute("SELECT COUNT(*) FROM sensor_history").fetchone()[0] == 0
        assert (
            conn.execute("SELECT COUNT(*) FROM sensor_history_5min").fetchone()[0] == 0
        )
        indexes = {r[1] for r in conn.execute("PRAGMA index_list(sensor_history)")}
        assert "idx_sensor_history_sensor_id_ts" not in indexes

        # The outbox is owed, so it is migrated in place: the pre-migration row
        # gets the migration moment as its queue receipt, never its producer time.
        row = conn.execute(
            "SELECT queued_at_ms, original_ts FROM alert_outbox"
        ).fetchone()
        assert (row["queued_at_ms"], row["original_ts"]) == (NOW, 5)
        outbox_indexes = {r[1] for r in conn.execute("PRAGMA index_list(alert_outbox)")}
        assert "idx_alert_outbox_status_tier_ts" not in outbox_indexes
        assert "idx_alert_outbox_status_tier_id" in outbox_indexes
    finally:
        await state.close()

    discarded = [
        rec for rec in caplog.records if "discarded 4 rows" in rec.getMessage()
    ]
    assert discarded, [rec.getMessage() for rec in caplog.records]


@pytest.mark.asyncio
async def test_a_failed_rebuild_leaves_the_old_tables_and_their_rows(
    tmp_path, monkeypatch
):
    path = tmp_path / "old.db"
    _old_store(path)
    from ori.state import store as store_module

    real = store_module._history_rebuild_statements
    monkeypatch.setattr(
        store_module,
        "_history_rebuild_statements",
        lambda: real()[:2] + ("CREATE TABLE sensor_history (broken",),
    )
    state = StateStore(str(path), allow_history_rebuild=True)
    with pytest.raises(sqlite3.OperationalError):
        await state.open()

    conn = sqlite3.connect(path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM sensor_history").fetchone()[0] == 3
        assert "received_at_ms" not in {
            r[1] for r in conn.execute("PRAGMA table_info(sensor_history)")
        }
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_an_opener_that_did_not_ask_to_rebuild_is_refused_and_changes_nothing(
    tmp_path,
):
    """The rebuild discards rows, so only the runtime's startup may ask for it."""
    from ori.state.store import HistoryReceiptMigrationRequiredError

    path = tmp_path / "old.db"
    _old_store(path)
    state = StateStore(str(path))
    with pytest.raises(HistoryReceiptMigrationRequiredError, match="discards 4 rows"):
        await state.open()

    conn = sqlite3.connect(path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM sensor_history").fetchone()[0] == 3
        assert "received_at_ms" not in {
            r[1] for r in conn.execute("PRAGMA table_info(sensor_history)")
        }
        assert "queued_at_ms" not in {
            r[1] for r in conn.execute("PRAGMA table_info(alert_outbox)")
        }, "the outbox column is added only once the history rebuild is permitted"
    finally:
        conn.close()


def test_a_read_only_cli_query_reports_the_pending_migration_and_keeps_every_row(
    tmp_path, monkeypatch, capsys
):
    """The real entry point: `state action-log` on a store from before the receipt."""
    from ori import cli_bridge
    from tests.test_cli_bridge import _read_stdout_json, _relative_store_config

    config_path = _relative_store_config(tmp_path / "data")
    db_path = tmp_path / "data" / "ori_state.db"
    _old_store(db_path)
    monkeypatch.chdir(tmp_path)

    before = db_path.read_bytes()
    assert sorted(db_path.parent.glob("ori_state.db-*")) == []

    rc = cli_bridge.main(["state", "action-log", "--path", str(config_path), "limit=1"])
    payload = _read_stdout_json(capsys)

    assert rc != 0
    assert payload["ok"] is False
    assert payload["error"]["code"] == "state_migration_required"
    assert "Start the runtime" in payload["error"]["detail"]
    # Refused means untouched: not a header pragma, not a created table, not a
    # journal beside the file. The bytes are the oracle.
    assert db_path.read_bytes() == before
    assert sorted(db_path.parent.glob("ori_state.db-*")) == []
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM sensor_history").fetchone()[0] == 3
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert tables == {
            "sensor_history",
            "sensor_history_5min",
            "alert_outbox",
            "sqlite_sequence",
        }
    finally:
        conn.close()


# ─── The operator surfaces ───────────────────────────────────────────────────


def test_the_approval_body_names_both_clocks() -> None:
    d = ActionDispatcher(state_store=None, alert_sender=AsyncMock(), config={})
    body = d._format_approval_message(
        device_id="dev",
        timestamp_ms=NOW + 6 * HOUR,
        result=_result(action_tier="C"),
        action="open_protected_circuit",
        timeout_seconds=30,
        device_timezone="UTC",
        proposal_id="AB12CD34",
        received_at_ms=NOW,
    )
    measured = ActionDispatcher._format_local_time(NOW + 6 * HOUR, "UTC")
    detected = ActionDispatcher._format_local_time(NOW, "UTC")
    assert f"Measured: {measured}\n" in body
    assert f"Detected: {detected}\n" in body
    assert "Time:" not in body


@pytest.mark.asyncio
async def test_the_provider_template_slot_is_the_time_ori_proposed_not_the_device_clock(
    tmp_path,
):
    """ "Ori proposes {action} at {time}" is the runtime's own clock."""
    state = StateStore(str(tmp_path / "slot.db"))
    await state.open()
    try:
        sender = AsyncMock()
        d = ActionDispatcher(
            state_store=state,
            alert_sender=sender,
            config={"operator_contact": "+234800000000", "device_timezone": "UTC"},
        )
        d.register_executor("close_gas_valve", AsyncMock())
        event = _event(_reading(1.0, timestamp=NOW + 6 * HOUR))
        event.received_at_ms = NOW
        context = SkillContext(
            skill=FakeSkill(), event=event, state_store=None, trigger_name="t"
        )
        with patch.object(d, "_listen_for_response", new=AsyncMock(return_value="NO")):
            await d.dispatch(
                "close_gas_valve",
                "C",
                context,
                _result(action_tier="C"),
                approval_timeout_seconds=10,
            )
        sent = sender.send.await_args.kwargs["alert"]
        assert sent.template_variables[2] == ActionDispatcher._format_local_time(
            NOW, "UTC"
        )
    finally:
        await state.close()


@pytest.mark.asyncio
async def test_the_tier_a_template_slot_is_the_time_ori_detected_the_risk() -> None:
    """ "Ori detected configured risk: {trigger} at {time}" is the runtime's clock."""
    from ori.runtime import _format_alert_timestamp
    from tests.test_alert_preferences import _runtime_with_policy

    class _Capture:
        alert = None

        async def send(self, *, alert, to_number, preferred_channel):
            from ori.actions.alert_delivery import AlertSendReceipt

            self.alert = alert
            return AlertSendReceipt.accepted_without_provider_receipt(
                channel=preferred_channel
            )

    runtime = _runtime_with_policy(None)
    sender = _Capture()
    handled = await runtime._send_or_queue_alert(
        channel="sms",
        message="load is high",
        recipient="+2348000000000",
        action_tier="A",
        trigger_name="anomalous_draw",
        original_ts=FAR_FUTURE,
        received_at_ms=NOW,
        alert_sender=sender,  # type: ignore[arg-type]
    )
    assert handled is True
    assert sender.alert is not None
    assert sender.alert.template_variables[2] == _format_alert_timestamp(
        NOW, runtime._device_timezone
    )
    # The Tier A body is what the caller composed and carries no time line of
    # its own; the measured time reaches no Tier A operator surface.
    assert sender.alert.sms_body == "load is high"
    assert "Measured:" not in sender.alert.sms_body


@pytest.mark.asyncio
async def test_a_hook_is_handed_the_receipt_beside_the_reading_time(store, monkeypatch):
    """A hook can take the runtime's clock as now; the device's clock stays under its own name."""
    from ori.skills.hooks_api import HookContext

    await _append_at(
        store, monkeypatch, NOW - HOUR, _reading(1.0, timestamp=FAR_FUTURE)
    )
    event = _event(_reading(2.0, timestamp=FAR_FUTURE))
    event.received_at_ms = NOW
    context = HookContext.build(event, store, "skill")
    assert (context.timestamp, context.received_at_ms) == (FAR_FUTURE, NOW)
    rows = context.history.fetch_history("s1", limit=1)
    assert (rows[0]["timestamp"], rows[0]["received_at_ms"]) == (FAR_FUTURE, NOW - HOUR)


@pytest.mark.asyncio
async def test_the_sandbox_twin_of_the_hook_context_carries_every_public_field(
    store, monkeypatch
):
    """A field added to the in-process context must cross the wire, or the twin diverges."""
    from ori.skills.hooks_api import HookContext
    from ori.skills.os_sandbox import _ChildHookContext, _serialize_hook_context

    await _append_at(
        store, monkeypatch, NOW - HOUR, _reading(1.0, timestamp=FAR_FUTURE)
    )
    event = _event(_reading(2.0, timestamp=FAR_FUTURE))
    event.received_at_ms = NOW
    context = HookContext.build(event, store, "skill")
    payload = _serialize_hook_context(context, include_result=False)["hook_ctx"]

    def _rpc(method: str, params: dict) -> object:
        if method == "history.fetch_history":
            return context.history.fetch_history(
                params["sensor_id"], params.get("limit", 1)
            )
        raise AssertionError(method)

    twin = _ChildHookContext(payload, _rpc)
    for name in (
        "trigger_name",
        "readings",
        "timestamp",
        "received_at_ms",
        "config",
        "derived",
    ):
        assert getattr(twin, name) == getattr(context, name), name
    assert twin.event is not None and context.event is not None
    for name in ("event_id", "device_id", "sensor_id", "timestamp", "received_at_ms"):
        assert getattr(twin.event, name) == getattr(context.event, name), name
    public = {
        name
        for name in vars(context)
        if not name.startswith("_") and name not in {"history", "state", "event"}
    }
    assert public <= set(vars(twin)), public - set(vars(twin))


@pytest.mark.asyncio
async def test_a_legacy_outbox_row_is_resent_with_the_queue_receipt_in_its_slot(
    tmp_path, monkeypatch
):
    """A row queued before template variables were stored takes the queue receipt, not the event's clock."""
    import asyncio

    from ori.runtime import _format_alert_timestamp
    from tests.test_alert_preferences import _runtime_with_policy

    store = StateStore(str(tmp_path / "legacy.db"))
    await store.open()
    try:
        monkeypatch.setattr("ori.state.store.now_ms", lambda: NOW)
        await store.enqueue_alert(
            alert_id="legacy",
            channel="sms",
            recipient="+2348000000000",
            message="m",
            action_tier="A",
            trigger_name="anomalous_draw",
            original_ts=FAR_FUTURE,
            template_variables=(),
        )
        runtime = _runtime_with_policy(None)
        runtime._state_store = store
        runtime._alert_outbox_retry_interval_s = 0.01
        runtime._shutdown_event = asyncio.Event()

        class _Capture:
            alert = None

            async def send(self, *, alert, to_number, preferred_channel):
                from ori.actions.alert_delivery import AlertSendReceipt

                self.alert = alert
                runtime._shutdown_event.set()
                return AlertSendReceipt.accepted_without_provider_receipt(
                    channel=preferred_channel
                )

        sender = _Capture()
        await asyncio.wait_for(runtime._alert_delivery_loop(sender), timeout=5)  # type: ignore[arg-type]
        assert sender.alert is not None
        assert sender.alert.template_variables[2] == _format_alert_timestamp(
            NOW, runtime._device_timezone
        )
    finally:
        await store.close()


# ─── Tier D reads the reading in hand ────────────────────────────────────────


def _skill_yaml(condition: str, tier: str) -> str:
    return textwrap.dedent(f"""\
        name: receipt-guard
        version: 0.1.0
        author: test
        signature: bundled
        sensors_required:
          - type: current_clamp
            protocol: i2c
        triggers:
          - name: t
            condition: "{condition}"
            cooldown_seconds: 0
            action_tier: {tier}
        actions:
          available:
            - name: alert_whatsapp
              tier: A
          defaults:
            t: [alert_whatsapp]
    """)


@pytest.mark.parametrize(
    "condition",
    [
        "history.avg_24h('load') * 1.5 < value",
        "value > 5 and history.last_n('load', 3)[0] > 1",
    ],
)
def test_a_tier_d_condition_that_reads_history_is_refused_at_load(tmp_path, condition):
    skill_dir = tmp_path / "receipt-guard"
    skill_dir.mkdir()
    (skill_dir / "skill.yaml").write_text(_skill_yaml(condition, "D"))
    loader = SkillLoader(require_signed=True)
    with (
        patch.object(loader, "_is_core_bundled_skill", return_value=True),
        pytest.raises(
            SkillValidationError, match="Tier D and its condition reads history"
        ),
    ):
        loader.load_one(skill_dir)


def test_the_same_condition_loads_below_tier_d(tmp_path):
    skill_dir = tmp_path / "receipt-guard"
    skill_dir.mkdir()
    (skill_dir / "skill.yaml").write_text(
        _skill_yaml("history.avg_24h('load') * 1.5 < value", "A")
    )
    loader = SkillLoader(require_signed=True)
    with patch.object(loader, "_is_core_bundled_skill", return_value=True):
        assert loader.load_one(skill_dir).triggers[0].condition.startswith("history.")


def test_no_bundled_tier_d_condition_names_history_directly() -> None:
    """The direct route only: what a hook derives and hands the condition is not seen here."""
    import yaml

    checked = 0
    for manifest in sorted((ROOT / "skills").glob("*/skill.yaml")):
        for trigger in yaml.safe_load(manifest.read_text()).get("triggers", []) or []:
            if str(trigger.get("action_tier", "")).upper() != "D":
                continue
            checked += 1
            names = {
                n.id
                for n in ast.walk(ast.parse(str(trigger["condition"]), mode="eval"))
                if isinstance(n, ast.Name)
            }
            assert "history" not in names, f"{manifest}: {trigger['name']}"
    assert checked, "no bundled Tier D trigger was found; the scan would pass vacuously"


# ─── The inventory ───────────────────────────────────────────────────────────

#: Tables whose time column is a producer's account, and the column.
PRODUCER_TIME_TABLES = {
    "sensor_history": "timestamp",
    "sensor_history_5min": "bucket_ms",
    "sensor_history_hourly": "bucket_ms",
    "sensor_history_daily": "bucket_ms",
    "alert_outbox": "original_ts",
}
_COL = r"(?:timestamp|bucket_ms|original_ts|\{time_col\})"
#: A decision on a producer-time column: ordering, an extreme, a comparison
#: against a bound or a subquery, a range, or arithmetic that buckets it.
_DECISION = re.compile(
    rf"ORDER BY {_COL}(?: (?:ASC|DESC))?"
    rf"|(?:MAX|MIN)\({_COL}\)"
    rf"|{_COL} (?:>=|<=|<>|!=|<|>|=) (?:\?|\()"
    rf"|{_COL} BETWEEN \? AND \?"
    rf"|GROUP BY [\w, ]*\({_COL} / \d+\)"
    rf"|\({_COL} / \d+\)",
    re.IGNORECASE,
)
_KEYWORD = re.compile(
    r"\b(order by|group by|max|min|between|and|asc|desc|select)\b", re.IGNORECASE
)


def _normalise_sql(sql: str) -> str:
    """One line, one space, no table aliases, keywords upper-cased.

    A ranking hides from a per-line scan behind a line break, an alias prefix
    or a lower-case keyword, so the literal is flattened before any pattern
    sees it and the clause it yields is spelled one way.
    """
    text = " ".join(sql.split())
    text = re.sub(r"\b\w+\.(?=\w)", "", text)
    text = re.sub(r"\(\s+", "(", text)
    text = re.sub(r"\s+\)", ")", text)
    return _KEYWORD.sub(lambda m: m.group(0).upper(), text)


#: Every decision the store makes on a producer-time column, keyed (enclosing
#: function, normalised clause), with the reason it is a filter against a
#: caller's bound, a measured-time bucket, or a value reported under its own
#: name beside the receipt — and never a ranking, a freshness, or a retention
#: decision.
CLASSIFIED_CLAUSES: dict[tuple[str, str], str] = {
    ("_avg_last_hours_sync", "timestamp >= ?"): (
        "an age bound paired with received_at_ms >= ? on the same row: the measured "
        "time can exclude a row the store received inside the window and never admit "
        "one it received outside it"
    ),
    ("_get_latest_readings_snapshot_sync", "timestamp >= ?"): (
        "the freshness window is an age, paired with received_at_ms >= ? and applied "
        "in the outer query to the row MAX(id) already chose: the measured bound can "
        "exclude that row and never choose another, so a sensor whose latest arrival "
        "is stale is absent rather than represented by an older row"
    ),
    ("_avg_last_hours_sync", "bucket_ms >= ?"): (
        "the same age bound on a rollup, paired with max_received_at_ms >= ?: the "
        "measured bucket can only exclude, the receipt bound decides admission"
    ),
    ("_compact_sync", "(timestamp / 300000)"): (
        "a bucket is keyed on when the world was measured so that a report and a "
        "same-weekday baseline stay about the world; what is compacted is decided by "
        "the WHERE on received_at_ms"
    ),
    ("_compact_sync", "GROUP BY sensor_id, (timestamp / 300000)"): (
        "grouping raw rows by their measured-time bucket; the receipt predicate "
        "decides which rows take part"
    ),
    ("_compact_sync", "(bucket_ms / 3600000)"): (
        "the hourly bucket of a measured-time bucket; retention of the source rows is "
        "decided on max_received_at_ms"
    ),
    ("_compact_sync", "GROUP BY sensor_id, (bucket_ms / 3600000)"): (
        "grouping 5-minute buckets by their measured hour; the receipt predicate "
        "decides which rows take part"
    ),
    ("_compact_sync", "(bucket_ms / 86400000)"): (
        "the daily bucket of a measured-time bucket; retention of the source rows is "
        "decided on max_received_at_ms"
    ),
    ("_compact_sync", "GROUP BY sensor_id, (bucket_ms / 86400000)"): (
        "grouping hourly buckets by their measured day; the receipt predicate "
        "decides which rows take part"
    ),
    ("_export_sensor_history_sync", "timestamp BETWEEN ? AND ?"): (
        "a filter against the bounds the caller supplied: what was measured between "
        "two instants is a question about the world, and received_at_ms travels on "
        "every row"
    ),
    ("_export_sensor_history_sync", "bucket_ms BETWEEN ? AND ?"): (
        "the same caller-bounded filter on a rollup tier, with the bucket's greatest "
        "receipt exported beside it"
    ),
    ("_export_sensor_history_sync", "ORDER BY timestamp ASC"): (
        "presentation order of a caller-bounded window under the producer column's own "
        "name; nothing is chosen or dropped by it and every row carries received_at_ms"
    ),
    ("_get_alert_outbox_summary_sync", "MIN(original_ts)"): (
        "the producer's account reported under its own name beside oldest_queued_at_ms; "
        "retry order is arrival and queue age is computed on the receipt"
    ),
    ("_time_of_week_baseline_sync", "bucket_ms >= ?"): (
        "a same-weekday baseline is a window of measured time behind the reference "
        "instant, which is the triggering reading's own measured time by design: the "
        "baseline is for the hour the world was measured in, so a device clock shifted "
        "by days selects another day's baseline, a residual the runtime does not mark"
    ),
    ("_time_of_week_baseline_sync", "bucket_ms < ?"): (
        "the upper bound of that measured-time window, the triggering reading's own "
        "measured time"
    ),
    ("_time_of_week_baseline_sync", "ORDER BY bucket_ms ASC"): (
        "presentation order of that window; the weekday and hour of each bucket are "
        "read from the measured time under its own name"
    ),
    ("_get_timeseries_sync", "{time_col} BETWEEN ? AND ?"): (
        "a chart window is a filter against the caller's bounds on measured time, "
        "which is where a point belongs on a time axis"
    ),
    ("_get_timeseries_sync", "ORDER BY {time_col} ASC"): (
        "presentation order of a caller-bounded chart window under the measured "
        "column's own name"
    ),
}

_LIMIT = (
    "This inventory reads SQL string literals inside functions of ori/state/store.py "
    "that name a producer-time table, flattened to one line with aliases stripped, and "
    "flags a producer-time column where it meets ORDER BY, MAX/MIN, a comparison against "
    "a bound or a subquery, BETWEEN, or bucketing arithmetic. It does not see a "
    "projection, an index definition, SQL assembled by concatenation outside one "
    "literal, or a ranking done in Python on the rows a query returned."
)


def _decision_clauses(source: str) -> dict[tuple[str, str], str]:
    tree = ast.parse(source)
    found: dict[tuple[str, str], str] = {}
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for node in ast.walk(function):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                sql = node.value
                if not any(table in sql for table in PRODUCER_TIME_TABLES):
                    continue
            elif isinstance(node, ast.JoinedStr):
                # An f-string names its table through a variable, so every one
                # that decides on a producer column is a candidate.
                parts: list[str] = []
                for part in node.values:
                    if isinstance(part, ast.Constant):
                        parts.append(str(part.value))
                    elif isinstance(part, ast.FormattedValue):
                        parts.append("{" + ast.unparse(part.value) + "}")
                sql = "".join(parts)
            else:
                continue
            normalised = _normalise_sql(sql)
            for match in _DECISION.finditer(normalised):
                clause = match.group(0)
                found[(function.name, clause)] = normalised
    return found


def _store_decision_clauses() -> dict[tuple[str, str], str]:
    return _decision_clauses(
        (ROOT / "ori" / "state" / "store.py").read_text(encoding="utf-8")
    )


def _planted(body: str) -> str:
    """A function holding one SQL literal, spelled exactly as given."""
    return 'def _latest(conn):\n    return conn.execute("""\n' + body + '\n""")\n'


@pytest.mark.parametrize(
    ("spelling", "clause"),
    [
        (
            "SELECT value FROM sensor_history ORDER BY timestamp DESC",
            "ORDER BY timestamp DESC",
        ),
        (
            "SELECT value FROM sensor_history sh ORDER BY sh.timestamp DESC",
            "ORDER BY timestamp DESC",
        ),
        (
            "SELECT value FROM sensor_history\n ORDER BY\n    timestamp DESC",
            "ORDER BY timestamp DESC",
        ),
        (
            "select value from sensor_history order by timestamp desc",
            "ORDER BY timestamp DESC",
        ),
        ("SELECT MAX(\n  timestamp\n) FROM sensor_history", "MAX(timestamp)"),
        (
            "SELECT * FROM sensor_history o WHERE o.timestamp = (SELECT MAX(i.timestamp) FROM sensor_history i)",
            "MAX(timestamp)",
        ),
        ("SELECT * FROM alert_outbox WHERE original_ts < ?", "original_ts < ?"),
        (
            "SELECT (bucket_ms / 3600000) FROM sensor_history_5min",
            "(bucket_ms / 3600000)",
        ),
    ],
    ids=[
        "bare",
        "alias",
        "split-line",
        "lower-case",
        "max-split",
        "correlated",
        "bound",
        "bucket",
    ],
)
def test_the_scanner_sees_a_ranking_however_it_is_spelled(
    spelling: str, clause: str
) -> None:
    """Positive controls: each spelling a ranking could hide behind is seen."""
    assert ("_latest", clause) in _decision_clauses(_planted(spelling))


@pytest.mark.parametrize(
    "spelling",
    [
        "SELECT timestamp, value FROM sensor_history WHERE sensor_id = ?",
        "SELECT value FROM sensor_history WHERE received_at_ms >= ? ORDER BY id DESC",
        "SELECT MAX(received_at_ms) FROM sensor_history",
        "SELECT * FROM action_log ORDER BY timestamp DESC",
    ],
    ids=["projection", "receipt-ranking", "receipt-max", "runtime-owned-table"],
)
def test_the_scanner_stays_quiet_where_no_producer_time_decides(spelling: str) -> None:
    """Negative controls: a projection or a receipt decision is not a finding."""
    assert not _decision_clauses(_planted(spelling))


def test_every_decision_on_a_producer_time_column_is_classified() -> None:
    found = _store_decision_clauses()
    assert found, "no producer-time decision found in the store; the scan is broken"
    unclassified = sorted(
        f"{fn}(): {clause}"
        for (fn, clause) in found
        if (fn, clause) not in CLASSIFIED_CLAUSES
    )
    assert not unclassified, (
        "the store decides something on a producer's clock that nobody has classified: "
        f"{unclassified}. A producer timestamp may be filtered against a bound the caller "
        "supplied, bucketed by measured time, or reported under its own name beside the "
        "receipt; it may never decide which row is current, fresh, or kept. Add the "
        "clause to CLASSIFIED_CLAUSES with that reason, or rewrite it on received_at_ms. "
        + _LIMIT
    )


def test_the_classification_table_describes_clauses_that_exist() -> None:
    found = _store_decision_clauses()
    stale = sorted(
        f"{fn}(): {clause}"
        for (fn, clause) in CLASSIFIED_CLAUSES
        if (fn, clause) not in found
    )
    assert not stale, (
        f"classified clauses that no longer exist: {stale}. Remove them, or the table "
        "stops describing the code and starts excusing it."
    )


@pytest.mark.parametrize("reason", sorted(set(CLASSIFIED_CLAUSES.values())))
def test_each_classification_states_a_reason(reason: str) -> None:
    assert len(reason) > 30, f"classification is too thin to review: {reason!r}"


# ─── Elapsed time on a wall clock may not authorise a physical act ───────────

#: Derived values that are an interval on the runtime's wall clock. A forward
#: step of that clock reads as elapsed time, and nothing in a hook can tell it
#: from a genuine long condition; until the runtime supplies an elapsed time
#: that survives a clock step, a trigger gated on one of these may reach
#: notifications only.
WALL_CLOCK_INTERVALS = (
    "empty_duration_minutes",
    "power_snapshot_fresh",
    "low_soc_persist_minutes",
    "outage_duration_minutes",
    "observed_window_hours",
)


def test_no_bundled_trigger_gated_on_a_wall_clock_interval_reaches_a_physical_action() -> (
    None
):
    """Binding a physical default to such a trigger fails here, not on a device."""
    import yaml

    checked = 0
    offenders: list[str] = []
    for manifest in sorted((ROOT / "skills").glob("*/skill.yaml")):
        skill = yaml.safe_load(manifest.read_text())
        actions = skill.get("actions") or {}
        tiers = {
            str(item.get("name")): str(item.get("tier", "")).upper()
            for item in actions.get("available") or []
            if isinstance(item, dict)
        }
        defaults = actions.get("defaults") or {}
        for trigger in skill.get("triggers") or []:
            condition = str(trigger.get("condition", ""))
            names = {
                n.id
                for n in ast.walk(ast.parse(condition, mode="eval"))
                if isinstance(n, ast.Name)
            }
            if not names & set(WALL_CLOCK_INTERVALS):
                continue
            checked += 1
            for action in defaults.get(trigger["name"]) or []:
                if tiers.get(str(action), "A") != "A":
                    offenders.append(
                        f"{manifest.parent.name}: {trigger['name']} -> {action}"
                    )
    assert checked, (
        "no bundled trigger is gated on a wall-clock interval; the scan would pass vacuously"
    )
    assert not offenders, (
        f"triggers gated on a wall-clock interval reach a physical action: {offenders}. "
        "A forward step of the runtime's clock reads as elapsed time and no hook can "
        "tell it from a genuine long condition, so such a trigger may reach "
        "notifications only until the runtime supplies an elapsed time that survives "
        "a clock step."
    )
