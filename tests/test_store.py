# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json
import sqlite3
import time
from datetime import datetime, timedelta
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest

from ori.network.events import ActionResult, OriEvent, ReasoningResult, SensorReading
from ori.state.store import StateStore

# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
async def store(tmp_path):
    s = StateStore(db_path=str(tmp_path / "test.db"))
    await s.open()
    yield s
    await s.close()


def _ms() -> int:
    return int(time.time() * 1000)


def _reading(
    sensor_id: str = "s1",
    sensor_type: str = "current_clamp",
    value: float = 5.0,
    unit: str = "ampere",
    timestamp: int | None = None,
    quality: float = 1.0,
    metadata: dict | None = None,
) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp=timestamp or _ms(),
        quality=quality,
        metadata=metadata or {},
    )


def _event(reading: SensorReading, device_id: str = "dev-01") -> OriEvent:
    return OriEvent.from_reading(reading, device_id)


def _action_result(
    action_name: str = "alert_whatsapp",
    tier: str = "A",
    executed: bool = True,
    approved: bool | None = None,
    action_taken: str = "alert_whatsapp",
    operator_response: str | None = None,
    proposal_id: str | None = None,
    safe_default_used: bool = False,
    correlation_id: str = "",
    timestamp: int | None = None,
) -> ActionResult:
    return ActionResult(
        action_name=action_name,
        tier=tier,
        executed=executed,
        approved=approved,
        action_taken=action_taken,
        timestamp=timestamp or _ms(),
        operator_response=operator_response,
        proposal_id=proposal_id,
        safe_default_used=safe_default_used,
        correlation_id=correlation_id,
    )


# ─── open / close / migration ─────────────────────────────────────────────────


class TestLifecycle:
    async def test_open_creates_tables(self, tmp_path):
        s = StateStore(db_path=str(tmp_path / "lifecycle.db"))
        await s.open()
        tables = await s._run(
            lambda: s._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        )
        names = {row["name"] for row in tables}
        await s.close()
        assert {
            "sensor_history",
            "reasoning_log",
            "action_log",
            "tier_c_decision_log",
            "causal_memory",
            "skill_state",
            "remote_command_log",
            "remote_command_security_incident_log",
            "remote_command_execution_log",
            "alert_outbox",
        } <= names

    async def test_open_is_idempotent(self, tmp_path):
        """Re-opening with the same path should not raise (DDL uses IF NOT EXISTS)."""
        path = str(tmp_path / "idem.db")
        s = StateStore(db_path=path)
        await s.open()
        await s.close()
        s2 = StateStore(db_path=path)
        await s2.open()
        await s2.close()


class TestMigrationHardening:
    def test_add_column_if_missing_ignores_duplicate_column_error(self):
        class _Conn:
            def execute(self, _sql):
                raise sqlite3.OperationalError("duplicate column name: device_id")

        s = StateStore(db_path=":memory:")
        s._conn = _Conn()  # type: ignore[assignment]
        s._add_column_if_missing("reasoning_log", "device_id", "TEXT")

    def test_add_column_if_missing_raises_non_duplicate_operational_error(self):
        class _Conn:
            def execute(self, _sql):
                raise sqlite3.OperationalError("database disk image is malformed")

        s = StateStore(db_path=":memory:")
        s._conn = _Conn()  # type: ignore[assignment]
        with pytest.raises(sqlite3.OperationalError, match="malformed"):
            s._add_column_if_missing("reasoning_log", "device_id", "TEXT")


# ─── append_history / get_history ─────────────────────────────────────────────


class TestCompactionGuard:
    def test_compact_sync_raises_on_invalid_cutoff_order(self, store):
        # hourly > 5min => invalid
        cutoffs = {
            "hourly": 1000,
            "5min": 500,
            "raw": 2000,
        }
        with pytest.raises(RuntimeError, match="Invalid compaction cutoffs"):
            store._compact_sync(cutoffs, now_ms=3000)

    async def test_compact_sync_raises_on_backward_clock_skew(self, store):
        # Insert a row into the future
        future_ts = _ms() + 10_000_000
        await store.append_history(_event(_reading(timestamp=future_ts)))

        # now_ms is in the past compared to DB
        past_ms = future_ts - 4_000_000
        cutoffs = {
            "hourly": past_ms - 30_000,
            "5min": past_ms - 20_000,
            "raw": past_ms - 10_000,
        }

        with pytest.raises(RuntimeError, match="Clock skew detected"):
            await store._run_write(store._compact_sync, cutoffs, past_ms, 3600000)

    async def test_compact_sync_succeeds_normally(self, store):
        # Insert a row safely in the past
        past_ts = _ms() - 1000
        await store.append_history(_event(_reading(timestamp=past_ts)))

        now = _ms()
        cutoffs = {
            "hourly": now - 300_000,
            "5min": now - 200_000,
            "raw": now - 100_000,
        }

        # Should not raise
        await store._run_write(store._compact_sync, cutoffs, now, 3600000)


class TestSensorHistory:
    async def test_append_and_retrieve(self, store):
        r = _reading(value=7.3)
        await store.append_history(_event(r))
        rows = await store.get_history("s1")
        assert len(rows) == 1
        assert rows[0].value == pytest.approx(7.3)
        assert rows[0].sensor_id == "s1"

    async def test_get_history_respects_limit(self, store):
        for i in range(10):
            await store.append_history(_event(_reading(value=float(i))))
        rows = await store.get_history("s1", limit=5)
        assert len(rows) == 5

    async def test_get_history_returns_most_recent_first(self, store):
        base = _ms()
        for i in range(3):
            r = _reading(value=float(i), timestamp=base + i * 1000)
            await store.append_history(_event(r))
        rows = await store.get_history("s1", limit=10)
        assert rows[0].value == pytest.approx(2.0)
        assert rows[1].value == pytest.approx(1.0)
        assert rows[2].value == pytest.approx(0.0)

    async def test_get_history_filters_by_sensor_id(self, store):
        await store.append_history(_event(_reading(sensor_id="s1", value=1.0)))
        await store.append_history(_event(_reading(sensor_id="s2", value=2.0)))
        rows = await store.get_history("s1")
        assert all(r.sensor_id == "s1" for r in rows)
        assert len(rows) == 1

    async def test_metadata_roundtrips(self, store):
        meta = {"source": "i2c", "channel": 0}
        r = _reading(metadata=meta)
        await store.append_history(_event(r))
        rows = await store.get_history("s1")
        assert rows[0].metadata == meta

    async def test_skips_event_without_reading(self, store):
        event = OriEvent(
            event_id="x",
            event_type="device.heartbeat",
            device_id="dev-01",
            sensor_id="s1",
            timestamp=_ms(),
            reading=None,
        )
        await store.append_history(event)  # must not raise
        rows = await store.get_history("s1")
        assert len(rows) == 0

    async def test_get_history_empty_returns_empty_list(self, store):
        rows = await store.get_history("nonexistent")
        assert rows == []


# ─── avg_last_n / avg_last_hours ──────────────────────────────────────────────


class TestAverages:
    async def test_avg_last_n_correct(self, store):
        for v in [2.0, 4.0, 6.0, 8.0]:
            await store.append_history(_event(_reading(value=v)))
        avg = await store.avg_last_n("s1", 4)
        assert avg == pytest.approx(5.0)

    async def test_avg_last_n_partial(self, store):
        base = _ms()
        for i, v in enumerate([1.0, 3.0, 5.0]):
            await store.append_history(
                _event(_reading(value=v, timestamp=base + i * 1000))
            )
        avg = await store.avg_last_n("s1", 2)
        # last 2 by timestamp are 3.0 and 5.0 → avg 4.0
        assert avg == pytest.approx(4.0)

    async def test_avg_last_n_no_data(self, store):
        avg = await store.avg_last_n("s-missing", 10)
        assert avg is None

    async def test_avg_last_hours_includes_recent(self, store):
        now = _ms()
        # reading from 30 minutes ago
        r = _reading(value=10.0, timestamp=now - 30 * 60 * 1000)
        await store.append_history(_event(r))
        avg = await store.avg_last_hours("s1", hours=1)
        assert avg == pytest.approx(10.0)

    async def test_avg_last_hours_excludes_old(self, store):
        now = _ms()
        old = _reading(value=999.0, timestamp=now - 2 * 3_600_000)
        recent = _reading(value=5.0, timestamp=now - 100)
        await store.append_history(_event(old))
        await store.append_history(_event(recent))
        avg = await store.avg_last_hours("s1", hours=1)
        assert avg == pytest.approx(5.0)

    async def test_avg_last_hours_no_data(self, store):
        avg = await store.avg_last_hours("s-missing", hours=24)
        assert avg is None

    def _insert_hourly(
        self,
        store,
        *,
        sensor_id: str,
        local_dt: datetime,
        value: float,
        sample_count: int = 12,
    ) -> None:
        bucket_ms = int(local_dt.timestamp() * 1000)
        store._conn.execute(
            """
            INSERT INTO sensor_history_hourly
                (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (sensor_id, "current_clamp", bucket_ms, value, "ampere", sample_count),
        )

    async def test_time_of_week_baseline_uses_site_local_weekday_hour(self, store):
        tz = ZoneInfo("Africa/Lagos")
        reference = datetime(2026, 6, 8, 9, 15, tzinfo=tz)  # Monday 09:15 local.
        sensor_id = "ac-current"
        for weeks_ago, value in [(1, 11.0), (2, 12.0), (3, 13.0), (4, 14.0)]:
            self._insert_hourly(
                store,
                sensor_id=sensor_id,
                local_dt=reference.replace(minute=0, second=0, microsecond=0)
                - timedelta(weeks=weeks_ago),
                value=value,
                sample_count=12,
            )

        # Same sensor, wrong local hour. This would pollute a naive broad query.
        self._insert_hourly(
            store,
            sensor_id=sensor_id,
            local_dt=reference.replace(hour=10, minute=0, second=0, microsecond=0)
            - timedelta(weeks=1),
            value=99.0,
        )
        store._conn.commit()

        baseline = await store.time_of_week_baseline(
            sensor_id=sensor_id,
            reference_timestamp_ms=int(reference.timestamp() * 1000),
            timezone="Africa/Lagos",
            lookback_weeks=8,
            min_weeks=3,
        )

        assert baseline["usable"] is True
        assert baseline["target_weekday"] == 0
        assert baseline["target_hour"] == 9
        assert baseline["covered_weeks"] == 4
        assert baseline["sample_count"] == 48
        assert baseline["avg_value"] == pytest.approx(12.5)
        assert baseline["unit"] == "ampere"
        assert baseline["tier"] == "hourly"

    async def test_time_of_week_baseline_fails_closed_on_low_coverage(self, store):
        tz = ZoneInfo("Africa/Lagos")
        reference = datetime(2026, 6, 8, 9, 0, tzinfo=tz)
        self._insert_hourly(
            store,
            sensor_id="ac-current",
            local_dt=reference - timedelta(weeks=1),
            value=11.0,
        )
        store._conn.commit()

        baseline = await store.time_of_week_baseline(
            sensor_id="ac-current",
            reference_timestamp_ms=int(reference.timestamp() * 1000),
            timezone="Africa/Lagos",
            lookback_weeks=8,
            min_weeks=3,
        )

        assert baseline["usable"] is False
        assert baseline["reason"] == "low_coverage"
        assert baseline["covered_weeks"] == 1
        assert baseline["avg_value"] == pytest.approx(11.0)

    async def test_export_sensor_history_unions_raw_and_compacted_tiers(self, store):
        await store.append_history(
            _event(
                _reading(
                    sensor_id="s1",
                    sensor_type="current_clamp",
                    value=4.2,
                    unit="ampere",
                    timestamp=1_000,
                    quality=0.98,
                )
            )
        )
        await store._run_write(
            lambda: store._conn.execute(
                """
                INSERT INTO sensor_history_5min
                    (sensor_id, sensor_type, bucket_ms, avg_value, unit, sample_count)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                ("s1", "current_clamp", 2_000, 5.5, "ampere", 12),
            )
        )
        await store._run_write(store._conn.commit)

        rows = await store.export_sensor_history(
            sensor_id="s1",
            start_ms=0,
            end_ms=3_000,
            limit=10,
        )

        assert [row["tier"] for row in rows] == ["raw", "5min"]
        assert rows[0]["timestamp"] == 1_000
        assert rows[0]["value"] == pytest.approx(4.2)
        assert rows[0]["quality"] == pytest.approx(0.98)
        assert rows[0]["sample_count"] == 1
        assert rows[1]["timestamp"] == 2_000
        assert rows[1]["value"] == pytest.approx(5.5)
        assert rows[1]["quality"] is None
        assert rows[1]["sample_count"] == 12

    async def test_export_sensor_history_filters_sensor_and_bounds(self, store):
        await store.append_history(_event(_reading(sensor_id="s1", timestamp=1_000)))
        await store.append_history(_event(_reading(sensor_id="s1", timestamp=2_000)))
        await store.append_history(_event(_reading(sensor_id="s2", timestamp=2_000)))

        rows = await store.export_sensor_history(
            sensor_id="s1",
            start_ms=1_500,
            end_ms=2_500,
        )

        assert len(rows) == 1
        assert rows[0]["sensor_id"] == "s1"
        assert rows[0]["timestamp"] == 2_000


# ─── action_log ───────────────────────────────────────────────────────────────


class TestActionLog:
    async def test_log_and_retrieve_tier_a(self, store):
        result = _action_result(tier="A", approved=None)
        await store.log_action(result, trigger_name="anomalous_draw")
        log = await store.get_action_log()
        assert len(log) == 1
        entry = log[0]
        assert entry["tier"] == "A"
        assert entry["executed"] is True
        assert entry["approved"] is None
        assert entry["trigger_name"] == "anomalous_draw"

    async def test_log_tier_c_approved(self, store):
        result = _action_result(
            tier="C",
            executed=True,
            approved=True,
            action_taken="open_safety_circuit",
            operator_response="YES",
        )
        await store.log_action(result, trigger_name="critical_fault")
        log = await store.get_action_log()
        assert log[0]["approved"] is True
        assert log[0]["operator_response"] == "YES"

    async def test_log_action_persists_correlation_id(self, store):
        await store.log_action(
            _action_result(correlation_id="corr-test-123"),
            trigger_name="anomalous_draw",
        )
        log = await store.get_action_log()
        assert log[0]["correlation_id"] == "corr-test-123"

    async def test_log_tier_c_rejected(self, store):
        result = _action_result(
            tier="C",
            executed=False,
            approved=False,
            action_taken="log_to_dashboard",
            operator_response="NO",
        )
        await store.log_action(result, trigger_name="critical_fault")
        log = await store.get_action_log()
        assert log[0]["approved"] is False
        assert log[0]["executed"] is False

    async def test_get_action_log_limit(self, store):
        for i in range(10):
            await store.log_action(
                _action_result(action_name=f"act_{i}"), trigger_name="t"
            )
        log = await store.get_action_log(limit=4)
        assert len(log) == 4

    async def test_get_action_log_most_recent_first(self, store):
        base = _ms()
        for i in range(3):
            r = _action_result(action_name=f"act_{i}", timestamp=base + i * 1000)
            await store.log_action(r, trigger_name="t")
        log = await store.get_action_log()
        assert log[0]["action_name"] == "act_2"

    async def test_get_action_log_empty(self, store):
        log = await store.get_action_log()
        assert log == []

    async def test_export_action_log_filters_and_includes_reporting_fields(self, store):
        base = _ms()
        await store.log_action_for_event(
            _action_result(
                action_name="open_safety_circuit",
                tier="C",
                executed=True,
                approved=False,
                action_taken="log_to_dashboard",
                operator_response="NO",
                proposal_id="AB12CD34",
                safe_default_used=True,
                correlation_id="corr-export-1",
                timestamp=base,
            ),
            trigger_name="overcurrent",
            device_id="dev-01",
            sensor_id="load-current",
            sensor_type="current_clamp",
        )
        await store.log_action_for_event(
            _action_result(
                action_name="alert_whatsapp",
                tier="A",
                timestamp=base + 1_000,
            ),
            trigger_name="voltage_warning",
            device_id="dev-02",
            sensor_id="voltage-main",
            sensor_type="voltage",
        )

        rows = await store.export_action_log(
            device_id="dev-01",
            since_ms=base - 1,
            until_ms=base + 1,
            tier="C",
            limit=10,
        )

        assert len(rows) == 1
        row = rows[0]
        assert row["action_name"] == "open_safety_circuit"
        assert row["tier"] == "C"
        assert row["device_id"] == "dev-01"
        assert row["sensor_id"] == "load-current"
        assert row["sensor_type"] == "current_clamp"
        assert row["trigger_name"] == "overcurrent"
        assert row["safe_default_used"] is True
        assert row["proposal_id"] == "AB12CD34"
        assert row["correlation_id"] == "corr-export-1"


class TestTierCDecisionLog:
    async def test_log_and_retrieve_tier_c_decision(self, store):
        await store.log_tier_c_decision(
            device_id="dev-01",
            site_type="pharmacy",
            location="Lagos",
            timezone="Africa/Lagos",
            sensor_id="load-current",
            sensor_type="current_clamp",
            reading_value=18.5,
            reading_unit="ampere",
            reading_timestamp=1234,
            history_window=[{"timestamp": 1000, "value": 10.0}],
            skill_name="energy-anomaly-detector",
            trigger_name="overcurrent",
            proposed_action="trip_relay",
            confidence=0.91,
            reasoning_tier="local_slm",
            reasoning_model="qwen.gguf",
            prompt_context_summary="load is high",
            operator_decision="rejected",
            operator_response="NO",
            decision_latency_ms=2500,
            approval_timeout_seconds=300,
            safe_default_action="log_to_dashboard",
            safe_default_used=True,
            action_taken="log_to_dashboard",
            action_executed=True,
            final_action_result={"approved": False},
            later_outcome=None,
            created_at=5000,
        )

        rows = await store.get_tier_c_decision_log()

        assert len(rows) == 1
        row = rows[0]
        assert row["device_id"] == "dev-01"
        assert row["site_type"] == "pharmacy"
        assert row["sensor_type"] == "current_clamp"
        assert row["reading_value"] == pytest.approx(18.5)
        assert row["history_window"] == [{"timestamp": 1000, "value": 10.0}]
        assert row["skill_name"] == "energy-anomaly-detector"
        assert row["operator_decision"] == "rejected"
        assert row["safe_default_used"] is True
        assert row["action_executed"] is True
        assert row["final_action_result"] == {"approved": False}
        assert row["later_outcome"] is None

    async def test_export_tier_c_decision_log_filters_bounds(self, store):
        for idx, device_id in enumerate(("dev-01", "dev-02", "dev-01")):
            await store.log_tier_c_decision(
                device_id=device_id,
                site_type="pharmacy",
                location="Lagos",
                timezone="Africa/Lagos",
                sensor_id="load-current",
                sensor_type="current_clamp",
                reading_value=18.5 + idx,
                reading_unit="ampere",
                reading_timestamp=1000 + idx,
                history_window=[{"timestamp": 900 + idx, "value": 10.0 + idx}],
                skill_name="energy-anomaly-detector",
                trigger_name="overcurrent",
                proposed_action="trip_relay",
                confidence=0.91,
                reasoning_tier="local_slm",
                reasoning_model="qwen.gguf",
                prompt_context_summary="load is high",
                operator_decision="rejected",
                operator_response="NO",
                decision_latency_ms=2500,
                approval_timeout_seconds=300,
                safe_default_action="log_to_dashboard",
                safe_default_used=True,
                action_taken="log_to_dashboard",
                action_executed=True,
                final_action_result={"approved": False, "idx": idx},
                later_outcome=None,
                created_at=5000 + idx * 1000,
            )

        rows = await store.export_tier_c_decision_log(
            device_id="dev-01",
            since_ms=5000,
            until_ms=7000,
            limit=10,
        )

        assert [row["created_at"] for row in rows] == [7000, 5000]
        assert {row["device_id"] for row in rows} == {"dev-01"}
        assert rows[0]["history_window"] == [{"timestamp": 902, "value": 12.0}]
        assert rows[0]["final_action_result"] == {"approved": False, "idx": 2}


# ─── alert_outbox ─────────────────────────────────────────────────────────────


class TestAlertOutbox:
    async def test_enqueue_and_fetch_retryable(self, store):
        inserted = await store.enqueue_alert(
            alert_id="a1",
            channel="sms",
            recipient="+2340000000000",
            message="msg",
            action_tier="A",
            trigger_name="high_draw",
            original_ts=1234,
        )
        assert inserted is True

        rows = await store.get_retryable_alerts(limit=10)
        assert len(rows) == 1
        assert rows[0]["alert_id"] == "a1"
        assert rows[0]["status"] == "pending"
        assert rows[0]["attempt_count"] == 0

    async def test_enqueue_deduplicates_by_alert_id(self, store):
        first = await store.enqueue_alert(
            alert_id="dup-1",
            channel="sms",
            recipient="+2340000000000",
            message="msg",
            action_tier="A",
            trigger_name="high_draw",
            original_ts=1234,
        )
        second = await store.enqueue_alert(
            alert_id="dup-1",
            channel="sms",
            recipient="+2340000000000",
            message="msg",
            action_tier="A",
            trigger_name="high_draw",
            original_ts=1234,
        )
        assert first is True
        assert second is False

        rows = await store.get_retryable_alerts(limit=10)
        assert len(rows) == 1

    async def test_mark_failed_increments_attempt_count(self, store):
        await store.enqueue_alert(
            alert_id="f1",
            channel="whatsapp",
            recipient="+2340000000000",
            message="msg",
            action_tier="B",
            trigger_name="high_draw",
            original_ts=1234,
        )

        await store.mark_alert_attempt_failed("f1")
        rows = await store.get_retryable_alerts(limit=10)
        assert len(rows) == 1
        assert rows[0]["status"] == "failed"
        assert rows[0]["attempt_count"] == 1
        assert rows[0]["last_attempt_ts"] is not None

    async def test_mark_delivered_removes_from_retryable(self, store):
        await store.enqueue_alert(
            alert_id="d1",
            channel="sms",
            recipient="+2340000000000",
            message="msg",
            action_tier="A",
            trigger_name="high_draw",
            original_ts=1234,
        )

        await store.mark_alert_delivered("d1")
        rows = await store.get_retryable_alerts(limit=10)
        assert rows == []

    async def test_alert_outbox_summary_counts_retryable_oldest(self, store):
        empty = await store.get_alert_outbox_summary()
        assert empty == {
            "backlog_count": 0,
            "oldest_queued_original_ts": None,
        }

        await store.enqueue_alert(
            alert_id="newer",
            channel="sms",
            recipient="+2340000000000",
            message="msg",
            action_tier="A",
            trigger_name="high_draw",
            original_ts=2000,
        )
        await store.enqueue_alert(
            alert_id="older",
            channel="whatsapp",
            recipient="+2340000000000",
            message="msg",
            action_tier="B",
            trigger_name="high_draw",
            original_ts=1000,
        )
        await store.enqueue_alert(
            alert_id="delivered",
            channel="sms",
            recipient="+2340000000000",
            message="msg",
            action_tier="A",
            trigger_name="high_draw",
            original_ts=500,
        )
        await store.mark_alert_delivered("delivered")

        summary = await store.get_alert_outbox_summary()

        assert summary == {
            "backlog_count": 2,
            "oldest_queued_original_ts": 1000,
        }

    async def test_mark_abandoned_removes_from_retryable(self, store):
        await store.enqueue_alert(
            alert_id="ab1",
            channel="sms",
            recipient="+2340000000000",
            message="msg",
            action_tier="A",
            trigger_name="high_draw",
            original_ts=1234,
        )

        await store.mark_alert_abandoned("ab1")
        rows = await store.get_retryable_alerts(limit=10)
        assert rows == []


class TestOfflineTokens:
    async def test_claim_offline_token_is_single_use(self, store):
        first = await store.claim_offline_token(
            token_id="tok-1",
            device_id="dev-01",
            action="open_safety_circuit",
        )
        second = await store.claim_offline_token(
            token_id="tok-1",
            device_id="dev-01",
            action="open_safety_circuit",
        )
        assert first is True
        assert second is False

    async def test_log_offline_token_attempt_persists(self, store):
        await store.log_offline_token_attempt(
            token_id="tok-2",
            device_id="dev-01",
            action="open_safety_circuit",
            approved=False,
            reason="expired",
        )
        row = await store._run_read(
            lambda conn: conn.execute(
                """
                SELECT token_id, approved, reason
                FROM offline_token_audit
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
        )
        assert row is not None
        assert row["token_id"] == "tok-2"
        assert bool(row["approved"]) is False
        assert row["reason"] == "expired"


class TestDevicePolicyCache:
    async def test_upsert_and_get_latest_device_policy_cache(self, store):
        await store.upsert_device_policy_cache(
            policy_version=4,
            tier="cloud",
            relay_b_enabled=True,
            relay_c_enabled=False,
            cloud_llm_enabled=False,
            valid_until=1_800_000_000,
            issued_at=1_700_000_000,
            signature="ed25519:test",
            raw_payload='{"policy_version":4}',
            cached_at_ms=1111,
        )
        row = await store.get_latest_device_policy_cache()
        assert row is not None
        assert row["policy_version"] == 4
        assert row["relay_b_enabled"] is True
        assert row["relay_c_enabled"] is False
        assert row["raw_payload"] == '{"policy_version":4}'

    async def test_get_latest_returns_highest_policy_version(self, store):
        await store.upsert_device_policy_cache(
            policy_version=2,
            tier="cloud",
            relay_b_enabled=True,
            relay_c_enabled=True,
            cloud_llm_enabled=True,
            valid_until=1_800_000_000,
            issued_at=1_700_000_000,
            signature="ed25519:a",
            raw_payload='{"policy_version":2}',
            cached_at_ms=1111,
        )
        await store.upsert_device_policy_cache(
            policy_version=5,
            tier="cloud",
            relay_b_enabled=False,
            relay_c_enabled=False,
            cloud_llm_enabled=False,
            valid_until=1_900_000_000,
            issued_at=1_700_000_100,
            signature="ed25519:b",
            raw_payload='{"policy_version":5}',
            cached_at_ms=2222,
        )
        row = await store.get_latest_device_policy_cache()
        assert row is not None
        assert row["policy_version"] == 5
        assert row["signature"] == "ed25519:b"


# ─── causal_memory ────────────────────────────────────────────────────────────


class TestCausalMemory:
    async def test_store_and_lookup(self, store):
        await store.store_causal_memory("k1", "resolution-A", 0.9)
        result = await store.lookup_causal_memory("k1")
        assert result == "resolution-A"

    async def test_lookup_missing_key_returns_none(self, store):
        result = await store.lookup_causal_memory("nonexistent")
        assert result is None

    async def test_lookup_increments_hit_count(self, store):
        await store.store_causal_memory("k1", "res", 0.8)
        await store.lookup_causal_memory("k1")
        await store.lookup_causal_memory("k1")
        row = await store._run(
            lambda: store._conn.execute(
                "SELECT hit_count FROM causal_memory WHERE pattern_key = ?", ("k1",)
            ).fetchone()
        )
        # initial store sets hit_count=1; each lookup increments by 1
        assert row["hit_count"] == 3

    async def test_store_upserts_on_conflict(self, store):
        await store.store_causal_memory("k1", "old", 0.5)
        await store.store_causal_memory("k1", "new", 0.95)
        result = await store.lookup_causal_memory("k1")
        assert result == "new"
        row = await store._run(
            lambda: store._conn.execute(
                "SELECT confidence FROM causal_memory WHERE pattern_key = ?", ("k1",)
            ).fetchone()
        )
        assert row["confidence"] == pytest.approx(0.95)

    async def test_hooks_history_facade_methods(self, store):
        reading = _reading(sensor_id="s-1", value=5.0, sensor_type="current")
        await store.append_history(OriEvent.from_reading(reading, "dev-01"))
        history = store.hooks_get_history("s-1", 1)
        assert len(history) == 1
        assert history[0].value == pytest.approx(5.0)
        assert store.hooks_avg_last_n("s-1", 1) == pytest.approx(5.0)
        assert store.hooks_avg_last_hours("s-1", 1) == pytest.approx(5.0)


# ─── skill_state ──────────────────────────────────────────────────────────────


class TestSkillState:
    async def test_set_and_get(self, store):
        await store.set_skill_state("energy-anomaly-detector", "last_alert_ts", "12345")
        value = await store.get_skill_state("energy-anomaly-detector", "last_alert_ts")
        assert value == "12345"

    async def test_get_missing_key_returns_none(self, store):
        value = await store.get_skill_state("no-skill", "no-key")
        assert value is None

    async def test_set_overwrites_existing(self, store):
        await store.set_skill_state("skill-x", "counter", "1")
        await store.set_skill_state("skill-x", "counter", "42")
        value = await store.get_skill_state("skill-x", "counter")
        assert value == "42"

    async def test_different_skills_isolated(self, store):
        await store.set_skill_state("skill-a", "k", "value-a")
        await store.set_skill_state("skill-b", "k", "value-b")
        assert await store.get_skill_state("skill-a", "k") == "value-a"
        assert await store.get_skill_state("skill-b", "k") == "value-b"

    async def test_json_value_roundtrip(self, store):
        payload = json.dumps({"threshold": 8.2, "enabled": True})
        await store.set_skill_state("skill-x", "cfg", payload)
        raw = await store.get_skill_state("skill-x", "cfg")
        assert json.loads(raw) == {"threshold": 8.2, "enabled": True}

    async def test_updated_at_advances_on_overwrite(self, store):
        await store.set_skill_state("skill-x", "k", "v1")
        row1 = await store._run(
            lambda: store._conn.execute(
                "SELECT updated_at FROM skill_state WHERE skill_name=? AND key=?",
                ("skill-x", "k"),
            ).fetchone()
        )
        # Ensure at least 1 ms passes
        import asyncio

        await asyncio.sleep(0.005)
        await store.set_skill_state("skill-x", "k", "v2")
        row2 = await store._run(
            lambda: store._conn.execute(
                "SELECT updated_at FROM skill_state WHERE skill_name=? AND key=?",
                ("skill-x", "k"),
            ).fetchone()
        )
        assert row2["updated_at"] >= row1["updated_at"]

    async def test_hooks_skill_state_facade_methods(self, store):
        store.hooks_set_skill_state("skill-y", "flag", "on")
        assert store.hooks_get_skill_state("skill-y", "flag") == "on"


# ─── reasoning_log ────────────────────────────────────────────────────────────


def _reasoning_result(
    prompt: str = "",
    confidence: float = 0.9,
    reasoning_status: str = "",
    correlation_id: str = "",
) -> ReasoningResult:
    return ReasoningResult(
        text="Anomaly detected.",
        tier="local_slm",
        model="qwen2.5",
        tokens_used=42,
        latency_ms=150,
        confidence=confidence,
        action_tier="A",
        prompt=prompt,
        reasoning_status=reasoning_status,
        correlation_id=correlation_id,
    )


class TestReasoningLog:
    async def _insert_reasoning(
        self,
        store,
        *,
        trigger_name: str = "load-current",
        device_id: str = "dev-01",
        timestamp: int = 1_000,
        tier: str = "local_slm",
        action_tier: str = "A",
        reasoning_status: str = "",
        correlation_id: str = "",
        prompt: str = "prompt",
        text: str = "response",
    ) -> None:
        result = _reasoning_result(
            prompt=prompt,
            reasoning_status=reasoning_status,
            correlation_id=correlation_id,
        )
        result.tier = tier
        result.action_tier = action_tier
        result.text = text
        with patch("ori.state.store.now_ms", return_value=timestamp):
            await store.log_reasoning(
                result=result,
                trigger_name=trigger_name,
                device_id=device_id,
            )

    async def test_log_reasoning_persists_row(self, store):
        await store.log_reasoning(
            result=_reasoning_result(),
            trigger_name="load-current",
            device_id="dev-01",
        )
        rows = await store._run(
            lambda: store._conn.execute("SELECT * FROM reasoning_log").fetchall()
        )
        assert len(rows) == 1

    async def test_log_reasoning_persists_prompt(self, store):
        """A non-empty prompt is stored and retrievable."""
        prompt_text = "Sensor: load-current\nValue: 8.2A\nIs this anomalous?"
        await store.log_reasoning(
            result=_reasoning_result(prompt=prompt_text),
            trigger_name="load-current",
            device_id="dev-01",
        )
        row = await store._run(
            lambda: store._conn.execute("SELECT prompt FROM reasoning_log").fetchone()
        )
        assert row["prompt"] == prompt_text

    async def test_log_reasoning_empty_prompt_stored_as_empty_string(self, store):
        await store.log_reasoning(
            result=_reasoning_result(prompt=""),
            trigger_name="load-current",
            device_id="dev-01",
        )
        row = await store._run(
            lambda: store._conn.execute("SELECT prompt FROM reasoning_log").fetchone()
        )
        assert row["prompt"] == ""

    async def test_log_reasoning_persists_device_id_and_model(self, store):
        await store.log_reasoning(
            result=_reasoning_result(),
            trigger_name="t",
            device_id="ikeja-01",
        )
        row = await store._run(
            lambda: store._conn.execute(
                "SELECT device_id, model FROM reasoning_log"
            ).fetchone()
        )
        assert row["device_id"] == "ikeja-01"
        assert row["model"] == "qwen2.5"

    async def test_log_reasoning_persists_reasoning_status(self, store):
        await store.log_reasoning(
            result=_reasoning_result(reasoning_status="incomplete"),
            trigger_name="t",
            device_id="ikeja-01",
        )
        row = await store._run(
            lambda: store._conn.execute(
                "SELECT reasoning_status FROM reasoning_log"
            ).fetchone()
        )
        assert row["reasoning_status"] == "incomplete"

    async def test_log_reasoning_persists_correlation_id(self, store):
        await store.log_reasoning(
            result=_reasoning_result(correlation_id="corr-reasoning-123"),
            trigger_name="t",
            device_id="ikeja-01",
        )
        row = await store._run(
            lambda: store._conn.execute(
                "SELECT correlation_id FROM reasoning_log"
            ).fetchone()
        )
        assert row["correlation_id"] == "corr-reasoning-123"

    async def test_export_reasoning_log_returns_bounded_rows_with_fields(self, store):
        await self._insert_reasoning(
            store,
            trigger_name="grid_instability",
            device_id="dev-01",
            timestamp=1_000,
            tier="gateway",
            action_tier="B",
            reasoning_status="complete",
            correlation_id="corr-1",
            prompt="Prompt text",
            text="Response text",
        )

        rows = await store.export_reasoning_log(limit=10)

        assert len(rows) == 1
        row = rows[0]
        assert row["trigger_name"] == "grid_instability"
        assert row["tier_used"] == "gateway"
        assert row["prompt"] == "Prompt text"
        assert row["response"] == "Response text"
        assert row["confidence"] == pytest.approx(0.9)
        assert row["action_tier"] == "B"
        assert row["device_id"] == "dev-01"
        assert row["model"] == "qwen2.5"
        assert row["tokens_used"] == 42
        assert row["latency_ms"] == 150
        assert row["proposed_action"] is None
        assert row["reasoning_status"] == "complete"
        assert row["correlation_id"] == "corr-1"
        assert row["timestamp"] == 1_000

    async def test_export_reasoning_log_filters_by_device_time_and_tier(self, store):
        await self._insert_reasoning(
            store,
            device_id="dev-01",
            timestamp=1_000,
            tier="local_slm",
            action_tier="A",
        )
        await self._insert_reasoning(
            store,
            device_id="dev-02",
            timestamp=2_000,
            tier="gateway",
            action_tier="B",
        )
        await self._insert_reasoning(
            store,
            device_id="dev-02",
            timestamp=3_000,
            tier="gateway",
            action_tier="C",
        )

        rows = await store.export_reasoning_log(
            device_id="dev-02",
            since_ms=1_500,
            until_ms=2_500,
            tier_used="gateway",
            action_tier="B",
            limit=10,
        )

        assert len(rows) == 1
        assert rows[0]["device_id"] == "dev-02"
        assert rows[0]["timestamp"] == 2_000
        assert rows[0]["action_tier"] == "B"

    async def test_export_reasoning_log_filters_by_status_and_correlation(self, store):
        await self._insert_reasoning(
            store,
            timestamp=1_000,
            reasoning_status="complete",
            correlation_id="corr-keep",
        )
        await self._insert_reasoning(
            store,
            timestamp=2_000,
            reasoning_status="incomplete",
            correlation_id="corr-keep",
        )
        await self._insert_reasoning(
            store,
            timestamp=3_000,
            reasoning_status="incomplete",
            correlation_id="corr-other",
        )

        rows = await store.export_reasoning_log(
            reasoning_status="incomplete",
            correlation_id="corr-keep",
            limit=10,
        )

        assert len(rows) == 1
        assert rows[0]["reasoning_status"] == "incomplete"
        assert rows[0]["correlation_id"] == "corr-keep"
        assert rows[0]["timestamp"] == 2_000

    async def test_export_reasoning_log_orders_most_recent_first(self, store):
        await self._insert_reasoning(store, timestamp=1_000, correlation_id="old")
        await self._insert_reasoning(store, timestamp=3_000, correlation_id="new")
        await self._insert_reasoning(store, timestamp=2_000, correlation_id="middle")

        rows = await store.export_reasoning_log(limit=10)

        assert [row["correlation_id"] for row in rows] == ["new", "middle", "old"]

    async def test_export_reasoning_log_caps_limit_at_1000(self, store):
        for i in range(1005):
            await self._insert_reasoning(
                store,
                timestamp=i,
                correlation_id=f"corr-{i}",
            )

        rows = await store.export_reasoning_log(limit=5_000)

        assert len(rows) == 1000
        assert rows[0]["correlation_id"] == "corr-1004"


# ─── inbound_messages ─────────────────────────────────────────────────────────


class TestInboundMessages:
    async def test_store_and_consume_message(self, store):
        await store.store_incoming_message(
            channel="sms",
            from_number="+234800000000",
            message="YES",
        )
        reply = await store.consume_incoming_message(
            channel="sms",
            from_number="+234800000000",
            since_ms=0,
        )
        assert reply == "YES"

    async def test_consume_respects_since_ms(self, store):
        await store.store_incoming_message(
            channel="sms",
            from_number="+234800000000",
            message="OLD",
            received_at_ms=1_000,
        )
        await store.store_incoming_message(
            channel="sms",
            from_number="+234800000000",
            message="NEW",
            received_at_ms=2_000,
        )
        reply = await store.consume_incoming_message(
            channel="sms",
            from_number="+234800000000",
            since_ms=1_500,
        )
        assert reply == "NEW"

    async def test_consume_is_single_use(self, store):
        await store.store_incoming_message(
            channel="sms",
            from_number="+234800000000",
            message="NO",
        )
        first = await store.consume_incoming_message(
            channel="sms",
            from_number="+234800000000",
            since_ms=0,
        )
        second = await store.consume_incoming_message(
            channel="sms",
            from_number="+234800000000",
            since_ms=0,
        )
        assert first == "NO"
        assert second is None


# ─── remote_command_execution_log ─────────────────────────────────────────────


class TestRemoteCommandSecurityIncidentLog:
    async def test_recent_incident_senders_are_grouped_by_sender(self, store):
        await store.log_remote_command_security_incident(
            incident_id="incident-1",
            channel="sms",
            from_number="+234800000001",
            reason="remote_command_rejection_feedback_suppressed",
            rejection_count=6,
            threshold=5,
            window_ms=600_000,
            created_at_ms=2_000,
        )
        await store.log_remote_command_security_incident(
            incident_id="incident-2",
            channel="sms",
            from_number="+234800000001",
            reason="remote_command_rejection_feedback_suppressed",
            rejection_count=7,
            threshold=5,
            window_ms=600_000,
            created_at_ms=3_000,
        )
        await store.log_remote_command_security_incident(
            incident_id="incident-3",
            channel="whatsapp",
            from_number="whatsapp:+234800000002",
            reason="remote_command_rejection_feedback_suppressed",
            rejection_count=6,
            threshold=5,
            window_ms=600_000,
            created_at_ms=4_000,
        )
        await store.log_remote_command_security_incident(
            incident_id="old-incident",
            channel="sms",
            from_number="+234800000003",
            reason="remote_command_rejection_feedback_suppressed",
            rejection_count=6,
            threshold=5,
            window_ms=600_000,
            created_at_ms=500,
        )

        senders = await store.get_recent_remote_command_incident_senders(
            since_ms=1_000,
        )

        assert senders == [
            {
                "channel": "whatsapp",
                "from_number": "whatsapp:+234800000002",
                "last_incident_at_ms": 4_000,
                "incident_count": 1,
            },
            {
                "channel": "sms",
                "from_number": "+234800000001",
                "last_incident_at_ms": 3_000,
                "incident_count": 2,
            },
        ]


class TestRemoteCommandExecutionLog:
    async def test_log_and_retrieve_execution_result(self, store):
        await store.log_remote_command_execution(
            command_id="cmd-1",
            channel="sms",
            command="REFRESH_POLICY",
            status="executed",
            detail="remote DevicePolicy refresh completed",
            executed=True,
            executed_at_ms=1234,
        )

        rows = await store.get_remote_command_execution_log()

        assert rows == [
            {
                "command_id": "cmd-1",
                "channel": "sms",
                "command": "REFRESH_POLICY",
                "status": "executed",
                "detail": "remote DevicePolicy refresh completed",
                "executed": True,
                "executed_at_ms": 1234,
            }
        ]
