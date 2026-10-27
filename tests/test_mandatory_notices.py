# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""A mandatory notice is never withheld, capped or abandoned.

Its kind is decided once, when it is created, and stored on its outbox row:
``tier_d`` for a first-party Tier D trigger's notice, ``protection_degraded``
for the runtime's own protection notices, ``optional`` for everything else.
The notice stays a Tier A act; the kind carries no authority.
"""

from __future__ import annotations

import sqlite3
import types
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ori.actions.alert_delivery import (
    AlertDeliveryReceipt,
    AlertSendReceipt,
    NoticeKind,
    notice_is_mandatory,
)
from ori.policy import alert_classes
from ori.runtime import OriRuntime
from ori.runtime._alert_text import resolve_notice_kind
from ori.state.store import StateStore

MANDATORY = [NoticeKind.TIER_D.value, NoticeKind.PROTECTION_DEGRADED.value]


async def _runtime(tmp_path: Path, name: str = "outbox.db") -> OriRuntime:
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = StateStore(str(tmp_path / name))
    await runtime._state_store.open()
    runtime._alert_outbox_retry_interval_s = 0.01
    return runtime


async def _enqueue(store: StateStore, alert_id: str, kind: str, **kw: Any) -> None:
    await store.enqueue_alert(
        alert_id=alert_id,
        channel="sms",
        recipient="+2340000000000",
        message=alert_id,
        action_tier=kw.pop("action_tier", "A"),
        trigger_name=kw.pop("trigger_name", "t"),
        original_ts=1234,
        notice_kind=kind,
    )


def _row(store: StateStore, alert_id: str) -> sqlite3.Row:
    assert store._conn is not None
    row = store._conn.execute(
        "SELECT * FROM alert_outbox WHERE alert_id = ?", (alert_id,)
    ).fetchone()
    assert row is not None
    return row


def test_only_optional_is_disposable():
    assert not notice_is_mandatory("optional")
    for kind in (*MANDATORY, "", "TIER_D", "something_new"):
        assert notice_is_mandatory(kind), kind


class TestNeverAbandoned:
    @pytest.mark.parametrize("kind", MANDATORY)
    async def test_the_retry_loop_keeps_a_mandatory_notice_past_the_threshold(
        self, tmp_path: Path, kind: str, caplog: pytest.LogCaptureFixture
    ):
        runtime = await _runtime(tmp_path)
        store = runtime._state_store
        assert store is not None
        await _enqueue(store, "m-1", kind)
        for _ in range(12):
            await store.mark_alert_attempt_failed("m-1")

        async def fail_and_stop(**kwargs: Any) -> AlertSendReceipt:
            runtime._shutdown_event.set()
            return AlertSendReceipt.refused(channel="sms")

        sender = AsyncMock()
        sender.send.side_effect = fail_and_stop
        sender.get_delivery_receipt.return_value = None
        try:
            with caplog.at_level("CRITICAL"):
                await runtime._alert_delivery_loop(sender)
            assert _row(store, "m-1")["status"] == "failed"
            assert "will keep retrying" in caplog.text
        finally:
            await store.close()

    @pytest.mark.parametrize("kind", MANDATORY)
    async def test_a_terminal_provider_failure_does_not_abandon_it(
        self, tmp_path: Path, kind: str, caplog: pytest.LogCaptureFixture
    ):
        runtime = await _runtime(tmp_path)
        store = runtime._state_store
        assert store is not None
        await _enqueue(store, "m-2", kind)
        for _ in range(12):
            await store.mark_alert_attempt_failed("m-2")
        await store.mark_alert_accepted(
            "m-2",
            accepted_channel="sms",
            provider_message_id="ATXid_1",
            provider_status="Sent",
            accepted_at_ms=1,
        )
        sender = AsyncMock()
        sender.get_delivery_receipt.return_value = AlertDeliveryReceipt(
            provider_message_id="ATXid_1",
            provider_status="Rejected",
            observed_at_ms=2,
            terminal_failure=True,
        )
        try:
            with caplog.at_level("CRITICAL"):
                await runtime._reconcile_alert_delivery_receipts(sender)
            assert _row(store, "m-2")["status"] == "failed"
            # This layer keeps it on its own, not only because the store refuses.
            assert "will keep retrying" in caplog.text
        finally:
            await store.close()

    @pytest.mark.parametrize("kind", [*MANDATORY, "something_new"])
    async def test_the_store_refuses_to_abandon_anything_but_optional(
        self, tmp_path: Path, kind: str
    ):
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        try:
            await _enqueue(store, "x", kind)
            await _enqueue(store, "o", "optional")
            assert await store.mark_alert_abandoned("x") is False
            assert await store.mark_alert_abandoned("o") is True
            assert _row(store, "x")["status"] == "pending"
            assert _row(store, "o")["status"] == "abandoned"
        finally:
            await store.close()


class TestABacklogNeverStarves:
    async def test_a_failed_row_goes_behind_rows_queued_before_its_failure(
        self, tmp_path: Path
    ):
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        try:
            for n in range(3):
                await _enqueue(store, f"r{n}", "optional")
            await store.mark_alert_attempt_failed("r0")
            await _enqueue(store, "late", "optional")
            order = [r["alert_id"] for r in await store.get_retryable_alerts(10)]
            assert order == ["r1", "r2", "r0", "late"]
        finally:
            await store.close()

    @pytest.mark.parametrize("batch", [1, 2, 3, 5])
    async def test_sustained_optional_arrivals_never_starve_a_mandatory_row(
        self, tmp_path: Path, batch: int
    ):
        """Real retry-loop passes; before each pass `batch` fresh optional rows
        arrive, more than the optional lane can take. The failing mandatory row
        is retried at least every other pass, and so is the oldest optional."""
        runtime = await _runtime(tmp_path)
        store = runtime._state_store
        assert store is not None
        runtime._alert_outbox_batch_size = batch
        await _enqueue(store, "mandatory", "tier_d")
        await store.mark_alert_attempt_failed("mandatory")
        await _enqueue(store, "first-optional", "optional")
        passes: list[list[str]] = [[]]
        arrivals = 0

        async def fail(*, alert: Any, **_kwargs: Any) -> AlertSendReceipt:
            passes[-1].append(alert.sms_body)
            if len(passes[-1]) == batch:
                if len(passes) == 8:
                    runtime._shutdown_event.set()
                else:
                    passes.append([])
                    nonlocal arrivals
                    for _ in range(batch):
                        arrivals += 1
                        await _enqueue(store, f"fresh-{arrivals}", "optional")
            return AlertSendReceipt.refused(channel="sms")

        sender = AsyncMock()
        sender.send.side_effect = fail
        sender.get_delivery_receipt.return_value = None
        try:
            await runtime._alert_delivery_loop(sender)
        finally:
            await store.close()
        served = [i for i, sent in enumerate(passes) if "mandatory" in sent]
        assert served and max(b - a for a, b in zip([-1, *served], served)) <= 2, passes
        assert any("first-optional" in sent for sent in passes[1:]), passes

    async def test_a_row_stamped_in_the_future_still_rotates(self, tmp_path: Path):
        """The order reads no clock: a device without an RTC can stamp an
        attempt years ahead before NTP corrects it."""
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        try:
            for n in range(50):
                await _enqueue(store, f"stuck-{n}", "tier_d")
            await _enqueue(store, "future", "tier_d")
            await store.mark_alert_attempt_failed("future", 2_000_000_000_000)
            seen = False
            for _ in range(5):
                batch = [r["alert_id"] for r in await store.get_retryable_alerts(50)]
                seen = seen or "future" in batch
                for alert_id in batch:
                    await store.mark_alert_attempt_failed(alert_id, 1_000)
            assert seen
        finally:
            await store.close()


class TestARowThisReleaseDecidedIsNeverDecidedAgain:
    async def test_an_optional_row_named_like_a_safety_notice_stays_optional(
        self, tmp_path: Path
    ):
        path = str(tmp_path / "s.db")
        store = StateStore(path)
        await store.open()
        await _enqueue(store, "skill", "optional", trigger_name="safety_check")
        await store.close()
        store = StateStore(path)
        await store.open()
        try:
            assert _row(store, "skill")["notice_kind"] == "optional"
        finally:
            await store.close()


class _Dispatcher:
    """A policy whose preference and cap both withhold every optional notice."""

    def permits_alert_class(self, *_a: Any, **_k: Any) -> bool:
        return False

    def permits_external_alert(self, *_a: Any, **_k: Any) -> bool:
        return False


class TestKindIsDecidedOnceAndStored:
    @pytest.mark.parametrize(
        "kind, action_tier, stored, sent",
        [
            ("tier_d", "A", "tier_d", True),
            # A declared Tier D is not authority: only the kind exempts.
            ("optional", "D", None, False),
            ("optional", "A", None, False),
        ],
    )
    async def test_a_mandatory_notice_passes_preference_and_cap_uncounted(
        self,
        tmp_path: Path,
        kind: str,
        action_tier: str,
        stored: str | None,
        sent: bool,
        monkeypatch: pytest.MonkeyPatch,
    ):
        # Bound to a preference class, so the preference applies to this trigger.
        monkeypatch.setitem(
            alert_classes.TRIGGER_ALERT_CLASS,
            ("energy-anomaly-detector", "dangerous_overcurrent"),
            alert_classes.UNUSUAL_CONSUMPTION_SPIKE,
        )
        runtime = await _runtime(tmp_path)
        store = runtime._state_store
        assert store is not None
        runtime._dispatcher = _Dispatcher()  # type: ignore[assignment]
        sender = AsyncMock()
        sender.send.return_value = AlertSendReceipt.refused(channel="sms")
        try:
            result = await runtime._send_or_queue_alert(
                channel="sms",
                message="m",
                recipient="+2340000000000",
                action_tier=action_tier,
                trigger_name="dangerous_overcurrent",
                original_ts=1,
                received_at_ms=1,
                alert_sender=sender,
                skill_name="energy-anomaly-detector",
                skill_is_first_party=True,
                notice_kind=kind,
            )
            assert store._conn is not None
            rows = store._conn.execute(
                "SELECT notice_kind, action_tier FROM alert_outbox"
            ).fetchall()
            if stored is None:
                assert rows == []
                assert result is not True
            else:
                assert [(r[0], r[1]) for r in rows] == [(stored, action_tier)]
                assert result is True
            assert sender.send.called is sent
            counted = store._conn.execute(
                "SELECT COUNT(*) FROM skill_state "
                "WHERE skill_name = '__runtime_alert_policy__'"
            ).fetchone()[0]
            assert counted == 0
        finally:
            await store.close()

    async def test_the_safety_route_stores_protection_degraded(self, tmp_path: Path):
        runtime = await _runtime(tmp_path)
        store = runtime._state_store
        assert store is not None
        runtime._operator_contact = "+2340000000000"
        sender = AsyncMock()
        sender.send.return_value = AlertSendReceipt.refused(channel="sms")
        try:
            await runtime._send_or_queue_safety_alert(
                message="SAFETY x", trigger_name="safety_absent", alert_sender=sender
            )
            assert store._conn is not None
            row = store._conn.execute(
                "SELECT notice_kind, action_tier FROM alert_outbox"
            ).fetchone()
            assert tuple(row) == ("protection_degraded", "A")
        finally:
            await store.close()


def _ctx(*, first_party: Any, triggers: list[Any], trigger_name: Any) -> Any:
    skill = types.SimpleNamespace(name="s", first_party=first_party, triggers=triggers)
    return types.SimpleNamespace(skill=skill, trigger_name=trigger_name, event=None)


class TestTheExecutorReadsTheMatchedTrigger:
    D = {"name": "dangerous_overcurrent", "action_tier": "D"}
    A = {"name": "anomalous_draw", "action_tier": "A"}

    @pytest.mark.parametrize(
        "first_party, trigger_name, expected",
        [
            (True, "dangerous_overcurrent", "tier_d"),
            (True, "anomalous_draw", "optional"),
            (False, "dangerous_overcurrent", "optional"),
            ("yes", "dangerous_overcurrent", "optional"),
            (True, "", "optional"),
            (True, None, "optional"),
            (True, "missing", "optional"),
        ],
    )
    def test_kind(self, first_party: Any, trigger_name: Any, expected: str):
        ctx = _ctx(
            first_party=first_party,
            triggers=[self.A, self.D],
            trigger_name=trigger_name,
        )
        assert resolve_notice_kind(ctx) == expected

    def test_trigger_objects_as_well_as_mappings(self):
        trigger = types.SimpleNamespace(name="dangerous_overcurrent", action_tier="d")
        ctx = _ctx(
            first_party=True, triggers=[trigger], trigger_name="dangerous_overcurrent"
        )
        assert resolve_notice_kind(ctx) == "tier_d"


_V250_OUTBOX = """
CREATE TABLE alert_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL UNIQUE,
    channel TEXT NOT NULL,
    recipient TEXT NOT NULL,
    message TEXT NOT NULL,
    intent TEXT NOT NULL DEFAULT 'tier_a_alert',
    template_variables_json TEXT NOT NULL DEFAULT '[]',
    action_tier TEXT NOT NULL,
    trigger_name TEXT NOT NULL DEFAULT '',
    original_ts INTEGER NOT NULL,
    queued_at_ms INTEGER NOT NULL DEFAULT 0,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_attempt_ts INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    accepted_channel TEXT NOT NULL DEFAULT '',
    provider_message_id TEXT NOT NULL DEFAULT '',
    provider_status TEXT NOT NULL DEFAULT '',
    accepted_at_ms INTEGER,
    delivered_at_ms INTEGER,
    last_status_at_ms INTEGER
)
"""

# The previous release's insert, as it still runs after a rollback.
_V250_INSERT = """
INSERT INTO alert_outbox
    (alert_id, channel, recipient, message, intent, template_variables_json,
     action_tier, trigger_name, original_ts, queued_at_ms, status)
VALUES (?, 'sms', '+234', 'm', 'tier_a_alert', '[]', ?, ?, 1, 1, ?)
"""


class TestMigration:
    ROWS = [
        ("d", "D", "critical", "failed", "tier_d"),
        ("safety", "A", "safety_absent", "pending", "protection_degraded"),
        (
            "unconnected",
            "A",
            "sensor_unconnected_warning",
            "failed",
            "protection_degraded",
        ),
        ("connected", "A", "sensor_connected_notice", "pending", "protection_degraded"),
        ("loss", "A", "measurement_degraded:s1", "pending", "protection_degraded"),
        (
            "loss2",
            "A",
            "measurement_degraded_persists:s1",
            "failed",
            "protection_degraded",
        ),
        ("skill", "A", "high_draw", "pending", "optional"),
        ("lookalike", "A", "safetyx", "pending", "optional"),
        ("held", "A", "safety_absent", "accepted", "protection_degraded"),
        ("gone", "A", "safety_absent", "abandoned", "protection_degraded"),
    ]

    async def test_queued_rows_are_classified_and_a_rollback_s_rows_again(
        self, tmp_path: Path
    ):
        path = tmp_path / "v250.db"
        conn = sqlite3.connect(path)
        conn.execute(_V250_OUTBOX)
        for alert_id, tier, trigger, status, _ in self.ROWS:
            conn.execute(_V250_INSERT, (alert_id, tier, trigger, status))
        conn.commit()
        conn.close()

        store = StateStore(str(path))
        await store.open()
        try:
            for alert_id, *_, expected in self.ROWS:
                assert _row(store, alert_id)["notice_kind"] == expected, alert_id
        finally:
            await store.close()

        # Rolled back: the previous release's insert still works on the
        # migrated table, and writes its notice optional, which that release
        # then abandons. Reopening under this release classifies it again.
        conn = sqlite3.connect(path)
        conn.execute(_V250_INSERT, ("after", "A", "safety_absent", "pending"))
        conn.commit()
        assert conn.execute(
            "SELECT notice_kind FROM alert_outbox WHERE alert_id = 'after'"
        ).fetchone() == (None,)
        conn.close()

        store = StateStore(str(path))
        await store.open()
        try:
            assert _row(store, "after")["notice_kind"] == "protection_degraded"
            # Placed behind every row already queued, so it waits its turn.
            assert store._conn is not None
            highest = store._conn.execute(
                "SELECT MAX(retry_seq) FROM alert_outbox WHERE alert_id != 'after'"
            ).fetchone()[0]
            assert _row(store, "after")["retry_seq"] > highest
        finally:
            await store.close()
