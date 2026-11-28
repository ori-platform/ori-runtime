# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The notice that a Tier D act failed: sent at once, queued beside it as a
`tier_d` row, and retried by the outbox until a provider accepts it."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import pytest

from ori.actions.alert_delivery import AlertSendReceipt, OutboundAlert
from ori.actions.alert_failover import AlertFailoverSender
from ori.runtime import OriRuntime
from ori.state.store import StateStore
from tests.waiting import wait_until

CONTACT = "+2340000000000"


class _Transport:
    """A WhatsApp provider that accepts or refuses, optionally held."""

    def __init__(self, *, accepted: bool, held: bool = False) -> None:
        self.accepted = accepted
        self.release = asyncio.Event()
        if not held:
            self.release.set()
        self.entered = asyncio.Event()
        self.sent: list[OutboundAlert] = []

    async def submit(self, *, alert: OutboundAlert, to_number: str) -> AlertSendReceipt:
        self.entered.set()
        await self.release.wait()
        self.sent.append(alert)
        if not self.accepted:
            return AlertSendReceipt.refused(channel="whatsapp")
        return AlertSendReceipt(
            accepted=True,
            channel="whatsapp",
            provider_message_id="SM" + "b" * 32,
            provider_status="queued",
            accepted_at_ms=1_800_000_000_000,
        )


class _Sms:
    """The last-resort SMSAction."""

    def __init__(self, *, accepted: bool) -> None:
        self.accepted = accepted
        self.sent: list[str] = []

    async def send(self, message: str, *, to_number: str) -> bool:
        self.sent.append(message)
        return self.accepted


def _runtime(store: StateStore | None) -> OriRuntime:
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._operator_contact = CONTACT
    runtime._primary_alert_channel = "whatsapp"
    runtime._device_location = "Test site"
    runtime._device_timezone = "UTC"
    runtime._state_store = store
    return runtime


def _sender(transport: _Transport) -> AlertFailoverSender:
    # No SMS channel configured: the last resort is what reaches SMS.
    return AlertFailoverSender(
        primary_channel="whatsapp", sms_sender=None, whatsapp_sender=transport
    )


async def _notify(runtime: OriRuntime, transport: _Transport, sms: _Sms) -> None:
    await runtime._send_tier_d_failure_notice(
        "trip_relay", "dev-01", alert_sender=_sender(transport), last_resort=sms
    )


async def _rows(store: StateStore) -> list[dict[str, Any]]:
    return await store.get_retryable_alerts(10, mandatory=True)


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    s = StateStore(str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


async def test_an_accepted_notice_is_recorded_accepted(store: StateStore) -> None:
    runtime, transport, sms = (
        _runtime(store),
        _Transport(accepted=True),
        _Sms(accepted=True),
    )
    await _notify(runtime, transport, sms)
    assert len(transport.sent) == 1 and sms.sent == []
    assert await _rows(store) == []


async def test_a_refused_notice_falls_to_the_direct_sms(store: StateStore) -> None:
    runtime, transport, sms = (
        _runtime(store),
        _Transport(accepted=False),
        _Sms(accepted=True),
    )
    await _notify(runtime, transport, sms)
    assert len(transport.sent) == 1
    assert len(sms.sent) == 1 and "trip_relay" in sms.sent[0]
    assert await _rows(store) == []


async def test_a_notice_nothing_accepts_is_left_queued_tier_d(
    store: StateStore,
) -> None:
    runtime, transport, sms = (
        _runtime(store),
        _Transport(accepted=False),
        _Sms(accepted=False),
    )
    await _notify(runtime, transport, sms)
    (row,) = await _rows(store)
    assert row["notice_kind"] == "tier_d"
    assert [r["alert_id"] for r in await runtime._next_retry_batch(10)] == [
        row["alert_id"]
    ]


async def test_the_retry_loop_leaves_a_row_alone_while_its_first_send_is_held(
    store: StateStore,
) -> None:
    runtime = _runtime(store)
    transport, sms = _Transport(accepted=True, held=True), _Sms(accepted=False)
    notifying = asyncio.create_task(_notify(runtime, transport, sms))
    await asyncio.wait_for(transport.entered.wait(), 5)
    await wait_until(lambda: _committed(store), what="the row to be queued")
    for _ in range(3):  # several retry ticks while the first send is held
        assert await runtime._next_retry_batch(10) == []
    transport.release.set()
    await asyncio.wait_for(notifying, 5)
    assert len(transport.sent) == 1
    assert await _rows(store) == []


def _committed(store: StateStore) -> bool:
    assert store._conn is not None
    return bool(store._conn.execute("SELECT 1 FROM alert_outbox").fetchone())


async def test_the_send_goes_and_is_recorded_while_the_store_is_held(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, transport, sms = (
        _runtime(store),
        _Transport(accepted=True),
        _Sms(accepted=False),
    )
    unblock = asyncio.Event()
    enqueue = store.enqueue_alert

    async def held(**kwargs: Any) -> bool:
        await unblock.wait()
        return await enqueue(**kwargs)

    monkeypatch.setattr(store, "enqueue_alert", held)
    notifying = asyncio.create_task(_notify(runtime, transport, sms))
    await wait_until(lambda: bool(transport.sent), what="the send, ahead of the store")
    assert not notifying.done()
    unblock.set()
    await asyncio.wait_for(notifying, 5)
    assert await _rows(store) == []
    assert len(transport.sent) == 1


async def test_a_queue_that_fails_still_sends_and_says_so(
    store: StateStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    runtime, transport, sms = (
        _runtime(store),
        _Transport(accepted=False),
        _Sms(accepted=False),
    )

    async def broken(**_kwargs: Any) -> bool:
        raise RuntimeError("database is locked")

    monkeypatch.setattr(store, "enqueue_alert", broken)
    with caplog.at_level(logging.CRITICAL):
        await _notify(runtime, transport, sms)
    assert len(transport.sent) == 1 and len(sms.sent) == 1
    assert any("neither accepted nor queued" in r.getMessage() for r in caplog.records)


async def test_a_cancelled_first_send_leaves_its_row_to_the_retry_loop(
    store: StateStore,
) -> None:
    runtime = _runtime(store)
    transport, sms = _Transport(accepted=True, held=True), _Sms(accepted=False)
    notifying = asyncio.create_task(_notify(runtime, transport, sms))
    await asyncio.wait_for(transport.entered.wait(), 5)
    await wait_until(lambda: _committed(store), what="the row to be queued")
    notifying.cancel()
    with pytest.raises(asyncio.CancelledError):
        await notifying
    assert not runtime._alert_first_attempts
    (row,) = await runtime._next_retry_batch(10)
    assert row["notice_kind"] == "tier_d"


async def test_a_queued_notice_is_retried_after_a_restart(tmp_path: Path) -> None:
    database = str(tmp_path / "state.db")
    store = StateStore(database)
    await store.open()
    try:
        await _notify(_runtime(store), _Transport(accepted=False), _Sms(accepted=False))
    finally:
        await store.close()
    reopened = StateStore(database)
    await reopened.open()
    try:
        (row,) = await _runtime(reopened)._next_retry_batch(10)
        assert row["notice_kind"] == "tier_d"
        assert "trip_relay" in row["message"]
    finally:
        await reopened.close()


async def test_without_an_alert_sender_the_route_sends_the_direct_sms() -> None:
    runtime = _runtime(None)
    sms = _Sms(accepted=True)
    context: Any = type("Ctx", (), {"alert_sender": None, "sms_action": sms})()
    await runtime._tier_d_failure_notice_route(context)("trip_relay", "dev-01")
    assert len(sms.sent) == 1


async def test_an_acceptance_it_cannot_record_is_not_sent_again(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, transport, sms = (
        _runtime(store),
        _Transport(accepted=True),
        _Sms(accepted=False),
    )

    async def broken(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("database is locked")

    monkeypatch.setattr(store, "mark_alert_accepted", broken)
    await _notify(runtime, transport, sms)
    assert await runtime._next_retry_batch(10) == []
    assert len(transport.sent) == 1


async def test_two_failures_in_one_millisecond_are_two_notices(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.package_layout import patch_runtime

    patch_runtime(monkeypatch, "now_ms", lambda: 1_800_000_000_000)
    runtime, transport, sms = (
        _runtime(store),
        _Transport(accepted=False),
        _Sms(accepted=False),
    )
    await _notify(runtime, transport, sms)
    await _notify(runtime, transport, sms)
    assert len(await _rows(store)) == 2


async def test_the_notice_is_sent_under_the_mandatory_budget(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, transport, sms = (
        _runtime(store),
        _Transport(accepted=True),
        _Sms(accepted=False),
    )
    asked: list[object] = []
    budget_check = runtime._budget_check

    def recorded(notice_kind: object, action_tier: str) -> dict[str, Any]:
        asked.append(notice_kind)
        return budget_check(notice_kind, action_tier)

    monkeypatch.setattr(runtime, "_budget_check", recorded)
    await _notify(runtime, transport, sms)
    assert asked == ["tier_d"]
    (row,) = [r for r in await _all_rows(store)]
    assert row["notice_kind"] == "tier_d"


async def _all_rows(store: StateStore) -> list[dict[str, Any]]:
    assert store._conn is not None
    return [
        dict(r)
        for r in store._conn.execute("SELECT notice_kind FROM alert_outbox").fetchall()
    ]


async def test_a_sender_that_raises_still_reaches_the_direct_sms(
    store: StateStore,
) -> None:
    class _Raising(_Transport):
        async def submit(
            self, *, alert: OutboundAlert, to_number: str
        ) -> AlertSendReceipt:
            raise RuntimeError("provider down")

    runtime, sms = _runtime(store), _Sms(accepted=True)
    await _notify(runtime, _Raising(accepted=True), sms)
    assert len(sms.sent) == 1
    assert await _rows(store) == []


async def test_without_an_operator_contact_nothing_is_queued(
    store: StateStore, caplog: pytest.LogCaptureFixture
) -> None:
    runtime, transport, sms = (
        _runtime(store),
        _Transport(accepted=True),
        _Sms(accepted=True),
    )
    runtime._operator_contact = ""
    with caplog.at_level(logging.CRITICAL):
        await _notify(runtime, transport, sms)
    assert transport.sent == [] and sms.sent == []
    assert await _all_rows(store) == []
    assert any("no operator_contact" in r.getMessage() for r in caplog.records)


async def test_a_row_in_flight_holds_no_slot_another_notice_needs(
    store: StateStore,
) -> None:
    """Excluded before the limit: a batch of one still reaches the next notice."""
    runtime = _runtime(store)
    for alert_id in ("older", "later"):
        assert await store.enqueue_alert(
            alert_id=alert_id,
            channel="sms",
            recipient=CONTACT,
            message="CRITICAL",
            action_tier="A",
            trigger_name="tier_d_failure:trip_relay",
            original_ts=1,
            notice_kind="tier_d",
        )
    runtime._alert_first_attempts["older"] += 1
    for _ in range(3):
        assert [r["alert_id"] for r in await runtime._next_retry_batch(1)] == ["later"]


async def test_a_queued_failure_notice_keeps_its_direct_sms_after_a_restart(
    tmp_path: Path,
) -> None:
    database = str(tmp_path / "state.db")
    store = StateStore(database)
    await store.open()
    try:
        await _notify(_runtime(store), _Transport(accepted=False), _Sms(accepted=False))
    finally:
        await store.close()

    reopened = StateStore(database)
    await reopened.open()
    try:
        runtime = _runtime(reopened)
        sms = _Sms(accepted=True)
        context: Any = type("Ctx", (), {"alert_sender": None, "sms_action": sms})()
        runtime._tier_d_failure_notice_route(
            context
        )  # as the restarted runtime wires it
        runtime._alert_outbox_retry_interval_s = 0.01
        loop = asyncio.create_task(
            runtime._alert_delivery_loop(_sender(_Transport(accepted=False)))
        )
        try:
            await wait_until(lambda: bool(sms.sent), what="the direct SMS on retry")
            await wait_until(
                lambda: not _committed_pending(reopened), what="the row accepted"
            )
        finally:
            runtime._shutdown_event.set()
            await asyncio.wait_for(loop, 5)
        assert len(sms.sent) == 1 and "trip_relay" in sms.sent[0]
    finally:
        await reopened.close()


def _committed_pending(store: StateStore) -> bool:
    assert store._conn is not None
    return bool(
        store._conn.execute(
            "SELECT 1 FROM alert_outbox WHERE status IN ('pending', 'failed')"
        ).fetchone()
    )


async def test_a_repeated_clock_after_a_restart_does_not_absorb_a_new_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.package_layout import patch_runtime

    patch_runtime(monkeypatch, "now_ms", lambda: 1_800_000_000_000)
    database = str(tmp_path / "state.db")
    store = StateStore(database)
    await store.open()
    try:
        await _notify(_runtime(store), _Transport(accepted=True), _Sms(accepted=False))
    finally:
        await store.close()
    reopened = StateStore(database)
    await reopened.open()
    try:
        await _notify(
            _runtime(reopened), _Transport(accepted=False), _Sms(accepted=False)
        )
        (row,) = await _rows(reopened)
        assert row["notice_kind"] == "tier_d"
    finally:
        await reopened.close()


async def _queued_row(store: StateStore, alert_id: str) -> None:
    assert await store.enqueue_alert(
        alert_id=alert_id,
        channel="whatsapp",
        recipient=CONTACT,
        message="CRITICAL",
        action_tier="A",
        trigger_name="tier_d_failure:trip_relay",
        original_ts=1,
        notice_kind="tier_d",
    )


async def _one_retry_pass(
    runtime: OriRuntime, transport: _Transport, passes: int = 2
) -> None:
    """Run the real retry loop until it has fetched *passes* batches, then stop it."""
    fetched: list[int] = []
    fetch = runtime._next_retry_batch

    async def counted(size: int) -> list[dict[str, Any]]:
        batch = await fetch(size)
        fetched.append(len(batch))
        return batch

    runtime._next_retry_batch = counted  # type: ignore[method-assign]
    runtime._alert_outbox_retry_interval_s = 0.01
    loop = asyncio.create_task(runtime._alert_delivery_loop(_sender(transport)))
    try:
        await wait_until(lambda: len(fetched) >= passes, what="the retry passes")
    finally:
        runtime._shutdown_event.set()
        await asyncio.wait_for(loop, 5)


@pytest.mark.parametrize("ordering", ["claimed-during-fetch", "settled-after-fetch"])
async def test_a_batch_row_taken_or_settled_since_the_fetch_is_not_sent(
    store: StateStore, monkeypatch: pytest.MonkeyPatch, ordering: str
) -> None:
    runtime, transport = _runtime(store), _Transport(accepted=True)
    await _queued_row(store, "x")
    get = store.get_retryable_alerts

    async def racing(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        rows = await get(*args, **kwargs)
        if ordering == "claimed-during-fetch":
            runtime._alert_first_attempts["x"] += 1  # its first attempt began meanwhile
        else:
            await store.mark_alert_accepted(
                "x",
                accepted_channel="whatsapp",
                provider_message_id="SM" + "c" * 32,
                provider_status="queued",
                accepted_at_ms=1,
                delivered_at_ms=None,
            )
        return rows

    monkeypatch.setattr(store, "get_retryable_alerts", racing)
    await _one_retry_pass(runtime, transport)
    assert transport.sent == []


async def test_an_optional_notice_spelling_the_prefix_gets_no_last_resort(
    store: StateStore,
) -> None:
    """A sensor id can spell `tier_d_failure:`; only a tier_d row has the last resort."""
    runtime = _runtime(store)
    assert await store.enqueue_alert(
        alert_id="optional",
        channel="whatsapp",
        recipient=CONTACT,
        message="ordinary optional alert",
        action_tier="A",
        trigger_name="tier_d_failure:my_sensor",
        original_ts=1,
        notice_kind="optional",
    )
    sms = _Sms(accepted=True)
    runtime._tier_d_last_resort = sms
    await _one_retry_pass(runtime, _Transport(accepted=False))
    assert sms.sent == []


async def test_the_real_route_sends_while_another_connection_holds_the_store(
    tmp_path: Path,
) -> None:
    import sqlite3

    database = str(tmp_path / "state.db")
    store = StateStore(database)
    await store.open()
    holder = sqlite3.connect(database, isolation_level=None)
    try:
        runtime, transport = _runtime(store), _Transport(accepted=True)
        context: Any = type(
            "Ctx",
            (),
            {"alert_sender": _sender(transport), "sms_action": _Sms(accepted=False)},
        )()
        holder.execute("BEGIN EXCLUSIVE")
        notifying = asyncio.ensure_future(
            runtime._tier_d_failure_notice_route(context)("trip_relay", "dev-01")
        )
        # Sent while the lock is still held: the first send waits on no store.
        await wait_until(lambda: bool(transport.sent), what="the send, store locked")
        holder.execute("ROLLBACK")
        await asyncio.wait_for(notifying, 30)
    finally:
        holder.close()
        await store.close()


async def test_a_store_error_on_one_row_does_not_end_the_retry_loop(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, transport = _runtime(store), _Transport(accepted=True)
    await _queued_row(store, "x")
    read = store.alert_is_retryable
    calls: list[str] = []

    async def failing_once(alert_id: str) -> bool:
        calls.append(alert_id)
        if len(calls) == 1:
            raise RuntimeError("disk I/O error")
        return await read(alert_id)

    monkeypatch.setattr(store, "alert_is_retryable", failing_once)
    runtime._alert_outbox_retry_interval_s = 0.01
    loop = asyncio.create_task(runtime._alert_delivery_loop(_sender(transport)))
    try:
        await wait_until(lambda: bool(transport.sent), what="a send after the error")
    finally:
        runtime._shutdown_event.set()
        await asyncio.wait_for(loop, 5)
    assert not loop.cancelled() and loop.exception() is None


@pytest.mark.parametrize("notice_kind", ["tier_d", "optional"])
async def test_a_retry_accepted_but_not_recorded_is_not_sent_again(
    store: StateStore, monkeypatch: pytest.MonkeyPatch, notice_kind: str
) -> None:
    runtime, transport = _runtime(store), _Transport(accepted=True)
    assert await store.enqueue_alert(
        alert_id="x",
        channel="whatsapp",
        recipient=CONTACT,
        message="CRITICAL",
        action_tier="A",
        trigger_name="tier_d_failure:trip_relay",
        original_ts=1,
        notice_kind=notice_kind,
    )

    async def broken(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("database is locked")

    monkeypatch.setattr(store, "mark_alert_accepted", broken)
    await _one_retry_pass(runtime, transport, passes=5)
    assert len(transport.sent) == 1


async def test_a_failed_receipt_reconcile_does_not_stop_the_retries(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, transport = _runtime(store), _Transport(accepted=True)
    await _queued_row(store, "x")

    async def broken(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("disk I/O error")

    monkeypatch.setattr(runtime, "_reconcile_alert_delivery_receipts", broken)
    await _one_retry_pass(runtime, transport)
    assert len(transport.sent) == 1
