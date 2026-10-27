# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The monthly cap counts observed provider acceptances, and what it withholds
is tallied.

device-policy/v2 caps a channel's messages in a month; the runtime counts each
provider acceptance it observes, so a refusal spends nothing and the retry a
provider accepts is counted then.
alert-delivery/v1 *Withholding tallies*: an optional notice the cap withholds
is tallied ``capped``, like one a preference withholds is tallied ``disabled``,
judged before the recipient, in the month of the runtime's clock.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest

from ori.actions.alert_delivery import AlertDeliveryReceipt, AlertSendReceipt
from ori.policy import alert_classes
from ori.policy.device_policy import DevicePolicy
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.runtime import OriRuntime
from ori.state.store import StateStore

SKILL = "energy-anomaly-detector"
TRIGGER = "grid_phcn_restored"


class _Sender:
    """Refuses or accepts every submission, as the test sets it."""

    def __init__(self) -> None:
        self.accept = False
        self.sent: list[str] = []

    async def send(self, *, alert: Any, to_number: str, **_: Any) -> AlertSendReceipt:
        self.sent.append(alert.sms_body)
        if not self.accept:
            return AlertSendReceipt.refused(channel="sms")
        return AlertSendReceipt(
            accepted=True, channel="sms", provider_message_id=f"m{len(self.sent)}"
        )

    async def get_delivery_receipt(self, **_: Any) -> AlertDeliveryReceipt | None:
        return None


async def _runtime(tmp_path: Path, *, cap: int, recipient: bool = True) -> OriRuntime:
    runtime = OriRuntime(config_path="ori.yaml")
    dispatcher = ActionDispatcher()
    dispatcher.update_policy(
        dataclasses.replace(
            DevicePolicy.unrestricted(),
            alert_sms_monthly_cap=cap,
            alert_whatsapp_monthly_cap=cap,
        )
    )
    runtime._dispatcher = dispatcher
    runtime._state_store = StateStore(str(tmp_path / "s.db"))
    await runtime._state_store.open()
    runtime._operator_contact = "+2340000000000" if recipient else ""
    runtime._alert_outbox_retry_interval_s = 0.01
    runtime._alert_outbox_max_non_tier_d_attempts = 2
    return runtime


async def _alert(runtime: OriRuntime, sender: _Sender, n: int, **kw: Any) -> Any:
    return await runtime._send_or_queue_alert(
        channel="sms",
        message=f"alert {n}",
        recipient=runtime._operator_contact,
        action_tier="A",
        trigger_name=kw.get("trigger", f"t{n}"),
        original_ts=kw.get("original_ts", 1),
        received_at_ms=1,
        alert_sender=sender,  # type: ignore[arg-type]
        skill_name=SKILL,
        skill_is_first_party=True,
    )


async def _retry_passes(runtime: OriRuntime, sender: Any, passes: int) -> None:
    """Run *passes* real retry-loop passes, then stop the loop."""
    done = 0
    original = runtime._reconcile_alert_delivery_receipts

    async def reconcile(alert_sender: Any) -> None:
        nonlocal done
        await original(alert_sender)
        done += 1
        if done >= passes:
            runtime._shutdown_event.set()

    runtime._reconcile_alert_delivery_receipts = reconcile  # type: ignore[method-assign]
    runtime._shutdown_event.clear()
    await runtime._alert_delivery_loop(sender)  # type: ignore[arg-type]
    runtime._reconcile_alert_delivery_receipts = original  # type: ignore[method-assign]


def _tallies(store: StateStore) -> dict[str, dict[str, Any]]:
    assert store._conn is not None
    rows = store._conn.execute(
        "SELECT key, value FROM skill_state WHERE skill_name = ?",
        ("__runtime_alert_preferences__",),
    ).fetchall()
    return {row[0]: json.loads(row[1]) for row in rows}


class TestTheCapCountsAcceptances:
    async def test_refusals_spend_nothing_even_once_abandoned(self, tmp_path: Path):
        """The issue's reproduction: two refused and abandoned alerts, then a
        third, which the cap must not withhold."""
        runtime = await _runtime(tmp_path, cap=2)
        sender = _Sender()
        try:
            assert await _alert(runtime, sender, 1) is True
            assert await _alert(runtime, sender, 2) is True
            await _retry_passes(runtime, sender, 3)
            store = runtime._state_store
            assert store is not None
            assert await store.get_retryable_alerts(10) == []
            assert await runtime._current_policy_counted_alerts("sms") == 0

            sender.accept = True
            assert await _alert(runtime, sender, 3) is True
            assert sender.sent[-1] == "alert 3"
            assert await runtime._current_policy_counted_alerts("sms") == 1
        finally:
            await runtime._state_store.close()  # type: ignore[union-attr]

    async def test_the_retry_a_provider_accepts_is_counted_once(self, tmp_path: Path):
        runtime = await _runtime(tmp_path, cap=5)
        runtime._alert_outbox_max_non_tier_d_attempts = 10
        sender = _Sender()
        try:
            assert await _alert(runtime, sender, 1) is True
            assert await runtime._current_policy_counted_alerts("sms") == 0
            sender.accept = True
            await _retry_passes(runtime, sender, 2)
            assert await runtime._current_policy_counted_alerts("sms") == 1
        finally:
            await runtime._state_store.close()  # type: ignore[union-attr]

    async def test_a_mandatory_notice_s_accepted_retry_is_not_counted(
        self, tmp_path: Path
    ):
        runtime = await _runtime(tmp_path, cap=5)
        sender = _Sender()
        store = runtime._state_store
        assert store is not None
        try:
            await store.enqueue_alert(
                alert_id="m",
                channel="sms",
                recipient="+234",
                message="m",
                action_tier="A",
                trigger_name="safety_absent",
                original_ts=1,
                notice_kind="protection_degraded",
            )
            sender.accept = True
            await _retry_passes(runtime, sender, 2)
            assert sender.sent == ["m"]
            assert await runtime._current_policy_counted_alerts("sms") == 0
        finally:
            await store.close()


class TestWhatTheCapWithholdsIsTallied:
    @pytest.mark.parametrize("recipient", [True, False])
    async def test_a_capped_notice_is_tallied_before_the_recipient_is_checked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recipient: bool
    ):
        monkeypatch.setitem(
            alert_classes.TRIGGER_ALERT_CLASS, (SKILL, TRIGGER), "grid_power_restored"
        )
        runtime = await _runtime(tmp_path, cap=0, recipient=recipient)
        sender = _Sender()
        store = runtime._state_store
        assert store is not None
        try:
            for n in range(3):
                assert await _alert(runtime, sender, n, trigger=TRIGGER) is False
            assert sender.sent == []
            month = dt.datetime.now(dt.UTC).strftime("%Y-%m")
            tally = _tallies(store)[f"capped:sms:grid_power_restored:{month}"]
            assert (tally["outcome"], tally["reason"]) == ("capped", "monthly_cap")
            assert tally["count"] == 3
        finally:
            await store.close()

    async def test_a_tally_s_month_is_the_runtime_s_not_the_event_s(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setitem(
            alert_classes.TRIGGER_ALERT_CLASS, (SKILL, TRIGGER), "grid_power_restored"
        )
        runtime = await _runtime(tmp_path, cap=0)
        sender = _Sender()
        store = runtime._state_store
        assert store is not None
        try:
            # An event stamped in 2001: its own clock is not the tally's.
            await _alert(runtime, sender, 1, trigger=TRIGGER, original_ts=10**12)
            month = dt.datetime.now(dt.UTC).strftime("%Y-%m")
            assert list(_tallies(store)) == [f"capped:sms:grid_power_restored:{month}"]
        finally:
            await store.close()


class TestEveryAwaitingReceiptIsPolled:
    async def test_unanswered_receipts_cannot_hold_the_batch(self, tmp_path: Path):
        """The #981 reproduction: three accepted rows the provider never
        reports on, then a newer one it reports failed, with a batch of three."""
        runtime = await _runtime(tmp_path, cap=-1)
        runtime._alert_outbox_batch_size = 3
        store = runtime._state_store
        assert store is not None
        polled: list[str] = []

        class Provider(_Sender):
            async def get_delivery_receipt(
                self, *, provider_message_id: str, **_: Any
            ) -> AlertDeliveryReceipt | None:
                polled.append(provider_message_id)
                if provider_message_id != "newest":
                    return None
                return AlertDeliveryReceipt(
                    provider_message_id="newest",
                    provider_status="Rejected",
                    observed_at_ms=1,
                    terminal_failure=True,
                )

        try:
            for n, mid in enumerate(["old-1", "old-2", "old-3", "newest"]):
                await store.enqueue_alert(
                    alert_id=mid,
                    channel="sms",
                    recipient="+234",
                    message=mid,
                    action_tier="A",
                    trigger_name="t",
                    original_ts=1,
                    notice_kind="tier_d",
                )
                await store.mark_alert_accepted(
                    mid,
                    accepted_channel="sms",
                    provider_message_id=mid,
                    provider_status="Sent",
                    accepted_at_ms=1_000 + n,
                )
            provider = Provider()
            for _ in range(2):
                await runtime._reconcile_alert_delivery_receipts(provider)  # type: ignore[arg-type]
            assert "newest" in polled
            assert store._conn is not None
            status = store._conn.execute(
                "SELECT status FROM alert_outbox WHERE alert_id = 'newest'"
            ).fetchone()[0]
            assert status == "failed"
        finally:
            await store.close()


def test_the_tally_key_keeps_its_earlier_form() -> None:
    """Counts written before the capped tally existed stay where they were."""
    from ori.runtime._alert_text import withheld_tally_key

    ts = int(dt.datetime(2026, 10, 1, tzinfo=dt.UTC).timestamp() * 1000)
    assert withheld_tally_key("disabled", "SMS", "c", ts) == "disabled:sms:c:2026-10"
    assert withheld_tally_key("capped", "sms", None, ts) == (
        "capped:sms:unclassified:2026-10"
    )


class _TwoChannels:
    """A failover sender over two scripted transports, recording each call."""

    def __init__(self, *, sms_accepts: bool, whatsapp_accepts: bool) -> None:
        from ori.actions.alert_failover import AlertFailoverSender

        self.calls: list[str] = []
        # Messages the provider later reports terminally failed.
        self.fail_ids: set[str] = set()
        outer = self

        class _Transport:
            def __init__(self, channel: str, accepts: bool) -> None:
                self.channel, self.accepts = channel, accepts

            async def submit(self, *, alert: Any, to_number: str) -> AlertSendReceipt:
                outer.calls.append(self.channel)
                if not self.accepts:
                    return AlertSendReceipt.refused(channel=self.channel)
                return AlertSendReceipt(
                    accepted=True,
                    channel=self.channel,
                    provider_message_id=f"{self.channel}{len(outer.calls)}",
                )

            async def get_delivery_receipt(
                self, provider_message_id: str
            ) -> AlertDeliveryReceipt | None:
                if provider_message_id not in outer.fail_ids:
                    return None
                outer.fail_ids.discard(provider_message_id)
                return AlertDeliveryReceipt(
                    provider_message_id=provider_message_id,
                    provider_status="Rejected",
                    observed_at_ms=1,
                    terminal_failure=True,
                )

        self.sms = _Transport("sms", sms_accepts)
        self.whatsapp = _Transport("whatsapp", whatsapp_accepts)
        self.sender = AlertFailoverSender(
            primary_channel="sms", sms_sender=self.sms, whatsapp_sender=self.whatsapp
        )


async def _policy_runtime(
    tmp_path: Path, *, sms: int | None, whatsapp: int | None, batch: int = 50
) -> OriRuntime:
    runtime = await _runtime(tmp_path, cap=0)
    assert runtime._dispatcher is not None
    runtime._dispatcher.update_policy(
        dataclasses.replace(
            DevicePolicy.unrestricted(),
            alert_sms_monthly_cap=sms,
            alert_whatsapp_monthly_cap=whatsapp,
        )
    )
    runtime._alert_outbox_batch_size = batch
    runtime._alert_outbox_max_non_tier_d_attempts = 3
    return runtime


async def _queue(store: StateStore, n: int, *, kind: str = "optional") -> None:
    await store.enqueue_alert(
        alert_id=f"q{n}",
        channel="sms",
        recipient="+234",
        message=f"q{n}",
        action_tier="A",
        trigger_name="t",
        original_ts=1,
        notice_kind=kind,
    )


def _row(store: StateStore, alert_id: str) -> Any:
    assert store._conn is not None
    return store._conn.execute(
        "SELECT status, attempt_count FROM alert_outbox WHERE alert_id = ?",
        (alert_id,),
    ).fetchone()


class TestEveryOptionalProviderCallIsChecked:
    async def test_serial_retries_stop_when_observed_usage_reaches_the_cap(
        self, tmp_path: Path
    ):
        runtime = await _policy_runtime(tmp_path, sms=2, whatsapp=0)
        store = runtime._state_store
        assert store is not None
        two = _TwoChannels(sms_accepts=True, whatsapp_accepts=True)
        try:
            for n in range(6):
                await _queue(store, n)
            await _retry_passes(runtime, two.sender, 3)
            assert two.calls == ["sms", "sms"]
            assert await runtime._current_policy_counted_alerts("sms") == 2
            # The other four wait, charged no attempt, never abandoned.
            assert [tuple(_row(store, f"q{n}")) for n in range(2, 6)] == [
                ("pending", 0)
            ] * 4
        finally:
            await store.close()

    async def test_failover_never_carries_an_optional_notice_into_cap_zero(
        self, tmp_path: Path
    ):
        runtime = await _policy_runtime(tmp_path, sms=5, whatsapp=0)
        store = runtime._state_store
        assert store is not None
        two = _TwoChannels(sms_accepts=False, whatsapp_accepts=True)
        try:
            await _queue(store, 0)
            await _retry_passes(runtime, two.sender, 2)
            assert "whatsapp" not in two.calls
            assert await runtime._current_policy_counted_alerts("whatsapp") == 0
        finally:
            await store.close()

    async def test_a_first_send_is_checked_on_each_channel_it_could_use(
        self, tmp_path: Path
    ):
        runtime = await _policy_runtime(tmp_path, sms=5, whatsapp=0)
        two = _TwoChannels(sms_accepts=False, whatsapp_accepts=True)
        try:
            result = await _alert(runtime, two.sender, 1)  # type: ignore[arg-type]
            assert result is True  # queued: the obligation is kept
            assert two.calls == ["sms"]
        finally:
            await runtime._state_store.close()  # type: ignore[union-attr]

    async def test_a_mandatory_notice_is_never_checked(self, tmp_path: Path):
        runtime = await _policy_runtime(tmp_path, sms=0, whatsapp=0)
        store = runtime._state_store
        assert store is not None
        two = _TwoChannels(sms_accepts=False, whatsapp_accepts=True)
        try:
            await _queue(store, 0, kind="tier_d")
            await _retry_passes(runtime, two.sender, 1)
            assert two.calls == ["sms", "whatsapp"]
        finally:
            await store.close()


class TestASpentChannelDefersWithoutStarving:
    async def test_a_backlog_beyond_the_batch_drains_through_the_open_channel(
        self, tmp_path: Path
    ):
        runtime = await _policy_runtime(tmp_path, sms=0, whatsapp=-1, batch=2)
        store = runtime._state_store
        assert store is not None
        two = _TwoChannels(sms_accepts=True, whatsapp_accepts=True)
        try:
            for n in range(5):
                await _queue(store, n)
            await _retry_passes(runtime, two.sender, 3)
            assert two.calls == ["whatsapp"] * 5
        finally:
            await store.close()

    async def test_a_deferred_batch_moves_behind_the_rows_it_held_back(
        self, tmp_path: Path
    ):
        runtime = await _policy_runtime(tmp_path, sms=0, whatsapp=0, batch=2)
        store = runtime._state_store
        assert store is not None
        two = _TwoChannels(sms_accepts=True, whatsapp_accepts=True)
        try:
            for n in range(4):
                await _queue(store, n)
            next_batch = [r["alert_id"] for r in await store.get_retryable_alerts(2)]
            assert next_batch == ["q0", "q1"]
            await _retry_passes(runtime, two.sender, 1)
            assert two.calls == []
            next_batch = [r["alert_id"] for r in await store.get_retryable_alerts(2)]
            assert next_batch == ["q2", "q3"]
            assert all(tuple(_row(store, f"q{n}")) == ("pending", 0) for n in range(4))
        finally:
            await store.close()

    async def test_a_deferred_row_is_sent_in_the_next_month(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Last month's usage stays recorded; the new month's key has none."""
        from tests.package_layout import patch_runtime

        january = int(
            dt.datetime(2030, 1, 31, 23, 59, tzinfo=dt.UTC).timestamp() * 1000
        )
        february = int(dt.datetime(2030, 2, 1, 0, 1, tzinfo=dt.UTC).timestamp() * 1000)
        clock = {"now": january}
        patch_runtime(monkeypatch, "now_ms", lambda: clock["now"])
        runtime = await _policy_runtime(tmp_path, sms=1, whatsapp=0)
        store = runtime._state_store
        assert store is not None
        two = _TwoChannels(sms_accepts=True, whatsapp_accepts=True)
        try:
            await _queue(store, 0)
            await _queue(store, 1)
            await _retry_passes(runtime, two.sender, 2)
            assert two.calls == ["sms"]
            clock["now"] = february
            await _retry_passes(runtime, two.sender, 1)
            assert two.calls == ["sms", "sms"]
            usage = "__runtime_alert_policy__"
            assert (
                await store.get_skill_state(usage, "external_alert_count:sms:2030-01")
                == "1"
            )
            assert (
                await store.get_skill_state(usage, "external_alert_count:sms:2030-02")
                == "1"
            )
        finally:
            await store.close()


class TestUsageIsCountedExactlyAsObserved:
    async def test_concurrent_increments_lose_nothing(self, tmp_path: Path):
        import asyncio

        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        try:
            await asyncio.gather(
                *(store.increment_skill_counter("ns", "k", 1) for _ in range(50))
            )
            assert await store.get_skill_state("ns", "k") == "50"
        finally:
            await store.close()

    async def test_an_unlimited_cap_still_records_usage(self, tmp_path: Path):
        runtime = await _policy_runtime(tmp_path, sms=-1, whatsapp=-1)
        two = _TwoChannels(sms_accepts=True, whatsapp_accepts=True)
        try:
            await _alert(runtime, two.sender, 1)  # type: ignore[arg-type]
            assert await runtime._current_policy_counted_alerts("sms") == 1
        finally:
            await runtime._state_store.close()  # type: ignore[union-attr]

    async def test_concurrent_sends_can_overshoot_and_that_is_the_stated_limit(
        self, tmp_path: Path
    ):
        """Two optional sends authorised before either is counted both go out.

        The cap bounds observed acceptances only between checks; this is the
        overshoot the capability matrix states.
        """
        import asyncio

        runtime = await _policy_runtime(tmp_path, sms=1, whatsapp=0)
        gate = asyncio.Event()

        class Slow:
            calls = 0

            async def send(self, *, alert: Any, to_number: str, **kw: Any) -> Any:
                may_use = kw.get("may_use")
                assert may_use is not None and await may_use("sms")
                Slow.calls += 1
                await gate.wait()
                return AlertSendReceipt(
                    accepted=True, channel="sms", provider_message_id=f"s{Slow.calls}"
                )

        try:
            sends = [
                asyncio.ensure_future(_alert(runtime, Slow(), n))  # type: ignore[arg-type]
                for n in range(2)
            ]
            await asyncio.sleep(0.05)
            gate.set()
            await asyncio.gather(*sends)
            assert await runtime._current_policy_counted_alerts("sms") == 2
        finally:
            await runtime._state_store.close()  # type: ignore[union-attr]

    async def test_each_acceptance_counts_on_the_channel_that_accepted_it(
        self, tmp_path: Path
    ):
        """Accepted on sms, reported terminally failed, then accepted again on
        whatsapp, which a retry tries first: two observed acceptances, one on
        each channel."""
        runtime = await _policy_runtime(tmp_path, sms=5, whatsapp=5)
        store = runtime._state_store
        assert store is not None
        two = _TwoChannels(sms_accepts=True, whatsapp_accepts=True)
        two.fail_ids.add("sms1")
        try:
            await _queue(store, 0)
            await _retry_passes(runtime, two.sender, 2)
            assert two.calls == ["sms", "whatsapp"]
            assert await runtime._current_policy_counted_alerts("sms") == 1
            assert await runtime._current_policy_counted_alerts("whatsapp") == 1
        finally:
            await store.close()

    async def test_a_first_send_racing_a_retry_can_overshoot_as_stated(
        self, tmp_path: Path
    ):
        """A retry and a first send, each checked before either is counted,
        both go out: the concurrent overshoot the capability matrix states."""
        import asyncio

        runtime = await _policy_runtime(tmp_path, sms=1, whatsapp=0)
        store = runtime._state_store
        assert store is not None
        gate = asyncio.Event()
        checked: list[str] = []

        class Slow:
            async def send(self, *, alert: Any, to_number: str, **kw: Any) -> Any:
                assert await kw["may_use"]("sms")
                checked.append(alert.sms_body)
                await gate.wait()
                return AlertSendReceipt(
                    accepted=True,
                    channel="sms",
                    provider_message_id=f"s{len(checked)}",
                )

            async def get_delivery_receipt(self, **_: Any) -> None:
                return None

        try:
            await _queue(store, 0)
            retry = asyncio.ensure_future(_retry_passes(runtime, Slow(), 1))
            first = asyncio.ensure_future(_alert(runtime, Slow(), 1))  # type: ignore[arg-type]
            while len(checked) < 2:
                await asyncio.sleep(0.01)
            gate.set()
            await asyncio.gather(retry, first)
            assert sorted(checked) == ["alert 1", "q0"]
            assert await runtime._current_policy_counted_alerts("sms") == 2
        finally:
            await store.close()

    async def test_a_lost_usage_write_is_reported_not_hidden(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ):
        runtime = await _policy_runtime(tmp_path, sms=5, whatsapp=0)
        store = runtime._state_store
        assert store is not None
        two = _TwoChannels(sms_accepts=True, whatsapp_accepts=True)

        async def broken(*_a: Any, **_k: Any) -> None:
            raise RuntimeError("disk full")

        store.increment_skill_counter = broken  # type: ignore[method-assign]
        try:
            with caplog.at_level("ERROR"):
                await _alert(runtime, two.sender, 1)  # type: ignore[arg-type]
            assert "undercounts" in caplog.text
        finally:
            await store.close()


async def test_an_exact_channel_send_is_checked_before_the_provider_call(
    tmp_path: Path,
) -> None:
    runtime = await _policy_runtime(tmp_path, sms=0, whatsapp=0)
    calls: list[str] = []

    class Exact:
        async def send_exact(self, **_: Any) -> AlertSendReceipt:
            calls.append("sms")
            return AlertSendReceipt(accepted=True, channel="sms")

    async def no(_channel: str) -> bool:
        return False

    try:
        receipt = await runtime._submit(
            Exact(),  # type: ignore[arg-type]
            object(),  # type: ignore[arg-type]
            "+234",
            "sms",
            allow_failover=False,
            budget={"may_use": no},
        )
        from ori.actions.alert_failover import CAP_SPENT

        assert (receipt.accepted, receipt.error, calls) == (False, CAP_SPENT, [])
    finally:
        await runtime._state_store.close()  # type: ignore[union-attr]
