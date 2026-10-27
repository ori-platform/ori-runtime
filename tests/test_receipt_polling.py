# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Every accepted message awaiting a receipt is polled in turn.

An accepted message takes the next queue position when it is accepted and again
after each poll that settles nothing, so messages a provider never reports on
cannot keep newer ones from being polled.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ori.actions.alert_delivery import AlertDeliveryReceipt
from ori.runtime import OriRuntime
from ori.state.store import StateStore


async def _accepted(store: StateStore, alert_id: str, at_ms: int) -> None:
    await store.mark_alert_accepted(
        alert_id,
        accepted_channel="sms",
        provider_message_id=alert_id,
        provider_status="Sent",
        accepted_at_ms=at_ms,
    )


async def _enqueue(store: StateStore, alert_id: str) -> None:
    await store.enqueue_alert(
        alert_id=alert_id,
        channel="sms",
        recipient="+234",
        message=alert_id,
        action_tier="A",
        trigger_name="t",
        original_ts=1,
        notice_kind="tier_d",
    )


class _Provider:
    """Never reports on any message but *answers*, which it reports failed."""

    def __init__(self, answers: str = "") -> None:
        self.answers = answers
        self.polled: list[str] = []

    async def get_delivery_receipt(
        self, *, provider_message_id: str, **_: Any
    ) -> AlertDeliveryReceipt | None:
        self.polled.append(provider_message_id)
        if provider_message_id != self.answers:
            return None
        return AlertDeliveryReceipt(
            provider_message_id=provider_message_id,
            provider_status="Rejected",
            observed_at_ms=1,
            terminal_failure=True,
        )


async def _runtime(tmp_path: Path, batch: int) -> OriRuntime:
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = StateStore(str(tmp_path / "s.db"))
    await runtime._state_store.open()
    runtime._alert_outbox_batch_size = batch
    return runtime


async def test_unanswered_receipts_cannot_hold_the_batch(tmp_path: Path) -> None:
    """The issue's reproduction: a batch of three, three accepted messages the
    provider never reports on, then a newer one it reports failed."""
    runtime = await _runtime(tmp_path, batch=3)
    store = runtime._state_store
    assert store is not None
    try:
        for n, alert_id in enumerate(["old-1", "old-2", "old-3", "newest"]):
            await _enqueue(store, alert_id)
            await _accepted(store, alert_id, 1_000 + n)
        provider = _Provider(answers="newest")
        for _ in range(2):
            await runtime._reconcile_alert_delivery_receipts(provider)  # type: ignore[arg-type]
        assert "newest" in provider.polled
        assert store._conn is not None
        status = store._conn.execute(
            "SELECT status FROM alert_outbox WHERE alert_id = 'newest'"
        ).fetchone()[0]
        assert status == "failed"
    finally:
        await store.close()


async def test_polling_follows_acceptance_order_not_queue_order(tmp_path: Path) -> None:
    """A message queued first but accepted last is polled after one accepted
    before it."""
    runtime = await _runtime(tmp_path, batch=1)
    store = runtime._state_store
    assert store is not None
    try:
        await _enqueue(store, "queued-first")
        await _enqueue(store, "queued-second")
        await _accepted(store, "queued-second", 1_000)
        await _accepted(store, "queued-first", 2_000)
        provider = _Provider()
        await runtime._reconcile_alert_delivery_receipts(provider)  # type: ignore[arg-type]
        assert provider.polled == ["queued-second"]
    finally:
        await store.close()


async def test_every_awaiting_message_is_polled_within_its_turn(tmp_path: Path) -> None:
    """With N awaiting and a batch of B, every message is polled within
    ceil(N / B) passes."""
    runtime = await _runtime(tmp_path, batch=2)
    store = runtime._state_store
    assert store is not None
    try:
        ids = [f"m{n}" for n in range(5)]
        for n, alert_id in enumerate(ids):
            await _enqueue(store, alert_id)
            await _accepted(store, alert_id, 1_000 + n)
        provider = _Provider()
        for _ in range(3):
            await runtime._reconcile_alert_delivery_receipts(provider)  # type: ignore[arg-type]
        assert set(provider.polled) == set(ids)
    finally:
        await store.close()
