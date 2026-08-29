# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The cross-store confirmation outbox: the durable record that an approved
epoch still needs the evidence store to confirm the identical anchor_epoch_id
before it may reach firmware (ori-specs/device-provisioning/v1.md)."""

from __future__ import annotations

import json

import pytest

from ori.security.firmware.telemetry import anchor_epoch_id
from ori.state.store import StateStore
from ori.utils.time_utils import now_ms

DEVICE = "ori-edge-confirm-01"
KEY_A = "AAAA" * 8 + "="
KEY_B = "BBBB" * 8 + "="
CAP = "sha256:" + "cc" * 32


@pytest.fixture
async def store(tmp_path):
    s = StateStore(db_path=str(tmp_path / "s.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


def epoch(key: str, cap: str = CAP, posture: str = "development") -> str:
    return anchor_epoch_id(
        device_id=DEVICE, public_key_b64=key, posture=posture, capability_hash=cap
    )


async def _register(store: StateStore, key: str, cap: str = CAP) -> None:
    await store.upsert_firmware_device_anchor(
        device_id=DEVICE,
        public_key_b64=key,
        posture="development",
        capability_hash=cap,
        manifest_json=json.dumps({"c": cap}),
        channel_map_json="{}",
    )


async def test_approval_enqueues_a_confirmation_obligation(store):
    await _register(store, KEY_A)
    # No obligation until approval.
    assert await store.get_firmware_confirmation_status(DEVICE, epoch(KEY_A)) is None

    await store.approve_firmware_device(DEVICE, actor="uid=1:op", reason="bring-up")

    # Approval records exactly one pending obligation, for the promoted epoch.
    assert (
        await store.get_firmware_confirmation_status(DEVICE, epoch(KEY_A))
        == "confirmation_pending"
    )
    pending = await store.list_pending_firmware_confirmations()
    assert [(p["device_id"], p["anchor_epoch_id"]) for p in pending] == [
        (DEVICE, epoch(KEY_A))
    ]


async def test_a_single_approval_records_exactly_one_row(store):
    await _register(store, KEY_A)
    await store.approve_firmware_device(DEVICE, actor="op", reason="r")
    # One promotion -> one obligation, not a duplicate per retry.
    assert len(await store.list_pending_firmware_confirmations()) == 1


async def test_re_promotion_reopens_confirmation(store):
    # revoke -> reinstate -> approve promotes the SAME epoch again. Because
    # the earlier revocation may have reached the evidence store, the grant must
    # re-confirm rather than keep the stale `confirmed`.
    await _register(store, KEY_A)
    await store.approve_firmware_device(DEVICE, actor="op", reason="r")
    await store.resolve_firmware_confirmation(
        DEVICE, epoch(KEY_A), status="confirmed", at_ms=now_ms()
    )

    await store.revoke_firmware_device(DEVICE, actor="op", reason="compromised")
    await store.reinstate_firmware_device(DEVICE, actor="op", reason="cleared")
    await store.approve_firmware_device(DEVICE, actor="op", reason="back")

    # Re-opened: the same epoch is confirmation_pending again, with a fresh
    # obligation the worker will pick up.
    assert (
        await store.get_firmware_confirmation_status(DEVICE, epoch(KEY_A))
        == "confirmation_pending"
    )
    pending = await store.list_pending_firmware_confirmations()
    assert [(p["device_id"], p["anchor_epoch_id"]) for p in pending] == [
        (DEVICE, epoch(KEY_A))
    ]
    assert pending[0]["attempt_count"] == 0


async def test_a_new_epoch_gets_its_own_obligation(store):
    # Approve A1, confirm it, then a manifest change + promotion creates a
    # NEW epoch that is again confirmation_pending while A1 stays confirmed.
    await _register(store, KEY_A)
    await store.approve_firmware_device(DEVICE, actor="op", reason="r")
    await store.resolve_firmware_confirmation(
        DEVICE, epoch(KEY_A), status="confirmed", at_ms=now_ms()
    )

    cap2 = "sha256:" + "dd" * 32
    await _register(store, KEY_A, cap2)  # same key, new manifest -> pending
    await store.approve_firmware_device(DEVICE, actor="op", reason="manifest")

    assert (
        await store.get_firmware_confirmation_status(DEVICE, epoch(KEY_A))
        == "confirmed"
    )
    assert (
        await store.get_firmware_confirmation_status(DEVICE, epoch(KEY_A, cap2))
        == "confirmation_pending"
    )


async def test_resolution_is_terminal_and_idempotent(store):
    await _register(store, KEY_A)
    await store.approve_firmware_device(DEVICE, actor="op", reason="r")

    await store.resolve_firmware_confirmation(
        DEVICE, epoch(KEY_A), status="quarantined", at_ms=now_ms()
    )
    assert (
        await store.get_firmware_confirmation_status(DEVICE, epoch(KEY_A))
        == "quarantined"
    )
    # A later attempt to confirm a quarantined grant must not move it.
    await store.resolve_firmware_confirmation(
        DEVICE, epoch(KEY_A), status="confirmed", at_ms=now_ms()
    )
    assert (
        await store.get_firmware_confirmation_status(DEVICE, epoch(KEY_A))
        == "quarantined"
    )
    # ...and it is no longer offered to the worker.
    assert await store.list_pending_firmware_confirmations() == []


async def test_summary_counts_and_oldest_age(store):
    await _register(store, KEY_A)
    await store.approve_firmware_device(DEVICE, actor="op", reason="r")

    base = now_ms()
    summary = await store.get_firmware_confirmation_summary(base + 5000)
    assert summary["confirmation_pending_count"] == 1
    assert summary["quarantined_count"] == 0
    assert summary["oldest_pending_age_ms"] is not None
    assert summary["oldest_pending_age_ms"] >= 0

    await store.resolve_firmware_confirmation(
        DEVICE, epoch(KEY_A), status="quarantined", at_ms=now_ms()
    )
    summary = await store.get_firmware_confirmation_summary(now_ms())
    assert summary["confirmation_pending_count"] == 0
    assert summary["quarantined_count"] == 1
    assert summary["oldest_pending_age_ms"] is None


async def test_invalid_resolution_status_is_refused(store):
    await _register(store, KEY_A)
    await store.approve_firmware_device(DEVICE, actor="op", reason="r")
    with pytest.raises(ValueError, match="invalid confirmation resolution"):
        await store.resolve_firmware_confirmation(
            DEVICE, epoch(KEY_A), status="confirmation_pending", at_ms=now_ms()
        )


async def test_re_approval_refuses_while_quarantined(store):
    # A quarantined epoch is a cross-store disagreement that needs explicit
    # operator resolution. Re-approving it must NOT silently clear the
    # quarantine: the promotion is refused and nothing changes.
    await _register(store, KEY_A)
    await store.approve_firmware_device(DEVICE, actor="op", reason="r")
    await store.resolve_firmware_confirmation(
        DEVICE, epoch(KEY_A), status="quarantined", at_ms=now_ms()
    )

    # Take the identity through revoke -> reinstate so the same epoch is
    # pending again and eligible for (attempted) re-promotion.
    await store.revoke_firmware_device(DEVICE, actor="op", reason="c")
    await store.reinstate_firmware_device(DEVICE, actor="op", reason="cleared")

    # The re-approval is refused, and the quarantine is untouched.
    assert (
        await store.approve_firmware_device(DEVICE, actor="op", reason="back") is False
    )
    assert (
        await store.get_firmware_confirmation_status(DEVICE, epoch(KEY_A))
        == "quarantined"
    )
    # The device did not become active.
    dev = await store.get_firmware_device(DEVICE)
    assert not dev["approved"]


async def test_upgrade_backfills_a_fail_closed_obligation(tmp_path):
    # A database approved before cross-store confirmation existed holds an
    # active anchor with NO obligation row. Reopening it must enrol that
    # anchor as confirmation_pending -- failing closed -- so the gates do
    # not grant effective authority the evidence store has never confirmed,
    # and the coordinator has a real row to resolve rather than silently
    # reporting success against nothing.
    import sqlite3

    db = str(tmp_path / "legacy.db")
    s = StateStore(db_path=db)
    await s.open()
    await _register(s, KEY_A)
    await s.approve_firmware_device(DEVICE, actor="op", reason="r")
    active_epoch = epoch(KEY_A)
    assert (
        await s.get_firmware_confirmation_status(DEVICE, active_epoch)
        == "confirmation_pending"
    )
    await s.close()

    # Simulate the pre-confirmation shape: the anchor is active, but no
    # obligation was ever recorded for it.
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM firmware_confirmation_outbox")
    conn.commit()
    conn.close()

    s = StateStore(db_path=db)
    await s.open()
    try:
        # The upgrade backfilled a fresh pending obligation for the active
        # anchor -- the gates now see a concrete not-yet-confirmed status
        # rather than None forever.
        assert (
            await s.get_firmware_confirmation_status(DEVICE, active_epoch)
            == "confirmation_pending"
        )
        pending = await s.list_pending_firmware_confirmations()
        assert [(p["device_id"], p["anchor_epoch_id"]) for p in pending] == [
            (DEVICE, active_epoch)
        ]

        # Idempotent: reopening again neither duplicates the row nor reopens
        # a resolution.
        await s.resolve_firmware_confirmation(
            DEVICE, active_epoch, status="confirmed", at_ms=now_ms()
        )
    finally:
        await s.close()

    s = StateStore(db_path=db)
    await s.open()
    try:
        assert (
            await s.get_firmware_confirmation_status(DEVICE, active_epoch)
            == "confirmed"
        )
        assert await s.list_pending_firmware_confirmations() == []
    finally:
        await s.close()
