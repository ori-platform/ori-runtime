# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Checkpoints reach the courier in the order they were produced.

A later checkpoint is not handed off while an earlier one is still its
predecessor: until the runtime durably records a verified `queued`
acknowledgement for it, a covering stop, or a verified terminal refusal. The
ordering is among checkpoints only: envelopes and registrations are handed off
while a checkpoint waits, however many checkpoints wait behind it. A copy whose
bytes are damaged is kept, counted and taken out of the order.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from typing import Any
from unittest.mock import patch

import pytest

from ori.gateway.evidence_outbound import (
    DRAIN_BATCH,
    RETRY_INTERVAL_S,
    EvidenceOutboundAckRouter,
)
from ori.security.evidence import first_party
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.security.evidence.ledger import EvidenceDeliveryLedger

from .test_outbound_route import ENVELOPE_SECRET, _auth
from .test_registration_obligation import (
    DEVICE,
    REFERENCE,
    Clock,
    Device,
    _retire_copy,
    _router,
    _serve,
    _stop,
    _tier_d_row,
)


@pytest.fixture
async def device(tmp_path):
    d = Device(tmp_path)
    await d.start()
    try:
        yield d
    finally:
        if d.attestor is not None:
            d.attestor.close()


def _ack(digest: str, outcome: str = "queued", reason: str = "") -> dict[str, Any]:
    return {
        "device_id": DEVICE,
        "artifact_type": "checkpoint",
        "artifact_digest": digest,
        "outcome": outcome,
        "reason": reason,
        "acknowledged_at_ms": 1,
    }


def _checkpoints(published: list[bytes]) -> list[str]:
    """Digests of the checkpoints carried, in the order they were carried."""
    out = []
    for payload in published:
        carriage = json.loads(payload)
        if carriage["artifact_type"] == "checkpoint":
            wire = base64.b64decode(carriage["artifact_b64"])
            out.append("sha256:" + hashlib.sha256(wire).hexdigest())
    return out


def _live(device: Device) -> FirstPartyEvidenceAttestor:
    assert device.attestor is not None
    return device.attestor


_ISSUED = iter(range(1_787_000_000_000, 1_787_000_000_000 + 10**6, 1000))


async def _checkpoint(device: Device) -> dict[str, Any]:
    """Issue a checkpoint distinct from the last: two in one millisecond are one."""
    with patch.object(first_party, "now_ms", return_value=next(_ISSUED)):
        issued = await _live(device).issue_checkpoint()
    assert issued is not None
    return issued


def _types(published: list[bytes]) -> list[str]:
    return [json.loads(p)["artifact_type"] for p in published]


async def test_a_later_checkpoint_waits_for_the_earlier_ones_acknowledgement(
    device: Device,
):
    """Shutdown checkpoint A loses its acknowledgement; reboot checkpoint B waits."""
    attestor = _live(device)
    a = await _checkpoint(device)
    assert a is not None
    clock = Clock(10**12)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        assert _checkpoints(client.published) == [a["artifact_digest"]]
        # A's acknowledgement never arrives; B is produced.
        b = await _checkpoint(device)
        assert b is not None
        await publisher.drain()
        assert _checkpoints(client.published) == [a["artifact_digest"]], (
            "B passed A while A was unacknowledged"
        )
        # A becomes due again and is retried; B still waits behind it.
        clock.now += int(RETRY_INTERVAL_S * 1000)
        await publisher.drain()
        assert _checkpoints(client.published) == [a["artifact_digest"]] * 2
        # A is acknowledged; now B goes.
        await _router(attestor, clock).handle_ack(_ack(a["artifact_digest"]))
        await publisher.drain()
        assert _checkpoints(client.published) == [
            a["artifact_digest"],
            a["artifact_digest"],
            b["artifact_digest"],
        ]
    finally:
        await _stop(shutdown, task)


async def test_order_survives_a_restart(device: Device):
    a = await _checkpoint(device)
    b = await _checkpoint(device)
    assert a is not None and b is not None
    device.restart_close()
    attestor = await device.start()
    clock = Clock(10**12)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        assert _checkpoints(client.published) == [a["artifact_digest"]]
        await _router(attestor, clock).handle_ack(_ack(a["artifact_digest"]))
        await publisher.drain()
        assert _checkpoints(client.published) == [
            a["artifact_digest"],
            b["artifact_digest"],
        ]
    finally:
        await _stop(shutdown, task)


async def test_envelopes_are_handed_off_while_a_checkpoint_waits(device: Device):
    attestor = _live(device)
    a = await _checkpoint(device)
    assert a is not None
    clock = Clock(10**12)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        b = await _checkpoint(device)
        assert b is not None
        assert await attestor.attest_action(_tier_d_row(9)) is not None
        await publisher.drain()
        assert "delivery_envelope" in _types(client.published)
        assert _checkpoints(client.published) == [a["artifact_digest"]]
    finally:
        await _stop(shutdown, task)


@pytest.mark.parametrize("reason", ["malformed", "binding_mismatch"])
async def test_a_terminal_refusal_releases_the_next_checkpoint_once_recorded(
    device: Device, reason: str
):
    """The refused bytes are kept, retired `refused`, before the successor goes."""
    attestor = _live(device)
    a = await _checkpoint(device)
    clock = Clock(10**12)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        b = await _checkpoint(device)
        routed = await _router(attestor, clock).handle_ack(
            _ack(a["artifact_digest"], outcome="refused", reason=reason)
        )
        assert routed.outcome == "applied"
        held = device.handoff(a["artifact_digest"])
        assert held["retire_outcome"] == "refused"
        assert held["artifact_json"] == a["artifact_json"]
        await publisher.drain()
        assert _checkpoints(client.published) == [
            a["artifact_digest"],
            b["artifact_digest"],
        ]
    finally:
        await _stop(shutdown, task)


async def test_a_deferral_leaves_the_checkpoint_a_predecessor(device: Device):
    attestor = _live(device)
    a = await _checkpoint(device)
    clock = Clock(10**12)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        await _checkpoint(device)
        await _router(attestor, clock).handle_ack(
            _ack(a["artifact_digest"], outcome="refused", reason="queue_full")
        )
        for _ in range(3):
            clock.now += 10**9
            await publisher.drain()
        assert set(_checkpoints(client.published)) == {a["artifact_digest"]}
    finally:
        await _stop(shutdown, task)


@pytest.mark.parametrize("outcome", ["queued", "malformed"])
async def test_a_forged_acknowledgement_releases_nothing(device: Device, outcome):
    attestor = _live(device)
    assert attestor.outbound is not None
    a = await _checkpoint(device)
    signed_at = 1787000003000
    clock = Clock(10**12)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        await _checkpoint(device)
        router = EvidenceOutboundAckRouter(
            device_id=DEVICE,
            outbox=attestor.outbound,
            message_auth=_auth(ENVELOPE_SECRET),
            now=lambda: signed_at + 1,
        )
        ack = _ack(a["artifact_digest"])
        if outcome != "queued":
            ack.update(outcome="refused", reason=outcome)
        forged = _auth("not-the-site-secret").sign(
            ack, message_type="evidence_outbound_ack", signed_at_ms=signed_at
        )
        assert (await router.handle_ack(forged)).outcome == "refused"
        clock.now += 10**9
        await publisher.drain()
        assert set(_checkpoints(client.published)) == {a["artifact_digest"]}
        assert device.handoff(a["artifact_digest"])["retired_at_ms"] is None
    finally:
        await _stop(shutdown, task)


async def test_a_crash_before_the_refusal_is_recorded_releases_nothing(
    device: Device,
):
    """No durable failure record, no release: across the crash and a restart."""
    attestor = _live(device)
    a = await _checkpoint(device)
    clock = Clock(10**12)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        b = await _checkpoint(device)

        def _crash(*_a: Any, **_k: Any) -> bool:
            raise sqlite3.OperationalError("disk I/O error")

        with patch.object(EvidenceDeliveryLedger, "retire_artifact", _crash):
            with pytest.raises(sqlite3.OperationalError):
                await _router(attestor, clock).handle_ack(
                    _ack(a["artifact_digest"], outcome="refused", reason="malformed")
                )
        clock.now += 10**9
        await publisher.drain()
        assert b["artifact_digest"] not in _checkpoints(client.published)
    finally:
        await _stop(shutdown, task)
    device.restart_close()
    attestor = await device.start()
    publisher, client, shutdown, task = await _serve(attestor, Clock(10**13))
    try:
        assert _checkpoints(client.published) == [a["artifact_digest"]]
        assert device.handoff(a["artifact_digest"])["retired_at_ms"] is None
    finally:
        await _stop(shutdown, task)


@pytest.mark.parametrize("outcome", ["queued", "refused"])
async def test_an_acknowledgement_for_a_copy_never_handed_off_is_refused(
    device: Device, outcome: str
):
    """The courier answers only for bytes it was given."""
    attestor = _live(device)
    a = await _checkpoint(device)
    clock = Clock(10**12)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        b = await _checkpoint(device)
        early = _ack(b["artifact_digest"])
        if outcome == "refused":
            early.update(outcome="refused", reason="malformed")
        routed = await _router(attestor, clock).handle_ack(early)
        assert routed.outcome == "refused" and routed.reason == "never handed off"
        row = device.handoff(b["artifact_digest"])
        assert row["retired_at_ms"] is None and row["attempts"] == 0
        await _router(attestor, clock).handle_ack(_ack(a["artifact_digest"]))
        await publisher.drain()
        assert _checkpoints(client.published)[-1] == b["artifact_digest"]
        routed = await _router(attestor, clock).handle_ack(_ack(b["artifact_digest"]))
        assert routed.outcome == "applied"
    finally:
        await _stop(shutdown, task)


async def test_a_registration_is_carried_past_more_held_checkpoints_than_a_batch(
    device: Device,
):
    attestor = _live(device)
    head = await _checkpoint(device)
    for _ in range(DRAIN_BATCH + 6):
        await _checkpoint(device)
    await attestor.reconcile_registration(REFERENCE)
    clock = Clock(10**12)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        await publisher.drain()
        assert _types(client.published).count("anchor_registration") == 1
        assert _checkpoints(client.published) == [head["artifact_digest"]]
    finally:
        await _stop(shutdown, task)


async def test_a_due_reoffer_is_found_behind_more_undue_ones_than_a_batch(
    device: Device,
):
    """Due is decided after the read, so the read must page, not stop at a limit."""
    attestor = _live(device)
    ledger = attestor._ledger
    assert ledger is not None
    now = 10**12
    clock = Clock(now)
    sealed = []
    for i in range(DRAIN_BATCH + 1):
        body = {
            "v": 1,
            "device_id": DEVICE,
            "pubkey_hex": attestor.public_key_hex,
            "anchor_epoch_id": f"sha256:{i + 1:064x}",
            "commissioning_digest": REFERENCE,
        }
        # Every one sealed just now and so not yet due, but the last.
        at = 1 if i == DRAIN_BATCH else now

        def _seal(body: dict[str, Any] = body, at: int = at) -> dict[str, Any]:
            return dict(ledger.seal_registration(body, sealed_at_ms=at))

        sealed.append(attestor._executor.run(_seal))
    # The re-offer delay runs from the copy's handoff attempt, so the one
    # meant to be due was handed off long ago and the rest just now.
    for row in sealed[:-1]:
        await _retire_copy(attestor, clock, row["artifact_digest"])
    await _retire_copy(attestor, Clock(1), sealed[-1]["artifact_digest"])
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        await publisher.drain()
        assert client.registrations() == [sealed[-1]["artifact_json"].encode()]
    finally:
        await _stop(shutdown, task)


async def test_a_due_registration_copy_is_found_behind_more_undue_ones_than_a_batch(
    device: Device,
):
    attestor = _live(device)
    assert attestor.outbound is not None
    ledger = attestor._ledger
    assert ledger is not None
    now = 10**12
    sealed = []
    for i in range(DRAIN_BATCH + 1):
        body = {
            "v": 1,
            "device_id": DEVICE,
            "pubkey_hex": attestor.public_key_hex,
            "anchor_epoch_id": f"sha256:{i + 1:064x}",
            "commissioning_digest": REFERENCE,
        }

        def _seal(body: dict[str, Any] = body) -> dict[str, Any]:
            return dict(ledger.seal_registration(body, sealed_at_ms=now))

        sealed.append(attestor._executor.run(_seal))
    # Every copy but the last was just handed off, and so is not yet due.
    for row in sealed[:-1]:
        await attestor.outbound.note_artifact_attempt(row["artifact_digest"], at_ms=now)
    publisher, client, shutdown, task = await _serve(attestor, Clock(now + 1))
    try:
        await publisher.drain()
    finally:
        await _stop(shutdown, task)
    assert client.registrations() == [sealed[-1]["artifact_json"].encode()]


async def test_a_due_envelope_is_found_behind_more_undue_ones_than_a_batch(
    device: Device,
):
    attestor = _live(device)
    assert attestor.outbound is not None
    now = 10**12
    for i in range(DRAIN_BATCH + 1):
        assert await attestor.attest_action(_tier_d_row(100 + i)) is not None
    # Every envelope but the last was just attempted, and so is not yet due.
    for local_seq in range(1, DRAIN_BATCH + 1):
        await attestor.outbound.record_attempt(local_seq, at_ms=now, failure=None)
    [last] = device.rows(
        "SELECT envelope_digest FROM evidence_delivery_ledger WHERE local_seq = ?",
        DRAIN_BATCH + 1,
    )
    publisher, client, shutdown, task = await _serve(attestor, Clock(now + 1))
    try:
        await publisher.drain()
    finally:
        await _stop(shutdown, task)
    envelopes = [
        "sha256:"
        + hashlib.sha256(base64.b64decode(json.loads(p)["artifact_b64"])).hexdigest()
        for p in client.published
        if json.loads(p)["artifact_type"] == "delivery_envelope"
    ]
    assert envelopes == [last["envelope_digest"]]


def _insert_damaged(device: Device, holder: str, body: bytes, digest: str) -> None:
    conn = sqlite3.connect(str(device.root / "evidence.db"))
    try:
        if holder == "outbox":
            conn.execute(
                "INSERT INTO evidence_outbox (artifact_type, artifact_json,"
                " artifact_digest, created_at_ms)"
                " VALUES ('checkpoint', CAST(? AS TEXT), ?, 1)",
                (body, digest),
            )
        elif holder == "envelope":
            conn.execute(
                "INSERT INTO evidence_delivery_ledger (event_id, chain_seq,"
                " device_id, anchor_epoch_id, key_id, envelope_json,"
                " envelope_digest, chain_row_digest, sealed_at_ms)"
                " VALUES ('damaged', 0, ?, 'e', 'k', CAST(? AS TEXT), ?, 'c', 1)",
                (DEVICE, body, digest),
            )
        else:
            conn.execute(
                "INSERT INTO evidence_registration_obligation (device_id,"
                " anchor_epoch_id, pubkey_hex, commissioning_reference,"
                " artifact_json, artifact_digest, sealed_at_ms)"
                " VALUES (?, ?, 'ab', ?, CAST(? AS TEXT), ?, 1)",
                (DEVICE, "sha256:" + "9" * 64, REFERENCE, body, digest),
            )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.parametrize("fault", ["unreadable", "digest_mismatch"])
@pytest.mark.parametrize("holder", ["outbox", "envelope", "obligation"])
async def test_a_damaged_copy_is_kept_counted_and_taken_off_the_route(
    device: Device, holder: str, fault: str, caplog: pytest.LogCaptureFixture
):
    """Recorded once: later drains do not read, report or count it again."""
    attestor = _live(device)
    if fault == "unreadable":
        # Hashes to its digest: only its bytes not being text is wrong. It
        # names no device, so it is not another identity's copy either.
        body = b'{"v":"\xff"}'
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
    else:
        body = canonical_json({"device_id": DEVICE, "v": 1})
        digest = "sha256:" + "e" * 64
    _insert_damaged(device, holder, body, digest)
    good = await _checkpoint(device)
    assert await attestor.attest_action(_tier_d_row(9)) is not None
    clock = Clock(10**12)
    caplog.set_level("ERROR", logger="ori.gateway.evidence_outbound")
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        for _ in range(3):
            clock.now += 10**10
            await publisher.drain()
        assert publisher.connected
    finally:
        await _stop(shutdown, task)
    reported = [r for r in caplog.records if "cannot be carried" in r.getMessage()]
    assert len(reported) == 1, "a recorded fault was read and reported again"
    wires = [json.loads(p)["artifact_b64"] for p in client.published]
    assert base64.b64encode(body).decode() not in wires
    assert good["artifact_digest"] in _checkpoints(client.published)
    assert "delivery_envelope" in _types(client.published)
    faults = device.rows("SELECT holder, reason FROM evidence_artifact_fault")
    assert [tuple(r) for r in faults] == [(holder, fault)]
    table, column = {
        "outbox": ("evidence_outbox", "artifact_json"),
        "envelope": ("evidence_delivery_ledger", "envelope_json"),
        "obligation": ("evidence_registration_obligation", "artifact_json"),
    }[holder]
    kept = device.rows(
        f"SELECT CAST({column} AS BLOB) AS b FROM {table} WHERE CAST({column} AS BLOB) = ?",
        body,
    )
    assert len(kept) == 1, "the damaged bytes were not kept"


async def test_a_stopped_checkpoint_leaves_the_order(device: Device):
    """Seven epochs, the middle one stopped: the rest go in order around it."""
    attestor = _live(device)
    ledger = attestor._ledger
    assert ledger is not None
    epochs = ["sha256:" + (c * 64) for c in "0123456"]
    digests = []
    for i, epoch in enumerate(epochs):
        body = canonical_json(
            {
                "v": 1,
                "device_id": DEVICE,
                "high_water_seq": i,
                "anchor_epoch_id": epoch,
                "boot_id": 1,
                "issued_at_ms": i,
            }
        )

        def _queue(body: bytes = body) -> dict[str, Any]:
            return dict(ledger.queue_artifact("checkpoint", body, created_at_ms=1))

        digests.append(attestor._executor.run(_queue)["artifact_digest"])
    conn = sqlite3.connect(str(device.root / "evidence.db"))
    try:
        conn.execute(
            "INSERT INTO evidence_offer_stop (scope, device_id, anchor_epoch_id,"
            " disposition, artifact_digest, stopped_at_ms) VALUES"
            " ('epoch', ?, ?, 'epoch_reprovisioning_required', ?, 1)",
            (DEVICE, epochs[2], digests[2]),
        )
        conn.commit()
    finally:
        conn.close()
    clock = Clock(10**12)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    seen: list[str] = []
    try:
        router = _router(attestor, clock)
        for _ in range(len(epochs) + 1):
            new = _checkpoints(client.published)[len(seen) :]
            seen += new
            for digest in new:
                await router.handle_ack(_ack(digest))
            await publisher.drain()
    finally:
        await _stop(shutdown, task)
    assert seen == [d for i, d in enumerate(digests) if i != 2]
    assert device.handoff(digests[2])["retired_at_ms"] is None
