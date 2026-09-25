# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The registration producer and its confirmation obligation.

Driven through the attestor the runtime builds, the outbound publisher and
acknowledgement router the runtime wires, and the ingest route an epoch
confirmation arrives by. A restart is a closed attestor and a new one opened
on the same files.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ori.gateway.evidence_outbound import (
    RETRY_BACKOFF_MAX_S,
    EvidenceOutboundAckRouter,
    MqttEvidenceOutboundPublisher,
    retry_due,
)
from ori.security.evidence import first_party
from ori.security.evidence.authority_keys import (
    PURPOSE_EPOCH,
    PURPOSE_RECEIPT,
    STATUS_ACTIVE,
    AuthorityKey,
)
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.security.evidence.ingest import EPOCH_DOMAIN
from ori.security.evidence.registration import (
    CONFIRMATION_OVERDUE_MS,
    REGISTRATION_DOMAIN,
    REOFFER_BASE_S,
    REOFFER_MAX_S,
    RegistrationStatus,
    reoffer_due,
)

DEVICE = "energy-monitor-ikeja-01"
SECRET = "install-secret-for-obligation-tests"
REFERENCE = "sha256:" + "ab" * 32
OTHER_REFERENCE = "sha256:" + "cd" * 32
EPOCH_SEED = bytes(range(32, 64))
RECEIPT_SEED = bytes(range(64, 96))
EPOCH_KEY_ID = "authority-epoch-1"
RECEIPT_KEY_ID = "authority-receipt-1"


def _pub(seed: bytes) -> str:
    return (
        Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw().hex()
    )


def _registry() -> dict[tuple[str, str], AuthorityKey]:
    return {
        (PURPOSE_EPOCH, EPOCH_KEY_ID): AuthorityKey(
            EPOCH_KEY_ID, _pub(EPOCH_SEED), PURPOSE_EPOCH, STATUS_ACTIVE
        ),
        (PURPOSE_RECEIPT, RECEIPT_KEY_ID): AuthorityKey(
            RECEIPT_KEY_ID, _pub(RECEIPT_SEED), PURPOSE_RECEIPT, STATUS_ACTIVE
        ),
    }


class Clock:
    def __init__(self, now: int) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


class _Client:
    def __init__(self) -> None:
        self.on_connect: Any = None
        self.on_subscribe: Any = None
        self.on_disconnect: Any = None
        self.on_message: Any = None
        self.published: list[bytes] = []

    def username_pw_set(self, *_a: Any, **_k: Any) -> None:
        pass

    def connect(self, *_a: Any, **_k: Any) -> None:
        pass

    def loop_start(self) -> None:
        self.on_connect(self, None, None, 0)

    def subscribe(self, topic: str, qos: int = 0) -> tuple[int, int]:
        self.on_subscribe(self, None, 1, [1], None)
        return (0, 1)

    def publish(self, topic: str, payload: bytes, qos: int = 0) -> None:
        if topic.endswith("/outbound"):
            self.published.append(payload)

    def loop_stop(self) -> None:
        pass

    def disconnect(self) -> None:
        pass

    def registrations(self) -> list[bytes]:
        out = []
        for payload in self.published:
            carriage = json.loads(payload)
            if carriage["artifact_type"] == "anchor_registration":
                out.append(base64.b64decode(carriage["artifact_b64"]))
        return out


class Device:
    """One device's evidence files, opened and reopened as a runtime would."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.attestor: FirstPartyEvidenceAttestor | None = None

    async def start(self) -> FirstPartyEvidenceAttestor:
        self.attestor = FirstPartyEvidenceAttestor(
            db_path=str(self.root / "evidence.db"),
            key_path=str(self.root / "evidence.key"),
            device_secret=SECRET,
            device_id=DEVICE,
            authority_keys=_registry(),
        )
        assert await self.attestor.start() is True
        return self.attestor

    def restart_close(self) -> None:
        assert self.attestor is not None
        self.attestor.close()
        self.attestor = None

    def rows(self, sql: str, *params: Any) -> list[sqlite3.Row]:
        conn = sqlite3.connect(str(self.root / "evidence.db"))
        conn.row_factory = sqlite3.Row
        try:
            return list(conn.execute(sql, params))
        finally:
            conn.close()

    def obligations(self) -> list[sqlite3.Row]:
        return self.rows("SELECT * FROM evidence_registration_obligation ORDER BY id")

    def handoff(self, digest: str) -> sqlite3.Row:
        return self.rows(
            "SELECT * FROM evidence_outbox WHERE artifact_digest = ?", digest
        )[0]


@pytest.fixture
async def device(tmp_path):
    d = Device(tmp_path)
    await d.start()
    try:
        yield d
    finally:
        if d.attestor is not None:
            d.attestor.close()


def _router(
    attestor: FirstPartyEvidenceAttestor, clock: Clock
) -> EvidenceOutboundAckRouter:
    assert attestor.outbound is not None
    return EvidenceOutboundAckRouter(
        device_id=DEVICE, outbox=attestor.outbound, now=clock
    )


async def _serve(
    attestor: FirstPartyEvidenceAttestor, clock: Clock
) -> tuple[MqttEvidenceOutboundPublisher, _Client, asyncio.Event, asyncio.Task[None]]:
    assert attestor.outbound is not None
    client = _Client()
    publisher = MqttEvidenceOutboundPublisher(
        broker_url="mqtt://localhost:1883",
        router=_router(attestor, clock),
        device_id=DEVICE,
        outbox=attestor.outbound,
        client_factory=lambda **_k: client,
        retry_interval_s=3600.0,
        now=clock,
    )
    shutdown = asyncio.Event()
    task = asyncio.create_task(publisher.serve_until(shutdown))
    for _ in range(200):
        if publisher.connected:
            break
        await asyncio.sleep(0.01)
    assert publisher.connected
    # The serve loop's own first drain may still be pending; draining here,
    # under the same lock, makes what the client has seen deterministic.
    await publisher.drain()
    return publisher, client, shutdown, task


async def _stop(shutdown: asyncio.Event, task: asyncio.Task[None]) -> None:
    shutdown.set()
    await asyncio.wait_for(task, 5)


def _queued(digest: str) -> dict[str, Any]:
    return {
        "device_id": DEVICE,
        "artifact_type": "anchor_registration",
        "artifact_digest": digest,
        "outcome": "queued",
        "reason": "",
        "acknowledged_at_ms": 1,
    }


async def _retire_copy(
    attestor: FirstPartyEvidenceAttestor, clock: Clock, digest: str
) -> None:
    """The courier's `queued` for a copy the publisher handed off."""
    assert attestor.outbound is not None
    await attestor.outbound.note_artifact_attempt(digest, at_ms=clock.now)
    routed = await _router(attestor, clock).handle_ack(_queued(digest))
    assert routed.outcome == "applied", routed


def _confirmation(
    attestor: FirstPartyEvidenceAttestor,
    *,
    seed: bytes = EPOCH_SEED,
    key_id: str = EPOCH_KEY_ID,
    **overrides: Any,
) -> dict[str, Any]:
    assert attestor.anchor is not None
    body: dict[str, Any] = {
        "v": 1,
        "device_id": DEVICE,
        "anchor_epoch_id": attestor.anchor.anchor_epoch_id,
        "pubkey_hex": attestor.public_key_hex,
        "actor": "commissioner@site",
        "confirmed_at_ms": 1787000009000,
        "key_id": key_id,
    }
    body.update(overrides)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    signature = key.sign(EPOCH_DOMAIN + canonical_json(body))
    body["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return body


async def _health(attestor: FirstPartyEvidenceAttestor, at_ms: int) -> dict[str, Any]:
    fields = await attestor.registration_health(at_ms)
    assert fields is not None
    return fields


# --------------------------------------------------------------------------
# Production
# --------------------------------------------------------------------------


async def test_without_a_reference_nothing_is_sealed(device):
    attestor = device.attestor
    assert await attestor.reconcile_registration(None) is (
        RegistrationStatus.PENDING_AUTHORISATION
    )
    assert device.obligations() == []
    assert await _health(attestor, 1) == {
        "registration_status": "pending_authorisation",
        "registration_pending_since_ms": None,
        "registration_confirmation_overdue": False,
        "registration_offer": "not_applicable",
        "delivery_stop_status": "not_stopped",
        "last_disposition": None,
        "foreign_identity_pending_count": 0,
        "stopped_local_artifact_count": 0,
        "stopped_local_bytes": 0,
        "oldest_stopped_local_since_ms": None,
    }


async def test_a_reference_seals_a_derived_self_signed_registration(device):
    attestor = device.attestor
    status = await attestor.reconcile_registration(REFERENCE)
    assert status is RegistrationStatus.PENDING_CONFIRMATION

    [obligation] = device.obligations()
    wire = obligation["artifact_json"].encode("utf-8")
    registration = json.loads(wire)
    anchor = attestor.anchor
    assert registration["commissioning_digest"] == REFERENCE
    assert registration["key_id"] == anchor.key_id
    assert registration["anchor_epoch_id"] == anchor.anchor_epoch_id
    assert registration["capability_profile"] == anchor.profile.as_document()
    assert canonical_json(registration) == wire, "the held bytes are not canonical"
    body = {k: v for k, v in registration.items() if k != "signature"}
    Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(registration["pubkey_hex"])
    ).verify(
        base64.b64decode(registration["signature"][len("ed25519:") :]),
        REGISTRATION_DOMAIN + canonical_json(body),
    )
    digest = "sha256:" + hashlib.sha256(wire).hexdigest()
    assert obligation["artifact_digest"] == digest
    handoff = device.handoff(digest)
    assert handoff["artifact_json"] == obligation["artifact_json"]
    assert handoff["retired_at_ms"] is None

    fields = await _health(attestor, obligation["sealed_at_ms"] + 1)
    assert fields["registration_status"] == "pending_confirmation"
    assert fields["registration_pending_since_ms"] == obligation["sealed_at_ms"]


async def test_reconciling_again_reseals_nothing(device, monkeypatch):
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    first = [dict(r) for r in device.obligations()]

    def resigned(**_kwargs: Any) -> dict[str, Any]:
        raise AssertionError("an open obligation under this reference was re-signed")

    monkeypatch.setattr(first_party, "build_anchor_registration", resigned)
    for _ in range(3):
        status = await attestor.reconcile_registration(REFERENCE)
        assert status is RegistrationStatus.PENDING_CONFIRMATION
    assert [dict(r) for r in device.obligations()] == first


async def test_the_ledger_keeps_the_first_bytes_for_one_reference(device):
    """The ledger holds on its own, whatever its caller checked."""
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    [held] = device.obligations()
    later = dict(json.loads(held["artifact_json"]))
    later["registered_at_ms"] = int(later["registered_at_ms"]) + 1
    ledger = attestor._ledger
    assert ledger is not None
    kept = attestor._executor.run(
        lambda: dict(ledger.seal_registration(later, sealed_at_ms=1))
    )
    assert kept["artifact_json"] == held["artifact_json"]
    assert [dict(r) for r in device.obligations()] == [dict(held)]


# --------------------------------------------------------------------------
# Carriage, the courier's acknowledgement, and the re-offer
# --------------------------------------------------------------------------


async def test_a_queued_acknowledgement_retires_only_the_courier_copy(device):
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    [obligation] = device.obligations()
    clock = Clock(obligation["sealed_at_ms"] + 1)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        assert client.registrations() == [obligation["artifact_json"].encode()]
        routed = await _router(attestor, clock).handle_ack(
            _queued(obligation["artifact_digest"])
        )
        assert routed.outcome == "applied"
        assert (
            device.handoff(obligation["artifact_digest"])["retire_outcome"] == "queued"
        )
        [still] = device.obligations()
        assert still["state"] == "open" and still["closed_at_ms"] is None
        fields = await _health(attestor, clock.now)
        assert fields["registration_status"] == "pending_confirmation"
    finally:
        await _stop(shutdown, task)


async def test_the_obligation_reoffers_identical_bytes_with_bounded_growing_delay(
    device,
):
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    [obligation] = device.obligations()
    sealed = int(obligation["sealed_at_ms"])
    held = obligation["artifact_json"].encode("utf-8")
    clock = Clock(sealed + 1)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        await _router(attestor, clock).handle_ack(
            _queued(obligation["artifact_digest"])
        )
        assert len(client.registrations()) == 1
        # The first re-offer runs from that first attempted offer, not from
        # sealing one second earlier.
        offered = clock.now

        base_ms = int(REOFFER_BASE_S * 1000)
        clock.now = offered + base_ms - 1
        await publisher.drain()
        assert len(client.registrations()) == 1, "re-offered before the delay"

        clock.now = offered + base_ms
        await publisher.drain()
        assert client.registrations() == [held, held]

        last = clock.now
        clock.now = last + 2 * base_ms - 1
        await publisher.drain()
        assert len(client.registrations()) == 2, "the delay did not grow"
        clock.now = last + 2 * base_ms
        await publisher.drain()
        assert client.registrations() == [held] * 3
        [row] = device.obligations()
        assert row["offers"] == 2 and row["state"] == "open"
    finally:
        await _stop(shutdown, task)


async def test_the_obligation_waits_while_its_courier_copy_is_still_pending(device):
    """Carried once per drain, never twice: the copy retries on its own schedule."""
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    [obligation] = device.obligations()
    clock = Clock(int(obligation["sealed_at_ms"]) + 10 * int(REOFFER_MAX_S * 1000))
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        assert client.registrations() == [obligation["artifact_json"].encode()]
        assert device.obligations()[0]["offers"] == 0
    finally:
        await _stop(shutdown, task)


def test_the_delay_is_bounded_and_the_attempts_are_not():
    base_ms = REOFFER_BASE_S * 1000
    cap_ms = REOFFER_MAX_S * 1000
    for offers in range(0, 200):
        expected = min(base_ms * 2**offers, cap_ms)
        assert not reoffer_due(offers, 0, at_ms=int(expected) - 1)
        assert reoffer_due(offers, 0, at_ms=int(expected))
    assert REOFFER_BASE_S > 0 and REOFFER_MAX_S >= REOFFER_BASE_S


@pytest.mark.parametrize("count", [1024, 1025, 10**6, 10**18])
def test_no_count_overflows_a_schedule(count):
    """Both counters are unbounded; neither schedule may raise at any value."""
    cap_ms = int(REOFFER_MAX_S * 1000)
    assert not reoffer_due(count, 0, at_ms=cap_ms - 1)
    assert reoffer_due(count, 0, at_ms=cap_ms)
    envelope_cap_ms = int(RETRY_BACKOFF_MAX_S * 1000)
    assert not retry_due(count, 0, at_ms=envelope_cap_ms - 1)
    assert retry_due(count, 0, at_ms=envelope_cap_ms)


@pytest.mark.parametrize(
    "count,last",
    [(10**6, 0), (3, "unreadable")],
    ids=["overflowing-count", "unreadable-schedule"],
)
async def test_the_route_survives_counts_that_would_overflow_an_exponent(
    device, count, last
):
    """Through the real route, no row's schedule can take the route down."""
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    [obligation] = device.obligations()
    seq = await attestor.attest_action(_tier_d_row(7))
    assert seq is not None
    checkpoint = await attestor.issue_checkpoint()
    assert checkpoint is not None

    clock = Clock(int(obligation["sealed_at_ms"]) + 10 * int(REOFFER_MAX_S * 1000))
    await _retire_copy(attestor, clock, obligation["artifact_digest"])
    conn = sqlite3.connect(str(device.root / "evidence.db"))
    try:
        conn.execute(
            "UPDATE evidence_registration_obligation SET offers = ?, last_offer_ms = ?",
            (count, last),
        )
        conn.execute(
            "UPDATE evidence_delivery_ledger SET attempts = ?, last_attempt_ms = ?",
            (count, last),
        )
        conn.execute(
            "UPDATE evidence_outbox SET attempts = ?, last_attempt_ms = ?"
            " WHERE artifact_type = 'checkpoint'",
            (count, last),
        )
        conn.commit()
    finally:
        conn.close()

    factory_calls: list[int] = []
    client = _Client()

    def factory(**_kwargs: Any) -> _Client:
        factory_calls.append(1)
        return client

    publisher = MqttEvidenceOutboundPublisher(
        broker_url="mqtt://localhost:1883",
        router=_router(attestor, clock),
        device_id=DEVICE,
        outbox=attestor.outbound,
        client_factory=factory,
        retry_interval_s=3600.0,
        now=clock,
    )
    shutdown = asyncio.Event()
    task = asyncio.create_task(publisher.serve_until(shutdown))
    try:
        for _ in range(300):
            if publisher.connected and len(client.published) >= 3:
                break
            await asyncio.sleep(0.01)
        types = [json.loads(p)["artifact_type"] for p in client.published]
        assert sorted(types) == [
            "anchor_registration",
            "checkpoint",
            "delivery_envelope",
        ]
        client.on_message(
            client,
            None,
            type(
                "_M",
                (),
                {
                    "payload": json.dumps(
                        {
                            **_queued(checkpoint["artifact_digest"]),
                            "artifact_type": "checkpoint",
                        }
                    ).encode()
                },
            )(),
        )
        for _ in range(300):
            row = device.handoff(checkpoint["artifact_digest"])
            if row["retired_at_ms"] is not None:
                break
            await asyncio.sleep(0.01)
        assert (
            device.handoff(checkpoint["artifact_digest"])["retire_outcome"] == "queued"
        )
        assert publisher.connected
        assert factory_calls == [1], "the route dropped and reconnected"
    finally:
        await _stop(shutdown, task)


def _tier_d_row(action_log_id: int) -> dict[str, Any]:
    return {
        "id": action_log_id,
        "action_name": "trip_relay",
        "tier": "D",
        "executed": 1,
        "approved": None,
        "action_taken": "trip_relay",
        "trigger_name": "dangerous_overcurrent",
        "timestamp": 1787000000000,
        "authority_json": json.dumps(
            {
                "kind": "tier_d_legacy_skill",
                "skill_name": "energy-anomaly-detector",
                "skill_version": "0.2.1",
                "trigger_name": "dangerous_overcurrent",
            }
        ),
    }


def test_a_clock_moved_backwards_does_not_stall_the_obligation():
    last = 4_000_000_000_000
    assert reoffer_due(5, last, at_ms=last - 1)
    assert reoffer_due(0, last, at_ms=1_787_000_000_000)


async def test_a_refused_courier_copy_does_not_end_the_obligation(device):
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    [obligation] = device.obligations()
    clock = Clock(int(obligation["sealed_at_ms"]) + 1)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        refusal = _queued(obligation["artifact_digest"])
        refusal.update(outcome="refused", reason="malformed")
        await _router(attestor, clock).handle_ack(refusal)
        assert (
            device.handoff(obligation["artifact_digest"])["retire_outcome"] == "refused"
        )
        clock.now += int(REOFFER_BASE_S * 1000)
        await publisher.drain()
        assert client.registrations()[-1] == obligation["artifact_json"].encode()
        assert device.obligations()[0]["state"] == "open"
    finally:
        await _stop(shutdown, task)


async def test_a_reoffer_the_route_loses_still_counts_as_an_attempted_offer(device):
    """The attempt is persisted before the bytes leave, so a lost publish does
    not make the next drain retry at once: the schedule runs from it."""
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    [obligation] = device.obligations()
    held = obligation["artifact_json"].encode("utf-8")
    clock = Clock(int(obligation["sealed_at_ms"]) + 1)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        routed = await _router(attestor, clock).handle_ack(
            _queued(obligation["artifact_digest"])
        )
        assert routed.outcome == "applied", routed
        # The acknowledgement nudges the serve loop; let that drain run at
        # this clock, where nothing is due, so the failing drain below is the
        # only one at the re-offer time.
        for _ in range(5):
            await asyncio.sleep(0)
        await publisher.drain()
        base_ms = int(REOFFER_BASE_S * 1000)
        clock.now += base_ms
        failing = clock.now
        original = _Client.publish

        def lose(self: Any, topic: str, payload: bytes, qos: int = 0) -> None:
            # Only the registration is lost; earlier stages keep carrying.
            if json.loads(payload)["artifact_type"] == "anchor_registration":
                raise OSError("broker gone")
            original(self, topic, payload, qos)

        with patch.object(_Client, "publish", lose):
            assert await publisher.drain() == 0, "a lost publish counted as carried"
        [row] = device.obligations()
        assert row["offers"] == 1 and row["last_offer_ms"] == failing
        assert client.registrations() == [held], "the lost publish was counted twice"

        clock.now = failing + 1
        await publisher.drain()
        assert client.registrations() == [held], "a lost re-offer was retried at once"
        clock.now = failing + 2 * base_ms - 1
        await publisher.drain()
        assert client.registrations() == [held]
        clock.now = failing + 2 * base_ms
        await publisher.drain()
        assert client.registrations() == [held, held]
        assert device.obligations()[0]["offers"] == 2
    finally:
        await _stop(shutdown, task)


async def test_the_obligation_and_its_bytes_survive_a_restart(device):
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    [obligation] = device.obligations()
    sealed = int(obligation["sealed_at_ms"])
    held = obligation["artifact_json"].encode("utf-8")
    clock = Clock(sealed + 1)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    await _router(attestor, clock).handle_ack(_queued(obligation["artifact_digest"]))
    offered = clock.now
    clock.now = offered + int(REOFFER_BASE_S * 1000)
    await publisher.drain()
    await _stop(shutdown, task)
    before_restart = client.registrations()
    assert before_restart == [held, held]

    device.restart_close()
    attestor = await device.start()
    assert await attestor.reconcile_registration(REFERENCE) is (
        RegistrationStatus.PENDING_CONFIRMATION
    )
    [row] = device.obligations()
    assert row["artifact_json"].encode() == held, "a restart resealed the registration"
    assert row["offers"] == 1
    fields = await _health(attestor, sealed + 5)
    assert fields["registration_pending_since_ms"] == sealed

    # The second re-offer runs 120 seconds from the first, which ran 60
    # seconds from the first attempted offer; the restart measures from the
    # persisted time.
    clock.now = offered + int(REOFFER_BASE_S * 1000) * 3
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        assert client.registrations() == [held], "not re-offered, or not identical"
        assert device.obligations()[0]["offers"] == 2
    finally:
        await _stop(shutdown, task)


async def test_a_replacement_reference_supersedes_the_open_obligation(device):
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    await attestor.reconcile_registration(OTHER_REFERENCE)
    first, second = device.obligations()
    assert first["state"] == "superseded" and first["closed_at_ms"] is not None
    assert second["state"] == "open"
    assert (
        json.loads(second["artifact_json"])["commissioning_digest"] == OTHER_REFERENCE
    )
    clock = Clock(int(second["sealed_at_ms"]) + 10 * int(REOFFER_MAX_S * 1000))
    for row in (first, second):
        await _retire_copy(attestor, clock, row["artifact_digest"])
    clock.now += int(REOFFER_BASE_S * 1000)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        assert client.registrations() == [second["artifact_json"].encode()]
    finally:
        await _stop(shutdown, task)


async def test_a_replacement_withdraws_the_superseded_courier_copy(device):
    """Nothing is acknowledged first: only the replacement is ever carried."""
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    await attestor.reconcile_registration(OTHER_REFERENCE)
    first, second = device.obligations()
    assert device.handoff(first["artifact_digest"])["withdrawn_at_ms"] is not None
    assert device.handoff(second["artifact_digest"])["withdrawn_at_ms"] is None
    publisher, client, shutdown, task = await _serve(
        attestor, Clock(int(second["sealed_at_ms"]) + 1)
    )
    try:
        assert client.registrations() == [second["artifact_json"].encode()]
    finally:
        await _stop(shutdown, task)
    conn = sqlite3.connect(str(device.root / "evidence.db"))
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE evidence_outbox SET withdrawn_at_ms = NULL")
    finally:
        conn.close()


async def test_an_earlier_epochs_obligation_is_reoffered_until_it_resolves(device):
    """Each epoch's obligation is independent; health reports the current one."""
    attestor = device.attestor
    ledger = attestor._ledger
    assert ledger is not None
    earlier = "sha256:" + "4" * 64
    held = attestor._executor.run(
        lambda: dict(
            ledger.seal_registration(
                {
                    "v": 1,
                    "device_id": DEVICE,
                    "pubkey_hex": attestor.public_key_hex,
                    "anchor_epoch_id": earlier,
                    "commissioning_digest": REFERENCE,
                },
                sealed_at_ms=1,
            )
        )
    )
    await attestor.reconcile_registration(REFERENCE)
    current = device.obligations()[1]
    clock = Clock(int(current["sealed_at_ms"]) + 100 * int(REOFFER_MAX_S * 1000))
    for digest in (held["artifact_digest"], current["artifact_digest"]):
        await _retire_copy(attestor, clock, digest)
    clock.now += int(REOFFER_BASE_S * 1000)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        assert sorted(client.registrations()) == sorted(
            [held["artifact_json"].encode(), current["artifact_json"].encode()]
        )
    finally:
        await _stop(shutdown, task)

    late = _confirmation(attestor, anchor_epoch_id=earlier, confirmed_at_ms=1)
    assert attestor.ingest.accept_epoch_confirmation(late).accepted
    assert device.obligations()[0]["state"] == "confirmed"
    backend = attestor.confirmation_backend()
    assert backend is not None and backend.active_anchor_epoch_id(DEVICE) is None
    status = await _health(attestor, clock.now)
    assert status["registration_status"] == "pending_confirmation"

    clock.now += 100 * int(REOFFER_MAX_S * 1000)
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        assert client.registrations() == [current["artifact_json"].encode()]
    finally:
        await _stop(shutdown, task)

    assert attestor.ingest.accept_epoch_confirmation(_confirmation(attestor)).accepted
    assert backend.active_anchor_epoch_id(DEVICE) == attestor.anchor.anchor_epoch_id
    assert attestor.ingest.accept_epoch_confirmation(late).accepted
    assert backend.active_anchor_epoch_id(DEVICE) == attestor.anchor.anchor_epoch_id, (
        "a late confirmation for an earlier epoch rolled the active epoch back"
    )


# --------------------------------------------------------------------------
# Confirmation
# --------------------------------------------------------------------------


async def test_an_active_epoch_recorded_without_a_registration_is_not_confirmed(
    device,
):
    """An earlier release applied confirmations with nothing sealed; none counts."""
    attestor = device.attestor
    conn = sqlite3.connect(str(device.root / "evidence.db"))
    try:
        conn.execute(
            "INSERT INTO evidence_device_epochs VALUES (?, ?, ?, ?, ?, ?)",
            (
                DEVICE,
                attestor.anchor.anchor_epoch_id,
                attestor.public_key_hex,
                "someone",
                1,
                EPOCH_KEY_ID,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    fields = await _health(attestor, 10**13)
    assert fields["registration_status"] == "pending_authorisation"
    assert await attestor.reconcile_registration(REFERENCE) is (
        RegistrationStatus.PENDING_CONFIRMATION
    )


async def test_a_confirmation_for_the_current_epoch_with_nothing_sealed_is_refused(
    device,
):
    attestor = device.attestor
    outcome = attestor.ingest.accept_epoch_confirmation(_confirmation(attestor))
    assert not outcome.accepted and outcome.reason == "binding_mismatch"
    assert await _health(attestor, 10**13) == {
        "registration_status": "pending_authorisation",
        "registration_pending_since_ms": None,
        "registration_confirmation_overdue": False,
        "registration_offer": "not_applicable",
        "delivery_stop_status": "not_stopped",
        "last_disposition": None,
        "foreign_identity_pending_count": 0,
        "stopped_local_artifact_count": 0,
        "stopped_local_bytes": 0,
        "oldest_stopped_local_since_ms": None,
    }
    backend = attestor.confirmation_backend()
    assert backend is not None and backend.active_anchor_epoch_id(DEVICE) is None
    await attestor.reconcile_registration(REFERENCE)
    fields = await _health(attestor, 10**13)
    assert fields["registration_status"] == "pending_confirmation"


async def test_a_verified_confirmation_completes_the_obligation(device):
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    [obligation] = device.obligations()
    sealed = int(obligation["sealed_at_ms"])
    overdue_at = sealed + CONFIRMATION_OVERDUE_MS + 1
    assert (await _health(attestor, overdue_at))["registration_confirmation_overdue"]

    outcome = attestor.ingest.accept_epoch_confirmation(_confirmation(attestor))
    assert outcome.accepted, outcome

    [closed] = device.obligations()
    assert closed["state"] == "confirmed"
    assert await _health(attestor, overdue_at) == {
        "registration_status": "confirmed",
        "registration_pending_since_ms": None,
        "registration_confirmation_overdue": False,
        "registration_offer": "not_applicable",
        "delivery_stop_status": "not_stopped",
        "last_disposition": None,
        "foreign_identity_pending_count": 0,
        "stopped_local_artifact_count": 0,
        "stopped_local_bytes": 0,
        "oldest_stopped_local_since_ms": None,
    }
    assert (
        await attestor.reconcile_registration(REFERENCE) is RegistrationStatus.CONFIRMED
    )
    assert await attestor.reconcile_registration(OTHER_REFERENCE) is (
        RegistrationStatus.CONFIRMED
    )
    assert len(device.obligations()) == 1, "a confirmed epoch was resealed"

    clock = Clock(sealed + 100 * int(REOFFER_MAX_S * 1000))
    await _retire_copy(attestor, clock, obligation["artifact_digest"])
    publisher, client, shutdown, task = await _serve(attestor, clock)
    try:
        assert client.registrations() == [], "a confirmed registration was re-offered"
    finally:
        await _stop(shutdown, task)

    device.restart_close()
    attestor = await device.start()
    assert (await _health(attestor, overdue_at))["registration_status"] == "confirmed"


def _other_key_hex() -> str:
    return _pub(bytes(range(100, 132)))


@pytest.mark.parametrize(
    "forge",
    [
        pytest.param(lambda a: _confirmation(a, seed=bytes(range(1, 33))), id="forged"),
        pytest.param(
            lambda a: _confirmation(a, seed=RECEIPT_SEED, key_id=RECEIPT_KEY_ID),
            id="receipt-purpose",
        ),
        pytest.param(lambda a: _confirmation(a, device_id="other"), id="other-device"),
        pytest.param(
            lambda a: _confirmation(a, pubkey_hex=_other_key_hex()), id="other-key"
        ),
        pytest.param(
            lambda a: _confirmation(a, anchor_epoch_id="sha256:" + "9" * 64),
            id="unregistered-epoch",
        ),
        pytest.param(
            lambda a: {**_confirmation(a), "anchor_epoch_id": "sha256:" + "9" * 64},
            id="epoch-swapped-after-signing",
        ),
        pytest.param(lambda a: {**_confirmation(a), "extra": 1}, id="unknown-field"),
        pytest.param(lambda a: {**_confirmation(a), "v": 2}, id="version"),
        pytest.param(lambda a: "not an object", id="not-an-object"),
    ],
)
async def test_a_forged_or_mismatched_confirmation_leaves_the_obligation_open(
    device, forge
):
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    outcome = attestor.ingest.accept_epoch_confirmation(forge(attestor))
    assert not outcome.accepted
    [row] = device.obligations()
    assert row["state"] == "open"
    fields = await _health(attestor, int(row["sealed_at_ms"]) + 1)
    assert fields["registration_status"] == "pending_confirmation"
    confirmation_backend = attestor.confirmation_backend()
    assert confirmation_backend is not None
    assert confirmation_backend.active_anchor_epoch_id(DEVICE) is None


async def test_overdue_is_true_only_past_the_bound(device):
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    sealed = int(device.obligations()[0]["sealed_at_ms"])
    before = await _health(attestor, sealed + CONFIRMATION_OVERDUE_MS - 1)
    at_bound = await _health(attestor, sealed + CONFIRMATION_OVERDUE_MS)
    assert before["registration_confirmation_overdue"] is False
    assert at_bound["registration_confirmation_overdue"] is True
    assert at_bound["registration_pending_since_ms"] == sealed


async def test_a_sealing_time_ahead_of_the_clock_is_reported_overdue(device):
    """Sealed at T+10d, read at T+2d: the time pending cannot be measured."""
    attestor = device.attestor
    day = 24 * 3600 * 1000
    t = 1_787_000_000_000
    with patch.object(first_party, "now_ms", return_value=t + 10 * day):
        await attestor.reconcile_registration(REFERENCE)
    fields = await _health(attestor, t + 2 * day)
    assert fields["registration_status"] == "pending_confirmation"
    assert fields["registration_pending_since_ms"] == t + 10 * day
    assert fields["registration_confirmation_overdue"] is True
    assert (await _health(attestor, t + 10 * day + 1))[
        "registration_confirmation_overdue"
    ] is False


# --------------------------------------------------------------------------
# The durable record defends itself
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE evidence_registration_obligation SET artifact_json = '{}'",
        "UPDATE evidence_registration_obligation SET anchor_epoch_id = 'sha256:"
        + "0" * 64
        + "'",
        "UPDATE evidence_registration_obligation SET sealed_at_ms = 1",
        "UPDATE evidence_registration_obligation SET device_id = 'other'",
        "UPDATE evidence_registration_obligation SET commissioning_reference = 'sha256:"
        + "0" * 64
        + "'",
        "UPDATE evidence_registration_obligation SET artifact_digest = 'x'",
        "DELETE FROM evidence_registration_obligation",
    ],
)
async def test_the_held_bytes_cannot_be_rewritten_or_dropped(device, statement):
    await device.attestor.reconcile_registration(REFERENCE)
    conn = sqlite3.connect(str(device.root / "evidence.db"))
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(statement)
    finally:
        conn.close()


async def test_a_closed_obligation_cannot_be_reopened(device):
    attestor = device.attestor
    await attestor.reconcile_registration(REFERENCE)
    assert attestor.ingest.accept_epoch_confirmation(_confirmation(attestor)).accepted
    conn = sqlite3.connect(str(device.root / "evidence.db"))
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(
                "UPDATE evidence_registration_obligation"
                " SET state = 'open', closed_at_ms = NULL"
            )
    finally:
        conn.close()
