# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The ledger's outbox: retained signed artifacts and what releases them."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.chain import EvidenceChain, attestation_event_id
from ori.security.evidence.device_key import EvidenceDeviceKey
from ori.security.evidence.ledger import (
    CHECKPOINT_DOMAIN,
    OUTBOX_ANCHOR_REGISTRATION,
    OUTBOX_CHECKPOINT,
    RETIRE_QUEUED,
    RETIRE_REFUSED,
    DeliveryLedgerError,
    EvidenceDeliveryLedger,
)

DEVICE = "energy-monitor-ikeja-01"


@pytest.fixture
def rig(tmp_path):
    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "install-secret")
    chain = EvidenceChain(tmp_path / "chain.db", key, DEVICE)
    ledger = EvidenceDeliveryLedger(
        tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id="epoch-1", key_id="key-1"
    )
    yield key, chain, ledger
    chain.close()
    ledger.close()


def _artifact(device_id: str = DEVICE, **extra) -> bytes:
    return canonical_json({"v": 1, "device_id": device_id, **extra})


def _append(chain, action_log_id: int):
    return chain.append(
        event_id=attestation_event_id(DEVICE, action_log_id),
        event_type="SAFETY_ACTION_EXECUTED",
        emitted_at_ms=1751500800000,
        payload={"kind": "runtime_action", "action_log_id": action_log_id},
        created_at_ms=1751500800040,
    )


def test_a_queued_artifact_keeps_its_exact_bytes_and_digest(rig):
    _, _, ledger = rig
    wire = _artifact(note="ké")
    row = ledger.queue_artifact(OUTBOX_ANCHOR_REGISTRATION, wire, created_at_ms=10)
    assert row["artifact_json"].encode("utf-8") == wire
    assert row["artifact_digest"] == "sha256:" + hashlib.sha256(wire).hexdigest()
    assert row["retired_at_ms"] is None and row["attempts"] == 0


def test_queueing_is_idempotent_by_digest(rig):
    _, _, ledger = rig
    wire = _artifact(seq=1)
    first = ledger.queue_artifact(OUTBOX_CHECKPOINT, wire, created_at_ms=10)
    second = ledger.queue_artifact(OUTBOX_CHECKPOINT, wire, created_at_ms=99)
    assert first["id"] == second["id"]
    assert second["created_at_ms"] == 10
    assert len(ledger.pending_artifacts()) == 1


@pytest.mark.parametrize(
    "artifact_type, wire",
    [
        ("delivery_envelope", _artifact()),
        ("commissioning_authorization", _artifact()),
        (OUTBOX_CHECKPOINT, _artifact(device_id="another-device")),
        (OUTBOX_CHECKPOINT, b"not json"),
        (OUTBOX_CHECKPOINT, b"[]"),
    ],
)
def test_the_outbox_refuses_what_it_does_not_carry(rig, artifact_type, wire):
    _, _, ledger = rig
    with pytest.raises(DeliveryLedgerError):
        ledger.queue_artifact(artifact_type, wire, created_at_ms=10)
    assert ledger.pending_artifacts() == []


def test_pending_artifacts_are_oldest_first_and_exclude_retired(rig):
    _, _, ledger = rig
    a = ledger.queue_artifact(OUTBOX_CHECKPOINT, _artifact(n=1), created_at_ms=1)
    b = ledger.queue_artifact(OUTBOX_CHECKPOINT, _artifact(n=2), created_at_ms=2)
    c = ledger.queue_artifact(OUTBOX_CHECKPOINT, _artifact(n=3), created_at_ms=3)
    assert ledger.retire_artifact(b["artifact_digest"], outcome=RETIRE_QUEUED, at_ms=5)
    pending = [row["artifact_digest"] for row in ledger.pending_artifacts()]
    assert pending == [a["artifact_digest"], c["artifact_digest"]]
    assert [row["artifact_digest"] for row in ledger.pending_artifacts(limit=1)] == [
        a["artifact_digest"]
    ]


def test_retirement_happens_once_and_is_final(rig):
    _, _, ledger = rig
    row = ledger.queue_artifact(OUTBOX_CHECKPOINT, _artifact(), created_at_ms=1)
    digest = row["artifact_digest"]
    assert ledger.retire_artifact(digest, outcome=RETIRE_QUEUED, at_ms=5)
    assert not ledger.retire_artifact(digest, outcome=RETIRE_QUEUED, at_ms=6)
    assert not ledger.retire_artifact(
        "sha256:" + "0" * 64, outcome=RETIRE_QUEUED, at_ms=6
    )
    with pytest.raises(DeliveryLedgerError):
        ledger.retire_artifact(digest, outcome="lost", at_ms=6)
    retired = ledger.find_artifact(digest)
    assert retired["retired_at_ms"] == 5 and retired["retire_outcome"] == RETIRE_QUEUED
    with pytest.raises(sqlite3.IntegrityError):
        ledger._connection.execute(
            "UPDATE evidence_outbox SET retired_at_ms = NULL, retire_outcome = NULL"
        )
    with pytest.raises(sqlite3.IntegrityError):
        ledger._connection.execute(
            "UPDATE evidence_outbox SET retire_outcome = ? ", (RETIRE_REFUSED,)
        )


def test_queued_bytes_cannot_be_rewritten_or_deleted(rig):
    _, _, ledger = rig
    ledger.queue_artifact(OUTBOX_CHECKPOINT, _artifact(), created_at_ms=1)
    with pytest.raises(sqlite3.IntegrityError):
        ledger._connection.execute("DELETE FROM evidence_outbox")
    with pytest.raises(sqlite3.IntegrityError):
        ledger._connection.execute("UPDATE evidence_outbox SET artifact_json = '{}'")
    with pytest.raises(sqlite3.IntegrityError):
        ledger._connection.execute(
            "UPDATE evidence_outbox SET artifact_type = 'anchor_registration'"
        )
    assert len(ledger.pending_artifacts()) == 1


def test_attempts_are_counted_without_touching_the_bytes(rig):
    _, _, ledger = rig
    row = ledger.queue_artifact(OUTBOX_CHECKPOINT, _artifact(), created_at_ms=1)
    ledger.note_artifact_attempt(row["artifact_digest"], at_ms=7)
    ledger.note_artifact_attempt(row["artifact_digest"], at_ms=9)
    after = ledger.find_artifact(row["artifact_digest"])
    assert after["attempts"] == 2 and after["last_attempt_ms"] == 9
    assert after["artifact_json"] == row["artifact_json"]


def test_issuing_a_checkpoint_retains_bytes_that_verify(rig):
    key, chain, ledger = rig
    ledger.seal(_append(chain, 1), sealed_at_ms=1751500800500)
    row = ledger.issue_checkpoint(issued_at_ms=1751500900000)
    assert row["artifact_type"] == OUTBOX_CHECKPOINT
    wire = row["artifact_json"].encode("utf-8")
    checkpoint = json.loads(wire)
    assert canonical_json(checkpoint) == wire
    assert checkpoint["high_water_seq"] == 1 and checkpoint["device_id"] == DEVICE
    body = {k: v for k, v in checkpoint.items() if k != "signature"}
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex)).verify(
        base64.b64decode(checkpoint["signature"].removeprefix("ed25519:")),
        CHECKPOINT_DOMAIN + canonical_json(body),
    )
    assert [r["artifact_digest"] for r in ledger.pending_artifacts()] == [
        row["artifact_digest"]
    ]


def test_a_retained_checkpoint_survives_reopening_the_ledger(tmp_path):
    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "install-secret")
    ledger = EvidenceDeliveryLedger(
        tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id="epoch-1", key_id="key-1"
    )
    issued = ledger.issue_checkpoint(issued_at_ms=5)
    ledger.close()
    reopened = EvidenceDeliveryLedger(
        tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id="epoch-1", key_id="key-1"
    )
    try:
        pending = reopened.pending_artifacts()
        assert [r["artifact_digest"] for r in pending] == [issued["artifact_digest"]]
        assert pending[0]["artifact_json"] == issued["artifact_json"]
    finally:
        reopened.close()


def test_awaiting_custody_lists_only_unheld_envelopes_oldest_first(rig):
    _, chain, ledger = rig
    first = ledger.seal(_append(chain, 1), sealed_at_ms=100)
    second = ledger.seal(_append(chain, 2), sealed_at_ms=200)
    ledger._apply_verified_custody(
        int(first["local_seq"]), custody_at_ms=300, key_id="hkdf-sha256:" + "a" * 64
    )
    awaiting = ledger.awaiting_custody()
    assert [r["local_seq"] for r in awaiting] == [second["local_seq"]]
    assert (
        ledger.find_by_envelope_digest(second["envelope_digest"])["local_seq"]
        == second["local_seq"]
    )
    assert ledger.find_by_envelope_digest("sha256:" + "f" * 64) is None
