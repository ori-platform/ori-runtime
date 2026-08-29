# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""What survives a restart: sealed envelopes, custody, and refusals.

The ledger holds delivery state, not the process, so an artifact arriving for
an envelope sealed before a restart is matched and applied, custody recorded
before a restart stays recorded with the receipt still outstanding, and a
refusal is visible afterwards rather than indistinguishable from silence.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.evidence.authority_keys import (
    PURPOSE_EPOCH,
    PURPOSE_RECEIPT,
    REGISTRY_SCHEMA,
    load_authority_key_registry,
)
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.chain import EvidenceChain, attestation_event_id
from ori.security.evidence.custody_keys import (
    CustodyKeyRegistry,
    derive_custody_key_id,
)
from ori.security.evidence.device_key import EvidenceDeviceKey
from ori.security.evidence.ingest import CUSTODY_DOMAIN
from ori.security.evidence.ingest_service import EvidenceIngestService
from ori.security.evidence.ledger import (
    CUSTODY_HELD,
    INGEST_REFUSAL_RETENTION,
    RECEIPT_ACCEPTED,
    RECEIPT_NONE,
    EvidenceDeliveryLedger,
)

DEVICE = "energy-monitor-ikeja-01"
EPOCH = "epoch-0002"
KEY_ID = "anchor-key-2"
RECEIPT_SEED = bytes(range(32))
EPOCH_SEED = bytes(range(32, 64))
CUSTODY_SECRET = "custody-secret-for-restart-tests-with-32b"
RECEIPT_DOMAIN = b"ori.evidence_delivery_receipt.v1\x00"


def _pub(seed: bytes) -> str:
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key.public_key().public_bytes_raw().hex()


def _sign(artifact: dict, domain: bytes, seed: bytes) -> dict:
    key = Ed25519PrivateKey.from_private_bytes(seed)
    body = {k: v for k, v in artifact.items() if k != "signature"}
    artifact["signature"] = (
        "ed25519:" + base64.b64encode(key.sign(domain + canonical_json(body))).decode()
    )
    return artifact


def _mac(artifact: dict, secret: str) -> dict:
    import hmac

    body = {k: v for k, v in artifact.items() if k != "mac"}
    artifact["mac"] = (
        "hmac-sha256:"
        + hmac.new(
            secret.encode(), CUSTODY_DOMAIN + canonical_json(body), hashlib.sha256
        ).hexdigest()
    )
    return artifact


class Site:
    """One device across restarts: the key and files persist, the process does not."""

    def __init__(self, tmp_path) -> None:
        self.root = tmp_path
        self.key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "secret")
        registry = tmp_path / "authority.json"
        registry.write_text(
            json.dumps(
                {
                    "schema": REGISTRY_SCHEMA,
                    "keys": [
                        {
                            "key_id": "auth-receipt-1",
                            "public_key_hex": _pub(RECEIPT_SEED),
                            "purpose": PURPOSE_RECEIPT,
                            "status": "active",
                        },
                        {
                            "key_id": "auth-epoch-1",
                            "public_key_hex": _pub(EPOCH_SEED),
                            "purpose": PURPOSE_EPOCH,
                            "status": "active",
                        },
                    ],
                }
            )
        )
        self.registry = load_authority_key_registry(registry)
        self.chain: EvidenceChain | None = None
        self.ledger: EvidenceDeliveryLedger | None = None
        self.service: EvidenceIngestService | None = None

    def boot(self) -> EvidenceIngestService:
        self.chain = EvidenceChain(self.root / "chain.db", self.key, DEVICE)
        self.ledger = EvidenceDeliveryLedger(
            self.root / "ledger.db",
            self.key,
            DEVICE,
            anchor_epoch_id=EPOCH,
            key_id=KEY_ID,
        )
        self.service = EvidenceIngestService(
            ledger=self.ledger,
            registry=self.registry,
            device_id=DEVICE,
            device_pubkey_hex=self.key.public_key_hex,
            custody_keys=CustodyKeyRegistry(active_secret=CUSTODY_SECRET),
        )
        return self.service

    def restart(self) -> EvidenceIngestService:
        self.stop()
        return self.boot()

    def stop(self) -> None:
        if self.chain is not None:
            self.chain.close()
        if self.ledger is not None:
            self.ledger.close()
        self.chain = self.ledger = self.service = None

    def seal(self, n: int) -> sqlite3.Row:
        assert self.chain is not None and self.ledger is not None
        row = self.chain.append(
            event_id=attestation_event_id(DEVICE, n),
            event_type="SAFETY_ACTION_EXECUTED",
            emitted_at_ms=1751500800000 + n * 1000,
            payload={"kind": "runtime_action", "action_log_id": n},
            created_at_ms=1751500800040 + n * 1000,
        )
        return self.ledger.seal(row, sealed_at_ms=1000 + n)

    def envelope(self, local_seq: int) -> sqlite3.Row:
        assert self.ledger is not None
        row = self.ledger.find_by_local_seq(local_seq)
        assert row is not None
        return row

    def receipt(self, from_seq: int, to_seq: int, *, accepted_at_ms: int) -> dict:
        assert self.ledger is not None
        digests = self.ledger.envelope_digests(from_seq, to_seq)
        raw = b"".join(
            bytes.fromhex(digests[s].split("sha256:")[1])
            for s in range(from_seq, to_seq + 1)
        )
        return _sign(
            {
                "v": 1,
                "device_id": DEVICE,
                "from_seq": from_seq,
                "to_seq": to_seq,
                "range_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "accepted_at_ms": accepted_at_ms,
                "key_id": "auth-receipt-1",
            },
            RECEIPT_DOMAIN,
            RECEIPT_SEED,
        )

    def custody(self, local_seq: int) -> dict:
        sealed = self.envelope(local_seq)
        return _mac(
            {
                "v": 1,
                "device_id": DEVICE,
                "local_seq": local_seq,
                "envelope_digest": str(sealed["envelope_digest"]),
                "custody_at_ms": 1787000000900,
                "key_id": derive_custody_key_id(CUSTODY_SECRET),
            },
            CUSTODY_SECRET,
        )


@pytest.fixture
def site(tmp_path):
    site = Site(tmp_path)
    site.boot()
    yield site
    site.stop()


def test_a_receipt_arriving_after_a_restart_is_matched_to_its_envelope(site):
    site.seal(1)
    site.seal(2)
    service = site.restart()
    outcome = service.accept_receipt(site.receipt(1, 2, accepted_at_ms=1787000001000))
    assert outcome.accepted and outcome.applied_sequences == (1, 2)
    assert site.envelope(1)["receipt_state"] == RECEIPT_ACCEPTED
    assert site.envelope(2)["receipt_state"] == RECEIPT_ACCEPTED


def test_a_receipt_arriving_long_after_a_restart_is_still_applied(site):
    """Receipts carry no freshness window; the envelope is the only binding."""
    site.seal(1)
    service = site.restart()
    a_year_later = 1751500800000 + 365 * 24 * 3600 * 1000
    outcome = service.accept_receipt(site.receipt(1, 1, accepted_at_ms=a_year_later))
    assert outcome.accepted
    assert site.envelope(1)["receipt_at_ms"] == a_year_later


def test_restart_after_custody_leaves_custody_recorded_and_receipt_outstanding(site):
    site.seal(1)
    assert site.service is not None
    assert site.service.accept_custody(site.custody(1)).accepted
    service = site.restart()
    assert site.ledger is not None
    envelope = site.envelope(1)
    assert envelope["custody_state"] == CUSTODY_HELD
    assert envelope["receipt_state"] == RECEIPT_NONE
    assert site.ledger.awaiting_custody() == []
    assert [r["local_seq"] for r in site.ledger.undelivered()] == [1]
    # Then the receipt lands, still for the same envelope.
    assert service.accept_receipt(
        site.receipt(1, 1, accepted_at_ms=1787000001000)
    ).accepted
    assert site.envelope(1)["receipt_state"] == RECEIPT_ACCEPTED


def test_a_receipt_for_an_envelope_sealed_before_the_restart_is_idempotent_after_it(
    site,
):
    site.seal(1)
    receipt = site.receipt(1, 1, accepted_at_ms=1787000001000)
    assert site.service is not None
    assert site.service.accept_receipt(receipt).accepted
    service = site.restart()
    again = service.accept_receipt(receipt)
    assert again.accepted
    assert site.envelope(1)["receipt_at_ms"] == 1787000001000


def test_custody_arriving_after_a_restart_is_applied(site):
    site.seal(1)
    custody = site.custody(1)
    service = site.restart()
    assert service.accept_custody(custody).accepted
    assert site.envelope(1)["custody_state"] == CUSTODY_HELD


# --------------------------------------------------------------------------
# Refusals are durable, visible, bounded and immutable
# --------------------------------------------------------------------------


def test_a_refusal_is_visible_after_a_restart(site):
    site.seal(1)
    bad = site.receipt(1, 1, accepted_at_ms=1787000001000)
    bad["device_id"] = "elsewhere"
    assert site.service is not None
    refused = site.service.accept_receipt(bad)
    assert not refused.accepted
    service = site.restart()
    assert site.ledger is not None
    assert [(r.artifact, r.reason) for r in service.rejections] == [
        ("delivery_receipt", refused.reason)
    ]
    count, last = site.ledger.ingest_refusal_summary()
    assert count == 1
    assert last is not None
    assert (
        last["artifact_type"] == "delivery_receipt" and last["reason"] == refused.reason
    )
    assert last["observed_at_ms"] > 0


def test_refusals_carry_no_artifact_bytes(site):
    site.seal(1)
    bad = site.receipt(1, 1, accepted_at_ms=1787000001000)
    bad["device_id"] = "elsewhere"
    assert site.service is not None
    site.service.accept_receipt(bad)
    assert site.ledger is not None
    (row,) = site.ledger.ingest_refusals()
    assert set(row.keys()) == {
        "id",
        "artifact_type",
        "reason",
        "detail",
        "observed_at_ms",
    }
    assert bad["signature"] not in row["detail"]
    assert bad["range_digest"] not in row["detail"]


def test_refusal_history_is_bounded_and_keeps_the_newest(site):
    assert site.ledger is not None
    for n in range(INGEST_REFUSAL_RETENTION + 25):
        site.ledger.record_ingest_refusal(
            artifact_type="delivery_receipt",
            reason="unknown_key",
            detail=f"probe {n}",
            observed_at_ms=n,
        )
    rows = site.ledger.ingest_refusals(limit=1000)
    assert len(rows) == INGEST_REFUSAL_RETENTION
    assert rows[0]["detail"] == "probe 25"
    assert rows[-1]["detail"] == f"probe {INGEST_REFUSAL_RETENTION + 24}"
    count, last = site.ledger.ingest_refusal_summary()
    assert count == INGEST_REFUSAL_RETENTION
    assert last is not None and last["observed_at_ms"] == INGEST_REFUSAL_RETENTION + 24


def test_a_recorded_refusal_cannot_be_rewritten(site):
    assert site.ledger is not None
    site.ledger.record_ingest_refusal(
        artifact_type="custody_acknowledgement",
        reason="bad_authenticator",
        detail="forged",
        observed_at_ms=5,
    )
    with pytest.raises(sqlite3.IntegrityError):
        site.ledger._connection.execute(
            "UPDATE evidence_ingest_refusals SET reason = 'unknown_key'"
        )


def test_an_accepted_artifact_records_no_refusal(site):
    site.seal(1)
    assert site.service is not None
    assert site.service.accept_custody(site.custody(1)).accepted
    assert site.service.rejections == ()
