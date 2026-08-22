# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The delivery ledger, per `ori-specs/evidence-exchange/v1`.

Two properties carry most of the weight, and both are things a plausible
implementation gets wrong quietly: `local_seq` must be gapless by construction
rather than by convention, and custody must never be able to stand in for a
receipt.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ori.security.evidence_canonical import canonical_json
from ori.security.evidence_chain import EvidenceChain, attestation_event_id
from ori.security.evidence_device_key import EvidenceDeviceKey
from ori.security.evidence_ledger import (
    CHECKPOINT_DOMAIN,
    CUSTODY_HELD,
    ENVELOPE_DOMAIN,
    RECEIPT_ACCEPTED,
    RECEIPT_NONE,
    SEALED_COLUMNS,
    DeliveryLedgerError,
    EvidenceDeliveryLedger,
)

DEVICE = "energy-monitor-ikeja-01"
EPOCH = "epoch-0002"
KEY_ID = "anchor-key-2"


@pytest.fixture
def rig(tmp_path):
    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "install-secret")
    chain = EvidenceChain(tmp_path / "chain.db", key, DEVICE)
    ledger = EvidenceDeliveryLedger(
        tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id=EPOCH, key_id=KEY_ID
    )
    yield key, chain, ledger
    chain.close()
    ledger.close()


def _append(chain, action_log_id: int, emitted: int = 1751500800000):
    return chain.append(
        event_id=attestation_event_id(DEVICE, action_log_id),
        event_type="SAFETY_ACTION_EXECUTED",
        emitted_at_ms=emitted,
        payload={
            "kind": "runtime_action",
            "attestation": "at_emission",
            "action_log_id": action_log_id,
        },
        created_at_ms=emitted + 40,
    )


# --------------------------------------------------------------------------
# What the envelope is
# --------------------------------------------------------------------------


def test_the_envelope_matches_the_contract_field_set(rig):
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1751500800500)
    envelope = json.loads(row["envelope_json"])
    assert set(envelope) == {
        "v",
        "device_id",
        "anchor_epoch_id",
        "key_id",
        "local_seq",
        "chain_row",
        "chain_row_digest",
        "sealed_at_ms",
        "signature",
    }
    assert envelope["v"] == 1


def test_the_envelope_signature_verifies_over_the_domain(rig):
    key, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1751500800500)
    envelope = json.loads(row["envelope_json"])
    body = {k: v for k, v in envelope.items() if k != "signature"}
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex))
    public.verify(
        base64.b64decode(envelope["signature"].split("ed25519:")[1]),
        ENVELOPE_DOMAIN + canonical_json(body),
    )


def test_the_chain_row_is_carried_unaltered_and_not_re_signed(rig):
    """The envelope wraps evidence; it does not replace or restate it."""
    _, chain, ledger = rig
    chain_row = _append(chain, 1)
    row = ledger.seal(chain_row, sealed_at_ms=1751500800500)
    carried = json.loads(row["envelope_json"])["chain_row"]

    assert carried["canonical_json"] == chain_row["canonical_json"]
    assert carried["signature"] == chain_row["signature"]
    assert carried["event_hash"] == chain_row["event_hash"]
    # Export bookkeeping is local and must not travel.
    assert "exported" not in carried
    assert "exported_at_ms" not in carried


def test_the_chain_row_digest_covers_the_signed_bytes(rig):
    _, chain, ledger = rig
    chain_row = _append(chain, 1)
    row = ledger.seal(chain_row, sealed_at_ms=1751500800500)
    expected = hashlib.sha256(chain_row["canonical_json"].encode()).hexdigest()
    assert row["chain_row_digest"] == f"sha256:{expected}"


def test_the_envelope_digest_covers_the_wire_bytes_not_the_preimage(rig):
    """Custody digests what it holds, which includes the signature."""
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1751500800500)
    wire = row["envelope_json"].encode()
    assert row["envelope_digest"] == "sha256:" + hashlib.sha256(wire).hexdigest()

    envelope = json.loads(wire)
    preimage = canonical_json({k: v for k, v in envelope.items() if k != "signature"})
    assert row["envelope_digest"] != "sha256:" + hashlib.sha256(preimage).hexdigest()


# --------------------------------------------------------------------------
# local_seq is gapless by construction
# --------------------------------------------------------------------------


def test_local_seq_is_allocated_gaplessly(rig):
    _, chain, ledger = rig
    for index in range(1, 6):
        row = ledger.seal(
            _append(chain, index, 1751500800000 + index * 1000), sealed_at_ms=index
        )
        assert row["local_seq"] == index
    assert ledger.verify_sequence() == []
    assert ledger.high_water_seq() == 5


def test_the_envelope_carries_the_sequence_it_was_allocated(rig):
    """Signing before allocation would mean signing a number not yet known."""
    _, chain, ledger = rig
    for index in (1, 2, 3):
        row = ledger.seal(
            _append(chain, index, 1751500800000 + index * 1000), sealed_at_ms=index
        )
        assert json.loads(row["envelope_json"])["local_seq"] == row["local_seq"]


def test_a_failed_seal_allocates_nothing(rig):
    """No envelope means no gap: there is nothing that could be missing."""
    _, chain, ledger = rig
    ledger.seal(_append(chain, 1), sealed_at_ms=1)
    broken = dict(_append(chain, 2, 1751500802000))
    # Fails inside the transaction, after the sequence has been read and
    # before the row is written — which is precisely the window that would
    # burn a number if allocation were not part of the same commit.
    broken["created_at_ms"] = "not-a-number"

    with pytest.raises(ValueError):
        ledger.seal(broken, sealed_at_ms=2)

    assert ledger.high_water_seq() == 1, "a failed seal consumed a sequence number"
    row = ledger.seal(_append(chain, 3, 1751500803000), sealed_at_ms=3)
    assert row["local_seq"] == 2, "the sequence skipped a number after a failure"
    assert ledger.verify_sequence() == []


def test_sealing_is_idempotent_on_the_chain_event(rig):
    _, chain, ledger = rig
    chain_row = _append(chain, 1)
    first = ledger.seal(chain_row, sealed_at_ms=1)
    again = ledger.seal(chain_row, sealed_at_ms=999)
    assert again["local_seq"] == first["local_seq"]
    assert again["envelope_json"] == first["envelope_json"]
    assert ledger.high_water_seq() == 1


def test_a_row_from_another_device_is_refused(rig, tmp_path):
    _, _, ledger = rig
    other_key = EvidenceDeviceKey.load_or_create(tmp_path / "other.key", "s")
    other = EvidenceChain(tmp_path / "other.db", other_key, "some-other-device")
    try:
        foreign = other.append(
            event_id="foreign-1",
            event_type="UPTIME_HEARTBEAT",
            emitted_at_ms=1,
            payload={},
            created_at_ms=2,
        )
        with pytest.raises(DeliveryLedgerError, match="different device"):
            ledger.seal(foreign, sealed_at_ms=1)
    finally:
        other.close()


# --------------------------------------------------------------------------
# Custody is not delivery
# --------------------------------------------------------------------------


def test_custody_does_not_make_a_row_delivered(rig):
    """A stalled gateway must not be able to look like successful delivery."""
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    ledger.record_custody(row["local_seq"], custody_at_ms=2, key_id="gw-secret-1")

    held = ledger.find(row["event_id"])
    assert held["custody_state"] == CUSTODY_HELD
    assert held["receipt_state"] == RECEIPT_NONE
    assert [r["local_seq"] for r in ledger.undelivered()] == [row["local_seq"]]


def test_only_a_receipt_marks_delivery(rig):
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    ledger.record_receipt(
        row["local_seq"], receipt_at_ms=3, key_id="authority-receipt-1"
    )

    delivered = ledger.find(row["event_id"])
    assert delivered["receipt_state"] == RECEIPT_ACCEPTED
    assert ledger.undelivered() == []


def test_custody_and_receipt_are_recorded_independently(rig):
    """A receipt can arrive without custody ever having been recorded."""
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    ledger.record_receipt(
        row["local_seq"], receipt_at_ms=3, key_id="authority-receipt-1"
    )

    stored = ledger.find(row["event_id"])
    assert stored["receipt_state"] == RECEIPT_ACCEPTED
    assert stored["custody_state"] == "none"
    assert stored["custody_key_id"] is None


def test_a_receipt_without_an_authority_key_is_refused(rig):
    """Enforced by the database, not by the caller remembering."""
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    connection = sqlite3.connect(ledger._db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="authority key"):
            connection.execute(
                "UPDATE evidence_delivery_ledger SET receipt_state = 'accepted' "
                "WHERE local_seq = ?",
                (row["local_seq"],),
            )
    finally:
        connection.close()


def test_delivery_states_are_a_closed_set(rig):
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    connection = sqlite3.connect(ledger._db_path)
    try:
        for column, value in (
            ("custody_state", "probably"),
            ("receipt_state", "delivered-ish"),
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    f"UPDATE evidence_delivery_ledger SET {column} = ? WHERE local_seq = ?",
                    (value, row["local_seq"]),
                )
    finally:
        connection.close()


# --------------------------------------------------------------------------
# Gaps are what this device observed
# --------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["seal_failed", "send_failed"])
def test_locally_observed_failures_are_recorded(rig, kind):
    _, _, ledger = rig
    ledger.record_local_failure(kind, reason="transport refused", observed_at_ms=5)
    failures = ledger.local_failures()
    assert [f["kind"] for f in failures] == [kind]


@pytest.mark.parametrize(
    "kind",
    ["truncated_in_transit", "deleted_by_gateway", "authority_lost_it", "unknown"],
)
def test_unobservable_failures_are_refused(rig, kind):
    """A device cannot witness what happened after the bytes left.

    Recording it anyway would fabricate evidence of tampering, which is worse
    than recording nothing — the ledger is the thing being trusted.
    """
    _, _, ledger = rig
    with pytest.raises(DeliveryLedgerError, match="locally observable"):
        ledger.record_local_failure(kind, reason="suspicion", observed_at_ms=5)


def test_observed_failures_cannot_be_deleted(rig):
    _, _, ledger = rig
    ledger.record_local_failure("send_failed", reason="timeout", observed_at_ms=5)
    connection = sqlite3.connect(ledger._db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM evidence_delivery_gaps")
    finally:
        connection.close()


def test_retry_metadata_accumulates_without_touching_the_envelope(rig):
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    before = row["envelope_json"]
    for attempt in range(3):
        ledger.record_attempt(
            row["local_seq"], at_ms=10 + attempt, failure="unreachable"
        )
    after = ledger.find(row["event_id"])
    assert after["attempts"] == 3
    assert after["last_failure"] == "unreachable"
    assert after["envelope_json"] == before


# --------------------------------------------------------------------------
# The sealed envelope is immutable
# --------------------------------------------------------------------------


SEALED_MUTATIONS = {
    "local_seq": 99,
    "event_id": "a-different-identity",
    "chain_seq": 42,
    "device_id": "some-other-device",
    "anchor_epoch_id": "epoch-9999",
    "key_id": "another-key",
    "envelope_json": "{}",
    "envelope_digest": "sha256:" + "0" * 64,
    "chain_row_digest": "sha256:" + "0" * 64,
    "sealed_at_ms": 999_999_999,
}


def test_every_sealed_column_is_covered_by_a_mutation():
    assert set(SEALED_MUTATIONS) == set(SEALED_COLUMNS)


@pytest.mark.parametrize("column", sorted(SEALED_MUTATIONS))
def test_sealed_columns_cannot_be_updated(rig, column):
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    # A mutation equal to the stored value changes nothing, so the trigger
    # never fires and the test passes while proving nothing. This caught
    # exactly that: `sealed_at_ms` was seeded with the value the row already
    # had.
    assert row[column] != SEALED_MUTATIONS[column], (
        f"the mutation for {column} equals the stored value and would not mutate"
    )
    connection = sqlite3.connect(ledger._db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                f"UPDATE evidence_delivery_ledger SET {column} = ? WHERE local_seq = ?",
                (SEALED_MUTATIONS[column], row["local_seq"]),
            )
    finally:
        connection.close()


def test_ledger_rows_cannot_be_deleted(rig):
    _, chain, ledger = rig
    ledger.seal(_append(chain, 1), sealed_at_ms=1)
    connection = sqlite3.connect(ledger._db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM evidence_delivery_ledger")
    finally:
        connection.close()


def test_verification_reports_a_hole_rather_than_raising(rig, tmp_path):
    """A hole means the database was edited; gapless is a construction property."""
    _, chain, ledger = rig
    for index in (1, 2, 3):
        ledger.seal(
            _append(chain, index, 1751500800000 + index * 1000), sealed_at_ms=index
        )

    forged = tmp_path / "forged.db"
    source = sqlite3.connect(ledger._db_path)
    source.execute("VACUUM INTO ?", (str(forged),))
    source.close()

    connection = sqlite3.connect(forged)
    connection.execute("DROP TRIGGER IF EXISTS evidence_ledger_no_delete")
    connection.execute("DELETE FROM evidence_delivery_ledger WHERE local_seq = 2")
    connection.commit()
    connection.close()

    key = EvidenceDeviceKey.load_or_create(tmp_path / "k2.key", "s")
    reopened = EvidenceDeliveryLedger(
        forged, key, DEVICE, anchor_epoch_id=EPOCH, key_id=KEY_ID
    )
    try:
        problems = reopened.verify_sequence()
        assert any("hole" in problem for problem in problems), problems
    finally:
        reopened.close()


def test_concurrent_seals_allocate_distinct_sequences(tmp_path):
    """The reason allocation lives inside the sealing transaction.

    Single-threaded, reading the head before or inside the transaction gives
    the same answer, so nothing above distinguishes them. Under concurrency
    they differ sharply: two sealers reading the head outside would both see
    the same predecessor and both claim the same `local_seq`, and one of them
    is wrong. Gapless "by construction" means the construction has to hold when
    two writers arrive at once.
    """
    import threading

    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "s")
    chain = EvidenceChain(tmp_path / "chain.db", key, DEVICE)
    rows = [
        _append(chain, index, 1751500800000 + index * 1000) for index in range(1, 9)
    ]
    chain.close()

    # The schema is created once, up front. A SQLite connection cannot cross
    # threads, so each thread must open its own — but eight of them racing to
    # create the same tables is not a scenario a runtime has, and it tests
    # SQLite's behaviour under schema-creation contention rather than the
    # property here. That property is that two writers cannot claim the same
    # `local_seq`, so only the seals race.
    EvidenceDeliveryLedger(
        tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id=EPOCH, key_id=KEY_ID
    ).close()

    ready = threading.Barrier(len(rows))
    results: list[tuple[int, str] | BaseException] = [None] * len(rows)  # type: ignore[list-item]

    def seal(position: int) -> None:
        ledger = EvidenceDeliveryLedger(
            tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id=EPOCH, key_id=KEY_ID
        )
        try:
            ready.wait(timeout=30)
            sealed = ledger.seal(dict(rows[position]), sealed_at_ms=1000 + position)
            results[position] = (int(sealed["local_seq"]), str(sealed["event_id"]))
        except BaseException as exc:  # recorded, not raised, so every thread finishes
            results[position] = exc
        finally:
            ledger.close()

    threads = [threading.Thread(target=seal, args=(i,)) for i in range(len(rows))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    failures = [r for r in results if isinstance(r, BaseException)]
    assert not failures, f"concurrent seals failed: {failures}"

    allocated = sorted(seq for seq, _ in results)  # type: ignore[misc]
    assert allocated == list(range(1, len(rows) + 1)), (
        f"concurrent seals did not allocate a gapless sequence: {allocated}"
    )

    ledger = EvidenceDeliveryLedger(
        tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id=EPOCH, key_id=KEY_ID
    )
    try:
        assert ledger.verify_sequence() == []
        assert ledger.high_water_seq() == len(rows)
        # Every envelope must number itself with the sequence it was given.
        for row in ledger.undelivered(limit=100):
            assert json.loads(row["envelope_json"])["local_seq"] == row["local_seq"]
    finally:
        ledger.close()


# --------------------------------------------------------------------------
# Checkpoints
# --------------------------------------------------------------------------


CHECKPOINT_VECTOR = (
    pathlib.Path(__file__).parent / "vectors" / "evidence_exchange" / "checkpoint.json"
)


def test_the_checkpoint_matches_the_contract_field_set(rig):
    _, chain, ledger = rig
    ledger.seal(_append(chain, 1), sealed_at_ms=1)
    checkpoint = ledger.checkpoint(issued_at_ms=1787000000900)
    assert set(checkpoint) == {
        "v",
        "device_id",
        "high_water_seq",
        "anchor_epoch_id",
        "boot_id",
        "key_id",
        "issued_at_ms",
        "signature",
    }
    assert checkpoint["v"] == 1


def test_the_checkpoint_is_signed_by_the_device_key_over_its_own_domain(rig):
    """Not the runtime-gateway HMAC envelope, which the gateway could forge."""
    key, chain, ledger = rig
    ledger.seal(_append(chain, 1), sealed_at_ms=1)
    checkpoint = ledger.checkpoint(issued_at_ms=1787000000900)

    body = {k: v for k, v in checkpoint.items() if k != "signature"}
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex))
    public.verify(
        base64.b64decode(checkpoint["signature"].split("ed25519:")[1]),
        CHECKPOINT_DOMAIN + canonical_json(body),
    )
    assert CHECKPOINT_DOMAIN != ENVELOPE_DOMAIN, "domains must be distinct"


def test_a_checkpoint_signed_under_the_envelope_domain_does_not_verify(rig):
    """Domain separation is what stops one artifact being replayed as another."""
    key, chain, ledger = rig
    ledger.seal(_append(chain, 1), sealed_at_ms=1)
    checkpoint = ledger.checkpoint(issued_at_ms=1787000000900)
    body = canonical_json({k: v for k, v in checkpoint.items() if k != "signature"})

    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex))
    signature = base64.b64decode(checkpoint["signature"].split("ed25519:")[1])
    with pytest.raises(Exception):
        public.verify(signature, ENVELOPE_DOMAIN + body)


def test_the_checkpoint_asserts_the_current_high_water(rig):
    _, chain, ledger = rig
    assert ledger.checkpoint(issued_at_ms=1)["high_water_seq"] == 0
    for index in (1, 2, 3):
        ledger.seal(
            _append(chain, index, 1751500800000 + index * 1000), sealed_at_ms=index
        )
    assert ledger.checkpoint(issued_at_ms=2)["high_water_seq"] == 3


def test_boot_id_increases_across_restarts(tmp_path):
    """A restart must be visible as a new boot, not read as a regression."""
    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "s")
    seen = []
    for run in range(4):
        ledger = EvidenceDeliveryLedger(
            tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id=EPOCH, key_id=KEY_ID
        )
        seen.append(ledger.checkpoint(issued_at_ms=run)["boot_id"])
        ledger.close()
    assert seen == [1, 2, 3, 4]


def test_several_checkpoints_in_one_run_share_a_boot(tmp_path):
    """An interval elapsing is not a restart."""
    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "s")
    ledger = EvidenceDeliveryLedger(
        tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id=EPOCH, key_id=KEY_ID
    )
    try:
        boots = {ledger.checkpoint(issued_at_ms=n)["boot_id"] for n in range(3)}
        assert boots == {1}
    finally:
        ledger.close()


def test_opening_the_ledger_to_read_does_not_consume_a_boot(tmp_path):
    """The counter means the device restarted. A reader is not a restart."""
    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "s")
    for _ in range(5):
        reader = EvidenceDeliveryLedger(
            tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id=EPOCH, key_id=KEY_ID
        )
        reader.undelivered()
        reader.close()

    ledger = EvidenceDeliveryLedger(
        tmp_path / "ledger.db", key, DEVICE, anchor_epoch_id=EPOCH, key_id=KEY_ID
    )
    try:
        assert ledger.checkpoint(issued_at_ms=1)["boot_id"] == 1
    finally:
        ledger.close()


def test_a_boot_id_cannot_be_replayed(rig):
    """Replaying one would let an old checkpoint be presented as current."""
    _, _, ledger = rig
    ledger.checkpoint(issued_at_ms=1)  # allocates the counter
    connection = sqlite3.connect(ledger._db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="strictly increase"):
            connection.execute(
                "UPDATE evidence_boot_counter SET boot_id = 1 WHERE id = 1"
            )
    finally:
        connection.close()


def test_the_boot_counter_holds_exactly_one_row(rig):
    _, _, ledger = rig
    ledger.checkpoint(issued_at_ms=1)
    connection = sqlite3.connect(ledger._db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO evidence_boot_counter (id, boot_id) VALUES (2, 99)"
            )
    finally:
        connection.close()


def test_a_checkpoint_is_issuable_before_any_evidence_exists(rig):
    """A device that has sealed nothing still has an obligation to report.

    Otherwise silence and "nothing to say" are indistinguishable, and a device
    that never checkpoints would be exempt rather than detected.
    """
    _, _, ledger = rig
    checkpoint = ledger.checkpoint(issued_at_ms=1787000000000)
    assert checkpoint["high_water_seq"] == 0
    assert checkpoint["boot_id"] >= 1


def test_issued_at_is_carried_verbatim_as_diagnostic_evidence(rig):
    """Signed record of what the device believed, never an input to a deadline."""
    _, _, ledger = rig
    for stamp in (1787000000000, 1, 4102444800000):
        assert ledger.checkpoint(issued_at_ms=stamp)["issued_at_ms"] == stamp


def test_the_checkpoint_reproduces_the_contract_vector_shape():
    """Field set and domain, checked against the contract rather than ourselves."""
    if not CHECKPOINT_VECTOR.exists():
        pytest.skip("exchange vectors are not vendored in this checkout")
    vector = json.loads(CHECKPOINT_VECTOR.read_text())
    assert vector["domain_ascii"].encode() + b"\x00" == CHECKPOINT_DOMAIN
    published = {k for k in vector["cases"][0]["artifact"]}
    assert published == {
        "v",
        "device_id",
        "high_water_seq",
        "anchor_epoch_id",
        "boot_id",
        "key_id",
        "issued_at_ms",
        "signature",
    }
