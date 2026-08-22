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
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ori.security.evidence_canonical import canonical_json
from ori.security.evidence_chain import EvidenceChain, attestation_event_id
from ori.security.evidence_device_key import EvidenceDeviceKey
from ori.security.evidence_ledger import (
    CHECKPOINT_DOMAIN,
    CUSTODY_HELD,
    ENVELOPE_DOMAIN,
    FAILURE_REASONS,
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
    ledger._apply_verified_custody(
        row["local_seq"], custody_at_ms=2, key_id="gw-secret-1"
    )

    held = ledger.find(row["event_id"])
    assert held["custody_state"] == CUSTODY_HELD
    assert held["receipt_state"] == RECEIPT_NONE
    assert [r["local_seq"] for r in ledger.undelivered()] == [row["local_seq"]]


def test_only_a_receipt_marks_delivery(rig):
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    ledger._apply_verified_receipt(
        row["local_seq"], receipt_at_ms=3, key_id="authority-receipt-1"
    )

    delivered = ledger.find(row["event_id"])
    assert delivered["receipt_state"] == RECEIPT_ACCEPTED
    assert ledger.undelivered() == []


def test_custody_and_receipt_are_recorded_independently(rig):
    """A receipt can arrive without custody ever having been recorded."""
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    ledger._apply_verified_receipt(
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


def test_a_delivery_failure_must_name_a_sealed_envelope(rig):
    """A failure with no envelope has no referent.

    Failing before sealing allocates nothing, so there is no member of the
    delivery sequence that could be missing. The contract calls that an
    evidence/v2 attestation gap against the action row, and recording it here
    too would report one failure twice in different registers.
    """
    _, chain, ledger = rig
    with pytest.raises(DeliveryLedgerError, match="no sealed envelope"):
        ledger.record_delivery_failure(1, reason="timeout", observed_at_ms=5)

    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    ledger.record_delivery_failure(row["local_seq"], reason="timeout", observed_at_ms=5)
    assert [f["local_seq"] for f in ledger.local_failures()] == [row["local_seq"]]


@pytest.mark.parametrize("reason", sorted(FAILURE_REASONS))
def test_every_published_reason_is_accepted(rig, reason):
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    ledger.record_delivery_failure(row["local_seq"], reason=reason, observed_at_ms=5)
    assert ledger.local_failures()[0]["reason"] == reason


@pytest.mark.parametrize(
    "reason",
    [
        "connection to evidence.internal refused",
        "Traceback: ConnectionError at 10.4.2.9:8443",
        "acmechain rejected the batch",
        "truncated_in_transit",
    ],
)
def test_free_text_reasons_are_refused(rig, reason):
    """Arbitrary text would put transport detail into an operator-readable file.

    A hostname, an endpoint or a private identity reaching this database is the
    disclosure the evidence path exists behind — and the last case is the other
    failure mode: a device claiming to have witnessed something it cannot see.
    """
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    with pytest.raises(DeliveryLedgerError, match="recognised failure reason"):
        ledger.record_delivery_failure(
            row["local_seq"], reason=reason, observed_at_ms=5
        )
    assert ledger.local_failures() == []


def test_observed_failures_cannot_be_deleted_or_edited(rig):
    """Blocking deletion alone left every field rewritable."""
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    ledger.record_delivery_failure(row["local_seq"], reason="timeout", observed_at_ms=5)
    connection = sqlite3.connect(ledger._db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM evidence_delivery_gaps")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE evidence_delivery_gaps SET reason = 'refused'")
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


# --------------------------------------------------------------------------
# Conformance against the exchange vectors
#
# Vendoring vectors and not driving the implementation through them proves
# nothing: the tests above compare what this code produces against a field list
# restated here, which is the same code agreeing with itself. These reproduce
# the contract's published bytes exactly.
# --------------------------------------------------------------------------


EXCHANGE = pathlib.Path(__file__).parent / "vectors" / "evidence_exchange"


def exchange(name: str) -> dict:
    return json.loads((EXCHANGE / name).read_text())


def _valid_case(vector: dict) -> dict:
    return next(case for case in vector["cases"] if case["name"] == "valid")


def _ledger_for(tmp_path, seed_hex: str, *, epoch: str, key_id: str):
    key_path = tmp_path / "vector.key"
    key = EvidenceDeviceKey.load_or_create(key_path, "vector-secret")
    # The vector publishes the seed the signature was made with, so the ledger
    # has to sign under that key rather than a freshly generated one.
    key._private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    key._public = key._private.public_key()
    return EvidenceDeliveryLedger(
        tmp_path / "vector.db", key, DEVICE, anchor_epoch_id=epoch, key_id=key_id
    )


def test_the_envelope_reproduces_the_contract_vector_byte_for_byte(tmp_path):
    vector = exchange("delivery-envelope.json")
    case = _valid_case(vector)
    published = case["artifact"]

    ledger = _ledger_for(
        tmp_path,
        vector["signing_key_seed_hex"],
        epoch=published["anchor_epoch_id"],
        key_id=published["key_id"],
    )
    try:
        built = ledger._build_envelope(
            dict(published["chain_row"]),
            published["local_seq"],
            published["sealed_at_ms"],
        )
    finally:
        ledger.close()

    assert built["chain_row_digest"] == published["chain_row_digest"]
    assert built["signature"] == published["signature"], (
        "the envelope signature differs from the contract's published bytes"
    )
    body = {k: v for k, v in built.items() if k != "signature"}
    assert canonical_json(body).hex() == case["canonical_hex"], (
        "the signing preimage differs from the contract's published bytes"
    )
    assert canonical_json(built).hex() == case["wire_hex"], (
        "the wire bytes differ from the contract's published bytes"
    )
    assert "sha256:" + hashlib.sha256(canonical_json(built)).hexdigest() == (
        "sha256:" + hashlib.sha256(bytes.fromhex(case["wire_hex"])).hexdigest()
    )


def test_the_checkpoint_reproduces_the_contract_vector_byte_for_byte(tmp_path):
    vector = exchange("checkpoint.json")
    case = _valid_case(vector)
    published = case["artifact"]

    ledger = _ledger_for(
        tmp_path,
        vector["signing_key_seed_hex"],
        epoch=published["anchor_epoch_id"],
        key_id=published["key_id"],
    )
    try:
        # `high_water_seq` and `boot_id` are read from state, so they are set
        # to the published values rather than reached by sealing thirteen rows
        # — the bytes are what is under test, not how the numbers got there.
        ledger._boot_id = published["boot_id"]
        ledger.high_water_seq = lambda: published["high_water_seq"]  # type: ignore[method-assign]
        built = ledger.checkpoint(issued_at_ms=published["issued_at_ms"])
    finally:
        ledger.close()

    assert built == published, (
        "the checkpoint differs from the contract's published artifact"
    )
    body = {k: v for k, v in built.items() if k != "signature"}
    assert canonical_json(body).hex() == case["canonical_hex"]


# Every exchange vector, and who owes it — taken from the contract's own
# producer table rather than from what this PR happens to implement.
#
# An earlier revision swept every unimplemented vector into "ingest", which was
# wrong twice: anchor registration is produced by the runtime, and commissioning
# authorisation is not the runtime's artifact at all. Filing work under whoever
# has not done it yet is how an obligation ends up owned by nobody.

# Produced by the runtime, in this step.
PRODUCED_HERE = {"delivery-envelope.json", "checkpoint.json"}

# Produced by the runtime, still outstanding: ori-platform/ori-runtime#350.
# Registration binds this device's verification key to the epoch authorising
# it, and is signed by the key being registered — a runtime obligation, not an
# ingest one.
RUNTIME_PRODUCER_OUTSTANDING = {"anchor-registration.json"}

# Received by the runtime and verified on ingest, step 4.
STEP_FOUR_INGEST_VECTORS = {
    "delivery-receipt.json",
    "epoch-confirmation.json",
    "custody-acknowledgement.json",
}

# Signed under `commissioning_authority`, a key the evidence authority holds
# against a registry established out of band. The runtime neither produces it
# nor roots it in the release bundle, so it is not this repository's to own.
NOT_RUNTIME_ARTIFACTS = {"commissioning-authorization.json"}


def test_every_exchange_vector_is_claimed_by_an_owner():
    present = {p.name for p in EXCHANGE.glob("*.json")} - {"MANIFEST.json"}
    claimed = (
        PRODUCED_HERE
        | RUNTIME_PRODUCER_OUTSTANDING
        | STEP_FOUR_INGEST_VECTORS
        | NOT_RUNTIME_ARTIFACTS
    )
    assert present == claimed, (
        f"an exchange vector has no recorded owner: {sorted(present ^ claimed)}"
    )


def test_the_owner_sets_do_not_overlap():
    """One artifact, one owner. Overlap would hide an unowned obligation."""
    sets = [
        PRODUCED_HERE,
        RUNTIME_PRODUCER_OUTSTANDING,
        STEP_FOUR_INGEST_VECTORS,
        NOT_RUNTIME_ARTIFACTS,
    ]
    seen: set[str] = set()
    for group in sets:
        assert not (seen & group), (
            f"vector claimed by two owners: {sorted(seen & group)}"
        )
        seen |= group


@pytest.mark.parametrize("name", sorted(PRODUCED_HERE))
def test_vectors_produced_here_have_a_valid_case(name):
    """The two this step owes must each carry a case to reproduce."""
    assert _valid_case(exchange(name))["expected"] == "accept"


# --------------------------------------------------------------------------
# Idempotency means the same evidence, and state transitions are final
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("signature", "ed25519:AA==", "64 bytes"),
        ("event_hash", "0" * 64, "event_hash disagrees"),
        ("event_id", "a-different-identity", "event_id disagrees"),
        ("device_id", "some-other-device", "different device"),
        ("payload_json", '{"kind": "tampered"}', "payload_json disagrees"),
        ("canonical_json", '{"not":"the signed bytes"}', "does not carry exactly"),
    ],
)
def test_a_row_that_does_not_verify_is_never_sealed(rig, field, value, expected):
    """The envelope binds framing to evidence, so it must not wrap a non-row.

    Comparing only `chain_row_digest` let a row through whose outer signature
    had been replaced: the digest covers `canonical_json`, so the bytes matched
    while the artifact did not. Validation now runs before the idempotency
    lookup, so an unverifiable row cannot slip past by having an identity that
    happens to match one already sealed.
    """
    _, chain, ledger = rig
    original = _append(chain, 1)
    ledger.seal(original, sealed_at_ms=1)

    impostor = dict(original)
    impostor[field] = value
    with pytest.raises(DeliveryLedgerError, match=expected):
        ledger.seal(impostor, sealed_at_ms=2)
    assert ledger.high_water_seq() == 1, "a refused row allocated a sequence"


def test_a_verifying_row_that_differs_where_it_is_unsigned_is_a_conflict(rig):
    """`created_at_ms` is carried but not signed, so it is the reachable conflict.

    Every other carried column is covered by the signature, so a row differing
    in one of those fails verification rather than reaching the comparison.
    This is the case where two rows both verify and are still not the same
    evidence.
    """
    _, chain, ledger = rig
    original = _append(chain, 1)
    ledger.seal(original, sealed_at_ms=1)

    later = dict(original)
    later["created_at_ms"] = int(original["created_at_ms"]) + 5000
    with pytest.raises(DeliveryLedgerError, match="created_at_ms"):
        ledger.seal(later, sealed_at_ms=2)

    assert ledger.high_water_seq() == 1, "the conflicting reseal allocated a sequence"


def test_resealing_the_same_row_is_still_idempotent(rig):
    """The conflict check must not break the property it guards."""
    _, chain, ledger = rig
    row = _append(chain, 1)
    first = ledger.seal(row, sealed_at_ms=1)
    again = ledger.seal(dict(row), sealed_at_ms=999)
    assert again["local_seq"] == first["local_seq"]
    assert again["envelope_json"] == first["envelope_json"]


@pytest.mark.parametrize(
    "call",
    [
        lambda ledger: ledger._apply_verified_custody(
            99, custody_at_ms=1, key_id="gw-1"
        ),
        lambda ledger: ledger._apply_verified_receipt(
            99, receipt_at_ms=1, key_id="auth-1"
        ),
        lambda ledger: ledger.record_attempt(99, at_ms=1, failure="timeout"),
        lambda ledger: ledger.record_delivery_failure(
            99, reason="timeout", observed_at_ms=1
        ),
    ],
)
def test_acting_on_an_unallocated_sequence_raises(rig, call):
    """A silent zero-row update is the worst outcome.

    The caller believes it recorded delivery state; nothing did, and nothing
    said so.
    """
    _, chain, ledger = rig
    ledger.seal(_append(chain, 1), sealed_at_ms=1)
    with pytest.raises(DeliveryLedgerError, match="no sealed envelope"):
        call(ledger)


def test_recorded_custody_cannot_be_withdrawn_or_rewritten(rig):
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    ledger._apply_verified_custody(
        row["local_seq"], custody_at_ms=2, key_id="gw-secret-1"
    )

    connection = sqlite3.connect(ledger._db_path)
    try:
        for column, value in (
            ("custody_state", "none"),
            ("custody_key_id", "some-other-generation"),
            ("custody_at_ms", 999),
        ):
            with pytest.raises(sqlite3.IntegrityError, match="custody"):
                connection.execute(
                    f"UPDATE evidence_delivery_ledger SET {column} = ? WHERE local_seq = ?",
                    (value, row["local_seq"]),
                )
    finally:
        connection.close()


def test_a_recorded_receipt_cannot_be_withdrawn_or_rewritten(rig):
    """Local state disagreeing with what the authority signed is the failure.

    The runtime acts on local state, so a receipt that could be reverted or
    re-attributed would let it believe delivery happened, or happened under a
    different key, with nothing to contradict it.
    """
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    ledger._apply_verified_receipt(
        row["local_seq"], receipt_at_ms=3, key_id="authority-1"
    )

    connection = sqlite3.connect(ledger._db_path)
    try:
        for column, value in (
            ("receipt_state", "none"),
            ("receipt_key_id", "an-impostor-key"),
            ("receipt_at_ms", 999),
        ):
            with pytest.raises(sqlite3.IntegrityError, match="receipt"):
                connection.execute(
                    f"UPDATE evidence_delivery_ledger SET {column} = ? WHERE local_seq = ?",
                    (value, row["local_seq"]),
                )
    finally:
        connection.close()


def test_the_verified_transitions_are_not_a_public_boundary():
    """Ingest is the only route in, and the naming has to say so.

    Neither method can check what it is told — the signature, purpose, range
    and digest verification that makes a custody or receipt claim meaningful
    belongs to step 4. A public unverified route into the same state would make
    that verification optional in practice.
    """
    public = {name for name in dir(EvidenceDeliveryLedger) if not name.startswith("_")}
    assert "record_custody" not in public
    assert "record_receipt" not in public
    for name in ("_apply_verified_custody", "_apply_verified_receipt"):
        assert hasattr(EvidenceDeliveryLedger, name)


# --------------------------------------------------------------------------
# The database defends itself
#
# Every check above goes through the application, which has its own guards.
# These go around it, on a second connection with default settings — which is
# what an operator with sqlite3, a diagnostic tool, or a future caller that
# forgets the helper actually is. Foreign keys are off by default and are a
# per-connection setting, so a constraint that lives only in the pragma or in
# Python is not a property of the database.
# --------------------------------------------------------------------------


def test_a_second_connection_cannot_write_an_orphan_failure(rig):
    _, chain, ledger = rig
    ledger.seal(_append(chain, 1), sealed_at_ms=1)
    connection = sqlite3.connect(ledger._db_path)
    try:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 0, (
            "this test is meaningless if the pragma happens to be on"
        )
        with pytest.raises(sqlite3.IntegrityError, match="sealed envelope"):
            connection.execute(
                "INSERT INTO evidence_delivery_gaps (kind, local_seq, reason, observed_at_ms)"
                " VALUES ('send_failed', 999, 'timeout', 1)"
            )
    finally:
        connection.close()


@pytest.mark.parametrize(
    "reason",
    [
        "private.host:8443",
        "connection refused by evidence.internal",
        "Traceback (most recent call last): ConnectionError",
    ],
)
def test_a_second_connection_cannot_write_disclosure_bearing_text(rig, reason):
    """The reason vocabulary is in the schema, not only in Python.

    This file is readable by whoever holds the device. A hostname or an
    endpoint reaching it is the disclosure the evidence path exists behind, and
    an application-level check does not stop another writer.
    """
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    connection = sqlite3.connect(ledger._db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint"):
            connection.execute(
                "INSERT INTO evidence_delivery_gaps (kind, local_seq, reason, observed_at_ms)"
                " VALUES ('send_failed', ?, ?, 1)",
                (row["local_seq"], reason),
            )
    finally:
        connection.close()


def test_the_boot_counter_cannot_be_deleted_and_reinserted(rig):
    """Resetting the generation by deletion walks around the monotonic trigger.

    An operator who can reset it can replay an old checkpoint generation as
    current, which is precisely what the counter exists to prevent.
    """
    _, _, ledger = rig
    ledger.checkpoint(issued_at_ms=1)
    connection = sqlite3.connect(ledger._db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="cannot be reset"):
            connection.execute("DELETE FROM evidence_boot_counter")
    finally:
        connection.close()


def test_the_ledger_connection_enforces_foreign_keys(rig):
    """Belt to the triggers' braces, for the connection the runtime uses."""
    _, _, ledger = rig
    assert ledger._connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1


# --------------------------------------------------------------------------
# The wire contract, and canonical form
# --------------------------------------------------------------------------


def test_non_canonical_signed_bytes_are_refused(rig):
    """Parsing proves the bytes are JSON, not that they are *the* canonical form.

    An indented or unsorted encoding of the same object signs and verifies
    perfectly while being a different artifact from the one a receiver
    reproduces — so the signature is valid and the evidence still does not
    match what anyone else will compute.
    """
    _, chain, ledger = rig
    row = dict(_append(chain, 1))
    envelope = json.loads(row["canonical_json"])

    noncanonical = json.dumps(envelope, indent=2, sort_keys=False).encode()
    assert noncanonical != canonical_json(envelope), "the fixture is already canonical"
    row["canonical_json"] = noncanonical.decode()
    row["event_hash"] = hashlib.sha256(noncanonical).hexdigest()
    row["signature"] = (
        "ed25519:"
        + base64.b64encode(
            Ed25519PrivateKey.from_private_bytes(
                rig[0]._private.private_bytes_raw()
            ).sign(noncanonical)
        ).decode()
    )

    with pytest.raises(DeliveryLedgerError, match="canonical form"):
        ledger.seal(row, sealed_at_ms=1)
    assert ledger.high_water_seq() == 0


@pytest.mark.parametrize(
    "mangle,expected",
    [
        (lambda sig: sig.split("ed25519:")[1], "exactly one"),
        (lambda sig: "ed25519:ed25519:" + sig.split("ed25519:")[1], "exactly one"),
        (lambda sig: "ed448:" + sig.split("ed25519:")[1], "exactly one"),
        # Embedded whitespace is the case that separates strict decoding from
        # permissive: `validate=False` silently strips it and returns a
        # perfectly good 64-byte signature, so this artifact would be accepted
        # here and rejected by any receiver that parses strictly. A character
        # outside the alphabet would not distinguish them — both reject it,
        # for different reasons.
        (
            lambda sig: (
                "ed25519:"
                + sig.split("ed25519:")[1][:20]
                + "\n"
                + sig.split("ed25519:")[1][20:]
            ),
            "Base64",
        ),
        # Substituting a character that may not be present mangles nothing when
        # it is absent, which made an earlier version of this case pass or fail
        # on the randomness of a generated key.
        (lambda sig: "ed25519:_" + sig.split("ed25519:")[1][1:], "Base64"),
        (lambda sig: "ed25519:" + sig.split("ed25519:")[1][:-8], "64 bytes"),
    ],
)
def test_the_signature_wire_format_is_enforced(rig, mangle, expected):
    """Verification proves mathematics; it says nothing about the wire contract.

    Splitting on the prefix and taking the last part returns the whole string
    when the prefix is absent, so a prefixless signature verified and was
    accepted — and a receiver parsing strictly would then reject an artifact
    this device considered good.
    """
    _, chain, ledger = rig
    row = dict(_append(chain, 1))
    row["signature"] = mangle(row["signature"])
    with pytest.raises(DeliveryLedgerError, match=expected):
        ledger.seal(row, sealed_at_ms=1)
    assert ledger.high_water_seq() == 0


def test_a_well_formed_signature_still_seals(rig):
    """The wire checks must not reject what the contract allows."""
    _, chain, ledger = rig
    row = _append(chain, 1)
    assert row["signature"].startswith("ed25519:")
    assert ledger.seal(row, sealed_at_ms=1)["local_seq"] == 1


# --------------------------------------------------------------------------
# Delivery state is structurally complete, in both directions
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE evidence_delivery_ledger SET custody_state='held' WHERE local_seq=1",
        "UPDATE evidence_delivery_ledger SET custody_state='held', custody_at_ms=1"
        " WHERE local_seq=1",
        "UPDATE evidence_delivery_ledger SET custody_state='held', custody_key_id=''"
        ", custody_at_ms=1 WHERE local_seq=1",
        "UPDATE evidence_delivery_ledger SET receipt_state='accepted' WHERE local_seq=1",
        "UPDATE evidence_delivery_ledger SET receipt_state='accepted', receipt_at_ms=1"
        " WHERE local_seq=1",
        "UPDATE evidence_delivery_ledger SET custody_at_ms=5 WHERE local_seq=1",
        "UPDATE evidence_delivery_ledger SET receipt_key_id='x' WHERE local_seq=1",
    ],
)
def test_half_written_delivery_state_is_refused(rig, statement):
    """A state naming nobody and no moment still reads as recorded to a query.

    Both directions are constrained: an acceptance without its metadata, and
    metadata without an acceptance — the second being the residue of a
    withdrawal that should not have been possible.
    """
    _, chain, ledger = rig
    ledger.seal(_append(chain, 1), sealed_at_ms=1)
    connection = sqlite3.connect(ledger._db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(statement)
    finally:
        connection.close()


def test_complete_delivery_state_is_still_accepted(rig):
    """The constraint must not reject the transitions the ledger itself makes."""
    _, chain, ledger = rig
    row = ledger.seal(_append(chain, 1), sealed_at_ms=1)
    ledger._apply_verified_custody(row["local_seq"], custody_at_ms=2, key_id="gw-1")
    ledger._apply_verified_receipt(row["local_seq"], receipt_at_ms=3, key_id="auth-1")
    stored = ledger.find(row["event_id"])
    assert stored["custody_state"] == CUSTODY_HELD
    assert stored["receipt_state"] == RECEIPT_ACCEPTED
