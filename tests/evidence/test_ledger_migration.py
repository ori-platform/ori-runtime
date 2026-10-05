# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""An evidence store built by the previous release, opened by this one.

The schema is the one v2.5.0-rc.11 shipped, vendored as a fixture. Opening it
adds the withdrawal column and its trigger and the registration tables, and
carries every row the previous release wrote.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.state.store import StateStore

PREVIOUS_SCHEMA = (
    Path(__file__).resolve().parent.parent
    / "fixtures"
    / "evidence_ledger_schema_v2.5.0-rc.11.sql"
)
DEVICE = "energy-monitor-ikeja-01"
SECRET = "install-secret-for-migration-tests"


def _previous_release_store(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(PREVIOUS_SCHEMA.read_text(encoding="utf-8"))
        checkpoint = json.dumps(
            {"v": 1, "device_id": DEVICE, "anchor_epoch_id": "sha256:" + "1" * 64}
        )
        conn.execute(
            "INSERT INTO evidence_outbox (artifact_type, artifact_json,"
            " artifact_digest, created_at_ms) VALUES ('checkpoint', ?, ?, 1)",
            (checkpoint, "sha256:" + "2" * 64),
        )
        conn.execute(
            "INSERT INTO evidence_outbox (artifact_type, artifact_json,"
            " artifact_digest, created_at_ms, retired_at_ms, retire_outcome)"
            " VALUES ('checkpoint', ?, ?, 1, 2, 'queued')",
            (checkpoint, "sha256:" + "3" * 64),
        )
        conn.execute(
            "INSERT INTO evidence_device_epochs VALUES (?, ?, ?, 'x', 1, 'k')",
            (DEVICE, "sha256:" + "1" * 64, "ab" * 32),
        )
        conn.execute("INSERT INTO evidence_boot_counter VALUES (1, 7)")
        conn.commit()
    finally:
        conn.close()


async def test_a_previous_release_store_is_carried_forward(tmp_path):
    db = tmp_path / "evidence.db"
    _previous_release_store(db)

    attestor = FirstPartyEvidenceAttestor(
        db_path=str(db),
        key_path=str(tmp_path / "evidence.key"),
        device_secret=SECRET,
        device_id=DEVICE,
    )
    assert await attestor.start() is True
    try:
        assert attestor.outbound is not None
        pending = await attestor.outbound.pending_artifacts()
        assert [r["artifact_digest"] for r in pending] == ["sha256:" + "2" * 64]
        carried = await attestor.outbound.find_artifact("sha256:" + "2" * 64)
        assert carried is not None and carried["withdrawn_at_ms"] is None
        assert await attestor.reconcile_registration("sha256:" + "ab" * 32) is not None
        fields = await attestor.registration_health(10**13)
        assert fields is not None
        assert fields["registration_status"] == "pending_confirmation"
        assert await attestor.issue_checkpoint() is not None
    finally:
        attestor.close()

    conn = sqlite3.connect(str(db))
    try:
        columns = {r[1] for r in conn.execute("PRAGMA table_info(evidence_outbox)")}
        assert "withdrawn_at_ms" in columns
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {
            "evidence_registration_obligation",
            "evidence_registration_confirmation",
            "evidence_current_anchor",
            "evidence_disposition",
            "evidence_offer_stop",
        } <= tables
        indexes = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
        assert "idx_evidence_outbox_waiting" in indexes
        assert (
            conn.execute("SELECT boot_id FROM evidence_boot_counter").fetchone()[0] > 7
        ), "the boot counter restarted"
        assert (
            conn.execute("SELECT COUNT(*) FROM evidence_device_epochs").fetchone()[0]
            == 1
        )
        assert (
            conn.execute(
                "SELECT retire_outcome FROM evidence_outbox WHERE artifact_digest = ?",
                ("sha256:" + "3" * 64,),
            ).fetchone()[0]
            == "queued"
        )
        conn.execute(
            "UPDATE evidence_outbox SET withdrawn_at_ms = 5 WHERE artifact_digest = ?",
            ("sha256:" + "2" * 64,),
        )
        conn.commit()
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(
                "UPDATE evidence_outbox SET withdrawn_at_ms = NULL"
                " WHERE artifact_digest = ?",
                ("sha256:" + "2" * 64,),
            )
    finally:
        conn.close()


async def test_opening_twice_migrates_once(tmp_path):
    db = tmp_path / "evidence.db"
    _previous_release_store(db)
    for _ in range(2):
        attestor = FirstPartyEvidenceAttestor(
            db_path=str(db),
            key_path=str(tmp_path / "evidence.key"),
            device_secret=SECRET,
            device_id=DEVICE,
        )
        assert await attestor.start() is True
        attestor.close()


async def test_a_state_store_without_the_reference_table_gains_it(tmp_path):
    """A state store from the previous release has no reference table until opened."""
    path = tmp_path / "state.db"
    store = StateStore(str(path))
    await store.open()
    await store.close()
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("DROP TRIGGER evidence_commissioning_reference_bound")
        conn.execute("DROP TRIGGER evidence_commissioning_reference_no_delete")
        conn.execute("DROP TABLE evidence_commissioning_reference")
        conn.commit()
    finally:
        conn.close()

    store = StateStore(str(path))
    await store.open()
    try:
        assert (
            await store.get_evidence_commissioning_reference(
                device_id=DEVICE, anchor_epoch_id="sha256:" + "1" * 64
            )
            is None
        )
    finally:
        await store.close()
    conn = sqlite3.connect(str(path))
    try:
        triggers = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
        }
        assert {
            "evidence_commissioning_reference_bound",
            "evidence_commissioning_reference_no_delete",
        } <= triggers
    finally:
        conn.close()


async def test_a_courier_answer_moves_out_of_last_failure_on_upgrade(tmp_path):
    db = tmp_path / "evidence.db"
    _previous_release_store(db)
    conn = sqlite3.connect(str(db))
    try:
        for seq, failure in ((1, "refused"), (2, "queue_full"), (3, "unreachable")):
            conn.execute(
                "INSERT INTO evidence_delivery_ledger (local_seq, event_id, chain_seq,"
                " device_id, anchor_epoch_id, key_id, envelope_json, envelope_digest,"
                " chain_row_digest, sealed_at_ms, attempts, last_failure)"
                " VALUES (?, ?, ?, ?, 'e', 'k', '{}', ?, ?, 1, 1, ?)",
                (seq, f"evt-{seq}", seq, DEVICE, f"d{seq}", f"c{seq}", failure),
            )
        conn.commit()
    finally:
        conn.close()

    attestor = FirstPartyEvidenceAttestor(
        db_path=str(db),
        key_path=str(tmp_path / "evidence.key"),
        device_secret=SECRET,
        device_id=DEVICE,
    )
    assert await attestor.start() is True
    attestor.close()

    conn = sqlite3.connect(str(db))
    try:
        rows = conn.execute(
            "SELECT local_seq, courier_answer, last_failure"
            " FROM evidence_delivery_ledger ORDER BY local_seq"
        ).fetchall()
    finally:
        conn.close()
    assert rows == [
        (1, "refused", None),
        (2, "queue_full", None),
        (3, None, "unreachable"),
    ]


async def test_an_unknown_stored_answer_fails_closed_after_upgrade(tmp_path):
    """An added column has no CHECK, so the ledger validates stored answers itself."""
    from ori.security.evidence.ledger import DeliveryLedgerError

    db = tmp_path / "evidence.db"
    _previous_release_store(db)
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "INSERT INTO evidence_delivery_ledger (local_seq, event_id, chain_seq,"
            " device_id, anchor_epoch_id, key_id, envelope_json, envelope_digest,"
            " chain_row_digest, sealed_at_ms, attempts)"
            " VALUES (1, 'evt-1', 1, ?, 'e', 'k', '{}', 'd1', 'c1', 1, 1)",
            (DEVICE,),
        )
        conn.commit()
    finally:
        conn.close()
    attestor = FirstPartyEvidenceAttestor(
        db_path=str(db),
        key_path=str(tmp_path / "evidence.key"),
        device_secret=SECRET,
        device_id=DEVICE,
    )
    assert await attestor.start() is True
    attestor.close()
    conn = sqlite3.connect(str(db))
    try:
        conn.execute("UPDATE evidence_delivery_ledger SET courier_answer = 'accepted'")
        conn.commit()
    finally:
        conn.close()

    attestor = FirstPartyEvidenceAttestor(
        db_path=str(db),
        key_path=str(tmp_path / "evidence.key"),
        device_secret=SECRET,
        device_id=DEVICE,
    )
    assert await attestor.start() is True
    try:
        ledger = attestor._ledger
        assert ledger is not None
        assert ledger.courier_answer_faults() == 1
        outbound = attestor.outbound
        assert outbound is not None
        with pytest.raises(DeliveryLedgerError, match="does not recognise"):
            await outbound.apply_courier_answer(
                1, answer="refused", at_ms=5, answered_at_ms=5
            )
    finally:
        attestor.close()


async def test_a_courier_answer_a_rolled_back_release_recorded_is_carried_over(
    tmp_path,
):
    """The carry-over holds on every open, not only the first."""
    db = tmp_path / "evidence.db"
    _previous_release_store(db)
    attestor = FirstPartyEvidenceAttestor(
        db_path=str(db),
        key_path=str(tmp_path / "evidence.key"),
        device_secret=SECRET,
        device_id=DEVICE,
    )
    assert await attestor.start() is True
    attestor.close()
    # The previous release, rolled back to, records a refusal the way it does:
    # in last_failure, with the columns this release added left untouched.
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "INSERT INTO evidence_delivery_ledger (local_seq, event_id, chain_seq,"
            " device_id, anchor_epoch_id, key_id, envelope_json, envelope_digest,"
            " chain_row_digest, sealed_at_ms, attempts, last_failure)"
            " VALUES (1, 'evt-1', 1, ?, 'e', 'k', '{}', 'd1', 'c1', 1, 2, 'refused')",
            (DEVICE,),
        )
        conn.commit()
    finally:
        conn.close()
    attestor = FirstPartyEvidenceAttestor(
        db_path=str(db),
        key_path=str(tmp_path / "evidence.key"),
        device_secret=SECRET,
        device_id=DEVICE,
    )
    assert await attestor.start() is True
    attestor.close()
    conn = sqlite3.connect(str(db))
    try:
        row = conn.execute(
            "SELECT courier_answer, last_failure FROM evidence_delivery_ledger"
        ).fetchone()
    finally:
        conn.close()
    assert row == ("refused", None)
