# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""evidence-exchange/v3, The projection follows the sealing epoch.

Each case of the vendored `epoch-return-v3.json` holds its records under one
sealing epoch, then reopens the same store sealing under the case's next epoch,
as a release change does, and requires exactly the records it states after.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from tests.evidence.test_restated_records_vectors import Receiver, _corrupt

VECTORS = (
    pathlib.Path(__file__).resolve().parents[1]
    / "vectors"
    / "evidence_exchange_receiver_state"
)
CORPUS = json.loads((VECTORS / "epoch-return-v3.json").read_text())
CASES = CORPUS["cases"]


def test_the_corpus_shares_restated_records_material() -> None:
    restated = json.loads((VECTORS / "restated-records-v3.json").read_text())
    assert CORPUS["device"] == {k: restated["device"][k] for k in CORPUS["device"]}
    assert CORPUS["sealed_registrations"] == restated["sealed_registrations"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_every_epoch_return_case(tmp_path: pathlib.Path, case: dict[str, Any]) -> None:
    before = Receiver(
        tmp_path, case["held_before"], sealing_epoch=case["sealing_before"]
    )
    try:
        assert before.held() == case["held_before"], (
            "the fixture did not hold the state"
        )
    finally:
        before.close()
    after = Receiver(
        tmp_path, case["held_before"], sealing_epoch=case["sealing_after"], hold=False
    )
    try:
        after.executor.run(
            after.ledger.record_current_anchor,
            posture="software_wrapped",
            recorded_at_ms=1788000000000,
        )
        assert after.held() == case["held_after"]
    finally:
        after.close()


async def test_a_start_moves_the_projection_to_the_sealing_epochs_record(
    tmp_path: pathlib.Path,
) -> None:
    """Through the attestor's real start: a held record for the epoch it seals
    under replaces a projection an earlier release left on another epoch."""
    import sqlite3

    from ori.security.evidence.first_party import FirstPartyEvidenceAttestor

    def attestor() -> FirstPartyEvidenceAttestor:
        return FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "evidence.db"),
            key_path=str(tmp_path / "device.key"),
            device_secret="s" * 32,
            device_id="edge-1",
        )

    first = attestor()
    assert await first.start() is True
    assert first._ledger is not None
    epoch = first._ledger._anchor_epoch_id
    pubkey = first._ledger._key.public_key_hex
    first.close()
    key_id = "sha256:" + "a" * 64
    with sqlite3.connect(tmp_path / "evidence.db") as db:
        db.execute(
            "INSERT INTO evidence_registration_obligation (device_id, anchor_epoch_id,"
            " pubkey_hex, commissioning_reference, artifact_json, artifact_digest,"
            " sealed_at_ms, state, closed_at_ms) VALUES (?, ?, ?, ?, '{}', ?, 1,"
            " 'confirmed', 2)",
            ("edge-1", epoch, pubkey, "sha256:" + "d" * 64, "sha256:" + "b" * 64),
        )
        db.execute(
            "INSERT INTO evidence_registration_confirmation (anchor_epoch_id,"
            " device_id, pubkey_hex, actor, confirmed_at_ms, key_id, applied_at_ms)"
            " VALUES (?, 'edge-1', ?, 'authority', 5, ?, 6)",
            (epoch, pubkey, key_id),
        )
        db.execute(
            "INSERT INTO evidence_device_epochs (device_id, anchor_epoch_id,"
            " pubkey_hex, actor, confirmed_at_ms, key_id) VALUES ('edge-1', ?, ?,"
            " 'someone', 1, ?)",
            ("sha256:" + "c" * 64, pubkey, key_id),
        )
    second = attestor()
    try:
        assert await second.start() is True
        with sqlite3.connect(tmp_path / "evidence.db") as db:
            row = db.execute(
                "SELECT anchor_epoch_id, actor, confirmed_at_ms FROM evidence_device_epochs"
            ).fetchone()
        assert row == (epoch, "authority", 5)
    finally:
        second.close()


def test_the_anchor_and_the_projection_are_written_together(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A projection write that fails rolls the anchor write back with it."""
    case = next(c for c in CASES if c["name"] == "return_to_an_earlier_confirmed_epoch")
    held = Receiver(tmp_path, case["held_before"], sealing_epoch=case["sealing_before"])
    held.close()
    after = Receiver(
        tmp_path, case["held_before"], sealing_epoch=case["sealing_after"], hold=False
    )
    try:

        def anchor() -> Any:
            return after.ledger._connection.execute(
                "SELECT anchor_epoch_id, recorded_at_ms FROM evidence_current_anchor"
            ).fetchone()

        before = after.executor.run(anchor)

        def broken(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("projection write failed")

        monkeypatch.setattr(after.ledger, "_apply_verified_epoch", broken)
        with pytest.raises(RuntimeError):
            after.executor.run(
                after.ledger.record_current_anchor,
                posture="software_wrapped",
                recorded_at_ms=1788000000000,
            )
        now = after.executor.run(anchor)
        assert (None if now is None else tuple(now)) == (
            None if before is None else tuple(before)
        )
    finally:
        after.close()


@pytest.mark.parametrize(
    ("column", "value"),
    [("key_id", "not-a-key"), ("confirmed_at_ms", "soon"), ("device_id", "another-01")],
)
def test_a_damaged_held_record_is_a_store_fault_never_projected(
    tmp_path: pathlib.Path, column: str, value: Any
) -> None:
    from ori.security.evidence.ledger import EvidenceStoreFaultError

    case = next(c for c in CASES if c["name"] == "return_to_an_earlier_confirmed_epoch")
    held = Receiver(tmp_path, case["held_before"], sealing_epoch=case["sealing_before"])
    held.close()
    after = Receiver(
        tmp_path, case["held_before"], sealing_epoch=case["sealing_after"], hold=False
    )
    try:
        _corrupt(
            after,
            f"UPDATE evidence_registration_confirmation SET {column} = ?"
            " WHERE anchor_epoch_id = ?",
            (value, case["sealing_after"]),
        )
        with pytest.raises(EvidenceStoreFaultError):
            after.executor.run(
                after.ledger.record_current_anchor,
                posture="software_wrapped",
                recorded_at_ms=1788000000000,
            )
    finally:
        after.close()
