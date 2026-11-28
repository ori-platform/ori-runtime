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

from tests.evidence.test_restated_records_vectors import Receiver

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
