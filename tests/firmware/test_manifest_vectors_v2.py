# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""firmware-telemetry/v2's manifest corpus, driven through registration.

The corpus is ori-specs' own, vendored under tests/vectors/firmware_telemetry.
Each case is registered as the first manifest for its device: an accepted case
is stored, and a refusal is refused for its declared reason and stores nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.telemetry import FirmwareVerificationError
from ori.state.store import StateStore

CORPUS = json.loads(
    (
        Path(__file__).parent.parent
        / "vectors"
        / "firmware_telemetry"
        / "manifest-vectors-v2.json"
    ).read_text(encoding="utf-8")
)
CONTEXT = CORPUS["verifier_context"]
CASES = {case["name"]: case for case in CORPUS["cases"]}
REJECTS = {case["name"]: case for case in CORPUS["reject_cases"]}


async def _register(tmp_path: Path, case: dict[str, Any]) -> tuple[str, bool]:
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        message = case["message"]
        try:
            await FirmwareTelemetryGate(store).register_device(
                device_id=CONTEXT["device_id"],
                public_key_b64=CONTEXT["public_key_b64"],
                posture=message["manifest"]["posture"],
                manifest_message=message,
            )
            outcome = "accepted"
        except FirmwareVerificationError as exc:
            outcome = exc.code
        stored = await store.get_firmware_device(CONTEXT["device_id"]) is not None
    finally:
        await store.close()
    return outcome, stored


def test_the_corpus_holds_accepted_cases_and_each_refusal_class() -> None:
    assert len(CASES) >= 7
    assert {case["reason"] for case in REJECTS.values()} == {
        "invalid_device_mode",
        "no_channels",
    }
    assert all(case["signature_valid"] for case in REJECTS.values())


@pytest.mark.parametrize("name", list(CASES))
async def test_every_accepted_case_registers(tmp_path: Path, name: str) -> None:
    assert await _register(tmp_path, CASES[name]) == ("accepted", True)


@pytest.mark.parametrize("name", list(REJECTS))
async def test_every_refusal_is_refused_for_its_reason_and_stores_nothing(
    tmp_path: Path, name: str
) -> None:
    assert await _register(tmp_path, REJECTS[name]) == (REJECTS[name]["reason"], False)
