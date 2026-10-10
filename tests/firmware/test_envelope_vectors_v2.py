# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""firmware-telemetry/v2 envelope-vectors-v2 through the runtime's real ingest gate.

Each case is judged on its own, against a device registered under the
corpus's verifier context with no prior message accepted. Every accepted case
is accepted with its version and nonce; every refusal is refused for its
declared reason, converts into no reading, and leaves the freshness mark
where it was.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.state.store import StateStore
from tests.firmware.test_telemetry import (
    PUBLIC_KEY_B64,
    SEALED_HASH,
    provision_and_approve,
)

VECTOR_PATH = (
    Path(__file__).parent.parent
    / "vectors"
    / "firmware_telemetry"
    / "envelope-vectors-v2.json"
)
# The digest firmware-telemetry/v2 Golden Vectors pins for this corpus.
SPEC_DECLARED_SHA256 = (
    "dff9e940de06bdb1dda12ec19c3f66679b39b4a1f4d7565d9a985e9282558d7f"
)

VECTORS = json.loads(VECTOR_PATH.read_text())
ACCEPTED = VECTORS["cases"]
REFUSED = VECTORS["reject_cases"] + VECTORS["precedence_cases"]


def test_the_vendored_corpus_is_the_one_the_contract_pins() -> None:
    assert hashlib.sha256(VECTOR_PATH.read_bytes()).hexdigest() == SPEC_DECLARED_SHA256


def test_the_corpus_context_is_the_registered_fixture() -> None:
    context = VECTORS["verifier_context"]
    assert context["public_key_b64"] == PUBLIC_KEY_B64
    assert context["capability_hash"] == SEALED_HASH
    assert context["posture"] == "sealed_flash"
    assert {
        (c["channel"], c["sensor_type"], c["unit"])
        for c in context["accepted_channels"]
    } == {
        ("ch0", "current", "ampere"),
        ("ch1", "voltage", "volt"),
    }


def _wire(case: dict[str, Any]) -> dict[str, Any]:
    return json.loads(bytes.fromhex(case["message_hex"]))


@pytest.fixture
async def gate(tmp_path: Path):
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        gate = FirmwareTelemetryGate(store)
        await provision_and_approve(gate, "manifest_full_sealed")
        yield gate
    finally:
        await store.close()


async def _mark(gate: FirmwareTelemetryGate) -> tuple[Any, Any, Any]:
    row = await gate._store.get_firmware_device(
        VECTORS["verifier_context"]["device_id"]
    )
    assert row is not None
    return row["last_boot_id"], row["last_seq"], row["last_uptime_ms"]


@pytest.mark.parametrize("case", ACCEPTED, ids=[c["name"] for c in ACCEPTED])
async def test_every_accepted_case_is_accepted(
    gate: FirmwareTelemetryGate, case: dict[str, Any]
) -> None:
    message = _wire(case)
    envelope = case["input"]
    assert message["envelope"] == envelope
    verification, readings = await gate.ingest(message, received_at_ms=1)
    assert verification.accepted, (verification.error_code, verification.error_detail)
    assert verification.version == envelope["v"]
    assert verification.liveness_nonce == envelope.get("liveness_nonce")
    assert verification.is_heartbeat == (envelope["readings"] == [])
    assert [r.sensor_id.split(":")[1] for r in readings] == [
        r["channel"] for r in envelope["readings"]
    ]
    assert await _mark(gate) == (
        envelope["boot_id"],
        envelope["seq"],
        envelope["device_uptime_ms"],
    )


@pytest.mark.parametrize("case", REFUSED, ids=[c["name"] for c in REFUSED])
async def test_every_refusal_is_refused_for_its_reason_and_becomes_nothing(
    gate: FirmwareTelemetryGate, case: dict[str, Any]
) -> None:
    before = await _mark(gate)
    verification, readings = await gate.ingest(_wire(case), received_at_ms=1)
    assert not verification.accepted
    assert verification.error_code == case["reason"], verification.error_detail
    assert readings == []
    assert await _mark(gate) == before
    assert gate.reading_age.health() == []
