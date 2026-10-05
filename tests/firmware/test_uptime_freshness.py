# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""`device_uptime_ms` may reset only when `boot_id` increases.

`firmware-telemetry/v1`, *Sequence And Freshness*. Telemetry and fault events
draw on one stream, so they share the stored uptime and the refusal.
"""

from __future__ import annotations

import base64
import copy
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.telemetry import ERR_UPTIME_REGRESSION, canonical_json_bytes
from ori.state.store import StateStore
from tests.firmware.test_telemetry import (
    CASES,
    GOLDEN_SEED,
    SEALED_DEVICE,
    provision_and_approve,
    signed_fault_message,
)

KEY = Ed25519PrivateKey.from_private_bytes(GOLDEN_SEED)


def _signed(family: str, body: dict[str, Any]) -> dict[str, Any]:
    signature = KEY.sign(canonical_json_bytes(body))
    return {
        family: body,
        "signature": "ed25519:" + base64.b64encode(signature).decode(),
    }


def _telemetry(*, boot_id: int, seq: int, uptime: int) -> dict[str, Any]:
    envelope = copy.deepcopy(CASES["telemetry_single_reading"]["input"])
    envelope.update(boot_id=boot_id, seq=seq, device_uptime_ms=uptime)
    return _signed("envelope", envelope)


def _fault(*, boot_id: int, seq: int, uptime: int) -> dict[str, Any]:
    fault = dict(signed_fault_message(seq=seq)["fault"])
    fault.update(boot_id=boot_id, device_uptime_ms=uptime)
    return _signed("fault", fault)


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


@pytest.fixture
async def gate(store: StateStore) -> FirmwareTelemetryGate:
    gate = FirmwareTelemetryGate(store)
    await provision_and_approve(gate, "manifest_full_sealed")
    return gate


async def _telemetry_code(gate: FirmwareTelemetryGate, **kw: int) -> str | None:
    verification, _ = await gate.ingest(_telemetry(**kw), received_at_ms=1)
    return None if verification.accepted else verification.error_code


async def _fault_code(gate: FirmwareTelemetryGate, **kw: int) -> str | None:
    verification = await gate.ingest_fault(_fault(**kw), received_at_ms=1)
    return None if verification.accepted else verification.error_code


async def test_same_boot_regression_is_refused_and_not_recorded(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    assert (
        await _telemetry_code(gate, boot_id=5, seq=11, uptime=4999)
        == ERR_UPTIME_REGRESSION
    )
    row = await store.get_firmware_device(SEALED_DEVICE)
    assert row is not None
    assert (row["last_seq"], row["last_uptime_ms"]) == (10, 5000)


async def test_equal_uptime_within_a_boot_is_accepted(
    gate: FirmwareTelemetryGate,
) -> None:
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    assert await _telemetry_code(gate, boot_id=5, seq=11, uptime=5000) is None


async def test_a_new_boot_resets_uptime(gate: FirmwareTelemetryGate) -> None:
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    assert await _telemetry_code(gate, boot_id=6, seq=11, uptime=12) is None
    assert (
        await _telemetry_code(gate, boot_id=6, seq=12, uptime=11)
        == ERR_UPTIME_REGRESSION
    )


async def test_faults_and_telemetry_share_the_check(
    gate: FirmwareTelemetryGate,
) -> None:
    assert await _telemetry_code(gate, boot_id=41, seq=10, uptime=5000) is None
    assert (
        await _fault_code(gate, boot_id=41, seq=11, uptime=4000)
        == ERR_UPTIME_REGRESSION
    )
    assert await _fault_code(gate, boot_id=41, seq=12, uptime=6000) is None
    assert (
        await _telemetry_code(gate, boot_id=41, seq=13, uptime=5999)
        == ERR_UPTIME_REGRESSION
    )


async def test_the_store_refuses_a_regression_a_stale_reader_missed(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    assert not await store.advance_firmware_freshness(
        SEALED_DEVICE, boot_id=5, seq=11, uptime_ms=4000
    )
    assert await store.advance_firmware_freshness(
        SEALED_DEVICE, boot_id=6, seq=11, uptime_ms=1
    )


async def test_an_upgraded_row_is_seeded_by_its_first_message(tmp_path: Path) -> None:
    db = str(tmp_path / "state.db")
    first = StateStore(db_path=db)
    await first.open()
    try:
        gate = FirmwareTelemetryGate(first)
        await provision_and_approve(gate, "manifest_full_sealed")
        assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    finally:
        await first.close()
    # A store written before the column existed: drop it, as an old schema had.
    conn = sqlite3.connect(db)
    conn.execute("ALTER TABLE firmware_device_registry DROP COLUMN last_uptime_ms")
    conn.commit()
    conn.close()

    upgraded = StateStore(db_path=db)
    await upgraded.open()
    try:
        row = await upgraded.get_firmware_device(SEALED_DEVICE)
        assert row is not None and row["last_uptime_ms"] is None
        gate = FirmwareTelemetryGate(upgraded)
        assert await _telemetry_code(gate, boot_id=5, seq=11, uptime=100) is None
        assert (
            await _telemetry_code(gate, boot_id=5, seq=12, uptime=99)
            == ERR_UPTIME_REGRESSION
        )
    finally:
        await upgraded.close()
