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


async def test_a_boot_advanced_by_a_release_without_uptime_does_not_refuse(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    """Rolled back, the previous release moves boot_id and seq but not uptime."""
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=86_400_000) is None
    assert store._conn is not None
    store._conn.execute(
        "UPDATE firmware_device_registry SET last_boot_id = 6, last_seq = 21"
        " WHERE device_id = ?",
        (SEALED_DEVICE,),
    )
    store._conn.commit()
    assert await _telemetry_code(gate, boot_id=6, seq=22, uptime=3000) is None
    assert (
        await _telemetry_code(gate, boot_id=6, seq=23, uptime=2999)
        == ERR_UPTIME_REGRESSION
    )


async def test_a_lost_advance_is_refused_under_its_own_reason(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    import asyncio

    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    original = store.get_firmware_device
    reads = 0

    async def stale_read(device_id: str) -> Any:
        # Both messages verify against the same mark before either advances.
        nonlocal reads
        reads += 1
        row = await original(device_id)
        await asyncio.sleep(0.05 if reads <= 2 else 0)
        return row

    store.get_firmware_device = stale_read  # type: ignore[method-assign]
    ahead, behind = await asyncio.gather(
        gate.ingest(_telemetry(boot_id=5, seq=11, uptime=6000), received_at_ms=1),
        gate.ingest(_telemetry(boot_id=5, seq=12, uptime=5500), received_at_ms=1),
    )
    codes = sorted(str(v.error_code) for v, _ in (ahead, behind) if not v.accepted)
    assert codes == [ERR_UPTIME_REGRESSION]


async def test_a_manifest_change_keeps_uptime_and_a_new_key_resets_it(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    from tests.firmware.test_telemetry import (
        PUBLIC_KEY_B64,
        signed_manifest_for_key,
    )

    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    sealed = {
        "posture": "sealed_flash",
        "secure_boot_enabled": True,
        "flash_encryption_enabled": True,
        "key_storage": "efuse_derived",
    }
    same_key = signed_manifest_for_key(
        GOLDEN_SEED, device_id=SEALED_DEVICE, firmware_version="0.2.0", **sealed
    )
    await gate.register_device(
        device_id=SEALED_DEVICE,
        public_key_b64=PUBLIC_KEY_B64,
        posture="sealed_flash",
        manifest_message=same_key,
    )
    assert await gate.approve_device(SEALED_DEVICE, actor="op", reason="manifest")
    row = await store.get_firmware_device(SEALED_DEVICE)
    assert row is not None
    assert (row["last_boot_id"], row["last_seq"], row["last_uptime_ms"]) == (
        5,
        10,
        5000,
    )

    new_key = signed_manifest_for_key(
        bytes([0x55]) * 32, device_id=SEALED_DEVICE, **sealed
    )
    await gate.reprovision_device(
        device_id=SEALED_DEVICE,
        public_key_b64=new_key["public_key_b64"],
        posture="sealed_flash",
        manifest_message=new_key,
        actor="op",
        reason="key rotation",
    )
    assert await gate.approve_device(SEALED_DEVICE, actor="op", reason="rotation")
    row = await store.get_firmware_device(SEALED_DEVICE)
    assert row is not None
    assert (row["last_boot_id"], row["last_seq"], row["last_uptime_ms"]) == (0, 0, None)
    assert store._conn is not None
    stored = store._conn.execute(
        "SELECT last_uptime_ms, last_uptime_boot_id FROM firmware_device_registry"
        " WHERE device_id = ?",
        (SEALED_DEVICE,),
    ).fetchone()
    assert tuple(stored) == (None, None)


@pytest.mark.parametrize("family", ["envelope", "fault"])
async def test_a_message_version_that_only_equals_one_is_refused(
    gate: FirmwareTelemetryGate, family: str
) -> None:
    if family == "envelope":
        body = copy.deepcopy(CASES["telemetry_single_reading"]["input"])
        body.update(v=True, boot_id=5, seq=10)
        verification, _ = await gate.ingest(_signed("envelope", body), received_at_ms=1)
    else:
        fault = dict(signed_fault_message(seq=10)["fault"])
        fault.update(v=True)
        verification = await gate.ingest_fault(
            _signed("fault", fault), received_at_ms=1
        )
    assert not verification.accepted and verification.error_code == "invalid_envelope"
