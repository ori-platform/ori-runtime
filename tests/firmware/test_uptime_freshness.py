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
from typing import Any, cast

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
        SEALED_DEVICE,
        boot_id=5,
        seq=11,
        uptime_ms=4000,
        verified_against=await _row(store),
    )
    assert await store.advance_firmware_freshness(
        SEALED_DEVICE,
        boot_id=6,
        seq=11,
        uptime_ms=1,
        verified_against=await _row(store),
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


async def _row(store: StateStore) -> dict[str, Any]:
    row = await store.get_firmware_device(SEALED_DEVICE)
    assert row is not None
    return row


def _stale_once(store: StateStore, stale: dict) -> None:
    """The next read returns *stale*: the mark the message verified against."""
    original = store.get_firmware_device
    calls = {"n": 0}

    async def read(device_id: str) -> Any:
        calls["n"] += 1
        return stale if calls["n"] == 1 else await original(device_id)

    store.get_firmware_device = read  # type: ignore[method-assign]


async def _lost(
    gate: FirmwareTelemetryGate,
    store: StateStore,
    *,
    ahead: dict[str, int],
    behind: dict[str, int],
    fault: bool = False,
    between: Any = None,
) -> str | None:
    """`behind` verifies against the mark before `ahead` committed, then loses."""
    stale = await store.get_firmware_device(SEALED_DEVICE)
    assert stale is not None
    assert await _telemetry_code(gate, **ahead) is None
    if between is not None:
        await between()
    _stale_once(store, stale)
    if fault:
        return await _fault_code(gate, **behind)
    return await _telemetry_code(gate, **behind)


@pytest.mark.parametrize("fault", [False, True], ids=["telemetry", "fault"])
async def test_a_lost_advance_is_refused_under_its_own_reason(
    gate: FirmwareTelemetryGate, store: StateStore, fault: bool
) -> None:
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    code = await _lost(
        gate,
        store,
        ahead={"boot_id": 5, "seq": 11, "uptime": 6000},
        behind={"boot_id": 5, "seq": 12, "uptime": 5500},
        fault=fault,
    )
    assert code == ERR_UPTIME_REGRESSION


async def test_a_lost_advance_behind_a_newer_boot_is_a_boot_rollback(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    code = await _lost(
        gate,
        store,
        ahead={"boot_id": 6, "seq": 11, "uptime": 100},
        behind={"boot_id": 5, "seq": 12, "uptime": 6000},
    )
    assert code == "boot_rollback"


async def test_a_lost_advance_on_a_spent_seq_is_a_replay(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    code = await _lost(
        gate,
        store,
        ahead={"boot_id": 5, "seq": 11, "uptime": 6000},
        behind={"boot_id": 5, "seq": 11, "uptime": 5500},
    )
    assert code == "sequence_replay"


async def test_a_device_revoked_before_the_advance_is_named(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None

    async def revoke() -> None:
        assert await gate.revoke_device(SEALED_DEVICE, actor="op", reason="lost")

    code = await _lost(
        gate,
        store,
        ahead={"boot_id": 5, "seq": 11, "uptime": 6000},
        behind={"boot_id": 5, "seq": 12, "uptime": 7000},
        between=revoke,
    )
    assert code == "device_revoked"


async def test_a_key_rotated_by_a_release_without_uptime_does_not_refuse(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    """Rolled back, the previous release re-keys and the device restarts at the same boot."""
    assert await _telemetry_code(gate, boot_id=3, seq=10, uptime=86_400_000) is None
    assert store._conn is not None
    store._conn.execute(
        "UPDATE firmware_device_registry SET key_epoch_id = 'rotated',"
        " last_boot_id = 3, last_seq = 1 WHERE device_id = ?",
        (SEALED_DEVICE,),
    )
    store._conn.commit()
    row = await store.get_firmware_device(SEALED_DEVICE)
    assert row is not None and row["last_uptime_ms"] is None
    stale = store._conn.execute(
        "SELECT COUNT(*) FROM firmware_device_registry WHERE device_id = ?"
        " AND last_uptime_mark IS NOT"
        " COALESCE(key_epoch_id, '') || ':' || last_boot_id || ':' || last_seq",
        (SEALED_DEVICE,),
    ).fetchone()
    assert tuple(stale) == (1,)
    assert await store.advance_firmware_freshness(
        SEALED_DEVICE,
        boot_id=3,
        seq=2,
        uptime_ms=2000,
        verified_against=await _row(store),
    )


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
        "SELECT last_uptime_ms, last_uptime_mark FROM firmware_device_registry"
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
    expected = "unsupported_version" if family == "envelope" else "invalid_envelope"
    assert not verification.accepted and verification.error_code == expected


def test_the_verifiers_refuse_a_regression_themselves() -> None:
    """The verifier is an entry point of its own, not only the store's check."""
    from ori.security.firmware.telemetry import (
        verify_fault_message,
        verify_telemetry_message,
    )
    from tests.firmware.test_telemetry import (
        PUBLIC_KEY_B64,
        SEALED_HASH,
        telemetry_message,
    )

    envelope = CASES["telemetry_single_reading"]["input"]
    common = {
        "anchor_device_id": envelope["device_id"],
        "anchor_public_key_b64": PUBLIC_KEY_B64,
        "anchor_posture": envelope["posture"],
        "accepted_manifest_hash": envelope["capability_hash"],
        "last_boot_id": envelope["boot_id"],
        "last_seq": envelope["seq"] - 1,
    }
    behind = verify_telemetry_message(
        telemetry_message("telemetry_single_reading"),
        last_uptime_ms=envelope["device_uptime_ms"] + 1,
        **common,
    )
    assert behind.error_code == ERR_UPTIME_REGRESSION
    level = verify_telemetry_message(
        telemetry_message("telemetry_single_reading"),
        last_uptime_ms=envelope["device_uptime_ms"],
        **common,
    )
    assert level.accepted

    fault = signed_fault_message(seq=130_486)
    result = verify_fault_message(
        fault,
        anchor_device_id=SEALED_DEVICE,
        anchor_public_key_b64=PUBLIC_KEY_B64,
        anchor_posture="sealed_flash",
        accepted_manifest_hash=SEALED_HASH,
        last_boot_id=41,
        last_seq=130_485,
        last_uptime_ms=925_001,
    )
    assert result.error_code == ERR_UPTIME_REGRESSION


async def test_a_mark_differing_only_in_key_epoch_is_not_compared(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    """A re-key landing on the same boot and seq leaves the old uptime behind."""
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=86_400_000) is None
    assert store._conn is not None
    store._conn.execute(
        "UPDATE firmware_device_registry SET key_epoch_id = 'rotated'"
        " WHERE device_id = ?",
        (SEALED_DEVICE,),
    )
    store._conn.commit()
    row = await store.get_firmware_device(SEALED_DEVICE)
    assert row is not None and (row["last_boot_id"], row["last_seq"]) == (5, 10)
    assert row["last_uptime_ms"] is None
    assert await store.advance_firmware_freshness(
        SEALED_DEVICE,
        boot_id=5,
        seq=11,
        uptime_ms=100,
        verified_against=await _row(store),
    )


async def test_a_device_unapproved_before_the_advance_is_named(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None

    async def revoke_and_reinstate() -> None:
        assert await gate.revoke_device(SEALED_DEVICE, actor="op", reason="check")
        assert await gate.reinstate_device(SEALED_DEVICE, actor="op", reason="check")

    code = await _lost(
        gate,
        store,
        ahead={"boot_id": 5, "seq": 11, "uptime": 6000},
        behind={"boot_id": 5, "seq": 12, "uptime": 7000},
        between=revoke_and_reinstate,
    )
    assert code == "device_not_approved"


def test_neither_verifier_defaults_the_stored_uptime() -> None:
    """A caller that forgets the stored uptime must fail, not skip the check."""
    import inspect

    from ori.security.firmware.telemetry import (
        verify_fault_message,
        verify_telemetry_message,
    )

    for verifier in (verify_telemetry_message, verify_fault_message):
        parameter = inspect.signature(verifier).parameters["last_uptime_ms"]
        assert parameter.default is inspect.Parameter.empty, verifier.__name__


_ROTATED_SEED = bytes([0x55]) * 32


async def _rotate_key(gate: FirmwareTelemetryGate) -> None:
    from tests.firmware.test_telemetry import signed_manifest_for_key

    new_key = signed_manifest_for_key(
        _ROTATED_SEED,
        device_id=SEALED_DEVICE,
        posture="sealed_flash",
        secure_boot_enabled=True,
        flash_encryption_enabled=True,
        key_storage="efuse_derived",
    )
    await gate.reprovision_device(
        device_id=SEALED_DEVICE,
        public_key_b64=new_key["public_key_b64"],
        posture="sealed_flash",
        manifest_message=new_key,
        actor="op",
        reason="key compromised",
    )
    assert await gate.approve_device(SEALED_DEVICE, actor="op", reason="rotation")


@pytest.mark.parametrize(
    ("claims_new_hash", "expected"),
    [(False, "capability_hash_mismatch"), (True, "signature_verification_failed")],
    ids=["old-hash", "new-hash"],
)
@pytest.mark.parametrize("fault", [False, True], ids=["telemetry", "fault"])
async def test_an_old_key_message_does_not_cross_an_approved_rotation(
    gate: FirmwareTelemetryGate,
    store: StateStore,
    fault: bool,
    claims_new_hash: bool,
    expected: str,
) -> None:
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    stale = await store.get_firmware_device(SEALED_DEVICE)
    await _rotate_key(gate)
    rotated = await store.get_firmware_device(SEALED_DEVICE)
    assert rotated is not None and stale is not None
    assert rotated["key_epoch_id"] != stale["key_epoch_id"]

    # Signed with the old key. The rotated anchor's hash is public, so the
    # attacker can claim it; the stale row it verified against is the old one.
    family = "fault" if fault else "envelope"
    message = (_fault if fault else _telemetry)(boot_id=5, seq=12, uptime=7000)
    if claims_new_hash:
        body = dict(message[family], capability_hash=rotated["capability_hash"])
        message = _signed(family, body)
        stale = dict(stale, capability_hash=rotated["capability_hash"])
    _stale_once(store, stale)
    if fault:
        result = await gate.ingest_fault(message, received_at_ms=1)
    else:
        result, _ = await gate.ingest(message, received_at_ms=1)

    assert not result.accepted and result.error_code == expected
    after = await store.get_firmware_device(SEALED_DEVICE)
    assert after is not None
    assert (after["last_boot_id"], after["last_seq"], after["last_uptime_ms"]) == (
        0,
        0,
        None,
    )
    assert store._conn is not None
    stored = store._conn.execute(
        "SELECT last_uptime_mark FROM firmware_device_registry WHERE device_id = ?",
        (SEALED_DEVICE,),
    ).fetchone()
    assert stored[0] is None
    recorded = store._conn.execute(
        "SELECT COUNT(*) FROM firmware_fault_events WHERE device_id = ?",
        (SEALED_DEVICE,),
    ).fetchone()
    assert recorded[0] == 0


async def test_a_message_verified_before_a_manifest_promotion_is_verified_again(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    from tests.firmware.test_telemetry import PUBLIC_KEY_B64, signed_manifest_for_key

    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    stale = await _row(store)
    same_key = signed_manifest_for_key(
        GOLDEN_SEED,
        device_id=SEALED_DEVICE,
        firmware_version="0.2.0",
        posture="sealed_flash",
        secure_boot_enabled=True,
        flash_encryption_enabled=True,
        key_storage="efuse_derived",
    )
    await gate.register_device(
        device_id=SEALED_DEVICE,
        public_key_b64=PUBLIC_KEY_B64,
        posture="sealed_flash",
        manifest_message=same_key,
    )
    assert await gate.approve_device(SEALED_DEVICE, actor="op", reason="manifest")

    _stale_once(store, stale)
    code = await _telemetry_code(gate, boot_id=5, seq=12, uptime=7000)

    assert code == "capability_hash_mismatch"
    after = await store.get_firmware_device(SEALED_DEVICE)
    assert after is not None and (after["last_seq"], after["last_uptime_ms"]) == (
        10,
        5000,
    )


async def test_a_message_still_valid_under_the_moved_anchor_is_accepted(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    """Re-verification is a verification, not a refusal under another name."""
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    stale = await store.get_firmware_device(SEALED_DEVICE)
    assert stale is not None
    moved = dict(stale, anchor_epoch_id="moved-under-the-message")
    _stale_once(store, moved)

    verification, readings = await gate.ingest(
        _telemetry(boot_id=5, seq=11, uptime=6000), received_at_ms=1
    )

    assert verification.accepted and readings
    assert readings[0].metadata["capability_hash"] == stale["capability_hash"]
    after = await store.get_firmware_device(SEALED_DEVICE)
    assert after is not None and (after["last_seq"], after["last_uptime_ms"]) == (
        11,
        6000,
    )


async def test_an_anchor_that_will_not_hold_still_is_refused(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    original_read = store.get_firmware_device
    original_advance = store.advance_firmware_freshness
    reads = {"n": 0}
    advances = {"n": 0}

    async def read(device_id: str) -> Any:
        row = await original_read(device_id)
        assert row is not None
        reads["n"] += 1
        return dict(row, anchor_epoch_id=f"moving-{reads['n']}")

    async def advance(*args: Any, **kwargs: Any) -> bool:
        advances["n"] += 1
        return await original_advance(*args, **kwargs)

    store.get_firmware_device = read  # type: ignore[method-assign]
    store.advance_firmware_freshness = advance  # type: ignore[method-assign]

    import asyncio

    # Unbounded re-verification would never return; fail rather than hang.
    code = await asyncio.wait_for(
        _telemetry_code(gate, boot_id=5, seq=11, uptime=6000), 5.0
    )

    assert code == "anchor_unstable"
    assert advances["n"] == 3
    store.get_firmware_device = original_read  # type: ignore[method-assign]
    after = await store.get_firmware_device(SEALED_DEVICE)
    assert after is not None and after["last_seq"] == 10


@pytest.mark.parametrize(
    "column",
    [
        "public_key_b64",
        "posture",
        "capability_hash",
        "channel_map_json",
        "anchor_epoch_id",
        "key_epoch_id",
    ],
)
async def test_the_store_refuses_an_advance_verified_against_another_anchor(
    gate: FirmwareTelemetryGate, store: StateStore, column: str
) -> None:
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    current = await store.get_firmware_device(SEALED_DEVICE)
    assert current is not None
    stale = dict(current, **{column: current[column] + "-before"})

    assert not await store.advance_firmware_freshness(
        SEALED_DEVICE, boot_id=5, seq=11, uptime_ms=6000, verified_against=stale
    )
    after = await store.get_firmware_device(SEALED_DEVICE)
    assert after is not None and after["last_seq"] == 10
    assert await store.advance_firmware_freshness(
        SEALED_DEVICE, boot_id=5, seq=11, uptime_ms=6000, verified_against=current
    )


@pytest.mark.parametrize(
    "verified_against",
    [{}, {"public_key_b64": None}, None],
    ids=["empty", "null-column", "no-row"],
)
async def test_the_store_refuses_an_advance_with_no_anchor_to_bind(
    gate: FirmwareTelemetryGate, store: StateStore, verified_against: Any
) -> None:
    current = await store.get_firmware_device(SEALED_DEVICE)
    assert current is not None
    if verified_against is not None:
        verified_against = dict(current, **verified_against) if verified_against else {}
    with pytest.raises((KeyError, TypeError, ValueError)):
        await store.advance_firmware_freshness(
            SEALED_DEVICE,
            boot_id=5,
            seq=11,
            uptime_ms=6000,
            verified_against=cast(Any, verified_against),
        )
    after = await store.get_firmware_device(SEALED_DEVICE)
    assert after is not None and after["last_seq"] == 0


async def _promote_same_key_manifest(gate: FirmwareTelemetryGate) -> None:
    from tests.firmware.test_telemetry import PUBLIC_KEY_B64, signed_manifest_for_key

    manifest = signed_manifest_for_key(
        GOLDEN_SEED,
        device_id=SEALED_DEVICE,
        firmware_version="0.9.0",
        posture="sealed_flash",
        secure_boot_enabled=True,
        flash_encryption_enabled=True,
        key_storage="efuse_derived",
    )
    await gate.register_device(
        device_id=SEALED_DEVICE,
        public_key_b64=PUBLIC_KEY_B64,
        posture="sealed_flash",
        manifest_message=manifest,
    )
    assert await gate.approve_device(SEALED_DEVICE, actor="op", reason="manifest")


@pytest.mark.parametrize(
    "between", [_rotate_key, _promote_same_key_manifest], ids=["rotation", "manifest"]
)
@pytest.mark.parametrize("fault", [False, True], ids=["telemetry", "fault"])
async def test_an_anchor_moved_during_the_advance_is_honoured_by_the_subscriber(
    gate: FirmwareTelemetryGate, store: StateStore, fault: bool, between: Any
) -> None:
    """The real interleaving: the advance is held open while an operator acts."""
    import asyncio

    from ori.network.event_bus import EventBus
    from ori.runtime import _build_firmware_telemetry_subscriber
    from ori.security.firmware.liveness import FirmwareLivenessSupervisor
    from tests.firmware.test_liveness_composition import _cfg

    bus = EventBus()
    delivered: list[Any] = []

    async def handler(event: Any) -> None:
        delivered.append(event)

    bus.subscribe("*", handler)
    subscriber = _build_firmware_telemetry_subscriber(
        _cfg(), bus, store, None, FirmwareLivenessSupervisor()
    )
    assert subscriber is not None
    assert await _telemetry_code(gate, boot_id=41, seq=10, uptime=1000) is None

    entered, released = asyncio.Event(), asyncio.Event()
    advance = store.advance_firmware_freshness

    async def held(*args: Any, **kwargs: Any) -> bool:
        if not entered.is_set():
            entered.set()
            await released.wait()
        return await advance(*args, **kwargs)

    store.advance_firmware_freshness = held  # type: ignore[method-assign]
    if fault:
        ingest = subscriber._ingest_fault(_fault(boot_id=41, seq=11, uptime=2000))
    else:
        ingest = subscriber._ingest_telemetry(
            _telemetry(boot_id=41, seq=11, uptime=2000)
        )
    task = asyncio.ensure_future(ingest)
    await asyncio.wait_for(entered.wait(), 2.0)
    await between(gate)
    released.set()
    await asyncio.wait_for(task, 2.0)

    assert delivered == []
    assert store._conn is not None
    faults = store._conn.execute(
        "SELECT COUNT(*) FROM firmware_fault_events WHERE device_id = ?",
        (SEALED_DEVICE,),
    ).fetchone()
    assert faults[0] == 0
    after = await store.get_firmware_device(SEALED_DEVICE)
    expected_seq = 0 if between is _rotate_key else 10
    assert after is not None and after["last_seq"] == expected_seq


async def test_a_move_outside_the_epochs_is_verified_again(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    """Every bound column decides "moved", not only the epoch identifiers.

    The stale row differs only in the stored channel map, which verification
    reads parsed: it verifies, loses the advance, and must be verified again.
    """
    assert await _telemetry_code(gate, boot_id=5, seq=10, uptime=5000) is None
    current = await _row(store)
    _stale_once(
        store, dict(current, channel_map_json=current["channel_map_json"] + " ")
    )

    verification, readings = await gate.ingest(
        _telemetry(boot_id=5, seq=11, uptime=6000), received_at_ms=1
    )

    assert verification.accepted and readings
    assert (await _row(store))["last_seq"] == 11
