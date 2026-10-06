# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Command authority holds where the command or approval is committed.

The signer and the approval publisher check revocation, approval,
confirmation and the manifest across several reads. A trust change that
lands after those reads must still stop the command at its sequence
allocation, and the retained approval before it is published.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Awaitable, Callable

import pytest

from ori.gateway.firmware_commands import FirmwareCommandService
from ori.security.firmware.commands import FirmwareCommandError
from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.liveness import FirmwareLivenessSupervisor
from ori.state.store import FIRMWARE_ANCHOR_COLUMNS, StateStore
from tests.firmware.test_command_egress import (
    PROVISIONER_SEED,
    RUNTIME_SEED,
    _FakePublisher,
    _register_device,
)
from tests.firmware.test_commands import _confirm_active
from tests.firmware.test_uptime_freshness import (
    _promote_same_key_manifest,
    _rotate_key,
)

Change = Callable[[FirmwareTelemetryGate, str], Awaitable[None]]


async def _revoke(gate: FirmwareTelemetryGate, device_id: str) -> None:
    assert await gate.revoke_device(device_id, actor="op", reason="compromised")


async def _revoke_and_reinstate(gate: FirmwareTelemetryGate, device_id: str) -> None:
    await _revoke(gate, device_id)
    assert await gate.reinstate_device(device_id, actor="op", reason="review")


async def _rotate(gate: FirmwareTelemetryGate, device_id: str) -> None:
    del device_id
    await _rotate_key(gate)


async def _promote(gate: FirmwareTelemetryGate, device_id: str) -> None:
    del device_id
    await _promote_same_key_manifest(gate)


async def _reapprove(gate: FirmwareTelemetryGate, device_id: str) -> None:
    """The same anchor, in service again, awaiting confirmation again."""
    await _revoke_and_reinstate(gate, device_id)
    assert await gate.approve_device(device_id, actor="op", reason="cleared")
    store = gate._store
    epoch = (await store.get_firmware_device(device_id))["anchor_epoch_id"]
    # Unbound, so a test that wraps the store's read does not re-enter here.
    status = await StateStore.get_firmware_confirmation_status(store, device_id, epoch)
    assert status == "confirmation_pending"


CHANGES = [
    pytest.param(_revoke, id="revoked"),
    pytest.param(_revoke_and_reinstate, id="unapproved"),
    pytest.param(_reapprove, id="unconfirmed"),
    pytest.param(_rotate, id="rotated"),
    pytest.param(_promote, id="manifest-promoted"),
]


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


async def _service(store: StateStore) -> tuple[FirmwareCommandService, Any, str]:
    device_id = await _register_device(store)
    await _confirm_active(store, device_id)
    publisher = _FakePublisher()
    service = FirmwareCommandService(
        store=store,
        publisher=publisher,  # type: ignore[arg-type]
        runtime_command_key_bytes=RUNTIME_SEED,
        provisioner_key_bytes=PROVISIONER_SEED,
        liveness_supervisor=FirmwareLivenessSupervisor(),
    )
    return service, publisher, device_id


def _last_cmd_seq(store: StateStore, device_id: str) -> int:
    assert store._conn is not None
    row = store._conn.execute(
        "SELECT last_cmd_seq FROM firmware_device_registry WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    return int(row[0])


@pytest.mark.parametrize("change", CHANGES)
async def test_a_command_is_not_signed_across_a_change_before_its_allocation(
    store: StateStore, change: Change
) -> None:
    service, publisher, device_id = await _service(store)
    gate = FirmwareTelemetryGate(store)
    allocate = store.allocate_firmware_command_seq

    async def change_first(device: str, **kwargs: Any) -> int:
        await change(gate, device)
        return await allocate(device, **kwargs)

    store.allocate_firmware_command_seq = change_first  # type: ignore[method-assign]

    with pytest.raises(FirmwareCommandError, match="authority changed"):
        await service.publish_command(
            device_id=device_id, action="relay_open", channel="relay0"
        )

    assert publisher.commands == []
    assert _last_cmd_seq(store, device_id) == 0


@pytest.mark.parametrize("change", CHANGES)
async def test_an_approval_is_not_published_across_a_change_after_its_checks(
    store: StateStore, change: Change
) -> None:
    service, publisher, device_id = await _service(store)
    gate = FirmwareTelemetryGate(store)
    confirmation = store.get_firmware_confirmation_status

    async def change_after(device: str, epoch: str) -> Any:
        status = await confirmation(device, epoch)
        await change(gate, device)
        return status

    store.get_firmware_confirmation_status = change_after  # type: ignore[method-assign]

    with pytest.raises(FirmwareCommandError, match="authority changed"):
        await service.publish_provisioning_approval(device_id)

    assert publisher.approvals == []


async def test_both_publish_when_nothing_changed(store: StateStore) -> None:
    service, publisher, device_id = await _service(store)

    await service.publish_command(
        device_id=device_id, action="relay_open", channel="relay0"
    )
    await service.publish_provisioning_approval(device_id)

    assert len(publisher.commands) == 1 and len(publisher.approvals) == 1
    assert _last_cmd_seq(store, device_id) == 1


@pytest.mark.parametrize("column", FIRMWARE_ANCHOR_COLUMNS)
async def test_the_store_binds_command_authority_to_every_anchor_column(
    store: StateStore, column: str
) -> None:
    device_id = await _register_device(store)
    await _confirm_active(store, device_id)
    current = await store.get_firmware_device(device_id)
    assert current is not None
    stale = dict(current, **{column: current[column] + "-before"})

    assert not await store.firmware_command_authority_holds(
        device_id, verified_against=stale
    )
    with pytest.raises(PermissionError):
        await store.allocate_firmware_command_seq(device_id, verified_against=stale)
    assert _last_cmd_seq(store, device_id) == 0
    assert await store.firmware_command_authority_holds(
        device_id, verified_against=current
    )


def test_the_bound_anchor_columns_are_the_verified_anchor() -> None:
    assert set(FIRMWARE_ANCHOR_COLUMNS) == {
        "public_key_b64",
        "posture",
        "capability_hash",
        "channel_map_json",
        "anchor_epoch_id",
        "key_epoch_id",
    }


@pytest.mark.parametrize(
    "verified_against",
    [{}, {"anchor_epoch_id": None}],
    ids=["empty", "null-column"],
)
async def test_command_authority_refuses_an_incomplete_anchor(
    store: StateStore, verified_against: dict[str, Any]
) -> None:
    device_id = await _register_device(store)
    await _confirm_active(store, device_id)
    current = await store.get_firmware_device(device_id)
    assert current is not None
    anchor = dict(current, **verified_against) if verified_against else {}
    with pytest.raises((KeyError, ValueError)):
        await store.allocate_firmware_command_seq(device_id, verified_against=anchor)
    with pytest.raises((KeyError, ValueError)):
        await store.firmware_command_authority_holds(device_id, verified_against=anchor)
    assert _last_cmd_seq(store, device_id) == 0


WITHDRAWALS = [change for change in CHANGES if change.id != "unconfirmed"]


async def _liveness_signer(store: StateStore) -> tuple[Any, dict[str, Any]]:
    from ori.security.firmware.liveness import FirmwareLivenessSigner

    device_id = await _register_device(store)
    await _confirm_active(store, device_id)
    row = await store.get_firmware_device(device_id)
    assert row is not None
    supervisor = FirmwareLivenessSupervisor()
    supervisor.note_telemetry(
        device_id=device_id, boot_id=41, capability_hash=row["capability_hash"]
    )
    signer = FirmwareLivenessSigner(store, RUNTIME_SEED, supervisor=supervisor)
    liveness = {
        "device_id": device_id,
        "boot_id": 41,
        "capability_hash": row["capability_hash"],
    }
    return signer, liveness


async def test_liveness_fails_stable_while_confirmation_is_pending(
    store: StateStore,
) -> None:
    signer, liveness = await _liveness_signer(store)
    await _reapprove(FirmwareTelemetryGate(store), liveness["device_id"])
    assert await signer.sign_liveness(**liveness)


@pytest.mark.parametrize("change", WITHDRAWALS)
async def test_liveness_is_not_signed_once_authority_is_gone(
    store: StateStore, change: Change
) -> None:
    from ori.security.firmware.liveness import FirmwareLivenessError

    signer, liveness = await _liveness_signer(store)
    device_id = liveness["device_id"]
    assert await signer.sign_liveness(**liveness)

    # Supervision is in memory and outlives the change by its window.
    await change(FirmwareTelemetryGate(store), device_id)
    assert signer._supervisor.supervised(**liveness)

    with pytest.raises(FirmwareLivenessError, match="no longer holds"):
        await signer.sign_liveness(**liveness)
    assert store._conn is not None
    spent = store._conn.execute(
        "SELECT last_runtime_seq FROM firmware_device_registry WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    assert spent[0] == 1
