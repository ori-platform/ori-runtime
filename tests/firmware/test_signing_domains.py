# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime command key signs only in its domains, and only for a declaring device.

firmware-commands/v2 Signing Domains and firmware-telemetry/v2 Runtime Key
Domains: a device whose accepted manifest does not declare
``runtime_key_domains`` gets no command and no liveness, the refusal comes
before any sequence is spent, and the runtime says so when it accepts the
manifest and when it starts over one it already holds.
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ori.gateway.firmware_commands import FirmwareCommandService
from ori.security.firmware.commands import FirmwareCommandError, FirmwareCommandSigner
from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.liveness import (
    FirmwareLivenessError,
    FirmwareLivenessSigner,
    FirmwareLivenessSupervisor,
)
from ori.security.firmware.signing_domains import (
    command_preimage,
    liveness_preimage,
)
from ori.state.store import StateStore
from tests.firmware.declaring import declaring_message
from tests.firmware.test_command_egress import PROVISIONER_SEED
from tests.firmware.test_commands import (
    MANIFEST_CASES,
    RUNTIME_SEED,
    TELEMETRY_VECTORS,
    _confirm_active,
)

SEALED = MANIFEST_CASES["manifest_full_sealed"]["input"]
DEVICE = SEALED["device_id"]


def _bare_message() -> dict[str, Any]:
    """The fixture manifest as signed, declaring nothing."""
    case = MANIFEST_CASES["manifest_full_sealed"]
    return {
        "manifest": case["input"],
        "manifest_hash": "sha256:" + case["canonical_sha256_hex"],
        "signature": "ed25519:" + case["signature_b64"],
    }


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


async def _provision(store: StateStore, message: dict[str, Any]) -> None:
    gate = FirmwareTelemetryGate(store)
    await gate.register_device(
        device_id=DEVICE,
        public_key_b64=TELEMETRY_VECTORS["public_key_b64"],
        posture=SEALED["posture"],
        manifest_message=message,
    )
    assert await gate.approve_device(DEVICE, actor="op", reason="test")
    await _confirm_active(store, DEVICE)


def _cmd_seq(store: StateStore) -> int:
    assert store._conn is not None
    row = store._conn.execute(
        "SELECT last_cmd_seq FROM firmware_device_registry WHERE device_id = ?",
        (DEVICE,),
    ).fetchone()
    return int(row[0] or 0)


def _signature(wire: bytes) -> bytes:
    return base64.b64decode(json.loads(wire)["signature"].removeprefix("ed25519:"))


async def test_a_command_for_an_undeclared_device_is_refused_before_a_sequence(
    store: StateStore,
) -> None:
    await _provision(store, _bare_message())
    signer = FirmwareCommandSigner(store, RUNTIME_SEED)
    with pytest.raises(FirmwareCommandError, match="runtime_key_domains"):
        await signer.sign_command(
            device_id=DEVICE, action="relay_open", channel="relay0"
        )
    assert _cmd_seq(store) == 0


async def test_a_command_for_a_declaring_device_is_signed_in_the_command_domain(
    store: StateStore,
) -> None:
    await _provision(store, declaring_message(SEALED))
    signer = FirmwareCommandSigner(store, RUNTIME_SEED)
    wire = await signer.sign_command(
        device_id=DEVICE, action="relay_open", channel="relay0"
    )
    body = wire[len(b'{"command":') : wire.rindex(b',"signature":')]
    public = Ed25519PublicKey.from_public_bytes(signer.public_key_bytes())
    public.verify(_signature(wire), command_preimage(body))
    for other in (body, liveness_preimage(body)):
        with pytest.raises(Exception):
            public.verify(_signature(wire), other)
    assert _cmd_seq(store) == 1


async def test_liveness_for_an_undeclared_device_is_refused_before_allocation(
    store: StateStore,
) -> None:
    await _provision(store, _bare_message())
    row = await store.get_firmware_device(DEVICE)
    assert row is not None
    supervisor = FirmwareLivenessSupervisor()
    supervisor.note_telemetry(
        device_id=DEVICE, boot_id=41, capability_hash=row["capability_hash"]
    )
    allocations: list[str] = []
    allocate = store.allocate_firmware_runtime_seq

    async def counted(device_id: str, **kwargs: Any) -> int:
        allocations.append(device_id)
        return await allocate(device_id, **kwargs)

    store.allocate_firmware_runtime_seq = counted  # type: ignore[method-assign]
    signer = FirmwareLivenessSigner(store, RUNTIME_SEED, supervisor=supervisor)
    with pytest.raises(FirmwareLivenessError, match="runtime_key_domains"):
        await signer.sign_liveness(
            device_id=DEVICE, boot_id=41, capability_hash=row["capability_hash"]
        )
    assert allocations == []


async def test_accepting_an_undeclared_manifest_says_so(
    store: StateStore, caplog: pytest.LogCaptureFixture
) -> None:
    gate = FirmwareTelemetryGate(store)
    with caplog.at_level(logging.WARNING):
        await gate.register_device(
            device_id=DEVICE,
            public_key_b64=TELEMETRY_VECTORS["public_key_b64"],
            posture=SEALED["posture"],
            manifest_message=_bare_message(),
        )
    assert any(
        "runtime_key_domains" in r.getMessage() and DEVICE in r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING
    )


async def test_accepting_a_declaring_manifest_is_silent(
    store: StateStore, caplog: pytest.LogCaptureFixture
) -> None:
    gate = FirmwareTelemetryGate(store)
    with caplog.at_level(logging.WARNING):
        await gate.register_device(
            device_id=DEVICE,
            public_key_b64=TELEMETRY_VECTORS["public_key_b64"],
            posture=SEALED["posture"],
            manifest_message=declaring_message(SEALED),
        )
    assert not any("runtime_key_domains" in r.getMessage() for r in caplog.records)


class _NoPublisher:
    async def publish_command(self, device_id: str, message: bytes) -> None:
        raise AssertionError("nothing is published")

    async def publish_runtime_liveness(self, device_id: str, message: bytes) -> None:
        raise AssertionError("nothing is published")

    async def publish_provisioning_approval(
        self, device_id: str, message: bytes
    ) -> None:
        raise AssertionError("nothing is published")


def _service(store: StateStore) -> FirmwareCommandService:
    return FirmwareCommandService(
        store=store,
        publisher=_NoPublisher(),  # type: ignore[arg-type]
        runtime_command_key_bytes=RUNTIME_SEED,
        provisioner_key_bytes=PROVISIONER_SEED,
        liveness_supervisor=FirmwareLivenessSupervisor(),
        liveness_table=None,
    )


async def test_the_startup_report_names_held_undeclared_devices(
    store: StateStore, caplog: pytest.LogCaptureFixture
) -> None:
    await _provision(store, _bare_message())
    with caplog.at_level(logging.WARNING):
        assert await _service(store).report_undeclared_devices() == (DEVICE,)
    assert any(DEVICE in r.getMessage() for r in caplog.records)


async def test_the_startup_report_passes_a_declaring_or_revoked_device(
    store: StateStore,
) -> None:
    await _provision(store, declaring_message(SEALED))
    assert await _service(store).report_undeclared_devices() == ()


async def test_the_startup_report_skips_a_revoked_device(store: StateStore) -> None:
    await _provision(store, _bare_message())
    assert await FirmwareTelemetryGate(store).revoke_device(
        DEVICE, actor="op", reason="gone"
    )
    assert await _service(store).report_undeclared_devices() == ()


async def test_an_unreadable_registry_is_reported_not_ignored(
    store: StateStore, caplog: pytest.LogCaptureFixture
) -> None:
    async def broken() -> list[tuple[str, Any]]:
        raise RuntimeError("store unreadable")

    store.list_firmware_device_manifests = broken  # type: ignore[method-assign]
    with caplog.at_level(logging.ERROR):
        assert await _service(store).report_undeclared_devices() == ()
    assert any("undeclared signing domains" in r.getMessage() for r in caplog.records)
