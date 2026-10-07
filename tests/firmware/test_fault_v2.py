# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""firmware-telemetry/v2 fault events and the firmware-commands/v2 refusal.

The corpus is ori-specs' own, vendored under tests/vectors/firmware_telemetry.
Every case goes through the gate the MQTT subscriber calls, against a real
store, so acceptance and refusal are observed where they are recorded.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from ori.gateway.firmware_commands import FirmwareCommandService
from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.liveness import FirmwareLivenessSupervisor
from ori.security.firmware.telemetry import (
    CLOSED_FAULT_DETAILS,
    CLOSED_FAULT_DETAILS_V2,
    verify_fault_message,
)
from ori.state.store import StateStore
from tests.firmware.test_command_authority import _last_cmd_seq
from tests.firmware.test_command_egress import (
    PROVISIONER_SEED,
    RUNTIME_SEED,
    _FakePublisher,
    _register_device,
)
from tests.firmware.test_telemetry import (
    PUBLIC_KEY_B64,
    SEALED_DEVICE,
    SEALED_HASH,
    provision_and_approve,
)

CORPUS = json.loads(
    (
        Path(__file__).parent.parent
        / "vectors"
        / "firmware_telemetry"
        / "fault-vectors-v2.json"
    ).read_text()
)
CASES = {case["name"]: case for case in CORPUS["cases"]}
REJECTS = {case["name"]: case for case in CORPUS["reject_cases"]}

# What each declared reason looks like at this verifier's boundary.
REASON_DETAIL = {
    "unsupported_version": "unsupported fault version",
    "detail_not_in_closed_set": " detail ",
}


def message(case: dict[str, Any]) -> dict[str, Any]:
    return json.loads(bytes.fromhex(case["message_hex"]))


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


async def _rows(store: StateStore, table: str) -> list[tuple[Any, ...]]:
    def read(conn: Any) -> list[tuple[Any, ...]]:
        return [tuple(r) for r in conn.execute(f"SELECT * FROM {table}").fetchall()]

    return await store._run_read(read)


def test_the_corpus_is_signed_by_the_shared_test_key_for_the_sealed_device() -> None:
    context = CORPUS["verifier_context"]
    assert CORPUS["public_key_b64"] == context["public_key_b64"] == PUBLIC_KEY_B64
    assert context["device_id"] == SEALED_DEVICE
    assert context["capability_hash"] == SEALED_HASH


@pytest.mark.parametrize("name", sorted(CASES))
async def test_every_case_is_accepted_and_recorded(
    gate: FirmwareTelemetryGate, store: StateStore, name: str
) -> None:
    case = CASES[name]
    verification = await gate.ingest_fault(message(case), received_at_ms=1)

    assert verification.accepted, verification.error_detail
    assert verification.version == case["input"]["v"]
    assert (verification.code, verification.detail) == (
        case["input"]["code"],
        case["input"]["detail"],
    )
    faults = await _rows(store, "firmware_fault_events")
    assert len(faults) == 1
    row = await store.get_firmware_device(SEALED_DEVICE)
    assert row is not None and row["last_seq"] == case["input"]["seq"]


@pytest.mark.parametrize("name", sorted(REJECTS))
async def test_every_refusal_is_refused_for_its_reason_and_consumes_nothing(
    gate: FirmwareTelemetryGate, store: StateStore, name: str
) -> None:
    case = REJECTS[name]
    verification = await gate.ingest_fault(message(case), received_at_ms=1)

    assert not verification.accepted
    assert verification.error_code == "invalid_envelope"
    assert REASON_DETAIL[case["reason"]] in verification.error_detail
    assert await _rows(store, "firmware_fault_events") == []
    row = await store.get_firmware_device(SEALED_DEVICE)
    assert row is not None and row["last_seq"] == 0


def test_the_v2_closed_sets_are_the_contracts() -> None:
    # Transcribed from firmware-telemetry/v2.md, not derived from the code.
    assert CLOSED_FAULT_DETAILS_V2 == {
        "command_rejected": frozenset(
            {
                "malformed",
                "wrong_device",
                "bad_signature",
                "replayed",
                "capability_mismatch",
                "unknown_action",
                "rate_limited",
                "storage_failure",
            }
        ),
        "ingress_degraded": frozenset(
            {
                "inbound_overflow",
                "subscribe_failed",
                "anchor_persist_failed",
                "mqtt_provision_epoch_failed",
                "provisioning_serial_io_failed",
                "provisioning_serial_overflow",
                "liveness_authority_failed",
            }
        ),
        "storage_degraded": frozenset({"buffer_write_failed", "buffer_mount_failed"}),
    }
    assert "rate_limited" not in CLOSED_FAULT_DETAILS["command_rejected"]


@pytest.mark.parametrize(
    "version",
    [2.0, True, None, "2", 3, 0, -1, 2**53 - 1, [2], {"v": 2}],
    ids=repr,
)
def test_a_fault_version_other_than_the_integer_one_or_two_is_refused(
    version: Any,
) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ori.security.firmware.telemetry import canonical_json_bytes

    fault = dict(CASES["v2_command_rejected_replayed"]["input"], v=version)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(CORPUS["test_seed_hex"]))
    import base64

    signature = "ed25519:" + base64.b64encode(
        key.sign(canonical_json_bytes(fault))
    ).decode("ascii")
    result = verify_fault_message(
        {"fault": fault, "signature": signature},
        anchor_device_id=SEALED_DEVICE,
        anchor_public_key_b64=PUBLIC_KEY_B64,
        anchor_posture="sealed_flash",
        accepted_manifest_hash=SEALED_HASH,
        last_boot_id=0,
        last_seq=0,
        last_uptime_ms=None,
    )
    assert not result.accepted
    assert result.error_detail == "unsupported fault version"


async def test_a_rate_limited_refusal_is_recorded_and_nothing_is_reissued(
    tmp_path: Path,
) -> None:
    """firmware-commands/v2: a refusal is never an execution and never retried."""
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        device_id = await _register_device(store)
        publisher = _FakePublisher()
        service = FirmwareCommandService(
            store=store,
            publisher=publisher,  # type: ignore[arg-type]
            runtime_command_key_bytes=RUNTIME_SEED,
            provisioner_key_bytes=PROVISIONER_SEED,
            liveness_supervisor=FirmwareLivenessSupervisor(),
        )
        await service.publish_command(
            device_id=device_id, action="relay_open", channel="relay0"
        )
        refusal = CASES["v2_command_rejected_rate_limited"]
        verification = await FirmwareTelemetryGate(store).ingest_fault(
            message(refusal), received_at_ms=1
        )
        await asyncio.sleep(0.05)

        assert verification.accepted and verification.detail == "rate_limited"
        assert len(publisher.commands) == 1
        assert _last_cmd_seq(store, device_id) == 1
        assert await _rows(store, "action_log") == []
        assert [r for r in await _rows(store, "firmware_fault_events")] != []
    finally:
        await store.close()


async def test_a_failed_command_publish_is_not_retried(tmp_path: Path) -> None:
    """An unresolved command stays unresolved: one attempt, one sequence."""
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        device_id = await _register_device(store)

        class _Failing(_FakePublisher):
            async def publish_command(self, device_id: str, message: bytes) -> None:
                await super().publish_command(device_id, message)
                raise ConnectionError("broker gone")

        publisher = _Failing()
        service = FirmwareCommandService(
            store=store,
            publisher=publisher,  # type: ignore[arg-type]
            runtime_command_key_bytes=RUNTIME_SEED,
            provisioner_key_bytes=PROVISIONER_SEED,
            liveness_supervisor=FirmwareLivenessSupervisor(),
        )
        with pytest.raises(ConnectionError):
            await service.publish_command(
                device_id=device_id, action="relay_open", channel="relay0"
            )
        await asyncio.sleep(0.05)

        assert len(publisher.commands) == 1
        assert _last_cmd_seq(store, device_id) == 1
    finally:
        await store.close()
