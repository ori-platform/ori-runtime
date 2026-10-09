# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A manifest's device_mode is the one its channels and actions determine.

`firmware-telemetry/v2`, *Device Mode*. Every manifest here is correctly signed
and hashed, so the only reason it can be refused is the mode or the channels.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.telemetry import (
    ERR_INVALID_DEVICE_MODE,
    ERR_NO_CHANNELS,
    FirmwareVerificationError,
    canonical_json_bytes,
    manifest_channel_map,
    verify_manifest_message,
)
from ori.state.store import StateStore
from tests.firmware.test_telemetry import signed_manifest_for_key

SEED = bytes([0x17]) * 32
DEVICE = "ori-fw-dev00001"
METERING = {
    "channel": "ch0",
    "sensor_type": "current",
    "unit": "ampere",
    "protocol": "adc",
    "source": "ads1115",
    "quality_floor": 0.8,
}
BRIDGED = {
    "channel": "ch1",
    "sensor_type": "current",
    "unit": "ampere",
    "protocol": "modbus_rtu",
    "source": "foreign_device",
    "quality_floor": 0.8,
    "controller_profile": {
        "id": "example-rectifier",
        "digest": "sha256:" + "ab" * 32,
        "profile_channel": "output_current",
        "qualification": "unqualified",
        "record": None,
    },
}
ACTION = {"action": "relay_open", "channel": "relay0", "authority": "runtime_commanded"}


def _verify(**overrides: Any) -> str:
    message = signed_manifest_for_key(SEED, device_id=DEVICE, **overrides)
    return verify_manifest_message(
        message,
        anchor_device_id=DEVICE,
        anchor_public_key_b64=message["public_key_b64"],
    )


@pytest.mark.parametrize(
    ("mode", "channels", "actions"),
    [
        ("sensor_node", [METERING], []),
        ("bridge_node", [BRIDGED], []),
        ("mixed", [METERING, BRIDGED], []),
        ("mixed", [METERING], [ACTION]),
        ("mixed", [BRIDGED], [ACTION]),
        ("mixed", [METERING, BRIDGED], [ACTION]),
    ],
    ids=[
        "sensor",
        "bridge",
        "metering_bridged",
        "metering_action",
        "bridged_action",
        "all_three",
    ],
)
def test_the_mode_the_arrays_determine_is_accepted(
    mode: str, channels: list[dict[str, Any]], actions: list[dict[str, Any]]
) -> None:
    _verify(device_mode=mode, channels=channels, actions=actions)


@pytest.mark.parametrize(
    ("mode", "channels", "actions"),
    [
        ("sensor_node", [METERING], [ACTION]),
        ("sensor_node", [BRIDGED], []),
        ("bridge_node", [METERING], []),
        ("mixed", [METERING], []),
        ("actuator_node", [METERING], [ACTION]),
        ("passive_node", [METERING], []),
        ("Sensor_node", [METERING], []),
        ("sensor_node\n", [METERING], []),
        ("x" * 100_000, [METERING], []),
        (1, [METERING], []),
        (None, [METERING], []),
        (["sensor_node"], [METERING], []),
    ],
    ids=[
        "passive_label_on_an_actuator",
        "sensor_label_on_a_bridge",
        "bridge_label_on_a_meter",
        "mixed_over_one_role",
        "actuator_label_on_mixed",
        "unknown",
        "case_variant",
        "control_character",
        "oversized",
        "integer",
        "null",
        "list",
    ],
)
def test_a_mode_outside_the_rule_is_refused(
    mode: Any, channels: list[dict[str, Any]], actions: list[dict[str, Any]]
) -> None:
    with pytest.raises(FirmwareVerificationError) as caught:
        _verify(device_mode=mode, channels=channels, actions=actions)
    assert caught.value.code == ERR_INVALID_DEVICE_MODE
    assert len(str(caught.value)) < 200


def test_a_channel_less_actuator_is_refused_for_its_channels() -> None:
    with pytest.raises(FirmwareVerificationError) as caught:
        _verify(device_mode="actuator_node", channels=[], actions=[ACTION])
    assert caught.value.code == ERR_NO_CHANNELS


@pytest.mark.parametrize(
    ("mode", "channels", "code"),
    [
        ("sensor_node", [METERING], ERR_INVALID_DEVICE_MODE),
        ("actuator_node", [], ERR_NO_CHANNELS),
    ],
    ids=["passive_label_on_an_actuator", "channel_less_actuator"],
)
async def test_registration_refuses_it_and_stores_no_anchor(
    tmp_path: Path, mode: str, channels: list[dict[str, Any]], code: str
) -> None:
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        gate = FirmwareTelemetryGate(store)
        message = signed_manifest_for_key(
            SEED,
            device_id=DEVICE,
            device_mode=mode,
            channels=channels,
            actions=[ACTION],
        )
        with pytest.raises(FirmwareVerificationError) as caught:
            await gate.register_device(
                device_id=DEVICE,
                public_key_b64=message["public_key_b64"],
                posture="development",
                manifest_message=message,
            )
        assert caught.value.code == code
        assert await store.get_firmware_device(DEVICE) is None
    finally:
        await store.close()


async def _legacy_register(
    store: StateStore, *, approve: bool, mode: str, actions: list[dict[str, Any]]
) -> tuple[str, str]:
    """Store an anchor the way a runtime without the device-mode rules did.

    The manifest is genuinely signed and its hash pinned; only the rules it
    predates are skipped. Returns the capability hash and the public key.
    """
    message = signed_manifest_for_key(
        SEED, device_id=DEVICE, device_mode=mode, channels=[METERING], actions=actions
    )
    manifest = message["manifest"]
    await store.upsert_firmware_device_anchor(
        device_id=DEVICE,
        public_key_b64=message["public_key_b64"],
        posture="development",
        capability_hash=message["manifest_hash"],
        manifest_json=canonical_json_bytes(manifest).decode("utf-8"),
        channel_map_json=json.dumps(manifest_channel_map(manifest), sort_keys=True),
    )
    if approve:
        assert await store.approve_firmware_device(DEVICE, actor="t", reason="t")
    return message["manifest_hash"], message["public_key_b64"]


def _heartbeat(capability_hash: str) -> dict[str, Any]:
    envelope = {
        "v": 1,
        "alg": "ed25519",
        "device_id": DEVICE,
        "boot_id": 1,
        "seq": 1,
        "capability_hash": capability_hash,
        "posture": "development",
        "device_uptime_ms": 1000,
        "emitted_at_ms": None,
        "readings": [],
    }
    signature = Ed25519PrivateKey.from_private_bytes(SEED).sign(
        canonical_json_bytes(envelope)
    )
    return {
        "envelope": envelope,
        "signature": "ed25519:" + base64.b64encode(signature).decode("ascii"),
    }


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


async def test_an_active_anchor_registered_before_the_rules_gets_no_evidence_in(
    store: StateStore,
) -> None:
    capability_hash, _ = await _legacy_register(
        store, approve=True, mode="sensor_node", actions=[ACTION]
    )
    verification, readings = await FirmwareTelemetryGate(store).ingest(
        _heartbeat(capability_hash)
    )
    assert verification.grade == "rejected"
    assert verification.error_code == ERR_INVALID_DEVICE_MODE
    assert readings == []
    row = await store.get_firmware_device(DEVICE)
    assert row is not None
    assert row["last_seq"] == 0
    assert row["capability_hash"] == capability_hash


async def test_a_pending_anchor_registered_before_the_rules_is_not_promoted(
    store: StateStore,
) -> None:
    await _legacy_register(store, approve=False, mode="sensor_node", actions=[ACTION])
    with pytest.raises(FirmwareVerificationError) as caught:
        await FirmwareTelemetryGate(store).approve_device(DEVICE, actor="t", reason="t")
    assert caught.value.code == ERR_INVALID_DEVICE_MODE
    row = await store.get_firmware_device(DEVICE)
    assert row is not None
    assert not row["approved"]


async def test_an_anchor_registered_before_the_rules_that_meets_them_still_works(
    store: StateStore,
) -> None:
    capability_hash, _ = await _legacy_register(
        store, approve=True, mode="mixed", actions=[ACTION]
    )
    verification, _ = await FirmwareTelemetryGate(store).ingest(
        _heartbeat(capability_hash)
    )
    assert verification.grade == "attested_dev"


async def test_a_fault_from_an_anchor_registered_before_the_rules_is_refused(
    store: StateStore,
) -> None:
    capability_hash, _ = await _legacy_register(
        store, approve=True, mode="sensor_node", actions=[ACTION]
    )
    fault = {
        "v": 2,
        "alg": "ed25519",
        "device_id": DEVICE,
        "boot_id": 1,
        "seq": 1,
        "capability_hash": capability_hash,
        "posture": "development",
        "device_uptime_ms": 1000,
        "code": "sensor_fault",
        "subject": "ch0",
        "detail": "read_failed",
    }
    signature = Ed25519PrivateKey.from_private_bytes(SEED).sign(
        canonical_json_bytes(fault)
    )
    verification = await FirmwareTelemetryGate(store).ingest_fault(
        {
            "fault": fault,
            "signature": "ed25519:" + base64.b64encode(signature).decode("ascii"),
        }
    )
    assert verification.error_code == ERR_INVALID_DEVICE_MODE
    row = await store.get_firmware_device(DEVICE)
    assert row is not None
    assert row["last_seq"] == 0


async def test_a_failing_pending_manifest_is_not_promoted_over_a_valid_active_one(
    store: StateStore,
) -> None:
    gate = FirmwareTelemetryGate(store)
    valid = signed_manifest_for_key(
        SEED,
        device_id=DEVICE,
        device_mode="mixed",
        channels=[METERING],
        actions=[ACTION],
    )
    await gate.register_device(
        device_id=DEVICE,
        public_key_b64=valid["public_key_b64"],
        posture="development",
        manifest_message=valid,
    )
    assert await gate.approve_device(DEVICE, actor="t", reason="t")
    await _legacy_register(store, approve=False, mode="sensor_node", actions=[ACTION])
    with pytest.raises(FirmwareVerificationError) as caught:
        await gate.approve_device(DEVICE, actor="t", reason="t")
    assert caught.value.code == ERR_INVALID_DEVICE_MODE
    row = await store.get_firmware_device(DEVICE)
    assert row is not None
    assert row["capability_hash"] == valid["manifest_hash"]


async def test_a_failing_active_anchor_is_repaired_by_registering_a_valid_manifest(
    store: StateStore,
) -> None:
    await _legacy_register(store, approve=True, mode="sensor_node", actions=[ACTION])
    gate = FirmwareTelemetryGate(store)
    valid = signed_manifest_for_key(
        SEED,
        device_id=DEVICE,
        device_mode="mixed",
        channels=[METERING],
        actions=[ACTION],
    )
    await gate.register_device(
        device_id=DEVICE,
        public_key_b64=valid["public_key_b64"],
        posture="development",
        manifest_message=valid,
    )
    assert await gate.approve_device(DEVICE, actor="t", reason="t")
    verification, _ = await gate.ingest(_heartbeat(valid["manifest_hash"]))
    assert verification.grade == "attested_dev"


async def test_promotion_is_bound_to_the_candidate_that_was_checked(
    store: StateStore,
) -> None:
    await _legacy_register(store, approve=False, mode="sensor_node", actions=[ACTION])
    pending = await store.get_pending_firmware_anchor(DEVICE)
    assert pending is not None
    assert not await store.approve_firmware_device(
        DEVICE, actor="t", reason="t", expected_anchor_epoch_id="another-epoch"
    )
    assert await store.get_pending_firmware_anchor(DEVICE) == pending
    row = await store.get_firmware_device(DEVICE)
    assert row is not None
    assert not row["approved"]


async def test_a_candidate_replaced_after_its_check_is_not_promoted(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = FirmwareTelemetryGate(store)
    valid = signed_manifest_for_key(
        SEED,
        device_id=DEVICE,
        device_mode="mixed",
        channels=[METERING],
        actions=[ACTION],
    )
    await gate.register_device(
        device_id=DEVICE,
        public_key_b64=valid["public_key_b64"],
        posture="development",
        manifest_message=valid,
    )
    promote = store.approve_firmware_device

    async def replaced_first(*args: Any, **kwargs: Any) -> bool:
        await _legacy_register(
            store, approve=False, mode="sensor_node", actions=[ACTION]
        )
        return await promote(*args, **kwargs)

    monkeypatch.setattr(store, "approve_firmware_device", replaced_first)
    assert not await gate.approve_device(DEVICE, actor="t", reason="t")
    row = await store.get_firmware_device(DEVICE)
    assert row is not None
    assert not row["approved"]
