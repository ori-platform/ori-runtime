# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Firmware telemetry verification against the shared golden vectors.

The vectors in tests/fixtures/firmware_layer1_vectors.json are the
cross-language signing contract shared with ori-edge-firmware (C
producer) and ori-verity (Rust chain). Every case must verify here
byte-for-byte; a divergence is a fleet-wide signature break, not a unit
test failure.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest

from ori.security.firmware_ingest import FirmwareTelemetryGate
from ori.security.firmware_telemetry import (
    FirmwareVerificationError,
    canonical_json_bytes,
    manifest_channel_map,
    verify_manifest_message,
    verify_telemetry_message,
)
from ori.state.store import StateStore

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "firmware_layer1_vectors.json").read_text()
)
PUBLIC_KEY_B64 = VECTORS["public_key_b64"]
CASES = {case["name"]: case for case in VECTORS["cases"]}

SEALED_DEVICE = "ori-fw-7c9f2b3a"
DEV_DEVICE = "ori-fw-dev00001"
SEALED_HASH = CASES["manifest_full_sealed"]["manifest_hash"]
DEV_HASH = CASES["manifest_minimal_dev"]["manifest_hash"]


def wire_signature(case: dict) -> str:
    return "ed25519:" + case["signature_b64"]


def telemetry_message(case_name: str) -> dict:
    case = CASES[case_name]
    return {"envelope": copy.deepcopy(case["input"]), "signature": wire_signature(case)}


def manifest_message(case_name: str) -> dict:
    case = CASES[case_name]
    return {
        "manifest": copy.deepcopy(case["input"]),
        "manifest_hash": "sha256:" + case["canonical_sha256_hex"],
        "signature": wire_signature(case),
    }


def verify(case_name: str, **overrides):
    case = CASES[case_name]
    envelope = case["input"]
    kwargs = {
        "anchor_device_id": envelope["device_id"],
        "anchor_public_key_b64": PUBLIC_KEY_B64,
        "anchor_posture": envelope["posture"],
        "accepted_manifest_hash": envelope["capability_hash"],
        "last_boot_id": 0,
        "last_seq": 0,
    }
    kwargs.update(overrides)
    return verify_telemetry_message(telemetry_message(case_name), **kwargs)


TELEMETRY_CASES = [name for name, case in CASES.items() if case["kind"] == "telemetry"]
MANIFEST_CASES = [name for name, case in CASES.items() if case["kind"] == "manifest"]


class TestGoldenVectors:
    @pytest.mark.parametrize("name", list(CASES))
    def test_canonical_bytes_match(self, name: str) -> None:
        case = CASES[name]
        assert canonical_json_bytes(case["input"]).hex() == case["canonical_hex"]
        assert (
            hashlib.sha256(bytes.fromhex(case["canonical_hex"])).hexdigest()
            == case["canonical_sha256_hex"]
        )

    @pytest.mark.parametrize("name", TELEMETRY_CASES)
    def test_every_telemetry_vector_verifies(self, name: str) -> None:
        result = verify(name)
        assert result.accepted, (name, result.error_code, result.error_detail)
        posture = CASES[name]["input"]["posture"]
        expected = (
            "attested"
            if posture in ("sealed_flash", "hardware_key")
            else "attested_dev"
        )
        assert result.grade == expected
        assert result.is_heartbeat == (len(CASES[name]["input"]["readings"]) == 0)

    @pytest.mark.parametrize("name", MANIFEST_CASES)
    def test_every_manifest_vector_verifies(self, name: str) -> None:
        manifest_hash = verify_manifest_message(
            manifest_message(name),
            anchor_device_id=CASES[name]["input"]["device_id"],
            anchor_public_key_b64=PUBLIC_KEY_B64,
        )
        assert manifest_hash == CASES[name]["manifest_hash"]

    def test_manifest_channel_map_is_derived_from_verified_manifest(self) -> None:
        channels = manifest_channel_map(CASES["manifest_full_sealed"]["input"])
        assert channels == {
            "ch0": {
                "sensor_type": "current",
                "unit": "ampere",
                "protocol": "adc",
                "source": "ads1115",
                "quality_floor": 0.8,
            },
            "ch1": {
                "sensor_type": "voltage",
                "unit": "volt",
                "protocol": "adc",
                "source": "ads1115",
                "quality_floor": 0.5,
            },
        }

    def test_manifest_rejects_unsupported_channel_protocol(self) -> None:
        message = manifest_message("manifest_full_sealed")
        message["manifest"]["channels"][0]["protocol"] = "zigbee"
        with pytest.raises(FirmwareVerificationError) as excinfo:
            verify_manifest_message(
                message,
                anchor_device_id=SEALED_DEVICE,
                anchor_public_key_b64=PUBLIC_KEY_B64,
            )
        assert excinfo.value.code == "unsupported_channel"

    def test_manifest_rejects_tier_authority_claim(self) -> None:
        message = manifest_message("manifest_full_sealed")
        message["manifest"]["actions"][0]["authority"] = "tier_d"
        with pytest.raises(FirmwareVerificationError) as excinfo:
            verify_manifest_message(
                message,
                anchor_device_id=SEALED_DEVICE,
                anchor_public_key_b64=PUBLIC_KEY_B64,
            )
        assert excinfo.value.code == "invalid_envelope"

    def test_tampered_envelope_rejected(self) -> None:
        message = telemetry_message("telemetry_single_reading")
        message["envelope"]["readings"][0]["value"] = 9.21
        result = verify_telemetry_message(
            message,
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
        )
        assert result.grade == "rejected"
        assert result.error_code == "signature_verification_failed"

    def test_tampered_manifest_rejected(self) -> None:
        message = manifest_message("manifest_full_sealed")
        message["manifest"]["device_mode"] = "sensor_node"
        with pytest.raises(FirmwareVerificationError) as excinfo:
            verify_manifest_message(
                message,
                anchor_device_id=SEALED_DEVICE,
                anchor_public_key_b64=PUBLIC_KEY_B64,
            )
        assert excinfo.value.code == "capability_hash_mismatch"


class TestFailClosed:
    def test_replayed_sequence_rejected(self) -> None:
        envelope = CASES["telemetry_single_reading"]["input"]
        result = verify("telemetry_single_reading", last_seq=envelope["seq"])
        assert result.error_code == "sequence_replay"
        result = verify("telemetry_single_reading", last_seq=envelope["seq"] - 1)
        assert result.accepted

    def test_boot_rollback_rejected(self) -> None:
        envelope = CASES["telemetry_single_reading"]["input"]
        result = verify(
            "telemetry_single_reading", last_boot_id=envelope["boot_id"] + 1
        )
        assert result.error_code == "boot_rollback"

    def test_capability_drift_rejected(self) -> None:
        result = verify("telemetry_single_reading", accepted_manifest_hash=DEV_HASH)
        assert result.error_code == "capability_hash_mismatch"

    def test_posture_mismatch_with_anchor_rejected(self) -> None:
        result = verify("telemetry_single_reading", anchor_posture="development")
        assert result.error_code == "invalid_posture"

    def test_wrong_public_key_rejected(self) -> None:
        other = base64.b64encode(bytes(32)).decode("ascii")
        result = verify("telemetry_single_reading", anchor_public_key_b64=other)
        assert result.error_code == "signature_verification_failed"

    def test_unapproved_and_revoked_rejected(self) -> None:
        assert verify("telemetry_single_reading", approved=False).error_code == (
            "device_not_approved"
        )
        assert (
            verify("telemetry_single_reading", revoked=True).error_code
            == "device_revoked"
        )

    def test_malformed_signature_encodings_rejected(self) -> None:
        good = telemetry_message("telemetry_single_reading")

        def with_signature(sig: str) -> str:
            message = copy.deepcopy(good)
            message["signature"] = sig
            return verify_telemetry_message(
                message,
                anchor_device_id=SEALED_DEVICE,
                anchor_public_key_b64=PUBLIC_KEY_B64,
                anchor_posture="sealed_flash",
                accepted_manifest_hash=SEALED_HASH,
                last_boot_id=0,
                last_seq=0,
            ).error_code

        bare = good["signature"][len("ed25519:") :]
        assert with_signature(bare) == "invalid_signature_format"
        assert with_signature("ecdsa:" + bare) == "invalid_signature_format"
        assert with_signature("ed25519:" + bare[:-4]) == "invalid_signature_format"
        url_safe = "ed25519:" + bare.replace("+", "-").replace("/", "_")
        if url_safe != good["signature"]:
            assert with_signature(url_safe) == "invalid_signature_format"

    def test_unsupported_alg_is_explicit(self) -> None:
        message = telemetry_message("telemetry_single_reading")
        message["envelope"]["alg"] = "ecdsa-p256"
        result = verify_telemetry_message(
            message,
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
        )
        assert result.error_code == "unsupported_alg"

    def test_extra_reading_fields_rejected(self) -> None:
        message = telemetry_message("telemetry_single_reading")
        message["envelope"]["readings"][0]["note"] = "extra"
        result = verify_telemetry_message(
            message,
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
        )
        assert result.error_code == "invalid_reading"

    def test_unmanifested_channel_rejected_after_signature_verifies(self) -> None:
        result = verify_telemetry_message(
            telemetry_message("telemetry_single_reading"),
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
            accepted_channels={
                "other": {
                    "sensor_type": "current",
                    "unit": "ampere",
                    "quality_floor": 0.0,
                }
            },
        )
        assert result.error_code == "unsupported_channel"

    def test_manifest_channel_type_or_unit_mismatch_rejected(self) -> None:
        result = verify_telemetry_message(
            telemetry_message("telemetry_single_reading"),
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
            accepted_channels={
                "ch0": {
                    "sensor_type": "voltage",
                    "unit": "volt",
                    "quality_floor": 0.0,
                }
            },
        )
        assert result.error_code == "invalid_reading"

    def test_quality_below_manifest_floor_rejected(self) -> None:
        result = verify_telemetry_message(
            telemetry_message("telemetry_float_edges"),
            anchor_device_id=DEV_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="development",
            accepted_manifest_hash=DEV_HASH,
            last_boot_id=0,
            last_seq=0,
            accepted_channels={
                "ch0": {
                    "sensor_type": "current",
                    "unit": "ampere",
                    "quality_floor": 0.8,
                }
            },
        )
        assert result.error_code == "invalid_reading"

    def test_out_of_zone_numbers_rejected(self) -> None:
        with pytest.raises(FirmwareVerificationError):
            canonical_json_bytes({"value": 1e16})
        with pytest.raises(FirmwareVerificationError):
            canonical_json_bytes({"value": 1.5e-7})
        canonical_json_bytes({"value": 0.0001})  # in-zone boundary is legal


@pytest.fixture
async def store(tmp_path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


@pytest.fixture
def gate(store):
    return FirmwareTelemetryGate(store)


async def provision_and_approve(gate: FirmwareTelemetryGate, manifest_case: str) -> str:
    manifest = CASES[manifest_case]["input"]
    manifest_hash = await gate.register_device(
        device_id=manifest["device_id"],
        public_key_b64=PUBLIC_KEY_B64,
        posture=manifest["posture"],
        manifest_message=manifest_message(manifest_case),
    )
    assert await gate.approve_device(manifest["device_id"])
    return manifest_hash


class TestFirmwareTelemetryGate:
    async def test_end_to_end_attested_reading(self, gate) -> None:
        await provision_and_approve(gate, "manifest_full_sealed")

        verification, readings = await gate.ingest(
            telemetry_message("telemetry_single_reading"), received_at_ms=1752537600000
        )
        assert verification.grade == "attested"
        assert len(readings) == 1
        reading = readings[0]
        assert reading.sensor_id == f"{SEALED_DEVICE}:ch0"
        assert reading.sensor_type == "current"
        assert reading.value == 8.21
        assert reading.unit == "ampere"
        # The runtime claims time; the device claims order and origin.
        assert reading.timestamp == 1752537600000
        assert reading.metadata["attestation"] == "attested"
        assert reading.metadata["posture"] == "sealed_flash"
        assert reading.metadata["boot_id"] == 41
        assert reading.metadata["seq"] == 130482
        assert reading.metadata["capability_hash"] == SEALED_HASH

    async def test_registry_persists_manifest_and_channel_map(
        self, gate, store
    ) -> None:
        await provision_and_approve(gate, "manifest_full_sealed")
        row = await store.get_firmware_device(SEALED_DEVICE)
        assert row["manifest"]["device_id"] == SEALED_DEVICE
        assert row["channel_map"]["ch0"]["sensor_type"] == "current"
        assert row["channel_map"]["ch0"]["unit"] == "ampere"

    async def test_approval_does_not_mutate_capability_hash(self, gate, store) -> None:
        manifest = CASES["manifest_full_sealed"]["input"]
        await gate.register_device(
            device_id=manifest["device_id"],
            public_key_b64=PUBLIC_KEY_B64,
            posture=manifest["posture"],
            manifest_message=manifest_message("manifest_full_sealed"),
        )
        before = await store.get_firmware_device(SEALED_DEVICE)
        assert before["approved"] is False
        assert before["capability_hash"] == SEALED_HASH
        assert await store.approve_firmware_device(SEALED_DEVICE)
        after = await store.get_firmware_device(SEALED_DEVICE)
        assert after["approved"] is True
        assert after["capability_hash"] == SEALED_HASH

    async def test_replay_rejected_after_acceptance(self, gate) -> None:
        await provision_and_approve(gate, "manifest_full_sealed")
        first, _ = await gate.ingest(telemetry_message("telemetry_single_reading"))
        assert first.accepted
        replayed, readings = await gate.ingest(
            telemetry_message("telemetry_single_reading")
        )
        assert replayed.grade == "rejected"
        assert replayed.error_code == "sequence_replay"
        assert readings == []

    async def test_heartbeat_advances_freshness_without_readings(
        self, gate, store
    ) -> None:
        await provision_and_approve(gate, "manifest_full_sealed")
        verification, readings = await gate.ingest(
            telemetry_message("telemetry_heartbeat_zero_readings")
        )
        assert verification.accepted
        assert verification.is_heartbeat
        assert readings == []
        row = await store.get_firmware_device(SEALED_DEVICE)
        assert (
            row["last_seq"]
            == CASES["telemetry_heartbeat_zero_readings"]["input"]["seq"]
        )

    async def test_gate_rejects_signed_reading_outside_manifest(self, gate) -> None:
        await provision_and_approve(gate, "manifest_minimal_dev")
        verification, readings = await gate.ingest(
            telemetry_message("telemetry_unicode_channel")
        )
        assert verification.grade == "rejected"
        assert verification.error_code == "unsupported_channel"
        assert readings == []

    async def test_unknown_device_rejected(self, gate) -> None:
        verification, readings = await gate.ingest(
            telemetry_message("telemetry_single_reading")
        )
        assert verification.grade == "rejected"
        assert verification.error_code == "anchor_missing"
        assert readings == []

    async def test_unapproved_device_rejected_until_approval(self, gate, store) -> None:
        manifest = CASES["manifest_full_sealed"]["input"]
        await gate.register_device(
            device_id=manifest["device_id"],
            public_key_b64=PUBLIC_KEY_B64,
            posture=manifest["posture"],
            manifest_message=manifest_message("manifest_full_sealed"),
        )
        verification, _ = await gate.ingest(
            telemetry_message("telemetry_single_reading")
        )
        assert verification.error_code == "device_not_approved"
        assert await gate.approve_device(SEALED_DEVICE)
        verification, _ = await gate.ingest(
            telemetry_message("telemetry_single_reading")
        )
        assert verification.accepted

    async def test_revoked_device_rejected(self, gate) -> None:
        await provision_and_approve(gate, "manifest_full_sealed")
        assert await gate.revoke_device(SEALED_DEVICE)
        verification, _ = await gate.ingest(
            telemetry_message("telemetry_single_reading")
        )
        assert verification.error_code == "device_revoked"

    async def test_ordered_ingest_across_boot_and_seq(self, gate) -> None:
        await provision_and_approve(gate, "manifest_full_sealed")
        first, _ = await gate.ingest(telemetry_message("telemetry_single_reading"))
        second, _ = await gate.ingest(telemetry_message("telemetry_multi_reading"))
        assert first.accepted and second.accepted
        # Same boot, older seq: a sequence replay.
        stale, _ = await gate.ingest(telemetry_message("telemetry_single_reading"))
        assert stale.error_code == "sequence_replay"
        third, _ = await gate.ingest(telemetry_message("telemetry_max_counters"))
        assert third.accepted
        # Older boot after a newer boot was accepted: a rollback signal.
        rolled, _ = await gate.ingest(telemetry_message("telemetry_multi_reading"))
        assert rolled.error_code == "boot_rollback"
