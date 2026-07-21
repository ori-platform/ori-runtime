# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Firmware telemetry verification against the shared golden vectors.

The vectors in tests/fixtures/firmware_layer1_vectors.json are the
cross-language signing contract shared with ori-edge-firmware (C
producer) and the private evidence-chain artifact. Every case must
verify here byte-for-byte; a divergence is a fleet-wide signature break,
not a unit test failure.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.security.firmware_ingest import FirmwareTelemetryGate
from ori.security.firmware_telemetry import (
    FAULT_TOKEN_MAX_LEN,
    FirmwareVerificationError,
    canonical_json_bytes,
    manifest_channel_map,
    verify_fault_message,
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


def signed_fault_message(
    *,
    seq: int = 130_486,
    code: str = "command_rejected",
    subject: str = "relay0",
    detail: str = "replayed",
) -> dict:
    """Build a real signed fault message with the shared test-only seed."""
    fault = {
        "v": 1,
        "alg": "ed25519",
        "device_id": SEALED_DEVICE,
        "boot_id": 41,
        "seq": seq,
        "capability_hash": SEALED_HASH,
        "posture": "sealed_flash",
        "device_uptime_ms": 925_000,
        "code": code,
        "subject": subject,
        "detail": detail,
    }
    private_key = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
    signature = private_key.sign(canonical_json_bytes(fault))
    return {
        "fault": fault,
        "signature": "ed25519:" + base64.b64encode(signature).decode("ascii"),
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

# Signed fault-event vectors, shared byte-for-byte with ori-edge-firmware
# (C producer) and ori-verity (Rust verifier). The runtime is the
# receiving end: these bytes and signatures are the contract it must
# accept, not a shape it gets to reinterpret.
FAULT_VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "firmware_fault_vectors.json").read_text()
)
FAULT_CASES = {case["name"]: case for case in FAULT_VECTORS["cases"]}

# The closed vocabulary of ori-specs/firmware-telemetry/v1.md. Additions
# are additive contract changes and land in all three repos together.
FAULT_CODE_VOCABULARY = {
    "brownout_relay_fault",
    "command_rejected",
    "ingress_degraded",
    "interlock_input_fault",
    "interlock_recovered",
    "interlock_tripped",
    "sensor_fault",
}


def golden_fault_message(case_name: str) -> dict:
    """The exact signed wire message the firmware publishes."""
    case = FAULT_CASES[case_name]
    return {"fault": copy.deepcopy(case["input"]), "signature": wire_signature(case)}


def signed_manifest_for_key(seed: bytes, *, device_id: str, **overrides) -> dict:
    """Build a manifest message genuinely signed by `seed`.

    Needed so a changed-key test presents a SELF-CONSISTENT manifest —
    exactly the attacker shape: someone signs a manifest with a key they
    control, claiming a device_id they do not own. A manifest signed by
    one key but presented with another is rejected at verification and
    never reaches the anchor lifecycle.
    """
    pub = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    manifest = {
        "v": 1,
        "alg": "ed25519",
        "device_id": device_id,
        "firmware_version": "0.1.0",
        "board_profile": "esp32s3-devkit",
        "device_mode": "sensor_node",
        "public_key_b64": pub,
        "posture": "development",
        "secure_boot_enabled": False,
        "flash_encryption_enabled": False,
        "key_storage": "dev_flash",
        "transports": ["mqtt"],
        "channels": [
            {
                "channel": "ch0",
                "sensor_type": "current",
                "unit": "ampere",
                "protocol": "adc",
                "source": "ads1115",
                "quality_floor": 0.8,
            }
        ],
        "actions": [],
        "interlocks": [],
    }
    manifest.update(overrides)
    canonical = canonical_json_bytes(manifest)
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(canonical)
    return {
        "manifest": manifest,
        "manifest_hash": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "signature": "ed25519:" + base64.b64encode(sig).decode("ascii"),
        "public_key_b64": pub,
    }


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


class TestGoldenFaultVectors:
    """The runtime's own verifier, run over the committed shared fault
    vectors. This is the receiving end of the cross-language loop: the C
    producer signs these bytes, ori-verity's ring verifier accepts them,
    and the ingestion gate must accept the identical bytes here."""

    @pytest.mark.parametrize("name", list(FAULT_CASES))
    def test_canonical_bytes_match(self, name: str) -> None:
        case = FAULT_CASES[name]
        assert canonical_json_bytes(case["input"]).hex() == case["canonical_hex"]
        assert (
            hashlib.sha256(bytes.fromhex(case["canonical_hex"])).hexdigest()
            == case["canonical_sha256_hex"]
        )

    @pytest.mark.parametrize("name", list(FAULT_CASES))
    def test_wire_message_matches(self, name: str) -> None:
        case = FAULT_CASES[name]
        message = (
            b'{"fault":'
            + bytes.fromhex(case["canonical_hex"])
            + b',"signature":"ed25519:'
            + case["signature_b64"].encode()
            + b'"}'
        )
        assert message.hex() == case["message_hex"]

    @pytest.mark.parametrize("name", list(FAULT_CASES))
    def test_golden_fault_verifies(self, name: str) -> None:
        fault = FAULT_CASES[name]["input"]
        result = verify_fault_message(
            golden_fault_message(name),
            anchor_device_id=fault["device_id"],
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture=fault["posture"],
            accepted_manifest_hash=fault["capability_hash"],
            last_boot_id=0,
            last_seq=0,
        )
        assert result.accepted, f"{name} was not accepted: {result.error_code}"
        # Posture drives the trust grade: a development-posture device
        # never earns the sealed-flash grade, even with a valid signature.
        expected_grade = (
            "attested" if fault["posture"] == "sealed_flash" else "attested_dev"
        )
        assert result.grade == expected_grade
        assert result.code == fault["code"]
        assert result.subject == fault["subject"]
        assert result.detail == fault["detail"]

    @pytest.mark.parametrize("name", list(FAULT_CASES))
    def test_tampered_golden_fault_rejected(self, name: str) -> None:
        fault = FAULT_CASES[name]["input"]
        message = golden_fault_message(name)
        message["fault"]["device_uptime_ms"] += 1
        result = verify_fault_message(
            message,
            anchor_device_id=fault["device_id"],
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture=fault["posture"],
            accepted_manifest_hash=fault["capability_hash"],
            last_boot_id=0,
            last_seq=0,
        )
        assert result.grade == "rejected"

    def test_vectors_cover_the_closed_vocabulary(self) -> None:
        covered = {case["input"]["code"] for case in FAULT_CASES.values()}
        assert covered == FAULT_CODE_VOCABULARY

    def test_fixture_metadata_is_self_consistent(self) -> None:
        # The fault corpus carries its own key metadata; the runtime must
        # verify against that, not against the telemetry corpus by luck.
        assert FAULT_VECTORS["contract"] == "ori-specs/firmware-telemetry/v1.md"
        assert FAULT_VECTORS["version"] == 1
        assert FAULT_VECTORS["public_key_b64"] == PUBLIC_KEY_B64
        names = [case["name"] for case in FAULT_VECTORS["cases"]]
        assert len(names) == len(set(names)), f"duplicate case names: {names}"

    def test_max_bound_vector_sits_exactly_on_the_limit(self) -> None:
        # The boundary the producer can actually emit: 63 characters.
        fault = FAULT_CASES["fault_max_bounds"]["input"]
        assert len(fault["subject"]) == FAULT_TOKEN_MAX_LEN
        assert len(fault["detail"]) == FAULT_TOKEN_MAX_LEN

    @pytest.mark.parametrize("field", ["subject", "detail"])
    def test_token_over_max_length_rejected(self, field: str) -> None:
        # A signed fault whose token exceeds what the producer's buffers
        # can hold is not a shape the firmware could have emitted; the
        # receiver must refuse it rather than accept a wider contract.
        result = verify_fault_message(
            signed_fault_message(**{field: "x" * (FAULT_TOKEN_MAX_LEN + 1)}),
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
        )
        assert result.grade == "rejected"
        assert result.error_code == "invalid_envelope"

    @pytest.mark.parametrize("field", ["subject", "detail"])
    @pytest.mark.parametrize("bad", ["relay/0", "bad token", "relay:0", "réf"])
    def test_token_outside_fleet_alphabet_rejected(self, field: str, bad: str) -> None:
        result = verify_fault_message(
            signed_fault_message(**{field: bad}),
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
        )
        assert result.grade == "rejected"
        assert result.error_code == "invalid_envelope"

    @pytest.mark.parametrize("field", ["subject", "detail"])
    def test_token_at_max_length_accepted(self, field: str) -> None:
        result = verify_fault_message(
            signed_fault_message(**{field: "x" * FAULT_TOKEN_MAX_LEN}),
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
        )
        assert result.accepted

    def test_golden_fault_never_becomes_telemetry(self) -> None:
        # A fault carries evidence about the device's own refusals; it
        # must never be readable as a SensorReading source.
        for name in FAULT_CASES:
            message = golden_fault_message(name)
            assert "envelope" not in message
            assert "readings" not in message["fault"]


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

    def test_signed_fault_event_verifies_without_becoming_telemetry(self) -> None:
        result = verify_fault_message(
            signed_fault_message(),
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
        )
        assert result.accepted
        assert result.grade == "attested"
        assert result.code == "command_rejected"
        assert result.subject == "relay0"
        assert result.detail == "replayed"

    def test_ingress_degraded_fault_verifies_with_each_detail(self) -> None:
        # firmware-telemetry/v1: ingress loss is never silent. Each
        # machine-readable detail token rides the same signed fault path.
        for i, detail in enumerate(
            ["inbound_overflow", "subscribe_failed", "anchor_persist_failed"]
        ):
            result = verify_fault_message(
                signed_fault_message(
                    seq=130_500 + i,
                    code="ingress_degraded",
                    subject="inbound",
                    detail=detail,
                ),
                anchor_device_id=SEALED_DEVICE,
                anchor_public_key_b64=PUBLIC_KEY_B64,
                anchor_posture="sealed_flash",
                accepted_manifest_hash=SEALED_HASH,
                last_boot_id=0,
                last_seq=0,
            )
            assert result.accepted
            assert result.code == "ingress_degraded"
            assert result.detail == detail

    def test_fault_event_rejects_unknown_code(self) -> None:
        result = verify_fault_message(
            signed_fault_message(code="made_up_fault"),
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
        )
        assert result.grade == "rejected"
        assert result.error_code == "invalid_envelope"


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

    async def test_signed_fault_is_recorded_and_consumes_freshness(
        self, gate, store
    ) -> None:
        await provision_and_approve(gate, "manifest_full_sealed")
        verification = await gate.ingest_fault(
            signed_fault_message(), received_at_ms=1_752_537_600_123
        )
        assert verification.accepted
        assert verification.code == "command_rejected"

        def _fault_rows(conn):
            return conn.execute(
                """
                SELECT device_id, boot_id, seq, code, subject, detail, received_at_ms
                FROM firmware_fault_events
                """
            ).fetchall()

        rows = [tuple(row) for row in await store._run_read(_fault_rows)]
        assert rows == [
            (
                SEALED_DEVICE,
                41,
                130_486,
                "command_rejected",
                "relay0",
                "replayed",
                1_752_537_600_123,
            )
        ]

        replayed, readings = await gate.ingest(
            telemetry_message("telemetry_single_reading")
        )
        assert replayed.error_code == "sequence_replay"
        assert readings == []


class TestRegistrationLifecycle:
    """ori-specs/device-provisioning/v1.md.

    Registration decides what a receiver will trust for everything
    afterwards, so it must never silently overwrite an anchor, clear a
    revocation, or re-open a replay window.
    """

    async def _register(self, gate, case="manifest_minimal_dev"):
        case_data = CASES[case]
        return await gate.register_device(
            device_id=case_data["input"]["device_id"],
            public_key_b64=PUBLIC_KEY_B64,
            posture=case_data["input"]["posture"],
            manifest_message=manifest_message(case),
        )

    @pytest.mark.asyncio
    async def test_exact_reregistration_is_idempotent(self, gate) -> None:
        await self._register(gate)
        await gate.approve_device(DEV_DEVICE)
        # Actually advance it, so a reset would be visible.
        await gate._store.advance_firmware_freshness(DEV_DEVICE, boot_id=3, seq=99)
        row_before = await gate._store.get_firmware_device(DEV_DEVICE)
        assert row_before["last_seq"] == 99

        await self._register(gate)  # identical anchor, again

        row_after = await gate._store.get_firmware_device(DEV_DEVICE)
        # Approval must survive: re-publishing a manifest is not an event.
        assert row_after["approved"] == row_before["approved"] == 1
        assert row_after["last_boot_id"] == row_before["last_boot_id"]
        assert row_after["last_seq"] == row_before["last_seq"]

    @pytest.mark.asyncio
    async def test_revocation_survives_registration(self, gate) -> None:
        await self._register(gate)
        await gate.approve_device(DEV_DEVICE)
        await gate.revoke_device(DEV_DEVICE)

        # The whole point: a device re-publishing its manifest is not a
        # decision to trust it again.
        with pytest.raises(FirmwareVerificationError) as excinfo:
            await self._register(gate)
        assert excinfo.value.code == "device_revoked"

        row = await gate._store.get_firmware_device(DEV_DEVICE)
        assert row["revoked"] == 1
        assert row["approved"] == 0

    @pytest.mark.asyncio
    async def test_changed_key_is_refused(self, gate) -> None:
        await self._register(gate)
        await gate.approve_device(DEV_DEVICE)

        # The attacker shape: a manifest SIGNED BY A KEY THEY CONTROL,
        # claiming a device_id they do not own. It is internally
        # consistent, so it passes verification — which is precisely why
        # the anchor lifecycle, not the signature check, must refuse it.
        attacker = signed_manifest_for_key(os.urandom(32), device_id=DEV_DEVICE)
        with pytest.raises(FirmwareVerificationError) as excinfo:
            await gate.register_device(
                device_id=DEV_DEVICE,
                public_key_b64=attacker["public_key_b64"],
                posture="development",
                manifest_message=attacker,
            )
        assert excinfo.value.code == "key_change_requires_reprovisioning"

        # The stored anchor is untouched.
        row = await gate._store.get_firmware_device(DEV_DEVICE)
        assert row["public_key_b64"] == PUBLIC_KEY_B64
        assert row["approved"] == 1

    @pytest.mark.asyncio
    async def test_manifest_change_fails_closed_for_now(self, gate) -> None:
        # The contract requires a same-key manifest change to become a
        # PENDING candidate beside the still-active anchor. That state
        # model is not implemented yet, so this refuses rather than
        # overwriting the active anchor — the behaviour the contract
        # forbids, and what this method used to do.
        await gate.register_device(
            device_id=SEALED_DEVICE,
            public_key_b64=PUBLIC_KEY_B64,
            posture="sealed_flash",
            manifest_message=manifest_message("manifest_full_sealed"),
        )
        await gate.approve_device(SEALED_DEVICE)
        await gate._store.advance_firmware_freshness(SEALED_DEVICE, boot_id=7, seq=1234)
        before = await gate._store.get_firmware_device(SEALED_DEVICE)

        with pytest.raises(FirmwareVerificationError) as excinfo:
            await gate.register_device(
                device_id=SEALED_DEVICE,
                public_key_b64=PUBLIC_KEY_B64,
                posture="sealed_flash",
                manifest_message=manifest_message("manifest_command_bench"),
            )
        assert excinfo.value.code == "manifest_epoch_unsupported"

        # Nothing moved: the active anchor, its approval, and the replay
        # window are all exactly as they were.
        after = await gate._store.get_firmware_device(SEALED_DEVICE)
        assert after["capability_hash"] == before["capability_hash"]
        assert after["approved"] == 1
        assert after["last_boot_id"] == 7
        assert after["last_seq"] == 1234
