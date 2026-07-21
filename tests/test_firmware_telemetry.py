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
# The fixed TEST-ONLY seed the shared vectors are signed with.
GOLDEN_SEED = bytes([0x42]) * 32
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

    @pytest.mark.parametrize("action", ["", "relay_toggle", "tier_d_cutoff"])
    def test_manifest_rejects_action_outside_closed_vocabulary(
        self, action: str
    ) -> None:
        message = manifest_message("manifest_full_sealed")
        message["manifest"]["actions"][0]["action"] = action
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
            signed_fault_message(
                code="sensor_fault", **{field: "x" * FAULT_TOKEN_MAX_LEN}
            ),
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

    @pytest.mark.parametrize(
        "detail",
        [
            "malformed",
            "wrong_device",
            "bad_signature",
            "replayed",
            "capability_mismatch",
            "unknown_action",
            "storage_failure",
        ],
    )
    def test_command_rejected_fault_accepts_closed_verdicts(self, detail: str) -> None:
        result = verify_fault_message(
            signed_fault_message(detail=detail),
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
        )
        assert result.accepted
        assert result.detail == detail

    @pytest.mark.parametrize("detail", ["", "invented_verdict"])
    def test_command_rejected_fault_rejects_unknown_verdict(self, detail: str) -> None:
        result = verify_fault_message(
            signed_fault_message(detail=detail),
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
        )
        assert result.error_code == "invalid_envelope"

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
    assert await gate.approve_device(
        manifest["device_id"], actor="test-operator", reason="test"
    )
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
        assert await store.approve_firmware_device(
            SEALED_DEVICE, actor="test-operator", reason="test"
        )
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
        assert await gate.approve_device(
            SEALED_DEVICE, actor="test-operator", reason="test"
        )
        verification, _ = await gate.ingest(
            telemetry_message("telemetry_single_reading")
        )
        assert verification.accepted

    async def test_revoked_device_rejected(self, gate) -> None:
        await provision_and_approve(gate, "manifest_full_sealed")
        assert await gate.revoke_device(
            SEALED_DEVICE, actor="test-operator", reason="test"
        )
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
        await gate.approve_device(DEV_DEVICE, actor="test-operator", reason="test")
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
        await gate.approve_device(DEV_DEVICE, actor="test-operator", reason="test")
        await gate.revoke_device(DEV_DEVICE, actor="test-operator", reason="test")

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
        await gate.approve_device(DEV_DEVICE, actor="test-operator", reason="test")

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
    async def test_manifest_change_becomes_a_pending_candidate(self, gate) -> None:
        # The contract: a same-key manifest change is a PENDING candidate
        # beside the still-active anchor. Overwriting the active anchor
        # would let a device replace its own accepted capability surface
        # by publishing, and would reset a replay window that never left
        # its key epoch.
        await gate.register_device(
            device_id=SEALED_DEVICE,
            public_key_b64=PUBLIC_KEY_B64,
            posture="sealed_flash",
            manifest_message=manifest_message("manifest_full_sealed"),
        )
        await gate.approve_device(SEALED_DEVICE, actor="test-operator", reason="test")
        await gate._store.advance_firmware_freshness(SEALED_DEVICE, boot_id=7, seq=1234)
        before = await gate._store.get_firmware_device(SEALED_DEVICE)

        await gate.register_device(
            device_id=SEALED_DEVICE,
            public_key_b64=PUBLIC_KEY_B64,
            posture="sealed_flash",
            manifest_message=manifest_message("manifest_command_bench"),
        )

        # The ACTIVE anchor is untouched: same capability hash, still
        # approved, replay window intact.
        after = await gate._store.get_firmware_device(SEALED_DEVICE)
        assert after["capability_hash"] == before["capability_hash"]
        assert after["approved"] == 1
        assert after["last_boot_id"] == 7
        assert after["last_seq"] == 1234
        # The key epoch never changed, so freshness had no reason to move.
        assert after["key_epoch_id"] == before["key_epoch_id"]

        # The new manifest is recorded as a pending candidate.
        pending = await gate._store.get_pending_firmware_anchor(SEALED_DEVICE)
        assert pending is not None
        assert pending["capability_hash"] != before["capability_hash"]
        assert pending["state"] == "pending"
        assert pending["key_epoch_id"] == before["key_epoch_id"]

    @pytest.mark.asyncio
    async def test_second_manifest_replaces_the_pending_candidate(self, gate) -> None:
        # A pending anchor grants nothing, so replacing one loses no
        # authority; refusing would strand a device whose earlier manifest
        # nobody promoted.
        await gate.register_device(
            device_id=SEALED_DEVICE,
            public_key_b64=PUBLIC_KEY_B64,
            posture="sealed_flash",
            manifest_message=manifest_message("manifest_full_sealed"),
        )
        await gate.approve_device(SEALED_DEVICE, actor="test-operator", reason="test")
        await gate.register_device(
            device_id=SEALED_DEVICE,
            public_key_b64=PUBLIC_KEY_B64,
            posture="sealed_flash",
            manifest_message=manifest_message("manifest_command_bench"),
        )
        first_pending = await gate._store.get_pending_firmware_anchor(SEALED_DEVICE)

        # A third manifest: same key, different hash again.
        third = signed_manifest_for_key(
            GOLDEN_SEED,
            device_id=SEALED_DEVICE,
            posture="sealed_flash",
            secure_boot_enabled=True,
            flash_encryption_enabled=True,
            key_storage="nvs_encrypted",
            firmware_version="9.9.9",
        )
        await gate.register_device(
            device_id=SEALED_DEVICE,
            public_key_b64=PUBLIC_KEY_B64,
            posture="sealed_flash",
            manifest_message=third,
        )

        now_pending = await gate._store.get_pending_firmware_anchor(SEALED_DEVICE)
        assert now_pending["anchor_epoch_id"] != first_pending["anchor_epoch_id"]

        # The replaced candidate is retained as discarded, never deleted:
        # it was never active, so no evidence is attributed to it.
        history = await gate._store.list_firmware_anchor_history(SEALED_DEVICE)
        discarded = [a for a in history if a["state"] == "discarded"]
        assert first_pending["anchor_epoch_id"] in {
            a["anchor_epoch_id"] for a in discarded
        }

    @pytest.mark.asyncio
    async def test_transitions_are_recorded(self, gate) -> None:
        await self._register(gate)
        transitions = await gate._store.list_firmware_anchor_transitions(DEV_DEVICE)
        assert [t["transition"] for t in transitions] == ["registered"]
        assert transitions[0]["to_epoch_id"].startswith("sha256:")
        assert transitions[0]["key_epoch_id"].startswith("sha256:")


class TestLifecycleMigration:
    """A database created before the lifecycle must not become invisible
    to it. The backfill derives epoch ids from what is already stored and
    records the anchor, so existing devices keep working."""

    @pytest.mark.asyncio
    async def test_preexisting_approved_device_backfills_as_active(
        self, tmp_path
    ) -> None:
        import sqlite3

        from ori.state.store import StateStore

        db = str(tmp_path / "legacy.db")
        # Build the pre-lifecycle shape: a registry row with no epoch ids
        # and no anchor history.
        store = StateStore(db_path=db)
        await store.open()
        await store.close()
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM firmware_device_anchors")
        conn.execute("DELETE FROM firmware_anchor_transitions")
        conn.execute(
            """
            INSERT INTO firmware_device_registry
                (device_id, public_key_b64, posture, capability_hash,
                 manifest_json, channel_map_json, board_profile, approved,
                 provisioned_at_ms, last_boot_id, last_seq, revoked,
                 revoked_at_ms, anchor_epoch_id, key_epoch_id)
            VALUES ('ori-fw-legacy01', ?, 'development', ?, '{}', '{}', '',
                    1, 1000, 5, 500, 0, NULL, '', '')
            """,
            (PUBLIC_KEY_B64, "sha256:" + "ab" * 32),
        )
        conn.commit()
        conn.close()

        # Reopening runs the migration.
        store = StateStore(db_path=db)
        await store.open()
        try:
            row = await store.get_firmware_device("ori-fw-legacy01")
            assert row["anchor_epoch_id"].startswith("sha256:")
            assert row["key_epoch_id"].startswith("sha256:")
            # Approval and freshness are preserved by the migration.
            assert row["approved"] is True
            assert row["last_seq"] == 500

            history = await store.list_firmware_anchor_history("ori-fw-legacy01")
            assert len(history) == 1
            assert history[0]["state"] == "active"
            assert history[0]["anchor_epoch_id"] == row["anchor_epoch_id"]

            transitions = await store.list_firmware_anchor_transitions(
                "ori-fw-legacy01"
            )
            assert transitions[0]["actor"] == "migration"
        finally:
            await store.close()

    @pytest.mark.asyncio
    async def test_preexisting_unapproved_device_backfills_as_pending(
        self, tmp_path
    ) -> None:
        import sqlite3

        from ori.state.store import StateStore

        db = str(tmp_path / "legacy2.db")
        store = StateStore(db_path=db)
        await store.open()
        await store.close()
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM firmware_device_anchors")
        conn.execute(
            """
            INSERT INTO firmware_device_registry
                (device_id, public_key_b64, posture, capability_hash,
                 manifest_json, channel_map_json, board_profile, approved,
                 provisioned_at_ms, last_boot_id, last_seq, revoked,
                 revoked_at_ms, anchor_epoch_id, key_epoch_id)
            VALUES ('ori-fw-legacy02', ?, 'development', ?, '{}', '{}', '',
                    0, 1000, 0, 0, 0, NULL, '', '')
            """,
            (PUBLIC_KEY_B64, "sha256:" + "cd" * 32),
        )
        conn.commit()
        conn.close()

        store = StateStore(db_path=db)
        await store.open()
        try:
            # Never approved, so never trusted for acceptance: pending.
            history = await store.list_firmware_anchor_history("ori-fw-legacy02")
            assert history[0]["state"] == "pending"

            # ...and never active, so no activation interval is invented.
            epoch = history[0]["anchor_epoch_id"]
            assert not await store.firmware_anchor_was_ever_active(
                "ori-fw-legacy02", epoch
            )
        finally:
            await store.close()

    async def _legacy_db(self, tmp_path, name, device_id, *, approved, revoked):
        """A pre-lifecycle registry row: no epoch ids, no anchor history."""
        import sqlite3

        from ori.state.store import StateStore

        db = str(tmp_path / name)
        store = StateStore(db_path=db)
        await store.open()
        await store.close()
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM firmware_device_anchors")
        conn.execute("DELETE FROM firmware_anchor_transitions")
        conn.execute(
            """
            INSERT INTO firmware_device_registry
                (device_id, public_key_b64, posture, capability_hash,
                 manifest_json, channel_map_json, board_profile, approved,
                 provisioned_at_ms, last_boot_id, last_seq, revoked,
                 revoked_at_ms, anchor_epoch_id, key_epoch_id)
            VALUES (?, ?, 'development', ?, '{}', '{}', '',
                    ?, 1000, 0, 0, ?, ?, '', '')
            """,
            (
                device_id,
                PUBLIC_KEY_B64,
                "sha256:" + "ef" * 32,
                1 if approved else 0,
                1 if revoked else 0,
                2000 if revoked else None,
            ),
        )
        conn.commit()
        conn.close()
        return db

    @pytest.mark.asyncio
    async def test_migrated_approved_device_is_still_ever_active(
        self, tmp_path
    ) -> None:
        """A device approved before the lifecycle existed WAS active.

        The migration is the only place that knows this: pre-lifecycle
        databases recorded no promotion, so without an inferred one the
        activation history would report the anchor as never active and
        evidence it legitimately authorised would read as unauthorised.
        """
        from ori.state.store import StateStore

        db = await self._legacy_db(
            tmp_path, "legacy3.db", "ori-fw-legacy03", approved=True, revoked=False
        )
        store = StateStore(db_path=db)
        await store.open()
        try:
            history = await store.list_firmware_anchor_history("ori-fw-legacy03")
            assert history[0]["state"] == "active"
            epoch = history[0]["anchor_epoch_id"]

            assert await store.firmware_anchor_was_ever_active("ori-fw-legacy03", epoch)
            intervals = await store.firmware_anchor_activation_intervals(
                "ori-fw-legacy03", epoch
            )
            assert len(intervals) == 1
            # Still active, so the interval is open.
            assert intervals[0]["deactivated_seq"] is None

            # It opens at the migration boundary, NOT at provisioned_at_ms
            # (1000). A device is often provisioned long before it is
            # approved, and starting there would vouch for evidence
            # produced in a window nobody can account for.
            boundary = intervals[0]["activated_at_ms"]
            assert boundary > 1000
            assert not await store.firmware_anchor_was_active_at(
                "ori-fw-legacy03", epoch, at_ms=1500
            )
            assert await store.firmware_anchor_was_active_at(
                "ori-fw-legacy03", epoch, at_ms=boundary + 1
            )

            # ...so the complete historical record is not provable, even
            # though the anchor is provably active now.
            assert not await store.firmware_activation_history_is_provable(
                "ori-fw-legacy03"
            )
        finally:
            await store.close()

    @pytest.mark.asyncio
    async def test_migrated_revoked_device_invents_no_activation(
        self, tmp_path
    ) -> None:
        """A revoked legacy row must not be credited with an activation.

        Revocation sets ``approved = 0``, so the stored shape is
        ``approved=0, revoked=1`` whether the identity was revoked after
        being promoted or before it was ever promoted. The two are
        indistinguishable in a pre-lifecycle database. Inventing a
        promotion would manufacture authorisation for an identity that may
        never have had any, so the migration records the history as
        unprovable and fails closed.
        """
        from ori.state.store import StateStore

        db = await self._legacy_db(
            tmp_path, "legacy4.db", "ori-fw-legacy04", approved=False, revoked=True
        )
        store = StateStore(db_path=db)
        await store.open()
        try:
            history = await store.list_firmware_anchor_history("ori-fw-legacy04")
            assert history[0]["state"] == "revoked"
            epoch = history[0]["anchor_epoch_id"]

            assert (
                await store.firmware_anchor_activation_intervals(
                    "ori-fw-legacy04", epoch
                )
                == []
            )
            assert not await store.firmware_anchor_was_ever_active(
                "ori-fw-legacy04", epoch
            )

            # ...but that emptiness means "cannot say", not "never active",
            # and a caller deciding authorisation must be able to tell.
            assert not await store.firmware_activation_history_is_provable(
                "ori-fw-legacy04"
            )
        finally:
            await store.close()

    async def _already_backfilled_db(self, tmp_path, name, device_id, *, state):
        """The state the FIRST lifecycle release's migration produced.

        Such a database already has an anchor row, so the pre-lifecycle
        backfill never revisits it -- which is exactly why the follow-up
        migration exists.
        """
        import sqlite3

        from ori.state.store import StateStore

        db = str(tmp_path / name)
        store = StateStore(db_path=db)
        await store.open()
        await store.close()

        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM firmware_device_anchors")
        conn.execute("DELETE FROM firmware_anchor_transitions")
        aid = "sha256:" + "11" * 32
        kid = "sha256:" + "22" * 32
        conn.execute(
            """
            INSERT INTO firmware_device_registry
                (device_id, public_key_b64, posture, capability_hash,
                 manifest_json, channel_map_json, board_profile, approved,
                 provisioned_at_ms, last_boot_id, last_seq, revoked,
                 revoked_at_ms, anchor_epoch_id, key_epoch_id)
            VALUES (?, ?, 'development', ?, '{}', '{}', '', ?, 1000, 0, 0,
                    ?, ?, ?, ?)
            """,
            (
                device_id,
                PUBLIC_KEY_B64,
                "sha256:" + "ef" * 32,
                1 if state == "active" else 0,
                1 if state == "revoked" else 0,
                2000 if state == "revoked" else None,
                aid,
                kid,
            ),
        )
        conn.execute(
            """
            INSERT INTO firmware_device_anchors
                (anchor_epoch_id, device_id, key_epoch_id, public_key_b64,
                 posture, capability_hash, manifest_json, channel_map_json,
                 board_profile, state, created_at_ms, state_changed_at_ms)
            VALUES (?, ?, ?, ?, 'development', ?, '{}', '{}', '', ?, 1000, 1000)
            """,
            (aid, device_id, kid, PUBLIC_KEY_B64, "sha256:" + "ef" * 32, state),
        )
        # The generic transition the earlier release wrote, and nothing else.
        conn.execute(
            """
            INSERT INTO firmware_anchor_transitions
                (device_id, transition, from_epoch_id, to_epoch_id,
                 key_epoch_id, actor, reason, occurred_at_ms)
            VALUES (?, 'registered', NULL, ?, ?, 'migration',
                    'backfilled from a pre-lifecycle registry row', 1000)
            """,
            (device_id, aid, kid),
        )
        conn.commit()
        conn.close()
        return db, aid

    @pytest.mark.asyncio
    async def test_already_backfilled_approved_row_gains_its_activation(
        self, tmp_path
    ) -> None:
        """An identity the first lifecycle release migrated is repaired.

        It already has an anchor row, so the pre-lifecycle backfill skips
        it, and without the follow-up migration an approved device would
        keep an activation history saying it was never active.
        """
        from ori.state.store import StateStore

        db, aid = await self._already_backfilled_db(
            tmp_path, "upgraded1.db", "ori-fw-upgraded01", state="active"
        )

        store = StateStore(db_path=db)
        await store.open()
        try:
            assert await store.firmware_anchor_was_ever_active("ori-fw-upgraded01", aid)
            intervals = await store.firmware_anchor_activation_intervals(
                "ori-fw-upgraded01", aid
            )
            assert len(intervals) == 1
            assert intervals[0]["deactivated_seq"] is None

            # The interval opens at the migration boundary, not at the
            # backfill's carried-over timestamp. Being approved proves the
            # anchor is active NOW; it says nothing about when it became
            # active, so the full record is not provable.
            assert intervals[0]["activated_at_ms"] > 1000
            assert not await store.firmware_activation_history_is_provable(
                "ori-fw-upgraded01"
            )

            # Evidence the receiver timed before the boundary fails closed;
            # evidence after it resolves.
            boundary = intervals[0]["activated_at_ms"]
            assert not await store.firmware_anchor_was_active_at(
                "ori-fw-upgraded01", aid, at_ms=boundary - 1
            )
            assert await store.firmware_anchor_was_active_at(
                "ori-fw-upgraded01", aid, at_ms=boundary + 1
            )
        finally:
            await store.close()

        # Reopening must not append a second inferred promotion.
        store = StateStore(db_path=db)
        await store.open()
        try:
            transitions = await store.list_firmware_anchor_transitions(
                "ori-fw-upgraded01"
            )
            assert [t["transition"] for t in transitions].count("promoted") == 1
            assert (
                len(
                    await store.firmware_anchor_activation_intervals(
                        "ori-fw-upgraded01", aid
                    )
                )
                == 1
            )
        finally:
            await store.close()

    @pytest.mark.asyncio
    async def test_already_backfilled_revoked_row_stays_explicitly_unknown(
        self, tmp_path
    ) -> None:
        """A revoked identity migrated by the earlier release stays unknown.

        Its stored shape cannot say whether it was ever promoted, so the
        follow-up migration marks it rather than inventing an activation.
        """
        from ori.state.store import StateStore

        db, aid = await self._already_backfilled_db(
            tmp_path, "upgraded2.db", "ori-fw-upgraded02", state="revoked"
        )

        store = StateStore(db_path=db)
        await store.open()
        try:
            assert not await store.firmware_anchor_was_ever_active(
                "ori-fw-upgraded02", aid
            )
            assert not await store.firmware_activation_history_is_provable(
                "ori-fw-upgraded02"
            )
        finally:
            await store.close()

        # Reopening must not append a second marker.
        store = StateStore(db_path=db)
        await store.open()
        try:
            transitions = await store.list_firmware_anchor_transitions(
                "ori-fw-upgraded02"
            )
            markers = [
                t for t in transitions if "cannot be reconstructed" in t["reason"]
            ]
            assert len(markers) == 1
            assert not await store.firmware_activation_history_is_provable(
                "ori-fw-upgraded02"
            )
        finally:
            await store.close()

    @pytest.mark.asyncio
    async def test_re_promotion_does_not_make_pre_migration_history_provable(
        self, tmp_path
    ) -> None:
        """A later real promotion says nothing about the earlier interval.

        Sequence: active before the lifecycle existed, backfilled by the
        first release, then revoked, reinstated and promoted again -- all
        before this repair runs. The anchor now has a genuine `promoted`
        transition, but when it was active *before* the migration was
        never recorded, so the history must stay unprovable rather than
        being credited by the later promotion.
        """
        import sqlite3

        from ori.state.store import StateStore

        db, aid = await self._already_backfilled_db(
            tmp_path, "upgraded3.db", "ori-fw-upgraded03", state="active"
        )

        # Post-backfill lifecycle activity, written directly so it lands
        # before the repair ever sees the database.
        conn = sqlite3.connect(db)
        for transition, frm, to in (
            ("revoked", aid, None),
            ("reinstated", aid, aid),
            ("promoted", None, aid),
        ):
            conn.execute(
                """
                INSERT INTO firmware_anchor_transitions
                    (device_id, transition, from_epoch_id, to_epoch_id,
                     key_epoch_id, actor, reason, occurred_at_ms)
                VALUES ('ori-fw-upgraded03', ?, ?, ?, ?, 'op', 'r', 3000)
                """,
                (transition, frm, to, "sha256:" + "22" * 32),
            )
        conn.execute(
            "UPDATE firmware_device_anchors SET state = 'active' "
            "WHERE anchor_epoch_id = ?",
            (aid,),
        )
        conn.commit()
        conn.close()

        store = StateStore(db_path=db)
        await store.open()
        try:
            # The recorded re-promotion is real, so there IS an interval.
            assert await store.firmware_anchor_was_ever_active("ori-fw-upgraded03", aid)
            # ...but the pre-migration interval was never recorded, so the
            # complete record is not provable.
            assert not await store.firmware_activation_history_is_provable(
                "ori-fw-upgraded03"
            )
        finally:
            await store.close()

    @pytest.mark.asyncio
    async def test_backfilled_pending_row_promoted_later_is_provable(
        self, tmp_path
    ) -> None:
        """The other side of the same distinction.

        An anchor the earlier release backfilled as `pending` was never
        approved before the lifecycle, so a promotion after the upgrade is
        its genuine first activation and the history is complete.
        """
        import sqlite3

        from ori.state.store import StateStore

        db, aid = await self._already_backfilled_db(
            tmp_path, "upgraded4.db", "ori-fw-upgraded04", state="pending"
        )

        conn = sqlite3.connect(db)
        conn.execute(
            """
            INSERT INTO firmware_anchor_transitions
                (device_id, transition, from_epoch_id, to_epoch_id,
                 key_epoch_id, actor, reason, occurred_at_ms)
            VALUES ('ori-fw-upgraded04', 'promoted', NULL, ?, ?, 'op', 'r', 3000)
            """,
            (aid, "sha256:" + "22" * 32),
        )
        conn.execute(
            "UPDATE firmware_device_anchors SET state = 'active' "
            "WHERE anchor_epoch_id = ?",
            (aid,),
        )
        conn.commit()
        conn.close()

        store = StateStore(db_path=db)
        await store.open()
        try:
            assert await store.firmware_anchor_was_ever_active("ori-fw-upgraded04", aid)
            assert await store.firmware_activation_history_is_provable(
                "ori-fw-upgraded04"
            )
        finally:
            await store.close()

    @pytest.mark.asyncio
    async def test_backfilled_pending_row_later_discarded_stays_provable(
        self, tmp_path
    ) -> None:
        """Being discarded proves an anchor was pending, never active.

        Only a pending candidate is ever discarded, so a backfilled anchor
        whose first subsequent transition discards it is provably never
        active. Marking it "cannot say" would throw away a fact the log
        does establish, and fail closed where failing closed is not
        warranted.
        """
        import sqlite3

        from ori.state.store import StateStore

        db, aid = await self._already_backfilled_db(
            tmp_path, "upgraded5.db", "ori-fw-upgraded05", state="pending"
        )

        other = "sha256:" + "33" * 32
        conn = sqlite3.connect(db)
        conn.execute(
            """
            INSERT INTO firmware_anchor_transitions
                (device_id, transition, from_epoch_id, to_epoch_id,
                 key_epoch_id, actor, reason, occurred_at_ms)
            VALUES ('ori-fw-upgraded05', 'discarded', ?, ?, ?, '', '', 3000)
            """,
            (aid, other, "sha256:" + "22" * 32),
        )
        conn.execute(
            "UPDATE firmware_device_anchors SET state = 'discarded' "
            "WHERE anchor_epoch_id = ?",
            (aid,),
        )
        conn.commit()
        conn.close()

        store = StateStore(db_path=db)
        await store.open()
        try:
            assert not await store.firmware_anchor_was_ever_active(
                "ori-fw-upgraded05", aid
            )
            # Provably never active, so the history is complete.
            assert await store.firmware_activation_history_is_provable(
                "ori-fw-upgraded05"
            )
        finally:
            await store.close()

    @pytest.mark.asyncio
    async def test_activation_history_is_not_provable_for_an_unknown_device(
        self, tmp_path
    ) -> None:
        """Absence of a marker is not evidence when there are no records."""
        from ori.state.store import StateStore

        store = StateStore(db_path=str(tmp_path / "empty.db"))
        await store.open()
        try:
            assert not await store.firmware_activation_history_is_provable(
                "ori-fw-does-not-exist"
            )
        finally:
            await store.close()

    @pytest.mark.asyncio
    async def test_migration_marks_the_inferred_promotion_as_inferred(
        self, tmp_path
    ) -> None:
        """The inferred promotion must not read as a recorded operator act.

        Pre-lifecycle databases never stored when a promotion happened, so
        it is reconstructed from the registry's flags. An operator reading
        the audit trail has to be able to tell.
        """
        from ori.state.store import StateStore

        db = await self._legacy_db(
            tmp_path, "legacy5.db", "ori-fw-legacy05", approved=True, revoked=False
        )
        store = StateStore(db_path=db)
        await store.open()
        try:
            transitions = await store.list_firmware_anchor_transitions(
                "ori-fw-legacy05"
            )
            promoted = [t for t in transitions if t["transition"] == "promoted"]
            assert len(promoted) == 1
            assert promoted[0]["actor"] == "migration"
            assert "never recorded" in promoted[0]["reason"]
            assert "unknown" in promoted[0]["reason"]

            # Active now, but when it became active was never recorded, so
            # the complete record is not provable.
            assert not await store.firmware_activation_history_is_provable(
                "ori-fw-legacy05"
            )
        finally:
            await store.close()


class TestAnchorStateInvariant:
    """ "Two active anchors" is a state no amount of careful calling code
    should be trusted to prevent, so the database enforces it."""

    @pytest.mark.asyncio
    async def test_database_refuses_a_second_active_or_pending(self, tmp_path) -> None:
        import sqlite3

        from ori.state.store import StateStore

        db = str(tmp_path / "inv.db")
        store = StateStore(db_path=db)
        await store.open()
        await store.close()

        conn = sqlite3.connect(db)

        def insert(epoch_id: str, state: str, device: str = "d1") -> None:
            conn.execute(
                """
                INSERT INTO firmware_device_anchors
                    (anchor_epoch_id, device_id, key_epoch_id, public_key_b64,
                     posture, capability_hash, state, created_at_ms,
                     state_changed_at_ms)
                VALUES (?, ?, 'k', 'p', 'development', 'h', ?, 1, 1)
                """,
                (epoch_id, device, state),
            )

        insert("a1", "active")
        insert("p1", "pending")
        conn.commit()

        for epoch_id, state in (("a2", "active"), ("p2", "pending")):
            with pytest.raises(sqlite3.IntegrityError):
                insert(epoch_id, state)
                conn.commit()
            conn.rollback()

        # History is append-only, so these repeat freely.
        insert("s1", "superseded")
        insert("s2", "superseded")
        insert("x1", "discarded")
        # A different identity is unaffected.
        insert("b1", "active", device="d2")
        conn.commit()
        conn.close()


class TestRegistryAndHistoryAgree:
    """The legacy registry and the anchor history must never disagree
    about which anchor is trusted. Each test here is a path where they
    previously could."""

    async def _register(self, gate, case):
        c = CASES[case]
        return await gate.register_device(
            device_id=c["input"]["device_id"],
            public_key_b64=PUBLIC_KEY_B64,
            posture=c["input"]["posture"],
            manifest_message=manifest_message(case),
        )

    @pytest.mark.asyncio
    async def test_approval_promotes_the_anchor(self, gate) -> None:
        await self._register(gate, "manifest_minimal_dev")
        history = await gate._store.list_firmware_anchor_history(DEV_DEVICE)
        assert history[0]["state"] == "pending"

        await gate.approve_device(DEV_DEVICE, actor="test-operator", reason="test")

        # Approval is promotion: history says active, and the registry
        # points at the same anchor. Accepting telemetry while history
        # still said "pending" was the split-brain.
        history = await gate._store.list_firmware_anchor_history(DEV_DEVICE)
        active = [a for a in history if a["state"] == "active"]
        assert len(active) == 1
        row = await gate._store.get_firmware_device(DEV_DEVICE)
        assert row["approved"] is True
        assert row["anchor_epoch_id"] == active[0]["anchor_epoch_id"]

        transitions = await gate._store.list_firmware_anchor_transitions(DEV_DEVICE)
        assert [t["transition"] for t in transitions] == ["registered", "promoted"]

    @pytest.mark.asyncio
    async def test_promoting_a_manifest_epoch_supersedes_the_previous(
        self, gate
    ) -> None:
        await self._register(gate, "manifest_full_sealed")
        await gate.approve_device(SEALED_DEVICE, actor="test-operator", reason="test")
        first = await gate._store.get_firmware_device(SEALED_DEVICE)

        await self._register(gate, "manifest_command_bench")
        await gate.approve_device(SEALED_DEVICE, actor="test-operator", reason="test")

        history = await gate._store.list_firmware_anchor_history(SEALED_DEVICE)
        states = {a["anchor_epoch_id"]: a["state"] for a in history}
        assert states[first["anchor_epoch_id"]] == "superseded"
        row = await gate._store.get_firmware_device(SEALED_DEVICE)
        assert states[row["anchor_epoch_id"]] == "active"
        # The superseded anchor is retained, never deleted: evidence
        # outlives the anchor that authorised it.
        assert first["anchor_epoch_id"] in states

    @pytest.mark.asyncio
    async def test_revocation_moves_the_anchor_and_discards_pending(self, gate) -> None:
        await self._register(gate, "manifest_full_sealed")
        await gate.approve_device(SEALED_DEVICE, actor="test-operator", reason="test")
        active_id = (await gate._store.get_firmware_device(SEALED_DEVICE))[
            "anchor_epoch_id"
        ]
        await self._register(gate, "manifest_command_bench")
        pending_id = (await gate._store.get_pending_firmware_anchor(SEALED_DEVICE))[
            "anchor_epoch_id"
        ]

        await gate.revoke_device(SEALED_DEVICE, actor="test-operator", reason="test")

        history = await gate._store.list_firmware_anchor_history(SEALED_DEVICE)
        states = {a["anchor_epoch_id"]: a["state"] for a in history}
        # Retained so reinstatement has something to return to.
        assert states[active_id] == "revoked"
        # An unpromoted candidate must not survive a revocation and
        # become promotable later.
        assert states[pending_id] == "discarded"
        assert await gate._store.get_pending_firmware_anchor(SEALED_DEVICE) is None

        transitions = await gate._store.list_firmware_anchor_transitions(SEALED_DEVICE)
        assert transitions[-1]["transition"] == "revoked"

    @pytest.mark.asyncio
    async def test_promotion_after_revocation_is_refused(self, gate) -> None:
        await self._register(gate, "manifest_minimal_dev")
        await gate.approve_device(DEV_DEVICE, actor="test-operator", reason="test")
        await gate.revoke_device(DEV_DEVICE, actor="test-operator", reason="test")
        # Nothing pending, identity revoked: there is nothing to promote
        # and promotion must not invent an anchor.
        assert (
            await gate.approve_device(DEV_DEVICE, actor="test-operator", reason="test")
            is False
        )

    @pytest.mark.asyncio
    async def test_registry_never_points_at_a_discarded_anchor(self, gate) -> None:
        # Pending A, then manifest B: A is discarded and B becomes the
        # candidate. The registry must follow B — previously it still
        # described A, so promotion would have activated the wrong
        # manifest.
        await self._register(gate, "manifest_full_sealed")
        first_pending = await gate._store.get_pending_firmware_anchor(SEALED_DEVICE)

        await self._register(gate, "manifest_command_bench")
        row = await gate._store.get_firmware_device(SEALED_DEVICE)
        second_pending = await gate._store.get_pending_firmware_anchor(SEALED_DEVICE)

        assert second_pending["anchor_epoch_id"] != first_pending["anchor_epoch_id"]
        assert row["capability_hash"] == second_pending["capability_hash"]

        await gate.approve_device(SEALED_DEVICE, actor="test-operator", reason="test")
        promoted = await gate._store.get_firmware_device(SEALED_DEVICE)
        assert promoted["anchor_epoch_id"] == second_pending["anchor_epoch_id"]

    @pytest.mark.asyncio
    async def test_republishing_a_discarded_anchor_is_not_unchanged(self, gate) -> None:
        # "unchanged" must be decided from the live anchor, not from the
        # registry pointer: a discarded anchor re-published is a new
        # candidate, not a no-op.
        await self._register(gate, "manifest_full_sealed")
        first = await gate._store.get_pending_firmware_anchor(SEALED_DEVICE)
        await self._register(gate, "manifest_command_bench")
        await self._register(gate, "manifest_full_sealed")

        now_pending = await gate._store.get_pending_firmware_anchor(SEALED_DEVICE)
        assert now_pending["anchor_epoch_id"] == first["anchor_epoch_id"]
        assert now_pending["state"] == "pending"


class TestRevokedLegacyMigration:
    @pytest.mark.asyncio
    async def test_revoked_legacy_row_does_not_become_promotable(
        self, tmp_path
    ) -> None:
        """A revoked legacy identity must not acquire a pending anchor:
        that would hand it a promotable candidate it never earned."""
        import sqlite3

        from ori.state.store import StateStore

        db = str(tmp_path / "legacy_revoked.db")
        store = StateStore(db_path=db)
        await store.open()
        await store.close()
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM firmware_device_anchors")
        conn.execute(
            """
            INSERT INTO firmware_device_registry
                (device_id, public_key_b64, posture, capability_hash,
                 manifest_json, channel_map_json, board_profile, approved,
                 provisioned_at_ms, last_boot_id, last_seq, revoked,
                 revoked_at_ms, anchor_epoch_id, key_epoch_id)
            VALUES ('ori-fw-legacy03', ?, 'development', ?, '{}', '{}', '',
                    0, 1000, 0, 0, 1, 2000, '', '')
            """,
            (PUBLIC_KEY_B64, "sha256:" + "ef" * 32),
        )
        conn.commit()
        conn.close()

        store = StateStore(db_path=db)
        await store.open()
        try:
            history = await store.list_firmware_anchor_history("ori-fw-legacy03")
            assert history[0]["state"] == "revoked"
            # Nothing promotable exists.
            assert await store.get_pending_firmware_anchor("ori-fw-legacy03") is None
            assert (
                await store.approve_firmware_device(
                    "ori-fw-legacy03", actor="test-operator", reason="test"
                )
                is False
            )
        finally:
            await store.close()


class TestTrustTransitionsAreAttributed:
    """ori-specs/device-provisioning/v1.md requires actor and reason on
    every operator decision that changes acceptance. An unattributed
    anchor change is indistinguishable from a compromise after the fact,
    so it must be impossible rather than merely discouraged."""

    async def _registered(self, gate):
        c = CASES["manifest_minimal_dev"]
        await gate.register_device(
            device_id=DEV_DEVICE,
            public_key_b64=PUBLIC_KEY_B64,
            posture=c["input"]["posture"],
            manifest_message=manifest_message("manifest_minimal_dev"),
        )

    @pytest.mark.asyncio
    async def test_promotion_requires_actor_and_reason(self, gate) -> None:
        await self._registered(gate)
        for actor, reason in (("", "why"), ("op", ""), ("  ", "why"), ("op", "  ")):
            with pytest.raises(ValueError, match="audited"):
                await gate.approve_device(DEV_DEVICE, actor=actor, reason=reason)
        # Nothing moved: the refusal happens before any state changes.
        history = await gate._store.list_firmware_anchor_history(DEV_DEVICE)
        assert history[0]["state"] == "pending"

    @pytest.mark.asyncio
    async def test_revocation_requires_actor_and_reason(self, gate) -> None:
        await self._registered(gate)
        await gate.approve_device(DEV_DEVICE, actor="op", reason="bench")
        with pytest.raises(ValueError, match="audited"):
            await gate.revoke_device(DEV_DEVICE, actor="", reason="compromised")
        row = await gate._store.get_firmware_device(DEV_DEVICE)
        assert row["revoked"] is False

    @pytest.mark.asyncio
    async def test_attribution_is_recorded(self, gate) -> None:
        await self._registered(gate)
        await gate.approve_device(
            DEV_DEVICE, actor="alice@ops", reason="bench bring-up"
        )
        transitions = await gate._store.list_firmware_anchor_transitions(DEV_DEVICE)
        promoted = [t for t in transitions if t["transition"] == "promoted"][0]
        assert promoted["actor"] == "alice@ops"
        assert promoted["reason"] == "bench bring-up"

    @pytest.mark.asyncio
    async def test_database_refuses_an_unattributed_trust_transition(
        self, tmp_path
    ) -> None:
        # Belt and braces: even a direct INSERT cannot write one.
        import sqlite3

        from ori.state.store import StateStore

        db = str(tmp_path / "audit.db")
        store = StateStore(db_path=db)
        await store.open()
        await store.close()
        conn = sqlite3.connect(db)

        def insert(transition: str, actor: str, reason: str) -> None:
            conn.execute(
                """
                INSERT INTO firmware_anchor_transitions
                    (device_id, transition, key_epoch_id, actor, reason,
                     occurred_at_ms)
                VALUES ('d1', ?, 'k', ?, ?, 1)
                """,
                (transition, actor, reason),
            )

        for transition in ("promoted", "revoked", "reinstated", "reprovisioned"):
            with pytest.raises(sqlite3.IntegrityError):
                insert(transition, "", "")
                conn.commit()
            conn.rollback()

        # Whitespace is attribution in form only: `actor <> \'\'` would
        # have accepted it.
        for transition in ("promoted", "revoked"):
            with pytest.raises(sqlite3.IntegrityError):
                insert(transition, "   ", "   ")
                conn.commit()
            conn.rollback()

        # Device-initiated events grant nothing, so they may be unattributed.
        insert("registered", "", "")
        insert("discarded", "", "")
        conn.commit()
        conn.close()


class TestLifecycleSequences:
    """The three recovery sequences ori-specs/device-provisioning/v1.md
    requires. Each was unexecutable before these operations existed."""

    async def _registered_and_active(self, gate, case="manifest_minimal_dev"):
        c = CASES[case]
        await gate.register_device(
            device_id=c["input"]["device_id"],
            public_key_b64=PUBLIC_KEY_B64,
            posture=c["input"]["posture"],
            manifest_message=manifest_message(case),
        )
        await gate.approve_device(c["input"]["device_id"], actor="op", reason="initial")

    @pytest.mark.asyncio
    async def test_revoked_key_unchanged__reinstate_then_promote(self, gate) -> None:
        await self._registered_and_active(gate)
        await gate.revoke_device(DEV_DEVICE, actor="op", reason="suspected")
        original = (await gate._store.list_firmware_anchor_history(DEV_DEVICE))[0]

        assert await gate.reinstate_device(
            DEV_DEVICE, actor="op", reason="cleared investigation"
        )
        # Reinstatement activates NOTHING: the anchor is pending.
        row = await gate._store.get_firmware_device(DEV_DEVICE)
        assert row["revoked"] is False
        assert row["approved"] is False
        pending = await gate._store.get_pending_firmware_anchor(DEV_DEVICE)
        assert pending["anchor_epoch_id"] == original["anchor_epoch_id"]

        assert await gate.approve_device(DEV_DEVICE, actor="op", reason="back")
        row = await gate._store.get_firmware_device(DEV_DEVICE)
        assert row["approved"] is True

        names = [
            t["transition"]
            for t in await gate._store.list_firmware_anchor_transitions(DEV_DEVICE)
        ]
        assert names == ["registered", "promoted", "revoked", "reinstated", "promoted"]

    @pytest.mark.asyncio
    async def test_revoked_and_key_changed__all_three_operations(self, gate) -> None:
        await self._registered_and_active(gate)
        # Give the device a command-sequence history to protect.
        assert await gate._store.allocate_firmware_command_seq(DEV_DEVICE) == 1
        assert await gate._store.allocate_firmware_command_seq(DEV_DEVICE) == 2
        await gate._store.advance_firmware_freshness(DEV_DEVICE, boot_id=4, seq=900)
        await gate.revoke_device(DEV_DEVICE, actor="op", reason="key compromised")

        # Re-provisioning a revoked identity is refused: reinstate first,
        # or the device returns to service without anyone saying so.
        new_seed = os.urandom(32)
        new_manifest = signed_manifest_for_key(new_seed, device_id=DEV_DEVICE)
        with pytest.raises(FirmwareVerificationError):
            await gate.reprovision_device(
                device_id=DEV_DEVICE,
                public_key_b64=new_manifest["public_key_b64"],
                posture="development",
                manifest_message=new_manifest,
                actor="op",
                reason="new key",
            )

        assert await gate.reinstate_device(DEV_DEVICE, actor="op", reason="rebuild")
        await gate.reprovision_device(
            device_id=DEV_DEVICE,
            public_key_b64=new_manifest["public_key_b64"],
            posture="development",
            manifest_message=new_manifest,
            actor="op",
            reason="nvs erased, device re-keyed",
        )
        # Still not active: the new key is pending.
        row = await gate._store.get_firmware_device(DEV_DEVICE)
        assert row["public_key_b64"] == PUBLIC_KEY_B64

        assert await gate.approve_device(DEV_DEVICE, actor="op", reason="confirmed")
        row = await gate._store.get_firmware_device(DEV_DEVICE)
        assert row["public_key_b64"] == new_manifest["public_key_b64"]

        # A re-keyed device restarts its counters, so the new key epoch
        # starts a fresh replay window rather than refusing it.
        assert row["last_boot_id"] == 0
        assert row["last_seq"] == 0
        # But cmd_seq is per DEVICE, not per key, and must continue.
        assert await gate._store.allocate_firmware_command_seq(DEV_DEVICE) == 3

        names = [
            t["transition"]
            for t in await gate._store.list_firmware_anchor_transitions(DEV_DEVICE)
        ]
        assert names == [
            "registered",
            "promoted",
            "revoked",
            "reinstated",
            "reprovisioned",
            "promoted",
        ]

    @pytest.mark.asyncio
    async def test_manifest_promotion_does_not_reset_freshness(self, gate) -> None:
        # The contrast with the key-change case above: same key, so the
        # replay window must NOT re-open.
        await self._registered_and_active(gate, "manifest_full_sealed")
        await gate._store.advance_firmware_freshness(SEALED_DEVICE, boot_id=4, seq=900)
        await gate.register_device(
            device_id=SEALED_DEVICE,
            public_key_b64=PUBLIC_KEY_B64,
            posture="sealed_flash",
            manifest_message=manifest_message("manifest_command_bench"),
        )
        await gate.approve_device(SEALED_DEVICE, actor="op", reason="new manifest")
        row = await gate._store.get_firmware_device(SEALED_DEVICE)
        assert row["last_boot_id"] == 4
        assert row["last_seq"] == 900

    @pytest.mark.asyncio
    async def test_reinstating_a_live_identity_is_refused(self, gate) -> None:
        await self._registered_and_active(gate)
        # Clearing a flag that is not set would write an audit row
        # describing an event that did not happen.
        assert await gate.reinstate_device(DEV_DEVICE, actor="op", reason="x") is False

    @pytest.mark.asyncio
    async def test_operations_require_attribution(self, gate) -> None:
        await self._registered_and_active(gate)
        await gate.revoke_device(DEV_DEVICE, actor="op", reason="r")
        with pytest.raises(ValueError, match="audited"):
            await gate.reinstate_device(DEV_DEVICE, actor="", reason="r")
        with pytest.raises(ValueError, match="audited"):
            await gate.reinstate_device(DEV_DEVICE, actor="op", reason="  ")


class TestReprovisioningMustActuallyRotate:
    """Re-provisioning REPLACES a key. Submitting the current one changes
    nothing, and it previously overwrote the active anchor row with a
    pending one while the registry still said approved."""

    async def _active(self, gate):
        c = CASES["manifest_minimal_dev"]
        await gate.register_device(
            device_id=DEV_DEVICE,
            public_key_b64=PUBLIC_KEY_B64,
            posture=c["input"]["posture"],
            manifest_message=manifest_message("manifest_minimal_dev"),
        )
        await gate.approve_device(DEV_DEVICE, actor="op", reason="init")

    @pytest.mark.asyncio
    async def test_same_key_is_refused_and_changes_nothing(self, gate) -> None:
        await self._active(gate)
        before = await gate._store.get_firmware_device(DEV_DEVICE)
        history_before = await gate._store.list_firmware_anchor_history(DEV_DEVICE)
        audit_before = await gate._store.list_firmware_anchor_transitions(DEV_DEVICE)

        with pytest.raises(FirmwareVerificationError) as excinfo:
            await gate.reprovision_device(
                device_id=DEV_DEVICE,
                public_key_b64=PUBLIC_KEY_B64,
                posture="development",
                manifest_message=manifest_message("manifest_minimal_dev"),
                actor="op",
                reason="same key",
            )
        assert excinfo.value.code == "same_key_not_a_rotation"

        # Registry, history and audit are all untouched.
        after = await gate._store.get_firmware_device(DEV_DEVICE)
        assert after == before
        history_after = await gate._store.list_firmware_anchor_history(DEV_DEVICE)
        assert [h["state"] for h in history_after] == [
            h["state"] for h in history_before
        ]
        assert "active" in {h["state"] for h in history_after}
        audit_after = await gate._store.list_firmware_anchor_transitions(DEV_DEVICE)
        assert len(audit_after) == len(audit_before)

    @pytest.mark.asyncio
    async def test_previously_used_key_is_refused(self, gate) -> None:
        # An old key may be exactly the one rotated away from because it
        # was compromised. Returning to it would make rotation reversible
        # by whoever still holds it.
        await self._active(gate)
        original = manifest_message("manifest_minimal_dev")

        second = signed_manifest_for_key(os.urandom(32), device_id=DEV_DEVICE)
        await gate.reprovision_device(
            device_id=DEV_DEVICE,
            public_key_b64=second["public_key_b64"],
            posture="development",
            manifest_message=second,
            actor="op",
            reason="rotate",
        )
        await gate.approve_device(DEV_DEVICE, actor="op", reason="promote")

        history_before = await gate._store.list_firmware_anchor_history(DEV_DEVICE)
        with pytest.raises(FirmwareVerificationError) as excinfo:
            await gate.reprovision_device(
                device_id=DEV_DEVICE,
                public_key_b64=PUBLIC_KEY_B64,
                posture="development",
                manifest_message=original,
                actor="op",
                reason="back to the old key",
            )
        assert excinfo.value.code == "key_epoch_reused"

        history_after = await gate._store.list_firmware_anchor_history(DEV_DEVICE)
        assert len(history_after) == len(history_before)
        row = await gate._store.get_firmware_device(DEV_DEVICE)
        assert row["public_key_b64"] == second["public_key_b64"]

    @pytest.mark.asyncio
    async def test_history_is_append_only_across_rotation(self, gate) -> None:
        await self._active(gate)
        first_id = (await gate._store.get_firmware_device(DEV_DEVICE))[
            "anchor_epoch_id"
        ]
        new = signed_manifest_for_key(os.urandom(32), device_id=DEV_DEVICE)
        await gate.reprovision_device(
            device_id=DEV_DEVICE,
            public_key_b64=new["public_key_b64"],
            posture="development",
            manifest_message=new,
            actor="op",
            reason="rotate",
        )
        await gate.approve_device(DEV_DEVICE, actor="op", reason="promote")

        history = await gate._store.list_firmware_anchor_history(DEV_DEVICE)
        ids = {h["anchor_epoch_id"] for h in history}
        # The original anchor is retained, not overwritten: evidence
        # outlives the anchor that authorised it.
        assert first_id in ids
        assert len(history) == 2
