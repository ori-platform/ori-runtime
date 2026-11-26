# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""firmware-telemetry/v2 and firmware-commands/v2: a `device_id` is a fleet
identifier other than exactly `.` and `..`, at every site the runtime admits,
verifies, signs for or publishes to one."""

import base64
import copy
import json
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.gateway import firmware_commands as gateway_commands
from ori.security.firmware import (
    commands,
    liveness,
    mqtt_certificate,
    mqtt_provisioning,
)
from ori.security.firmware.telemetry import (
    ERR_UNKNOWN_DEVICE,
    FirmwareVerificationError,
    canonical_json_bytes,
    is_firmware_device_id,
    verify_fault_message,
    verify_manifest_message,
    verify_telemetry_message,
)
from tests.firmware.test_mqtt_provisioning import CASES as PROVISIONING_CASES
from tests.firmware.test_mqtt_provisioning import DEVICE_PUBLIC_KEY
from tests.firmware.test_mqtt_provisioning import VECTORS as PROVISIONING_VECTORS
from tests.firmware.test_telemetry import (
    CASES,
    GOLDEN_SEED,
    PUBLIC_KEY_B64,
    SEALED_HASH,
    signed_envelope,
    signed_manifest_for_key,
)

DOT_SEGMENTS = [".", ".."]
STILL_ALLOWED = [".a", "a.", "...", "a..b", "-", "_", "A" * 48]
HASH = "sha256:" + "0" * 64


def test_the_rule_refuses_exactly_the_two_dot_segments() -> None:
    assert [v for v in DOT_SEGMENTS if is_firmware_device_id(v)] == []
    assert all(is_firmware_device_id(v) for v in STILL_ALLOWED)
    assert not is_firmware_device_id("A" * 49)
    assert not is_firmware_device_id("a/b")


def _sign_csr(device_id: str) -> bytes:
    return mqtt_provisioning.build_create_csr_request(
        actor="op",
        anchor_epoch_id="sha256:" + "a" * 64,
        device_id=device_id,
        provision_seq=1,
        reason="test",
    )


def _liveness(device_id: str) -> bytes:
    return liveness.build_liveness_bytes(
        boot_id=1, capability_hash=HASH, device_id=device_id, runtime_seq=1
    )


SITES: list[tuple[str, Callable[[str], object], type[Exception]]] = [
    ("mqtt certificate", mqtt_certificate._device_id, ValueError),
    ("liveness signing", _liveness, liveness.FirmwareLivenessError),
    ("command signing", commands._require_device_id, commands.FirmwareCommandError),
    (
        "command topic",
        lambda d: gateway_commands._topic(d, "cmd"),
        gateway_commands.FirmwareCommandPublishError,
    ),
    ("provisioning", _sign_csr, mqtt_provisioning.FirmwareMqttProvisioningError),
]


@pytest.mark.parametrize(("site", "check", "error"), SITES, ids=[s[0] for s in SITES])
@pytest.mark.parametrize("device_id", DOT_SEGMENTS)
def test_every_site_refuses_a_dot_segment(
    site: str, check: Callable[[str], object], error: type[Exception], device_id: str
) -> None:
    with pytest.raises(error):
        check(device_id)


@pytest.mark.parametrize(("site", "check", "error"), SITES, ids=[s[0] for s in SITES])
@pytest.mark.parametrize("device_id", STILL_ALLOWED)
def test_every_site_still_accepts_the_rest_of_the_grammar(
    site: str, check: Callable[[str], object], error: type[Exception], device_id: str
) -> None:
    check(device_id)


@pytest.mark.parametrize("device_id", DOT_SEGMENTS)
def test_a_manifest_naming_a_dot_segment_is_refused_even_by_its_own_anchor(
    device_id: str,
) -> None:
    message = signed_manifest_for_key(bytes([7]) * 32, device_id=device_id)
    pub = message.pop("public_key_b64")
    with pytest.raises(FirmwareVerificationError) as raised:
        verify_manifest_message(
            message, anchor_device_id=device_id, anchor_public_key_b64=pub
        )
    assert raised.value.code == ERR_UNKNOWN_DEVICE

    control = signed_manifest_for_key(bytes([7]) * 32, device_id="a.")
    verify_manifest_message(
        control,
        anchor_device_id="a.",
        anchor_public_key_b64=control.pop("public_key_b64"),
    )


def _anchor(device_id: str, posture: str) -> dict[str, Any]:
    return {
        "anchor_device_id": device_id,
        "anchor_public_key_b64": PUBLIC_KEY_B64,
        "anchor_posture": posture,
        "last_boot_id": 0,
        "last_seq": 0,
        "last_uptime_ms": None,
    }


def _envelope_verdict(device_id: str) -> Any:
    case = next(c for c in CASES.values() if c["kind"] == "telemetry")
    envelope = copy.deepcopy(case["input"]) | {"device_id": device_id}
    return verify_telemetry_message(
        signed_envelope(envelope),
        accepted_manifest_hash=envelope["capability_hash"],
        **_anchor(device_id, envelope["posture"]),
    )


def _fault_verdict(device_id: str) -> Any:
    fault = {
        "v": 1,
        "alg": "ed25519",
        "device_id": device_id,
        "boot_id": 41,
        "seq": 130_486,
        "capability_hash": SEALED_HASH,
        "posture": "sealed_flash",
        "device_uptime_ms": 925_000,
        "code": "command_rejected",
        "subject": "relay0",
        "detail": "replayed",
    }
    signature = Ed25519PrivateKey.from_private_bytes(GOLDEN_SEED).sign(
        canonical_json_bytes(fault)
    )
    message = {
        "fault": fault,
        "signature": "ed25519:" + base64.b64encode(signature).decode("ascii"),
    }
    return verify_fault_message(
        message,
        accepted_manifest_hash=SEALED_HASH,
        **_anchor(device_id, "sealed_flash"),
    )


@pytest.mark.parametrize("verdict", [_envelope_verdict, _fault_verdict])
@pytest.mark.parametrize("device_id", DOT_SEGMENTS)
def test_an_envelope_or_fault_naming_a_dot_segment_is_refused(
    verdict: Callable[[str], Any], device_id: str
) -> None:
    result = verdict(device_id)
    assert not result.accepted
    assert result.error_code == ERR_UNKNOWN_DEVICE
    control = verdict("a.")
    assert control.accepted, control.error_code


def _resigned_device_message(case_name: str, device_id: str) -> bytes:
    case = PROVISIONING_CASES[case_name]
    original = '"device_id":"%s"' % json.loads(case["signed_object"])["device_id"]
    signed = case["signed_object"].replace(original, '"device_id":"%s"' % device_id)
    signature = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(PROVISIONING_VECTORS["device_test_seed_hex"])
    ).sign(signed.encode())
    encoded = (
        case["signature"].split(":", 1)[0]
        + ":"
        + base64.b64encode(signature).decode("ascii")
    )
    return (
        '{"%s":%s,"signature":"%s"}' % (case["outer_field"], signed, encoded)
    ).encode()


@pytest.mark.parametrize("case_name", ["csr_response", "install_result"])
@pytest.mark.parametrize("device_id", DOT_SEGMENTS)
def test_a_signed_device_response_naming_a_dot_segment_is_refused(
    case_name: str, device_id: str
) -> None:
    with pytest.raises(mqtt_provisioning.FirmwareMqttProvisioningError):
        mqtt_provisioning.verify_device_message(
            _resigned_device_message(case_name, device_id),
            device_public_key_bytes=DEVICE_PUBLIC_KEY,
        )
    accepted = mqtt_provisioning.verify_device_message(
        _resigned_device_message(case_name, "a."),
        device_public_key_bytes=DEVICE_PUBLIC_KEY,
    )
    assert accepted["device_id"] == "a."
