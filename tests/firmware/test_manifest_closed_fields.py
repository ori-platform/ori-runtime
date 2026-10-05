# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A signed manifest carries the contract's fields and nothing else.

`firmware-telemetry/v1`, *Deployment Maintenance Limit*: the manifest parser
refuses unrecognised keys. Each variant here is correctly signed and hashed,
so the only reason it can be refused is its shape.
"""

from __future__ import annotations

from typing import Any

import pytest

from ori.security.firmware.telemetry import (
    ERR_INVALID_ENVELOPE,
    FirmwareVerificationError,
    verify_manifest_message,
)
from tests.firmware.test_telemetry import signed_manifest_for_key

SEED = bytes([0x17]) * 32
DEVICE = "ori-fw-dev00001"
ACTION = {"action": "relay_open", "channel": "relay0", "authority": "runtime_commanded"}
INTERLOCK = {
    "name": "local_overcurrent_interlock",
    "channel": "ch0",
    "action": "relay_open",
}


def _verify(**overrides: Any) -> str:
    message = signed_manifest_for_key(SEED, device_id=DEVICE, **overrides)
    return verify_manifest_message(
        message,
        anchor_device_id=DEVICE,
        anchor_public_key_b64=message["public_key_b64"],
    )


def test_contract_shapes_are_accepted() -> None:
    _verify()
    _verify(actions=[ACTION], interlocks=[INTERLOCK])
    _verify(deployment_maintenance_limit_ms=900000)


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"debug_port": "uart0"}, "unknown"),
        ({"actions": [{**ACTION, "note": "x"}]}, "action 0 has unexpected fields"),
        ({"actions": [{"action": "relay_open", "channel": "relay0"}]}, "action 0"),
        ({"interlocks": [{**INTERLOCK, "note": "x"}]}, "interlock 0"),
        ({"interlocks": [{"name": "i", "channel": "ch0"}]}, "interlock 0"),
        ({"interlocks": ["not-an-object"]}, "interlock 0"),
        ({"interlocks": [{**INTERLOCK, "channel": 0}]}, "channel"),
        ({"secure_boot_enabled": 0}, "secure_boot_enabled must be a boolean"),
        ({"flash_encryption_enabled": "no"}, "flash_encryption_enabled must be"),
        ({"deployment_maintenance_limit_ms": 0}, "positive integer"),
        ({"deployment_maintenance_limit_ms": True}, "positive integer"),
        ({"deployment_maintenance_limit_ms": "900000"}, "positive integer"),
    ],
    ids=[
        "extra_root_key",
        "action_extra_key",
        "action_missing_key",
        "interlock_extra_key",
        "interlock_missing_key",
        "interlock_not_object",
        "interlock_non_string",
        "secure_boot_not_bool",
        "flash_encryption_not_bool",
        "limit_zero",
        "limit_bool",
        "limit_string",
    ],
)
def test_signed_manifest_outside_the_contract_is_refused(
    overrides: dict[str, Any], reason: str
) -> None:
    with pytest.raises(FirmwareVerificationError) as caught:
        _verify(**overrides)
    assert caught.value.code == ERR_INVALID_ENVELOPE
    assert reason in str(caught.value)


def test_a_missing_required_root_field_is_refused() -> None:
    message = signed_manifest_for_key(SEED, device_id=DEVICE)
    del message["manifest"]["key_storage"]
    with pytest.raises(FirmwareVerificationError, match="missing \\['key_storage'\\]"):
        verify_manifest_message(
            message,
            anchor_device_id=DEVICE,
            anchor_public_key_b64=message["public_key_b64"],
        )
