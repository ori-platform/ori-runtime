# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""A fixture manifest that declares the runtime key's signing domains.

The shared Layer 1 fixtures predate ``runtime_key_domains``, and the runtime
signs nothing for a device whose manifest does not declare it. This adds the
member and re-signs under the disclosed test device seed, which the vendored
firmware-telemetry/v2 manifest corpus publishes; never provision that seed.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.firmware.signing_domains import (
    RUNTIME_KEY_DOMAINS_FIELD,
    RUNTIME_KEY_DOMAINS_VALUE,
)
from ori.security.firmware.telemetry import canonical_json_bytes

_SEED = bytes.fromhex(
    json.loads(
        (
            Path(__file__).parent.parent
            / "vectors"
            / "firmware_telemetry"
            / "manifest-vectors-v2.json"
        ).read_text()
    )["test_seed_hex"]
)


def declaring_message(manifest: dict[str, Any]) -> dict[str, Any]:
    """A signed manifest message for ``manifest`` plus ``runtime_key_domains``."""
    declared = copy.deepcopy(manifest)
    declared[RUNTIME_KEY_DOMAINS_FIELD] = RUNTIME_KEY_DOMAINS_VALUE
    body = canonical_json_bytes(declared)
    signature = Ed25519PrivateKey.from_private_bytes(_SEED).sign(body)
    return {
        "manifest": declared,
        "manifest_hash": "sha256:" + hashlib.sha256(body).hexdigest(),
        "signature": "ed25519:" + base64.b64encode(signature).decode("ascii"),
    }


def fault_under(message: dict[str, Any], capability_hash: str) -> dict[str, Any]:
    """A fault message re-signed by the test device under ``capability_hash``."""
    fault = copy.deepcopy(message["fault"])
    fault["capability_hash"] = capability_hash
    signature = Ed25519PrivateKey.from_private_bytes(_SEED).sign(
        canonical_json_bytes(fault)
    )
    return {
        "fault": fault,
        "signature": "ed25519:" + base64.b64encode(signature).decode("ascii"),
    }


def envelope_under(envelope: dict[str, Any], capability_hash: str) -> dict[str, Any]:
    """A telemetry message re-signed by the test device under ``capability_hash``."""
    signed = copy.deepcopy(envelope)
    signed["capability_hash"] = capability_hash
    signature = Ed25519PrivateKey.from_private_bytes(_SEED).sign(
        canonical_json_bytes(signed)
    )
    return {
        "envelope": signed,
        "signature": "ed25519:" + base64.b64encode(signature).decode("ascii"),
    }
