# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Sign test bindings the way a commissioning producer would.

Test tooling only. The real producer is ori-cli; this exists so the runtime's
consumer can be exercised against documents whose signing key the test
controls, using the corpus's published test seed or a fresh one.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.security.commissioning.anchors import COMMISSIONING_ANCHOR_ENV
from ori.security.commissioning.binding import canonical_bytes


def private_key(seed_hex: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def public_key_b64(seed_hex: str) -> str:
    raw = (
        private_key(seed_hex).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return base64.b64encode(raw).decode("ascii")


def sign_envelope(binding: dict[str, Any], seed_hex: str) -> dict[str, Any]:
    """Wrap `binding` in the wire envelope, signed over its canonical bytes."""
    body = copy.deepcopy(binding)
    body["signing_key"] = "ed25519:" + public_key_b64(seed_hex)
    signature = private_key(seed_hex).sign(canonical_bytes(body))
    return {
        "binding": body,
        "signature": "ed25519:" + base64.b64encode(signature).decode("ascii"),
    }


def _observations(mapping: dict[str, str], active_high: bool) -> list[dict[str, Any]]:
    """Both outcomes commanded and observed, with the level each one drives."""
    energised = "high" if active_high else "low"
    released = "low" if active_high else "high"

    def level(outcome: str) -> str:
        return energised if mapping[outcome] == "energised" else released

    return [
        {
            "commanded": "open_protected_circuit",
            "coil_state": mapping["open_protected_circuit"],
            "gpio_level": level("open_protected_circuit"),
            "load_present_before": True,
            "load_present_after": False,
            "sensor_before": 6.4,
            "sensor_after": 0.02,
            "terminal_state_observed": "open",
        },
        {
            "commanded": "close_protected_circuit",
            "coil_state": mapping["close_protected_circuit"],
            "gpio_level": level("close_protected_circuit"),
            "load_present_before": False,
            "load_present_after": True,
            "sensor_before": 0.02,
            "sensor_after": 6.4,
            "terminal_state_observed": "closed",
        },
    ]


def local_gpio_binding(
    *,
    device_id: str,
    sensor_id: str,
    gpio_pin: int,
    active_high: bool,
    binding_seq: int = 1,
    supersedes: str | None = None,
    inventory_generation: int = 1,
    proof_method: str = "undemonstrated",
    control_proof_method: str | None = None,
    open_outcome: str = "de_energised",
    terminal_state: str = "open",
) -> dict[str, Any]:
    """One zone: a current clamp protecting a circuit through a local GPIO relay.

    `control_proof_method` defaults to None, which is the contract's absent leg
    and therefore a provisional zone.
    """
    close_outcome = "energised" if open_outcome == "de_energised" else "de_energised"
    mapping = {
        "open_protected_circuit": open_outcome,
        "close_protected_circuit": close_outcome,
        "de_energised_terminal_state": terminal_state,
    }
    observations = _observations(mapping, active_high)
    if proof_method == "undemonstrated":
        proof: dict[str, Any] = {
            "method": "undemonstrated",
            "performed_at_ms": 1800000000000,
            "reason": "bench: no load wired at commissioning",
            "observations": [],
        }
    else:
        proof = {
            "method": proof_method,
            "performed_at_ms": 1800000000000,
            "observations": observations,
        }
    if control_proof_method == "commanded_and_observed":
        proof["control_path"] = {
            "method": "commanded_and_observed",
            "performed_at_ms": 1800000600000,
            # Its own copy: sharing the list would let a test that mutates one
            # leg be refused by the other.
            "observations": copy.deepcopy(observations),
        }
    elif control_proof_method == "undemonstrated":
        proof["control_path"] = {
            "method": "undemonstrated",
            "performed_at_ms": 1800000600000,
            "reason": "bench: the panel was not available to command",
            "observations": [],
        }
    return {
        "v": 1,
        "binding_seq": binding_seq,
        "device_id": device_id,
        "issued_at_ms": 1800000000000,
        "signer_id": "commissioning-test",
        "signing_key": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "inventory_generation": inventory_generation,
        "supersedes": supersedes,
        "actor": "installer:test",
        "reason": "test commissioning",
        "zones": [
            {
                "zone_id": "bench",
                "rated_capacity": {
                    "parameter": "rated_capacity_amps",
                    "value": 10.0,
                    "provenance": "nameplate",
                },
                "sensor": {
                    "sensor_id": sensor_id,
                    "quantity": "current",
                    "unit": "ampere",
                    "range_min": 0.0,
                    "range_max": 100.0,
                    "direction": "positive_is_load_draw",
                    "noise_floor": 0.05,
                    "calibration_ref": "bench-2026-08-29",
                },
                "actuator": {
                    "kind": "local_gpio",
                    "identity": {"gpio_pin": gpio_pin, "active_high": active_high},
                    "commissioned_mapping": mapping,
                },
                "proof": proof,
            }
        ],
    }


def commission_relay(
    config_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    device_id: str,
    sensor_id: str,
    gpio_pin: int = 26,
    active_high: bool = False,
    seed_hex: str = "7" * 64,
    **overrides: Any,
) -> Path:
    """Write an accepted binding beside *config_path* and configure its anchor.

    The shortest route to a runtime whose relay is commissioned: the test
    controls the signing key, the anchor is that key, and the binding names
    the config's device, sensor and pin. Both proof legs are proven unless a
    caller overrides one, because a relay is driven only from a binding in
    force.
    """
    overrides.setdefault("proof_method", "actuate_and_observe")
    overrides.setdefault("control_proof_method", "commanded_and_observed")
    binding = local_gpio_binding(
        device_id=device_id,
        sensor_id=sensor_id,
        gpio_pin=gpio_pin,
        active_high=active_high,
        **overrides,
    )
    target = Path(config_path).resolve().parent / "commissioning" / "binding.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(sign_envelope(binding, seed_hex)))
    monkeypatch.setenv(COMMISSIONING_ANCHOR_ENV, public_key_b64(seed_hex))
    return target
