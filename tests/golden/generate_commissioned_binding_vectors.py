# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Authoring tool for the commissioned-safety-binding v1 golden vectors.

Reproduces `ori-specs/commissioned-safety-binding/binding-vectors-v1.json`
byte-for-byte. The tool is not the authority; the committed file is.

Case expectations are authored from the contract, not recorded from an
implementation: a corpus produced by running a verifier certifies whatever
that verifier does, including its defects.
"""

import argparse
import base64
import copy
import hashlib
import json
import pathlib
import sys
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# TEST-ONLY seeds. Never use in production. The commissioning and provisioning
# seeds are distinct because the contract's central rule is that the two keys
# are different key material, and a corpus sharing one seed could not express
# the `wrong_authority` case at all.
COMMISSIONING_SEED = bytes.fromhex("3" * 64)
PROVISIONING_SEED = bytes.fromhex("4" * 64)
PREVIOUS_SEED = bytes.fromhex("5" * 64)
ROGUE_SEED = bytes.fromhex("9" * 64)

DEVICE_ID = "energy-monitor-ikeja-01"


def key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def pub_hex(seed: bytes) -> str:
    from cryptography.hazmat.primitives import serialization

    return (
        key(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def pub_b64(seed: bytes) -> str:
    return base64.b64encode(bytes.fromhex(pub_hex(seed))).decode()


def canonical(value: Any) -> bytes:
    """Canonical form of gateway-mqtt-canonical-json/v1, D-011 number zone."""
    _check_numbers(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _check_numbers(value: Any) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > 9007199254740991:
            raise ValueError(f"integer outside the agreement zone: {value}")
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"non-finite number: {value}")
        if value != 0.0 and not (1e-4 <= abs(value) < 1e16):
            raise ValueError(f"float outside the agreement zone: {value}")
        text = repr(value)
        if "e" in text or "E" in text or "." not in text:
            raise ValueError(f"float not in fixed notation with a fraction: {text}")
        return
    if isinstance(value, dict):
        for v in value.values():
            _check_numbers(v)
    elif isinstance(value, list):
        for v in value:
            _check_numbers(v)


def digest(binding: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(binding)).hexdigest()


def sign(binding: dict, seed: bytes) -> str:
    return "ed25519:" + base64.b64encode(key(seed).sign(canonical(binding))).decode()


def non_canonical(b64: str) -> str:
    """A different spelling of the same bytes.

    Base64 leaves the low bits of the final character unused when the input is
    not a multiple of three. Setting them non-zero produces a string that
    `validate=True` accepts and that decodes identically -- which is why strict
    decoding is not enough and round-trip equality is the rule.
    """
    raw = base64.b64decode(b64, validate=True)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for index, char in enumerate(b64):
        if char == "=":
            continue
        for candidate in alphabet:
            if candidate == char:
                continue
            variant = b64[:index] + candidate + b64[index + 1 :]
            try:
                if base64.b64decode(variant, validate=True) == raw:
                    return variant
            except Exception:  # noqa: BLE001 - candidate simply does not decode
                continue
    raise AssertionError("no non-canonical spelling found")


def envelope(binding: dict, seed: bytes = COMMISSIONING_SEED) -> dict:
    return {"binding": binding, "signature": sign(binding, seed)}


# ── the reference site: two clamps, two contactors, correctly bound ──────────

ZONE_MAIN = {
    "zone_id": "main-distribution",
    "rated_capacity": {
        "parameter": "rated_capacity_amps",
        "value": 10.0,
        "provenance": "nameplate",
    },
    "sensor": {
        "sensor_id": "load-current-main",
        "quantity": "current",
        "unit": "ampere",
        "range_min": 0.0,
        "range_max": 100.0,
        "direction": "positive_is_load_draw",
        "noise_floor": 0.05,
        "calibration_ref": "sct013-100-2026-08-19-a",
    },
    "actuator": {
        "kind": "local_gpio",
        "identity": {"gpio_pin": 26, "active_high": False},
        "commissioned_mapping": {
            "open_protected_circuit": "de_energised",
            "close_protected_circuit": "energised",
            "de_energised_terminal_state": "open",
        },
    },
    "proof": {
        "method": "actuate_and_observe",
        "performed_at_ms": 1800000000000,
        "observations": [
            {
                "commanded": "open_protected_circuit",
                "coil_state": "de_energised",
                "gpio_level": "high",
                "load_present_before": True,
                "load_present_after": False,
                "sensor_before": 6.4,
                "sensor_after": 0.02,
                "terminal_state_observed": "open",
            },
            {
                "commanded": "close_protected_circuit",
                "coil_state": "energised",
                "gpio_level": "low",
                "load_present_before": False,
                "load_present_after": True,
                "sensor_before": 0.02,
                "sensor_after": 6.4,
                "terminal_state_observed": "closed",
            },
        ],
    },
}

ZONE_PUMP = {
    "zone_id": "borehole-pump",
    "rated_capacity": {
        "parameter": "rated_capacity_amps",
        "value": 4.0,
        "provenance": "nameplate",
    },
    "sensor": {
        "sensor_id": "load-current-pump",
        "quantity": "current",
        "unit": "ampere",
        "range_min": 0.0,
        "range_max": 100.0,
        "direction": "positive_is_load_draw",
        "noise_floor": 0.05,
        "calibration_ref": "sct013-100-2026-08-19-b",
    },
    "actuator": {
        "kind": "firmware_channel",
        "identity": {
            "firmware_device_id": "ori-fw-7c9f2b3a",
            "channel": "relay0",
        },
        "commissioned_mapping": {
            "open_protected_circuit": "energised",
            "close_protected_circuit": "de_energised",
            "de_energised_terminal_state": "closed",
        },
    },
    "proof": {
        "method": "actuate_and_observe",
        "performed_at_ms": 1800000000000,
        "observations": [
            {
                "commanded": "open_protected_circuit",
                "coil_state": "energised",
                "load_present_before": True,
                "load_present_after": False,
                "sensor_before": 2.1,
                "sensor_after": 0.01,
                "terminal_state_observed": "open",
            },
            {
                "commanded": "close_protected_circuit",
                "coil_state": "de_energised",
                "load_present_before": False,
                "load_present_after": True,
                "sensor_before": 0.01,
                "sensor_after": 2.1,
                "terminal_state_observed": "closed",
            },
        ],
    },
}


def base_binding(seq: int = 1, supersedes: Any = None) -> dict:
    return {
        "v": 1,
        "binding_seq": seq,
        "device_id": DEVICE_ID,
        "issued_at_ms": 1800000000000,
        "signer_id": "commissioning-lagos-ikeja",
        "signing_key": "ed25519:" + pub_b64(COMMISSIONING_SEED),
        "supersedes": supersedes,
        "actor": "installer:ade",
        "reason": "initial commissioning",
        "zones": [copy.deepcopy(ZONE_MAIN), copy.deepcopy(ZONE_PUMP)],
    }


INVENTORY = {
    "sensor_ids": ["load-current-main", "load-current-pump"],
    "actuators": [
        {"kind": "local_gpio", "identity": {"gpio_pin": 26, "active_high": False}},
        {
            "kind": "firmware_channel",
            "identity": {
                "firmware_device_id": "ori-fw-7c9f2b3a",
                "channel": "relay0",
            },
        },
    ],
}


def context(**overrides: Any) -> dict:
    ctx = {
        "device_id": DEVICE_ID,
        "commissioning_anchor_current_hex": pub_hex(COMMISSIONING_SEED),
        "commissioning_anchor_previous_hex": pub_hex(PREVIOUS_SEED),
        "provisioning_anchor_hex": pub_hex(PROVISIONING_SEED),
        "accepted_binding_seq": 0,
        "accepted_binding_hash": None,
        "declared_inventory": INVENTORY,
        "deployment_posture": "production",
        "profile_multiplier": 5.0,
    }
    ctx.update(overrides)
    return ctx


def accepted_zone_state(binding: dict) -> dict:
    """What a consumer retains from the binding in force.

    Retention is already required for audit; a revision is checked against it
    so a changed actuator cannot inherit the proof of the one it replaced.
    """
    return {
        z["zone_id"]: {
            "identity": z["actuator"]["identity"],
            "mapping": z["actuator"]["commissioned_mapping"],
            "calibration_ref": z["sensor"]["calibration_ref"],
            "proof_at_ms": z["proof"]["performed_at_ms"],
        }
        for z in binding["zones"]
    }


def mutate(fn) -> dict:
    b = base_binding()
    fn(b)
    return b


def case(
    name: str, binding: dict, note: str, ctx: dict, seed=COMMISSIONING_SEED
) -> dict:
    env = envelope(binding, seed)
    return {
        "name": name,
        "note": note,
        "binding": binding,
        "verifier_context": ctx,
        "canonical_hex": canonical(binding).hex(),
        "canonical_sha256": digest(binding),
        "signature_b64": env["signature"].removeprefix("ed25519:"),
        "message_hex": canonical(env).hex(),
    }


# The stage a verdict is decided at is part of the vector, not folded into a
# single top-level list: a case that refuses for the right reason at the wrong
# stage is not evidence that the named check exists.
VERDICT_STAGE = {
    "malformed": "parses",
    "wrong_device": "device_id",
    "unknown_signer": "key_selection",
    "anchor_collision": "key_selection",
    "bad_signature": "signature",
    "wrong_authority": "authority",
    "superseded_signer": "authority",
    "stale": "freshness",
    "mapping_contradiction": "mapping_self_consistency",
    "proof_contradiction": "proof_consistency",
    "stale_proof": "proof_consistency",
    "out_of_bounds": "bounds",
    "ambiguous_binding": "disambiguation",
    "unknown_hardware": "inventory",
    "unbound_actuator": "inventory",
    "undemonstrated_binding": "activation_posture",
}


def reject(name, binding, note, reason, ctx, seed=COMMISSIONING_SEED, sig_valid=True):
    c = case(name, binding, note, ctx, seed)
    c["reason"] = reason
    c["stage"] = VERDICT_STAGE[reason]
    c["signature_valid"] = sig_valid
    return c


# ── accept cases ─────────────────────────────────────────────────────────────

accept_cases = [
    case(
        "two_zone_site_correctly_bound",
        base_binding(),
        "Two clamps and two contactors, each pair bound by identity and proven "
        "by actuation. The two zones carry opposite commissioned mappings, so a "
        "verifier that derives one from a convention rather than reading it "
        "fails exactly one of them.",
        context(),
    ),
]


def _pre_energisation(b: dict) -> None:
    b["reason"] = "commissioning before first energisation"
    for z in b["zones"]:
        z["proof"] = {
            "method": "pre_energisation",
            "performed_at_ms": 1800000000000,
            "observations": [
                {
                    "commanded": "open_protected_circuit",
                    "coil_state": z["actuator"]["commissioned_mapping"][
                        "open_protected_circuit"
                    ],
                    "load_present_before": True,
                    "load_present_after": False,
                    "terminal_state_observed": "open",
                    "instrument": "multimeter_continuity",
                },
                {
                    "commanded": "close_protected_circuit",
                    "coil_state": z["actuator"]["commissioned_mapping"][
                        "close_protected_circuit"
                    ],
                    "load_present_before": False,
                    "load_present_after": True,
                    "terminal_state_observed": "closed",
                    "instrument": "multimeter_continuity",
                },
            ],
        }


accept_cases.append(
    case(
        "pre_energisation_proof_accepted",
        mutate(_pre_energisation),
        "Terminal states proven at the terminals with a meter before the site "
        "load was first energised. Acceptable for autonomous actuation: the "
        "association is measured, not asserted.",
        context(),
    )
)


def _undemonstrated(b: dict) -> None:
    b["reason"] = "load could not be interrupted at commissioning"
    b["zones"][1]["proof"] = {
        "method": "undemonstrated",
        "performed_at_ms": 1800000000000,
        "reason": "borehole pump serves a live ward; interruption refused by site",
        "observations": [],
    }


accept_cases.append(
    case(
        "undemonstrated_zone_accepted_in_development",
        mutate(_undemonstrated),
        "Document is well-formed and accepted. The borehole zone's actuating "
        "profiles stay inactive and the runtime logs a consolidated WARNING; "
        "its non-actuating profiles remain available. The main zone is "
        "unaffected.",
        context(deployment_posture="development"),
    )
)
accept_cases[-1]["expected_activation"] = {
    "main-distribution": "actuating_profiles_active",
    "borehole-pump": "actuating_profiles_inactive_warned",
}


def _revision(b: dict) -> None:
    b["binding_seq"] = 2
    b["reason"] = "recalibration after clamp re-seating"
    b["zones"][0]["sensor"]["calibration_ref"] = "sct013-100-2026-08-26-a"
    b["zones"][0]["proof"]["performed_at_ms"] = 1800000600000


_first = base_binding()
accept_cases.append(
    case(
        "revision_with_fresh_proof_accepted",
        mutate(
            lambda b: (_revision(b), b.__setitem__("supersedes", digest(_first)))[0]
        ),
        "A recalibration changes `calibration_ref`, so the prior proof no "
        "longer establishes the binding and a fresh one is carried. "
        "`supersedes` names the canonical hash of the document it replaces.",
        context(
            accepted_binding_seq=1,
            accepted_binding_hash=digest(_first),
            accepted_zone_state=accepted_zone_state(_first),
        ),
    )
)

# ── reject cases ─────────────────────────────────────────────────────────────

reject_cases = []


def _rej(name, note, reason, fn, ctx=None, seed=COMMISSIONING_SEED, sig_valid=True):
    reject_cases.append(
        reject(name, mutate(fn), note, reason, ctx or context(), seed, sig_valid)
    )


_rej(
    "transposed_binding",
    "The contact was observed to open and the instrument still finds the load "
    "energised afterwards, because the clamp is on a different circuit from "
    "the contactor. This is the transposition case, and it is caught by the "
    "instrument's own load determination rather than by reading a threshold "
    "into a current value.",
    "proof_contradiction",
    lambda b: b["zones"][0]["proof"]["observations"][0].update(
        {"load_present_after": True, "sensor_after": 6.4}
    ),
)

_rej(
    "terminal_state_observed_contradicts_command",
    "The contact was observed closed after a command to open the circuit.",
    "proof_contradiction",
    lambda b: b["zones"][0]["proof"]["observations"][0].update(
        {"terminal_state_observed": "closed"}
    ),
)

_rej(
    "proof_performed_on_an_idle_load",
    "The load was not drawing before the open command, so opening it "
    "demonstrated nothing: an idle circuit reads the same on both sides of an "
    "actuation. A low reading after the command is not on its own evidence "
    "that this contactor controls this circuit.",
    "proof_contradiction",
    lambda b: b["zones"][0]["proof"]["observations"][0].update(
        {"load_present_before": False, "sensor_before": 0.02}
    ),
)

_rej(
    "proof_delta_within_the_sensor_noise_floor",
    "The instrument reports the load gone, and the recorded current moved by "
    "0.02 A against a declared noise floor of 0.05 A. A change the sensor "
    "cannot resolve is not a measurement, whatever the instrument says.",
    "proof_contradiction",
    lambda b: b["zones"][0]["proof"]["observations"][0].update(
        {"sensor_before": 6.4, "sensor_after": 6.38}
    ),
)

_rej(
    "polarity_mismatch",
    "`active_high` is false, so a de-energised coil is driven by a high GPIO "
    "level. The observation records a low level for the de-energised command, "
    "which contradicts the declared driver polarity.",
    "proof_contradiction",
    lambda b: b["zones"][0]["proof"]["observations"][0].update({"gpio_level": "low"}),
)

_rej(
    "outcomes_name_one_coil_state",
    "Both circuit outcomes map to `de_energised`. A coil has two states, so one "
    "of the two observations is wrong.",
    "mapping_contradiction",
    lambda b: b["zones"][0]["actuator"]["commissioned_mapping"].update(
        {"close_protected_circuit": "de_energised"}
    ),
)

_rej(
    "terminal_state_contradicts_open_outcome",
    "`open_protected_circuit` is `de_energised` while "
    "`de_energised_terminal_state` is `closed`. Both cannot be observations of "
    "the same channel.",
    "mapping_contradiction",
    lambda b: b["zones"][0]["actuator"]["commissioned_mapping"].update(
        {"de_energised_terminal_state": "closed"}
    ),
)

_rej(
    "capacity_above_sensor_full_scale",
    "A 120 A capacity on a clamp that reads to 100 A describes a load the "
    "sensor cannot measure at all.",
    "out_of_bounds",
    lambda b: b["zones"][0]["rated_capacity"].update({"value": 120.0}),
)

_rej(
    "trip_point_above_sensor_full_scale",
    "Capacity is comfortably in range at 25 A, and the release-owned "
    "multiplier of 5.0 puts the trip point at 125 A, beyond the clamp's 100 A "
    "full scale. A saturating sensor reports the hazard as a merely high "
    "reading, so the cutoff can never fire. This is the case a capacity-only "
    "bound misses.",
    "out_of_bounds",
    lambda b: b["zones"][0]["rated_capacity"].update({"value": 25.0}),
)

_rej(
    "signed_by_provisioning_authority",
    "Genuinely signed by the provisioning authority, which is why the verdict "
    "is reachable at all: it is decided after the signature verifies, so a "
    "stranger cannot manufacture the event by naming that key over a forged "
    "signature. Refused because the commercial plane must not be able to move "
    "a trip point by raising a declared capacity.",
    "wrong_authority",
    lambda b: (
        b.__setitem__("signer_id", "product-provisioning-prod"),
        b.__setitem__("signing_key", "ed25519:" + pub_b64(PROVISIONING_SEED)),
    )[0],
    seed=PROVISIONING_SEED,
)

_rej(
    "signed_by_previous_commissioning_generation",
    "The previous generation is verify-only for the binding already in force. "
    "A new binding must be signed by the current generation, or a compromised "
    "key would keep authoring bindings after rotation.",
    "superseded_signer",
    lambda b: b.__setitem__("signing_key", "ed25519:" + pub_b64(PREVIOUS_SEED)),
    seed=PREVIOUS_SEED,
)

_rej(
    "signing_key_is_not_a_commissioning_generation",
    "Self-consistent - the document names the key that signed it - and that "
    "key is neither generation of the commissioning anchor.",
    "unknown_signer",
    lambda b: b.__setitem__("signing_key", "ed25519:" + pub_b64(ROGUE_SEED)),
    seed=ROGUE_SEED,
)

_rej(
    "anchors_are_identical_key_material",
    "Both configured anchors are the same 32 bytes, so `wrong_authority` could "
    "never be reached and the separation the contract rests on does not exist. "
    "Refused at configuration load, before any document is verified.",
    "anchor_collision",
    lambda b: None,
    ctx=context(provisioning_anchor_hex=pub_hex(COMMISSIONING_SEED)),
)

_rej(
    "replayed_binding_seq",
    "`binding_seq` does not strictly exceed the accepted one.",
    "stale",
    lambda b: None,
    ctx=context(accepted_binding_seq=1, accepted_binding_hash=digest(base_binding())),
)

_rej(
    "supersedes_does_not_match_accepted",
    "`binding_seq` advances but `supersedes` names a document that is not the "
    "one in force, so the chain does not connect.",
    "stale",
    lambda b: (
        b.__setitem__("binding_seq", 2),
        b.__setitem__("supersedes", "sha256:" + "0" * 64),
    )[0],
    ctx=context(accepted_binding_seq=1, accepted_binding_hash=digest(base_binding())),
)

_rej(
    "actuator_replaced_without_fresh_proof",
    "The revision moves the main contactor to a different GPIO pin and carries "
    "the previous proof unchanged. A new actuator does not inherit the mapping "
    "the previous one was proven to have.",
    "stale_proof",
    lambda b: (
        b.__setitem__("binding_seq", 2),
        b.__setitem__("supersedes", digest(base_binding())),
        b["zones"][0]["actuator"]["identity"].__setitem__("gpio_pin", 19),
    )[0],
    ctx=context(
        accepted_binding_seq=1,
        accepted_binding_hash=digest(base_binding()),
        accepted_zone_state=accepted_zone_state(base_binding()),
        declared_inventory={
            "sensor_ids": INVENTORY["sensor_ids"],
            "actuators": [
                {
                    "kind": "local_gpio",
                    "identity": {"gpio_pin": 19, "active_high": False},
                },
                INVENTORY["actuators"][1],
            ],
        },
    ),
)

_rej(
    "undemonstrated_zone_under_hardened_posture",
    "Same document as the accepted development case. Under production posture "
    "an undemonstrated zone cannot activate an actuating profile, and a runtime "
    "that quietly disabled the cutoff while reporting healthy is the worst "
    "available outcome, so startup fails.",
    "undemonstrated_binding",
    _undemonstrated,
    ctx=context(deployment_posture="production"),
)

_rej(
    "duplicate_actuator_identity",
    "Two zones claim the same contactor. Refused rather than resolved: there is "
    "no ordering preference and no nearest-match rule.",
    "ambiguous_binding",
    lambda b: (
        b["zones"][1].__setitem__("actuator", copy.deepcopy(ZONE_MAIN["actuator"])),
        b["zones"][1].__setitem__("proof", copy.deepcopy(ZONE_MAIN["proof"])),
    )[0],
)

_rej(
    "duplicate_sensor_id",
    "One clamp bound into two zones with different actuators.",
    "ambiguous_binding",
    lambda b: b["zones"][1]["sensor"].__setitem__("sensor_id", "load-current-main"),
)

_rej(
    "sensor_absent_from_declared_inventory",
    "A binding may only name hardware the device declared.",
    "unknown_hardware",
    lambda b: b["zones"][1]["sensor"].__setitem__("sensor_id", "load-current-annexe"),
)

_rej(
    "declared_actuator_left_unbound",
    "The device declares two actuators and the document binds one. Refused in "
    "hardened posture rather than silently leaving a contactor ungoverned.",
    "unbound_actuator",
    lambda b: b.__setitem__("zones", [copy.deepcopy(ZONE_MAIN)]),
)

_rej(
    "wrong_device",
    "A binding signed for one device must never be accepted by another.",
    "wrong_device",
    lambda b: b.__setitem__("device_id", "energy-monitor-yaba-02"),
)

_rej(
    "bad_signature",
    "Names the current commissioning key and is signed by someone who does not "
    "hold it. Key selection finds the named key and the signature is what "
    "refuses; no authority verdict is issued over an unverified document.",
    "bad_signature",
    lambda b: None,
    seed=ROGUE_SEED,
    sig_valid=False,
)

_rej(
    "unknown_actuator_kind",
    "`kind` is a closed vocabulary. An unrecognised kind is refused, never "
    "treated as the nearest known one.",
    "malformed",
    lambda b: b["zones"][0]["actuator"].__setitem__("kind", "modbus_coil"),
)

_rej(
    "reason_absent",
    "`actor` and `reason` are structurally required, so a document missing "
    "either is a shape violation rejected before signature verification. There "
    "is no audit-specific verdict.",
    "malformed",
    lambda b: b.pop("reason"),
)

_rej(
    "mapping_key_absent",
    "The mapping has no default: a channel missing any of its three facts "
    "cannot be actuated.",
    "malformed",
    lambda b: b["zones"][0]["actuator"]["commissioned_mapping"].pop(
        "de_energised_terminal_state"
    ),
)

_rej(
    "signing_key_with_non_canonical_padding",
    "A different spelling of the same 32 bytes: strict base64 accepts it and it "
    "decodes to the identical key. Only round-trip equality refuses it, and "
    "without that rule two implementations disagree about a document neither "
    "considers malformed.",
    "malformed",
    lambda b: b.__setitem__(
        "signing_key",
        "ed25519:" + non_canonical(b["signing_key"].removeprefix("ed25519:")),
    ),
)

_rej(
    "signing_key_is_not_valid_base64",
    "The signed body names a key that is not base64 at all. A verifier that "
    "raises here rather than returning a verdict has not refused the document.",
    "malformed",
    lambda b: b.__setitem__("signing_key", "ed25519:!!!!not-base64!!!!"),
)

_rej(
    "signing_key_is_not_thirty_two_bytes",
    "Well-formed base64 that is not an Ed25519 public key. Length is part of "
    "the grammar, so this never reaches key selection.",
    "malformed",
    lambda b: b.__setitem__("signing_key", "ed25519:AAAA"),
)

_rej(
    "supersedes_is_not_a_digest",
    "`supersedes` is either null or a lowercase sha256 digest; a free string "
    "would make the revision chain unverifiable.",
    "malformed",
    lambda b: b.__setitem__("supersedes", "the previous one"),
)

_rej(
    "actuator_kind_is_an_array",
    "A closed vocabulary tested by membership before its type is checked "
    "raises rather than refuses: arrays and objects are unhashable. Every "
    "vocabulary in this contract has the same shape, so one of them is "
    "carried as the representative case.",
    "malformed",
    lambda b: b["zones"][0]["actuator"].__setitem__("kind", []),
)

_rej(
    "proof_method_is_an_object",
    "The same defect on a different vocabulary, and on the field that selects "
    "which shape the rest of the proof must have.",
    "malformed",
    lambda b: b["zones"][0]["proof"].__setitem__("method", {}),
)

_rej(
    "noise_floor_declared_as_a_boolean",
    "JSON separates booleans from numbers and some languages do not: in Python "
    "True is an instance of int, so a naive numeric check accepts this. A "
    "verifier that does is reading a threshold out of a flag.",
    "malformed",
    lambda b: b["zones"][0]["sensor"].__setitem__("noise_floor", True),
)

_rej(
    "signer_id_is_whitespace_only",
    "A field carrying no information is not a field that was supplied, and an "
    "empty signer in an audit record is worse than an absent one because it "
    "looks answered.",
    "malformed",
    lambda b: b.__setitem__("signer_id", "   "),
)

_rej(
    "unknown_sensor_field",
    "The closed grammar reaches nested objects. A sensor field a consumer does "
    "not read is refused rather than dropped.",
    "malformed",
    lambda b: b["zones"][0]["sensor"].__setitem__("contact_type", "nc"),
)

_rej(
    "unknown_observation_field",
    "An observation is a closed shape too. An extra field in a proof is a "
    "claim about how the proof was performed, and an ignored claim is worse "
    "than a refused one.",
    "malformed",
    lambda b: b["zones"][0]["proof"]["observations"][0].__setitem__(
        "assumed_from_datasheet", True
    ),
)

_rej(
    "identity_shape_does_not_match_actuator_kind",
    "A local-GPIO identity on a firmware channel names an actuator that does "
    "not exist, and would leave active_high unread on a device with no pin.",
    "malformed",
    lambda b: b["zones"][1]["actuator"].__setitem__(
        "identity", {"gpio_pin": 26, "active_high": True}
    ),
)

_rej(
    "gpio_level_recorded_for_a_firmware_channel",
    "A pin level is meaningless for a channel with no pin, so recording one is "
    "a shape error rather than an ignorable extra.",
    "malformed",
    lambda b: b["zones"][1]["proof"]["observations"][0].__setitem__(
        "gpio_level", "high"
    ),
)

_rej(
    "one_sided_sensor_reading",
    "Readings are paired: a before with no after cannot show a change, and a "
    "verifier that skipped the delta rule on a missing field would silently "
    "accept the weaker proof.",
    "malformed",
    lambda b: b["zones"][0]["proof"]["observations"][0].pop("sensor_after"),
)

_rej(
    "superseded_derivation_field_present",
    "`contact_type` is the field this contract exists to make unrepresentable. "
    "Unknown keys inside a zone are refused so a stale safety field cannot be "
    "silently ignored by a consumer that does not read it.",
    "malformed",
    lambda b: b["zones"][0]["actuator"].__setitem__("contact_type", "nc"),
)

# ── firmware profile: the mapping a device may actually act on ──────────────
#
# A manifest reference proves the firmware *claims* a relationship to a
# binding. It cannot prove the firmware holds the mapping that binding
# records, because a build system can embed a correct hash beside a wrong
# mapping. The device therefore receives the mapping itself, signed by the
# commissioning authority and bound to the binding hash.

_REFERENCE = base_binding()
_PUMP = _REFERENCE["zones"][1]


def firmware_profile(**overrides) -> dict:
    profile = {
        "v": 1,
        "binding_hash": digest(_REFERENCE),
        "binding_seq": _REFERENCE["binding_seq"],
        "device_id": DEVICE_ID,
        "firmware_device_id": _PUMP["actuator"]["identity"]["firmware_device_id"],
        "channel": _PUMP["actuator"]["identity"]["channel"],
        "commissioned_mapping": copy.deepcopy(
            _PUMP["actuator"]["commissioned_mapping"]
        ),
        "signing_key": "ed25519:" + pub_b64(COMMISSIONING_SEED),
    }
    profile.update(overrides)
    return profile


PROFILE_VERDICT_STAGE = {
    "malformed": "parses",
    "superseded_signer": "authority",
    "wrong_device": "device_binding",
    "profile_channel_mismatch": "device_binding",
    "unknown_signer": "key_selection",
    "anchor_collision": "key_selection",
    "bad_signature": "signature",
    "wrong_authority": "authority",
    "profile_binding_mismatch": "binding_match",
    "profile_mapping_mismatch": "mapping_match",
}


def profile_case(
    name,
    note,
    profile,
    seed=COMMISSIONING_SEED,
    reason=None,
    sig_valid=True,
    ctx_overrides=None,
):
    env = {"firmware_profile": profile, "signature": sign(profile, seed)}
    c = {
        "name": name,
        "note": note,
        "firmware_profile": profile,
        "verifier_context": {
            "firmware_device_id": _PUMP["actuator"]["identity"]["firmware_device_id"],
            "channel": _PUMP["actuator"]["identity"]["channel"],
            "accepted_binding_hash": digest(_REFERENCE),
            "accepted_binding_seq": _REFERENCE["binding_seq"],
            "expected_mapping": copy.deepcopy(
                _PUMP["actuator"]["commissioned_mapping"]
            ),
            "commissioning_anchor_current_hex": pub_hex(COMMISSIONING_SEED),
            "commissioning_anchor_previous_hex": pub_hex(PREVIOUS_SEED),
            "provisioning_anchor_hex": pub_hex(PROVISIONING_SEED),
        },
        "canonical_hex": canonical(profile).hex(),
        "canonical_sha256": digest(profile),
        "signature_b64": env["signature"].removeprefix("ed25519:"),
        "message_hex": canonical(env).hex(),
    }
    if ctx_overrides:
        c["verifier_context"].update(ctx_overrides)
    if reason:
        c["reason"] = reason
        c["stage"] = PROFILE_VERDICT_STAGE[reason]
        c["signature_valid"] = sig_valid
    return c


firmware_profile_cases = [
    profile_case(
        "profile_matches_the_accepted_binding",
        "The device holds the mapping itself, signed by the commissioning "
        "authority and bound to the binding hash. A runtime and a device that "
        "both verify this object cannot disagree about which coil state opens "
        "the circuit.",
        firmware_profile(),
    )
]

firmware_profile_reject_cases = [
    profile_case(
        "profile_mapping_disagrees_with_the_binding",
        "Correct binding hash, inverted mapping. This is the case a manifest "
        "reference cannot catch: the hashes match and the device drives the "
        "opposite coil state. Only carrying the mapping inside the signed "
        "object makes it detectable.",
        firmware_profile(
            commissioned_mapping={
                "open_protected_circuit": "de_energised",
                "close_protected_circuit": "energised",
                "de_energised_terminal_state": "open",
            }
        ),
        reason="profile_mapping_mismatch",
    ),
    profile_case(
        "profile_names_a_different_binding",
        "The mapping is right for a document that is not the one in force. The "
        "sequence still parses, so the refusal is the binding check rather than "
        "the grammar.",
        firmware_profile(binding_hash="sha256:" + "0" * 64),
        reason="profile_binding_mismatch",
    ),
    profile_case(
        "profile_binding_hash_is_malformed",
        "`binding_hash` is a lowercase sha256 digest. A free string would make "
        "the tie between a profile and the binding it came from unverifiable.",
        firmware_profile(binding_hash="the current one"),
        reason="malformed",
    ),
    profile_case(
        "profile_signing_key_is_malformed",
        "A key that is not 32 bytes of strict base64 is refused by the grammar, "
        "before any key can be selected.",
        firmware_profile(signing_key="ed25519:AAAA"),
        reason="malformed",
    ),
    profile_case(
        "profile_for_another_channel",
        "A profile is scoped to one channel on one device.",
        firmware_profile(channel="relay1"),
        reason="profile_channel_mismatch",
    ),
    profile_case(
        "profile_signed_by_the_provisioning_authority",
        "Same authority rule as the binding, and decided the same way: after "
        "the signature verifies, so a build system cannot commission a channel "
        "by signing its own profile and cannot manufacture the verdict either.",
        firmware_profile(signing_key="ed25519:" + pub_b64(PROVISIONING_SEED)),
        seed=PROVISIONING_SEED,
        reason="wrong_authority",
    ),
    profile_case(
        "profile_for_another_device",
        "A profile signed for one firmware device must never actuate another, "
        "the same rule inbound commands already enforce.",
        firmware_profile(firmware_device_id="ori-fw-0000ffff"),
        reason="wrong_device",
    ),
    profile_case(
        "profile_with_an_unknown_field",
        "The profile is a closed shape. An unrecognised key is refused rather "
        "than ignored, so a stale mapping field cannot ride along unread.",
        firmware_profile(contact_type="nc"),
        reason="malformed",
    ),
    profile_case(
        "profile_bad_signature",
        "Names the current commissioning key and is signed by someone who does "
        "not hold it. Exercises the profile's own signature stage, which the "
        "binding corpus cannot cover on its behalf.",
        firmware_profile(),
        seed=ROGUE_SEED,
        reason="bad_signature",
        sig_valid=False,
    ),
    profile_case(
        "profile_signed_by_the_previous_commissioning_generation",
        "Rotation applies to a profile exactly as it does to a binding: the "
        "previous generation verifies and does not sign. Reported as "
        "superseded rather than unknown, because dismissing it at key "
        "selection would describe our own rotated key as a stranger and hide "
        "that the profile was once legitimately signed.",
        firmware_profile(signing_key="ed25519:" + pub_b64(PREVIOUS_SEED)),
        seed=PREVIOUS_SEED,
        reason="superseded_signer",
    ),
    profile_case(
        "profile_anchors_are_identical_key_material",
        "A collision involving the previous generation is as fatal as one "
        "involving the current: if either commissioning anchor is the "
        "provisioning key, the separation the contract rests on does not "
        "exist for profiles either.",
        firmware_profile(),
        reason="anchor_collision",
        ctx_overrides={"commissioning_anchor_previous_hex": pub_hex(PROVISIONING_SEED)},
    ),
    profile_case(
        "profile_signing_key_is_not_an_anchor",
        "Self-consistent and signed by a key that is neither configured "
        "anchor, so no candidate can be selected and no signature is "
        "attempted.",
        firmware_profile(signing_key="ed25519:" + pub_b64(ROGUE_SEED)),
        seed=ROGUE_SEED,
        reason="unknown_signer",
    ),
]

# ── envelope: the wrapper, not only what it wraps ────────────────────────────
#
# A grammar that closes the signed object and leaves its container open is not
# closed. An unknown field beside the signature is unread; a signature of the
# wrong length reaches a verifier that may raise on it rather than refuse it.

_ENV_REF = base_binding()
_ENV_SIG = sign(_ENV_REF, COMMISSIONING_SEED)


def envelope_case(name, note, env, reason, ctx=None):
    return {
        "name": name,
        "note": note,
        "envelope": env,
        "verifier_context": ctx if ctx is not None else context(),
        "reason": reason,
        "stage": "parses",
        "canonical_hex": canonical(env).hex(),
    }


envelope_reject_cases = [
    envelope_case(
        "envelope_carries_an_unknown_field",
        "A field beside the signature is outside the signed bytes, so it is "
        "unauthenticated by construction. Ignoring it lets an intermediary add "
        "content a careless consumer might read.",
        {"binding": _ENV_REF, "signature": _ENV_SIG, "received_at_ms": 1800000000001},
        "malformed",
    ),
    envelope_case(
        "envelope_signature_absent",
        "An unsigned document is not a weakly signed one.",
        {"binding": _ENV_REF},
        "malformed",
    ),
    envelope_case(
        "envelope_signature_without_its_algorithm_prefix",
        "The wire encoding is `ed25519:<base64>`; a bare base64 string does not "
        "say what algorithm produced it.",
        {"binding": _ENV_REF, "signature": _ENV_SIG.removeprefix("ed25519:")},
        "malformed",
    ),
    envelope_case(
        "envelope_signature_is_not_valid_base64",
        "Refused by the grammar rather than by a decoder throwing inside verification.",
        {"binding": _ENV_REF, "signature": "ed25519:!!!!not base64!!!!"},
        "malformed",
    ),
    envelope_case(
        "envelope_signature_is_the_wrong_length",
        "Ed25519 signatures are 64 bytes. A value that was never a candidate "
        "authenticator is malformed rather than a failed authentication.",
        {
            "binding": _ENV_REF,
            "signature": "ed25519:" + base64.b64encode(b"\x00" * 32).decode(),
        },
        "malformed",
    ),
    envelope_case(
        "envelope_signature_with_non_canonical_padding",
        "The same 64 bytes spelled differently. The rule that applies to a "
        "public key applies to a signature for the same reason.",
        {
            "binding": _ENV_REF,
            "signature": "ed25519:" + non_canonical(_ENV_SIG.removeprefix("ed25519:")),
        },
        "malformed",
    ),
    envelope_case(
        "envelope_binding_is_not_an_object",
        "The wrapper names one document; a string is not one.",
        {"binding": "see attached", "signature": _ENV_SIG},
        "malformed",
    ),
]

# The profile envelope is a second wire shape, and a corpus that exercises the
# rule on only one of them cannot tell a conforming implementation from one
# that validates bindings strictly and profiles loosely. The device-side
# consumer is the one written in C, so it is the worse of the two to leave
# unexercised.
_PROFILE_ENV = firmware_profile()
_PROFILE_ENV_SIG = sign(_PROFILE_ENV, COMMISSIONING_SEED)
_PROFILE_ENV_CTX = profile_case("_", "_", firmware_profile())["verifier_context"]

envelope_reject_cases += [
    envelope_case(
        "profile_envelope_carries_an_unknown_field",
        "The same rule as the binding envelope, on the shape a firmware device "
        "actually receives. A field outside the signed bytes is unauthenticated "
        "by construction whichever document it accompanies.",
        {
            "firmware_profile": _PROFILE_ENV,
            "signature": _PROFILE_ENV_SIG,
            "provisioned_at_ms": 1800000000001,
        },
        "malformed",
        ctx=_PROFILE_ENV_CTX,
    ),
    envelope_case(
        "profile_envelope_signature_is_not_valid_base64",
        "Refused by the grammar rather than by a decoder throwing inside "
        "verification, on the constrained consumer where that distinction "
        "matters most.",
        {
            "firmware_profile": _PROFILE_ENV,
            "signature": "ed25519:!!!!not base64!!!!",
        },
        "malformed",
        ctx=_PROFILE_ENV_CTX,
    ),
    envelope_case(
        "profile_envelope_signature_with_non_canonical_padding",
        "The same 64 bytes spelled differently, in the profile envelope.",
        {
            "firmware_profile": _PROFILE_ENV,
            "signature": "ed25519:"
            + non_canonical(_PROFILE_ENV_SIG.removeprefix("ed25519:")),
        },
        "malformed",
        ctx=_PROFILE_ENV_CTX,
    ),
    envelope_case(
        "profile_envelope_signature_absent",
        "An unsigned profile is not a weakly signed one.",
        {"firmware_profile": _PROFILE_ENV},
        "malformed",
        ctx=_PROFILE_ENV_CTX,
    ),
]

corpus = {
    "contract": "ori-specs/commissioned-safety-binding/v1.md",
    "version": 1,
    "comment": (
        "Cross-language golden vectors for the commissioned safety binding. A "
        "producer must emit these exact canonical bytes; an independent "
        "verifier in a different language must accept every case in 'cases' "
        "and refuse every case in 'reject_cases' with the declared reason, "
        "evaluated against the declared verifier_context. Signed with the "
        "TEST-ONLY seeds below - never use them in production. The "
        "commissioning and provisioning seeds are deliberately distinct: a "
        "corpus sharing one key could not express wrong_authority at all."
    ),
    "acceptance_order": [
        "parses",
        "device_id",
        "key_selection",
        "signature",
        "authority",
        "freshness",
        "mapping_self_consistency",
        "proof_consistency",
        "bounds",
        "disambiguation",
        "inventory",
        "activation_posture",
    ],
    "commissioning_test_seed_hex": COMMISSIONING_SEED.hex(),
    "commissioning_public_key_hex": pub_hex(COMMISSIONING_SEED),
    "commissioning_public_key_b64": pub_b64(COMMISSIONING_SEED),
    "provisioning_test_seed_hex": PROVISIONING_SEED.hex(),
    "provisioning_public_key_hex": pub_hex(PROVISIONING_SEED),
    "provisioning_public_key_b64": pub_b64(PROVISIONING_SEED),
    "previous_commissioning_test_seed_hex": PREVIOUS_SEED.hex(),
    "previous_commissioning_public_key_hex": pub_hex(PREVIOUS_SEED),
    "rogue_test_seed_hex": ROGUE_SEED.hex(),
    "rogue_public_key_hex": pub_hex(ROGUE_SEED),
    "signature_encoding": "ed25519:<standard-base64-64-byte-signature>",
    "canonical_form": "ori-specs/gateway-mqtt-canonical-json/v1.md, numbers additionally constrained to the D-011 agreement zone",
    "signed_over": "canonical bytes of the 'binding' object, not the envelope",
    "authority_rule": "binding.signing_key is compared against configured anchors as raw key material before the signature is verified; signer_id is an audit label and is never an authority input",
    "firmware_profile_comment": (
        "The mapping a firmware device may act on. Signed by the commissioning "
        "authority and bound to the binding hash, because a manifest reference "
        "proves only that firmware claims a relationship to a binding - a build "
        "system can embed a correct hash beside a wrong mapping."
    ),
    "firmware_profile_acceptance_order": [
        "parses",
        "device_binding",
        "key_selection",
        "signature",
        "authority",
        "binding_match",
        "mapping_match",
    ],
    "envelope_comment": (
        "The wire wrapper around a signed document. Closed like everything "
        "else: signature encoding and decoded length are grammar, and an "
        "unknown field beside the signature is outside the signed bytes and "
        "therefore unauthenticated by construction."
    ),
    "cases": accept_cases,
    "reject_cases": reject_cases,
    "envelope_reject_cases": envelope_reject_cases,
    "firmware_profile_cases": firmware_profile_cases,
    "firmware_profile_reject_cases": firmware_profile_reject_cases,
}


def _cli() -> int:
    """Authoring tool, deliberately awkward to fire by accident.

    There is no default write path. A consumer repository must not be able to
    regenerate its own expectations casually: the whole point of a vendored
    corpus is that it came from the contract, and a tool that silently
    overwrites it turns a conformance fixture into a self-portrait.

    `--check` compares in memory and touches nothing. `--output` writes, and
    has to be asked for.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--check",
        metavar="CORPUS",
        help="compare the generated bytes against CORPUS; write nothing",
    )
    group.add_argument(
        "--output",
        metavar="PATH",
        help="write the corpus to PATH (deliberate authoring only)",
    )
    args = parser.parse_args()

    body = (json.dumps(corpus, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    digest = hashlib.sha256(body).hexdigest()

    if args.check:
        existing = pathlib.Path(args.check).read_bytes()
        if existing == body:
            print(f"{args.check}: reproduces byte-for-byte ({digest})")
            return 0
        print(f"{args.check}: DIFFERS from generated bytes", file=sys.stderr)
        print(f"  on disk:   {hashlib.sha256(existing).hexdigest()}", file=sys.stderr)
        print(f"  generated: {digest}", file=sys.stderr)
        print(
            "  A corpus change is a contract change. Update ori-specs first, "
            "then re-vendor.",
            file=sys.stderr,
        )
        return 1

    pathlib.Path(args.output).write_bytes(body)
    print(f"accept={len(accept_cases)} reject={len(reject_cases)}")
    print(f"wrote {args.output}")
    print("sha256:", digest)
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
