# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Verification of device-signed firmware telemetry (evidence Layer 1).

Implements the consumer side of ``ori-specs/firmware-telemetry/v1.md``:
provisioning anchors, capability-manifest pinning, Ed25519 envelope
verification, ``(boot_id, seq)`` freshness, and receiver-derived trust
grades. The canonical JSON rules here are the byte-level signing
contract shared with the C producer (ori-edge-firmware) and the private
evidence-chain artifact; the shared golden vectors are committed under
``tests/fixtures`` and any divergence is a fleet-wide signature break.

Grade semantics (never signed by firmware — receiver-derived):

* ``attested``      — signature valid, fresh, posture ``sealed_flash``
  or ``hardware_key``.
* ``attested_dev``  — signature valid and fresh, but posture is
  ``development``; never eligible for insurer-facing export.
* ``unattested``    — no device signature (legacy adapters); outside
  this module's scope by definition.
* ``rejected``      — any verification failure; fail closed, construct
  no ``SensorReading``, and record the reason code.

Heartbeat envelopes (``readings: []``) prove liveness, posture,
freshness, and manifest binding; they advance the high-water mark but
never construct a ``SensorReading`` and never trigger reasoning or
actions.

Canonical number constraint:
non-integer numbers must be exactly zero or have magnitude in
``[1e-4, 1e16)`` — the empirically verified zone where CPython,
``serde_json``, and the C serializer produce identical bytes. Values
outside the zone are invalid by contract.

Chain-append atomicity with the high-water-mark advance remains the
verifier-grade target (see DECISIONS.md); the registry lives in the
runtime state store and its advance is a guarded, strictly monotonic
UPDATE.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Mapping

__all__ = [
    "FirmwareFaultVerification",
    "FirmwareVerificationError",
    "TelemetryVerification",
    "canonical_json_bytes",
    "manifest_channel_map",
    "verify_fault_message",
    "verify_manifest_message",
    "verify_telemetry_message",
]

SUPPORTED_ALG = "ed25519"
SIGNATURE_PREFIX = "ed25519:"
JSON_SAFE_INT_MAX = 9007199254740991  # 2**53 - 1

POSTURES = ("development", "sealed_flash", "hardware_key")
PRODUCTION_POSTURES = ("sealed_flash", "hardware_key")
SUPPORTED_TRANSPORTS = frozenset({"mqtt", "uart", "rs485"})
SUPPORTED_CHANNEL_PROTOCOLS = frozenset(
    {"adc", "gpio", "i2c", "uart", "modbus_rtu", "rs232", "pulse", "one_wire"}
)
SUPPORTED_ACTION_AUTHORITIES = frozenset({"local_interlock_only", "runtime_commanded"})
SUPPORTED_FIRMWARE_ACTIONS = frozenset({"relay_open", "relay_close"})

GRADE_ATTESTED = "attested"
GRADE_ATTESTED_DEV = "attested_dev"
GRADE_REJECTED = "rejected"

# Error vocabulary from the contract's error-semantics table.
ERR_UNKNOWN_DEVICE = "unknown_device"
ERR_INVALID_SIGNATURE_FORMAT = "invalid_signature_format"
ERR_PUBLIC_KEY_MISMATCH = "public_key_mismatch"
ERR_SIGNATURE_FAILED = "signature_verification_failed"
ERR_CAPABILITY_HASH_MISMATCH = "capability_hash_mismatch"
ERR_SEQUENCE_REPLAY = "sequence_replay"
ERR_BOOT_ROLLBACK = "boot_rollback"
ERR_UNSUPPORTED_CHANNEL = "unsupported_channel"
ERR_INVALID_POSTURE = "invalid_posture"
ERR_INVALID_READING = "invalid_reading"
ERR_INVALID_ENVELOPE = "invalid_envelope"
ERR_UNSUPPORTED_ALG = "unsupported_alg"
ERR_DEVICE_REVOKED = "device_revoked"
ERR_DEVICE_NOT_APPROVED = "device_not_approved"
# ori-specs/device-provisioning/v1.md: a changed key may never arrive
# through ordinary registration.
ERR_KEY_CHANGE_REQUIRES_REPROVISIONING = "key_change_requires_reprovisioning"
# Re-provisioning must actually replace the key. Submitting the current key
# changes nothing, and returning to a previously used one would make
# rotation reversible by whoever still holds the old key.
ERR_SAME_KEY_NOT_A_ROTATION = "same_key_not_a_rotation"
ERR_KEY_EPOCH_REUSED = "key_epoch_reused"


def key_epoch_id(*, device_id: str, public_key_b64: str) -> str:
    """The epoch identifier for a device identity and its key.

    ori-specs/device-provisioning/v1.md. Deterministically derived so two
    independent stores compute the same value without coordinating —
    that is what makes "both accepted the same epoch" checkable rather
    than asserted. Changes ONLY when the device key changes, which is why
    it is the epoch telemetry replay state is scoped to.
    """
    return (
        "sha256:"
        + hashlib.sha256(
            canonical_json_bytes(
                {"device_id": device_id, "public_key_b64": public_key_b64, "v": 1}
            )
        ).hexdigest()
    )


def anchor_epoch_id(
    *,
    device_id: str,
    public_key_b64: str,
    posture: str,
    capability_hash: str,
) -> str:
    """The epoch identifier for a whole anchor.

    Changes when the key, posture, or capability hash changes. Posture is
    included because a device that becomes ``sealed_flash`` is materially
    a different trust proposition from the same device in
    ``development``, even with an unchanged key and manifest.

    This is the value cross-store agreement is expressed in.
    """
    return (
        "sha256:"
        + hashlib.sha256(
            canonical_json_bytes(
                {
                    "capability_hash": capability_hash,
                    "device_id": device_id,
                    "posture": posture,
                    "public_key_b64": public_key_b64,
                    "v": 1,
                }
            )
        ).hexdigest()
    )


FIRMWARE_FAULT_CODES = frozenset(
    {
        "command_rejected",
        "interlock_input_fault",
        "interlock_recovered",
        "interlock_tripped",
        "sensor_fault",
        "brownout_relay_fault",
        "ingress_degraded",
        # firmware-telemetry/v1: reported late, from a latch outside the store
        # that failed, so its own (boot_id, seq) describe when it was reported
        # rather than what was lost. Absence proves nothing — a device whose
        # storage is failing badly enough may never emit it — and sequence
        # gaps are not a substitute signal, because reservation ceilings make
        # gaps expected across a reboot.
        "storage_degraded",
    }
)

# firmware-commands/v1: command rejection details are a closed wire
# vocabulary. Accepting an invented token would make a valid signature look
# contract-compliant even though no conforming firmware command verifier can
# emit it.
COMMAND_REJECTION_VERDICTS = frozenset(
    {
        "malformed",
        "wrong_device",
        "bad_signature",
        "replayed",
        "capability_mismatch",
        "unknown_action",
        "storage_failure",
    }
)

# firmware-telemetry/v1 constrains ``detail`` to one of four degrees, and "not
# a closed set" does not mean "anything goes". Each code is validated as far as
# its category allows -- no further, and no less:
#
#   closed set    exact membership (below)
#   context-bound interlock rule name, known only from the pinned manifest
#   open          sensor_fault: no vocabulary can anticipate a future driver
#
# The remaining codes are absent on purpose. In particular, firmware currently
# emits brownout details as relay_err_<n>, but merged v1 did not make that
# grammar a receiver rejection rule. Tightening it here would reject payloads
# that v1 previously accepted and therefore requires a new major contract.
CLOSED_FAULT_DETAILS: dict[str, frozenset[str]] = {
    "command_rejected": COMMAND_REJECTION_VERDICTS,
    "ingress_degraded": frozenset(
        {
            "inbound_overflow",
            "subscribe_failed",
            "anchor_persist_failed",
            "mqtt_provision_epoch_failed",
            "provisioning_serial_io_failed",
            "provisioning_serial_overflow",
        }
    ),
    "storage_degraded": frozenset({"buffer_write_failed", "buffer_mount_failed"}),
}

# firmware-telemetry/v1: ``subject`` and ``detail`` are fleet-safe tokens
# bounded at 63 characters (the producer's 64-byte buffers include the
# NUL). The receiver enforces the same bound as the producer: accepting a
# shape the firmware could never emit would let a forged-but-unsigned
# field shape through the contract, and would let the two sides disagree
# about what is representable.
FAULT_TOKEN_MAX_LEN = 63
_FLEET_TOKEN_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
)


class FirmwareVerificationError(Exception):
    """A verification failure with a contract error code.

    Failures must be auditable and must never be downgraded to
    low-quality readings.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _check_canonical_numbers(obj: Any, path: str = "$") -> None:
    if isinstance(obj, bool):
        return
    if isinstance(obj, int):
        if abs(obj) > JSON_SAFE_INT_MAX:
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, f"integer outside JSON-safe range at {path}"
            )
    elif isinstance(obj, float):
        if not math.isfinite(obj):
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, f"non-finite number at {path}"
            )
        magnitude = abs(obj)
        if magnitude != 0.0 and not (1e-4 <= magnitude < 1e16):
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE,
                f"float outside the cross-language canonical zone at {path}",
            )
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise FirmwareVerificationError(
                    ERR_INVALID_ENVELOPE, f"non-string object key at {path}"
                )
            _check_canonical_numbers(value, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            _check_canonical_numbers(value, f"{path}[{index}]")


def canonical_json_bytes(obj: Any) -> bytes:
    """Canonical JSON bytes of *obj* per the Layer 1 contract.

    Keys sorted at every nesting level, no whitespace, UTF-8, RFC 8259
    escapes, no NaN/Infinity, numbers restricted to the cross-language
    agreement zone.
    """
    _check_canonical_numbers(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _decode_public_key(public_key_b64: str) -> bytes:
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FirmwareVerificationError(ERR_PUBLIC_KEY_MISMATCH, str(exc)) from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != public_key_b64:
        raise FirmwareVerificationError(
            ERR_PUBLIC_KEY_MISMATCH, "public key is not canonical 32-byte base64"
        )
    return raw


def _decode_wire_signature(signature: str) -> bytes:
    if not isinstance(signature, str) or not signature.startswith(SIGNATURE_PREFIX):
        raise FirmwareVerificationError(
            ERR_INVALID_SIGNATURE_FORMAT, "signature must use ed25519:<base64>"
        )
    payload = signature[len(SIGNATURE_PREFIX) :]
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FirmwareVerificationError(ERR_INVALID_SIGNATURE_FORMAT, str(exc)) from exc
    if len(raw) != 64:
        raise FirmwareVerificationError(
            ERR_INVALID_SIGNATURE_FORMAT, "decoded signature must be 64 bytes"
        )
    # Reject non-canonical (malleable) encodings: re-encoding must
    # reproduce the wire payload exactly, including padding.
    if base64.b64encode(raw).decode("ascii") != payload:
        raise FirmwareVerificationError(
            ERR_INVALID_SIGNATURE_FORMAT, "signature base64 is not canonical"
        )
    return raw


def _verify_signature(public_key: bytes, message: bytes, signature: bytes) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - hard runtime dependency
        raise FirmwareVerificationError(
            ERR_SIGNATURE_FAILED, "cryptography Ed25519 support unavailable"
        ) from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature as exc:
        raise FirmwareVerificationError(
            ERR_SIGNATURE_FAILED, "signature does not verify"
        ) from exc


def _require_str(obj: dict[str, Any], key: str, code: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise FirmwareVerificationError(code, f"missing or invalid {key}")
    return value


def _require_int(obj: dict[str, Any], key: str, code: str) -> int:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FirmwareVerificationError(code, f"missing or invalid {key}")
    if value > JSON_SAFE_INT_MAX:
        raise FirmwareVerificationError(code, f"{key} outside JSON-safe range")
    return value


def _require_list(obj: dict[str, Any], key: str, code: str) -> list[Any]:
    value = obj.get(key)
    if not isinstance(value, list):
        raise FirmwareVerificationError(code, f"missing or invalid {key}")
    return value


def _validate_transport_list(manifest: dict[str, Any]) -> None:
    transports = _require_list(manifest, "transports", ERR_INVALID_ENVELOPE)
    if not transports:
        raise FirmwareVerificationError(
            ERR_INVALID_ENVELOPE, "transports cannot be empty"
        )
    for transport in transports:
        if not isinstance(transport, str) or transport not in SUPPORTED_TRANSPORTS:
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, f"unsupported transport {transport!r}"
            )


def _validate_manifest_actions(manifest: dict[str, Any]) -> None:
    actions = _require_list(manifest, "actions", ERR_INVALID_ENVELOPE)
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, f"action {index} is not an object"
            )
        name = _require_str(action, "action", ERR_INVALID_ENVELOPE)
        if name not in SUPPORTED_FIRMWARE_ACTIONS:
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, f"unsupported firmware action {name!r}"
            )
        _require_str(action, "channel", ERR_INVALID_ENVELOPE)
        authority = _require_str(action, "authority", ERR_INVALID_ENVELOPE)
        if authority not in SUPPORTED_ACTION_AUTHORITIES:
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE,
                f"action {name!r} has unsupported authority {authority!r}",
            )


def manifest_channel_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return a normalized channel map from a verified manifest shape.

    The result is the runtime's durable contract for what the firmware
    device is allowed to report. Telemetry readings must match by
    channel, sensor_type, and unit; quality must meet the manifest's
    floor when one is declared.
    """
    channels = _require_list(manifest, "channels", ERR_INVALID_ENVELOPE)
    if not channels:
        raise FirmwareVerificationError(
            ERR_INVALID_ENVELOPE, "channels cannot be empty"
        )

    out: dict[str, dict[str, Any]] = {}
    allowed_keys = {
        "channel",
        "sensor_type",
        "unit",
        "protocol",
        "source",
        "quality_floor",
    }
    for index, channel in enumerate(channels):
        if not isinstance(channel, dict):
            raise FirmwareVerificationError(
                ERR_UNSUPPORTED_CHANNEL, f"channel {index} is not an object"
            )
        if set(channel) != allowed_keys:
            raise FirmwareVerificationError(
                ERR_UNSUPPORTED_CHANNEL, f"channel {index} has unexpected fields"
            )
        name = _require_str(channel, "channel", ERR_UNSUPPORTED_CHANNEL)
        if name in out:
            raise FirmwareVerificationError(
                ERR_UNSUPPORTED_CHANNEL, f"duplicate channel {name!r}"
            )
        sensor_type = _require_str(channel, "sensor_type", ERR_INVALID_READING)
        unit = _require_str(channel, "unit", ERR_INVALID_READING)
        protocol = _require_str(channel, "protocol", ERR_UNSUPPORTED_CHANNEL)
        if protocol not in SUPPORTED_CHANNEL_PROTOCOLS:
            raise FirmwareVerificationError(
                ERR_UNSUPPORTED_CHANNEL, f"unsupported protocol {protocol!r}"
            )
        source = _require_str(channel, "source", ERR_UNSUPPORTED_CHANNEL)
        quality_floor = channel.get("quality_floor")
        if (
            isinstance(quality_floor, bool)
            or not isinstance(quality_floor, (int, float))
            or not math.isfinite(float(quality_floor))
            or not (0.0 <= float(quality_floor) <= 1.0)
        ):
            raise FirmwareVerificationError(
                ERR_INVALID_READING, f"invalid quality_floor for channel {name!r}"
            )
        out[name] = {
            "sensor_type": sensor_type,
            "unit": unit,
            "protocol": protocol,
            "source": source,
            "quality_floor": float(quality_floor),
        }
    return out


def _validate_manifest_contract(manifest: dict[str, Any]) -> None:
    _require_str(manifest, "firmware_version", ERR_INVALID_ENVELOPE)
    _require_str(manifest, "board_profile", ERR_INVALID_ENVELOPE)
    _require_str(manifest, "device_mode", ERR_INVALID_ENVELOPE)
    _require_str(manifest, "key_storage", ERR_INVALID_ENVELOPE)
    _validate_transport_list(manifest)
    manifest_channel_map(manifest)
    _validate_manifest_actions(manifest)
    _require_list(manifest, "interlocks", ERR_INVALID_ENVELOPE)


def verify_manifest_message(
    message: dict[str, Any],
    *,
    anchor_device_id: str,
    anchor_public_key_b64: str,
) -> str:
    """Verify a signed capability-manifest message against a
    provisioning anchor and return its canonical ``sha256:<hex>`` hash.

    Rejects (fail closed) on device-id or public-key mismatch with the
    anchor, hash mismatch, signature failure, unsupported algorithm, or
    a posture whose boolean security fields disagree.
    """
    if not isinstance(message, dict) or not isinstance(message.get("manifest"), dict):
        raise FirmwareVerificationError(ERR_INVALID_ENVELOPE, "missing manifest object")
    manifest: dict[str, Any] = message["manifest"]

    if manifest.get("v") != 1:
        raise FirmwareVerificationError(
            ERR_INVALID_ENVELOPE, "unsupported manifest version"
        )
    if manifest.get("alg") != SUPPORTED_ALG:
        raise FirmwareVerificationError(ERR_UNSUPPORTED_ALG, str(manifest.get("alg")))
    if _require_str(manifest, "device_id", ERR_INVALID_ENVELOPE) != anchor_device_id:
        raise FirmwareVerificationError(
            ERR_UNKNOWN_DEVICE, "manifest device_id mismatch"
        )
    if (
        _require_str(manifest, "public_key_b64", ERR_PUBLIC_KEY_MISMATCH)
        != anchor_public_key_b64
    ):
        raise FirmwareVerificationError(
            ERR_PUBLIC_KEY_MISMATCH, "manifest public key does not match anchor"
        )

    posture = _require_str(manifest, "posture", ERR_INVALID_POSTURE)
    if posture not in POSTURES:
        raise FirmwareVerificationError(ERR_INVALID_POSTURE, posture)
    if posture in PRODUCTION_POSTURES:
        if not (
            manifest.get("secure_boot_enabled") is True
            and manifest.get("flash_encryption_enabled") is True
        ):
            raise FirmwareVerificationError(
                ERR_INVALID_POSTURE,
                "production posture claimed without secure boot + flash encryption",
            )
    _validate_manifest_contract(manifest)

    canonical = canonical_json_bytes(manifest)
    manifest_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
    claimed_hash = message.get("manifest_hash")
    if claimed_hash != manifest_hash:
        raise FirmwareVerificationError(
            ERR_CAPABILITY_HASH_MISMATCH, "manifest_hash mismatch"
        )

    public_key = _decode_public_key(anchor_public_key_b64)
    signature = _decode_wire_signature(str(message.get("signature", "")))
    _verify_signature(public_key, canonical, signature)
    return manifest_hash


@dataclass
class TelemetryVerification:
    """Outcome of one telemetry-message verification."""

    grade: str
    device_id: str
    boot_id: int = 0
    seq: int = 0
    posture: str = ""
    capability_hash: str = ""
    device_uptime_ms: int = 0
    is_heartbeat: bool = False
    readings: list[dict[str, Any]] = field(default_factory=list)
    error_code: str = ""
    error_detail: str = ""

    @property
    def accepted(self) -> bool:
        return self.grade in (GRADE_ATTESTED, GRADE_ATTESTED_DEV)


@dataclass
class FirmwareFaultVerification:
    """Outcome of one signed firmware fault-event verification."""

    grade: str
    device_id: str
    boot_id: int = 0
    seq: int = 0
    posture: str = ""
    device_uptime_ms: int = 0
    code: str = ""
    subject: str = ""
    detail: str = ""
    error_code: str = ""
    error_detail: str = ""

    @property
    def accepted(self) -> bool:
        return self.grade in (GRADE_ATTESTED, GRADE_ATTESTED_DEV)


def _validate_reading(
    reading: Any,
    index: int,
    accepted_channels: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    if not isinstance(reading, dict):
        raise FirmwareVerificationError(
            ERR_INVALID_READING, f"reading {index} is not an object"
        )
    allowed_keys = {"channel", "sensor_type", "unit", "value", "quality"}
    if set(reading.keys()) != allowed_keys:
        raise FirmwareVerificationError(
            ERR_INVALID_READING, f"reading {index} has unexpected fields"
        )
    channel = _require_str(reading, "channel", ERR_UNSUPPORTED_CHANNEL)
    sensor_type = _require_str(reading, "sensor_type", ERR_INVALID_READING)
    unit = _require_str(reading, "unit", ERR_INVALID_READING)
    value = reading.get("value")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FirmwareVerificationError(
            ERR_INVALID_READING, f"reading {index} value not numeric"
        )
    if not math.isfinite(float(value)):
        raise FirmwareVerificationError(
            ERR_INVALID_READING, f"reading {index} value not finite"
        )
    quality = reading.get("quality")
    if isinstance(quality, bool) or not isinstance(quality, (int, float)):
        raise FirmwareVerificationError(
            ERR_INVALID_READING, f"reading {index} quality invalid"
        )
    if not (0.0 <= float(quality) <= 1.0):
        raise FirmwareVerificationError(
            ERR_INVALID_READING, f"reading {index} quality out of range"
        )
    if accepted_channels is not None:
        expected = accepted_channels.get(channel)
        if expected is None:
            raise FirmwareVerificationError(
                ERR_UNSUPPORTED_CHANNEL,
                f"reading {index} channel {channel!r} is not in the accepted manifest",
            )
        if sensor_type != expected.get("sensor_type") or unit != expected.get("unit"):
            raise FirmwareVerificationError(
                ERR_INVALID_READING,
                f"reading {index} does not match the accepted manifest channel",
            )
        quality_floor = expected.get("quality_floor")
        if quality_floor is not None and float(quality) < float(quality_floor):
            raise FirmwareVerificationError(
                ERR_INVALID_READING,
                f"reading {index} quality below manifest floor",
            )
    return {
        "channel": channel,
        "sensor_type": sensor_type,
        "unit": unit,
        "value": float(value),
        "quality": float(quality),
    }


def verify_telemetry_message(
    message: dict[str, Any],
    *,
    anchor_device_id: str,
    anchor_public_key_b64: str,
    anchor_posture: str,
    accepted_manifest_hash: str,
    last_boot_id: int,
    last_seq: int,
    approved: bool = True,
    revoked: bool = False,
    accepted_channels: Mapping[str, Mapping[str, Any]] | None = None,
) -> TelemetryVerification:
    """Verify one signed telemetry message per the contract's consumer
    flow. Never raises for contract violations: returns a ``rejected``
    verification carrying the error code, so the caller can raise a
    fault event and record the rejection without exceptions steering
    control flow on the hot path.
    """

    def rejected(code: str, detail: str = "") -> TelemetryVerification:
        return TelemetryVerification(
            grade=GRADE_REJECTED,
            device_id=anchor_device_id,
            error_code=code,
            error_detail=detail,
        )

    try:
        if revoked:
            raise FirmwareVerificationError(ERR_DEVICE_REVOKED)
        if not approved:
            raise FirmwareVerificationError(ERR_DEVICE_NOT_APPROVED)
        if not isinstance(message, dict) or not isinstance(
            message.get("envelope"), dict
        ):
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, "missing envelope object"
            )
        envelope: dict[str, Any] = message["envelope"]

        if envelope.get("v") != 1:
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, "unsupported envelope version"
            )
        if envelope.get("alg") != SUPPORTED_ALG:
            raise FirmwareVerificationError(
                ERR_UNSUPPORTED_ALG, str(envelope.get("alg"))
            )
        if (
            _require_str(envelope, "device_id", ERR_INVALID_ENVELOPE)
            != anchor_device_id
        ):
            raise FirmwareVerificationError(
                ERR_UNKNOWN_DEVICE, "envelope device_id mismatch"
            )

        capability_hash = _require_str(
            envelope, "capability_hash", ERR_CAPABILITY_HASH_MISMATCH
        )
        if capability_hash != accepted_manifest_hash:
            # Capability drift: the device is treated as unapproved
            # until an operator explicitly re-approves it.
            raise FirmwareVerificationError(
                ERR_CAPABILITY_HASH_MISMATCH,
                "capability hash does not match pinned manifest",
            )

        posture = _require_str(envelope, "posture", ERR_INVALID_POSTURE)
        if posture not in POSTURES:
            raise FirmwareVerificationError(ERR_INVALID_POSTURE, posture)
        if posture != anchor_posture:
            # A device must not upgrade (or change) its own grade by
            # claiming a posture other than the provisioned one.
            raise FirmwareVerificationError(
                ERR_INVALID_POSTURE, "posture does not match provisioning anchor"
            )

        boot_id = _require_int(envelope, "boot_id", ERR_INVALID_ENVELOPE)
        seq = _require_int(envelope, "seq", ERR_INVALID_ENVELOPE)
        uptime = _require_int(envelope, "device_uptime_ms", ERR_INVALID_ENVELOPE)
        if "emitted_at_ms" not in envelope:
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, "missing emitted_at_ms"
            )
        emitted = envelope["emitted_at_ms"]
        if emitted is not None and (
            isinstance(emitted, bool) or not isinstance(emitted, int)
        ):
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, "invalid emitted_at_ms"
            )

        readings_raw = envelope.get("readings")
        if not isinstance(readings_raw, list):
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, "readings must be an array"
            )
        readings = [
            _validate_reading(r, i, accepted_channels)
            for i, r in enumerate(readings_raw)
        ]

        # Signature over the canonical envelope bytes, against the
        # anchored key only — never a key carried in the message.
        canonical = canonical_json_bytes(envelope)
        public_key = _decode_public_key(anchor_public_key_b64)
        signature = _decode_wire_signature(str(message.get("signature", "")))
        _verify_signature(public_key, canonical, signature)

        # Freshness after signature: a rejected counter on a validly
        # signed envelope is a replay signal worth recording as such.
        if boot_id < last_boot_id:
            raise FirmwareVerificationError(
                ERR_BOOT_ROLLBACK, f"boot_id {boot_id} < {last_boot_id}"
            )
        if seq <= last_seq:
            raise FirmwareVerificationError(
                ERR_SEQUENCE_REPLAY, f"seq {seq} <= {last_seq}"
            )

        grade = GRADE_ATTESTED if posture in PRODUCTION_POSTURES else GRADE_ATTESTED_DEV
        return TelemetryVerification(
            grade=grade,
            device_id=anchor_device_id,
            boot_id=boot_id,
            seq=seq,
            posture=posture,
            capability_hash=capability_hash,
            device_uptime_ms=uptime,
            is_heartbeat=len(readings) == 0,
            readings=readings,
        )
    except FirmwareVerificationError as exc:
        return rejected(exc.code, exc.detail)


def verify_fault_message(
    message: dict[str, Any],
    *,
    anchor_device_id: str,
    anchor_public_key_b64: str,
    anchor_posture: str,
    accepted_manifest_hash: str,
    last_boot_id: int,
    last_seq: int,
    approved: bool = True,
    revoked: bool = False,
) -> FirmwareFaultVerification:
    """Verify one signed firmware fault event.

    Fault events share the telemetry freshness stream and signature
    contract but never become ``SensorReading`` objects. They are
    evidence about a device-side refusal, suspension, or backstop.
    """

    def rejected(code: str, detail: str = "") -> FirmwareFaultVerification:
        return FirmwareFaultVerification(
            grade=GRADE_REJECTED,
            device_id=anchor_device_id,
            error_code=code,
            error_detail=detail,
        )

    try:
        if revoked:
            raise FirmwareVerificationError(ERR_DEVICE_REVOKED)
        if not approved:
            raise FirmwareVerificationError(ERR_DEVICE_NOT_APPROVED)
        if not isinstance(message, dict) or not isinstance(message.get("fault"), dict):
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, "missing fault object"
            )
        fault: dict[str, Any] = message["fault"]

        allowed_keys = {
            "v",
            "alg",
            "device_id",
            "boot_id",
            "seq",
            "capability_hash",
            "posture",
            "device_uptime_ms",
            "code",
            "subject",
            "detail",
        }
        if set(fault) != allowed_keys:
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, "fault object has unexpected fields"
            )
        if fault.get("v") != 1:
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, "unsupported fault version"
            )
        if fault.get("alg") != SUPPORTED_ALG:
            raise FirmwareVerificationError(ERR_UNSUPPORTED_ALG, str(fault.get("alg")))
        if _require_str(fault, "device_id", ERR_INVALID_ENVELOPE) != anchor_device_id:
            raise FirmwareVerificationError(
                ERR_UNKNOWN_DEVICE, "fault device_id mismatch"
            )

        capability_hash = _require_str(
            fault, "capability_hash", ERR_CAPABILITY_HASH_MISMATCH
        )
        if capability_hash != accepted_manifest_hash:
            raise FirmwareVerificationError(
                ERR_CAPABILITY_HASH_MISMATCH,
                "capability hash does not match pinned manifest",
            )

        posture = _require_str(fault, "posture", ERR_INVALID_POSTURE)
        if posture not in POSTURES:
            raise FirmwareVerificationError(ERR_INVALID_POSTURE, posture)
        if posture != anchor_posture:
            raise FirmwareVerificationError(
                ERR_INVALID_POSTURE, "posture does not match provisioning anchor"
            )

        boot_id = _require_int(fault, "boot_id", ERR_INVALID_ENVELOPE)
        seq = _require_int(fault, "seq", ERR_INVALID_ENVELOPE)
        uptime = _require_int(fault, "device_uptime_ms", ERR_INVALID_ENVELOPE)
        code = _require_str(fault, "code", ERR_INVALID_ENVELOPE)
        if code not in FIRMWARE_FAULT_CODES:
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, f"unsupported fault code {code!r}"
            )
        subject = fault.get("subject")
        detail = fault.get("detail")
        if not isinstance(subject, str) or not isinstance(detail, str):
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE, "fault subject and detail must be strings"
            )
        for _name, _token in (("subject", subject), ("detail", detail)):
            if len(_token) > FAULT_TOKEN_MAX_LEN:
                raise FirmwareVerificationError(
                    ERR_INVALID_ENVELOPE,
                    f"fault {_name} exceeds {FAULT_TOKEN_MAX_LEN} characters",
                )
            if not _FLEET_TOKEN_CHARS.issuperset(_token):
                raise FirmwareVerificationError(
                    ERR_INVALID_ENVELOPE,
                    f"fault {_name} leaves the fleet-safe token alphabet",
                )
        closed_details = CLOSED_FAULT_DETAILS.get(code)
        if closed_details is not None and detail not in closed_details:
            # Empty is rejected here too: a closed-vocabulary code carries the
            # condition, and a blank one names nothing a consumer can act on.
            raise FirmwareVerificationError(
                ERR_INVALID_ENVELOPE,
                f"unsupported {code} detail {detail!r}",
            )
        canonical = canonical_json_bytes(fault)
        public_key = _decode_public_key(anchor_public_key_b64)
        signature = _decode_wire_signature(str(message.get("signature", "")))
        _verify_signature(public_key, canonical, signature)

        if boot_id < last_boot_id:
            raise FirmwareVerificationError(
                ERR_BOOT_ROLLBACK, f"boot_id {boot_id} < {last_boot_id}"
            )
        if seq <= last_seq:
            raise FirmwareVerificationError(
                ERR_SEQUENCE_REPLAY, f"seq {seq} <= {last_seq}"
            )

        grade = GRADE_ATTESTED if posture in PRODUCTION_POSTURES else GRADE_ATTESTED_DEV
        return FirmwareFaultVerification(
            grade=grade,
            device_id=anchor_device_id,
            boot_id=boot_id,
            seq=seq,
            posture=posture,
            device_uptime_ms=uptime,
            code=code,
            subject=subject,
            detail=detail,
        )
    except FirmwareVerificationError as exc:
        return rejected(exc.code, exc.detail)
