# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Runtime-side signing of inbound firmware commands.

Implements the producer half of ``ori-specs/firmware-commands/v1.md``:
one fixed byte grammar, signed with the runtime command key. The
device verifier accepts exactly this canonical form and nothing else,
so this module builds the bytes directly — no JSON library, because the
contract is the exact byte sequence, not "equivalent JSON".

Contract rules enforced here (fail closed, before signing):

* ``action``, ``channel``, ``device_id`` are fleet identifiers
  (``[A-Za-z0-9._-]``, non-empty, length-bounded);
* ``capability_hash`` is ``sha256:`` + 64 lowercase hex — the manifest
  epoch the command is bound to (a command signed against a superseded
  manifest is dead by construction on the device);
* ``cmd_seq`` is a canonical integer in ``1 .. 2**53 - 1``, strictly
  increasing per device — allocate through the state store, never
  locally, and never reuse a value even for retries.

The shared golden command vectors
(``tests/fixtures/firmware_command_vectors.json``) pin this signer's
bytes against the C verifier in ``ori-edge-firmware``.
"""

from __future__ import annotations

import base64
import re
from typing import Any

__all__ = [
    "FirmwareCommandSigner",
    "FirmwareCommandError",
    "build_command_bytes",
    "build_provisioning_approval_bytes",
]

_FLEET_ID = re.compile(r"^[A-Za-z0-9._-]{1,48}$")
_CAPABILITY_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACTION_MAX = 31
_CHANNEL_MAX = 31
_CMD_SEQ_MAX = 2**53 - 1
_POSTURES = frozenset({"development", "sealed_flash", "hardware_key"})
# The v1 action vocabulary; part of signed payloads, wire-contract frozen.
_ACTIONS = frozenset({"relay_open", "relay_close"})


class FirmwareCommandError(ValueError):
    """A command that must not be signed."""


def _require_fleet_id(value: str, field: str, max_len: int = 48) -> str:
    if not isinstance(value, str) or not _FLEET_ID.match(value) or len(value) > max_len:
        raise FirmwareCommandError(
            f"{field} is not a valid fleet identifier: {value!r}"
        )
    return value


def _validate_command_fields(action: str, channel: str, device_id: str) -> None:
    """The request's own v1 vocabulary and fleet shape — checked before
    anything else, so a locally refusable request never touches the
    registry or consumes a sequence."""
    _require_fleet_id(action, "action", _ACTION_MAX)
    if action not in _ACTIONS:
        raise FirmwareCommandError(f"action outside the v1 vocabulary: {action!r}")
    _require_fleet_id(channel, "channel", _CHANNEL_MAX)
    _require_fleet_id(device_id, "device_id")


def build_command_bytes(
    *,
    action: str,
    capability_hash: str,
    channel: str,
    cmd_seq: int,
    device_id: str,
) -> bytes:
    """The exact signed bytes of one command object, per the fixed
    grammar. Raises :class:`FirmwareCommandError` on any field the
    device verifier would refuse — never sign what cannot be accepted.
    """
    _validate_command_fields(action, channel, device_id)
    if not isinstance(capability_hash, str) or not _CAPABILITY_HASH.match(
        capability_hash
    ):
        raise FirmwareCommandError("capability_hash must be sha256: + 64 lowercase hex")
    if (
        isinstance(cmd_seq, bool)
        or not isinstance(cmd_seq, int)
        or not (1 <= cmd_seq <= _CMD_SEQ_MAX)
    ):
        raise FirmwareCommandError(f"cmd_seq out of range: {cmd_seq!r}")
    return (
        '{"action":"%s","capability_hash":"%s","channel":"%s",'
        '"cmd_seq":%d,"device_id":"%s","v":1}'
        % (action, capability_hash, channel, cmd_seq, device_id)
    ).encode("utf-8")


def _require_canonical_b64_32(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise FirmwareCommandError(f"{field} must be canonical base64")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise FirmwareCommandError(f"{field} must be canonical base64") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise FirmwareCommandError(f"{field} must encode exactly 32 bytes")
    return value


def _build_approval_object_bytes(
    *,
    capability_hash: str,
    device_id: str,
    posture: str,
    public_key_b64: str,
    runtime_public_key_b64: str,
) -> bytes:
    _require_fleet_id(device_id, "device_id")
    if not isinstance(capability_hash, str) or not _CAPABILITY_HASH.match(
        capability_hash
    ):
        raise FirmwareCommandError("capability_hash must be sha256: + 64 lowercase hex")
    if posture not in _POSTURES:
        raise FirmwareCommandError(f"posture outside the v1 vocabulary: {posture!r}")
    _require_canonical_b64_32(public_key_b64, "public_key_b64")
    _require_canonical_b64_32(runtime_public_key_b64, "runtime_public_key_b64")
    return (
        '{"capability_hash":"%s","device_id":"%s","posture":"%s",'
        '"public_key_b64":"%s","runtime_public_key_b64":"%s","v":1}'
        % (
            capability_hash,
            device_id,
            posture,
            public_key_b64,
            runtime_public_key_b64,
        )
    ).encode("utf-8")


def build_provisioning_approval_bytes(
    *,
    capability_hash: str,
    device_id: str,
    posture: str,
    public_key_b64: str,
    runtime_public_key_b64: str,
    provisioner_private_key_bytes: bytes,
) -> bytes:
    """Build one signed provisioning approval message.

    The approval object is signed in the exact fixed grammar defined by
    ``ori-specs/firmware-commands/v1.md``. The outer message is retained on
    ``ori/fw/<device_id>/provision`` so a rebooted firmware node can rehydrate
    the current runtime command key without waiting for a fresh publish.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if (
        not isinstance(provisioner_private_key_bytes, bytes)
        or len(provisioner_private_key_bytes) != 32
    ):
        raise FirmwareCommandError("provisioner key must be 32 raw Ed25519 seed bytes")
    approval = _build_approval_object_bytes(
        capability_hash=capability_hash,
        device_id=device_id,
        posture=posture,
        public_key_b64=public_key_b64,
        runtime_public_key_b64=runtime_public_key_b64,
    )
    signature = Ed25519PrivateKey.from_private_bytes(
        provisioner_private_key_bytes
    ).sign(approval)
    sig_b64 = base64.b64encode(signature).decode("ascii")
    return (
        b'{"approval":'
        + approval
        + b',"signature":"ed25519:'
        + sig_b64.encode()
        + b'"}'
    )


def _manifest_authorizes(manifest: Any, action: str, channel: str) -> bool:
    """Exact runtime_commanded match in the device's accepted manifest."""
    if not isinstance(manifest, dict):
        return False
    actions = manifest.get("actions")
    if not isinstance(actions, list):
        return False
    return any(
        isinstance(entry, dict)
        and entry.get("action") == action
        and entry.get("channel") == channel
        and entry.get("authority") == "runtime_commanded"
        for entry in actions
    )


class FirmwareCommandSigner:
    """Signs commands with the runtime command key and allocates
    strictly increasing per-device sequence numbers through the store.
    """

    def __init__(self, store: Any, private_key_bytes: bytes) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if not isinstance(private_key_bytes, bytes) or len(private_key_bytes) != 32:
            raise FirmwareCommandError(
                "runtime command key must be 32 raw Ed25519 seed bytes"
            )
        self._store = store
        self._key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)

    def public_key_bytes(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign_command_bytes(self, command: bytes) -> bytes:
        """Wire message for pre-built command bytes (vector/test path)."""
        import base64

        signature = self._key.sign(command)
        sig_b64 = base64.b64encode(signature).decode("ascii")
        return (
            b'{"command":'
            + command
            + b',"signature":"ed25519:'
            + sig_b64.encode()
            + b'"}'
        )

    async def sign_command(
        self,
        *,
        device_id: str,
        action: str,
        channel: str,
    ) -> bytes:
        """Builds, sequences, and signs one command for a provisioned
        device. The capability hash is the device's accepted manifest
        hash from the registry; the sequence is allocated through the
        store's strictly increasing per-device counter — a lost command
        is retried with a fresh sequence, never re-signed.
        """
        # Request shape and v1 vocabulary first: a locally refusable
        # request must consume nothing — not a registry read, not a
        # sequence — even if a future manifest lists such an action.
        _validate_command_fields(action, channel, device_id)
        row = await self._store.get_firmware_device(device_id)
        if row is None:
            raise FirmwareCommandError(
                f"no provisioning anchor for device {device_id!r}"
            )
        if row.get("revoked"):
            raise FirmwareCommandError(f"device {device_id!r} is revoked")
        if not row.get("approved"):
            raise FirmwareCommandError(f"device {device_id!r} is not approved")
        # The accepted manifest is the authority surface: never sign a
        # command the device would refuse as unknown_action — it would
        # spend a sequence on a knowingly impossible instruction.
        if not _manifest_authorizes(row.get("manifest"), action, channel):
            raise FirmwareCommandError(
                f"manifest does not grant runtime_commanded authority for "
                f"({action!r}, {channel!r}) on device {device_id!r}"
            )
        cmd_seq = await self._store.allocate_firmware_command_seq(device_id)
        command = build_command_bytes(
            action=action,
            capability_hash=row["capability_hash"],
            channel=channel,
            cmd_seq=cmd_seq,
            device_id=device_id,
        )
        return self.sign_command_bytes(command)
