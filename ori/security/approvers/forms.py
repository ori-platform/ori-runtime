# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The value forms of tier-c-approvers/v1, and the bytes its objects sign.

Every form here is decided from the value alone, so a request is refused on
its form before any registry state is read.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any, Final

from ori.security.ed25519_keys import key_identity

INTEGER_MAX: Final = 9007199254740991

CHANNELS: Final = frozenset({"sms", "whatsapp", "lan_ed25519"})
PHONE_CHANNELS: Final = frozenset({"sms", "whatsapp"})
OPERATIONS: Final = frozenset({"recover", "local_seed", "enrol"})

ENROL_DOMAIN: Final = b"ori.tier_c_approver.enrol.v1\x00"
POSSESSION_DOMAIN: Final = b"ori.tier_c_approver.possession.v1\x00"
REVOKE_DOMAIN: Final = b"ori.tier_c_approver.revoke.v1\x00"

#: RFC 8410 SubjectPublicKeyInfo DER prefix for an Ed25519 key.
SPKI_PREFIX: Final = bytes.fromhex("302a300506032b6570032100")

_ID = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
#: A device ID is runtime-config/v2's `device.id`, which allows 128.
_DEVICE_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_E164 = re.compile(r"\+[1-9][0-9]{1,14}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
LAN_PREFIX: Final = "ed25519:"


def canonical(value: Any) -> bytes:
    """Profile 2 canonical JSON: sorted keys, compact, unescaped UTF-8."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_b64(value: object, size: int) -> bytes | None:
    """The *size* raw bytes, when *value* is their one canonical padded spelling."""
    if not isinstance(value, str) or not value.isascii():
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != size or base64.b64encode(raw).decode("ascii") != value:
        return None
    return raw


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def is_id(value: object) -> bool:
    return isinstance(value, str) and _ID.match(value) is not None


def is_device_id(value: object) -> bool:
    return isinstance(value, str) and _DEVICE_ID.match(value) is not None


def is_e164(value: object) -> bool:
    return isinstance(value, str) and _E164.match(value) is not None


def is_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.match(value) is not None


def is_integer(value: object, minimum: int = 0) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= INTEGER_MAX
    )


def lan_key(value: object) -> bytes | None:
    """The raw key of a `lan_ed25519` value, `ed25519:` and canonical Base64."""
    if not isinstance(value, str) or not value.startswith(LAN_PREFIX):
        return None
    return canonical_b64(value[len(LAN_PREFIX) :], 32)


def is_value(channel: object, value: object) -> bool:
    # Membership is tested on text alone: a list or object is not hashable.
    if not isinstance(channel, str):
        return False
    if channel in PHONE_CHANNELS:
        return is_e164(value)
    if channel == "lan_ed25519":
        return lan_key(value) is not None
    return False


def value_key(channel: str, value: str) -> str:
    """What a duplicate or tombstone check compares.

    A phone value is its number alone, whatever its channel. A LAN value is
    the key's identity, so a key and its negation are one value.
    """
    if channel in PHONE_CHANNELS:
        return "phone:" + value
    raw = lan_key(value)
    if raw is None:
        raise ValueError("not a lan_ed25519 value")
    return "lan:" + key_identity(raw).hex()


def spki_sha256(raw_key: bytes) -> str:
    return sha256_hex(SPKI_PREFIX + raw_key)


def is_candidate(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"approver_id", "credential_id", "channel", "value"}
        and is_id(value["approver_id"])
        and is_id(value["credential_id"])
        and is_value(value["channel"], value["value"])
    )


def is_signed_object(value: object, id_member: str) -> bool:
    """An authorization (`authorizer_credential_id`) or a possession object."""
    return (
        isinstance(value, dict)
        and set(value)
        == {"v", "challenge_id", "challenge_sha256", id_member, "signature"}
        and type(value["v"]) is int
        and value["v"] == 1
        and canonical_b64(value["challenge_id"], 16) is not None
        and is_sha256_hex(value["challenge_sha256"])
        and is_id(value[id_member])
        and canonical_b64(value["signature"], 64) is not None
    )


def signed_preimage(domain: bytes, signed: dict[str, Any]) -> bytes:
    return domain + canonical({k: v for k, v in signed.items() if k != "signature"})


def challenge_object(
    *,
    challenge_id: str,
    device_id: str,
    site_id: str,
    identity_epoch: str,
    operation: str,
    registry_revision: int,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "v": 1,
        "challenge_id": challenge_id,
        "device_id": device_id,
        "site_id": site_id,
        "identity_epoch": identity_epoch,
        "operation": operation,
        "registry_revision": registry_revision,
        "candidates": sorted(candidates, key=lambda c: c["credential_id"]),
    }
