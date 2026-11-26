# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""runtime-posture/v1's record: its members, canonical bytes and signature.

The runtime authors one signed record of its posture, which every other
component forwards and none edits. This module builds it and refuses any
member outside v1's forms, so the runtime never signs a record a receiver
would refuse as `malformed`. It grants nothing and reads no state: callers
supply the members and the signer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

SIGNING_DOMAIN = b"ori.runtime_posture.v1\x00"
#: RFC 8410 SubjectPublicKeyInfo DER prefix of a raw Ed25519 key.
_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_MAX_INTEGER = 2**53 - 1
_DEVICE_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
_RELEASE = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?"
)
_RELEASE_MAX = 64
_PROFILES = frozenset({"development", "staging", "production"})
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_ALERT_CLASS = re.compile(r"[a-z][a-z0-9_]{0,31}")
_ALERT_CLASSES_MAX = 10


class PostureRecordError(ValueError):
    """A member v1 cannot carry; no record is signed."""


def key_identity(public_key: bytes) -> str:
    """`sha256:` and the hex SHA-256 of the key's SubjectPublicKeyInfo DER."""
    if len(public_key) != 32:
        raise PostureRecordError("a posture key is 32 raw Ed25519 bytes")
    return "sha256:" + hashlib.sha256(_SPKI_PREFIX + public_key).hexdigest()


@dataclass(frozen=True)
class PostureMembers:
    """Every member of the record but its key identity and signature."""

    device_id: str
    release: str | None
    deployment_profile: str
    commissioned_binding: str | None
    alert_classes: tuple[str, ...]
    boot_generation: int
    posture_seq: int
    issued_at_ms: int


def _integer(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PostureRecordError(f"{name} is not an integer")
    if not 1 <= value <= _MAX_INTEGER:
        raise PostureRecordError(f"{name} is outside 1 to 2^53 - 1")
    return value


def alert_class_list(classes: Iterable[str]) -> tuple[str, ...]:
    """The classes in strictly ascending byte order, each once, within v1's bounds.

    A run that can raise more classes than v1 carries, or a longer name,
    publishes no record rather than a truncated list.
    """
    names = list(classes)
    for name in names:
        if not (
            isinstance(name, str) and name.isascii() and _ALERT_CLASS.fullmatch(name)
        ):
            raise PostureRecordError(f"alert class {name!r} is outside v1's form")
    ordered = tuple(sorted(set(names), key=lambda name: name.encode("ascii")))
    if len(ordered) > _ALERT_CLASSES_MAX:
        raise PostureRecordError(f"more than {_ALERT_CLASSES_MAX} alert classes")
    return ordered


def _checked(members: PostureMembers) -> dict[str, object]:
    device_id = members.device_id
    if not (
        isinstance(device_id, str)
        and device_id.isascii()
        and _DEVICE_ID.fullmatch(device_id)
    ):
        raise PostureRecordError("device_id is outside v1's form")
    release = members.release
    if release is not None and not (
        isinstance(release, str)
        and release.isascii()
        and len(release) <= _RELEASE_MAX
        and _RELEASE.fullmatch(release)
    ):
        raise PostureRecordError("release is outside v1's form")
    if members.deployment_profile not in _PROFILES:
        raise PostureRecordError("deployment_profile is outside v1's form")
    binding = members.commissioned_binding
    if binding is not None and not (
        isinstance(binding, str) and _SHA256.fullmatch(binding)
    ):
        raise PostureRecordError("commissioned_binding is outside v1's form")
    classes = alert_class_list(members.alert_classes)
    if classes != tuple(members.alert_classes):
        raise PostureRecordError("alert_classes is not strictly ascending")
    return {
        "v": 1,
        "device_id": members.device_id,
        "release": release,
        "deployment_profile": members.deployment_profile,
        "commissioned_binding": binding,
        "alert_classes": list(classes),
        "boot_generation": _integer("boot_generation", members.boot_generation),
        "posture_seq": _integer("posture_seq", members.posture_seq),
        "issued_at_ms": _integer("issued_at_ms", members.issued_at_ms),
    }


def _canonical(record: dict[str, object]) -> bytes:
    # Every value is ASCII and needs no escape, and every number is an integer
    # token, so sorted compact JSON is gateway-mqtt-canonical-json/v1's form.
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def build_record(
    members: PostureMembers,
    *,
    public_key: bytes,
    sign: Callable[[bytes], bytes],
) -> bytes:
    """The signed record's canonical bytes, exactly as published.

    *sign* is the posture key's Ed25519 signer; *public_key* its raw 32 bytes.
    Raises :class:`PostureRecordError` for any member v1 cannot carry.
    """
    record = _checked(members)
    record["key_identity"] = key_identity(public_key)
    signature = sign(SIGNING_DOMAIN + _canonical(record))
    if len(signature) != 64:
        raise PostureRecordError("an Ed25519 signature is 64 bytes")
    record["signature"] = base64.b64encode(signature).decode("ascii")
    return _canonical(record)
