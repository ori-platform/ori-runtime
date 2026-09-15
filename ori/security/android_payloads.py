# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Signed publication of the Android runtime payload, per `runtime-mobile/v2`.

A protocol of its own rather than a variant of the release-bundle one. What is
shared with bundle signing is the KMS key, the signing role and the shape of a
detached envelope; what is separate is the schema, the domain separator, the
target grammar and the key registry, so a payload signature can never verify as
a bundle signature or the reverse.

`verify_payload` runs the contract's nine checks in order and names the stage
that refuses. The same stage names are recorded in the conformance corpus, so a
refusal reached at the wrong stage is a disagreement with the contract even when
the reason is right.

`create_payload_envelope` is the producer. It records the strip state and checks
the API level from the ELF image itself, because a build flag and the build that
honoured it can disagree and only the bytes say which happened.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ori.security.release_bundles import ReleaseKey

SIGNATURE_SCHEMA = "ori.android_runtime_payload_signature.v1"
SIGNATURE_DOMAIN = SIGNATURE_SCHEMA.encode("ascii") + b"\0"
KEY_REGISTRY_SCHEMA = "ori.android_runtime_payload_keys.v1"
KEY_PURPOSE = "android_runtime_payload"

# The v2 targets and the ELF identity each requires: (EI_CLASS, e_machine).
TARGETS: Mapping[str, tuple[int, int]] = {
    "android-arm64-v8a-api21": (2, 183),
    "android-armeabi-v7a-api21": (1, 40),
    "android-x86_64-api21": (2, 62),
}

STAGES = (
    "envelope",
    "signature",
    "identity",
    "artifact_name",
    "presence",
    "basename",
    "integrity",
    "abi",
    "content",
)

# The public keys of every seed the conformance corpus publishes. Anyone with a
# clone of ori-specs can sign under them, so no registry holding one loads.
PUBLISHED_TEST_PUBLIC_KEYS = frozenset(
    {
        "dPyio7OJ+xpk2b9SzA3UwpZPOATAz3x1XoUTxtuBmNw=",
        "bw8O6z+/+SXGbQPhnc5I1e3J/+5RzSaucd055W9/3aI=",
        "i7BOHBuD3d8xH1vN33xQ7ePAgC9H7HluKhMc9BKY2fM=",
        "P3cI1fXMK8YztZ0rOi7ZLnR5IgxvCK3iCL682FgKuTs=",
    }
)

SHELL_INTERPRETER = b"system/bin/sh"
PLACEHOLDER_MARKER = b"ORI_ANDROID_RUNTIME_PAYLOAD_SHIM"

_ENVELOPE_FIELDS = frozenset(
    {
        "artifact",
        "artifact_sha256",
        "artifact_size",
        "key_id",
        "runtime_version",
        "schema",
        "signature",
        "stripped",
        "target",
    }
)
_REGISTRY_FIELDS = frozenset({"keys", "schema"})
_KEY_FIELDS = frozenset({"key_id", "public_key_b64", "purpose", "status"})
_VERIFYING_STATUSES = frozenset({"active", "verify_only"})
_KNOWN_STATUSES = frozenset({"active", "verify_only", "revoked"})

_KEY_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
_TARGET_RE = re.compile(r"android-[a-z0-9_-]+-api[1-9][0-9]*")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
# Printable ASCII other than '"' and '\\', so no canonical encoding escapes anything.
_ARTIFACT_RE = re.compile(r"[!#-\[\]-~]{1,255}")
_TARGET_API_RE = re.compile(r"-api([1-9][0-9]*)")

_MAX_DOCUMENT_BYTES = 64 * 1024
_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
_MAX_ARTIFACT_SIZE = 2**53 - 1
_MAX_INTEGER_DIGITS = 16

_SHT_NOBITS = 8
_ANDROID_IDENT_SECTION = ".note.android.ident"
_ANDROID_NOTE_NAME = b"Android\0"
_ANDROID_NOTE_TYPE = 1


class AndroidPayloadError(Exception):
    """A refusal, carrying the contract's stage and reason."""

    def __init__(self, stage: str, reason: str, detail: str) -> None:
        super().__init__(f"{stage}/{reason}: {detail}")
        self.stage = stage
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class PayloadBuild:
    """What the ELF image says about how it was built."""

    api_level: int | None
    stripped: bool


@dataclass(frozen=True)
class VerifiedPayload:
    artifact: str
    artifact_sha256: str
    artifact_size: int
    key_id: str
    runtime_version: str
    target: str
    stripped: bool


def payload_artifact_name(runtime_version: str, target: str) -> str:
    """The published name, derived rather than trusted."""
    return f"ori-runtime-{runtime_version}-{target}.so"


def load_payload_key_registry(source: bytes | Path) -> dict[str, ReleaseKey]:
    """Load a strict registry whose every entry is purpose-bound to payloads.

    Refusing a foreign purpose here is the first of two checks. Verification
    checks purpose again on its own, so a registry built some other way still
    cannot make a bundle key verify a payload.
    """
    # Bytes or a path, never a bare string: a string could be read as either a
    # path or the document itself, and the wrong reading loads the wrong thing.
    raw = source.read_bytes() if isinstance(source, Path) else source
    document = _strict_json(raw, stage="registry", reason="untrusted_release_key")
    if not isinstance(document, dict) or set(document) != _REGISTRY_FIELDS:
        _refuse("registry", "untrusted_release_key", "registry fields")
    if document["schema"] != KEY_REGISTRY_SCHEMA or not isinstance(
        document["keys"], list
    ):
        _refuse("registry", "untrusted_release_key", "registry schema")
    if not document["keys"]:
        _refuse("registry", "untrusted_release_key", "registry holds no keys")

    keys: dict[str, ReleaseKey] = {}
    for entry in document["keys"]:
        if not isinstance(entry, dict) or set(entry) != _KEY_FIELDS:
            _refuse("registry", "untrusted_release_key", "key entry fields")
        key_id = entry["key_id"]
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            _refuse("registry", "untrusted_release_key", "key_id form")
        if key_id in keys:
            _refuse("registry", "untrusted_release_key", f"duplicate key_id {key_id}")
        if entry["purpose"] != KEY_PURPOSE:
            _refuse("registry", "untrusted_release_key", f"{key_id} purpose")
        status = entry["status"]
        if not isinstance(status, str) or status not in _KNOWN_STATUSES:
            _refuse("registry", "untrusted_release_key", f"{key_id} status")
        if _decode_public_key(entry["public_key_b64"]) is None:
            _refuse("registry", "untrusted_release_key", f"{key_id} public key")
        if entry["public_key_b64"] in PUBLISHED_TEST_PUBLIC_KEYS:
            _refuse(
                "registry",
                "untrusted_release_key",
                f"{key_id} is a published conformance test key",
            )
        keys[key_id] = ReleaseKey(
            key_id=key_id,
            public_key_b64=entry["public_key_b64"],
            purpose=entry["purpose"],
            status=status,
        )
    return keys


def canonical_signature_message(fields: Mapping[str, Any]) -> bytes:
    """The domain separator followed by the canonical encoding of the fields."""
    unsigned = {name: value for name, value in fields.items() if name != "signature"}
    encoded = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return SIGNATURE_DOMAIN + encoded


def check_payload_bytes(data: bytes, target: str) -> None:
    """The ABI and content checks, from the ELF header and never from prose."""
    if target not in TARGETS:
        _refuse("abi", "unsupported_target", f"{target} is not a v2 target")
    if len(data) < 20 or data[:4] != b"\x7fELF":
        _refuse("abi", "unsupported_target", "not an ELF image")
    want_class, want_machine = TARGETS[target]
    machine = data[18] | (data[19] << 8)
    if data[5] != 1:
        _refuse("abi", "unsupported_target", "not little-endian")
    if data[4] != want_class or machine != want_machine:
        _refuse(
            "abi",
            "unsupported_target",
            f"class {data[4]} machine {machine}, expected {want_class} {want_machine}",
        )
    if SHELL_INTERPRETER in data:
        _refuse("content", "invalid_artifact", "shell interpreter line present")
    if PLACEHOLDER_MARKER in data:
        _refuse("content", "invalid_artifact", "placeholder marker present")


def inspect_payload_build(data: bytes) -> PayloadBuild:
    """Read the API level note and the strip state from the section headers.

    Stripped means no `.symtab` and no `.debug*` section. The API level is the
    one the NDK records in `.note.android.ident`, or None when there is none. A
    section table that points outside the image is refused, never guessed at.
    """
    sections = _elf_sections(data)
    stripped = not any(
        name == ".symtab" or name.startswith(".debug") for name, _, _ in sections
    )
    api_level = None
    for name, offset, size in sections:
        if name == _ANDROID_IDENT_SECTION:
            api_level = _android_note_api_level(data[offset : offset + size])
    return PayloadBuild(api_level=api_level, stripped=stripped)


def create_payload_envelope(
    *,
    artifact: bytes,
    artifact_name: str,
    runtime_version: str,
    target: str,
    key_id: str,
    signer: Callable[[bytes], bytes],
    require_stripped: bool = False,
) -> dict[str, Any]:
    """Sign a built payload, recording what its bytes say about the build.

    The name the file was staged under must be the derived one, the API level
    in its Android note must be the target's, and `stripped` is measured rather
    than taken from the caller. A release passes `require_stripped`, so a build
    that ignored its strip setting fails before signing instead of publishing a
    payload a third larger than the one that was meant.
    """
    if target not in TARGETS:
        _refuse("identity", "unsupported_target", f"{target} is not a v2 target")
    if not isinstance(runtime_version, str) or not _VERSION_RE.fullmatch(
        runtime_version
    ):
        _refuse("envelope", "invalid_signature_envelope", "runtime_version form")
    derived = payload_artifact_name(runtime_version, target)
    if artifact_name != derived:
        _refuse(
            "artifact_name",
            "artifact_integrity_mismatch",
            f"{artifact_name!r} is not the derived name {derived!r}",
        )
    _check_producible(artifact, target)
    build = inspect_payload_build(artifact)
    match = _TARGET_API_RE.search(target)
    assert match is not None  # every v2 target carries an API level
    if build.api_level is None:
        _refuse("abi", "unsupported_target", "payload records no Android API level")
    if build.api_level != int(match.group(1)):
        _refuse(
            "abi",
            "unsupported_target",
            f"payload was built for API {build.api_level}, not the target's",
        )
    if require_stripped and not build.stripped:
        _refuse("content", "invalid_artifact", "payload still carries symbols")
    return sign_payload_fields(
        artifact=artifact,
        runtime_version=runtime_version,
        target=target,
        key_id=key_id,
        stripped=build.stripped,
        signer=signer,
    )


def sign_payload_fields(
    *,
    artifact: bytes,
    runtime_version: str,
    target: str,
    key_id: str,
    stripped: bool,
    signer: Callable[[bytes], bytes],
) -> dict[str, Any]:
    """Build and sign an envelope for bytes already checked against the target.

    Every consumer check a producer can make is made first, so a signer never
    lends its authority to a payload a consumer would refuse. The conformance
    corpus drives this directly: its accepted envelopes are what it produces
    from their seeds, byte for byte.
    """
    if not isinstance(runtime_version, str) or not _VERSION_RE.fullmatch(
        runtime_version
    ):
        _refuse("envelope", "invalid_signature_envelope", "runtime_version form")
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        _refuse("envelope", "invalid_signature_envelope", "key_id form")
    if not isinstance(stripped, bool):
        _refuse("envelope", "invalid_signature_envelope", "stripped form")
    if target not in TARGETS:
        _refuse("identity", "unsupported_target", f"{target} is not a v2 target")
    derived = payload_artifact_name(runtime_version, target)
    _check_producible(artifact, target)

    fields: dict[str, Any] = {
        "artifact": derived,
        "artifact_sha256": "sha256:" + hashlib.sha256(artifact).hexdigest(),
        "artifact_size": len(artifact),
        "key_id": key_id,
        "runtime_version": runtime_version,
        "schema": SIGNATURE_SCHEMA,
        "stripped": stripped,
        "target": target,
    }
    signature = signer(canonical_signature_message(fields))
    if not isinstance(signature, bytes) or len(signature) != 64:
        _refuse("signature", "invalid_signature", "signer did not return 64 bytes")
    fields["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return fields


def read_staged_payload(directory: Path, name: str) -> bytes:
    """A staged payload whose `.sha256` beside it names and matches it exactly."""
    artifact = directory / name
    if artifact.is_symlink() or not artifact.is_file():
        _refuse("presence", "invalid_artifact", f"missing payload {name}")
    data = artifact.read_bytes()
    try:
        recorded = (directory / f"{name}.sha256").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        _refuse("integrity", "artifact_integrity_mismatch", f"no checksum for {name}")
    if recorded != f"{hashlib.sha256(data).hexdigest()}  {name}\n":
        _refuse(
            "integrity",
            "artifact_integrity_mismatch",
            f"{name} does not match its staged checksum",
        )
    return data


def _check_producible(artifact: bytes, target: str) -> None:
    if not isinstance(artifact, bytes) or not artifact:
        _refuse("presence", "invalid_artifact", "payload is empty")
    if len(artifact) > _MAX_PAYLOAD_BYTES:
        _refuse(
            "integrity",
            "artifact_integrity_mismatch",
            "payload exceeds the size ceiling",
        )
    check_payload_bytes(artifact, target)


def encode_signature_envelope(envelope: Mapping[str, Any]) -> bytes:
    return (json.dumps(dict(envelope), sort_keys=True, indent=2) + "\n").encode("utf-8")


def verify_payload(
    *,
    envelope_text: str | bytes,
    registry: Mapping[str, ReleaseKey],
    artifact: bytes | None,
    downloaded_basename: str,
    runtime_version: str,
    target: str,
) -> VerifiedPayload:
    """Establish, in order, everything a consumer needs before packaging.

    `runtime_version` is the release the consumer selected and `target` the ABI
    slot it is filling. Neither is read from the envelope: they are what the
    envelope is checked against.
    """
    envelope = _parse_envelope(envelope_text)
    _verify_signature(envelope, registry)
    if artifact is not None and not isinstance(artifact, bytes):
        raise TypeError("artifact must be bytes or None")

    if envelope["runtime_version"] != runtime_version:
        _refuse(
            "identity",
            "artifact_integrity_mismatch",
            "runtime_version is not the selected release",
        )
    if envelope["target"] not in TARGETS:
        _refuse("identity", "unsupported_target", "target is not a v2 target")
    if envelope["target"] != target:
        _refuse("identity", "unsupported_target", "target is not the slot being filled")

    derived = payload_artifact_name(runtime_version, target)
    if envelope["artifact"] != derived:
        _refuse(
            "artifact_name",
            "artifact_integrity_mismatch",
            "artifact is not the derived name",
        )

    if artifact is None:
        _refuse("presence", "invalid_artifact", "payload absent")

    if downloaded_basename != derived:
        _refuse(
            "basename",
            "artifact_integrity_mismatch",
            "downloaded file is not the derived name",
        )

    if len(artifact) != envelope["artifact_size"]:
        _refuse("integrity", "artifact_integrity_mismatch", "size")
    if "sha256:" + hashlib.sha256(artifact).hexdigest() != envelope["artifact_sha256"]:
        _refuse("integrity", "artifact_integrity_mismatch", "digest")

    check_payload_bytes(artifact, target)

    return VerifiedPayload(
        artifact=envelope["artifact"],
        artifact_sha256=envelope["artifact_sha256"],
        artifact_size=envelope["artifact_size"],
        key_id=envelope["key_id"],
        runtime_version=envelope["runtime_version"],
        target=envelope["target"],
        stripped=envelope["stripped"],
    )


def _parse_envelope(text: str | bytes) -> dict[str, Any]:
    if isinstance(text, str):
        try:
            raw = text.encode("utf-8")
        except UnicodeEncodeError:
            _refuse("envelope", "invalid_signature_envelope", "not encodable as UTF-8")
    else:
        raw = text
    envelope = _strict_json(raw, stage="envelope", reason="invalid_signature_envelope")
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_FIELDS:
        _refuse("envelope", "invalid_signature_envelope", "envelope fields")

    if not _is_plain_filename(envelope["artifact"]):
        _refuse(
            "envelope", "invalid_signature_envelope", "artifact is not a plain filename"
        )
    digest = envelope["artifact_sha256"]
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        _refuse("envelope", "invalid_signature_envelope", "artifact_sha256 form")
    size = envelope["artifact_size"]
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or not 0 < size <= _MAX_ARTIFACT_SIZE
    ):
        _refuse("envelope", "invalid_signature_envelope", "artifact_size form")
    key_id = envelope["key_id"]
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        _refuse("envelope", "invalid_signature_envelope", "key_id form")
    version = envelope["runtime_version"]
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        _refuse("envelope", "invalid_signature_envelope", "runtime_version form")
    if envelope["schema"] != SIGNATURE_SCHEMA:
        _refuse("envelope", "invalid_signature_envelope", "schema")
    if _decode_signature(envelope["signature"]) is None:
        _refuse("envelope", "invalid_signature_envelope", "signature form")
    if not isinstance(envelope["stripped"], bool):
        _refuse("envelope", "invalid_signature_envelope", "stripped form")
    target = envelope["target"]
    if not isinstance(target, str) or not _TARGET_RE.fullmatch(target):
        _refuse("envelope", "invalid_signature_envelope", "target form")
    return envelope


def _verify_signature(
    envelope: Mapping[str, Any], registry: Mapping[str, ReleaseKey]
) -> None:
    key = registry.get(envelope["key_id"])
    if key is None or key.key_id != envelope["key_id"]:
        _refuse("signature", "untrusted_release_key", "key_id is not in the registry")
    if key.purpose != KEY_PURPOSE:
        _refuse(
            "signature",
            "untrusted_release_key",
            "key purpose is not android_runtime_payload",
        )
    if key.status not in _VERIFYING_STATUSES:
        _refuse("signature", "untrusted_release_key", f"key status {key.status}")
    public_key = _decode_public_key(key.public_key_b64)
    signature = _decode_signature(envelope["signature"])
    if public_key is None or signature is None:
        _refuse("signature", "untrusted_release_key", "registry key is unusable")
    try:
        public_key.verify(signature, canonical_signature_message(envelope))
    except InvalidSignature:
        _refuse("signature", "invalid_signature", "signature does not verify")


def _strict_json(raw: bytes, *, stage: str, reason: str) -> Any:
    if len(raw) > _MAX_DOCUMENT_BYTES:
        _refuse(stage, reason, "document exceeds the size ceiling")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for name, value in items:
            if name in document:
                _refuse(stage, reason, f"duplicate key {name!r}")
            document[name] = value
        return document

    def constant(name: str) -> NoReturn:
        _refuse(stage, reason, f"non-finite value {name}")

    def bounded_integer(digits: str) -> int:
        if len(digits.lstrip("-")) > _MAX_INTEGER_DIGITS:
            _refuse(stage, reason, "integer longer than any defined field allows")
        return int(digits)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _refuse(stage, reason, "not UTF-8")
    if text.startswith("\ufeff"):
        _refuse(stage, reason, "byte-order mark")
    try:
        return json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=constant,
            parse_int=bounded_integer,
        )
    except ValueError:
        _refuse(stage, reason, "not strict JSON")
    except RecursionError:
        # No defined field nests; refusing here is refusing without recursing.
        _refuse(stage, reason, "nested beyond any defined field")


def _is_plain_filename(value: object) -> bool:
    if not isinstance(value, str) or value in (".", ".."):
        return False
    return "/" not in value and _ARTIFACT_RE.fullmatch(value) is not None


def _elf_sections(data: bytes) -> list[tuple[str, int, int]]:
    """(name, offset, size) of every section with file contents, bounds-checked."""
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[5] != 1:
        _refuse("abi", "unsupported_target", "not a little-endian ELF image")
    if data[4] == 2:
        header, entry, minimum = "<16xHHIQQQIHHHHHH", "<IIQQQQIIQQ", 64
    elif data[4] == 1:
        header, entry, minimum = "<16xHHIIIIIHHHHHH", "<IIIIIIIIII", 40
    else:
        _refuse("abi", "unsupported_target", "unknown ELF class")
    if len(data) < struct.calcsize(header):
        _refuse("abi", "unsupported_target", "truncated ELF header")
    fields = struct.unpack_from(header, data)
    shoff, shentsize, shnum, shstrndx = fields[5], fields[10], fields[11], fields[12]
    if shoff == 0 or shnum == 0:
        return []
    if shentsize < minimum or shoff + shnum * shentsize > len(data):
        _refuse("abi", "unsupported_target", "section header table outside the image")
    raw = []
    for index in range(shnum):
        values = struct.unpack_from(entry, data, shoff + index * shentsize)
        name, kind, offset, size = values[0], values[1], values[4], values[5]
        if kind != _SHT_NOBITS and offset + size > len(data):
            _refuse("abi", "unsupported_target", "section contents outside the image")
        raw.append((name, kind, offset, size))
    if shstrndx >= shnum:
        _refuse("abi", "unsupported_target", "section name table index out of range")
    _, _, names_offset, names_size = raw[shstrndx]
    names = data[names_offset : names_offset + names_size]
    sections = []
    for name, kind, offset, size in raw:
        if name >= len(names) or b"\0" not in names[name:]:
            _refuse("abi", "unsupported_target", "section name outside the name table")
        label = names[name : names.index(b"\0", name)].decode("ascii", "replace")
        if kind != _SHT_NOBITS:
            sections.append((label, offset, size))
        else:
            sections.append((label, 0, 0))
    return sections


def _android_note_api_level(note: bytes) -> int | None:
    """The API level in an ELF note section's Android ident note, if present."""
    position = 0
    while position + 12 <= len(note):
        namesz, descsz, kind = struct.unpack_from("<III", note, position)
        name_start = position + 12
        desc_start = name_start + ((namesz + 3) & ~3)
        desc_end = desc_start + descsz
        if desc_end > len(note):
            break
        name = note[name_start : name_start + namesz]
        if name == _ANDROID_NOTE_NAME and kind == _ANDROID_NOTE_TYPE and descsz >= 4:
            return int(struct.unpack_from("<I", note, desc_start)[0])
        position = desc_start + ((descsz + 3) & ~3)
    return None


def _decode_signature(value: object) -> bytes | None:
    """The one canonical spelling of a 64-byte signature, or None."""
    if not isinstance(value, str) or not value.startswith("ed25519:"):
        return None
    encoded = value[len("ed25519:") :]
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != encoded:
        return None
    return decoded


def _decode_public_key(value: object) -> Ed25519PublicKey | None:
    if not isinstance(value, str):
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        return None


def _refuse(stage: str, reason: str, detail: str) -> NoReturn:
    raise AndroidPayloadError(stage, reason, detail)
