# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed verification and extraction for signed Runtime release bundles."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import shutil
import stat
import tarfile
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, Any, Callable, Iterator, NoReturn

SIGNATURE_SCHEMA = "ori.runtime_release_bundle_signature.v1"
MANIFEST_SCHEMA = "ori.runtime_release_bundle_manifest.v1"
SIGNATURE_DOMAIN = b"ori.runtime_release_bundle_signature.v1\0"
RELEASE_KEY_PURPOSE = "runtime_release_bundle"
KEY_REGISTRY_SCHEMA = "ori.runtime_release_keys.v1"
_SIGNATURE_FIELDS = {
    "artifact",
    "artifact_sha256",
    "artifact_size",
    "key_id",
    "runtime_version",
    "schema",
    "signature",
    "target",
}
_MANIFEST_FIELDS = {"files", "python", "runtime_version", "schema", "target"}
_KEY_REGISTRY_FIELDS = {"keys", "schema"}
_KEY_FIELDS = {"key_id", "public_key_b64", "purpose", "status"}
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
_TARGET_RE = re.compile(r"^linux-(?:x86_64|aarch64)-python3\.(?:11|12)$")
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_MAX_JSON_BYTES = 1024 * 1024
_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 4096
_MAX_EXTRACTED_BYTES = 4 * 1024 * 1024 * 1024
_MAX_MEMBER_PATH_BYTES = 512
_COPY_CHUNK_BYTES = 1024 * 1024


class ReleaseBundleError(Exception):
    """Stable, automation-safe release bundle verification failure."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ReleaseKey:
    key_id: str
    public_key_b64: str
    purpose: str = RELEASE_KEY_PURPOSE
    status: str = "active"


@dataclass(frozen=True)
class VerifiedReleaseBundle:
    artifact: Path
    artifact_sha256: str
    artifact_size: int
    key_id: str
    runtime_version: str
    target: str


@dataclass(frozen=True)
class ExtractedReleaseBundle:
    root: Path
    runtime_version: str
    target: str
    python: str
    file_count: int


def release_artifact_name(runtime_version: str, target: str) -> str:
    """Validate a v1 release identity and return its canonical artifact name."""
    if not _VERSION_RE.fullmatch(runtime_version):
        _fail("invalid_signature_envelope", "runtime_version is malformed")
    if not _TARGET_RE.fullmatch(target):
        _fail("invalid_signature_envelope", "target is unsupported")
    return f"ori-runtime-{runtime_version}-{target}.tar.gz"


def load_release_key_registry(path: str | Path) -> dict[str, ReleaseKey]:
    """Load a strict, purpose-bound pinned release-key registry."""
    raw = _load_strict_json(
        Path(path),
        label="release key registry",
        code="untrusted_release_key",
    )
    if not isinstance(raw, dict):
        _fail("untrusted_release_key", "release key registry must be an object")
    _require_exact_fields(
        raw,
        _KEY_REGISTRY_FIELDS,
        code="untrusted_release_key",
        label="release key registry",
    )
    if raw.get("schema") != KEY_REGISTRY_SCHEMA:
        _fail("untrusted_release_key", "unsupported release key registry schema")
    entries = raw.get("keys")
    if not isinstance(entries, list) or not entries:
        _fail("untrusted_release_key", "release key registry must contain keys")

    registry: dict[str, ReleaseKey] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            _fail(
                "untrusted_release_key", f"release key entry {index} is not an object"
            )
        _require_exact_fields(
            entry,
            _KEY_FIELDS,
            code="untrusted_release_key",
            label=f"release key entry {index}",
        )
        key_id = _registry_string(entry, "key_id")
        if not _KEY_ID_RE.fullmatch(key_id) or key_id in registry:
            _fail("untrusted_release_key", "release key id is malformed or duplicated")
        purpose = _registry_string(entry, "purpose")
        if purpose != RELEASE_KEY_PURPOSE:
            _fail("untrusted_release_key", "release key purpose is not allowed")
        status = _registry_string(entry, "status")
        if status not in {"active", "verify_only", "revoked"}:
            _fail("untrusted_release_key", "release key status is unsupported")
        public_key_b64 = _registry_string(entry, "public_key_b64")
        _decode_canonical_base64(
            public_key_b64,
            label="release public key",
            expected_length=32,
            code="untrusted_release_key",
        )
        registry[key_id] = ReleaseKey(
            key_id=key_id,
            public_key_b64=public_key_b64,
            purpose=purpose,
            status=status,
        )
    return registry


def load_signature_envelope(path: str | Path) -> dict[str, Any]:
    """Load a strict detached signature envelope from disk."""
    envelope = _load_strict_json(
        Path(path),
        label="signature envelope",
        code="invalid_signature_envelope",
    )
    if not isinstance(envelope, dict):
        _fail("invalid_signature_envelope", "signature envelope must be an object")
    _require_exact_fields(
        envelope,
        _SIGNATURE_FIELDS,
        code="invalid_signature_envelope",
        label="signature envelope",
    )
    _validate_signature_envelope(envelope)
    return envelope


def canonical_signature_message(envelope: dict[str, Any]) -> bytes:
    """Return domain-separated canonical bytes for the detached envelope."""
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    _validate_json_value(unsigned, code="invalid_signature_envelope")
    encoded = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return SIGNATURE_DOMAIN + encoded


def create_signature_envelope(
    *,
    artifact_path: str | Path,
    runtime_version: str,
    target: str,
    key_id: str,
    signer: Callable[[bytes], bytes],
) -> dict[str, Any]:
    """Create a strict envelope using a purpose-specific external signer.

    The callable boundary allows an approved HSM or signing service to own the
    private key. This function never loads a key from runtime configuration or
    an environment variable.
    """
    artifact = Path(artifact_path)
    artifact_size, artifact_digest = _hash_file(artifact)
    envelope: dict[str, Any] = {
        "artifact": artifact.name,
        "artifact_sha256": artifact_digest,
        "artifact_size": artifact_size,
        "key_id": key_id,
        "runtime_version": runtime_version,
        "schema": SIGNATURE_SCHEMA,
        "signature": "ed25519:" + base64.b64encode(bytes(64)).decode("ascii"),
        "target": target,
    }
    _validate_signature_envelope(envelope)
    expected_name = release_artifact_name(runtime_version, target)
    if artifact.name != expected_name:
        _fail(
            "invalid_signature_envelope",
            "artifact filename is not bound to runtime version and target",
        )
    try:
        signature = signer(canonical_signature_message(envelope))
    except ReleaseBundleError:
        raise
    except Exception as exc:
        raise ReleaseBundleError("signing_failed", "release signer failed") from exc
    if not isinstance(signature, bytes) or len(signature) != 64:
        _fail("signing_failed", "release signer must return exactly 64 bytes")
    envelope["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return envelope


def write_signature_envelope(path: str | Path, envelope: dict[str, Any]) -> None:
    """Atomically write a validated detached signature envelope."""
    _require_exact_fields(
        envelope,
        _SIGNATURE_FIELDS,
        code="invalid_signature_envelope",
        label="signature envelope",
    )
    _validate_signature_envelope(envelope)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    payload = (
        json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    try:
        with temporary.open("xb") as handle:
            os.chmod(temporary, 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def verify_release_bundle(
    *,
    artifact_path: str | Path,
    envelope_path: str | Path,
    key_registry: dict[str, ReleaseKey],
    expected_version: str | None = None,
    expected_target: str | None = None,
) -> VerifiedReleaseBundle:
    """Authenticate exact bundle bytes before archive inspection."""
    artifact = Path(artifact_path)
    envelope = load_signature_envelope(envelope_path)
    artifact_name = _string_field(envelope, "artifact")
    runtime_version = _string_field(envelope, "runtime_version")
    target = _string_field(envelope, "target")
    key_id = _string_field(envelope, "key_id")

    if artifact.name != artifact_name:
        _fail(
            "artifact_integrity_mismatch", "artifact filename does not match envelope"
        )
    if expected_version is not None and runtime_version != expected_version:
        _fail("artifact_integrity_mismatch", "runtime version does not match request")
    if expected_target is not None and target != expected_target:
        _fail("unsupported_target", "bundle target does not match detected target")
    expected_artifact_name = f"ori-runtime-{runtime_version}-{target}.tar.gz"
    if artifact_name != expected_artifact_name:
        _fail(
            "artifact_integrity_mismatch",
            "artifact filename is not bound to runtime version and target",
        )

    release_key = key_registry.get(key_id)
    if release_key is None:
        _fail("untrusted_release_key", f"unknown release key id {key_id!r}")
    if release_key.key_id != key_id or release_key.purpose != RELEASE_KEY_PURPOSE:
        _fail("untrusted_release_key", "release key purpose or identity mismatch")
    if release_key.status not in {"active", "verify_only"}:
        _fail("untrusted_release_key", f"release key {key_id!r} is not trusted")

    signature = _decode_signature(_string_field(envelope, "signature"))
    public_key = _decode_canonical_base64(
        release_key.public_key_b64,
        label="release public key",
        expected_length=32,
        code="untrusted_release_key",
    )
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            canonical_signature_message(envelope),
        )
    except ImportError as exc:
        raise ReleaseBundleError(
            "crypto_unavailable",
            "cryptography Ed25519 support is unavailable",
        ) from exc
    except ReleaseBundleError:
        raise
    except Exception as exc:
        raise ReleaseBundleError(
            "signature_verification_failed",
            "release bundle signature verification failed",
        ) from exc

    expected_size = _integer_field(envelope, "artifact_size")
    expected_digest = _string_field(envelope, "artifact_sha256")
    actual_size, actual_digest = _hash_file(artifact)
    if actual_size != expected_size or actual_digest != expected_digest:
        _fail("artifact_integrity_mismatch", "artifact size or SHA-256 mismatch")

    return VerifiedReleaseBundle(
        artifact=artifact,
        artifact_sha256=actual_digest,
        artifact_size=actual_size,
        key_id=key_id,
        runtime_version=runtime_version,
        target=target,
    )


def extract_verified_bundle(
    verified: VerifiedReleaseBundle,
    *,
    destination: str | Path,
) -> ExtractedReleaseBundle:
    """Validate, extract, and manifest-check an authenticated bundle."""
    destination_path = Path(destination)
    if destination_path.exists():
        _fail("unsafe_bundle_archive", "extraction destination already exists")
    destination_path.mkdir(mode=0o700, parents=True)

    try:
        with _open_artifact(verified.artifact) as artifact_handle:
            actual_size, actual_digest = _hash_stream(artifact_handle)
            if (
                actual_size != verified.artifact_size
                or actual_digest != verified.artifact_sha256
            ):
                _fail(
                    "artifact_integrity_mismatch",
                    "artifact changed after signature verification",
                )
            artifact_handle.seek(0)
            with tarfile.open(fileobj=artifact_handle, mode="r:gz") as archive:
                members, top_level = _validate_archive_members(archive)
                expected_root = (
                    f"ori-runtime-{verified.runtime_version}-{verified.target}"
                )
                if top_level != expected_root:
                    _fail(
                        "unsafe_bundle_archive",
                        "archive root does not match signed identity",
                    )
                for member in members:
                    _extract_member(archive, member, destination_path)

        root = destination_path / top_level
        return _verify_extracted_manifest(root, verified)
    except ReleaseBundleError:
        shutil.rmtree(destination_path, ignore_errors=True)
        raise
    except (OSError, EOFError, tarfile.TarError) as exc:
        shutil.rmtree(destination_path, ignore_errors=True)
        raise ReleaseBundleError(
            "unsafe_bundle_archive",
            "bundle archive could not be safely inspected or extracted",
        ) from exc
    except Exception:
        shutil.rmtree(destination_path, ignore_errors=True)
        raise


def _validate_signature_envelope(envelope: dict[str, Any]) -> None:
    if envelope.get("schema") != SIGNATURE_SCHEMA:
        _fail("invalid_signature_envelope", "unsupported signature envelope schema")
    artifact = _string_field(envelope, "artifact")
    if Path(artifact).name != artifact or not artifact.endswith(".tar.gz"):
        _fail("invalid_signature_envelope", "artifact must be a plain .tar.gz filename")
    digest = _string_field(envelope, "artifact_sha256")
    if not _SHA256_RE.fullmatch(digest):
        _fail("invalid_signature_envelope", "artifact_sha256 is malformed")
    artifact_size = _integer_field(envelope, "artifact_size")
    if artifact_size <= 0 or artifact_size > _MAX_ARTIFACT_BYTES:
        _fail("invalid_signature_envelope", "artifact_size is outside bounds")
    if not _KEY_ID_RE.fullmatch(_string_field(envelope, "key_id")):
        _fail("invalid_signature_envelope", "key_id is malformed")
    if not _VERSION_RE.fullmatch(_string_field(envelope, "runtime_version")):
        _fail("invalid_signature_envelope", "runtime_version is malformed")
    if not _TARGET_RE.fullmatch(_string_field(envelope, "target")):
        _fail("invalid_signature_envelope", "target is unsupported")
    _decode_signature(_string_field(envelope, "signature"))


def _decode_signature(value: str) -> bytes:
    if not value.startswith("ed25519:"):
        _fail("invalid_signature_envelope", "signature must use ed25519")
    return _decode_canonical_base64(
        value.removeprefix("ed25519:"),
        label="release signature",
        expected_length=64,
        code="invalid_signature_envelope",
    )


def _validate_archive_members(
    archive: tarfile.TarFile,
) -> tuple[list[tarfile.TarInfo], str]:
    members = archive.getmembers()
    if not members or len(members) > _MAX_ARCHIVE_MEMBERS:
        _fail("unsafe_bundle_archive", "archive member count is outside bounds")

    seen: set[str] = set()
    seen_casefold: set[str] = set()
    top_levels: set[str] = set()
    total_size = 0
    for member in members:
        raw_name = member.name
        if not raw_name or len(raw_name.encode("utf-8")) > _MAX_MEMBER_PATH_BYTES:
            _fail("unsafe_bundle_archive", "archive member path is empty or too long")
        if "\\" in raw_name or unicodedata.normalize("NFC", raw_name) != raw_name:
            _fail("unsafe_bundle_archive", "archive member path is non-canonical")
        path = PurePosixPath(raw_name)
        if path.is_absolute() or ".." in path.parts or "." in path.parts:
            _fail("unsafe_bundle_archive", f"unsafe archive path {raw_name!r}")
        normalized = path.as_posix().rstrip("/")
        if raw_name.rstrip("/") != normalized:
            _fail("unsafe_bundle_archive", "archive member path is non-canonical")
        if (
            not normalized
            or normalized in seen
            or normalized.casefold() in seen_casefold
        ):
            _fail("unsafe_bundle_archive", "duplicate or case-colliding archive path")
        seen.add(normalized)
        seen_casefold.add(normalized.casefold())
        top_levels.add(path.parts[0])

        if not (member.isdir() or member.isreg()):
            _fail("unsafe_bundle_archive", f"unsupported archive member {raw_name!r}")
        if member.mode & (stat.S_ISUID | stat.S_ISGID):
            _fail("unsafe_bundle_archive", f"privileged mode on {raw_name!r}")
        if member.size < 0:
            _fail("unsafe_bundle_archive", f"negative member size on {raw_name!r}")
        total_size += member.size
        if total_size > _MAX_EXTRACTED_BYTES:
            _fail("unsafe_bundle_archive", "archive expands beyond size limit")

    if len(top_levels) != 1:
        _fail("unsafe_bundle_archive", "archive must contain one top-level directory")
    top_level = next(iter(top_levels))
    if not any(item.isdir() and item.name.rstrip("/") == top_level for item in members):
        _fail("unsafe_bundle_archive", "top-level archive directory is missing")
    return members, top_level


def _extract_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
) -> None:
    target = destination.joinpath(*PurePosixPath(member.name).parts)
    if member.isdir():
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        return

    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    source = archive.extractfile(member)
    if source is None:
        _fail("unsafe_bundle_archive", f"cannot read archive member {member.name!r}")
    with source:
        _copy_new_file(source, target, member.size)


def _copy_new_file(source: IO[bytes], target: Path, expected_size: int) -> None:
    written = 0
    with target.open("xb") as output:
        os.chmod(target, 0o600)
        while True:
            chunk = source.read(_COPY_CHUNK_BYTES)
            if not chunk:
                break
            written += len(chunk)
            if written > expected_size:
                _fail("unsafe_bundle_archive", "archive member exceeded declared size")
            output.write(chunk)
    if written != expected_size:
        _fail("unsafe_bundle_archive", "archive member was truncated")


def _verify_extracted_manifest(
    root: Path,
    verified: VerifiedReleaseBundle,
) -> ExtractedReleaseBundle:
    manifest_path = root / "BUNDLE-MANIFEST.json"
    manifest = _load_strict_json(
        manifest_path,
        label="bundle manifest",
        code="bundle_manifest_mismatch",
    )
    if not isinstance(manifest, dict):
        _fail("bundle_manifest_mismatch", "bundle manifest must be an object")
    _require_exact_fields(
        manifest,
        _MANIFEST_FIELDS,
        code="bundle_manifest_mismatch",
        label="bundle manifest",
    )
    if manifest.get("schema") != MANIFEST_SCHEMA:
        _fail("bundle_manifest_mismatch", "unsupported bundle manifest schema")
    if manifest.get("runtime_version") != verified.runtime_version:
        _fail("bundle_manifest_mismatch", "manifest runtime version mismatch")
    if manifest.get("target") != verified.target:
        _fail("bundle_manifest_mismatch", "manifest target mismatch")
    python_version = manifest.get("python")
    expected_python = verified.target.rsplit("python", 1)[1]
    if python_version != expected_python:
        _fail("bundle_manifest_mismatch", "manifest Python version mismatch")

    declared = manifest.get("files")
    if not isinstance(declared, dict) or not declared:
        _fail("bundle_manifest_mismatch", "manifest files must be a non-empty object")
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != manifest_path
    }
    if set(declared) != actual_paths:
        _fail("bundle_manifest_mismatch", "manifest and extracted file sets differ")
    for relative_path, expected_digest in declared.items():
        if not isinstance(relative_path, str) or not _is_safe_relative_path(
            relative_path
        ):
            _fail("bundle_manifest_mismatch", "manifest contains unsafe file path")
        if not isinstance(expected_digest, str) or not _SHA256_RE.fullmatch(
            expected_digest
        ):
            _fail("bundle_manifest_mismatch", "manifest contains malformed digest")
        _, digest = _hash_file(root.joinpath(*PurePosixPath(relative_path).parts))
        if digest != expected_digest:
            _fail("bundle_manifest_mismatch", f"digest mismatch for {relative_path!r}")

    return ExtractedReleaseBundle(
        root=root,
        runtime_version=verified.runtime_version,
        target=verified.target,
        python=python_version,
        file_count=len(actual_paths),
    )


def _load_strict_json(path: Path, *, label: str, code: str) -> Any:
    try:
        if path.stat().st_size > _MAX_JSON_BYTES:
            _fail(code, f"{label} exceeds size limit")
        raw = path.read_text(encoding="utf-8")
    except ReleaseBundleError:
        raise
    except OSError as exc:
        raise ReleaseBundleError(
            code,
            f"cannot read {label}",
        ) from exc

    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(code, f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(
            raw,
            object_pairs_hook=strict_object,
            parse_constant=lambda value: _fail(
                code, f"non-finite JSON value {value!r}"
            ),
        )
    except ReleaseBundleError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseBundleError(
            code,
            f"{label} is not strict UTF-8 JSON",
        ) from exc


def _validate_json_value(value: Any, *, code: str, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail(code, f"non-finite JSON value at {path}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, code=code, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail(code, f"non-string JSON key at {path}")
            _validate_json_value(item, code=code, path=f"{path}.{key}")
        return
    _fail(code, f"non-JSON value at {path}")


def _require_exact_fields(
    value: dict[str, Any],
    expected: set[str],
    *,
    code: str,
    label: str,
) -> None:
    fields = set(value)
    if fields != expected:
        missing = sorted(expected - fields)
        unknown = sorted(fields - expected)
        _fail(code, f"{label} fields mismatch; missing={missing}, unknown={unknown}")


def _decode_canonical_base64(
    value: str,
    *,
    label: str,
    expected_length: int,
    code: str,
) -> bytes:
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise ReleaseBundleError(code, f"{label} is not valid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        _fail(code, f"{label} is not canonical base64")
    if len(decoded) != expected_length:
        _fail(code, f"{label} must decode to {expected_length} bytes")
    return decoded


def _hash_file(path: Path) -> tuple[int, str]:
    with _open_artifact(path) as handle:
        return _hash_stream(handle)


@contextmanager
def _open_artifact(path: Path) -> Iterator[IO[bytes]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(path, flags)
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            _fail("artifact_integrity_mismatch", "artifact is not a regular file")
        if file_stat.st_size <= 0 or file_stat.st_size > _MAX_ARTIFACT_BYTES:
            _fail("artifact_integrity_mismatch", "artifact size is outside bounds")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            yield handle
    except ReleaseBundleError:
        raise
    except OSError as exc:
        raise ReleaseBundleError(
            "artifact_integrity_mismatch",
            f"cannot safely open artifact {path.name!r}",
        ) from exc
    finally:
        if fd != -1:
            os.close(fd)


def _hash_stream(handle: IO[bytes]) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while chunk := handle.read(_COPY_CHUNK_BYTES):
        size += len(chunk)
        digest.update(chunk)
    return size, f"sha256:{digest.hexdigest()}"


def _is_safe_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(
        value
        and not path.is_absolute()
        and ".." not in path.parts
        and "." not in path.parts
    )


def _string_field(value: dict[str, Any], name: str) -> str:
    field = value.get(name)
    if not isinstance(field, str) or not field:
        _fail("invalid_signature_envelope", f"{name} must be a non-empty string")
    return field


def _integer_field(value: dict[str, Any], name: str) -> int:
    field = value.get(name)
    if isinstance(field, bool) or not isinstance(field, int):
        _fail("invalid_signature_envelope", f"{name} must be an integer")
    return field


def _registry_string(value: dict[str, Any], name: str) -> str:
    field = value.get(name)
    if not isinstance(field, str) or not field:
        _fail("untrusted_release_key", f"{name} must be a non-empty string")
    return field


def _fail(code: str, detail: str) -> NoReturn:
    raise ReleaseBundleError(code, detail)
