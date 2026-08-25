# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import builtins
import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.security import release_bundles
from ori.security.release_bundles import (
    KEY_REGISTRY_SCHEMA,
    MANIFEST_SCHEMA,
    RELEASE_KEY_PURPOSE,
    SIGNATURE_SCHEMA,
    ExtractedReleaseBundle,
    ReleaseBundleError,
    ReleaseKey,
    VerifiedReleaseBundle,
    canonical_signature_message,
    create_signature_envelope,
    extract_verified_bundle,
    load_release_key_registry,
    load_signature_envelope,
    verify_release_bundle,
    write_signature_envelope,
)

VERSION = "2.3.0"
TARGET = "linux-x86_64-python3.12"
ARTIFACT_NAME = f"ori-runtime-{VERSION}-{TARGET}.tar.gz"
KEY_ID = "ori-runtime-release-test"


def _private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _release_key(
    *, purpose: str = RELEASE_KEY_PURPOSE, status: str = "active"
) -> ReleaseKey:
    public = _private_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return ReleaseKey(
        key_id=KEY_ID,
        public_key_b64=base64.b64encode(public).decode("ascii"),
        purpose=purpose,
        status=status,
    )


def _manifest(files: dict[str, bytes]) -> bytes:
    return json.dumps(
        {
            "files": {
                name: f"sha256:{hashlib.sha256(value).hexdigest()}"
                for name, value in files.items()
            },
            "python": "3.12",
            "runtime_version": VERSION,
            "schema": MANIFEST_SCHEMA,
            "target": TARGET,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _write_archive(
    tmp_path: Path,
    *,
    files: dict[str, bytes] | None = None,
    manifest_files: dict[str, bytes] | None = None,
    extra_members: list[tarfile.TarInfo] | None = None,
    root: str | None = None,
) -> Path:
    files = files or {
        "wheelhouse/requirements.txt": b"PyYAML==6.0.2 --hash=sha256:abc\n",
        "wheelhouse/ori_runtime-2.3.0-py3-none-any.whl": b"wheel",
        "templates/ori.linux.yaml.example": b"device: {}\n",
        "systemd/ori-runtime.service": b"[Service]\n",
    }
    artifact = tmp_path / ARTIFACT_NAME
    root = root or f"ori-runtime-{VERSION}-{TARGET}"
    with tarfile.open(artifact, "w:gz") as archive:
        root_info = tarfile.TarInfo(root)
        root_info.type = tarfile.DIRTYPE
        root_info.mode = 0o755
        archive.addfile(root_info)
        payloads = {
            "BUNDLE-MANIFEST.json": _manifest(
                files if manifest_files is None else manifest_files
            ),
            **files,
        }
        for name, payload in payloads.items():
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
        for info in extra_members or []:
            archive.addfile(info)
    return artifact


def _write_envelope(
    tmp_path: Path,
    artifact: Path,
    *,
    changes: dict[str, object] | None = None,
    resign: bool = True,
) -> Path:
    raw = artifact.read_bytes()
    envelope: dict[str, object] = {
        "artifact": artifact.name,
        "artifact_sha256": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "artifact_size": len(raw),
        "key_id": KEY_ID,
        "runtime_version": VERSION,
        "schema": SIGNATURE_SCHEMA,
        "signature": "ed25519:" + base64.b64encode(bytes(64)).decode("ascii"),
        "target": TARGET,
    }
    envelope.update(changes or {})
    if resign:
        signature = _private_key().sign(canonical_signature_message(envelope))
        envelope["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    path = tmp_path / f"{artifact.name}.signature.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    return path


def _verify(tmp_path: Path) -> tuple[Path, VerifiedReleaseBundle]:
    artifact = _write_archive(tmp_path)
    envelope = _write_envelope(tmp_path, artifact)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry={KEY_ID: _release_key()},
        expected_version=VERSION,
        expected_target=TARGET,
    )
    return artifact, verified


def test_verifies_and_extracts_exact_signed_bundle(tmp_path: Path) -> None:
    artifact, verified = _verify(tmp_path)

    extracted = extract_verified_bundle(verified, destination=tmp_path / "extract")

    assert isinstance(extracted, ExtractedReleaseBundle)
    assert extracted.runtime_version == VERSION
    assert extracted.target == TARGET
    assert extracted.python == "3.12"
    assert extracted.file_count == 4
    assert extracted.root.name == artifact.name.removesuffix(".tar.gz")


def test_extraction_members_remain_below_exact_private_workspace_under_umask_0002(
    tmp_path: Path,
) -> None:
    """Recursive member parents are safe only below the pinned 0700 root."""
    files = {"deep/implicit/payload.txt": b"verified payload"}
    artifact = _write_archive(tmp_path, files=files)
    envelope = _write_envelope(tmp_path, artifact)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry={KEY_ID: _release_key()},
    )
    destination = tmp_path / "extract"
    previous_umask = os.umask(0o002)
    try:
        extracted = extract_verified_bundle(verified, destination=destination)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert stat.S_IMODE(extracted.root.stat().st_mode) == 0o700
    assert stat.S_IMODE((extracted.root / "deep").stat().st_mode) == 0o775
    assert stat.S_IMODE((extracted.root / "deep" / "implicit").stat().st_mode) == 0o700
    assert (extracted.root / "deep" / "implicit" / "payload.txt").read_bytes() == (
        b"verified payload"
    )


def test_verify_only_key_can_verify_existing_release(tmp_path: Path) -> None:
    artifact = _write_archive(tmp_path)
    envelope = _write_envelope(tmp_path, artifact)

    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry={KEY_ID: _release_key(status="verify_only")},
    )

    assert verified.key_id == KEY_ID


def test_reports_crypto_backend_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _write_archive(tmp_path)
    envelope = _write_envelope(tmp_path, artifact)
    real_import = builtins.__import__

    def guarded_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "cryptography.hazmat.primitives.asymmetric.ed25519":
            raise ImportError("simulated unavailable cryptography")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    with pytest.raises(ReleaseBundleError) as exc:
        verify_release_bundle(
            artifact_path=artifact,
            envelope_path=envelope,
            key_registry={KEY_ID: _release_key()},
        )

    assert exc.value.code == "crypto_unavailable"


def test_loads_strict_purpose_bound_release_key_registry(tmp_path: Path) -> None:
    key = _release_key()
    path = tmp_path / "release-keys.json"
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": key.key_id,
                        "public_key_b64": key.public_key_b64,
                        "purpose": key.purpose,
                        "status": key.status,
                    }
                ],
                "schema": KEY_REGISTRY_SCHEMA,
            }
        ),
        encoding="utf-8",
    )

    registry = load_release_key_registry(path)

    assert registry == {KEY_ID: key}


@pytest.mark.parametrize(
    "mutation",
    [
        {"schema": "ori.runtime_release_keys.v2"},
        {"keys": []},
        {"keys": [{"key_id": KEY_ID}]},
        {
            "keys": [
                {
                    "key_id": KEY_ID,
                    "public_key_b64": "AA==",
                    "purpose": RELEASE_KEY_PURPOSE,
                    "status": "active",
                }
            ]
        },
    ],
)
def test_rejects_malformed_release_key_registry(
    tmp_path: Path,
    mutation: dict[str, object],
) -> None:
    value: dict[str, object] = {
        "keys": [],
        "schema": KEY_REGISTRY_SCHEMA,
    }
    value.update(mutation)
    path = tmp_path / "release-keys.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ReleaseBundleError) as exc:
        load_release_key_registry(path)

    assert exc.value.code == "untrusted_release_key"


def test_creates_writes_and_verifies_signature_envelope(tmp_path: Path) -> None:
    artifact = _write_archive(tmp_path)
    envelope = create_signature_envelope(
        artifact_path=artifact,
        runtime_version=VERSION,
        target=TARGET,
        key_id=KEY_ID,
        signer=_private_key().sign,
    )
    path = tmp_path / f"{artifact.name}.signature.json"

    write_signature_envelope(path, envelope)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=path,
        key_registry={KEY_ID: _release_key()},
    )

    assert verified.artifact_sha256 == envelope["artifact_sha256"]
    assert path.stat().st_mode & 0o777 == 0o600


def test_rejects_signer_returning_wrong_length(tmp_path: Path) -> None:
    artifact = _write_archive(tmp_path)

    with pytest.raises(ReleaseBundleError) as exc:
        create_signature_envelope(
            artifact_path=artifact,
            runtime_version=VERSION,
            target=TARGET,
            key_id=KEY_ID,
            signer=lambda _: b"short",
        )

    assert exc.value.code == "signing_failed"


@pytest.mark.parametrize(
    ("key", "code"),
    [
        (None, "untrusted_release_key"),
        (_release_key(purpose="community_skill"), "untrusted_release_key"),
        (_release_key(status="revoked"), "untrusted_release_key"),
    ],
)
def test_rejects_unknown_wrong_purpose_and_revoked_keys(
    tmp_path: Path,
    key: ReleaseKey | None,
    code: str,
) -> None:
    artifact = _write_archive(tmp_path)
    envelope = _write_envelope(tmp_path, artifact)
    registry = {} if key is None else {KEY_ID: key}

    with pytest.raises(ReleaseBundleError) as exc:
        verify_release_bundle(
            artifact_path=artifact,
            envelope_path=envelope,
            key_registry=registry,
        )

    assert exc.value.code == code


def test_rejects_signature_from_other_profile(tmp_path: Path) -> None:
    artifact = _write_archive(tmp_path)
    envelope = _write_envelope(tmp_path, artifact)
    parsed = json.loads(envelope.read_text())
    unsigned = {key: value for key, value in parsed.items() if key != "signature"}
    wrong_payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    parsed["signature"] = "ed25519:" + base64.b64encode(
        _private_key().sign(wrong_payload)
    ).decode("ascii")
    envelope.write_text(json.dumps(parsed), encoding="utf-8")

    with pytest.raises(ReleaseBundleError) as exc:
        verify_release_bundle(
            artifact_path=artifact,
            envelope_path=envelope,
            key_registry={KEY_ID: _release_key()},
        )

    assert exc.value.code == "signature_verification_failed"


def test_rejects_artifact_mutation_after_valid_signature(tmp_path: Path) -> None:
    artifact = _write_archive(tmp_path)
    envelope = _write_envelope(tmp_path, artifact)
    artifact.write_bytes(artifact.read_bytes() + b"mutation")

    with pytest.raises(ReleaseBundleError) as exc:
        verify_release_bundle(
            artifact_path=artifact,
            envelope_path=envelope,
            key_registry={KEY_ID: _release_key()},
        )

    assert exc.value.code == "artifact_integrity_mismatch"


def test_rechecks_artifact_before_archive_inspection(tmp_path: Path) -> None:
    artifact, verified = _verify(tmp_path)
    artifact.write_bytes(artifact.read_bytes() + b"mutation-after-verification")

    with pytest.raises(ReleaseBundleError) as exc:
        extract_verified_bundle(verified, destination=tmp_path / "extract")

    assert exc.value.code == "artifact_integrity_mismatch"
    assert not (tmp_path / "extract").exists()


def test_rejects_symlink_artifact_even_when_target_bytes_are_valid(
    tmp_path: Path,
) -> None:
    artifact = _write_archive(tmp_path)
    envelope = _write_envelope(tmp_path, artifact)
    real_artifact = tmp_path / "real.tar.gz"
    artifact.rename(real_artifact)
    artifact.symlink_to(real_artifact)

    with pytest.raises(ReleaseBundleError) as exc:
        verify_release_bundle(
            artifact_path=artifact,
            envelope_path=envelope,
            key_registry={KEY_ID: _release_key()},
        )

    assert exc.value.code == "artifact_integrity_mismatch"


def test_rejects_authenticated_bytes_that_are_not_a_tar_archive(tmp_path: Path) -> None:
    artifact = tmp_path / ARTIFACT_NAME
    artifact.write_bytes(b"not-a-tar-archive")
    envelope = _write_envelope(tmp_path, artifact)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry={KEY_ID: _release_key()},
    )

    with pytest.raises(ReleaseBundleError) as exc:
        extract_verified_bundle(verified, destination=tmp_path / "extract")

    assert exc.value.code == "unsafe_bundle_archive"
    assert not (tmp_path / "extract").exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"artifact_size": 0},
        {"artifact_size": 4 * 1024 * 1024 * 1024 + 1},
        {"artifact_sha256": "sha256:" + "A" * 64},
        {"runtime_version": "latest"},
        {"target": "linux-any-python3.12"},
        {"unexpected": True},
    ],
)
def test_rejects_malformed_signature_envelope(
    tmp_path: Path,
    changes: dict[str, object],
) -> None:
    artifact = _write_archive(tmp_path)
    envelope = _write_envelope(tmp_path, artifact, changes=changes)

    with pytest.raises(ReleaseBundleError) as exc:
        load_signature_envelope(envelope)

    assert exc.value.code == "invalid_signature_envelope"


def test_rejects_duplicate_signature_envelope_key(tmp_path: Path) -> None:
    artifact = _write_archive(tmp_path)
    envelope = _write_envelope(tmp_path, artifact)
    raw = envelope.read_text()
    envelope.write_text(raw.replace('{"artifact":', '{"artifact":"other","artifact":'))

    with pytest.raises(ReleaseBundleError, match="duplicate JSON key"):
        load_signature_envelope(envelope)


def test_rejects_target_and_version_mismatch(tmp_path: Path) -> None:
    artifact = _write_archive(tmp_path)
    envelope = _write_envelope(tmp_path, artifact)

    with pytest.raises(ReleaseBundleError) as target_exc:
        verify_release_bundle(
            artifact_path=artifact,
            envelope_path=envelope,
            key_registry={KEY_ID: _release_key()},
            expected_target="linux-aarch64-python3.12",
        )
    with pytest.raises(ReleaseBundleError) as version_exc:
        verify_release_bundle(
            artifact_path=artifact,
            envelope_path=envelope,
            key_registry={KEY_ID: _release_key()},
            expected_version="2.2.0",
        )

    assert target_exc.value.code == "unsupported_target"
    assert version_exc.value.code == "artifact_integrity_mismatch"


@pytest.mark.parametrize(
    "kind",
    [
        "traversal",
        "absolute",
        "symlink",
        "double_separator",
        "backslash",
        "non_nfc",
    ],
)
def test_rejects_unsafe_archive_members(tmp_path: Path, kind: str) -> None:
    if kind == "traversal":
        info = tarfile.TarInfo("root/../escape")
    elif kind == "absolute":
        info = tarfile.TarInfo("/escape")
    elif kind == "symlink":
        info = tarfile.TarInfo("root/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
    elif kind == "double_separator":
        info = tarfile.TarInfo("root//ambiguous")
    elif kind == "backslash":
        info = tarfile.TarInfo("root\\ambiguous")
    else:
        info = tarfile.TarInfo("root/cafe\u0301")
    info.size = 0
    artifact = _write_archive(tmp_path, extra_members=[info])
    envelope = _write_envelope(tmp_path, artifact)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry={KEY_ID: _release_key()},
    )

    with pytest.raises(ReleaseBundleError) as exc:
        extract_verified_bundle(verified, destination=tmp_path / "extract")

    assert exc.value.code == "unsafe_bundle_archive"
    assert not (tmp_path / "extract").exists()


def test_rejects_archive_member_count_over_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _write_archive(tmp_path)
    envelope = _write_envelope(tmp_path, artifact)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry={KEY_ID: _release_key()},
    )
    monkeypatch.setattr(release_bundles, "_MAX_ARCHIVE_MEMBERS", 2)

    with pytest.raises(ReleaseBundleError) as exc:
        extract_verified_bundle(verified, destination=tmp_path / "extract")

    assert exc.value.code == "unsafe_bundle_archive"


def test_rejects_archive_expansion_over_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _write_archive(tmp_path)
    envelope = _write_envelope(tmp_path, artifact)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry={KEY_ID: _release_key()},
    )
    monkeypatch.setattr(release_bundles, "_MAX_EXTRACTED_BYTES", 1)

    with pytest.raises(ReleaseBundleError) as exc:
        extract_verified_bundle(verified, destination=tmp_path / "extract")

    assert exc.value.code == "unsafe_bundle_archive"


def test_rejects_authenticated_truncated_tar_archive(tmp_path: Path) -> None:
    artifact = _write_archive(tmp_path)
    raw = artifact.read_bytes()
    artifact.write_bytes(raw[: len(raw) // 2])
    envelope = _write_envelope(tmp_path, artifact)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry={KEY_ID: _release_key()},
    )

    with pytest.raises(ReleaseBundleError) as exc:
        extract_verified_bundle(verified, destination=tmp_path / "extract")

    assert exc.value.code == "unsafe_bundle_archive"


def test_manifest_rejects_undeclared_file(tmp_path: Path) -> None:
    files = {
        "wheelhouse/requirements.txt": b"locked\n",
        "wheelhouse/undeclared.whl": b"unexpected",
    }
    artifact = _write_archive(
        tmp_path,
        files=files,
        manifest_files={"wheelhouse/requirements.txt": b"locked\n"},
    )
    envelope = _write_envelope(tmp_path, artifact)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry={KEY_ID: _release_key()},
    )

    with pytest.raises(ReleaseBundleError) as exc:
        extract_verified_bundle(verified, destination=tmp_path / "extract")

    assert exc.value.code == "bundle_manifest_mismatch"
    assert not (tmp_path / "extract").exists()


def test_manifest_rejects_declared_digest_mismatch(tmp_path: Path) -> None:
    artifact = _write_archive(
        tmp_path,
        files={"wheelhouse/requirements.txt": b"actual\n"},
        manifest_files={"wheelhouse/requirements.txt": b"different\n"},
    )
    envelope = _write_envelope(tmp_path, artifact)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry={KEY_ID: _release_key()},
    )

    with pytest.raises(ReleaseBundleError) as exc:
        extract_verified_bundle(verified, destination=tmp_path / "extract")

    assert exc.value.code == "bundle_manifest_mismatch"
    assert "digest mismatch" in exc.value.detail


def test_rejects_archive_root_not_bound_to_signed_identity(tmp_path: Path) -> None:
    artifact = _write_archive(tmp_path, root="ori-runtime-other")
    envelope = _write_envelope(tmp_path, artifact)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry={KEY_ID: _release_key()},
    )

    with pytest.raises(ReleaseBundleError) as exc:
        extract_verified_bundle(verified, destination=tmp_path / "extract")

    assert exc.value.code == "unsafe_bundle_archive"


def test_rejects_case_colliding_archive_members(tmp_path: Path) -> None:
    info = tarfile.TarInfo(
        f"ori-runtime-{VERSION}-{TARGET}/Wheelhouse/requirements.txt"
    )
    info.size = 0
    artifact = _write_archive(tmp_path, extra_members=[info])
    envelope = _write_envelope(tmp_path, artifact)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry={KEY_ID: _release_key()},
    )

    with pytest.raises(ReleaseBundleError) as exc:
        extract_verified_bundle(verified, destination=tmp_path / "extract")

    assert exc.value.code == "unsafe_bundle_archive"


def test_extraction_destination_must_be_new(tmp_path: Path) -> None:
    _, verified = _verify(tmp_path)
    destination = tmp_path / "extract"
    destination.mkdir()

    with pytest.raises(ReleaseBundleError) as exc:
        extract_verified_bundle(verified, destination=destination)

    assert exc.value.code == "unsafe_bundle_archive"


def test_extraction_destination_parent_must_already_exist(tmp_path: Path) -> None:
    _, verified = _verify(tmp_path)
    destination = tmp_path / "missing" / "extract"

    with pytest.raises(ReleaseBundleError) as exc:
        extract_verified_bundle(verified, destination=destination)

    assert exc.value.code == "unsafe_bundle_archive"
    assert "workspace could not be prepared" in exc.value.detail
    assert not destination.parent.exists()
