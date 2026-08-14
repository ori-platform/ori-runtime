# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import runpy
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ori.security.release_bundles import (
    KEY_REGISTRY_SCHEMA,
    RELEASE_KEY_PURPOSE,
    ReleaseBundleError,
    ReleaseKey,
    create_signature_envelope,
    extract_verified_bundle,
    verify_release_bundle,
    write_signature_envelope,
)
from scripts.build_release_bundle import BundleBuildError, build_release_bundle

VERSION = "2.3.0"
TARGET = f"linux-x86_64-python{sys.version_info.major}.{sys.version_info.minor}"
KEY_ID = "ori-runtime-release-test"


# ZIP stores modification times as DOS timestamps with two-second resolution,
# and `writestr` stamps entries with the current local time. Two wheels built
# either side of a two-second boundary therefore differ by two bytes, which
# would make the determinism assertion below fail intermittently on inputs
# rather than on the builder it is meant to test.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def _add_zip_entry(archive: zipfile.ZipFile, name: str, data: str) -> None:
    info = zipfile.ZipInfo(name, date_time=_ZIP_EPOCH)
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def _write_runtime_wheel(path: Path, version: str = VERSION) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        _add_zip_entry(
            archive,
            f"ori_runtime-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: ori-runtime\nVersion: {version}\n",
        )


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    (wheelhouse / "requirements.txt").write_text(
        "PyYAML==6.0.2 --hash=sha256:" + "a" * 64 + "\n",
        encoding="utf-8",
    )
    _write_runtime_wheel(wheelhouse / f"ori_runtime-{VERSION}-py3-none-any.whl")
    with zipfile.ZipFile(wheelhouse / "PyYAML-6.0.2-py3-none-any.whl", "w") as archive:
        _add_zip_entry(
            archive,
            "pyyaml-6.0.2.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: PyYAML\nVersion: 6.0.2\n",
        )
    (wheelhouse / "MANIFEST.sha256").write_text(
        "legacy manifest with /builder-specific/absolute/path\n",
        encoding="utf-8",
    )
    config = tmp_path / "ori.linux.yaml.example"
    config.write_text("device: {}\n", encoding="utf-8")
    service = tmp_path / "ori-runtime.service.in"
    service.write_text("[Service]\nExecStart=@ORI_ROOT@/runtime\n", encoding="utf-8")
    return wheelhouse, config, service


def _build(tmp_path: Path, output_name: str) -> Path:
    wheelhouse, config, service = _inputs(tmp_path)
    return build_release_bundle(
        wheelhouse=wheelhouse,
        runtime_version=VERSION,
        target=TARGET,
        config_template=config,
        service_template=service,
        output_dir=tmp_path / output_name,
        source_date_epoch=1_700_000_000,
    )


def _write_key_registry(
    path: Path,
    private_key: Ed25519PrivateKey,
    *,
    status: str = "active",
) -> None:
    public = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": KEY_ID,
                        "public_key_b64": base64.b64encode(public).decode("ascii"),
                        "purpose": RELEASE_KEY_PURPOSE,
                        "status": status,
                    }
                ],
                "schema": KEY_REGISTRY_SCHEMA,
            }
        ),
        encoding="utf-8",
    )


def _archive_fingerprint(path: Path) -> dict[str, object]:
    """Describe an archive precisely enough to explain a determinism failure."""
    raw = path.read_bytes()
    with gzip.open(path, "rb") as handle:
        decompressed = handle.read()
    with tarfile.open(path, "r:gz") as archive:
        members = [
            {
                "name": member.name,
                "type": member.type,
                "size": member.size,
                "mtime": member.mtime,
                "mode": oct(member.mode),
                "uid": member.uid,
                "gid": member.gid,
                "uname": member.uname,
                "gname": member.gname,
            }
            for member in archive.getmembers()
        ]
        manifest = archive.extractfile("ori-runtime/BUNDLE-MANIFEST.json")
        manifest_bytes = manifest.read() if manifest is not None else b""
    return {
        "gzip_header": raw[:10].hex(),  # includes the embedded mtime and flags
        "member_order": [m["name"] for m in members],
        "members": members,
        "manifest": manifest_bytes,
        "uncompressed_sha256": hashlib.sha256(decompressed).hexdigest(),
    }


def _explain_difference(first: Path, second: Path) -> str:
    left, right = _archive_fingerprint(first), _archive_fingerprint(second)
    differences = [key for key in left if left[key] != right[key]]
    lines = [f"bundles differ in: {differences or 'compressed bytes only'}"]
    for member_a, member_b in zip(left["members"], right["members"]):
        if member_a != member_b:
            lines.append(f"  first  {member_a}")
            lines.append(f"  second {member_b}")
    return "\n".join(lines)


def test_build_is_deterministic_and_verifies_end_to_end(tmp_path: Path) -> None:
    first = _build(tmp_path / "first", "dist")
    second = _build(tmp_path / "second", "dist")
    if first.read_bytes() != second.read_bytes():
        kept = tmp_path.parent / "determinism-failure"
        kept.mkdir(exist_ok=True)
        shutil.copy2(first, kept / "first.tar.gz")
        shutil.copy2(second, kept / "second.tar.gz")
        pytest.fail(f"{_explain_difference(first, second)}\nartifacts kept in {kept}")

    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    envelope = create_signature_envelope(
        artifact_path=first,
        runtime_version=VERSION,
        target=TARGET,
        key_id=KEY_ID,
        signer=private_key.sign,
    )
    signature_path = first.with_name(f"{first.name}.signature.json")
    write_signature_envelope(signature_path, envelope)
    public = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    verified = verify_release_bundle(
        artifact_path=first,
        envelope_path=signature_path,
        key_registry={
            KEY_ID: ReleaseKey(
                key_id=KEY_ID,
                public_key_b64=base64.b64encode(public).decode("ascii"),
                purpose=RELEASE_KEY_PURPOSE,
            )
        },
    )

    extracted = extract_verified_bundle(verified, destination=tmp_path / "extract")
    manifest = json.loads((extracted.root / "BUNDLE-MANIFEST.json").read_text())
    assert manifest["runtime_version"] == VERSION
    assert "wheelhouse/requirements.txt" in manifest["files"]
    assert "wheelhouse/MANIFEST.sha256" not in manifest["files"]
    checksum = first.with_name(f"{first.name}.sha256").read_text().split()[0]
    assert checksum == hashlib.sha256(first.read_bytes()).hexdigest()


def test_rejects_unlocked_requirements(tmp_path: Path) -> None:
    wheelhouse, config, service = _inputs(tmp_path)
    (wheelhouse / "requirements.txt").write_text("PyYAML==6.0.2\n")

    with pytest.raises(BundleBuildError, match="not hash-locked"):
        build_release_bundle(
            wheelhouse=wheelhouse,
            runtime_version=VERSION,
            target=TARGET,
            config_template=config,
            service_template=service,
            output_dir=tmp_path / "dist",
        )


def test_rejects_runtime_wheel_version_mismatch(tmp_path: Path) -> None:
    wheelhouse, config, service = _inputs(tmp_path)
    next(wheelhouse.glob("ori_runtime*.whl")).unlink()
    _write_runtime_wheel(wheelhouse / "ori_runtime-9.9.9-py3-none-any.whl", "9.9.9")

    with pytest.raises(BundleBuildError, match="does not match"):
        build_release_bundle(
            wheelhouse=wheelhouse,
            runtime_version=VERSION,
            target=TARGET,
            config_template=config,
            service_template=service,
            output_dir=tmp_path / "dist",
        )


def test_rejects_wheelhouse_missing_locked_dependency_wheel(tmp_path: Path) -> None:
    wheelhouse, config, service = _inputs(tmp_path)
    (wheelhouse / "PyYAML-6.0.2-py3-none-any.whl").unlink()

    with pytest.raises(BundleBuildError, match="not offline-complete"):
        build_release_bundle(
            wheelhouse=wheelhouse,
            runtime_version=VERSION,
            target=TARGET,
            config_template=config,
            service_template=service,
            output_dir=tmp_path / "dist",
        )


def test_rejects_symlinked_wheelhouse_entry(tmp_path: Path) -> None:
    wheelhouse, config, service = _inputs(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    (wheelhouse / "linked.txt").symlink_to(outside)

    with pytest.raises(BundleBuildError, match="regular file"):
        build_release_bundle(
            wheelhouse=wheelhouse,
            runtime_version=VERSION,
            target=TARGET,
            config_template=config,
            service_template=service,
            output_dir=tmp_path / "dist",
        )


def test_rejects_unsupported_target_without_traceback(tmp_path: Path) -> None:
    wheelhouse, config, service = _inputs(tmp_path)

    with pytest.raises(BundleBuildError, match="target is unsupported"):
        build_release_bundle(
            wheelhouse=wheelhouse,
            runtime_version=VERSION,
            target="linux-armv7l-python3.12",
            config_template=config,
            service_template=service,
            output_dir=tmp_path / "dist",
        )


def test_offline_signing_cli_produces_verifiable_envelope(tmp_path: Path) -> None:
    artifact = _build(tmp_path, "dist")
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    private_key_path = tmp_path / "release-key.pem"
    private_key_path.write_bytes(
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    private_key_path.chmod(0o600)
    registry_path = tmp_path / "release-keys.json"
    _write_key_registry(registry_path, private_key)
    signature_path = artifact.with_name(f"{artifact.name}.signature.json")
    env = dict(os.environ)
    env.pop("GITHUB_ACTIONS", None)

    result = subprocess.run(
        [
            sys.executable,
            "scripts/sign-release-bundle.py",
            "--artifact",
            str(artifact),
            "--runtime-version",
            VERSION,
            "--target",
            TARGET,
            "--key-id",
            KEY_ID,
            "--key-registry",
            str(registry_path),
            "--private-key-file",
            str(private_key_path),
            "--output",
            str(signature_path),
        ],
        cwd=Path.cwd(),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    public = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=signature_path,
        key_registry={
            KEY_ID: ReleaseKey(
                key_id=KEY_ID,
                public_key_b64=base64.b64encode(public).decode("ascii"),
            )
        },
    )
    assert verified.key_id == KEY_ID


def test_private_key_loader_closes_descriptor_when_fstat_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "release-key.pem"
    key_path.write_text("not inspected", encoding="utf-8")
    key_path.chmod(0o600)
    script = runpy.run_path("scripts/sign-release-bundle.py")
    load_private_key = script["_load_private_key"]
    closed: list[int] = []
    real_close = os.close

    def fail_fstat(_fd: int) -> os.stat_result:
        raise OSError("simulated descriptor inspection failure")

    def record_close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(os, "fstat", fail_fstat)
    monkeypatch.setattr(os, "close", record_close)

    with pytest.raises(ReleaseBundleError, match="cannot inspect private key"):
        load_private_key(key_path)

    assert len(closed) == 1


def test_local_private_key_signing_cli_refuses_github_actions(tmp_path: Path) -> None:
    artifact = _build(tmp_path, "dist")
    key_path = tmp_path / "release-key.pem"
    key_path.write_text("not used", encoding="utf-8")
    key_path.chmod(0o600)
    registry_path = tmp_path / "release-keys.json"
    _write_key_registry(
        registry_path, Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    )
    env = {**os.environ, "GITHUB_ACTIONS": "true"}

    result = subprocess.run(
        [
            sys.executable,
            "scripts/sign-release-bundle.py",
            "--artifact",
            str(artifact),
            "--runtime-version",
            VERSION,
            "--target",
            TARGET,
            "--key-id",
            KEY_ID,
            "--key-registry",
            str(registry_path),
            "--private-key-file",
            str(key_path),
            "--output",
            str(tmp_path / "signature.json"),
        ],
        cwd=Path.cwd(),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "forbidden in GitHub Actions" in result.stderr
    assert not (tmp_path / "signature.json").exists()


def test_signing_cli_refuses_verify_only_key_for_new_release(tmp_path: Path) -> None:
    artifact = _build(tmp_path, "dist")
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    key_path = tmp_path / "release-key.pem"
    key_path.write_bytes(
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    key_path.chmod(0o600)
    registry_path = tmp_path / "release-keys.json"
    _write_key_registry(registry_path, private_key, status="verify_only")
    output = tmp_path / "signature.json"
    env = dict(os.environ)
    env.pop("GITHUB_ACTIONS", None)

    result = subprocess.run(
        [
            sys.executable,
            "scripts/sign-release-bundle.py",
            "--artifact",
            str(artifact),
            "--runtime-version",
            VERSION,
            "--target",
            TARGET,
            "--key-id",
            KEY_ID,
            "--key-registry",
            str(registry_path),
            "--private-key-file",
            str(key_path),
            "--output",
            str(output),
        ],
        cwd=Path.cwd(),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "must be active" in result.stderr
    assert not output.exists()
