#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Build a deterministic unsigned Runtime release bundle from a wheelhouse."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

from ori.security.release_bundles import (
    MANIFEST_SCHEMA,
    ReleaseBundleError,
    release_artifact_name,
)

_COPY_CHUNK_BYTES = 1024 * 1024
_LOCKED_REQUIREMENT_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^ ;\\]+)(?:[ ;\\]|$)"
)


class BundleBuildError(Exception):
    """Raised when trusted build inputs cannot produce a release bundle."""


def build_release_bundle(
    *,
    wheelhouse: Path,
    runtime_version: str,
    target: str,
    config_template: Path,
    service_template: Path,
    output_dir: Path,
    source_date_epoch: int = 0,
) -> Path:
    """Build an exact, reproducible tar.gz without signing authority."""
    try:
        artifact_name = release_artifact_name(runtime_version, target)
    except ReleaseBundleError as exc:
        raise BundleBuildError(exc.detail) from exc
    if source_date_epoch < 0 or source_date_epoch > 0xFFFFFFFF:
        raise BundleBuildError("SOURCE_DATE_EPOCH is outside gzip timestamp bounds")
    expected_python = target.rsplit("python", 1)[1]
    running_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    if expected_python != running_python:
        raise BundleBuildError(
            "bundle target Python version does not match the trusted build interpreter"
        )
    _require_regular_directory(wheelhouse, "wheelhouse")
    _require_regular_file(config_template, "config template")
    _require_regular_file(service_template, "systemd service template")
    _validate_wheelhouse(wheelhouse, runtime_version)

    output_dir.mkdir(parents=True, exist_ok=True)
    artifact = output_dir / artifact_name
    if artifact.is_symlink():
        raise BundleBuildError("output artifact must not be a symlink")

    with tempfile.TemporaryDirectory(
        prefix=".ori-release-bundle-",
        dir=output_dir,
    ) as temporary_name:
        temporary = Path(temporary_name)
        root = temporary / artifact_name.removesuffix(".tar.gz")
        bundle_wheelhouse = root / "wheelhouse"
        bundle_wheelhouse.mkdir(parents=True, mode=0o700)
        for source in _release_wheelhouse_files(wheelhouse):
            _require_regular_file(source, f"wheelhouse entry {source.name!r}")
            shutil.copyfile(source, bundle_wheelhouse / source.name)

        templates = root / "templates"
        templates.mkdir(mode=0o700)
        shutil.copyfile(config_template, templates / "ori.linux.yaml.example")
        systemd = root / "systemd"
        systemd.mkdir(mode=0o700)
        shutil.copyfile(service_template, systemd / "ori-runtime.service")

        files = {
            path.relative_to(root).as_posix(): _sha256(path)
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }
        manifest = {
            "files": files,
            "python": target.rsplit("python", 1)[1],
            "runtime_version": runtime_version,
            "schema": MANIFEST_SCHEMA,
            "target": target,
        }
        (root / "BUNDLE-MANIFEST.json").write_text(
            json.dumps(
                manifest,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )

        candidate = temporary / f".{artifact_name}.tmp"
        _write_deterministic_tar_gz(
            root=root,
            destination=candidate,
            mtime=source_date_epoch,
        )
        os.chmod(candidate, 0o644)
        os.replace(candidate, artifact)

    checksum = output_dir / f"{artifact_name}.sha256"
    _atomic_write(
        checksum,
        f"{_sha256(artifact).removeprefix('sha256:')}  {artifact.name}\n".encode(),
        mode=0o644,
    )
    return artifact


def _validate_wheelhouse(wheelhouse: Path, runtime_version: str) -> None:
    requirements = wheelhouse / "requirements.txt"
    _require_regular_file(requirements, "wheelhouse requirements.txt")
    if "sha256:" not in requirements.read_text(encoding="utf-8"):
        raise BundleBuildError("wheelhouse requirements.txt is not hash-locked")

    wheel_identities: set[tuple[str, str]] = set()
    runtime_wheels: list[Path] = []
    for wheel in wheelhouse.glob("*.whl"):
        name, version = _wheel_identity(wheel)
        normalized_name = _normalize_distribution_name(name)
        wheel_identities.add((normalized_name, version))
        if normalized_name == "ori-runtime":
            runtime_wheels.append(wheel)
            if version != runtime_version:
                raise BundleBuildError(
                    "runtime wheel version does not match requested release version"
                )
    if len(runtime_wheels) != 1:
        raise BundleBuildError("wheelhouse must contain exactly one ori-runtime wheel")

    required_identities: set[tuple[str, str]] = set()
    requirement_files = sorted(wheelhouse.glob("requirements*.txt"))
    for requirement_file in requirement_files:
        _require_regular_file(
            requirement_file,
            f"wheelhouse requirement file {requirement_file.name!r}",
        )
        required_identities.update(_locked_requirements(requirement_file))
    missing = sorted(required_identities - wheel_identities)
    if missing:
        rendered = ", ".join(f"{name}=={version}" for name, version in missing)
        raise BundleBuildError(
            f"wheelhouse is not offline-complete; missing wheels: {rendered}"
        )


def _locked_requirements(path: Path) -> set[tuple[str, str]]:
    requirements: set[tuple[str, str]] = set()
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not raw_line or raw_line[0].isspace() or raw_line.startswith(("#", "--")):
            continue
        match = _LOCKED_REQUIREMENT_RE.match(raw_line)
        if match is None:
            raise BundleBuildError(
                f"unsupported requirement at {path.name}:{line_number}"
            )
        requirements.add((_normalize_distribution_name(match[1]), match[2]))
    if not requirements:
        raise BundleBuildError(f"{path.name} contains no locked requirements")
    return requirements


def _normalize_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _release_wheelhouse_files(wheelhouse: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(wheelhouse.iterdir(), key=lambda item: item.name):
        _require_regular_file(path, f"wheelhouse entry {path.name!r}")
        if path.name == "MANIFEST.sha256":
            continue
        if path.suffix == ".whl" or (
            path.name.startswith("requirements") and path.suffix == ".txt"
        ):
            files.append(path)
            continue
        raise BundleBuildError(f"unexpected wheelhouse entry {path.name!r}")
    return files


def _wheel_identity(path: Path) -> tuple[str, str]:
    _require_regular_file(path, f"wheel {path.name!r}")
    try:
        with zipfile.ZipFile(path) as archive:
            metadata_names = [
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_names) != 1:
                raise BundleBuildError(f"wheel {path.name!r} has ambiguous METADATA")
            metadata = archive.read(metadata_names[0]).decode("utf-8")
    except (OSError, UnicodeError, zipfile.BadZipFile, KeyError) as exc:
        raise BundleBuildError(f"wheel {path.name!r} is invalid") from exc
    fields: dict[str, str] = {}
    for line in metadata.splitlines():
        if line.startswith("Name: "):
            fields["name"] = line.removeprefix("Name: ").strip()
        elif line.startswith("Version: "):
            fields["version"] = line.removeprefix("Version: ").strip()
    if not fields.get("name") or not fields.get("version"):
        raise BundleBuildError(f"wheel {path.name!r} is missing Name or Version")
    return fields["name"], fields["version"]


def _write_deterministic_tar_gz(*, root: Path, destination: Path, mtime: int) -> None:
    paths = [root, *sorted(root.rglob("*"), key=lambda item: item.as_posix())]
    with destination.open("xb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=mtime
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                for path in paths:
                    relative = path.relative_to(root.parent).as_posix()
                    info = tarfile.TarInfo(relative)
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = mtime
                    info.mode = 0o755 if path.is_dir() else 0o644
                    if path.is_dir():
                        info.type = tarfile.DIRTYPE
                        info.size = 0
                        archive.addfile(info)
                    else:
                        info.type = tarfile.REGTYPE
                        info.size = path.stat().st_size
                        with path.open("rb") as source:
                            archive.addfile(info, source)


def _require_regular_directory(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise BundleBuildError(f"cannot inspect {label}") from exc
    if path.is_symlink() or not stat.S_ISDIR(mode):
        raise BundleBuildError(f"{label} must be a regular directory")


def _require_regular_file(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise BundleBuildError(f"cannot inspect {label}") from exc
    if path.is_symlink() or not stat.S_ISREG(mode):
        raise BundleBuildError(f"{label} must be a regular file")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_COPY_CHUNK_BYTES):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _atomic_write(path: Path, payload: bytes, *, mode: int) -> None:
    if path.is_symlink():
        raise BundleBuildError(f"output path {path.name!r} must not be a symlink")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as handle:
            os.chmod(temporary, mode)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic unsigned Ori Runtime release bundle."
    )
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--runtime-version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--config-template", required=True, type=Path)
    parser.add_argument("--service-template", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
    )
    args = parser.parse_args(argv)
    try:
        artifact = build_release_bundle(
            wheelhouse=args.wheelhouse,
            runtime_version=args.runtime_version,
            target=args.target,
            config_template=args.config_template,
            service_template=args.service_template,
            output_dir=args.output_dir,
            source_date_epoch=args.source_date_epoch,
        )
    except BundleBuildError as exc:
        parser.exit(2, f"bundle_build_failed: {exc}\n")
    print(artifact)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
