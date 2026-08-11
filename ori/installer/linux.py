# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed filesystem transaction for verified Linux releases."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from ori.security.release_bundles import ExtractedReleaseBundle

_VERSION_RE = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
    r"(?:-(?P<suffix>[a-zA-Z0-9][a-zA-Z0-9.-]*))?$"
)


class LinuxInstallError(Exception):
    """Stable installer failure safe to surface to operators."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class InstallLayout:
    root: Path
    releases: Path
    current: Path
    data: Path

    @classmethod
    def resolve(cls, root: str | Path) -> InstallLayout:
        candidate = Path(root).expanduser()
        if not candidate.is_absolute():
            raise LinuxInstallError(
                "unsafe_install_root", "install root must be absolute"
            )
        if candidate == Path(candidate.anchor):
            raise LinuxInstallError(
                "unsafe_install_root", "filesystem root is forbidden"
            )
        if candidate.exists() and candidate.is_symlink():
            raise LinuxInstallError(
                "unsafe_install_root", "install root must not be a symlink"
            )
        resolved = candidate.resolve(strict=False)
        return cls(
            root=resolved,
            releases=resolved / "releases",
            current=resolved / "current",
            data=resolved / "data",
        )

    def release(self, version: str) -> Path:
        if not _VERSION_RE.fullmatch(version):
            raise LinuxInstallError(
                "invalid_release_version", "version is not canonical"
            )
        return self.releases / version


@dataclass(frozen=True)
class InstallResult:
    version: str
    previous_version: str | None
    changed: bool
    rolled_back: bool


class OfflineReleasePreparer:
    """Build an isolated release environment without package-index access."""

    def __init__(
        self,
        *,
        bundle: ExtractedReleaseBundle,
        runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
        | None = None,
        bootstrap_python: str = sys.executable,
    ) -> None:
        self._bundle = bundle
        self._runner = runner or _run_command
        self._bootstrap_python = bootstrap_python

    def prepare(self, staging: Path) -> None:
        wheelhouse = self._bundle.root / "wheelhouse"
        requirements = wheelhouse / "requirements.txt"
        wheels = sorted(wheelhouse.glob("ori_runtime-*.whl"))
        if not wheelhouse.is_dir() or not requirements.is_file() or len(wheels) != 1:
            raise LinuxInstallError(
                "offline_install_failed", "verified wheelhouse is incomplete"
            )
        venv = staging / "venv"
        self._run([self._bootstrap_python, "-m", "venv", str(venv)])
        python = str(venv / "bin" / "python")
        base = [
            python,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse),
        ]
        self._run([*base, "--require-hashes", "-r", str(requirements)])
        pi_requirements = wheelhouse / "requirements-pi.txt"
        if pi_requirements.is_file():
            self._run([*base, "--require-hashes", "-r", str(pi_requirements)])
        self._run([*base, "--no-deps", str(wheels[0])])

    def validate(self, release: Path) -> None:
        python = release / "venv" / "bin" / "python"
        if not python.is_file():
            raise LinuxInstallError(
                "offline_install_failed", "release interpreter is missing"
            )
        self._run(
            [
                str(python),
                "-c",
                "import importlib.metadata as m; import ori.runtime; print(m.version('ori-runtime'))",
            ],
            expected_stdout=self._bundle.runtime_version,
        )

    def _run(
        self, command: Sequence[str], *, expected_stdout: str | None = None
    ) -> None:
        try:
            result = self._runner(command)
        except (OSError, subprocess.SubprocessError) as exc:
            raise LinuxInstallError(
                "offline_install_failed", "offline environment command could not run"
            ) from exc
        if result.returncode != 0:
            raise LinuxInstallError(
                "offline_install_failed", "offline environment command failed"
            )
        if expected_stdout is not None and result.stdout.strip() != expected_stdout:
            raise LinuxInstallError(
                "offline_install_failed", "installed Runtime version mismatch"
            )


def install_release(
    *,
    layout: InstallLayout,
    version: str,
    prepare: Callable[[Path], None],
    validate: Callable[[Path], None],
    restart_service: Callable[[], None],
    stop_service: Callable[[], None],
    check_health: Callable[[Path], None],
    allow_downgrade: bool = False,
) -> InstallResult:
    """Prepare, activate, and health-gate one already-authenticated release."""
    destination = layout.release(version)
    _ensure_private_directory(layout.root)
    _ensure_private_directory(layout.releases)
    _ensure_private_directory(layout.data)
    previous = _active_release(layout)
    previous_version = previous.name if previous is not None else None

    if previous == destination and destination.is_dir():
        validate(destination)
        return InstallResult(
            version, previous_version, changed=False, rolled_back=False
        )
    if previous_version is not None and _version_key(version) < _version_key(
        previous_version
    ):
        if not allow_downgrade:
            raise LinuxInstallError(
                "downgrade_forbidden", "use explicit downgrade approval"
            )

    created = False
    if not destination.exists():
        staging = layout.releases / f".{version}.{uuid.uuid4().hex}.staging"
        staging.mkdir(mode=0o700)
        try:
            prepare(staging)
            validate(staging)
            os.replace(staging, destination)
            created = True
            validate(destination)
        except Exception:
            if created and destination.exists():
                shutil.rmtree(destination)
            raise
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    elif not destination.is_dir() or destination.is_symlink():
        raise LinuxInstallError(
            "unsafe_install_root", "release destination is not a directory"
        )
    else:
        validate(destination)

    _set_active(layout, destination)
    try:
        restart_service()
        check_health(destination)
    except Exception as activation_error:
        try:
            if previous is None:
                layout.current.unlink(missing_ok=True)
                stop_service()
            else:
                _set_active(layout, previous)
                restart_service()
                check_health(previous)
        except Exception as rollback_error:
            raise LinuxInstallError(
                "rollback_failed",
                f"activation failed ({activation_error}); rollback failed ({rollback_error})",
            ) from rollback_error
        if created:
            shutil.rmtree(destination)
        raise LinuxInstallError(
            "post_install_health_failed",
            f"activation failed and was rolled back: {activation_error}",
        ) from activation_error

    return InstallResult(version, previous_version, changed=True, rolled_back=False)


def uninstall_runtime(
    *,
    layout: InstallLayout,
    stop_service: Callable[[], None],
    remove_data: bool = False,
) -> None:
    """Remove executable releases while retaining operator data by default."""
    _assert_managed_path(layout, layout.releases)
    try:
        stop_service()
    except Exception as exc:
        raise LinuxInstallError(
            "service_start_failed", "service could not be stopped"
        ) from exc
    layout.current.unlink(missing_ok=True)
    if layout.releases.is_symlink():
        raise LinuxInstallError("unsafe_install_root", "releases must not be a symlink")
    if layout.releases.exists():
        shutil.rmtree(layout.releases)
    if remove_data and layout.data.exists():
        _assert_managed_path(layout, layout.data)
        shutil.rmtree(layout.data)


def _active_release(layout: InstallLayout) -> Path | None:
    if not layout.current.exists() and not layout.current.is_symlink():
        return None
    if not layout.current.is_symlink():
        raise LinuxInstallError(
            "unsafe_install_root", "current must be a managed symlink"
        )
    target = layout.current.resolve(strict=False)
    _assert_managed_path(layout, target)
    if target.parent != layout.releases:
        raise LinuxInstallError(
            "unsafe_install_root", "current target is not a direct release"
        )
    if not target.exists():
        layout.current.unlink()
        return None
    if target.is_symlink() or not target.is_dir():
        raise LinuxInstallError("unsafe_install_root", "current release is unavailable")
    return target


def _set_active(layout: InstallLayout, release: Path) -> None:
    _assert_managed_path(layout, release)
    if (
        release.parent != layout.releases
        or release.is_symlink()
        or not release.is_dir()
    ):
        raise LinuxInstallError(
            "unsafe_install_root", "active release is not a direct directory"
        )
    temporary = layout.root / f".current.{uuid.uuid4().hex}.tmp"
    relative = release.relative_to(layout.root)
    os.symlink(relative, temporary)
    try:
        os.replace(temporary, layout.current)
    finally:
        temporary.unlink(missing_ok=True)


def _assert_managed_path(layout: InstallLayout, path: Path) -> None:
    try:
        path.resolve(strict=False).relative_to(layout.root)
    except ValueError as exc:
        raise LinuxInstallError(
            "unsafe_install_root", "path escapes install root"
        ) from exc


def _ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise LinuxInstallError(
            "unsafe_install_root", f"{path.name} must not be a symlink"
        )
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.is_dir():
        raise LinuxInstallError(
            "unsafe_install_root", f"{path.name} is not a directory"
        )
    path.chmod(0o700)


def _version_key(
    version: str,
) -> tuple[int, int, int, bool, tuple[tuple[int, int, str], ...]]:
    match = _VERSION_RE.fullmatch(version)
    if match is None:
        raise LinuxInstallError("invalid_release_version", "version is not canonical")
    suffix = match.group("suffix")
    prerelease = tuple(
        (0, int(identifier), "") if identifier.isdigit() else (1, 0, identifier)
        for identifier in (suffix or "").split(".")
        if identifier
    )
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        suffix is None,
        prerelease,
    )


def _run_command(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=300
    )
