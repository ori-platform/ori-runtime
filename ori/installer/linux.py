# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed filesystem transaction for verified Linux releases."""

from __future__ import annotations

import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, Sequence

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


@dataclass(frozen=True)
class SystemdServiceProfile:
    """Explicit systemd scope and unprivileged runtime identity."""

    scope: Literal["user", "system"]
    service_user: str | None

    def __post_init__(self) -> None:
        if self.scope == "user":
            if self.service_user is not None:
                raise LinuxInstallError(
                    "service_start_failed", "user units must not set User="
                )
            return
        if self.scope != "system" or self.service_user is None:
            raise LinuxInstallError(
                "service_start_failed", "service profile is inconsistent"
            )
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.service_user):
            raise LinuxInstallError(
                "service_start_failed", "system service user is invalid"
            )
        if self.service_user == "root":
            raise LinuxInstallError(
                "service_start_failed", "Runtime service user must be unprivileged"
            )

    @classmethod
    def user(cls) -> SystemdServiceProfile:
        return cls(scope="user", service_user=None)

    @classmethod
    def system(cls, service_user: str) -> SystemdServiceProfile:
        return cls(scope="system", service_user=service_user)


@dataclass(frozen=True)
class _PermissionChange:
    path: Path
    uid: int
    gid: int
    mode: int
    original_uid: int
    original_gid: int
    original_mode: int
    device: int
    inode: int


@dataclass(frozen=True)
class BootPersistence:
    enabled: bool
    detail: str


class SystemdServiceManager:
    """Shell-free systemd lifecycle adapter with explicit unit scope."""

    def __init__(
        self,
        *,
        profile: SystemdServiceProfile,
        unit_path: Path,
        runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
        | None = None,
        effective_uid: int | None = None,
    ) -> None:
        self._profile = profile
        self._unit_path = unit_path
        self._runner = runner or _run_command
        self._effective_uid = os.geteuid() if effective_uid is None else effective_uid
        if (
            not unit_path.is_absolute()
            or unit_path.name != "ori-runtime.service"
            or unit_path.parent.resolve(strict=False) != unit_path.parent
        ):
            raise LinuxInstallError(
                "service_start_failed", "systemd unit path is unsafe"
            )
        if profile.scope == "system" and self._effective_uid != 0:
            raise LinuxInstallError(
                "service_start_failed", "system unit management requires root"
            )
        if profile.scope == "user" and self._effective_uid == 0:
            raise LinuxInstallError(
                "service_start_failed", "user unit must not run as root"
            )

    def install_unit(self, rendered: str) -> None:
        """Atomically place a rendered unit without enabling or starting it."""
        if "@ORI_" in rendered or "\x00" in rendered:
            raise LinuxInstallError(
                "service_start_failed", "rendered service unit is invalid"
            )
        self._validate_unit_profile(rendered)
        parent = self._unit_path.parent
        if parent.is_symlink():
            raise LinuxInstallError(
                "service_start_failed", "systemd unit directory must not be a symlink"
            )
        parent.mkdir(parents=True, exist_ok=True, mode=self._directory_mode())
        previous: tuple[bytes, int] | None = None
        installed = False
        try:
            if self._unit_path.is_symlink() or (
                self._unit_path.exists() and not self._unit_path.is_file()
            ):
                raise LinuxInstallError(
                    "service_start_failed", "managed service unit is unsafe"
                )
            if self._unit_path.is_file():
                previous = (
                    self._unit_path.read_bytes(),
                    stat.S_IMODE(self._unit_path.stat().st_mode),
                )
            installed = True
            self._atomic_write(rendered.encode("utf-8"), self._unit_mode())
            self._run([*self._systemctl(), "daemon-reload"], "daemon reload")
        except (LinuxInstallError, OSError) as exc:
            if not installed:
                if isinstance(exc, LinuxInstallError):
                    raise
                raise LinuxInstallError(
                    "service_start_failed", "service unit could not be installed"
                ) from exc
            try:
                if previous is None:
                    self._unit_path.unlink(missing_ok=True)
                else:
                    self._atomic_write(previous[0], previous[1])
                self._run([*self._systemctl(), "daemon-reload"], "rollback reload")
            except (LinuxInstallError, OSError) as rollback_error:
                raise LinuxInstallError(
                    "service_start_failed",
                    "service unit installation and rollback failed",
                ) from rollback_error
            if isinstance(exc, LinuxInstallError):
                raise
            raise LinuxInstallError(
                "service_start_failed", "service unit could not be installed"
            ) from exc

    def restart(self) -> None:
        self._run([*self._systemctl(), "restart", self._unit_path.name], "restart")

    def stop(self) -> None:
        self._run([*self._systemctl(), "stop", self._unit_path.name], "stop")

    def enable(self) -> BootPersistence:
        self._run([*self._systemctl(), "enable", self._unit_path.name], "enable")
        return self.boot_persistence()

    def boot_persistence(self) -> BootPersistence:
        if self._profile.scope == "system":
            result = self._run_raw(["systemctl", "is-enabled", self._unit_path.name])
            state = result.stdout.strip().lower()
            if state == "enabled" and result.returncode == 0:
                return BootPersistence(True, "system unit enabled for boot")
            if state in {
                "alias",
                "bad",
                "disabled",
                "enabled-runtime",
                "generated",
                "indirect",
                "linked",
                "linked-runtime",
                "masked",
                "masked-runtime",
                "not-found",
                "static",
                "transient",
            }:
                return BootPersistence(
                    False, f"system unit is {state}; boot startup is not persistent"
                )
            raise LinuxInstallError(
                "service_start_failed", "service enablement query was malformed"
            )
        result = self._run_raw(
            [
                "loginctl",
                "show-user",
                str(self._effective_uid),
                "-p",
                "Linger",
                "--value",
            ]
        )
        if result.returncode != 0:
            raise LinuxInstallError(
                "service_start_failed", "service linger query failed"
            )
        linger_value = result.stdout.strip().lower()
        if linger_value not in {"yes", "no"}:
            raise LinuxInstallError(
                "service_start_failed", "service linger query was malformed"
            )
        linger = linger_value == "yes"
        detail = (
            "user lingering is enabled"
            if linger
            else "user lingering is disabled; boot startup is not persistent"
        )
        return BootPersistence(linger, detail)

    def disable_and_remove(self) -> None:
        if self._unit_path.is_symlink():
            raise LinuxInstallError(
                "service_start_failed", "service unit must not be a symlink"
            )
        if not self._unit_path.exists() and not self._unit_path.is_symlink():
            self._run([*self._systemctl(), "daemon-reload"], "daemon reload")
            return
        self._run(
            [*self._systemctl(), "disable", "--now", self._unit_path.name],
            "disable",
        )
        try:
            self._unit_path.unlink(missing_ok=True)
        except OSError as exc:
            raise LinuxInstallError(
                "service_start_failed", "service unit could not be removed"
            ) from exc
        self._run([*self._systemctl(), "daemon-reload"], "daemon reload")

    def _atomic_write(self, content: bytes, mode: int) -> None:
        temporary = self._unit_path.parent / (
            f".{self._unit_path.name}.{uuid.uuid4().hex}.tmp"
        )
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                mode,
            )
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                output.write(content)
                output.flush()
                os.fsync(descriptor)
            os.fchmod(descriptor, mode)
            os.replace(temporary, self._unit_path)
            parent_descriptor = os.open(
                self._unit_path.parent,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
            )
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)

    def _validate_unit_profile(self, rendered: str) -> None:
        section = ""
        users: list[str] = []
        targets: list[str] = []
        for raw_line in rendered.splitlines():
            if raw_line.rstrip().endswith("\\"):
                raise LinuxInstallError(
                    "service_start_failed", "service unit continuations are forbidden"
                )
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if section == "Service" and key.strip() == "User":
                users.append(value.strip())
            if section == "Install" and key.strip() == "WantedBy":
                targets.append(value.strip())
        expected_target = (
            "default.target" if self._profile.scope == "user" else "multi-user.target"
        )
        if targets != [expected_target]:
            raise LinuxInstallError(
                "service_start_failed", "service unit target does not match profile"
            )
        if self._profile.scope == "user":
            valid_user = not users
        else:
            valid_user = users == [self._profile.service_user]
        if not valid_user:
            raise LinuxInstallError(
                "service_start_failed", "service unit identity does not match profile"
            )

    def _systemctl(self) -> list[str]:
        return (
            ["systemctl", "--user"] if self._profile.scope == "user" else ["systemctl"]
        )

    def _directory_mode(self) -> int:
        return 0o700 if self._profile.scope == "user" else 0o755

    def _unit_mode(self) -> int:
        return 0o600 if self._profile.scope == "user" else 0o644

    def _run(self, command: Sequence[str], operation: str) -> None:
        result = self._run_raw(command)
        if result.returncode != 0:
            raise LinuxInstallError(
                "service_start_failed", f"service {operation} failed"
            )

    def _run_raw(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            result = self._runner(command)
        except (OSError, subprocess.SubprocessError) as exc:
            raise LinuxInstallError(
                "service_start_failed", "service command could not run"
            ) from exc
        return result


def render_systemd_unit(
    template: str,
    *,
    profile: SystemdServiceProfile,
    root: Path,
    data_dir: Path,
    config_path: Path,
    env_file: Path,
) -> str:
    """Render a shell-free unit without mixing user and system semantics."""
    paths = {
        "@ORI_ROOT@": root,
        "@ORI_DATA_DIR@": data_dir,
        "@ORI_CONFIG@": config_path,
        "@ORI_ENV_FILE@": env_file,
    }
    rendered = template
    for marker, path in paths.items():
        value = str(path)
        if (
            not path.is_absolute()
            or any(character.isspace() for character in value)
            or "%" in value
            or "@" in value
        ):
            raise LinuxInstallError(
                "unsafe_install_root", "systemd paths contain unsafe unit syntax"
            )
        if marker not in rendered:
            raise LinuxInstallError(
                "service_start_failed", f"service template is missing {marker}"
            )
        rendered = rendered.replace(marker, value)

    if "@ORI_USER_DIRECTIVE@" not in rendered or "@ORI_WANTED_BY@" not in rendered:
        raise LinuxInstallError(
            "service_start_failed", "service template is missing profile markers"
        )
    if profile.scope == "user":
        user_directive = ""
        wanted_by = "default.target"
    elif profile.scope == "system" and profile.service_user is not None:
        user_directive = f"User={profile.service_user}"
        wanted_by = "multi-user.target"
    else:
        raise LinuxInstallError(
            "service_start_failed", "service profile is inconsistent"
        )
    rendered = rendered.replace("@ORI_USER_DIRECTIVE@", user_directive)
    rendered = rendered.replace("@ORI_WANTED_BY@", wanted_by)
    if re.search(r"@[A-Z0-9_]+@", rendered):
        raise LinuxInstallError(
            "service_start_failed", "service template has unresolved markers"
        )
    return rendered


def apply_system_service_permissions(
    layout: InstallLayout, profile: SystemdServiceProfile
) -> None:
    """Make verified code readable, and only data writable, by a system service."""
    if profile.scope != "system" or profile.service_user is None:
        raise LinuxInstallError(
            "service_start_failed", "system permissions require a system profile"
        )
    if os.geteuid() != 0:
        raise LinuxInstallError(
            "service_start_failed", "system permissions require root"
        )
    try:
        account = pwd.getpwnam(profile.service_user)
    except KeyError as exc:
        raise LinuxInstallError(
            "service_start_failed", "system service user does not exist"
        ) from exc

    _assert_managed_path(layout, layout.root)
    root_stat = layout.root.lstat()
    plan = [
        _permission_change(
            layout.root, root_stat, uid=0, gid=account.pw_gid, mode=0o750
        )
    ]
    plan.extend(
        _owned_tree_plan(
            layout,
            layout.releases,
            uid=0,
            gid=account.pw_gid,
            directory_mode=0o750,
            regular_mode=0o440,
            executable_mode=0o550,
            allow_file_symlinks=True,
        )
    )
    _assert_managed_path(layout, layout.data)
    plan.extend(
        _owned_tree_plan(
            layout,
            layout.data,
            uid=account.pw_uid,
            gid=account.pw_gid,
            directory_mode=0o700,
            regular_mode=0o600,
            executable_mode=0o700,
            allow_file_symlinks=False,
        )
    )
    _apply_permission_plan(plan)


def _owned_tree_plan(
    layout: InstallLayout,
    root: Path,
    *,
    uid: int,
    gid: int,
    directory_mode: int,
    regular_mode: int,
    executable_mode: int,
    allow_file_symlinks: bool,
) -> list[_PermissionChange]:
    if root.is_symlink() or not root.is_dir():
        raise LinuxInstallError(
            "unsafe_install_root", "permission root must be a managed directory"
        )
    plan: list[_PermissionChange] = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        _assert_managed_path(layout, current_path)
        plan.append(
            _permission_change(
                current_path,
                current_path.lstat(),
                uid=uid,
                gid=gid,
                mode=directory_mode,
            )
        )
        for directory in directories:
            path = current_path / directory
            if path.is_symlink():
                if not allow_file_symlinks:
                    raise LinuxInstallError(
                        "unsafe_install_root", "data symlinks are forbidden"
                    )
                _validate_release_symlink(layout, path, require_internal=True)
        for filename in files:
            path = current_path / filename
            if path.is_symlink():
                if not allow_file_symlinks:
                    raise LinuxInstallError(
                        "unsafe_install_root", "data symlinks are forbidden"
                    )
                _validate_release_symlink(layout, path, require_internal=False)
                continue
            if not path.is_file():
                raise LinuxInstallError(
                    "unsafe_install_root", "special files are forbidden"
                )
            path_stat = path.lstat()
            existing_mode = path_stat.st_mode
            mode = executable_mode if existing_mode & 0o100 else regular_mode
            plan.append(
                _permission_change(path, path_stat, uid=uid, gid=gid, mode=mode)
            )
    return plan


def _validate_release_symlink(
    layout: InstallLayout, path: Path, *, require_internal: bool
) -> None:
    try:
        relative = path.relative_to(layout.releases)
        release_root = layout.releases / relative.parts[0]
        target = path.resolve(strict=True)
        target.relative_to(layout.root)
    except (OSError, RuntimeError, ValueError) as exc:
        if require_internal:
            raise LinuxInstallError(
                "unsafe_install_root", "release directory symlink escapes its release"
            ) from exc
    else:
        try:
            target.relative_to(release_root)
        except ValueError:
            if require_internal:
                raise LinuxInstallError(
                    "unsafe_install_root",
                    "release directory symlink escapes its release",
                )
        else:
            expected = target.is_dir() if require_internal else target.is_file()
            if not expected:
                raise LinuxInstallError(
                    "unsafe_install_root", "release symlink target has wrong type"
                )
            return

    if require_internal:
        raise LinuxInstallError(
            "unsafe_install_root", "release directory symlink escapes its release"
        )
    try:
        target_stat = path.resolve(strict=True).stat()
    except (OSError, RuntimeError) as exc:
        raise LinuxInstallError(
            "unsafe_install_root", "release file symlink target is unavailable"
        ) from exc
    target_mode = stat.S_IMODE(target_stat.st_mode)
    if (
        not stat.S_ISREG(target_stat.st_mode)
        or target_stat.st_uid != 0
        or target_mode & 0o022
        or not target_mode & 0o111
    ):
        raise LinuxInstallError(
            "unsafe_install_root", "external release symlink target is not trusted"
        )


def _permission_change(
    path: Path, path_stat: os.stat_result, *, uid: int, gid: int, mode: int
) -> _PermissionChange:
    return _PermissionChange(
        path=path,
        uid=uid,
        gid=gid,
        mode=mode,
        original_uid=path_stat.st_uid,
        original_gid=path_stat.st_gid,
        original_mode=stat.S_IMODE(path_stat.st_mode),
        device=path_stat.st_dev,
        inode=path_stat.st_ino,
    )


def _apply_permission_plan(plan: Sequence[_PermissionChange]) -> None:
    applied: list[_PermissionChange] = []
    try:
        for change in plan:
            _set_owned_mode(change, change.uid, change.gid, change.mode)
            applied.append(change)
    except (OSError, NotImplementedError) as exc:
        for change in reversed(applied):
            try:
                _set_owned_mode(
                    change,
                    change.original_uid,
                    change.original_gid,
                    change.original_mode,
                )
            except (OSError, NotImplementedError):
                # Preserve the initiating failure; rollback is best effort after
                # the permission transaction has already become unrecoverable.
                pass
        raise LinuxInstallError(
            "service_start_failed", "service filesystem permissions could not be set"
        ) from exc


def _set_owned_mode(change: _PermissionChange, uid: int, gid: int, mode: int) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(change.path, flags)
    try:
        current = os.fstat(descriptor)
        if current.st_dev != change.device or current.st_ino != change.inode:
            raise OSError("permission target changed after validation")
        try:
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
        except (OSError, NotImplementedError):
            try:
                os.fchown(descriptor, current.st_uid, current.st_gid)
                os.fchmod(descriptor, stat.S_IMODE(current.st_mode))
            except (OSError, NotImplementedError):
                # Preserve the original ownership/mode failure; the caller rolls
                # back earlier entries and maps it to the stable service error.
                pass
            raise
    finally:
        os.close(descriptor)


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
    service_profile: SystemdServiceProfile | None = None,
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
        if service_profile is not None and service_profile.scope == "system":
            apply_system_service_permissions(layout, service_profile)
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

    if service_profile is not None and service_profile.scope == "system":
        try:
            apply_system_service_permissions(layout, service_profile)
        except Exception:
            if created and destination.exists():
                shutil.rmtree(destination)
            raise
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
    created = not path.exists()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.is_dir():
        raise LinuxInstallError(
            "unsafe_install_root", f"{path.name} is not a directory"
        )
    if created:
        path.chmod(0o700)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o020:
        raise LinuxInstallError("unsafe_install_root", f"{path.name} is group-writable")
    if mode & 0o007:
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
