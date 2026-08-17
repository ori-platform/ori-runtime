# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Post-installation diagnostics for an installed Ori Runtime.

Checks are classified so callers can act on them. A *mandatory* failure means
the installation is not usable — an invalid or unreadable config, a runtime
that is not running or reports a different device, or permissions that would
stop the service reading what it needs. Everything else is advisory: a user
service that will not survive logout is a real warning, but it is not a reason
to roll back a working install, and a deliberately disabled integration is not
a fault at all.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import socket
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from ori.utils import terminal

PASS = terminal.PASS
WARN = terminal.WARN
FAIL = terminal.FAIL
_STATUSES = (PASS, WARN, FAIL)

CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class UnsafeExecutionError(Exception):
    """Running these checks here would execute untrusted code with privilege."""


@dataclass(frozen=True)
class DoctorCheck:
    """One diagnostic result.

    ``mandatory`` marks a check whose failure means the installation cannot be
    used, so an installer may roll back on it.
    """

    name: str
    status: str
    message: str
    mandatory: bool = False
    remedy: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise ValueError(f"invalid doctor status: {self.status!r}")


@dataclass(frozen=True)
class InstallIdentity:
    """Where an installation lives and how it runs."""

    scope: str
    version: str
    install_root: Path
    active_release: Path
    config_path: Path
    data_path: Path
    health_socket: Path
    unit_path: Path
    service_user: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "version": self.version,
            "install_root": str(self.install_root),
            "active_release": str(self.active_release),
            "config_path": str(self.config_path),
            "data_path": str(self.data_path),
            "health_socket": str(self.health_socket),
            "unit_path": str(self.unit_path),
            "service_user": self.service_user,
        }


def blocking_failures(checks: Sequence[DoctorCheck]) -> list[DoctorCheck]:
    """Return failures that make an installation unusable."""
    return [c for c in checks if c.status == FAIL and c.mandatory]


def has_failures(checks: Sequence[DoctorCheck]) -> bool:
    return any(c.status == FAIL for c in checks)


def assert_execution_allowed(identity: InstallIdentity) -> None:
    """Refuse to run an installation's own code with borrowed privilege.

    Diagnostics execute the interpreter inside the active release. A user-scope
    release is writable by that user, so running it as root would turn
    ``sudo ori doctor --scope user`` into privilege escalation: anyone able to
    edit their own installation could choose what root executes.

    Detecting scope stays privilege-independent — root may legitimately *ask*
    where a user installation lives. Only execution is constrained.
    """
    if os.geteuid() != 0:
        return
    if identity.scope == "user":
        raise UnsafeExecutionError(
            "refusing to execute a user-scope installation as root: "
            f"{identity.active_release} is writable by its owner. "
            "Re-run without sudo, as the user who owns the installation."
        )
    # A `system` label is a claim, not a guarantee: it can be supplied
    # alongside a root that points into a user's home. What actually makes
    # execution safe is that no unprivileged account can alter the interpreter
    # or anything leading to it, so that is what gets verified.
    untrusted = _first_untrusted_component(interpreter_path(identity))
    if untrusted is not None:
        raise UnsafeExecutionError(
            f"refusing to execute as root: {untrusted} is not owned by root or "
            "is writable by another account, so its contents are not trusted "
            "with privilege. Inspect this installation as the user who owns it."
        )


def interpreter_path(identity: InstallIdentity) -> Path:
    """The interpreter every diagnostic subprocess runs."""
    return identity.active_release / "venv" / "bin" / "python"


def _first_untrusted_component(path: Path) -> Path | None:
    """Return the first component root should not trust, walking downwards.

    A missing component ends the walk successfully: if every existing ancestor
    is root-owned and unwritable by others, no unprivileged account can create
    what is missing, so nothing there can be planted.
    """
    for candidate in [*reversed(path.parents), path]:
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            return candidate
        if info.st_uid != 0 or info.st_mode & 0o022:
            return candidate
    return None


def _run(
    command: Sequence[str], runner: CommandRunner
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(command)
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(list(command), 1, "", str(exc))


def _default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=30
    )


def check_paths(identity: InstallIdentity) -> list[DoctorCheck]:
    """Report where this installation lives, so scope is never ambiguous."""
    return [
        DoctorCheck(
            name="install.identity",
            status=PASS,
            message=(
                f"Ori {identity.version} installed in {identity.scope} scope at "
                f"{identity.install_root}"
            ),
            details=identity.as_dict(),
        )
    ]


def check_config(identity: InstallIdentity, runner: CommandRunner) -> list[DoctorCheck]:
    """Validate the installed config through the runtime's own validator."""
    if not identity.config_path.is_file():
        return [
            DoctorCheck(
                name="config.present",
                status=FAIL,
                message=f"Config not found at {identity.config_path}",
                mandatory=True,
                remedy="Reinstall, or restore the config from backup.",
            )
        ]
    if not os.access(identity.config_path, os.R_OK):
        return [
            DoctorCheck(
                name="config.readable",
                status=FAIL,
                message=f"Config is not readable: {identity.config_path}",
                mandatory=True,
                remedy=f"Check ownership and mode on {identity.config_path}.",
            )
        ]
    result = _run(
        [
            str(interpreter_path(identity)),
            "-m",
            "ori.cli_bridge",
            "config",
            "validate",
            "--path",
            str(identity.config_path),
        ],
        runner,
    )
    if result.returncode == 0:
        return [
            DoctorCheck(
                name="config.valid",
                status=PASS,
                message="Config validates.",
                details={"config_path": str(identity.config_path)},
            )
        ]
    return [
        DoctorCheck(
            name="config.valid",
            status=FAIL,
            message="Config failed validation.",
            mandatory=True,
            remedy=f"Run: ori config validate --path {identity.config_path}",
            details={"detail": _error_detail(result.stdout)},
        )
    ]


def _error_detail(stdout: str) -> str:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return stdout.strip()[:400]
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("detail", ""))[:400]
    return stdout.strip()[:400]


def check_runtime(
    identity: InstallIdentity, expected_device_id: str, runner: CommandRunner
) -> list[DoctorCheck]:
    """Confirm the runtime is answering and is the device we installed."""
    result = _run(
        [
            str(interpreter_path(identity)),
            "-m",
            "ori.cli_bridge",
            "health",
            "snapshot",
            "--socket",
            str(identity.health_socket),
            "--timeout-ms",
            "3000",
        ],
        runner,
    )
    if result.returncode != 0:
        return [
            DoctorCheck(
                name="runtime.health",
                status=FAIL,
                message="Runtime is not answering on its health socket.",
                mandatory=True,
                remedy="Check logs: journalctl -u ori-runtime -n 50",
                details={"socket": str(identity.health_socket)},
            )
        ]
    health = _health_payload(result.stdout)
    if health is None:
        return [
            DoctorCheck(
                name="runtime.health",
                status=FAIL,
                message="Runtime returned an unreadable health snapshot.",
                mandatory=True,
                remedy="Restart the service and retry.",
            )
        ]

    checks = [
        DoctorCheck(
            name="runtime.health",
            status=FAIL if health.get("critical") else PASS,
            message=(
                "Runtime reports a critical condition."
                if health.get("critical")
                else f"Runtime is healthy (up {health.get('uptime_s', 0):.0f}s)."
            ),
            mandatory=True,
            remedy="Inspect degradation_reasons in ori doctor --json.",
            details={"degradation_reasons": health.get("degradation_reasons", [])},
        )
    ]
    reported = str(health.get("device_id", ""))
    checks.append(
        DoctorCheck(
            name="runtime.identity",
            status=PASS if reported == expected_device_id else FAIL,
            message=(
                f"Runtime is serving device {reported}."
                if reported == expected_device_id
                else f"Runtime reports {reported!r}, expected {expected_device_id!r}."
            ),
            mandatory=True,
            remedy="A mismatched device means the wrong config or a stale socket.",
            details={"reported": reported, "expected": expected_device_id},
        )
    )
    checks.extend(_capability_checks(health))
    return checks


def _health_payload(stdout: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    result = payload.get("result") if isinstance(payload, dict) else None
    health = result.get("health") if isinstance(result, dict) else None
    return health if isinstance(health, dict) else None


def _capability_checks(health: dict[str, Any]) -> list[DoctorCheck]:
    """Optional integrations: reported, never a failure when switched off."""
    posture = health.get("capability_posture")
    if not isinstance(posture, dict):
        return []
    optional = {
        "sms_available": "SMS alerting",
        "whatsapp_available": "WhatsApp alerting",
        "relay_connected": "Relay control",
        "gateway_reachable": "Gateway",
        "local_slm_loaded": "Local SLM",
    }
    enabled = [label for key, label in optional.items() if posture.get(key)]
    disabled = [label for key, label in optional.items() if not posture.get(key)]
    return [
        DoctorCheck(
            name="capabilities.optional",
            status=PASS if not disabled else WARN,
            message=(
                "All optional capabilities are available."
                if not disabled
                else "Optional capabilities not active: " + ", ".join(disabled)
            ),
            remedy="Enable these in ori.yaml only if this deployment needs them.",
            details={"available": enabled, "unavailable": disabled},
        )
    ]


def check_service(
    identity: InstallIdentity, runner: CommandRunner | None = None
) -> list[DoctorCheck]:
    """Service state, and whether it survives a reboot."""
    runner = runner or _default_runner
    systemctl = ["systemctl"] if identity.scope == "system" else ["systemctl", "--user"]
    unit = "ori-runtime.service"
    active = _run([*systemctl, "is-active", unit], runner).stdout.strip()
    enabled = _run([*systemctl, "is-enabled", unit], runner).stdout.strip()

    checks = [
        DoctorCheck(
            name="service.active",
            status=PASS if active == "active" else FAIL,
            message=(
                "Service is running."
                if active == "active"
                else f"Service is not running (state: {active or 'unknown'})."
            ),
            mandatory=True,
            remedy=f"Start it: {' '.join(systemctl)} start {unit}",
            details={"state": active},
        )
    ]

    if identity.scope == "system":
        persists = enabled == "enabled"
        checks.append(
            DoctorCheck(
                name="service.boot_persistence",
                status=PASS if persists else WARN,
                message=(
                    "Persistence: system unit enabled — starts during boot "
                    "without login."
                    if persists
                    else "Persistence: none — system unit is not enabled, so it "
                    f"will not start at boot (state: {enabled or 'unknown'})."
                ),
                remedy=f"Enable it: {' '.join(systemctl)} enable {unit}",
                details={
                    "enabled": enabled,
                    "persistence_source": "system_unit" if persists else "none",
                },
            )
        )
        return checks

    # Bind the query to whoever owns the installation. The inspecting account
    # is not necessarily that user, and its lingering state says nothing about
    # whether *this* installation comes back.
    owner = resolve_service_identity(identity)
    owner_name = owner.name if owner else os.environ.get("USER", "$USER")
    owner_id = str(owner.uid) if owner else str(os.getuid())
    lingering = (
        _run(["loginctl", "show-user", owner_id, "-p", "Linger", "--value"], runner)
        .stdout.strip()
        .lower()
    )
    linger_on = lingering == "yes"
    unit_enabled = enabled == "enabled"

    checks.append(
        DoctorCheck(
            name="service.enabled",
            status=PASS if unit_enabled else WARN,
            message=(
                "User unit is enabled."
                if unit_enabled
                else f"User unit is not enabled (state: {enabled or 'unknown'})."
            ),
            remedy=f"Enable it: {' '.join(systemctl)} enable {unit}",
            details={"enabled": enabled},
        )
    )

    # Both are required: lingering starts a user manager at boot, but it only
    # starts units that are enabled. Either alone leaves the runtime down.
    persists = linger_on and unit_enabled
    if persists:
        message = (
            "Persistence: user lingering enabled and unit enabled — starts "
            "during boot without login."
        )
    elif linger_on:
        message = (
            "Persistence: none — lingering is enabled but the unit is not, so "
            "the user manager starts at boot without starting Ori."
        )
    else:
        message = (
            "Persistence: none — stops after the user's last session ends and "
            "does not start at boot unless lingering is enabled. Closing a "
            "terminal does not end the session; a desktop session keeps the "
            "service alive."
        )
    remedies = []
    if not linger_on:
        remedies.append(f"sudo loginctl enable-linger {owner_name}")
    if not unit_enabled:
        remedies.append(f"{' '.join(systemctl)} enable {unit}")
    checks.append(
        DoctorCheck(
            name="service.boot_persistence",
            status=PASS if persists else WARN,
            message=message,
            remedy=" && ".join(remedies),
            details={
                "linger": lingering,
                "linger_user": owner_name,
                "enabled": enabled,
                "persistence_source": "user_lingering" if persists else "none",
            },
        )
    )
    return checks


READ, WRITE, EXECUTE = 4, 2, 1


@dataclass(frozen=True)
class ServiceIdentity:
    """The account the service actually runs as."""

    name: str
    uid: int
    gids: frozenset[int]
    groups_complete: bool = True


def resolve_service_identity(identity: InstallIdentity) -> ServiceIdentity | None:
    """Return the account the service runs as, or None if unresolvable.

    System scope takes it from the unit's ``User=``. User scope runs as the
    owner of the installation, which is read from the filesystem rather than
    assumed to be whoever invoked doctor.
    """
    if identity.scope == "system":
        name = identity.service_user
        if not name:
            return None
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            return None
    else:
        try:
            entry = pwd.getpwuid(identity.install_root.stat().st_uid)
        except (OSError, KeyError):
            return None
    gids = {entry.pw_gid}
    try:
        gids.update(os.getgrouplist(entry.pw_name, entry.pw_gid))
        complete = True
    except (OSError, OverflowError):
        # Large gids (macOS `nobody`) overflow getgrouplist's C int. Judging the
        # account on its primary group alone understates its access, so the
        # negative check below records that it may have missed a group grant.
        complete = False
    return ServiceIdentity(entry.pw_name, entry.pw_uid, frozenset(gids), complete)


def _mode_allows(info: os.stat_result, service: ServiceIdentity, bit: int) -> bool:
    """Whether POSIX mode bits grant ``bit`` to ``service`` on this inode.

    Ownership decides the class: POSIX consults owner bits when the uid matches
    even if the group bits are more permissive.
    """
    if service.uid == 0:
        return True
    if info.st_uid == service.uid:
        return bool((info.st_mode >> 6) & bit)
    if info.st_gid in service.gids:
        return bool((info.st_mode >> 3) & bit)
    return bool(info.st_mode & bit)


def _is_dir(path: Path) -> bool:
    """``Path.is_dir`` raises on EACCES; an unreadable parent is not an answer."""
    try:
        return path.is_dir()
    except OSError:
        return False


def _grants(path: Path, service: ServiceIdentity, bit: int) -> bool:
    try:
        return _mode_allows(path.stat(), service, bit)
    except OSError:
        return False


def _first_unsearchable(directory: Path, service: ServiceIdentity) -> Path | None:
    """Return the first directory on the way into ``directory`` lacking search.

    Reading a file proves nothing if the service cannot walk to it: a mode of
    0644 on ``ori.yaml`` is irrelevant when ``data/`` denies search. Every
    component from the filesystem root down to ``directory`` is checked.
    """
    for candidate in [*reversed(directory.parents), directory]:
        if not _grants(candidate, service, EXECUTE):
            return candidate
    return None


def _reachable(
    name: str,
    target: Path,
    service: ServiceIdentity,
    *,
    needs: int,
    ok_message: str,
    bad_message: str,
    remedy: str,
    directory: bool = False,
) -> DoctorCheck:
    """Check that ``service`` can walk to ``target`` and then use it."""
    walk_to = target if directory else target.parent
    blocked = _first_unsearchable(walk_to, service)
    if blocked is not None:
        return DoctorCheck(
            name=name,
            status=FAIL,
            message=(f"{service.name} cannot search {blocked} on the way to {target}."),
            mandatory=True,
            remedy=f"Grant search access: chmod o+x {blocked}",
            details={"blocked_at": str(blocked)},
        )
    missing = [
        bit
        for bit in (READ, WRITE, EXECUTE)
        if needs & bit and not _grants(target, service, bit)
    ]
    return DoctorCheck(
        name=name,
        status=PASS if not missing else FAIL,
        message=ok_message if not missing else bad_message,
        mandatory=True,
        remedy=remedy,
    )


def check_permissions(identity: InstallIdentity) -> list[DoctorCheck]:
    """Prove the service identity can operate — and cannot rewrite its code.

    ``os.access`` would answer for the doctor process, which is usually root
    and can do anything, so it cannot show that ``ori-runtime`` is able to read
    its config or barred from modifying a verified release. These checks read
    ownership and mode and evaluate them against the service account instead.
    """
    if not _is_dir(identity.data_path):
        return [
            DoctorCheck(
                name="permissions.data",
                status=FAIL,
                message=f"Data directory is missing: {identity.data_path}",
                mandatory=True,
                remedy="Reinstall to recreate it.",
            )
        ]

    service = resolve_service_identity(identity)
    if service is None:
        return [
            DoctorCheck(
                name="permissions.service_user",
                status=FAIL,
                message="Cannot resolve the account the service runs as.",
                mandatory=True,
                remedy=f"Check User= in {identity.unit_path} and that it exists.",
            )
        ]
    if identity.scope == "system" and service.uid == 0:
        return [
            DoctorCheck(
                name="permissions.service_user",
                status=FAIL,
                message=f"System service runs as root ({service.name}).",
                mandatory=True,
                remedy=f"Set User=ori-runtime in {identity.unit_path}.",
                details={"service_user": service.name, "uid": service.uid},
            )
        ]

    interpreter = interpreter_path(identity)
    return [
        DoctorCheck(
            name="permissions.identity",
            status=PASS,
            message=f"Service runs as {service.name} (uid {service.uid}).",
            details={
                "service_user": service.name,
                "uid": service.uid,
                "groups_complete": service.groups_complete,
            },
        ),
        _reachable(
            "permissions.traverse",
            identity.install_root,
            service,
            needs=EXECUTE,
            directory=True,
            ok_message=f"{service.name} can reach {identity.install_root}.",
            bad_message=f"{service.name} cannot search {identity.install_root}.",
            remedy=f"Grant search access: chmod o+x {identity.install_root}",
        ),
        _reachable(
            "permissions.config",
            identity.config_path,
            service,
            needs=READ,
            ok_message=f"{service.name} can read the config.",
            bad_message=f"{service.name} cannot read {identity.config_path}.",
            remedy=f"chown {service.name} {identity.config_path} and chmod 0640 it.",
        ),
        _reachable(
            "permissions.interpreter",
            interpreter,
            service,
            needs=READ | EXECUTE,
            ok_message=f"{service.name} can execute the release interpreter.",
            bad_message=f"{service.name} cannot execute {interpreter}.",
            remedy=f"Check mode on {interpreter}; it must be readable and executable.",
        ),
        _reachable(
            "permissions.data",
            identity.data_path,
            service,
            needs=WRITE | EXECUTE,
            directory=True,
            ok_message=f"{service.name} can write its data directory.",
            bad_message=f"{service.name} cannot write {identity.data_path}.",
            remedy=f"chown -R {service.name} {identity.data_path} and chmod 0700 it.",
        ),
        _code_integrity(identity, service),
    ]


def _integrity_violation(
    identity: InstallIdentity, service: ServiceIdentity
) -> str | None:
    """Return why the release is not immutable to ``service``, or None.

    Write permission lives on the inode being modified, so a read-only release
    directory says nothing about the files inside it: a 0666 module under a
    0555 directory is still rewritable. Every directory and regular file in the
    tree is therefore checked individually.

    Anything that cannot be inspected or classified is a violation, not a pass —
    an unverifiable claim of immutability is worth nothing.
    """
    from ori.installer.linux import (  # local import: installer is optional
        InstallLayout,
        LinuxInstallError,
        _validate_release_symlink,
    )

    try:
        layout = InstallLayout.resolve(identity.install_root)
    except LinuxInstallError as exc:
        return f"{identity.install_root} is not a usable install root ({exc})"

    stack = [identity.active_release]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError as exc:
            return f"{current} could not be listed ({exc.strerror})"
        for entry in entries:
            try:
                info = entry.lstat()
            except OSError as exc:
                return f"{entry} could not be inspected ({exc.strerror})"

            if stat.S_ISLNK(info.st_mode):
                # Symlinks carry no meaningful mode of their own; the installer
                # already defines which ones a release may contain, so reuse
                # that rule rather than inventing a second one here.
                try:
                    _validate_release_symlink(
                        layout, entry, require_internal=entry.is_dir()
                    )
                except LinuxInstallError as exc:
                    return f"{entry} is not a permitted release symlink ({exc})"
                continue

            if stat.S_ISDIR(info.st_mode):
                if _mode_allows(info, service, WRITE):
                    return f"{entry} is writable by {service.name}"
                stack.append(entry)
                continue

            if not stat.S_ISREG(info.st_mode):
                return f"{entry} is a special file, which a release must not contain"

            if _mode_allows(info, service, WRITE):
                return f"{entry} is writable by {service.name}"
    return None


def _code_integrity(identity: InstallIdentity, service: ServiceIdentity) -> DoctorCheck:
    """The service must not be able to rewrite the code it executes.

    This is a negative property, so incomplete information cannot support it.
    If supplementary groups could not be enumerated, an unseen group might
    carry write access to the release, and the check fails rather than
    presenting an unverified claim as a pass.

    The property is only reachable under privilege separation. System scope has
    it: the code is root-owned and the service runs as an unprivileged account
    that can neither write it nor change its mode. User scope cannot, because
    the release and the runtime share one Unix owner — an owner may always
    ``chmod`` its own tree, so a compromised runtime can restore write access to
    the code it is about to execute. Mode bits there describe the current state,
    not a boundary, and reporting them as immutability would be a false
    assurance. User scope is reported honestly as a warning instead.
    """
    if identity.scope == "user":
        return _user_scope_code_advisory(identity, service)
    if identity.scope != "system":
        # An unrecognised scope is not a third deployment model to be given the
        # benefit of the doubt. `!= "system"` would have handed one the user
        # scope's advisory and turned a mandatory check into a passing warning.
        return DoctorCheck(
            name="permissions.code",
            status=FAIL,
            message=(
                f"Installation scope {identity.scope!r} is unrecognised, so "
                "whether the service can rewrite its own code cannot be "
                "established."
            ),
            mandatory=True,
            remedy="Reinstall with --scope system or --scope user.",
            details={"scope": identity.scope},
        )

    remedy = (
        f"Make the release read-only to the service: "
        f"chown -R root:root {identity.active_release} && "
        f"chmod -R go-w {identity.active_release}"
    )
    if not service.groups_complete:
        return DoctorCheck(
            name="permissions.code",
            status=FAIL,
            message=(
                f"Could not establish that {service.name} is unable to modify "
                f"{identity.active_release}: its supplementary group membership "
                "could not be resolved, and an unresolved group may grant write "
                "access."
            ),
            mandatory=True,
            remedy=remedy,
            details={"groups_complete": False},
        )

    if _mode_allows_path(identity.active_release, service, WRITE):
        violation: str | None = (
            f"{identity.active_release} is writable by {service.name}"
        )
    else:
        violation = _integrity_violation(identity, service)

    if violation is None:
        return DoctorCheck(
            name="permissions.code",
            status=PASS,
            message=f"{service.name} cannot modify the verified release.",
            mandatory=True,
            remedy=remedy,
            details={"release": str(identity.active_release)},
        )
    return DoctorCheck(
        name="permissions.code",
        status=FAIL,
        message=(
            f"The verified release is not immutable to {service.name}: "
            f"{violation}. The service could rewrite the code it executes."
        ),
        mandatory=True,
        remedy=remedy,
        details={"offending_path": violation.split(" ", 1)[0]},
    )


def _user_scope_code_advisory(
    identity: InstallIdentity, service: ServiceIdentity
) -> DoctorCheck:
    """State plainly that user scope cannot offer code immutability.

    This is a property of the deployment model, not a defect in the install, so
    it is never blocking: a user-scope installation that reports this warning is
    a complete and usable installation. Sealing the tree read-only would silence
    the warning without creating the boundary — the owner can restore write at
    any time — which is why no such sealing is attempted.
    """
    return DoctorCheck(
        name="permissions.code",
        status=WARN,
        message=(
            f"User-scope code is owned by the runtime account ({service.name}) "
            "and cannot be made immutable from that account. Use system scope "
            "for a production deployment with root-owned verified code."
        ),
        mandatory=False,
        remedy=(
            "Reinstall with --scope system to run the runtime as a dedicated "
            "unprivileged account that cannot modify the verified release."
        ),
        details={"release": str(identity.active_release), "scope": identity.scope},
    )


def _mode_allows_path(path: Path, service: ServiceIdentity, bit: int) -> bool:
    try:
        return _mode_allows(path.lstat(), service, bit)
    except OSError:
        return True  # uninspectable: treat as unproven, never as safe


def check_prerequisites() -> list[DoctorCheck]:
    """Host tools the installer and runtime depend on."""
    checks: list[DoctorCheck] = []
    for command, why in (
        ("systemctl", "service management"),
        ("openssl", "release signature verification"),
    ):
        found = shutil.which(command)
        checks.append(
            DoctorCheck(
                name=f"prerequisite.{command}",
                status=PASS if found else WARN,
                message=(
                    f"{command} is available."
                    if found
                    else f"{command} is not on PATH ({why})."
                ),
                remedy=f"Install {command} with your distribution's package manager.",
                details={"path": found or ""},
            )
        )
    return checks


def check_gateway(
    identity: InstallIdentity, runner: CommandRunner
) -> list[DoctorCheck]:
    """Report whether an enabled gateway has a broker to reach.

    The runtime and the gateway normally run on the same device — the gateway
    is the site coordinator, and its broker is usually on loopback. Config
    validation accepts ``gateway.enabled: true`` without one, so nothing else
    tells an operator that the broker is missing until an export request or a
    Tier 3 reasoning call quietly fails.

    Advisory rather than mandatory, deliberately. A broker may legitimately
    start after the runtime, so failing an installation on it would create a
    startup race; and gateway reasoning is discretionary — Tier D fires from
    the rule path and is unaffected by broker availability.

    Secret presence is deliberately **not** reported. The service reads its
    shared secret from its own environment file, which this process does not
    inherit, so any answer here would describe the caller rather than the
    service. A missing secret fails runtime startup, where it is visible and
    accurate.
    """
    posture = _gateway_posture_from_config(identity, runner)
    if posture is None or not posture.get("enabled"):
        return []

    checks: list[DoctorCheck] = []
    broker_error = str(posture.get("broker_error") or "")
    host = str(posture.get("broker_host") or "")
    port = posture.get("broker_port")

    if broker_error:
        checks.append(
            DoctorCheck(
                name="gateway.broker",
                status=WARN,
                message=f"Gateway is enabled but broker_url is unusable: {broker_error}",
                remedy="Set gateway.broker_url, e.g. mqtt://127.0.0.1:1883.",
            )
        )
    elif not host or not isinstance(port, int):
        checks.append(
            DoctorCheck(
                name="gateway.broker",
                status=WARN,
                message="Gateway is enabled but no broker_url is configured.",
                remedy="Set gateway.broker_url, e.g. mqtt://127.0.0.1:1883.",
            )
        )
    else:
        reachable = _tcp_reachable(host, port)
        checks.append(
            DoctorCheck(
                name="gateway.broker",
                status=PASS if reachable else WARN,
                message=(
                    f"Gateway broker reachable at {host}:{port}."
                    if reachable
                    else f"Gateway is enabled but no broker answers at {host}:{port}."
                ),
                remedy=(
                    "Install and start an MQTT broker on this device, then harden "
                    "it as described in docs/MQTT_SECURITY.md."
                ),
                details={
                    "host": host,
                    "port": port,
                    "loopback": posture.get("broker_is_loopback"),
                },
            )
        )

    # The verified property is the *binding*, not the secret. Naming this
    # `gateway.shared_secret` would read as "the secret is fine", which this
    # cannot establish — the service reads it from an environment file this
    # process does not inherit.
    secret_env = str(posture.get("shared_secret_env") or "")
    if posture.get("auth_enabled") and secret_env:
        checks.append(
            DoctorCheck(
                name="gateway.shared_secret_reference",
                status=PASS,
                message=(
                    f"Gateway auth is configured to read its secret from "
                    f"{secret_env}; delivery is enforced when the runtime starts."
                ),
                details={"shared_secret_env": secret_env},
            )
        )
    return checks


def _gateway_posture_from_config(
    identity: InstallIdentity, runner: CommandRunner
) -> dict[str, Any] | None:
    """Read the gateway posture the bridge reports for the installed config."""
    if not identity.config_path.is_file():
        return None
    result = _run(
        [
            str(interpreter_path(identity)),
            "-m",
            "ori.cli_bridge",
            "config",
            "show",
            "--path",
            str(identity.config_path),
        ],
        runner,
    )
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    config = payload.get("result", {}).get("config", {})
    gateway = config.get("gateway") if isinstance(config, dict) else None
    return gateway if isinstance(gateway, dict) else None


def _tcp_reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    """Whether something accepts a TCP connection at *host*:*port*.

    A connect probe only. It proves a listener exists, not that it speaks MQTT
    or will accept these credentials — those fail later and visibly.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def run_doctor(
    identity: InstallIdentity,
    expected_device_id: str,
    *,
    runner: CommandRunner | None = None,
) -> list[DoctorCheck]:
    """Run every check and return them in report order."""
    assert_execution_allowed(identity)
    active = runner or _default_runner
    checks: list[DoctorCheck] = []
    checks.extend(check_paths(identity))
    checks.extend(check_prerequisites())
    checks.extend(check_config(identity, active))
    checks.extend(check_gateway(identity, active))
    checks.extend(check_service(identity, active))
    checks.extend(check_runtime(identity, expected_device_id, active))
    checks.extend(check_permissions(identity))
    return checks


def render_report(
    checks: Sequence[DoctorCheck], identity: InstallIdentity, *, stream: Any = None
) -> str:
    """Render a concise human summary. Colour decorates; text carries meaning."""
    out = stream if stream is not None else sys.stdout
    counts = {
        status: sum(1 for c in checks if c.status == status) for status in _STATUSES
    }
    lines = [
        "",
        terminal.heading("Ori Runtime — doctor", stream=out),
        "",
        f"  {terminal.muted('scope', stream=out)}    {identity.scope}"
        f"   {terminal.muted('version', stream=out)}  {identity.version}",
        f"  {terminal.muted('root', stream=out)}     {terminal.path(str(identity.install_root), stream=out)}",
        f"  {terminal.muted('release', stream=out)}  {terminal.path(str(identity.active_release), stream=out)}",
        f"  {terminal.muted('config', stream=out)}   {terminal.path(str(identity.config_path), stream=out)}",
        f"  {terminal.muted('data', stream=out)}     {terminal.path(str(identity.data_path), stream=out)}",
        f"  {terminal.muted('socket', stream=out)}   {terminal.path(str(identity.health_socket), stream=out)}",
        f"  {terminal.muted('unit', stream=out)}     {terminal.path(str(identity.unit_path), stream=out)}"
        + (
            f"   {terminal.muted('user', stream=out)} {identity.service_user}"
            if identity.service_user
            else ""
        ),
        "",
    ]
    for check in checks:
        lines.append(
            f"  {terminal.status_label(check.status, stream=out)}  "
            f"{check.name.ljust(28)} {check.message}"
        )
        if check.status != PASS and check.remedy:
            lines.append(f"        {terminal.muted(check.remedy, stream=out)}")

    lines.append("")
    summary = f"{counts[PASS]} pass · {counts[WARN]} warn · {counts[FAIL]} fail"
    blocking = blocking_failures(checks)
    if blocking:
        lines.append(terminal.failure(f"FAIL — {summary}", stream=out))
        lines.append(
            terminal.failure(
                f"  {len(blocking)} blocking issue(s) must be fixed.", stream=out
            )
        )
    elif counts[FAIL] or counts[WARN]:
        lines.append(terminal.warning(f"OK with warnings — {summary}", stream=out))
    else:
        lines.append(terminal.success(f"OK — {summary}", stream=out))
    lines.append("")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ori doctor",
        description="Diagnose an installed Ori Runtime.",
    )
    parser.add_argument("--scope", choices=("user", "system"), default=None)
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help=(
            "diagnose the installation at this exact root instead of the "
            "default one; the release it contains is still refused execution "
            "as root unless every path leading to it is root-owned"
        ),
    )
    parser.add_argument("--json", action="store_true", help="Emit one JSON document.")
    return parser


def run(
    scope: str | None = None, *, root: Path | None = None, json_mode: bool = False
) -> int:
    """Diagnose an installation and report it. Returns the process exit code.

    Callers that already hold these values use this directly; rendering them
    back into argv only to re-parse them would be a round trip with no decision
    in it.
    """
    from ori.installer.paths import (  # local import: optional dep
        AmbiguousScopeError,
        UnmanagedReleaseError,
        resolve_identity,
    )

    try:
        identity, device_id = resolve_identity(scope=scope, root=root)
    except AmbiguousScopeError as exc:
        print(f"ambiguous installation: {exc}", file=sys.stderr)
        return 2
    except UnmanagedReleaseError as exc:
        print(f"unusable installation: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"no Ori installation found: {exc}", file=sys.stderr)
        return 2

    try:
        checks = run_doctor(identity, device_id)
    except UnsafeExecutionError as exc:
        print(f"refusing to run: {exc}", file=sys.stderr)
        return 2
    if json_mode:
        json.dump(
            {
                "schema_version": 1,
                "identity": {**identity.as_dict(), "device_id": device_id},
                "checks": [asdict(c) for c in checks],
            },
            sys.stdout,
            indent=2,
            sort_keys=True,
        )
        sys.stdout.write("\n")
    else:
        print(render_report(checks, identity))
    return 1 if blocking_failures(checks) else 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return run(args.scope, root=args.root, json_mode=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
