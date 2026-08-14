# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""What happens after a release is activated, and what must undo it.

Two things are settled here. The launcher is written so a bare ``ori`` resolves
to whatever release is active at the time it runs. Then the installed doctor is
executed — by absolute path, never through ``PATH``, because the command may not
be resolvable yet and an installation must not be validated by a different
release that happens to be earlier in the search order.

The diagnostics run inside the install transaction. An installation that is not
actually usable is rolled back rather than reported healthy, which is the whole
reason the check exists; warnings, including a user service that will not
survive a reboot, are reported and kept.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ori.installer import launcher
from ori.installer.linux import LinuxInstallError

DOCTOR_TIMEOUT_S = 120


@dataclass(frozen=True)
class ActivationOutcome:
    """What the post-activation steps produced, for the install report."""

    launcher_path: Path | None
    launcher_installed: bool
    launcher_conflict: str
    path_guidance: str
    checks: list[dict[str, Any]]

    @property
    def warnings(self) -> list[dict[str, Any]]:
        return [c for c in self.checks if c.get("status") == "WARN"]


def _restore(path: Path, content: bytes, mode: int) -> None:
    """Put back exactly what was there before, atomically."""
    staged = path.with_name(f".{path.name}.restore")
    staged.write_bytes(content)
    staged.chmod(mode)
    os.replace(staged, path)


def install_launcher(
    path: Path, install_root: Path, scope: str
) -> tuple[bool, str, Callable[[], None]]:
    """Write the ``ori`` launcher and return how to undo exactly that.

    On a fresh install the undo removes the file. On an upgrade it restores the
    previous launcher byte for byte: rolling back to the old release while
    deleting the command that ran it would leave the operator worse off than
    if the upgrade had never been attempted.

    A launcher conflict is not a reason to fail an otherwise good install: the
    runtime is what the operator asked for, and the command is a convenience.
    It is reported so they can resolve it rather than discover it later.
    """
    previous: tuple[bytes, int] | None = None
    if path.is_file() and not path.is_symlink():
        try:
            previous = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        except OSError:
            previous = None

    try:
        launcher.install(path, install_root, scope)
    except launcher.LauncherConflictError as exc:
        return False, str(exc), _noop
    except OSError as exc:
        return False, f"could not write {path}: {exc}", _noop

    if previous is None:

        def undo_new() -> None:
            remove_launcher(path, install_root)

        return True, "", undo_new

    content, mode = previous

    def undo_upgrade() -> None:
        try:
            _restore(path, content, mode)
        except OSError:  # pragma: no cover - surfaced by the rollback collector
            raise

    return True, "", undo_upgrade


def _noop() -> None:
    return None


# Doctor exits 0 when nothing blocks and 1 when it found blocking failures.
# Both are complete diagnoses that we act on below. Anything else — 2 for
# "could not run", or a crash — means there is no diagnosis at all, and an
# undiagnosed installation must never be approved.
_DIAGNOSED = frozenset({0, 1})
_REPORT_SCHEMA = 1
_STATUSES = frozenset({"PASS", "WARN", "FAIL"})


def _unreadable(detail: str) -> LinuxInstallError:
    return LinuxInstallError(
        "post_install_health_failed", f"post-install diagnostics {detail}"
    )


def remove_launcher(path: Path, install_root: Path) -> bool:
    """Remove the launcher if we wrote it, tolerating a path that is not ours."""
    try:
        return launcher.remove(path, install_root)
    except OSError:
        return False


def run_installed_doctor(
    release: Path,
    scope: str,
    *,
    root: Path,
    expected_device_id: str,
) -> list[dict[str, Any]]:
    """Run the doctor shipped in this release and verify what it reports.

    Addressed absolutely, because resolving ``ori`` through ``PATH`` would
    validate whichever release the shell finds first — possibly not the one
    just installed. Bound to ``root``, because otherwise diagnostics resolve
    the *default* installation and would approve or condemn the wrong tree.

    Everything the report claims is then checked against what was actually
    installed. A diagnosis that cannot be verified is not a diagnosis.
    """
    executable = release / "venv" / "bin" / "ori"
    if not executable.is_file():
        raise _unreadable(f"are unavailable: {executable} does not exist")
    try:
        completed = subprocess.run(
            [
                str(executable),
                "doctor",
                "--scope",
                scope,
                "--root",
                str(root),
                "--json",
            ],
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=DOCTOR_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _unreadable(f"could not be run: {exc}") from exc

    if completed.returncode not in _DIAGNOSED:
        raise _unreadable(
            f"exited {completed.returncode} without producing a diagnosis"
        )

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise _unreadable("returned output that is not JSON") from exc
    if not isinstance(payload, dict):
        raise _unreadable("returned a report that is not an object")
    if payload.get("schema_version") != _REPORT_SCHEMA:
        raise _unreadable(
            f"returned schema {payload.get('schema_version')!r}, "
            f"expected {_REPORT_SCHEMA}"
        )

    _assert_diagnosed_this_install(
        payload.get("identity"),
        scope=scope,
        root=root,
        release=release,
        expected_device_id=expected_device_id,
    )
    checks = _validated_checks(payload.get("checks"))
    _assert_complete(checks)
    _assert_status_agrees(completed.returncode, checks)
    return checks


# Every diagnosis must cover these areas. Some are answered by one of several
# checks depending on what doctor found — an unreadable config never reaches
# validation — so each entry lists the acceptable answers.
_REQUIRED_CATEGORIES: tuple[tuple[str, ...], ...] = (
    ("install.identity",),
    ("config.present", "config.readable", "config.valid"),
    ("service.active",),
    ("service.boot_persistence",),
    ("runtime.health",),
    ("permissions.data", "permissions.service_user", "permissions.code"),
)

# A report that *approves* an installation has to show each area actually
# succeeded. Doctor emits all of these on a healthy install, so a report that
# approves while omitting one is not a healthy install — it is an incomplete
# report, and silence is not a pass.
_REQUIRED_WHEN_APPROVING: tuple[str, ...] = (
    "install.identity",
    "config.valid",
    "service.active",
    "service.boot_persistence",
    "runtime.health",
    "runtime.identity",
    "permissions.code",
)


def _assert_complete(checks: list[dict[str, Any]]) -> None:
    """Require the diagnosis to cover everything, not merely to be well formed.

    Validating each supplied entry cannot detect the entries that were never
    supplied, and an installation approved on a report that never looked at
    the config, the runtime, or the service permissions has not been checked
    at all.
    """
    names = {str(check["name"]) for check in checks}
    for group in _REQUIRED_CATEGORIES:
        if not names.intersection(group):
            raise _unreadable(
                "returned no result for " + " or ".join(repr(n) for n in group)
            )
    if blocking(checks):
        return
    missing = [name for name in _REQUIRED_WHEN_APPROVING if name not in names]
    if missing:
        raise _unreadable(
            "approved this installation without checking "
            + ", ".join(repr(name) for name in missing)
        )


def _assert_status_agrees(returncode: int, checks: list[dict[str, Any]]) -> None:
    """The exit code and the checks must tell the same story.

    A report whose body disagrees with the status its own process exited with
    is not trustworthy in either direction, so neither half is believed on its
    own.
    """
    failures = blocking(checks)
    if returncode == 0 and failures:
        raise _unreadable(
            f"exited 0 while reporting {len(failures)} blocking failure(s)"
        )
    if returncode == 1 and not failures:
        raise _unreadable("exited 1 without reporting any blocking failure")


def _assert_diagnosed_this_install(
    identity: Any,
    *,
    scope: str,
    root: Path,
    release: Path,
    expected_device_id: str,
) -> None:
    """Confirm the report describes the installation we just activated."""
    if not isinstance(identity, dict):
        raise _unreadable("returned a report with no installation identity")
    for field, expected in (
        ("scope", scope),
        ("install_root", str(root)),
        ("active_release", str(release)),
    ):
        actual = identity.get(field)
        if actual != expected:
            raise _unreadable(
                f"described a different installation: {field} was {actual!r}, "
                f"expected {expected!r}"
            )
    reported = identity.get("device_id")
    if reported != expected_device_id:
        # Absent is not "fine": a report that does not say which device it
        # diagnosed cannot show it diagnosed this one.
        raise _unreadable(
            f"described device {reported!r}, expected {expected_device_id!r}"
        )


def _validated_checks(checks: Any) -> list[dict[str, Any]]:
    """Every entry must be usable; a dropped entry could be the failing one."""
    if not isinstance(checks, list) or not checks:
        raise _unreadable("returned no checks")
    validated: list[dict[str, Any]] = []
    for entry in checks:
        if not isinstance(entry, dict):
            raise _unreadable(f"returned a malformed check: {entry!r}")
        name, status = entry.get("name"), entry.get("status")
        if not isinstance(name, str) or not name:
            raise _unreadable(f"returned a check with no name: {entry!r}")
        if status not in _STATUSES:
            raise _unreadable(f"returned check {name!r} with status {status!r}")
        # `mandatory` decides whether a failure blocks the install, so a report
        # that omits it is not answering the question that matters.
        if "mandatory" not in entry or not isinstance(entry["mandatory"], bool):
            raise _unreadable(f"returned check {name!r} without a boolean 'mandatory'")
        if not isinstance(entry.get("message"), str):
            raise _unreadable(f"returned check {name!r} without a message")
        validated.append(entry)
    return validated


def blocking(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Checks whose failure means the installation is not usable."""
    return [c for c in checks if c.get("status") == "FAIL" and c.get("mandatory")]


def assert_usable(checks: list[dict[str, Any]]) -> None:
    """Raise if diagnostics found something that makes this install unusable.

    Raised inside the transaction, so the caller's existing rollback restores
    the previous release. Warnings never reach here: a disabled optional
    integration and a non-persistent user service are both real installations.
    """
    failures = blocking(checks)
    if not failures:
        return
    detail = "; ".join(
        f"{c.get('name', 'check')}: {c.get('message', '')}" for c in failures
    )
    raise LinuxInstallError(
        "post_install_health_failed",
        f"post-install diagnostics failed: {detail}",
    )


def next_step(outcome: ActivationOutcome) -> str:
    """What the operator should actually do next — and only if it will work.

    Naming a command that does not resolve is how an installation ends with a
    confident instruction the operator cannot follow.
    """
    if not outcome.launcher_installed:
        return (
            "The ori command was not installed. "
            + outcome.launcher_conflict
            + " Diagnostics can still be run directly."
        )
    if outcome.path_guidance:
        return outcome.path_guidance
    return "Run `ori doctor` at any time to check this installation."
