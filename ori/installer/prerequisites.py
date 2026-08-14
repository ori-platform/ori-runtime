# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Optional help installing OS prerequisites, on the operator's say-so.

An installer that quietly changes a host's packages is an installer nobody can
reason about afterwards. So this asks first, shows exactly which packages and
exactly which command, and defaults to No. Unattended runs never ask and never
change anything: they fail with the command to run.

Two boundaries are absolute. Nothing here resolves Python packages — runtime
dependencies come only from the authenticated, hash-locked wheelhouse inside the
verified bundle, and adding a second source would undo that guarantee. And
nothing is passed through a shell: package names come from a fixed allowlist and
are placed into a fixed argument array, so there is no string for an unexpected
value to escape from.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from ori.installer.linux import LinuxInstallError

FAILURE_CODE = "prerequisite_install_failed"

# Distributions this installer knows how to help with. Anything else is
# reported, never guessed at with a package manager it has not been tested on.
# Raspberry Pi OS reports ID=raspbian on 32-bit images and ID=debian on 64-bit
# ones, so the primary production platform needs both entries to be recognised.
SUPPORTED: dict[tuple[str, str], str] = {
    ("debian", "12"): "Debian Bookworm / Raspberry Pi OS (64-bit)",
    ("raspbian", "12"): "Raspberry Pi OS Bookworm",
    ("ubuntu", "24.04"): "Ubuntu 24.04",
}

# Exact package names. A name that is not here is never installed, whatever
# asks for it.
#
# Deliberately minimal. `openssl` and `ca-certificates` are shared operating
# system components that unrelated software depends on, so installing them is
# not this installer's authority to take — and it would be pointless anyway:
# both are needed to *download and verify* a release, so by the time the
# authenticated installer runs, it is far too late for them to matter. Doctor
# reports them as advisory. The only thing this installer genuinely cannot
# proceed without is the ability to build its offline environment.
ALLOWED_PACKAGES = frozenset({"python3-venv"})

# Present on every supported system and load-bearing for far more than Ori.
# Replacing one is an operating-system decision, so it is reported with the
# command and never offered as something this installer will run.
PROTECTED = frozenset(
    {"systemd", "python3", "bash", "libc6", "libssl3", "openssl", "ca-certificates"}
)


@dataclass(frozen=True)
class Prerequisite:
    """Something the host needs, and the package that provides it.

    ``probe`` answers whether the capability is actually usable, which is not
    always the same question as whether a file exists on ``PATH``.
    """

    name: str
    package: str
    why: str
    probe: Callable[[], bool] | None = None

    def present(self) -> bool:
        if self.probe is not None:
            return self.probe()
        return shutil.which(self.name) is not None


VENV_PROBE_TIMEOUT_S = 60


def venv_capable(python: str | None = None) -> bool:
    """Whether this interpreter can actually build a pip-enabled environment.

    Importing ``venv`` and ``ensurepip`` proves neither: Debian ships both in
    the standard library while withholding the ``python3-venv`` package that
    makes creation work, which is exactly the failure this is meant to catch.
    So the capability is tested by using it, once, in a directory that is
    thrown away.
    """
    interpreter = python or sys.executable
    try:
        with tempfile.TemporaryDirectory(prefix="ori-venv-probe-") as workspace:
            completed = subprocess.run(
                [interpreter, "-m", "venv", str(Path(workspace) / "probe")],
                capture_output=True,
                check=False,
                stdin=subprocess.DEVNULL,
                timeout=VENV_PROBE_TIMEOUT_S,
            )
            return completed.returncode == 0
    except (OSError, subprocess.SubprocessError):
        # Unable to even attempt it: report the capability as unavailable
        # rather than raising out of what is meant to be a question.
        return False


# Only what this installer cannot proceed without. `openssl` and
# `ca-certificates` matter to the bootstrap that downloads and verifies the
# bundle, and doctor reports them as advisory; making them required here would
# fail installations that are in fact fine.
REQUIRED: tuple[Prerequisite, ...] = (
    Prerequisite(
        "python3-venv",
        "python3-venv",
        "building the offline runtime",
        probe=venv_capable,
    ),
)


@dataclass(frozen=True)
class Platform:
    identifier: str
    version: str
    label: str


def detect_platform(os_release: Path = Path("/etc/os-release")) -> Platform | None:
    """Identify the distribution, or None when it is not one we help with."""
    values: dict[str, str] = {}
    try:
        for line in os_release.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key.strip()] = value.strip().strip('"')
    except (OSError, UnicodeError):
        return None
    identifier = values.get("ID", "")
    version = values.get("VERSION_ID", "")
    label = SUPPORTED.get((identifier, version))
    if label is None:
        return None
    return Platform(identifier, version, label)


def missing(prerequisites: Sequence[Prerequisite] = REQUIRED) -> list[Prerequisite]:
    return [item for item in prerequisites if not item.present()]


def install_command(packages: Sequence[str]) -> list[str]:
    """Build the fixed argument array that installs ``packages``.

    Every name is checked against the allowlist first. The result is a list
    handed straight to ``execve`` — never a string, never a shell — so a
    package name has nothing to escape from even if one were to slip through.
    """
    rejected = [name for name in packages if name not in ALLOWED_PACKAGES]
    if rejected:
        raise LinuxInstallError(
            FAILURE_CODE,
            f"refusing to install packages outside the allowlist: {rejected}",
        )
    return [
        "apt-get",
        "install",
        "--no-install-recommends",
        "--yes",
        *sorted(packages),
    ]


def describe(packages: Sequence[str], *, as_root: bool) -> str:
    """The exact command an operator would run, quoted for copying."""
    command = install_command(packages)
    return " ".join(command) if as_root else "sudo " + " ".join(command)


def _still_missing(
    absent: Sequence[Prerequisite], command_text: str, reason: str
) -> LinuxInstallError:
    return LinuxInstallError(
        FAILURE_CODE,
        f"{reason} Still missing: "
        + ", ".join(f"{item.name} (for {item.why})" for item in absent)
        + f". Install them and re-run, or run: {command_text}",
    )


def ensure(
    *,
    unattended: bool,
    prompt: Callable[[str], str] = input,
    write: Callable[[str], None] = print,
    prerequisites: Sequence[Prerequisite] = REQUIRED,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]] | None = None,
) -> list[str]:
    """Ensure the host has what the installation needs. Returns what was installed.

    Everything here is required — that is what makes it a prerequisite. So
    declining, lacking privilege, or running on a distribution this installer
    cannot prepare all end the same way: the host is left exactly as it was
    found, and the installation stops with the command to run.

    "No" means "do not change my system for me". It never means "continue
    without something the installation needs".
    """
    absent = missing(prerequisites)
    if not absent:
        return []

    packages = sorted({item.package for item in absent})
    as_root = os.geteuid() == 0
    command_text = describe(packages, as_root=as_root)

    if unattended:
        # Never prompt, never mutate: automation gets the command instead.
        raise _still_missing(
            absent,
            command_text,
            "Missing OS prerequisites, and unattended mode does not modify the host.",
        )

    platform = detect_platform()
    write("")
    write("Some OS packages this installation needs are missing:")
    for item in absent:
        write(f"  {item.name:<24} {item.package}  — {item.why}")
    write("")
    if platform is None:
        write(
            "This host is not one the installer knows how to prepare "
            "automatically. Install the packages above with your "
            "distribution's package manager, then re-run."
        )
        raise _still_missing(
            absent,
            command_text,
            "This distribution is not one the installer prepares automatically.",
        )
    if not as_root:
        write(
            "Installing these needs administrator privileges, which this "
            "installer will not take on your behalf. Run:"
        )
        write(f"    {command_text}")
        write("then re-run this installation.")
        raise _still_missing(
            absent,
            command_text,
            "Installing prerequisites needs administrator "
            "privileges, which this installer does not take on your behalf.",
        )

    write(f"On {platform.label}, this would run exactly:")
    write(f"    {command_text}")
    write(
        "apt may install required OS dependencies and update package-manager "
        "state. No Python packages are downloaded from package indexes."
    )
    write("")
    try:
        answer = prompt("Install these packages now? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer not in ("y", "yes"):
        write("Leaving the host unchanged.")
        raise _still_missing(absent, command_text, "Prerequisites were not installed.")

    _run_apt(packages, runner)

    # A zero exit code says apt believed it succeeded. It does not say the
    # capability is now usable by *this* interpreter, which is the only thing
    # the installation actually depends on, so the probe is repeated.
    remaining = missing(prerequisites)
    if remaining:
        raise _still_missing(
            remaining,
            command_text,
            "The packages installed, but the capability is still unavailable "
            "to this interpreter.",
        )
    return packages


def _run_apt(
    packages: Sequence[str],
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]] | None,
) -> None:
    execute = runner or _default_runner
    command = install_command(packages)
    try:
        completed = execute(command)
    except (OSError, subprocess.SubprocessError) as exc:
        raise LinuxInstallError(
            FAILURE_CODE, f"package installation could not be started: {exc}"
        ) from exc
    if completed.returncode != 0:
        # Stopping here is the point: a partially prepared host must not be
        # built on, and the operator gets one stable code to act on.
        raise LinuxInstallError(
            FAILURE_CODE,
            f"package installation failed (apt-get exited "
            f"{completed.returncode}). Some packages may have been installed "
            "or partly configured before it stopped, so inspect the host "
            "before retrying; the installation did not continue.",
        )


def _default_runner(
    command: Sequence[str],
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(list(command), check=False, stdin=subprocess.DEVNULL)
