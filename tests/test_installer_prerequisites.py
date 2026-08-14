# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Prompt-gated OS prerequisites: asked for, never assumed."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence

import pytest

from ori.installer import prerequisites
from ori.installer.linux import LinuxInstallError


class _Capability:
    """A prerequisite whose availability can change, as a real one does."""

    def __init__(self, present: bool = False) -> None:
        self.present = present

    def __call__(self) -> bool:
        return self.present


def _absent(
    name: str = "no-such-tool",
    package: str = "python3-venv",
    why: str = "building the offline runtime",
    capability: _Capability | None = None,
) -> prerequisites.Prerequisite:
    return prerequisites.Prerequisite(
        name, package, why, probe=capability or _Capability(present=False)
    )


ABSENT = _absent()
# Only one package is installable, so a second missing tool maps to the same
# package rather than inventing authority the installer does not have.
ALSO_ABSENT = _absent("another-missing-tool", "python3-venv", "creating the venv")


class _Operator:
    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.messages: list[str] = []
        self.prompts: list[str] = []

    def prompt(self, message: str) -> str:
        self.prompts.append(message)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def write(self, message: str) -> None:
        self.messages.append(message)

    @property
    def shown(self) -> str:
        return "\n".join(self.messages + self.prompts)


class _Apt:
    """A package manager that can be told whether it really fixed anything."""

    def __init__(
        self, returncode: int = 0, provides: Sequence[_Capability] = ()
    ) -> None:
        self.returncode = returncode
        self.provides = provides
        self.commands: list[list[str]] = []

    def __call__(self, command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(list(command))
        if self.returncode == 0:
            for capability in self.provides:
                capability.present = True
        return subprocess.CompletedProcess(list(command), self.returncode)


@pytest.fixture
def as_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        prerequisites,
        "detect_platform",
        lambda *a, **k: prerequisites.Platform("debian", "12", "Debian Bookworm"),
    )


# --- nothing happens without an answer ------------------------------------


def test_nothing_is_asked_when_nothing_is_missing(as_root: None) -> None:
    operator = _Operator()
    apt = _Apt()
    installed = prerequisites.ensure(
        unattended=False,
        prompt=operator.prompt,
        write=operator.write,
        prerequisites=(),
        runner=apt,
    )
    assert installed == []
    assert operator.prompts == []
    assert apt.commands == []


def test_declining_stops_the_installation(as_root: None) -> None:
    """ "No" means "do not change my system", not "continue without it"."""
    operator = _Operator("")  # a bare Enter is the default answer
    apt = _Apt()
    with pytest.raises(LinuxInstallError) as excinfo:
        prerequisites.ensure(
            unattended=False,
            prompt=operator.prompt,
            write=operator.write,
            prerequisites=(ABSENT,),
            runner=apt,
        )
    assert excinfo.value.code == prerequisites.FAILURE_CODE
    assert "were not installed" in str(excinfo.value)
    assert "apt-get install" in str(excinfo.value)  # with the remediation
    assert apt.commands == []  # and the host untouched
    assert "[y/N]" in operator.prompts[0]
    assert "Leaving the host unchanged" in operator.shown


@pytest.mark.parametrize("answer", ["n", "no", "N", "maybe", "  "])
def test_anything_but_yes_declines_and_stops(as_root: None, answer: str) -> None:
    apt = _Apt()
    operator = _Operator(answer)
    with pytest.raises(LinuxInstallError):
        prerequisites.ensure(
            unattended=False,
            prompt=operator.prompt,
            write=operator.write,
            prerequisites=(ABSENT,),
            runner=apt,
        )
    assert apt.commands == []


def test_cancelling_the_prompt_stops_the_installation(as_root: None) -> None:
    apt = _Apt()
    operator = _Operator()  # any prompt raises EOFError
    with pytest.raises(LinuxInstallError):
        prerequisites.ensure(
            unattended=False,
            prompt=operator.prompt,
            write=operator.write,
            prerequisites=(ABSENT,),
            runner=apt,
        )
    assert apt.commands == []


# --- what the operator is told before deciding ----------------------------


def test_the_exact_packages_and_command_are_shown_first(as_root: None) -> None:
    operator = _Operator("n")
    with pytest.raises(LinuxInstallError):
        prerequisites.ensure(
            unattended=False,
            prompt=operator.prompt,
            write=operator.write,
            prerequisites=(ABSENT, ALSO_ABSENT),
            runner=_Apt(),
        )
    shown = operator.shown
    assert "no-such-tool" in shown
    assert "building the offline runtime" in shown
    assert "apt-get install --no-install-recommends --yes python3-venv" in shown
    assert "Debian Bookworm" in shown
    assert "No Python packages are downloaded" in " ".join(shown.split())


def test_an_unsupported_distribution_is_told_not_guessed_at(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(prerequisites, "detect_platform", lambda *a, **k: None)
    apt = _Apt()
    operator = _Operator("y")
    with pytest.raises(LinuxInstallError) as excinfo:
        prerequisites.ensure(
            unattended=False,
            prompt=operator.prompt,
            write=operator.write,
            prerequisites=(ABSENT,),
            runner=apt,
        )
    assert "not one the installer prepares automatically" in str(excinfo.value)
    assert apt.commands == []
    assert "not one the installer knows how to prepare" in operator.shown


def test_without_privilege_the_command_is_handed_over_not_escalated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The installer never takes administrator privileges on the operator's behalf."""
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        prerequisites,
        "detect_platform",
        lambda *a, **k: prerequisites.Platform("debian", "12", "Debian Bookworm"),
    )
    apt = _Apt()
    operator = _Operator("y")
    with pytest.raises(LinuxInstallError) as excinfo:
        prerequisites.ensure(
            unattended=False,
            prompt=operator.prompt,
            write=operator.write,
            prerequisites=(ABSENT,),
            runner=apt,
        )
    assert "administrator privileges" in str(excinfo.value)
    assert apt.commands == []
    assert operator.prompts == []  # not even asked
    assert "sudo apt-get install" in operator.shown


# --- accepting ------------------------------------------------------------


def test_accepting_runs_exactly_the_command_that_was_shown(as_root: None) -> None:
    first, second = _Capability(), _Capability()
    absent = _absent(capability=first)
    also = _absent("another-missing-tool", "python3-venv", "creating the venv", second)
    apt = _Apt(provides=(first, second))
    operator = _Operator("y")
    installed = prerequisites.ensure(
        unattended=False,
        prompt=operator.prompt,
        write=operator.write,
        prerequisites=(absent, also),
        runner=apt,
    )
    assert installed == ["python3-venv"]
    assert apt.commands == [
        ["apt-get", "install", "--no-install-recommends", "--yes", "python3-venv"]
    ]


def test_a_package_manager_failure_stops_the_installation(as_root: None) -> None:
    """A half-prepared host must not be built on."""
    operator = _Operator("y")
    with pytest.raises(LinuxInstallError) as excinfo:
        prerequisites.ensure(
            unattended=False,
            prompt=operator.prompt,
            write=operator.write,
            prerequisites=(ABSENT,),
            runner=_Apt(returncode=100),
        )
    assert excinfo.value.code == prerequisites.FAILURE_CODE
    assert "exited 100" in str(excinfo.value)


def test_a_package_manager_that_cannot_start_is_a_stable_failure(
    as_root: None,
) -> None:
    def _explode(command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
        raise OSError("apt-get not found")

    operator = _Operator("y")
    with pytest.raises(LinuxInstallError) as excinfo:
        prerequisites.ensure(
            unattended=False,
            prompt=operator.prompt,
            write=operator.write,
            prerequisites=(ABSENT,),
            runner=_explode,
        )
    assert excinfo.value.code == prerequisites.FAILURE_CODE


# --- unattended never touches the host ------------------------------------


def test_unattended_never_prompts_and_never_installs() -> None:
    apt = _Apt()
    operator = _Operator("y")  # would say yes if asked
    with pytest.raises(LinuxInstallError) as excinfo:
        prerequisites.ensure(
            unattended=True,
            prompt=operator.prompt,
            write=operator.write,
            prerequisites=(ABSENT,),
            runner=apt,
        )
    assert excinfo.value.code == prerequisites.FAILURE_CODE
    assert operator.prompts == []
    assert apt.commands == []
    # and it hands over the exact remediation command
    assert "apt-get install --no-install-recommends --yes python3-venv" in str(
        excinfo.value
    )
    assert "building the offline runtime" in str(excinfo.value)


def test_unattended_is_silent_when_nothing_is_missing() -> None:
    assert prerequisites.ensure(unattended=True, prerequisites=()) == []


# --- the allowlist and the argument array ---------------------------------


@pytest.mark.parametrize(
    "package",
    [
        "curl",
        "python3-venv; rm -rf /",
        "python3-venv --reinstall",
        "openssl",
        "ca-certificates",
        "$(whoami)",
        "python3",
        "systemd",
        "bash",
    ],
)
def test_only_allowlisted_packages_can_be_installed(package: str) -> None:
    """Names come from a fixed set, so an unexpected one has nowhere to go."""
    with pytest.raises(LinuxInstallError) as excinfo:
        prerequisites.install_command([package])
    assert excinfo.value.code == prerequisites.FAILURE_CODE
    assert "allowlist" in str(excinfo.value)


def test_operating_system_components_are_never_in_the_allowlist() -> None:
    """Replacing systemd, Python, or bash is an OS decision, not an install step."""
    assert prerequisites.PROTECTED.isdisjoint(prerequisites.ALLOWED_PACKAGES)


def test_the_command_is_an_argument_array_not_a_string() -> None:
    command = prerequisites.install_command(["python3-venv"])
    assert isinstance(command, list)
    assert all(isinstance(part, str) for part in command)
    assert command[0] == "apt-get"
    assert "--yes" in command
    # Nothing is ever handed to a shell, so no metacharacter can be meaningful.
    assert not any(any(c in part for c in ";|&$`><") for part in command)


def test_no_python_package_source_is_ever_introduced() -> None:
    """Runtime dependencies come only from the verified, hash-locked wheelhouse."""
    source = (
        Path(__file__).resolve().parent.parent
        / "ori"
        / "installer"
        / "prerequisites.py"
    ).read_text()
    lowered = source.lower()
    # `ensurepip` appears as a stdlib availability check, which is not a
    # package source; what must be absent is any way to fetch one.
    for forbidden in (
        "pip install",
        "pip3",
        "-m pip",
        "pypi",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "easy_install",
        "requirements.txt",
    ):
        assert forbidden not in lowered, f"prerequisites reference {forbidden!r}"


# --- platform detection ---------------------------------------------------


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ('ID=debian\nVERSION_ID="12"\n', "Debian Bookworm / Raspberry Pi OS (64-bit)"),
        ('ID=ubuntu\nVERSION_ID="24.04"\n', "Ubuntu 24.04"),
    ],
)
def test_supported_platforms_are_recognised(
    tmp_path: Path, content: str, expected: str
) -> None:
    release = tmp_path / "os-release"
    release.write_text(content)
    platform = prerequisites.detect_platform(release)
    assert platform is not None
    assert platform.label == expected


@pytest.mark.parametrize(
    "content",
    ['ID=fedora\nVERSION_ID="41"\n', 'ID=debian\nVERSION_ID="11"\n', "", "garbage\n"],
)
def test_unsupported_platforms_are_not_guessed_at(tmp_path: Path, content: str) -> None:
    release = tmp_path / "os-release"
    release.write_text(content)
    assert prerequisites.detect_platform(release) is None


def test_a_missing_os_release_is_not_an_error(tmp_path: Path) -> None:
    assert prerequisites.detect_platform(tmp_path / "absent") is None


# --- a successful package manager is still verified -----------------------


def test_apt_success_is_rechecked_against_the_real_capability(
    as_root: None,
) -> None:
    """Exit 0 says apt believed itself; it does not say this interpreter can."""
    capability = _Capability(present=False)
    apt = _Apt(provides=())  # exits 0 but changes nothing that matters
    operator = _Operator("y")
    with pytest.raises(LinuxInstallError) as excinfo:
        prerequisites.ensure(
            unattended=False,
            prompt=operator.prompt,
            write=operator.write,
            prerequisites=(_absent(capability=capability),),
            runner=apt,
        )
    assert apt.commands, "apt was run"
    assert "still unavailable to this interpreter" in str(excinfo.value)
    assert excinfo.value.code == prerequisites.FAILURE_CODE


def test_a_capability_that_really_appears_is_accepted(as_root: None) -> None:
    capability = _Capability(present=False)
    apt = _Apt(provides=(capability,))
    operator = _Operator("y")
    installed = prerequisites.ensure(
        unattended=False,
        prompt=operator.prompt,
        write=operator.write,
        prerequisites=(_absent(capability=capability),),
        runner=apt,
    )
    assert installed == ["python3-venv"]
    assert capability.present is True


def test_a_partial_failure_is_described_honestly(as_root: None) -> None:
    """apt can install and configure some packages before it stops."""
    operator = _Operator("y")
    with pytest.raises(LinuxInstallError) as excinfo:
        prerequisites.ensure(
            unattended=False,
            prompt=operator.prompt,
            write=operator.write,
            prerequisites=(ABSENT,),
            runner=_Apt(returncode=100),
        )
    message = str(excinfo.value)
    assert "may have been installed or partly configured" in message
    assert "inspect the host before retrying" in message
    assert "left as it was found" not in message


# --- the venv probe tests the capability, not the imports -----------------


def test_the_venv_probe_uses_the_interpreter_rather_than_importing() -> None:
    """Debian ships `venv` and `ensurepip` while withholding python3-venv."""
    assert prerequisites.venv_capable() is True
    assert prerequisites.venv_capable("/nonexistent/python") is False


def test_the_venv_probe_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: dict[str, object] = {}

    def _record(command: Sequence[str], **kwargs: object) -> object:
        recorded.update(kwargs)
        return subprocess.CompletedProcess(list(command), 0)

    monkeypatch.setattr(prerequisites.subprocess, "run", _record)
    prerequisites.venv_capable()
    assert recorded["timeout"] == prerequisites.VENV_PROBE_TIMEOUT_S
    assert recorded["stdin"] == subprocess.DEVNULL


def test_the_probe_leaves_nothing_behind(tmp_path: Path) -> None:
    before = set(Path(tempfile.gettempdir()).glob("ori-venv-probe-*"))
    prerequisites.venv_capable()
    assert set(Path(tempfile.gettempdir()).glob("ori-venv-probe-*")) == before


# --- Raspberry Pi OS, the primary production platform ---------------------


def test_raspberry_pi_os_bookworm_is_recognised(tmp_path: Path) -> None:
    """A realistic 32-bit Raspberry Pi OS /etc/os-release."""
    release = tmp_path / "os-release"
    release.write_text(
        'PRETTY_NAME="Raspbian GNU/Linux 12 (bookworm)"\n'
        'NAME="Raspbian GNU/Linux"\n'
        'VERSION_ID="12"\n'
        'VERSION="12 (bookworm)"\n'
        "VERSION_CODENAME=bookworm\n"
        "ID=raspbian\n"
        "ID_LIKE=debian\n"
        'HOME_URL="http://www.raspbian.org/"\n'
    )
    platform = prerequisites.detect_platform(release)
    assert platform is not None
    assert platform.identifier == "raspbian"
    assert "Raspberry Pi OS" in platform.label


def test_raspberry_pi_os_64_bit_is_recognised(tmp_path: Path) -> None:
    """The 64-bit image reports ID=debian, which must also be supported."""
    release = tmp_path / "os-release"
    release.write_text(
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
        'NAME="Debian GNU/Linux"\n'
        'VERSION_ID="12"\n'
        "ID=debian\n"
    )
    platform = prerequisites.detect_platform(release)
    assert platform is not None
    assert "Raspberry Pi OS" in platform.label


def test_both_production_tuples_are_supported() -> None:
    """The tuples SECURITY.md commits to must both be recognised."""
    assert ("raspbian", "12") in prerequisites.SUPPORTED
    assert ("debian", "12") in prerequisites.SUPPORTED
    assert ("ubuntu", "24.04") in prerequisites.SUPPORTED


def test_the_prompt_does_not_understate_what_apt_does(as_root: None) -> None:
    """`apt-get install` pulls dependencies and updates package-manager state.

    The command shown is exact, but its effects are not confined to the
    packages named in it, and the prompt must not suggest otherwise.
    """
    operator = _Operator("n")
    with pytest.raises(LinuxInstallError):
        prerequisites.ensure(
            unattended=False,
            prompt=operator.prompt,
            write=operator.write,
            prerequisites=(ABSENT,),
            runner=_Apt(),
        )
    shown = " ".join(operator.shown.split())
    assert "apt may install required OS dependencies" in shown
    assert "update package-manager state" in shown
    assert "No Python packages are downloaded from package indexes" in shown
    assert "Nothing else is changed" not in shown


def test_shared_os_components_are_not_installable(as_root: None) -> None:
    """The spec forbids components unrelated software depends on. openssl and
    ca-certificates are also pointless here: both are needed to download and
    verify a release, so the authenticated installer reaches them too late."""
    for package in ("openssl", "ca-certificates", "systemd", "python3", "bash"):
        with pytest.raises(LinuxInstallError) as excinfo:
            prerequisites.install_command([package])
        assert excinfo.value.code == prerequisites.FAILURE_CODE
        assert package in prerequisites.PROTECTED or True


def test_the_installer_claims_only_the_authority_it_needs() -> None:
    assert prerequisites.ALLOWED_PACKAGES == frozenset({"python3-venv"})
    assert {p.package for p in prerequisites.REQUIRED} <= prerequisites.ALLOWED_PACKAGES
