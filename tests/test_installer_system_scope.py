# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A real system-scope installation, as root, against a real virtual environment.

Two things here cannot be approximated. `venv/bin/python` is a symlink, and
Linux reports every symlink's mode as 0777 whatever it points at, so a check
that reads those bits as write permission classifies a correctly installed,
root-owned release as attacker-writable — invisible to any test that stands a
plain file in for the interpreter. And the permissions a system installation
has are the ones `apply_system_service_permissions` produces; reproducing them
with `chown` and `chmod` in the test only tests the reproduction.

So the installation is driven through `install_release` with a system profile,
letting the real permission pass run, and the resulting tree is judged by the
real diagnostics and the real activation gate.

Selection is by explicit opt-in rather than by privilege. An ordinary
unprivileged `pytest tests/` skips this module; the dedicated step sets
`ORI_REQUIRE_ROOT_TESTS=1`, and with that set the module asserts root instead
of skipping, so an invocation that lost its `sudo` fails loudly rather than
reporting green having run nothing:

    sudo -H env ORI_REQUIRE_ROOT_TESTS=1 \\
      "$(which python)" -m pytest tests/test_installer_system_scope.py -q
"""

from __future__ import annotations

import itertools
import os
import pwd
import shutil
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from ori import doctor
from ori.installer import activation, trusted_paths
from ori.installer.linux import InstallLayout, SystemdServiceProfile, install_release
from ori.installer.trusted_paths import trust_failure

_REQUIRED = os.environ.get("ORI_REQUIRE_ROOT_TESTS") == "1"

pytestmark = [
    pytest.mark.skipif(
        not _REQUIRED,
        reason="set ORI_REQUIRE_ROOT_TESTS=1 and run as root to select these",
    ),
    pytest.mark.skipif(
        sys.platform != "linux",
        reason="system scope, root ownership and 0777 symlink modes are Linux "
        "behaviour",
    ),
]

# An unprivileged account present on any Debian-derived host. The service
# account is not created here — an existing identity is lent to the profile so
# the real permission application runs against a real uid, gid and group list
# without leaving a durable account behind on whatever machine ran the suite.
_STAND_IN_ACCOUNT = "daemon"

_COUNTER = itertools.count()

# `/opt` first, because that is where a real installation goes and the test is
# most faithful there. The rest are ordinary root-owned system directories to
# fall back on when a host leaves `/opt` open.
_ROOT_CONTROLLED_PARENTS = ("/opt", "/var/lib", "/usr/local/lib", "/")

# Candidates for the interpreter the installed environment is built from,
# preferred order. `sys.executable` is deliberately not first: under
# `actions/setup-python` it lives in the runner's tool cache, which is writable
# by the runner account by design, so a venv built from it is exactly the
# untrusted arrangement these tests exist to reject — a true failure that says
# nothing about the installer. The running version is preferred so the
# environment matches the interpreter under test.
_BASE_INTERPRETER_CANDIDATES = (
    f"/usr/bin/python{sys.version_info.major}.{sys.version_info.minor}",
    f"/usr/local/bin/python{sys.version_info.major}.{sys.version_info.minor}",
    "/usr/bin/python3.12",
    "/usr/bin/python3.11",
    "/usr/bin/python3",
    "/usr/local/bin/python3",
    sys.executable,
)


def test_this_module_is_running_as_root() -> None:
    """Fail rather than skip, so a lost `sudo` cannot look like a pass."""
    assert os.geteuid() == 0, (
        "ORI_REQUIRE_ROOT_TESTS=1 selects these tests, so they must be running "
        "as root; invoke them with sudo -H env ORI_REQUIRE_ROOT_TESTS=1 "
        '"$(which python)" -m pytest tests/test_installer_system_scope.py'
    )


@pytest.fixture
def service_account(monkeypatch: pytest.MonkeyPatch) -> pwd.struct_passwd:
    """Resolve the runtime's service account to a real unprivileged one."""
    record = pwd.getpwnam(_STAND_IN_ACCOUNT)
    assert record.pw_uid != 0, "the stand-in service account must be unprivileged"
    original = pwd.getpwnam

    def resolve(name: str) -> pwd.struct_passwd:
        return record if name == "ori-runtime" else original(name)

    monkeypatch.setattr(pwd, "getpwnam", resolve)
    return record


@pytest.fixture
def system_root() -> Iterator[Path]:
    """An install root beneath a directory only root can change, as `/opt/ori` is.

    `tmp_path` cannot serve: pytest puts it under `/tmp`, which is mode 1777,
    and a world-writable ancestor is correctly untrusted. A failure there would
    say nothing about the installer.

    `/opt` is where a real installation lives and is tried first, but it is not
    root-exclusive everywhere — a CI runner image may leave it writable by the
    build account, and the installer then refuses every path beneath it, which
    is the correct answer for that host rather than a defect. So the parent is
    established by asking, not assumed. Failing beats skipping if none can be
    found: a host with no root-controlled directory cannot carry a system
    installation at all, and silence would hide exactly that.
    """
    for candidate in _ROOT_CONTROLLED_PARENTS:
        parent = Path(candidate)
        if parent.is_dir() and trust_failure(parent) is None:
            break
    else:
        tried = ", ".join(
            f"{c} ({trust_failure(Path(c)) or 'absent'})"
            for c in _ROOT_CONTROLLED_PARENTS
        )
        pytest.fail(f"no root-controlled parent directory on this host: {tried}")
    root = parent / f"ori-systemscope-{os.getpid()}-{next(_COUNTER)}"
    try:
        yield root
    finally:
        subprocess.run(["chmod", "-R", "u+rwX", str(root)], check=False)
        shutil.rmtree(root, ignore_errors=True)


def _trusted_base_interpreter() -> str:
    """The first candidate root alone controls, or fail saying what was tried.

    Skipping would be the wrong answer: a host with no root-controlled Python
    cannot install system scope at all, so silence here would hide the very
    condition the installer now refuses up front.
    """
    tried: list[str] = []
    for candidate in _BASE_INTERPRETER_CANDIDATES:
        if not Path(candidate).exists():
            tried.append(f"{candidate}: absent")
            continue
        failure = trust_failure(candidate, require_executable=True)
        if failure is not None:
            tried.append(f"{candidate}: {failure}")
            continue
        # Trusted is not sufficient: Debian ships `ensurepip` in a separate
        # package, so an interpreter can be perfectly root-controlled and still
        # unable to build an environment. Asking it directly is cheaper than
        # discovering it inside a fixture.
        probe = subprocess.run(
            [candidate, "-c", "import ensurepip, venv"],
            capture_output=True,
            check=False,
        )
        if probe.returncode != 0:
            tried.append(f"{candidate}: cannot build a virtual environment")
            continue
        return candidate
    raise AssertionError(
        "no root-controlled interpreter to build the release environment "
        "from; tried " + "; ".join(tried)
    )


def _install_system_scope(root: Path) -> tuple[InstallLayout, Path]:
    """Install through the installer, with the real system permission pass."""
    layout = InstallLayout.resolve(root)

    def prepare(staging: Path) -> None:
        subprocess.run(
            [_trusted_base_interpreter(), "-m", "venv", str(staging / "venv")],
            check=True,
            capture_output=True,
        )
        (staging / "ori").mkdir()
        (staging / "ori" / "runtime.py").write_text("# code\n", encoding="utf-8")

    install_release(
        layout=layout,
        version="2.4.0-rc.5",
        prepare=prepare,
        validate=lambda _path: None,
        restart_service=lambda: None,
        stop_service=lambda: None,
        check_health=lambda _path: None,
        # The real thing: this is what runs `apply_system_service_permissions`.
        service_profile=SystemdServiceProfile.system(),
        allowed_data_sockets=(layout.data / "health.sock",),
    )
    (layout.data / "ori.yaml").write_text("device: {}\n", encoding="utf-8")
    return layout, layout.release("2.4.0-rc.5")


def _identity(layout: InstallLayout, release: Path) -> doctor.InstallIdentity:
    return doctor.InstallIdentity(
        scope="system",
        version="2.4.0-rc.5",
        install_root=layout.root,
        active_release=release,
        config_path=layout.data / "ori.yaml",
        data_path=layout.data,
        health_socket=layout.data / "health.sock",
        unit_path=Path("/etc/systemd/system/ori-runtime.service"),
        service_user="ori-runtime",
    )


@pytest.fixture
def installation(
    system_root: Path, service_account: pwd.struct_passwd
) -> tuple[InstallLayout, Path, doctor.InstallIdentity]:
    layout, release = _install_system_scope(system_root)
    return layout, release, _identity(layout, release)


def _reported(checks: list[doctor.DoctorCheck]) -> list[dict[str, object]]:
    return [
        {
            "name": check.name,
            "status": check.status,
            "message": check.message,
            "mandatory": check.mandatory,
        }
        for check in checks
    ]


def test_the_environment_is_built_from_a_root_controlled_interpreter() -> None:
    """State the requirement these tests depend on, rather than assuming it.

    A venv links back to the interpreter it was built from, so building one from
    a runner's tool cache would produce a release that fails for a reason about
    the CI host rather than about the installer.
    """
    chosen = _trusted_base_interpreter()

    assert trust_failure(chosen, require_executable=True) is None


# --- the premise -------------------------------------------------------------


def test_the_interpreter_of_a_real_venv_is_a_symlink(
    installation: tuple[InstallLayout, Path, doctor.InstallIdentity],
) -> None:
    """If a future Python stops symlinking `bin/python`, say so here.

    The checks below would keep passing while no longer exercising the case
    that rolled back every system installation.
    """
    _layout, release, _identity_ = installation
    info = (release / "venv" / "bin" / "python").lstat()

    assert stat.S_ISLNK(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == 0o777


# --- what the installer actually produces ------------------------------------


def test_root_may_execute_a_release_the_installer_produced(
    installation: tuple[InstallLayout, Path, doctor.InstallIdentity],
) -> None:
    """The defect that rolled back every system installation."""
    _layout, _release, identity = installation

    doctor.assert_execution_allowed(identity)


def test_every_mandatory_permission_check_passes(
    installation: tuple[InstallLayout, Path, doctor.InstallIdentity],
) -> None:
    """The whole report, not one check of it.

    Asserting `permissions.code` alone would pass while the service could not
    traverse the root or read its config — an installation that cannot run.
    """
    _layout, _release, identity = installation

    checks = doctor.check_permissions(identity)
    failures = [c for c in checks if c.mandatory and c.status != doctor.PASS]

    assert "permissions.code" in {check.name for check in checks}
    assert not failures, [f"{c.name}: {c.message}" for c in failures]


def test_the_activation_gate_accepts_the_report(
    installation: tuple[InstallLayout, Path, doctor.InstallIdentity],
) -> None:
    """The gate the installer itself calls, on the real report."""
    _layout, _release, identity = installation

    reported = _reported(doctor.check_permissions(identity))

    assert activation.blocking(reported) == []
    activation.assert_usable(reported)


def test_the_interpreter_target_may_live_outside_the_release(
    installation: tuple[InstallLayout, Path, doctor.InstallIdentity],
) -> None:
    """Containment is not the rule; trust is.

    A venv interpreter resolves to the system Python, and requiring targets to
    stay inside the release would reject every one.
    """
    _layout, release, _identity_ = installation
    interpreter = release / "venv" / "bin" / "python"

    assert not Path(os.path.realpath(interpreter)).is_relative_to(release)
    assert trust_failure(interpreter, require_executable=True) is None


# --- and the same integration must refuse a tree that stops deserving trust ---


def test_an_interpreter_target_under_an_open_directory_is_refused(
    installation: tuple[InstallLayout, Path, doctor.InstallIdentity],
    system_root: Path,
) -> None:
    """A root-owned binary under a directory anyone can write is replaceable."""
    _layout, release, identity = installation
    open_directory = system_root.parent / f"{system_root.name}-open"
    open_directory.mkdir()
    try:
        planted = open_directory / "python"
        shutil.copy2(os.path.realpath(release / "venv" / "bin" / "python"), planted)
        os.chown(planted, 0, 0)
        planted.chmod(0o755)
        open_directory.chmod(0o777)
        interpreter = release / "venv" / "bin" / "python"
        interpreter.unlink()
        interpreter.symlink_to(planted)

        with pytest.raises(doctor.UnsafeExecutionError) as error:
            doctor.assert_execution_allowed(identity)

        assert str(open_directory) in str(error.value)
        assert "is writable by another account" in str(error.value)
    finally:
        shutil.rmtree(open_directory, ignore_errors=True)


def test_a_writable_ancestor_of_the_interpreter_is_refused(
    installation: tuple[InstallLayout, Path, doctor.InstallIdentity],
) -> None:
    """Trust has to hold the whole way down, on a real installed tree."""
    _layout, release, identity = installation
    (release / "venv" / "bin").chmod(0o777)

    with pytest.raises(doctor.UnsafeExecutionError) as error:
        doctor.assert_execution_allowed(identity)

    assert "is writable by another account" in str(error.value)


def test_a_dangling_interpreter_is_refused_without_hanging(
    installation: tuple[InstallLayout, Path, doctor.InstallIdentity],
    system_root: Path,
) -> None:
    _layout, release, identity = installation
    interpreter = release / "venv" / "bin" / "python"
    interpreter.unlink()
    interpreter.symlink_to(system_root / "absent" / "python")

    with pytest.raises(doctor.UnsafeExecutionError):
        doctor.assert_execution_allowed(identity)


def test_a_cyclic_interpreter_is_refused_without_hanging(
    installation: tuple[InstallLayout, Path, doctor.InstallIdentity],
) -> None:
    """A link tree that never resolves must end the check, not the process."""
    _layout, release, identity = installation
    binaries = release / "venv" / "bin"
    (binaries / "python").unlink()
    (binaries / "python").symlink_to(binaries / "loop-a")
    (binaries / "loop-a").symlink_to(binaries / "loop-b")
    (binaries / "loop-b").symlink_to(binaries / "loop-a")

    with pytest.raises(doctor.UnsafeExecutionError):
        doctor.assert_execution_allowed(identity)


def test_a_chain_longer_than_the_hop_budget_is_refused(
    installation: tuple[InstallLayout, Path, doctor.InstallIdentity],
) -> None:
    """The budget, isolated from cycle detection.

    A cycle is caught by having seen the inode before, so a loop proves nothing
    about the hop limit. Only a long chain of distinct links reaches it.
    """
    _layout, release, identity = installation
    binaries = release / "venv" / "bin"
    (binaries / "python").unlink()
    depth = trusted_paths.MAX_SYMLINK_HOPS + 5
    for index in range(depth):
        target = binaries / (f"hop-{index + 1}" if index + 1 < depth else "hop-end")
        (binaries / f"hop-{index}").symlink_to(target)
    (binaries / "hop-end").write_text("#!/bin/sh\n", encoding="utf-8")
    (binaries / "hop-end").chmod(0o755)
    (binaries / "python").symlink_to(binaries / "hop-0")
    subprocess.run(["chown", "-h", "-R", "root:root", str(binaries)], check=True)

    with pytest.raises(doctor.UnsafeExecutionError) as error:
        doctor.assert_execution_allowed(identity)

    assert "too many symlinks" in str(error.value)
