# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Doctor diagnostics: privilege boundary, persistence, and service permissions."""

from __future__ import annotations

import json
import os
import pwd
import socket
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Sequence

import pytest

from ori import doctor
from ori.installer import trusted_paths
from ori.utils import terminal


def _identity(root: Path, scope: str = "user", service_user: str | None = None):
    release = root / "releases" / "2.3.1"
    return doctor.InstallIdentity(
        scope=scope,
        version="2.3.1",
        install_root=root,
        active_release=release,
        config_path=root / "data" / "ori.yaml",
        data_path=root / "data",
        health_socket=root / "data" / "health.sock",
        unit_path=root / "unit" / "ori-runtime.service",
        service_user=service_user,
    )


def _layout(root: Path) -> None:
    release = root / "releases" / "2.3.1"
    (release / "venv" / "bin").mkdir(parents=True)
    interpreter = release / "venv" / "bin" / "python"
    interpreter.write_text("#!/bin/sh\n")
    interpreter.chmod(0o755)
    (root / "data").mkdir(parents=True)
    (root / "data" / "ori.yaml").write_text("device:\n  id: pi-01\n")


class _Runner:
    """Answers systemctl and loginctl from a script, recording every call."""

    def __init__(self, **replies: str) -> None:
        self.replies = replies
        self.calls: list[list[str]] = []

    def __call__(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(command))
        for key, value in self.replies.items():
            if key.replace("_", "-") in command:
                return subprocess.CompletedProcess(list(command), 0, value, "")
        return subprocess.CompletedProcess(list(command), 1, "", "")


# --- privilege boundary ---------------------------------------------------


def test_user_scope_is_never_executed_as_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`sudo ori doctor --scope user` would let a user choose what root runs."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(doctor.UnsafeExecutionError) as excinfo:
        doctor.assert_execution_allowed(_identity(tmp_path, scope="user"))
    assert "without sudo" in str(excinfo.value)


def test_run_doctor_refuses_before_spawning_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    runner = _Runner()
    with pytest.raises(doctor.UnsafeExecutionError):
        doctor.run_doctor(_identity(tmp_path, scope="user"), "pi-01", runner=runner)
    assert runner.calls == []


# Which component of a temporary tree is untrusted first is the platform's
# choice, not the installer's: pytest builds under `/tmp` on Linux, which is
# mode 1777, and under a user-owned `/var/folders/...` on macOS. Both are
# genuine refusals, so the assertion is that root declined and said which
# component and why — not which of the two reasons this host happened to reach.
_TRUST_REASONS = ("is not owned by root", "is writable by another account")


def _refusal_is_explained(message: str) -> bool:
    return "refusing to execute as root" in message and any(
        reason in message for reason in _TRUST_REASONS
    )


def test_a_system_label_on_a_user_owned_root_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--scope system --root /home/alice/...` must not launder a user install."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    with pytest.raises(doctor.UnsafeExecutionError) as excinfo:
        doctor.assert_execution_allowed(_identity(tmp_path, scope="system"))

    assert _refusal_is_explained(str(excinfo.value)), excinfo.value


def test_run_doctor_refuses_a_laundered_root_before_spawning_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _layout(tmp_path)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    runner = _Runner()
    with pytest.raises(doctor.UnsafeExecutionError):
        doctor.run_doctor(_identity(tmp_path, scope="system"), "pi-01", runner=runner)
    assert runner.calls == []


def test_an_explicit_root_is_still_refused_execution_as_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--root` exists so an installer can diagnose the tree it just activated.

    It is safe because authorisation never came from the scope label: what is
    checked is whether every path leading to the interpreter is root-owned.
    """
    _layout(tmp_path)
    (tmp_path / "current").symlink_to(tmp_path / "releases" / "2.3.1")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert doctor.main(["--scope", "system", "--root", str(tmp_path)]) == 2
    assert "refusing to run" in capsys.readouterr().err


def test_a_root_owned_chain_is_trusted() -> None:
    """The real system layout: root-owned, not writable by group or other."""
    assert doctor._interpreter_trust_failure(Path("/usr/bin/env")) is None


def test_an_untrusted_component_is_named(tmp_path: Path, not_root: None) -> None:
    """A temporary tree is untrusted somewhere above; that must be caught.

    The component named is whichever fails first — user-owned on one platform,
    world-writable on another — and either answer identifies a path root cannot
    rely on.
    """
    failure = doctor._interpreter_trust_failure(tmp_path / "x" / "y")

    assert failure is not None
    assert any(reason in failure for reason in _TRUST_REASONS), failure


def test_a_group_writable_component_is_untrusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Root ownership alone is not enough if another account can write it."""
    monkeypatch.setattr(
        trusted_paths.os,
        "lstat",
        lambda path: SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o775),
    )

    failure = doctor._interpreter_trust_failure(tmp_path)

    assert failure is not None
    assert "is writable by another account" in failure


def test_a_missing_component_below_a_trusted_chain_is_accepted() -> None:
    """Nothing unprivileged can create it, so there is nothing to plant.

    The execution guard asks only whether anything untrusted lies on the path;
    whether the interpreter exists is the caller's concern.
    """
    assert trusted_paths.trust_failure("/usr/absent/venv/bin/python") is None


def test_an_interpreter_that_does_not_exist_is_refused() -> None:
    """Executing it is the question here, and a missing file cannot be run."""
    failure = doctor._interpreter_trust_failure(Path("/usr/absent/venv/bin/python"))

    assert failure is not None
    assert "does not exist" in failure


def test_user_scope_as_its_owner_is_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    doctor.assert_execution_allowed(_identity(tmp_path, scope="user"))


# --- boot persistence -----------------------------------------------------


def _persistence(checks: Sequence[doctor.DoctorCheck]) -> doctor.DoctorCheck:
    return next(c for c in checks if c.name == "service.boot_persistence")


def test_lingering_without_an_enabled_unit_does_not_start_at_boot(
    tmp_path: Path,
) -> None:
    """The user manager starts at boot, but only starts units that are enabled."""
    _layout(tmp_path)
    runner = _Runner(is_active="active", is_enabled="disabled", Linger="yes")
    checks = doctor.check_service(_identity(tmp_path, scope="user"), runner)
    persistence = _persistence(checks)
    assert persistence.status == terminal.WARN
    assert persistence.details["persistence_source"] == "none"
    assert "unit is not" in persistence.message
    assert "enable" in persistence.remedy


def test_enabled_unit_without_lingering_does_not_start_at_boot(
    tmp_path: Path,
) -> None:
    _layout(tmp_path)
    runner = _Runner(is_active="active", is_enabled="enabled", Linger="no")
    persistence = _persistence(
        doctor.check_service(_identity(tmp_path, scope="user"), runner)
    )
    assert persistence.status == terminal.WARN
    assert persistence.details["persistence_source"] == "none"
    assert "last session ends" in persistence.message
    assert "Closing a terminal does not end the session" in persistence.message
    assert "enable-linger" in persistence.remedy


def test_both_conditions_together_are_persistent(tmp_path: Path) -> None:
    _layout(tmp_path)
    runner = _Runner(is_active="active", is_enabled="enabled", Linger="yes")
    persistence = _persistence(
        doctor.check_service(_identity(tmp_path, scope="user"), runner)
    )
    assert persistence.status == terminal.PASS
    assert persistence.details["persistence_source"] == "user_lingering"
    assert "without login" in persistence.message


def test_linger_is_queried_for_the_installation_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The inspecting account's lingering state says nothing about this install."""
    _layout(tmp_path)
    owner_uid = tmp_path.stat().st_uid
    monkeypatch.setattr(os, "getuid", lambda: 4242)
    runner = _Runner(is_active="active", is_enabled="enabled", Linger="yes")
    doctor.check_service(_identity(tmp_path, scope="user"), runner)
    loginctl = next(c for c in runner.calls if c[0] == "loginctl")
    assert loginctl[2] == str(owner_uid)
    assert "4242" not in loginctl


def test_system_persistence_names_the_unit_as_its_source(tmp_path: Path) -> None:
    _layout(tmp_path)
    runner = _Runner(is_active="active", is_enabled="enabled")
    persistence = _persistence(
        doctor.check_service(_identity(tmp_path, scope="system"), runner)
    )
    assert persistence.status == terminal.PASS
    assert persistence.details["persistence_source"] == "system_unit"
    assert not any(c[0] == "loginctl" for c in runner.calls)


def test_inactive_service_is_a_blocking_failure(tmp_path: Path) -> None:
    _layout(tmp_path)
    runner = _Runner(is_active="inactive", is_enabled="enabled")
    checks = doctor.check_service(_identity(tmp_path, scope="system"), runner)
    active = next(c for c in checks if c.name == "service.active")
    assert active.status == terminal.FAIL
    assert active.mandatory is True


# --- service permissions --------------------------------------------------


def _checks(root: Path) -> dict[str, doctor.DoctorCheck]:
    """Permission checks under system scope, where code immutability is claimed.

    The service account is this test's own user, so the release tree is owned by
    the very account the runtime would run as. That is the adversarial shape the
    check exists to catch: under system scope a release the service can write is
    a finding, whoever that service happens to be.
    """
    return {
        c.name: c
        for c in doctor.check_permissions(
            _identity(
                root, scope="system", service_user=pwd.getpwuid(os.getuid()).pw_name
            )
        )
    }


def _user_scope_checks(root: Path) -> dict[str, doctor.DoctorCheck]:
    return {c.name: c for c in doctor.check_permissions(_identity(root, scope="user"))}


@pytest.fixture
def not_root() -> None:
    if os.geteuid() == 0:
        pytest.skip("mode-based denial cannot be observed as root")


def test_a_healthy_layout_passes(tmp_path: Path, not_root: None) -> None:
    _layout(tmp_path)
    _sealed(tmp_path)
    try:
        results = _checks(tmp_path)
        assert results["permissions.config"].status == terminal.PASS
        assert results["permissions.interpreter"].status == terminal.PASS
        assert results["permissions.data"].status == terminal.PASS
        assert results["permissions.code"].status == terminal.PASS
    finally:
        _unseal(tmp_path)


def _release(root: Path) -> Path:
    return root / "releases" / "2.3.1"


def _sealed(root: Path) -> None:
    """Make the release tree immutable to its owner, deepest entries first."""
    release = _release(root)
    for entry in sorted(release.rglob("*"), reverse=True):
        if entry.is_symlink():
            continue
        executable = entry.is_dir() or entry.stat().st_mode & 0o100
        entry.chmod(0o555 if executable else 0o444)
    release.chmod(0o555)


def _unseal(root: Path) -> None:
    release = _release(root)
    release.chmod(0o755)
    for entry in sorted(release.rglob("*")):
        if not entry.is_symlink():
            entry.chmod(0o755)


def test_a_writable_file_under_a_read_only_release_fails(
    tmp_path: Path, not_root: None
) -> None:
    """Modifying a file needs write on the file, not on its parent directory."""
    _layout(tmp_path)
    payload = _release(tmp_path) / "ori_payload.py"
    payload.write_text("# code\n")
    _sealed(tmp_path)
    payload.chmod(0o666)
    try:
        code = _checks(tmp_path)["permissions.code"]
        assert code.status == terminal.FAIL
        assert code.mandatory is True
        assert code.details["offending_path"] == str(payload)
        assert "not immutable" in code.message
    finally:
        _unseal(tmp_path)


def test_a_writable_nested_directory_fails(tmp_path: Path, not_root: None) -> None:
    _layout(tmp_path)
    nested = _release(tmp_path) / "ori" / "skills"
    nested.mkdir(parents=True)
    _sealed(tmp_path)
    nested.chmod(0o775)
    try:
        code = _checks(tmp_path)["permissions.code"]
        assert code.status == terminal.FAIL
        assert code.details["offending_path"] == str(nested)
    finally:
        _unseal(tmp_path)


def test_a_sealed_release_passes(tmp_path: Path, not_root: None) -> None:
    _layout(tmp_path)
    (_release(tmp_path) / "ori").mkdir()
    (_release(tmp_path) / "ori" / "runtime.py").write_text("# code\n")
    _sealed(tmp_path)
    try:
        assert _checks(tmp_path)["permissions.code"].status == terminal.PASS
    finally:
        _unseal(tmp_path)


# --- user scope cannot claim code immutability ----------------------------


def test_user_scope_reports_an_advisory_rather_than_a_failure(
    tmp_path: Path, not_root: None
) -> None:
    """A user-scope install is complete; it just cannot offer immutability.

    The release and the runtime share one Unix owner, so the account that runs
    the code can always restore write access to it. Failing here would reject a
    working workstation install for a property its deployment model never had.
    """
    _layout(tmp_path)
    (_release(tmp_path) / "ori").mkdir()
    (_release(tmp_path) / "ori" / "runtime.py").write_text("# code\n")

    code = _user_scope_checks(tmp_path)["permissions.code"]

    assert code.status == terminal.WARN
    assert code.mandatory is False
    assert "cannot be made immutable" in code.message
    assert "system scope" in code.message


def test_user_scope_advisory_is_not_silenced_by_read_only_modes(
    tmp_path: Path, not_root: None
) -> None:
    """Sealing the tree must not buy a passing claim.

    Mode bits describe the current state, not a boundary: the owner may chmod
    them back at any moment, so a compromised runtime can restore write access
    to the code it is about to execute. Reporting PASS because the bits look
    right at this instant would be a false assurance — which is exactly why the
    installer does not seal user-scope trees to make this check quiet.
    """
    _layout(tmp_path)
    (_release(tmp_path) / "ori").mkdir()
    (_release(tmp_path) / "ori" / "runtime.py").write_text("# code\n")
    _sealed(tmp_path)
    try:
        code = _user_scope_checks(tmp_path)["permissions.code"]

        assert code.status == terminal.WARN
        assert code.mandatory is False
    finally:
        _unseal(tmp_path)


@pytest.mark.parametrize("scope", ["systemx", "SYSTEM", "", "root"])
def test_an_unrecognised_scope_is_refused_rather_than_treated_as_user(
    tmp_path: Path, not_root: None, scope: str
) -> None:
    """An unknown scope is not a third deployment model to be trusted.

    Testing `scope != "system"` would hand anything unrecognised the user
    scope's advisory, turning a mandatory security check into a passing warning
    for any value that is merely misspelled.
    """
    _layout(tmp_path)
    identity = _identity(tmp_path, scope=scope, service_user=None)

    code = {c.name: c for c in doctor.check_permissions(identity)}["permissions.code"]

    assert code.status == terminal.FAIL
    assert code.mandatory is True
    assert "unrecognised" in code.message


def test_system_scope_still_fails_on_a_release_the_service_can_write(
    tmp_path: Path, not_root: None
) -> None:
    """The scope split must not weaken the scope that can enforce it."""
    _layout(tmp_path)
    (_release(tmp_path) / "ori").mkdir()
    (_release(tmp_path) / "ori" / "runtime.py").write_text("# code\n")

    code = _checks(tmp_path)["permissions.code"]

    assert code.status == terminal.FAIL
    assert code.mandatory is True
    assert "not immutable" in code.message


def test_an_uninspectable_directory_fails_closed(
    tmp_path: Path, not_root: None
) -> None:
    _layout(tmp_path)
    opaque = _release(tmp_path) / "opaque"
    opaque.mkdir()
    (opaque / "module.py").write_text("# code\n")
    _sealed(tmp_path)
    opaque.chmod(0o111)  # searchable but not listable
    try:
        code = _checks(tmp_path)["permissions.code"]
        assert code.status == terminal.FAIL
        assert "could not be listed" in code.message
    finally:
        opaque.chmod(0o755)
        _unseal(tmp_path)


def test_a_special_file_in_a_release_fails(tmp_path: Path, not_root: None) -> None:
    _layout(tmp_path)
    fifo = _release(tmp_path) / "channel"
    os.mkfifo(fifo)
    _sealed(tmp_path)
    try:
        code = _checks(tmp_path)["permissions.code"]
        assert code.status == terminal.FAIL
        assert "special file" in code.message
        assert code.details["offending_path"] == str(fifo)
    finally:
        _unseal(tmp_path)


def test_a_permitted_internal_symlink_passes(tmp_path: Path, not_root: None) -> None:
    """A venv interpreter symlink inside its own release is legitimate."""
    _layout(tmp_path)
    binary = _release(tmp_path) / "venv" / "bin" / "python3.12"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o555)
    (_release(tmp_path) / "venv" / "bin" / "python3").symlink_to(binary)
    _sealed(tmp_path)
    try:
        assert _checks(tmp_path)["permissions.code"].status == terminal.PASS
    finally:
        _unseal(tmp_path)


def test_a_symlink_escaping_the_release_fails(tmp_path: Path, not_root: None) -> None:
    _layout(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("# attacker-controlled\n")
    escape = _release(tmp_path) / "venv" / "bin" / "escape"
    escape.symlink_to(outside)
    _sealed(tmp_path)
    try:
        code = _checks(tmp_path)["permissions.code"]
        assert code.status == terminal.FAIL
        assert code.details["offending_path"] == str(escape)
        assert "not a permitted release symlink" in code.message
    finally:
        _unseal(tmp_path)


def test_a_dangling_symlink_fails(tmp_path: Path, not_root: None) -> None:
    _layout(tmp_path)
    dangling = _release(tmp_path) / "venv" / "bin" / "missing"
    dangling.symlink_to(tmp_path / "nowhere")
    _sealed(tmp_path)
    try:
        assert _checks(tmp_path)["permissions.code"].status == terminal.FAIL
    finally:
        _unseal(tmp_path)


def test_a_writable_release_directory_fails(tmp_path: Path, not_root: None) -> None:
    _layout(tmp_path)
    _sealed(tmp_path)
    _release(tmp_path).chmod(0o755)
    try:
        code = _checks(tmp_path)["permissions.code"]
        assert code.status == terminal.FAIL
        assert code.mandatory is True
        assert code.details["offending_path"] == str(_release(tmp_path))
        assert "could rewrite the code it executes" in code.message
    finally:
        _unseal(tmp_path)


def test_an_unreadable_config_fails(tmp_path: Path, not_root: None) -> None:
    _layout(tmp_path)
    (tmp_path / "data" / "ori.yaml").chmod(0o000)
    config = _checks(tmp_path)["permissions.config"]
    assert config.status == terminal.FAIL
    assert config.mandatory is True


def test_an_unwritable_data_directory_fails(tmp_path: Path, not_root: None) -> None:
    _layout(tmp_path)
    (tmp_path / "releases" / "2.3.1").chmod(0o555)
    (tmp_path / "data").chmod(0o555)
    try:
        data = _checks(tmp_path)["permissions.data"]
        assert data.status == terminal.FAIL
        assert data.mandatory is True
    finally:
        (tmp_path / "data").chmod(0o755)


def test_a_non_executable_interpreter_fails(tmp_path: Path, not_root: None) -> None:
    _layout(tmp_path)
    (tmp_path / "releases" / "2.3.1" / "venv" / "bin" / "python").chmod(0o644)
    assert _checks(tmp_path)["permissions.interpreter"].status == terminal.FAIL


def test_an_unsearchable_ancestor_is_named(tmp_path: Path, not_root: None) -> None:
    """Doctor may be able to stat a path the service account cannot reach."""
    root = tmp_path / "outer" / "ori"
    root.mkdir(parents=True)
    _layout(root)
    (tmp_path / "outer").chmod(0o750)  # owner only: the service user is elsewhere
    identity = _identity(root, scope="system", service_user="nobody")
    results = {c.name: c for c in doctor.check_permissions(identity)}
    traverse = results["permissions.traverse"]
    assert traverse.status == terminal.FAIL
    assert traverse.mandatory is True
    assert str(tmp_path / "outer") in traverse.message


def test_unresolved_groups_block_the_code_integrity_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, not_root: None
) -> None:
    """A negative property cannot be proven from incomplete group information."""
    _layout(tmp_path)
    (tmp_path / "releases" / "2.3.1").chmod(0o555)

    def _raise(name: str, gid: int) -> list[int]:
        raise OverflowError("gid too large")

    monkeypatch.setattr(os, "getgrouplist", _raise)
    code = _checks(tmp_path)["permissions.code"]
    assert code.status == terminal.FAIL
    assert code.mandatory is True
    assert "Could not establish" in code.message
    assert "supplementary group" in code.message


@pytest.mark.parametrize(
    "blocked",
    ["releases", "releases/2.3.1", "releases/2.3.1/venv", "releases/2.3.1/venv/bin"],
)
def test_an_unsearchable_directory_above_the_interpreter_fails(
    tmp_path: Path, not_root: None, blocked: str
) -> None:
    """Mode on the interpreter proves nothing if the service cannot walk to it."""
    _layout(tmp_path)
    target = tmp_path / blocked
    target.chmod(0o644)
    try:
        check = _checks(tmp_path)["permissions.interpreter"]
        assert check.status == terminal.FAIL
        assert check.mandatory is True
        assert str(target) in check.message
        assert check.details["blocked_at"] == str(target)
    finally:
        target.chmod(0o755)


def test_an_unsearchable_data_directory_fails(tmp_path: Path, not_root: None) -> None:
    _layout(tmp_path)
    (tmp_path / "data").chmod(0o644)
    try:
        check = _checks(tmp_path)["permissions.config"]
        assert check.status == terminal.FAIL
        assert str(tmp_path / "data") in check.message
    finally:
        (tmp_path / "data").chmod(0o755)


def test_an_unresolvable_service_user_is_a_blocking_failure(tmp_path: Path) -> None:
    _layout(tmp_path)
    identity = _identity(tmp_path, scope="system", service_user="no-such-account")
    check = doctor.check_permissions(identity)[0]
    assert check.name == "permissions.service_user"
    assert check.status == terminal.FAIL
    assert check.mandatory is True


def test_a_system_service_running_as_root_is_a_blocking_failure(
    tmp_path: Path,
) -> None:
    _layout(tmp_path)
    identity = _identity(tmp_path, scope="system", service_user=pwd.getpwuid(0).pw_name)
    check = doctor.check_permissions(identity)[0]
    assert check.name == "permissions.service_user"
    assert check.status == terminal.FAIL
    assert "runs as root" in check.message


def test_missing_data_directory_is_a_blocking_failure(tmp_path: Path) -> None:
    (tmp_path / "releases" / "2.3.1").mkdir(parents=True)
    checks = doctor.check_permissions(_identity(tmp_path, scope="user"))
    assert checks[0].name == "permissions.data"
    assert checks[0].mandatory is True


def test_mode_evaluation_uses_the_owner_class_first() -> None:
    """POSIX consults owner bits on a uid match even when group bits are wider."""

    class _Stat:
        st_mode = 0o0070  # owner: ---, group: rwx
        st_uid = 1000
        st_gid = 50

    service = doctor.ServiceIdentity("svc", 1000, frozenset({50}))
    assert doctor._mode_allows(_Stat(), service, doctor.READ) is False
    other = doctor.ServiceIdentity("other", 1001, frozenset({50}))
    assert doctor._mode_allows(_Stat(), other, doctor.READ) is True


# --- classification and reporting ----------------------------------------


def test_only_mandatory_failures_block(tmp_path: Path) -> None:
    checks = [
        doctor.DoctorCheck("a", terminal.WARN, "advisory"),
        doctor.DoctorCheck("b", terminal.FAIL, "optional integration off"),
        doctor.DoctorCheck("c", terminal.FAIL, "runtime down", mandatory=True),
    ]
    blocking = doctor.blocking_failures(checks)
    assert [c.name for c in blocking] == ["c"]


def test_disabled_optional_capabilities_warn_but_never_block() -> None:
    checks = doctor._capability_checks(
        {"capability_posture": {"sms_available": True, "relay_connected": False}}
    )
    assert checks[0].status == terminal.WARN
    assert checks[0].mandatory is False
    assert "Relay control" in checks[0].message


def test_an_invalid_status_is_rejected() -> None:
    with pytest.raises(ValueError):
        doctor.DoctorCheck("x", "BROKEN", "message")


def test_report_states_scope_paths_and_persistence(tmp_path: Path) -> None:
    identity = _identity(tmp_path, scope="user")
    checks = [
        doctor.DoctorCheck(
            "service.boot_persistence", terminal.WARN, "Persistence: none — stops"
        )
    ]
    report = doctor.render_report(checks, identity, stream=None)
    for expected in (
        "user",
        str(identity.install_root),
        str(identity.config_path),
        str(identity.health_socket),
        str(identity.unit_path),
        "Persistence: none",
        "WARN",
    ):
        assert expected in report


def test_json_report_is_a_single_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ori.installer import paths

    _layout(tmp_path)
    identity = _identity(tmp_path, scope="user")
    monkeypatch.setattr(paths, "resolve_identity", lambda **k: (identity, "pi-01"))
    monkeypatch.setattr(doctor, "run_doctor", lambda *a, **k: [])
    assert doctor.main(["--scope", "user", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["identity"]["scope"] == "user"
    assert payload["checks"] == []


# ─── Gateway broker ───────────────────────────────────────────────────────────


def _gateway_runner(posture: dict, tmp_path: Path):
    """A runner returning the bridge's config-show payload for *posture*."""

    def run(command):
        payload = {"result": {"config": {"gateway": posture}}}
        return subprocess.CompletedProcess(
            command, 0, stdout=json.dumps(payload), stderr=""
        )

    return run


def _with_config(root: Path) -> None:
    (root / "data").mkdir(parents=True, exist_ok=True)
    (root / "data" / "ori.yaml").write_text("device: {}\n", encoding="utf-8")


def test_gateway_check_is_silent_when_gateway_is_disabled(tmp_path):
    """Most deployments never enable the gateway; they should see nothing."""
    _with_config(tmp_path)
    checks = doctor.check_gateway(
        _identity(tmp_path), _gateway_runner({"enabled": False}, tmp_path)
    )
    assert checks == []


def test_gateway_check_warns_when_no_broker_answers(tmp_path):
    """An enabled gateway with no broker is invisible until something fails.

    Advisory, not mandatory: a broker may start after the runtime, and gateway
    reasoning is discretionary — Tier D fires from the rule path regardless.
    """
    _with_config(tmp_path)
    posture = {
        "enabled": True,
        "broker_host": "127.0.0.1",
        "broker_port": 1,  # nothing listens here
        "broker_is_loopback": True,
        "auth_enabled": False,
    }
    checks = doctor.check_gateway(
        _identity(tmp_path), _gateway_runner(posture, tmp_path)
    )

    broker = next(c for c in checks if c.name == "gateway.broker")
    assert broker.status == doctor.WARN
    assert broker.mandatory is False
    assert "no broker answers" in broker.message


def test_gateway_check_passes_when_a_listener_answers(tmp_path):
    """Probe a real listener so the pass path is not asserted by construction."""
    _with_config(tmp_path)
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        posture = {
            "enabled": True,
            "broker_host": "127.0.0.1",
            "broker_port": port,
            "broker_is_loopback": True,
            "auth_enabled": False,
        }
        checks = doctor.check_gateway(
            _identity(tmp_path), _gateway_runner(posture, tmp_path)
        )

    broker = next(c for c in checks if c.name == "gateway.broker")
    assert broker.status == doctor.PASS


def test_gateway_check_reports_the_secret_variable_without_claiming_presence(
    tmp_path,
):
    """Naming the variable helps; claiming to know whether it is set does not.

    The service reads its secret from its own environment file, which `ori
    doctor` does not inherit. An earlier revision warned from `os.environ` and
    so reported a false "not set" against correctly configured, running
    deployments.
    """
    _with_config(tmp_path)
    posture = {
        "enabled": True,
        "broker_host": "127.0.0.1",
        "broker_port": 1,
        "auth_enabled": True,
        "shared_secret_env": "GATEWAY_SHARED_SECRET",
    }
    checks = doctor.check_gateway(
        _identity(tmp_path), _gateway_runner(posture, tmp_path)
    )

    secret = next(c for c in checks if c.name == "gateway.shared_secret_reference")
    assert secret.status == doctor.PASS
    assert "GATEWAY_SHARED_SECRET" in secret.message
    assert "delivery is enforced when the runtime starts" in secret.message
    assert all(c.status != doctor.FAIL for c in checks)


def test_gateway_check_reports_both_conditions_independently(tmp_path):
    """A broker problem must not suppress the other diagnostic."""
    _with_config(tmp_path)
    posture = {
        "enabled": True,
        "broker_host": "",
        "broker_port": None,
        "auth_enabled": True,
        "shared_secret_env": "GATEWAY_SHARED_SECRET",
    }
    checks = doctor.check_gateway(
        _identity(tmp_path), _gateway_runner(posture, tmp_path)
    )

    assert [c.name for c in checks] == [
        "gateway.broker",
        "gateway.shared_secret_reference",
    ]
    assert checks[0].status == doctor.WARN


def test_gateway_check_surfaces_an_unusable_broker_url(tmp_path):
    _with_config(tmp_path)
    posture = {
        "enabled": True,
        "broker_host": "",
        "broker_port": None,
        "broker_error": "gateway.broker_url has an invalid port",
        "auth_enabled": False,
    }
    checks = doctor.check_gateway(
        _identity(tmp_path), _gateway_runner(posture, tmp_path)
    )

    assert checks[0].status == doctor.WARN
    assert "unusable" in checks[0].message
