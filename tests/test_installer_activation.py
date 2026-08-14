# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Post-activation diagnostics, the launcher, and the guidance that follows."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from ori.installer import activation, launcher
from ori.installer.linux import LinuxInstallError

DEVICE_ID = "pi-01"


def _healthy_checks() -> list[dict[str, object]]:
    """The checks a real doctor emits for a healthy installation."""
    return [
        _check("install.identity", "PASS"),
        _check("prerequisite.systemctl", "PASS"),
        _check("config.valid", "PASS", mandatory=True),
        _check("service.active", "PASS", mandatory=True),
        _check("service.boot_persistence", "PASS"),
        _check("runtime.health", "PASS", mandatory=True),
        _check("runtime.identity", "PASS", mandatory=True),
        _check("capabilities.optional", "WARN"),
        _check("permissions.code", "PASS", mandatory=True),
    ]


def _report(root: Path, release: Path, checks: list[dict[str, object]]) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "identity": {
                "scope": "user",
                "install_root": str(root),
                "active_release": str(release),
                "device_id": DEVICE_ID,
            },
            "checks": checks,
        }
    )


def _release(
    root: Path,
    checks: list[dict[str, object]] | None = None,
    *,
    report: str | None = None,
    exit_code: int = 0,
) -> Path:
    """A release whose `ori` command reports the given doctor result."""
    release = root / "releases" / "2.3.1"
    entry = release / "venv" / "bin"
    entry.mkdir(parents=True)
    payload = (
        report
        if report is not None
        else _report(root, release, checks or _healthy_checks())
    )
    (entry / "ori").write_text(
        f"#!/bin/sh\ncat <<'ORI_REPORT'\n{payload}\nORI_REPORT\nexit {exit_code}\n"
    )
    (entry / "ori").chmod(0o755)
    return release


def _report_with(root: Path, release: Path, checks: list[dict[str, object]]) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "identity": {
                "scope": "user",
                "install_root": str(root),
                "active_release": str(release),
                "device_id": DEVICE_ID,
            },
            "checks": checks,
        }
    )


def _run(root: Path, release: Path) -> list[dict[str, object]]:
    return activation.run_installed_doctor(
        release, "user", root=root, expected_device_id=DEVICE_ID
    )


def _check(name: str, status: str, *, mandatory: bool = False) -> dict[str, object]:
    return {
        "name": name,
        "status": status,
        "message": f"{name} is {status}",
        "mandatory": mandatory,
    }


# --- the doctor is addressed absolutely -----------------------------------


def test_the_installed_doctor_is_run_by_absolute_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PATH would validate whichever release the shell finds first."""
    release = _release(tmp_path)
    recorded: list[list[str]] = []
    real_run = subprocess.run

    def _record(command: list[str], **kwargs: object) -> object:
        recorded.append(command)
        return real_run(command, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(activation.subprocess, "run", _record)
    _run(tmp_path, release)

    assert recorded[0][0] == str(release / "venv" / "bin" / "ori")
    assert Path(recorded[0][0]).is_absolute()
    assert recorded[0][1] == "doctor"
    assert "--json" in recorded[0]
    assert recorded[0][recorded[0].index("--scope") + 1] == "user"
    # Bound to the tree being activated, not to whatever the default root is.
    assert recorded[0][recorded[0].index("--root") + 1] == str(tmp_path)


def test_a_release_without_the_command_is_a_failure(tmp_path: Path) -> None:
    release = tmp_path / "releases" / "2.3.1"
    (release / "venv" / "bin").mkdir(parents=True)
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert excinfo.value.code == "post_install_health_failed"


def test_an_unreadable_report_is_a_failure(tmp_path: Path) -> None:
    release = tmp_path / "releases" / "2.3.1"
    entry = release / "venv" / "bin"
    entry.mkdir(parents=True)
    (entry / "ori").write_text('#!/bin/sh\necho "not json"\n')
    (entry / "ori").chmod(0o755)
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert "not JSON" in str(excinfo.value)


# --- what blocks an installation, and what does not -----------------------


def test_a_mandatory_failure_blocks_the_installation() -> None:
    checks = [
        _check("install.identity", "PASS"),
        _check("runtime.health", "FAIL", mandatory=True),
    ]
    with pytest.raises(LinuxInstallError) as excinfo:
        activation.assert_usable(checks)
    assert excinfo.value.code == "post_install_health_failed"
    assert "runtime.health" in str(excinfo.value)


def test_a_non_persistent_user_service_does_not_block(tmp_path: Path) -> None:
    """A warning is a real installation, not a reason to undo one."""
    checks = [
        _check("service.boot_persistence", "WARN"),
        _check("capabilities.optional", "WARN"),
    ]
    activation.assert_usable(checks)  # does not raise
    assert activation.blocking(checks) == []


def test_a_non_mandatory_failure_does_not_block() -> None:
    activation.assert_usable([_check("optional.thing", "FAIL")])


def test_warnings_are_surfaced_for_the_report() -> None:
    outcome = activation.ActivationOutcome(
        launcher_path=Path("/usr/local/bin/ori"),
        launcher_installed=True,
        launcher_conflict="",
        path_guidance="",
        checks=[
            _check("service.boot_persistence", "WARN"),
            _check("install.identity", "PASS"),
        ],
    )
    assert [w["name"] for w in outcome.warnings] == ["service.boot_persistence"]


# --- the launcher, and honest guidance ------------------------------------


def test_the_launcher_is_installed_for_the_active_root(tmp_path: Path) -> None:
    path = tmp_path / "bin" / "ori"
    installed, conflict, _undo = activation.install_launcher(
        path, tmp_path / "ori", "user"
    )
    assert installed is True
    assert conflict == ""
    assert launcher.is_managed(path, tmp_path / "ori")


def test_a_launcher_conflict_is_reported_not_fatal(tmp_path: Path) -> None:
    """The runtime is what was asked for; the command is a convenience."""
    path = tmp_path / "bin" / "ori"
    path.parent.mkdir(parents=True)
    path.write_text("#!/bin/sh\n# the operator's own\n")
    before = path.read_bytes()

    installed, conflict, _undo = activation.install_launcher(
        path, tmp_path / "ori", "user"
    )
    assert installed is False
    assert "not a launcher this installer wrote" in conflict
    assert path.read_bytes() == before


def test_next_step_does_not_promise_a_command_that_was_not_installed() -> None:
    outcome = activation.ActivationOutcome(
        launcher_path=Path("/usr/local/bin/ori"),
        launcher_installed=False,
        launcher_conflict="something is already there.",
        path_guidance="",
        checks=[],
    )
    step = activation.next_step(outcome)
    assert "was not installed" in step
    assert "Run `ori doctor`" not in step


def test_next_step_gives_the_export_line_when_path_is_missing() -> None:
    outcome = activation.ActivationOutcome(
        launcher_path=Path("/home/a/.local/bin/ori"),
        launcher_installed=True,
        launcher_conflict="",
        path_guidance='export PATH="/home/a/.local/bin:$PATH"',
        checks=[],
    )
    assert 'export PATH="/home/a/.local/bin:$PATH"' in activation.next_step(outcome)


def test_next_step_names_the_command_only_when_it_will_resolve() -> None:
    outcome = activation.ActivationOutcome(
        launcher_path=Path("/usr/local/bin/ori"),
        launcher_installed=True,
        launcher_conflict="",
        path_guidance="",
        checks=[],
    )
    assert activation.next_step(outcome) == (
        "Run `ori doctor` at any time to check this installation."
    )


# --- the report must be verified, not trusted -----------------------------


def test_a_crashed_doctor_cannot_approve_an_installation(tmp_path: Path) -> None:
    """A diagnostics process that failed produced no diagnosis at all."""
    release = _release(tmp_path, exit_code=7)
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert "exited 7" in str(excinfo.value)


def test_a_blocking_diagnosis_is_still_a_diagnosis(tmp_path: Path) -> None:
    """Doctor exits 1 when it finds blocking failures; that report is usable."""
    checks = [c for c in _healthy_checks() if c["name"] != "runtime.health"] + [
        _check("runtime.health", "FAIL", mandatory=True)
    ]
    release = _release(tmp_path, checks, exit_code=1)
    returned = _run(tmp_path, release)
    with pytest.raises(LinuxInstallError) as excinfo:
        activation.assert_usable(returned)
    assert "runtime.health" in str(excinfo.value)


def test_an_unexpected_schema_is_refused(tmp_path: Path) -> None:
    release = _release(
        tmp_path, report=json.dumps({"schema_version": 99, "checks": []})
    )
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert "schema" in str(excinfo.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scope", "system"),
        ("install_root", "/somewhere/else"),
        ("active_release", "/somewhere/else/releases/9.9.9"),
        ("device_id", "not-this-device"),
    ],
)
def test_a_report_about_another_installation_is_refused(
    tmp_path: Path, field: str, value: str
) -> None:
    """Diagnosing the wrong tree must never approve this one."""
    release = tmp_path / "releases" / "2.3.1"
    identity = {
        "scope": "user",
        "install_root": str(tmp_path),
        "active_release": str(release),
        "device_id": DEVICE_ID,
    }
    identity[field] = value
    _release(
        tmp_path,
        report=json.dumps(
            {
                "schema_version": 1,
                "identity": identity,
                "checks": [_check("install.identity", "PASS")],
            }
        ),
    )
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert "different installation" in str(excinfo.value) or "described device" in str(
        excinfo.value
    )


def test_a_report_with_no_identity_is_refused(tmp_path: Path) -> None:
    release = _release(
        tmp_path, report=json.dumps({"schema_version": 1, "checks": [{"x": 1}]})
    )
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert "no installation identity" in str(excinfo.value)


@pytest.mark.parametrize(
    "checks",
    [
        ["malformed"],
        [{"name": "x", "status": "BOGUS"}],
        [{"status": "PASS"}],
        [{"name": "", "status": "PASS"}],
        [{"name": "x", "status": "PASS", "mandatory": "yes"}],
        [],
    ],
)
def test_a_malformed_check_is_never_silently_dropped(
    tmp_path: Path, checks: list[object]
) -> None:
    """A discarded entry could be the very one that was failing."""
    release = tmp_path / "releases" / "2.3.1"
    _release(
        tmp_path,
        report=json.dumps(
            {
                "schema_version": 1,
                "identity": {
                    "scope": "user",
                    "install_root": str(tmp_path),
                    "active_release": str(release),
                    "device_id": DEVICE_ID,
                },
                "checks": checks,
            }
        ),
    )
    with pytest.raises(LinuxInstallError):
        _run(tmp_path, release)


def test_the_reproduced_fail_open_case_is_closed(tmp_path: Path) -> None:
    """Exactly the report that previously passed: bad exit code, junk checks."""
    release = _release(
        tmp_path, report=json.dumps({"checks": ["malformed"]}), exit_code=7
    )
    with pytest.raises(LinuxInstallError):
        _run(tmp_path, release)


# --- launcher lifecycle ---------------------------------------------------


def test_the_launcher_is_removed_on_uninstall(tmp_path: Path) -> None:
    path = tmp_path / "bin" / "ori"
    activation.install_launcher(path, tmp_path / "ori", "user")
    removed = activation.remove_launcher(path, tmp_path / "ori")
    assert removed is True
    assert not path.exists()


def test_uninstall_leaves_an_operator_owned_command_alone(tmp_path: Path) -> None:
    path = tmp_path / "bin" / "ori"
    path.parent.mkdir(parents=True)
    path.write_text("#!/bin/sh\n# the operator's own\n")
    before = path.read_bytes()
    removed = activation.remove_launcher(path, tmp_path / "ori")
    assert removed is False
    assert path.read_bytes() == before


def test_removing_an_absent_launcher_is_not_an_error(tmp_path: Path) -> None:
    removed = activation.remove_launcher(tmp_path / "nothing", tmp_path / "ori")
    assert removed is False


# --- rollback must restore, not merely remove -----------------------------


def test_a_fresh_install_rollback_removes_the_launcher(tmp_path: Path) -> None:
    path = tmp_path / "bin" / "ori"
    installed, _conflict, undo = activation.install_launcher(
        path, tmp_path / "ori", "user"
    )
    assert installed is True
    undo()
    assert not path.exists()


def test_an_upgrade_rollback_restores_the_previous_launcher(tmp_path: Path) -> None:
    """Rolling back to the old release must not delete the command that runs it."""
    path = tmp_path / "bin" / "ori"
    root = tmp_path / "ori"
    launcher.install(path, root, "user")
    before = path.read_bytes()
    before_mode = path.stat().st_mode

    # A later release writes a different launcher body over the working one.
    body, guard = launcher._TEMPLATES[1]
    newer = body.replace(
        'exec "$ORI_ENTRY_POINT" "$@"',
        '# 2.3.2\nexec "$ORI_ENTRY_POINT" "$@"',
    )
    launcher._TEMPLATES[2] = (newer, guard)
    previous_version = launcher.SCHEMA_VERSION
    launcher.SCHEMA_VERSION = 2
    try:
        installed, _conflict, undo = activation.install_launcher(path, root, "user")
        assert installed is True
        assert path.read_bytes() != before  # the upgrade really replaced it
        undo()
    finally:
        launcher.SCHEMA_VERSION = previous_version
        del launcher._TEMPLATES[2]

    assert path.read_bytes() == before
    assert path.stat().st_mode == before_mode
    assert launcher.is_managed(path, root)


def test_a_conflicting_path_rolls_back_to_nothing(tmp_path: Path) -> None:
    """Nothing was written, so undoing must not touch the operator's file."""
    path = tmp_path / "bin" / "ori"
    path.parent.mkdir(parents=True)
    path.write_text("#!/bin/sh\n# the operator's own\n")
    before = path.read_bytes()

    installed, conflict, undo = activation.install_launcher(
        path, tmp_path / "ori", "user"
    )
    assert installed is False
    assert conflict
    undo()
    assert path.read_bytes() == before


# --- the report must be complete ------------------------------------------


def test_a_report_that_omits_the_device_is_refused(tmp_path: Path) -> None:
    """Not saying which device was diagnosed cannot show it was this one."""
    release = tmp_path / "releases" / "2.3.1"
    _release(
        tmp_path,
        report=json.dumps(
            {
                "schema_version": 1,
                "identity": {
                    "scope": "user",
                    "install_root": str(tmp_path),
                    "active_release": str(release),
                },
                "checks": [_check("runtime.health", "FAIL")],
            }
        ),
        exit_code=1,
    )
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert "described device None" in str(excinfo.value)


def test_a_check_without_mandatory_is_refused(tmp_path: Path) -> None:
    """`mandatory` decides whether a failure blocks; omitting it dodges that."""
    release = tmp_path / "releases" / "2.3.1"
    _release(
        tmp_path,
        report=_report_with(
            tmp_path,
            release,
            [{"name": "runtime.health", "status": "FAIL", "message": "down"}],
        ),
        exit_code=1,
    )
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert "without a boolean 'mandatory'" in str(excinfo.value)


def test_a_check_without_a_message_is_refused(tmp_path: Path) -> None:
    release = tmp_path / "releases" / "2.3.1"
    _release(
        tmp_path,
        report=_report_with(
            tmp_path,
            release,
            [{"name": "x", "status": "PASS", "mandatory": False}],
        ),
    )
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert "without a message" in str(excinfo.value)


def test_exit_zero_while_reporting_a_blocking_failure_is_refused(
    tmp_path: Path,
) -> None:
    checks = [c for c in _healthy_checks() if c["name"] != "runtime.health"] + [
        _check("runtime.health", "FAIL", mandatory=True)
    ]
    release = _release(tmp_path, checks, exit_code=0)
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert "exited 0 while reporting" in str(excinfo.value)


def test_exit_one_without_a_blocking_failure_is_refused(tmp_path: Path) -> None:
    release = _release(tmp_path, _healthy_checks(), exit_code=1)
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert "exited 1 without reporting" in str(excinfo.value)


def test_the_second_reproduced_fail_open_case_is_closed(tmp_path: Path) -> None:
    """The exact report that was previously accepted at exit 1."""
    release = tmp_path / "releases" / "2.3.1"
    _release(
        tmp_path,
        report=json.dumps(
            {
                "schema_version": 1,
                "identity": {
                    "scope": "user",
                    "install_root": str(tmp_path),
                    "active_release": str(release),
                },
                "checks": [{"name": "runtime.health", "status": "FAIL"}],
            }
        ),
        exit_code=1,
    )
    with pytest.raises(LinuxInstallError):
        _run(tmp_path, release)


# --- the diagnosis must be complete, not merely well formed ---------------


def test_a_report_that_checked_almost_nothing_is_refused(tmp_path: Path) -> None:
    """Validating each supplied entry cannot see the entries never supplied.

    This payload is individually valid in every respect and exits 0, but it
    never looked at the config, the runtime, the service, or permissions.
    """
    release = tmp_path / "releases" / "2.3.1"
    _release(
        tmp_path,
        report=_report_with(
            tmp_path,
            release,
            [
                {
                    "name": "install.identity",
                    "status": "PASS",
                    "message": "looks installed",
                    "mandatory": False,
                }
            ],
        ),
        exit_code=0,
    )
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert "returned no result for" in str(excinfo.value)


@pytest.mark.parametrize(
    "omitted",
    [
        "config.valid",
        "service.active",
        "service.boot_persistence",
        "runtime.health",
        "runtime.identity",
        "permissions.code",
    ],
)
def test_an_approving_report_may_not_omit_any_area(
    tmp_path: Path, omitted: str
) -> None:
    """Silence about an area is not a pass for it."""
    release = tmp_path / "releases" / "2.3.1"
    checks = [c for c in _healthy_checks() if c["name"] != omitted]
    _release(tmp_path, report=_report_with(tmp_path, release, checks), exit_code=0)
    with pytest.raises(LinuxInstallError) as excinfo:
        _run(tmp_path, release)
    assert omitted in str(excinfo.value) or "no result for" in str(excinfo.value)


def test_a_conditional_category_accepts_any_of_its_outcomes(
    tmp_path: Path,
) -> None:
    """An unreadable config never reaches validation, and that is a real report."""
    release = tmp_path / "releases" / "2.3.1"
    checks = [c for c in _healthy_checks() if c["name"] != "config.valid"] + [
        _check("config.readable", "FAIL", mandatory=True)
    ]
    _release(tmp_path, report=_report_with(tmp_path, release, checks), exit_code=1)
    returned = _run(tmp_path, release)  # accepted as a complete diagnosis
    with pytest.raises(LinuxInstallError):
        activation.assert_usable(returned)  # and it blocks, as it should


def test_a_complete_healthy_report_is_accepted(tmp_path: Path) -> None:
    release = _release(tmp_path)
    returned = _run(tmp_path, release)
    activation.assert_usable(returned)
    assert {str(c["name"]) for c in returned} >= set(
        activation._REQUIRED_WHEN_APPROVING
    )


def test_every_required_check_is_one_the_doctor_actually_emits() -> None:
    """Guards against requiring a name doctor never produces, which would make
    every real installation unusable rather than every fake report detectable."""
    source = (Path(__file__).resolve().parent.parent / "ori" / "doctor.py").read_text()
    required = set(activation._REQUIRED_WHEN_APPROVING)
    for group in activation._REQUIRED_CATEGORIES:
        required.update(group)
    for name in sorted(required):
        assert f'"{name}"' in source, f"doctor never emits {name!r}"


def test_a_real_doctor_run_satisfies_the_activation_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The completeness rule must describe what doctor actually produces.

    A grep for the literals proves only that the names exist somewhere. This
    drives the real `run_doctor` over a healthy layout and feeds its output
    through the same boundary an installation passes, so a requirement that
    doctor never satisfies would make every install fail rather than every
    forged report fail.
    """
    from ori import doctor

    if os.geteuid() == 0:
        # The tree would be root-owned, and doctor would correctly report that
        # the service can rewrite its own code. A healthy user-scope install
        # cannot be modelled by root, so there is nothing honest to assert.
        pytest.skip("a root-owned tree cannot model a healthy user-scope install")
    # A user-scope release is refused execution as root, correctly, so pin a
    # non-root uid rather than have a root CI container fail this.
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    release = tmp_path / "releases" / "2.3.1"
    (release / "venv" / "bin").mkdir(parents=True)
    interpreter = release / "venv" / "bin" / "python"
    interpreter.write_text("#!/bin/sh\n")
    interpreter.chmod(0o555)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "ori.yaml").write_text(f"device:\n  id: {DEVICE_ID}\n")
    for entry in sorted(release.rglob("*"), reverse=True):
        if not entry.is_symlink():
            executable = entry.is_dir() or entry.stat().st_mode & 0o100
            entry.chmod(0o555 if executable else 0o444)
    release.chmod(0o555)

    health = {
        "result": {
            "health": {
                "device_id": DEVICE_ID,
                "uptime_s": 10,
                "critical": False,
                "degradation_reasons": [],
                "capability_posture": {"sms_available": True},
            }
        }
    }

    def runner(command: object) -> subprocess.CompletedProcess[str]:
        argv = list(command)  # type: ignore[call-overload]
        joined = " ".join(argv)
        output = ""
        if "is-active" in argv:
            output = "active"
        elif "is-enabled" in argv:
            output = "enabled"
        elif "Linger" in joined:
            output = "yes"
        elif "health" in argv:
            output = json.dumps(health)
        return subprocess.CompletedProcess(argv, 0, output, "")

    identity = doctor.InstallIdentity(
        scope="user",
        version="2.3.1",
        install_root=tmp_path,
        active_release=release,
        config_path=tmp_path / "data" / "ori.yaml",
        data_path=tmp_path / "data",
        health_socket=tmp_path / "data" / "health.sock",
        unit_path=tmp_path / "unit",
        service_user=None,
    )
    checks = doctor.run_doctor(identity, DEVICE_ID, runner=runner)
    report = [
        {
            "name": c.name,
            "status": c.status,
            "message": c.message,
            "mandatory": c.mandatory,
        }
        for c in checks
    ]

    activation._validated_checks(report)
    activation._assert_complete(report)
    activation._assert_status_agrees(0, report)
    activation.assert_usable(report)
