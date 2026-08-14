# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The `ori` command, and the launcher that makes it resolvable."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from ori import cli
from ori.installer import launcher

REPO = Path(__file__).resolve().parent.parent


def _console_scripts() -> dict[str, str]:
    with (REPO / "pyproject.toml").open("rb") as handle:
        scripts: dict[str, str] = tomllib.load(handle)["project"]["scripts"]
    return scripts


# --- the command exists and is wired up ----------------------------------


def test_ori_is_a_declared_console_script() -> None:
    assert _console_scripts()["ori"] == "ori.cli:main"


def test_existing_commands_are_kept_for_compatibility() -> None:
    """Specialised entry points stay; `ori` is an addition, not a replacement."""
    declared = _console_scripts()
    for name in (
        "ori-runtime",
        "ori-install-linux",
        "ori-config-install",
        "ori-phone-doctor",
        "ori-firmware-provisioner",
        "ori-inverter-profile-doctor",
    ):
        assert name in declared


@pytest.mark.parametrize(
    "command",
    [
        [],
        ["doctor"],
        ["status"],
        ["config"],
        ["config", "validate"],
        ["install"],
        ["uninstall"],
    ],
)
def test_every_command_has_help(command: list[str]) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ori.cli", *command, "--help"],
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    assert result.returncode == 0
    assert result.stdout.strip()


@pytest.mark.parametrize(
    "command", [["doctor"], ["status"], ["install"], ["uninstall"]]
)
def test_help_explains_scope_and_exit_status(command: list[str]) -> None:
    """Operator-facing help must answer what it acts on and what its result means."""
    result = subprocess.run(
        [sys.executable, "-m", "ori.cli", *command, "--help"],
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    text = result.stdout
    assert "examples:" in text
    assert "exit status:" in text
    assert "scope:" in text
    assert "lingering" in text


def test_help_uses_the_precise_persistence_language() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ori.cli", "doctor", "--help"],
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    assert "after your last session ends" in result.stdout
    assert "logout" not in result.stdout.lower()


def test_version_reports_the_running_release() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ori.cli", "--version"],
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    with (REPO / "pyproject.toml").open("rb") as handle:
        expected = tomllib.load(handle)["project"]["version"]
    assert result.stdout.strip() == f"ori {expected}"


def test_no_command_prints_help_to_stderr_and_exits_unusable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main([]) == cli.EXIT_UNUSABLE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage: ori" in captured.err


def test_config_without_a_subcommand_is_unusable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["config"]) == cli.EXIT_UNUSABLE
    assert "usage: ori config" in capsys.readouterr().err


# --- machine output -------------------------------------------------------


def test_json_mode_keeps_stdout_a_single_valid_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Automation parses stdout, so prose and diagnostics must go to stderr."""
    config = tmp_path / "ori.yaml"
    config.write_text("device:\n  id: pi-01\n")
    monkeypatch.setattr(
        "ori.cli_bridge.run_bridge",
        lambda argv: (0, {"result": {"valid": True}}),
    )
    assert cli.main(["config", "validate", "--path", str(config), "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"result": {"valid": True}}


def test_human_mode_prints_a_summary_not_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "ori.yaml"
    config.write_text("device:\n  id: pi-01\n")
    monkeypatch.setattr(
        "ori.cli_bridge.run_bridge", lambda argv: (0, {"result": {"valid": True}})
    )
    assert cli.main(["config", "validate", "--path", str(config)]) == 0
    out = capsys.readouterr().out
    assert "Config is valid" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_an_invalid_config_reports_the_reason_and_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "ori.cli_bridge.run_bridge",
        lambda argv: (1, {"error": {"detail": "device.id must not be empty"}}),
    )
    assert cli.main(["config", "validate", "--path", "/x/ori.yaml"]) == cli.EXIT_FAILED
    assert "device.id must not be empty" in capsys.readouterr().out


def test_a_missing_installation_is_unusable_not_a_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ori.installer import paths

    monkeypatch.setattr(paths, "user_root", lambda: Path("/nonexistent/user"))
    monkeypatch.setattr(paths, "SYSTEM_ROOT", Path("/nonexistent/system"))
    assert cli.main(["status"]) == cli.EXIT_UNUSABLE
    assert "no installation found" in capsys.readouterr().err


def test_an_ambiguous_installation_demands_a_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ori.installer import paths

    for root in (tmp_path / "user", tmp_path / "system"):
        (root / "releases" / "2.3.1").mkdir(parents=True)
        (root / "current").symlink_to(root / "releases" / "2.3.1")
    monkeypatch.setattr(paths, "user_root", lambda: tmp_path / "user")
    monkeypatch.setattr(paths, "SYSTEM_ROOT", tmp_path / "system")
    assert cli.main(["status"]) == cli.EXIT_UNUSABLE
    assert "--scope" in capsys.readouterr().err


# --- install delegates to the incoming bundle -----------------------------


def test_install_refuses_a_bundle_that_is_not_present(tmp_path: Path) -> None:
    from ori.installer.upgrade import UpgradeError, install_from_bundle

    args = argparse.Namespace(
        bundle=str(tmp_path / "absent.tar.gz"),
        signature=str(tmp_path / "absent.sig"),
        expected_version=None,
        scope="user",
        unattended=True,
        device_id=None,
        name=None,
        location=None,
    )
    with pytest.raises(UpgradeError) as excinfo:
        install_from_bundle(args)
    assert "bundle not found" in str(excinfo.value)


def _fake_installer(path: Path, body: str) -> Path:
    """A stand-in for the ori-install-linux inside a verified bundle."""
    path.write_text("#!/usr/bin/env python3\n" + body)
    path.chmod(0o755)
    return path


_RECORDING_INSTALLER = """
import json, sys
sys.stderr.write("preparing the installation\\n")
json.dump({"schema_version": 1, "ok": True, "argv": sys.argv[1:],\n           "status": "healthy", "version": "2.4.0"}, sys.stdout)
"""

_PROMPTING_INSTALLER = """
import json, sys
# A prompt an operator must be able to see while the process waits.
print("Choose [1]: ", end="", file=sys.stderr, flush=True)
answer = sys.stdin.readline().strip()
json.dump({"schema_version": 1, "ok": True, "status": "healthy",\n           "answer": answer}, sys.stdout)
"""


def _args(**overrides: object) -> argparse.Namespace:
    base = dict(
        bundle="/b.tar.gz",
        signature="/b.sig",
        expected_version=None,
        scope="user",
        unattended=False,
        device_id=None,
        name=None,
        location=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class _Verified:
    runtime_version = "2.3.1"


def test_handoff_always_requests_machine_output(tmp_path: Path) -> None:
    """stdout is the parseable contract regardless of what the operator asked for."""
    from ori.installer.upgrade import _run_installer

    installer = _fake_installer(tmp_path / "ori-install-linux", _RECORDING_INSTALLER)
    payload = _run_installer(
        installer, Path("/b.tar.gz"), Path("/b.sig"), _Verified(), _args()
    )
    assert "--json" in payload["argv"]
    assert payload["argv"][0] == "install"


def test_handoff_forwards_identity_and_scope(tmp_path: Path) -> None:
    from ori.installer.upgrade import _run_installer

    installer = _fake_installer(tmp_path / "ori-install-linux", _RECORDING_INSTALLER)
    payload = _run_installer(
        installer,
        Path("/b.tar.gz"),
        Path("/b.sig"),
        _Verified(),
        _args(scope="system", device_id="pi-01", name="Site A", unattended=True),
    )
    argv = payload["argv"]
    assert argv[argv.index("--scope") + 1] == "system"
    assert argv[argv.index("--device-id") + 1] == "pi-01"
    assert argv[argv.index("--name") + 1] == "Site A"
    assert "--unattended" in argv
    assert argv[argv.index("--expected-version") + 1] == "2.3.1"


def test_an_interactive_prompt_reaches_the_operator(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """A captured prompt is an operator staring at a silent, blocked process."""
    from ori.installer.upgrade import _run_installer

    installer = _fake_installer(tmp_path / "ori-install-linux", _PROMPTING_INSTALLER)
    answers = tmp_path / "answers"
    answers.write_text("2\n")
    with answers.open() as stdin:
        original = os.dup(0)
        os.dup2(stdin.fileno(), 0)
        try:
            payload = _run_installer(
                installer, Path("/b.tar.gz"), Path("/b.sig"), _Verified(), _args()
            )
        finally:
            os.dup2(original, 0)
            os.close(original)

    assert payload["answer"] == "2"  # the operator's answer got through
    assert "Choose [1]:" in capfd.readouterr().err  # and they could see the question


def test_unattended_never_leaves_a_child_waiting_for_input(tmp_path: Path) -> None:
    from ori.installer.upgrade import _run_installer

    installer = _fake_installer(tmp_path / "ori-install-linux", _PROMPTING_INSTALLER)
    payload = _run_installer(
        installer,
        Path("/b.tar.gz"),
        Path("/b.sig"),
        _Verified(),
        _args(unattended=True),
    )
    assert payload["answer"] == ""  # stdin was closed, not left hanging


def test_a_failing_installer_surfaces_its_reason(tmp_path: Path) -> None:
    from ori.installer.upgrade import UpgradeError, _run_installer

    installer = _fake_installer(
        tmp_path / "ori-install-linux",
        "import json,sys\n"
        'json.dump({"error": {"detail": "unsafe_install_root"}}, sys.stdout)\n'
        "sys.exit(1)\n",
    )
    with pytest.raises(UpgradeError) as excinfo:
        _run_installer(
            installer, Path("/b.tar.gz"), Path("/b.sig"), _Verified(), _args()
        )
    assert "unsafe_install_root" in str(excinfo.value)


def test_the_incoming_environment_is_built_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Runtime dependencies come only from the bundle's hash-locked wheelhouse."""
    from ori.installer import upgrade

    bundle_root = tmp_path / "verified"
    (bundle_root / "wheelhouse").mkdir(parents=True)
    (bundle_root / "wheelhouse" / "requirements.txt").write_text("PyYAML==6.0.2\n")
    (bundle_root / "wheelhouse" / "ori_runtime-2.3.1-py3-none-any.whl").write_bytes(b"")

    commands: list[list[str]] = []

    def _record(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        environment = tmp_path / "venv" / "bin"
        environment.mkdir(parents=True, exist_ok=True)
        (environment / "ori-install-linux").write_text("#!/bin/sh\n")
        return subprocess.CompletedProcess(command, 0, "", "")

    # Patch through monkeypatch: `upgrade.subprocess` is the global module, so
    # assigning to it directly would leak into every later test.
    monkeypatch.setattr(subprocess, "run", _record)
    upgrade._build_installer(bundle_root, tmp_path / "venv")

    pip_commands = [c for c in commands if "pip" in c]
    assert pip_commands, "no dependency installation happened"
    for command in pip_commands:
        assert "--no-index" in command
        assert not any(arg.startswith("http") for arg in command)
    assert any("--require-hashes" in c for c in pip_commands)


def test_an_incomplete_wheelhouse_is_refused(tmp_path: Path) -> None:
    from ori.installer.upgrade import UpgradeError, _build_installer

    bundle_root = tmp_path / "verified"
    (bundle_root / "wheelhouse").mkdir(parents=True)
    with pytest.raises(UpgradeError) as excinfo:
        _build_installer(bundle_root, tmp_path / "venv")
    assert "wheelhouse is incomplete" in str(excinfo.value)


# --- the launcher ---------------------------------------------------------


def test_launcher_resolves_the_active_release_at_execution_time(
    tmp_path: Path,
) -> None:
    """An upgrade or rollback must take effect without rewriting the launcher."""
    path = tmp_path / "bin" / "ori"
    launcher.install(path, tmp_path / "ori", "system")
    content = path.read_text()
    assert "current/venv/bin/ori" in content
    assert "releases/" not in content  # no release pinned into the file
    assert content.startswith("#!/bin/sh\n")


def test_launcher_is_executable_and_atomic(tmp_path: Path) -> None:
    path = tmp_path / "bin" / "ori"
    launcher.install(path, tmp_path / "ori", "system")
    assert path.stat().st_mode & 0o111
    assert not list(path.parent.glob(".ori.*.tmp"))  # no staging left behind


def test_reinstalling_over_our_own_launcher_is_allowed(tmp_path: Path) -> None:
    """An upgrade rewrites the launcher for the same installation."""
    path = tmp_path / "bin" / "ori"
    root = tmp_path / "ori"
    launcher.install(path, root, "system")
    launcher.install(path, root, "system")
    assert launcher.is_managed(path, root)
    assert not list(path.parent.glob(".ori.*.tmp"))


@pytest.mark.parametrize(
    ("name", "make"),
    [
        ("an operator's own script", lambda p: p.write_text("#!/bin/sh\necho mine\n")),
        ("a directory", lambda p: p.mkdir()),
        ("a symlink", lambda p: p.symlink_to("/bin/sh")),
        ("a dangling symlink", lambda p: p.symlink_to("/nonexistent")),
        ("an unreadable file", lambda p: (p.write_bytes(b"\xff\xfe"), p.chmod(0o000))),
    ],
)
def test_an_unmanaged_path_is_never_destroyed(
    tmp_path: Path, name: str, make: object
) -> None:
    """os.replace overwrites without asking, so the refusal must come first."""
    path = tmp_path / "bin" / "ori"
    path.parent.mkdir(parents=True)
    make(path)  # type: ignore[operator]
    before = path.read_bytes() if path.is_file() and os.access(path, os.R_OK) else None

    with pytest.raises(launcher.LauncherConflictError) as excinfo:
        launcher.install(path, tmp_path / "ori", "system")

    assert "is not a launcher this installer wrote" in str(excinfo.value)
    assert os.path.lexists(path)
    if before is not None:
        assert path.read_bytes() == before


def test_a_launcher_from_an_older_release_can_be_upgraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A security fix to the launcher body must remain deliverable.

    Identity comes from the metadata lines, so a body written by an earlier
    release is still recognised as ours and replaced.
    """
    path = tmp_path / "bin" / "ori"
    root = tmp_path / "ori"
    launcher.install(path, root, "user")
    installed = path.read_text()
    assert launcher.read_identity(path) == launcher.LauncherIdentity(
        schema=1, install_root=str(root), scope="user"
    )

    # A later release adds a launcher form and keeps the previous one, so
    # launchers written by this release remain recognisable and upgradeable.
    body, guard = launcher._TEMPLATES[1]
    newer = body.replace(
        'exec "$ORI_ENTRY_POINT" "$@"',
        '# a newer, hardened body\nexec "$ORI_ENTRY_POINT" "$@"',
    )
    monkeypatch.setitem(launcher._TEMPLATES, 2, (newer, guard))
    monkeypatch.setattr(launcher, "SCHEMA_VERSION", 2)
    launcher.install(path, root, "user")

    upgraded = path.read_text()
    assert upgraded != installed
    assert "a newer, hardened body" in upgraded
    assert launcher.is_managed(path, root)
    assert not list(path.parent.glob(".ori.*.tmp"))


def test_a_launcher_from_a_newer_release_is_not_downgraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unknown schema was written by something newer; leave it alone."""
    path = tmp_path / "bin" / "ori"
    root = tmp_path / "ori"
    body, guard = launcher._TEMPLATES[1]
    monkeypatch.setitem(launcher._TEMPLATES, 99, (body, guard))
    monkeypatch.setattr(launcher, "SCHEMA_VERSION", 99)
    launcher.install(path, root, "user")
    before = path.read_bytes()

    monkeypatch.delitem(launcher._TEMPLATES, 99)
    monkeypatch.setattr(launcher, "SCHEMA_VERSION", 1)
    assert launcher.is_managed(path, root) is False
    with pytest.raises(launcher.LauncherConflictError) as excinfo:
        launcher.install(path, root, "user")
    assert "newer version of Ori" in str(excinfo.value)
    assert path.read_bytes() == before


def test_a_file_that_merely_mentions_the_marker_is_untouched(
    tmp_path: Path,
) -> None:
    """Identity is declared in full, not inferred from a familiar-looking line."""
    path = tmp_path / "bin" / "ori"
    path.parent.mkdir(parents=True)
    root = tmp_path / "ori"
    path.write_text(
        f"#!/bin/sh\n{launcher.MARKER}\n"
        f"# someone copied this line\nORI_INSTALL_ROOT={root}\necho mine\n"
    )
    before = path.read_bytes()

    assert launcher.read_identity(path) is None
    with pytest.raises(launcher.LauncherConflictError):
        launcher.install(path, root, "user")
    assert path.read_bytes() == before
    removed = launcher.remove(path, root)
    assert removed is False


@pytest.mark.parametrize(
    "body",
    [
        "#!/bin/sh\n# ori-launcher-schema: 1\n# ori-launcher-root: /r\n",
        (
            "#!/bin/sh\n# ori-launcher-schema: one\n# ori-launcher-root: /r\n"
            "# ori-launcher-scope: user\n"
        ),
    ],
)
def test_incomplete_or_malformed_identity_is_not_ours(
    tmp_path: Path, body: str
) -> None:
    path = tmp_path / "ori"
    path.write_text(body if launcher.MARKER in body else f"{launcher.MARKER}\n{body}")
    assert launcher.read_identity(path) is None


def test_a_root_that_would_break_the_metadata_line_is_refused(
    tmp_path: Path,
) -> None:
    for bad in ("with\nnewline", "with\rreturn", "   "):
        with pytest.raises(ValueError):
            launcher.render(Path(bad), "user")


def test_a_forged_launcher_with_perfect_metadata_is_untouched(tmp_path: Path) -> None:
    """Metadata is self-asserted: any script can carry it, so it cannot authorise.

    This file declares everything a genuine launcher declares — marker, schema,
    the exact expected root, and a valid scope — but the body is the operator's.
    """
    root = tmp_path / "ori"
    path = tmp_path / "bin" / "ori"
    path.parent.mkdir(parents=True)
    path.write_text(
        "#!/bin/sh\n"
        f"{launcher.MARKER}\n"
        f"# ori-launcher-schema: {launcher.SCHEMA_VERSION}\n"
        f"# ori-launcher-root: {root}\n"
        "# ori-launcher-scope: user\n"
        "\n"
        "# the operator's own tooling, which happens to carry these lines\n"
        'exec /opt/my-wrapper/ori "$@"\n'
    )
    before = path.read_bytes()

    # It claims a complete, valid identity...
    assert launcher.read_identity(path) == launcher.LauncherIdentity(
        schema=launcher.SCHEMA_VERSION, install_root=str(root), scope="user"
    )
    # ...and is still not ours, because the body is not one we emit.
    assert launcher.matched_form(path, root) is None
    assert launcher.is_managed(path, root) is False

    with pytest.raises(launcher.LauncherConflictError):
        launcher.install(path, root, "user")
    assert path.read_bytes() == before
    removed = launcher.remove(path, root)
    assert removed is False


def test_a_genuine_launcher_with_one_byte_changed_is_untouched(
    tmp_path: Path,
) -> None:
    """A modified body is no longer a form this installer emitted."""
    root = tmp_path / "ori"
    path = tmp_path / "bin" / "ori"
    launcher.install(path, root, "user")
    path.write_text(path.read_text() + "# appended by someone\n")
    before = path.read_bytes()

    assert launcher.matched_form(path, root) is None
    with pytest.raises(launcher.LauncherConflictError):
        launcher.install(path, root, "user")
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("installed", "requested"), [("user", "system"), ("system", "user")]
)
def test_a_scope_transition_is_refused_at_the_same_root(
    tmp_path: Path, installed: str, requested: str
) -> None:
    """The user form carries a root refusal the system form does not.

    Swapping one for the other during an ordinary reinstall would silently
    change the privilege policy of an already-installed command.
    """
    root = tmp_path / "ori"
    path = tmp_path / "bin" / "ori"
    launcher.install(path, root, installed)
    before = path.read_bytes()

    with pytest.raises(launcher.LauncherConflictError) as excinfo:
        launcher.install(path, root, requested)

    message = str(excinfo.value)
    assert "Changing scope is a migration" in message
    assert f"{installed}-scope installation" in message
    assert path.read_bytes() == before
    assert launcher.matched_form(path, root) == launcher.LauncherForm(
        version=launcher.SCHEMA_VERSION, scope=installed
    )


def test_reinstalling_the_same_scope_still_succeeds(tmp_path: Path) -> None:
    root = tmp_path / "ori"
    path = tmp_path / "bin" / "ori"
    launcher.install(path, root, "user")
    launcher.install(path, root, "user")
    form = launcher.matched_form(path, root)
    assert form is not None and form.scope == "user"


def test_a_replaced_user_launcher_keeps_its_root_refusal(tmp_path: Path) -> None:
    """A user launcher must never lose its pre-Python guard through a reinstall."""
    root = tmp_path / "ori"
    path = tmp_path / "bin" / "ori"
    launcher.install(path, root, "user")
    launcher.install(path, root, "user")
    content = path.read_text()
    assert launcher._TRUSTED_ID in content
    assert "refusing to run a user installation as root" in content


def test_another_installations_launcher_is_not_taken_over(tmp_path: Path) -> None:
    path = tmp_path / "bin" / "ori"
    launcher.install(path, tmp_path / "other-root", "system")
    before = path.read_bytes()
    with pytest.raises(launcher.LauncherConflictError) as excinfo:
        launcher.install(path, tmp_path / "ori", "system")
    assert "declares the Ori installation at" in str(excinfo.value)
    assert path.read_bytes() == before


def test_launcher_runs_and_reports_a_missing_release(tmp_path: Path) -> None:
    """The emitted command must actually run, not merely exist."""
    path = tmp_path / "bin" / "ori"
    launcher.install(path, tmp_path / "ori", "system")
    result = subprocess.run([str(path), "doctor"], capture_output=True, text=True)
    assert result.returncode == 69
    assert "no active release" in result.stderr


def test_launcher_execs_the_active_release(tmp_path: Path) -> None:
    root = tmp_path / "ori"
    entry = root / "releases" / "2.3.1" / "venv" / "bin"
    entry.mkdir(parents=True)
    (entry / "ori").write_text('#!/bin/sh\necho "release 2.3.1 ran: $*"\n')
    (entry / "ori").chmod(0o755)
    (root / "current").symlink_to(root / "releases" / "2.3.1")

    path = tmp_path / "bin" / "ori"
    launcher.install(path, root, "system")
    result = subprocess.run([str(path), "doctor"], capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout.strip() == "release 2.3.1 ran: doctor"


def test_launcher_follows_a_rollback_without_being_rewritten(tmp_path: Path) -> None:
    root = tmp_path / "ori"
    for version in ("2.3.0", "2.3.1"):
        entry = root / "releases" / version / "venv" / "bin"
        entry.mkdir(parents=True)
        (entry / "ori").write_text(f'#!/bin/sh\necho "{version}"\n')
        (entry / "ori").chmod(0o755)
    current = root / "current"
    current.symlink_to(root / "releases" / "2.3.1")

    path = tmp_path / "bin" / "ori"
    launcher.install(path, root, "system")
    before = path.read_bytes()
    assert (
        subprocess.run([str(path)], capture_output=True, text=True).stdout.strip()
        == "2.3.1"
    )

    current.unlink()
    current.symlink_to(root / "releases" / "2.3.0")
    assert (
        subprocess.run([str(path)], capture_output=True, text=True).stdout.strip()
        == "2.3.0"
    )
    assert path.read_bytes() == before


def _decoy_release(root: Path, sentinel: Path) -> None:
    """An active release that records the fact it was executed."""
    entry = root / "releases" / "2.3.1" / "venv" / "bin"
    entry.mkdir(parents=True)
    (entry / "ori").write_text(f"#!/bin/sh\ntouch {sentinel}\necho executed\n")
    (entry / "ori").chmod(0o755)
    (root / "current").symlink_to(root / "releases" / "2.3.1")


def _trusted_id_stub(directory: Path, body: str) -> Path:
    """Stand in for /usr/bin/id at an absolute path the guard will trust."""
    directory.mkdir(parents=True, exist_ok=True)
    stub = directory / "id"
    stub.write_text(body)
    stub.chmod(0o755)
    return stub


def _path_with_fake_id(directory: Path) -> dict[str, str]:
    """An environment whose PATH-resolved `id` lies about the current user."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "id").write_text("#!/bin/sh\necho 1000\n")
    (directory / "id").chmod(0o755)
    environment = dict(os.environ)
    environment["PATH"] = f"{directory}:{environment['PATH']}"
    return environment


def test_a_user_launcher_refuses_root_before_reaching_the_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`sudo ori` must be refused by the shell, before any release code runs.

    The Python guard cannot help here: the launcher executes the release's own
    interpreter first, and that interpreter is writable by the account that
    owns the installation.
    """
    root = tmp_path / "ori"
    sentinel = tmp_path / "release-was-executed"
    _decoy_release(root, sentinel)
    stub = _trusted_id_stub(tmp_path / "trusted", "#!/bin/sh\necho 0\n")
    monkeypatch.setattr(launcher, "_TRUSTED_ID", str(stub))

    path = tmp_path / "bin" / "ori"
    launcher.install(path, root, "user")
    result = subprocess.run([str(path), "doctor"], capture_output=True, text=True)

    assert result.returncode == 77
    assert "refusing to run a user installation as root" in result.stderr
    assert not sentinel.exists(), "the release was executed despite the refusal"


def test_a_fake_id_on_path_cannot_influence_the_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The account being constrained also controls PATH, so PATH cannot decide."""
    root = tmp_path / "ori"
    sentinel = tmp_path / "release-was-executed"
    _decoy_release(root, sentinel)
    stub = _trusted_id_stub(tmp_path / "trusted", "#!/bin/sh\necho 0\n")
    monkeypatch.setattr(launcher, "_TRUSTED_ID", str(stub))

    path = tmp_path / "bin" / "ori"
    launcher.install(path, root, "user")
    result = subprocess.run(
        [str(path)],
        capture_output=True,
        text=True,
        env=_path_with_fake_id(tmp_path / "fakebin"),
    )

    assert result.returncode == 77
    assert not sentinel.exists()


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("absent", None),
        ("failing", "#!/bin/sh\nexit 1\n"),
        ("empty output", "#!/bin/sh\necho\n"),
        ("non-numeric", "#!/bin/sh\necho root\n"),
        ("partly numeric", "#!/bin/sh\necho 0abc\n"),
    ],
)
def test_an_untrustworthy_uid_check_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, body: str | None
) -> None:
    """Without a trustworthy answer the launcher refuses rather than guesses."""
    root = tmp_path / "ori"
    sentinel = tmp_path / "release-was-executed"
    _decoy_release(root, sentinel)
    if body is None:
        monkeypatch.setattr(launcher, "_TRUSTED_ID", str(tmp_path / "no-such-id"))
    else:
        stub = _trusted_id_stub(tmp_path / "trusted", body)
        monkeypatch.setattr(launcher, "_TRUSTED_ID", str(stub))

    path = tmp_path / "bin" / "ori"
    launcher.install(path, root, "user")
    result = subprocess.run([str(path)], capture_output=True, text=True)

    assert result.returncode == 77
    assert "cannot verify the current user" in result.stderr
    assert not sentinel.exists()


def test_the_shipped_guard_names_an_absolute_trusted_executable() -> None:
    """The default must not be PATH-resolved, and must not use a helper that is."""
    assert launcher._TRUSTED_ID.startswith("/")
    script = launcher.render(Path("/home/a/.local/ori"), "user")
    assert launcher._TRUSTED_ID in script
    for helper in ("command -v", "$(env ", "which "):
        assert helper not in script


def test_a_user_launcher_runs_normally_for_its_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-root owner reaches the release.

    The uid is stubbed rather than inherited: under a root CI container the
    real `/usr/bin/id` reports 0 and the launcher would refuse, which is the
    correct behaviour but not what this test is about.
    """
    root = tmp_path / "ori"
    sentinel = tmp_path / "release-was-executed"
    _decoy_release(root, sentinel)
    stub = _trusted_id_stub(tmp_path / "trusted", "#!/bin/sh\necho 1000\n")
    monkeypatch.setattr(launcher, "_TRUSTED_ID", str(stub))
    path = tmp_path / "bin" / "ori"
    launcher.install(path, root, "user")

    result = subprocess.run([str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert sentinel.exists()


def test_a_system_launcher_may_be_run_by_root(tmp_path: Path) -> None:
    """Its target is installer-controlled and root-owned, so root is expected."""
    root = tmp_path / "ori"
    sentinel = tmp_path / "release-was-executed"
    _decoy_release(root, sentinel)
    path = tmp_path / "bin" / "ori"
    launcher.install(path, root, "system")

    assert "id -u" not in launcher.render(root, "system")
    result = subprocess.run([str(path)], capture_output=True, text=True)
    assert result.returncode == 0
    assert sentinel.exists()


def test_scope_must_be_stated_to_render_a_launcher(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        launcher.render(tmp_path / "ori", "root")


def test_uninstall_removes_only_launchers_it_wrote(tmp_path: Path) -> None:
    root = tmp_path / "ori"
    ours = tmp_path / "bin" / "ori"
    launcher.install(ours, root, "system")

    theirs = tmp_path / "bin" / "ori-theirs"
    theirs.write_text("#!/bin/sh\n# an operator's own script\n")
    other_install = tmp_path / "bin" / "ori-other"
    launcher.install(other_install, tmp_path / "elsewhere", "system")

    removed_theirs = launcher.remove(theirs, root)
    assert removed_theirs is False
    assert theirs.exists()
    removed_other = launcher.remove(other_install, root)  # different install root
    assert removed_other is False
    assert other_install.exists()
    removed_ours = launcher.remove(ours, root)
    assert removed_ours is True
    assert not ours.exists()


def test_a_symlink_at_the_launcher_path_is_not_ours(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("#!/bin/sh\n")
    link = tmp_path / "ori"
    link.symlink_to(target)
    assert launcher.is_managed(link, tmp_path / "ori-root") is False


def test_path_guidance_gives_the_exact_export_command(tmp_path: Path) -> None:
    path = tmp_path / ".local" / "bin" / "ori"
    guidance = launcher.path_guidance(path, ["/usr/bin", "/bin"])
    assert guidance is not None
    assert f'export PATH="{path.parent}:$PATH"' in guidance
    assert "~/.profile" in guidance


def test_no_path_guidance_when_the_command_will_already_resolve(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bin" / "ori"
    assert launcher.path_guidance(path, [str(path.parent), "/usr/bin"]) is None


def test_path_guidance_reads_the_environment_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One place answers whether a bare `ori` resolves, and it returns the fix."""
    path = tmp_path / "bin" / "ori"
    monkeypatch.setenv("PATH", f"{path.parent}:/usr/bin")
    assert launcher.path_guidance(path) is None
    monkeypatch.setenv("PATH", "/usr/bin")
    guidance = launcher.path_guidance(path)
    assert guidance is not None and str(path.parent) in guidance


def test_launcher_quotes_a_hostile_install_root(tmp_path: Path) -> None:
    """The root is interpolated into a shell script, so it must be quoted."""
    root = tmp_path / "ori; touch /tmp/ori-pwned"
    path = tmp_path / "bin" / "ori"
    launcher.install(path, root, "system")
    result = subprocess.run([str(path)], capture_output=True, text=True)
    assert result.returncode == 69
    assert not Path("/tmp/ori-pwned").exists()
    assert str(root) in result.stderr


def test_launcher_directory_is_created_when_absent(tmp_path: Path) -> None:
    path = tmp_path / "brand" / "new" / "bin" / "ori"
    launcher.install(path, tmp_path / "ori", "system")
    assert path.is_file()
    assert os.access(path, os.X_OK)


def test_doctor_dispatch_passes_parsed_values_straight_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`ori doctor` calls doctor.run directly, with no argv round trip."""
    from ori import doctor

    seen: dict[str, object] = {}

    def _run(
        scope: str | None = None,
        *,
        root: Path | None = None,
        json_mode: bool = False,
    ) -> int:
        seen.update(scope=scope, root=root, json_mode=json_mode)
        return 0

    monkeypatch.setattr(doctor, "run", _run)
    assert (
        cli.main(["doctor", "--scope", "system", "--root", "/opt/ori", "--json"]) == 0
    )
    assert seen == {"scope": "system", "root": Path("/opt/ori"), "json_mode": True}

    seen.clear()
    assert cli.main(["doctor"]) == 0
    assert seen == {"scope": None, "root": None, "json_mode": False}


def test_doctor_dispatch_returns_the_diagnostic_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ori import doctor

    monkeypatch.setattr(doctor, "run", lambda *a, **k: cli.EXIT_FAILED)
    assert cli.main(["doctor"]) == cli.EXIT_FAILED


def test_status_dispatch_reports_service_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`ori status` runs the real service checks and reflects their result."""
    from ori import doctor
    from ori.installer import paths

    root = tmp_path / "ori"
    (root / "releases" / "2.3.1").mkdir(parents=True)
    (root / "data").mkdir()
    (root / "current").symlink_to(root / "releases" / "2.3.1")
    monkeypatch.setattr(paths, "user_root", lambda: root)
    monkeypatch.setattr(paths, "SYSTEM_ROOT", tmp_path / "absent")
    monkeypatch.setattr(
        doctor,
        "check_service",
        lambda identity, runner=None: [
            doctor.DoctorCheck("service.active", "FAIL", "down", mandatory=True)
        ],
    )
    assert cli.main(["status", "--json"]) == cli.EXIT_FAILED
    payload = json.loads(capsys.readouterr().out)
    assert payload["identity"]["scope"] == "user"
    assert payload["service"][0]["status"] == "FAIL"


# --- the handoff must reject a malformed success envelope -----------------


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ('{"ok": true, "status": "healthy"}', "schema"),
        ('{"schema_version": 2, "ok": true, "status": "healthy"}', "schema"),
        ('{"schema_version": "1", "ok": true, "status": "healthy"}', "schema"),
        ('{"schema_version": 1, "status": "healthy"}', "did not report success"),
        (
            '{"schema_version": 1, "ok": false, "status": "healthy"}',
            "did not report success",
        ),
        (
            '{"schema_version": 1, "ok": "yes", "status": "healthy"}',
            "did not report success",
        ),
        ('{"schema_version": 1, "ok": true}', "status"),
        ('{"schema_version": 1, "ok": true, "status": "degraded"}', "status"),
    ],
)
def test_a_malformed_success_envelope_is_rejected(
    tmp_path: Path, payload: str, expected: str
) -> None:
    """Exit 0 with a dictionary is not proof the installation succeeded."""
    from ori.installer.upgrade import UpgradeError, _run_installer

    installer = _fake_installer(
        tmp_path / "ori-install-linux",
        f"import sys\nsys.stdout.write({payload!r})\n",
    )

    class _Verified:
        runtime_version = "2.4.0"

    args = argparse.Namespace(
        scope="user", unattended=True, device_id=None, name=None, location=None
    )
    with pytest.raises(UpgradeError) as excinfo:
        _run_installer(installer, Path("/b.tar.gz"), Path("/b.sig"), _Verified(), args)
    assert expected in str(excinfo.value)


def test_a_valid_success_envelope_is_accepted(tmp_path: Path) -> None:
    from ori.installer.upgrade import _run_installer

    installer = _fake_installer(
        tmp_path / "ori-install-linux",
        'import sys\nsys.stdout.write(\'{"schema_version": 1, "ok": true, '
        '"status": "healthy", "version": "2.4.0"}\')\n',
    )

    class _Verified:
        runtime_version = "2.4.0"

    args = argparse.Namespace(
        scope="user", unattended=True, device_id=None, name=None, location=None
    )
    payload = _run_installer(
        installer, Path("/b.tar.gz"), Path("/b.sig"), _Verified(), args
    )
    assert payload["ok"] is True
    assert payload["version"] == "2.4.0"


def test_ori_install_exposes_the_whole_installer_surface() -> None:
    """A flag the installer accepts but `ori install` drops would look like it
    worked. Derive the expectation from the installer's own parser."""
    from ori.installer.cli import build_parser as installer_parser

    installer_flags = {
        option
        for action in installer_parser()
        ._subparsers._group_actions[0]  # type: ignore[union-attr]
        .choices["install"]
        ._actions
        for option in action.option_strings
        if option.startswith("--")
    }
    ori_flags = {
        option
        for action in cli._build_parser()
        ._subparsers._group_actions[0]  # type: ignore[union-attr]
        .choices["install"]
        ._actions
        for option in action.option_strings
        if option.startswith("--")
    }
    # `ori install` names the bundle by path and re-verifies it; --expected-version
    # is set from the verified bundle rather than accepted from the caller.
    missing = installer_flags - ori_flags - {"--help", "--expected-version"}
    assert not missing, f"ori install does not expose: {sorted(missing)}"


def test_every_exposed_option_is_forwarded(tmp_path: Path) -> None:
    """Exposing a flag and not forwarding it is the same defect, later."""
    from ori.installer.upgrade import _run_installer

    installer = _fake_installer(tmp_path / "ori-install-linux", _RECORDING_INSTALLER)

    class _Verified:
        runtime_version = "2.4.0"

    args = argparse.Namespace(
        scope="system",
        unattended=True,
        device_id="pi-01",
        generate_device_id=True,
        name="Site A",
        location="Lagos",
        deployment_type="server",
        operator_contact="ops@example.com",
        service_user="ori-runtime",
        root="/opt/ori",
        allow_downgrade=True,
    )
    argv = _run_installer(
        installer, Path("/b.tar.gz"), Path("/b.sig"), _Verified(), args
    )["argv"]

    for option, value in (
        ("--scope", "system"),
        ("--device-id", "pi-01"),
        ("--name", "Site A"),
        ("--location", "Lagos"),
        ("--deployment-type", "server"),
        ("--operator-contact", "ops@example.com"),
        ("--service-user", "ori-runtime"),
        ("--root", "/opt/ori"),
    ):
        assert argv[argv.index(option) + 1] == value, f"{option} not forwarded"
    for flag in ("--unattended", "--generate-device-id", "--allow-downgrade"):
        assert flag in argv, f"{flag} not forwarded"
