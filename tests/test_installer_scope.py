# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Scope selection, privilege boundaries, and installation path resolution."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ori.installer import paths, scope_prompt
from ori.installer.linux import LinuxInstallError


def _make_install(root: Path, version: str = "2.3.1") -> Path:
    release = root / "releases" / version
    (release / "venv" / "bin").mkdir(parents=True)
    (root / "data").mkdir(parents=True, exist_ok=True)
    (root / "current").symlink_to(release)
    return release


class _Prompt:
    """A scripted operator."""

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.shown: list[str] = []

    def __call__(self, message: str) -> str:
        self.shown.append(message)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


@pytest.fixture
def tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)


# --- scope decision -------------------------------------------------------


def test_supplied_scope_is_not_second_guessed() -> None:
    for scope in ("user", "system"):
        assert (
            scope_prompt.choose_scope(
                supplied=scope, unattended=False, write=lambda _: None
            )
            == scope
        )


def test_unattended_without_scope_fails_before_any_mutation() -> None:
    with pytest.raises(LinuxInstallError) as excinfo:
        scope_prompt.choose_scope(supplied=None, unattended=True, write=lambda _: None)
    assert excinfo.value.code == "config_validation_failed"
    assert "--scope" in str(excinfo.value)


def test_non_interactive_stdin_never_invents_a_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No terminal means no submitted answer, so the shown default must not apply."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(LinuxInstallError) as excinfo:
        scope_prompt.choose_scope(supplied=None, unattended=False, write=lambda _: None)
    assert excinfo.value.code == "config_validation_failed"


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ("1", "system"),
        ("2", "user"),
        ("system", "system"),
        ("user", "user"),
        ("", "system"),
    ],
)
def test_submitted_answers(tty: None, answer: str, expected: str) -> None:
    prompt = _Prompt(answer)
    assert (
        scope_prompt.choose_scope(
            supplied=None, unattended=False, prompt=prompt, write=lambda _: None
        )
        == expected
    )


def test_prompt_states_both_consequences(tty: None) -> None:
    written: list[str] = []
    scope_prompt.choose_scope(
        supplied=None, unattended=False, prompt=_Prompt("1"), write=written.append
    )
    shown = "\n".join(written)
    assert "Requires administrator privileges." in shown
    assert "Does not start at boot without lingering." in shown
    assert "ori-runtime" in shown


def test_invalid_answer_reprompts_then_gives_up(tty: None) -> None:
    prompt = _Prompt("maybe", "3", "yes")
    with pytest.raises(LinuxInstallError) as excinfo:
        scope_prompt.choose_scope(
            supplied=None, unattended=False, prompt=prompt, write=lambda _: None
        )
    assert "3 attempts" in str(excinfo.value)
    assert len(prompt.shown) == 3


def test_cancelling_the_prompt_is_not_a_choice(tty: None) -> None:
    with pytest.raises(LinuxInstallError) as excinfo:
        scope_prompt.choose_scope(
            supplied=None, unattended=False, prompt=_Prompt(), write=lambda _: None
        )
    assert "cancelled" in str(excinfo.value)


# --- privilege boundary ---------------------------------------------------


def test_system_scope_without_root_refuses_and_never_escalates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    argv = ["ori-install-linux", "install", "--device-id", "pi-01"]
    with pytest.raises(LinuxInstallError) as excinfo:
        scope_prompt.require_privilege("system", argv)
    message = str(excinfo.value)
    assert "sudo ori-install-linux install --device-id pi-01 --scope system" in message


def test_user_scope_as_root_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(LinuxInstallError):
        scope_prompt.require_privilege("user", ["ori-install-linux", "install"])


def test_permitted_combinations_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    scope_prompt.require_privilege("system", ["x"])
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    scope_prompt.require_privilege("user", ["x"])


# --- rerun command --------------------------------------------------------


def test_rerun_replaces_an_existing_scope_without_leaking_its_value() -> None:
    for form in (["--scope", "user"], ["--scope=user"]):
        command = scope_prompt.rerun_command(
            ["ori-install-linux", "install", *form, "--device-id", "pi-01"], "system"
        )
        assert command == "ori-install-linux install --device-id pi-01 --scope system"
        assert "user" not in command


def test_rerun_places_scope_before_a_forwarding_separator() -> None:
    """After `--` the scope belongs to the forwarded program, not this one."""
    command = scope_prompt.rerun_command(
        ["install-linux.sh", "--version", "2.3.1", "--", "--device-id", "pi-01"],
        "system",
    )
    assert command == (
        "install-linux.sh --version 2.3.1 --scope system -- --device-id pi-01"
    )
    assert command.index("--scope") < command.index(" -- ")


def test_rerun_quotes_arguments_for_reuse() -> None:
    command = scope_prompt.rerun_command(
        ["ori-install-linux", "install", "--name", "Site A; rm -rf /"], "system"
    )
    assert "'Site A; rm -rf /'" in command


# --- installation discovery -----------------------------------------------


def test_ambiguous_installations_refuse_to_guess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    user_root = tmp_path / "home" / ".local" / "ori"
    system_root = tmp_path / "opt" / "ori"
    _make_install(user_root)
    _make_install(system_root)
    monkeypatch.setattr(paths, "user_root", lambda: user_root)
    monkeypatch.setattr(paths, "SYSTEM_ROOT", system_root)
    with pytest.raises(paths.AmbiguousScopeError) as excinfo:
        paths.detect_scope()
    assert "--scope" in str(excinfo.value)


@pytest.mark.parametrize("euid", [0, 1000])
def test_scope_detection_never_infers_from_privilege(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, euid: int
) -> None:
    """A root shell inspecting a user installation must still see user scope."""
    user_root = tmp_path / "home" / ".local" / "ori"
    _make_install(user_root)
    monkeypatch.setattr(paths, "user_root", lambda: user_root)
    monkeypatch.setattr(paths, "SYSTEM_ROOT", tmp_path / "absent")
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    monkeypatch.setattr(os, "getuid", lambda: euid)
    assert paths.detect_scope() == "user"


def test_no_installation_is_reported_as_such(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "user_root", lambda: tmp_path / "a")
    monkeypatch.setattr(paths, "SYSTEM_ROOT", tmp_path / "b")
    with pytest.raises(FileNotFoundError):
        paths.detect_scope()


def test_resolve_identity_describes_the_active_release(tmp_path: Path) -> None:
    release = _make_install(tmp_path, version="2.3.1")
    identity, _ = paths.resolve_identity(scope="user", root=tmp_path)
    assert identity.active_release == release.resolve()
    assert identity.version == "2.3.1"
    assert identity.config_path == tmp_path / "data" / "ori.yaml"
    assert identity.service_user is None


def test_current_pointing_outside_the_release_directory_is_refused(
    tmp_path: Path,
) -> None:
    """`current` is only as trustworthy as whoever can write it."""
    root = tmp_path / "ori"
    (root / "releases").mkdir(parents=True)
    (root / "data").mkdir()
    attacker = tmp_path / "elsewhere"
    (attacker / "venv" / "bin").mkdir(parents=True)
    (root / "current").symlink_to(attacker)
    with pytest.raises(paths.UnmanagedReleaseError) as excinfo:
        paths.resolve_identity(scope="user", root=root)
    assert "outside the managed release directory" in str(excinfo.value)


def test_nested_release_target_is_refused(tmp_path: Path) -> None:
    """Only a direct child of releases/ is a release."""
    root = tmp_path / "ori"
    nested = root / "releases" / "2.3.1" / "inner"
    nested.mkdir(parents=True)
    (root / "data").mkdir()
    (root / "current").symlink_to(nested)
    with pytest.raises(paths.UnmanagedReleaseError):
        paths.resolve_identity(scope="user", root=root)


def test_launcher_path_reflects_scope() -> None:
    assert paths.launcher_path("system") == Path("/usr/local/bin/ori")
    assert paths.launcher_path("user") == Path.home() / ".local" / "bin" / "ori"
