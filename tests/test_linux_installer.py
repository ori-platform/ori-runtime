# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest

from ori.installer.linux import (
    InstallLayout,
    LinuxInstallError,
    OfflineReleasePreparer,
    SystemdServiceProfile,
    apply_system_service_permissions,
    install_release,
    render_systemd_unit,
    uninstall_runtime,
)
from ori.security.release_bundles import ExtractedReleaseBundle


def _prepare(path: Path) -> None:
    (path / "venv").mkdir()
    (path / "venv" / "installed.txt").write_text("ok", encoding="utf-8")


def _validate(path: Path) -> None:
    assert (path / "venv" / "installed.txt").read_text(encoding="utf-8") == "ok"


def test_first_install_activates_only_after_prepare_and_validate(
    tmp_path: Path,
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    result = install_release(
        layout=layout,
        version="2.3.0",
        prepare=_prepare,
        validate=_validate,
        restart_service=lambda: None,
        stop_service=lambda: None,
        check_health=lambda _path: None,
    )
    assert result.changed is True
    assert layout.current.resolve() == layout.release("2.3.0")


def test_release_is_revalidated_after_staging_move(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    validated: list[str] = []

    def validate(path: Path) -> None:
        validated.append(path.name)
        _validate(path)

    install_release(
        layout=layout,
        version="2.3.0",
        prepare=_prepare,
        validate=validate,
        restart_service=lambda: None,
        stop_service=lambda: None,
        check_health=lambda _path: None,
    )
    assert validated[0].endswith(".staging")
    assert validated[1] == "2.3.0"


def test_failed_post_move_validation_removes_unusable_release(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")

    def validate(path: Path) -> None:
        _validate(path)
        if not path.name.endswith(".staging"):
            raise RuntimeError("relocated release is unusable")

    with pytest.raises(RuntimeError, match="relocated release is unusable"):
        install_release(
            layout=layout,
            version="2.3.0",
            prepare=_prepare,
            validate=validate,
            restart_service=lambda: None,
            stop_service=lambda: None,
            check_health=lambda _path: None,
        )

    assert not layout.release("2.3.0").exists()
    assert list(layout.releases.iterdir()) == []
    assert not layout.current.exists()


def test_failed_upgrade_restores_healthy_previous_release(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    install_release(
        layout=layout,
        version="2.3.0",
        prepare=_prepare,
        validate=_validate,
        restart_service=lambda: None,
        stop_service=lambda: None,
        check_health=lambda _path: None,
    )
    restarts = 0

    def restart() -> None:
        nonlocal restarts
        restarts += 1

    def health(path: Path) -> None:
        if path.name == "2.4.0":
            raise RuntimeError("critical health")

    with pytest.raises(LinuxInstallError) as exc:
        install_release(
            layout=layout,
            version="2.4.0",
            prepare=_prepare,
            validate=_validate,
            restart_service=restart,
            stop_service=lambda: None,
            check_health=health,
        )
    assert exc.value.code == "post_install_health_failed"
    assert layout.current.resolve() == layout.release("2.3.0")
    assert not layout.release("2.4.0").exists()
    assert restarts == 2


def test_rollback_failure_has_distinct_error(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    install_release(
        layout=layout,
        version="2.3.0",
        prepare=_prepare,
        validate=_validate,
        restart_service=lambda: None,
        stop_service=lambda: None,
        check_health=lambda _path: None,
    )

    with pytest.raises(LinuxInstallError) as exc:
        install_release(
            layout=layout,
            version="2.4.0",
            prepare=_prepare,
            validate=_validate,
            restart_service=lambda: None,
            stop_service=lambda: None,
            check_health=lambda _path: (_ for _ in ()).throw(RuntimeError("unhealthy")),
        )
    assert exc.value.code == "rollback_failed"


def test_same_version_is_idempotent_and_downgrade_requires_opt_in(
    tmp_path: Path,
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    kwargs = dict(
        layout=layout,
        prepare=_prepare,
        validate=_validate,
        restart_service=lambda: None,
        stop_service=lambda: None,
        check_health=lambda _path: None,
    )
    install_release(version="2.4.0", **kwargs)
    assert install_release(version="2.4.0", **kwargs).changed is False
    with pytest.raises(LinuxInstallError, match="downgrade_forbidden"):
        install_release(version="2.3.0", **kwargs)
    install_release(version="2.3.0", allow_downgrade=True, **kwargs)
    assert layout.current.resolve() == layout.release("2.3.0")


def test_uninstall_retains_data_unless_explicitly_removed(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    install_release(
        layout=layout,
        version="2.3.0",
        prepare=_prepare,
        validate=_validate,
        restart_service=lambda: None,
        stop_service=lambda: None,
        check_health=lambda _path: None,
    )
    (layout.data / "ori.yaml").write_text("operator data", encoding="utf-8")
    uninstall_runtime(layout=layout, stop_service=lambda: None)
    assert not layout.releases.exists()
    assert (layout.data / "ori.yaml").exists()
    uninstall_runtime(layout=layout, stop_service=lambda: None, remove_data=True)
    assert not layout.data.exists()


@pytest.mark.parametrize("root", ["relative", "/"])
def test_unsafe_install_roots_are_rejected(root: str) -> None:
    with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
        InstallLayout.resolve(root)


def test_noncanonical_version_is_rejected_with_stable_error(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    with pytest.raises(LinuxInstallError) as exc:
        layout.release("2.3.0candidate")
    assert exc.value.code == "invalid_release_version"


def test_prerelease_numeric_identifiers_use_semver_ordering(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    kwargs = dict(
        layout=layout,
        prepare=_prepare,
        validate=_validate,
        restart_service=lambda: None,
        stop_service=lambda: None,
        check_health=lambda _path: None,
    )
    install_release(version="2.3.0-rc.2", **kwargs)
    install_release(version="2.3.0-rc.10", **kwargs)
    with pytest.raises(LinuxInstallError, match="downgrade_forbidden"):
        install_release(version="2.3.0-rc.2", **kwargs)
    install_release(version="2.3.0", **kwargs)


def test_first_install_failure_removes_active_pointer_and_stops_service(
    tmp_path: Path,
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    stopped = 0

    def stop() -> None:
        nonlocal stopped
        stopped += 1

    with pytest.raises(LinuxInstallError) as exc:
        install_release(
            layout=layout,
            version="2.3.0",
            prepare=_prepare,
            validate=_validate,
            restart_service=lambda: None,
            stop_service=stop,
            check_health=lambda _path: (_ for _ in ()).throw(RuntimeError("unhealthy")),
        )
    assert exc.value.code == "post_install_health_failed"
    assert not layout.current.exists()
    assert stopped == 1


def test_releases_symlink_is_rejected(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    outside = tmp_path / "outside"
    outside.mkdir()
    layout.root.mkdir()
    layout.releases.symlink_to(outside, target_is_directory=True)
    with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
        install_release(
            layout=layout,
            version="2.3.0",
            prepare=_prepare,
            validate=_validate,
            restart_service=lambda: None,
            stop_service=lambda: None,
            check_health=lambda _path: None,
        )


def test_dangling_managed_current_pointer_is_repaired(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.releases.mkdir(parents=True)
    layout.current.symlink_to(Path("releases") / "2.2.0")
    install_release(
        layout=layout,
        version="2.3.0",
        prepare=_prepare,
        validate=_validate,
        restart_service=lambda: None,
        stop_service=lambda: None,
        check_health=lambda _path: None,
    )
    assert layout.current.resolve() == layout.release("2.3.0")


def test_uninstall_stops_service_before_removing_release(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    release = layout.release("2.3.0")
    release.mkdir(parents=True)
    (release / "installed.txt").write_text("present", encoding="utf-8")
    observed = False

    def stop() -> None:
        nonlocal observed
        observed = (release / "installed.txt").is_file()

    uninstall_runtime(layout=layout, stop_service=stop)
    assert observed is True


def test_offline_preparer_uses_only_verified_wheelhouse_and_exact_version(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    (wheelhouse / "requirements.txt").write_text("locked", encoding="utf-8")
    (wheelhouse / "ori_runtime-2.3.0-py3-none-any.whl").write_bytes(b"wheel")
    bundle = ExtractedReleaseBundle(root, "2.3.0", "linux-x86_64-python3.12", "3.12", 2)
    commands: list[Sequence[str]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if "venv" in command:
            venv = Path(command[-1])
            (venv / "bin").mkdir(parents=True)
            (venv / "bin" / "python").write_text("", encoding="utf-8")
            (venv / "bin" / "ori-runtime").write_text("", encoding="utf-8")
        stdout = "2.3.0\n" if "import importlib.metadata" in command[-1] else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    preparer = OfflineReleasePreparer(
        bundle=bundle, runner=runner, bootstrap_python="python3"
    )
    release = tmp_path / "release"
    release.mkdir()
    preparer.prepare(release)
    preparer.validate(release)
    pip_commands = [command for command in commands if "pip" in command]
    assert all(
        "--no-index" in command and "--find-links" in command
        for command in pip_commands
    )
    assert "--require-hashes" in pip_commands[0]
    assert "--no-deps" in pip_commands[-1]


def test_offline_preparer_rejects_missing_or_ambiguous_runtime_wheel(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    (wheelhouse / "requirements.txt").write_text("locked", encoding="utf-8")
    bundle = ExtractedReleaseBundle(root, "2.3.0", "linux-x86_64-python3.12", "3.12", 1)
    preparer = OfflineReleasePreparer(bundle=bundle)
    with pytest.raises(LinuxInstallError, match="offline_install_failed"):
        preparer.prepare(tmp_path / "release")


def test_user_systemd_unit_uses_user_target_without_user_directive(
    tmp_path: Path,
) -> None:
    rendered = render_systemd_unit(
        _service_template(),
        profile=SystemdServiceProfile.user(),
        root=(tmp_path / "root").resolve(),
        data_dir=(tmp_path / "data").resolve(),
        config_path=(tmp_path / "config.yaml").resolve(),
        env_file=(tmp_path / "runtime.env").resolve(),
    )
    assert "WantedBy=default.target" in rendered
    assert "User=" not in rendered
    assert "@ORI_" not in rendered


def test_system_systemd_unit_uses_unprivileged_user_and_system_target(
    tmp_path: Path,
) -> None:
    rendered = render_systemd_unit(
        _service_template(),
        profile=SystemdServiceProfile.system("ori-runtime"),
        root=(tmp_path / "root").resolve(),
        data_dir=(tmp_path / "data").resolve(),
        config_path=(tmp_path / "config.yaml").resolve(),
        env_file=(tmp_path / "runtime.env").resolve(),
    )
    assert "User=ori-runtime" in rendered
    assert "WantedBy=multi-user.target" in rendered
    assert "@ORI_" not in rendered


@pytest.mark.parametrize("service_user", ["root", "0", "Bad User", "ori;root"])
def test_system_systemd_profile_rejects_unsafe_identity(service_user: str) -> None:
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        SystemdServiceProfile.system(service_user)


@pytest.mark.parametrize(
    ("scope", "service_user"),
    [("user", "ori-runtime"), ("system", None), ("invalid", None)],
)
def test_systemd_profile_direct_construction_cannot_bypass_invariants(
    scope: str, service_user: str | None
) -> None:
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        SystemdServiceProfile(scope=scope, service_user=service_user)  # type: ignore[arg-type]


def test_systemd_renderer_rejects_relative_paths_and_template_drift(
    tmp_path: Path,
) -> None:
    kwargs = {
        "profile": SystemdServiceProfile.user(),
        "root": (tmp_path / "root").resolve(),
        "data_dir": (tmp_path / "data").resolve(),
        "config_path": (tmp_path / "config.yaml").resolve(),
        "env_file": (tmp_path / "runtime.env").resolve(),
    }
    with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
        render_systemd_unit(_service_template(), **{**kwargs, "root": Path("relative")})
    with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
        render_systemd_unit(
            _service_template(), **{**kwargs, "root": Path("/opt/ori bad")}
        )
    with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
        render_systemd_unit(
            _service_template(), **{**kwargs, "root": Path("/opt/ori%n")}
        )
    with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
        render_systemd_unit(
            _service_template(),
            **{**kwargs, "root": Path("/opt/@ORI_USER_DIRECTIVE@")},
        )
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        render_systemd_unit(
            _service_template().replace("@ORI_CONFIG@", "/fixed"), **kwargs
        )
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        render_systemd_unit(_service_template() + "\n@UNKNOWN_MARKER@\n", **kwargs)


def _service_template() -> str:
    return Path("packaging/systemd/ori-runtime.service.in").read_text(encoding="utf-8")


def test_system_permissions_keep_code_root_owned_and_data_service_owned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    executable = layout.release("2.3.0") / "venv" / "bin" / "python"
    regular = layout.release("2.3.0") / "ori" / "runtime.py"
    state = layout.data / "ori.db"
    executable.parent.mkdir(parents=True)
    regular.parent.mkdir(parents=True)
    layout.data.mkdir()
    executable.write_bytes(b"python")
    executable.chmod(0o700)
    regular.write_bytes(b"runtime")
    state.write_bytes(b"state")
    inode_paths = {
        path.stat().st_ino: path for path in [layout.root, *layout.root.rglob("*")]
    }
    ownership: dict[Path, tuple[int, int]] = {}
    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
    )
    monkeypatch.setattr(
        "ori.installer.linux.os.fchown",
        lambda descriptor, uid, gid: ownership.__setitem__(
            inode_paths[os.fstat(descriptor).st_ino], (uid, gid)
        ),
    )

    apply_system_service_permissions(layout, SystemdServiceProfile.system("ori"))

    assert ownership[layout.root] == (0, 1002)
    assert ownership[regular] == (0, 1002)
    assert regular.stat().st_mode & 0o777 == 0o440
    assert executable.stat().st_mode & 0o777 == 0o550
    assert ownership[layout.data] == (1001, 1002)
    assert ownership[state] == (1001, 1002)
    assert state.stat().st_mode & 0o777 == 0o600


def test_system_permissions_fail_closed_for_non_root_and_data_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.releases.mkdir(parents=True)
    layout.data.mkdir()
    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 501)
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        apply_system_service_permissions(layout, SystemdServiceProfile.system("ori"))

    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
    )
    monkeypatch.setattr("ori.installer.linux.os.fchown", lambda *_args: None)
    (layout.data / "escape").symlink_to(tmp_path / "outside")
    with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
        apply_system_service_permissions(layout, SystemdServiceProfile.system("ori"))
    assert layout.root.stat().st_mode & 0o777 == 0o755


def test_system_upgrade_preserves_access_and_reapplies_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    destination = layout.release("2.3.0")
    destination.mkdir(parents=True)
    _prepare(destination)
    layout.data.mkdir()
    layout.root.chmod(0o750)
    layout.releases.chmod(0o750)
    observed_modes: list[tuple[int, int]] = []

    def apply_permissions(
        applied_layout: InstallLayout, _profile: SystemdServiceProfile
    ) -> None:
        observed_modes.append(
            (
                applied_layout.root.stat().st_mode & 0o777,
                applied_layout.releases.stat().st_mode & 0o777,
            )
        )

    monkeypatch.setattr(
        "ori.installer.linux.apply_system_service_permissions", apply_permissions
    )
    install_release(
        layout=layout,
        version="2.3.0",
        prepare=_prepare,
        validate=_validate,
        restart_service=lambda: None,
        stop_service=lambda: None,
        check_health=lambda _path: None,
        service_profile=SystemdServiceProfile.system("ori"),
    )
    assert observed_modes == [(0o750, 0o750)]


def test_permission_failure_is_stable_and_restores_current_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.releases.mkdir(parents=True)
    layout.data.mkdir()
    original = layout.root.stat()
    ownership_calls: list[tuple[int, int]] = []
    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
    )
    monkeypatch.setattr(
        "ori.installer.linux.os.fchown",
        lambda _descriptor, uid, gid: ownership_calls.append((uid, gid)),
    )
    monkeypatch.setattr(
        "ori.installer.linux.os.fchmod",
        lambda *_args: (_ for _ in ()).throw(NotImplementedError("old glibc")),
    )
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        apply_system_service_permissions(layout, SystemdServiceProfile.system("ori"))
    assert ownership_calls == [(0, 1002), (original.st_uid, original.st_gid)]


def test_system_permissions_accept_internal_venv_directory_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    release = layout.release("2.3.0")
    library = release / "lib"
    binary = release / "bin"
    library.mkdir(parents=True)
    binary.mkdir()
    (release / "lib64").symlink_to("lib", target_is_directory=True)
    interpreter = binary / "python3"
    interpreter.write_bytes(b"python")
    interpreter.chmod(0o700)
    (binary / "python").symlink_to("python3")
    layout.data.mkdir()
    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
    )
    monkeypatch.setattr("ori.installer.linux.os.fchown", lambda *_args: None)

    apply_system_service_permissions(layout, SystemdServiceProfile.system("ori"))

    assert (release / "lib64").resolve() == library
    assert (binary / "python").resolve() == interpreter
    assert interpreter.stat().st_mode & 0o777 == 0o550


def test_system_permissions_reject_escaping_release_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    release = layout.release("2.3.0")
    release.mkdir(parents=True)
    layout.data.mkdir()
    outside_directory = tmp_path / "outside"
    outside_directory.mkdir()
    (release / "lib64").symlink_to(outside_directory, target_is_directory=True)
    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
    )
    monkeypatch.setattr("ori.installer.linux.os.fchown", lambda *_args: None)

    with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
        apply_system_service_permissions(layout, SystemdServiceProfile.system("ori"))

    (release / "lib64").unlink()
    external_python = tmp_path / "python"
    external_python.write_bytes(b"python")
    external_python.chmod(0o755)
    (release / "python").symlink_to(external_python)
    with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
        apply_system_service_permissions(layout, SystemdServiceProfile.system("ori"))


def test_permission_failure_removes_new_release_before_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    monkeypatch.setattr(
        "ori.installer.linux.apply_system_service_permissions",
        lambda *_args: (_ for _ in ()).throw(
            LinuxInstallError("unsafe_install_root", "permission failure")
        ),
    )
    with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
        install_release(
            layout=layout,
            version="2.3.0",
            prepare=_prepare,
            validate=_validate,
            restart_service=lambda: None,
            stop_service=lambda: None,
            check_health=lambda _path: None,
            service_profile=SystemdServiceProfile.system("ori"),
        )
    assert not layout.release("2.3.0").exists()
    assert not layout.current.exists()
