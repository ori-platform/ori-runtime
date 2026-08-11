# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from ori.installer.linux import (
    InstallLayout,
    LinuxInstallError,
    OfflineReleasePreparer,
    install_release,
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
