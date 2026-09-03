# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json
import os
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
import yaml

from ori.installer import linux as installer_linux
from ori.installer import trusted_paths
from ori.installer.linux import (
    BootPersistence,
    InstallerConfigInput,
    InstallLayout,
    LinuxInstallError,
    OfflineReleasePreparer,
    RuntimeHealthVerifier,
    SystemdServiceManager,
    SystemdServiceProfile,
    apply_system_service_permissions,
    ensure_service_account,
    install_composed_release,
    install_release,
    provision_runtime_config,
    render_systemd_unit,
    uninstall_runtime,
)
from ori.security.release_bundles import ExtractedReleaseBundle


def _short_socket_temp_dir() -> str:
    """Use a portable short path that stays within AF_UNIX sun_path limits."""
    posix_tmp = Path("/tmp")
    return str(posix_tmp if posix_tmp.is_dir() else Path(tempfile.gettempdir()))


def _health_result(
    command: Sequence[str],
    *,
    returncode: int = 0,
    socket_ok: bool = True,
    critical: bool = False,
    device_id: str = "ori-01",
) -> subprocess.CompletedProcess[str]:
    if returncode == 0:
        payload = {
            "schema_version": 1,
            "ok": True,
            "command": "health snapshot",
            "result": {
                "schema_version": 1,
                "ok": socket_ok,
                "health": {"device_id": device_id, "critical": critical},
            },
        }
    else:
        payload = {
            "schema_version": 1,
            "ok": False,
            "command": "health snapshot",
            "error": {"code": "health_socket_unavailable", "detail": "not ready"},
        }
    return subprocess.CompletedProcess(command, returncode, json.dumps(payload), "")


def _declared_entry_points() -> tuple[str, ...]:
    """Read the console scripts from pyproject rather than restating them.

    A hardcoded list silently stops covering any entry point added later, and
    an unrepaired entry point is exactly the class of defect these tests exist
    to catch.
    """
    root = Path(__file__).resolve().parent.parent
    with (root / "pyproject.toml").open("rb") as handle:
        return tuple(sorted(tomllib.load(handle)["project"]["scripts"]))


ENTRY_POINTS = _declared_entry_points()


def _prepare(path: Path) -> None:
    """Build a venv shaped like a real one, including staging-bound shebangs.

    pip bakes the absolute interpreter path into console scripts at install
    time, so a tree built here and moved elsewhere reproduces the relocation
    the installer has to repair.
    """
    bin_dir = path / "venv" / "bin"
    bin_dir.mkdir(parents=True)
    (path / "venv" / "installed.txt").write_text("ok", encoding="utf-8")
    interpreter = bin_dir / "python"
    # Symlinked like a real venv interpreter, so the shebang resolves to a
    # genuine signed binary. The repair must leave symlinks alone.
    interpreter.symlink_to("/bin/sh")
    for name in ENTRY_POINTS:
        script = bin_dir / name
        script.write_text(f"#!{bin_dir / 'python'}\n# entry point\n", encoding="utf-8")
        script.chmod(0o755)


def _validate(path: Path) -> None:
    assert (path / "venv" / "installed.txt").read_text(encoding="utf-8") == "ok"


def _real_interpreter(interpreter: Path) -> None:
    """Give a fake release an interpreter that genuinely starts.

    The rollback pre-check runs the release's own interpreter and imports the
    runtime through it, because an executable bit is not evidence: a file
    containing the text `python` satisfies every file-level check and fails at
    the one moment a rollback needs it.
    """
    interpreter.parent.mkdir(parents=True, exist_ok=True)
    interpreter.symlink_to(sys.executable)


def _health_release(tmp_path: Path) -> Path:
    release = (tmp_path / "releases" / "2.3.0").resolve()
    _real_interpreter(release / "venv" / "bin" / "python")
    return release


def test_runtime_health_verifier_uses_activated_release_bridge(tmp_path: Path) -> None:
    release = _health_release(tmp_path)
    socket_path = (tmp_path / "data" / "health.sock").resolve()
    calls: list[tuple[list[str], float]] = []

    def runner(
        command: Sequence[str], timeout: float
    ) -> subprocess.CompletedProcess[str]:
        calls.append((list(command), timeout))
        return _health_result(command)

    health = RuntimeHealthVerifier(
        socket_path=socket_path,
        expected_device_id="ori-01",
        timeout_seconds=10,
        runner=runner,
    ).verify(release)

    assert health == {"device_id": "ori-01", "critical": False}
    assert calls[0][0] == [
        str(release / "venv" / "bin" / "python"),
        "-m",
        "ori.cli_bridge",
        "health",
        "snapshot",
        "--socket",
        str(socket_path),
        "--timeout-ms",
        "3000",
    ]
    assert 9.9 < calls[0][1] <= 10


def test_runtime_health_verifier_runs_real_bridge_against_unix_socket(
    tmp_path: Path,
) -> None:
    release = _health_release(tmp_path)
    shutil.rmtree(release / "venv")
    (release / "venv").symlink_to(Path(sys.prefix), target_is_directory=True)
    with tempfile.TemporaryDirectory(
        prefix="ori-health-", dir=_short_socket_temp_dir()
    ) as socket_dir:
        socket_path = Path(socket_dir).resolve() / "health.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        server.listen(1)

        def serve_once() -> None:
            connection, _ = server.accept()
            with connection:
                assert connection.recv(1024).strip() == b"GET_HEALTH"
                connection.sendall(
                    b'{"schema_version":1,"ok":true,"health":'
                    b'{"device_id":"ori-real","critical":false}}\n'
                )

        thread = threading.Thread(target=serve_once, daemon=True)
        thread.start()
        try:
            health = RuntimeHealthVerifier(
                socket_path=socket_path,
                expected_device_id="ori-real",
                timeout_seconds=5,
            ).verify(release)
        finally:
            server.close()
            thread.join(timeout=5)

        assert health == {"device_id": "ori-real", "critical": False}
        assert not thread.is_alive()


def test_runtime_health_verifier_retries_only_transient_socket_failure(
    tmp_path: Path,
) -> None:
    release = _health_release(tmp_path)
    responses = [1, 0]
    sleeps: list[float] = []

    def runner(
        command: Sequence[str], _timeout: float
    ) -> subprocess.CompletedProcess[str]:
        return _health_result(command, returncode=responses.pop(0))

    health = RuntimeHealthVerifier(
        socket_path=(tmp_path / "data" / "health.sock").resolve(),
        expected_device_id="ori-01",
        runner=runner,
        sleeper=sleeps.append,
    ).verify(release)

    assert health["device_id"] == "ori-01"
    assert sleeps == [0.25]


@pytest.mark.parametrize(
    "result",
    [
        subprocess.CompletedProcess([], 0, "not-json", "secret"),
        subprocess.CompletedProcess([], 0, '{"schema_version":1,"ok":true}', ""),
        _health_result([], socket_ok=False),
        _health_result([], critical=True),
    ],
)
def test_runtime_health_verifier_rejects_malformed_or_critical_health(
    tmp_path: Path, result: subprocess.CompletedProcess[str]
) -> None:
    release = _health_release(tmp_path)
    with pytest.raises(LinuxInstallError) as raised:
        RuntimeHealthVerifier(
            socket_path=(tmp_path / "data" / "health.sock").resolve(),
            expected_device_id="ori-01",
            runner=lambda _command, _timeout: result,
        ).verify(release)
    assert raised.value.code == "post_install_health_failed"
    assert "secret" not in raised.value.detail


def test_runtime_health_verifier_reports_wrong_runtime_identity(tmp_path: Path) -> None:
    release = _health_release(tmp_path)
    with pytest.raises(LinuxInstallError) as raised:
        RuntimeHealthVerifier(
            socket_path=(tmp_path / "data" / "health.sock").resolve(),
            expected_device_id="ori-01",
            runner=lambda command, _timeout: _health_result(
                command, device_id="wrong-device"
            ),
        ).verify(release)
    assert raised.value.detail == (
        "runtime health identity does not match configured device"
    )


def test_runtime_health_verifier_reports_subprocess_deadline(tmp_path: Path) -> None:
    release = _health_release(tmp_path)

    def runner(
        command: Sequence[str], timeout: float
    ) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command, timeout)

    with pytest.raises(LinuxInstallError) as raised:
        RuntimeHealthVerifier(
            socket_path=(tmp_path / "data" / "health.sock").resolve(),
            expected_device_id="ori-01",
            runner=runner,
        ).verify(release)
    assert raised.value.detail == (
        "runtime health bridge exceeded the verification deadline"
    )


def test_runtime_health_verifier_enforces_overall_deadline(tmp_path: Path) -> None:
    release = _health_release(tmp_path)
    now = 0.0

    def monotonic() -> float:
        return now

    def sleeper(delay: float) -> None:
        nonlocal now
        now += delay

    def runner(
        command: Sequence[str], _timeout: float
    ) -> subprocess.CompletedProcess[str]:
        return _health_result(command, returncode=1)

    with pytest.raises(LinuxInstallError, match="before the deadline"):
        RuntimeHealthVerifier(
            socket_path=(tmp_path / "data" / "health.sock").resolve(),
            expected_device_id="ori-01",
            timeout_seconds=0.5,
            poll_interval_seconds=0.25,
            runner=runner,
            monotonic=monotonic,
            sleeper=sleeper,
        ).verify(release)
    assert now == 0.5


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


def test_first_install_scaffolding_is_private_under_group_writable_umask(
    tmp_path: Path,
) -> None:
    """Exercise the real first-install order without a pre-created root.

    Debian's private-user-group setup commonly supplies 0002. Host-owned
    parents may inherit that umask, while the outermost-first installer loop
    creates each managed directory explicitly and pins it to 0700.
    """
    layout = InstallLayout.resolve(tmp_path / "home" / ".local" / "ori")
    previous_umask = os.umask(0o002)
    try:
        install_release(
            layout=layout,
            version="2.3.0",
            prepare=_prepare,
            validate=_validate,
            restart_service=lambda: None,
            stop_service=lambda: None,
            check_health=lambda _path: None,
        )
    finally:
        os.umask(previous_umask)

    assert [
        stat.S_IMODE(directory.stat().st_mode)
        for directory in (layout.root, layout.releases, layout.data)
    ] == [0o700, 0o700, 0o700]
    assert stat.S_IMODE((tmp_path / "home" / ".local").stat().st_mode) == 0o775


def test_creation_provenance_race_refuses_existing_entry_and_rolls_back_only_ours(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EEXIST after an absence observation must not become `created=True`.

    Replacing the hardened helper with main's exists/mkdir/chmod sequence makes
    this test silently adopt ``data`` and complete the install. The assertion
    therefore pins both creation-result provenance and rollback ownership.
    """
    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.root.mkdir(mode=0o700)
    real_mkdir = os.mkdir

    def mkdir_with_race(
        candidate: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if Path(candidate) == layout.data:
            real_mkdir(candidate, mode, dir_fd=dir_fd)
            os.chmod(candidate, 0o775, dir_fd=dir_fd)
            raise FileExistsError(17, "simulated concurrent creation", str(candidate))
        real_mkdir(candidate, mode, dir_fd=dir_fd)

    monkeypatch.setattr(installer_linux.os, "mkdir", mkdir_with_race)

    with pytest.raises(LinuxInstallError, match="data is writable by another account"):
        install_release(
            layout=layout,
            version="2.3.0",
            prepare=_prepare,
            validate=_validate,
            restart_service=lambda: None,
            stop_service=lambda: None,
            check_health=lambda _path: None,
        )

    assert stat.S_IMODE(layout.data.stat().st_mode) == 0o775
    assert layout.root.exists(), "the pre-existing root is not rollback-owned"
    assert not layout.releases.exists(), "only our successful mkdir is rolled back"


def test_path_substitution_never_chmods_or_accepts_the_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mode repair stays on the opened inode and substitution fails closed.

    The test hooks both mutation APIs so it also mutation-checks the old
    pathname implementation: Path.chmod would change and accept the substitute;
    descriptor-backed fchmod changes only the displaced, already-open inode.
    """
    path = tmp_path / "ori"
    displaced = tmp_path / "opened-inode"
    path.mkdir(mode=0o700)
    path.chmod(0o701)
    real_mkdir = os.mkdir
    real_fchmod = os.fchmod
    real_path_chmod = Path.chmod
    replaced = False

    def replace_entry() -> None:
        nonlocal replaced
        if replaced:
            return
        path.rename(displaced)
        real_mkdir(path, 0o755)
        os.chmod(path, 0o755)
        replaced = True

    def raced_fchmod(descriptor: int, mode: int) -> None:
        replace_entry()
        real_fchmod(descriptor, mode)

    def raced_path_chmod(candidate: Path, *args: object, **kwargs: object) -> None:
        if candidate == path:
            replace_entry()
        real_path_chmod(candidate, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(installer_linux.os, "fchmod", raced_fchmod)
    monkeypatch.setattr(Path, "chmod", raced_path_chmod)

    with pytest.raises(LinuxInstallError, match="changed during preparation"):
        installer_linux._ensure_private_directory(path)

    assert replaced is True
    assert stat.S_IMODE(path.stat().st_mode) == 0o755
    assert stat.S_IMODE(displaced.stat().st_mode) == 0o700


def test_scaffolding_cleanup_refuses_a_substituted_inode(tmp_path: Path) -> None:
    path = tmp_path / "ori"
    displaced = tmp_path / "created-by-installer"
    created = installer_linux._ensure_private_directory(path)
    assert created is not None
    path.rename(displaced)
    path.mkdir(mode=0o700)

    installer_linux._remove_created_scaffolding([created])

    assert path.exists(), "the replacement was not created by this invocation"
    assert displaced.exists(), "the proven inode is no longer at its recorded path"


@pytest.mark.parametrize("mode", [0o770, 0o775, 0o720, 0o2775, 0o707])
def test_preexisting_directory_writable_by_another_account_is_refused_unmodified(
    tmp_path: Path, mode: int
) -> None:
    path = tmp_path / "ori"
    path.mkdir(mode=0o700)
    path.chmod(mode)

    with pytest.raises(LinuxInstallError, match="writable by another account"):
        installer_linux._ensure_private_directory(path)

    assert stat.S_IMODE(path.stat().st_mode) == mode


@pytest.mark.parametrize(
    ("kind", "detail"),
    [
        ("symlink", "must not be a symlink"),
        ("file", "is not a directory"),
        ("missing_parent", "parent is unavailable"),
    ],
)
def test_private_directory_object_failures_are_stable_and_non_creating(
    tmp_path: Path, kind: str, detail: str
) -> None:
    path = tmp_path / "ori"
    if kind == "symlink":
        outside = tmp_path / "outside"
        outside.mkdir()
        path.symlink_to(outside, target_is_directory=True)
    elif kind == "file":
        path.write_text("not a directory", encoding="utf-8")
    else:
        path = tmp_path / "missing" / "ori"

    with pytest.raises(LinuxInstallError) as raised:
        installer_linux._ensure_private_directory(path)

    assert detail in raised.value.detail
    if kind == "missing_parent":
        assert not path.parent.exists()


def test_owner_stripping_umask_is_rejected_stably_and_cleaned_up(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ori"
    previous_umask = os.umask(0o500)
    try:
        with pytest.raises(LinuxInstallError) as raised:
            installer_linux._ensure_private_directory(path)
    finally:
        os.umask(previous_umask)

    assert "owner-stripping umasks are unsupported" in raised.value.detail
    assert not path.exists()


def test_missing_descriptor_platform_contract_fails_without_partial_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "ori"
    monkeypatch.delattr(installer_linux.os, "O_NOFOLLOW")

    with pytest.raises(LinuxInstallError, match="descriptor support"):
        installer_linux._ensure_private_directory(path)

    assert not path.exists()


def test_composed_install_orders_assets_health_and_enablement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    events: list[str] = []

    class Preparer:
        def prepare(self, release: Path) -> None:
            events.append("prepare")
            interpreter = release / "venv" / "bin" / "python"
            interpreter.parent.mkdir(parents=True)
            interpreter.write_bytes(b"python")
            interpreter.chmod(0o700)

        def validate(self, _release: Path) -> None:
            events.append("validate")

    class Manager:
        def install_unit(self, _rendered: str) -> Callable[[], None]:
            events.append("unit")
            return lambda: events.append("unit-rollback")

        def restart(self) -> None:
            events.append("restart")

        def stop(self) -> None:
            events.append("stop")

        def enable(self) -> BootPersistence:
            events.append("enable")
            return BootPersistence(True, "enabled")

        def boot_persistence(self) -> BootPersistence:
            return BootPersistence(True, "enabled")

    class Health:
        def verify(self, _release: Path) -> dict[str, object]:
            events.append("health")
            return {"device_id": "ori-01", "critical": False}

    def provision(**_kwargs: object) -> Callable[[], None]:
        events.append("config")
        return lambda: events.append("config-rollback")

    monkeypatch.setattr("ori.installer.linux.provision_runtime_config", provision)
    result = install_composed_release(
        layout=layout,
        bundle=ExtractedReleaseBundle(
            tmp_path, "2.3.0", "linux-x86_64-python3.12", "3.12", 1
        ),
        values=InstallerConfigInput("ori-01", "Office", "Lagos"),
        service_profile=SystemdServiceProfile.user(),
        service_manager=Manager(),  # type: ignore[arg-type]
        unit_template=_service_template(),
        env_file=layout.data / "runtime.env",
        preparer=Preparer(),  # type: ignore[arg-type]
        health_verifier=Health(),  # type: ignore[arg-type]
    )

    assert result.install.changed is True
    assert result.health["device_id"] == "ori-01"
    assert events == [
        "prepare",
        "validate",
        "validate",
        "config",
        "unit",
        "restart",
        "health",
        "enable",
    ]

    events.clear()
    repeated = install_composed_release(
        layout=layout,
        bundle=ExtractedReleaseBundle(
            tmp_path, "2.3.0", "linux-x86_64-python3.12", "3.12", 1
        ),
        values=InstallerConfigInput("ori-01", "Office", "Lagos"),
        service_profile=SystemdServiceProfile.user(),
        service_manager=Manager(),  # type: ignore[arg-type]
        unit_template=_service_template(),
        env_file=layout.data / "runtime.env",
        preparer=Preparer(),  # type: ignore[arg-type]
        health_verifier=Health(),  # type: ignore[arg-type]
    )
    assert repeated.install.changed is False
    assert events == ["validate", "config", "unit", "restart", "health", "enable"]


@pytest.mark.parametrize("stop_fails", [False, True])
def test_composed_first_install_failure_attempts_all_rollback_steps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stop_fails: bool
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    events: list[str] = []

    class Preparer:
        def prepare(self, release: Path) -> None:
            interpreter = release / "venv" / "bin" / "python"
            interpreter.parent.mkdir(parents=True)
            interpreter.write_bytes(b"python")
            interpreter.chmod(0o700)

        def validate(self, _release: Path) -> None:
            return

    class Manager:
        def install_unit(self, _rendered: str) -> Callable[[], None]:
            events.append("unit")
            return lambda: events.append("unit-rollback")

        def restart(self) -> None:
            events.append("restart")

        def stop(self) -> None:
            events.append("stop")
            if stop_fails:
                raise LinuxInstallError("service_start_failed", "stop failed")

        def enable(self) -> BootPersistence:
            raise AssertionError("must not enable unhealthy service")

        def boot_persistence(self) -> BootPersistence:
            raise AssertionError("must not query failed install")

    class Health:
        def verify(self, _release: Path) -> dict[str, object]:
            events.append("health")
            raise LinuxInstallError("post_install_health_failed", "critical")

    def provision(**_kwargs: object) -> Callable[[], None]:
        events.append("config")
        return lambda: events.append("config-rollback")

    monkeypatch.setattr("ori.installer.linux.provision_runtime_config", provision)
    with pytest.raises(LinuxInstallError) as raised:
        install_composed_release(
            layout=layout,
            bundle=ExtractedReleaseBundle(
                tmp_path, "2.3.0", "linux-x86_64-python3.12", "3.12", 1
            ),
            values=InstallerConfigInput("ori-01", "Office", "Lagos"),
            service_profile=SystemdServiceProfile.user(),
            service_manager=Manager(),  # type: ignore[arg-type]
            unit_template=_service_template(),
            env_file=layout.data / "runtime.env",
            preparer=Preparer(),  # type: ignore[arg-type]
            health_verifier=Health(),  # type: ignore[arg-type]
        )

    expected_code = "rollback_failed" if stop_fails else "post_install_health_failed"
    assert raised.value.code == expected_code
    assert events == [
        "config",
        "unit",
        "restart",
        "health",
        "stop",
        "unit-rollback",
        "config-rollback",
    ]
    assert not layout.current.exists()
    assert layout.release("2.3.0").exists() is stop_fails


def test_composed_reinstall_integrates_config_dac_and_live_health_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with tempfile.TemporaryDirectory(
        prefix="ori-composed-", dir=_short_socket_temp_dir()
    ) as root:
        layout = InstallLayout.resolve(Path(root) / "ori")
        socket_path = layout.data / "health.sock"
        server: socket.socket | None = None
        server_thread: threading.Thread | None = None
        server_errors: list[Exception] = []

        class Preparer:
            def prepare(self, release: Path) -> None:
                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "venv",
                        "--system-site-packages",
                        str(release / "venv"),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                interpreter = release / "venv" / "bin" / "python"
                interpreter.unlink()
                shutil.copy2(Path(sys.executable).resolve(), interpreter)
                version_dir = f"python{sys.version_info.major}.{sys.version_info.minor}"
                site_packages = release / "venv" / "lib" / version_dir / "site-packages"
                active_site_packages = (
                    Path(sys.prefix) / "lib" / version_dir / "site-packages"
                )
                (site_packages / "ori-test-dependencies.pth").write_text(
                    str(active_site_packages) + "\n", encoding="utf-8"
                )
                for alias in (
                    "python3",
                    version_dir,
                ):
                    alias_path = interpreter.parent / alias
                    if alias_path.is_symlink():
                        alias_path.unlink()
                        alias_path.symlink_to("python")

            def validate(self, release: Path) -> None:
                assert (release / "venv" / "bin" / "python").is_file()

        class Manager:
            def install_unit(self, _rendered: str) -> Callable[[], None]:
                return lambda: None

            def restart(self) -> None:
                nonlocal server, server_thread
                if server is not None:
                    return
                server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                server.bind(str(socket_path))
                server.listen(2)

                def serve() -> None:
                    assert server is not None
                    try:
                        for _ in range(2):
                            connection, _ = server.accept()
                            with connection:
                                assert connection.recv(1024).strip() == b"GET_HEALTH"
                                connection.sendall(
                                    b'{"schema_version":1,"ok":true,"health":'
                                    b'{"device_id":"ori-01","critical":false}}\n'
                                )
                    except Exception as exc:
                        server_errors.append(exc)

                server_thread = threading.Thread(target=serve, daemon=True)
                server_thread.start()

            def stop(self) -> None:
                return

            def enable(self) -> BootPersistence:
                return BootPersistence(True, "enabled")

            def boot_persistence(self) -> BootPersistence:
                return BootPersistence(True, "enabled")

        current_account = pwd.getpwuid(os.getuid())
        monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
        monkeypatch.setattr(
            "ori.installer.linux.pwd.getpwnam", lambda _name: current_account
        )
        monkeypatch.setattr("ori.installer.linux.os.fchown", lambda *_args: None)
        bundle = ExtractedReleaseBundle(
            Path(root), "2.3.0", "linux-x86_64-python3.12", "3.12", 1
        )
        kwargs = {
            "layout": layout,
            "bundle": bundle,
            "values": InstallerConfigInput("ori-01", "Office", "Lagos"),
            "service_profile": SystemdServiceProfile.system(),
            "service_manager": Manager(),
            "unit_template": _service_template(),
            "env_file": layout.data / "runtime.env",
            "preparer": Preparer(),
        }
        try:
            first = install_composed_release(**kwargs)  # type: ignore[arg-type]
            assert first.install.changed is True
            assert socket_path.exists()
            repeated = install_composed_release(**kwargs)  # type: ignore[arg-type]
            assert repeated.install.changed is False
            assert (layout.data / "ori.yaml").stat().st_mode & 0o777 == 0o600
            assert layout.current.resolve() == layout.release("2.3.0")
        finally:
            if server is not None:
                server.close()
            if server_thread is not None:
                server_thread.join(timeout=5)
        assert server_errors == []
        assert server_thread is not None and not server_thread.is_alive()


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
    # This invocation created the install root, and the failure left it empty,
    # so nothing of it remains — an operator whose first install failed has no
    # directory tree suggesting Ori is installed.
    assert not layout.releases.exists()
    assert not layout.root.exists()
    assert not layout.current.exists()


def test_systemd_manager_separates_user_and_system_commands(tmp_path: Path) -> None:
    user_commands: list[Sequence[str]] = []
    system_commands: list[Sequence[str]] = []

    def user_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        user_commands.append(command)
        stdout = "yes\n" if command[0] == "loginctl" else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    def system_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        system_commands.append(command)
        stdout = "enabled\n" if "is-enabled" in command else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    user = SystemdServiceManager(
        profile=SystemdServiceProfile.user(),
        unit_path=(tmp_path / "user" / "ori-runtime.service").resolve(),
        runner=user_runner,
        effective_uid=1001,
    )
    system = SystemdServiceManager(
        profile=SystemdServiceProfile.system(),
        unit_path=(tmp_path / "system" / "ori-runtime.service").resolve(),
        runner=system_runner,
        effective_uid=0,
    )
    user.restart()
    assert user.enable().enabled is True
    system.restart()
    assert system.enable().enabled is True
    assert user_commands == [
        ["systemctl", "--user", "restart", "ori-runtime.service"],
        ["systemctl", "--user", "enable", "ori-runtime.service"],
        ["loginctl", "show-user", "1001", "-p", "Linger", "--value"],
    ]
    assert system_commands == [
        ["systemctl", "restart", "ori-runtime.service"],
        ["systemctl", "enable", "ori-runtime.service"],
        ["systemctl", "is-enabled", "ori-runtime.service"],
    ]


def test_systemd_manager_installs_atomically_without_enabling(tmp_path: Path) -> None:
    commands: list[Sequence[str]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    unit = (tmp_path / "units" / "ori-runtime.service").resolve()
    manager = SystemdServiceManager(
        profile=SystemdServiceProfile.user(),
        unit_path=unit,
        runner=runner,
        effective_uid=1001,
    )
    manager.install_unit(_rendered_unit(tmp_path, SystemdServiceProfile.user()))
    assert unit.read_text(encoding="utf-8").startswith("# Copyright")
    assert unit.stat().st_mode & 0o777 == 0o600
    assert commands == [["systemctl", "--user", "daemon-reload"]]


def test_user_systemd_recursive_parents_remain_below_private_home(
    tmp_path: Path,
) -> None:
    """Systemd parents are host-owned, not managed install scaffolding.

    Recursive mkdir may leave host-policy modes on implicit parents. They are
    safe here because the user service hierarchy stays beneath the invoking
    account's pre-existing 0700 home, which the installer leaves untouched.
    """
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    unit = (home / ".config" / "systemd" / "user" / "ori-runtime.service").resolve()
    manager = SystemdServiceManager(
        profile=SystemdServiceProfile.user(),
        unit_path=unit,
        runner=lambda command: subprocess.CompletedProcess(command, 0, "", ""),
        effective_uid=1001,
    )
    previous_umask = os.umask(0o002)
    try:
        manager.install_unit(_rendered_unit(tmp_path, SystemdServiceProfile.user()))
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    assert stat.S_IMODE((home / ".config").stat().st_mode) == 0o775
    assert stat.S_IMODE((home / ".config" / "systemd").stat().st_mode) == 0o775
    assert stat.S_IMODE(unit.parent.stat().st_mode) == 0o700


def test_systemd_unit_transaction_can_remove_new_unit(tmp_path: Path) -> None:
    unit = (tmp_path / "systemd" / "ori-runtime.service").resolve()
    commands: list[list[str]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(list(command))
        return subprocess.CompletedProcess(command, 0, "", "")

    manager = SystemdServiceManager(
        profile=SystemdServiceProfile.user(),
        unit_path=unit,
        runner=runner,
        effective_uid=1001,
    )
    rollback = manager.install_unit(
        _rendered_unit(tmp_path, SystemdServiceProfile.user())
    )
    rollback()

    assert not unit.exists()
    assert commands == [
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "disable", "--now", "ori-runtime.service"],
        ["systemctl", "--user", "daemon-reload"],
    ]


@pytest.mark.parametrize("existing", [False, True])
def test_systemd_manager_rolls_back_unit_when_daemon_reload_fails(
    tmp_path: Path, existing: bool
) -> None:
    calls = 0

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(command, 1 if calls == 1 else 0, "", "")

    unit = (tmp_path / "units" / "ori-runtime.service").resolve()
    unit.parent.mkdir()
    if existing:
        unit.write_text("old unit\n", encoding="utf-8")
        unit.chmod(0o640)
    manager = SystemdServiceManager(
        profile=SystemdServiceProfile.user(),
        unit_path=unit,
        runner=runner,
        effective_uid=1001,
    )
    with pytest.raises(LinuxInstallError, match="daemon reload"):
        manager.install_unit(_rendered_unit(tmp_path, SystemdServiceProfile.user()))
    if existing:
        assert unit.read_text(encoding="utf-8") == "old unit\n"
        assert unit.stat().st_mode & 0o777 == 0o640
    else:
        assert not unit.exists()
    assert calls == 2


def test_systemd_manager_removal_is_idempotent_when_unit_is_absent(
    tmp_path: Path,
) -> None:
    commands: list[Sequence[str]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        stdout = "inactive\n" if "is-active" in command else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    manager = SystemdServiceManager(
        profile=SystemdServiceProfile.user(),
        unit_path=(tmp_path / "units" / "ori-runtime.service").resolve(),
        runner=runner,
        effective_uid=1001,
    )
    manager.disable_and_remove()
    assert commands == [
        ["systemctl", "--user", "is-active", "ori-runtime.service"],
        ["systemctl", "--user", "daemon-reload"],
    ]


def test_systemd_manager_stops_loaded_service_when_unit_is_absent(
    tmp_path: Path,
) -> None:
    commands: list[Sequence[str]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        stdout = "active\n" if "is-active" in command else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    manager = SystemdServiceManager(
        profile=SystemdServiceProfile.user(),
        unit_path=(tmp_path / "units" / "ori-runtime.service").resolve(),
        runner=runner,
        effective_uid=1001,
    )
    manager.disable_and_remove()
    assert commands == [
        ["systemctl", "--user", "is-active", "ori-runtime.service"],
        ["systemctl", "--user", "stop", "ori-runtime.service"],
        ["systemctl", "--user", "daemon-reload"],
    ]


def test_systemd_manager_disables_before_removing_unit(tmp_path: Path) -> None:
    commands: list[Sequence[str]] = []
    unit = (tmp_path / "units" / "ori-runtime.service").resolve()
    unit.parent.mkdir()
    unit.write_text("unit\n", encoding="utf-8")

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if len(commands) == 1:
            assert unit.exists()
        else:
            assert not unit.exists()
        return subprocess.CompletedProcess(command, 0, "", "")

    manager = SystemdServiceManager(
        profile=SystemdServiceProfile.user(),
        unit_path=unit,
        runner=runner,
        effective_uid=1001,
    )
    manager.disable_and_remove()
    assert commands == [
        ["systemctl", "--user", "disable", "--now", "ori-runtime.service"],
        ["systemctl", "--user", "daemon-reload"],
    ]


@pytest.mark.parametrize(
    ("manager_profile", "rendered_profile"),
    [
        (SystemdServiceProfile.system(), SystemdServiceProfile.user()),
        (SystemdServiceProfile.user(), SystemdServiceProfile.system()),
    ],
)
def test_systemd_manager_rejects_rendered_profile_mismatch(
    tmp_path: Path,
    manager_profile: SystemdServiceProfile,
    rendered_profile: SystemdServiceProfile,
) -> None:
    commands: list[Sequence[str]] = []
    unit = (tmp_path / "units" / "ori-runtime.service").resolve()
    manager = SystemdServiceManager(
        profile=manager_profile,
        unit_path=unit,
        runner=lambda command: (
            commands.append(command) or subprocess.CompletedProcess(command, 0, "", "")
        ),
        effective_uid=0 if manager_profile.scope == "system" else 1001,
    )
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        manager.install_unit(_rendered_unit(tmp_path, rendered_profile))
    assert commands == []
    assert not unit.exists()


def test_systemd_manager_rejects_hidden_continuation_directives(
    tmp_path: Path,
) -> None:
    manager = SystemdServiceManager(
        profile=SystemdServiceProfile.user(),
        unit_path=(tmp_path / "units" / "ori-runtime.service").resolve(),
        runner=lambda command: subprocess.CompletedProcess(command, 0, "", ""),
        effective_uid=1001,
    )
    rendered = _rendered_unit(tmp_path, SystemdServiceProfile.user()).replace(
        "Type=simple", "Type=simple\\\nUser=root"
    )
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        manager.install_unit(rendered)


def test_system_boot_persistence_queries_real_enablement(tmp_path: Path) -> None:
    states = iter([(1, "disabled\n"), (0, "enabled\n")])

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        returncode, stdout = next(states)
        return subprocess.CompletedProcess(command, returncode, stdout, "")

    manager = SystemdServiceManager(
        profile=SystemdServiceProfile.system(),
        unit_path=(tmp_path / "units" / "ori-runtime.service").resolve(),
        runner=runner,
        effective_uid=0,
    )
    assert manager.boot_persistence().enabled is False
    assert manager.boot_persistence().enabled is True


def test_user_boot_persistence_reports_missing_linger(tmp_path: Path) -> None:
    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "no\n", "")

    manager = SystemdServiceManager(
        profile=SystemdServiceProfile.user(),
        unit_path=(tmp_path / "units" / "ori-runtime.service").resolve(),
        runner=runner,
        effective_uid=1001,
    )
    persistence = manager.boot_persistence()
    assert persistence.enabled is False
    assert "not persistent" in persistence.detail


def test_user_boot_persistence_rejects_malformed_linger_state(tmp_path: Path) -> None:
    manager = SystemdServiceManager(
        profile=SystemdServiceProfile.user(),
        unit_path=(tmp_path / "units" / "ori-runtime.service").resolve(),
        runner=lambda command: subprocess.CompletedProcess(command, 0, "unknown\n", ""),
        effective_uid=1001,
    )
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        manager.boot_persistence()


def test_systemd_manager_rejects_root_user_scope_and_command_failures(
    tmp_path: Path,
) -> None:
    unit = (tmp_path / "units" / "ori-runtime.service").resolve()
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        SystemdServiceManager(
            profile=SystemdServiceProfile.user(), unit_path=unit, effective_uid=0
        )
    manager = SystemdServiceManager(
        profile=SystemdServiceProfile.system(),
        unit_path=unit,
        effective_uid=0,
        runner=lambda command: subprocess.CompletedProcess(command, 1, "", "failed"),
    )
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        manager.restart()


def _rendered_unit(tmp_path: Path, profile: SystemdServiceProfile) -> str:
    return render_systemd_unit(
        _service_template(),
        profile=profile,
        root=(tmp_path / "root").resolve(),
        data_dir=(tmp_path / "data").resolve(),
        config_path=(tmp_path / "data" / "ori.yaml").resolve(),
        env_file=(tmp_path / "data" / "runtime.env").resolve(),
    )


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
    layout.root.mkdir(mode=0o700)
    layout.releases.mkdir(mode=0o700)
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
            for name in ENTRY_POINTS:
                (venv / "bin" / name).write_text("", encoding="utf-8")
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


_EXT_SUFFIX = ".cpython-313-aarch64-linux-gnu.so"
_ADMITTED = Path("/usr/lib/python3/dist-packages")


def _pi_preparer(
    tmp_path: Path,
    *,
    source: Path | None,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str = _EXT_SUFFIX,
    on_pi: bool = True,
    purelib: Path | None = None,
    occupied: bool = False,
    shim_present: bool = True,
    occupied_dirs: tuple[str, ...] = (),
    import_answer: str = "ok",
    shim_import_answer: str | None = None,
) -> tuple[Path, list[Sequence[str]], Callable[[], None]]:
    """A Pi bundle whose system probe answers with *source* as lgpio's home."""
    root = tmp_path / "bundle"
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    (wheelhouse / "requirements.txt").write_text("locked", encoding="utf-8")
    (wheelhouse / "requirements-pi.txt").write_text("locked", encoding="utf-8")
    (wheelhouse / "ori_runtime-2.3.0-py3-none-any.whl").write_bytes(b"wheel")
    bundle = ExtractedReleaseBundle(
        root, "2.3.0", "linux-aarch64-python3.13", "3.13", 2
    )

    site_packages = purelib or tmp_path / "release" / "venv" / "site-packages"
    commands: list[Sequence[str]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if "venv" in command:
            venv = Path(command[-1])
            (venv / "bin").mkdir(parents=True)
            (venv / "bin" / "python").write_text("", encoding="utf-8")
            for name in ENTRY_POINTS:
                (venv / "bin" / name).write_text("", encoding="utf-8")
            site_packages.mkdir(parents=True, exist_ok=True)
            if occupied:
                (site_packages / "lgpio.py").write_text("SQUATTER", encoding="utf-8")
            for name in occupied_dirs:
                occupant = site_packages / name
                occupant.mkdir(parents=True, exist_ok=True)
                (occupant / "squatter.py").write_text("SQUATTER", encoding="utf-8")
        body = command[-1]
        stdout = ""
        if "sys._base_executable" in body:
            stdout = "/usr/bin/python3.13"
        elif "EXT_SUFFIX" in body:
            stdout = suffix
        elif "find_spec" in body:
            if source is None:
                stdout = ""
            elif "'RPi'" in body:
                stdout = str(source / "RPi" / "__init__.py") if shim_present else ""
            else:
                stdout = str(source / "lgpio.py")
        elif "print('ok')" in body:
            # The post-stage check asks the release interpreter whether what
            # was copied can actually be imported. The two member sets are
            # asked separately, because only one of them is mandatory.
            if "RPi.GPIO" in body:
                stdout = (
                    import_answer if shim_import_answer is None else shim_import_answer
                )
            else:
                stdout = import_answer
        elif "purelib" in body:
            stdout = str(site_packages)
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(installer_linux, "_is_raspberry_pi", lambda: on_pi)
    release = tmp_path / "release"
    release.mkdir()
    preparer = OfflineReleasePreparer(
        bundle=bundle, runner=runner, bootstrap_python="python3"
    )
    return site_packages, commands, lambda: preparer.prepare(release)


def _plant(directory: Path, *, suffix: str = _EXT_SUFFIX) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "lgpio.py").write_text("PIN_FACTORY", encoding="utf-8")
    (directory / f"_lgpio{suffix}").write_bytes(b"\x7fELF")
    (directory / "yaml.py").write_text("", encoding="utf-8")
    # An extension left behind for a different interpreter ABI.
    (directory / "_lgpio.cpython-310-aarch64-linux-gnu.so").write_bytes(b"stale")
    # adafruit-blinka's platform library, as `python3-rpi-lgpio` lays it out,
    # with the metadata a directory copy would sweep up beside it.
    shim = directory / "RPi"
    (shim / "GPIO").mkdir(parents=True, exist_ok=True)
    (shim / "__init__.py").write_text("", encoding="utf-8")
    (shim / "GPIO" / "__init__.py").write_text("BLINKA_SHIM", encoding="utf-8")
    (shim / "GPIO" / "scratch.py").write_text("NOT_IN_MANIFEST", encoding="utf-8")
    egg = directory / "rpi_lgpio-0.6.egg-info"
    egg.mkdir(parents=True, exist_ok=True)
    (egg / "PKG-INFO").write_text("", encoding="utf-8")


def _accept_system_files(monkeypatch: pytest.MonkeyPatch) -> None:
    """Treat planted fixtures as root-owned; tests do not run as root."""
    monkeypatch.setattr(installer_linux, "_system_file_failure", lambda path: None)


def test_offline_preparer_copies_the_pin_factory_into_a_pi_venv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """gpiozero without a backend silently falls back to NativeFactory.

    The bytes are copied rather than linked: the release permission transaction
    requires an external symlink target to be executable and apt ships these
    `0644`, so a link is refused at a later seam than the one that made it.
    """
    _plant(tmp_path / "dist")
    _accept_system_files(monkeypatch)
    monkeypatch.setattr(
        installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (tmp_path / "dist",)
    )
    purelib, _, run = _pi_preparer(
        tmp_path, source=tmp_path / "dist", monkeypatch=monkeypatch
    )
    run()
    staged = sorted(entry.name for entry in purelib.iterdir())
    assert staged == ["RPi", f"_lgpio{_EXT_SUFFIX}", "lgpio.py"]
    assert not any((purelib / name).is_symlink() for name in staged)
    assert (purelib / "lgpio.py").read_text(encoding="utf-8") == "PIN_FACTORY"
    # The shim keeps its package layout, or `import RPi.GPIO` cannot work.
    assert (purelib / "RPi" / "GPIO" / "__init__.py").read_text(
        encoding="utf-8"
    ) == "BLINKA_SHIM"


@pytest.mark.parametrize(
    "suffix",
    [
        ".cpython-311-aarch64-linux-gnu.so",
        ".cpython-312-aarch64-linux-gnu.so",
        ".cpython-313-aarch64-linux-gnu.so",
    ],
)
def test_offline_preparer_stages_the_shim_for_every_supported_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str
) -> None:
    """The shim is pure Python; only the pin factory extension is ABI-bound.

    3.12 and 3.13 are supported targets and 3.11 is community, so a change that
    staged only for the interpreter it was written on would break two of the
    three published aarch64 bundles. The extension is selected by the ABI tag;
    the shim's two files are the same on all of them.
    """
    dist = tmp_path / "dist"
    _plant(dist, suffix=suffix)
    _accept_system_files(monkeypatch)
    monkeypatch.setattr(installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (dist,))
    purelib, _, run = _pi_preparer(
        tmp_path, source=dist, monkeypatch=monkeypatch, suffix=suffix
    )
    run()
    staged = sorted(entry.name for entry in purelib.iterdir())
    assert staged == ["RPi", f"_lgpio{suffix}", "lgpio.py"]
    assert (purelib / "RPi" / "GPIO" / "__init__.py").read_text(
        encoding="utf-8"
    ) == "BLINKA_SHIM"
    # The extension for another interpreter is left where it was.
    assert not (purelib / "_lgpio.cpython-310-aarch64-linux-gnu.so").exists()


@pytest.mark.parametrize("occupied", ["RPi", "RPi/GPIO"])
def test_offline_preparer_refuses_to_merge_into_a_tree_it_did_not_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, occupied: str
) -> None:
    """An existing directory is refused, not merged into.

    A file or a symlink at a manifest component was already refused; an
    ordinary directory was not, so the staged files would land beside whatever
    put it there. `RPi/` from a different package is exactly the tree that
    would be merged into, and the result imports as `RPi.GPIO`.

    The shim is best effort, so this reports rather than failing the install —
    but nothing may be written on the way to that decision.
    """
    _plant(tmp_path / "dist")
    _accept_system_files(monkeypatch)
    monkeypatch.setattr(
        installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (tmp_path / "dist",)
    )
    purelib, _, run = _pi_preparer(
        tmp_path,
        source=tmp_path / "dist",
        monkeypatch=monkeypatch,
        occupied_dirs=(occupied,),
    )
    run()
    # The occupant is untouched and nothing of the manifest joined it.
    occupant = purelib / occupied
    assert (occupant / "squatter.py").read_text(encoding="utf-8") == "SQUATTER"
    assert not (purelib / "RPi" / "__init__.py").exists()
    assert not (purelib / "RPi" / "GPIO" / "__init__.py").exists()
    # The pin factory is unaffected: it shares no path component with the shim.
    assert (purelib / "lgpio.py").read_text(encoding="utf-8") == "PIN_FACTORY"


def test_offline_preparer_installs_without_the_blinka_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing shim reports and never fails the install.

    A Pi that staged the pin factory but has no shim installs today, and the
    classic `python3-rpi.gpio` can occupy the same import name. Refusing either
    would break a working deployment to add a capability it may not use — the
    runtime reports the i2c driver unavailable at connect instead. A Pi with no
    pin factory never reaches here; mandatory staging refuses first.
    """
    dist = tmp_path / "dist"
    _plant(dist)
    shutil.rmtree(dist / "RPi")
    _accept_system_files(monkeypatch)
    monkeypatch.setattr(installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (dist,))
    purelib, _, run = _pi_preparer(
        tmp_path, source=dist, monkeypatch=monkeypatch, shim_present=False
    )
    run()
    staged = sorted(entry.name for entry in purelib.iterdir())
    assert staged == [f"_lgpio{_EXT_SUFFIX}", "lgpio.py"]


def test_offline_preparer_takes_back_a_shim_the_release_cannot_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A different package can occupy the same import name.

    The classic RPi.GPIO keeps its implementation in a compiled `_GPIO`
    extension this manifest does not carry, so the copied files would be a
    package that cannot import. Half-staged is worse than absent.
    """
    _plant(tmp_path / "dist")
    _accept_system_files(monkeypatch)
    monkeypatch.setattr(
        installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (tmp_path / "dist",)
    )
    purelib, _, run = _pi_preparer(
        tmp_path,
        source=tmp_path / "dist",
        monkeypatch=monkeypatch,
        shim_import_answer="",
    )
    run()
    staged = sorted(entry.name for entry in purelib.iterdir())
    assert staged == [f"_lgpio{_EXT_SUFFIX}", "lgpio.py"]
    assert not (purelib / "RPi").exists()


def test_offline_preparer_refuses_a_release_that_cannot_import_the_pin_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pin factory is mandatory, so its import failure is fatal."""
    _plant(tmp_path / "dist")
    _accept_system_files(monkeypatch)
    monkeypatch.setattr(
        installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (tmp_path / "dist",)
    )
    _, _, run = _pi_preparer(
        tmp_path,
        source=tmp_path / "dist",
        monkeypatch=monkeypatch,
        import_answer="",
    )
    with pytest.raises(LinuxInstallError) as excinfo:
        run()
    assert "could not be imported" in str(excinfo.value)


def test_offline_preparer_takes_only_the_current_abi_and_nothing_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A glob would admit an extension built for another interpreter ABI."""
    _plant(tmp_path / "dist")
    _accept_system_files(monkeypatch)
    monkeypatch.setattr(
        installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (tmp_path / "dist",)
    )
    purelib, _, run = _pi_preparer(
        tmp_path, source=tmp_path / "dist", monkeypatch=monkeypatch
    )
    run()
    staged = {entry.name for entry in purelib.iterdir()}
    assert "yaml.py" not in staged
    assert "_lgpio.cpython-310-aarch64-linux-gnu.so" not in staged
    # A directory copy of RPi/ would take both of these.
    assert "rpi_lgpio-0.6.egg-info" not in staged
    assert not (purelib / "RPi" / "GPIO" / "scratch.py").exists()


def test_offline_preparer_probes_the_system_in_isolated_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Discovery must not depend on PYTHON* variables or the working directory."""
    _plant(tmp_path / "dist")
    _accept_system_files(monkeypatch)
    monkeypatch.setattr(
        installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (tmp_path / "dist",)
    )
    _, commands, run = _pi_preparer(
        tmp_path, source=tmp_path / "dist", monkeypatch=monkeypatch
    )
    run()
    probes = [command for command in commands if "-c" in command]
    assert probes, "the preparer probed nothing"
    assert all("-I" in command for command in probes)


def test_offline_preparer_refuses_a_pin_factory_outside_admitted_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The interpreter says where it would import from; only a known home counts."""
    _plant(tmp_path / "elsewhere")
    _accept_system_files(monkeypatch)
    monkeypatch.setattr(installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (_ADMITTED,))
    _, _, run = _pi_preparer(
        tmp_path, source=tmp_path / "elsewhere", monkeypatch=monkeypatch
    )
    with pytest.raises(LinuxInstallError, match="prerequisite_install_failed"):
        run()


def test_offline_preparer_refuses_a_pi_bundle_without_the_pin_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Pi bundle carries GPIO wheels because the device is meant to drive pins.

    Finishing the install without that capability is the silent degradation this
    path exists to remove, and development posture would not catch it.
    """
    _, _, run = _pi_preparer(tmp_path, source=None, monkeypatch=monkeypatch)
    with pytest.raises(LinuxInstallError, match="prerequisite_install_failed"):
        run()


def test_offline_preparer_refuses_a_pin_factory_it_cannot_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ownership and mode are checked before any byte enters the release."""
    _plant(tmp_path / "dist")
    # World-writable rather than wrongly-owned: the suite runs as root in a
    # container and as an ordinary user on a laptop, and only one of those can
    # make a file fail an ownership check.
    (tmp_path / "dist" / "lgpio.py").chmod(0o666)
    monkeypatch.setattr(
        installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (tmp_path / "dist",)
    )
    _, _, run = _pi_preparer(
        tmp_path, source=tmp_path / "dist", monkeypatch=monkeypatch
    )
    with pytest.raises(LinuxInstallError, match="prerequisite_install_failed"):
        run()


def test_offline_preparer_stages_nothing_on_hardware_that_is_not_a_pi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An `aarch64` bundle also serves Linux that is not a Pi.

    The source here is present and valid, so an absent module cannot be what
    makes this pass. Non-Pi hardware must not stage the factory even when it
    could: the host has no pins to drive, and copying system code into a release
    that will never use it is exposure bought for nothing. Nothing is copied and
    the system is never probed at all.
    """
    _plant(tmp_path / "dist")
    _accept_system_files(monkeypatch)
    monkeypatch.setattr(
        installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (tmp_path / "dist",)
    )
    purelib, commands, run = _pi_preparer(
        tmp_path, source=tmp_path / "dist", monkeypatch=monkeypatch, on_pi=False
    )
    run()
    assert list(purelib.iterdir()) == []
    assert not any("find_spec" in command[-1] for command in commands)


def test_offline_preparer_reads_pi_hardware_rather_than_trusting_the_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The model file is the signal, and a missing one is not a Pi."""
    monkeypatch.setattr(installer_linux, "_DEVICE_MODEL", tmp_path / "absent")
    assert installer_linux._is_raspberry_pi() is False

    model = tmp_path / "model"
    model.write_bytes(b"Raspberry Pi 4 Model B Rev 1.5\x00")
    monkeypatch.setattr(installer_linux, "_DEVICE_MODEL", model)
    assert installer_linux._is_raspberry_pi() is True

    model.write_bytes(b"Some Other ARM Board\x00")
    assert installer_linux._is_raspberry_pi() is False


def test_offline_preparer_binds_the_destination_to_the_venv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Root is about to write where a probe pointed, so the path is bound.

    Every other privileged write in this installer is tied to its intended
    path; a destination named by a subprocess is no exception.
    """
    _plant(tmp_path / "dist")
    _accept_system_files(monkeypatch)
    monkeypatch.setattr(
        installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (tmp_path / "dist",)
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    _, _, run = _pi_preparer(
        tmp_path, source=tmp_path / "dist", monkeypatch=monkeypatch, purelib=outside
    )
    with pytest.raises(LinuxInstallError, match="prerequisite_install_failed"):
        run()
    assert list(outside.iterdir()) == [], "a file was written outside the venv"


def test_offline_preparer_refuses_to_overwrite_a_staged_pin_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fresh venv holds neither name; one already there means something else."""
    _plant(tmp_path / "dist")
    _accept_system_files(monkeypatch)
    monkeypatch.setattr(
        installer_linux, "_SYSTEM_PACKAGE_DIRECTORIES", (tmp_path / "dist",)
    )
    purelib, _, run = _pi_preparer(
        tmp_path, source=tmp_path / "dist", monkeypatch=monkeypatch, occupied=True
    )
    with pytest.raises(LinuxInstallError, match="prerequisite_install_failed"):
        run()
    assert (purelib / "lgpio.py").read_text(encoding="utf-8") == "SQUATTER"


def test_system_file_failure_names_each_way_a_file_is_untrusted(
    tmp_path: Path,
) -> None:
    """The check the installer runs before copying anything out of the system."""
    missing = tmp_path / "absent.py"
    assert installer_linux._system_file_failure(missing) == "is missing"

    directory = tmp_path / "adirectory"
    directory.mkdir()
    assert installer_linux._system_file_failure(directory) == "is not a regular file"

    link = tmp_path / "alink.py"
    real = tmp_path / "real.py"
    real.write_text("", encoding="utf-8")
    link.symlink_to(real)
    assert installer_linux._system_file_failure(link) == "is not a regular file"

    loose = tmp_path / "loose.py"
    loose.write_text("", encoding="utf-8")
    loose.chmod(0o666)
    assert installer_linux._system_file_failure(loose) in {
        # Which one is reported depends on whether the suite runs as root.
        "is not owned by root",
        "is writable beyond its owner",
    }
    tight = tmp_path / "tight.py"
    tight.write_text("", encoding="utf-8")
    tight.chmod(0o644)
    expected = None if os.geteuid() == 0 else "is not owned by root"
    assert installer_linux._system_file_failure(tight) == expected


def test_offline_preparer_leaves_a_generic_venv_isolated(tmp_path: Path) -> None:
    """A bundle carrying no Pi wheels never probes the system at all."""
    root = tmp_path / "bundle"
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    (wheelhouse / "requirements.txt").write_text("locked", encoding="utf-8")
    (wheelhouse / "ori_runtime-2.3.0-py3-none-any.whl").write_bytes(b"wheel")
    bundle = ExtractedReleaseBundle(root, "2.3.0", "linux-x86_64-python3.13", "3.13", 2)
    commands: list[Sequence[str]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if "venv" in command:
            venv = Path(command[-1])
            (venv / "bin").mkdir(parents=True)
            (venv / "bin" / "python").write_text("", encoding="utf-8")
            for name in ENTRY_POINTS:
                (venv / "bin" / name).write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    release = tmp_path / "release"
    release.mkdir()
    OfflineReleasePreparer(
        bundle=bundle, runner=runner, bootstrap_python="python3"
    ).prepare(release)
    assert not any("find_spec" in command[-1] for command in commands)
    assert "--system-site-packages" not in next(
        command for command in commands if "venv" in command
    )


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


def test_offline_preparer_accepts_a_candidate_reporting_its_pep440_version(
    tmp_path: Path,
) -> None:
    """A `2.4.0-rc.3` bundle installs a wheel that reports `2.4.0rc3`.

    The bundle carries the SemVer identity and `importlib.metadata` reports the
    PEP 440 one. Comparing them as strings fails every candidate install on the
    device, after the signature has already been verified — which is the point
    at which the operator has no fallback.
    """
    root = tmp_path / "bundle"
    root.mkdir()
    bundle = ExtractedReleaseBundle(
        root, "2.4.0-rc.3", "linux-x86_64-python3.12", "3.12", 1
    )
    release = tmp_path / "release"
    interpreter = release / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"python")
    for name in ENTRY_POINTS:
        (interpreter.parent / name).write_text("", encoding="utf-8")
    preparer = OfflineReleasePreparer(
        bundle=bundle,
        runner=lambda command: subprocess.CompletedProcess(
            command, 0, "2.4.0rc3\n", ""
        ),
    )

    preparer.validate(release)


def test_offline_preparer_rejects_a_candidate_reporting_the_final_version(
    tmp_path: Path,
) -> None:
    """`2.4.0` is not what a `2.4.0-rc.3` bundle installs.

    Reconciling the two spellings must not blur the two builds together.
    """
    root = tmp_path / "bundle"
    root.mkdir()
    bundle = ExtractedReleaseBundle(
        root, "2.4.0-rc.3", "linux-x86_64-python3.12", "3.12", 1
    )
    release = tmp_path / "release"
    interpreter = release / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"python")
    preparer = OfflineReleasePreparer(
        bundle=bundle,
        runner=lambda command: subprocess.CompletedProcess(command, 0, "2.4.0\n", ""),
    )

    with pytest.raises(LinuxInstallError, match="version mismatch"):
        preparer.validate(release)


def test_offline_preparer_rejects_installed_runtime_version_mismatch(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    root.mkdir()
    bundle = ExtractedReleaseBundle(root, "2.3.0", "linux-x86_64-python3.12", "3.12", 1)
    release = tmp_path / "release"
    interpreter = release / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"python")
    preparer = OfflineReleasePreparer(
        bundle=bundle,
        runner=lambda command: subprocess.CompletedProcess(command, 0, "2.4.0\n", ""),
    )

    with pytest.raises(LinuxInstallError, match="version mismatch"):
        preparer.validate(release)


def test_user_systemd_unit_uses_user_target_without_user_directive(
    tmp_path: Path,
) -> None:
    rendered = render_systemd_unit(
        _service_template(),
        profile=SystemdServiceProfile.user(),
        root=(tmp_path / "root").resolve(),
        data_dir=(tmp_path / "data").resolve(),
        config_path=(tmp_path / "data" / "config.yaml").resolve(),
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
        profile=SystemdServiceProfile.system(),
        root=(tmp_path / "root").resolve(),
        data_dir=(tmp_path / "data").resolve(),
        config_path=(tmp_path / "data" / "config.yaml").resolve(),
        env_file=(tmp_path / "runtime.env").resolve(),
    )
    assert "User=ori-runtime" in rendered
    assert "WantedBy=multi-user.target" in rendered
    assert "@ORI_" not in rendered


@pytest.mark.parametrize(
    "service_user", ["root", "0", "Bad User", "ori;root", "ori", "postgres"]
)
def test_system_systemd_profile_refuses_any_other_identity(service_user: str) -> None:
    """The account name is a constant, so no other value may reach a unit file.

    A configurable name would have to be carried by the unit file, the
    permission checks, the documentation and every support answer, and each
    could disagree. `root` and `ori;root` are refused for the obvious reasons;
    `ori` and `postgres` are refused for the same one as any other name.
    """
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        SystemdServiceProfile(scope="system", service_user=service_user)


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
        "config_path": (tmp_path / "data" / "config.yaml").resolve(),
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
    for config_path in (
        (tmp_path / "outside" / "config.yaml").resolve(),
        (tmp_path / "data-sibling" / "config.yaml").resolve(),
        kwargs["data_dir"] / ".." / "outside" / "config.yaml",
    ):
        with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
            render_systemd_unit(
                _service_template(), **{**kwargs, "config_path": config_path}
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

    apply_system_service_permissions(
        layout,
        SystemdServiceProfile.system(),
        releases=[layout.release("2.3.0")],
    )

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
    layout.root.mkdir(mode=0o700)
    layout.root.chmod(0o755)
    layout.releases.mkdir(mode=0o700)
    layout.data.mkdir(mode=0o700)
    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 501)
    with pytest.raises(LinuxInstallError, match="service_start_failed"):
        # No scoped release: this covers permission application failing, not
        # which trees are in scope.
        apply_system_service_permissions(layout, SystemdServiceProfile.system())

    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
    )
    monkeypatch.setattr("ori.installer.linux.os.fchown", lambda *_args: None)
    (layout.data / "escape").symlink_to(tmp_path / "outside")
    with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
        apply_system_service_permissions(
            layout,
            SystemdServiceProfile.system(),
            releases=[layout.release("2.3.0")],
        )
    assert layout.root.stat().st_mode & 0o777 == 0o755


def test_system_permissions_allow_only_configured_runtime_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with tempfile.TemporaryDirectory(
        prefix="ori-dac-", dir=_short_socket_temp_dir()
    ) as root:
        layout = InstallLayout.resolve(Path(root) / "ori")
        layout.releases.mkdir(parents=True)
        layout.data.mkdir()
        health_path = layout.data / "health.sock"
        unexpected_path = layout.data / "unexpected.sock"
        health_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unexpected_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        health_socket.bind(str(health_path))
        unexpected_socket.bind(str(unexpected_path))
        monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
        monkeypatch.setattr(
            "ori.installer.linux.pwd.getpwnam",
            lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
        )
        monkeypatch.setattr("ori.installer.linux.os.fchown", lambda *_args: None)
        try:
            with pytest.raises(LinuxInstallError, match="special files are forbidden"):
                apply_system_service_permissions(
                    layout,
                    SystemdServiceProfile.system(),
                    allowed_data_sockets=(health_path,),
                )
            unexpected_socket.close()
            unexpected_path.unlink()
            apply_system_service_permissions(
                layout,
                SystemdServiceProfile.system(),
                allowed_data_sockets=(health_path,),
            )
            assert health_path.exists()
        finally:
            health_socket.close()
            unexpected_socket.close()


def test_system_upgrade_preserves_access_and_reapplies_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    destination = layout.release("2.3.0")
    destination.mkdir(parents=True)
    _prepare(destination)
    layout.data.mkdir(mode=0o700)
    layout.root.chmod(0o750)
    layout.releases.chmod(0o750)
    observed_modes: list[tuple[int, int]] = []

    def apply_permissions(
        applied_layout: InstallLayout,
        _profile: SystemdServiceProfile,
        **_kwargs: object,
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
        service_profile=SystemdServiceProfile.system(),
    )
    assert observed_modes == [(0o750, 0o750)]


def _release_with_interpreter(layout: InstallLayout, version: str) -> Path:
    """A release for permission-plan tests, which do not run the probe.

    The interpreter is a plain file rather than a symlink to the running
    Python: an external symlink target is judged by the permission plan, and a
    real interpreter lives outside the install root by definition.
    """
    # Explicit modes rather than the ambient umask: on a private-user-group
    # host, umask 0002 makes a default mkdir group-writable and the installer
    # refuses such a tree. Fixtures must not depend on the umask the suite
    # happens to run under.
    layout.releases.mkdir(parents=True, mode=0o750, exist_ok=True)
    release = layout.release(version)
    interpreter = release / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True, mode=0o750)
    interpreter.write_bytes(b"python")
    interpreter.chmod(0o700)
    return release


def _startable_release(layout: InstallLayout, version: str) -> Path:
    """A release for tests that cross the rollback pre-check."""
    release = layout.release(version)
    _real_interpreter(release / "venv" / "bin" / "python")
    return release


def _as_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
    )
    monkeypatch.setattr("ori.installer.linux.os.fchown", lambda *_args: None)
    monkeypatch.setattr("ori.installer.linux.os.fchmod", lambda *_args: None)


def test_retiring_moves_a_release_out_of_the_selectable_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Retirement quarantines rather than deletes.

    An operator retiring a release to unblock an interpreter removal is making
    a sequencing decision. Losing the tree at the same moment would turn that
    into data loss, so deletion stays a separate act.
    """
    from ori.installer.linux import RETIRED_DIRNAME, list_releases, retire_release

    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.data.mkdir(parents=True)
    active = _release_with_interpreter(layout, "2.5.0")
    old = _release_with_interpreter(layout, "2.4.0")
    layout.current.symlink_to(active)
    monkeypatch.setattr("ori.installer.linux.os.chown", lambda *_args: None)

    destination = retire_release(layout, "2.4.0")

    assert not old.exists()
    assert destination == layout.root / RETIRED_DIRNAME / "2.4.0"
    assert (destination / "venv" / "bin" / "python").is_file()
    assert [entry["version"] for entry in list_releases(layout)] == ["2.5.0"]


def test_retiring_the_active_release_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ori.installer.linux import retire_release

    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.data.mkdir(parents=True)
    active = _release_with_interpreter(layout, "2.5.0")
    layout.current.symlink_to(active)
    monkeypatch.setattr("ori.installer.linux.os.chown", lambda *_args: None)

    with pytest.raises(LinuxInstallError, match="active release"):
        retire_release(layout, "2.5.0")
    assert active.is_dir()


def test_retirement_cannot_run_while_an_install_holds_the_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No argument can protect an in-progress install's rollback target.

    Neither command can see the other's state, so passing the target between
    them is not possible in production — an earlier version of this test did
    exactly that and proved nothing. Exclusion is the only mechanism that
    works, and it is what production actually has.
    """
    from ori.installer.linux import release_lifecycle_lock, retire_release

    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.data.mkdir(parents=True)
    _release_with_interpreter(layout, "2.4.0")

    with release_lifecycle_lock(layout):
        with pytest.raises(LinuxInstallError, match="already in progress|in progress"):
            retire_release(layout, "2.4.0")


def test_a_first_install_is_locked_before_the_root_exists(
    tmp_path: Path,
) -> None:
    """The hole an earlier placement left open.

    Locking the root's own descriptor cannot start before the root exists, so a
    first install held nothing. The moment it created the root, a second caller
    locked it and entered the same supposedly exclusive transaction.
    """
    from ori.installer.linux import release_lifecycle_lock

    layout = InstallLayout.resolve(tmp_path / "ori")
    assert not layout.root.exists()

    with release_lifecycle_lock(layout):
        layout.root.mkdir(parents=True)
        with pytest.raises(LinuxInstallError, match="in progress"):
            with release_lifecycle_lock(layout):
                pass


def test_roots_sharing_a_parent_do_not_block_each_other(tmp_path: Path) -> None:
    """`/opt` holds one install root today and could hold another.

    The lock is named for the root it guards, so exclusion stays per-root
    rather than becoming a lock on the directory installs happen to live in.
    """
    from ori.installer.linux import release_lifecycle_lock

    first = InstallLayout.resolve(tmp_path / "ori")
    second = InstallLayout.resolve(tmp_path / "ori-other")

    with release_lifecycle_lock(first):
        with release_lifecycle_lock(second):
            pass


def test_the_lock_is_released_so_a_later_command_can_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exclusion that never lets go is an outage, not a safeguard."""
    from ori.installer.linux import release_lifecycle_lock, retire_release

    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.data.mkdir(parents=True)
    _release_with_interpreter(layout, "2.4.0")

    with release_lifecycle_lock(layout):
        pass
    retire_release(layout, "2.4.0")
    assert not layout.release("2.4.0").exists()


def test_user_scope_retirement_is_refused_with_a_stable_error(
    tmp_path: Path,
) -> None:
    """It moves a root-owned tree between root-owned directories.

    A user-scope implementation is a different ownership model, not a smaller
    version of this one. Half-implementing it raised an uncaught PermissionError
    rather than an installer error the CLI can render.
    """
    from ori.installer.linux import retire_release

    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.data.mkdir(parents=True)
    _release_with_interpreter(layout, "2.4.0")

    with pytest.raises(LinuxInstallError, match="scope system"):
        retire_release(layout, "2.4.0", scope="user")
    assert layout.release("2.4.0").is_dir()


def test_a_symlinked_quarantine_directory_is_refused(
    tmp_path: Path,
) -> None:
    """os.replace through a symlinked quarantine would move a release outside.

    A plain mkdir(exist_ok=True) accepts an existing symlink, so the retirement
    destination could be anywhere the link points.
    """
    from ori.installer.linux import RETIRED_DIRNAME, retire_release

    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.data.mkdir(parents=True)
    _release_with_interpreter(layout, "2.4.0")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (layout.root / RETIRED_DIRNAME).symlink_to(elsewhere)

    with pytest.raises(LinuxInstallError):
        retire_release(layout, "2.4.0")
    assert layout.release("2.4.0").is_dir()
    assert not any(elsewhere.iterdir())


def test_retiring_something_that_is_not_a_release_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a canonical direct child of releases/ may be retired."""
    from ori.installer.linux import retire_release

    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.releases.mkdir(parents=True)
    monkeypatch.setattr("ori.installer.linux.os.chown", lambda *_args: None)

    with pytest.raises(LinuxInstallError):
        retire_release(layout, "never-installed")
    with pytest.raises(LinuxInstallError):
        retire_release(layout, "../data")


def test_retiring_the_same_release_twice_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second retirement would overwrite the quarantined copy."""
    from ori.installer.linux import retire_release

    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.data.mkdir(parents=True)
    _release_with_interpreter(layout, "2.4.0")
    monkeypatch.setattr("ori.installer.linux.os.chown", lambda *_args: None)
    retire_release(layout, "2.4.0")

    _release_with_interpreter(layout, "2.4.0")
    with pytest.raises(LinuxInstallError, match="already been retired"):
        retire_release(layout, "2.4.0")


def test_listing_does_not_change_what_it_reports(tmp_path: Path) -> None:
    """A read-only command must be read-only.

    `_active_release` unlinks a dangling `current` as part of resolving it,
    which is right inside an install transaction and wrong in a listing. On the
    bench Pi, running the listing removed the symlink it was asked to report.
    """
    from ori.installer.linux import list_releases

    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.releases.mkdir(parents=True)
    layout.current.symlink_to(layout.releases / "2.4.0")
    assert layout.current.is_symlink()

    list_releases(layout)

    assert layout.current.is_symlink(), "listing removed the dangling current link"


def test_listing_reports_which_release_is_active_and_has_an_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`has_interpreter` reports a file, and is named for that.

    It does not identify releases that block an upgrade — only the active
    rollback candidate is load-bearing, and whether that one starts is
    established by starting it at install time. Calling this field `runnable`
    would claim both things it does not check.
    """
    from ori.installer.linux import list_releases

    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.data.mkdir(parents=True)
    active = _release_with_interpreter(layout, "2.5.0")
    broken = layout.release("2.4.0")
    (broken / "venv" / "bin").mkdir(parents=True)
    (broken / "venv" / "bin" / "python").symlink_to(tmp_path / "gone" / "python")
    layout.current.symlink_to(active)

    entries = {entry["version"]: entry for entry in list_releases(layout)}
    assert entries["2.5.0"]["active"] is True
    assert entries["2.5.0"]["has_interpreter"] is True
    assert entries["2.4.0"]["active"] is False
    assert entries["2.4.0"]["has_interpreter"] is False


def test_a_stale_retained_release_cannot_block_an_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The defect: any retained release held a veto over every future install.

    A release whose interpreter lived outside the install root kept that
    reference after being superseded. Removing the interpreter — the documented
    order, after a later release is installed and healthy — then failed the
    external-symlink check for a tree nothing in the transaction referred to,
    and left the installation permanently un-upgradeable.
    """
    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.data.mkdir(parents=True)
    candidate = _release_with_interpreter(layout, "2.5.0")

    # A superseded release pointing at an interpreter that no longer exists.
    stale = layout.release("2.4.0")
    (stale / "venv" / "bin").mkdir(parents=True)
    (stale / "venv" / "bin" / "python").symlink_to(tmp_path / "removed" / "python")

    _as_root(monkeypatch)
    apply_system_service_permissions(
        layout, SystemdServiceProfile.system(), releases=[candidate]
    )


def test_the_rollback_candidate_is_in_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scoping to the candidate alone would leave the restore target unowned."""
    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.data.mkdir(parents=True)
    candidate = _release_with_interpreter(layout, "2.5.0")
    previous = _release_with_interpreter(layout, "2.4.0")

    planned: list[Path] = []
    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
    )
    monkeypatch.setattr(
        "ori.installer.linux._apply_permission_plan",
        lambda plan: planned.extend(change.path for change in plan),
    )
    apply_system_service_permissions(
        layout, SystemdServiceProfile.system(), releases=[candidate, previous]
    )
    assert previous / "venv" / "bin" / "python" in planned
    assert candidate / "venv" / "bin" / "python" in planned


def test_history_outside_the_scope_is_never_walked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inert history must not be searched, not merely tolerated."""
    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.data.mkdir(parents=True)
    candidate = _release_with_interpreter(layout, "2.5.0")
    history = _release_with_interpreter(layout, "2.3.0")

    planned: list[Path] = []
    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
    )
    monkeypatch.setattr(
        "ori.installer.linux._apply_permission_plan",
        lambda plan: planned.extend(change.path for change in plan),
    )
    apply_system_service_permissions(
        layout, SystemdServiceProfile.system(), releases=[candidate]
    )
    assert layout.releases in planned, "the releases directory itself is still owned"
    assert not any(str(path).startswith(str(history)) for path in planned), (
        "a release outside the transaction was walked"
    )


def test_reinstalling_the_active_version_does_not_plan_it_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The candidate and the rollback target are the same tree on a reinstall.

    Planning it twice would apply two permission changes to every file, and
    the second would record the first's result as the original to restore.
    """
    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.data.mkdir(parents=True)
    release = _release_with_interpreter(layout, "2.5.0")

    planned: list[Path] = []
    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
    )
    monkeypatch.setattr(
        "ori.installer.linux._apply_permission_plan",
        lambda plan: planned.extend(change.path for change in plan),
    )
    apply_system_service_permissions(
        layout, SystemdServiceProfile.system(), releases=[release, release]
    )
    interpreter = release / "venv" / "bin" / "python"
    assert planned.count(interpreter) == 1


def test_a_rollback_candidate_that_cannot_start_is_refused(
    tmp_path: Path,
) -> None:
    """An executable bit is not evidence that a release starts.

    On the bench Pi a file containing the text `not python` was accepted as a
    valid rollback candidate: it is a regular file, it has the executable bit,
    and it is not an interpreter. That is only discovered during a rollback,
    which is the one moment there is no remaining fallback.
    """
    from ori.installer.linux import _assert_release_starts

    impostor = tmp_path / "2.4.0"
    interpreter = impostor / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("not python\n", encoding="utf-8")
    interpreter.chmod(0o755)
    assert interpreter.is_file() and os.access(interpreter, os.X_OK)

    with pytest.raises(LinuxInstallError, match="does not start|could not be executed"):
        _assert_release_starts(impostor)


def test_a_real_release_passes_the_start_probe(tmp_path: Path) -> None:
    """The probe must not refuse a release that genuinely runs.

    A real venv, because that is what the probe is judging. A bare symlink to
    the running interpreter is not one — it has no `pyvenv.cfg`, so it cannot
    see the packages the release would ship, and it would fail for a reason
    the probe is not testing for.
    """
    from ori.installer.linux import _assert_release_starts

    release = tmp_path / "2.5.0"
    subprocess.run(
        [sys.executable, "-m", "venv", "--system-site-packages", str(release / "venv")],
        check=True,
        capture_output=True,
    )
    version_dir = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site_packages = release / "venv" / "lib" / version_dir / "site-packages"
    site_packages.mkdir(parents=True, exist_ok=True)
    (site_packages / "ori-under-test.pth").write_text(
        str(Path(sys.prefix) / "lib" / version_dir / "site-packages") + "\n",
        encoding="utf-8",
    )

    _assert_release_starts(release)


def test_the_probe_runs_the_release_captured_at_the_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not a fresh read of `current`.

    `current` is moved between capture and preflight. Without that the test
    cannot tell a captured value from a re-read that happens to agree, which
    is the whole difference being asserted.
    """
    probed: list[Path] = []
    monkeypatch.setattr(
        "ori.installer.linux._assert_release_starts",
        lambda release: probed.append(release),
    )

    layout = InstallLayout.resolve(tmp_path / "ori")
    # The root is created with an explicit private mode rather than inheriting
    # the ambient umask. On a private-user-group host, umask 0002 makes a
    # default mkdir group-writable, and the installer refuses such a root — as
    # it should. That is a fixture detail, not what this test is about.
    layout.root.mkdir(parents=True, mode=0o750)
    layout.data.mkdir(mode=0o700)
    captured = _release_with_interpreter(layout, "2.4.0")
    decoy = _release_with_interpreter(layout, "2.3.0")
    layout.current.symlink_to(captured)

    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
    )
    monkeypatch.setattr(
        "ori.installer.linux._apply_permission_plan", lambda _plan: None
    )

    def prepare(staging: Path) -> None:
        interpreter = staging / "venv" / "bin" / "python"
        interpreter.parent.mkdir(parents=True)
        interpreter.write_bytes(b"python")
        interpreter.chmod(0o700)
        # Repoint `current` after the transaction captured it.
        layout.current.unlink()
        layout.current.symlink_to(decoy)

    # 2.5.0 is deliberately not pre-created: an existing destination skips
    # staging entirely, and `prepare` would never run.
    install_release(
        layout=layout,
        version="2.5.0",
        prepare=prepare,
        validate=lambda _path: None,
        restart_service=lambda: None,
        stop_service=lambda: None,
        check_health=lambda _path: None,
        service_profile=SystemdServiceProfile.system(),
    )

    assert layout.current.resolve() != captured, "the hook did not move `current`"
    assert probed == [captured], (
        f"probed {probed} rather than the release captured at the start"
    )


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
        # No scoped release: this covers permission application failing, not
        # which trees are in scope.
        apply_system_service_permissions(layout, SystemdServiceProfile.system())
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

    apply_system_service_permissions(
        layout,
        SystemdServiceProfile.system(),
        releases=[layout.release("2.3.0")],
    )

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
    host_euid = os.geteuid()
    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1002),
    )
    monkeypatch.setattr("ori.installer.linux.os.fchown", lambda *_args: None)

    with pytest.raises(LinuxInstallError, match="unsafe_install_root"):
        apply_system_service_permissions(
            layout,
            SystemdServiceProfile.system(),
            releases=[layout.release("2.3.0")],
        )

    (release / "lib64").unlink()
    external_python = tmp_path / "python"
    external_python.write_bytes(b"python")
    external_python.chmod(0o755)
    if host_euid == 0:
        os.chown(external_python, 65534, 65534)
    (release / "python").symlink_to(external_python)
    with pytest.raises(
        LinuxInstallError, match="external release symlink target is not trusted"
    ):
        apply_system_service_permissions(
            layout,
            SystemdServiceProfile.system(),
            releases=[layout.release("2.3.0")],
        )


def test_permission_failure_removes_new_release_before_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    monkeypatch.setattr(
        "ori.installer.linux.apply_system_service_permissions",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
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
            service_profile=SystemdServiceProfile.system(),
        )
    assert not layout.release("2.3.0").exists()
    assert not layout.current.exists()


def test_installer_config_is_validated_by_runtime_bridge_and_written_privately(
    tmp_path: Path,
) -> None:
    config_path = (tmp_path / "data" / "ori.yaml").resolve()
    socket_path = (tmp_path / "data" / "health.sock").resolve()
    provision_runtime_config(
        values=InstallerConfigInput(
            device_id="ori-lagos-01",
            name="Lagos Office",
            location="Lagos, Nigeria",
            deployment_type="server",
        ),
        config_path=config_path,
        release_python=Path(sys.executable),
        health_socket_path=socket_path,
    )
    loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert loaded["device"] == {
        "id": "ori-lagos-01",
        "name": "Lagos Office",
        "location": "Lagos, Nigeria",
        "deployment_type": "server",
        "deployment_profile": "development",
    }
    assert loaded["health_socket"]["path"] == str(socket_path)
    assert loaded["actions"]["sms"]["enabled"] is False
    assert config_path.stat().st_mode & 0o777 == 0o600
    assert list(config_path.parent.glob(".ori.yaml.*.tmp")) == []


def test_config_parent_uses_managed_directory_policy_under_umask_0002(
    tmp_path: Path,
) -> None:
    config_path = (tmp_path / "data" / "ori.yaml").resolve()
    previous_umask = os.umask(0o002)
    try:
        provision_runtime_config(
            values=InstallerConfigInput("ori-01", "Office", "Lagos"),
            config_path=config_path,
            release_python=Path(sys.executable),
            health_socket_path=config_path.parent / "health.sock",
        )
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(config_path.parent.stat().st_mode) == 0o700


def test_config_parent_refuses_group_writable_directory_without_mutation(
    tmp_path: Path,
) -> None:
    config_path = (tmp_path / "data" / "ori.yaml").resolve()
    config_path.parent.mkdir(mode=0o700)
    config_path.parent.chmod(0o775)

    with pytest.raises(LinuxInstallError) as raised:
        provision_runtime_config(
            values=InstallerConfigInput("ori-01", "Office", "Lagos"),
            config_path=config_path,
            release_python=Path(sys.executable),
            health_socket_path=config_path.parent / "health.sock",
        )

    assert raised.value.code == "config_validation_failed"
    assert stat.S_IMODE(config_path.parent.stat().st_mode) == 0o775
    assert not config_path.exists()


def test_successful_config_provision_can_restore_previous_content_and_mode(
    tmp_path: Path,
) -> None:
    config_path = (tmp_path / "data" / "ori.yaml").resolve()
    config_path.parent.mkdir(mode=0o700)
    config_path.write_text("previous\n", encoding="utf-8")
    config_path.chmod(0o640)

    rollback = provision_runtime_config(
        values=InstallerConfigInput("ori-01", "Office", "Lagos"),
        config_path=config_path,
        release_python=Path(sys.executable),
        health_socket_path=config_path.parent / "health.sock",
    )
    rollback()

    assert config_path.read_text(encoding="utf-8") == "previous\n"
    assert config_path.stat().st_mode & 0o777 == 0o640


def test_system_config_is_owned_by_service_identity_without_ordering_dependency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = (tmp_path / "data" / "ori.yaml").resolve()
    ownership: list[tuple[int, int]] = []
    monkeypatch.setattr("ori.installer.linux.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda _user: SimpleNamespace(pw_uid=991, pw_gid=992),
    )
    monkeypatch.setattr(
        "ori.installer.linux.os.fchown",
        lambda _descriptor, uid, gid: ownership.append((uid, gid)),
    )

    provision_runtime_config(
        values=InstallerConfigInput("ori-01", "Office", "Lagos"),
        config_path=config_path,
        release_python=Path(sys.executable),
        health_socket_path=config_path.parent / "health.sock",
        service_profile=SystemdServiceProfile.system(),
    )

    assert ownership == [(991, 992)]
    assert config_path.stat().st_mode & 0o777 == 0o600


def test_config_health_socket_must_share_writable_data_directory(
    tmp_path: Path,
) -> None:
    with pytest.raises(LinuxInstallError, match="writable config data directory"):
        provision_runtime_config(
            values=InstallerConfigInput("ori-01", "Office", "Lagos"),
            config_path=(tmp_path / "data" / "ori.yaml").resolve(),
            release_python=Path(sys.executable),
            health_socket_path=(tmp_path / "run" / "health.sock").resolve(),
        )


def test_config_destination_error_uses_stable_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        installer_linux,
        "_ensure_private_directory",
        lambda _path: (_ for _ in ()).throw(
            LinuxInstallError("unsafe_install_root", "denied")
        ),
    )
    with pytest.raises(LinuxInstallError) as raised:
        provision_runtime_config(
            values=InstallerConfigInput("ori-01", "Office", "Lagos"),
            config_path=(tmp_path / "data" / "ori.yaml").resolve(),
            release_python=Path(sys.executable),
            health_socket_path=(tmp_path / "data" / "health.sock").resolve(),
        )
    assert raised.value.code == "config_validation_failed"


def test_invalid_generated_config_preserves_existing_file(tmp_path: Path) -> None:
    config_path = (tmp_path / "data" / "ori.yaml").resolve()
    config_path.parent.mkdir(mode=0o700)
    config_path.write_text("existing\n", encoding="utf-8")

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 2, '{"ok":false}', "secret detail")

    with pytest.raises(LinuxInstallError, match="config_validation_failed"):
        provision_runtime_config(
            values=InstallerConfigInput("ori-01", "Office", "Lagos"),
            config_path=config_path,
            release_python=Path(sys.executable).resolve(),
            health_socket_path=(tmp_path / "data" / "health.sock").resolve(),
            runner=runner,
        )
    assert config_path.read_text(encoding="utf-8") == "existing\n"
    assert list(config_path.parent.glob(".ori.yaml.*.tmp")) == []


@pytest.mark.parametrize(
    ("kwargs", "detail"),
    [
        (
            {"device_id": "bad id", "name": "Office", "location": "Lagos"},
            "device ID must be 1-64 lowercase letters.*starting with a letter or digit",
        ),
        ({"device_id": "ori-01", "name": "${SECRET}", "location": "Lagos"}, "name"),
        (
            {"device_id": "ori-01", "name": "Office", "location": "Lagos\nroot"},
            "location",
        ),
    ],
)
def test_installer_config_rejects_unsafe_operator_values(
    kwargs: dict[str, str], detail: str
) -> None:
    with pytest.raises(LinuxInstallError, match=detail):
        InstallerConfigInput(**kwargs)  # type: ignore[arg-type]


def test_config_validator_requires_exact_success_envelope(tmp_path: Path) -> None:
    for stdout in (
        "not-json",
        '{"schema_version":1,"ok":true}',
        '{"schema_version":2,"ok":true,"command":"config validate","result":{"valid":true}}',
    ):
        with pytest.raises(LinuxInstallError, match="config_validation_failed"):
            provision_runtime_config(
                values=InstallerConfigInput("ori-01", "Office", "Lagos"),
                config_path=(tmp_path / "ori.yaml").resolve(),
                release_python=Path(sys.executable).resolve(),
                health_socket_path=(tmp_path / "health.sock").resolve(),
                runner=lambda command, output=stdout: subprocess.CompletedProcess(
                    command, 0, output, ""
                ),
            )


def test_config_directory_sync_failure_restores_previous_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = (tmp_path / "data" / "ori.yaml").resolve()
    config_path.parent.mkdir(mode=0o700)
    config_path.write_text("existing\n", encoding="utf-8")
    config_path.chmod(0o640)
    real_fsync = os.fsync
    calls = 0

    def fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("directory sync failed")
        real_fsync(descriptor)

    monkeypatch.setattr("ori.installer.linux.os.fsync", fsync)
    with pytest.raises(LinuxInstallError, match="config_validation_failed"):
        provision_runtime_config(
            values=InstallerConfigInput("ori-01", "Office", "Lagos"),
            config_path=config_path,
            release_python=Path(sys.executable),
            health_socket_path=(tmp_path / "data" / "health.sock").resolve(),
        )
    assert config_path.read_text(encoding="utf-8") == "existing\n"
    assert config_path.stat().st_mode & 0o777 == 0o640
    assert list(config_path.parent.iterdir()) == [config_path]


def _real_venv_prepare(path: Path) -> None:
    """Build a venv whose entry points are genuinely executable shell scripts.

    They must run from the final release directory, so the shebang has to be
    rebound when the tree moves — exactly what pip-installed console scripts do.
    """
    bin_dir = path / "venv" / "bin"
    bin_dir.mkdir(parents=True)
    interpreter = bin_dir / "python"
    # Symlinked like a real venv interpreter, so the shebang resolves to a
    # genuine signed binary. The repair must leave symlinks alone.
    interpreter.symlink_to("/bin/sh")
    for name in ENTRY_POINTS:
        script = bin_dir / name
        script.write_text(f"#!{interpreter}\n# console script\n", encoding="utf-8")
        script.chmod(0o755)


def _install(layout: InstallLayout, version: str, **overrides: object) -> object:
    arguments: dict[str, object] = {
        "layout": layout,
        "version": version,
        "prepare": _real_venv_prepare,
        "validate": lambda _path: None,
        "restart_service": lambda: None,
        "stop_service": lambda: None,
        "check_health": lambda _path: None,
    }
    arguments.update(overrides)
    return install_release(**arguments)  # type: ignore[arg-type]


def test_every_entry_point_executes_from_the_final_release_directory(
    tmp_path: Path,
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    _install(layout, "2.3.1")

    bin_dir = layout.release("2.3.1") / "venv" / "bin"
    for name in ENTRY_POINTS:
        completed = subprocess.run(
            [str(bin_dir / name), "--help"], capture_output=True, check=False
        )
        assert completed.returncode == 0, (
            f"{name} did not execute: {completed.stderr.decode()!r}"
        )


def test_no_entry_point_retains_a_staging_shebang(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    _install(layout, "2.3.1")

    release = layout.release("2.3.1")
    expected = f"#!{release / 'venv' / 'bin' / 'python'}"
    for name in ENTRY_POINTS:
        first = (
            (release / "venv" / "bin" / name)
            .read_text(encoding="utf-8")
            .splitlines()[0]
        )
        assert ".staging" not in first
        assert first == expected


def test_failed_shebang_repair_leaves_no_orphan_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")

    def refuse(_staging: Path, _destination: Path) -> None:
        raise LinuxInstallError("offline_install_failed", "induced repair failure")

    monkeypatch.setattr("ori.installer.linux._repair_relocated_shebangs", refuse)
    with pytest.raises(LinuxInstallError, match="induced repair failure"):
        _install(layout, "2.3.1")

    assert not layout.release("2.3.1").exists()
    assert not layout.releases.exists()
    assert not layout.root.exists()
    assert not layout.current.exists()


def test_repair_is_idempotent_across_reinstalls(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    first = _install(layout, "2.3.1")
    repeated = _install(layout, "2.3.1")

    assert first.changed is True  # type: ignore[attr-defined]
    assert repeated.changed is False  # type: ignore[attr-defined]
    entry = layout.release("2.3.1") / "venv" / "bin" / "ori-install-linux"
    assert subprocess.run([str(entry), "--help"], check=False).returncode == 0


def test_a_retained_release_keeps_its_own_interpreter(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")
    _install(layout, "2.3.1")
    _install(layout, "2.4.0")

    for version in ("2.3.1", "2.4.0"):
        release = layout.release(version)
        first = (
            (release / "venv" / "bin" / "ori-runtime")
            .read_text(encoding="utf-8")
            .splitlines()[0]
        )
        # Upgrading must not rebind an older release onto the new interpreter.
        assert first == f"#!{release / 'venv' / 'bin' / 'python'}"
        assert (
            subprocess.run(
                [str(release / "venv" / "bin" / "ori-runtime"), "--help"], check=False
            ).returncode
            == 0
        )


def test_unexpected_staging_reference_is_refused(tmp_path: Path) -> None:
    layout = InstallLayout.resolve(tmp_path / "ori")

    def prepare(path: Path) -> None:
        _real_venv_prepare(path)
        rogue = path / "venv" / "bin" / "rogue"
        rogue.write_text(f"#!{path}/elsewhere/python\n", encoding="utf-8")
        rogue.chmod(0o755)

    with pytest.raises(LinuxInstallError, match="offline_install_failed"):
        _install(layout, "2.3.1", prepare=prepare)
    assert not layout.release("2.3.1").exists()


@pytest.mark.slow
def test_real_packaged_commands_start_from_the_final_release(tmp_path: Path) -> None:
    """Run the actual packaged CLIs, not synthetic stand-ins.

    The synthetic test proves shebang relocation; this proves the six real
    commands start with their full locked dependency set from the final path.
    """
    wheelhouse = tmp_path / "wheelhouse"
    build = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", ".", "-w", str(wheelhouse)],
        capture_output=True,
        text=True,
        check=False,
    )
    # Skipping on a setup failure would let the release gate pass without ever
    # running the six commands — the false green this test exists to prevent.
    assert build.returncode == 0, f"wheel build failed:\n{build.stderr[-2000:]}"
    wheels = sorted(wheelhouse.glob("ori_runtime-*.whl"))
    assert len(wheels) == 1, f"expected exactly one built wheel, found {wheels}"
    wheel = wheels[0]

    def prepare(staging: Path) -> None:
        created = subprocess.run(
            [sys.executable, "-m", "venv", str(staging / "venv")],
            capture_output=True,
            text=True,
            check=False,
        )
        assert created.returncode == 0, (
            f"venv creation failed:\n{created.stderr[-2000:]}"
        )
        python = staging / "venv" / "bin" / "python"
        install = subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--quiet",
                "--require-hashes",
                "-r",
                "requirements/runtime.txt",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert install.returncode == 0, (
            f"locked dependency install failed:\n{install.stderr[-2000:]}"
        )
        packaged = subprocess.run(
            [str(python), "-m", "pip", "install", "--quiet", "--no-deps", str(wheel)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert packaged.returncode == 0, (
            f"wheel install failed:\n{packaged.stderr[-2000:]}"
        )

    layout = InstallLayout.resolve(tmp_path / "ori")
    install_release(
        layout=layout,
        version="2.3.1",
        prepare=prepare,
        validate=lambda _path: None,
        restart_service=lambda: None,
        stop_service=lambda: None,
        check_health=lambda _path: None,
    )

    bin_dir = layout.release("2.3.1") / "venv" / "bin"
    for name in ENTRY_POINTS:
        completed = subprocess.run(
            [str(bin_dir / name), "--help"], capture_output=True, text=True, check=False
        )
        assert completed.returncode == 0, (
            f"{name} did not start: {completed.stderr[-300:]!r}"
        )

    # Nothing under bin/ may still name the staging directory, including the
    # generated activation scripts.
    for entry in bin_dir.iterdir():
        if entry.is_symlink() or not entry.is_file():
            continue
        assert ".staging" not in entry.read_bytes().decode("utf-8", "ignore"), (
            entry.name
        )


def test_long_path_sh_wrapper_form_is_rebound(tmp_path: Path) -> None:
    """pip emits a `#!/bin/sh` re-exec wrapper when the shebang would be too long.

    Linux caps shebangs at 127 bytes, so a long install root produces this form
    and the interpreter lives on line 2. Rewriting only line 1 leaves it stale.
    """

    def prepare(staging: Path) -> None:
        _real_venv_prepare(staging)
        interpreter = staging / "venv" / "bin" / "python"
        wrapper = staging / "venv" / "bin" / "long-form"
        wrapper.write_text(
            f"#!/bin/sh\n'''exec' {interpreter} \"$0\" \"$@\"\n' '''\nexit 0\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

    layout = InstallLayout.resolve(tmp_path / "ori")
    _install(layout, "2.3.1", prepare=prepare)

    release = layout.release("2.3.1")
    wrapper = release / "venv" / "bin" / "long-form"
    body = wrapper.read_text(encoding="utf-8")

    assert ".staging" not in body
    assert str(release / "venv" / "bin" / "python") in body
    # Not executed here: the stand-in interpreter is a /bin/sh symlink, so the
    # re-exec would recurse. Real execution of this form is covered by the six
    # packaged commands in the wheel-installed test.


# --- the system service account -------------------------------------------


def _absent_account(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda name: (_ for _ in ()).throw(KeyError(name)),
    )


def test_account_creation_requires_root(monkeypatch: pytest.MonkeyPatch) -> None:
    _absent_account(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    with pytest.raises(LinuxInstallError, match="requires root") as error:
        ensure_service_account(SystemdServiceProfile.system(), unattended=True)

    # The operator gets the command, not just the diagnosis.
    assert "useradd" in error.value.detail
    assert "--scope user" in error.value.detail


def test_account_creation_without_useradd_names_the_manual_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _absent_account(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr("ori.installer.linux._trusted_useradd", lambda: None)

    with pytest.raises(LinuxInstallError, match="useradd is not available") as error:
        ensure_service_account(SystemdServiceProfile.system(), unattended=True)

    assert "sudo useradd --system --no-create-home" in error.value.detail


def test_declining_account_creation_stops_the_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ "No" means do not change my system — never "continue without it".

    Proceeding would produce a unit whose User= does not exist, which fails at
    service start rather than here, where the remedy is still in front of you.
    """
    _absent_account(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux._trusted_useradd", lambda: "/usr/sbin/useradd"
    )
    monkeypatch.setattr(
        "ori.installer.linux._run_account_command",
        lambda _c: pytest.fail("must not create an account after a refusal"),
    )

    with pytest.raises(LinuxInstallError, match="is required for a system") as error:
        ensure_service_account(
            SystemdServiceProfile.system(),
            unattended=False,
            prompt=lambda _p: "n",
            write=lambda _s: None,
        )

    assert "sudo useradd" in error.value.detail


def test_account_creation_is_confirmed_against_the_account_not_the_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A zero exit is the tool's opinion; the account is the fact.

    Believing the exit code defers the failure to service start, by which point
    the installation looks complete.
    """
    _absent_account(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux._trusted_useradd", lambda: "/usr/sbin/useradd"
    )
    monkeypatch.setattr(
        "ori.installer.linux._run_account_command",
        lambda command: subprocess.CompletedProcess(list(command), 0, "", ""),
    )

    with pytest.raises(LinuxInstallError, match="could not create"):
        ensure_service_account(SystemdServiceProfile.system(), unattended=True)


def test_user_scope_never_touches_system_accounts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ori.installer.linux._run_account_command",
        lambda _c: pytest.fail("user scope must not create an account"),
    )

    assert (
        ensure_service_account(SystemdServiceProfile.user(), unattended=True) is False
    )


def test_an_existing_account_is_adopted_without_being_touched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Adopting an identity is not licence to reshape it.

    Every precondition for creating one is satisfied here — root, useradd
    present, unattended — so the only thing standing between this call and a
    `useradd` invocation is the account already existing.
    """
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda name: SimpleNamespace(pw_name=name, pw_uid=4242, pw_gid=4242),
    )
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux._trusted_useradd", lambda: "/usr/sbin/useradd"
    )
    monkeypatch.setattr(
        "ori.installer.linux._run_account_command",
        lambda _c: pytest.fail("an existing account must not be modified"),
    )

    created = ensure_service_account(
        SystemdServiceProfile.system(),
        unattended=True,
        write=lambda _s: None,
    )

    assert created is False


def test_cleanup_removes_every_empty_directory_it_created(tmp_path: Path) -> None:
    """One surviving directory must not strand its empty siblings.

    A failure that leaves an operator's config in `data/` should still take the
    empty `releases/` with it; the root then stays because it genuinely still
    holds something.
    """
    root = tmp_path / "ori"
    releases, data = root / "releases", root / "data"
    for directory in (root, releases, data):
        directory.mkdir()
    (data / "ori.yaml").write_text("device: {}\n", encoding="utf-8")
    created = []
    for directory in (root, releases, data):
        info = directory.stat()
        created.append(
            installer_linux._CreatedDirectory(
                path=directory,
                device=info.st_dev,
                inode=info.st_ino,
            )
        )

    installer_linux._remove_created_scaffolding(created)

    assert not releases.exists()
    assert data.exists(), "operator data must never be removed by cleanup"
    assert root.exists(), "a root still holding data must stay"


def test_an_existing_account_with_uid_zero_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An `ori-runtime` that resolves to root defeats the point of system scope.

    Doctor rejects uid 0, but only once the unit is installed and started — by
    which time the service has already run as root. Name resolution alone is
    not evidence that an account is unprivileged.
    """
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda name: SimpleNamespace(pw_name=name, pw_uid=0, pw_gid=0),
    )
    monkeypatch.setattr(
        "ori.installer.linux._run_account_command",
        lambda _c: pytest.fail("nothing may be built on a root-owned identity"),
    )

    with pytest.raises(LinuxInstallError, match="uid 0") as error:
        ensure_service_account(SystemdServiceProfile.system(), unattended=True)

    assert "--scope user" in error.value.detail


def test_a_created_account_is_verified_to_be_unprivileged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The check after creation must prove the same property as the one before.

    A host tool that hands back uid 0 satisfies "the name now resolves" while
    producing exactly the account system scope exists to avoid.
    """
    state = {"created": False}

    def getpwnam(name: str) -> object:
        if not state["created"]:
            raise KeyError(name)
        return SimpleNamespace(pw_name=name, pw_uid=0, pw_gid=0)

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr("ori.installer.linux.pwd.getpwnam", getpwnam)
    monkeypatch.setattr(
        "ori.installer.linux._trusted_useradd", lambda: "/usr/sbin/useradd"
    )

    def useradd(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        state["created"] = True
        return subprocess.CompletedProcess(list(command), 0, "", "")

    monkeypatch.setattr("ori.installer.linux._run_account_command", useradd)

    with pytest.raises(LinuxInstallError, match="uid 0"):
        ensure_service_account(
            SystemdServiceProfile.system(), unattended=True, write=lambda _s: None
        )


def test_useradd_is_never_taken_from_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """This runs as root, so `PATH` must not decide what is executed.

    A writable directory ahead of the system ones on root's `PATH` would
    otherwise choose the binary, and the installer would run it with full
    privilege.
    """
    attacker = tmp_path / "bin"
    attacker.mkdir()
    planted = attacker / "useradd"
    planted.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    planted.chmod(0o755)
    monkeypatch.setenv("PATH", f"{attacker}:/usr/sbin:/sbin")

    resolved = installer_linux._trusted_useradd()

    assert resolved != str(planted)
    assert resolved is None or resolved in installer_linux._USERADD_LOCATIONS


@pytest.mark.parametrize(
    ("uid", "mode", "trusted", "why"),
    [
        (0, 0o755, True, "root-owned and writable only by root"),
        (0, 0o775, False, "group-writable, so not only root could have put it there"),
        (0, 0o757, False, "world-writable"),
        (1000, 0o755, False, "owned by somebody other than root"),
        (1000, 0o700, False, "unwritable by others, but still not root's"),
    ],
)
def test_a_useradd_is_trusted_only_when_root_alone_could_have_placed_it(
    monkeypatch: pytest.MonkeyPatch, uid: int, mode: int, trusted: bool, why: str
) -> None:
    """Each condition is isolated, so one guard cannot cover for the other.

    A root-owned but group-writable binary and a well-permissioned one owned by
    somebody else are both substitutions; a test that only supplies files
    failing on both counts passes whichever guard is removed.
    """
    candidate = "/usr/sbin/useradd"
    _fake_filesystem(
        monkeypatch,
        {
            "/": _ROOT_DIR,
            "/usr": _ROOT_DIR,
            "/usr/sbin": _ROOT_DIR,
            candidate: (stat.S_IFREG | mode, uid),
        },
    )

    resolved = installer_linux._trusted_useradd()

    assert (resolved == candidate) is trusted, why


_ROOT_DIR = (stat.S_IFDIR | 0o755, 0)
_SAFE_BINARY = (stat.S_IFREG | 0o755, 0)


def _fake_filesystem(
    monkeypatch: pytest.MonkeyPatch,
    entries: dict[str, tuple[int, int]],
    *,
    links: dict[str, str] | None = None,
) -> None:
    """Install a synthetic tree so each component's mode can be stated exactly.

    Real directories cannot be used: the cases that matter are root-owned ones,
    and creating those needs root, which the suite must not require.
    """

    def lookup(path: object, **_kwargs: object) -> SimpleNamespace:
        key = str(path)
        if key not in entries:
            raise FileNotFoundError(key)
        mode, uid = entries[key]
        return SimpleNamespace(st_mode=mode, st_uid=uid, st_dev=1, st_ino=hash(key))

    def readlink(path: object) -> str:
        key = str(path)
        if (links or {}).get(key) is None:
            raise OSError(22, "Invalid argument", key)
        return (links or {})[key]

    monkeypatch.setattr(trusted_paths.os, "lstat", lookup)
    monkeypatch.setattr(trusted_paths.os, "readlink", readlink)
    monkeypatch.setattr(
        installer_linux, "_USERADD_LOCATIONS", ("/usr/sbin/useradd",), raising=True
    )


def test_a_useradd_under_root_controlled_directories_is_trusted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The safe case, so the unsafe ones below are not passing by accident."""
    _fake_filesystem(
        monkeypatch,
        {
            "/": _ROOT_DIR,
            "/usr": _ROOT_DIR,
            "/usr/sbin": _ROOT_DIR,
            "/usr/sbin/useradd": _SAFE_BINARY,
        },
    )

    assert installer_linux._trusted_useradd() == "/usr/sbin/useradd"


@pytest.mark.parametrize(
    ("parent", "why"),
    [
        ((stat.S_IFDIR | 0o775, 0), "group-writable parent"),
        ((stat.S_IFDIR | 0o777, 0), "world-writable parent"),
        ((stat.S_IFDIR | 0o755, 1000), "parent owned by another account"),
    ],
)
def test_a_useradd_beneath_an_unsafe_parent_is_not_trusted(
    monkeypatch: pytest.MonkeyPatch, parent: tuple[int, int], why: str
) -> None:
    """Replacing a file needs write on its directory, not on the file.

    The executable here is impeccable — regular, root-owned, 0755. Judging it
    alone would call an account that can rename it out from under the installer
    trustworthy.
    """
    _fake_filesystem(
        monkeypatch,
        {
            "/": _ROOT_DIR,
            "/usr": _ROOT_DIR,
            "/usr/sbin": parent,
            "/usr/sbin/useradd": _SAFE_BINARY,
        },
    )

    assert installer_linux._trusted_useradd() is None, why


def test_an_unsafe_grandparent_is_caught_as_well(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control has to hold the whole way down, not just at the last step."""
    _fake_filesystem(
        monkeypatch,
        {
            "/": _ROOT_DIR,
            "/usr": (stat.S_IFDIR | 0o777, 0),
            "/usr/sbin": _ROOT_DIR,
            "/usr/sbin/useradd": _SAFE_BINARY,
        },
    )

    assert installer_linux._trusted_useradd() is None


def test_a_root_owned_symlink_component_does_not_disqualify_a_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A link's own mode grants nothing; Linux reports every one as 0777."""
    _fake_filesystem(
        monkeypatch,
        {
            "/": _ROOT_DIR,
            "/usr": _ROOT_DIR,
            "/usr/sbin": _ROOT_DIR,
            "/usr/sbin/useradd": (stat.S_IFLNK | 0o777, 0),
            "/usr/sbin/useradd.real": _SAFE_BINARY,
        },
        links={"/usr/sbin/useradd": "/usr/sbin/useradd.real"},
    )

    assert installer_linux._trusted_useradd() == "/usr/sbin/useradd"


def test_a_symlink_component_owned_by_another_account_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ownership still counts, even where the mode bits do not."""
    _fake_filesystem(
        monkeypatch,
        {
            "/": _ROOT_DIR,
            "/usr": _ROOT_DIR,
            "/usr/sbin": _ROOT_DIR,
            "/usr/sbin/useradd": (stat.S_IFLNK | 0o777, 1000),
            "/usr/sbin/useradd.real": _SAFE_BINARY,
        },
        links={"/usr/sbin/useradd": "/usr/sbin/useradd.real"},
    )

    assert installer_linux._trusted_useradd() is None


def test_a_symlink_landing_under_an_unsafe_directory_is_not_trusted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A safe name may still resolve somewhere anyone can rewrite."""
    _fake_filesystem(
        monkeypatch,
        {
            "/": _ROOT_DIR,
            "/usr": _ROOT_DIR,
            "/usr/sbin": _ROOT_DIR,
            "/usr/sbin/useradd": (stat.S_IFLNK | 0o777, 0),
            "/opt": (stat.S_IFDIR | 0o777, 0),
            "/opt/useradd": _SAFE_BINARY,
        },
        links={"/usr/sbin/useradd": "/opt/useradd"},
    )

    assert installer_linux._trusted_useradd() is None


def test_a_useradd_that_is_not_a_regular_file_is_not_trusted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directory or device in that position is not a binary to execute."""
    _fake_filesystem(
        monkeypatch,
        {
            "/": _ROOT_DIR,
            "/usr": _ROOT_DIR,
            "/usr/sbin": _ROOT_DIR,
            "/usr/sbin/useradd": (stat.S_IFDIR | 0o755, 0),
        },
    )

    assert installer_linux._trusted_useradd() is None


def test_a_useradd_that_is_not_executable_is_not_trusted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_filesystem(
        monkeypatch,
        {
            "/": _ROOT_DIR,
            "/usr": _ROOT_DIR,
            "/usr/sbin": _ROOT_DIR,
            "/usr/sbin/useradd": (stat.S_IFREG | 0o644, 0),
        },
    )

    assert installer_linux._trusted_useradd() is None


def test_a_hung_useradd_reports_a_stable_code_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`TimeoutExpired` is a SubprocessError, not an OSError.

    Left uncaught it travels past `main`, which maps only the installer's own
    error types, and reaches the operator as a traceback carrying no remedy.
    """
    _absent_account(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        installer_linux, "_trusted_useradd", lambda: "/usr/sbin/useradd"
    )

    def hangs(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(list(command), 30)

    with pytest.raises(LinuxInstallError) as error:
        ensure_service_account(
            SystemdServiceProfile.system(), unattended=True, runner=hangs
        )

    assert error.value.code == "service_start_failed"
    assert "timed out" in error.value.detail
    assert "sudo useradd" in error.value.detail


def test_a_partially_created_scaffolding_is_still_cleaned_up(
    tmp_path: Path,
) -> None:
    """Cleanup must know about directories made before the failing one.

    A pre-existing root with an unsafe `data` creates `releases/` and then
    raises. Recording the created directories only after the last one would
    leave that `releases/` behind with nothing aware it had been made.
    """
    root = tmp_path / "ori"
    root.mkdir(mode=0o700)
    (tmp_path / "elsewhere").mkdir()
    (root / "data").symlink_to(tmp_path / "elsewhere")
    layout = InstallLayout.resolve(root)

    with pytest.raises(LinuxInstallError, match="symlink"):
        install_release(
            layout=layout,
            version="2.4.0-rc.4",
            prepare=lambda _p: None,
            validate=lambda _p: None,
            restart_service=lambda: None,
            stop_service=lambda: None,
            check_health=lambda _p: None,
        )

    assert not (root / "releases").exists()
    assert root.exists(), "a root this run did not create must never be removed"


def test_uninstall_leaves_the_service_account_in_place(tmp_path: Path) -> None:
    """Files outside the install root may belong to it, and uids get reused.

    Asserted by running the uninstall rather than by reading it: a check that
    the source does not contain "userdel" passes just as happily when the
    removal moves behind a helper with another name.
    """
    layout = InstallLayout.resolve(tmp_path / "ori")
    layout.releases.mkdir(parents=True)
    (layout.releases / "2.4.0-rc.4").mkdir()
    layout.data.mkdir(parents=True, exist_ok=True)
    account_commands: list[Sequence[str]] = []

    with mock.patch.object(
        installer_linux, "_run_account_command", side_effect=account_commands.append
    ):
        uninstall_runtime(layout=layout, stop_service=lambda: None)

    assert account_commands == []
    assert not layout.releases.exists()


def _relocatable_bin(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A staged venv bin as pip leaves it after installing a wheel with scripts."""
    staging = tmp_path / ".staging"
    destination = tmp_path / "release"
    bin_dir = destination / "venv" / "bin"
    bin_dir.mkdir(parents=True)
    interpreter = f"#!{staging / 'venv' / 'bin' / 'python'}\n"
    for name in ("ori-runtime", "i2cscan.py"):
        script = bin_dir / name
        script.write_text(interpreter + "print('hi')\n", encoding="utf-8")
        script.chmod(0o755)
    (bin_dir / "python").symlink_to("/usr/bin/python3")
    return staging, destination, bin_dir


def test_script_bytecode_pip_left_in_bin_is_discarded_not_refused(
    tmp_path: Path,
) -> None:
    """pyftdi installs .py scripts into bin and pip byte-compiles them there."""
    from ori.installer.linux import _repair_relocated_shebangs

    staging, destination, bin_dir = _relocatable_bin(tmp_path)
    cache = bin_dir / "__pycache__"
    cache.mkdir()
    (cache / "i2cscan.cpython-313.pyc").write_bytes(
        b"\x00pyc" + str(staging / "venv" / "bin" / "i2cscan.py").encode()
    )

    _repair_relocated_shebangs(staging, destination)

    assert not cache.exists()
    expected = f"#!{destination / 'venv' / 'bin' / 'python'}"
    for name in ("ori-runtime", "i2cscan.py"):
        first = (bin_dir / name).read_text(encoding="utf-8").splitlines()[0]
        assert first == expected, name
    assert sorted(p.name for p in bin_dir.iterdir()) == [
        "i2cscan.py",
        "ori-runtime",
        "python",
    ]


def test_a_bytecode_cache_that_is_not_a_directory_is_refused(tmp_path: Path) -> None:
    from ori.installer.linux import _repair_relocated_shebangs

    staging, destination, bin_dir = _relocatable_bin(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (bin_dir / "__pycache__").symlink_to(elsewhere)

    with pytest.raises(LinuxInstallError) as excinfo:
        _repair_relocated_shebangs(staging, destination)
    assert excinfo.value.code == "offline_install_failed"
    assert "__pycache__" in str(excinfo.value)
    assert elsewhere.exists(), "a refused link must never be followed or removed"


def test_other_directories_in_bin_are_still_refused(tmp_path: Path) -> None:
    from ori.installer.linux import _repair_relocated_shebangs

    staging, destination, bin_dir = _relocatable_bin(tmp_path)
    (bin_dir / "plugins").mkdir()

    with pytest.raises(LinuxInstallError) as excinfo:
        _repair_relocated_shebangs(staging, destination)
    assert "plugins" in str(excinfo.value)
