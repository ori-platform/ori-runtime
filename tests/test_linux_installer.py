# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

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


def _health_release(tmp_path: Path) -> Path:
    release = (tmp_path / "releases" / "2.3.0").resolve()
    interpreter = release / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"python")
    interpreter.chmod(0o700)
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
            "service_profile": SystemdServiceProfile.system("ori"),
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
        profile=SystemdServiceProfile.system("ori"),
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
        (SystemdServiceProfile.system("ori"), SystemdServiceProfile.user()),
        (SystemdServiceProfile.user(), SystemdServiceProfile.system("ori")),
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
        profile=SystemdServiceProfile.system("ori"),
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
        profile=SystemdServiceProfile.system("ori"),
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
        profile=SystemdServiceProfile.system("ori-runtime"),
        root=(tmp_path / "root").resolve(),
        data_dir=(tmp_path / "data").resolve(),
        config_path=(tmp_path / "data" / "config.yaml").resolve(),
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
                    SystemdServiceProfile.system("ori"),
                    allowed_data_sockets=(health_path,),
                )
            unexpected_socket.close()
            unexpected_path.unlink()
            apply_system_service_permissions(
                layout,
                SystemdServiceProfile.system("ori"),
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
    layout.data.mkdir()
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
    host_euid = os.geteuid()
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
    if host_euid == 0:
        os.chown(external_python, 65534, 65534)
    (release / "python").symlink_to(external_python)
    with pytest.raises(
        LinuxInstallError, match="external release symlink target is not trusted"
    ):
        apply_system_service_permissions(layout, SystemdServiceProfile.system("ori"))


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
            service_profile=SystemdServiceProfile.system("ori"),
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


def test_successful_config_provision_can_restore_previous_content_and_mode(
    tmp_path: Path,
) -> None:
    config_path = (tmp_path / "data" / "ori.yaml").resolve()
    config_path.parent.mkdir()
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
        service_profile=SystemdServiceProfile.system("ori"),
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
        "ori.installer.linux.Path.mkdir",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("denied")),
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
    config_path.parent.mkdir()
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
    config_path.parent.mkdir()
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
