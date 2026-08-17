# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import textwrap
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest

from ori.installer import cli
from ori.installer.linux import (
    InstallerConfigInput,
    InstallerInputOptions,
    LinuxInstallError,
)
from ori.security.release_bundles import ReleaseBundleError


@pytest.fixture(autouse=True)
def _unprivileged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin a non-root uid, whoever runs the suite.

    These tests exercise verification ordering and error mapping with
    `--scope user`; under a root CI container the privilege guard would refuse
    before any of that ran, turning ten correct refusals into ten confusing
    failures. The guard itself is covered directly in test_installer_scope.py.
    """
    monkeypatch.setattr(os, "geteuid", lambda: 1000)


@pytest.fixture(autouse=True)
def _host_is_prepared(monkeypatch: pytest.MonkeyPatch) -> None:
    """These tests are about the install transaction, not the host's packages.

    The real check creates a throwaway venv, which is both slow here and
    entangled with tests that patch `tempfile`. Prerequisite behaviour has its
    own suite; tests that care about the interaction opt back in.
    """
    monkeypatch.setattr(cli.prerequisites, "ensure", lambda **_kwargs: [])


def _install_args(tmp_path: Path) -> list[str]:
    return [
        "install",
        "--bundle",
        str(tmp_path / "bundle.tar.gz"),
        "--signature",
        str(tmp_path / "bundle.tar.gz.sig"),
        "--root",
        str(tmp_path / "ori"),
        "--scope",
        "user",
        "--unattended",
        "--device-id",
        "ori-01",
        "--name",
        "Office",
        "--location",
        "Lagos",
    ]


@pytest.mark.parametrize("option", ["--bund", "--signat", "--expected-vers"])
def test_installer_rejects_abbreviated_release_identity_options(
    option: str,
) -> None:
    with pytest.raises(SystemExit) as error:
        cli.build_parser().parse_args(["install", option, "value"])
    assert error.value.code == 2


def test_detected_release_target_normalizes_supported_machine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli.platform, "machine", lambda: "arm64")
    version = SimpleNamespace(major=3, minor=12)
    monkeypatch.setattr(cli.sys, "version_info", version)

    assert cli.detected_release_target() == "linux-aarch64-python3.12"


@pytest.mark.parametrize(
    ("system", "machine", "version"),
    [
        ("Darwin", "arm64", (3, 12)),
        ("Linux", "riscv64", (3, 12)),
        ("Linux", "x86_64", (3, 13)),
    ],
)
def test_detected_release_target_rejects_unsupported_host(
    monkeypatch: pytest.MonkeyPatch,
    system: str,
    machine: str,
    version: tuple[int, int],
) -> None:
    monkeypatch.setattr(cli.platform, "system", lambda: system)
    monkeypatch.setattr(cli.platform, "machine", lambda: machine)
    monkeypatch.setattr(
        cli.sys, "version_info", SimpleNamespace(major=version[0], minor=version[1])
    )

    with pytest.raises(ReleaseBundleError, match="unsupported_target"):
        cli.detected_release_target()


def test_install_verifies_before_extracting_and_composing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []
    extracted_root = tmp_path / "extracted-root"
    service = extracted_root / "systemd" / "ori-runtime.service"
    service.parent.mkdir(parents=True)
    service.write_text("verified template", encoding="utf-8")
    verified = SimpleNamespace(runtime_version="2.3.0")
    extracted = SimpleNamespace(root=extracted_root, runtime_version="2.3.0")

    monkeypatch.setattr(
        cli, "detected_release_target", lambda: "linux-x86_64-python3.12"
    )
    monkeypatch.setattr(
        cli,
        "load_release_key_registry",
        lambda _path: {"ori-runtime-release-2026-01": object()},
    )

    def verify(**kwargs: object) -> object:
        calls.append("verify")
        assert kwargs["expected_target"] == "linux-x86_64-python3.12"
        return verified

    def extract(_verified: object, *, destination: Path) -> object:
        calls.append("extract")
        assert destination.name == "verified"
        return extracted

    def compose(**kwargs: object) -> object:
        calls.append("compose")
        assert kwargs["unit_template"] == "verified template"
        values = kwargs["values"]
        assert getattr(values, "device_id") == "ori-01"
        return SimpleNamespace(
            install=SimpleNamespace(changed=True, version="2.3.0"),
            health={"device_id": "ori-01", "critical": False},
            boot_persistence=SimpleNamespace(enabled=False),
        )

    monkeypatch.setattr(cli, "verify_release_bundle", verify)
    monkeypatch.setattr(cli, "extract_verified_bundle", extract)
    monkeypatch.setattr(cli, "install_composed_release", compose)
    monkeypatch.setattr(cli, "SystemdServiceManager", lambda **_kwargs: object())
    original_collect = cli.collect_installer_config

    def collect(
        options: InstallerInputOptions, **channel: object
    ) -> InstallerConfigInput:
        calls.append("collect")
        return original_collect(options, **channel)  # type: ignore[arg-type]

    monkeypatch.setattr(cli, "collect_installer_config", collect)

    assert cli.main([*_install_args(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert calls == ["verify", "collect", "extract", "compose"]
    assert payload["status"] == "healthy"
    for key in (
        "install_root",
        "active_release",
        "config_path",
        "data_path",
        "health_socket",
        "unit_path",
        "scope",
        "version",
    ):
        assert payload[key], f"install result does not report {key}"


def test_install_failure_is_stable_and_has_no_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli, "detected_release_target", lambda: "linux-x86_64-python3.12"
    )
    monkeypatch.setattr(
        cli,
        "load_release_key_registry",
        lambda _path: (_ for _ in ()).throw(
            ReleaseBundleError("untrusted_release_key", "registry rejected")
        ),
    )

    with pytest.raises(SystemExit) as error:
        cli.main(_install_args(tmp_path))

    stderr = capsys.readouterr().err
    assert error.value.code == 2
    assert stderr == "untrusted_release_key: registry rejected\n"
    assert "Traceback" not in stderr


def test_signature_failure_prevents_extraction_and_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli, "detected_release_target", lambda: "linux-x86_64-python3.12"
    )
    monkeypatch.setattr(cli, "load_release_key_registry", lambda _path: {})
    monkeypatch.setattr(
        cli,
        "verify_release_bundle",
        lambda **_kwargs: (_ for _ in ()).throw(
            ReleaseBundleError(
                "signature_verification_failed", "release signature rejected"
            )
        ),
    )
    monkeypatch.setattr(
        cli,
        "extract_verified_bundle",
        lambda *_args, **_kwargs: pytest.fail("unverified bundle was extracted"),
    )
    monkeypatch.setattr(
        cli,
        "install_composed_release",
        lambda **_kwargs: pytest.fail("unverified bundle was installed"),
    )
    monkeypatch.setattr(
        cli,
        "collect_installer_config",
        lambda _options: pytest.fail("input was collected for an unverified bundle"),
    )

    with pytest.raises(SystemExit) as error:
        cli.main(_install_args(tmp_path))

    assert error.value.code == 2
    assert capsys.readouterr().err == (
        "signature_verification_failed: release signature rejected\n"
    )


def test_workspace_failure_maps_to_stable_archive_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli, "detected_release_target", lambda: "linux-x86_64-python3.12"
    )
    monkeypatch.setattr(cli, "load_release_key_registry", lambda _path: {})
    monkeypatch.setattr(cli, "verify_release_bundle", lambda **_kwargs: object())
    monkeypatch.setattr(cli, "SystemdServiceManager", lambda **_kwargs: object())
    monkeypatch.setattr(
        cli.tempfile,
        "TemporaryDirectory",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("disk unavailable")),
    )

    with pytest.raises(SystemExit) as error:
        cli.main(_install_args(tmp_path))

    assert error.value.code == 2
    assert capsys.readouterr().err == (
        "unsafe_bundle_archive: verified bundle workspace is unavailable\n"
    )


@pytest.mark.skipif(
    Path("/etc").resolve() != Path("/etc"),
    reason="system scope resolves /etc, which is not canonical on this host",
)
def test_a_user_controlled_interpreter_is_refused_before_any_host_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A pyenv or home-directory Python cannot carry a system installation.

    The release environment is built from it and links back to it, so its code
    would be replaceable by whoever controls that prefix. Diagnostics would
    catch it — after the bundle is unpacked, the environment built, the account
    created and the unit started, and the whole thing then rolled back. It is
    knowable in microseconds, so nothing may be spent before it is asked.
    """
    prefix = tmp_path / "pyenv" / "versions" / "3.12.3" / "bin"
    prefix.mkdir(parents=True)
    interpreter = prefix / "python3.12"
    interpreter.write_text("#!/bin/sh\n", encoding="utf-8")
    interpreter.chmod(0o755)

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "_base_executable", str(interpreter), raising=False)
    monkeypatch.setattr(
        cli,
        "load_release_key_registry",
        lambda _path: pytest.fail("verification must not begin"),
    )
    monkeypatch.setattr(
        "ori.installer.linux._run_account_command",
        lambda _c: pytest.fail("no account may be created"),
    )

    with pytest.raises(SystemExit) as error:
        cli.main(_system_install_args(tmp_path))

    assert error.value.code == 2
    message = capsys.readouterr().err
    assert "only root can change" in message
    assert "apt install" in message
    assert "--scope user" in message
    assert not (tmp_path / "ori").exists()


def test_a_root_controlled_interpreter_is_accepted_for_system_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The check must not refuse the ordinary case it exists to protect.

    Under a user-scope profile this returns before inspecting anything, so a
    user-scope call would keep passing even if every system interpreter were
    refused. The profile is therefore system, and the path the primitive was
    handed is recorded — accepting without looking is the failure this guards.
    """
    from ori.installer import linux as installer_linux
    from ori.installer.linux import (
        SystemdServiceProfile,
        require_trusted_base_interpreter,
    )

    inspected: list[str] = []
    real = installer_linux.trust_failure

    def recording(path: object, **kwargs: object) -> object:
        inspected.append(str(path))
        return real(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(installer_linux, "trust_failure", recording)
    # Root-owned, unwritable by others, and beneath root-controlled directories
    # on every supported host.
    monkeypatch.setattr(sys, "_base_executable", "/usr/bin/env", raising=False)

    require_trusted_base_interpreter(SystemdServiceProfile.system())

    assert inspected == ["/usr/bin/env"]


def test_the_interpreter_refusal_uses_a_documented_failure_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Automation branches on the code, not on the sentence."""
    from ori.installer.linux import (
        LinuxInstallError,
        SystemdServiceProfile,
        require_trusted_base_interpreter,
    )

    interpreter = tmp_path / "bin" / "python3.12"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("#!/bin/sh\n", encoding="utf-8")
    interpreter.chmod(0o755)
    monkeypatch.setattr(sys, "_base_executable", str(interpreter), raising=False)

    with pytest.raises(LinuxInstallError) as error:
        require_trusted_base_interpreter(SystemdServiceProfile.system())

    assert error.value.code == "unsupported_target"


def test_a_different_service_account_name_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One name, everywhere — it is not a per-host choice.

    A configurable account would have to be carried by the unit file, the
    permission checks and the documentation, any of which could then disagree
    with the others about who the runtime is.
    """
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        cli,
        "load_release_key_registry",
        lambda _path: pytest.fail("verification must not begin"),
    )
    args = [*_system_install_args(tmp_path), "--service-user", "somebody-else"]

    with pytest.raises(SystemExit) as error:
        cli.main(args)

    assert error.value.code == 2
    message = capsys.readouterr().err
    assert "always ori-runtime" in message
    assert "cannot be renamed" in message


def test_the_canonical_service_account_name_is_still_accepted() -> None:
    """A script that already passes the documented default keeps working.

    The flag shipped in v2.3.0, and what the installer's compatibility promise
    protects is the meaning of a flag an operator already wrote. Omitting it and
    passing the canonical name resolve to the same profile.
    """
    explicit = cli._profile("system", "ori-runtime")
    omitted = cli._profile("system", None)

    assert explicit == omitted
    assert explicit.service_user == "ori-runtime"


def test_a_service_user_on_user_scope_is_refused() -> None:
    """User units have no `User=`, so naming an account there means something
    the installation cannot honour — silently ignoring it would produce a user
    install the operator believes runs as somebody else."""
    with pytest.raises(LinuxInstallError, match="only for system scope"):
        cli._profile("user", "ori-runtime")


def test_a_renamed_service_account_is_refused_at_the_profile() -> None:
    with pytest.raises(LinuxInstallError, match="cannot be renamed"):
        cli._profile("system", "somebody-else")


@pytest.mark.skipif(
    Path("/etc").resolve() != Path("/etc"),
    reason="system scope resolves /etc, which is not canonical on this host",
)
def test_the_account_is_created_after_verification_and_before_the_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Creating an account is a durable host change, so it waits its turn.

    An unsigned or tampered bundle must not be able to leave an account behind,
    and confirmation promises that nothing has been changed yet — so creation
    follows verification and the operator's agreement. It precedes the packages,
    the bundle being opened and the environment being built, so a host that
    cannot provide the account is not discovered after minutes of work, and a
    declined account has not already cost an OS package install.
    """
    calls: list[str] = []
    accounts = {"exists": False}

    def getpwnam(name: str) -> object:
        if accounts["exists"]:
            return SimpleNamespace(pw_name=name, pw_uid=4242, pw_gid=4242)
        raise KeyError(name)

    def useradd(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        calls.append("account")
        accounts["exists"] = True
        return subprocess.CompletedProcess(list(command), 0, "", "")

    def verify(**_kwargs: object) -> object:
        calls.append("verify")
        return SimpleNamespace(runtime_version="2.4.0-rc.4")

    original_collect = cli.collect_installer_config

    def collect(options: object, **channel: object) -> object:
        calls.append("collect")
        return original_collect(options, **channel)  # type: ignore[arg-type]

    def extract(_verified: object, *, destination: Path) -> object:
        calls.append("extract")
        raise LinuxInstallError("offline_install_failed", "stop before building")

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        cli, "detected_release_target", lambda: "linux-x86_64-python3.12"
    )
    monkeypatch.setattr(cli, "load_release_key_registry", lambda _p: {"k": object()})
    monkeypatch.setattr(cli, "verify_release_bundle", verify)
    monkeypatch.setattr(cli, "collect_installer_config", collect)
    monkeypatch.setattr(cli, "extract_verified_bundle", extract)
    monkeypatch.setattr("ori.installer.linux.pwd.getpwnam", getpwnam)
    monkeypatch.setattr(
        "ori.installer.linux._trusted_useradd", lambda: "/usr/sbin/useradd"
    )
    monkeypatch.setattr("ori.installer.linux._run_account_command", useradd)
    monkeypatch.setattr(
        cli.prerequisites,
        "ensure",
        lambda **_kwargs: calls.append("prerequisites") or [],
    )

    with pytest.raises(SystemExit):
        cli.main(_system_install_args(tmp_path))

    # The account precedes the packages: it is the change an operator is most
    # likely to decline, and declining it ends the run. Asking afterwards would
    # mean packages had been installed for an installation that never finished.
    assert calls == ["verify", "collect", "account", "prerequisites", "extract"]


@pytest.mark.skipif(
    Path("/etc").resolve() != Path("/etc"),
    reason="system scope resolves /etc, which is not canonical on this host",
)
def test_an_unsigned_bundle_leaves_no_account_behind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected bundle must not mutate the host.

    System scope, because that is the only scope with an account to create: a
    user-scope run would pass this trivially without ever reaching the code
    under test.
    """
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        "ori.installer.linux.pwd.getpwnam",
        lambda name: (_ for _ in ()).throw(KeyError(name)),
    )
    monkeypatch.setattr(
        "ori.installer.linux._run_account_command",
        lambda _c: pytest.fail("an unverified bundle must not create an account"),
    )
    monkeypatch.setattr(
        cli,
        "verify_release_bundle",
        lambda **_k: (_ for _ in ()).throw(
            ReleaseBundleError("untrusted_release_key", "not signed by a known key")
        ),
    )

    with pytest.raises(SystemExit):
        cli.main(_system_install_args(tmp_path))


def _system_install_args(tmp_path: Path) -> list[str]:
    return [
        "install",
        "--bundle",
        str(tmp_path / "bundle.tar.gz"),
        "--signature",
        str(tmp_path / "bundle.tar.gz.sig"),
        "--root",
        str(tmp_path / "ori"),
        "--scope",
        "system",
        "--unattended",
        "--device-id",
        "ori-01",
        "--name",
        "Office",
        "--location",
        "Lagos",
    ]


def test_uninstall_disables_unit_before_removing_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []

    class Manager:
        def disable_and_remove(self) -> None:
            calls.append("disable")

    monkeypatch.setattr(cli, "SystemdServiceManager", lambda **_kwargs: Manager())

    def uninstall(**kwargs: object) -> None:
        calls.append("uninstall")
        stop = kwargs["stop_service"]
        assert callable(stop)
        stop()
        calls.append("guard")

    monkeypatch.setattr(cli, "uninstall_runtime", uninstall)
    arguments = [
        "uninstall",
        "--scope",
        "user",
        "--root",
        str(tmp_path / "ori"),
        "--remove-data",
    ]

    assert cli.main(arguments) == 0
    assert calls == ["disable", "uninstall", "guard"]
    assert json.loads(capsys.readouterr().out)["data_removed"] is True


def test_uninstall_unit_failure_preserves_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Manager:
        def disable_and_remove(self) -> None:
            raise LinuxInstallError("service_start_failed", "service disable failed")

    monkeypatch.setattr(cli, "SystemdServiceManager", lambda **_kwargs: Manager())
    monkeypatch.setattr(
        cli,
        "uninstall_runtime",
        lambda **_kwargs: pytest.fail("release removed after unit failure"),
    )

    with pytest.raises(SystemExit) as error:
        cli.main(["uninstall", "--scope", "user", "--root", str(tmp_path / "ori")])

    assert error.value.code == 2
    assert capsys.readouterr().err == "service_start_failed: service disable failed\n"


def test_uninstall_deletion_guard_fails_without_successful_disable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured_stop: list[object] = []

    class Manager:
        def disable_and_remove(self) -> None:
            return None

    monkeypatch.setattr(cli, "SystemdServiceManager", lambda **_kwargs: Manager())

    def capture(**kwargs: object) -> None:
        captured_stop.append(kwargs["stop_service"])

    monkeypatch.setattr(cli, "uninstall_runtime", capture)
    assert (
        cli.main(["uninstall", "--scope", "user", "--root", str(tmp_path / "ori")]) == 0
    )
    assert len(captured_stop) == 1
    guard = captured_stop[0]
    assert callable(guard)

    # The closure is the deletion-time invariant: if future code reorders the
    # removal before successful disablement, it fails closed rather than acting
    # as the old no-op did.
    assert guard() is None


def test_entrypoint_does_not_use_shell_or_network_clients() -> None:
    source = Path(cli.__file__).read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "requests" not in source
    assert "urllib" not in source
    assert "curl" not in source
    assert "wget" not in source
    assert subprocess.__name__ not in source


def test_module_entrypoint_exposes_only_fixed_service_paths() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ori.installer.cli", "install", "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert "--bundle" in result.stdout
    assert "--signature" in result.stdout
    assert "--key-registry" not in result.stdout
    assert "--unit-path" not in result.stdout
    assert "--env-file" not in result.stdout


def test_packaged_release_registry_pins_approved_public_key() -> None:
    registry_path = Path(cli.__file__).with_name("release-keys.json")
    registry = cli.load_release_key_registry(registry_path)

    assert list(registry) == ["ori-runtime-release-2026-01"]
    key = registry["ori-runtime-release-2026-01"]
    assert key.purpose == "runtime_release_bundle"
    assert key.status == "active"
    public_key = base64.b64decode(key.public_key_b64, validate=True)
    assert hashlib.sha256(public_key).hexdigest() == (
        "d4f44308d60fb78a33f709eebc85271f2b8c0d4e59e50bb77bf08f5864918c90"
    )


def test_read_service_template_rejects_missing_verified_asset(tmp_path: Path) -> None:
    with pytest.raises(LinuxInstallError, match="verified service template"):
        cli._read_service_template(tmp_path)


def test_prompts_never_reach_stdout(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`input()` writes its prompt to stdout, where an orchestrator captures it.

    The operator would then see nothing while the installer waited for them.
    """
    monkeypatch.setattr("sys.stdin", io.StringIO("pi-01\n"))
    prompt, _write = cli.operator_channel()
    answer = prompt("Device ID: ")
    captured = capsys.readouterr()

    assert answer == "pi-01"
    assert captured.out == ""
    assert captured.err == "Device ID: "


def test_progress_never_reaches_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _prompt, write = cli.operator_channel()
    write("preparing the installation")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "preparing the installation" in captured.err


def test_the_channel_signals_end_of_input_like_input_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    prompt, _write = cli.operator_channel()
    with pytest.raises(EOFError):
        prompt("Device ID: ")


def test_a_real_interactive_install_keeps_stdout_parseable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drive ori.installer.cli itself, answering its real prompts over stdin."""
    script = textwrap.dedent(
        """
        import json, sys
        from ori.installer import cli
        from ori.installer.linux import InstallerInputOptions

        prompt, write = cli.operator_channel()
        write("preparing the installation")
        values = cli.collect_installer_config(
            InstallerInputOptions(
                unattended=False, device_id=None, name=None, location=None,
                deployment_type="pi", operator_contact=None,
            ),
            prompt=prompt,
            write=write,
        )
        json.dump({"device_id": values.device_id, "status": "healthy"}, sys.stdout)
        """
    )
    source = tmp_path / "interactive.py"
    source.write_text(script)

    completed = subprocess.run(
        [sys.executable, str(source)],
        input="pi-01\nSite A\nLagos\n\ny\n",
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent.parent,
    )

    assert completed.returncode == 0, completed.stderr
    # stdout is exactly one JSON document: no prompt text, no progress.
    payload = json.loads(completed.stdout)
    assert payload["device_id"] == "pi-01"
    # and the operator could actually see what was being asked.
    assert "preparing the installation" in completed.stderr
    assert completed.stderr.strip(), "the operator saw nothing while it waited"


def test_human_mode_prints_a_summary_and_warns_when_not_persistent() -> None:
    summary = cli.render_install_summary(
        {
            "version": "2.3.1",
            "scope": "user",
            "device_id": "pi-01",
            "install_root": "/home/a/.local/ori",
            "config_path": "/home/a/.local/ori/data/ori.yaml",
            "boot_persistence": False,
        }
    )
    assert "Ori Runtime installed" in summary
    assert "/home/a/.local/ori/data/ori.yaml" in summary
    assert "WARNING" in summary
    assert "last\n  session ends" in summary
    assert "enable-linger" in summary


def test_human_mode_confirms_persistence_when_it_holds() -> None:
    summary = cli.render_install_summary(
        {"version": "2.3.1", "scope": "system", "boot_persistence": True}
    )
    assert "Starts during boot" in summary
    assert "WARNING" not in summary


def test_a_failing_json_install_still_emits_one_json_document(
    tmp_path: Path,
) -> None:
    """A JSON run must produce JSON whether it succeeded or not.

    Failing to plain text leaves an orchestrator nothing to parse, so a precise
    code such as `unsupported_target` reaches the operator as a generic
    "installation failed".
    """
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "ori.installer.cli",
            *_install_args(tmp_path),
            "--json",
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent.parent,
    )

    assert completed.returncode == 2
    payload = json.loads(completed.stdout)
    assert payload["ok"] is False
    assert payload["schema_version"] == 1
    assert payload["error"]["code"]
    assert payload["error"]["detail"]
    # The human-readable line stays on stderr, out of the parseable stream.
    assert payload["error"]["code"] in completed.stderr


def test_a_failing_human_install_stays_human(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "ori.installer.cli", *_install_args(tmp_path)],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent.parent,
    )
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert ":" in completed.stderr


def test_the_orchestrator_surfaces_the_installers_own_code(tmp_path: Path) -> None:
    """The outer command must not flatten a precise failure into a generic one."""
    from ori.installer.upgrade import UpgradeError, _run_installer

    installer = tmp_path / "ori-install-linux"
    installer.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        'json.dump({"schema_version": 1, "ok": False, "error": '
        '{"code": "unsupported_target", "detail": "installer requires Linux"}},'
        " sys.stdout)\n"
        "sys.exit(2)\n"
    )
    installer.chmod(0o755)

    class _Verified:
        runtime_version = "2.3.1"

    args = argparse.Namespace(
        scope="user",
        unattended=True,
        device_id=None,
        name=None,
        location=None,
    )
    with pytest.raises(UpgradeError) as excinfo:
        _run_installer(installer, Path("/b.tar.gz"), Path("/b.sig"), _Verified(), args)
    assert "unsupported_target" in str(excinfo.value)
    assert "installer requires Linux" in str(excinfo.value)


def test_scope_has_no_default_at_the_install_entry_point() -> None:
    """Scope decides reboot survival and code-writability; never chosen silently."""
    args = cli.build_parser().parse_args(
        ["install", "--bundle", "b", "--signature", "s"]
    )
    assert args.scope is None


def test_unattended_install_without_a_scope_fails_before_any_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = [a for a in _install_args(tmp_path) if a not in ("--scope", "user")]
    with pytest.raises(SystemExit) as error:
        cli.main(arguments)
    assert error.value.code == 2
    assert "unattended mode requires --scope" in capsys.readouterr().err
    assert not (tmp_path / "ori").exists()


def test_uninstall_without_a_scope_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["uninstall", "--root", str(tmp_path / "ori")])
    assert error.value.code == 2
    assert "requires --scope" in capsys.readouterr().err


def test_the_host_is_never_changed_before_the_bundle_is_authenticated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify before mutate: an unsigned bundle must not reach a package prompt."""
    order: list[str] = []
    monkeypatch.setattr(
        cli,
        "detected_release_target",
        lambda: order.append("platform") or "linux-x86_64-python3.12",
    )
    monkeypatch.setattr(
        cli,
        "load_release_key_registry",
        lambda _path: order.append("registry") or {},
    )
    monkeypatch.setattr(
        cli,
        "verify_release_bundle",
        lambda **kwargs: order.append("verify") or object(),
    )
    # Opt back in: this test is precisely about when prerequisites are checked.
    monkeypatch.setattr(
        cli.prerequisites,
        "ensure",
        lambda **kwargs: order.append("prerequisites") or [],
    )
    original_collect = cli.collect_installer_config
    monkeypatch.setattr(
        cli,
        "collect_installer_config",
        lambda *a, **k: order.append("identity") or original_collect(*a, **k),
    )
    monkeypatch.setattr(
        cli,
        "SystemdServiceManager",
        lambda **k: (_ for _ in ()).throw(RuntimeError("stop here")),
    )
    with pytest.raises(RuntimeError):
        cli._install(cli.build_parser().parse_args(_install_args(tmp_path)))
    # Identity is confirmed before the host is touched, because confirmation
    # promises nothing has changed yet.
    assert order == ["platform", "registry", "verify", "identity", "prerequisites"]


def test_a_rejected_bundle_never_touches_the_package_manager(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A tampered or wrong-target bundle must change nothing about the host."""
    prerequisite_calls: list[str] = []
    apt_calls: list[list[str]] = []

    monkeypatch.setattr(
        cli, "detected_release_target", lambda: "linux-x86_64-python3.12"
    )
    monkeypatch.setattr(cli, "load_release_key_registry", lambda _path: {})
    monkeypatch.setattr(
        cli,
        "verify_release_bundle",
        lambda **_kwargs: (_ for _ in ()).throw(
            ReleaseBundleError("signature_invalid", "signature verification failed")
        ),
    )
    monkeypatch.setattr(
        cli.prerequisites,
        "ensure",
        lambda **kwargs: prerequisite_calls.append("ensure") or [],
    )
    monkeypatch.setattr(
        cli.prerequisites,
        "_default_runner",
        lambda command: apt_calls.append(list(command)),
    )

    with pytest.raises(SystemExit) as error:
        cli.main(_install_args(tmp_path))

    assert error.value.code == 2
    assert "signature_invalid" in capsys.readouterr().err
    assert prerequisite_calls == [], "prerequisites ran on an unauthenticated bundle"
    assert apt_calls == [], "the package manager ran on an unauthenticated bundle"


def test_declining_confirmation_never_reaches_the_package_manager(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Confirmation promises nothing has changed yet; apt would make that false."""
    apt_calls: list[object] = []
    monkeypatch.setattr(
        cli, "detected_release_target", lambda: "linux-x86_64-python3.12"
    )
    monkeypatch.setattr(cli, "load_release_key_registry", lambda _path: {})
    monkeypatch.setattr(cli, "verify_release_bundle", lambda **_k: object())
    monkeypatch.undo()  # re-apply below without the autouse prerequisite stub
    monkeypatch.setattr(
        cli, "detected_release_target", lambda: "linux-x86_64-python3.12"
    )
    monkeypatch.setattr(cli, "load_release_key_registry", lambda _path: {})
    monkeypatch.setattr(cli, "verify_release_bundle", lambda **_k: object())
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        cli.prerequisites, "ensure", lambda **k: apt_calls.append("ensure") or []
    )
    monkeypatch.setattr(
        cli,
        "collect_installer_config",
        lambda *a, **k: (_ for _ in ()).throw(
            LinuxInstallError(
                "config_validation_failed",
                "installation was cancelled before any change was made",
            )
        ),
    )
    with pytest.raises(SystemExit):
        cli.main(_install_args(tmp_path))
    assert apt_calls == [], "packages were installed before the operator confirmed"


def test_human_output_carries_the_next_step(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The original defect was an install that named a command that did not
    exist. Computing honest guidance and not printing it repeats it."""
    summary = cli.render_install_summary(
        {
            "version": "2.4.0",
            "scope": "user",
            "boot_persistence": False,
            "next_step": (
                "/home/pi/.local/bin is not on your PATH, so the `ori` command "
                "will not be found yet.\nAdd it for this shell:\n"
                '    export PATH="/home/pi/.local/bin:$PATH"'
            ),
            "warnings": ["Persistence: none — stops after the last session ends"],
        }
    )
    assert "not on your PATH" in summary
    assert 'export PATH="/home/pi/.local/bin:$PATH"' in summary
    assert "Persistence: none" in summary


@pytest.mark.parametrize(
    ("step", "expected"),
    [
        ("Run `ori doctor` at any time to check this installation.", "ori doctor"),
        ("The ori command was not installed. something is there.", "was not installed"),
        ('Add it for this shell:\n    export PATH="/x:$PATH"', "export PATH"),
    ],
)
def test_every_guidance_shape_reaches_human_output(step: str, expected: str) -> None:
    summary = cli.render_install_summary(
        {
            "version": "2.4.0",
            "scope": "user",
            "boot_persistence": True,
            "next_step": step,
        }
    )
    assert expected in summary


def test_the_success_envelope_is_versioned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The decision names this the stable machine contract; it must say so."""
    monkeypatch.setattr(
        cli,
        "_install",
        lambda args: {"status": "healthy", "schema_version": 1, "ok": True},
    )
    assert cli.main([*_install_args(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert payload["ok"] is True
