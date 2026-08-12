# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
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


def _install_args(tmp_path: Path) -> list[str]:
    return [
        "install",
        "--bundle",
        str(tmp_path / "bundle.tar.gz"),
        "--signature",
        str(tmp_path / "bundle.tar.gz.sig"),
        "--root",
        str(tmp_path / "ori"),
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

    def collect(options: InstallerInputOptions) -> InstallerConfigInput:
        calls.append("collect")
        return original_collect(options)

    monkeypatch.setattr(cli, "collect_installer_config", collect)

    assert cli.main(_install_args(tmp_path)) == 0
    payload = json.loads(capsys.readouterr().out)
    assert calls == ["verify", "collect", "extract", "compose"]
    assert payload["status"] == "healthy"
    assert payload["next_step"] == "Run ori doctor for ongoing diagnostics."


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


def test_user_scope_rejects_service_user_before_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "load_release_key_registry",
        lambda _path: pytest.fail("verification must not begin"),
    )
    args = [*_install_args(tmp_path), "--service-user", "ori-runtime"]

    with pytest.raises(SystemExit) as error:
        cli.main(args)

    assert error.value.code == 2
    assert "--service-user is valid only for system scope" in capsys.readouterr().err


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
        cli.main(["uninstall", "--root", str(tmp_path / "ori")])

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
    assert cli.main(["uninstall", "--root", str(tmp_path / "ori")]) == 0
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
