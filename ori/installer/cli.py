# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Authenticated local entrypoint for transactional Linux installation."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
from importlib import resources
from pathlib import Path
from typing import NoReturn, Sequence

from ori.installer.linux import (
    InstallerInputOptions,
    InstallLayout,
    LinuxInstallError,
    SystemdServiceManager,
    SystemdServiceProfile,
    collect_installer_config,
    install_composed_release,
    uninstall_runtime,
)
from ori.security.release_bundles import (
    ReleaseBundleError,
    extract_verified_bundle,
    load_release_key_registry,
    verify_release_bundle,
)

_SERVICE_NAME = "ori-runtime.service"


def detected_release_target() -> str:
    """Return the v1 release target for this interpreter and Linux machine."""
    if platform.system() != "Linux":
        raise ReleaseBundleError("unsupported_target", "installer requires Linux")
    architecture = platform.machine().lower()
    normalized_architecture = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }.get(architecture)
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    if normalized_architecture is None or python_version not in {"3.11", "3.12"}:
        raise ReleaseBundleError(
            "unsupported_target", "Linux architecture or Python version is unsupported"
        )
    return f"linux-{normalized_architecture}-python{python_version}"


def _profile(scope: str, service_user: str | None) -> SystemdServiceProfile:
    if scope == "user":
        if service_user is not None:
            raise LinuxInstallError(
                "service_start_failed", "--service-user is valid only for system scope"
            )
        return SystemdServiceProfile.user()
    return SystemdServiceProfile.system(service_user or "ori-runtime")


def _paths(
    scope: str,
    *,
    root: Path | None,
) -> tuple[InstallLayout, Path, Path]:
    if scope == "user":
        default_root = Path.home() / ".local" / "ori"
        default_unit = Path.home() / ".config" / "systemd" / "user" / _SERVICE_NAME
        default_env = Path.home() / ".config" / "ori" / "runtime.env"
    else:
        default_root = Path("/opt/ori")
        default_unit = Path("/etc/systemd/system") / _SERVICE_NAME
        default_env = Path("/etc/ori/runtime.env")
    layout = InstallLayout.resolve(root or default_root)
    selected_unit = default_unit.expanduser()
    selected_env = default_env.expanduser()
    try:
        unsafe_path = (
            not selected_unit.is_absolute()
            or not selected_env.is_absolute()
            or selected_unit != Path(os.path.normpath(str(selected_unit)))
            or selected_env != Path(os.path.normpath(str(selected_env)))
            or selected_unit.parent.resolve(strict=False) != selected_unit.parent
            or selected_env.parent.resolve(strict=False) != selected_env.parent
        )
    except OSError as exc:
        raise LinuxInstallError(
            "unsafe_install_root", "service paths could not be inspected"
        ) from exc
    if unsafe_path:
        raise LinuxInstallError("unsafe_install_root", "service paths are unsafe")
    return layout, selected_unit, selected_env


def _read_service_template(bundle_root: Path) -> str:
    path = bundle_root / "systemd" / "ori-runtime.service"
    try:
        if path.is_symlink() or not path.is_file():
            raise LinuxInstallError(
                "service_start_failed", "verified service template is unavailable"
            )
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise LinuxInstallError(
            "service_start_failed", "verified service template could not be read"
        ) from exc


def _install(args: argparse.Namespace) -> dict[str, object]:
    profile = _profile(args.scope, args.service_user)
    layout, unit_path, env_file = _paths(
        args.scope,
        root=args.root,
    )
    target = detected_release_target()
    registry_resource = resources.files("ori.installer").joinpath("release-keys.json")
    with resources.as_file(registry_resource) as registry_path:
        registry = load_release_key_registry(registry_path)
    verified = verify_release_bundle(
        artifact_path=args.bundle,
        envelope_path=args.signature,
        key_registry=registry,
        expected_version=args.expected_version,
        expected_target=target,
    )
    values = collect_installer_config(
        InstallerInputOptions(
            unattended=args.unattended,
            device_id=args.device_id,
            name=args.name,
            location=args.location,
            deployment_type=args.deployment_type,
            operator_contact=args.operator_contact,
        )
    )
    service_manager = SystemdServiceManager(
        profile=profile,
        unit_path=unit_path,
    )
    try:
        with tempfile.TemporaryDirectory(prefix="ori-release-") as temporary:
            extracted = extract_verified_bundle(
                verified, destination=Path(temporary) / "verified"
            )
            result = install_composed_release(
                layout=layout,
                bundle=extracted,
                values=values,
                service_profile=profile,
                service_manager=service_manager,
                unit_template=_read_service_template(extracted.root),
                env_file=env_file,
                allow_downgrade=args.allow_downgrade,
            )
    except OSError as exc:
        raise ReleaseBundleError(
            "unsafe_bundle_archive", "verified bundle workspace is unavailable"
        ) from exc
    return {
        "boot_persistence": result.boot_persistence.enabled,
        "changed": result.install.changed,
        "device_id": values.device_id,
        "health": result.health,
        "next_step": "Run ori doctor for ongoing diagnostics.",
        "scope": profile.scope,
        "status": "healthy",
        "version": result.install.version,
    }


def _uninstall(args: argparse.Namespace) -> dict[str, object]:
    profile = _profile(args.scope, args.service_user)
    layout, unit_path, _env_file = _paths(
        args.scope,
        root=args.root,
    )
    service_manager = SystemdServiceManager(profile=profile, unit_path=unit_path)
    service_disabled = False
    service_manager.disable_and_remove()
    service_disabled = True

    def require_disabled_service() -> None:
        if not service_disabled:
            raise LinuxInstallError(
                "service_start_failed", "service was not disabled before removal"
            )

    uninstall_runtime(
        layout=layout,
        stop_service=require_disabled_service,
        remove_data=args.remove_data,
    )
    return {
        "data_removed": args.remove_data,
        "scope": profile.scope,
        "status": "uninstalled",
    }


def _add_scope_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scope", choices=("user", "system"), default="user")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--service-user")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ori-install-linux",
        description="Install an authenticated Ori Runtime release without live resolution.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    install = commands.add_parser("install", help="verify and install a local bundle")
    _add_scope_arguments(install)
    install.add_argument("--bundle", required=True, type=Path)
    install.add_argument("--signature", required=True, type=Path)
    install.add_argument("--expected-version")
    install.add_argument("--allow-downgrade", action="store_true")
    install.add_argument("--unattended", action="store_true")
    install.add_argument("--device-id")
    install.add_argument("--name")
    install.add_argument("--location")
    install.add_argument("--deployment-type", choices=("pi", "server"), default="pi")
    install.add_argument("--operator-contact")

    uninstall = commands.add_parser("uninstall", help="remove Runtime and its unit")
    _add_scope_arguments(uninstall)
    uninstall.add_argument("--remove-data", action="store_true")
    return parser


def _exit_error(error: ReleaseBundleError | LinuxInstallError) -> NoReturn:
    print(f"{error.code}: {error.detail}", file=sys.stderr)
    raise SystemExit(2)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = _install(args) if args.command == "install" else _uninstall(args)
    except (ReleaseBundleError, LinuxInstallError) as exc:
        _exit_error(exc)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return os.EX_OK


if __name__ == "__main__":
    raise SystemExit(main())
