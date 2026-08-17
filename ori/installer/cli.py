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
from typing import Callable, NoReturn, Sequence

from ori.installer import (
    activation,
    launcher,
    paths,
    prerequisites,
    scope_prompt,
)
from ori.installer.linux import (
    SERVICE_USER,
    InstallerInputOptions,
    InstallLayout,
    LinuxInstallError,
    SystemdServiceManager,
    SystemdServiceProfile,
    collect_installer_config,
    ensure_service_account,
    install_composed_release,
    require_trusted_base_interpreter,
    uninstall_runtime,
)
from ori.security.release_bundles import (
    ReleaseBundleError,
    extract_verified_bundle,
    load_release_key_registry,
    verify_release_bundle,
)
from ori.utils import terminal

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


def _profile(scope: str, service_user: str | None = None) -> SystemdServiceProfile:
    """Resolve the service profile, accepting only the canonical account name.

    `--service-user` shipped in v2.3.0 and is kept rather than removed, because
    an explicit flag an operator already wrote is what the installer's
    compatibility promise protects. What it no longer does is name a different
    account: the runtime's system identity is fixed, so the flag now accepts the
    one value it always defaulted to and refuses the rest with a reason.
    """
    if scope == "user":
        if service_user is not None:
            raise LinuxInstallError(
                "service_start_failed", "--service-user is valid only for system scope"
            )
        return SystemdServiceProfile.user()
    if service_user is not None and service_user != SERVICE_USER:
        raise LinuxInstallError(
            "service_start_failed",
            f"the system service account is always {SERVICE_USER} and cannot be "
            f"renamed; drop --service-user, or pass --service-user {SERVICE_USER}",
        )
    return SystemdServiceProfile.system()


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
    prompt, write = operator_channel()
    scope = scope_prompt.choose_scope(
        supplied=args.scope,
        unattended=args.unattended,
        prompt=prompt,
        write=write,
    )
    # Refused, never escalated: the operator is given the exact command to
    # repeat rather than having a privilege boundary crossed on their behalf.
    scope_prompt.require_privilege(scope, sys.argv)
    profile = _profile(scope, args.service_user)
    # Read-only, so it costs nothing and can be answered before the operator is
    # asked anything: a system install whose interpreter is not root-controlled
    # cannot succeed, and finding that out after building an environment is the
    # expensive way to learn it.
    require_trusted_base_interpreter(profile)
    layout, unit_path, env_file = _paths(
        scope,
        root=args.root,
    )
    # On a host this installer cannot serve at all, a package list is the
    # wrong thing to talk about.
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
    # Identity is collected and confirmed first, because confirmation promises
    # that nothing has been changed yet. Installing packages before the
    # operator has agreed to proceed would make that promise false.
    values = collect_installer_config(
        InstallerInputOptions(
            unattended=args.unattended,
            device_id=args.device_id,
            name=args.name,
            location=args.location,
            deployment_type=args.deployment_type,
            operator_contact=args.operator_contact,
            generate_device_id=args.generate_device_id,
        ),
        prompt=prompt,
        write=write,
    )
    # Confirmed. Now the host may be changed — and only now, with the bundle
    # already proven authentic, so an unsigned or tampered bundle can never
    # reach a package prompt.
    #
    # The account goes first among those changes. It is the one an operator is
    # most likely to decline, and declining it ends the installation: asking
    # afterwards would mean OS packages had already been installed for a run
    # that was never going to finish. Deliberately not part of
    # `prerequisites.ensure`, which offers packages — an account is a different
    # kind of change and asks for itself.
    ensure_service_account(
        profile, unattended=args.unattended, prompt=prompt, write=write
    )
    prerequisites.ensure(unattended=args.unattended, prompt=prompt, write=write)

    service_manager = SystemdServiceManager(
        profile=profile,
        unit_path=unit_path,
    )
    launcher_path = paths.launcher_path(profile.scope)
    checks: list[dict[str, object]] = []
    launcher_state: dict[str, object] = {"installed": False, "conflict": ""}

    def after_activation(
        release: Path, register_rollback: Callable[[Callable[[], None]], None]
    ) -> None:
        # The launcher goes in first and registers its own removal, so a failed
        # diagnosis does not leave an `ori` command behind pointing at a
        # release that rollback is about to undo.
        installed, conflict, undo_launcher = activation.install_launcher(
            launcher_path, layout.root, profile.scope
        )
        launcher_state.update(installed=installed, conflict=conflict)
        if installed:
            register_rollback(undo_launcher)
        # Diagnostics run by absolute path and bound to this exact root: `ori`
        # may not resolve yet, and a different installation must never be the
        # one that approves or condemns this tree.
        checks.extend(
            activation.run_installed_doctor(
                release,
                profile.scope,
                root=layout.root,
                expected_device_id=values.device_id,
            )
        )
        activation.assert_usable(checks)

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
                post_activation=after_activation,
            )
    except OSError as exc:
        raise ReleaseBundleError(
            "unsafe_bundle_archive", "verified bundle workspace is unavailable"
        ) from exc
    installed = bool(launcher_state["installed"])
    outcome = activation.ActivationOutcome(
        launcher_path=launcher_path,
        launcher_installed=installed,
        launcher_conflict=str(launcher_state["conflict"]),
        path_guidance=(
            launcher.path_guidance(launcher_path) or "" if installed else ""
        ),
        checks=checks,
    )
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "ok": True,
        "active_release": str(layout.releases / result.install.version),
        "diagnostics": checks,
        "launcher_installed": installed,
        "launcher_path": str(launcher_path),
        # Persistence is rendered by the summary itself with its remedy, so
        # doctor's version of it would be a second copy of the same advice.
        "warnings": [
            str(c.get("message", ""))
            for c in outcome.warnings
            if c.get("name") != "service.boot_persistence"
        ],
        "boot_persistence": result.boot_persistence.enabled,
        "changed": result.install.changed,
        "config_path": str(layout.data / "ori.yaml"),
        "data_path": str(layout.data),
        "device_id": values.device_id,
        "health": result.health,
        "health_socket": str(layout.data / "health.sock"),
        "install_root": str(layout.root),
        "next_step": activation.next_step(outcome),
        "scope": profile.scope,
        "service_user": profile.service_user,
        "status": "healthy",
        "unit_path": str(unit_path),
        "version": result.install.version,
    }


def _uninstall(args: argparse.Namespace) -> dict[str, object]:
    if args.scope is None:
        raise LinuxInstallError(
            "config_validation_failed",
            "uninstall requires --scope system or --scope user",
        )
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
    # Left behind, the launcher would resolve to a release that no longer
    # exists. Only launchers this installer wrote for this root are removed.
    launcher_path = paths.launcher_path(profile.scope)
    launcher_removed = activation.remove_launcher(launcher_path, layout.root)
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "ok": True,
        "data_removed": args.remove_data,
        "launcher_path": str(launcher_path),
        "launcher_removed": launcher_removed,
        "scope": profile.scope,
        "status": "uninstalled",
    }


def _add_output_arguments(parser: argparse.ArgumentParser) -> None:
    """Machine output is requested explicitly, never inferred.

    An orchestrating `ori install` always passes --json so the handoff has a
    stable parseable contract regardless of what an interactive run prints.
    """
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit one JSON document on stdout; prompts and progress go to stderr",
    )


def _add_scope_arguments(parser: argparse.ArgumentParser) -> None:
    # No default: scope decides whether the runtime survives a reboot and
    # whether it can rewrite its own code, so it is never chosen silently.
    parser.add_argument("--scope", choices=("user", "system"), default=None)
    parser.add_argument("--service-user")
    parser.add_argument("--root", type=Path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ori-install-linux",
        description="Install an authenticated Ori Runtime release without live resolution.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    install = commands.add_parser(
        "install", help="verify and install a local bundle", allow_abbrev=False
    )
    _add_scope_arguments(install)
    _add_output_arguments(install)
    install.add_argument("--bundle", required=True, type=Path)
    install.add_argument("--signature", required=True, type=Path)
    install.add_argument("--expected-version")
    install.add_argument("--allow-downgrade", action="store_true")
    install.add_argument("--unattended", action="store_true")
    install.add_argument("--device-id")
    install.add_argument(
        "--generate-device-id",
        action="store_true",
        help=(
            "derive a device ID from this host when --device-id is omitted; "
            "adds a random suffix on stock-image hostnames, so an unattended "
            "run is only reproducible when this is off"
        ),
    )
    install.add_argument("--name")
    install.add_argument("--location")
    install.add_argument("--deployment-type", choices=("pi", "server"), default="pi")
    install.add_argument("--operator-contact")

    uninstall = commands.add_parser(
        "uninstall", help="remove Runtime and its unit", allow_abbrev=False
    )
    _add_scope_arguments(uninstall)
    _add_output_arguments(uninstall)
    uninstall.add_argument("--remove-data", action="store_true")
    return parser


def operator_channel() -> tuple[Callable[[str], str], Callable[[str], None]]:
    """Return (prompt, write) that never write to stdout.

    ``input()`` writes its prompt to stdout. When stdout is being captured as
    the machine-readable result — which is exactly what an orchestrating
    ``ori install`` does — that prompt vanishes, and the operator is left
    watching a silent process that is in fact waiting for them.

    Prompts and progress therefore go to stderr in both modes, leaving stdout
    for the result alone. Stdin is untouched, so the bootstrap's reopened
    ``/dev/tty`` still supplies the answers during a piped install.
    """

    def prompt(message: str) -> str:
        sys.stderr.write(message)
        sys.stderr.flush()
        line = sys.stdin.readline()
        if not line:
            raise EOFError  # same contract as input() at end of input
        return line.rstrip("\n")

    def write(message: str) -> None:
        print(message, file=sys.stderr)

    return prompt, write


def render_install_summary(result: dict[str, object]) -> str:
    """A human summary of what was installed and where."""
    out = sys.stdout
    persistent = bool(result.get("boot_persistence"))
    lines = [
        "",
        terminal.heading("Ori Runtime installed", stream=out),
        "",
        f"  version   {result.get('version', '')}",
        f"  scope     {result.get('scope', '')}",
        f"  device    {result.get('device_id', '')}",
    ]
    for label, key in (
        ("root", "install_root"),
        ("release", "active_release"),
        ("config", "config_path"),
        ("data", "data_path"),
        ("socket", "health_socket"),
        ("unit", "unit_path"),
    ):
        value = result.get(key)
        if value:
            lines.append(f"  {label.ljust(9)} {terminal.path(str(value), stream=out)}")
    service_user = result.get("service_user")
    if service_user:
        lines.append(f"  runs as   {service_user}")

    lines.append("")
    if persistent:
        lines.append(
            terminal.success(
                "  Starts during boot without anyone logging in.", stream=out
            )
        )
    else:
        lines.append(
            terminal.warning(
                "  WARNING: this service is not persistent. It stops after your "
                "last\n  session ends and does not start at boot unless lingering "
                "is enabled.",
                stream=out,
            )
        )
        lines.append(
            terminal.warning(
                "  Enable it with: sudo loginctl enable-linger $USER", stream=out
            )
        )
    # Martins' original report was an installation that ended by naming a
    # command that did not exist. Computing honest guidance and then not
    # printing it in the default output would reproduce exactly that.
    step = str(result.get("next_step", "")).strip()
    if step:
        lines.append("")
        lines.extend(f"  {line}" for line in step.splitlines())

    warnings = result.get("warnings")
    if isinstance(warnings, list):
        for warning in warnings:
            lines.append(terminal.warning(f"  {warning}", stream=out))

    lines.append("")
    return "\n".join(lines)


# One schema number covers both outcomes: a consumer reads schema_version and
# branches on ok, rather than guessing which shape it received.
RESULT_SCHEMA_VERSION = 1
ERROR_SCHEMA_VERSION = RESULT_SCHEMA_VERSION


def _exit_error(
    error: ReleaseBundleError | LinuxInstallError, *, json_mode: bool = False
) -> NoReturn:
    """Report a stable failure, in the form the caller asked for.

    A JSON run must produce a JSON document whether it succeeded or not.
    Failing to plain text leaves an orchestrator with nothing to parse, so a
    precise installer error such as ``unsupported_target`` degrades into a
    generic "installation failed" by the time an operator sees it.
    """
    print(f"{error.code}: {error.detail}", file=sys.stderr)
    if json_mode:
        print(
            json.dumps(
                {
                    "schema_version": ERROR_SCHEMA_VERSION,
                    "ok": False,
                    "error": {"code": error.code, "detail": error.detail},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    raise SystemExit(2)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = _install(args) if args.command == "install" else _uninstall(args)
    except (ReleaseBundleError, LinuxInstallError) as exc:
        _exit_error(exc, json_mode=bool(getattr(args, "json", False)))
    if getattr(args, "json", False) or args.command != "install":
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(render_install_summary(result))
    return os.EX_OK


if __name__ == "__main__":
    raise SystemExit(main())
