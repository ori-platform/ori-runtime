# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``ori`` command: one entry point an operator can remember.

This is a front door, not a second implementation. Every subcommand delegates
to the hardened code that already owns its behaviour — signature verification,
the install transaction, config validation, diagnostics — so there is exactly
one place where each security decision is made.

Help text carries what an operator actually needs at the moment they are stuck:
what the command will change, which scope it acts on, what the exit status
means, and how to run it without a terminal.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import IO, Any, Sequence

from ori.utils import terminal


def _version() -> str:
    """The version of the release actually executing, not a compiled-in string."""
    from importlib import metadata

    try:
        return metadata.version("ori-runtime")
    except metadata.PackageNotFoundError:  # pragma: no cover - source checkout
        return "unknown"


EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNUSABLE = 2

_EXIT_STATUS_HELP = """
exit status:
  0  the command succeeded, or diagnostics found nothing blocking
  1  the command ran and reported a failure (a blocking doctor result,
     a failed install, an invalid config)
  2  the command could not run at all (no installation found, an
     ambiguous scope, or a refusal on safety grounds)
"""

_SCOPE_HELP = """
scope:
  system   Installed under /opt/ori, run by the unprivileged ori-runtime user,
           started during boot without anyone logging in. Recommended for
           deployed devices. Requires administrator privileges.
  user     Installed under ~/.local/ori and run as your login user. Intended
           for workstation evaluation. Stops after your last session ends and
           does not start at boot unless lingering is enabled.

  Scope is never guessed from whether you used sudo. When both a user and a
  system installation exist, pass --scope to say which one you mean.
"""


def _formatter(prog: str) -> argparse.HelpFormatter:
    return argparse.RawDescriptionHelpFormatter(prog, max_help_position=32)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ori",
        description="Ori Runtime — inspect, install, and maintain this device.",
        epilog=(
            "examples:\n"
            "  ori doctor                    diagnose the installation\n"
            "  ori doctor --json             the same, as one JSON document\n"
            "  ori status                    a one-screen summary\n"
            "  ori config validate           check the installed config\n"
            "  ori install --bundle ... --signature ...\n"
            "                                verify and install a release\n"
            "\n"
            "Run `ori <command> --help` for what each one changes.\n"
            + _EXIT_STATUS_HELP
        ),
        formatter_class=_formatter,
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ori {_version()}",
        help="print the version of the running release and exit",
    )
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    _add_doctor(commands)
    _add_status(commands)
    _add_config(commands)
    _add_install(commands)
    _add_uninstall(commands)
    return parser


def _scope_argument(parser: argparse.ArgumentParser, *, required: bool = False) -> None:
    parser.add_argument(
        "--scope",
        choices=("user", "system"),
        required=required,
        help=(
            "which installation to act on; required when both exist"
            if not required
            else "which installation to act on (no default: state it explicitly)"
        ),
    )


def _add_doctor(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = commands.add_parser(
        "doctor",
        help="diagnose the installation and report what is wrong",
        description=(
            "Check that this device's runtime is installed correctly, running, "
            "serving the right device, readable by its service account, and "
            "unable to modify its own verified code. Changes nothing."
        ),
        epilog=(
            "examples:\n"
            "  ori doctor                    diagnose the only installation\n"
            "  ori doctor --scope system     diagnose the system installation\n"
            "  ori doctor --json             emit one JSON document on stdout\n"
            "\n"
            "Optional integrations that are switched off are reported as "
            "warnings, not failures.\n"
            "A user service that does not survive a reboot is a warning too.\n"
            + _SCOPE_HELP
            + _EXIT_STATUS_HELP
        ),
        formatter_class=_formatter,
        allow_abbrev=False,
    )
    _scope_argument(parser)
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="diagnose the installation at this exact root",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit one JSON document on stdout; diagnostics go to stderr",
    )
    parser.set_defaults(handler=_run_doctor)


def _add_status(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = commands.add_parser(
        "status",
        help="show where this installation lives and whether it is running",
        description=(
            "Summarise the installation: scope, version, paths, service state, "
            "and whether the runtime comes back after a reboot. Changes "
            "nothing, and does not execute the release."
        ),
        epilog=(
            "examples:\n"
            "  ori status\n"
            "  ori status --scope user --json\n" + _SCOPE_HELP + _EXIT_STATUS_HELP
        ),
        formatter_class=_formatter,
        allow_abbrev=False,
    )
    _scope_argument(parser)
    parser.add_argument(
        "--json", action="store_true", help="emit one JSON document on stdout"
    )
    parser.set_defaults(handler=_run_status)


def _add_config(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = commands.add_parser(
        "config",
        help="inspect this device's configuration",
        description="Work with the installed ori.yaml.",
        formatter_class=_formatter,
        allow_abbrev=False,
    )
    subcommands = parser.add_subparsers(dest="subcommand", metavar="<subcommand>")
    validate = subcommands.add_parser(
        "validate",
        help="check the config and report the first problem",
        description=(
            "Validate a config through the runtime's own loader, so what it "
            "accepts here is exactly what the runtime will accept at startup."
        ),
        epilog=(
            "examples:\n"
            "  ori config validate                     the installed config\n"
            "  ori config validate --path ./ori.yaml   a config before deploying it\n"
            "\n"
            "exit status:\n"
            "  0  the config is valid\n"
            "  1  the config is invalid; the reason is printed\n"
            "  2  the config could not be read\n"
        ),
        formatter_class=_formatter,
        allow_abbrev=False,
    )
    _scope_argument(validate)
    validate.add_argument(
        "--path", help="validate this file instead of the installed config"
    )
    validate.add_argument(
        "--json", action="store_true", help="emit one JSON document on stdout"
    )
    validate.set_defaults(handler=_run_config_validate)
    parser.set_defaults(handler=_require_subcommand, parser=parser)


def _add_install(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = commands.add_parser(
        "install",
        help="verify and install a release bundle",
        description=(
            "Verify a signed release bundle and hand the installation to the "
            "installer shipped inside that verified bundle. The installed "
            "release never installs its successor: the new bundle brings its "
            "own installer, so an upgrade is carried out by the code that was "
            "signed alongside it."
        ),
        epilog=(
            "examples:\n"
            "  ori install --bundle ori-runtime.tar.gz \\\n"
            "              --signature ori-runtime.tar.gz.signature.json \\\n"
            "              --scope system\n"
            "\n"
            "unattended:\n"
            "  Pass --unattended with --scope and every identity option you "
            "want set.\n"
            "  Unattended runs never prompt and never modify the host's "
            "packages.\n" + _SCOPE_HELP + _EXIT_STATUS_HELP
        ),
        formatter_class=_formatter,
        allow_abbrev=False,
    )
    parser.add_argument("--bundle", required=True, help="path to the release bundle")
    parser.add_argument(
        "--signature", required=True, help="path to its detached signature envelope"
    )
    _scope_argument(parser)
    parser.add_argument("--expected-version", help="refuse a bundle of another version")
    parser.add_argument(
        "--unattended", action="store_true", help="never prompt; fail instead of asking"
    )
    parser.add_argument("--device-id", help="stable identifier for this device")
    parser.add_argument(
        "--generate-device-id",
        action="store_true",
        help=(
            "derive a device ID from this host when --device-id is omitted; "
            "adds a random suffix on stock-image hostnames, so an unattended "
            "run is only reproducible when this is off"
        ),
    )
    parser.add_argument("--name", help="human-readable name for this device")
    parser.add_argument("--location", help="where this device is installed")
    parser.add_argument(
        "--deployment-type",
        choices=("pi", "server"),
        default="pi",
        help="hardware profile this device is deployed on",
    )
    parser.add_argument(
        "--operator-contact", help="who to reach about this device (optional)"
    )
    parser.add_argument(
        "--service-user",
        help="retained for compatibility; the system account is always ori-runtime",
    )
    parser.add_argument(
        "--root", help="install under this root instead of the default for the scope"
    )
    parser.add_argument(
        "--allow-downgrade",
        action="store_true",
        help="permit installing a version older than the active one",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit one JSON document on stdout"
    )
    parser.set_defaults(handler=_run_install)


def _add_uninstall(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = commands.add_parser(
        "uninstall",
        help="stop the service and remove the installation",
        description=(
            "Disable and remove the service, then remove the installation and "
            "the launcher this installer wrote. Collected data is kept unless "
            "--remove-data is given."
        ),
        epilog=(
            "examples:\n"
            "  ori uninstall --scope user\n"
            "  sudo ori uninstall --scope system --remove-data\n"
            "\n"
            "Only launchers written by this installer are removed; a file you "
            "put at that path yourself is left alone.\n"
            + _SCOPE_HELP
            + _EXIT_STATUS_HELP
        ),
        formatter_class=_formatter,
        allow_abbrev=False,
    )
    _scope_argument(parser, required=True)
    parser.add_argument(
        "--remove-data",
        action="store_true",
        help="also delete collected data and the device config",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit one JSON document on stdout"
    )
    parser.set_defaults(handler=_run_uninstall)


def _out(args: argparse.Namespace) -> IO[str]:
    """In JSON mode stdout carries the document alone; prose goes to stderr."""
    return sys.stderr if getattr(args, "json", False) else sys.stdout


def _emit(args: argparse.Namespace, payload: dict[str, Any], human: str) -> None:
    if getattr(args, "json", False):
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(human)


def _require_subcommand(args: argparse.Namespace) -> int:
    args.parser.print_help(sys.stderr)
    return EXIT_UNUSABLE


def _resolve(args: argparse.Namespace) -> tuple[Any, str] | int:
    """Resolve the installation, turning every lookup failure into an exit code."""
    from ori.installer.paths import (
        AmbiguousScopeError,
        UnmanagedReleaseError,
        resolve_identity,
    )

    try:
        return resolve_identity(scope=args.scope)
    except AmbiguousScopeError as exc:
        print(f"ori: {exc}", file=sys.stderr)
        return EXIT_UNUSABLE
    except UnmanagedReleaseError as exc:
        print(f"ori: unusable installation: {exc}", file=sys.stderr)
        return EXIT_UNUSABLE
    except FileNotFoundError as exc:
        print(f"ori: no installation found: {exc}", file=sys.stderr)
        return EXIT_UNUSABLE


def _run_doctor(args: argparse.Namespace) -> int:
    from ori import doctor

    return doctor.run(args.scope, root=args.root, json_mode=args.json)


def _run_status(args: argparse.Namespace) -> int:
    from ori import doctor

    resolved = _resolve(args)
    if isinstance(resolved, int):
        return resolved
    identity, _device_id = resolved
    checks = doctor.check_service(identity)
    payload = {
        "schema_version": 1,
        "identity": identity.as_dict(),
        "service": [
            {"name": c.name, "status": c.status, "message": c.message} for c in checks
        ],
    }
    _emit(args, payload, doctor.render_report(checks, identity, stream=_out(args)))
    return EXIT_FAILED if doctor.has_failures(checks) else EXIT_OK


def _run_config_validate(args: argparse.Namespace) -> int:
    from ori.cli_bridge import run_bridge

    path = args.path
    if path is None:
        resolved = _resolve(args)
        if isinstance(resolved, int):
            return resolved
        path = str(resolved[0].config_path)

    status, payload = run_bridge(["config", "validate", "--path", path])
    stream = _out(args)
    if status == 0:
        _emit(
            args, payload, terminal.success(f"Config is valid: {path}", stream=stream)
        )
        return EXIT_OK
    detail = payload.get("error", {})
    message = detail.get("detail", "config validation failed")
    _emit(
        args,
        payload,
        terminal.failure(f"Config is not valid: {path}", stream=stream)
        + f"\n  {message}",
    )
    return EXIT_FAILED


def _run_install(args: argparse.Namespace) -> int:
    from ori.installer.upgrade import UpgradeError, install_from_bundle

    try:
        payload = install_from_bundle(args)
    except UpgradeError as exc:
        print(f"ori: {exc}", file=sys.stderr)
        return EXIT_FAILED
    _emit(args, payload, str(payload.get("summary", "")))
    return EXIT_OK if payload.get("status") == "healthy" else EXIT_FAILED


def _run_uninstall(args: argparse.Namespace) -> int:
    from ori.installer.cli import main as installer_main

    forwarded = ["uninstall", "--scope", args.scope]
    if args.remove_data:
        forwarded.append("--remove-data")
    return installer_main(forwarded)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "handler", None) is None:
        parser.print_help(sys.stderr)
        return EXIT_UNUSABLE
    handler: Any = args.handler
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
