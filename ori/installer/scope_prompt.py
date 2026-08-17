# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Make installation scope an explicit operator decision.

Scope determines whether the runtime comes back after a power cut and whether
it can rewrite its own code, so it is never chosen silently. Interactive runs
present both options with their consequences and require a submitted answer;
unattended runs require ``--scope`` and fail before touching the host.

Privilege is never escalated here. If an operator picks system scope without
root, the run ends with the exact command to repeat — keeping the privilege
boundary visible instead of hiding a ``sudo`` inside the installer.
"""

from __future__ import annotations

import os
import shlex
import sys
from typing import IO, Callable, Sequence

from ori.installer.linux import LinuxInstallError
from ori.utils import terminal

_PROMPT = """
{heading}

  {one} System — recommended for deployed devices
     Starts during boot without login.
     Runs as dedicated unprivileged user ori-runtime.
     Requires administrator privileges.

  {two} User — intended for workstation evaluation
     Runs as your login user.
     Stops after your last session unless lingering is enabled.
     Does not start at boot without lingering.

Type 1 or 2. Press Enter to accept 1 (system).
"""

_CHOICES = {"1": "system", "2": "user", "system": "system", "user": "user"}
_ATTEMPTS = 3


def choose_scope(
    *,
    supplied: str | None,
    unattended: bool,
    prompt: Callable[[str], str] = input,
    write: Callable[[str], None] = print,
    stream: IO[str] | None = None,
) -> str:
    """Return the installation scope, asking only when it is safe to ask."""
    if supplied is not None:
        return supplied
    if unattended:
        # No default: automation that omits scope must fail, not guess.
        raise LinuxInstallError(
            "config_validation_failed",
            "unattended mode requires --scope system or --scope user",
        )
    if not sys.stdin.isatty():
        # Nothing to read, so any choice here would be invented.
        raise LinuxInstallError(
            "config_validation_failed",
            "installation scope is required; pass --scope system or --scope user",
        )

    out = stream if stream is not None else sys.stdout
    write(
        _PROMPT.format(
            heading=terminal.heading("Installation scope:", stream=out),
            one=terminal.style("1.", terminal.BOLD, stream=out),
            two=terminal.style("2.", terminal.BOLD, stream=out),
        )
    )
    for _attempt in range(_ATTEMPTS):
        try:
            answer = prompt("Choose [1]: ").strip().lower()
        except (EOFError, KeyboardInterrupt) as exc:
            raise LinuxInstallError(
                "config_validation_failed", "installation was cancelled"
            ) from exc
        # An empty submission accepts the shown default; the operator still had
        # to submit it, so the choice is theirs.
        if not answer:
            return "system"
        if answer in _CHOICES:
            return _CHOICES[answer]
        write("  Enter 1 for system or 2 for user.")
    raise LinuxInstallError(
        "config_validation_failed", "no installation scope chosen after 3 attempts"
    )


def require_privilege(scope: str, argv: Sequence[str]) -> None:
    """Refuse a scope the current privilege cannot install, with the fix.

    The installer never escalates for the operator: doing so would move the
    privilege boundary out of their sight, and any input collected beforehand
    would have to be carried across it.
    """
    euid = os.geteuid()
    if scope == "system" and euid != 0:
        raise LinuxInstallError(
            "service_start_failed",
            "system scope requires administrator privileges. Re-run:\n"
            f"  sudo {rerun_command(argv, scope)}",
        )
    if scope == "user" and euid == 0:
        raise LinuxInstallError(
            "service_start_failed",
            "user scope must not be installed as root; re-run without sudo",
        )


def rerun_command(argv: Sequence[str], scope: str) -> str:
    """Build the exact command that repeats this run with the scope fixed."""
    filtered: list[str] = []
    skip_value = False
    for argument in argv:
        if skip_value:
            # This is the value belonging to a --scope we already dropped.
            skip_value = False
            continue
        if argument == "--scope":
            skip_value = True
            continue
        if argument.startswith("--scope="):
            continue
        filtered.append(argument)
    # `--` ends this parser's options: anything after it is forwarded onward,
    # so appending the scope there would hand it to the wrong program.
    if "--" in filtered:
        separator = filtered.index("--")
        return shlex.join(
            [*filtered[:separator], "--scope", scope, *filtered[separator:]]
        )
    return shlex.join([*filtered, "--scope", scope])
