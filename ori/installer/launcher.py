# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``ori`` launcher: one stable command across upgrades and rollbacks.

The launcher resolves the active release when it runs, never when it is
written. Baking today's release path into the command would pin it: an upgrade
would leave the operator running the previous version, and a rollback would
leave them running a release that no longer exists.

Installation is transactional in the same sense as the rest of the installer —
the replacement is written beside the target, fsynced, and moved into place with
``os.replace``, so a launcher is either the old one or the new one and never a
half-written file.
"""

from __future__ import annotations

import os
import shlex
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

MARKER = "# ori-launcher: managed by Ori Runtime — do not edit"
_MODE = 0o755

# The launcher body will change between releases — a security fix to the
# privilege guard is exactly the case that must remain deliverable. So identity
# lives in fixed metadata lines that any installer can parse, and ownership is
# decided from those rather than from the body of whichever template happens to
# be running. Bump this when the metadata format itself changes, not when the
# script body does.
SCHEMA_VERSION = 1

_SCHEMA_KEY = "# ori-launcher-schema:"
_ROOT_KEY = "# ori-launcher-root:"
_SCOPE_KEY = "# ori-launcher-scope:"
_SCOPES = ("user", "system")

_TEMPLATE_V1 = """#!/bin/sh
{marker}
# ori-launcher-schema: {schema}
# ori-launcher-root: {root_metadata}
# ori-launcher-scope: {scope}
#
# Resolves the active release at execution time so that upgrades and rollbacks
# take effect without rewriting this file.
set -eu
{privilege_guard}
ORI_INSTALL_ROOT={root}
ORI_ENTRY_POINT="$ORI_INSTALL_ROOT/current/venv/bin/ori"

if [ ! -x "$ORI_ENTRY_POINT" ]; then
    echo "ori: no active release at $ORI_INSTALL_ROOT/current" >&2
    echo "ori: the installation may be mid-upgrade, rolled back, or removed" >&2
    exit 69
fi

exec "$ORI_ENTRY_POINT" "$@"
"""


# A user installation is writable by the account that owns it, so running it
# as root would let that account choose what root executes. Python refuses this
# too, but the launcher reaches the release first — the refusal has to happen
# in the shell, before the interpreter inside the release is invoked at all.
# Resolved through PATH, `id` is chosen by whoever runs the launcher — which
# is exactly the account this guard exists to constrain. The check therefore
# names an absolute, root-owned executable and refuses when it cannot get a
# trustworthy answer from it.
_TRUSTED_ID = "/usr/bin/id"

_USER_PRIVILEGE_GUARD_V1 = """
ORI_TRUSTED_ID={trusted_id}
if [ ! -x "$ORI_TRUSTED_ID" ]; then
    echo "ori: cannot verify the current user: $ORI_TRUSTED_ID is unavailable." >&2
    echo "ori: refusing to continue without that check." >&2
    exit 77
fi
if ! ORI_UID=$("$ORI_TRUSTED_ID" -u 2>/dev/null); then
    echo "ori: cannot verify the current user; refusing to continue." >&2
    exit 77
fi
case "$ORI_UID" in
    ''|*[!0-9]*)
        echo "ori: cannot verify the current user; refusing to continue." >&2
        exit 77
        ;;
esac
if [ "$ORI_UID" -eq 0 ]; then
    echo "ori: refusing to run a user installation as root." >&2
    echo "ori: its files are writable by their owner, so this would execute" >&2
    echo "ori: unprivileged code with full privilege. Re-run without sudo." >&2
    exit 77
fi
"""


# Ownership is decided by exact match against the forms this installer knows
# how to emit — not by what a file claims about itself. Metadata lines can be
# copied into any script; a byte-for-byte match cannot. When the body changes,
# add the new version here and keep the immediately previous one so launchers
# written by the last release stay upgradeable.
_TEMPLATES: dict[int, tuple[str, str]] = {1: (_TEMPLATE_V1, _USER_PRIVILEGE_GUARD_V1)}


def supported_versions() -> frozenset[int]:
    return frozenset(_TEMPLATES)


def render(install_root: Path, scope: str, *, version: int | None = None) -> str:
    """Return launcher text that resolves ``install_root`` at execution time.

    A system launcher may be run by anyone: its target is installer-controlled
    and root-owned. A user launcher refuses root outright.
    """
    if scope not in _SCOPES:
        raise ValueError(f"unknown scope: {scope!r}")
    resolved = SCHEMA_VERSION if version is None else version
    try:
        template, guard = _TEMPLATES[resolved]
    except KeyError:
        raise ValueError(f"unknown launcher version: {resolved!r}") from None
    text = str(install_root)
    # The root appears on a single metadata line, so anything that could break
    # out of one line would break identity parsing for every later installer.
    if any(character in text for character in "\n\r") or not text.strip():
        raise ValueError(f"unusable install root: {install_root!r}")
    return template.format(
        marker=MARKER,
        schema=resolved,
        root_metadata=text,
        scope=scope,
        root=shlex.quote(text),
        privilege_guard=(
            guard.format(trusted_id=shlex.quote(_TRUSTED_ID)) if scope == "user" else ""
        ),
    )


class LauncherConflictError(Exception):
    """Something we did not write occupies the launcher path."""


def _assert_replaceable(path: Path, install_root: Path, scope: str) -> None:
    """Refuse to destroy anything this installer did not create.

    ``os.replace`` overwrites without asking, so the check has to happen here.
    A symlink, a directory, an unreadable file, another installation's
    launcher, or an operator's own script all mean the same thing: not ours.
    """
    if not os.path.lexists(path):
        return

    form = matched_form(path, install_root)
    if form is not None:
        if form.scope != scope:
            # The user form carries a root refusal that the system form does
            # not. Swapping one for the other silently would change the
            # privilege policy of an installed command.
            raise LauncherConflictError(
                f"{path} is the launcher for the {form.scope}-scope "
                f"installation at {install_root}, and this is a {scope}-scope "
                "install. Changing scope is a migration: uninstall the "
                f"{form.scope}-scope installation first."
            )
        return

    identity = read_identity(path)
    if identity is not None and identity.schema not in supported_versions():
        raise LauncherConflictError(
            f"{path} appears to have been written by a newer version of Ori "
            f"(launcher schema {identity.schema}; this release understands "
            f"{sorted(supported_versions())}). Use that version to change it."
        )
    if identity is not None and identity.install_root != str(install_root):
        raise LauncherConflictError(
            f"{path} declares the Ori installation at {identity.install_root}, "
            f"not {install_root}. Remove that installation first, or choose "
            "another location for this one."
        )
    raise LauncherConflictError(
        f"{path} already exists and is not a launcher this installer wrote, so "
        "it will not be replaced. Move it aside, or choose another location "
        "for the ori command."
    )


def install(path: Path, install_root: Path, scope: str) -> None:
    """Write the launcher to ``path``, replacing only a launcher of our own."""
    _assert_replaceable(path, install_root, scope)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, staged_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    staged = Path(staged_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(render(install_root, scope))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(staged, _MODE)
        os.replace(staged, path)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    _fsync_directory(path.parent)


def _fsync_directory(directory: Path) -> None:
    """Persist the rename itself, not merely the bytes it points at."""
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - some filesystems refuse directory fsync
        pass
    finally:
        os.close(fd)


@dataclass(frozen=True)
class LauncherForm:
    """A launcher this installer recognises as one of its own."""

    version: int
    scope: str


@dataclass(frozen=True)
class LauncherIdentity:
    """What a file *claims* about itself. Never sufficient to authorise a write."""

    schema: int
    install_root: str
    scope: str


def read_identity(path: Path) -> LauncherIdentity | None:
    """Parse a file's declared identity, for diagnostics only.

    These lines are self-asserted: any script can contain them. They are used
    to explain a conflict — which installation a launcher belongs to, or that
    it came from a newer release — never to decide whether a file may be
    overwritten. :func:`matched_form` makes that decision.
    """
    try:
        if path.is_symlink() or not path.is_file():
            return None
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    if MARKER not in content.splitlines():
        return None

    values: dict[str, str] = {}
    for line in content.splitlines():
        for key in (_SCHEMA_KEY, _ROOT_KEY, _SCOPE_KEY):
            if line.startswith(key) and key not in values:
                values[key] = line[len(key) :].strip()
    if len(values) != 3:
        return None
    try:
        schema = int(values[_SCHEMA_KEY])
    except ValueError:
        return None
    return LauncherIdentity(schema, values[_ROOT_KEY], values[_SCOPE_KEY])


def matched_form(path: Path, install_root: Path) -> LauncherForm | None:
    """Return the launcher form ``path`` exactly is, or None if it is not ours.

    The file must be byte-for-byte one of the launchers this installer emits
    for this install root. An operator's script carrying the same metadata
    lines does not match, so it is never overwritten.
    """
    try:
        if path.is_symlink() or not path.is_file():
            return None
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    for version in sorted(_TEMPLATES, reverse=True):
        for scope in _SCOPES:
            if content == render(install_root, scope, version=version):
                return LauncherForm(version, scope)
    return None


def is_managed(path: Path, install_root: Path) -> bool:
    """Whether ``path`` is exactly a launcher this installer wrote."""
    return matched_form(path, install_root) is not None


def remove(path: Path, install_root: Path) -> bool:
    """Remove the launcher if we wrote it. Returns whether it was removed."""
    if not is_managed(path, install_root):
        return False
    try:
        path.unlink()
    except OSError:
        return False
    _fsync_directory(path.parent)
    return True


def path_guidance(path: Path, path_entries: Sequence[str] | None = None) -> str | None:
    """Return what the operator must do before a bare ``ori`` will work.

    Claiming the command is ready when its directory is not on PATH is the
    failure this exists to prevent, so the caller gets the exact export line
    rather than a suggestion to check their shell configuration.
    """
    entries = (
        [e for e in os.environ.get("PATH", "").split(os.pathsep) if e]
        if path_entries is None
        else path_entries
    )
    directory = str(path.parent)
    if directory in entries:
        return None
    return (
        f"{directory} is not on your PATH, so the `ori` command will not be "
        f"found yet.\nAdd it for this shell:\n"
        f'    export PATH="{directory}:$PATH"\n'
        f"To make it permanent, add that line to ~/.profile (or ~/.bashrc, or "
        f"~/.zshrc for zsh)."
    )
