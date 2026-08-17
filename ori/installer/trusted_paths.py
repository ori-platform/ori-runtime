# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""One definition of a path only root can change.

Several places need the same answer before they hand something privilege: the
interpreter root is about to execute, an executable a release links out to, the
`useradd` the installer runs as root. Each previously asked it in its own way,
and the answers disagreed — most consequentially over symlinks, whose mode bits
Linux reports as ``0777`` regardless of what they point at. Reading that as
write permission classifies every virtual environment's ``bin/python`` as
attacker-writable, which is how a correctly installed, root-owned release came
to be refused by its own diagnostics.

The rule stated once, here:

- Ownership is checked on every component. Anything not owned by root is
  untrusted, symlinks included.
- Write permission is checked on directories and on the final file. It is never
  checked on a symlink, because a symlink's mode grants nothing: replacing one
  requires write permission on the directory holding it, which the walk has
  already established.
- Symlinks are followed one hop at a time, and every destination along the way
  is validated in full — not only the path that resolution finally lands on.
- Resolution is bounded and cycle-aware, so a malicious or broken link tree
  ends the check instead of the process.

Trust is the test, not containment. A virtual environment's interpreter
normally resolves to ``/usr/bin/python3.12`` or ``/usr/local/bin/python3.12``,
well outside the installation, and that is fine as long as root alone controls
it. Requiring targets to stay inside the release would reject every venv ever
built.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

# Deep enough for any legitimate interpreter chain — `python` to `python3` to
# `python3.12` to the packaged binary is four — and shallow enough that a
# hostile link tree ends quickly.
MAX_SYMLINK_HOPS = 40

_OTHER_WRITE = stat.S_IWGRP | stat.S_IWOTH


def trust_failure(
    path: str | os.PathLike[str],
    *,
    require_executable: bool = False,
) -> str | None:
    """Return why root cannot trust *path*, naming the component, or None.

    With *require_executable*, the path must exist and end at a regular,
    root-owned, root-writable-only executable. Without it, the path is judged
    as far as it exists: a component that is missing beneath trusted ancestors
    cannot be created by an unprivileged account, so nothing can be planted
    there and the walk ends successfully.
    """
    failure = _walk(
        Path(path),
        require_executable=require_executable,
        budget=[MAX_SYMLINK_HOPS],
        seen=set(),
    )
    if failure is None:
        return None
    component, reason = failure
    return f"{component} {reason}"


def _walk(
    path: Path,
    *,
    require_executable: bool,
    budget: list[int],
    seen: set[tuple[int, int]],
) -> tuple[Path, str] | None:
    for component in [*reversed(path.parents), path]:
        final = component == path
        try:
            info = os.lstat(component)
        except FileNotFoundError:
            if require_executable:
                # Something has to be run at the end of this path, and a gap
                # anywhere along it means there is nothing to run.
                return component, "does not exist"
            # Beneath trusted ancestors, only root could create what is
            # missing, so there is nothing here to distrust.
            return None
        except OSError as exc:
            # Never "probably fine": an inode that cannot be inspected cannot
            # be shown to be safe.
            return component, f"could not be inspected ({exc.strerror or exc})"

        if info.st_uid != 0:
            return component, "is not owned by root"

        if stat.S_ISLNK(info.st_mode):
            failure = _follow(
                component,
                require_executable=require_executable and final,
                budget=budget,
                seen=seen,
            )
            if failure is not None:
                return failure
            if final:
                return None
            continue

        if stat.S_ISDIR(info.st_mode):
            if info.st_mode & _OTHER_WRITE:
                return component, "is writable by another account"
            if final and require_executable:
                # A directory where the executable should be. Traversing into
                # the next component is what makes a directory acceptable, and
                # there is no next component here.
                return component, "is not a regular file"
            continue

        if not final:
            return component, "is not a directory"

        if require_executable and not stat.S_ISREG(info.st_mode):
            return component, "is not a regular file"
        if info.st_mode & _OTHER_WRITE:
            return component, "is writable by another account"
        if require_executable and not info.st_mode & 0o111:
            return component, "is not executable"
        return None
    return None


def _follow(
    link: Path,
    *,
    require_executable: bool,
    budget: list[int],
    seen: set[tuple[int, int]],
) -> tuple[Path, str] | None:
    """Validate one hop and everything the destination itself rests on."""
    budget[0] -= 1
    if budget[0] < 0:
        return link, "resolves through too many symlinks"
    try:
        info = os.lstat(link)
    except OSError as exc:
        return link, f"could not be inspected ({exc.strerror or exc})"
    identity = (info.st_dev, info.st_ino)
    if identity in seen:
        return link, "resolves through a symlink cycle"
    seen.add(identity)

    try:
        target = os.readlink(link)
    except OSError as exc:
        return link, f"symlink could not be read ({exc.strerror or exc})"

    destination = Path(os.path.normpath(os.path.join(link.parent, target)))
    return _walk(
        destination,
        require_executable=require_executable,
        budget=budget,
        seen=seen,
    )
