# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path


def path_is_relative_to(path: Path, prefix: Path) -> bool:
    """Return True when path is inside prefix without requiring either to exist."""
    try:
        path.relative_to(prefix)
        return True
    except ValueError:
        return False


def shown(name: object) -> str:
    """A filesystem name as operator output, quoted and escaped.

    A refusal is produced when something about a path is already wrong, which
    is when an operator reads most carefully and distrusts least. The name in
    it is not always one they chose: a walk over a path's parents reports
    whichever component failed, and a directory listing reports whatever it
    found, so a name a less-privileged account created in a shared location
    reaches a terminal intact.

    `repr` of the string covers what that name can do there: an escape
    sequence that erases the line it is printed on, a newline that forges a
    second diagnostic, a carriage return that overwrites the first, a bidi
    mark that reverses how the rest reads, and the surrogate escapes Python
    uses for bytes that are not valid in the filesystem encoding.
    """
    return repr(str(name))
