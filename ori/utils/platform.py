# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The host platform, read at runtime.

pyright evaluates a comparison on `sys.platform`, `os.name` or
`sys.version_info` against the platform it analyses for, and neither reports
nor type-checks the branch that comparison rules out. The runtime ships on
Linux and runs its tests on macOS too, so a branch written that way is code no
checker ever reads. These return the same values as plain `str`, which no
checker narrows, so every branch keyed on them stays checked.
"""

from __future__ import annotations

import os
import sys

__all__ = ["os_name", "runtime_platform", "runtime_version_info"]


def runtime_platform() -> str:
    """`sys.platform`, as a value the type checker does not evaluate."""
    return sys.platform


def os_name() -> str:
    """`os.name`, as a value the type checker does not evaluate."""
    return os.name


def runtime_version_info() -> tuple[int, ...]:
    """The interpreter's version numbers, as a value the checker does not evaluate."""
    return tuple(sys.version_info[:3])
