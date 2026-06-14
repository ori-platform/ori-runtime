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
