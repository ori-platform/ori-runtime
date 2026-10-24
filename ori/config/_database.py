# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``database`` section, and anchoring a declared path to the configuration."""

import logging
import os
from pathlib import Path
from typing import Any

from ori.config._fields import ConfigValidationError
from ori.utils.path_utils import shown

logger = logging.getLogger("ori.config")


#: SQLite's private in-memory database. It names no file, so it is not a path
#: to resolve.
_IN_MEMORY_STORE = ":memory:"


def parse_database_path(data: Any) -> str:
    if data is None:
        return "ori_state.db"
    if not isinstance(data, dict):
        raise ConfigValidationError("'database' section must be a mapping.")
    path = str(data.get("path", "ori_state.db") or "").strip()
    if not path:
        raise ConfigValidationError("database.path must not be empty.")
    return path


def anchor_to_config(declared: str, config_path: str) -> str:
    """Anchor a relative path to the directory holding the configuration.

    A relative path otherwise resolves against the working directory of
    whatever process loaded the configuration, so the file a deployment reads
    or writes would be a property of where it was started.
    """
    if not declared:
        return declared
    candidate = Path(declared).expanduser()
    if candidate.is_absolute():
        return str(candidate)
    home = Path(config_path).expanduser().resolve(strict=False).parent
    return str(Path(os.path.normpath(home / candidate)))


def resolve_database_path(declared: str, config_path: str) -> str:
    """Resolve a relative store path against the configuration that declared it.

    A relative path otherwise resolves against the caller's working directory,
    which makes both the store a command opens and the production
    encrypted-storage check a property of where a process was started.
    """
    if declared == _IN_MEMORY_STORE:
        return declared
    if Path(declared).expanduser().is_absolute():
        return anchor_to_config(declared, config_path)
    resolved = Path(anchor_to_config(declared, config_path))
    legacy = Path(declared)
    if legacy.is_file() and not resolved.exists():
        # Opening the resolved store creates it, so a deployment that relied on
        # the working directory would come up on an empty one. A file of that
        # name in the working directory is a coincidence as often as it is that
        # deployment, so this reports rather than refuses.
        logger.warning(
            "[config] database.path %s resolves to %s, which does not exist, "
            "while a file of that name exists at %s. A relative database.path "
            "is resolved against the directory holding the configuration, not "
            "the working directory. If that file is this device's store, move "
            "it beside the configuration or declare database.path absolutely.",
            shown(declared),
            shown(resolved),
            shown(legacy.resolve(strict=False)),
        )
    return str(resolved)
