# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``os_sandbox`` section."""

import logging
from typing import Any

from ori.config._fields import ConfigValidationError

logger = logging.getLogger("ori.config")


def parse_os_sandbox(data: Any) -> dict:
    """Parse community skill OS sandbox settings."""
    defaults = {
        "enabled": True,
        "require_for_community": False,
        "exec_timeout_ms": 2000,
        "max_output_bytes": 65536,
    }
    if data is None:
        return defaults
    if not isinstance(data, dict):
        logger.warning(
            "[config] 'os_sandbox' is not a mapping. Falling back to defaults."
        )
        return defaults

    out = dict(defaults)
    out["enabled"] = bool(data.get("enabled", True))
    out["require_for_community"] = bool(data.get("require_for_community", False))
    try:
        out["exec_timeout_ms"] = int(data.get("exec_timeout_ms", 2000))
        out["max_output_bytes"] = int(data.get("max_output_bytes", 65536))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "os_sandbox.exec_timeout_ms and os_sandbox.max_output_bytes must be integers."
        ) from exc
    if out["exec_timeout_ms"] < 100:
        raise ConfigValidationError("os_sandbox.exec_timeout_ms must be >= 100.")
    if out["max_output_bytes"] < 4096:
        raise ConfigValidationError("os_sandbox.max_output_bytes must be >= 4096.")
    return out
