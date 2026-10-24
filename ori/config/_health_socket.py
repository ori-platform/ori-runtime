# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``health_socket`` section."""

import logging
from typing import Any

from ori.config._fields import ConfigValidationError

logger = logging.getLogger("ori.config")


def parse_health_socket(data: Any) -> dict:
    """Parse local read-only health socket configuration."""
    default_socket = {
        "enabled": True,
        "path": "/run/ori/health.sock",
        "mode": 0o660,
    }

    if data is None:
        return default_socket

    if not isinstance(data, dict):
        logger.warning(
            "[config] 'health_socket' is not a mapping. Falling back to defaults."
        )
        return default_socket

    out = dict(default_socket)
    out["enabled"] = bool(data.get("enabled", default_socket["enabled"]))

    path = str(data.get("path", default_socket["path"]) or "").strip()
    if not path:
        raise ConfigValidationError("health_socket.path must not be empty.")
    if "\x00" in path:
        raise ConfigValidationError("health_socket.path contains invalid null bytes.")
    out["path"] = path

    raw_mode = data.get("mode", default_socket["mode"])
    try:
        if isinstance(raw_mode, str):
            mode = int(raw_mode, 0)
        else:
            mode = int(raw_mode)
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "health_socket.mode must be a valid integer (e.g. 0o660)."
        ) from exc
    if mode < 0 or mode > 0o777:
        raise ConfigValidationError("health_socket.mode must be between 0 and 0o777.")
    out["mode"] = mode

    return out
