# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``device_policy`` section."""

import logging
from typing import Any

from ori.config._fields import ConfigValidationError

logger = logging.getLogger("ori.config")


def parse_device_policy(data: Any) -> dict:
    """Parse remote DevicePolicy fetch settings."""
    default_policy = {
        "enabled": False,
        "url": "",
        "auth_token": "",
        "public_key_b64": "",
        "request_timeout_ms": 3000,
        "max_clock_skew_s": 300,
        "refresh_enabled": False,
        "refresh_interval_s": 21600,
    }

    if data is None:
        return default_policy

    if not isinstance(data, dict):
        logger.warning(
            "[config] 'device_policy' is not a mapping. Falling back to defaults."
        )
        return default_policy

    try:
        enabled = bool(data.get("enabled", False))
        url = str(data.get("url", "") or "").strip()
        auth_token = str(data.get("auth_token", "") or "").strip()
        public_key_b64 = str(data.get("public_key_b64", "") or "").strip()
        request_timeout_ms = int(data.get("request_timeout_ms", 3000))
        max_clock_skew_s = int(data.get("max_clock_skew_s", 300))
        refresh_enabled = bool(data.get("refresh_enabled", False))
        refresh_interval_s = int(data.get("refresh_interval_s", 21600))
    except (TypeError, ValueError):
        logger.warning(
            "[config] 'device_policy' has invalid types. Falling back to defaults."
        )
        return default_policy

    if request_timeout_ms < 100:
        raise ConfigValidationError("device_policy.request_timeout_ms must be >= 100.")
    if max_clock_skew_s < 1:
        raise ConfigValidationError("device_policy.max_clock_skew_s must be >= 1.")
    if refresh_interval_s < 60:
        raise ConfigValidationError("device_policy.refresh_interval_s must be >= 60.")

    if enabled:
        if not url:
            raise ConfigValidationError(
                "device_policy.enabled is true but 'url' is empty."
            )
        if not url.startswith("https://"):
            raise ConfigValidationError(
                "device_policy.url must start with https:// when enabled."
            )
        if not auth_token or "${" in auth_token:
            raise ConfigValidationError(
                "device_policy.auth_token is missing or not properly interpolated."
            )
        if not public_key_b64 or "${" in public_key_b64:
            raise ConfigValidationError(
                "device_policy.public_key_b64 is missing or not properly interpolated."
            )

    out: dict[str, Any] = {
        "enabled": enabled,
        "url": url,
        "auth_token": auth_token,
        "public_key_b64": public_key_b64,
        "request_timeout_ms": request_timeout_ms,
        "max_clock_skew_s": max_clock_skew_s,
        "refresh_enabled": refresh_enabled,
        "refresh_interval_s": refresh_interval_s,
    }
    return out
