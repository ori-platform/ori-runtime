# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``telemetry_export`` section."""

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from ori.config._env import ENV_NAME_RE
from ori.config._fields import ConfigValidationError
from ori.utils.bool_utils import is_truthy
from ori.utils.net_utils import is_loopback_host


@dataclass
class TelemetryExportConfig:
    enabled: bool = False
    endpoint: str = ""
    api_key_env: str = ""
    flush_interval_s: float = 30.0
    batch_size: int = 50
    timeout_ms: int = 3000
    max_queue_size: int = 1000


def parse_telemetry_export(data: Any) -> TelemetryExportConfig:
    if data is None:
        return TelemetryExportConfig()
    if not isinstance(data, dict):
        raise ConfigValidationError("'telemetry_export' section must be a mapping.")

    enabled = is_truthy(data.get("enabled", False))
    endpoint = str(data.get("endpoint", "") or "").strip()
    api_key_env = str(data.get("api_key_env", "") or "").strip()

    try:
        flush_interval_s = float(data.get("flush_interval_s", 30.0))
        batch_size = int(data.get("batch_size", 50))
        timeout_ms = int(data.get("timeout_ms", 3000))
        max_queue_size = int(data.get("max_queue_size", 1000))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "telemetry_export.flush_interval_s, batch_size, timeout_ms, and "
            "max_queue_size must be numeric."
        ) from exc

    if flush_interval_s < 1.0 or flush_interval_s > 300.0:
        raise ConfigValidationError(
            "telemetry_export.flush_interval_s must be between 1 and 300 seconds."
        )
    if batch_size < 1 or batch_size > 500:
        raise ConfigValidationError(
            "telemetry_export.batch_size must be between 1 and 500."
        )
    if timeout_ms < 100 or timeout_ms > 30_000:
        raise ConfigValidationError(
            "telemetry_export.timeout_ms must be between 100 and 30000."
        )
    if max_queue_size < batch_size:
        raise ConfigValidationError(
            "telemetry_export.max_queue_size must be greater than or equal to "
            "telemetry_export.batch_size."
        )

    if enabled:
        if not endpoint:
            raise ConfigValidationError(
                "telemetry_export.endpoint is required when telemetry_export.enabled=true."
            )
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ConfigValidationError(
                "telemetry_export.endpoint must be an absolute http(s) URL."
            )
        if parsed.scheme != "https" and not is_loopback_host(parsed.hostname):
            raise ConfigValidationError(
                "telemetry_export.endpoint must use https:// unless it targets "
                "localhost or 127.0.0.1."
            )
        if not api_key_env:
            raise ConfigValidationError(
                "telemetry_export.api_key_env is required when "
                "telemetry_export.enabled=true."
            )
        if not ENV_NAME_RE.match(api_key_env):
            raise ConfigValidationError(
                "telemetry_export.api_key_env must be an environment variable name."
            )

    return TelemetryExportConfig(
        enabled=enabled,
        endpoint=endpoint,
        api_key_env=api_key_env,
        flush_interval_s=flush_interval_s,
        batch_size=batch_size,
        timeout_ms=timeout_ms,
        max_queue_size=max_queue_size,
    )
