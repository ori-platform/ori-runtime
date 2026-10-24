# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``device`` section."""

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ori.config._fields import (
    ConfigValidationError,
    checked_device_id,
    checked_site_id,
)
from ori.config._fields import require_str as _require_str

logger = logging.getLogger("ori.config")


def _validate_iana_timezone(tz_name: str) -> bool:
    try:
        ZoneInfo(tz_name)
        return True
    except ZoneInfoNotFoundError:
        return False


def _detect_host_timezone() -> str | None:
    """Best-effort host timezone detection using IANA names only."""
    tz_env = str(os.environ.get("TZ", "")).strip()
    if tz_env and _validate_iana_timezone(tz_env):
        return tz_env

    local_tz = datetime.now().astimezone().tzinfo
    key = str(getattr(local_tz, "key", "") or "").strip()
    if key and _validate_iana_timezone(key):
        return key
    return None


def _resolve_device_timezone(raw_value: Any) -> str:
    """Resolve runtime timezone: config value -> host timezone -> UTC."""
    configured = str(raw_value or "").strip()
    if configured:
        if _validate_iana_timezone(configured):
            return configured
        logger.warning(
            "[config] device.timezone=%r is invalid; attempting host timezone fallback.",
            configured,
        )

    host_tz = _detect_host_timezone()
    if host_tz:
        logger.info("[config] using host timezone fallback: %s", host_tz)
        return host_tz

    logger.warning(
        "[config] unable to resolve device timezone from config/host; falling back to UTC."
    )
    return str(timezone.utc)


@dataclass
class DeviceConfig:
    id: str
    name: str
    location: str
    rated_capacity_amps: float = 10.0
    timezone: str = "Africa/Lagos"
    country_code: str = ""
    deployment_type: str = "pi"  # 'pi' | 'phone' | 'edge_node' | 'server'
    deployment_profile: str = "development"  # 'development' | 'staging' | 'production'
    site_type: str = ""  # business/site context, e.g. pharmacy | office | factory
    #: runtime-config/v2 `device.site_id`: the provisioning authority's site
    #: identifier the Tier C approver registry is bound to. "" when absent.
    site_id: str = ""


def parse_device(data: Any) -> DeviceConfig:
    if not isinstance(data, dict):
        raise ConfigValidationError("'device' section must be a mapping.")

    device_id = checked_device_id(_require_str(data, "id", "device"))

    deployment_type = str(data.get("deployment_type", "pi")).strip().lower()
    if deployment_type not in {"pi", "phone", "edge_node", "server"}:
        raise ConfigValidationError(
            "device.deployment_type must be one of "
            "['phone', 'pi', 'edge_node', 'server']."
        )
    deployment_profile = (
        str(data.get("deployment_profile", "development")).strip().lower()
    )
    if deployment_profile not in {"development", "staging", "production"}:
        raise ConfigValidationError(
            "device.deployment_profile must be one of "
            "['development', 'staging', 'production']."
        )
    site_id = checked_site_id(data.get("site_id"))
    country_code = str(data.get("country_code", "")).strip().upper()
    if country_code and (len(country_code) != 2 or not country_code.isalpha()):
        raise ConfigValidationError(
            "device.country_code must be a 2-letter ISO country code (e.g. NG, US, KE)."
        )

    return DeviceConfig(
        id=device_id,
        name=_require_str(data, "name", "device"),
        location=_require_str(data, "location", "device"),
        rated_capacity_amps=float(data.get("rated_capacity_amps", 10.0)),
        timezone=_resolve_device_timezone(data.get("timezone", "")),
        country_code=country_code,
        deployment_type=deployment_type,
        deployment_profile=deployment_profile,
        site_type=str(data.get("site_type", "") or "").strip(),
        site_id=site_id,
    )
