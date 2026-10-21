# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""String fields of ori.yaml, refused rather than coerced when YAML gives another type."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any


class ConfigValidationError(Exception):
    pass


def require_str(data: dict, key: str, context: str) -> str:
    value = data.get(key)
    if value is None:
        raise ConfigValidationError(f"'{context}.{key}' is required but missing.")
    return _string_or_refuse(value, f"{context}.{key}", "must be a string")


def require_optional_str(value: Any, context: str, *, skill_name: str = "") -> str:
    """Return *value* when it is a string, or "" when absent; refuse any other type."""
    if value is None:
        return ""
    named = f" (skill {skill_name!r})" if skill_name else ""
    return _string_or_refuse(value, context, f"must be a string or absent{named}")


def _string_or_refuse(value: Any, context: str, requirement: str) -> str:
    """Refuse rather than ``str()`` a non-string: ``str()`` of a mapping reads as
    a real value to every later reader."""
    if isinstance(value, str):
        return value
    hint = ""
    if isinstance(value, (bool, int, float, date)):
        hint = (
            "; YAML reads an unquoted number, boolean or date as that type, "
            "so quote the value, e.g. '1.0'"
        )
    raise ConfigValidationError(
        f"{context} {requirement}, got {type(value).__name__}: {value!r}{hint}"
    )


def checked_device_endpoint(value: str, field: str, *, urls_supported: bool) -> str:
    """Refuse a device endpoint that names neither a node nor a reachable URL.

    A device path is not resolved against the configuration the way a data file
    is: it names something the host owns, and there is no directory it would be
    relative to. Left relative it would follow the working directory, which the
    unit points at a runtime directory systemd empties on every stop.

    Whether a URL is accepted is the consumer's own rule rather than a shared
    one. `usb_serial` hands anything containing `://` to `serial_for_url`, so
    it can reach a bridge; `serial` and the GSM modem call `Serial()` directly,
    which takes a port name only. Admitting a URL where it cannot be opened
    would move the failure from config load to the first read.
    """
    if not value:
        return value
    if urls_supported and "://" in value:
        return value
    if not Path(value).expanduser().is_absolute():
        supported = " or a URL its transport can open" if urls_supported else ""
        raise ConfigValidationError(
            f"{field} must be an absolute device path{supported}: {value!r}"
        )
    return value
