# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Boolean parsing helpers shared across runtime modules."""

from typing import Any

_TRUTHY_STRINGS = {"1", "true", "yes", "on"}


def is_truthy(value: Any) -> bool:
    """Parse common truthy representations into a boolean value."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in _TRUTHY_STRINGS
    return bool(value)
