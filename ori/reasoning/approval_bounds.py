# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The release bound on a Tier C proposal's lifetime, with no imports of its own."""

from __future__ import annotations

from typing import Any, Final

#: The release-defined maximum Tier C proposal lifetime. A deployment may
#: shorten it through `approval_timeout_seconds` and never extend it; physical
#: authority left open longer than this is stale against the conditions that
#: produced it.
MAX_PROPOSAL_LIFETIME_S: Final = 3600


def approval_timeout_accepted(
    value: Any, *, release_maximum_s: int = MAX_PROPOSAL_LIFETIME_S
) -> bool:
    """Whether *value* is an `approval_timeout_seconds` a deployment may set.

    An integer from 1 to the release maximum. A fraction, a Boolean, a string
    and anything outside the bound are refused, never rounded or clamped.
    """
    return type(value) is int and 1 <= value <= int(release_maximum_s)
