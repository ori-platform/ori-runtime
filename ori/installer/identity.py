# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Suggested device identity, derived from the host rather than invented.

An operator installing on a machine already called ``pi-ikeja-01`` should not
have to think up an identifier; the host already answers the question. What the
host cannot answer — where the device is, who to contact — is left blank rather
than filled with a plausible-looking guess, because a wrong location in a fleet
report is worse than an empty one.

Randomness enters in exactly one place: a stock image whose hostname is shared
by every other device flashed from it. Even then it is opt-in for unattended
runs, so automation stays reproducible.
"""

from __future__ import annotations

import re
import secrets
import socket
from dataclasses import dataclass

# Hostnames that stock images ship with. They identify the image, not the
# device, so a fleet of them would collide on identity.
GENERIC_HOSTNAMES = frozenset(
    {
        "localhost",
        "raspberrypi",
        "ubuntu",
        "debian",
        "pop-os",
        "fedora",
        "archlinux",
        "linux",
        "orangepi",
        "nanopi",
    }
)

DEVICE_ID_HINT = (
    "1-64 characters: lowercase letters, digits, dots, dashes, underscores. "
    "Examples: pi-ikeja-01, hvac.roof.3, meter_02"
)

_INVALID = re.compile(r"[^a-z0-9._-]+")
_LEADING = re.compile(r"^[^a-z0-9]+")
_MAX_LENGTH = 64
_SUFFIX_BYTES = 2  # four hex characters: enough to separate a rack of clones


@dataclass(frozen=True)
class SuggestedIdentity:
    """What the host suggests, and whether anything was invented."""

    device_id: str
    name: str
    generated_suffix: bool

    @property
    def deterministic(self) -> bool:
        """Whether re-running would produce the same identity."""
        return not self.generated_suffix


def host_name() -> str:
    try:
        return socket.gethostname()
    except OSError:  # pragma: no cover - platform dependent
        return ""


def normalise(hostname: str) -> str:
    """Reduce a hostname to something the device-ID rules accept."""
    candidate = hostname.strip().lower().split(".")[0]
    candidate = _INVALID.sub("-", candidate)
    candidate = _LEADING.sub("", candidate).strip("-._")
    return candidate[:_MAX_LENGTH]


def needs_suffix(normalised: str) -> bool:
    """Whether this hostname cannot identify one device on its own."""
    return not normalised or normalised in GENERIC_HOSTNAMES


def suggest(
    hostname: str | None = None, *, allow_generated: bool = True
) -> SuggestedIdentity | None:
    """Suggest an identity from the host, or None when nothing can be suggested.

    ``allow_generated`` is what keeps unattended runs reproducible: without it,
    a host that would need a random suffix yields no suggestion at all rather
    than a value that changes on every run.
    """
    raw = host_name() if hostname is None else hostname
    normalised = normalise(raw)
    if not needs_suffix(normalised):
        return SuggestedIdentity(normalised, raw.strip().split(".")[0], False)
    if not allow_generated:
        return None
    stem = normalised or "ori"
    suffix = secrets.token_hex(_SUFFIX_BYTES)
    device_id = f"{stem[: _MAX_LENGTH - len(suffix) - 1]}-{suffix}"
    display = raw.strip().split(".")[0] or device_id
    return SuggestedIdentity(device_id, display, True)
