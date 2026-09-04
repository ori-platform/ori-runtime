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
from pathlib import Path
from typing import TYPE_CHECKING

from ori.config import ConfigValidationError, read_config_document

if TYPE_CHECKING:  # pragma: no cover - import cycle at runtime
    from ori.installer.linux import InstallLayout

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


@dataclass(frozen=True)
class InstalledIdentity:
    """The identity an existing installation already carries.

    A device's identity is not a preference the installer may re-ask on every
    run. It keys the runtime's MQTT topics, the client identifiers per-device
    broker ACLs are written against, and the `(device_id, timestamp)` index on
    every stored reasoning, action and Tier C decision row. Changing it while
    the data directory survives leaves all of that stranded.
    """

    device_id: str
    name: str
    location: str


class InstalledConfigUnreadableError(Exception):
    """An installation exists but its identity could not be read.

    Distinct from "no installation": a fresh install may derive an identity
    from the host, whereas an upgrade that cannot read the identity it is
    replacing must stop rather than invent one.
    """


def _exists(path: Path, description: str) -> bool:
    """Whether *path* is there, distinguishing absent from uninspectable.

    `Path.exists()` propagates PermissionError rather than answering False, so
    a path inside a directory this process cannot read would otherwise raise
    out of identity detection as an unhandled error.
    """
    try:
        return path.exists() or path.is_symlink()
    except OSError as exc:
        raise InstalledConfigUnreadableError(
            f"{description} at {path} could not be inspected, so whether this "
            f"root is in use cannot be determined: {exc}"
        ) from exc


def _entries(directory: Path, description: str) -> list[str]:
    """List *directory*, distinguishing absent from uninspectable.

    A directory that cannot be read is not an empty one. Collapsing every
    OSError into "no entries" would turn a permissions failure or an I/O
    error into "unused root", which is the one answer that licenses deriving
    a new identity — fail-open on exactly the question that must fail closed.
    """
    try:
        return sorted(entry.name for entry in directory.iterdir())
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise InstalledConfigUnreadableError(
            f"{description} at {directory} could not be inspected, so whether "
            f"this root is in use cannot be determined: {exc}"
        ) from exc


# Directories this installer creates as scaffolding. Their presence says
# nothing; their contents do.
_SCAFFOLDING = frozenset({"releases", "data", "current"})


def _occupancy(layout: InstallLayout) -> list[str]:
    """Every sign that the managed root is already in use.

    Named rather than enumerated by filename: an earlier version listed four
    known files in the data directory, so deleting `ori.yaml` while an
    activated release remained made an occupied installation read as empty.
    A device's identity is not recoverable from a release tree, which is
    precisely why its absence there has to stop the run rather than license
    a new one.
    """
    signs: list[str] = []
    current = layout.current
    if _exists(current, "the active release pointer"):
        signs.append(f"an activated release at {current}")
    releases = _entries(layout.releases, "the releases directory")
    if releases:
        signs.append(f"managed releases ({', '.join(releases)})")
    data_entries = _entries(layout.data, "the data directory")
    if data_entries:
        signs.append(f"runtime state ({', '.join(data_entries)})")
    # Anything the installer did not put here is still occupancy: an unused
    # managed root is unused, not merely free of the artifacts this code
    # happens to know the names of.
    unexpected = [
        name
        for name in _entries(layout.root, "the install root")
        if name not in _SCAFFOLDING
    ]
    if unexpected:
        signs.append(f"unexpected entries ({', '.join(unexpected)})")
    return signs


def read_installed(layout: InstallLayout) -> InstalledIdentity | None:
    """Return the identity carried by the installation at *layout*, if any.

    Returns ``None`` only for a managed root that is genuinely unused, which
    is the sole case that licenses deriving an identity from the host.
    Re-running the installer over a root that holds anything is not a fresh
    install, however it is invoked.

    A configuration that cannot be parsed, one carrying no device id, and an
    occupied root without a readable configuration all raise. Each would
    otherwise let a run invent an identity for a device whose real one is
    merely unreadable — and ``device.id`` is not a display name. It is part of
    the durable identity namespace: evidence idempotency keys derive from it,
    the signing anchor is registered against it, MQTT topics and client
    identifiers embed it, broker ACLs are assigned by it, the firmware
    registry relates to it, and stored rows are indexed by it.
    """
    config_path = layout.data / "ori.yaml"
    if not _exists(config_path, "the runtime configuration"):
        occupied = _occupancy(layout)
        if occupied:
            raise InstalledConfigUnreadableError(
                f"{layout.root} already holds {', and '.join(occupied)}, but no "
                "readable configuration, so the device it belongs to cannot be "
                "identified. Deriving a new identity here would strand that "
                "installation."
            )
        return None
    try:
        document = read_config_document(str(config_path))
    except ConfigValidationError as exc:
        raise InstalledConfigUnreadableError(
            f"an installation exists at {config_path} but its configuration "
            "could not be read"
        ) from exc
    device = document.get("device") if isinstance(document, dict) else None
    if not isinstance(device, dict):
        raise InstalledConfigUnreadableError(
            f"an installation exists at {config_path} but declares no device section"
        )
    device_id = str(device.get("id", "") or "").strip()
    if not device_id:
        raise InstalledConfigUnreadableError(
            f"an installation exists at {config_path} but declares no device id"
        )
    return InstalledIdentity(
        device_id=device_id,
        name=str(device.get("name", "") or "").strip(),
        location=str(device.get("location", "") or "").strip(),
    )
