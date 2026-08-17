# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Resolve where an Ori installation lives, without guessing.

Scope is never inferred from privilege: a root shell may well be inspecting a
user installation. Detection looks for an actual install root and reports what
it finds, so every command can state the scope and paths it is acting on.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml

from ori.doctor import InstallIdentity

SERVICE_NAME = "ori-runtime.service"
SYSTEM_ROOT = Path("/opt/ori")
SYSTEM_UNIT = Path("/etc/systemd/system") / SERVICE_NAME
SYSTEM_LAUNCHER = Path("/usr/local/bin/ori")
USER_LAUNCHER_DIR = Path.home() / ".local" / "bin"


def user_root() -> Path:
    return Path.home() / ".local" / "ori"


def user_unit() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / SERVICE_NAME


def default_root(scope: str) -> Path:
    return SYSTEM_ROOT if scope == "system" else user_root()


def default_unit(scope: str) -> Path:
    return SYSTEM_UNIT if scope == "system" else user_unit()


def launcher_path(scope: str) -> Path:
    return SYSTEM_LAUNCHER if scope == "system" else USER_LAUNCHER_DIR / "ori"


class AmbiguousScopeError(Exception):
    """Both a user and a system installation exist; the caller must choose."""


class UnmanagedReleaseError(Exception):
    """``current`` does not point at a release this installer manages."""


class IndeterminateScopeError(Exception):
    """An install root could not be inspected, so scope cannot be settled."""


class _Presence(Enum):
    """What inspecting an install root established.

    `INACCESSIBLE` is deliberately not folded into `ABSENT`. A root that cannot
    be read is not a root that is not there, and treating the two alike would
    let a permission problem silently choose a scope — or, as shipped, let the
    exception escape as a traceback out of a diagnostic command.
    """

    PRESENT = "present"
    ABSENT = "absent"
    INACCESSIBLE = "inaccessible"


def _presence(root: Path) -> _Presence:
    """Whether an installation is active at *root*, as far as we may look."""
    try:
        return _Presence.PRESENT if (root / "current").exists() else _Presence.ABSENT
    except OSError:
        # A system root left behind by an install this account cannot read is
        # ordinary — `/opt/ori` is 0700 to root — and must not end the command.
        return _Presence.INACCESSIBLE


def detect_scope(root: Path | None = None) -> str:
    """Return the scope of the one managed installation present.

    Effective UID is never consulted: a root shell inspecting a user
    installation is ordinary, and inferring scope from privilege would report
    the wrong paths. Detection succeeds only when exactly one installation
    exists; otherwise the caller must say which it means.
    """
    if root is not None:
        return "system" if root == SYSTEM_ROOT else "user"
    user = _presence(user_root())
    system = _presence(SYSTEM_ROOT)

    if user is _Presence.PRESENT and system is _Presence.PRESENT:
        raise AmbiguousScopeError(
            f"installations exist at both {user_root()} and {SYSTEM_ROOT}; "
            "pass --scope user or --scope system"
        )
    # One installation is definitely here and the other cannot be read. The
    # unreadable one cannot be the one this account is running, so naming the
    # readable one is the only answer that is both usable and true — and every
    # report states the scope it settled on.
    if user is _Presence.PRESENT:
        return "user"
    if system is _Presence.PRESENT:
        return "system"
    if _Presence.INACCESSIBLE in (user, system):
        unreadable = " and ".join(
            str(candidate)
            for candidate, presence in ((user_root(), user), (SYSTEM_ROOT, system))
            if presence is _Presence.INACCESSIBLE
        )
        raise IndeterminateScopeError(
            f"could not inspect {unreadable}, and no other installation was "
            "found; pass --scope user or --scope system explicitly"
        )
    raise FileNotFoundError(f"no installation at {user_root()} or {SYSTEM_ROOT}")


def resolve_identity(
    *, scope: str | None = None, root: Path | None = None
) -> tuple[InstallIdentity, str]:
    """Return the installation's identity and its configured device id."""
    resolved_scope = scope or detect_scope(root)
    install_root = root or default_root(resolved_scope)
    current = install_root / "current"
    if not current.is_symlink() and not current.exists():
        raise FileNotFoundError(f"no active release at {current}")
    active = current.resolve()
    if not active.is_dir():
        raise FileNotFoundError(f"active release is unavailable: {active}")
    # `current` is a symlink, so its target is only as trustworthy as whoever
    # can write it. Callers execute the interpreter inside the active release,
    # so require a release this installer laid down rather than following the
    # link wherever it points.
    releases = (install_root / "releases").resolve()
    if active.parent != releases:
        raise UnmanagedReleaseError(
            f"{current} points outside the managed release directory: "
            f"{active} is not a release in {releases}"
        )

    data = install_root / "data"
    config_path = data / "ori.yaml"
    identity = InstallIdentity(
        scope=resolved_scope,
        version=active.name,
        install_root=install_root,
        active_release=active,
        config_path=config_path,
        data_path=data,
        health_socket=data / "health.sock",
        unit_path=default_unit(resolved_scope),
        service_user=_service_user(resolved_scope),
    )
    return identity, _device_id(config_path)


def _service_user(scope: str) -> str | None:
    if scope != "system":
        return None
    unit = SYSTEM_UNIT
    try:
        for line in unit.read_text(encoding="utf-8").splitlines():
            if line.startswith("User="):
                return line.split("=", 1)[1].strip()
    except OSError:
        return None
    return None


def _device_id(config_path: Path) -> str:
    """Read the configured device id, tolerating an unreadable config.

    Doctor reports an unreadable config as its own failure, so this must not
    raise and mask that clearer diagnosis.
    """
    try:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return ""
    device = document.get("device") if isinstance(document, dict) else None
    return str(device.get("id", "")) if isinstance(device, dict) else ""
