# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed filesystem transaction for verified Linux releases."""

from __future__ import annotations

import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Literal, Sequence

import yaml

from ori.installer import identity
from ori.installer.trusted_paths import trust_failure
from ori.security.release_bundles import ExtractedReleaseBundle, distribution_version

_VERSION_RE = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
    r"(?:-(?P<suffix>[a-zA-Z0-9][a-zA-Z0-9.-]*))?$"
)


class LinuxInstallError(Exception):
    """Stable installer failure safe to surface to operators."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class InstallLayout:
    root: Path
    releases: Path
    current: Path
    data: Path

    @classmethod
    def resolve(cls, root: str | Path) -> InstallLayout:
        candidate = Path(root).expanduser()
        if not candidate.is_absolute():
            raise LinuxInstallError(
                "unsafe_install_root", "install root must be absolute"
            )
        if candidate == Path(candidate.anchor):
            raise LinuxInstallError(
                "unsafe_install_root", "filesystem root is forbidden"
            )
        if candidate.exists() and candidate.is_symlink():
            raise LinuxInstallError(
                "unsafe_install_root", "install root must not be a symlink"
            )
        resolved = candidate.resolve(strict=False)
        return cls(
            root=resolved,
            releases=resolved / "releases",
            current=resolved / "current",
            data=resolved / "data",
        )

    def release(self, version: str) -> Path:
        if not _VERSION_RE.fullmatch(version):
            raise LinuxInstallError(
                "invalid_release_version", "version is not canonical"
            )
        return self.releases / version


@dataclass(frozen=True)
class InstallResult:
    version: str
    previous_version: str | None
    changed: bool
    rolled_back: bool


@dataclass(frozen=True)
class ComposedInstallResult:
    install: InstallResult
    health: dict[str, object]
    boot_persistence: BootPersistence


@dataclass(frozen=True)
class InstallerConfigInput:
    device_id: str
    name: str
    location: str
    deployment_type: Literal["pi", "server"] = "pi"
    deployment_profile: Literal["development"] = "development"
    operator_contact: str = ""

    def __post_init__(self) -> None:
        _validate_device_id(self.device_id)
        for field_name, value in (("name", self.name), ("location", self.location)):
            _validate_device_text(field_name, value)
        if self.deployment_type not in {"pi", "server"}:
            raise LinuxInstallError(
                "config_validation_failed", "deployment type is unsupported"
            )
        if self.deployment_profile != "development":
            raise LinuxInstallError(
                "config_validation_failed",
                "installer-generated hardened profiles require signed provisioning",
            )
        _validate_operator_contact(self.operator_contact)


@dataclass(frozen=True)
class InstallerInputOptions:
    """Operator-supplied values before interactive or unattended collection."""

    unattended: bool = False
    device_id: str | None = None
    name: str | None = None
    location: str | None = None
    deployment_type: Literal["pi", "server"] = "pi"
    operator_contact: str | None = None
    # Off by default so an unattended run is reproducible: a random suffix
    # would give the same automation a different device on every execution.
    generate_device_id: bool = False
    # The identity already on disk, when this run is upgrading rather than
    # installing. Present means the device has an identity the installer must
    # keep; absent means nothing is installed and the host may supply one.
    installed: identity.InstalledIdentity | None = None


def collect_installer_config(
    options: InstallerInputOptions,
    *,
    prompt: Callable[[str], str] = input,
    write: Callable[[str], None] = print,
) -> InstallerConfigInput:
    """Collect validated config values without ever collecting credentials.

    Unattended mode is deliberately non-interactive and fails when any required
    identity value is absent. Interactive mode accepts explicitly supplied
    values and prompts only for missing fields, retrying invalid prompt input a
    bounded number of times.
    """
    installed = options.installed
    if installed is not None:
        # `device.id` is not a display name. Evidence idempotency keys derive
        # from it, the signing anchor is registered against it, MQTT topics
        # and client identifiers embed it, broker ACLs are assigned by it, and
        # stored rows are indexed by it. An install or an upgrade may not
        # change it, and no flag makes that safe: rewriting it while the state
        # database survives would silently break the uniqueness that already
        # signed evidence depends on. Adopting a new identity is a migration
        # ceremony, not an installer option.
        supplied = (options.device_id or "").strip()
        if supplied and supplied != installed.device_id:
            raise LinuxInstallError(
                "config_validation_failed",
                f"this installation is device {installed.device_id!r} and "
                f"--device-id was given as {supplied!r}. An install cannot "
                "change an established identity: evidence idempotency keys, "
                "the signing anchor, MQTT topics, broker ACLs and stored rows "
                "all derive from it. Omit --device-id to keep it.",
            )
        if options.generate_device_id:
            raise LinuxInstallError(
                "config_validation_failed",
                f"this installation is device {installed.device_id!r}, so "
                "--generate-device-id contradicts it. That flag derives a new "
                "identity from the host and applies only to an empty root.",
            )
        options = replace(options, device_id=installed.device_id)
        # Name and location are already recorded too. An upgrade that demanded
        # them again would fail an unattended run that has no reason to carry
        # them, and re-prompt an interactive one for answers already on disk.
        if not (options.name or "").strip() and installed.name:
            options = replace(options, name=installed.name)
        if not (options.location or "").strip() and installed.location:
            options = replace(options, location=installed.location)

    if options.unattended:
        device_id = options.device_id
        name = options.name
        if options.generate_device_id and not (device_id or "").strip():
            # Opt-in, because the generated suffix is random: automation that
            # did not ask for this must get the same device on every run.
            generated = identity.suggest()
            if generated is None:  # pragma: no cover - suggest always yields one
                raise LinuxInstallError(
                    "config_validation_failed",
                    "no device identity could be derived from this host",
                )
            device_id = generated.device_id
            name = name or generated.name
        missing = [
            flag
            for flag, value in (
                ("--device-id", device_id),
                ("--name", name),
                ("--location", options.location),
            )
            if value is None or not value.strip()
        ]
        if missing:
            raise LinuxInstallError(
                "config_validation_failed",
                "unattended mode requires " + ", ".join(missing),
            )
        return InstallerConfigInput(
            device_id=_validated_input(device_id or "", _validate_device_id),
            name=_validated_input(
                name or "", lambda value: _validate_device_text("name", value)
            ),
            location=_validated_input(
                options.location or "",
                lambda value: _validate_device_text("location", value),
            ),
            deployment_type=options.deployment_type,
            operator_contact=_validated_input(
                options.operator_contact or "", _validate_operator_contact
            ),
        )

    # A host-derived suggestion answers "what should this device be called",
    # which is only an open question on an empty root. On an upgrade the
    # answer is already on disk and is not the operator's to revise here.
    suggestion = identity.suggest() if installed is None else None
    device_id = _collect_interactive_value(
        supplied=options.device_id,
        label="Device ID",
        validate=_validate_device_id,
        prompt=prompt,
        write=write,
        hint=identity.DEVICE_ID_HINT,
        default=(
            installed.device_id
            if installed is not None
            else (suggestion.device_id if suggestion else None)
        ),
    )
    name = _collect_interactive_value(
        supplied=options.name,
        label="Device name",
        validate=lambda value: _validate_device_text("name", value),
        prompt=prompt,
        write=write,
        default=(
            installed.name or None
            if installed is not None
            else (suggestion.name if suggestion else None)
        ),
    )
    # Neither of these can be derived from the host, and a plausible-looking
    # guess is worse than a blank in a fleet report.
    location = _collect_interactive_value(
        supplied=options.location,
        label="Device location",
        validate=lambda value: _validate_device_text("location", value),
        prompt=prompt,
        write=write,
        default=installed.location or None if installed is not None else None,
    )
    operator_contact = _collect_interactive_value(
        supplied=options.operator_contact,
        label="Operator contact (optional)",
        validate=_validate_operator_contact,
        prompt=prompt,
        write=write,
        optional=True,
    )
    _confirm(
        device_id=device_id,
        name=name,
        location=location,
        operator_contact=operator_contact,
        prompt=prompt,
        write=write,
    )
    return InstallerConfigInput(
        device_id=device_id,
        name=name,
        location=location,
        deployment_type=options.deployment_type,
        operator_contact=operator_contact,
    )


def _collect_interactive_value(
    *,
    supplied: str | None,
    label: str,
    validate: Callable[[str], None],
    prompt: Callable[[str], str],
    write: Callable[[str], None],
    hint: str = "",
    default: str | None = None,
    optional: bool = False,
) -> str:
    """Ask for one value, showing what is acceptable and what will be used.

    Rejected input is never echoed back: it can contain anything an operator
    mistyped, including something pasted from a credential manager. Only the
    rule that was broken is repeated.
    """
    if supplied is not None:
        return _validated_input(supplied, validate)
    if hint:
        write(f"  {hint}")
    suffix = f" [{default}]" if default else ""
    for _attempt in range(3):
        try:
            value = prompt(f"{label}{suffix}: ")
        except (EOFError, KeyboardInterrupt) as exc:
            raise LinuxInstallError(
                "config_validation_failed", "interactive input was cancelled"
            ) from exc
        if not value.strip():
            if default:
                return _validated_input(default, validate)
            if optional:
                return _validated_input("", validate)
        try:
            return _validated_input(value, validate)
        except LinuxInstallError as exc:
            write(f"  {exc.detail}")
            continue
    raise LinuxInstallError(
        "config_validation_failed", "interactive input failed after 3 attempts"
    )


def _confirm(
    *,
    device_id: str,
    name: str,
    location: str,
    operator_contact: str,
    prompt: Callable[[str], str],
    write: Callable[[str], None],
) -> None:
    """Show what will be installed and require the operator to accept it.

    Installation changes the host, so the values are read back before anything
    is written rather than discovered afterwards in the config.
    """
    write("")
    write("This device will be installed as:")
    write(f"  Device ID         {device_id}")
    write(f"  Device name       {name}")
    write(f"  Device location   {location}")
    write(f"  Operator contact  {operator_contact or '(none)'}")
    write("")
    try:
        answer = prompt("Proceed with these values? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt) as exc:
        raise LinuxInstallError(
            "config_validation_failed", "installation was cancelled"
        ) from exc
    if answer and answer not in ("y", "yes"):
        raise LinuxInstallError(
            "config_validation_failed",
            "installation was cancelled before any change was made",
        )


def _validated_input(value: str, validate: Callable[[str], None]) -> str:
    validate(value)
    return value.strip()


def _validate_device_id(value: str) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", value):
        raise LinuxInstallError(
            "config_validation_failed",
            "device ID must be 1-64 lowercase letters, digits, dots, dashes, or "
            "underscores, starting with a letter or digit",
        )


def _validate_device_text(field_name: str, value: str) -> None:
    if (
        not value.strip()
        or len(value) > 128
        or _has_control_character(value)
        or "${" in value
    ):
        raise LinuxInstallError(
            "config_validation_failed", f"device {field_name} is invalid"
        )


def _validate_operator_contact(value: str) -> None:
    if len(value) > 64 or _has_control_character(value) or "${" in value:
        raise LinuxInstallError(
            "config_validation_failed", "operator contact is invalid"
        )


def provision_runtime_config(
    *,
    values: InstallerConfigInput,
    config_path: Path,
    release_python: Path,
    health_socket_path: Path,
    service_profile: SystemdServiceProfile | None = None,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] | None = None,
) -> Callable[[], None]:
    """Generate, validate, and atomically install a minimal Runtime config."""
    for path in (config_path, release_python, health_socket_path):
        if not path.is_absolute() or _has_control_character(str(path)):
            raise LinuxInstallError(
                "config_validation_failed", "config paths must be absolute and safe"
            )
    if health_socket_path.parent != config_path.parent:
        raise LinuxInstallError(
            "config_validation_failed",
            "health socket must be inside the writable config data directory",
        )
    owner: tuple[int, int] | None = None
    if service_profile is not None:
        if (
            service_profile.scope == "system"
            and service_profile.service_user is not None
        ):
            if os.geteuid() != 0:
                raise LinuxInstallError(
                    "config_validation_failed",
                    "system config provisioning requires root",
                )
            try:
                account = pwd.getpwnam(service_profile.service_user)
            except KeyError as exc:
                raise LinuxInstallError(
                    "config_validation_failed", "system service user does not exist"
                ) from exc
            owner = (account.pw_uid, account.pw_gid)
    try:
        interpreter = release_python.resolve(strict=True)
    except OSError as exc:
        raise LinuxInstallError(
            "config_validation_failed", "release interpreter is unavailable"
        ) from exc
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        raise LinuxInstallError(
            "config_validation_failed", "release interpreter is unavailable"
        )
    try:
        unsafe_destination = (
            config_path.is_symlink()
            or config_path.parent.is_symlink()
            or config_path.parent.resolve(strict=False) != config_path.parent
            or (config_path.exists() and not config_path.is_file())
        )
    except OSError as exc:
        raise LinuxInstallError(
            "config_validation_failed", "config destination could not be inspected"
        ) from exc
    if unsafe_destination:
        raise LinuxInstallError(
            "config_validation_failed", "config destination is unsafe"
        )
    document = {
        "device": {
            "id": values.device_id,
            "name": values.name.strip(),
            "location": values.location.strip(),
            "deployment_type": values.deployment_type,
            "deployment_profile": values.deployment_profile,
        },
        "sensors": [],
        "skills": [],
        "reasoning": {},
        "gateway": {"enabled": False},
        "telemetry_export": {"enabled": False},
        "device_policy": {"enabled": False},
        "actions": {
            "primary_alert_channel": "sms",
            "operator_contact": values.operator_contact.strip(),
            "sms": {"enabled": False},
            "relay": {"enabled": False},
        },
        "security": {
            "config_signature": {"require_signed": False},
            "skills": {"require_signed": False},
        },
        "health_socket": {
            "enabled": True,
            "path": str(health_socket_path),
            "mode": "0o660",
        },
    }
    encoded = yaml.safe_dump(document, sort_keys=False).encode("utf-8")
    try:
        # In the composed transaction this is ``layout.data``, already created
        # by the managed-scaffolding loop. Keep the standalone API equally
        # strict: creation provenance and any mode repair must come from the
        # same no-follow descriptor primitive, not a pathname check followed by
        # recursive mkdir/chmod operations.
        _ensure_private_directory(config_path.parent)
        previous: tuple[bytes, int, int, int] | None = None
        if config_path.is_file():
            previous_stat = config_path.stat()
            previous = (
                config_path.read_bytes(),
                stat.S_IMODE(previous_stat.st_mode),
                previous_stat.st_uid,
                previous_stat.st_gid,
            )
    except LinuxInstallError as exc:
        raise LinuxInstallError(
            "config_validation_failed", "config destination could not be prepared"
        ) from exc
    except OSError as exc:
        raise LinuxInstallError(
            "config_validation_failed", "config destination could not be prepared"
        ) from exc
    temporary = config_path.parent / f".{config_path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = -1
    replaced = False
    command_runner = runner or _run_command
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(encoded)
            output.flush()
            os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
        if owner is not None:
            os.fchown(descriptor, *owner)
        try:
            result = command_runner(
                [
                    str(release_python),
                    "-m",
                    "ori.cli_bridge",
                    "config",
                    "validate",
                    "--path",
                    str(temporary),
                ]
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise LinuxInstallError(
                "config_validation_failed", "config validator could not run"
            ) from exc
        if result.returncode != 0 or not _valid_config_response(result.stdout):
            raise LinuxInstallError(
                "config_validation_failed", "generated config did not validate"
            )
        os.replace(temporary, config_path)
        replaced = True
        parent_descriptor = os.open(
            config_path.parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except LinuxInstallError:
        raise
    except OSError as exc:
        if replaced:
            try:
                _restore_config(config_path, previous)
            except OSError as rollback_error:
                raise LinuxInstallError(
                    "config_validation_failed",
                    "config write and rollback failed",
                ) from rollback_error
        raise LinuxInstallError(
            "config_validation_failed", "config could not be written"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)

    rolled_back = False

    def rollback() -> None:
        nonlocal rolled_back
        if rolled_back:
            return
        try:
            _restore_config(config_path, previous)
        except OSError as exc:
            raise LinuxInstallError(
                "config_validation_failed", "config rollback failed"
            ) from exc
        rolled_back = True

    return rollback


def _restore_config(path: Path, previous: tuple[bytes, int, int, int] | None) -> None:
    if previous is None:
        path.unlink(missing_ok=True)
    else:
        temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.rollback"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                previous[1],
            )
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                output.write(previous[0])
                output.flush()
                os.fsync(descriptor)
            os.fchmod(descriptor, previous[1])
            os.fchown(descriptor, previous[2], previous[3])
            os.replace(temporary, path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
    parent_descriptor = os.open(
        path.parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    )
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _valid_config_response(stdout: str) -> bool:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return False
    return bool(
        isinstance(payload, dict)
        and payload.get("schema_version") == 1
        and payload.get("ok") is True
        and payload.get("command") == "config validate"
        and isinstance(payload.get("result"), dict)
        and payload["result"].get("valid") is True
    )


def _has_control_character(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _unsafe_unit_value(value: str) -> bool:
    return (
        any(character.isspace() for character in value) or "%" in value or "@" in value
    )


# The system service runs as one account, under one name, everywhere. `postgres`
# and `docker` are not per-host choices, and neither is this: a fixed name is
# what lets documentation, unit files, permission checks, support answers and an
# operator's own muscle memory all refer to the same thing. A configurable name
# buys nothing an operator wants and costs a variable that every one of those
# has to carry.
SERVICE_USER = "ori-runtime"


@dataclass(frozen=True)
class SystemdServiceProfile:
    """Explicit systemd scope and unprivileged runtime identity."""

    scope: Literal["user", "system"]
    service_user: str | None

    def __post_init__(self) -> None:
        if self.scope == "user":
            if self.service_user is not None:
                raise LinuxInstallError(
                    "service_start_failed", "user units must not set User="
                )
            return
        if self.scope != "system" or self.service_user is None:
            raise LinuxInstallError(
                "service_start_failed", "service profile is inconsistent"
            )
        # Not a format check: the name is a constant, so anything else reaching
        # here is a caller inventing an identity the rest of the system does not
        # know about.
        if self.service_user != SERVICE_USER:
            raise LinuxInstallError(
                "service_start_failed",
                f"the system service account is always {SERVICE_USER}",
            )

    @classmethod
    def user(cls) -> SystemdServiceProfile:
        return cls(scope="user", service_user=None)

    @classmethod
    def system(cls) -> SystemdServiceProfile:
        return cls(scope="system", service_user=SERVICE_USER)


@dataclass(frozen=True)
class _PermissionChange:
    path: Path
    uid: int
    gid: int
    mode: int
    original_uid: int
    original_gid: int
    original_mode: int
    device: int
    inode: int


@dataclass(frozen=True)
class BootPersistence:
    enabled: bool
    detail: str


class RuntimeHealthVerifier:
    """Bounded health gate using the activated release's own Runtime bridge."""

    def __init__(
        self,
        *,
        socket_path: Path,
        expected_device_id: str,
        timeout_seconds: float = 30.0,
        poll_interval_seconds: float = 0.25,
        runner: Callable[[Sequence[str], float], subprocess.CompletedProcess[str]]
        | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        try:
            socket_parent_is_canonical = (
                socket_path.parent.resolve(strict=False) == socket_path.parent
            )
        except OSError as exc:
            raise LinuxInstallError(
                "post_install_health_failed",
                "health socket path could not be inspected",
            ) from exc
        if (
            not socket_path.is_absolute()
            or _has_control_character(str(socket_path))
            or not socket_parent_is_canonical
            or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", expected_device_id)
            or not 0 < timeout_seconds <= 300
            or not 0 < poll_interval_seconds <= timeout_seconds
        ):
            raise LinuxInstallError(
                "post_install_health_failed", "health verification settings are invalid"
            )
        self._socket_path = socket_path
        self._expected_device_id = expected_device_id
        self._timeout_seconds = timeout_seconds
        self._poll_interval_seconds = poll_interval_seconds
        self._runner = runner or _run_health_command
        self._monotonic = monotonic
        self._sleeper = sleeper

    def verify(self, release: Path) -> dict[str, object]:
        """Wait for non-critical health and return the validated health snapshot."""
        release_python = release / "venv" / "bin" / "python"
        if (
            not release.is_absolute()
            or release.is_symlink()
            or not release_python.exists()
            or not release_python.is_file()
            or not os.access(release_python, os.X_OK)
        ):
            raise LinuxInstallError(
                "post_install_health_failed", "activated release interpreter is unsafe"
            )
        deadline = self._monotonic() + self._timeout_seconds
        while True:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise LinuxInstallError(
                    "post_install_health_failed",
                    "runtime health socket did not become ready before the deadline",
                )
            bridge_timeout_ms = max(100, min(3000, int(remaining * 1000)))
            try:
                result = self._runner(
                    [
                        str(release_python),
                        "-m",
                        "ori.cli_bridge",
                        "health",
                        "snapshot",
                        "--socket",
                        str(self._socket_path),
                        "--timeout-ms",
                        str(bridge_timeout_ms),
                    ],
                    remaining,
                )
            except subprocess.TimeoutExpired as exc:
                raise LinuxInstallError(
                    "post_install_health_failed",
                    "runtime health bridge exceeded the verification deadline",
                ) from exc
            except (OSError, subprocess.SubprocessError) as exc:
                raise LinuxInstallError(
                    "post_install_health_failed", "runtime health bridge could not run"
                ) from exc

            outcome, health = _health_bridge_response(result)
            if outcome == "healthy" and health is not None:
                if health.get("device_id") != self._expected_device_id:
                    raise LinuxInstallError(
                        "post_install_health_failed",
                        "runtime health identity does not match configured device",
                    )
                return health
            if outcome != "retry":
                raise LinuxInstallError(
                    "post_install_health_failed", "runtime reported unhealthy status"
                )
            delay = min(self._poll_interval_seconds, deadline - self._monotonic())
            if delay > 0:
                self._sleeper(delay)


def _health_bridge_response(
    result: subprocess.CompletedProcess[str],
) -> tuple[Literal["healthy", "retry", "failed"], dict[str, object] | None]:
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return "failed", None
    if not isinstance(payload, dict):
        return "failed", None
    if result.returncode != 0:
        error = payload.get("error")
        if (
            payload.get("schema_version") == 1
            and payload.get("ok") is False
            and payload.get("command") == "health snapshot"
            and isinstance(error, dict)
            and error.get("code")
            in {"health_socket_unavailable", "health_socket_error"}
        ):
            return "retry", None
        return "failed", None
    result_payload = payload.get("result")
    if not (
        payload.get("schema_version") == 1
        and payload.get("ok") is True
        and payload.get("command") == "health snapshot"
        and isinstance(result_payload, dict)
        and result_payload.get("schema_version") == 1
        and result_payload.get("ok") is True
        and isinstance(result_payload.get("health"), dict)
    ):
        return "failed", None
    health = result_payload["health"]
    if health.get("critical", False) is not False:
        return "failed", None
    return "healthy", health


class SystemdServiceManager:
    """Shell-free systemd lifecycle adapter with explicit unit scope."""

    def __init__(
        self,
        *,
        profile: SystemdServiceProfile,
        unit_path: Path,
        runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
        | None = None,
        effective_uid: int | None = None,
    ) -> None:
        self._profile = profile
        self._unit_path = unit_path
        self._runner = runner or _run_command
        self._effective_uid = os.geteuid() if effective_uid is None else effective_uid
        if (
            not unit_path.is_absolute()
            or unit_path.name != "ori-runtime.service"
            or unit_path.parent.resolve(strict=False) != unit_path.parent
        ):
            raise LinuxInstallError(
                "service_start_failed", "systemd unit path is unsafe"
            )
        if profile.scope == "system" and self._effective_uid != 0:
            raise LinuxInstallError(
                "service_start_failed", "system unit management requires root"
            )
        if profile.scope == "user" and self._effective_uid == 0:
            raise LinuxInstallError(
                "service_start_failed", "user unit must not run as root"
            )

    def install_unit(self, rendered: str) -> Callable[[], None]:
        """Atomically place a rendered unit without enabling or starting it."""
        if "@ORI_" in rendered or "\x00" in rendered:
            raise LinuxInstallError(
                "service_start_failed", "rendered service unit is invalid"
            )
        self._validate_unit_profile(rendered)
        parent = self._unit_path.parent
        if parent.is_symlink():
            raise LinuxInstallError(
                "service_start_failed", "systemd unit directory must not be a symlink"
            )
        # This is deliberately not installer-owned scaffolding. System scope
        # writes inside a root-owned systemd hierarchy; user scope writes below
        # the invoking account's private home. Recursive creation may prepare
        # host-owned parents, which must keep the host's policy and must never
        # be adopted or chmodded by ``_ensure_private_directory``. The unit
        # itself is still placed with O_EXCL/O_NOFOLLOW in ``_atomic_write``.
        parent.mkdir(parents=True, exist_ok=True, mode=self._directory_mode())
        previous: tuple[bytes, int] | None = None
        installed = False
        try:
            if self._unit_path.is_symlink() or (
                self._unit_path.exists() and not self._unit_path.is_file()
            ):
                raise LinuxInstallError(
                    "service_start_failed", "managed service unit is unsafe"
                )
            if self._unit_path.is_file():
                previous = (
                    self._unit_path.read_bytes(),
                    stat.S_IMODE(self._unit_path.stat().st_mode),
                )
            installed = True
            self._atomic_write(rendered.encode("utf-8"), self._unit_mode())
            self._run([*self._systemctl(), "daemon-reload"], "daemon reload")
        except (LinuxInstallError, OSError) as exc:
            if not installed:
                if isinstance(exc, LinuxInstallError):
                    raise
                raise LinuxInstallError(
                    "service_start_failed", "service unit could not be installed"
                ) from exc
            try:
                if previous is None:
                    self._unit_path.unlink(missing_ok=True)
                else:
                    self._atomic_write(previous[0], previous[1])
                self._run([*self._systemctl(), "daemon-reload"], "rollback reload")
            except (LinuxInstallError, OSError) as rollback_error:
                raise LinuxInstallError(
                    "service_start_failed",
                    "service unit installation and rollback failed",
                ) from rollback_error
            if isinstance(exc, LinuxInstallError):
                raise
            raise LinuxInstallError(
                "service_start_failed", "service unit could not be installed"
            ) from exc

        rolled_back = False

        def rollback() -> None:
            nonlocal rolled_back
            if rolled_back:
                return
            if previous is None:
                self.disable_and_remove()
            else:
                try:
                    self._atomic_write(previous[0], previous[1])
                    self._run([*self._systemctl(), "daemon-reload"], "rollback reload")
                except (LinuxInstallError, OSError) as exc:
                    raise LinuxInstallError(
                        "service_start_failed", "service unit rollback failed"
                    ) from exc
            rolled_back = True

        return rollback

    def restart(self) -> None:
        self._run([*self._systemctl(), "restart", self._unit_path.name], "restart")

    def stop(self) -> None:
        self._run([*self._systemctl(), "stop", self._unit_path.name], "stop")

    def enable(self) -> BootPersistence:
        self._run([*self._systemctl(), "enable", self._unit_path.name], "enable")
        return self.boot_persistence()

    def boot_persistence(self) -> BootPersistence:
        if self._profile.scope == "system":
            result = self._run_raw(["systemctl", "is-enabled", self._unit_path.name])
            state = result.stdout.strip().lower()
            if state == "enabled" and result.returncode == 0:
                return BootPersistence(True, "system unit enabled for boot")
            if state in {
                "alias",
                "bad",
                "disabled",
                "enabled-runtime",
                "generated",
                "indirect",
                "linked",
                "linked-runtime",
                "masked",
                "masked-runtime",
                "not-found",
                "static",
                "transient",
            }:
                return BootPersistence(
                    False, f"system unit is {state}; boot startup is not persistent"
                )
            raise LinuxInstallError(
                "service_start_failed", "service enablement query was malformed"
            )
        result = self._run_raw(
            [
                "loginctl",
                "show-user",
                str(self._effective_uid),
                "-p",
                "Linger",
                "--value",
            ]
        )
        if result.returncode != 0:
            raise LinuxInstallError(
                "service_start_failed", "service linger query failed"
            )
        linger_value = result.stdout.strip().lower()
        if linger_value not in {"yes", "no"}:
            raise LinuxInstallError(
                "service_start_failed", "service linger query was malformed"
            )
        linger = linger_value == "yes"
        detail = (
            "user lingering is enabled"
            if linger
            else "user lingering is disabled; boot startup is not persistent"
        )
        return BootPersistence(linger, detail)

    def disable_and_remove(self) -> None:
        if self._unit_path.is_symlink():
            raise LinuxInstallError(
                "service_start_failed", "service unit must not be a symlink"
            )
        if not self._unit_path.exists() and not self._unit_path.is_symlink():
            result = self._run_raw(
                [*self._systemctl(), "is-active", self._unit_path.name]
            )
            state = result.stdout.strip().lower()
            if state in {"active", "activating", "reloading", "deactivating"}:
                self._run([*self._systemctl(), "stop", self._unit_path.name], "stop")
            elif state not in {"failed", "inactive", "unknown"}:
                raise LinuxInstallError(
                    "service_start_failed", "service activity query was malformed"
                )
            self._run([*self._systemctl(), "daemon-reload"], "daemon reload")
            return
        self._run(
            [*self._systemctl(), "disable", "--now", self._unit_path.name],
            "disable",
        )
        try:
            self._unit_path.unlink(missing_ok=True)
        except OSError as exc:
            raise LinuxInstallError(
                "service_start_failed", "service unit could not be removed"
            ) from exc
        self._run([*self._systemctl(), "daemon-reload"], "daemon reload")

    def _atomic_write(self, content: bytes, mode: int) -> None:
        temporary = self._unit_path.parent / (
            f".{self._unit_path.name}.{uuid.uuid4().hex}.tmp"
        )
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                mode,
            )
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                output.write(content)
                output.flush()
                os.fsync(descriptor)
            os.fchmod(descriptor, mode)
            os.replace(temporary, self._unit_path)
            parent_descriptor = os.open(
                self._unit_path.parent,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
            )
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)

    def _validate_unit_profile(self, rendered: str) -> None:
        section = ""
        users: list[str] = []
        targets: list[str] = []
        for raw_line in rendered.splitlines():
            if raw_line.rstrip().endswith("\\"):
                raise LinuxInstallError(
                    "service_start_failed", "service unit continuations are forbidden"
                )
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if section == "Service" and key.strip() == "User":
                users.append(value.strip())
            if section == "Install" and key.strip() == "WantedBy":
                targets.append(value.strip())
        expected_target = (
            "default.target" if self._profile.scope == "user" else "multi-user.target"
        )
        if targets != [expected_target]:
            raise LinuxInstallError(
                "service_start_failed", "service unit target does not match profile"
            )
        if self._profile.scope == "user":
            valid_user = not users
        else:
            valid_user = users == [self._profile.service_user]
        if not valid_user:
            raise LinuxInstallError(
                "service_start_failed", "service unit identity does not match profile"
            )

    def _systemctl(self) -> list[str]:
        return (
            ["systemctl", "--user"] if self._profile.scope == "user" else ["systemctl"]
        )

    def _directory_mode(self) -> int:
        return 0o700 if self._profile.scope == "user" else 0o755

    def _unit_mode(self) -> int:
        return 0o600 if self._profile.scope == "user" else 0o644

    def _run(self, command: Sequence[str], operation: str) -> None:
        result = self._run_raw(command)
        if result.returncode != 0:
            raise LinuxInstallError(
                "service_start_failed", f"service {operation} failed"
            )

    def _run_raw(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            result = self._runner(command)
        except (OSError, subprocess.SubprocessError) as exc:
            raise LinuxInstallError(
                "service_start_failed", "service command could not run"
            ) from exc
        return result


def render_systemd_unit(
    template: str,
    *,
    profile: SystemdServiceProfile,
    root: Path,
    data_dir: Path,
    config_path: Path,
    env_file: Path,
) -> str:
    """Render a shell-free unit without mixing user and system semantics."""
    paths = {
        "@ORI_ROOT@": root,
        "@ORI_DATA_DIR@": data_dir,
        "@ORI_CONFIG@": config_path,
        "@ORI_ENV_FILE@": env_file,
    }
    rendered = template
    for marker, path in paths.items():
        value = str(path)
        if (
            not path.is_absolute()
            or path != Path(os.path.normpath(value))
            or _unsafe_unit_value(value)
        ):
            raise LinuxInstallError(
                "unsafe_install_root", "systemd paths contain unsafe unit syntax"
            )
        if marker not in rendered:
            raise LinuxInstallError(
                "service_start_failed", f"service template is missing {marker}"
            )
        rendered = rendered.replace(marker, value)

    if config_path == data_dir or not config_path.is_relative_to(data_dir):
        raise LinuxInstallError(
            "unsafe_install_root",
            "systemd config path must be inside the writable data directory",
        )

    if "@ORI_USER_DIRECTIVE@" not in rendered or "@ORI_WANTED_BY@" not in rendered:
        raise LinuxInstallError(
            "service_start_failed", "service template is missing profile markers"
        )
    if profile.scope == "user":
        user_directive = ""
        wanted_by = "default.target"
    elif profile.scope == "system" and profile.service_user is not None:
        user_directive = f"User={profile.service_user}"
        wanted_by = "multi-user.target"
    else:
        raise LinuxInstallError(
            "service_start_failed", "service profile is inconsistent"
        )
    rendered = rendered.replace("@ORI_USER_DIRECTIVE@", user_directive)
    rendered = rendered.replace("@ORI_WANTED_BY@", wanted_by)
    if re.search(r"@[A-Z0-9_]+@", rendered):
        raise LinuxInstallError(
            "service_start_failed", "service template has unresolved markers"
        )
    return rendered


def require_trusted_base_interpreter(profile: SystemdServiceProfile) -> None:
    """Refuse a system install built on an interpreter root does not control.

    The release's virtual environment is created from whichever interpreter the
    bootstrap selected, and `bin/python` in that environment links back to it.
    So an interpreter under a user-writable prefix — pyenv, a home directory,
    `/usr/local` owned by an admin account — produces a release whose executing
    code an unprivileged account can replace. Diagnostics catch that, but only
    after the bundle has been unpacked, the environment built, the service
    account created and the unit started, and the whole installation then rolls
    back for a condition that was knowable in microseconds.

    Read-only, so it runs before anything is prompted, created, or built. User
    scope is unaffected: it never claims code the runtime cannot rewrite.
    """
    if profile.scope != "system":
        return
    # In a virtual environment `sys.executable` is the environment's own stub;
    # `_base_executable` is the interpreter a new environment would actually be
    # built from, which is the one whose provenance matters here.
    base = getattr(sys, "_base_executable", None) or sys.executable
    failure = trust_failure(base, require_executable=True)
    if failure is None:
        return
    raise LinuxInstallError(
        "unsupported_target",
        f"a system install needs an interpreter only root can change, but "
        f"{failure}. The release environment is built from it, so its "
        f"code would be replaceable by whoever controls that path. Install "
        f"Python from the distribution — for example 'sudo apt install "
        f"python3' — and run this again with that interpreter, or install "
        f"with --scope user for a workstation or trial.",
    )


def ensure_service_account(
    profile: SystemdServiceProfile,
    *,
    unattended: bool = False,
    prompt: Callable[[str], str] = input,
    write: Callable[[str], None] = print,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] | None = None,
) -> bool:
    """Resolve the system service account, creating it when it is absent.

    Returns whether this call created it.

    A distribution package creates the account its service runs as; requiring an
    operator to run `useradd` by hand asks them to perform the one step the
    installer is best placed to get right, and to get it wrong in ways nobody
    sees until the service starts. So this creates it — with a fixed name, a
    fixed shape, and no login.

    An account that already exists is used exactly as found. It may have been
    given a home, a group, or an ACL deliberately, and adopting an existing
    identity is not licence to reshape it.
    """
    if profile.scope != "system" or profile.service_user is None:
        return False
    if _account_is_usable(profile.service_user):
        return False

    manual = (
        f"sudo useradd --system --no-create-home --shell {_nologin_shell()} "
        f"{profile.service_user}"
    )
    if os.geteuid() != 0:
        raise LinuxInstallError(
            "service_start_failed",
            f"creating the {profile.service_user} account requires root. "
            f"Re-run with sudo, create it manually ({manual}), or install with "
            "--scope user for a workstation or trial.",
        )

    useradd = _trusted_useradd()
    if useradd is None:
        raise LinuxInstallError(
            "service_start_failed",
            f"the {profile.service_user} account does not exist and useradd is "
            f"not available to create it. Create it manually: {manual}",
        )

    if not unattended and not _confirmed_account_creation(
        profile.service_user, prompt=prompt, write=write
    ):
        raise LinuxInstallError(
            "service_start_failed",
            f"the {profile.service_user} account is required for a system "
            f"install. Create it manually ({manual}), or install with "
            "--scope user for a workstation or trial.",
        )

    command = [
        useradd,
        "--system",
        "--no-create-home",
        "--shell",
        _nologin_shell(),
        profile.service_user,
    ]
    run = runner or _run_account_command
    try:
        result = run(command)
    except subprocess.TimeoutExpired as exc:
        # `TimeoutExpired` is a SubprocessError, not an OSError, so it would
        # otherwise travel past this handler and past `main`, which maps only
        # the installer's own error types. A useradd waiting on a lock the
        # installer cannot see would reach the operator as a traceback with no
        # remedy in it.
        raise LinuxInstallError(
            "service_start_failed",
            f"creating the {profile.service_user} account timed out after "
            f"{_ACCOUNT_COMMAND_TIMEOUT_SECONDS:g}s. Another process may hold "
            f"the account database lock. Create it manually: {manual}",
        ) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise LinuxInstallError(
            "service_start_failed",
            f"could not create the {profile.service_user} account: {exc}. "
            f"Create it manually: {manual}",
        ) from exc
    # A zero exit is the tool's opinion; the account is the fact. Proceeding on
    # the former would defer the failure to the point where the service starts.
    if result.returncode != 0 or not _account_is_usable(profile.service_user):
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        raise LinuxInstallError(
            "service_start_failed",
            f"could not create the {profile.service_user} account"
            + (f" ({detail[-1]})" if detail else "")
            + f". Create it manually: {manual}",
        )
    write(f"Created system service account {profile.service_user}.")
    return True


def _account_is_usable(name: str) -> bool:
    """Whether *name* resolves to an account the runtime may run as.

    Resolving is not enough. An account carrying uid 0 — whether aliased there
    deliberately or created by a host tool that reuses the id — would run the
    service as root, which is the single thing system scope exists to prevent.
    Doctor rejects uid 0, but it runs after the unit has been installed and
    started, so a name-only check hands the service root first and objects
    afterwards.
    """
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        return False
    if account.pw_uid == 0:
        raise LinuxInstallError(
            "service_start_failed",
            f"the {name} account exists but has uid 0. The runtime must not run "
            "as root under system scope. Remove or rename that account, or "
            "install with --scope user for a workstation or trial.",
        )
    return True


def _nologin_shell() -> str:
    """The shell that denies login, wherever this distribution keeps it."""
    for candidate in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
        if Path(candidate).exists():
            return candidate
    return "/bin/false"


def _confirmed_account_creation(
    name: str,
    *,
    prompt: Callable[[str], str],
    write: Callable[[str], None],
) -> bool:
    """Ask before adding an account to the host, as package installs do.

    Declining is a complete answer: the installation stops and the operator is
    given the command. It never means "continue without the account", which
    would produce a service that cannot start.
    """
    write(
        f"\nA system install runs the runtime as {name}, an unprivileged "
        f"account with no home directory and no login shell.\n"
        f"That account does not exist yet and will be created.\n"
        f"It is left in place if you later uninstall, because files elsewhere "
        f"may belong to it.\n"
    )
    for _attempt in range(3):
        try:
            answer = prompt(f"Create the {name} account? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        if answer in {"", "y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        write("  Answer y or n.")
    return False


# Fixed, in preference order. `PATH` is not consulted: this runs as root, and a
# `PATH` carrying a writable directory ahead of the system ones would choose
# what the installer executes with full privilege. An operator whose useradd
# lives somewhere else can create the account by hand — the message says how.
_USERADD_LOCATIONS: tuple[str, ...] = (
    "/usr/sbin/useradd",
    "/sbin/useradd",
    "/usr/local/sbin/useradd",
)


def _trusted_useradd() -> str | None:
    """Return a useradd only root could have placed there, or None.

    `PATH` is never consulted: this runs as root, and a `PATH` carrying a
    writable directory ahead of the system ones would choose what the installer
    executes with full privilege. Each fixed location is then judged by the same
    path-trust primitive the rest of the installer uses.
    """
    for candidate in _USERADD_LOCATIONS:
        if trust_failure(candidate, require_executable=True) is None:
            return candidate
    return None


_ACCOUNT_COMMAND_TIMEOUT_SECONDS = 30.0


def _run_account_command(
    command: Sequence[str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        check=False,
        timeout=_ACCOUNT_COMMAND_TIMEOUT_SECONDS,
    )


def apply_system_service_permissions(
    layout: InstallLayout,
    profile: SystemdServiceProfile,
    *,
    allowed_data_sockets: Sequence[Path] = (),
) -> None:
    """Make verified code readable, and only data writable, by a system service."""
    if profile.scope != "system" or profile.service_user is None:
        raise LinuxInstallError(
            "service_start_failed", "system permissions require a system profile"
        )
    if os.geteuid() != 0:
        raise LinuxInstallError(
            "service_start_failed", "system permissions require root"
        )
    try:
        account = pwd.getpwnam(profile.service_user)
    except KeyError as exc:
        raise LinuxInstallError(
            "service_start_failed", "system service user does not exist"
        ) from exc

    allowed_sockets: frozenset[Path] = frozenset(allowed_data_sockets)
    for socket_path in allowed_sockets:
        try:
            unsafe_socket = (
                not socket_path.is_absolute()
                or _has_control_character(str(socket_path))
                or socket_path.parent.resolve(strict=False) != socket_path.parent
                or not socket_path.is_relative_to(layout.data)
                or socket_path == layout.data
            )
        except OSError as exc:
            raise LinuxInstallError(
                "unsafe_install_root", "allowed data socket could not be inspected"
            ) from exc
        if unsafe_socket:
            raise LinuxInstallError(
                "unsafe_install_root", "allowed data socket path is unsafe"
            )

    _assert_managed_path(layout, layout.root)
    root_stat = layout.root.lstat()
    plan = [
        _permission_change(
            layout.root, root_stat, uid=0, gid=account.pw_gid, mode=0o750
        )
    ]
    plan.extend(
        _owned_tree_plan(
            layout,
            layout.releases,
            uid=0,
            gid=account.pw_gid,
            directory_mode=0o750,
            regular_mode=0o440,
            executable_mode=0o550,
            allow_file_symlinks=True,
        )
    )
    _assert_managed_path(layout, layout.data)
    plan.extend(
        _owned_tree_plan(
            layout,
            layout.data,
            uid=account.pw_uid,
            gid=account.pw_gid,
            directory_mode=0o700,
            regular_mode=0o600,
            executable_mode=0o700,
            allow_file_symlinks=False,
            allowed_sockets=allowed_sockets,
        )
    )
    _apply_permission_plan(plan)


def _owned_tree_plan(
    layout: InstallLayout,
    root: Path,
    *,
    uid: int,
    gid: int,
    directory_mode: int,
    regular_mode: int,
    executable_mode: int,
    allow_file_symlinks: bool,
    allowed_sockets: frozenset[Path] = frozenset(),
) -> list[_PermissionChange]:
    if root.is_symlink() or not root.is_dir():
        raise LinuxInstallError(
            "unsafe_install_root", "permission root must be a managed directory"
        )
    plan: list[_PermissionChange] = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        _assert_managed_path(layout, current_path)
        plan.append(
            _permission_change(
                current_path,
                current_path.lstat(),
                uid=uid,
                gid=gid,
                mode=directory_mode,
            )
        )
        for directory in directories:
            path = current_path / directory
            if path.is_symlink():
                if not allow_file_symlinks:
                    raise LinuxInstallError(
                        "unsafe_install_root", "data symlinks are forbidden"
                    )
                _validate_release_symlink(layout, path, require_internal=True)
        for filename in files:
            path = current_path / filename
            if path.is_symlink():
                if not allow_file_symlinks:
                    raise LinuxInstallError(
                        "unsafe_install_root", "data symlinks are forbidden"
                    )
                _validate_release_symlink(layout, path, require_internal=False)
                continue
            path_stat = path.lstat()
            if stat.S_ISSOCK(path_stat.st_mode) and path in allowed_sockets:
                continue
            if not path.is_file():
                raise LinuxInstallError(
                    "unsafe_install_root", "special files are forbidden"
                )
            existing_mode = path_stat.st_mode
            mode = executable_mode if existing_mode & 0o100 else regular_mode
            plan.append(
                _permission_change(path, path_stat, uid=uid, gid=gid, mode=mode)
            )
    return plan


def _validate_release_symlink(
    layout: InstallLayout, path: Path, *, require_internal: bool
) -> None:
    try:
        relative = path.relative_to(layout.releases)
        release_root = layout.releases / relative.parts[0]
        target = path.resolve(strict=True)
        target.relative_to(layout.root)
    except (OSError, RuntimeError, ValueError) as exc:
        if require_internal:
            raise LinuxInstallError(
                "unsafe_install_root", "release directory symlink escapes its release"
            ) from exc
    else:
        try:
            target.relative_to(release_root)
        except ValueError:
            if require_internal:
                raise LinuxInstallError(
                    "unsafe_install_root",
                    "release directory symlink escapes its release",
                )
        else:
            expected = target.is_dir() if require_internal else target.is_file()
            if not expected:
                raise LinuxInstallError(
                    "unsafe_install_root", "release symlink target has wrong type"
                )
            return

    if require_internal:
        raise LinuxInstallError(
            "unsafe_install_root", "release directory symlink escapes its release"
        )
    # An external target's own mode is not the whole question: replacing a file
    # needs write permission on the directory holding it, so everything leading
    # to it is verified as well, through the same primitive the root-execution
    # guard uses. The two boundaries answering differently is how a release can
    # admit a link that diagnostics then refuse.
    failure = trust_failure(path, require_executable=True)
    if failure is not None:
        raise LinuxInstallError(
            "unsafe_install_root",
            f"external release symlink target is not trusted: {failure}",
        )


def _permission_change(
    path: Path, path_stat: os.stat_result, *, uid: int, gid: int, mode: int
) -> _PermissionChange:
    return _PermissionChange(
        path=path,
        uid=uid,
        gid=gid,
        mode=mode,
        original_uid=path_stat.st_uid,
        original_gid=path_stat.st_gid,
        original_mode=stat.S_IMODE(path_stat.st_mode),
        device=path_stat.st_dev,
        inode=path_stat.st_ino,
    )


def _apply_permission_plan(plan: Sequence[_PermissionChange]) -> None:
    applied: list[_PermissionChange] = []
    try:
        for change in plan:
            _set_owned_mode(change, change.uid, change.gid, change.mode)
            applied.append(change)
    except (OSError, NotImplementedError) as exc:
        for change in reversed(applied):
            try:
                _set_owned_mode(
                    change,
                    change.original_uid,
                    change.original_gid,
                    change.original_mode,
                )
            except (OSError, NotImplementedError):
                # Preserve the initiating failure; rollback is best effort after
                # the permission transaction has already become unrecoverable.
                pass
        raise LinuxInstallError(
            "service_start_failed", "service filesystem permissions could not be set"
        ) from exc


def _set_owned_mode(change: _PermissionChange, uid: int, gid: int, mode: int) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(change.path, flags)
    try:
        current = os.fstat(descriptor)
        if current.st_dev != change.device or current.st_ino != change.inode:
            raise OSError("permission target changed after validation")
        try:
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
        except (OSError, NotImplementedError):
            try:
                os.fchown(descriptor, current.st_uid, current.st_gid)
                os.fchmod(descriptor, stat.S_IMODE(current.st_mode))
            except (OSError, NotImplementedError):
                # Preserve the original ownership/mode failure; the caller rolls
                # back earlier entries and maps it to the stable service error.
                pass
            raise
    finally:
        os.close(descriptor)


class OfflineReleasePreparer:
    """Build an isolated release environment without package-index access."""

    def __init__(
        self,
        *,
        bundle: ExtractedReleaseBundle,
        runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
        | None = None,
        bootstrap_python: str = sys.executable,
    ) -> None:
        self._bundle = bundle
        self._runner = runner or _run_command
        self._bootstrap_python = bootstrap_python

    def prepare(self, staging: Path) -> None:
        wheelhouse = self._bundle.root / "wheelhouse"
        requirements = wheelhouse / "requirements.txt"
        wheels = sorted(wheelhouse.glob("ori_runtime-*.whl"))
        if not wheelhouse.is_dir() or not requirements.is_file() or len(wheels) != 1:
            raise LinuxInstallError(
                "offline_install_failed", "verified wheelhouse is incomplete"
            )
        venv = staging / "venv"
        self._run([self._bootstrap_python, "-m", "venv", str(venv)])
        python = str(venv / "bin" / "python")
        base = [
            python,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse),
        ]
        self._run([*base, "--require-hashes", "-r", str(requirements)])
        pi_requirements = wheelhouse / "requirements-pi.txt"
        if pi_requirements.is_file():
            self._run([*base, "--require-hashes", "-r", str(pi_requirements)])
        self._run([*base, "--no-deps", str(wheels[0])])

    def validate(self, release: Path) -> None:
        python = release / "venv" / "bin" / "python"
        if not python.is_file():
            raise LinuxInstallError(
                "offline_install_failed", "release interpreter is missing"
            )
        # `importlib.metadata` reports the PEP 440 spelling and the bundle
        # declares the SemVer one, so a candidate reads back as `2.4.0rc3`
        # against a bundle identified as `2.4.0-rc.3`. Both name the same build;
        # comparing them directly would fail every pre-release install on the
        # device, after signature verification had already passed.
        self._run(
            [
                str(python),
                "-c",
                "import importlib.metadata as m; import ori.runtime; print(m.version('ori-runtime'))",
            ],
            expected_stdout=distribution_version(self._bundle.runtime_version),
        )
        # Execute a console script rather than stat it. A relocated venv leaves
        # every entry point with a dangling interpreter while the interpreter
        # symlink itself still works, so importability alone proves nothing.
        entrypoint = release / "venv" / "bin" / "ori-install-linux"
        if not entrypoint.is_file():
            raise LinuxInstallError(
                "offline_install_failed", "release entrypoint is missing"
            )
        self._run([str(entrypoint), "--help"])

    def _run(
        self, command: Sequence[str], *, expected_stdout: str | None = None
    ) -> None:
        try:
            result = self._runner(command)
        except (OSError, subprocess.SubprocessError) as exc:
            raise LinuxInstallError(
                "offline_install_failed", "offline environment command could not run"
            ) from exc
        if result.returncode != 0:
            raise LinuxInstallError(
                "offline_install_failed", "offline environment command failed"
            )
        if expected_stdout is not None and result.stdout.strip() != expected_stdout:
            raise LinuxInstallError(
                "offline_install_failed", "installed Runtime version mismatch"
            )


# A post-activation step and the callback it uses to register its own undo,
# so work done after activation is covered by the same rollback as the rest.
PostActivation = Callable[[Path, Callable[[Callable[[], None]], None]], None]


def install_composed_release(
    *,
    layout: InstallLayout,
    bundle: ExtractedReleaseBundle,
    values: InstallerConfigInput,
    service_profile: SystemdServiceProfile,
    service_manager: SystemdServiceManager,
    unit_template: str,
    env_file: Path,
    allow_downgrade: bool = False,
    preparer: OfflineReleasePreparer | None = None,
    health_verifier: RuntimeHealthVerifier | None = None,
    post_activation: PostActivation | None = None,
) -> ComposedInstallResult:
    """Compose release, config, unit, health, and enablement as one transaction."""
    config_path = layout.data / "ori.yaml"
    socket_path = layout.data / "health.sock"
    rendered = render_systemd_unit(
        unit_template,
        profile=service_profile,
        root=layout.root,
        data_dir=layout.data,
        config_path=config_path,
        env_file=env_file,
    )
    release_preparer = preparer or OfflineReleasePreparer(bundle=bundle)
    verifier = health_verifier or RuntimeHealthVerifier(
        socket_path=socket_path,
        expected_device_id=values.device_id,
    )
    rollbacks: list[Callable[[], None]] = []
    health: dict[str, object] | None = None
    persistence: BootPersistence | None = None

    def rollback_assets() -> None:
        first_error: Exception | None = None
        for rollback in reversed(rollbacks):
            try:
                rollback()
            except Exception as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise LinuxInstallError(
                "rollback_failed", "installer asset rollback failed"
            ) from first_error

    def prepare_assets(release: Path) -> None:
        try:
            rollbacks.append(
                provision_runtime_config(
                    values=values,
                    config_path=config_path,
                    release_python=release / "venv" / "bin" / "python",
                    health_socket_path=socket_path,
                    service_profile=service_profile,
                )
            )
            rollbacks.append(service_manager.install_unit(rendered))
        except Exception:
            rollback_assets()
            raise

    def check_health(release: Path) -> None:
        nonlocal health
        health = verifier.verify(release)

    def enable_service(release: Path) -> None:
        nonlocal persistence
        persistence = service_manager.enable()
        if service_profile.scope == "system" and not persistence.enabled:
            raise LinuxInstallError(
                "service_start_failed", "system service is not enabled for boot"
            )
        # Diagnostics run inside the transaction so that an installation which
        # is not actually usable is rolled back rather than reported healthy.
        if post_activation is not None:
            # The hook registers its own undo as it goes, so anything it has
            # already changed is reverted if a later step fails.
            post_activation(release, rollbacks.append)

    install = install_release(
        layout=layout,
        version=bundle.runtime_version,
        prepare=release_preparer.prepare,
        validate=release_preparer.validate,
        restart_service=service_manager.restart,
        stop_service=service_manager.stop,
        check_health=check_health,
        allow_downgrade=allow_downgrade,
        service_profile=service_profile,
        prepare_activation=prepare_assets,
        rollback_activation=rollback_assets,
        commit_activation=enable_service,
        allowed_data_sockets=(socket_path,),
    )
    if health is None or persistence is None:
        raise LinuxInstallError(
            "post_install_health_failed", "installer result is incomplete"
        )
    return ComposedInstallResult(install, health, persistence)


def _repair_relocated_shebangs(staging: Path, destination: Path) -> None:
    """Rebind console-script interpreters after the release is moved into place.

    pip writes an absolute interpreter path into every console script at install
    time. Building in a staging directory and moving the tree leaves those
    pointing at a path that no longer exists, so every entry point in
    ``venv/bin`` becomes unrunnable while the interpreter symlink still works.

    The venv is generated locally from the authenticated, hash-locked
    wheelhouse; it is not part of the signed artifact. Rebinding it therefore
    changes nothing that was signed, and the bundle's own manifest still governs
    the bytes that were verified.
    """
    bin_dir = destination / "venv" / "bin"
    if bin_dir.is_symlink() or not bin_dir.is_dir():
        raise LinuxInstallError(
            "offline_install_failed", "release venv bin directory is unsafe"
        )
    old_bin = f"{staging}/venv/bin/".encode()
    new_bin = f"{destination}/venv/bin/".encode()
    staging_reference = str(staging).encode()
    try:
        entries = sorted(bin_dir.iterdir())
    except OSError as exc:
        raise LinuxInstallError(
            "offline_install_failed", "release venv bin directory is unreadable"
        ) from exc

    # These embed the environment root rather than an interpreter and carry no
    # shebang, so they are rebound first and skipped by the shebang pass.
    _repair_activation_scripts(staging, destination, bin_dir)

    for entry in entries:
        if entry.name in _ACTIVATION_SCRIPTS:
            continue
        # Interpreter symlinks carry no shebang and must never be rewritten.
        if entry.is_symlink():
            continue
        try:
            info = entry.stat()
            if not stat.S_ISREG(info.st_mode):
                raise LinuxInstallError(
                    "offline_install_failed",
                    f"unexpected special file in release venv bin: {entry.name}",
                )
            if not info.st_mode & 0o111:
                continue
            data = entry.read_bytes()
        except OSError as exc:
            raise LinuxInstallError(
                "offline_install_failed", f"cannot inspect {entry.name}"
            ) from exc

        break_at = data.find(b"\n")
        first = data if break_at == -1 else data[:break_at]
        if not first.startswith(b"#!"):
            # Compiled binaries have no shebang; a staging reference in one
            # would mean something unexpected produced it.
            if staging_reference in data:
                raise LinuxInstallError(
                    "offline_install_failed",
                    f"{entry.name} references the staging path without a shebang",
                )
            continue

        # pip writes two wrapper forms. Normally the interpreter is the shebang
        # itself; when that path would exceed the kernel's shebang limit it
        # emits a `#!/bin/sh` wrapper that re-execs the interpreter on the next
        # line instead. Linux caps shebangs at 127 bytes, so a long install
        # root produces the second form.
        long_form = first.startswith(b"#!/bin/sh") and _LONG_EXEC + old_bin in data
        if not first.startswith(b"#!" + old_bin) and not long_form:
            if staging_reference in data:
                raise LinuxInstallError(
                    "offline_install_failed",
                    f"{entry.name} points at an unexpected staging interpreter",
                )
            continue
        _rewrite_preserving_mode(
            entry, data.replace(old_bin, new_bin), stat.S_IMODE(info.st_mode)
        )

    _assert_no_staging_references(bin_dir, staging_reference)
    _fsync_directory(bin_dir)


def _rewrite_preserving_mode(path: Path, content: bytes, mode: int) -> None:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(content)
            output.flush()
            os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.replace(temporary, path)
    except OSError as exc:
        raise LinuxInstallError(
            "offline_install_failed", f"cannot rebind {path.name}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


_ACTIVATION_SCRIPTS = ("activate", "activate.csh", "activate.fish", "Activate.ps1")
_LONG_EXEC = b"'''exec' "


def _repair_activation_scripts(staging: Path, destination: Path, bin_dir: Path) -> None:
    """Rebind the generated activation scripts.

    These embed the environment root rather than a shebang, so the shebang pass
    leaves them pointing at the staging directory. They are only used by an
    interactive ``source``, but shipping known-stale paths is not acceptable.
    Only the exact generated names are touched.
    """
    old_root = str(staging / "venv").encode()
    new_root = str(destination / "venv").encode()
    for name in _ACTIVATION_SCRIPTS:
        script = bin_dir / name
        if script.is_symlink() or not script.is_file():
            continue
        try:
            info = script.stat()
            data = script.read_bytes()
        except OSError as exc:
            raise LinuxInstallError(
                "offline_install_failed", f"cannot inspect {name}"
            ) from exc
        if old_root not in data:
            continue
        _rewrite_preserving_mode(
            script, data.replace(old_root, new_root), stat.S_IMODE(info.st_mode)
        )


def _assert_no_staging_references(bin_dir: Path, staging_reference: bytes) -> None:
    """Fail closed on any surviving staging path, not just in shebangs."""
    for entry in sorted(bin_dir.iterdir()):
        if entry.is_symlink() or not entry.is_file():
            continue
        try:
            data = entry.read_bytes()
        except OSError as exc:
            raise LinuxInstallError(
                "offline_install_failed", f"cannot reread {entry.name}"
            ) from exc
        if staging_reference in data:
            raise LinuxInstallError(
                "offline_install_failed",
                f"{entry.name} still references the staging directory",
            )


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    except OSError as exc:
        raise LinuxInstallError(
            "offline_install_failed", "cannot fsync the release venv bin directory"
        ) from exc
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def install_release(
    *,
    layout: InstallLayout,
    version: str,
    prepare: Callable[[Path], None],
    validate: Callable[[Path], None],
    restart_service: Callable[[], None],
    stop_service: Callable[[], None],
    check_health: Callable[[Path], None],
    allow_downgrade: bool = False,
    service_profile: SystemdServiceProfile | None = None,
    prepare_activation: Callable[[Path], None] | None = None,
    rollback_activation: Callable[[], None] | None = None,
    commit_activation: Callable[[Path], None] | None = None,
    allowed_data_sockets: Sequence[Path] = (),
) -> InstallResult:
    """Prepare, activate, and health-gate one already-authenticated release."""
    destination = layout.release(version)
    # Built inside the try, one directory at a time. A comprehension binds its
    # result only after the last element, so a root that exists while `data` is
    # a symlink would create `releases/`, raise, and leave it behind with no
    # record that this run had made it.
    scaffolding: list[_CreatedDirectory] = []
    try:
        # ``root`` is the first boundary the installer owns. Its parent may be
        # a host-owned directory such as ``~/.local`` and is intentionally
        # governed by host policy. Prepare it separately; every managed entry
        # below it is then created exactly one component at a time so implicit
        # parents cannot escape descriptor validation or rollback provenance.
        try:
            layout.root.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise LinuxInstallError(
                "unsafe_install_root", "install root parent could not be prepared"
            ) from exc
        for directory in (layout.root, layout.releases, layout.data):
            # Ordered outermost first, so cleanup can unwind it in reverse.
            created_directory = _ensure_private_directory(directory)
            if created_directory is not None:
                scaffolding.append(created_directory)
        return _install_release(
            layout=layout,
            version=version,
            destination=destination,
            prepare=prepare,
            validate=validate,
            restart_service=restart_service,
            stop_service=stop_service,
            check_health=check_health,
            allow_downgrade=allow_downgrade,
            service_profile=service_profile,
            prepare_activation=prepare_activation,
            rollback_activation=rollback_activation,
            commit_activation=commit_activation,
            allowed_data_sockets=allowed_data_sockets,
        )
    except Exception:
        # A failed install leaves the host as it found it, as far as it still
        # can. `_install_release` already removes the release tree it created;
        # this takes the empty scaffolding with it, so a first install that
        # fails does not leave an install root behind suggesting Ori is there.
        _remove_created_scaffolding(scaffolding)
        raise


def _install_release(
    *,
    layout: InstallLayout,
    version: str,
    destination: Path,
    prepare: Callable[[Path], None],
    validate: Callable[[Path], None],
    restart_service: Callable[[], None],
    stop_service: Callable[[], None],
    check_health: Callable[[Path], None],
    allow_downgrade: bool,
    service_profile: SystemdServiceProfile | None,
    prepare_activation: Callable[[Path], None] | None,
    rollback_activation: Callable[[], None] | None,
    commit_activation: Callable[[Path], None] | None,
    allowed_data_sockets: Sequence[Path],
) -> InstallResult:
    """Install into an install root whose directories already exist."""
    previous = _active_release(layout)
    previous_version = previous.name if previous is not None else None
    same_version = previous == destination and destination.is_dir()
    if previous_version is not None and _version_key(version) < _version_key(
        previous_version
    ):
        if not allow_downgrade:
            raise LinuxInstallError(
                "downgrade_forbidden", "use explicit downgrade approval"
            )

    created = False
    if not destination.exists():
        staging = layout.releases / f".{version}.{uuid.uuid4().hex}.staging"
        staging.mkdir(mode=0o700)
        try:
            prepare(staging)
            validate(staging)
            os.replace(staging, destination)
            created = True
            # Rebind before revalidating, so validation exercises the tree that
            # will actually run — and before DAC hardening makes it read-only.
            _repair_relocated_shebangs(staging, destination)
            validate(destination)
        except Exception:
            if created and destination.exists():
                shutil.rmtree(destination)
            raise
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    elif not destination.is_dir() or destination.is_symlink():
        raise LinuxInstallError(
            "unsafe_install_root", "release destination is not a directory"
        )
    else:
        validate(destination)

    if service_profile is not None and service_profile.scope == "system":
        try:
            apply_system_service_permissions(
                layout,
                service_profile,
                allowed_data_sockets=allowed_data_sockets,
            )
        except Exception:
            if created and destination.exists():
                shutil.rmtree(destination)
            raise
    if prepare_activation is not None:
        try:
            prepare_activation(destination)
        except Exception:
            if created and destination.exists():
                shutil.rmtree(destination)
            raise
    try:
        _set_active(layout, destination)
        restart_service()
        check_health(destination)
        if commit_activation is not None:
            commit_activation(destination)
    except Exception as activation_error:
        rollback_error: Exception | None = None

        def attempt_rollback(operation: Callable[[], None]) -> None:
            nonlocal rollback_error
            try:
                operation()
            except Exception as exc:
                if rollback_error is None:
                    rollback_error = exc

        if previous is None:
            attempt_rollback(lambda: layout.current.unlink(missing_ok=True))
            attempt_rollback(stop_service)
            if rollback_activation is not None:
                attempt_rollback(rollback_activation)
        else:
            attempt_rollback(lambda: _set_active(layout, previous))
            if rollback_activation is not None:
                attempt_rollback(rollback_activation)
            attempt_rollback(restart_service)
            attempt_rollback(lambda: check_health(previous))
        if rollback_error is not None:
            raise LinuxInstallError(
                "rollback_failed",
                f"activation failed ({activation_error}); rollback failed ({rollback_error})",
            ) from rollback_error
        if created:
            shutil.rmtree(destination)
        if isinstance(activation_error, LinuxInstallError):
            raise activation_error
        raise LinuxInstallError(
            "post_install_health_failed",
            f"activation failed and was rolled back: {activation_error}",
        ) from activation_error

    return InstallResult(
        version, previous_version, changed=not same_version, rolled_back=False
    )


def uninstall_runtime(
    *,
    layout: InstallLayout,
    stop_service: Callable[[], None],
    remove_data: bool = False,
) -> None:
    """Remove executable releases while retaining operator data by default."""
    _assert_managed_path(layout, layout.releases)
    try:
        stop_service()
    except Exception as exc:
        raise LinuxInstallError(
            "service_start_failed", "service could not be stopped"
        ) from exc
    layout.current.unlink(missing_ok=True)
    if layout.releases.is_symlink():
        raise LinuxInstallError("unsafe_install_root", "releases must not be a symlink")
    if layout.releases.exists():
        shutil.rmtree(layout.releases)
    if remove_data and layout.data.exists():
        _assert_managed_path(layout, layout.data)
        shutil.rmtree(layout.data)


def _active_release(layout: InstallLayout) -> Path | None:
    if not layout.current.exists() and not layout.current.is_symlink():
        return None
    if not layout.current.is_symlink():
        raise LinuxInstallError(
            "unsafe_install_root", "current must be a managed symlink"
        )
    target = layout.current.resolve(strict=False)
    _assert_managed_path(layout, target)
    if target.parent != layout.releases:
        raise LinuxInstallError(
            "unsafe_install_root", "current target is not a direct release"
        )
    if not target.exists():
        layout.current.unlink()
        return None
    if target.is_symlink() or not target.is_dir():
        raise LinuxInstallError("unsafe_install_root", "current release is unavailable")
    return target


def _set_active(layout: InstallLayout, release: Path) -> None:
    _assert_managed_path(layout, release)
    if (
        release.parent != layout.releases
        or release.is_symlink()
        or not release.is_dir()
    ):
        raise LinuxInstallError(
            "unsafe_install_root", "active release is not a direct directory"
        )
    temporary = layout.root / f".current.{uuid.uuid4().hex}.tmp"
    relative = release.relative_to(layout.root)
    os.symlink(relative, temporary)
    try:
        os.replace(temporary, layout.current)
    finally:
        temporary.unlink(missing_ok=True)


def _assert_managed_path(layout: InstallLayout, path: Path) -> None:
    try:
        path.resolve(strict=False).relative_to(layout.root)
    except ValueError as exc:
        raise LinuxInstallError(
            "unsafe_install_root", "path escapes install root"
        ) from exc


@dataclass(frozen=True)
class _CreatedDirectory:
    path: Path
    device: int
    inode: int


def _ensure_private_directory(path: Path) -> _CreatedDirectory | None:
    """Create one managed directory privately, or validate the existing inode.

    A successful ``mkdir`` is the only creation-provenance signal. An earlier
    ``exists`` result cannot say whether ``mkdir(exist_ok=True)`` later met a
    different entry. Once opened, type and mode decisions stay bound to that
    no-follow descriptor, and the pathname is rechecked before success so a
    concurrent replacement fails closed instead of becoming the install root.

    Linux and macOS both provide the required O_DIRECTORY/O_NOFOLLOW and
    fchmod contract. A platform without it is rejected explicitly; silently
    falling back to stat-then-chmod would restore the race this function closes.
    """
    created = False
    completed = False
    descriptor = -1
    created_identity: tuple[int, int] | None = None
    try:
        try:
            os.mkdir(path, 0o700)
            created = True
            created_info = os.stat(path, follow_symlinks=False)
            created_identity = (created_info.st_dev, created_info.st_ino)
        except FileExistsError:
            # EEXIST establishes no trust. It only says this invocation did not
            # create the entry; the descriptor checks below decide whether the
            # existing object is acceptable and it is never rollback-owned.
            pass

        try:
            open_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
            fchmod = os.fchmod
        except AttributeError as exc:
            raise LinuxInstallError(
                "unsafe_install_root",
                "platform lacks no-follow directory descriptor support",
            ) from exc

        descriptor = os.open(path, open_flags)
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):  # O_DIRECTORY also enforces this.
            raise LinuxInstallError(
                "unsafe_install_root", f"{path.name} is not a directory"
            )
        descriptor_identity = (info.st_dev, info.st_ino)
        if created_identity is not None and descriptor_identity != created_identity:
            raise LinuxInstallError(
                "unsafe_install_root", f"{path.name} changed during preparation"
            )

        mode = stat.S_IMODE(info.st_mode)
        if not created and mode & 0o020:
            # Never silently adopt a shared pre-existing directory. Its exact
            # mode is evidence that another account could replace entries.
            raise LinuxInstallError(
                "unsafe_install_root", f"{path.name} is group-writable"
            )
        if created or mode & 0o007:
            # Pin created directories despite umask/default ACLs, and tighten
            # only the previously accepted (non-group-writable) existing case.
            fchmod(descriptor, 0o700)
            info = os.fstat(descriptor)
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise LinuxInstallError(
                    "unsafe_install_root", f"{path.name} could not be made private"
                )

        current = os.stat(path, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != descriptor_identity:
            raise LinuxInstallError(
                "unsafe_install_root", f"{path.name} changed during preparation"
            )
        completed = True
        if created:
            return _CreatedDirectory(
                path=path,
                device=descriptor_identity[0],
                inode=descriptor_identity[1],
            )
        return None
    except LinuxInstallError:
        raise
    except OSError as exc:
        detail = _private_directory_error_detail(path, created=created, error=exc)
        raise LinuxInstallError("unsafe_install_root", detail) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if created and not completed:
            _remove_created_directory(path, created_identity)


def _private_directory_error_detail(
    path: Path, *, created: bool, error: OSError
) -> str:
    """Explain a kernel refusal without using pathname state as authority."""
    if created and isinstance(error, PermissionError):
        return (
            f"{path.name} was created but is not accessible; "
            "owner-stripping umasks are unsupported"
        )
    if created:
        return f"{path.name} could not be verified after creation"
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return f"{path.name} parent is unavailable"
    except OSError:
        return f"{path.name} could not be prepared"
    if stat.S_ISLNK(info.st_mode):
        return f"{path.name} must not be a symlink"
    if not stat.S_ISDIR(info.st_mode):
        return f"{path.name} is not a directory"
    return f"{path.name} could not be prepared"


def _remove_created_directory(path: Path, identity: tuple[int, int] | None) -> None:
    """Best-effort cleanup only when the pathname still names our inode."""
    if identity is None:
        return
    try:
        current = os.stat(path, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != identity:
            return
        path.rmdir()
    except OSError:
        # Replacement, content, disappearance, or permissions all mean leave it
        # alone. Cleanup must never replace the original installer diagnosis.
        return


def _remove_created_scaffolding(
    directories: Sequence[_CreatedDirectory],
) -> None:
    """Undo the empty directory tree this invocation brought into being.

    Only directories this run created are considered, and only while they are
    still empty, so a pre-existing install root — or one still holding an
    operator's data or an earlier release — is never removed by a failure. They
    are unwound in reverse, because the parent cannot go until the child has.

    Best-effort by construction: this runs while an installation failure is
    already propagating, and a directory that cannot be removed is untidy, not
    unsafe. Raising here would replace the operator's real diagnosis with a
    cleanup error.
    """
    for created in reversed(list(directories)):
        try:
            current = os.stat(created.path, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (created.device, created.inode):
                continue
            created.path.rmdir()
        except OSError:
            # Not empty, not present, or not permitted — all fine to leave, and
            # none of them says anything about the next one. Stopping here would
            # strand an empty `releases/` simply because `data/` held a config
            # the operator should keep. A parent still holding a survivor fails
            # on its own attempt, which is the correct reason to leave it.
            continue


def _version_key(
    version: str,
) -> tuple[int, int, int, bool, tuple[tuple[int, int, str], ...]]:
    match = _VERSION_RE.fullmatch(version)
    if match is None:
        raise LinuxInstallError("invalid_release_version", "version is not canonical")
    suffix = match.group("suffix")
    prerelease = tuple(
        (0, int(identifier), "") if identifier.isdigit() else (1, 0, identifier)
        for identifier in (suffix or "").split(".")
        if identifier
    )
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        suffix is None,
        prerelease,
    )


def _run_command(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=300
    )


def _run_health_command(
    command: Sequence[str], timeout_seconds: float
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_seconds,
    )
