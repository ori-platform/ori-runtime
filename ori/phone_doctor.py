# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Phone deployment readiness checks for Android/Termux installs."""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ori.config import Config, ConfigValidationError
from ori.utils.bool_utils import is_truthy

_DIRECT_SERIAL_GLOBS = ("/dev/ttyUSB*", "/dev/ttyACM*")
_TERMUX_USB_TIMEOUT_S = 2.0
_STATUSES = ("pass", "warn", "fail")

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BLUE = "\033[94m"


def c(text: str, *codes: str) -> str:
    return "".join(codes) + str(text) + RESET


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    message: str
    details: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise ValueError(f"invalid doctor check status: {self.status!r}")


def run_phone_doctor(config_path: str = "ori.yaml") -> list[DoctorCheck]:
    """Run phone deployment readiness checks without starting the runtime loop."""
    checks: list[DoctorCheck] = []
    checks.extend(_check_termux_environment())
    checks.append(_check_wake_lock_command())
    checks.append(_check_usb_readiness())

    config: Config | None = None
    try:
        config = Config.load(config_path)
    except ConfigValidationError as exc:
        checks.append(
            DoctorCheck(
                name="config.load",
                status="fail",
                message=f"Config validation failed: {exc}",
                details={"config_path": config_path},
            )
        )
    except Exception as exc:
        checks.append(
            DoctorCheck(
                name="config.load",
                status="fail",
                message=f"Could not load config: {exc}",
                details={"config_path": config_path},
            )
        )
    else:
        checks.append(
            DoctorCheck(
                name="config.load",
                status="pass",
                message="Config loads successfully.",
                details={"config_path": config_path},
            )
        )
        checks.extend(_check_phone_config(config))

    return checks


def has_failures(checks: list[DoctorCheck]) -> bool:
    return any(check.status == "fail" for check in checks)


def _check_termux_environment() -> list[DoctorCheck]:
    prefix = os.environ.get("PREFIX", "")
    home = os.environ.get("HOME", "")
    looks_like_termux = (
        "com.termux" in prefix
        or "com.termux" in home
        or Path("/data/data/com.termux/files/usr").exists()
    )

    checks = [
        DoctorCheck(
            name="termux.environment",
            status="pass" if looks_like_termux else "warn",
            message=(
                "Termux environment detected."
                if looks_like_termux
                else "Termux environment not detected on this host."
            ),
            details={"PREFIX": prefix, "HOME": home},
        )
    ]

    command_expectations = {
        "python": "Python is available.",
        "git": "Git is available.",
        "sshd": "OpenSSH server is available for support access.",
        "termux-usb": "Termux:API USB helper is available.",
    }
    for command, ok_message in command_expectations.items():
        checks.append(
            DoctorCheck(
                name=f"command.{command}",
                status="pass" if shutil.which(command) else "warn",
                message=(
                    ok_message
                    if shutil.which(command)
                    else f"{command} is not available on PATH."
                ),
            )
        )
    return checks


def _check_wake_lock_command() -> DoctorCheck:
    if shutil.which("termux-wake-lock"):
        return DoctorCheck(
            name="termux.wake_lock",
            status="pass",
            message="termux-wake-lock is available; run it before starting Ori.",
        )
    return DoctorCheck(
        name="termux.wake_lock",
        status="warn",
        message=(
            "termux-wake-lock is not available. Install Termux:API and disable "
            "battery optimization before unattended phone testing."
        ),
    )


def _check_usb_readiness() -> DoctorCheck:
    direct_devices = _find_direct_serial_devices()
    if direct_devices:
        return DoctorCheck(
            name="usb.readiness",
            status="pass",
            message="Direct USB serial device path is available.",
            details={"serial_devices": direct_devices},
        )

    termux_devices = _list_termux_usb_devices()
    if termux_devices:
        return DoctorCheck(
            name="usb.readiness",
            status="warn",
            message=(
                "termux-usb sees USB device(s), but no /dev/ttyUSB* or "
                "/dev/ttyACM* serial stream is exposed. Use an approved "
                "USB-serial bridge and configure a socket:// device_path."
            ),
            details={"termux_usb_devices": termux_devices},
        )

    if shutil.which("termux-usb"):
        return DoctorCheck(
            name="usb.readiness",
            status="warn",
            message="No USB serial meter detected yet.",
        )

    return DoctorCheck(
        name="usb.readiness",
        status="warn",
        message="termux-usb is unavailable and no direct USB serial device was found.",
    )


def _find_direct_serial_devices() -> list[str]:
    devices: list[str] = []
    for pattern in _DIRECT_SERIAL_GLOBS:
        devices.extend(glob.glob(pattern))
    return sorted(set(devices))


def _list_termux_usb_devices() -> list[str]:
    if shutil.which("termux-usb") is None:
        return []
    try:
        result = subprocess.run(
            ["termux-usb", "-l"],
            check=False,
            capture_output=True,
            text=True,
            timeout=_TERMUX_USB_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    return _parse_termux_usb_output(result.stdout)


def _parse_termux_usb_output(output: str) -> list[str]:
    cleaned = output.strip()
    if not cleaned:
        return []
    if cleaned.startswith("[") and cleaned.endswith("]"):
        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            return [str(item) for item in parsed if str(item).strip()]
        return []
    return [line.strip() for line in cleaned.splitlines() if line.strip()]


def _check_phone_config(config: Config) -> list[DoctorCheck]:
    checks = [
        _deployment_type_check(config),
        _relay_check(config),
        _gateway_check(config),
        _sensor_check(config),
        _telemetry_check(config),
        _health_socket_check(config),
        _operator_contact_check(config),
    ]
    return checks


def _deployment_type_check(config: Config) -> DoctorCheck:
    deployment_type = config.device.deployment_type
    return DoctorCheck(
        name="config.deployment_type",
        status="pass" if deployment_type == "phone" else "fail",
        message=(
            "device.deployment_type is phone."
            if deployment_type == "phone"
            else f"device.deployment_type must be phone, got {deployment_type!r}."
        ),
    )


def _relay_check(config: Config) -> DoctorCheck:
    enabled = is_truthy(config.actions.relay.get("enabled", False))
    return DoctorCheck(
        name="config.relay",
        status="fail" if enabled else "pass",
        message=(
            "actions.relay.enabled is false for phone mode."
            if not enabled
            else "actions.relay.enabled must remain false for phone-only deployments."
        ),
    )


def _gateway_check(config: Config) -> DoctorCheck:
    if not config.gateway.enabled:
        return DoctorCheck(
            name="config.gateway",
            status="pass",
            message="gateway.enabled is false for phone-only mode.",
        )
    return DoctorCheck(
        name="config.gateway",
        status="warn",
        message=(
            "gateway.enabled is true. This is valid only when the phone is "
            "explicitly bridged to a local Ori gateway."
        ),
    )


def _sensor_check(config: Config) -> DoctorCheck:
    usb_sensors = [
        sensor
        for sensor in config.sensors
        if sensor.protocol == "usb_serial" and sensor.type.startswith("usb_")
    ]
    if not usb_sensors:
        return DoctorCheck(
            name="config.usb_sensor",
            status="fail",
            message="No usb_serial energy sensor is configured.",
        )

    details = []
    needs_path = False
    for sensor in usb_sensors:
        device_path = str(sensor.metadata.get("device_path", "") or "").strip()
        auto_detect = is_truthy(sensor.metadata.get("auto_detect_device_path", False))
        details.append(
            {
                "id": sensor.id,
                "type": sensor.type,
                "device_path": device_path,
                "auto_detect_device_path": auto_detect,
            }
        )
        if not device_path and not auto_detect:
            needs_path = True

    if needs_path:
        return DoctorCheck(
            name="config.usb_sensor",
            status="fail",
            message=(
                "At least one usb_serial sensor lacks device_path and does not "
                "enable auto_detect_device_path."
            ),
            details={"sensors": details},
        )
    return DoctorCheck(
        name="config.usb_sensor",
        status="pass",
        message="usb_serial energy sensor configuration is present.",
        details={"sensors": details},
    )


def _telemetry_check(config: Config) -> DoctorCheck:
    telemetry = config.telemetry_export
    if not telemetry.enabled:
        return DoctorCheck(
            name="config.telemetry_export",
            status="warn",
            message="telemetry_export is disabled; cloud sync will not run.",
        )

    env_name = telemetry.api_key_env
    env_value = os.environ.get(env_name, "").strip() if env_name else ""
    if not env_value:
        return DoctorCheck(
            name="config.telemetry_export",
            status="fail",
            message=(
                f"telemetry_export is enabled but {env_name or 'api_key_env'} "
                "is not set in the environment."
            ),
            details={"api_key_env": env_name, "endpoint": telemetry.endpoint},
        )

    return DoctorCheck(
        name="config.telemetry_export",
        status="pass",
        message="telemetry_export is enabled and its API key environment variable is set.",
        details={"api_key_env": env_name, "endpoint": telemetry.endpoint},
    )


def _health_socket_check(config: Config) -> DoctorCheck:
    health_socket = (
        config.health_socket if isinstance(config.health_socket, dict) else {}
    )
    enabled = is_truthy(health_socket.get("enabled", False))
    path = str(health_socket.get("path", "") or "").strip()
    details = {"enabled": enabled, "path": path}

    if not enabled:
        return DoctorCheck(
            name="config.health_socket",
            status="warn",
            message=(
                "health_socket is disabled; local support diagnostics will be limited."
            ),
            details=details,
        )
    if path.startswith("/run/"):
        return DoctorCheck(
            name="config.health_socket",
            status="fail",
            message=(
                "health_socket.path uses /run, which is not writable in Termux. "
                "Use a path under /data/data/com.termux/files/home/.ori/."
            ),
            details=details,
        )
    return DoctorCheck(
        name="config.health_socket",
        status="pass",
        message="health_socket uses a phone-writable path.",
        details=details,
    )


def _operator_contact_check(config: Config) -> DoctorCheck:
    contact = config.actions.operator_contact.strip()
    if contact and "X" not in contact:
        return DoctorCheck(
            name="config.operator_contact",
            status="pass",
            message="actions.operator_contact is configured.",
        )
    return DoctorCheck(
        name="config.operator_contact",
        status="warn",
        message=(
            "actions.operator_contact is missing or still looks like a placeholder. "
            "Tier A/Tier C operator messages may not reach a real person."
        ),
    )


def _format_text(checks: list[DoctorCheck]) -> str:
    width = 78
    config_path = _config_path_from_checks(checks)
    counts = {
        "pass": sum(1 for check in checks if check.status == "pass"),
        "warn": sum(1 for check in checks if check.status == "warn"),
        "fail": sum(1 for check in checks if check.status == "fail"),
    }

    lines = [
        "",
        c("╔" + "═" * (width - 2) + "╗", BOLD + CYAN),
        c("║", BOLD + CYAN)
        + c("  ORI  PHONE DOCTOR".center(width - 2), BOLD + WHITE)
        + c("║", BOLD + CYAN),
        c("║", BOLD + CYAN)
        + c(f"  Config: {config_path}".center(width - 2), DIM)
        + c("║", BOLD + CYAN),
        c("╚" + "═" * (width - 2) + "╝", BOLD + CYAN),
        "",
        "  "
        + c(f"{counts['pass']} pass", GREEN)
        + c("  ·  ", DIM)
        + c(f"{counts['warn']} warn", YELLOW)
        + c("  ·  ", DIM)
        + c(f"{counts['fail']} fail", RED if counts["fail"] else DIM),
        "",
    ]

    for title, group_checks in _group_checks(checks):
        if not group_checks:
            continue
        lines.append(
            c(f"── {title} " + "─" * max(0, width - len(title) - 5), BOLD + BLUE)
        )
        lines.append("")
        for check in group_checks:
            lines.extend(_format_check(check))
        lines.append("")

    if has_failures(checks):
        lines.append(
            c(
                "Result: FAIL — fix blocking checks before customer activation.",
                RED,
                BOLD,
            )
        )
    else:
        lines.append(
            c("Result: PASS", GREEN, BOLD)
            + c(" — warnings are advisory for this host/profile.", DIM)
        )
    return "\n".join(lines)


def _config_path_from_checks(checks: list[DoctorCheck]) -> str:
    for check in checks:
        if check.name == "config.load" and check.details:
            raw = check.details.get("config_path")
            if raw:
                return str(raw)
    return "ori.yaml"


def _group_checks(
    checks: list[DoctorCheck],
) -> list[tuple[str, list[DoctorCheck]]]:
    termux: list[DoctorCheck] = []
    config: list[DoctorCheck] = []
    other: list[DoctorCheck] = []
    for check in checks:
        if (
            check.name.startswith(("termux.", "command."))
            or check.name == "usb.readiness"
        ):
            termux.append(check)
        elif check.name.startswith("config."):
            config.append(check)
        else:
            other.append(check)
    return [
        ("ANDROID / TERMUX", termux),
        ("ORI CONFIG", config),
        ("OTHER", other),
    ]


def _format_check(check: DoctorCheck) -> list[str]:
    label = _status_label(check.status)
    name = c(check.name.ljust(28), CYAN)
    lines = [f"  {label}  {name} {check.message}"]
    if check.details:
        details = json.dumps(check.details, sort_keys=True)
        lines.append(f"       {c(details, DIM)}")
    return lines


def _status_label(status: str) -> str:
    if status == "pass":
        return c("PASS", GREEN, BOLD)
    if status == "warn":
        return c("WARN", YELLOW, BOLD)
    return c("FAIL", RED, BOLD)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate Android/Termux Phone Starter readiness without starting the runtime loop."
    )
    parser.add_argument(
        "--config",
        default="ori.yaml",
        help="Path to ori.yaml. Defaults to ./ori.yaml.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Always exit 0, even when fail checks are present.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    checks = run_phone_doctor(config_path=args.config)

    if args.json:
        print(json.dumps([asdict(check) for check in checks], indent=2, sort_keys=True))
    else:
        print(_format_text(checks))

    if has_failures(checks) and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
