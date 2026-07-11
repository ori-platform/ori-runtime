# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Runtime-owned JSON bridge for external CLI tooling.

The Go CLI must not reimplement runtime config parsing, skill validation, or
runtime health semantics. This module exposes a narrow read-only command surface
that delegates those operations to the runtime package and returns deterministic
JSON envelopes.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from ori.config import Config, ConfigValidationError, SensorConfig
from ori.skills.loader import Skill, SkillLoader, SkillValidationError
from ori.skills.sandbox import SkillSecurityError

_SCHEMA_VERSION = 1
_DEFAULT_HEALTH_TIMEOUT_MS = 3000
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
_LEGACY_COMMANDS = {
    "config-validate": "config validate",
    "config-show": "config show",
    "skills-list": "skills list",
    "skills-validate": "skills validate",
    "health-snapshot": "health snapshot",
}
_PUBLIC_COMMANDS = {
    ("config", "validate"): "config-validate",
    ("config", "show"): "config-show",
    ("skills", "list"): "skills-list",
    ("skills", "validate"): "skills-validate",
    ("health", "snapshot"): "health-snapshot",
}
_SENSITIVE_KEY_FRAGMENTS = (
    "authorization",
    "bearer",
    "password",
    "private",
    "secret",
    "token",
)


class BridgeError(Exception):
    """Bridge command error that should be returned as structured JSON."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def main(argv: list[str] | None = None) -> int:
    """Run the CLI bridge and emit exactly one JSON object to stdout."""

    rc, payload = run_bridge(sys.argv[1:] if argv is None else argv)
    _write_json_response(payload)
    return rc


def run_bridge(argv: list[str]) -> tuple[int, dict[str, Any]]:
    """Execute a bridge command and return ``(exit_code, response_payload)``."""

    command = ""
    public_command = ""
    try:
        command, public_command, args = _parse_command(argv)

        if command in {"config-validate", "config-show"}:
            path = _required_option(args, "--path", command)
            result = _config_result(path)
        elif command == "skills-list":
            skills_dir = _required_option(args, "--skills-dir", command)
            result = _skills_result(
                skills_dir,
                require_signed=_flag_present(args, "--require-signed"),
            )
        elif command == "skills-validate":
            skills_dir = _required_option(args, "--skills-dir", command)
            result = _skills_result(
                skills_dir,
                require_signed=_flag_present(args, "--require-signed"),
            )
        elif command == "health-snapshot":
            socket_path = _required_option(args, "--socket", command)
            timeout_ms = _optional_int_option(
                args,
                "--timeout-ms",
                default=_DEFAULT_HEALTH_TIMEOUT_MS,
                minimum=100,
                command=command,
            )
            result = asyncio.run(_read_health_snapshot(socket_path, timeout_ms))
        else:
            raise BridgeError(
                "unknown_command",
                "unsupported bridge command",
            )
    except BridgeError as exc:
        return 2, _error(
            command=public_command,
            code=exc.code,
            detail=exc.detail,
        )
    except ConfigValidationError as exc:
        return 2, _error(
            command=public_command,
            code="config_validation_error",
            detail=str(exc),
        )
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return 2, _error(
            command=public_command,
            code="runtime_error",
            detail=str(exc),
        )
    except Exception as exc:
        return 1, _error(
            command=public_command,
            code="internal_error",
            detail=str(exc),
        )

    return 0, {
        "schema_version": _SCHEMA_VERSION,
        "ok": True,
        "command": public_command,
        "result": result,
    }


def _parse_command(argv: list[str]) -> tuple[str, str, list[str]]:
    """Parse public noun/verb bridge commands with legacy aliases.

    The public bridge shape mirrors operator-facing CLI grouping:
    ``config validate --path ori.yaml``. The legacy single-token verbs are
    accepted as compatibility aliases until all sibling CLIs migrate.
    """

    if not argv:
        raise BridgeError("missing_command", "bridge command is required")

    first = argv[0]
    if first in _LEGACY_COMMANDS:
        return first, _LEGACY_COMMANDS[first], argv[1:]

    if first in {group for group, _ in _PUBLIC_COMMANDS}:
        if len(argv) < 2:
            raise BridgeError(
                "invalid_arguments",
                f"{first} requires a subcommand",
            )
        pair = (first, argv[1])
        command = _PUBLIC_COMMANDS.get(pair)
        if command is None:
            allowed = sorted(
                subcommand for group, subcommand in _PUBLIC_COMMANDS if group == first
            )
            raise BridgeError(
                "unknown_command",
                f"unsupported {first} subcommand {argv[1]!r}; expected one of: "
                + ", ".join(allowed),
            )
        return command, " ".join(pair), argv[2:]

    raise BridgeError(
        "unknown_command",
        "unsupported bridge command",
    )


def _required_option(args: list[str], name: str, command: str) -> str:
    try:
        index = args.index(name)
    except ValueError as exc:
        raise BridgeError(
            "invalid_arguments",
            f"{command} requires {name}",
        ) from exc
    try:
        value = args[index + 1]
    except IndexError as exc:
        raise BridgeError(
            "invalid_arguments",
            f"{command} requires a value after {name}",
        ) from exc
    if not value.strip() or value.startswith("--"):
        raise BridgeError(
            "invalid_arguments",
            f"{command} requires a non-empty value after {name}",
        )
    return value


def _optional_int_option(
    args: list[str],
    name: str,
    *,
    default: int,
    minimum: int,
    command: str,
) -> int:
    if name not in args:
        return default
    raw = _required_option(args, name, command)
    try:
        value = int(raw)
    except ValueError as exc:
        raise BridgeError(
            "invalid_arguments",
            f"{name} must be an integer",
        ) from exc
    if value < minimum:
        raise BridgeError(
            "invalid_arguments",
            f"{name} must be >= {minimum}",
        )
    return value


def _flag_present(args: list[str], name: str) -> bool:
    return name in set(args)


def _config_result(path: str) -> dict[str, Any]:
    config = Config.load(path)
    return {
        "valid": True,
        "path": str(Path(path)),
        "config": _summarize_config(config),
    }


def _summarize_config(config: Config) -> dict[str, Any]:
    return {
        "device": {
            "id": config.device.id,
            "name": config.device.name,
            "location": config.device.location,
            "timezone": config.device.timezone,
            "country_code": config.device.country_code,
            "deployment_type": config.device.deployment_type,
            "deployment_profile": config.device.deployment_profile,
            "site_type": config.device.site_type,
        },
        "sensors": [_summarize_sensor(sensor) for sensor in config.sensors],
        "skills": [
            {
                "name": skill.name,
                "version": skill.version,
            }
            for skill in config.skills
        ],
        "config_signature": _config_signature_posture(config),
        "telemetry_export": _telemetry_export_posture(config),
        "device_policy": _device_policy_posture(config),
        "phone_runtime_mobile": _phone_runtime_mobile_posture(config),
    }


def _summarize_sensor(sensor: SensorConfig) -> dict[str, Any]:
    return {
        "id": sensor.id,
        "type": sensor.type,
        "protocol": sensor.protocol,
        "poll_interval_ms": sensor.poll_interval_ms,
        "metadata_keys": sorted(str(key) for key in sensor.metadata),
        "device_path_kind": _device_path_kind(sensor),
    }


def _device_path_kind(sensor: SensorConfig) -> str:
    device_path = str(sensor.metadata.get("device_path", "") or "").strip()
    if not device_path:
        return "none"
    if device_path.startswith("socket://"):
        return "socket"
    if device_path.startswith("/dev/"):
        return "direct_serial"
    parsed = urlparse(device_path)
    if parsed.scheme:
        return "url"
    return "path"


def _config_signature_posture(config: Config) -> dict[str, Any]:
    signature = config.security.get("config_signature") or {}
    if not isinstance(signature, dict):
        signature = {}
    return {
        "required": bool(signature.get("required")),
        "verified": bool(signature.get("verified")),
        "signer_id": _optional_str(signature.get("signer_id")),
        "signed_at_ms": signature.get("signed_at_ms"),
        "trust_anchor_env": _optional_str(signature.get("trust_anchor_env")),
    }


def _telemetry_export_posture(config: Config) -> dict[str, Any]:
    endpoint = str(config.telemetry_export.endpoint or "").strip()
    parsed = urlparse(endpoint)
    hostname = parsed.hostname or ""
    return {
        "enabled": bool(config.telemetry_export.enabled),
        "endpoint_configured": bool(endpoint),
        "endpoint_scheme": parsed.scheme,
        "endpoint_host": hostname,
        "endpoint_path": parsed.path,
        "endpoint_uses_https": parsed.scheme == "https",
        "endpoint_is_loopback_http": (
            parsed.scheme == "http" and hostname in _LOOPBACK_HOSTS
        ),
        "api_key_env": config.telemetry_export.api_key_env,
        "flush_interval_s": config.telemetry_export.flush_interval_s,
        "batch_size": config.telemetry_export.batch_size,
        "timeout_ms": config.telemetry_export.timeout_ms,
        "max_queue_size": config.telemetry_export.max_queue_size,
    }


def _device_policy_posture(config: Config) -> dict[str, Any]:
    policy = config.device_policy if isinstance(config.device_policy, dict) else {}
    url = str(policy.get("url", "") or "").strip()
    parsed = urlparse(url)
    return {
        "enabled": bool(policy.get("enabled")),
        "url_configured": bool(url),
        "url_scheme": parsed.scheme,
        "url_host": parsed.hostname or "",
        "url_path": parsed.path,
        "auth_token_configured": bool(policy.get("auth_token")),
        "public_key_configured": bool(policy.get("public_key_b64")),
        "request_timeout_ms": policy.get("request_timeout_ms"),
        "max_clock_skew_s": policy.get("max_clock_skew_s"),
        "refresh_enabled": bool(policy.get("refresh_enabled")),
        "refresh_interval_s": policy.get("refresh_interval_s"),
    }


def _phone_runtime_mobile_posture(config: Config) -> dict[str, Any]:
    applies = config.device.deployment_type == "phone"
    socket_bridge_sensor_ids = [
        sensor.id
        for sensor in config.sensors
        if sensor.protocol == "usb_serial"
        and str(sensor.metadata.get("device_path", "")).startswith("socket://")
    ]
    direct_serial_sensor_ids = [
        sensor.id
        for sensor in config.sensors
        if sensor.protocol == "usb_serial"
        and str(sensor.metadata.get("device_path", "")).startswith("/dev/")
    ]
    return {
        "applies": applies,
        "signed_config_required": bool(
            (config.security.get("config_signature") or {}).get("required")
        ),
        "socket_bridge_sensor_ids": socket_bridge_sensor_ids,
        "direct_serial_sensor_ids": direct_serial_sensor_ids,
        "tier_c_physical_authority": False if applies else None,
        "tier_d_physical_authority": False if applies else None,
    }


def _skills_result(skills_dir: str, *, require_signed: bool) -> dict[str, Any]:
    root = Path(skills_dir)
    if not root.exists():
        raise BridgeError(
            "invalid_arguments",
            f"skills directory does not exist: {skills_dir}",
        )
    if not root.is_dir():
        raise BridgeError(
            "invalid_arguments",
            f"skills path is not a directory: {skills_dir}",
        )

    loader = SkillLoader(require_signed=require_signed)
    skills: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for skill_dir in _iter_skill_dirs(root):
        try:
            skills.append(_summarize_skill(loader.load_one(skill_dir), skill_dir))
        except (
            SkillValidationError,
            SkillSecurityError,
            yaml.YAMLError,
            OSError,
        ) as exc:
            errors.append(
                {
                    "skill_dir": str(skill_dir),
                    "code": _skill_error_code(exc),
                    "detail": str(exc),
                }
            )

    return {
        "valid": not errors,
        "skills_dir": str(root),
        "skill_count": len(skills),
        "error_count": len(errors),
        "skills": skills,
        "errors": errors,
    }


def _iter_skill_dirs(root: Path) -> list[Path]:
    if (root / "skill.yaml").exists():
        return [root]
    return sorted(
        child
        for child in root.iterdir()
        if child.is_dir()
        and child.name != "template"
        and (child / "skill.yaml").exists()
    )


def _summarize_skill(skill: Skill, skill_dir: Path) -> dict[str, Any]:
    return {
        "skill_dir": str(skill_dir),
        "name": skill.name,
        "version": skill.version,
        "author": skill.author,
        "sensors_required": skill.sensors_required,
        "triggers": [
            {
                "name": trigger.name,
                "action_tier": trigger.action_tier,
                "escalate_to": trigger.escalate_to,
                "bypass_llm": trigger.bypass_llm,
                "requires_approval": trigger.requires_approval,
                "reasoning_policy": trigger.reasoning_policy,
            }
            for trigger in skill.triggers
        ],
    }


def _skill_error_code(exc: Exception) -> str:
    if isinstance(exc, SkillSecurityError):
        return "skill_security_error"
    if isinstance(exc, SkillValidationError):
        return "skill_validation_error"
    if isinstance(exc, yaml.YAMLError):
        return "skill_yaml_error"
    return "skill_load_error"


async def _read_health_snapshot(socket_path: str, timeout_ms: int) -> dict[str, Any]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(path=socket_path),
            timeout=timeout_ms / 1000,
        )
    except (OSError, TimeoutError) as exc:
        raise BridgeError("health_socket_unavailable", str(exc)) from exc

    try:
        writer.write(b"GET_HEALTH\n")
        await asyncio.wait_for(writer.drain(), timeout=timeout_ms / 1000)
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout_ms / 1000)
    except (OSError, TimeoutError) as exc:
        raise BridgeError("health_socket_error", str(exc)) from exc
    finally:
        writer.close()
        await writer.wait_closed()

    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BridgeError(
            "health_socket_invalid_json",
            "health socket returned invalid JSON",
        ) from exc
    if not isinstance(response, dict):
        raise BridgeError(
            "health_socket_invalid_json",
            "health socket response must be a JSON object",
        )
    return response


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _redact_for_output(value: Any) -> Any:
    """Recursively redact obviously sensitive values before stdout emission."""
    if isinstance(value, dict):
        return {
            str(key): (
                "[redacted]"
                if _is_sensitive_output_key(str(key))
                else _redact_for_output(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_for_output(item) for item in value]
    return value


def _is_sensitive_output_key(key: str) -> bool:
    lowered = key.lower()
    if lowered.endswith("_env") or lowered.endswith("_configured"):
        return False
    if lowered == "signature":
        return True
    return any(fragment in lowered for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _write_json_response(payload: dict[str, Any]) -> None:
    safe_payload = _redact_for_output(payload)
    encoded = json.dumps(safe_payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    sys.stdout.buffer.write(encoded + b"\n")


def _error(*, command: str, code: str, detail: str) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "ok": False,
        "command": command or None,
        "error": {
            "code": code,
            "detail": detail,
        },
    }


if __name__ == "__main__":
    raise SystemExit(main())
