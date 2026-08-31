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
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from ori.config import (
    Config,
    ConfigValidationError,
    SensorConfig,
    requires_production_posture,
)
from ori.gateway.mqtt_security import parse_gateway_broker_endpoint
from ori.network.events import SensorReading
from ori.security.commissioning.anchors import (
    AnchorError,
    anchor_collision,
    load_commissioning_anchors,
    provisioning_anchor,
)
from ori.security.commissioning.binding import (
    AcceptedBinding,
    BindingRefusedError,
    parse_document,
    verify_binding_envelope,
)
from ori.security.commissioning.loader import (
    BINDING_RELATIVE_PATH,
    DeclaredInventory,
    accepted_from_row,
    is_the_binding_in_force,
    verifier_context,
)
from ori.security.commissioning.profiles import (
    ProfileSetError,
    load_shipped_profile_set,
)
from ori.skills.loader import Skill, SkillLoader, SkillValidationError
from ori.skills.sandbox import SkillSecurityError
from ori.state.store import StateStore
from ori.utils.bool_utils import is_truthy

_SCHEMA_VERSION = 1
_DEFAULT_HEALTH_TIMEOUT_MS = 3000
_DEFAULT_STATE_DB_PATH = "ori_state.db"
_MAX_STATE_LIMIT = 1000
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
    ("state", "action-log"): "state-action-log",
    ("state", "history"): "state-history",
    ("commissioning", "inventory"): "commissioning-inventory",
    ("commissioning", "deliver"): "commissioning-deliver",
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
    """Bridge command error that should be returned as structured JSON.

    `stage` is carried only by verdicts that have one. A commissioned binding
    is refused *at* a stage, and a refusal only proves a check ran if every
    earlier stage passed, so losing the stage would reduce a typed verdict to
    a sentence.
    """

    def __init__(self, code: str, detail: str, stage: str | None = None) -> None:
        self.stage = stage
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
    # Most commands return a mapping; the state reads return a list of rows.
    result: dict[str, Any] | list[dict[str, Any]]
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
                listing=True,
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
        elif command == "state-action-log":
            result = asyncio.run(_read_state_action_log(args))
        elif command == "state-history":
            result = asyncio.run(_read_state_history(args))
        elif command == "commissioning-inventory":
            path = _required_option(args, "--path", command)
            result = asyncio.run(_commissioning_inventory(path))
        elif command == "commissioning-deliver":
            path = _required_option(args, "--path", command)
            binding_path = _required_option(args, "--binding", command)
            result = asyncio.run(
                _commissioning_deliver(
                    path, binding_path, force=_flag_present(args, "--force")
                )
            )
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
            stage=exc.stage,
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
        "gateway": _gateway_posture(config),
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


def _gateway_posture(config: Config) -> dict[str, Any]:
    """Describe the gateway broker a deployment expects to reach.

    The runtime and the gateway normally run on the same device, so an enabled
    gateway asserts that a broker exists — usually on loopback. Nothing else
    reports whether one is actually there, and a config declaring
    ``gateway.enabled: true`` validates happily with no broker running.

    Normalisation comes from :func:`parse_gateway_broker_endpoint`, the same
    parser the transport uses, so diagnostics cannot disagree with the runtime
    about default ports or a bare host. A `broker_url` that cannot be parsed is
    reported as a structured error rather than raising out of the command.

    Only the *name* of the shared-secret variable is reported. Whether the
    secret is present cannot be answered here: the service receives it from its
    own environment file, which this process does not inherit, so any answer
    would describe the caller rather than the service.
    """
    broker_url = str(config.gateway.broker_url or "").strip()
    posture: dict[str, Any] = {
        "enabled": bool(config.gateway.enabled),
        "broker_configured": bool(broker_url),
        "auth_enabled": is_truthy(config.gateway.auth.get("enabled", False)),
        "encryption_enabled": is_truthy(
            config.gateway.encryption.get("enabled", False)
        ),
        "tls_enabled": is_truthy(config.gateway.tls.get("enabled", False)),
        "shared_secret_env": str(
            config.gateway.auth.get("shared_secret_env", "") or ""
        ).strip(),
    }

    if not broker_url:
        posture.update(
            broker_scheme="", broker_host="", broker_port=None, broker_is_loopback=False
        )
        return posture

    try:
        endpoint = parse_gateway_broker_endpoint(broker_url)
    except ValueError as exc:
        posture.update(
            broker_scheme="",
            broker_host="",
            broker_port=None,
            broker_is_loopback=False,
            broker_error=str(exc),
        )
        return posture

    posture.update(
        broker_scheme=endpoint.scheme,
        broker_host=endpoint.host,
        broker_port=endpoint.port,
        broker_is_loopback=endpoint.host in _LOOPBACK_HOSTS,
    )
    return posture


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


def _skills_result(
    skills_dir: str, *, require_signed: bool, listing: bool = False
) -> dict[str, Any]:
    """Report on the skills under *skills_dir*. Executes nothing either way.

    ``listing`` selects between the two questions an operator can ask:

    - Validation (default) answers "would the runtime activate this?", so a
      skill the runtime refuses is an error here too. Anything else would
      approve skills that then fail to load, at exactly the moment someone is
      deciding whether installing one is safe.
    - Listing answers "what is installed?". A skill the runtime will not
      activate still has a name and a version, and the operator reading the
      list is usually trying to find out why — so it is reported with
      ``activation`` describing the refusal rather than reduced to an error.
    """
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
            # Neither path calls load_one: inspecting a skill must not run it.
            if listing:
                summary = _summarize_skill(loader.inspect_one(skill_dir), skill_dir)
                summary["activation"] = _activation_status(loader, skill_dir)
            else:
                summary = _summarize_skill(loader.validate_one(skill_dir), skill_dir)
            skills.append(summary)
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

    # `valid` is conjunctive. Consumers read it as "these skills are usable",
    # and a skill the runtime refuses to activate is not usable — reporting
    # `valid: true` beside a per-skill `activation.ok: false` would put the
    # safe-looking answer in the field automation actually branches on, and the
    # disqualifying detail in one it does not. `activatable` is published
    # separately so a consumer can tell the two failure modes apart without
    # walking the list.
    unactivatable = [
        skill for skill in skills if not skill.get("activation", {"ok": True})["ok"]
    ]
    return {
        "valid": not errors and not unactivatable,
        # Also conjunctive. A skill that failed to parse or validate is not
        # activatable either — it never got far enough to have an activation
        # verdict, and reporting `activatable: true` beside `valid: false`
        # would describe a malformed skill as runnable.
        "activatable": not errors and not unactivatable,
        "skills_dir": str(root),
        "skill_count": len(skills),
        "error_count": len(errors),
        "unactivatable_count": len(unactivatable),
        "skills": skills,
        "errors": errors,
    }


def _activation_status(loader: SkillLoader, skill_dir: Path) -> dict[str, Any]:
    """Whether the runtime would activate this skill, and why not if it would not."""
    try:
        loader._assert_hooks_activatable(skill_dir)
    except SkillSecurityError as exc:
        return {"ok": False, "code": "hooks_not_activatable", "detail": str(exc)}
    return {"ok": True}


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


async def _read_state_action_log(args: list[str]) -> list[dict[str, Any]]:
    filters = _parse_state_filters(
        args,
        command="state action-log",
        allowed={"limit"},
    )
    limit = _state_limit(filters.get("limit"), default=50)
    store = _state_store_from_default_path()
    await store.open()
    try:
        return await store.get_action_log(limit=limit)
    finally:
        await store.close()


async def _read_state_history(args: list[str]) -> list[dict[str, Any]]:
    filters = _parse_state_filters(
        args,
        command="state history",
        allowed={"sensor_id", "limit"},
    )
    sensor_id = str(filters.get("sensor_id", "") or "").strip()
    if not sensor_id:
        raise BridgeError(
            "invalid_arguments",
            "state history requires sensor_id",
        )
    limit = _state_limit(filters.get("limit"), default=100)
    store = _state_store_from_default_path()
    await store.open()
    try:
        readings = await store.get_history(sensor_id=sensor_id, limit=limit)
    finally:
        await store.close()
    return [_sensor_reading_to_dict(reading) for reading in readings]


def _parse_state_filters(
    args: list[str],
    *,
    command: str,
    allowed: set[str],
) -> dict[str, str]:
    filters: dict[str, str] = {}
    for raw in args:
        if "=" not in raw:
            raise BridgeError(
                "invalid_arguments",
                f"{command} filter {raw!r} must use key=value syntax",
            )
        key, value = raw.split("=", 1)
        key = key.strip()
        if not key or key not in allowed:
            expected = ", ".join(sorted(allowed))
            raise BridgeError(
                "invalid_arguments",
                f"{command} unsupported filter {key!r}; expected one of: {expected}",
            )
        if key in filters:
            raise BridgeError(
                "invalid_arguments",
                f"{command} received duplicate filter {key!r}",
            )
        if value == "":
            raise BridgeError(
                "invalid_arguments",
                f"{command} filter {key!r} requires a non-empty value",
            )
        filters[key] = value
    return filters


def _state_limit(raw: str | None, *, default: int) -> int:
    if raw is None:
        return default
    try:
        limit = int(raw)
    except ValueError as exc:
        raise BridgeError(
            "invalid_arguments",
            "limit must be an integer",
        ) from exc
    if limit < 1 or limit > _MAX_STATE_LIMIT:
        raise BridgeError(
            "invalid_arguments",
            f"limit must be between 1 and {_MAX_STATE_LIMIT}",
        )
    return limit


def _commissioning_store(config: Config) -> StateStore:
    """The store the runtime itself opens, resolved the way the runtime does."""
    db_path = str(config.raw.get("database", {}).get("path", _DEFAULT_STATE_DB_PATH))
    return StateStore(db_path=db_path)


def _declared_actuators(config: Config) -> list[dict[str, Any]]:
    """Actuating hardware the configuration declares, by identity.

    A local-GPIO actuator is named by its pin alone. Polarity is a commissioned
    fact, not an inventory one, so reporting `active_high` here would answer
    the question the ceremony exists to ask. A declared pin counts whether or
    not `enabled` is set: the pin is what declares the physical path.
    """
    pin = config.actions.relay.get("gpio_pin")
    if pin is None:
        return []
    return [{"kind": "local_gpio", "identity": {"gpio_pin": int(pin)}}]


def _commissioning_posture(config: Config) -> str:
    """The posture the runtime's own verifier will apply, and only those two."""
    hardened = requires_production_posture(
        device=config.device, security=config.security
    )
    return "production" if hardened else "development"


async def _in_force_binding(config: Config) -> AcceptedBinding | None:
    """The accepted binding this device holds, or None.

    A retained binding for another device is not in force, which is how the
    loader reads it; reporting it here would let a producer chain a revision
    onto a document this device never accepted.
    """
    db_path = Path(
        str(config.raw.get("database", {}).get("path", _DEFAULT_STATE_DB_PATH))
    )
    if not db_path.is_file():
        # A device that has never started has no store, and asking it a
        # question must not build one. Opening the store applies the DDL, so
        # this read would otherwise materialise the runtime's whole durable
        # state owned by whoever ran an inventory query -- on a system install
        # that is root, and the service account could then never open it.
        return None
    store = _commissioning_store(config)
    await store.open()
    try:
        row = await store.get_commissioned_binding_in_force()
    finally:
        await store.close()
    if row is None or str(row.get("device_id")) != str(config.device.id):
        return None
    binding = accepted_from_row(row)
    return binding if binding.in_force_eligible else None


async def _commissioning_inventory(config_path: str) -> dict[str, Any]:
    """The candidate set a binding may name: hardware, posture, and where the chain is."""
    config = Config.load(config_path)
    in_force = await _in_force_binding(config)
    return {
        "device_id": str(config.device.id),
        "sensor_ids": sorted(str(sensor.id) for sensor in config.sensors),
        "actuators": _declared_actuators(config),
        "deployment_posture": _commissioning_posture(config),
        "accepted_binding_seq": in_force.binding_seq if in_force else 0,
        "accepted_binding_hash": in_force.canonical_hash if in_force else None,
    }


async def _commissioning_deliver(
    config_path: str, binding_path: str, *, force: bool
) -> dict[str, Any]:
    """Verify a signed envelope against this device, then install it if it passed.

    The verdict is the runtime's own: the same verifier, over the same context
    the loader builds at startup, so a document accepted here is the document
    that will be accepted then. Nothing is written until every stage has
    passed, and this does not make the binding live -- the runtime reads the
    file when it next starts.
    """
    config = Config.load(config_path)
    device_id = str(config.device.id)
    try:
        text = Path(binding_path).read_bytes().decode("utf-8")
    except OSError as exc:
        raise BridgeError("binding_unreadable", str(exc)) from exc
    except UnicodeDecodeError:
        # A document that is not UTF-8 is malformed by the contract's own
        # grammar. Letting it reach the generic handler would report the same
        # class of defect as every other malformed document under a different
        # name, and an operator cannot tell a bad file from a broken tool.
        raise _refused("parses", "malformed") from None

    try:
        anchors = load_commissioning_anchors()
    except AnchorError as exc:
        raise BridgeError("anchor_error", str(exc)) from exc
    try:
        profiles = load_shipped_profile_set()
    except ProfileSetError as exc:
        raise BridgeError("profile_set_error", str(exc)) from exc

    prov = provisioning_anchor(config.security)
    in_force = await _in_force_binding(config)

    if anchor_collision(anchors, prov):
        # Decided before any document is read, exactly as at configuration load.
        raise _refused("key_selection", "anchor_collision")

    try:
        document = parse_document(text)
    except BindingRefusedError as refusal:
        raise _refused(refusal.stage, refusal.reason) from None

    if in_force is not None and is_the_binding_in_force(document, in_force):
        return {
            "device_id": device_id,
            "accepted": True,
            "installed": False,
            "already_in_force": True,
            "binding_seq": in_force.binding_seq,
            "binding_hash": in_force.canonical_hash,
            "binding_seq_in_force": in_force.binding_seq,
            "state": "in_force",
            "message": (
                "this document is already the binding in force; nothing to install"
            ),
        }

    context = verifier_context(
        device_id=device_id,
        anchors=anchors,
        provisioning_anchor=prov,
        in_force=in_force,
        inventory=DeclaredInventory.from_config(
            [str(sensor.id) for sensor in config.sensors],
            _declared_gpio_pin(config),
        ),
        posture=_commissioning_posture(config),  # type: ignore[arg-type]
        profiles=profiles,
        document=document,
    )
    try:
        accepted = verify_binding_envelope(document, context)
    except BindingRefusedError as refusal:
        raise _refused(refusal.stage, refusal.reason) from None

    target = Path(config_path).resolve().parent / BINDING_RELATIVE_PATH
    payload = text.encode("utf-8")
    if target.exists() and target.read_bytes() != payload and not force:
        raise BridgeError(
            "binding_already_staged",
            f"a different document is already staged at {target}; "
            "pass --force to replace it",
        )
    _write_staged_binding(target, payload)

    # Verification is not authority: a document missing either proof leg is
    # provisional, and saying only that it verified would let an installer read
    # a staged document as a commissioned relay.
    provisional = not accepted.in_force_eligible
    return {
        "device_id": device_id,
        "accepted": True,
        "installed": True,
        "already_in_force": False,
        "binding_seq": accepted.binding_seq,
        "binding_hash": accepted.canonical_hash,
        "binding_seq_in_force": in_force.binding_seq if in_force else 0,
        "state": "provisional" if provisional else "in_force",
        "unproven_zones": sorted(
            zone.zone_id for zone in accepted.zones if not zone.in_force_eligible
        ),
        "message": (
            "binding verified and staged, and provisional: a proof leg is "
            "unproven, so the runtime will not connect the actuator or command "
            "its coil"
            if provisional
            else "binding verified and staged; the runtime reads it when it next starts"
        ),
    }


def _declared_gpio_pin(config: Config) -> int | None:
    pin = config.actions.relay.get("gpio_pin")
    return int(pin) if pin is not None else None


def _refused(stage: str, reason: str) -> BridgeError:
    """A refused binding, reported the way this bridge reports a rejected document.

    `config validate` already answers an invalid document with `ok: false` and
    exit 2, and a binding the runtime refuses is the same kind of answer: the
    operator handed the tool something the contract does not accept. The code
    is the contract's reason and the stage rides alongside it, because a
    refusal only proves a check ran if every earlier stage passed.
    """
    return BridgeError(
        code=reason,
        detail=(
            f"binding refused at {stage}; the binding in force is unchanged "
            "and nothing was written"
        ),
        stage=stage,
    )


def _write_staged_binding(target: Path, payload: bytes) -> None:
    """Write the document whole or not at all.

    A half-written binding at the contract's path is a document the runtime
    would refuse at `parses` on its next start, which is safe but indis-
    tinguishable from a tampered one.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _state_store_from_default_path() -> StateStore:
    path = Path(_DEFAULT_STATE_DB_PATH)
    if not path.exists():
        raise BridgeError(
            "state_store_unavailable",
            f"state database does not exist: {_DEFAULT_STATE_DB_PATH}",
        )
    if not path.is_file():
        raise BridgeError(
            "state_store_unavailable",
            f"state database path is not a file: {_DEFAULT_STATE_DB_PATH}",
        )
    return StateStore(str(path))


def _sensor_reading_to_dict(reading: SensorReading) -> dict[str, Any]:
    return {
        "sensor_id": reading.sensor_id,
        "sensor_type": reading.sensor_type,
        "value": reading.value,
        "unit": reading.unit,
        "timestamp": reading.timestamp,
        "quality": reading.quality,
        "metadata": reading.metadata,
    }


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


def _error(
    *, command: str, code: str, detail: str, stage: str | None = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "detail": detail}
    if stage is not None:
        error["stage"] = stage
    return {
        "schema_version": _SCHEMA_VERSION,
        "ok": False,
        "command": command or None,
        "error": error,
    }


if __name__ == "__main__":
    raise SystemExit(main())
