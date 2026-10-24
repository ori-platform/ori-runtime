# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``gateway`` section."""

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ori.config._fields import ConfigValidationError
from ori.utils.bool_utils import is_truthy
from ori.utils.net_utils import is_loopback_host

logger = logging.getLogger("ori.config")


@dataclass
class GatewayConfig:
    enabled: bool
    broker_url: str
    reasoning: dict = field(default_factory=dict)
    node_heartbeat: dict = field(default_factory=dict)
    firmware_telemetry: dict = field(default_factory=dict)
    firmware_commands: dict = field(default_factory=dict)
    auth: dict = field(default_factory=dict)
    custody: dict = field(default_factory=dict)
    tls: dict = field(default_factory=dict)
    encryption: dict = field(default_factory=dict)
    broker_posture: dict = field(default_factory=dict)


def parse_gateway(data: Any) -> GatewayConfig:
    if not isinstance(data, dict):
        raise ConfigValidationError("'gateway' section must be a mapping.")
    node_heartbeat_raw = data.get("node_heartbeat") or {}
    if not isinstance(node_heartbeat_raw, dict):
        raise ConfigValidationError(
            "'gateway.node_heartbeat' section must be a mapping."
        )
    node_heartbeat = dict(node_heartbeat_raw)
    node_heartbeat["enabled"] = (
        str(node_heartbeat.get("enabled", "true")).strip().lower() == "true"
        or node_heartbeat.get("enabled") is True
    )
    try:
        interval_seconds = float(node_heartbeat.get("interval_seconds", 30))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "gateway.node_heartbeat.interval_seconds must be a number"
        ) from exc
    if interval_seconds < 1:
        raise ConfigValidationError(
            "gateway.node_heartbeat.interval_seconds must be >= 1"
        )
    node_heartbeat["interval_seconds"] = interval_seconds

    reasoning_raw = data.get("reasoning") or {}
    if not isinstance(reasoning_raw, dict):
        raise ConfigValidationError("'gateway.reasoning' section must be a mapping.")
    reasoning = dict(reasoning_raw)
    reasoning["enabled"] = (
        str(reasoning.get("enabled", "true")).strip().lower() == "true"
        or reasoning.get("enabled") is True
    )
    try:
        timeout_ms = int(reasoning.get("timeout_ms", 10_000))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "gateway.reasoning.timeout_ms must be an integer"
        ) from exc
    if timeout_ms < 100:
        raise ConfigValidationError("gateway.reasoning.timeout_ms must be >= 100")
    reasoning["timeout_ms"] = timeout_ms

    firmware_telemetry_raw = data.get("firmware_telemetry") or {}
    if not isinstance(firmware_telemetry_raw, dict):
        raise ConfigValidationError(
            "'gateway.firmware_telemetry' section must be a mapping."
        )
    firmware_telemetry = dict(firmware_telemetry_raw)
    firmware_telemetry["enabled"] = (
        str(firmware_telemetry.get("enabled", "false")).strip().lower() == "true"
        or firmware_telemetry.get("enabled") is True
    )
    topic = str(firmware_telemetry.get("topic", "ori/fw/+/telemetry") or "").strip()
    if firmware_telemetry["enabled"] and not topic:
        raise ConfigValidationError(
            "gateway.firmware_telemetry.topic must not be empty when enabled"
        )
    if "#" in topic:
        raise ConfigValidationError(
            "gateway.firmware_telemetry.topic must not use # wildcard"
        )
    try:
        firmware_qos = int(firmware_telemetry.get("qos", 1))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "gateway.firmware_telemetry.qos must be an integer"
        ) from exc
    if firmware_qos not in {0, 1, 2}:
        raise ConfigValidationError("gateway.firmware_telemetry.qos must be 0, 1, or 2")
    firmware_telemetry["topic"] = topic or "ori/fw/+/telemetry"
    firmware_telemetry["qos"] = firmware_qos
    # Where the controller profile documents a release publishes are held. A
    # document is used only through the digest a signed manifest names, so
    # this chooses which documents are available, never what one means.
    profiles_dir = firmware_telemetry.get("controller_profiles_dir", "")
    if profiles_dir is None:
        profiles_dir = ""
    if not isinstance(profiles_dir, str) or "\x00" in profiles_dir:
        raise ConfigValidationError(
            "gateway.firmware_telemetry.controller_profiles_dir must be a path"
        )
    firmware_telemetry["controller_profiles_dir"] = profiles_dir.strip()

    firmware_commands_raw = data.get("firmware_commands") or {}
    if not isinstance(firmware_commands_raw, dict):
        raise ConfigValidationError(
            "'gateway.firmware_commands' section must be a mapping."
        )
    firmware_commands = dict(firmware_commands_raw)
    firmware_commands["enabled"] = (
        str(firmware_commands.get("enabled", "false")).strip().lower() == "true"
        or firmware_commands.get("enabled") is True
    )
    try:
        command_qos = int(firmware_commands.get("qos", 1))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "gateway.firmware_commands.qos must be an integer"
        ) from exc
    if command_qos != 1:
        raise ConfigValidationError(
            "gateway.firmware_commands.qos must be 1 per firmware-commands/v1"
        )
    try:
        publish_timeout_s = float(firmware_commands.get("publish_timeout_s", 10.0))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "gateway.firmware_commands.publish_timeout_s must be a number"
        ) from exc
    if not math.isfinite(publish_timeout_s) or publish_timeout_s <= 0:
        raise ConfigValidationError(
            "gateway.firmware_commands.publish_timeout_s must be a finite number > 0"
        )
    runtime_command_key_env = str(
        firmware_commands.get("runtime_command_key_env", "") or ""
    ).strip()
    provisioner_key_env = str(
        firmware_commands.get("provisioner_key_env", "") or ""
    ).strip()
    if firmware_commands["enabled"] and (
        not runtime_command_key_env or not provisioner_key_env
    ):
        raise ConfigValidationError(
            "gateway.firmware_commands.runtime_command_key_env and "
            "gateway.firmware_commands.provisioner_key_env are required when enabled"
        )
    # Bounded by the reconciler's own backoff ceiling rather than an
    # independent number. A base interval above the ceiling is incoherent: the
    # first delay would already exceed the maximum the backoff is allowed to
    # reach, so there is nothing to back off to and the documented ceiling
    # would be a false claim for that configuration.
    from ori.security.firmware.reconciliation import (
        DEFAULT_INTERVAL_S,
        DEFAULT_MAX_INTERVAL_S,
    )

    try:
        confirmation_retry_interval_s = float(
            firmware_commands.get("confirmation_retry_interval_s", DEFAULT_INTERVAL_S)
        )
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "gateway.firmware_commands.confirmation_retry_interval_s must be a number"
        ) from exc
    if not math.isfinite(confirmation_retry_interval_s):
        # NaN would make every deadline comparison false and stop the worker
        # retrying while it reported itself healthy, which is the failure the
        # retry exists to prevent.
        raise ConfigValidationError(
            "gateway.firmware_commands.confirmation_retry_interval_s must be finite"
        )
    if not 1.0 <= confirmation_retry_interval_s <= DEFAULT_MAX_INTERVAL_S:
        raise ConfigValidationError(
            "gateway.firmware_commands.confirmation_retry_interval_s must be "
            f"between 1 and {DEFAULT_MAX_INTERVAL_S:.0f} seconds, the maximum "
            "the retry backoff is allowed to reach"
        )
    # firmware-commands/v2, Which `v` the runtime publishes: liveness goes at
    # v 2 alone to every device declaring the signing domains, so the switch
    # that chose v 1 or the pair is gone. Refused rather than ignored, since a
    # deployment that set it to keep v 1 would otherwise change unannounced.
    if "publish_liveness_v2" in firmware_commands:
        raise ConfigValidationError(
            "gateway.firmware_commands.publish_liveness_v2 is retired: the runtime "
            "publishes liveness at v 2 alone to every device that declares "
            "runtime_key_domains (firmware-commands/v2). Remove the key."
        )
    firmware_commands["qos"] = command_qos
    firmware_commands["publish_timeout_s"] = publish_timeout_s
    firmware_commands["confirmation_retry_interval_s"] = confirmation_retry_interval_s
    firmware_commands["runtime_command_key_env"] = runtime_command_key_env
    firmware_commands["provisioner_key_env"] = provisioner_key_env

    # Custody keys are their own section, not part of `auth`, because they are
    # a different secret for a different purpose. Folding them into `auth`
    # would invite reuse of the envelope secret, which is the confusion this
    # section exists to end.
    from ori.security.evidence.custody_keys import is_well_formed_key_id

    custody_raw = data.get("custody") or {}
    if not isinstance(custody_raw, dict):
        raise ConfigValidationError("'gateway.custody' section must be a mapping.")
    custody = dict(custody_raw)
    custody_secret_env = str(custody.get("secret_env", "") or "").strip()
    custody["secret_env"] = custody_secret_env
    previous_custody_secret_env = str(
        custody.get("previous_secret_env", "") or ""
    ).strip()
    if (
        previous_custody_secret_env
        and previous_custody_secret_env == custody_secret_env
    ):
        raise ConfigValidationError(
            "gateway.custody.previous_secret_env must differ from secret_env"
        )
    custody["previous_secret_env"] = previous_custody_secret_env

    # A retired generation is named, never re-derived: its secret was destroyed,
    # so the identifier is the only record that it existed.
    retired_raw = custody.get("retired_key_ids") or []
    if not isinstance(retired_raw, list):
        raise ConfigValidationError(
            "'gateway.custody.retired_key_ids' must be a list of key_id strings."
        )
    retired: list[str] = []
    for entry in retired_raw:
        key_id = str(entry or "").strip()
        if not is_well_formed_key_id(key_id):
            raise ConfigValidationError(
                "gateway.custody.retired_key_ids entries must look like "
                f"'hkdf-sha256:<32 lowercase hex>'; got {key_id!r}"
            )
        if key_id in retired:
            raise ConfigValidationError(
                f"gateway.custody.retired_key_ids lists {key_id} more than once"
            )
        retired.append(key_id)
    custody["retired_key_ids"] = retired
    data["custody"] = custody

    auth_raw = data.get("auth") or {}
    if not isinstance(auth_raw, dict):
        raise ConfigValidationError("'gateway.auth' section must be a mapping.")
    auth = dict(auth_raw)
    auth["enabled"] = (
        str(auth.get("enabled", "false")).strip().lower() == "true"
        or auth.get("enabled") is True
    )
    shared_secret_env = str(auth.get("shared_secret_env", "") or "").strip()
    if auth["enabled"] and not shared_secret_env:
        raise ConfigValidationError(
            "gateway.auth.shared_secret_env is required when gateway.auth.enabled is true"
        )
    auth["shared_secret_env"] = shared_secret_env
    previous_shared_secret_env = str(
        auth.get("previous_shared_secret_env", "") or ""
    ).strip()
    if (
        auth["enabled"]
        and previous_shared_secret_env
        and previous_shared_secret_env == shared_secret_env
    ):
        raise ConfigValidationError(
            "gateway.auth.previous_shared_secret_env must differ from shared_secret_env"
        )
    auth["previous_shared_secret_env"] = previous_shared_secret_env
    try:
        max_clock_skew_ms = int(auth.get("max_clock_skew_ms", 300_000))
        replay_ttl_ms = int(auth.get("replay_ttl_ms", 300_000))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConfigValidationError(
            "gateway.auth.max_clock_skew_ms and gateway.auth.replay_ttl_ms must be integers"
        ) from exc
    if max_clock_skew_ms < 1_000:
        raise ConfigValidationError("gateway.auth.max_clock_skew_ms must be >= 1000")
    if replay_ttl_ms < 1_000:
        raise ConfigValidationError("gateway.auth.replay_ttl_ms must be >= 1000")
    auth["max_clock_skew_ms"] = max_clock_skew_ms
    auth["replay_ttl_ms"] = replay_ttl_ms
    auth["persistent_replay_cache"] = is_truthy(
        auth.get("persistent_replay_cache", True)
    )

    tls_raw = data.get("tls") or {}
    if not isinstance(tls_raw, dict):
        raise ConfigValidationError("'gateway.tls' section must be a mapping.")
    tls = dict(tls_raw)
    if "insecure_skip_verify" in tls or "insecure" in tls:
        raise ConfigValidationError(
            "gateway.tls.insecure_skip_verify is not supported; configure ca_certfile for self-signed brokers"
        )
    tls["enabled"] = (
        str(tls.get("enabled", "false")).strip().lower() == "true"
        or tls.get("enabled") is True
    )
    for key in ("ca_certfile", "certfile", "keyfile", "keyfile_password_env"):
        tls[key] = str(tls.get(key, "") or "").strip()
    if tls["keyfile"] and not tls["certfile"]:
        raise ConfigValidationError(
            "gateway.tls.certfile is required when gateway.tls.keyfile is set"
        )
    if tls["keyfile_password_env"] and not tls["keyfile"]:
        raise ConfigValidationError(
            "gateway.tls.keyfile is required when gateway.tls.keyfile_password_env is set"
        )

    encryption_raw = data.get("encryption") or {}
    if not isinstance(encryption_raw, dict):
        raise ConfigValidationError("'gateway.encryption' section must be a mapping.")
    encryption = dict(encryption_raw)
    encryption["enabled"] = (
        str(encryption.get("enabled", "false")).strip().lower() == "true"
        or encryption.get("enabled") is True
    )
    if encryption["enabled"] and not auth["enabled"]:
        raise ConfigValidationError(
            "gateway.encryption.enabled requires gateway.auth.enabled"
        )

    broker_posture = _parse_gateway_broker_posture(data.get("broker_posture"))

    enabled = bool(data.get("enabled", False))
    broker_url = str(data.get("broker_url", ""))
    if enabled and "${" in broker_url:
        # `expand_env_vars` deliberately leaves `${VAR}` literal when the
        # variable is unset, and every other field carrying a secret or an
        # endpoint checks for the leftover. This one did not, so an unset
        # variable produced a URL the parser below accepts and no client can
        # reach: the only symptom was a refusal from every connection, with
        # nothing naming the cause. Report it here, where the variable can be
        # named, rather than leaving an operator to infer it from a broker log.
        unexpanded = re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", broker_url)
        detail = f": {', '.join(unexpanded)}" if unexpanded else ""
        raise ConfigValidationError(
            "gateway.broker_url contains an unexpanded environment variable"
            f"{detail}. Set it in the environment, or remove it from the URL."
        )
    if enabled:
        # An enabled gateway with an unusable endpoint is invalid configuration,
        # not a runtime availability problem. Validated with the same parser the
        # transport uses, so a config that loads is one the transport can act on;
        # whether a broker actually answers stays advisory in `ori doctor`.
        from ori.gateway.mqtt_security import parse_gateway_broker_endpoint

        try:
            parse_gateway_broker_endpoint(broker_url)
        except ValueError as exc:
            raise ConfigValidationError(str(exc)) from exc

    return GatewayConfig(
        enabled=enabled,
        broker_url=broker_url,
        reasoning=reasoning,
        node_heartbeat=node_heartbeat,
        firmware_telemetry=firmware_telemetry,
        firmware_commands=firmware_commands,
        auth=auth,
        custody=custody,
        tls=tls,
        encryption=encryption,
        broker_posture=broker_posture,
    )


def _parse_gateway_broker_posture(data: Any) -> dict[str, Any]:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigValidationError(
            "'gateway.broker_posture' section must be a mapping."
        )

    deployment_check = str(data.get("deployment_check", "warning")).strip().lower()
    if deployment_check not in {"warning", "required"}:
        raise ConfigValidationError(
            "gateway.broker_posture.deployment_check must be 'warning' or 'required'."
        )
    anonymous_access = str(data.get("anonymous_access", "unknown")).strip().lower()
    if anonymous_access not in {"unknown", "disabled"}:
        raise ConfigValidationError(
            "gateway.broker_posture.anonymous_access must be 'unknown' or 'disabled'."
        )
    acl_policy = str(data.get("acl_policy", "unknown")).strip().lower()
    if acl_policy not in {"unknown", "per_device_required"}:
        raise ConfigValidationError(
            "gateway.broker_posture.acl_policy must be 'unknown' or 'per_device_required'."
        )

    return {
        **data,
        "deployment_check": deployment_check,
        "anonymous_access": anonymous_access,
        "acl_policy": acl_policy,
        "require_credentials": is_truthy(data.get("require_credentials", False)),
    }


def warn_gateway_network_posture(gateway: GatewayConfig) -> None:
    """Warn about weak non-loopback gateway broker posture in development.

    Staging and production profiles fail closed on the same conditions in
    ``validate_production_security_posture``; development deployments get a
    single consolidated WARNING instead so LAN testing stays possible.
    """
    if not bool(gateway.enabled):
        return

    broker_url = str(gateway.broker_url or "").strip()
    if not broker_url:
        return
    parsed = urlparse(broker_url if "://" in broker_url else f"mqtt://{broker_url}")
    if parsed.hostname is None or is_loopback_host(parsed.hostname):
        return

    missing: list[str] = []
    if parsed.scheme.lower() != "mqtts" and not is_truthy(
        gateway.tls.get("enabled", False)
    ):
        missing.append("gateway TLS (mqtts:// or gateway.tls.enabled: true)")
    if not is_truthy(gateway.auth.get("enabled", False)):
        missing.append("gateway.auth.enabled: true")
    if not is_truthy(gateway.encryption.get("enabled", False)):
        missing.append("gateway.encryption.enabled: true")

    broker_posture = gateway.broker_posture
    if broker_posture.get("deployment_check") != "required":
        missing.append("gateway.broker_posture.deployment_check: required")
    if broker_posture.get("anonymous_access") != "disabled":
        missing.append("gateway.broker_posture.anonymous_access: disabled")
    if broker_posture.get("acl_policy") != "per_device_required":
        missing.append("gateway.broker_posture.acl_policy: per_device_required")
    if not is_truthy(broker_posture.get("require_credentials", False)):
        missing.append("gateway.broker_posture.require_credentials: true")
    if not (parsed.username and parsed.password):
        missing.append("MQTT username and password in gateway.broker_url")

    if missing:
        logger.warning(
            "[config] non-loopback gateway broker is missing hardening that "
            "staging/production posture requires: %s",
            "; ".join(missing),
        )
