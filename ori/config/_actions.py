# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``actions`` section."""

from dataclasses import dataclass, field
from typing import Any

from ori.config._fields import ConfigValidationError
from ori.utils.bool_utils import is_truthy

# BCM GPIO pins valid for relay use on Raspberry Pi 4 and CM4 (both BCM2711).
# Mirrors ori/actions/relay.py::_VALID_BCM_PINS — kept here to avoid a
# config → actions import. If the range ever changes, update both.
# If Ori is ported to a non-Broadcom SoC, replace this with a hardware-profile
# abstraction rather than removing startup pin validation.
_VALID_BCM_PINS: frozenset[int] = frozenset(range(2, 28))


@dataclass
class ActionChannelConfig:
    primary_alert_channel: str  # 'sms' | 'whatsapp'
    operator_contact: str = ""  # phone number for Tier C approvals and emergency SMS
    secondary_contact: str = ""  # escalation contact if operator doesn't respond
    approval_require_scoped_replies: bool = True
    whatsapp: dict = field(default_factory=dict)
    sms: dict = field(default_factory=dict)
    relay: dict = field(default_factory=dict)
    coap: dict = field(default_factory=dict)
    local_console: dict = field(default_factory=dict)
    offline_tokens: dict = field(default_factory=dict)
    alert_outbox: dict = field(default_factory=dict)
    setup_notifications: dict = field(default_factory=dict)


def parse_actions(data: Any) -> ActionChannelConfig:
    if not isinstance(data, dict):
        raise ConfigValidationError("'actions' section must be a mapping.")

    primary = str(data.get("primary_alert_channel", "sms"))
    if primary not in {"sms", "whatsapp"}:
        raise ConfigValidationError(
            f"actions.primary_alert_channel must be 'sms' or 'whatsapp', "
            f"got: {primary!r}"
        )

    whatsapp_raw = data.get("whatsapp") or {}
    if not isinstance(whatsapp_raw, dict):
        raise ConfigValidationError(
            "'actions.whatsapp' must be a mapping when provided."
        )
    whatsapp = dict(whatsapp_raw)

    relay_raw: dict = data.get("relay") or {}
    relay: dict = dict(relay_raw)

    # Polarity is a commissioned fact about the driver stage. It reaches the
    # actuator from the signed commissioned binding, never from this document:
    # a provisioning-signed value here would let one authority set what another
    # was required to prove (commissioned-safety-binding/v2, runtime-config/v2
    # `foreign_field`).
    if "active_high" in relay:
        raise ConfigValidationError(
            "actions.relay.active_high is not a configuration value: input "
            "polarity is a commissioned fact and is read from the signed "
            "commissioned binding beside the config, never from ori.yaml. "
            "Remove the key."
        )

    relay_enabled = (
        str(relay.get("enabled", "")).lower() == "true" or relay.get("enabled") is True
    )

    if relay_enabled and "gpio_pin" not in relay:
        raise ConfigValidationError(
            "actions.relay.enabled is true but no 'gpio_pin' is configured. "
            "A valid BCM gpio_pin must be provided to use relay actions."
        )

    if "gpio_pin" in relay:
        relay["gpio_pin"] = int(relay["gpio_pin"])
        if relay["gpio_pin"] not in _VALID_BCM_PINS:
            raise ConfigValidationError(
                f"actions.relay.gpio_pin={relay['gpio_pin']} is outside the "
                f"valid BCM range (2-27) for Raspberry Pi 4. "
                f"Misconfigured pins must be caught at startup, not during "
                f"a safety action. Check ori.yaml."
            )

    coap_raw = data.get("coap") or {}
    if not isinstance(coap_raw, dict):
        raise ConfigValidationError("'actions.coap' must be a mapping when provided.")
    coap = dict(coap_raw)
    coap.setdefault("timeout_s", 2.0)

    coap_enabled = (
        str(coap.get("enabled", "")).lower() == "true" or coap.get("enabled") is True
    )
    if coap_enabled:
        commands = coap.get("commands") or {}
        if not isinstance(commands, dict):
            raise ConfigValidationError(
                "actions.coap.commands must be a mapping when coap is enabled."
            )
        for command_name, spec in commands.items():
            if not isinstance(spec, dict):
                raise ConfigValidationError(
                    f"actions.coap.commands.{command_name} must be a mapping."
                )
            uri = str(spec.get("uri", "")).strip()
            method = str(spec.get("method", "POST")).strip().upper()
            if not uri:
                raise ConfigValidationError(
                    f"actions.coap.commands.{command_name}.uri is required."
                )
            if not uri.startswith(("coap://", "coaps://")):
                raise ConfigValidationError(
                    f"actions.coap.commands.{command_name}.uri must start with coap:// or coaps://."
                )
            if method not in {"GET", "POST", "PUT", "DELETE"}:
                raise ConfigValidationError(
                    f"actions.coap.commands.{command_name}.method must be one of GET/POST/PUT/DELETE."
                )

        allowed_hosts = coap.get("allowed_hosts") or []
        if (
            not isinstance(allowed_hosts, list)
            or len(allowed_hosts) == 0
            or not all(isinstance(host, str) and host.strip() for host in allowed_hosts)
        ):
            raise ConfigValidationError(
                "actions.coap.allowed_hosts must be a non-empty list of hostnames/IPs when coap is enabled."
            )

    local_console_raw = data.get("local_console") or {}
    if not isinstance(local_console_raw, dict):
        raise ConfigValidationError(
            "'actions.local_console' must be a mapping when provided."
        )
    local_console_enabled = bool(local_console_raw.get("enabled", False))
    local_console_poll_interval_ms = int(
        local_console_raw.get("poll_interval_ms", 1000)
    )
    local_console_approval_channel_id = str(
        local_console_raw.get("approval_channel_id", "local_console")
    )
    if local_console_poll_interval_ms < 100:
        raise ConfigValidationError(
            "actions.local_console.poll_interval_ms must be >= 100."
        )
    local_console: dict[str, Any] = {
        "enabled": local_console_enabled,
        "poll_interval_ms": local_console_poll_interval_ms,
        "approval_channel_id": local_console_approval_channel_id,
    }

    offline_tokens_raw = data.get("offline_tokens") or {}
    if not isinstance(offline_tokens_raw, dict):
        raise ConfigValidationError(
            "'actions.offline_tokens' must be a mapping when provided."
        )
    offline_tokens_enabled = bool(offline_tokens_raw.get("enabled", False))
    offline_tokens_public_key_b64 = str(offline_tokens_raw.get("public_key_b64", ""))
    offline_tokens_max_clock_skew_s = int(
        offline_tokens_raw.get("max_clock_skew_s", 300)
    )
    if offline_tokens_max_clock_skew_s < 0:
        raise ConfigValidationError(
            "actions.offline_tokens.max_clock_skew_s must be >= 0."
        )
    if offline_tokens_enabled:
        if not offline_tokens_public_key_b64 or "${" in offline_tokens_public_key_b64:
            raise ConfigValidationError(
                "actions.offline_tokens.enabled=true requires actions.offline_tokens.public_key_b64."
            )
    offline_tokens: dict[str, Any] = {
        "enabled": offline_tokens_enabled,
        "public_key_b64": offline_tokens_public_key_b64,
        "max_clock_skew_s": offline_tokens_max_clock_skew_s,
    }

    setup_notifications_raw = data.get("setup_notifications") or {}
    if not isinstance(setup_notifications_raw, dict):
        raise ConfigValidationError(
            "'actions.setup_notifications' must be a mapping when provided."
        )
    setup_channels_raw = setup_notifications_raw.get("channels", ["primary"])
    if isinstance(setup_channels_raw, str):
        setup_channels_raw = [setup_channels_raw]
    if not isinstance(setup_channels_raw, list):
        raise ConfigValidationError(
            "actions.setup_notifications.channels must be a list of sms/whatsapp/primary."
        )
    setup_channels: list[str] = []
    for raw_channel in setup_channels_raw:
        channel = str(raw_channel).strip().lower()
        if channel not in {"sms", "whatsapp", "primary"}:
            raise ConfigValidationError(
                "actions.setup_notifications.channels entries must be sms, whatsapp, or primary."
            )
        if channel not in setup_channels:
            setup_channels.append(channel)
    setup_notifications = {
        "enabled": is_truthy(setup_notifications_raw.get("enabled", False)),
        "channels": setup_channels,
    }

    alert_outbox_raw = data.get("alert_outbox") or {}
    if not isinstance(alert_outbox_raw, dict):
        raise ConfigValidationError(
            "'actions.alert_outbox' must be a mapping when provided."
        )
    try:
        retry_interval_minutes = float(
            alert_outbox_raw.get("retry_interval_minutes", 0.5)
        )
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "actions.alert_outbox.retry_interval_minutes must be a number."
        ) from exc
    try:
        max_non_tier_d_attempts = int(
            alert_outbox_raw.get("max_non_tier_d_attempts", 10)
        )
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "actions.alert_outbox.max_non_tier_d_attempts must be an integer."
        ) from exc
    try:
        tier_d_critical_warning_threshold = int(
            alert_outbox_raw.get("tier_d_critical_warning_threshold", 3)
        )
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "actions.alert_outbox.tier_d_critical_warning_threshold must be an integer."
        ) from exc
    try:
        batch_size = int(alert_outbox_raw.get("batch_size", 50))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "actions.alert_outbox.batch_size must be an integer."
        ) from exc

    alert_outbox = {
        "retry_interval_minutes": retry_interval_minutes,
        "max_non_tier_d_attempts": max_non_tier_d_attempts,
        "tier_d_critical_warning_threshold": tier_d_critical_warning_threshold,
        "batch_size": batch_size,
    }
    if alert_outbox["retry_interval_minutes"] <= 0:
        raise ConfigValidationError(
            "actions.alert_outbox.retry_interval_minutes must be > 0."
        )
    if alert_outbox["max_non_tier_d_attempts"] < 1:
        raise ConfigValidationError(
            "actions.alert_outbox.max_non_tier_d_attempts must be >= 1."
        )
    if alert_outbox["tier_d_critical_warning_threshold"] < 1:
        raise ConfigValidationError(
            "actions.alert_outbox.tier_d_critical_warning_threshold must be >= 1."
        )
    if not 1 <= alert_outbox["batch_size"] <= 1000:
        raise ConfigValidationError(
            "actions.alert_outbox.batch_size must be between 1 and 1000."
        )

    approval_require_scoped_replies = is_truthy(
        data.get("approval_require_scoped_replies", True)
    )

    return ActionChannelConfig(
        primary_alert_channel=primary,
        operator_contact=str(data.get("operator_contact") or ""),
        secondary_contact=str(data.get("secondary_contact") or ""),
        approval_require_scoped_replies=approval_require_scoped_replies,
        whatsapp=whatsapp,
        sms=data.get("sms") or {},
        relay=relay,
        coap=coap,
        local_console=local_console,
        offline_tokens=offline_tokens,
        alert_outbox=alert_outbox,
        setup_notifications=setup_notifications,
    )
