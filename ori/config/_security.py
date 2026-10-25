# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``security`` section."""

import logging
import os
from ipaddress import ip_network
from typing import Any

from ori.config._env import ENV_NAME_RE
from ori.config._fields import ConfigValidationError
from ori.security.config_signatures import (
    CONFIG_REQUIRE_SIGNED_ENV,
    DEFAULT_CONFIG_TRUST_ANCHOR_ENV,
)
from ori.security.remote_commands.commands import (
    configured_sender_is_ascii,
    normalize_configured_sender,
)
from ori.security.remote_commands.lockout import normalize_remote_command_lockout_config
from ori.utils.bool_utils import is_truthy

logger = logging.getLogger("ori.config")


def parse_security(data: Any) -> dict:
    """Parse security controls that are not tied to one action channel."""
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigValidationError("'security' must be a mapping.")

    out = dict(data)
    remote = out.get("remote_commands") or {}
    if not isinstance(remote, dict):
        raise ConfigValidationError("security.remote_commands must be a mapping.")

    try:
        max_skew_seconds = int(remote.get("max_skew_seconds", 300))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "security.remote_commands.max_skew_seconds must be an integer."
        ) from exc
    if max_skew_seconds < 0:
        raise ConfigValidationError(
            "security.remote_commands.max_skew_seconds must be >= 0."
        )

    enabled = (
        str(remote.get("enabled", "")).strip().lower() == "true"
        or remote.get("enabled") is True
    )
    hmac_secret_env = str(
        remote.get("hmac_secret_env", "ORI_REMOTE_COMMAND_HMAC_SECRET")
    ).strip()
    if enabled and not hmac_secret_env:
        raise ConfigValidationError(
            "security.remote_commands.hmac_secret_env is required when enabled."
        )
    previous_hmac_secret_env = str(
        remote.get("previous_hmac_secret_env", "") or ""
    ).strip()
    if (
        enabled
        and previous_hmac_secret_env
        and previous_hmac_secret_env == hmac_secret_env
    ):
        raise ConfigValidationError(
            "security.remote_commands.previous_hmac_secret_env must differ from hmac_secret_env."
        )

    allowed_senders = _parse_remote_command_allowed_senders(
        remote.get("allowed_senders")
    )
    allow_unlisted_senders = (
        str(remote.get("allow_unlisted_senders", "")).strip().lower() == "true"
        or remote.get("allow_unlisted_senders") is True
    )
    if enabled and not allow_unlisted_senders and not any(allowed_senders.values()):
        logger.warning(
            "[config] remote commands are enabled without allowed_senders; "
            "all remote command senders will be rejected."
        )

    try:
        lockout = normalize_remote_command_lockout_config(remote.get("lockout"))
    except ValueError as exc:
        raise ConfigValidationError(str(exc)) from exc

    out["remote_commands"] = {
        **remote,
        "enabled": enabled,
        "hmac_secret_env": hmac_secret_env,
        "previous_hmac_secret_env": previous_hmac_secret_env,
        "max_skew_seconds": max_skew_seconds,
        "allowed_senders": allowed_senders,
        "allow_unlisted_senders": allow_unlisted_senders,
        "lockout": lockout,
    }

    skills_security = out.get("skills") or {}
    if not isinstance(skills_security, dict):
        raise ConfigValidationError("security.skills must be a mapping.")
    out["skills"] = {
        **skills_security,
        "require_signed": is_truthy(skills_security.get("require_signed", False)),
    }
    config_signature = out.get("config_signature") or {}
    if not isinstance(config_signature, dict):
        raise ConfigValidationError("security.config_signature must be a mapping.")
    trust_anchor_env = str(
        os.environ.get("ORI_CONFIG_TRUST_ANCHOR_ENV")
        or config_signature.get("trust_anchor_env")
        or DEFAULT_CONFIG_TRUST_ANCHOR_ENV
    ).strip()
    if not trust_anchor_env or not ENV_NAME_RE.fullmatch(trust_anchor_env):
        raise ConfigValidationError(
            "security.config_signature.trust_anchor_env must be a valid "
            "environment variable name."
        )
    out["config_signature"] = {
        **config_signature,
        "require_signed": is_truthy(config_signature.get("require_signed", False))
        or is_truthy(os.environ.get(CONFIG_REQUIRE_SIGNED_ENV, "")),
        "trust_anchor_env": trust_anchor_env,
        "verified": False,
        "required": False,
        "signer_id": "",
        "signed_at_ms": None,
    }
    out["enforce_production_posture"] = is_truthy(
        out.get("enforce_production_posture", False)
    )
    return out


def validate_sms_webhook_source_cidrs(data: Any) -> None:
    """Validate optional SMS webhook source CIDR allowlist."""
    if data is None:
        return
    if not isinstance(data, list):
        raise ConfigValidationError(
            "actions.sms.incoming_webhook.allowed_source_cidrs must be a list."
        )
    for index, item in enumerate(data):
        cidr = str(item).strip()
        if not cidr:
            raise ConfigValidationError(
                "actions.sms.incoming_webhook.allowed_source_cidrs entries "
                "must not be empty."
            )
        try:
            network = ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ConfigValidationError(
                "actions.sms.incoming_webhook.allowed_source_cidrs "
                f"entry {index} is not a valid IP/CIDR: {cidr!r}"
            ) from exc
        if network.prefixlen == 0:
            raise ConfigValidationError(
                "actions.sms.incoming_webhook.allowed_source_cidrs must not "
                "contain a catch-all network."
            )


def sms_webhook_source_cidrs_present(data: Any) -> bool:
    if not isinstance(data, list):
        return False
    return any(str(item).strip() for item in data)


def _parse_remote_command_allowed_senders(data: Any) -> dict[str, list[str]]:
    """Parse remote command sender allowlist by ingress channel."""
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigValidationError(
            "security.remote_commands.allowed_senders must be a mapping."
        )
    result: dict[str, list[str]] = {"sms": [], "whatsapp": []}
    for channel, raw_senders in data.items():
        normalized_channel = str(channel or "").strip().lower()
        if not normalized_channel:
            continue
        if not isinstance(raw_senders, list):
            raise ConfigValidationError(
                f"security.remote_commands.allowed_senders.{normalized_channel} must be a list."
            )
        seen: set[str] = set()
        normalized: list[str] = []
        for sender in raw_senders:
            if not configured_sender_is_ascii(sender):
                raise ConfigValidationError(
                    f"security.remote_commands.allowed_senders.{normalized_channel} "
                    "holds a sender with non-ASCII characters; write its digits in "
                    "ASCII."
                )
            value = normalize_configured_sender(normalized_channel, sender)
            if value and value not in seen:
                seen.add(value)
                normalized.append(value)
        result[normalized_channel] = normalized
    return result
