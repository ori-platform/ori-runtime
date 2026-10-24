# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Remote-command verification, lockout configuration and SMS ingress posture."""

import logging
import os
from typing import Any

from ori.config import Config
from ori.security.offline_tokens import OfflineTierCTokenVerifier
from ori.security.remote_commands.commands import RemoteCommandVerifier
from ori.security.remote_commands.lockout import default_remote_command_lockout_config
from ori.utils.bool_utils import is_truthy
from ori.utils.net_utils import is_loopback_host

logger = logging.getLogger("ori.runtime")


def validate_remote_policy_reference_args(
    reference_url: str,
    expected_sha256: str,
) -> str | None:
    """Return a precondition error for invalid APPLY_POLICY reference args."""
    if not str(reference_url or "").strip().startswith("https://"):
        return "policy reference URL must start with https://"
    digest = str(expected_sha256 or "").strip().lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        return "policy reference sha256 must be a 64-character hex digest"
    return None


def build_offline_token_verifier(actions_cfg: Any) -> OfflineTierCTokenVerifier | None:
    offline_cfg = {}
    if actions_cfg is not None and hasattr(actions_cfg, "offline_tokens"):
        candidate = getattr(actions_cfg, "offline_tokens", {}) or {}
        if isinstance(candidate, dict):
            offline_cfg = candidate
    if not is_truthy(offline_cfg.get("enabled", False)):
        return None
    return OfflineTierCTokenVerifier(
        public_key_b64=str(offline_cfg.get("public_key_b64", "")),
        max_clock_skew_s=int(offline_cfg.get("max_clock_skew_s", 300)),
    )


def build_remote_command_verifier(config: Config) -> RemoteCommandVerifier | None:
    security_cfg = config.security if isinstance(config.security, dict) else {}
    remote_cfg = security_cfg.get("remote_commands") or {}
    if not isinstance(remote_cfg, dict):
        return None
    if not is_truthy(remote_cfg.get("enabled", False)):
        return None

    secret_env = str(
        remote_cfg.get("hmac_secret_env", "ORI_REMOTE_COMMAND_HMAC_SECRET")
    ).strip()
    shared_secret = os.environ.get(secret_env, "")
    if not shared_secret:
        logger.warning(
            "[runtime] remote commands enabled but configured HMAC secret "
            "environment variable is not set; commands will fail closed."
        )
    previous_secret_env = str(remote_cfg.get("previous_hmac_secret_env", "") or "")
    previous_shared_secret = (
        os.environ.get(previous_secret_env, "") if previous_secret_env else ""
    )
    if previous_secret_env and not previous_shared_secret:
        logger.warning(
            "[runtime] remote command previous HMAC secret environment variable "
            "is configured but empty; previous-secret verification disabled."
        )
    max_skew_ms = int(remote_cfg.get("max_skew_seconds", 300)) * 1000
    return RemoteCommandVerifier(
        device_id=str(config.device.id),
        shared_secret=shared_secret,
        previous_shared_secret=previous_shared_secret,
        max_skew_ms=max_skew_ms,
        allowed_senders=remote_cfg.get("allowed_senders"),
        allow_unlisted_senders=is_truthy(
            remote_cfg.get("allow_unlisted_senders", False)
        ),
    )


def remote_command_lockout_config(config: Config | None) -> dict[str, Any]:
    if config is None or not isinstance(config.security, dict):
        return default_remote_command_lockout_config()
    remote_cfg = config.security.get("remote_commands") or {}
    if not isinstance(remote_cfg, dict):
        return default_remote_command_lockout_config()
    lockout_cfg = remote_cfg.get("lockout")
    if not isinstance(lockout_cfg, dict):
        return default_remote_command_lockout_config()
    return {**default_remote_command_lockout_config(), **lockout_cfg}


def build_sms_allowed_senders(config: Config) -> set[str]:
    """Return the normalized set of phone numbers permitted to send inbound SMS.

    Built from ``actions.operator_contact`` and ``actions.secondary_contact``.
    An empty set admits no approval reply from anyone.
    """
    senders: set[str] = set()
    for raw in (config.actions.operator_contact, config.actions.secondary_contact):
        normalized = "".join(ch for ch in str(raw or "") if ch.isdigit() or ch == "+")
        if normalized:
            senders.add(normalized)
    return senders


def warn_sms_webhook_security_posture(config: Config) -> None:
    """Emit startup warnings for public SMS webhook ingress gaps.

    Production/staging posture fails config load for these conditions. This
    warning path exists for development configs that bind the webhook on a
    non-loopback interface before production posture is enabled.
    """
    sms_cfg = config.actions.sms if isinstance(config.actions.sms, dict) else {}
    webhook_cfg = sms_cfg.get("incoming_webhook") or {}
    if not isinstance(webhook_cfg, dict):
        return
    if not is_truthy(webhook_cfg.get("enabled", False)):
        return

    host = str(webhook_cfg.get("host", "127.0.0.1") or "").strip()
    if is_loopback_host(host):
        return

    signature_cfg = webhook_cfg.get("signature") or {}
    signature_mode = (
        str(signature_cfg.get("mode", "token_only") or "token_only").strip().lower()
        if isinstance(signature_cfg, dict)
        else "token_only"
    )
    if signature_mode == "token_only":
        logger.error(
            "[runtime-security] SMS_WEBHOOK: incoming_webhook.host=%r is not "
            "loopback and signature.mode=token_only. Public SMS webhook ingress "
            "must be fronted by a signing bridge or configured with "
            "signature.mode=token_and_hmac/hmac_required.",
            host,
        )

    source_cidrs = webhook_cfg.get("allowed_source_cidrs") or []
    if not source_cidrs:
        logger.warning(
            "[runtime-security] SMS_WEBHOOK: incoming_webhook.host=%r is not "
            "loopback and allowed_source_cidrs is empty. Restrict ingress to "
            "Africa's Talking provider IP ranges or a trusted reverse proxy.",
            host,
        )
