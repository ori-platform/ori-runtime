# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Production posture: when it applies, and what it requires of a parsed configuration."""

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ori.config._actions import ActionChannelConfig
from ori.config._database import _IN_MEMORY_STORE
from ori.config._device import DeviceConfig
from ori.config._document import _load_config_document, _read_config_text
from ori.config._fields import ConfigValidationError
from ori.config._gateway import GatewayConfig
from ori.config._security import sms_webhook_source_cidrs_present
from ori.config._state import StateConfig
from ori.security.config_signatures import CONFIG_REQUIRE_SIGNED_ENV
from ori.utils.bool_utils import is_truthy
from ori.utils.net_utils import is_loopback_host
from ori.utils.path_utils import path_is_relative_to


def hardened_posture_declared(config_path: str) -> bool:
    """Whether a document asks for hardened posture, read before it is expanded.

    Anything that must decide before `Config.load` cannot ask the loaded
    configuration what posture it is in, because the values that expansion
    depends on are supplied by exactly the decisions being made. The document
    is admitted through the same reader the loader uses and read for the two
    fields that settle it. A document that cannot be read is treated as
    hardened: the caller is choosing whether to widen its own trust, and an
    unreadable answer is not a reason to widen it.
    """
    try:
        raw = _load_config_document(_read_config_text(config_path), config_path)
    except Exception:
        return True
    if not isinstance(raw, dict):
        return True
    device = raw.get("device")
    security = raw.get("security")
    profile = ""
    if isinstance(device, dict):
        profile = str(device.get("deployment_profile", "") or "").strip().lower()
    enforce_raw = ""
    enforce = False
    if isinstance(security, dict):
        enforce = security.get("enforce_production_posture") is True
        enforce_raw = str(security.get("enforce_production_posture", "") or "")
    # A field that is itself expanded says nothing yet about the posture, and
    # what it expands to is exactly what the caller is deciding whether to
    # supply. Read unexpanded, `${ORI_POSTURE}` is neither staging nor
    # production, so it would answer no to the question it decides.
    if "${" in profile or "${" in enforce_raw:
        return True
    return profile in {"staging", "production"} or enforce


def requires_production_posture(
    *, device: DeviceConfig, security: dict[str, Any]
) -> bool:
    """Return whether runtime startup must enforce hardened host capabilities.

    Staging and production profiles cannot opt out. Development deployments may
    deliberately opt in so operators can exercise the same fail-closed posture
    before promotion.
    """
    return bool(
        device.deployment_profile in {"staging", "production"}
        or security.get("enforce_production_posture") is True
    )


def validate_production_security_posture(
    *,
    device: DeviceConfig,
    gateway: GatewayConfig,
    actions: ActionChannelConfig,
    security: dict[str, Any],
    state: StateConfig,
    database_path: str,
    config_signature_verified: bool,
) -> None:
    """Fail closed on unsafe production posture.

    Development and loopback deployments may intentionally use weaker local
    settings. Production posture is opt-in by ``security`` or implied by
    ``device.deployment_profile: staging|production``. An explicit false
    ``security.enforce_production_posture`` does not override those profiles.
    """
    enforce = requires_production_posture(device=device, security=security)
    if not enforce:
        return

    skills_security = security.get("skills") or {}
    if not isinstance(skills_security, dict) or not is_truthy(
        skills_security.get("require_signed", False)
    ):
        raise ConfigValidationError(
            "production posture requires security.skills.require_signed: true"
        )

    # A Tier C proposal goes to operator_contact over SMS or WhatsApp. Without
    # one, every proposal falls to its safe default with no operator ever
    # asked, which a hardened deployment must not do quietly.
    approval_channels = [
        name
        for name in ("sms", "whatsapp")
        if isinstance(getattr(actions, name, None), dict)
        and is_truthy(getattr(actions, name).get("enabled", False))
    ]
    contact = str(actions.operator_contact or "")
    # Normalised as the approval allowlist normalises it: a placeholder or
    # any value with no number in it admits nobody.
    dialable = "".join(ch for ch in contact if ch.isdigit() or ch == "+")
    if approval_channels and (
        "${" in contact or not any(ch.isdigit() for ch in dialable)
    ):
        raise ConfigValidationError(
            "production posture requires actions.operator_contact, a phone "
            f"number, when {' or '.join(approval_channels)} is enabled: without "
            "it no Tier C proposal reaches an operator and no Tier D failure "
            "is reported to one"
        )

    remote = security.get("remote_commands") or {}
    if isinstance(remote, dict) and is_truthy(remote.get("enabled", False)):
        if is_truthy(remote.get("allow_unlisted_senders", False)):
            raise ConfigValidationError(
                "production posture forbids "
                "security.remote_commands.allow_unlisted_senders: true"
            )
        allowed_senders = remote.get("allowed_senders")
        if not isinstance(allowed_senders, dict) or not any(
            bool(v) for v in allowed_senders.values()
        ):
            raise ConfigValidationError(
                "production posture requires "
                "security.remote_commands.allowed_senders when remote commands are enabled"
            )
        lockout_raw = remote.get("lockout")
        lockout: dict[str, Any] = lockout_raw if isinstance(lockout_raw, dict) else {}
        if not is_truthy(lockout.get("enforcement_enabled", False)):
            raise ConfigValidationError(
                "production posture requires "
                "security.remote_commands.lockout.enforcement_enabled: true "
                "when remote commands are enabled"
            )

    if gateway.enabled:
        broker_url = str(gateway.broker_url or "").strip()
        if not broker_url:
            raise ConfigValidationError(
                "production posture requires gateway.broker_url when gateway is enabled"
            )
        parsed = urlparse(broker_url if "://" in broker_url else f"mqtt://{broker_url}")
        scheme = parsed.scheme.lower()
        if parsed.hostname is None:
            raise ConfigValidationError(
                "production posture requires gateway.broker_url to include a hostname"
            )
        # Payload-level protections do not depend on network position: a
        # loopback broker is still reachable by other local processes, so
        # HMAC auth and export encryption are required for every broker.
        if not is_truthy(gateway.auth.get("enabled", False)):
            raise ConfigValidationError(
                "production posture requires gateway.auth.enabled: true "
                "when gateway is enabled"
            )
        if database_path == _IN_MEMORY_STORE:
            # gateway-api/v2 Senders: signing times never repeat across a
            # restart, which an in-memory store cannot keep.
            raise ConfigValidationError(
                "production posture requires database.path to name a file when "
                "gateway.auth is enabled: the gateway signing clock must be durable"
            )
        if not is_truthy(gateway.encryption.get("enabled", False)):
            raise ConfigValidationError(
                "production posture requires gateway.encryption.enabled: true "
                "when gateway is enabled"
            )
        non_loopback = not is_loopback_host(parsed.hostname)
        if non_loopback:
            if scheme != "mqtts" and not is_truthy(gateway.tls.get("enabled", False)):
                raise ConfigValidationError(
                    "production posture requires gateway TLS for non-loopback brokers "
                    "(use mqtts:// or gateway.tls.enabled: true)"
                )
            broker_posture = gateway.broker_posture
            if broker_posture.get("deployment_check") != "required":
                raise ConfigValidationError(
                    "production posture requires "
                    "gateway.broker_posture.deployment_check: required "
                    "for non-loopback brokers"
                )
            if broker_posture.get("anonymous_access") != "disabled":
                raise ConfigValidationError(
                    "production posture requires "
                    "gateway.broker_posture.anonymous_access: disabled "
                    "for non-loopback brokers"
                )
            if broker_posture.get("acl_policy") != "per_device_required":
                raise ConfigValidationError(
                    "production posture requires "
                    "gateway.broker_posture.acl_policy: per_device_required "
                    "for non-loopback brokers"
                )
            if not is_truthy(broker_posture.get("require_credentials", False)):
                raise ConfigValidationError(
                    "production posture requires "
                    "gateway.broker_posture.require_credentials: true "
                    "for non-loopback brokers"
                )
            if not parsed.username or not parsed.password:
                raise ConfigValidationError(
                    "production posture requires gateway.broker_url to include "
                    "MQTT username and password for non-loopback brokers"
                )

    sms_cfg = actions.sms if isinstance(actions.sms, dict) else {}
    incoming = sms_cfg.get("incoming_webhook") or {}
    if isinstance(incoming, dict) and is_truthy(incoming.get("enabled", False)):
        host = str(incoming.get("host", "127.0.0.1") or "").strip()
        if not is_loopback_host(host):
            allowed_source_cidrs = incoming.get("allowed_source_cidrs")
            if not sms_webhook_source_cidrs_present(allowed_source_cidrs):
                raise ConfigValidationError(
                    "production posture requires "
                    "actions.sms.incoming_webhook.allowed_source_cidrs for public "
                    "SMS webhook ingress"
                )
            signature = incoming.get("signature") or {}
            mode = (
                str(signature.get("mode", "token_only")).strip().lower()
                if isinstance(signature, dict)
                else "token_only"
            )
            if mode == "token_only":
                raise ConfigValidationError(
                    "production posture forbids public SMS webhook token_only mode; "
                    "use token_and_hmac or hmac_required"
                )

    _validate_state_store_encryption_posture(
        state=state,
        database_path=database_path,
    )

    config_signature = security.get("config_signature") or {}
    if not isinstance(config_signature, dict) or not is_truthy(
        config_signature.get("require_signed", False)
    ):
        raise ConfigValidationError(
            "production posture requires security.config_signature.require_signed: "
            f"true or {CONFIG_REQUIRE_SIGNED_ENV}=true"
        )
    if not config_signature_verified:
        raise ConfigValidationError(
            "production posture requires a verified config_signature block"
        )


def _validate_state_store_encryption_posture(
    *,
    state: StateConfig,
    database_path: str,
) -> None:
    encryption = state.encryption
    if encryption.mode != "filesystem_required":
        raise ConfigValidationError(
            "production posture requires state.encryption.mode: filesystem_required"
        )

    marker_ok = False
    if encryption.marker_file:
        marker_path = Path(encryption.marker_file).expanduser()
        if not marker_path.is_file():
            raise ConfigValidationError(
                "state.encryption.marker_file must point to an existing file "
                "when configured."
            )
        marker_ok = True

    db_path = Path(database_path).expanduser().resolve(strict=False)
    prefix_ok = any(
        path_is_relative_to(
            db_path,
            Path(prefix).expanduser().resolve(strict=False),
        )
        for prefix in encryption.encrypted_path_prefixes
    )
    if not (marker_ok or prefix_ok):
        raise ConfigValidationError(
            "production posture requires database.path to live under one of "
            "state.encryption.encrypted_path_prefixes or a valid "
            "state.encryption.marker_file."
        )
