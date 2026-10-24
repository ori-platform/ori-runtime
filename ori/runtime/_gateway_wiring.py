# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Builders for the runtime-gateway MQTT services, and gateway posture warnings."""

import logging
import os
import stat
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlparse

from ori.config import Config
from ori.gateway.envelope_auth import (
    build_gateway_message_auth as _build_gateway_message_auth,
)
from ori.gateway.heartbeat import MqttGatewayHeartbeatSubscriber
from ori.gateway.node_heartbeat import MqttRuntimeNodeHeartbeatPublisher
from ori.gateway.reasoning import MqttGatewayReasoner
from ori.reasoning.capability_posture import CapabilityPostureTracker
from ori.reasoning.context_enricher import ContextEnricher, ContextEnricherConfig
from ori.security.gateway_messages import (
    GatewayEnvelopeState,
    GatewayMessageEncryptionConfig,
    GatewayMessageEncryptor,
)
from ori.utils.net_utils import is_loopback_host

logger = logging.getLogger("ori.runtime")


def build_gateway_reasoner(
    config: Config, envelope_state: GatewayEnvelopeState | None = None
) -> MqttGatewayReasoner | None:
    """Instantiate the MQTT Tier 3 gateway reasoner when configured."""
    if not bool(config.gateway.enabled):
        return None
    reasoning_cfg = (
        config.gateway.reasoning if isinstance(config.gateway.reasoning, dict) else {}
    )
    if not bool(reasoning_cfg.get("enabled", True)):
        return None
    try:
        reasoner = MqttGatewayReasoner(
            broker_url=config.gateway.broker_url,
            device_id=config.device.id,
            timeout_ms=int(reasoning_cfg.get("timeout_ms", 10_000)),
            tls_config=getattr(config.gateway, "tls", {}),
            message_auth=_build_gateway_message_auth(config, envelope_state),
        )
    except Exception:
        logger.exception("[runtime] invalid gateway reasoning configuration")
        return None
    logger.info(
        "[runtime] MQTT gateway reasoning enabled on ori/%s/reasoning/request",
        config.device.id,
    )
    return reasoner


def build_gateway_message_encryptor(config: Config) -> GatewayMessageEncryptor | None:
    """Build optional AES-GCM encryption for sensitive export payloads."""
    raw_encryption = getattr(config.gateway, "encryption", {})
    encryption_cfg = raw_encryption if isinstance(raw_encryption, dict) else {}
    if not bool(encryption_cfg.get("enabled", False)):
        return None
    raw_auth = getattr(config.gateway, "auth", {})
    auth_cfg = raw_auth if isinstance(raw_auth, dict) else {}
    if not bool(auth_cfg.get("enabled", False)):
        raise ValueError("gateway encryption requires gateway auth")
    env_name = str(auth_cfg.get("shared_secret_env", "") or "").strip()
    secret = os.environ.get(env_name, "") if env_name else ""
    if not secret:
        raise ValueError(
            "gateway encryption is enabled but configured shared-secret "
            "environment variable is empty"
        )
    return GatewayMessageEncryptor(GatewayMessageEncryptionConfig(shared_secret=secret))


def build_gateway_heartbeat_subscriber(
    config: Config,
    posture_tracker: CapabilityPostureTracker,
    envelope_state: GatewayEnvelopeState | None = None,
) -> MqttGatewayHeartbeatSubscriber | None:
    """Instantiate the MQTT gateway heartbeat subscriber when configured."""
    if not bool(config.gateway.enabled):
        return None
    auth_cfg = getattr(config.gateway, "auth", {}) or {}
    auth_enabled = bool(auth_cfg.get("enabled", False))
    if not auth_enabled:
        logger.warning(
            "[gateway-heartbeat] gateway.auth.enabled is false — heartbeat "
            "payloads are accepted without HMAC verification. A spoofed "
            "heartbeat can corrupt gateway liveness state and cause the "
            "elevator to burn escalation timeout budget on a non-existent "
            "gateway. Enable gateway.auth for all production deployments."
        )
    try:
        subscriber = MqttGatewayHeartbeatSubscriber(
            broker_url=config.gateway.broker_url,
            posture_tracker=posture_tracker,
            device_id=config.device.id,
            tls_config=getattr(config.gateway, "tls", {}),
            authenticator=_build_gateway_message_auth(config, envelope_state),
        )
    except Exception:
        logger.exception("[runtime] invalid gateway heartbeat configuration")
        return None
    logger.info(
        "[runtime] MQTT gateway heartbeat subscriber enabled on %s (auth=%s)",
        "ori/gateway/health",
        "enabled" if auth_enabled else "disabled",
    )
    return subscriber


def read_private_key_file(path: str) -> bytes:
    """Read one root/runtime-owned private-key file without following symlinks."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("secure private-key file opening is unsupported")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("cannot open firmware MQTT client CA private key") from exc
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise RuntimeError(
                "firmware MQTT client CA private key must be a regular file"
            )
        if file_stat.st_uid not in {0, os.geteuid()}:
            raise RuntimeError(
                "firmware MQTT client CA private key has an invalid owner"
            )
        if file_stat.st_mode & 0o077:
            raise RuntimeError(
                "firmware MQTT client CA private key must have mode 0o600 or stricter"
            )
        with os.fdopen(fd, "rb", closefd=False) as handle:
            value = handle.read(64 * 1024 + 1)
    finally:
        os.close(fd)
    if not value or len(value) > 64 * 1024:
        raise RuntimeError("firmware MQTT client CA private key size is invalid")
    return value


def read_public_pem_file(path: str) -> bytes:
    """Read bounded public PEM material without accepting a private key."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("secure certificate file opening is unsupported")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("cannot open firmware MQTT public certificate file") from exc
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise RuntimeError(
                "firmware MQTT public certificate must be a regular file"
            )
        with os.fdopen(fd, "rb", closefd=False) as handle:
            value = handle.read(64 * 1024 + 1)
    finally:
        os.close(fd)
    if not value or len(value) > 64 * 1024 or b"PRIVATE KEY" in value.upper():
        raise RuntimeError("firmware MQTT public certificate material is invalid")
    return value


def build_runtime_node_heartbeat_publisher(
    config: Config,
    health_snapshot_provider: Callable[[], dict[str, Any] | Awaitable[dict[str, Any]]],
    envelope_state: GatewayEnvelopeState | None = None,
) -> MqttRuntimeNodeHeartbeatPublisher | None:
    """Instantiate the runtime-to-gateway node heartbeat publisher when configured."""
    if not bool(config.gateway.enabled):
        return None
    heartbeat_cfg = (
        config.gateway.node_heartbeat
        if isinstance(getattr(config.gateway, "node_heartbeat", {}), dict)
        else {}
    )
    if not bool(heartbeat_cfg.get("enabled", True)):
        return None
    auth_cfg = getattr(config.gateway, "auth", {}) or {}
    auth_enabled = bool(auth_cfg.get("enabled", False))
    if not auth_enabled:
        logger.warning(
            "[runtime-heartbeat] gateway.auth.enabled is false — node heartbeat "
            "payloads are published without HMAC. Enable gateway.auth for "
            "production deployments."
        )
    try:
        publisher = MqttRuntimeNodeHeartbeatPublisher(
            broker_url=config.gateway.broker_url,
            device_id=config.device.id,
            health_snapshot_provider=health_snapshot_provider,
            interval_seconds=float(heartbeat_cfg.get("interval_seconds", 30)),
            tls_config=getattr(config.gateway, "tls", {}),
            authenticator=_build_gateway_message_auth(config, envelope_state),
        )
    except Exception:
        logger.exception("[runtime] invalid runtime node heartbeat configuration")
        return None
    logger.info(
        "[runtime] MQTT runtime node heartbeat publisher enabled on ori/%s/runtime/heartbeat (auth=%s)",
        config.device.id,
        "enabled" if auth_enabled else "disabled",
    )
    return publisher


def build_context_enricher(config: Config) -> ContextEnricher | None:
    """Build ContextEnricher from reasoning.context_enricher config block."""
    enricher_raw = getattr(config.reasoning, "context_enricher", {}) or {}
    if not bool(enricher_raw.get("enabled", False)):
        return None
    try:
        cfg = ContextEnricherConfig(
            enabled=True,
            staleness_window_ms=int(enricher_raw.get("staleness_window_ms", 60_000)),
            max_entries=int(enricher_raw.get("max_entries", 5)),
            include_sources=list(enricher_raw.get("include_sources") or []),
        )
        return ContextEnricher(cfg)
    except Exception:
        logger.exception(
            "[runtime] failed to construct ContextEnricher — enrichment disabled"
        )
        return None


def warn_gateway_security_posture(config: Config) -> None:
    """Emit startup warnings for gateway security posture gaps.

    Called once during runtime startup after all gateway components are built.
    Does not raise — posture issues are warnings, not startup failures, because
    loopback-only sites are intentionally configured without TLS or auth.
    """
    if not bool(config.gateway.enabled):
        return

    auth_cfg = getattr(config.gateway, "auth", {}) or {}
    tls_cfg = getattr(config.gateway, "tls", {}) or {}
    broker_url = str(getattr(config.gateway, "broker_url", "") or "")

    auth_enabled = bool(auth_cfg.get("enabled", False))
    tls_enabled = bool(tls_cfg.get("enabled", False))
    # Parse the host out rather than prefix-matching the URL. Production
    # posture requires broker credentials, so the very configuration this
    # runtime asks for — `mqtt://user:pass@127.0.0.1:1883` — carries userinfo
    # ahead of the host and matches no prefix. Classifying that as a public
    # broker made the runtime log, at ERROR, that traffic was unauthenticated
    # while it was in fact authenticated. A security channel that cries wolf
    # is worse than a silent one: the operator either acts on a false alarm or
    # learns to ignore it.
    parsed = urlparse(broker_url if "://" in broker_url else f"mqtt://{broker_url}")
    is_loopback = is_loopback_host(parsed.hostname)

    if not auth_enabled:
        if not is_loopback:
            logger.error(
                "[runtime-security] GATEWAY: gateway.auth.enabled is false and broker "
                "is not loopback — MQTT traffic is unauthenticated. "
                "Set gateway.auth.enabled: true and provide GATEWAY_SHARED_SECRET."
            )
        else:
            logger.warning(
                "[runtime-security] gateway.auth.enabled is false — HMAC envelope "
                "authentication disabled. Acceptable for loopback-only deployments only."
            )

    if not tls_enabled and not is_loopback:
        logger.warning(
            "[runtime-security] GATEWAY: gateway.tls.enabled is false and broker is "
            "not loopback — MQTT payloads are unencrypted on the network. "
            "Enable TLS for any non-loopback gateway deployment."
        )

    if auth_enabled and not tls_enabled and not is_loopback:
        logger.warning(
            "[runtime-security] GATEWAY: HMAC auth is enabled but TLS is not. "
            "Payloads are authenticated but visible in transit on the LAN. "
            "Enable gateway.tls for defense-in-depth."
        )
