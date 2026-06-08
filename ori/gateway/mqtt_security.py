# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Shared MQTT transport security helpers for runtime-gateway clients."""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlparse


@dataclass(frozen=True)
class GatewayBrokerConfig:
    host: str
    port: int
    username: str = ""
    password: str = ""
    scheme: str = "mqtt"
    tls_context: ssl.SSLContext | None = None


def parse_gateway_broker_url(
    broker_url: str,
    *,
    tls_config: Mapping[str, Any] | None = None,
) -> GatewayBrokerConfig:
    """Parse `gateway.broker_url` and optional TLS config."""
    raw = str(broker_url or "").strip()
    if not raw:
        raise ValueError("gateway.broker_url is required when gateway.enabled is true")
    parsed = urlparse(raw if "://" in raw else f"mqtt://{raw}")
    if parsed.scheme not in {"mqtt", "tcp", "mqtts"}:
        raise ValueError("gateway.broker_url must use mqtt://, tcp://, or mqtts://")
    if not parsed.hostname:
        raise ValueError("gateway.broker_url must include a broker host")

    tls_context = build_gateway_tls_context(parsed.scheme, tls_config)
    default_port = 8883 if parsed.scheme == "mqtts" else 1883
    return GatewayBrokerConfig(
        host=parsed.hostname,
        port=parsed.port or default_port,
        username=parsed.username or "",
        password=parsed.password or "",
        scheme=parsed.scheme,
        tls_context=tls_context,
    )


def build_gateway_tls_context(
    scheme: str,
    tls_config: Mapping[str, Any] | None = None,
) -> ssl.SSLContext | None:
    """Build an SSL context for gateway MQTT transport when configured."""
    cfg = dict(tls_config or {})
    enabled = _as_bool(cfg.get("enabled"), default=False) or scheme == "mqtts"
    ca_certfile = _text(cfg.get("ca_certfile"))
    certfile = _text(cfg.get("certfile"))
    keyfile = _text(cfg.get("keyfile"))
    keyfile_password_env = _text(cfg.get("keyfile_password_env"))
    needs_context = enabled or any(
        (ca_certfile, certfile, keyfile, keyfile_password_env)
    )
    if not needs_context:
        return None

    if keyfile and not certfile:
        raise ValueError("gateway.tls.certfile is required when keyfile is set")
    if keyfile_password_env and not keyfile:
        raise ValueError(
            "gateway.tls.keyfile is required when keyfile_password_env is set"
        )
    password = (
        os.environ.get(keyfile_password_env, "") if keyfile_password_env else None
    )
    if keyfile_password_env and not password:
        raise ValueError(
            f"gateway.tls.keyfile_password_env {keyfile_password_env!r} is empty"
        )

    try:
        context = ssl.create_default_context(cafile=ca_certfile or None)
        if certfile:
            context.load_cert_chain(
                certfile=certfile,
                keyfile=keyfile or None,
                password=password,
            )
        return context
    except Exception as exc:
        raise ValueError(f"invalid gateway MQTT TLS configuration: {exc}") from exc


def apply_tls_context(client: Any, broker: GatewayBrokerConfig) -> None:
    """Apply broker TLS context to a Paho client when present."""
    if broker.tls_context is None:
        return
    tls_set_context = getattr(client, "tls_set_context", None)
    if not callable(tls_set_context):
        raise RuntimeError("MQTT client does not support tls_set_context")
    tls_set_context(broker.tls_context)


def _as_bool(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _text(value: Any) -> str:
    return str(value or "").strip()
