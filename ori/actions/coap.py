# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""CoAP action executor for constrained-device actuation commands."""

from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

try:
    import aiocoap as _aiocoap  # type: ignore[import-untyped]

    _AIOCOAP_AVAILABLE = True
except ImportError:
    _aiocoap = None
    _AIOCOAP_AVAILABLE = False

_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "DELETE"})


def _as_bool(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    token = str(value).strip().lower()
    if token in {"1", "true", "yes", "on"}:
        return True
    if token in {"0", "false", "no", "off"}:
        return False
    return default


class CoAPAction:
    """Dispatch command payloads to CoAP endpoints with strict allowlisting."""

    def __init__(self, config: dict | None = None) -> None:
        cfg = config if isinstance(config, dict) else {}
        self._enabled = _as_bool(cfg.get("enabled", False))
        self._timeout_s = max(0.2, float(cfg.get("timeout_s", 2.0)))
        self._retries = max(0, int(cfg.get("retries", 1)))
        self._commands = cfg.get("commands", {}) or {}

        allowed_hosts = cfg.get("allowed_hosts", []) or []
        self._allowed_hosts = {
            str(host).strip().lower() for host in allowed_hosts if str(host).strip()
        }

        if self._enabled and not _AIOCOAP_AVAILABLE:
            logger.warning(
                "CoAPAction: aiocoap is not installed — CoAP command delivery disabled."
            )

    async def execute_command(
        self,
        command_name: str,
        payload_override: str | None = None,
    ) -> bool:
        """Execute a named command from ``actions.coap.commands``."""
        if not self._enabled:
            logger.debug("CoAPAction: disabled, skipping command=%r", command_name)
            return False

        if not _AIOCOAP_AVAILABLE or _aiocoap is None:
            logger.warning(
                "CoAPAction: aiocoap missing — cannot execute command=%r",
                command_name,
            )
            return False

        if not isinstance(self._commands, dict):
            logger.error("CoAPAction: actions.coap.commands must be a mapping")
            return False

        spec = self._commands.get(command_name)
        if not isinstance(spec, dict):
            logger.error(
                "CoAPAction: unknown command=%r. Define it under actions.coap.commands.",
                command_name,
            )
            return False

        uri = str(spec.get("uri", "")).strip()
        method = str(spec.get("method", "POST")).strip().upper()
        payload = (
            payload_override
            if payload_override is not None
            else spec.get("payload", "")
        )
        payload_bytes = self._encode_payload(payload)

        if not self._validate_target(uri=uri, method=method):
            return False

        for attempt in range(self._retries + 1):
            ok = await self._send_once(uri=uri, method=method, payload=payload_bytes)
            if ok:
                return True
            if attempt < self._retries:
                await asyncio.sleep(min(1.0, 0.2 * (2**attempt)))

        return False

    def _validate_target(self, *, uri: str, method: str) -> bool:
        if method not in _ALLOWED_METHODS:
            logger.error(
                "CoAPAction: invalid method=%r (allowed=%s)",
                method,
                sorted(_ALLOWED_METHODS),
            )
            return False

        parsed = urlparse(uri)
        if parsed.scheme not in {"coap", "coaps"}:
            logger.error("CoAPAction: uri must use coap/coaps scheme, got %r", uri)
            return False
        host = (parsed.hostname or "").strip().lower()
        if not host:
            logger.error("CoAPAction: uri host is required")
            return False

        # SSRF/actuation-boundary hardening: explicit host allowlist is required.
        if not self._allowed_hosts:
            logger.error(
                "CoAPAction: actions.coap.allowed_hosts is empty while CoAP is enabled"
            )
            return False
        if host not in self._allowed_hosts:
            logger.error(
                "CoAPAction: host %r is not in actions.coap.allowed_hosts",
                host,
            )
            return False

        return True

    async def _send_once(self, *, uri: str, method: str, payload: bytes) -> bool:
        assert _aiocoap is not None
        context = None
        try:
            context = await _aiocoap.Context.create_client_context()
            code = getattr(_aiocoap, method, None)
            if code is None:
                logger.error("CoAPAction: method constant missing for %r", method)
                return False

            request = _aiocoap.Message(code=code, uri=uri, payload=payload)
            response = await asyncio.wait_for(
                context.request(request).response,
                timeout=self._timeout_s,
            )
            response_code = str(response.code)
            if response_code.startswith("2."):
                return True
            logger.warning(
                "CoAPAction: non-success response for uri=%s code=%s",
                uri,
                response_code,
            )
            return False
        except asyncio.TimeoutError:
            logger.warning("CoAPAction: timeout sending CoAP command to %s", uri)
            return False
        except Exception:
            logger.exception("CoAPAction: failed sending CoAP command to %s", uri)
            return False
        finally:
            if context is not None:
                try:
                    await context.shutdown()
                except Exception:
                    logger.debug("CoAPAction: context shutdown failed", exc_info=True)

    @staticmethod
    def _encode_payload(payload: object) -> bytes:
        if payload is None:
            return b""
        if isinstance(payload, (bytes, bytearray)):
            return bytes(payload)
        if isinstance(payload, (dict, list)):
            return json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )
        return str(payload).encode("utf-8")
