# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Secure remote DevicePolicy fetch and verification helpers."""

import asyncio
import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from ori.policy.device_policy import DevicePolicy
from ori.skills.sandbox import SkillSecurityError
from ori.skills.signing import verify_signed_payload


class RemotePolicyFetchError(Exception):
    """Policy fetch/verification failure with machine-readable reason code."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        policy_version: int | None = None,
        payload_timestamp: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.policy_version = policy_version
        self.payload_timestamp = payload_timestamp


@dataclass(frozen=True)
class RemotePolicyFetchConfig:
    url: str
    auth_token: str
    public_key_b64: str
    request_timeout_ms: int = 3000
    max_clock_skew_s: int = 300


@dataclass(frozen=True)
class FetchedRemotePolicy:
    policy: DevicePolicy
    raw_payload: str
    payload: dict[str, Any]


def _parse_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


def _to_int(value: Any, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise RemotePolicyFetchError(
            "invalid_payload",
            f"policy field '{field}' must be an integer",
        ) from exc


def device_policy_from_payload(
    payload: dict[str, Any],
    *,
    context_label: str = "policy payload",
) -> DevicePolicy:
    required = (
        "tier",
        "relay_b_enabled",
        "relay_c_enabled",
        "cloud_llm_enabled",
        "valid_until",
        "policy_version",
        "issued_at",
        "signature",
    )
    missing = [k for k in required if k not in payload]
    if missing:
        raise RemotePolicyFetchError(
            "invalid_payload",
            f"{context_label} missing required fields: {', '.join(missing)}",
        )

    return DevicePolicy(
        tier=str(payload.get("tier", "")),
        relay_b_enabled=_parse_bool(payload.get("relay_b_enabled")),
        relay_c_enabled=_parse_bool(payload.get("relay_c_enabled")),
        cloud_llm_enabled=_parse_bool(payload.get("cloud_llm_enabled")),
        valid_until=_to_int(payload.get("valid_until"), "valid_until"),
        policy_version=_to_int(payload.get("policy_version"), "policy_version"),
        issued_at=_to_int(payload.get("issued_at"), "issued_at"),
        signature=str(payload.get("signature", "")),
    )


def _build_config(raw: dict[str, Any]) -> RemotePolicyFetchConfig:
    url = str(raw.get("url", "") or "").strip()
    auth_token = str(raw.get("auth_token", "") or "").strip()
    public_key_b64 = str(raw.get("public_key_b64", "") or "").strip()
    request_timeout_ms = _to_int(
        raw.get("request_timeout_ms", 3000), "request_timeout_ms"
    )
    max_clock_skew_s = _to_int(raw.get("max_clock_skew_s", 300), "max_clock_skew_s")
    return RemotePolicyFetchConfig(
        url=url,
        auth_token=auth_token,
        public_key_b64=public_key_b64,
        request_timeout_ms=request_timeout_ms,
        max_clock_skew_s=max_clock_skew_s,
    )


def _http_get_json(cfg: RemotePolicyFetchConfig) -> tuple[str, dict[str, Any]]:
    body = _http_get_json_bytes(cfg)
    return _decode_json_body(body)


def _http_get_json_bytes(cfg: RemotePolicyFetchConfig) -> bytes:
    req = urllib.request.Request(
        cfg.url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {cfg.auth_token}",
        },
        method="GET",
    )
    timeout_s = max(0.1, cfg.request_timeout_ms / 1000.0)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            body = resp.read()
            status = int(getattr(resp, "status", 200))
    except urllib.error.HTTPError as exc:
        raise RemotePolicyFetchError(
            "auth_or_http_error",
            f"policy endpoint returned HTTP {exc.code}",
        ) from exc
    except urllib.error.URLError as exc:
        raise RemotePolicyFetchError(
            "network_error",
            f"policy endpoint network error: {exc.reason}",
        ) from exc
    except TimeoutError as exc:
        raise RemotePolicyFetchError(
            "network_timeout", "policy endpoint timed out"
        ) from exc

    if status != 200:
        raise RemotePolicyFetchError(
            "auth_or_http_error",
            f"policy endpoint returned HTTP {status}",
        )
    return body


def _decode_json_body(body: bytes) -> tuple[str, dict[str, Any]]:
    try:
        raw_payload = body.decode("utf-8")
    except Exception as exc:
        raise RemotePolicyFetchError(
            "invalid_payload",
            "policy endpoint returned non-UTF8 payload",
        ) from exc

    try:
        payload = json.loads(raw_payload)
    except Exception as exc:
        raise RemotePolicyFetchError(
            "invalid_payload",
            "policy endpoint returned non-JSON payload",
        ) from exc

    if not isinstance(payload, dict):
        raise RemotePolicyFetchError(
            "invalid_payload",
            "policy payload must be a JSON object",
        )
    return raw_payload, payload


def _verify_payload(
    payload: dict[str, Any],
    cfg: RemotePolicyFetchConfig,
    *,
    current_policy_version: int | None,
) -> DevicePolicy:
    required = ("timestamp",)
    missing = [k for k in required if k not in payload]
    if missing:
        raise RemotePolicyFetchError(
            "invalid_payload",
            f"policy payload missing required fields: {', '.join(missing)}",
        )

    payload_ts = _to_int(payload.get("timestamp"), "timestamp")
    now_s = int(time.time())
    if abs(now_s - payload_ts) > int(cfg.max_clock_skew_s):
        raise RemotePolicyFetchError(
            "stale_timestamp",
            "policy payload timestamp is outside allowed skew window",
            policy_version=_to_int(payload.get("policy_version"), "policy_version"),
            payload_timestamp=payload_ts,
        )

    policy_version = _to_int(payload.get("policy_version"), "policy_version")
    if current_policy_version is not None and policy_version < current_policy_version:
        raise RemotePolicyFetchError(
            "version_downgrade",
            "policy_version is lower than current in-memory version",
            policy_version=policy_version,
            payload_timestamp=payload_ts,
        )

    try:
        verify_signed_payload(
            payload,
            cfg.public_key_b64,
            context_label="device policy payload",
        )
    except SkillSecurityError as exc:
        raise RemotePolicyFetchError(
            "invalid_signature",
            str(exc),
            policy_version=policy_version,
            payload_timestamp=payload_ts,
        ) from exc

    parsed = device_policy_from_payload(payload, context_label="policy payload")
    if parsed.policy_version != policy_version:
        raise RemotePolicyFetchError(
            "invalid_payload",
            "policy_version value changed during payload parsing",
        )
    return parsed


def _validate_fetch_config(cfg: RemotePolicyFetchConfig) -> None:
    if not cfg.url.startswith("https://"):
        raise RemotePolicyFetchError(
            "invalid_config",
            "device_policy.url must start with https://",
        )
    if not cfg.auth_token:
        raise RemotePolicyFetchError(
            "invalid_config", "device_policy.auth_token is empty"
        )
    if not cfg.public_key_b64:
        raise RemotePolicyFetchError(
            "invalid_config",
            "device_policy.public_key_b64 is empty",
        )
    if cfg.request_timeout_ms < 100:
        raise RemotePolicyFetchError(
            "invalid_config",
            "device_policy.request_timeout_ms must be >= 100",
        )
    if cfg.max_clock_skew_s < 1:
        raise RemotePolicyFetchError(
            "invalid_config",
            "device_policy.max_clock_skew_s must be >= 1",
        )


async def fetch_remote_device_policy_bundle(
    raw_config: dict[str, Any],
    *,
    current_policy_version: int | None = None,
) -> FetchedRemotePolicy:
    """Fetch + verify and return both parsed policy and exact raw payload JSON."""
    cfg = _build_config(raw_config)
    _validate_fetch_config(cfg)

    raw_payload, payload = await asyncio.to_thread(_http_get_json, cfg)
    verified = _verify_payload(
        payload,
        cfg,
        current_policy_version=current_policy_version,
    )
    return FetchedRemotePolicy(
        policy=verified,
        raw_payload=raw_payload,
        payload=payload,
    )


async def fetch_remote_device_policy_bundle_by_reference(
    raw_config: dict[str, Any],
    *,
    url: str,
    expected_sha256: str,
    current_policy_version: int | None = None,
) -> FetchedRemotePolicy:
    """Fetch a referenced signed DevicePolicy bundle after content-hash check."""
    ref_url = str(url or "").strip()
    digest = str(expected_sha256 or "").strip().lower()
    if not ref_url:
        raise RemotePolicyFetchError("invalid_config", "policy reference URL is empty")
    if not ref_url.startswith("https://"):
        raise RemotePolicyFetchError(
            "invalid_config",
            "policy reference URL must start with https://",
        )
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise RemotePolicyFetchError(
            "invalid_config",
            "policy reference sha256 must be a 64-character hex digest",
        )

    cfg = _build_config({**raw_config, "url": ref_url})
    _validate_fetch_config(cfg)

    body = await asyncio.to_thread(_http_get_json_bytes, cfg)
    actual_digest = hashlib.sha256(body).hexdigest()
    if actual_digest != digest:
        raise RemotePolicyFetchError(
            "hash_mismatch",
            "policy reference content hash does not match expected sha256",
        )

    raw_payload, payload = _decode_json_body(body)
    verified = _verify_payload(
        payload,
        cfg,
        current_policy_version=current_policy_version,
    )
    return FetchedRemotePolicy(
        policy=verified,
        raw_payload=raw_payload,
        payload=payload,
    )
