# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Ed25519 verification for generated Ori runtime configs.

The config file is the runtime's authority boundary: it decides which sensors
exist, which skills run, what the device policy endpoint is, and whether relay
paths are enabled. A generated config must therefore be verified by the runtime
before the parsed YAML is trusted.
"""

import base64
import json
import os
import re
from dataclasses import dataclass
from typing import Any

from ori.utils.bool_utils import is_truthy

CONFIG_SIGNATURE_SCHEMA = "ori.config_signature.v1"
CONFIG_SIGNATURE_SECTION = "config_signature"
DEFAULT_CONFIG_TRUST_ANCHOR_ENV = "ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64"
CONFIG_TRUST_ANCHOR_ENV_OVERRIDE = "ORI_CONFIG_TRUST_ANCHOR_ENV"
CONFIG_REQUIRE_SIGNED_ENV = "ORI_CONFIG_REQUIRE_SIGNED"
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ConfigSignatureError(Exception):
    """Raised when an Ori runtime config signature cannot be trusted."""


@dataclass(frozen=True)
class ConfigSignaturePolicy:
    require_signed: bool = False
    trust_anchor_env: str = DEFAULT_CONFIG_TRUST_ANCHOR_ENV


@dataclass(frozen=True)
class ConfigSignatureVerification:
    verified: bool
    required: bool
    trust_anchor_env: str
    signer_id: str = ""
    signed_at_ms: int | None = None
    schema: str = CONFIG_SIGNATURE_SCHEMA


def config_signature_policy_from_raw_config(
    raw_config: dict[str, Any],
) -> ConfigSignaturePolicy:
    """Extract signature policy from raw, unexpanded YAML data.

    The env-level requirement is intentionally evaluated outside the YAML file.
    APK/production launchers can set ``ORI_CONFIG_REQUIRE_SIGNED=true`` so a
    tampered config cannot opt out by changing ``deployment_profile`` or
    ``security.config_signature.require_signed`` to development values.
    """
    security = raw_config.get("security") or {}
    if security and not isinstance(security, dict):
        raise ConfigSignatureError("security must be a mapping")
    signature_cfg = security.get("config_signature") or {}
    if signature_cfg and not isinstance(signature_cfg, dict):
        raise ConfigSignatureError("security.config_signature must be a mapping")

    require_signed = is_truthy(signature_cfg.get("require_signed", False)) or is_truthy(
        os.environ.get(CONFIG_REQUIRE_SIGNED_ENV, "")
    )

    trust_anchor_env = str(
        os.environ.get(CONFIG_TRUST_ANCHOR_ENV_OVERRIDE)
        or signature_cfg.get("trust_anchor_env")
        or DEFAULT_CONFIG_TRUST_ANCHOR_ENV
    ).strip()
    if not trust_anchor_env or not _ENV_NAME_RE.fullmatch(trust_anchor_env):
        raise ConfigSignatureError(
            "security.config_signature.trust_anchor_env must be a valid "
            "environment variable name"
        )

    return ConfigSignaturePolicy(
        require_signed=bool(require_signed),
        trust_anchor_env=trust_anchor_env,
    )


def verify_config_signature_if_needed(
    raw_config: dict[str, Any],
    policy: ConfigSignaturePolicy,
) -> ConfigSignatureVerification:
    """Verify a generated runtime config when required or when signed.

    Development configs may remain unsigned. If a ``config_signature`` block is
    present, it is always verified so a broken signature cannot be ignored.
    """
    signature_block = raw_config.get(CONFIG_SIGNATURE_SECTION)
    has_signature_block = signature_block is not None
    required = bool(policy.require_signed)

    if not required and not has_signature_block:
        return ConfigSignatureVerification(
            verified=False,
            required=False,
            trust_anchor_env=policy.trust_anchor_env,
        )

    if not isinstance(signature_block, dict):
        raise ConfigSignatureError(
            "missing config_signature block"
            if required
            else "config_signature must be a mapping"
        )

    schema = str(signature_block.get("schema") or "").strip()
    if schema != CONFIG_SIGNATURE_SCHEMA:
        raise ConfigSignatureError(
            f"config_signature.schema must be {CONFIG_SIGNATURE_SCHEMA!r}"
        )

    signer_id = str(signature_block.get("signer_id") or "").strip()
    if not signer_id:
        raise ConfigSignatureError("config_signature.signer_id is required")

    signed_at_ms = _int_field(signature_block.get("signed_at_ms"), "signed_at_ms")
    if signed_at_ms <= 0:
        raise ConfigSignatureError("config_signature.signed_at_ms must be > 0")

    signature = str(signature_block.get("signature") or "").strip()
    if not signature.startswith("ed25519:"):
        raise ConfigSignatureError(
            "config_signature.signature must use ed25519:<base64>"
        )

    trust_anchor = str(os.environ.get(policy.trust_anchor_env, "")).strip()
    if not trust_anchor:
        raise ConfigSignatureError(
            f"config signature trust anchor env {policy.trust_anchor_env!r} is not set"
        )

    _verify_ed25519_signature(
        signature=signature,
        public_key_b64=trust_anchor,
        payload=canonical_config_signature_payload(raw_config),
    )
    return ConfigSignatureVerification(
        verified=True,
        required=required,
        trust_anchor_env=policy.trust_anchor_env,
        signer_id=signer_id,
        signed_at_ms=signed_at_ms,
        schema=schema,
    )


def canonical_config_signature_payload(raw_config: dict[str, Any]) -> bytes:
    """Return canonical bytes signed by product provisioning.

    The top-level ``config_signature`` section is an envelope. The signature
    covers the runtime config body plus stable envelope metadata, excluding only
    the signature value itself.
    """
    signature_block = raw_config.get(CONFIG_SIGNATURE_SECTION)
    if not isinstance(signature_block, dict):
        raise ConfigSignatureError("config_signature must be a mapping")

    unsigned_config = {
        key: value
        for key, value in raw_config.items()
        if key != CONFIG_SIGNATURE_SECTION
    }
    envelope = {
        "config": unsigned_config,
        "schema": str(signature_block.get("schema") or "").strip(),
        "signed_at_ms": _int_field(signature_block.get("signed_at_ms"), "signed_at_ms"),
        "signer_id": str(signature_block.get("signer_id") or "").strip(),
    }
    return json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _verify_ed25519_signature(
    *,
    signature: str,
    public_key_b64: str,
    payload: bytes,
) -> None:
    _, signature_b64 = signature.split(":", 1)
    try:
        signature_bytes = base64.b64decode(
            signature_b64.encode("ascii"),
            validate=True,
        )
    except Exception as exc:
        raise ConfigSignatureError(
            "config_signature.signature is not valid base64"
        ) from exc

    try:
        public_key_bytes = base64.b64decode(
            str(public_key_b64).encode("ascii"),
            validate=True,
        )
    except Exception as exc:
        raise ConfigSignatureError(
            "config signature trust anchor is not base64"
        ) from exc

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as exc:
        raise ConfigSignatureError(
            "cryptography Ed25519 support is unavailable on this runtime"
        ) from exc

    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature_bytes,
            payload,
        )
    except Exception as exc:
        raise ConfigSignatureError("config signature verification failed") from exc


def _int_field(value: Any, field_name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigSignatureError(
            f"config_signature.{field_name} must be an integer"
        ) from exc
