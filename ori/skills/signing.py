# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Ed25519 signature helpers for signed payload verification."""

import base64
import json
import math
from typing import Any

from ori.skills.sandbox import SkillSecurityError


def _decode_canonical_base64(value: str, *, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise SkillSecurityError(f"invalid base64 {label}") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise SkillSecurityError(f"non-canonical base64 {label}")
    return decoded


def _validate_canonical_json_value(
    value: Any,
    *,
    path: str = "$",
    active_containers: set[int] | None = None,
) -> None:
    """Reject values that cannot be represented deterministically as JSON."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SkillSecurityError(
                f"signed payload contains non-finite number at {path}"
            )
        return

    if active_containers is None:
        active_containers = set()

    if isinstance(value, (list, dict)):
        identity = id(value)
        if identity in active_containers:
            raise SkillSecurityError(f"signed payload contains a cycle at {path}")
        active_containers.add(identity)
        try:
            if isinstance(value, list):
                for index, item in enumerate(value):
                    _validate_canonical_json_value(
                        item,
                        path=f"{path}[{index}]",
                        active_containers=active_containers,
                    )
                return

            for key, item in value.items():
                if not isinstance(key, str):
                    raise SkillSecurityError(
                        f"signed payload contains non-string object key at {path}"
                    )
                _validate_canonical_json_value(
                    item,
                    path=f"{path}.{key}",
                    active_containers=active_containers,
                )
            return
        finally:
            active_containers.remove(identity)

    raise SkillSecurityError(
        f"signed payload contains non-JSON value at {path}: {type(value).__name__}"
    )


def canonical_signed_payload(raw_payload: dict[str, Any]) -> bytes:
    """Build canonical bytes for signature verification.

    The signature field itself is excluded from the signed payload.
    """
    canonical_obj = {k: v for k, v in raw_payload.items() if k != "signature"}
    _validate_canonical_json_value(canonical_obj)
    canonical_json = json.dumps(
        canonical_obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return canonical_json.encode("utf-8")


def canonical_skill_payload(raw_skill: dict[str, Any]) -> bytes:
    """Backward-compatible alias for community skill payload canonicalization."""
    return canonical_signed_payload(raw_skill)


def verify_signed_payload(
    raw_payload: dict[str, Any],
    trust_anchor_public_key_b64: str,
    *,
    context_label: str = "payload",
) -> None:
    """Verify an Ed25519 signature against the configured trust anchor.

    Raises:
        SkillSecurityError: If signature/trust anchor is missing, malformed,
            or verification fails.
    """
    signature_field = str(raw_payload.get("signature") or "").strip()
    if not signature_field:
        raise SkillSecurityError("missing required 'signature' field")

    if ":" not in signature_field:
        raise SkillSecurityError(
            "invalid signature format. Expected 'ed25519:<base64_signature>'"
        )
    scheme, signature_b64 = signature_field.split(":", 1)
    if scheme != "ed25519":
        raise SkillSecurityError(
            "unsupported signature scheme. Expected 'ed25519:<base64_signature>'"
        )
    if not signature_b64.strip():
        raise SkillSecurityError("signature payload is empty")

    trust_anchor_public_key_b64 = str(trust_anchor_public_key_b64 or "").strip()
    if not trust_anchor_public_key_b64:
        raise SkillSecurityError(f"{context_label} verification trust anchor is empty")

    signature_bytes = _decode_canonical_base64(
        signature_b64,
        label="signature payload",
    )
    if len(signature_bytes) != 64:
        raise SkillSecurityError("signature payload must decode to exactly 64 bytes")
    public_key_bytes = _decode_canonical_base64(
        trust_anchor_public_key_b64,
        label="trust anchor public key",
    )
    if len(public_key_bytes) != 32:
        raise SkillSecurityError(
            "trust anchor public key must decode to exactly 32 bytes"
        )

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as exc:
        raise SkillSecurityError(
            "cryptography Ed25519 support is unavailable on this runtime"
        ) from exc

    payload_bytes = canonical_signed_payload(raw_payload)
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        key.verify(signature_bytes, payload_bytes)
    except Exception as exc:
        raise SkillSecurityError(
            f"{context_label} signature verification failed"
        ) from exc


def verify_community_skill_signature(
    raw_skill: dict[str, Any],
    trust_anchor_public_key_b64: str,
) -> None:
    """Verify a community skill signature against the configured trust anchor."""
    verify_signed_payload(
        raw_skill,
        trust_anchor_public_key_b64,
        context_label="community skill",
    )
