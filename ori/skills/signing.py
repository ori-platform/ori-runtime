# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Ed25519 signature helpers for community skill verification."""

import base64
import json
from typing import Any

from ori.skills.sandbox import SkillSecurityError


def canonical_skill_payload(raw_skill: dict[str, Any]) -> bytes:
    """Build canonical bytes for signature verification.

    The signature field itself is excluded from the signed payload.
    """
    canonical_obj = {k: v for k, v in raw_skill.items() if k != "signature"}
    canonical_json = json.dumps(
        canonical_obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return canonical_json.encode("utf-8")


def verify_community_skill_signature(
    raw_skill: dict[str, Any],
    trust_anchor_public_key_b64: str,
) -> None:
    """Verify a community skill signature against the configured trust anchor.

    Raises:
        SkillSecurityError: If signature/trust anchor is missing, malformed,
            or verification fails.
    """
    signature_field = str(raw_skill.get("signature") or "").strip()
    if not signature_field:
        raise SkillSecurityError("missing required 'signature' field")

    if ":" not in signature_field:
        raise SkillSecurityError(
            "invalid signature format. Expected 'ed25519:<base64_signature>'"
        )
    scheme, signature_b64 = signature_field.split(":", 1)
    if scheme.lower() != "ed25519":
        raise SkillSecurityError(
            "unsupported signature scheme. Expected 'ed25519:<base64_signature>'"
        )
    if not signature_b64.strip():
        raise SkillSecurityError("signature payload is empty")

    trust_anchor_public_key_b64 = str(trust_anchor_public_key_b64 or "").strip()
    if not trust_anchor_public_key_b64:
        raise SkillSecurityError("community skill verification trust anchor is empty")

    try:
        signature_bytes = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except Exception as exc:
        raise SkillSecurityError("invalid base64 signature payload") from exc

    try:
        public_key_bytes = base64.b64decode(
            trust_anchor_public_key_b64.encode("ascii"),
            validate=True,
        )
    except Exception as exc:
        raise SkillSecurityError("invalid trust anchor public key encoding") from exc

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as exc:
        raise SkillSecurityError(
            "cryptography Ed25519 support is unavailable on this runtime"
        ) from exc

    payload_bytes = canonical_skill_payload(raw_skill)
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        key.verify(signature_bytes, payload_bytes)
    except Exception as exc:
        raise SkillSecurityError(
            "community skill signature verification failed"
        ) from exc
