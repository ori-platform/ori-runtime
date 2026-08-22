# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Producing this device's anchor registration, per `evidence-exchange/v1`.

Chain verification starts from the device's verification key. Until that key is
registered against the epoch authorising it, a receiver holding a perfectly
signed chain row has nothing to attribute it to — the evidence is well-formed
and unattributable, which is worse than absent because it looks complete.

**Control is not authorisation, and this is the distinction the artifact is
built around.** A registration is signed by the key being registered, which
proves whoever holds that key wrote it and nothing more. Anyone with a fresh
keypair can produce one claiming any actor and any reason. The right to deploy
a key comes from a separately signed commissioning authorisation, issued under
a key the evidence authority holds against a registry established out of band,
and the registration binds it by digest rather than restating its claims.

Verifying that authorisation is the authority's, not this device's, because the
authority holds the trust root the check would need.

The digest covers the **complete** authorisation including its signature.
Binding to the unsigned body would let a valid body be paired with a different
signature, which is exactly the substitution the binding exists to prevent.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from ori.security.evidence_anchor import (
    EvidenceCapabilityProfile,
    derive_anchor_epoch_id,
    derive_key_id,
)
from ori.security.evidence_canonical import canonical_json
from ori.security.evidence_device_key import EvidenceDeviceKey

REGISTRATION_VERSION = 1
REGISTRATION_DOMAIN = b"ori.evidence_anchor_registration.v1\x00"
ALGORITHM = "ed25519"

REGISTRATION_FIELDS = frozenset(
    {
        "v",
        "device_id",
        "pubkey_hex",
        "anchor_epoch_id",
        "alg",
        "posture",
        "capability_profile",
        "registered_at_ms",
        "commissioning_digest",
        "key_id",
        "signature",
    }
)

# What a commissioning authorisation must carry for this device to bind it.
#
# The runtime does not cryptographically verify the authorisation, because it
# does not hold the commissioning authority's trust root: that registry is
# established out of band and lives with the evidence authority, which is where
# authorisation verification belongs. Checking the signature here would prove
# signer authenticity if the device held an independently trusted key — it is
# not that the check is meaningless, it is that this topology deliberately does
# not give a device that key.
#
# It must still refuse to bind an authorisation that does not describe this
# registration, which is a structural check requiring no trust root at all.
COMMISSIONING_FIELDS = frozenset(
    {
        "v",
        "device_id",
        "pubkey_hex",
        "anchor_epoch_id",
        "actor",
        "reason",
        "issued_at_ms",
        "key_id",
        "signature",
    }
)


class RegistrationError(RuntimeError):
    """An anchor registration could not be produced."""


def commissioning_digest(authorisation: dict[str, Any]) -> str:
    """`sha256:` over the canonical bytes of the complete authorisation.

    Including its signature, deliberately. A digest over the unsigned body
    would let the same body travel with a different signature, so the
    registration would bind a claim rather than the signed artifact making it.
    """
    return "sha256:" + hashlib.sha256(canonical_json(authorisation)).hexdigest()


def build_anchor_registration(
    *,
    device_key: EvidenceDeviceKey,
    device_id: str,
    anchor_epoch_id: str,
    posture: str,
    key_id: str,
    registered_at_ms: int,
    authorisation: dict[str, Any],
    capability_profile: dict[str, Any],
) -> dict[str, Any]:
    """Build and sign this device's registration for one epoch.

    Idempotent by construction rather than by bookkeeping: every input is
    either fixed or supplied, so the same arguments produce the same bytes.
    `(device_id, anchor_epoch_id)` is the identity a receiver deduplicates on,
    and re-presenting an identical binding has no effect there either.
    """
    if not device_id or not anchor_epoch_id or not key_id:
        raise RegistrationError(
            "a registration must name a device, an epoch and the key it registers"
        )
    _require_authorisation_describes_this(
        authorisation,
        device_id=device_id,
        anchor_epoch_id=anchor_epoch_id,
        pubkey_hex=device_key.public_key_hex,
    )

    # The authority recomputes both key_id and anchor_epoch_id from these
    # inputs before accepting the registration, so a claim that disagrees with
    # the profile carried alongside it is refused rather than trusted. Building
    # them here from anything other than the same inputs would produce a
    # registration this device could sign and no authority would accept.
    expected_key_id = derive_key_id(
        device_id=str(device_id), pubkey_hex=device_key.public_key_hex
    )
    if str(key_id) != expected_key_id:
        raise RegistrationError(
            "key_id must be derived from the device identity and this key"
        )
    expected_epoch = derive_anchor_epoch_id(
        device_id=str(device_id),
        pubkey_hex=device_key.public_key_hex,
        posture=str(posture),
        profile=_profile_from_document(capability_profile),
    )
    if str(anchor_epoch_id) != expected_epoch:
        raise RegistrationError(
            "anchor_epoch_id must be derived from the device identity, key, "
            "posture and capability profile"
        )

    registration: dict[str, Any] = {
        "v": REGISTRATION_VERSION,
        "device_id": str(device_id),
        "pubkey_hex": device_key.public_key_hex,
        "anchor_epoch_id": str(anchor_epoch_id),
        "alg": ALGORITHM,
        "posture": str(posture),
        "capability_profile": dict(capability_profile),
        "registered_at_ms": int(registered_at_ms),
        "commissioning_digest": commissioning_digest(authorisation),
        "key_id": str(key_id),
    }
    signature = device_key.sign(REGISTRATION_DOMAIN + canonical_json(registration))
    registration["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return registration


def _require_authorisation_describes_this(
    authorisation: Any,
    *,
    device_id: str,
    anchor_epoch_id: str,
    pubkey_hex: str,
) -> None:
    """Refuse to bind an authorisation that does not cover this registration.

    Structural agreement only — the same device, key and epoch. The evidence
    authority performs the authoritative check, since it holds the
    commissioning trust root and this device does not, so this is not the
    security boundary.

    It is the difference between producing something obviously wrong and
    producing something the authority must quarantine, and a quarantine is an
    incident rather than a retry.
    """
    if not isinstance(authorisation, dict):
        raise RegistrationError("the commissioning authorisation is not an object")
    present = set(authorisation)
    if present != set(COMMISSIONING_FIELDS):
        raise RegistrationError(
            f"the commissioning authorisation carries {sorted(present - COMMISSIONING_FIELDS)} "
            f"and is missing {sorted(COMMISSIONING_FIELDS - present)}"
        )
    if authorisation.get("v") != REGISTRATION_VERSION:
        raise RegistrationError(
            f"the commissioning authorisation declares version {authorisation.get('v')!r}"
        )
    for field, expected in (
        ("device_id", device_id),
        ("anchor_epoch_id", anchor_epoch_id),
    ):
        if str(authorisation.get(field)) != str(expected):
            raise RegistrationError(
                f"the commissioning authorisation names {field} "
                f"{authorisation.get(field)!r}, not {expected!r}"
            )
    if str(authorisation.get("pubkey_hex", "")).lower() != pubkey_hex.lower():
        raise RegistrationError(
            "the commissioning authorisation authorises a different key than this "
            "device holds"
        )


def _profile_from_document(document: dict[str, Any]) -> EvidenceCapabilityProfile:
    """Read a capability profile from its wire form, refusing an unusable one."""
    try:
        return EvidenceCapabilityProfile(
            artifact_purposes=tuple(document["artifact_purposes"]),
            chain_protocol=str(document["chain_protocol"]),
            signing_alg=str(document["signing_alg"]),
            firmware_freshness_verified=bool(document["firmware_freshness_verified"]),
        )
    except (KeyError, TypeError) as exc:
        raise RegistrationError(
            "the capability profile is missing a field the epoch derives from"
        ) from exc
