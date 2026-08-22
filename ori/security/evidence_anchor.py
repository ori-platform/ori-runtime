# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Derive the identifiers this runtime seals evidence under.

Implements `ori-specs/runtime-evidence-anchor/v1.md`. Both identifiers are
derived and never configured: they name the key that signs immutable evidence,
so a value an operator can set is a value that will eventually be set wrongly on
some device, permanently. A sealed envelope cannot be rewritten, and the
mismatch would surface only when the authority refused a batch.

The evidence authority recomputes both before accepting a registration. That is
what makes the epoch a check rather than a declaration -- a device that merely
asserted its epoch, with the inputs withheld, would be naming the trust
proposition it wished to be judged under.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from ori.security.evidence_canonical import canonical_json

#: Key custody posture for a key held as an encrypted file on a general-purpose
#: operating system. Not `sealed_flash` and not `hardware_key`: the private key
#: is exportable by a party holding the installation secret with host access,
#: and claiming otherwise would overclaim non-exportability inside an artifact a
#: third party may rely on. Filesystem encryption strengthens the deployment
#: posture without changing this answer, so it must not promote the value.
POSTURE_SOFTWARE_WRAPPED = "software_wrapped"

#: The closed purpose vocabulary from evidence-exchange/v1.
KEY_PURPOSES = frozenset(
    {
        "evidence_device",
        "commissioning_authority",
        "evidence_authority_receipt",
        "evidence_authority_epoch",
        "gateway_custody",
    }
)

CHAIN_PROTOCOL = "ori.evidence.v2"
SIGNING_ALG = "ed25519"
PROFILE_VERSION = 1


class AnchorDerivationError(ValueError):
    """An input cannot be derived from, and must be refused rather than fixed."""


def public_key_b64(pubkey_hex: str) -> str:
    """Convert a registration's ``pubkey_hex`` to the derivation's encoding.

    The bridge is normative because a verifier that guesses it computes
    different bytes and refuses a conforming registration. Malformed input is
    refused rather than normalised: normalising would let two distinct wire
    forms derive the same identifiers, so a device could present its key in a
    spelling the authority never recorded.
    """
    if len(pubkey_hex) != 64:
        raise AnchorDerivationError(
            f"pubkey_hex must be 64 characters, got {len(pubkey_hex)}"
        )
    if pubkey_hex != pubkey_hex.lower():
        raise AnchorDerivationError("pubkey_hex must be lowercase")
    try:
        raw = bytes.fromhex(pubkey_hex)
    except ValueError as exc:
        raise AnchorDerivationError("pubkey_hex is not hexadecimal") from exc
    if len(raw) != 32:
        raise AnchorDerivationError("pubkey_hex must decode to exactly 32 bytes")
    return base64.b64encode(raw).decode("ascii")


@dataclass(frozen=True)
class EvidenceCapabilityProfile:
    """The trust-relevant properties an epoch is derived from.

    Deliberately not a hash of runtime configuration or skills. Those change for
    reasons unrelated to trust, and folding them in would mint a new epoch --
    invalidating cross-store agreement -- every time an operator edited
    something with no bearing on whether the evidence can be believed.
    """

    artifact_purposes: tuple[str, ...]
    chain_protocol: str = CHAIN_PROTOCOL
    signing_alg: str = SIGNING_ALG
    #: Whether Layer 1 freshness is atomically *verified*, not merely signed. A
    #: runtime that records supplied coordinates without validating them against
    #: confirmed registration and epoch state reports False.
    firmware_freshness_verified: bool = False

    def as_document(self) -> dict[str, Any]:
        purposes = list(self.artifact_purposes)
        if sorted(purposes) != purposes:
            raise AnchorDerivationError("artifact_purposes must be sorted")
        if len(set(purposes)) != len(purposes):
            raise AnchorDerivationError("artifact_purposes must not repeat a purpose")
        unknown = [p for p in purposes if p not in KEY_PURPOSES]
        if unknown:
            raise AnchorDerivationError(
                f"artifact_purposes contains unknown purposes: {unknown}"
            )
        return {
            "artifact_purposes": purposes,
            "chain_protocol": self.chain_protocol,
            "firmware_freshness_verified": bool(self.firmware_freshness_verified),
            "signing_alg": self.signing_alg,
            "v": PROFILE_VERSION,
        }


def _digest(document: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest()


def capability_hash(profile: EvidenceCapabilityProfile) -> str:
    """Digest of the evidence capability profile."""
    return _digest(profile.as_document())


def derive_key_id(*, device_id: str, pubkey_hex: str) -> str:
    """The ``(evidence_device, key_id)`` selector for this device key.

    For a fixed device identity it changes only when the key changes. `device_id`
    is also an input, so two devices never share a selector.
    """
    if not device_id:
        raise AnchorDerivationError("a key_id must name a device")
    return _digest(
        {
            "device_id": device_id,
            "public_key_b64": public_key_b64(pubkey_hex),
            "v": PROFILE_VERSION,
        }
    )


def derive_anchor_epoch_id(
    *,
    device_id: str,
    pubkey_hex: str,
    posture: str,
    profile: EvidenceCapabilityProfile,
) -> str:
    """The epoch naming this whole trust proposition.

    Changes when the key, the posture, or the evidence capabilities change.
    """
    if not device_id:
        raise AnchorDerivationError("an epoch must name a device")
    if not posture:
        raise AnchorDerivationError("an epoch must name a custody posture")
    return _digest(
        {
            "capability_hash": capability_hash(profile),
            "device_id": device_id,
            "posture": posture,
            "public_key_b64": public_key_b64(pubkey_hex),
            "v": PROFILE_VERSION,
        }
    )


@dataclass(frozen=True)
class RuntimeAnchor:
    """This runtime's derived evidence identity."""

    device_id: str
    pubkey_hex: str
    posture: str
    profile: EvidenceCapabilityProfile
    key_id: str
    anchor_epoch_id: str


def derive_runtime_anchor(
    *,
    device_id: str,
    pubkey_hex: str,
    posture: str = POSTURE_SOFTWARE_WRAPPED,
    profile: EvidenceCapabilityProfile | None = None,
) -> RuntimeAnchor:
    """Derive both identifiers together, so they cannot disagree."""
    resolved = profile or EvidenceCapabilityProfile(
        artifact_purposes=(
            "evidence_authority_epoch",
            "evidence_authority_receipt",
            "gateway_custody",
        )
    )
    return RuntimeAnchor(
        device_id=device_id,
        pubkey_hex=pubkey_hex,
        posture=posture,
        profile=resolved,
        key_id=derive_key_id(device_id=device_id, pubkey_hex=pubkey_hex),
        anchor_epoch_id=derive_anchor_epoch_id(
            device_id=device_id,
            pubkey_hex=pubkey_hex,
            posture=posture,
            profile=resolved,
        ),
    )
