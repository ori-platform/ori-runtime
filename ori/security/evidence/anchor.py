# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Derive the identifiers this runtime seals evidence under.

Implements `ori-specs/runtime-evidence-anchor/v2.md`. Both identifiers are
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

from ori.security.evidence.canonical import canonical_json

#: Key custody posture for a key held as an encrypted file on a general-purpose
#: operating system. Not `sealed_flash` and not `hardware_key`: the private key
#: is exportable by a party holding the installation secret with host access,
#: and claiming otherwise would overclaim non-exportability inside an artifact a
#: third party may rely on. Filesystem encryption strengthens the deployment
#: posture without changing this answer, so it must not promote the value.
POSTURE_SOFTWARE_WRAPPED = "software_wrapped"

#: The closed purpose vocabulary from evidence-exchange/v2.
KEY_PURPOSES = frozenset(
    {
        "evidence_device",
        "commissioning_authority",
        "evidence_authority_receipt",
        "evidence_authority_epoch",
        "evidence_authority_disposition",
        "gateway_custody",
    }
)

#: The closed carriage-capability vocabulary from runtime-evidence-anchor/v2.
#: A capability is declared only by a release that guarantees it, and this
#: release declares none: the declaration is an epoch migration, taken together
#: with the disposition purpose when the disposition verifier ships.
CARRIAGE_CAPABILITIES = frozenset({"checkpoint_fifo_handoff_v1"})

#: Every member a profile document may carry. Anything else is refused: a
#: member the derivation ignores would be signed into the registration while
#: the epoch was derived without it, and the authority recomputes from what is
#: carried.
PROFILE_MEMBERS = frozenset(
    {
        "v",
        "artifact_purposes",
        "chain_protocol",
        "signing_alg",
        "firmware_freshness_verified",
        "carriage_capabilities",
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
    #: Carriage behaviours this release guarantees. Empty means none declared,
    #: and the member is then absent from the document.
    carriage_capabilities: tuple[str, ...] = ()

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> "EvidenceCapabilityProfile":
        """Read a profile from its wire form, refusing one that cannot derive.

        An explicit empty `carriage_capabilities` is refused here rather than
        read as "none declared": the contract says a profile declaring none
        omits the member, so an empty array is a malformed profile.
        """
        if not isinstance(document, dict):
            raise AnchorDerivationError("the capability profile must be an object")
        unknown = sorted(set(document) - PROFILE_MEMBERS)
        if unknown:
            raise AnchorDerivationError(
                f"the capability profile carries members the epoch does not derive "
                f"from: {unknown}"
            )
        try:
            version = document["v"]
            purposes = document["artifact_purposes"]
            protocol = document["chain_protocol"]
            alg = document["signing_alg"]
            freshness = document["firmware_freshness_verified"]
        except KeyError as exc:
            raise AnchorDerivationError(
                "the capability profile is missing a field the epoch derives from"
            ) from exc
        # `True == 1` and `1.0 == 1`, so the type is checked, not the value alone.
        if type(version) is not int or version != PROFILE_VERSION:
            raise AnchorDerivationError("the capability profile version is not 1")
        # Typed strictly rather than coerced: `bool("false")` is True, and a
        # profile read leniently derives an epoch its own document contradicts.
        if not isinstance(purposes, list):
            raise AnchorDerivationError("artifact_purposes must be a list")
        if not isinstance(protocol, str) or not isinstance(alg, str):
            raise AnchorDerivationError(
                "chain_protocol and signing_alg must be strings"
            )
        if not isinstance(freshness, bool):
            raise AnchorDerivationError("firmware_freshness_verified must be a boolean")
        capabilities: tuple[str, ...] = ()
        if "carriage_capabilities" in document:
            declared = document["carriage_capabilities"]
            if not isinstance(declared, list) or not declared:
                raise AnchorDerivationError(
                    "carriage_capabilities must be a non-empty list when present"
                )
            capabilities = tuple(declared)
        profile = cls(
            artifact_purposes=tuple(purposes),
            chain_protocol=protocol,
            signing_alg=alg,
            firmware_freshness_verified=freshness,
            carriage_capabilities=capabilities,
        )
        profile.as_document()
        return profile

    def as_document(self) -> dict[str, Any]:
        purposes = list(self.artifact_purposes)
        _check_sorted_vocabulary(purposes, "artifact_purposes", KEY_PURPOSES, "purpose")
        capabilities = list(self.carriage_capabilities)
        _check_sorted_vocabulary(
            capabilities, "carriage_capabilities", CARRIAGE_CAPABILITIES, "capability"
        )
        document: dict[str, Any] = {
            "artifact_purposes": purposes,
            "chain_protocol": self.chain_protocol,
            "firmware_freshness_verified": bool(self.firmware_freshness_verified),
            "signing_alg": self.signing_alg,
            "v": PROFILE_VERSION,
        }
        if capabilities:
            document["carriage_capabilities"] = capabilities
        return document


def _check_sorted_vocabulary(
    entries: list[Any], field: str, vocabulary: frozenset[str], noun: str
) -> None:
    """Sorted, without repeats, and drawn from the closed vocabulary."""
    if any(not isinstance(entry, str) for entry in entries):
        raise AnchorDerivationError(f"{field} must contain only strings")
    if sorted(entries) != entries:
        raise AnchorDerivationError(f"{field} must be sorted")
    if len(set(entries)) != len(entries):
        raise AnchorDerivationError(f"{field} must not repeat a {noun}")
    unknown = [entry for entry in entries if entry not in vocabulary]
    if unknown:
        raise AnchorDerivationError(f"{field} contains unknown {noun}s: {unknown}")


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


def _public_key_b64_to_hex(value: Any) -> str:
    raw = base64.b64decode(str(value or ""), validate=True)
    if len(raw) != 32:
        raise ValueError("Layer 1 public key must decode to 32 bytes")
    return raw.hex()
