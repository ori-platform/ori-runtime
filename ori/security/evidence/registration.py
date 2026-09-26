# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Producing this device's anchor registration, per `evidence-exchange/v2`.

Chain verification starts from the device's verification key. Until that key is
registered against the epoch authorising it, a receiver holding a perfectly
signed chain row has nothing to attribute it to.

A registration is signed by the key being registered, which proves control of
the key and nothing more. The right to deploy the key comes from a separately
signed commissioning authorisation the device never holds. What the device
holds is the **commissioning reference** -- the authorisation's
`commissioning_digest` -- delivered locally through `evidence commission`, and
the registration carries it. The reference grants nothing on its own: the
evidence authority resolves it against the authorisations it holds.
"""

from __future__ import annotations

import base64
import re
from enum import Enum
from typing import Any

from ori.security.evidence.anchor import (
    AnchorDerivationError,
    EvidenceCapabilityProfile,
    derive_anchor_epoch_id,
    derive_key_id,
)
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.device_key import EvidenceDeviceKey

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

#: A commissioning reference, and an anchor epoch: `sha256:` plus 64 lowercase
#: hex, exactly. Anything else is refused rather than normalised.
DIGEST_PATTERN = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

#: Release-owned re-offer schedule for an unconfirmed registration. Not
#: configuration: an operator able to set the delay to zero or the ceiling to
#: forever could silence the obligation.
REOFFER_BASE_S = 60.0
REOFFER_MAX_S = 3600.0
#: More doublings than any ceiling here needs; the exponent never grows past it.
MAX_DOUBLINGS = 16

#: How long a registration may stay unconfirmed before health reports it
#: overdue: the contract's 7,200 seconds, overdue at the bound itself. A
#: diagnostic bound only; it gates nothing.
CONFIRMATION_OVERDUE_MS = 7_200 * 1000

#: How often the runtime reads the recorded reference and reconciles the
#: registration it implies.
RECONCILE_INTERVAL_S = 15.0


class RegistrationStatus(str, Enum):
    """Registration status at the runtime, per current epoch."""

    DISABLED = "disabled"
    PENDING_AUTHORISATION = "pending_authorisation"
    PENDING_CONFIRMATION = "pending_confirmation"
    CONFIRMED = "confirmed"


class RegistrationOffer(str, Enum):
    """How the current epoch's registration is being offered."""

    OFFERING = "offering"
    SUSPENDED = "suspended"
    CLOSED = "closed"
    NOT_APPLICABLE = "not_applicable"


#: The health field reporting whether a disposition stopped delivery, and how
#: far: not at all, for the current epoch, or for the whole identity.
DELIVERY_STATUS_FIELD = "delivery_stop_status"
DELIVERY_NOT_STOPPED = "not_stopped"
DELIVERY_EPOCH_STOPPED = "epoch_stopped"
DELIVERY_IDENTITY_STOPPED = "identity_stopped"


class RegistrationError(RuntimeError):
    """An anchor registration could not be produced."""


def is_digest(value: object) -> bool:
    """Whether *value* is exactly `sha256:` plus 64 lowercase hex."""
    return isinstance(value, str) and DIGEST_PATTERN.match(value) is not None


def reoffer_due(offers: int, last_offer_ms: int, *, at_ms: int) -> bool:
    """Whether the next re-offer is due under bounded exponential delay.

    A clock that has moved backwards past the last offer makes it due at once:
    waiting for the clock to catch up would stall the obligation for as long as
    the correction was large.
    """
    elapsed_ms = at_ms - int(last_offer_ms)
    if elapsed_ms < 0:
        return True
    # Doubling stops once the ceiling is reached: the offer count is unbounded,
    # and an exponent that followed it would overflow a float within weeks.
    doublings = min(max(0, int(offers)), MAX_DOUBLINGS)
    delay_s = min(REOFFER_BASE_S * (1 << doublings), REOFFER_MAX_S)
    return elapsed_ms >= delay_s * 1000.0


def build_anchor_registration(
    *,
    device_key: EvidenceDeviceKey,
    device_id: str,
    anchor_epoch_id: str,
    posture: str,
    key_id: str,
    registered_at_ms: int,
    commissioning_reference: str,
    capability_profile: dict[str, Any],
) -> dict[str, Any]:
    """Build and sign this device's registration for one epoch."""
    if not device_id or not anchor_epoch_id or not key_id:
        raise RegistrationError(
            "a registration must name a device, an epoch and the key it registers"
        )
    if not is_digest(commissioning_reference):
        raise RegistrationError(
            "a commissioning reference is sha256: plus 64 lowercase hex"
        )

    # The authority recomputes both identifiers from the carried inputs and
    # refuses a claim that disagrees, so they are checked here before signing.
    expected_key_id = derive_key_id(
        device_id=str(device_id), pubkey_hex=device_key.public_key_hex
    )
    if str(key_id) != expected_key_id:
        raise RegistrationError(
            "key_id must be derived from the device identity and this key"
        )
    profile = _profile_from_document(capability_profile)
    expected_epoch = derive_anchor_epoch_id(
        device_id=str(device_id),
        pubkey_hex=device_key.public_key_hex,
        posture=str(posture),
        profile=profile,
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
        # The document the epoch was derived from, not the one supplied: the
        # authority recomputes the epoch from what is carried.
        "capability_profile": profile.as_document(),
        "registered_at_ms": int(registered_at_ms),
        "commissioning_digest": commissioning_reference,
        "key_id": str(key_id),
    }
    signature = device_key.sign(REGISTRATION_DOMAIN + canonical_json(registration))
    registration["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return registration


def _profile_from_document(document: dict[str, Any]) -> EvidenceCapabilityProfile:
    """Read a capability profile from its wire form, refusing an unusable one."""
    try:
        return EvidenceCapabilityProfile.from_document(document)
    except AnchorDerivationError as exc:
        raise RegistrationError(str(exc)) from exc
