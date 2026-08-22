# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Typed request and outcome for producing an anchor registration.

A registration asserts that a device key is authorised for an epoch. Under
`evidence-exchange/v1` the right to make that assertion does not come from the
device: a self-signed registration carrying `actor` and `reason` as plain fields
proves only that whoever holds the key wrote those strings. Authority comes from
a separately signed commissioning authorisation, issued under the
`commissioning_authority` purpose, and the registration binds it by digest.

The runtime holds no commissioning key and has no channel that delivers such an
authorisation today, tracked as ori-specs#91. So this module can produce a
registration only when one is supplied, and reports `PENDING_AUTHORISATION`
otherwise. That is the correct outcome rather than a limitation to work around:
manufacturing an authorisation from locally recorded attribution would collapse
control back into authority, which is precisely what the contract separates.

`PENDING_AUTHORISATION` is a durable working state, not a terminal one. Nothing
further happens without an authorisation, but the obligation stays alive: the
caller retries when one becomes available rather than closing the attempt. Two
properties hold throughout. The state is observable without naming the evidence
authority, and it never gates a Tier D safety action -- physical safety does not
wait on evidence infrastructure, and an unregistered anchor must not become a
reason a relay failed to open.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol


class RegistrationStatus(str, Enum):
    """Outcome of asking the runtime to register an anchor."""

    #: A signed authorisation was supplied and a registration was produced.
    RECORDED = "recorded"
    #: No commissioning authorisation is available. Nothing was produced and
    #: the device has gained no authority. Durable and retryable: the caller
    #: keeps the obligation and retries when an authorisation appears.
    PENDING_AUTHORISATION = "pending_authorisation"
    #: An authorisation was supplied but does not describe this registration.
    REFUSED = "refused"


@dataclass(frozen=True)
class AnchorRegistrationRequest:
    """What the runtime knows locally about an anchor it wants registered.

    Deliberately not the legacy FFI argument list. That signature was positional
    and untyped, carried `actor` and `reason` as if the device could assert them,
    and had no place for the commissioning authorisation at all -- which made it
    easy to call without the one input that confers authority.
    """

    device_id: str
    public_key_hex: str
    anchor_epoch_id: str
    posture: str


@dataclass(frozen=True)
class RegistrationOutcome:
    """Result of a registration attempt."""

    status: RegistrationStatus
    detail: str = ""
    registration: Mapping[str, Any] | None = None

    @property
    def authoritative(self) -> bool:
        """Whether this outcome grants the device any authority.

        Always false. Producing a registration is a request to the authority,
        not a grant: only a signed epoch confirmation arriving through ingest
        makes an epoch active. The property exists so a caller cannot read
        ``RECORDED`` as approval.
        """
        return False


class CommissioningAuthorisationSource(Protocol):
    """Supplies the signed commissioning authorisation for a registration.

    No implementation exists yet, because nothing delivers one to the device.
    The protocol names the missing input explicitly so its absence is a visible
    hole rather than an argument quietly omitted at a call site.
    """

    def authorisation_for(
        self, *, device_id: str, anchor_epoch_id: str
    ) -> Mapping[str, Any] | None:
        """Return the signed authorisation, or None when none is held."""
        ...
