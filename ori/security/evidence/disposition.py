# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The seam through which an evidence disposition reaches the runtime's state.

Per `evidence-exchange/v2`, *Evidence disposition*. A verifier proves the
artifact's shape, key and signature (verification steps 1 to 3) and hands a
`VerifiedDisposition` across this seam; the runtime then checks the device,
the binding to an artifact it sealed, and whether the effect is already in
force (steps 4 to 6), and applies the effect. No verifier is installed on this
release, so `NoDispositionVerifier` verifies nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class DispositionScope(str, Enum):
    """How far a disposition reaches: one artifact, one epoch, or the identity."""

    ARTIFACT = "artifact"
    EPOCH = "epoch"
    IDENTITY = "identity"


class DispositionValue(str, Enum):
    """The closed disposition vocabulary."""

    RETAINED_PENDING = "retained_pending"
    ARTIFACT_TERMINAL = "artifact_terminal"
    EPOCH_REPROVISIONING_REQUIRED = "epoch_reprovisioning_required"
    IDENTITY_REPLACEMENT_REQUIRED = "identity_replacement_required"


#: The one scope each value permits, from the contract's value table.
PERMITTED_SCOPE: dict[DispositionValue, DispositionScope] = {
    DispositionValue.RETAINED_PENDING: DispositionScope.ARTIFACT,
    DispositionValue.ARTIFACT_TERMINAL: DispositionScope.ARTIFACT,
    DispositionValue.EPOCH_REPROVISIONING_REQUIRED: DispositionScope.EPOCH,
    DispositionValue.IDENTITY_REPLACEMENT_REQUIRED: DispositionScope.IDENTITY,
}


@dataclass(frozen=True)
class VerifiedDisposition:
    """A disposition whose shape, key and signature a verifier proved.

    `digest` is `sha256:` over the disposition's own wire bytes, which is what
    makes a byte-identical repetition recognisable.
    """

    digest: str
    triggering_digest: str
    device_id: str
    anchor_epoch_id: str
    scope: DispositionScope
    value: DispositionValue
    decided_at_ms: int
    key_id: str


class DispositionVerifier(Protocol):
    """Proves an arriving disposition, or returns None when it does not verify."""

    def verify_disposition(self, artifact: object) -> VerifiedDisposition | None:
        raise NotImplementedError


class NoDispositionVerifier:
    """The verifier installed until the disposition key registry ships: none verifies."""

    def verify_disposition(self, artifact: object) -> VerifiedDisposition | None:
        return None


def disposition_fault(disposition: VerifiedDisposition) -> str | None:
    """Why a verified disposition is malformed, or None when its shape holds."""
    if not isinstance(disposition.value, DispositionValue):
        return "the disposition value is outside the closed vocabulary"
    if not isinstance(disposition.scope, DispositionScope):
        return "the disposition scope is outside the closed vocabulary"
    if PERMITTED_SCOPE[disposition.value] is not disposition.scope:
        return "the disposition value does not permit that scope"
    if disposition.anchor_epoch_id == "" and (
        disposition.scope is not DispositionScope.ARTIFACT
    ):
        return "only an artifact-scoped disposition may name no epoch"
    return None
