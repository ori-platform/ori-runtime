# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The only route from an arriving artifact to a change in evidence state.

`evidence_ingest` proves an artifact is what it claims. `evidence_ledger` holds
what the device believes. This joins them, and it exists as a single seam on
purpose: the ledger's `_apply_verified_*` methods cannot check what they are
told, so if there were two ways to reach them one of them would eventually be
the unverified one.

Nothing here decides anything. It verifies, applies what verified, and records
what did not — because a rejection is information about the courier, the
authority, or an attacker, and a device that silently drops them cannot explain
why its evidence never arrived.
"""

from __future__ import annotations

from dataclasses import dataclass

from ori.security.evidence.authority_keys import AuthorityKey
from ori.security.evidence.custody_keys import CustodyKeyRegistry
from ori.security.evidence.ingest import (
    REJECT_UNKNOWN_KEY,
    IngestRejectedError,
    verify_custody_acknowledgement,
    verify_delivery_receipt,
    verify_epoch_confirmation,
)
from ori.security.evidence.ledger import EvidenceDeliveryLedger

ACCEPTED = "accepted"
REJECTED = "rejected"


@dataclass(frozen=True)
class IngestOutcome:
    """What happened to one arriving artifact, and why."""

    artifact: str
    state: str
    reason: str | None = None
    detail: str | None = None
    applied_sequences: tuple[int, ...] = ()

    @property
    def accepted(self) -> bool:
        return self.state == ACCEPTED


class EvidenceIngestService:
    """Verifies arriving artifacts and applies the ones that prove out."""

    def __init__(
        self,
        *,
        ledger: EvidenceDeliveryLedger,
        registry: dict[tuple[str, str], AuthorityKey],
        device_id: str,
        device_pubkey_hex: str,
        custody_keys: CustodyKeyRegistry | None = None,
    ) -> None:
        self._ledger = ledger
        self._registry = registry
        self._device_id = str(device_id)
        self._device_pubkey_hex = str(device_pubkey_hex)
        # Named for what it holds. The previous parameter was
        # `gateway_shared_secret`, which described the runtime-gateway envelope
        # secret and invited exactly the wrong value at the call site -- and
        # got it.
        self._custody_keys = custody_keys
        self._rejections: list[IngestOutcome] = []

    @property
    def rejections(self) -> tuple[IngestOutcome, ...]:
        """Every artifact refused since this service was constructed."""
        return tuple(self._rejections)

    def _refuse(self, artifact: str, exc: IngestRejectedError) -> IngestOutcome:
        outcome = IngestOutcome(
            artifact=artifact, state=REJECTED, reason=exc.reason, detail=exc.detail
        )
        self._rejections.append(outcome)
        return outcome

    def accept_custody(self, artifact: object) -> IngestOutcome:
        """Record that the gateway holds an envelope — never that it arrived."""
        local_seq = _int_field(artifact, "local_seq")
        if local_seq is None:
            return self._refuse(
                "custody_acknowledgement",
                IngestRejectedError("malformed", "the custody names no local_seq"),
            )
        sealed = self._ledger.find_by_local_seq(local_seq)
        if sealed is None:
            return self._refuse(
                "custody_acknowledgement",
                IngestRejectedError(
                    "unknown_sequence",
                    "the custody names an envelope never sealed here",
                ),
            )
        try:
            if self._custody_keys is None:
                return self._refuse(
                    "custody_acknowledgement",
                    IngestRejectedError(
                        REJECT_UNKNOWN_KEY,
                        "no custody key registry is configured",
                    ),
                )
            verified = verify_custody_acknowledgement(
                artifact,
                device_id=self._device_id,
                custody_keys=self._custody_keys,
                authority_keys=self._registry,
                expected_digest=str(sealed["envelope_digest"]),
                expected_local_seq=local_seq,
            )
        except IngestRejectedError as exc:
            return self._refuse("custody_acknowledgement", exc)

        self._ledger._apply_verified_custody(
            verified.local_seq,
            custody_at_ms=verified.custody_at_ms,
            key_id=verified.key_id,
        )
        return IngestOutcome(
            artifact="custody_acknowledgement",
            state=ACCEPTED,
            applied_sequences=(verified.local_seq,),
        )

    def accept_receipt(self, artifact: object) -> IngestOutcome:
        """Mark a contiguous range delivered, on the authority's signature alone."""
        from_seq = _int_field(artifact, "from_seq")
        to_seq = _int_field(artifact, "to_seq")
        digests = (
            self._ledger.envelope_digests(from_seq, to_seq)
            if from_seq is not None and to_seq is not None and to_seq >= from_seq
            else {}
        )
        try:
            verified = verify_delivery_receipt(
                artifact,
                device_id=self._device_id,
                registry=self._registry,
                envelope_digests=digests,
            )
        except IngestRejectedError as exc:
            return self._refuse("delivery_receipt", exc)

        applied = tuple(range(verified.from_seq, verified.to_seq + 1))
        for local_seq in applied:
            self._ledger._apply_verified_receipt(
                local_seq, receipt_at_ms=verified.accepted_at_ms, key_id=verified.key_id
            )
        return IngestOutcome(
            artifact="delivery_receipt", state=ACCEPTED, applied_sequences=applied
        )

    def accept_epoch_confirmation(self, artifact: object) -> IngestOutcome:
        """Persist a confirmed epoch, which is what makes firmware authority effective.

        The device's own verification key is the binding that matters here: a
        confirmation naming another device's anchor must not advance this
        one's, and that check is the difference between an authority statement
        about someone else and one about us.
        """
        try:
            verified = verify_epoch_confirmation(
                artifact,
                device_id=self._device_id,
                registry=self._registry,
                expected_pubkey_hex=self._device_pubkey_hex,
            )
        except IngestRejectedError as exc:
            return self._refuse("epoch_confirmation", exc)

        self._ledger._apply_verified_epoch(
            verified.device_id,
            anchor_epoch_id=verified.anchor_epoch_id,
            pubkey_hex=verified.pubkey_hex,
            actor=verified.actor,
            confirmed_at_ms=verified.confirmed_at_ms,
            key_id=verified.key_id,
        )
        return IngestOutcome(artifact="epoch_confirmation", state=ACCEPTED)


class ConfirmedEpochReader:
    """The confirmation coordinator's view of proven epoch state.

    The coordinator was written against a chain object that answered
    `active_anchor_epoch_id` from the private artifact in this process. Under
    the off-device topology that answer arrives as a signed confirmation and is
    persisted by ingest, so this is the same question asked of the same
    conceptual authority — reached differently.

    Registration is deliberately absent. Pushing an anchor to the authority is
    an outbound artifact this runtime does not yet produce, tracked as #350;
    until it exists a confirmation cannot be *caused* from here, only observed.
    """

    def __init__(self, ledger: EvidenceDeliveryLedger) -> None:
        self._ledger = ledger

    def active_anchor_epoch_id(self, device_id: str) -> str | None:
        return self._ledger.active_anchor_epoch_id(device_id)


def _int_field(artifact: object, name: str) -> int | None:
    if not isinstance(artifact, dict):
        return None
    value = artifact.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value
