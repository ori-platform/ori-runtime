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

import hashlib
import logging
from collections import OrderedDict
from dataclasses import dataclass

from ori.security.evidence.authority_keys import AuthorityKey
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.custody_keys import CustodyKeyRegistry
from ori.security.evidence.disposition import (
    DispositionVerifier,
    NoDispositionVerifier,
    disposition_fault,
)
from ori.security.evidence.ingest import (
    REJECT_BINDING_MISMATCH,
    REJECT_MALFORMED,
    REJECT_REASONS,
    REJECT_RESTATEMENT_CONFLICT,
    REJECT_UNKNOWN_KEY,
    REJECT_UNKNOWN_SEQUENCE,
    IngestRejectedError,
    UnreadableChainRowError,
    is_json_integer,
    verify_custody_acknowledgement,
    verify_delivery_receipt,
    verify_epoch_confirmation,
)
from ori.security.evidence.ledger import (
    INGEST_REFUSAL_RETENTION,
    DispositionRefusedError,
    EvidenceDeliveryLedger,
    RestatementConflictError,
    UnsealedRegistrationError,
    is_store_fault,
)
from ori.security.evidence.policy import safe_failure_reason
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

ACCEPTED = "accepted"
REJECTED = "rejected"
#: Neither applied nor refused: the store failed, so nothing was decided.
UNDECIDED = "undecided"


@dataclass(frozen=True)
class IngestOutcome:
    """What happened to one arriving artifact, and why."""

    artifact: str
    state: str
    reason: str | None = None
    detail: str | None = None
    applied_sequences: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        # The courier reads `refused` with its reason, and `applied` with none;
        # an outcome that could be published any other way is never built.
        if self.state == REJECTED:
            if self.reason not in REJECT_REASONS:
                raise ValueError(
                    f"a refusal must carry a receiver rejection reason, not "
                    f"{self.reason!r}"
                )
        elif self.state in (ACCEPTED, UNDECIDED):
            if self.reason is not None:
                raise ValueError(f"a {self.state} outcome carries no reason")
        else:
            raise ValueError(f"{self.state!r} is not an ingest outcome state")

    @property
    def accepted(self) -> bool:
        return self.state == ACCEPTED

    @property
    def decided(self) -> bool:
        """Whether the receiver answered; an undecided artifact is answered never."""
        return self.state in (ACCEPTED, REJECTED)


class EvidenceIngestService:
    """Verifies arriving artifacts and applies the ones that prove out.

    Per evidence-exchange/v3: a verified artifact restating a held record is
    accepted when it agrees and refused `restatement_conflict` when it does
    not; every record one artifact changes is written in one transaction; and
    a store fault leaves the artifact undecided, with no rejection reason, and
    raises the application-storage fault signal.
    """

    def __init__(
        self,
        *,
        ledger: EvidenceDeliveryLedger,
        registry: dict[tuple[str, str], AuthorityKey],
        device_id: str,
        device_pubkey_hex: str,
        custody_keys: CustodyKeyRegistry | None = None,
        disposition_verifier: DispositionVerifier | None = None,
    ) -> None:
        self._ledger = ledger
        self._disposition_verifier: DispositionVerifier = (
            disposition_verifier or NoDispositionVerifier()
        )
        self._registry = registry
        self._device_id = str(device_id)
        self._device_pubkey_hex = str(device_pubkey_hex)
        # Named for what it holds. The previous parameter was
        # `gateway_shared_secret`, which described the runtime-gateway envelope
        # secret and invited exactly the wrong value at the call site -- and
        # got it.
        self._custody_keys = custody_keys
        self._refused: OrderedDict[tuple[str, str, str], None] = OrderedDict()
        # In memory and never in the store, so it reports a store that cannot
        # be read or written; a restart starts it clear.
        self._application_storage_fault = False

    @property
    def application_storage_fault(self) -> bool:
        """runtime-health/v4's signal: a store fault since the last application."""
        return self._application_storage_fault

    @property
    def rejections(self) -> tuple[IngestOutcome, ...]:
        """Refused artifacts the ledger retains, oldest first, across restarts.

        The ledger reads a retained reason outside the vocabulary as a store
        fault, on this path and on the health summary alike.
        """
        return tuple(
            IngestOutcome(
                artifact=str(row["artifact_type"]),
                state=REJECTED,
                reason=str(row["reason"]),
                detail=str(row["detail"]),
            )
            for row in self._ledger.ingest_refusals()
        )

    def _refuse(
        self, subject: object, artifact: str, exc: IngestRejectedError
    ) -> IngestOutcome:
        """Refuse *subject*, recording the refusal once per artifact and reason.

        A courier redelivers what it holds no acknowledgement for, so the same
        artifact can be refused again for the same reason; that is a repeat of
        one refusal, not a second, and the ledger keeps it once. Remembered for
        the newest refusals the ledger retains, within this process.

        A decided refusal is answered even when its record cannot be written.
        """
        outcome = IngestOutcome(
            artifact=artifact, state=REJECTED, reason=exc.reason, detail=exc.detail
        )
        key = (artifact, _subject_digest(subject), exc.reason)
        if key in self._refused:
            self._refused.move_to_end(key)
            return outcome
        try:
            self._ledger.record_ingest_refusal(
                artifact_type=artifact,
                reason=exc.reason,
                detail=exc.detail,
                observed_at_ms=now_ms(),
            )
        except Exception as fault:
            if is_store_fault(fault):
                self._raise_storage_fault(artifact, "recording its refusal", fault)
            else:
                logger.error(
                    "[evidence] the refusal of a %s could not be recorded (%s)",
                    artifact,
                    safe_failure_reason(fault),
                )
            return outcome
        self._refused[key] = None
        while len(self._refused) > INGEST_REFUSAL_RETENTION:
            self._refused.popitem(last=False)
        return outcome

    def _raise_storage_fault(
        self, artifact: str, stage: str, fault: BaseException
    ) -> None:
        self._application_storage_fault = True
        logger.error(
            "[evidence] the store failed while %s a %s (%s); nothing was decided "
            "from it",
            stage,
            artifact,
            safe_failure_reason(fault),
        )

    def _undecided(self, artifact: str, fault: BaseException) -> IngestOutcome:
        self._raise_storage_fault(artifact, "deciding or applying", fault)
        return IngestOutcome(
            artifact=artifact, state=UNDECIDED, detail="the evidence store failed"
        )

    def _applied(
        self,
        artifact: str,
        *,
        applied_sequences: tuple[int, ...] = (),
        detail: str | None = None,
    ) -> IngestOutcome:
        self._application_storage_fault = False
        return IngestOutcome(
            artifact=artifact,
            state=ACCEPTED,
            detail=detail,
            applied_sequences=applied_sequences,
        )

    def accept_custody(self, artifact: object) -> IngestOutcome:
        """Record that the gateway holds an envelope — never that it arrived."""
        try:
            return self._accept_custody(artifact)
        except Exception as fault:
            if not is_store_fault(fault):
                raise
            return self._undecided("custody_acknowledgement", fault)

    def _accept_custody(self, artifact: object) -> IngestOutcome:
        local_seq = _int_field(artifact, "local_seq")
        if local_seq is None:
            return self._refuse(
                artifact,
                "custody_acknowledgement",
                IngestRejectedError("malformed", "the custody names no local_seq"),
            )
        envelope_digest = self._ledger.sealed_envelope_digest(local_seq)
        if envelope_digest is None:
            return self._refuse(
                artifact,
                "custody_acknowledgement",
                IngestRejectedError(
                    REJECT_UNKNOWN_SEQUENCE,
                    "the custody names an envelope never sealed here",
                ),
            )
        try:
            if self._custody_keys is None:
                return self._refuse(
                    artifact,
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
                expected_digest=envelope_digest,
                expected_local_seq=local_seq,
            )
        except IngestRejectedError as exc:
            return self._refuse(artifact, "custody_acknowledgement", exc)

        try:
            self._ledger._apply_verified_custody(
                verified.local_seq,
                custody_at_ms=verified.custody_at_ms,
                key_id=verified.key_id,
                recorded_at_ms=now_ms(),
            )
        except RestatementConflictError as exc:
            return self._refuse(
                artifact,
                "custody_acknowledgement",
                IngestRejectedError(REJECT_RESTATEMENT_CONFLICT, str(exc)),
            )
        return self._applied(
            "custody_acknowledgement", applied_sequences=(verified.local_seq,)
        )

    def accept_receipt(self, artifact: object) -> IngestOutcome:
        """Mark a contiguous range delivered, on the authority's signature alone."""
        try:
            return self._accept_receipt(artifact)
        except Exception as fault:
            if not is_store_fault(fault):
                raise
            return self._undecided("delivery_receipt", fault)

    def _accept_receipt(self, artifact: object) -> IngestOutcome:
        from_seq = _int_field(artifact, "from_seq")
        to_seq = _int_field(artifact, "to_seq")
        digests = (
            self._ledger.chain_row_digests(from_seq, to_seq)
            if from_seq is not None and to_seq is not None and to_seq >= from_seq
            else {}
        )
        try:
            verified = verify_delivery_receipt(
                artifact,
                device_id=self._device_id,
                registry=self._registry,
                chain_row_digests=digests,
            )
        except IngestRejectedError as exc:
            return self._refuse(artifact, "delivery_receipt", exc)
        except UnreadableChainRowError as exc:
            return self._undecided("delivery_receipt", exc)

        applied = self._ledger._apply_verified_receipts(
            verified.sequences,
            receipt_at_ms=verified.accepted_at_ms,
            key_id=verified.key_id,
        )
        return self._applied("delivery_receipt", applied_sequences=applied)

    def accept_disposition(self, artifact: object) -> IngestOutcome:
        """Apply a verified evidence disposition, in the contract's order.

        The verifier checks the artifact's shape, key and signature; the one
        installed on this release verifies nothing, so every disposition is
        refused and nothing changes. Whether it names this device, an artifact
        this device sealed, and an effect not already in force is decided here
        and in the ledger, and any refusal changes nothing.
        """
        try:
            return self._accept_disposition(artifact)
        except Exception as fault:
            if not is_store_fault(fault):
                raise
            return self._undecided("disposition", fault)

    def _accept_disposition(self, artifact: object) -> IngestOutcome:
        try:
            verified = self._disposition_verifier.verify_disposition(artifact)
        except Exception:
            verified = None
        if verified is None:
            return self._refuse(
                artifact,
                "disposition",
                IngestRejectedError(
                    REJECT_UNKNOWN_KEY, "no disposition verifies on this release"
                ),
            )
        fault = disposition_fault(verified)
        if fault is not None:
            return self._refuse(
                artifact, "disposition", IngestRejectedError(REJECT_MALFORMED, fault)
            )
        if verified.device_id != self._device_id:
            return self._refuse(
                artifact,
                "disposition",
                IngestRejectedError(
                    REJECT_BINDING_MISMATCH, "the disposition names another device"
                ),
            )
        try:
            applied = self._ledger._apply_verified_disposition(verified, at_ms=now_ms())
        except DispositionRefusedError as exc:
            return self._refuse(
                artifact, "disposition", IngestRejectedError(exc.reason, exc.detail)
            )
        return self._applied("disposition", detail=applied)

    def accept_epoch_confirmation(self, artifact: object) -> IngestOutcome:
        """Persist a confirmed epoch, which is what makes firmware authority effective.

        Bound to a registration this device sealed for the epoch and the key
        the confirmation names, whichever epoch it is: a confirmation naming
        another device's anchor must not advance this one's, and an earlier
        epoch sealed under an earlier key is still this device's.
        """
        try:
            return self._accept_epoch_confirmation(artifact)
        except Exception as fault:
            if not is_store_fault(fault):
                raise
            return self._undecided("epoch_confirmation", fault)

    def _accept_epoch_confirmation(self, artifact: object) -> IngestOutcome:
        try:
            verified = verify_epoch_confirmation(
                artifact,
                device_id=self._device_id,
                registry=self._registry,
            )
        except IngestRejectedError as exc:
            return self._refuse(artifact, "epoch_confirmation", exc)

        try:
            self._ledger._apply_verified_epoch_confirmation(
                verified.device_id,
                anchor_epoch_id=verified.anchor_epoch_id,
                pubkey_hex=verified.pubkey_hex,
                actor=verified.actor,
                confirmed_at_ms=verified.confirmed_at_ms,
                key_id=verified.key_id,
                closed_at_ms=now_ms(),
            )
        except UnsealedRegistrationError as exc:
            return self._refuse(
                artifact,
                "epoch_confirmation",
                IngestRejectedError(REJECT_BINDING_MISMATCH, str(exc)),
            )
        except RestatementConflictError as exc:
            return self._refuse(
                artifact,
                "epoch_confirmation",
                IngestRejectedError(REJECT_RESTATEMENT_CONFLICT, str(exc)),
            )
        return self._applied("epoch_confirmation")


class ConfirmedEpochReader:
    """The confirmation coordinator's view of proven epoch state.

    The coordinator was written against a chain object that answered
    `active_anchor_epoch_id` from the private artifact in this process. Under
    the off-device topology that answer arrives as a signed confirmation and is
    persisted by ingest, so this is the same question asked of the same
    conceptual authority — reached differently.
    """

    def __init__(self, ledger: EvidenceDeliveryLedger) -> None:
        self._ledger = ledger

    def active_anchor_epoch_id(self, device_id: str) -> str | None:
        return self._ledger.active_anchor_epoch_id(device_id)


def _subject_digest(subject: object) -> str:
    """A stable identity for a refused artifact, whatever shape it arrived in."""
    try:
        body = canonical_json(subject)
    except Exception:
        body = repr(subject).encode("utf-8", "backslashreplace")
    return hashlib.sha256(body).hexdigest()


def _int_field(artifact: object, name: str) -> int | None:
    """An integer in the contract's zone, or None; read before any store lookup."""
    if not isinstance(artifact, dict):
        return None
    value = artifact.get(name)
    return value if is_json_integer(value) else None
