# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Executor-bound façades over the runtime's evidence state.

Every object holding evidence state -- the chain, the delivery ledger, the
ingest service and the confirmed-epoch reader -- carries a ``sqlite3``
connection bound to the thread that opened it. Callers reach them from three
different places: the event loop, the confirmation coordinator's
``asyncio.to_thread`` worker, and MQTT callback threads. None of those is the
owning thread.

These façades are the only public way in. Each marshals onto the evidence
executor, so a caller cannot reach a raw ledger or chain and touch it from the
wrong thread. That is the point: the constraint should be impossible to violate
rather than documented and hoped for.
"""

from __future__ import annotations

from typing import Any, Protocol

from ori.security.evidence.executor import EvidenceExecutor
from ori.security.evidence.ingest_service import IngestOutcome


class IngestBackend(Protocol):
    """What the ingest façade needs. Implemented by EvidenceIngestService."""

    def accept_custody(self, artifact: object) -> IngestOutcome:
        """Record that a courier holds an envelope. Never that it arrived."""
        raise NotImplementedError

    def accept_receipt(self, artifact: object) -> IngestOutcome:
        """Apply an authority receipt for a contiguous delivered range."""
        raise NotImplementedError

    def accept_epoch_confirmation(self, artifact: object) -> IngestOutcome:
        """Activate an anchor epoch the authority has confirmed."""
        raise NotImplementedError

    def accept_disposition(self, artifact: object) -> IngestOutcome:
        """Suspend or close a registration attempt on a verified disposition."""
        raise NotImplementedError

    @property
    def rejections(self) -> tuple[IngestOutcome, ...]:
        """Every artifact refused, so a refusal is visible rather than silent."""
        raise NotImplementedError


class ConfirmedEpochProvider(Protocol):
    """What the confirmation façade reads. Implemented by ConfirmedEpochReader."""

    def active_anchor_epoch_id(self, device_id: str) -> str | None:
        """The epoch a signed confirmation proved active, or None."""
        raise NotImplementedError


class BoundIngestService:
    """Inbound authority artifacts, applied on the evidence owner thread.

    Inbound artifacts arrive on an MQTT callback thread. Calling the ingest
    service from there would raise ``sqlite3.ProgrammingError`` on the first
    artifact, and only once a gateway actually delivered one -- a failure that
    no offline test would reach.
    """

    def __init__(self, executor: EvidenceExecutor, service: IngestBackend) -> None:
        self._executor = executor
        self._service = service

    def accept_custody(self, artifact: object) -> IngestOutcome:
        return self._executor.run(self._service.accept_custody, artifact)

    def accept_receipt(self, artifact: object) -> IngestOutcome:
        return self._executor.run(self._service.accept_receipt, artifact)

    def accept_epoch_confirmation(self, artifact: object) -> IngestOutcome:
        return self._executor.run(self._service.accept_epoch_confirmation, artifact)

    def accept_disposition(self, artifact: object) -> IngestOutcome:
        return self._executor.run(self._service.accept_disposition, artifact)

    @property
    def rejections(self) -> tuple[IngestOutcome, ...]:
        return self._executor.run(lambda: self._service.rejections)


class OutboundLedger(Protocol):
    """What the outbound façade needs. Implemented by EvidenceDeliveryLedger."""

    def awaiting_custody(
        self, limit: int = 100, *, after_seq: int = 0, only_seq: int | None = None
    ) -> list[Any]:
        raise NotImplementedError

    def pending_artifacts(
        self,
        limit: int = 100,
        *,
        artifact_type: str | None = None,
        after_id: int = 0,
        only_id: int | None = None,
    ) -> list[Any]:
        raise NotImplementedError

    def record_artifact_fault(
        self, holder: str, holder_id: int, *, reason: str, at_ms: int
    ) -> None:
        raise NotImplementedError

    def find_by_envelope_digest(self, envelope_digest: str) -> Any:
        raise NotImplementedError

    def find_artifact(self, artifact_digest: str) -> Any:
        raise NotImplementedError

    def record_attempt(
        self, local_seq: int, *, at_ms: int, failure: str | None
    ) -> None:
        raise NotImplementedError

    def record_delivery_failure(
        self, local_seq: int, *, reason: str, observed_at_ms: int
    ) -> None:
        raise NotImplementedError

    def note_artifact_attempt(self, artifact_digest: str, *, at_ms: int) -> None:
        raise NotImplementedError

    def retire_artifact(
        self, artifact_digest: str, *, outcome: str, at_ms: int
    ) -> bool:
        raise NotImplementedError

    def registration_reoffers_due(
        self, *, at_ms: int, limit: int = 100, only_id: int | None = None
    ) -> list[Any]:
        raise NotImplementedError

    def note_registration_offer(self, artifact_digest: str, *, at_ms: int) -> None:
        raise NotImplementedError


def _rows(rows: list[Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def _row(row: Any) -> dict[str, Any] | None:
    return None if row is None else dict(row)


class BoundOutboundQueue:
    """The courier-facing view of the ledger, read and updated on its thread.

    Rows come back as plain dicts: the publisher runs on the event loop and an
    acknowledgement arrives on an MQTT thread, and neither may hold a cursor
    the evidence thread owns.
    """

    def __init__(self, executor: EvidenceExecutor, ledger: OutboundLedger) -> None:
        self._executor = executor
        self._ledger = ledger

    async def awaiting_custody(
        self, limit: int = 100, *, after_seq: int = 0, only_seq: int | None = None
    ) -> list[dict[str, Any]]:
        return await self._executor.run_async(
            lambda: _rows(
                self._ledger.awaiting_custody(
                    limit, after_seq=after_seq, only_seq=only_seq
                )
            )
        )

    async def pending_artifacts(
        self,
        limit: int = 100,
        *,
        artifact_type: str | None = None,
        after_id: int = 0,
        only_id: int | None = None,
    ) -> list[dict[str, Any]]:
        return await self._executor.run_async(
            lambda: _rows(
                self._ledger.pending_artifacts(
                    limit,
                    artifact_type=artifact_type,
                    after_id=after_id,
                    only_id=only_id,
                )
            )
        )

    async def record_artifact_fault(
        self, holder: str, holder_id: int, *, reason: str, at_ms: int
    ) -> None:
        await self._executor.run_async(
            self._ledger.record_artifact_fault,
            holder,
            holder_id,
            reason=reason,
            at_ms=at_ms,
        )

    async def find_envelope(self, envelope_digest: str) -> dict[str, Any] | None:
        return await self._executor.run_async(
            lambda: _row(self._ledger.find_by_envelope_digest(envelope_digest))
        )

    async def find_artifact(self, artifact_digest: str) -> dict[str, Any] | None:
        return await self._executor.run_async(
            lambda: _row(self._ledger.find_artifact(artifact_digest))
        )

    async def record_attempt(
        self, local_seq: int, *, at_ms: int, failure: str | None
    ) -> None:
        await self._executor.run_async(
            self._ledger.record_attempt, local_seq, at_ms=at_ms, failure=failure
        )

    async def record_delivery_failure(
        self, local_seq: int, *, reason: str, observed_at_ms: int
    ) -> None:
        await self._executor.run_async(
            self._ledger.record_delivery_failure,
            local_seq,
            reason=reason,
            observed_at_ms=observed_at_ms,
        )

    async def note_artifact_attempt(self, artifact_digest: str, *, at_ms: int) -> None:
        await self._executor.run_async(
            self._ledger.note_artifact_attempt, artifact_digest, at_ms=at_ms
        )

    async def retire_artifact(
        self, artifact_digest: str, *, outcome: str, at_ms: int
    ) -> bool:
        return await self._executor.run_async(
            self._ledger.retire_artifact, artifact_digest, outcome=outcome, at_ms=at_ms
        )

    async def registration_reoffers_due(
        self, *, at_ms: int, limit: int = 100, only_id: int | None = None
    ) -> list[dict[str, Any]]:
        return await self._executor.run_async(
            lambda: _rows(
                self._ledger.registration_reoffers_due(
                    at_ms=at_ms, limit=limit, only_id=only_id
                )
            )
        )

    async def note_registration_offer(
        self, artifact_digest: str, *, at_ms: int
    ) -> None:
        await self._executor.run_async(
            self._ledger.note_registration_offer, artifact_digest, at_ms=at_ms
        )


class ExecutorBoundConfirmationBackend:
    """The confirmation coordinator's view of evidence state.

    ``active_anchor_epoch_id`` reads epochs proven by a signed confirmation
    arriving through ingest. Until one arrives it returns ``None``, and the
    coordinator holds the obligation pending rather than treating an
    unanswered registration as authority.

    It offers no way to register an anchor. The runtime registers only its own
    anchor, through the registration producer and under the commissioning
    reference recorded at the device, so nothing reached through this view
    can cause a confirmation.
    """

    def __init__(
        self,
        executor: EvidenceExecutor,
        reader: ConfirmedEpochProvider,
    ) -> None:
        self._executor = executor
        self._reader = reader

    def active_anchor_epoch_id(self, device_id: str) -> str | None:
        return self._executor.run(self._reader.active_anchor_epoch_id, device_id)
