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

from typing import Protocol

from ori.security.evidence_executor import EvidenceExecutor
from ori.security.evidence_ingest_service import IngestOutcome
from ori.security.evidence_registrar import (
    AnchorRegistrationRequest,
    RegistrationOutcome,
)


class IngestBackend(Protocol):
    """What the ingest façade needs. Implemented by EvidenceIngestService."""

    def accept_custody(self, artifact: object) -> IngestOutcome: ...

    def accept_receipt(self, artifact: object) -> IngestOutcome: ...

    def accept_epoch_confirmation(self, artifact: object) -> IngestOutcome: ...

    @property
    def rejections(self) -> tuple[IngestOutcome, ...]: ...


class ConfirmedEpochProvider(Protocol):
    """What the confirmation façade reads. Implemented by ConfirmedEpochReader."""

    def active_anchor_epoch_id(self, device_id: str) -> str | None: ...


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

    @property
    def rejections(self) -> tuple[IngestOutcome, ...]:
        return self._executor.run(lambda: self._service.rejections)


class ExecutorBoundConfirmationBackend:
    """The confirmation coordinator's view of evidence state.

    The coordinator was written against a chain object that answered both
    questions from a private artifact in this process. Under the off-device
    topology they are answered differently, and the difference is the point:

    ``register_layer1_device`` no longer promotes anything. It produces a signed
    anchor registration and records it as pending outbound. Authority is granted
    only by a signed confirmation arriving back through ingest, so a device
    cannot confirm its own epoch by asserting it locally.

    ``active_anchor_epoch_id`` reads epochs proven by such a confirmation. Until
    one arrives it returns ``None``, and the coordinator holds the obligation
    pending rather than treating an unanswered registration as authority.
    """

    def __init__(
        self,
        executor: EvidenceExecutor,
        reader: ConfirmedEpochProvider,
        registrar: AnchorRegistrar,
    ) -> None:
        self._executor = executor
        self._reader = reader
        self._registrar = registrar

    def register_anchor(
        self, request: AnchorRegistrationRequest
    ) -> RegistrationOutcome:
        """Ask the authority to register an anchor. Grants nothing locally."""
        return self._executor.run(self._registrar.register, request)

    def active_anchor_epoch_id(self, device_id: str) -> str | None:
        return self._executor.run(self._reader.active_anchor_epoch_id, device_id)


class AnchorRegistrar(Protocol):
    """Produces an anchor registration, or reports why it cannot."""

    def register(self, request: AnchorRegistrationRequest) -> RegistrationOutcome: ...
