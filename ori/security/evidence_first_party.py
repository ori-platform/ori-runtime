# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Signs Tier C/D action evidence into the runtime's own evidence chain.

This replaces the loader that imported a private evidence artifact named by
three environment variables. The format it produced was never publicly
specified, which meant a device could not be independently verified and the
runtime could not be built or tested without an artifact most environments did
not have. `evidence/v2.md` specifies the format, and this produces it.

The chain, the delivery ledger and the ingest service each hold a thread-bound
SQLite connection, so all three are constructed on -- and reached only through
-- a single `EvidenceExecutor`. See `evidence_executor` for why that discipline
is structural rather than conventional.

What this deliberately does not do is grant authority. Attesting an action
records that it happened. It does not register an anchor, and it does not make
an epoch active: only a signed epoch confirmation arriving through ingest does
that. Nor does it gate anything -- attestation runs after the action executed,
so a chain that will not open can never become the reason a relay failed.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ori.security.custody_keys import CustodyKeyRegistry
from ori.security.evidence_anchor import RuntimeAnchor, derive_runtime_anchor
from ori.security.evidence_bound import (
    BoundIngestService,
    ExecutorBoundConfirmationBackend,
)
from ori.security.evidence_chain import (
    SCHEMA_VERSION,
    EvidenceChain,
    attestation_event_id,
)
from ori.security.evidence_device_key import EvidenceDeviceKey
from ori.security.evidence_executor import EvidenceExecutor
from ori.security.evidence_ingest_service import (
    ConfirmedEpochReader,
    EvidenceIngestService,
)
from ori.security.evidence_ledger import EvidenceDeliveryLedger
from ori.security.evidence_policy import safe_failure_reason
from ori.security.evidence_registrar import (
    AnchorRegistrationRequest,
    RegistrationOutcome,
    RegistrationStatus,
)
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

#: Chain event type for a Tier C/D action.
ACTION_EVENT_TYPE = "SAFETY_ACTION_EXECUTED"


class PendingAuthorisationRegistrar:
    """Produces no registration, because no authorisation is available.

    `evidence-exchange/v1` requires a separately signed commissioning
    authorisation, and nothing delivers one to a device today -- how it should
    is open as ori-specs#91. The registrar exists so the gap has a named,
    testable shape instead of an unimplemented call site, and so the outcome is
    a durable pending state the caller retries rather than a silent no-op.

    It must never synthesise an authorisation from locally recorded attribution.
    A registration carrying `actor` and `reason` as plain fields proves only
    that whoever holds the key wrote those strings, which is exactly the
    collapse of control into authority the contract exists to prevent.
    """

    def register(self, request: AnchorRegistrationRequest) -> RegistrationOutcome:
        logger.info(
            "[evidence] anchor registration for epoch %s is pending: no "
            "commissioning authorisation is held",
            request.anchor_epoch_id,
        )
        return RegistrationOutcome(
            status=RegistrationStatus.PENDING_AUTHORISATION,
            detail="no commissioning authorisation is held for this epoch",
        )


class FirstPartyEvidenceAttestor:
    """Opens the first-party evidence stack and signs action rows into it."""

    def __init__(
        self,
        *,
        db_path: str,
        key_path: str,
        device_secret: str,
        device_id: str,
        custody_keys: CustodyKeyRegistry | None = None,
        authority_keys: dict[tuple[str, str], Any] | None = None,
    ) -> None:
        self._db_path = str(db_path)
        self._key_path = str(key_path)
        self._device_secret = str(device_secret)
        self._device_id = str(device_id)
        # Derived once the key exists, never supplied. A caller cannot pass an
        # epoch or selector that disagrees with the key actually in use, because
        # there is no argument through which to pass one.
        self._anchor: RuntimeAnchor | None = None
        self._custody_keys = custody_keys
        self._authority_keys = dict(authority_keys or {})

        self._executor = EvidenceExecutor()
        self._chain: EvidenceChain | None = None
        self._ledger: EvidenceDeliveryLedger | None = None
        self._ingest: BoundIngestService | None = None
        self._public_key_hex = ""

    @property
    def available(self) -> bool:
        return self._chain is not None

    @property
    def public_key_hex(self) -> str:
        """This device's own verification anchor, as hex."""
        return self._public_key_hex

    @property
    def protocol_version(self) -> str:
        """Schema version of the chain this runtime writes."""
        return SCHEMA_VERSION if self._chain is not None else ""

    @property
    def action_event_type(self) -> str:
        return ACTION_EVENT_TYPE

    @property
    def atomic_freshness_available(self) -> bool:
        """Whether Layer 1 freshness is atomically *verified*, not merely signed.

        False, and deliberately so. This attestor signs the firmware
        coordinates its caller supplies, which records that those values were
        presented -- it does not establish that they were fresh, monotonic, or
        attributable to a confirmed epoch. The previous implementation checked
        registration and epoch state inside the same transaction as the append
        before claiming this.

        Reporting True on the strength of signing alone would let the runtime
        describe an unverified reading as freshness-bound evidence. Returning
        False keeps the claim honest until the transactional validation exists;
        the coordinates are still signed, and still recorded as presented.
        """
        return False

    @property
    def anchor(self) -> RuntimeAnchor | None:
        """The derived identity this runtime seals evidence under."""
        return self._anchor

    @property
    def ingest(self) -> BoundIngestService | None:
        """Inbound authority artifacts, marshalled onto the evidence thread."""
        return self._ingest

    async def start(self) -> bool:
        """Open the key, chain and ledger on the evidence thread.

        First start on a device is key provisioning: the Ed25519 device key is
        generated and sealed at ``key_path``. Failure is contained -- the
        runtime continues without attestation rather than refusing to run,
        because evidence records what happened and must not decide whether it
        may happen.
        """
        try:
            await self._executor.run_async(self._open_sync)
        except Exception as exc:
            logger.warning(
                "[evidence] evidence signing is unavailable (%s); Tier C/D "
                "actions continue and are recorded as attestation gaps until "
                "signing is restored.",
                safe_failure_reason(exc),
            )
            self._chain = None
            self._ledger = None
            self._ingest = None
            return False
        return True

    def _open_sync(self) -> None:
        """Construct every thread-bound object on the evidence worker."""
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        key = EvidenceDeviceKey.load_or_create(self._key_path, self._device_secret)
        anchor = derive_runtime_anchor(
            device_id=self._device_id, pubkey_hex=key.public_key_hex
        )
        chain = EvidenceChain(self._db_path, key, self._device_id)
        ledger = EvidenceDeliveryLedger(
            self._db_path,
            key,
            self._device_id,
            anchor_epoch_id=anchor.anchor_epoch_id,
            key_id=anchor.key_id,
        )
        service = EvidenceIngestService(
            ledger=ledger,
            registry=self._authority_keys,
            device_id=self._device_id,
            device_pubkey_hex=key.public_key_hex,
            custody_keys=self._custody_keys,
        )
        self._anchor = anchor
        self._chain = chain
        self._ledger = ledger
        self._ingest = BoundIngestService(self._executor, service)
        self._public_key_hex = key.public_key_hex

    def attestation_event_id(self, action_log_id: int) -> str:
        """Deterministic idempotency key for one action_log row.

        Derived per `evidence/v2`, which binds the device into the identity and
        uses the neutral namespace. It deliberately does not reproduce the v1
        identifier: that namespace encodes a private product name in its bytes,
        and a v2 row carrying a v1 identity would be wrong on both counts.
        Identifiers already written under v1 stay as they are and stay opaque.
        """
        return attestation_event_id(self._device_id, action_log_id)

    async def attest_action(
        self, action_row: dict[str, Any], *, reconciled: bool = False
    ) -> int | None:
        """Sign one action_log row into the chain; return the chain seq.

        Idempotent on the deterministic event id, so retrying a row whose append
        succeeded but whose status update was lost returns the existing seq
        rather than attesting twice.

        Returns None on failure. Callers mark the row failed and leave repair to
        reconciliation; they must not treat None as a reason to undo the action,
        which has already happened.
        """
        if self._chain is None:
            return None
        action_log_id = int(action_row.get("id", 0))
        event_id = self.attestation_event_id(action_log_id)
        payload = _action_payload(action_row, reconciled=reconciled)
        emitted_at_ms = int(action_row.get("timestamp", 0))
        try:
            row = await self._executor.run_async(
                self._append_and_seal_sync, event_id, emitted_at_ms, payload
            )
            return int(row["seq"])
        except Exception:
            logger.warning(
                "[evidence] failed to sign action_log id=%s tier=%s",
                action_row.get("id"),
                action_row.get("tier"),
            )
            return None

    def _append_and_seal_sync(
        self, event_id: str, emitted_at_ms: int, payload: dict[str, Any]
    ) -> Any:
        """Append the row, then seal it into a delivery envelope.

        Both steps, or the row is signed but undeliverable: it would advance no
        delivery high-water mark and give the courier nothing to carry, while
        the runtime reported the action as attested. Each step is idempotent on
        its own identity, so a crash between them is repaired by retrying.

        Both run on the evidence worker, and ``EvidenceExecutor.run`` admits a
        nested call inline, so this does not deadlock the single-slot executor.
        """
        assert self._chain is not None
        assert self._ledger is not None
        row = self._chain.append(
            event_id=event_id,
            event_type=ACTION_EVENT_TYPE,
            emitted_at_ms=emitted_at_ms,
            payload=payload,
            created_at_ms=now_ms(),
        )
        self._ledger.seal(row, sealed_at_ms=now_ms())
        return row

    async def chain_head_hash(self) -> str | None:
        """The hash of the most recent chain row, or None when unavailable.

        Read on the health path, so a failure returns None rather than raising:
        health exists to report state, and a health call that raises reports
        nothing at all -- including the parts that were fine.
        """
        if self._chain is None:
            return None
        try:
            return await self._executor.run_async(self._head_hash_sync)
        except Exception as exc:
            logger.warning(
                "[evidence] chain head read failed (%s)", safe_failure_reason(exc)
            )
            return None

    def _head_hash_sync(self) -> str:
        assert self._chain is not None
        _seq, head_hash = self._chain.head()
        return head_hash

    async def pending_export_count(self) -> int | None:
        """Sealed envelopes no courier has acknowledged holding.

        Measured on the delivery ledger, not the chain: a chain row exists as
        soon as an action is signed, and counting those would report evidence as
        awaiting a courier before sealing had produced anything to carry.

        Custody rather than receipt, because they fail for different reasons and
        conflating them hides which hop is stalled. An accepted custody
        acknowledgement is what makes this fall; a receipt does not, since it
        moves the next hop.
        """
        if self._ledger is None:
            return None
        try:
            return await self._executor.run_async(self._pending_count_sync)
        except Exception as exc:
            logger.warning(
                "[evidence] pending count read failed (%s)", safe_failure_reason(exc)
            )
            return None

    def _pending_count_sync(self) -> int:
        assert self._ledger is not None
        return self._ledger.awaiting_custody_count()

    async def issue_checkpoint(self) -> dict[str, Any] | None:
        """Sign a checkpoint for the current high-water mark.

        A checkpoint turns unexplained silence into a missed obligation: without
        one, a stalled courier and an idle device look the same to the
        authority. Failure is contained -- a checkpoint that cannot be issued
        must not stop the runtime, since it is a record about the runtime rather
        than a precondition for it.
        """
        if self._ledger is None:
            return None
        try:
            return await self._executor.run_async(self._checkpoint_sync, now_ms())
        except Exception as exc:
            logger.warning(
                "[evidence] could not issue a checkpoint (%s); the high-water "
                "mark is unchanged and the next interval will retry",
                safe_failure_reason(exc),
            )
            return None

    def _checkpoint_sync(self, issued_at_ms: int) -> dict[str, Any]:
        assert self._ledger is not None
        return self._ledger.checkpoint(issued_at_ms=issued_at_ms)

    def confirmation_backend(self) -> ExecutorBoundConfirmationBackend | None:
        """The confirmation coordinator's bound view of evidence state."""
        if self._ledger is None:
            return None
        return ExecutorBoundConfirmationBackend(
            self._executor,
            ConfirmedEpochReader(self._ledger),
            PendingAuthorisationRegistrar(),
        )

    def close(self) -> None:
        """Close the chain and ledger on their owning thread, then stop it."""

        def _teardown() -> None:
            for handle in (self._ledger, self._chain):
                if handle is None:
                    continue
                try:
                    handle.close()
                except Exception as exc:  # pragma: no cover - teardown detail
                    logger.info(
                        "[evidence] an evidence handle did not close cleanly (%s)",
                        safe_failure_reason(exc),
                    )
            self._chain = None
            self._ledger = None
            self._ingest = None

        self._executor.close(teardown=_teardown)


def _action_payload(action_row: dict[str, Any], *, reconciled: bool) -> dict[str, Any]:
    """Build the signed payload for one action row.

    Field names and spellings are what a verifier reads, so they are contract
    surface rather than internal detail.
    """
    payload: dict[str, Any] = {
        "kind": "runtime_action",
        "attestation": "reconciled_late" if reconciled else "at_emission",
        "action_log_id": int(action_row.get("id", 0)),
        "action_name": str(action_row.get("action_name", "")),
        "action_tier": str(action_row.get("tier", "")),
        "executed": bool(action_row.get("executed")),
        "approved": action_row.get("approved"),
        "action_taken": str(action_row.get("action_taken", "")),
        "trigger_name": str(action_row.get("trigger_name", "")),
        "proposal_id": str(action_row.get("proposal_id", "") or ""),
        "correlation_id": str(action_row.get("correlation_id", "") or ""),
        "sensor_id": str(action_row.get("sensor_id", "") or ""),
        "input_attestation_grade": str(
            action_row.get("input_attestation_grade", "unattested") or "unattested"
        ),
        "input_posture": str(action_row.get("input_posture", "") or ""),
    }
    device_id = str(action_row.get("input_firmware_device_id", "") or "")
    boot_id = action_row.get("input_firmware_boot_id")
    seq = action_row.get("input_firmware_seq")
    if device_id and boot_id is not None and seq is not None:
        # Bound in the same signed payload as the action, so the freshness of
        # the reading that justified it cannot be separated from it later.
        payload["input_firmware_device_id"] = device_id
        payload["input_firmware_boot_id"] = int(boot_id)
        payload["input_firmware_seq"] = int(seq)
    return payload
