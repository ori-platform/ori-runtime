# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Evidence: checkpoints, registration, and pending attestations."""

import asyncio
import logging

from ori.runtime._constants import EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S
from ori.runtime._firmware import FirmwareCommands
from ori.security.evidence.first_party import (
    AUTHORITY_UNAVAILABLE_REASON,
    AuthorityUnavailableError,
    FirstPartyEvidenceAttestor,
)
from ori.security.evidence.ledger import DEFAULT_CHECKPOINT_INTERVAL_S
from ori.security.evidence.policy import safe_failure_reason
from ori.security.evidence.registration import RECONCILE_INTERVAL_S, RegistrationStatus

logger = logging.getLogger("ori.runtime")


class EvidenceLoops(FirmwareCommands):
    """Issuing evidence checkpoints, registering, and reconciling pending attestations."""

    async def _evidence_checkpoint_loop(
        self, attestor: FirstPartyEvidenceAttestor
    ) -> None:
        """Retain a signed checkpoint every interval. The cadence is release-owned."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(), timeout=DEFAULT_CHECKPOINT_INTERVAL_S
                )
                return
            except asyncio.TimeoutError:
                pass  # the interval elapsed: retain the next checkpoint
            await attestor.issue_checkpoint()

    async def _evidence_registration_loop(
        self, attestor: FirstPartyEvidenceAttestor
    ) -> None:
        """Reconcile the anchor registration with the recorded reference, forever.

        Reads the reference at startup and every interval, so one recorded
        over the operator socket while the runtime runs is sealed without a
        restart. The cadence is release-owned.
        """
        while not self._shutdown_event.is_set():
            await self._reconcile_evidence_registration(attestor)
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(), timeout=RECONCILE_INTERVAL_S
                )
                return
            except asyncio.TimeoutError:
                pass  # the interval elapsed: reconcile again

    async def _reconcile_evidence_registration(
        self, attestor: FirstPartyEvidenceAttestor
    ) -> RegistrationStatus | None:
        """One reconciliation. A failed read seals nothing and is retried."""
        anchor = attestor.anchor
        store = self._state_store
        if anchor is None or store is None:
            return None
        try:
            reference = await store.get_evidence_commissioning_reference(
                device_id=anchor.device_id, anchor_epoch_id=anchor.anchor_epoch_id
            )
        except Exception as exc:
            logger.warning(
                "[evidence] the commissioning reference could not be read (%s); "
                "the next interval retries",
                type(exc).__name__,
            )
            return None
        return await attestor.reconcile_registration(reference)

    async def _issue_shutdown_checkpoint(self) -> None:
        attestor = self._evidence_attestor
        if attestor is None or not attestor.available:
            return
        await attestor.issue_checkpoint()
        publisher = self._evidence_outbound_publisher
        if publisher is not None:
            await publisher.flush(EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S)

    async def _reconcile_pending_attestations(self) -> None:
        """Repair evidence gaps left by crashes or signing outages.

        Option B append-after-log (DECISIONS.md 2026-07-10): rows stuck in
        ``pending``/``failed`` are re-signed with their original timestamps
        (the chain records write time separately, so late signing is
        transparent) and marked ``reconciled``. Rows that still cannot be
        signed stay ``failed`` and remain visible as gaps — never fabricated.
        """
        if self._evidence_attestor is None or self._state_store is None:
            return
        if not hasattr(self._state_store, "get_actions_needing_attestation"):
            return
        try:
            rows = await self._state_store.get_actions_needing_attestation()
        except Exception:
            logger.warning("[evidence] reconciliation scan failed")
            return
        if not rows:
            return
        repaired = 0
        for row in rows:
            if row.get("record_kind", "dispatch") != "dispatch":
                # Only a dispatch is ever marked for attestation; a non-dispatch
                # row here is a corrupt record, refused and reported, never
                # signed and never silently skipped.
                logger.critical(
                    "[evidence] action_log id=%s is a %r record marked for "
                    "attestation; refused",
                    row.get("id"),
                    row.get("record_kind"),
                )
                try:
                    await self._state_store.set_action_attestation(
                        int(row["id"]), status="refused", reason="not_a_dispatch_record"
                    )
                except Exception as exc:
                    logger.warning(
                        "[evidence] could not refuse action_log row (%s)",
                        safe_failure_reason(exc),
                    )
                continue
            # Cross-store confirmation gate: firmware-sourced evidence is
            # accepted only once the source device's active epoch is
            # confirmed in the evidence store. The coordinator reconciles the
            # two stores and returns the stored status; anything short of
            # confirmed leaves the row pending (fail closed) rather than
            # signing under authority the evidence store cannot back. The
            # local approved flag is deliberately NOT the gate here.
            if not await self._firmware_source_confirmed(row):
                continue
            # reconciled=True stamps the signed payload as late evidence —
            # a verifier must never mistake it for emission-time signing.
            try:
                seq = await self._evidence_attestor.attest_action(
                    dict(row), reconciled=True
                )
            except AuthorityUnavailableError as exc:
                # A row from before the licence was recorded, or one whose
                # snapshot disagrees with its own columns. Neither improves by
                # being retried, so it leaves the reconciliation set instead of
                # being attempted on every pass.
                logger.error(
                    "[evidence] refusing to attest action id=%s tier=%s: %s",
                    row.get("id"),
                    row.get("tier"),
                    exc,
                )
                await self._state_store.set_action_attestation(
                    int(row["id"]),
                    status="refused",
                    attestation_seq=None,
                    reason=AUTHORITY_UNAVAILABLE_REASON,
                )
                continue
            status = "reconciled" if seq is not None else "failed"
            try:
                await self._state_store.set_action_attestation(
                    int(row["id"]), status=status, attestation_seq=seq
                )
            except Exception:
                logger.warning(
                    "[evidence] failed to record reconciliation for action id=%s",
                    row.get("id"),
                )
                continue
            if seq is not None:
                repaired += 1
        remaining = len(rows) - repaired
        logger.warning(
            "[evidence] startup reconciliation: %d repaired, %d still unsigned",
            repaired,
            remaining,
        )
