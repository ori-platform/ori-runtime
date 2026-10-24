# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Firmware commands and the confirmations that settle them."""

import logging

from ori.runtime._core import RuntimeCore
from ori.security.firmware.confirmation import CONFIRMED as _FIRMWARE_CONFIRMED
from ori.security.firmware.reconciliation import FirmwareConfirmationReconciler

logger = logging.getLogger("ori.runtime")


class FirmwareCommands(RuntimeCore):
    """Approving and publishing firmware commands, and draining their confirmations."""

    async def approve_firmware_commands(self, device_id: str) -> bytes:
        """Publish the retained provisioning approval for one firmware device."""
        if self._firmware_command_service is None:
            raise RuntimeError("firmware command egress is not enabled")
        return await self._firmware_command_service.publish_provisioning_approval(
            device_id
        )

    async def publish_firmware_command(
        self,
        *,
        device_id: str,
        action: str,
        channel: str,
    ) -> bytes:
        """Sign and publish one non-retained firmware command."""
        if self._firmware_command_service is None:
            raise RuntimeError("firmware command egress is not enabled")
        return await self._firmware_command_service.publish_command(
            device_id=device_id,
            action=action,
            channel=channel,
        )

    def _nudge_firmware_confirmations(self) -> None:
        """Reconcile outstanding obligations now, because a link came back.

        A restored transport is the most likely moment for a pending
        confirmation to resolve, so waiting out the remaining backoff would be
        the wrong response to the one event suggesting a retry will work.
        """
        reconciler = self._firmware_confirmation_reconciler
        if reconciler is not None:
            reconciler.nudge()

    async def _drain_pending_firmware_confirmations(self) -> None:
        """Reconcile every outstanding confirmation obligation once, now.

        Approval records a durable confirmation_pending obligation but cannot
        itself reach the evidence store (the provisioner is offline). At the
        runtime's earliest opportunity, drain every pending obligation through
        the coordinator, so a normally-approved device -- one with no firmware
        action waiting -- still gets its epoch confirmed and can publish
        approvals and receive commands.

        Recurring retries are the reconciler's `serve_until`, started as a
        background task. This drives the same worker once, so startup does not
        wait out an interval before doing what it can immediately.
        """
        reconciler = self._firmware_confirmation_reconciler
        if reconciler is None:
            # The coordinator is what decides whether draining is possible;
            # the reconciler only schedules around it. Building a transient
            # one here keeps a caller that has a coordinator from getting a
            # silent no-op because scheduling was not set up.
            coordinator = self._firmware_confirmation_coordinator
            if coordinator is None or self._state_store is None:
                return
            reconciler = FirmwareConfirmationReconciler(
                store=self._state_store, coordinator=coordinator
            )
        confirmed, seen = await reconciler.reconcile_once()
        if seen:
            logger.info(
                "[confirmation] startup drain: %d of %d devices confirmed",
                confirmed,
                seen,
            )

    async def _firmware_source_confirmed(self, row: dict) -> bool:
        """Whether a firmware-sourced action may be signed yet.

        A row with no firmware source device is not gated -- there is no
        cross-store anchor to confirm. For a firmware-sourced row, the
        coordinator reconciles the runtime and evidence stores and returns
        the source device's stored confirmation status; only ``confirmed``
        permits signing. A firmware-sourced row with no coordinator
        available fails closed.
        """
        source_device_id = str(row.get("input_firmware_device_id", "") or "").strip()
        if not source_device_id:
            return True
        coordinator = self._firmware_confirmation_coordinator
        if coordinator is None:
            logger.warning(
                "[confirmation] no coordinator available; leaving firmware "
                "evidence for %s pending",
                source_device_id,
            )
            return False
        try:
            status = await coordinator.confirm(source_device_id)
        except Exception:
            logger.warning(
                "[confirmation] reconciling %s failed; leaving evidence pending",
                source_device_id,
            )
            return False
        return status == _FIRMWARE_CONFIRMED
