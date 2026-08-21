# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Cross-store epoch confirmation coordinator.

Approval is the authority boundary (ori-specs/device-provisioning/v1.md).
The offline provisioner promotes an anchor locally and records a durable
``confirmation_pending`` obligation, but authority becomes *effective*
only when the runtime store and the evidence store agree on the identical
``anchor_epoch_id``. The gates -- not the local ``approved`` flag --
enforce that: firmware commands and provisioning approvals do not reach
firmware, and firmware evidence is not accepted, until the active epoch is
``confirmed``.

This coordinator is the one place that reconciles the two stores. It is
runtime-owned and holds exactly what it needs -- the runtime store and
the evidence-chain handle -- rather than being folded into the evidence
attestor, which must not own reconciliation. The runtime invokes it at
its earliest opportunity; recurring scheduling (startup, reconnect,
periodic) is layered on later around this same coordinator.

Outcomes (never overwriting the evidence store to force agreement):

- exact epoch match                          -> ``confirmed``
- evidence store unavailable, or no active
  epoch after a push                         -> remain ``confirmation_pending``
- a *different* active epoch already held    -> ``quarantined``

The evidence store is read FIRST. A store that already holds a
conflicting active epoch would reject a blind push, and pushing before
reading would misclassify that genuine disagreement as a transient
outage. So agreement or disagreement is decided from a readback, and a
push happens only when the store holds nothing active to disagree with.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ori.security.evidence import _public_key_b64_to_hex
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

# Terminal + working states, matching the outbox and the spec.
CONFIRMED = "confirmed"
CONFIRMATION_PENDING = "confirmation_pending"
QUARANTINED = "quarantined"


class FirmwareConfirmationCoordinator:
    """Reconciles a locally-approved anchor with the evidence store.

    ``chain`` is the evidence-chain handle exposing
    ``register_layer1_device`` and ``active_anchor_epoch_id``. ``store`` is
    the runtime state store.
    """

    def __init__(self, *, store: Any, chain: Any) -> None:
        self._store = store
        self._chain = chain

    async def confirm(self, device_id: str) -> str:
        """Attempt to confirm the device's currently active epoch.

        Returns the resulting confirmation status. Idempotent and safe to
        call repeatedly: an already-``confirmed`` epoch is left untouched
        (fail-stable), and a ``quarantined`` one is never re-resolved by a
        retry -- only an operator clears it.
        """
        device = await self._store.get_firmware_device(device_id)
        if device is None or not device.get("approved") or device.get("revoked"):
            # No active grant to confirm. A revoked or unapproved identity
            # has no epoch the runtime is asserting authority for.
            return CONFIRMATION_PENDING

        epoch = str(device.get("anchor_epoch_id", "") or "")
        if not epoch:
            return CONFIRMATION_PENDING

        status = await self._store.get_firmware_confirmation_status(device_id, epoch)
        if status == CONFIRMED:
            return CONFIRMED  # fail-stable: an already-confirmed epoch stands.
        if status == QUARANTINED:
            return QUARANTINED  # terminal until an operator resolves it.

        # Attribute any push to the SAME operator decision that approved the
        # device locally, never invented here.
        attribution = await self._store.firmware_active_promotion_attribution(device_id)
        if attribution is None:
            await self._record_attempt(device_id, epoch)
            return CONFIRMATION_PENDING

        # Read BEFORE any push. A store that already holds a conflicting
        # active epoch would reject a blind push, and pushing first would
        # misread that genuine disagreement as a transient outage.
        try:
            chain_epoch = await self._readback(device_id)
        except Exception:
            return await self._unreachable(device_id, epoch)

        if chain_epoch is not None:
            # The store already has an active epoch. Decide from it, without
            # pushing: an exact match confirms, anything else is a real
            # disagreement to quarantine.
            return await self._decide(device_id, epoch, chain_epoch)

        # Nothing active on the far side to disagree with, so it is safe to
        # register-and-promote, then read back what took effect.
        try:
            await self._push(device, attribution)
            chain_epoch = await self._readback(device_id)
        except Exception:
            return await self._unreachable(device_id, epoch)

        if chain_epoch is None:
            # Pushed, but still nothing active. Do not treat as agreement;
            # remain pending and retry.
            await self._record_attempt(device_id, epoch)
            return CONFIRMATION_PENDING

        return await self._decide(device_id, epoch, chain_epoch)

    async def _decide(self, device_id: str, epoch: str, chain_epoch: str) -> str:
        if chain_epoch == epoch:
            await self._store.resolve_firmware_confirmation(
                device_id, epoch, status=CONFIRMED, at_ms=now_ms()
            )
            return CONFIRMED
        # The two stores disagree on the active epoch. Quarantine for
        # operator review; never overwrite the evidence store to force
        # agreement.
        logger.error(
            "[confirmation] epoch disagreement for %s: runtime %s, evidence "
            "store %s; quarantining for operator review",
            device_id,
            epoch,
            chain_epoch,
        )
        await self._store.resolve_firmware_confirmation(
            device_id, epoch, status=QUARANTINED, at_ms=now_ms()
        )
        return QUARANTINED

    async def _unreachable(self, device_id: str, epoch: str) -> str:
        # Fail-closed path for granting authority: remain pending, retried
        # later, never optimistic.
        # Detail at DEBUG, not WARNING: the exception is raised by the chain
        # handle and can name the private component or its files.
        logger.warning(
            "[confirmation] confirmation authority unreachable for %s epoch %s; "
            "remaining confirmation_pending",
            device_id,
            epoch,
        )
        await self._record_attempt(device_id, epoch)
        return CONFIRMATION_PENDING

    async def _record_attempt(self, device_id: str, epoch: str) -> None:
        # Recorded so a stuck grant is visibly being worked rather than idle.
        await self._store.record_firmware_confirmation_attempt(
            device_id, epoch, now_ms()
        )

    async def _push(self, device: dict, attribution: dict) -> None:
        """Register-and-promote the anchor into the evidence store,
        idempotently.

        Mirrors the same operator decision recorded locally; the FFI's
        register-and-promote requires that attribution.
        """
        public_key_hex = _public_key_b64_to_hex(device.get("public_key_b64"))
        await asyncio.to_thread(
            self._chain.register_layer1_device,
            str(device["device_id"]),
            public_key_hex,
            str(device.get("alg", "") or ""),
            str(device.get("posture", "") or ""),
            str(device.get("capability_hash", "") or ""),
            str(device.get("board_profile", "") or ""),
            int(device.get("provisioned_at_ms", 0) or 0),
            True,
            str(attribution["actor"]),
            str(attribution["reason"]),
        )

    async def _readback(self, device_id: str) -> str | None:
        result = await asyncio.to_thread(self._chain.active_anchor_epoch_id, device_id)
        return str(result) if result is not None else None
