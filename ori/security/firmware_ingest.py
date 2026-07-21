# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Ingestion gate for device-signed firmware telemetry.

Binds the pure verification core (:mod:`ori.security.firmware_telemetry`)
to the state store's device registry, and converts accepted envelopes
into :class:`~ori.network.events.SensorReading` objects.

Trust boundary rules enforced here:

* A failed verification never becomes a ``SensorReading`` — the result
  carries the contract error code for fault handling and audit.
* The freshness high-water mark advances through the store's guarded
  UPDATE; if a concurrent writer got there first, the message is
  reported as ``sequence_replay`` even though its signature verified.
* Heartbeat envelopes advance freshness and liveness but produce no
  readings and must never reach reasoning or actions.
* The device claims order and origin; the runtime claims time. Reading
  timestamps are the trusted receipt time, and the device's advisory
  ``emitted_at_ms`` and uptime ride along in metadata, clearly labelled.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from ori.network.events import SensorReading
from ori.security.firmware_telemetry import (
    ERR_DEVICE_REVOKED,
    ERR_KEY_CHANGE_REQUIRES_REPROVISIONING,
    ERR_MANIFEST_EPOCH_UNSUPPORTED,
    ERR_SEQUENCE_REPLAY,
    GRADE_REJECTED,
    FirmwareFaultVerification,
    FirmwareVerificationError,
    TelemetryVerification,
    canonical_json_bytes,
    manifest_channel_map,
    verify_fault_message,
    verify_manifest_message,
    verify_telemetry_message,
)

logger = logging.getLogger(__name__)

__all__ = ["FirmwareTelemetryGate"]

ERR_ANCHOR_MISSING = "anchor_missing"


def _now_ms() -> int:
    return int(time.time() * 1000)


class FirmwareTelemetryGate:
    """Registry-backed verification of firmware telemetry messages."""

    def __init__(self, store: Any) -> None:
        self._store = store

    async def register_device(
        self,
        *,
        device_id: str,
        public_key_b64: str,
        posture: str,
        manifest_message: dict[str, Any],
        board_profile: str = "",
    ) -> str:
        """Provision a device anchor from its signed capability manifest.

        Verifies the manifest against the supplied anchor identity and
        stores the anchor with its pinned capability hash, unapproved:
        telemetry is not accepted until an operator approves. Returns
        the pinned ``sha256:<hex>`` capability hash. Raises
        :class:`FirmwareVerificationError` on any mismatch.
        """
        manifest_hash = verify_manifest_message(
            manifest_message,
            anchor_device_id=device_id,
            anchor_public_key_b64=public_key_b64,
        )
        manifest = manifest_message["manifest"]
        if manifest.get("posture") != posture:
            raise FirmwareVerificationError(
                "invalid_posture",
                "manifest posture does not match provisioning posture",
            )
        channel_map = manifest_channel_map(manifest)
        outcome = await self._store.upsert_firmware_device_anchor(
            device_id=device_id,
            public_key_b64=public_key_b64,
            posture=posture,
            capability_hash=manifest_hash,
            board_profile=str(manifest.get("board_profile", board_profile)),
            manifest_json=canonical_json_bytes(manifest).decode("utf-8"),
            channel_map_json=json.dumps(
                channel_map,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ),
        )

        # ori-specs/device-provisioning/v1.md. Registration may refuse; it
        # never silently overwrites an anchor or clears a revocation.
        if outcome == "refused_revoked":
            raise FirmwareVerificationError(
                ERR_DEVICE_REVOKED,
                f"device {device_id!r} is revoked; reinstatement is an explicit "
                "operation, never a side effect of registration",
            )
        if outcome == "refused_manifest_epoch_unsupported":
            raise FirmwareVerificationError(
                ERR_MANIFEST_EPOCH_UNSUPPORTED,
                f"device {device_id!r} published a new capability hash under its "
                "existing key. The lifecycle requires this to become a pending "
                "candidate beside the active anchor; that state model is not "
                "implemented yet, so it is refused rather than overwriting the "
                "active anchor.",
            )
        if outcome == "refused_key_change":
            raise FirmwareVerificationError(
                ERR_KEY_CHANGE_REQUIRES_REPROVISIONING,
                f"device {device_id!r} presented a different public key; a key "
                "change requires an explicit re-provisioning transaction with "
                "independent identity confirmation",
            )

        if outcome == "unchanged":
            logger.debug(
                "firmware device %s re-published an identical anchor (no-op)",
                device_id,
            )
        else:
            logger.info(
                "firmware device %s provisioned (posture=%s, awaiting approval)",
                device_id,
                posture,
            )
        return manifest_hash

    async def approve_device(self, device_id: str) -> bool:
        """Operator approval for the currently stored verified anchor."""
        return bool(await self._store.approve_firmware_device(device_id))

    async def revoke_device(self, device_id: str) -> bool:
        return bool(await self._store.revoke_firmware_device(device_id))

    async def ingest(
        self,
        message: dict[str, Any],
        *,
        received_at_ms: int | None = None,
    ) -> tuple[TelemetryVerification, list[SensorReading]]:
        """Verify one telemetry message and, when accepted, return the
        trusted-time-stamped readings. Rejections return an empty
        reading list and the contract error code on the verification.
        """
        received = received_at_ms if received_at_ms is not None else _now_ms()

        envelope = message.get("envelope") if isinstance(message, dict) else None
        device_id = ""
        if isinstance(envelope, dict) and isinstance(envelope.get("device_id"), str):
            device_id = envelope["device_id"]

        row = await self._store.get_firmware_device(device_id) if device_id else None
        if row is None:
            verification = TelemetryVerification(
                grade=GRADE_REJECTED,
                device_id=device_id,
                error_code=ERR_ANCHOR_MISSING,
                error_detail="no provisioning anchor for device",
            )
            self._log_rejection(verification)
            return verification, []

        verification = verify_telemetry_message(
            message,
            anchor_device_id=row["device_id"],
            anchor_public_key_b64=row["public_key_b64"],
            anchor_posture=row["posture"],
            accepted_manifest_hash=row["capability_hash"],
            last_boot_id=row["last_boot_id"],
            last_seq=row["last_seq"],
            approved=row["approved"],
            revoked=row["revoked"],
            accepted_channels=row["channel_map"],
        )
        if not verification.accepted:
            self._log_rejection(verification)
            return verification, []

        advanced = await self._store.advance_firmware_freshness(
            verification.device_id,
            boot_id=verification.boot_id,
            seq=verification.seq,
        )
        if not advanced:
            # A concurrent writer advanced the mark first: this message
            # is a replay/duplicate no matter what its signature says.
            verification = TelemetryVerification(
                grade=GRADE_REJECTED,
                device_id=verification.device_id,
                error_code=ERR_SEQUENCE_REPLAY,
                error_detail="high-water mark advanced by a newer message",
            )
            self._log_rejection(verification)
            return verification, []

        if verification.is_heartbeat:
            # Liveness/posture/freshness proof only: no readings, no
            # reasoning, no actions.
            return verification, []

        emitted_at = None
        if isinstance(envelope, dict):
            emitted_at = envelope.get("emitted_at_ms")
        readings = [
            SensorReading(
                sensor_id=f"{verification.device_id}:{reading['channel']}",
                sensor_type=reading["sensor_type"],
                value=reading["value"],
                unit=reading["unit"],
                timestamp=received,
                quality=reading["quality"],
                metadata={
                    "source": "firmware",
                    "attestation": verification.grade,
                    "posture": verification.posture,
                    "firmware_device_id": verification.device_id,
                    "boot_id": verification.boot_id,
                    "seq": verification.seq,
                    "capability_hash": row["capability_hash"],
                    "device_uptime_ms": verification.device_uptime_ms,
                    # Advisory only; never a freshness or ordering proof.
                    "device_emitted_at_ms": emitted_at,
                },
            )
            for reading in verification.readings
        ]
        return verification, readings

    async def ingest_fault(
        self,
        message: dict[str, Any],
        *,
        received_at_ms: int | None = None,
    ) -> FirmwareFaultVerification:
        """Verify and durably record one signed firmware fault event.

        Fault events consume the same device freshness stream as
        telemetry, but they must never become ``SensorReading`` objects
        and must never trigger runtime actions.
        """
        received = received_at_ms if received_at_ms is not None else _now_ms()

        fault = message.get("fault") if isinstance(message, dict) else None
        device_id = ""
        if isinstance(fault, dict) and isinstance(fault.get("device_id"), str):
            device_id = fault["device_id"]

        row = await self._store.get_firmware_device(device_id) if device_id else None
        if row is None:
            verification = FirmwareFaultVerification(
                grade=GRADE_REJECTED,
                device_id=device_id,
                error_code=ERR_ANCHOR_MISSING,
                error_detail="no provisioning anchor for device",
            )
            self._log_fault_rejection(verification)
            return verification

        verification = verify_fault_message(
            message,
            anchor_device_id=row["device_id"],
            anchor_public_key_b64=row["public_key_b64"],
            anchor_posture=row["posture"],
            accepted_manifest_hash=row["capability_hash"],
            last_boot_id=row["last_boot_id"],
            last_seq=row["last_seq"],
            approved=row["approved"],
            revoked=row["revoked"],
        )
        if not verification.accepted:
            self._log_fault_rejection(verification)
            return verification

        advanced = await self._store.advance_firmware_freshness(
            verification.device_id,
            boot_id=verification.boot_id,
            seq=verification.seq,
        )
        if not advanced:
            verification = FirmwareFaultVerification(
                grade=GRADE_REJECTED,
                device_id=verification.device_id,
                error_code=ERR_SEQUENCE_REPLAY,
                error_detail="high-water mark advanced by a newer message",
            )
            self._log_fault_rejection(verification)
            return verification

        await self._store.append_firmware_fault_event(
            device_id=verification.device_id,
            boot_id=verification.boot_id,
            seq=verification.seq,
            grade=verification.grade,
            posture=verification.posture,
            capability_hash=row["capability_hash"],
            code=verification.code,
            subject=verification.subject,
            detail=verification.detail,
            device_uptime_ms=verification.device_uptime_ms,
            received_at_ms=received,
            fault_json=canonical_json_bytes(fault).decode("utf-8")
            if isinstance(fault, dict)
            else "{}",
        )
        logger.warning(
            "firmware fault accepted: device=%s code=%s subject=%s detail=%s",
            verification.device_id,
            verification.code,
            verification.subject or "<none>",
            verification.detail or "<none>",
        )
        return verification

    @staticmethod
    def _log_rejection(verification: TelemetryVerification) -> None:
        # Auditable, never silently downgraded to a low-quality reading.
        logger.warning(
            "firmware telemetry rejected: device=%s code=%s detail=%s",
            verification.device_id or "<unknown>",
            verification.error_code,
            verification.error_detail,
        )

    @staticmethod
    def _log_fault_rejection(verification: FirmwareFaultVerification) -> None:
        logger.warning(
            "firmware fault rejected: device=%s code=%s detail=%s",
            verification.device_id or "<unknown>",
            verification.error_code,
            verification.error_detail,
        )
