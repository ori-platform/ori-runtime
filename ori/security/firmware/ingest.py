# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Ingestion gate for device-signed firmware telemetry.

Binds the pure verification core (:mod:`ori.security.firmware.telemetry`)
to the state store's device registry, and converts accepted envelopes
into :class:`~ori.network.events.SensorReading` objects.

Trust boundary rules enforced here:

* A failed verification never becomes a ``SensorReading`` — the result
  carries the contract error code for fault handling and audit.
* The freshness high-water mark advances through the store's guarded
  UPDATE; if a concurrent writer got there first, the message is
  reported as ``sequence_replay`` even though its signature verified.
* The advance is bound to the anchor the message was verified against.
  If a promotion, rotation or re-registration moved the anchor in
  between, the message is verified again against the anchor now held.
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
from typing import Any, Callable, TypeVar

from ori.network.events import SensorReading
from ori.security.firmware.telemetry import (
    ERR_BOOT_ROLLBACK,
    ERR_DEVICE_NOT_APPROVED,
    ERR_DEVICE_REVOKED,
    ERR_KEY_CHANGE_REQUIRES_REPROVISIONING,
    ERR_KEY_EPOCH_REUSED,
    ERR_SAME_KEY_NOT_A_ROTATION,
    ERR_SEQUENCE_REPLAY,
    ERR_UNKNOWN_DEVICE,
    ERR_UPTIME_REGRESSION,
    GRADE_REJECTED,
    MANIFEST_POLICY_REVISION,
    FirmwareFaultVerification,
    FirmwareVerificationError,
    TelemetryVerification,
    canonical_json_bytes,
    manifest_channel_map,
    validate_manifest_policy,
    verify_fault_message,
    verify_manifest_message,
    verify_telemetry_message,
)
from ori.state.store import FIRMWARE_ANCHOR_COLUMNS

logger = logging.getLogger(__name__)

__all__ = ["FirmwareTelemetryGate"]

ERR_ANCHOR_MISSING = "anchor_missing"
# Verifies against the current anchor, but the anchor moved under every advance.
ERR_ANCHOR_UNSTABLE = "anchor_unstable"

# Advances one message may lose to an anchor moving under it.
_MAX_LOST_ADVANCES = 3

_V = TypeVar("_V", TelemetryVerification, FirmwareFaultVerification)


def _now_ms() -> int:
    return int(time.time() * 1000)


class FirmwareTelemetryGate:
    """Registry-backed verification of firmware telemetry messages."""

    def __init__(self, store: Any) -> None:
        self._store = store
        self._manifest_policy: dict[tuple[str, str, str], tuple[str, str] | None] = {}

    def _stored_manifest_refusal(
        self, device_id: str, capability_hash: str, manifest: Any
    ) -> tuple[str, str] | None:
        """Why a stored manifest fails the current manifest rules, if it does.

        Decided once per anchor and rule revision: the manifest is pinned by the
        capability hash, so the answer cannot change while both stay the same.
        """
        key = (device_id, capability_hash, MANIFEST_POLICY_REVISION)
        if key in self._manifest_policy:
            return self._manifest_policy[key]
        refusal: tuple[str, str] | None = None
        try:
            validate_manifest_policy(manifest)
        except FirmwareVerificationError as exc:
            refusal = (
                exc.code,
                f"stored manifest fails {MANIFEST_POLICY_REVISION}: {exc.detail}; "
                "re-register the device",
            )
        self._manifest_policy[key] = refusal
        return refusal

    async def _freshness_refusal(self, verification: Any) -> tuple[str, str]:
        """The reason a message lost the atomic advance, read against the new mark."""
        row = await self._store.get_firmware_device(verification.device_id)
        if row is not None:
            if row["revoked"]:
                return ERR_DEVICE_REVOKED, "device was revoked before the advance"
            if not row["approved"]:
                return ERR_DEVICE_NOT_APPROVED, "device is not approved"
            boot_id = int(row["last_boot_id"])
            last_uptime = row["last_uptime_ms"]
            if verification.boot_id < boot_id:
                return ERR_BOOT_ROLLBACK, (
                    f"boot_id {verification.boot_id} < {boot_id}"
                )
            if (
                verification.boot_id == boot_id
                and verification.seq > int(row["last_seq"])
                and last_uptime is not None
                and verification.device_uptime_ms < last_uptime
            ):
                return ERR_UPTIME_REGRESSION, (
                    f"device_uptime_ms {verification.device_uptime_ms} < "
                    f"{last_uptime} within boot {boot_id}"
                )
        return ERR_SEQUENCE_REPLAY, "high-water mark advanced by a newer message"

    async def _verify_and_advance(
        self,
        device_id: str,
        verify: Callable[[dict[str, Any]], _V],
        rejected: Callable[[str, str], _V],
        record: Callable[[_V, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> tuple[_V, dict[str, Any] | None]:
        """Verify against the stored anchor and advance freshness under it.

        Returns the verification and, when it was accepted and the mark
        advanced, the row it was verified against. A `record` builds the
        fault row committed in the advance's own transaction.
        """
        row = await self._store.get_firmware_device(device_id) if device_id else None
        attempts = 0
        while True:
            if row is None:
                return rejected(
                    ERR_ANCHOR_MISSING, "no provisioning anchor for device"
                ), None
            refusal = self._stored_manifest_refusal(
                str(row["device_id"]), str(row["capability_hash"]), row.get("manifest")
            )
            if refusal is not None:
                return rejected(*refusal), None
            verification = verify(row)
            if not verification.accepted:
                return verification, None
            if attempts >= _MAX_LOST_ADVANCES:
                return rejected(
                    ERR_ANCHOR_UNSTABLE,
                    f"the anchor changed under each of {attempts} advances",
                ), None
            extra: dict[str, Any] = {}
            if record is not None:
                extra["fault_event"] = record(verification, row)
            if await self._store.advance_firmware_freshness(
                verification.device_id,
                boot_id=verification.boot_id,
                seq=verification.seq,
                uptime_ms=verification.device_uptime_ms,
                verified_against=row,
                **extra,
            ):
                return verification, row
            attempts += 1
            current = await self._store.get_firmware_device(device_id)
            if current is not None and all(
                current[column] == row[column] for column in FIRMWARE_ANCHOR_COLUMNS
            ):
                # The mark moved: the message is refused against the mark it
                # now faces, under that reason.
                code, detail = await self._freshness_refusal(verification)
                return rejected(code, detail), None
            row = current

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
        if outcome == "refused_key_change":
            raise FirmwareVerificationError(
                ERR_KEY_CHANGE_REQUIRES_REPROVISIONING,
                f"device {device_id!r} presented a different public key; a key "
                "change requires an explicit re-provisioning transaction with "
                "independent identity confirmation",
            )

        if outcome == "pending_manifest_epoch":
            logger.info(
                "firmware device %r published a new manifest epoch; stored as a "
                "PENDING candidate awaiting promotion (the active anchor is "
                "unchanged)",
                device_id,
            )
        elif outcome == "unchanged":
            logger.debug(
                "firmware device %r re-published an identical anchor (no-op)",
                device_id,
            )
        else:
            logger.info(
                "firmware device %r provisioned (posture=%s, awaiting approval)",
                device_id,
                posture,
            )
        return manifest_hash

    async def approve_device(
        self,
        device_id: str,
        *,
        actor: str,
        reason: str,
        expected_anchor_epoch_id: str | None = None,
    ) -> bool:
        """Promote the pending anchor to active.

        `actor` and `reason` are mandatory: promotion is a trust
        transition, and ori-specs/device-provisioning/v1.md requires every
        one to be attributed. The pending candidate is the anchor checked
        against the current manifest rules, and the store promotes only that
        candidate: one replaced in between is not promoted. A caller that
        confirmed a particular candidate names it in `expected_anchor_epoch_id`.
        """
        pending = await self._store.get_pending_firmware_anchor(device_id)
        if pending is None:
            return False
        if (
            expected_anchor_epoch_id is not None
            and pending["anchor_epoch_id"] != expected_anchor_epoch_id
        ):
            return False
        try:
            manifest = json.loads(pending["manifest_json"])
        except (TypeError, ValueError):
            manifest = None
        refusal = self._stored_manifest_refusal(
            device_id, str(pending["capability_hash"]), manifest
        )
        if refusal is not None:
            raise FirmwareVerificationError(*refusal)
        return bool(
            await self._store.approve_firmware_device(
                device_id,
                actor=actor,
                reason=reason,
                expected_anchor_epoch_id=str(pending["anchor_epoch_id"]),
            )
        )

    async def revoke_device(self, device_id: str, *, actor: str, reason: str) -> bool:
        """Take an identity out of service. Attribution is mandatory."""
        return bool(
            await self._store.revoke_firmware_device(
                device_id, actor=actor, reason=reason
            )
        )

    async def reinstate_device(
        self, device_id: str, *, actor: str, reason: str
    ) -> bool:
        """Return a revoked identity to service.

        Clears the revoked flag and returns the retained anchor to
        **pending**. It activates nothing: promotion stays a separate,
        separately audited act.
        """
        return bool(
            await self._store.reinstate_firmware_device(
                device_id, actor=actor, reason=reason
            )
        )

    async def reprovision_device(
        self,
        *,
        device_id: str,
        public_key_b64: str,
        posture: str,
        manifest_message: dict[str, Any],
        actor: str,
        reason: str,
        board_profile: str = "",
    ) -> str:
        """Accept a NEW key for an existing identity.

        Ordinary registration refuses a changed key because a self-signed
        manifest proves consistency, never provenance. This is the
        deliberate path, and the caller is responsible for having
        confirmed the device identity independently of the manifest.

        Stores the new-key anchor as pending; the previously active anchor
        stays active until promotion.
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
        outcome = await self._store.reprovision_firmware_device(
            device_id=device_id,
            public_key_b64=public_key_b64,
            posture=posture,
            capability_hash=manifest_hash,
            manifest_json=canonical_json_bytes(manifest).decode("utf-8"),
            channel_map_json=json.dumps(
                channel_map,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ),
            board_profile=str(manifest.get("board_profile", board_profile)),
            actor=actor,
            reason=reason,
        )
        if outcome == "unknown_device":
            raise FirmwareVerificationError(
                ERR_UNKNOWN_DEVICE, f"cannot re-provision unknown device {device_id!r}"
            )
        if outcome == "revoked":
            raise FirmwareVerificationError(
                ERR_DEVICE_REVOKED,
                f"device {device_id!r} is revoked; reinstate it first, or it "
                "would return to service without anyone saying so",
            )
        if outcome == "refused_same_key":
            raise FirmwareVerificationError(
                ERR_SAME_KEY_NOT_A_ROTATION,
                f"device {device_id!r} submitted its CURRENT key; re-provisioning "
                "replaces a key, and accepting this would move the active anchor "
                "back to pending while the registry still trusted it",
            )
        if outcome == "refused_key_reuse":
            raise FirmwareVerificationError(
                ERR_KEY_EPOCH_REUSED,
                f"device {device_id!r} has used that key before. An old key may "
                "be the one rotated away from because it was compromised, so "
                "returning to it would make rotation reversible",
            )
        logger.info(
            "firmware device %r re-provisioned with a new key; pending promotion",
            device_id,
        )
        return manifest_hash

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

        def verify(row: dict[str, Any]) -> TelemetryVerification:
            return verify_telemetry_message(
                message,
                anchor_device_id=row["device_id"],
                anchor_public_key_b64=row["public_key_b64"],
                anchor_posture=row["posture"],
                accepted_manifest_hash=row["capability_hash"],
                last_boot_id=row["last_boot_id"],
                last_seq=row["last_seq"],
                last_uptime_ms=row["last_uptime_ms"],
                approved=row["approved"],
                revoked=row["revoked"],
                accepted_channels=row["channel_map"],
            )

        def rejected(code: str, detail: str) -> TelemetryVerification:
            return TelemetryVerification(
                grade=GRADE_REJECTED,
                device_id=device_id,
                error_code=code,
                error_detail=detail,
            )

        verification, row = await self._verify_and_advance(device_id, verify, rejected)
        if row is None:
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

        def verify(row: dict[str, Any]) -> FirmwareFaultVerification:
            return verify_fault_message(
                message,
                anchor_device_id=row["device_id"],
                anchor_public_key_b64=row["public_key_b64"],
                anchor_posture=row["posture"],
                accepted_manifest_hash=row["capability_hash"],
                last_boot_id=row["last_boot_id"],
                last_seq=row["last_seq"],
                last_uptime_ms=row["last_uptime_ms"],
                approved=row["approved"],
                revoked=row["revoked"],
            )

        def rejected(code: str, detail: str) -> FirmwareFaultVerification:
            return FirmwareFaultVerification(
                grade=GRADE_REJECTED,
                device_id=device_id,
                error_code=code,
                error_detail=detail,
            )

        def record(
            verification: FirmwareFaultVerification, row: dict[str, Any]
        ) -> dict[str, Any]:
            return {
                "grade": verification.grade,
                "posture": verification.posture,
                "capability_hash": row["capability_hash"],
                "code": verification.code,
                "subject": verification.subject,
                "detail": verification.detail,
                "device_uptime_ms": verification.device_uptime_ms,
                "received_at_ms": received,
                "fault_json": canonical_json_bytes(fault).decode("utf-8")
                if isinstance(fault, dict)
                else "{}",
            }

        verification, row = await self._verify_and_advance(
            device_id, verify, rejected, record
        )
        if row is None:
            self._log_fault_rejection(verification)
            return verification

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
