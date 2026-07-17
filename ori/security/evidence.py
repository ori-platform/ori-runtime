# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""On-device evidence signing for Tier C/D actions.

The runtime consumes a private evidence-chain artifact as an exactly pinned,
prebuilt dependency (see DECISIONS.md 2026-07-10). This module is the only
runtime boundary to it: a lazy import of the configured extension module,
wrapped so that

* a deployment without the artifact degrades to ``available = False``
  with a WARNING — evidence signing never blocks the action path;
* every chain call runs on one dedicated thread, because the pyo3
  chain class is not sendable between threads;
* signing failures mark the action_log row ``failed`` and are repaired
  by startup reconciliation where possible (Option B append-after-log —
  explicitly weaker than single-transaction atomicity, which remains the
  verifier-grade target).

Late-signing semantics (be precise — verifiers will be adversarial):
an action that fires while signing is unavailable stays visible as a gap
(``attestation_status`` ``pending``/``failed``). Startup reconciliation
may sign it late, and when it does, the lateness is explicit twice over:
the signed payload carries ``attestation: reconciled_late`` (versus
``at_emission`` on the normal path) and the chain independently records
the write time next to the original ``emitted_at_ms``. Rows that still
cannot be signed remain ``failed`` and visible. The runtime never
presents late evidence as emission-time evidence.

Idempotency: every attestation derives a deterministic ``event_id`` from
(device_id, action_log id), which is UNIQUE in the chain schema. The
attestor looks the id up before appending, so a crash between the chain
append and the action_log status update cannot double-attest on retry.

Artifact identity: the pin itself is enforced by deployment packaging
(the offline wheelhouse installs an exact version — the runtime cannot
verify provenance of an already-importable module). What the runtime
does verify at startup is that the loaded artifact speaks the expected
``PROTOCOL_VERSION`` and exposes the idempotent append surface; on
mismatch, evidence stays unavailable and health says so, alongside the
loaded ``ARTIFACT_VERSION``.

Event vocabulary: artifacts >= 0.2.0 provide the dedicated
``SAFETY_ACTION_EXECUTED`` event type and new attestations use it.
Older artifacts (or unparseable versions) fall back to
``MAINTENANCE_PERFORMED`` with the same fully descriptive payload
(``kind: runtime_action``) — the form all pre-0.2.0 chains carry.
Verifiers must accept both forms (ori-specs ``evidence/v1.md``).
"""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import logging
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

logger = logging.getLogger(__name__)

_ATTESTED_TIERS = ("C", "D")
_INPUT_ATTESTATION_GRADES = frozenset({"attested", "attested_dev", "unattested"})
_INPUT_POSTURES = frozenset({"development", "sealed_flash", "hardware_key"})

DEFAULT_PROTOCOL_VERSION = "evidence.v1"

SAFETY_ACTION_EVENT_TYPE = "SAFETY_ACTION_EXECUTED"
LEGACY_ACTION_EVENT_TYPE = "MAINTENANCE_PERFORMED"
# First artifact version whose event vocabulary includes the dedicated
# safety-action type.
_SAFETY_EVENT_MIN_ARTIFACT = (0, 2, 0)
# 0.3.0 exposed append_event_with_freshness, but 0.4.0 is the first
# Python FFI artifact that also exposes Layer 1 device registry seeding.
_ATOMIC_FRESHNESS_MIN_ARTIFACT = (0, 4, 0)


def expected_protocol_version() -> str:
    """Protocol version expected from the configured private artifact."""
    return (
        os.environ.get("ORI_EVIDENCE_ARTIFACT_PROTOCOL_VERSION", "").strip()
        or DEFAULT_PROTOCOL_VERSION
    )


def _artifact_module_name() -> str:
    """Import name for the configured private evidence-chain artifact."""
    module_name = os.environ.get("ORI_EVIDENCE_ARTIFACT_MODULE", "").strip()
    if not module_name:
        raise ImportError("private evidence artifact module is not configured")
    if module_name.startswith(".") or any(
        part == "" for part in module_name.split(".")
    ):
        raise ImportError("private evidence artifact module name is invalid")
    for part in module_name.split("."):
        if not part.replace("_", "").isalnum() or part[0].isdigit():
            raise ImportError("private evidence artifact module name is invalid")
    return module_name


def _artifact_chain_class_name() -> str:
    """Class name for the configured private evidence-chain artifact."""
    class_name = os.environ.get("ORI_EVIDENCE_ARTIFACT_CLASS", "").strip()
    if not class_name:
        return "EvidenceChain"
    if not class_name.replace("_", "").isalnum() or class_name[0].isdigit():
        raise ImportError("private evidence artifact chain class name is invalid")
    return class_name


def _normalise_input_evidence(grade_value: Any, posture_value: Any) -> tuple[str, str]:
    """Return a verifier-safe input grade/posture pair for action payloads."""
    grade = str(grade_value or "").strip().lower()
    posture = str(posture_value or "").strip().lower()
    if grade not in _INPUT_ATTESTATION_GRADES:
        return "unattested", ""
    if grade == "unattested":
        return "unattested", ""
    if grade == "attested_dev":
        if posture in _INPUT_POSTURES and posture == "development":
            return "attested_dev", "development"
        return "unattested", ""
    if posture in _INPUT_POSTURES and posture != "development":
        return "attested", posture
    return "unattested", ""


# Fixed namespace for deterministic attestation event ids. Never change:
# ids derived from it are the idempotency keys of already-signed evidence.
_ATTESTATION_EVENT_NAMESPACE = uuid.UUID("6f726920-7665-5269-7479-2065766e7431")


def tier_requires_attestation(tier: str) -> bool:
    """True when *tier* is on the evidence-signing path (Tier C/D)."""
    return str(tier or "").upper() in _ATTESTED_TIERS


def _artifact_supports_safety_event(artifact_version: str) -> bool:
    """True when *artifact_version* provides ``SAFETY_ACTION_EXECUTED``.

    Conservative on anything unparseable: the legacy event type is the
    one every artifact accepts, so a version we cannot read must not
    select the new vocabulary.
    """
    parts = str(artifact_version or "").split(".")
    if len(parts) < 3:
        return False
    try:
        parsed = tuple(int(p) for p in parts[:3])
    except ValueError:
        return False
    return parsed >= _SAFETY_EVENT_MIN_ARTIFACT


def _artifact_supports_atomic_freshness(artifact_version: str) -> bool:
    """True when *artifact_version* exposes atomic Layer 1 freshness append."""
    parts = str(artifact_version or "").split(".")
    if len(parts) < 3:
        return False
    try:
        parsed = tuple(int(p) for p in parts[:3])
    except ValueError:
        return False
    return parsed >= _ATOMIC_FRESHNESS_MIN_ARTIFACT


def _firmware_freshness_source(action_row: dict) -> tuple[str, int, int] | None:
    """Return Layer 1 source freshness for this row, when safely present."""
    source_device_id = str(action_row.get("input_firmware_device_id", "") or "").strip()
    try:
        boot_id = int(action_row.get("input_firmware_boot_id", 0) or 0)
        seq = int(action_row.get("input_firmware_seq", 0) or 0)
    except (TypeError, ValueError):
        return None
    if not source_device_id or boot_id <= 0 or seq <= 0:
        return None
    return source_device_id, boot_id, seq


def _public_key_b64_to_hex(value: Any) -> str:
    raw = base64.b64decode(str(value or ""), validate=True)
    if len(raw) != 32:
        raise ValueError("Layer 1 public key must decode to 32 bytes")
    return raw.hex()


class EvidenceAttestor:
    """Signs Tier C/D action evidence into the local evidence chain."""

    def __init__(
        self,
        *,
        db_path: str,
        key_path: str,
        device_secret: str,
        device_id: str,
    ) -> None:
        self._db_path = str(db_path)
        self._key_path = str(key_path)
        self._device_secret = str(device_secret)
        self._device_id = str(device_id)
        self._chain: Any = None
        # The pyo3 chain object is unsendable: it must be constructed and
        # used on the same thread. One dedicated worker guarantees that.
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="ori-evidence"
        )
        self._public_key_hex = ""
        self._artifact_version = ""
        self._protocol_version = ""
        self._action_event_type = LEGACY_ACTION_EVENT_TYPE
        self._atomic_freshness_available = False

    @property
    def available(self) -> bool:
        return self._chain is not None

    @property
    def public_key_hex(self) -> str:
        """Device verification anchor (register off-device at provisioning)."""
        return self._public_key_hex

    @property
    def artifact_version(self) -> str:
        """Version of the loaded evidence artifact ('' when unavailable)."""
        return self._artifact_version

    @property
    def protocol_version(self) -> str:
        """Protocol version declared by the loaded artifact."""
        return self._protocol_version

    @property
    def action_event_type(self) -> str:
        """Chain event type used for new Tier C/D attestations."""
        return self._action_event_type

    @property
    def atomic_freshness_available(self) -> bool:
        """Whether the loaded artifact can atomically bind Layer 1 freshness."""
        return self._atomic_freshness_available

    async def start(self) -> bool:
        """Open (or create) the chain and key on the evidence thread.

        First start on a device is key provisioning: the Ed25519 device key
        is generated and sealed at ``key_path``, and the public anchor is
        logged so the provisioning flow can register it off-device.
        """
        loop = asyncio.get_running_loop()
        # The chain lives in this single-slot holder, never in a bare
        # local: on any rejection path the holder is handed whole to
        # _release_chain(), so no frame keeps a reference that would make
        # the unsendable pyo3 object drop on the wrong thread.
        holder: list[Any] = [None]
        try:
            holder[0] = await loop.run_in_executor(self._executor, self._open_sync)
            self._public_key_hex = await loop.run_in_executor(
                self._executor, holder[0].public_key_hex
            )
        except Exception:
            self._chain = None
            logger.warning(
                "[evidence] private evidence chain unavailable; Tier C/D actions will be "
                "recorded as attestation gaps until signing is restored.",
                exc_info=True,
            )
            self._release_chain(holder)
            return False
        required = ("seq_for_event_id", "append_event")
        protocol_version = expected_protocol_version()
        if self._protocol_version != protocol_version or not all(
            hasattr(holder[0], name) for name in required
        ):
            logger.warning(
                "[evidence] loaded evidence artifact (version=%r, protocol=%r) "
                "does not provide protocol %s with idempotent appends; evidence "
                "signing stays unavailable — check the pinned artifact.",
                self._artifact_version,
                self._protocol_version,
                protocol_version,
            )
            self._release_chain(holder)
            return False
        self._action_event_type = (
            SAFETY_ACTION_EVENT_TYPE
            if _artifact_supports_safety_event(self._artifact_version)
            else LEGACY_ACTION_EVENT_TYPE
        )
        self._atomic_freshness_available = bool(
            _artifact_supports_atomic_freshness(self._artifact_version)
            and hasattr(holder[0], "append_event_with_freshness")
            and hasattr(holder[0], "register_layer1_device")
            and hasattr(holder[0], "registered_layer1_device")
        )
        self._chain = holder.pop()
        logger.warning(
            "[evidence] chain open db=%s artifact=%s — REGISTER this device "
            "verification anchor off-device at provisioning: %s",
            self._db_path,
            self._artifact_version,
            self._public_key_hex,
        )
        return True

    def _open_sync(self) -> Any:
        # The exact pin is enforced by deployment packaging (offline
        # wheelhouse); the runtime verifies protocol identity in start().
        # The artifact is optional and absent from dev/CI environments, so
        # static analyzers cannot resolve it — that is expected.
        artifact = importlib.import_module(_artifact_module_name())

        self._protocol_version = str(getattr(artifact, "PROTOCOL_VERSION", ""))
        self._artifact_version = str(getattr(artifact, "ARTIFACT_VERSION", ""))
        chain_class = getattr(artifact, _artifact_chain_class_name())
        return chain_class(self._db_path, self._key_path, self._device_secret)

    def attestation_event_id(self, action_log_id: int) -> str:
        """Deterministic idempotency key for one action_log row."""
        return str(
            uuid.uuid5(
                _ATTESTATION_EVENT_NAMESPACE,
                f"{self._device_id}:action_log:{int(action_log_id)}",
            )
        )

    async def attest_action(
        self, action_row: dict, *, reconciled: bool = False
    ) -> int | None:
        """Sign one action_log row into the chain; return the chain seq.

        Idempotent: the deterministic event id is looked up first, so
        retrying a row whose append succeeded but whose status update was
        lost returns the existing seq instead of double-attesting.
        ``reconciled=True`` marks the signed payload as late evidence.

        Returns None (and logs) on failure — callers mark the row
        ``failed`` and leave repair to reconciliation.
        """
        if self._chain is None:
            return None
        action_log_id = int(action_row.get("id", 0))
        event_id = self.attestation_event_id(action_log_id)
        input_attestation_grade, input_posture = _normalise_input_evidence(
            action_row.get("input_attestation_grade", "unattested"),
            action_row.get("input_posture", ""),
        )
        payload = {
            "kind": "runtime_action",
            "attestation": "reconciled_late" if reconciled else "at_emission",
            "action_log_id": action_log_id,
            "action_name": str(action_row.get("action_name", "")),
            "action_tier": str(action_row.get("tier", "")),
            "executed": bool(action_row.get("executed")),
            "approved": action_row.get("approved"),
            "action_taken": str(action_row.get("action_taken", "")),
            "trigger_name": str(action_row.get("trigger_name", "")),
            "proposal_id": str(action_row.get("proposal_id", "") or ""),
            "correlation_id": str(action_row.get("correlation_id", "") or ""),
            "sensor_id": str(action_row.get("sensor_id", "") or ""),
            "input_attestation_grade": input_attestation_grade,
            "input_posture": input_posture,
        }
        freshness_source = _firmware_freshness_source(action_row)
        if freshness_source is not None:
            source_device_id, boot_id, source_seq = freshness_source
            payload["input_firmware_device_id"] = source_device_id
            payload["input_firmware_boot_id"] = boot_id
            payload["input_firmware_seq"] = source_seq
        emitted_at_ms = int(action_row.get("timestamp", 0))
        loop = asyncio.get_running_loop()
        try:
            existing = await loop.run_in_executor(
                self._executor, self._chain.seq_for_event_id, event_id
            )
            if existing is not None:
                return int(existing)
            if self._atomic_freshness_available and freshness_source is not None:
                source_device_id, boot_id, source_seq = freshness_source
                await self._sync_layer1_device_registration(action_row)
                seq = await loop.run_in_executor(
                    self._executor,
                    self._chain.append_event_with_freshness,
                    self._action_event_type,
                    self._device_id,
                    emitted_at_ms,
                    json.dumps(payload),
                    source_device_id,
                    boot_id,
                    source_seq,
                    event_id,
                )
            else:
                seq = await loop.run_in_executor(
                    self._executor,
                    self._chain.append_event,
                    self._action_event_type,
                    self._device_id,
                    emitted_at_ms,
                    json.dumps(payload),
                    event_id,
                )
            return int(seq)
        except Exception:
            logger.warning(
                "[evidence] failed to sign action_log id=%s tier=%s",
                action_row.get("id"),
                action_row.get("tier"),
                exc_info=True,
            )
            return None

    async def _sync_layer1_device_registration(self, action_row: dict) -> None:
        """Ensure the private chain has the source device anchor before atomic append."""
        registration = action_row.get("input_firmware_registration")
        if not isinstance(registration, dict):
            raise ValueError("Layer 1 source device registration is missing")
        source_device_id = str(
            action_row.get("input_firmware_device_id", "") or ""
        ).strip()
        if registration.get("device_id") != source_device_id:
            raise ValueError("Layer 1 source device registration mismatch")
        if not registration.get("approved") or registration.get("revoked"):
            raise ValueError("Layer 1 source device is not approved")

        public_key_hex = _public_key_b64_to_hex(registration.get("public_key_b64"))
        expected = {
            "device_id": source_device_id,
            "public_key": public_key_hex,
            "alg": str(registration.get("alg", "") or ""),
            "posture": str(registration.get("posture", "") or ""),
            "capability_hash": str(registration.get("capability_hash", "") or ""),
            "hardware_profile": str(registration.get("board_profile", "") or ""),
        }
        loop = asyncio.get_running_loop()
        existing = await loop.run_in_executor(
            self._executor,
            self._chain.registered_layer1_device,
            source_device_id,
        )
        if existing is not None:
            for key, value in expected.items():
                if existing.get(key) != value:
                    raise ValueError(f"Layer 1 registry mismatch for {key}")
            if not existing.get("approved") or existing.get("revoked"):
                raise ValueError(
                    "Layer 1 source device is not approved in evidence chain"
                )
            return

        await loop.run_in_executor(
            self._executor,
            self._chain.register_layer1_device,
            source_device_id,
            public_key_hex,
            expected["alg"],
            expected["posture"],
            expected["capability_hash"],
            expected["hardware_profile"],
            int(registration.get("provisioned_at_ms", 0) or 0),
            True,
        )

    async def chain_head_hash(self) -> str | None:
        if self._chain is None:
            return None
        loop = asyncio.get_running_loop()
        try:
            head = await loop.run_in_executor(
                self._executor, self._chain.chain_head_hash
            )
            return str(head) if head else None
        except Exception:
            logger.warning("[evidence] chain head read failed", exc_info=True)
            return None

    async def pending_export_count(self) -> int | None:
        if self._chain is None:
            return None
        loop = asyncio.get_running_loop()
        try:
            return int(
                await loop.run_in_executor(self._executor, self._chain.pending_count)
            )
        except Exception:
            logger.warning("[evidence] pending count read failed", exc_info=True)
            return None

    def _release_chain(self, holder: list) -> None:
        """Drop the chain held in *holder* on the evidence thread.

        The pyo3 chain object is unsendable: its LAST reference must be
        released on the thread that created it, or the extension raises
        at GC time. This must run on EVERY path where a chain object
        exists but is not (or no longer) retained — rejected starts
        included. Callers must MOVE their only reference into *holder*
        (and clear their local) before calling, so the reference cleared
        here on the evidence thread is the final one.
        """
        if not holder or holder[0] is None:
            return
        try:
            self._executor.submit(holder.clear).result(timeout=5)
        except Exception:
            logger.warning(
                "[evidence] chain release on evidence thread failed",
                exc_info=True,
            )

    def close(self) -> None:
        holder = [self._chain]
        self._chain = None
        self._release_chain(holder)
        self._executor.shutdown(wait=False)
