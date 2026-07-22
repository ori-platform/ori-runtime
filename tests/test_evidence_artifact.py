# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""FFI compatibility smoke tests against the real private evidence artifact.

The unit suite in test_evidence.py deliberately runs against a fake
artifact module: absence behaviour and fault injection can only be tested
without the real artifact. What the fake cannot prove is that the runtime
and the real artifact speak the same protocol — a drifted FFI
signature would leave the fake suite green while every deployment fell
back to "evidence unavailable".

This module closes that gap. It auto-skips when the private artifact module is
not importable (dev machines and the main CI matrix), and runs in the
dedicated ``evidence-artifact`` CI job, which builds the wheel from the
private artifact source ref supplied by CI secrets, then checks it
matches the expected private artifact version supplied by CI secrets.
Everything here drives the real EvidenceAttestor against the real chain:
key provisioning, signing, idempotent re-append, atomic Layer 1
freshness binding, late-marking, chain verification against the
provisioned anchor, and restart persistence.
"""

import base64
import importlib
import json
import os
import sqlite3

import pytest

_ARTIFACT_MODULE = os.environ.get("ORI_EVIDENCE_ARTIFACT_MODULE", "").strip()
_CHAIN_TABLE = os.environ.get("ORI_EVIDENCE_ARTIFACT_CHAIN_TABLE", "evidence_chain")
if not _CHAIN_TABLE.replace("_", "").isalnum() or _CHAIN_TABLE[0].isdigit():
    pytest.skip(
        "ORI_EVIDENCE_ARTIFACT_CHAIN_TABLE is not a safe SQL identifier",
        allow_module_level=True,
    )
if not _ARTIFACT_MODULE:
    pytest.skip(
        "ORI_EVIDENCE_ARTIFACT_MODULE is not configured",
        allow_module_level=True,
    )
try:
    evidence_artifact = importlib.import_module(_ARTIFACT_MODULE)
except ImportError:
    pytest.skip("real private evidence artifact not installed", allow_module_level=True)

from ori.security.evidence import (  # noqa: E402
    EvidenceAttestor,
    _artifact_supports_safety_event,
    expected_protocol_version,
)
from ori.security.firmware_confirmation import (  # noqa: E402
    FirmwareConfirmationCoordinator,
)
from ori.state.store import StateStore  # noqa: E402

_FW_DEVICE = "ori-fw-artifact-01"
_FW_PUBLIC_KEY_B64 = base64.b64encode(bytes([0x42]) * 32).decode("ascii")
_FW_CAPABILITY_HASH = (
    "sha256:13751b5335ccedcd4ffcc82bbda28ebfb7558859f36a74e710f1a0b0ab23da8d"
)
_FW_APPROVAL_ACTOR = "uid=0:artifact-smoke"
_FW_APPROVAL_REASON = "ffi smoke provisioning"


def _expected_artifact_version() -> str | None:
    return os.environ.get("ORI_EVIDENCE_ARTIFACT_VERSION")


def _attestor(tmp_path, *, device_secret: str = "install-secret") -> EvidenceAttestor:
    return EvidenceAttestor(
        db_path=str(tmp_path / "evidence.db"),
        key_path=str(tmp_path / "evidence.key"),
        device_secret=device_secret,
        device_id="artifact-smoke-01",
    )


def _tier_d_row(row_id: int) -> dict:
    return {
        "id": row_id,
        "action_name": "emergency_cutoff",
        "tier": "D",
        "executed": True,
        "approved": None,
        "action_taken": "emergency_cutoff",
        "trigger_name": "dangerous_overcurrent",
        "timestamp": 1_760_000_000_000 + row_id,
    }


def _firmware_tier_d_row(row_id: int, registration: dict) -> dict:
    # The registration snapshot is the durable device record the runtime
    # store holds, exactly as the real dispatcher captures it -- so the
    # anchor the coordinator confirmed and the anchor the attestor verifies
    # are the same one.
    row = _tier_d_row(row_id)
    row.update(
        {
            "input_attestation_grade": "attested",
            "input_posture": "sealed_flash",
            "input_firmware_device_id": _FW_DEVICE,
            "input_firmware_boot_id": 7,
            "input_firmware_seq": 11,
            "input_firmware_registration": registration,
        }
    )
    return row


async def _confirm_firmware_anchor(attestor, store) -> dict:
    """Register, approve, and cross-store confirm the smoke firmware device.

    Mirrors production: the coordinator -- not the attestor -- pushes the
    anchor into the real chain and confirms the identical epoch. Returns the
    durable registration snapshot (with approval provenance) the dispatcher
    would attach to the action row.
    """
    await store.upsert_firmware_device_anchor(
        device_id=_FW_DEVICE,
        public_key_b64=_FW_PUBLIC_KEY_B64,
        posture="sealed_flash",
        capability_hash=_FW_CAPABILITY_HASH,
        manifest_json="{}",
        channel_map_json="{}",
        board_profile="esp32-s3-pzem-v1",
        provisioned_at_ms=1_760_000_000_000,
    )
    assert await store.approve_firmware_device(
        _FW_DEVICE, actor=_FW_APPROVAL_ACTOR, reason=_FW_APPROVAL_REASON
    )
    coordinator = FirmwareConfirmationCoordinator(
        store=store, chain=attestor.confirmation_chain()
    )
    # Confirms the runtime and the real evidence store agree on the identical
    # anchor_epoch_id -- the cross-store contract, end to end.
    assert await coordinator.confirm(_FW_DEVICE) == "confirmed"

    registration = dict(await store.get_firmware_device(_FW_DEVICE))
    registration["approval_actor"] = _FW_APPROVAL_ACTOR
    registration["approval_reason"] = _FW_APPROVAL_REASON
    return registration


def _chain_row(db_path: str, seq: int) -> dict:
    # Test-only forensic read; the runtime itself never reads chain SQLite.
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT event_type, device_id, emitted_at_ms, payload_json "
            f"FROM {_CHAIN_TABLE} WHERE seq = ?",
            (seq,),
        ).fetchone()
    assert row is not None, f"chain row seq={seq} missing"
    return dict(row)


def _firmware_chain_row(db_path: str, firmware_device_id: str) -> dict:
    """Locate the signed firmware action event by its payload, not by seq.

    The confirmation coordinator's register-and-promote may itself append
    chain events, so the firmware action's physical seq is not a fixed
    offset. Selecting on the payload keeps the assertion robust to how many
    chain rows the promotion occupies.
    """
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT event_type, device_id, emitted_at_ms, payload_json "
            f"FROM {_CHAIN_TABLE} ORDER BY seq"
        ).fetchall()
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, ValueError):
            continue
        if payload.get("input_firmware_device_id") == firmware_device_id:
            return dict(row)
    layout = [(r["event_type"], r["device_id"]) for r in rows]
    raise AssertionError(
        f"no signed firmware event for {firmware_device_id!r}; chain layout={layout}"
    )


def test_artifact_identity_matches_expected_private_version():
    assert evidence_artifact.PROTOCOL_VERSION == expected_protocol_version()
    expected = _expected_artifact_version()
    if not expected:
        pytest.skip("ORI_EVIDENCE_ARTIFACT_VERSION is not configured")
    assert evidence_artifact.ARTIFACT_VERSION == expected, (
        f"installed artifact {evidence_artifact.ARTIFACT_VERSION!r} does not match "
        f"expected private artifact version {expected!r}"
    )
    # The expected private artifact must be vocabulary-capable; the runtime selects
    # SAFETY_ACTION_EXECUTED from it.
    assert _artifact_supports_safety_event(evidence_artifact.ARTIFACT_VERSION)


@pytest.mark.asyncio
async def test_provisioning_signing_idempotency_and_verification(tmp_path):
    attestor = _attestor(tmp_path)
    try:
        assert await attestor.start() is True
        assert attestor.available is True
        anchor = attestor.public_key_hex
        assert len(anchor) == 64 and int(anchor, 16) >= 0
        assert attestor.action_event_type == "SAFETY_ACTION_EXECUTED"

        seq = await attestor.attest_action(_tier_d_row(1))
        assert seq == 1
        # Idempotent against the real UNIQUE event_id + seq lookup.
        assert await attestor.attest_action(_tier_d_row(1)) == 1

        head = await attestor.chain_head_hash()
        assert head and len(head) == 64
        assert await attestor.pending_export_count() == 1

        row = _chain_row(attestor._db_path, 1)
        assert row["event_type"] == "SAFETY_ACTION_EXECUTED"
        assert row["device_id"] == "artifact-smoke-01"
        assert row["emitted_at_ms"] == 1_760_000_000_001
        payload = json.loads(row["payload_json"])
        assert payload["kind"] == "runtime_action"
        assert payload["attestation"] == "at_emission"
        assert payload["action_tier"] == "D"

        # Late signing is explicit in the real signed payload too.
        assert await attestor.attest_action(_tier_d_row(2), reconciled=True) == 2
        late = json.loads(_chain_row(attestor._db_path, 2)["payload_json"])
        assert late["attestation"] == "reconciled_late"

        assert attestor.atomic_freshness_available is True
        # Firmware-source evidence is signed only after the coordinator
        # confirms the anchor into the real chain; the attestor never
        # promotes it itself.
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        try:
            registration = await _confirm_firmware_anchor(attestor, store)
            pre_count = await attestor.pending_export_count()
            fw_seq = await attestor.attest_action(_firmware_tier_d_row(3, registration))
        finally:
            await store.close()
        # A genuinely new signed event, not an idempotent no-op: the chain's
        # pending-export count advances by exactly one.
        assert fw_seq is not None
        assert await attestor.pending_export_count() == pre_count + 1

        # The whole chain verifies against the provisioned anchor. The pyo3
        # chain is unsendable, so the call must run on the attestor's
        # dedicated evidence thread; it raises on any integrity failure.
        attestor._executor.submit(attestor._chain.verify_chain, anchor).result()
    finally:
        attestor.close()

    # After close, the chain is fully durable and readable from a fresh
    # connection (the real artifact's atomic freshness append is not visible
    # cross-connection while the chain handle is still open). Confirm the
    # firmware action carries the Layer 1 source identity in its signed
    # payload.
    fw_row = _firmware_chain_row(attestor._db_path, "ori-fw-artifact-01")
    assert fw_row["event_type"] == "SAFETY_ACTION_EXECUTED"
    firmware = json.loads(fw_row["payload_json"])
    assert firmware["input_attestation_grade"] == "attested"
    assert firmware["input_posture"] == "sealed_flash"
    assert firmware["input_firmware_device_id"] == "ori-fw-artifact-01"
    assert firmware["input_firmware_boot_id"] == 7
    assert firmware["input_firmware_seq"] == 11


@pytest.mark.asyncio
async def test_chain_survives_restart_with_same_secret(tmp_path):
    first = _attestor(tmp_path)
    assert await first.start() is True
    anchor = first.public_key_hex
    assert await first.attest_action(_tier_d_row(1)) == 1
    head = await first.chain_head_hash()
    first.close()

    second = _attestor(tmp_path)
    try:
        assert await second.start() is True
        assert second.public_key_hex == anchor
        assert await second.chain_head_hash() == head
        # The idempotency lookup works across restarts.
        assert await second.attest_action(_tier_d_row(1)) == 1
    finally:
        second.close()


@pytest.mark.asyncio
async def test_wrong_device_secret_fails_closed(tmp_path):
    first = _attestor(tmp_path)
    assert await first.start() is True
    first.close()

    imposter = _attestor(tmp_path, device_secret="wrong-secret")
    try:
        assert await imposter.start() is False
        assert imposter.available is False
        assert await imposter.attest_action(_tier_d_row(9)) is None
    finally:
        imposter.close()
