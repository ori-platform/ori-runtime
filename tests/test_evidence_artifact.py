# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""FFI compatibility smoke tests against the REAL ori_verity artifact.

The unit suite in test_evidence.py deliberately runs against a fake
``ori_verity`` module: absence behaviour and fault injection can only be
tested without the real artifact. What the fake cannot prove is that the
runtime and the real artifact speak the same protocol — a drifted FFI
signature would leave the fake suite green while every deployment fell
back to "evidence unavailable".

This module closes that gap. It auto-skips when ``ori_verity`` is not
importable (dev machines and the main CI matrix), and runs in the
dedicated ``evidence-artifact`` CI job, which builds the wheel from the
private artifact source ref supplied by CI secrets, then checks it
matches the expected private artifact version supplied by CI secrets.
Everything here drives the real EvidenceAttestor against the real chain:
key provisioning, signing, idempotent re-append, atomic Layer 1
freshness binding, late-marking, chain verification against the
provisioned anchor, and restart persistence.
"""

import base64
import json
import os
import sqlite3

import pytest

ori_verity = pytest.importorskip(
    "ori_verity", reason="real ori_verity artifact not installed"
)

from ori.security.evidence import (  # noqa: E402
    EXPECTED_PROTOCOL_VERSION,
    EvidenceAttestor,
    _artifact_supports_safety_event,
)


def _expected_artifact_version() -> str | None:
    return os.environ.get("ORI_EVIDENCE_ARTIFACT_VERSION")


def _attestor(tmp_path, *, device_secret: str = "install-secret") -> EvidenceAttestor:
    return EvidenceAttestor(
        db_path=str(tmp_path / "verity.db"),
        key_path=str(tmp_path / "verity.key"),
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


def _firmware_tier_d_row(row_id: int) -> dict:
    row = _tier_d_row(row_id)
    row.update(
        {
            "input_attestation_grade": "attested",
            "input_posture": "sealed_flash",
            "input_firmware_device_id": "ori-fw-artifact-01",
            "input_firmware_boot_id": 7,
            "input_firmware_seq": 11,
            "input_firmware_registration": {
                "device_id": "ori-fw-artifact-01",
                "public_key_b64": base64.b64encode(bytes([0x42]) * 32).decode("ascii"),
                "alg": "ed25519",
                "posture": "sealed_flash",
                "capability_hash": (
                    "sha256:"
                    "13751b5335ccedcd4ffcc82bbda28ebfb7558859f36a74e710f1a0b0ab23da8d"
                ),
                "board_profile": "esp32-s3-pzem-v1",
                "approved": True,
                "provisioned_at_ms": 1_760_000_000_000,
                "revoked": False,
            },
        }
    )
    return row


def _chain_row(db_path: str, seq: int) -> dict:
    # Test-only forensic read; the runtime itself never reads chain SQLite.
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT event_type, device_id, emitted_at_ms, payload_json "
            "FROM verity_chain WHERE seq = ?",
            (seq,),
        ).fetchone()
    assert row is not None, f"chain row seq={seq} missing"
    return dict(row)


def test_artifact_identity_matches_expected_private_version():
    assert ori_verity.PROTOCOL_VERSION == EXPECTED_PROTOCOL_VERSION
    expected = _expected_artifact_version()
    if not expected:
        pytest.skip("ORI_EVIDENCE_ARTIFACT_VERSION is not configured")
    assert ori_verity.ARTIFACT_VERSION == expected, (
        f"installed artifact {ori_verity.ARTIFACT_VERSION!r} does not match "
        f"expected private artifact version {expected!r}"
    )
    # The expected private artifact must be vocabulary-capable; the runtime selects
    # SAFETY_ACTION_EXECUTED from it.
    assert _artifact_supports_safety_event(ori_verity.ARTIFACT_VERSION)


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
        assert await attestor.attest_action(_firmware_tier_d_row(3)) == 3
        firmware = json.loads(_chain_row(attestor._db_path, 3)["payload_json"])
        assert firmware["input_attestation_grade"] == "attested"
        assert firmware["input_posture"] == "sealed_flash"
        assert firmware["input_firmware_device_id"] == "ori-fw-artifact-01"
        assert firmware["input_firmware_boot_id"] == 7
        assert firmware["input_firmware_seq"] == 11

        # The whole chain verifies against the provisioned anchor. The pyo3
        # chain is unsendable, so the call must run on the attestor's
        # dedicated evidence thread; it raises on any integrity failure.
        attestor._executor.submit(attestor._chain.verify_chain, anchor).result()
    finally:
        attestor.close()


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
