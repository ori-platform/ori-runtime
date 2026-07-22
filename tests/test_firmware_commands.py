# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Runtime command signing against the shared golden command vectors.

The vectors in tests/fixtures/firmware_command_vectors.json are shared
with ori-edge-firmware, whose C verifier accepts exactly these bytes.
This signer must reproduce them byte-for-byte; a divergence means
commands the device will refuse.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ori.security.firmware_commands import (
    FirmwareCommandError,
    FirmwareCommandSigner,
    build_command_bytes,
)
from ori.security.firmware_ingest import FirmwareTelemetryGate
from ori.state.store import StateStore

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "firmware_command_vectors.json").read_text()
)
RUNTIME_SEED = bytes.fromhex(VECTORS["runtime_test_seed_hex"])

TELEMETRY_VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "firmware_layer1_vectors.json").read_text()
)
MANIFEST_CASES = {
    c["name"]: c for c in TELEMETRY_VECTORS["cases"] if c["kind"] == "manifest"
}


class TestGoldenCommandVectors:
    @pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
    def test_signer_reproduces_vector_bytes(self, case: dict) -> None:
        signer = FirmwareCommandSigner(store=None, private_key_bytes=RUNTIME_SEED)
        assert signer.public_key_bytes().hex() == VECTORS["runtime_public_key_hex"]

        i = case["input"]
        command = build_command_bytes(
            action=i["action"],
            capability_hash=i["capability_hash"],
            channel=i["channel"],
            cmd_seq=i["cmd_seq"],
            device_id=i["device_id"],
        )
        assert command.hex() == case["command_hex"]
        message = signer.sign_command_bytes(command)
        # Ed25519 is deterministic: the whole wire message is pinned.
        assert message.hex() == case["message_hex"]


class TestFailClosedBuild:
    def test_rejects_what_the_device_would_refuse(self) -> None:
        good = dict(
            action="relay_open",
            capability_hash="sha256:" + "ab" * 32,
            channel="relay0",
            cmd_seq=1,
            device_id="ori-fw-7c9f2b3a",
        )
        build_command_bytes(**good)

        for bad in (
            {"action": "relay open"},
            {"action": "ota_begin"},  # outside the v1 vocabulary
            {"channel": ""},
            {"channel": "relay{0}"},
            {"device_id": 'ori"bad'},
            {"capability_hash": "sha256:short"},
            {"capability_hash": "SHA256:" + "ab" * 32},
            {"cmd_seq": 0},
            {"cmd_seq": 2**53},
            {"cmd_seq": True},
        ):
            with pytest.raises(FirmwareCommandError):
                build_command_bytes(**{**good, **bad})

    def test_signer_requires_raw_seed(self) -> None:
        with pytest.raises(FirmwareCommandError):
            FirmwareCommandSigner(store=None, private_key_bytes=b"short")


@pytest.fixture
async def store(tmp_path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


def manifest_message(case_name: str) -> dict:
    case = MANIFEST_CASES[case_name]
    return {
        "manifest": case["input"],
        "manifest_hash": "sha256:" + case["canonical_sha256_hex"],
        "signature": "ed25519:" + case["signature_b64"],
    }


async def provision(store) -> str:
    gate = FirmwareTelemetryGate(store)
    manifest = MANIFEST_CASES["manifest_full_sealed"]["input"]
    await gate.register_device(
        device_id=manifest["device_id"],
        public_key_b64=TELEMETRY_VECTORS["public_key_b64"],
        posture=manifest["posture"],
        manifest_message=manifest_message("manifest_full_sealed"),
    )
    assert await gate.approve_device(
        manifest["device_id"], actor="test-operator", reason="test"
    )
    await _confirm_active(store, manifest["device_id"])
    return manifest["device_id"]


async def _confirm_active(store, device_id: str) -> None:
    """Mark the device's active epoch cross-store confirmed.

    Publishing a command or approval now requires the evidence store to
    have confirmed the same anchor_epoch_id. Tests that exercise a
    fully-usable device stand in for the runtime coordinator by resolving
    the obligation directly.
    """
    from ori.utils.time_utils import now_ms

    dev = await store.get_firmware_device(device_id)
    await store.resolve_firmware_confirmation(
        device_id, dev["anchor_epoch_id"], status="confirmed", at_ms=now_ms()
    )


class TestSequenceAllocation:
    async def test_strictly_increasing_per_device(self, store) -> None:
        device_id = await provision(store)
        seqs = [await store.allocate_firmware_command_seq(device_id) for _ in range(5)]
        assert seqs == [1, 2, 3, 4, 5]

    async def test_unknown_device_refused(self, store) -> None:
        with pytest.raises(KeyError):
            await store.allocate_firmware_command_seq("ori-fw-missing")

    async def test_sign_command_end_to_end(self, store) -> None:
        device_id = await provision(store)
        signer = FirmwareCommandSigner(store=store, private_key_bytes=RUNTIME_SEED)

        first = await signer.sign_command(
            device_id=device_id, action="relay_open", channel="relay0"
        )
        second = await signer.sign_command(
            device_id=device_id, action="relay_open", channel="relay0"
        )
        assert b'"cmd_seq":1,' in first
        assert b'"cmd_seq":2,' in second
        # The manifest-epoch binding rides in the signed bytes.
        row = await store.get_firmware_device(device_id)
        assert row["capability_hash"].encode() in first

        # Lost commands are retried with a fresh sequence, never reused.
        third = await signer.sign_command(
            device_id=device_id, action="relay_open", channel="relay0"
        )
        assert b'"cmd_seq":3,' in third

    async def test_manifest_authority_gates_signing(self, store) -> None:
        device_id = await provision(store)
        signer = FirmwareCommandSigner(store=store, private_key_bytes=RUNTIME_SEED)

        # The sealed manifest's only runtime_commanded pair is
        # relay_open/relay0. Everything else must be refused BEFORE a
        # sequence is allocated — the runtime never manufactures a
        # command the device would refuse.
        with pytest.raises(FirmwareCommandError, match="authority"):
            await signer.sign_command(
                device_id=device_id, action="relay_close", channel="relay0"
            )
        with pytest.raises(FirmwareCommandError, match="authority"):
            # relay1 exists in the manifest, but as local_interlock_only.
            await signer.sign_command(
                device_id=device_id, action="relay_open", channel="relay1"
            )
        with pytest.raises(FirmwareCommandError, match="authority"):
            await signer.sign_command(
                device_id=device_id, action="relay_open", channel="relay9"
            )

        # Even a manifest that (in some future epoch) grants an
        # out-of-vocabulary action must not let signing reach the
        # allocator: the v1 vocabulary is checked before the registry.
        row = await store.get_firmware_device(device_id)
        doctored = dict(row["manifest"])
        doctored["actions"] = [
            {
                "action": "ota_begin",
                "channel": "relay0",
                "authority": "runtime_commanded",
            }
        ]
        # A different manifest is a different capability hash, so this is
        # a new anchor epoch: it arrives as a pending candidate and must be
        # promoted before it grants anything.
        await store.upsert_firmware_device_anchor(
            device_id=device_id,
            public_key_b64=row["public_key_b64"],
            posture=row["posture"],
            capability_hash="sha256:" + "ee" * 32,
            manifest_json=json.dumps(doctored),
            channel_map_json="{}",
        )
        assert await store.approve_firmware_device(
            device_id, actor="test-operator", reason="test"
        )
        await _confirm_active(store, device_id)
        with pytest.raises(FirmwareCommandError, match="vocabulary"):
            await signer.sign_command(
                device_id=device_id, action="ota_begin", channel="relay0"
            )

        # No sequence was consumed by any refusal above.
        assert await store.allocate_firmware_command_seq(device_id) == 1

    async def test_sign_refuses_unapproved_and_revoked(self, store) -> None:
        gate = FirmwareTelemetryGate(store)
        manifest = MANIFEST_CASES["manifest_full_sealed"]["input"]
        await gate.register_device(
            device_id=manifest["device_id"],
            public_key_b64=TELEMETRY_VECTORS["public_key_b64"],
            posture=manifest["posture"],
            manifest_message=manifest_message("manifest_full_sealed"),
        )
        signer = FirmwareCommandSigner(store=store, private_key_bytes=RUNTIME_SEED)
        with pytest.raises(FirmwareCommandError):
            await signer.sign_command(
                device_id=manifest["device_id"], action="relay_open", channel="relay0"
            )
        assert await gate.approve_device(
            manifest["device_id"], actor="test-operator", reason="test"
        )
        # Approved locally but not yet cross-store confirmed: the command
        # gate refuses until the evidence store confirms the epoch.
        with pytest.raises(FirmwareCommandError, match="not cross-store confirmed"):
            await signer.sign_command(
                device_id=manifest["device_id"], action="relay_open", channel="relay0"
            )
        await _confirm_active(store, manifest["device_id"])
        await signer.sign_command(
            device_id=manifest["device_id"], action="relay_open", channel="relay0"
        )
        assert await gate.revoke_device(
            manifest["device_id"], actor="test-operator", reason="test"
        )
        with pytest.raises(FirmwareCommandError):
            await signer.sign_command(
                device_id=manifest["device_id"], action="relay_open", channel="relay0"
            )
