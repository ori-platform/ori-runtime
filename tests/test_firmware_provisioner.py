# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Provisioning CLI tests.

The CLI orchestrates the runtime's existing provisioning path rather
than signing approvals itself, so the properties worth testing are the
ones a parallel authority would have skipped: an unregistered,
unapproved, or revoked device must not receive an approval, and the
operator must confirm the device identity independently of the manifest
that asserts it.

Approval *bytes* are already covered by the shared golden vectors and by
the firmware's own C tests; ``selfcheck`` guards that agreement here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.firmware_provisioner import golden_selfcheck, main
from ori.security.firmware_telemetry import canonical_json_bytes


def _pub_b64(seed: bytes) -> str:
    raw = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return base64.b64encode(raw).decode("ascii")


def signed_manifest(device_seed: bytes, **overrides) -> dict:
    """A manifest message shaped exactly as the device publishes one."""
    manifest = {
        "v": 1,
        "alg": "ed25519",
        "device_id": "ori-fw-bench0001",
        "firmware_version": "0.1.0",
        "board_profile": "esp32s3-devkit",
        "device_mode": "mixed",
        "public_key_b64": _pub_b64(device_seed),
        "posture": "development",
        "secure_boot_enabled": False,
        "flash_encryption_enabled": False,
        "key_storage": "dev_flash",
        "transports": ["mqtt"],
        "channels": [
            {
                "channel": "ch0",
                "sensor_type": "current",
                "unit": "ampere",
                "protocol": "uart",
                "source": "pzem",
                "quality_floor": 0.8,
            }
        ],
        "actions": [
            {
                "action": "relay_open",
                "channel": "relay0",
                "authority": "runtime_commanded",
            }
        ],
        "interlocks": [
            {
                "name": "local_overcurrent_interlock",
                "channel": "ch0",
                "action": "relay_open",
            }
        ],
    }
    manifest.update(overrides)
    canonical = canonical_json_bytes(manifest)
    signature = Ed25519PrivateKey.from_private_bytes(device_seed).sign(canonical)
    return {
        "manifest": manifest,
        "manifest_hash": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "signature": "ed25519:" + base64.b64encode(signature).decode("ascii"),
    }


@pytest.fixture
def bench(tmp_path):
    """A keyed bench: authority + runtime seeds on disk, a device
    manifest ready to register, and paths for the CLI."""
    device_seed = os.urandom(32)
    main(["keygen", "--out-dir", str(tmp_path)])
    message = signed_manifest(device_seed)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(message))
    return {
        "db": str(tmp_path / "o.db"),
        "manifest": str(manifest_path),
        "message": message,
        "device_key": message["manifest"]["public_key_b64"],
        "auth_seed": str(tmp_path / "provisioner_seed.b64"),
        "rt_seed": str(tmp_path / "runtime_command_seed.b64"),
        "out": str(tmp_path / "approval.json"),
        "tmp": tmp_path,
    }


def _publish(bench, device_id="ori-fw-bench0001"):
    return main(
        [
            "publish",
            "--db",
            bench["db"],
            "--device-id",
            device_id,
            "--provisioner-seed",
            bench["auth_seed"],
            "--runtime-command-seed",
            bench["rt_seed"],
            "--out",
            bench["out"],
        ]
    )


def _register(bench):
    return main(["register", "--db", bench["db"], "--manifest", bench["manifest"]])


def _approve(bench, key=None):
    return main(
        [
            "approve",
            "--db",
            bench["db"],
            "--device-id",
            "ori-fw-bench0001",
            "--confirm-device-key",
            key if key is not None else bench["device_key"],
        ]
    )


class TestTransactionControls:
    """Each of these is a control a parallel signing path would skip."""

    def test_unregistered_device_gets_no_approval(self, bench) -> None:
        assert _publish(bench) == 2

    def test_registered_but_unapproved_gets_no_approval(self, bench) -> None:
        assert _register(bench) == 0
        # register stores the anchor UNAPPROVED on purpose.
        assert _publish(bench) == 2

    def test_approved_device_gets_an_approval(self, bench) -> None:
        assert _register(bench) == 0
        assert _approve(bench) == 0
        assert _publish(bench) == 0
        approval = json.loads(Path(bench["out"]).read_text())["approval"]
        assert approval["device_id"] == "ori-fw-bench0001"
        assert approval["public_key_b64"] == bench["device_key"]

    def test_revoked_device_gets_no_approval(self, bench) -> None:
        import asyncio

        from ori.security.firmware_ingest import FirmwareTelemetryGate
        from ori.state.store import StateStore

        assert _register(bench) == 0
        assert _approve(bench) == 0

        async def revoke():
            store = StateStore(db_path=bench["db"])
            await store.open()
            await FirmwareTelemetryGate(store).revoke_device("ori-fw-bench0001")
            await store.close()

        asyncio.run(revoke())
        # A revoked device must not be re-armed by publishing again.
        assert _publish(bench) == 2

    def test_approval_is_signed_from_the_registry_not_the_manifest(self, bench) -> None:
        assert _register(bench) == 0
        assert _approve(bench) == 0
        # Corrupt the on-disk manifest after registration. The approval
        # must still reflect the stored row, because the registry is the
        # source of truth once the anchor exists.
        bad = json.loads(Path(bench["manifest"]).read_text())
        bad["manifest"]["device_id"] = "ori-fw-someone-else"
        Path(bench["manifest"]).write_text(json.dumps(bad))
        assert _publish(bench) == 0
        approval = json.loads(Path(bench["out"]).read_text())["approval"]
        assert approval["device_id"] == "ori-fw-bench0001"


class TestIdentityConfirmation:
    def test_wrong_confirmed_key_blocks_approval(self, bench) -> None:
        assert _register(bench) == 0
        # Verifying a manifest against the key inside it proves internal
        # consistency, not that it came from the board on the bench.
        assert _approve(bench, key=_pub_b64(os.urandom(32))) == 2
        assert _publish(bench) == 2

    def test_approving_an_unregistered_device_fails(self, bench) -> None:
        assert _approve(bench) == 2


class TestRegistration:
    def test_tampered_manifest_is_not_registered(self, bench) -> None:
        message = json.loads(Path(bench["manifest"]).read_text())
        message["manifest"]["firmware_version"] = "9.9.9"
        Path(bench["manifest"]).write_text(json.dumps(message))
        assert _register(bench) == 2

    def test_inconsistent_posture_is_not_registered(self, bench, tmp_path) -> None:
        # A development board must not register as sealed_flash: the
        # posture's boolean fields disagree with the claim.
        seed = os.urandom(32)
        message = signed_manifest(seed, posture="sealed_flash")
        path = tmp_path / "sealed.json"
        path.write_text(json.dumps(message))
        assert main(["register", "--db", bench["db"], "--manifest", str(path)]) == 2


class TestKeygen:
    def test_seeds_are_owner_only_and_never_overwritten(self, tmp_path) -> None:
        assert main(["keygen", "--out-dir", str(tmp_path)]) == 0
        seed = tmp_path / "provisioner_seed.b64"
        # This key grants command authority over a fleet.
        assert stat.S_IMODE(seed.stat().st_mode) == 0o600
        # A second keygen must not silently invalidate a fleet's anchor.
        assert main(["keygen", "--out-dir", str(tmp_path)]) == 2

    def test_seeds_are_canonical_base64_the_runtime_can_load(self, tmp_path) -> None:
        # The runtime loads seeds from env as base64. Emitting hex would
        # generate keys it cannot use, so the approval would install a
        # runtime key that never signs anything.
        from ori.gateway.firmware_commands import load_raw_ed25519_seed_from_env

        main(["keygen", "--out-dir", str(tmp_path)])
        for name in ("provisioner_seed.b64", "runtime_command_seed.b64"):
            value = (tmp_path / name).read_text().strip()
            os.environ["ORI_TEST_SEED"] = value
            try:
                loaded = load_raw_ed25519_seed_from_env(
                    "ORI_TEST_SEED", label="test seed"
                )
            finally:
                del os.environ["ORI_TEST_SEED"]
            assert len(loaded) == 32

    def test_emits_the_firmware_c_array(self, tmp_path, capsys) -> None:
        main(["keygen", "--out-dir", str(tmp_path)])
        out = capsys.readouterr().out
        # Must match the declaration in device/main/app_main.c.
        assert (
            "static const uint8_t BENCH_PROVISIONER_PUBKEY"
            "[ORI_ED25519_PUBLIC_KEY_LEN] = {" in out
        )
        assert out.count("0x") == 32


class TestContractDiagnostic:
    def test_selfcheck_reproduces_the_shared_vectors(self) -> None:
        # The tie to the firmware's C verifier: these are the same bytes
        # ori-edge-firmware's test_provisioning.c accepts.
        assert golden_selfcheck() == []

    def test_selfcheck_cli(self, capsys) -> None:
        assert main(["selfcheck"]) == 0
        assert "reproduced byte-for-byte" in capsys.readouterr().out


class TestRevocationIsNotSilentlyCleared:
    """The store's anchor upsert resets `revoked` to 0. Re-registering a
    revoked device would therefore re-arm it silently, so the CLI
    requires the operator to say so explicitly."""

    def _revoke(self, bench) -> None:
        import asyncio

        from ori.security.firmware_ingest import FirmwareTelemetryGate
        from ori.state.store import StateStore

        async def go():
            store = StateStore(db_path=bench["db"])
            await store.open()
            await FirmwareTelemetryGate(store).revoke_device("ori-fw-bench0001")
            await store.close()

        asyncio.run(go())

    def test_reregistering_a_revoked_device_is_refused(self, bench) -> None:
        assert _register(bench) == 0
        assert _approve(bench) == 0
        self._revoke(bench)
        # Without this guard the upsert would clear the revocation and a
        # subsequent approve+publish would re-arm a revoked device.
        assert _register(bench) == 2
        assert _publish(bench) == 2

    def test_reregistration_is_possible_when_explicit(self, bench) -> None:
        assert _register(bench) == 0
        self._revoke(bench)
        rc = main(
            [
                "register",
                "--db",
                bench["db"],
                "--manifest",
                bench["manifest"],
                "--allow-revoked",
            ]
        )
        assert rc == 0
        # Still unapproved: clearing revocation does not grant authority.
        assert _publish(bench) == 2
