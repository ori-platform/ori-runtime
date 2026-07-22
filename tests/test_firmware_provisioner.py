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
        "device_seed": device_seed,
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
            "--reason",
            "bench provisioning",
        ]
    )


def _confirm(bench, device_id="ori-fw-bench0001"):
    """Stand in for the runtime confirmation coordinator.

    Publishing now requires the evidence store to have confirmed the active
    epoch; the offline provisioner cannot do that, so tests resolve the
    obligation directly to reach the publish path.
    """
    import asyncio

    from ori.state.store import StateStore
    from ori.utils.time_utils import now_ms

    async def _run():
        store = StateStore(db_path=bench["db"])
        await store.open()
        try:
            dev = await store.get_firmware_device(device_id)
            await store.resolve_firmware_confirmation(
                device_id, dev["anchor_epoch_id"], status="confirmed", at_ms=now_ms()
            )
        finally:
            await store.close()

    asyncio.run(_run())


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
        _confirm(bench)
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
            await FirmwareTelemetryGate(store).revoke_device(
                "ori-fw-bench0001", actor="test-operator", reason="test"
            )
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
        _confirm(bench)
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


class TestRevocationSurvivesRegistration:
    """ori-specs/device-provisioning/v1.md: revocation belongs to the
    identity. The store refuses registration of a revoked identity, so no
    CLI flag can clear it — returning a device to service is reinstatement,
    an explicit operation."""

    def _revoke(self, bench) -> None:
        import asyncio

        from ori.security.firmware_ingest import FirmwareTelemetryGate
        from ori.state.store import StateStore

        async def go():
            store = StateStore(db_path=bench["db"])
            await store.open()
            await FirmwareTelemetryGate(store).revoke_device(
                "ori-fw-bench0001", actor="test-operator", reason="test"
            )
            await store.close()

        asyncio.run(go())

    def test_reregistering_a_revoked_device_is_refused(self, bench) -> None:
        assert _register(bench) == 0
        assert _approve(bench) == 0
        self._revoke(bench)
        # Registration must not re-arm a revoked identity, and there is no
        # flag that would let it.
        assert _register(bench) == 2
        assert _publish(bench) == 2

    def test_revocation_survives_a_manifest_change(self, bench) -> None:
        assert _register(bench) == 0
        assert _approve(bench) == 0
        self._revoke(bench)

        # RE-SIGNED with the device's own key, so the manifest is valid and
        # the refusal comes from the anchor lifecycle rather than from
        # signature verification. An unsigned edit would be rejected before
        # revocation was ever consulted, and would prove nothing.
        changed = signed_manifest(bench["device_seed"], firmware_version="0.2.0")
        Path(bench["manifest"]).write_text(json.dumps(changed))

        assert _register(bench) == 2
        assert _publish(bench) == 2


class TestActorIsAuthenticated:
    """The contract requires the *authenticated* operator. A name typed on
    the command line is an assertion; anyone can type any name."""

    def test_actor_is_derived_from_the_os_principal(self) -> None:
        from ori.firmware_provisioner import authenticated_actor

        actor = authenticated_actor()
        assert actor.startswith("uid=")
        assert actor.strip() == actor and actor != ""

    def test_actor_ignores_caller_controlled_environment(self, monkeypatch) -> None:
        # getpass.getuser() trusts LOGNAME/USER, so it would be spoofable
        # by the very caller being attributed. The real UID is not.
        from ori.firmware_provisioner import authenticated_actor

        before = authenticated_actor()
        monkeypatch.setenv("USER", "someone-else")
        monkeypatch.setenv("LOGNAME", "someone-else")
        assert authenticated_actor() == before
        assert "someone-else" not in authenticated_actor()

    def test_label_annotates_but_never_replaces_the_principal(self) -> None:
        from ori.firmware_provisioner import authenticated_actor

        principal = authenticated_actor()
        labelled = authenticated_actor("bench operator")
        assert labelled.startswith(principal)
        assert "bench operator" in labelled

    def test_approve_records_the_authenticated_actor(self, bench) -> None:
        import asyncio

        from ori.firmware_provisioner import authenticated_actor
        from ori.state.store import StateStore

        assert _register(bench) == 0
        assert _approve(bench) == 0

        async def transitions():
            store = StateStore(db_path=bench["db"])
            await store.open()
            rows = await store.list_firmware_anchor_transitions("ori-fw-bench0001")
            await store.close()
            return rows

        promoted = [
            t for t in asyncio.run(transitions()) if t["transition"] == "promoted"
        ]
        assert promoted[0]["actor"] == authenticated_actor()
        assert promoted[0]["reason"] == "bench provisioning"

    def test_fails_closed_without_a_real_uid(self, monkeypatch) -> None:
        # On a platform with no real UID there is nothing to authenticate
        # against. Recording a placeholder would put an unattributable row
        # in the audit log while looking like attribution, so the
        # operation is refused instead.
        import os as os_module

        from ori.firmware_provisioner import ProvisionerError, authenticated_actor

        monkeypatch.delattr(os_module, "getuid", raising=False)
        with pytest.raises(ProvisionerError, match="authenticated OS principal"):
            authenticated_actor()

    def test_uid_without_a_passwd_entry_still_authenticates(self, monkeypatch) -> None:
        # A UID with no passwd entry is still an authenticated principal;
        # only the display name is missing.
        import pwd

        from ori.firmware_provisioner import authenticated_actor

        monkeypatch.setattr(
            pwd, "getpwuid", lambda _uid: (_ for _ in ()).throw(KeyError("no entry"))
        )
        actor = authenticated_actor()
        assert actor.startswith("uid=")
        assert ":" not in actor


class TestPromotionConfirmsTheAnchorBeingActivated:
    """`approve` must confirm the key of the anchor about to be ACTIVATED,
    not the one currently active. After re-provisioning they differ, and
    checking the active key made a re-keyed device impossible to promote."""

    def _manifest_for(self, bench, seed, path):
        message = signed_manifest(seed)
        Path(path).write_text(json.dumps(message))
        return message["manifest"]["public_key_b64"]

    def test_reprovisioned_key_can_be_promoted(self, bench, tmp_path) -> None:
        import os

        assert _register(bench) == 0
        assert _approve(bench) == 0

        new_seed = os.urandom(32)
        new_manifest = tmp_path / "m2.json"
        new_key = self._manifest_for(bench, new_seed, new_manifest)

        assert (
            main(
                [
                    "reprovision",
                    "--db",
                    bench["db"],
                    "--manifest",
                    str(new_manifest),
                    "--confirm-device-key",
                    new_key,
                    "--reason",
                    "device re-keyed",
                ]
            )
            == 0
        )
        # Confirming the NEW key promotes it.
        assert _approve(bench, key=new_key) == 0

    def test_confirming_the_superseded_key_is_refused(self, bench, tmp_path) -> None:
        import os

        assert _register(bench) == 0
        assert _approve(bench) == 0
        new_seed = os.urandom(32)
        new_manifest = tmp_path / "m3.json"
        new_key = self._manifest_for(bench, new_seed, new_manifest)
        main(
            [
                "reprovision",
                "--db",
                bench["db"],
                "--manifest",
                str(new_manifest),
                "--confirm-device-key",
                new_key,
                "--reason",
                "re-keyed",
            ]
        )
        # The old key is no longer the one being activated.
        assert _approve(bench, key=bench["device_key"]) == 2

    def test_reprovision_requires_the_key_to_match_the_manifest(
        self, bench, tmp_path
    ) -> None:
        import os

        assert _register(bench) == 0
        assert _approve(bench) == 0
        new_manifest = tmp_path / "m4.json"
        self._manifest_for(bench, os.urandom(32), new_manifest)
        # Confirming a key that is not the one in the manifest defeats the
        # whole point of independent confirmation.
        assert (
            main(
                [
                    "reprovision",
                    "--db",
                    bench["db"],
                    "--manifest",
                    str(new_manifest),
                    "--confirm-device-key",
                    _pub_b64(os.urandom(32)),
                    "--reason",
                    "x",
                ]
            )
            == 2
        )


class TestBackfillDoesNotFireOnNewDevices:
    def test_reopening_does_not_add_a_migration_transition(self, bench) -> None:
        """A freshly registered device has an empty anchor_epoch_id by
        design — nothing is promoted yet. Detecting legacy rows by that
        emptiness made the backfill fire on every new device and write a
        spurious 'migration' audit row."""
        import asyncio

        from ori.state.store import StateStore

        assert _register(bench) == 0

        async def transitions():
            store = StateStore(db_path=bench["db"])
            await store.open()  # runs migrations again
            rows = await store.list_firmware_anchor_transitions("ori-fw-bench0001")
            await store.close()
            return rows

        first = asyncio.run(transitions())
        second = asyncio.run(transitions())
        assert len(first) == len(second) == 1
        assert second[0]["actor"] == ""
        assert "migration" not in {t["actor"] for t in second}
