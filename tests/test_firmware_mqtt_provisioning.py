# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Firmware MQTT provisioning contract and golden-vector tests."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from ori.security.firmware_mqtt_provisioning import (
    FirmwareMqttProvisioningError,
    FirmwareMqttProvisioningService,
    FirmwareMqttProvisioningSigner,
    build_create_csr_request,
    build_install_request,
    build_revoke_request,
    build_status_request,
    verify_device_message,
)
from ori.state.store import StateStore

FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "firmware_mqtt_provisioning_vectors.json"
)
FIXTURE_SHA256 = "1e6ee11c2df3633965650a2cab2380f31879fe6dd4babe62a813784395bc89a0"
VECTORS = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
CASES = {case["name"]: case for case in VECTORS["cases"]}
PA_SEED = bytes.fromhex(VECTORS["provisioner_test_seed_hex"])
DEVICE_PUBLIC_KEY = bytes.fromhex(VECTORS["device_public_key_hex"])


def _wire_message(case: dict) -> bytes:
    return (
        '{"%s":%s,"signature":"%s"}'
        % (case["outer_field"], case["signed_object"], case["signature"])
    ).encode()


def test_fixture_digest_is_pinned_to_specs() -> None:
    assert hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest() == FIXTURE_SHA256


@pytest.mark.parametrize(
    "case",
    [case for case in VECTORS["cases"] if case["signer"] == "provisioning_authority"],
    ids=lambda case: case["name"],
)
def test_signer_reproduces_every_provisioning_authority_vector(case: dict) -> None:
    signer = FirmwareMqttProvisioningSigner(PA_SEED)
    assert signer.sign_request(case["signed_object"].encode()) == _wire_message(case)


@pytest.mark.parametrize(
    "case",
    [case for case in VECTORS["cases"] if case["signer"] == "device_layer1"],
    ids=lambda case: case["name"],
)
def test_verifier_accepts_every_device_response_vector(case: dict) -> None:
    result = verify_device_message(
        _wire_message(case), device_public_key_bytes=DEVICE_PUBLIC_KEY
    )
    assert result["kind"] in {"csr", "status", "install"}


def test_builders_reproduce_primary_request_objects() -> None:
    epoch = "sha256:a620b4b540b39b50fb2c1179c4ce656cdcae16ace5d573fa42b6a1a652e00d18"
    common = {
        "actor": "operator-17",
        "anchor_epoch_id": epoch,
        "device_id": "ori-fw-7c9f2b3a",
    }
    assert (
        build_create_csr_request(
            **common, provision_seq=41, reason="initial-mqtt-enrollment"
        ).decode()
        == CASES["create_csr_request"]["signed_object"]
    )
    assert (
        build_install_request(
            **common,
            broker_ca_pem_b64=(
                "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tClkyRT0K"
                "LS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
            ),
            broker_uri="mqtts://broker.example:8883",
            client_cert_pem_b64=(
                "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tClkyeHBaVzUw"
                "Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
            ),
            provision_seq=42,
            reason="initial-mqtt-enrollment",
            time_server="time.example",
        ).decode()
        == CASES["install_request"]["signed_object"]
    )
    assert (
        build_revoke_request(
            **common, provision_seq=43, reason="certificate-compromise"
        ).decode()
        == CASES["revoke_request"]["signed_object"]
    )
    assert (
        build_status_request(**common, request_id="inventory-20260723-01").decode()
        == CASES["status_request"]["signed_object"]
    )


def test_verifier_rejects_tampering_and_noncanonical_outer_order() -> None:
    case = CASES["status_response"]
    message = _wire_message(case)
    with pytest.raises(FirmwareMqttProvisioningError, match="signature"):
        verify_device_message(
            message.replace(b'"revoked":false', b'"revoked":true'),
            device_public_key_bytes=DEVICE_PUBLIC_KEY,
        )
    with pytest.raises(FirmwareMqttProvisioningError, match="canonical"):
        verify_device_message(
            (
                '{"signature":"%s","response":%s}'
                % (case["signature"], case["signed_object"])
            ).encode(),
            device_public_key_bytes=DEVICE_PUBLIC_KEY,
        )


def test_signer_refuses_noncanonical_or_unknown_request_grammar() -> None:
    signer = FirmwareMqttProvisioningSigner(PA_SEED)
    with pytest.raises(FirmwareMqttProvisioningError, match="canonical"):
        signer.sign_request(
            b'{"v":1,"reason":"test","provision_seq":1,"kind":"revoke",'
            b'"device_id":"ori-fw-01","anchor_epoch_id":"sha256:'
            + b"aa" * 32
            + b'","actor":"operator-17"}'
        )
    with pytest.raises(FirmwareMqttProvisioningError, match="unsupported"):
        signer.sign_request(
            b'{"actor":"operator-17","anchor_epoch_id":"sha256:'
            + b"aa" * 32
            + b'","device_id":"ori-fw-01","kind":"erase","v":1}'
        )


@pytest.mark.parametrize(
    "override",
    [
        {"actor": ""},
        {"actor": "operator space"},
        {"reason": 'bad"reason'},
        {"reason": "bad\nreason"},
        {"provision_seq": 0},
        {"provision_seq": 2**53},
    ],
)
def test_create_csr_builder_refuses_noncanonical_fields(override: dict) -> None:
    fields = {
        "actor": "operator-17",
        "anchor_epoch_id": "sha256:" + "aa" * 32,
        "device_id": "ori-fw-01",
        "provision_seq": 1,
        "reason": "test-enrollment",
        **override,
    }
    with pytest.raises(FirmwareMqttProvisioningError):
        build_create_csr_request(**fields)


def test_install_refuses_private_key_material() -> None:
    private_pem = "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"

    with pytest.raises(FirmwareMqttProvisioningError, match="public PEM"):
        build_install_request(
            actor="operator-17",
            anchor_epoch_id="sha256:" + "aa" * 32,
            broker_ca_pem_b64=base64.b64encode(private_pem.encode()).decode(),
            broker_uri="mqtts://broker.example:8883",
            client_cert_pem_b64=base64.b64encode(b"certificate").decode(),
            device_id="ori-fw-01",
            provision_seq=1,
            reason="test-enrollment",
            time_server="time.example",
        )


async def _insert_registry_row(store: StateStore, device_id: str) -> None:
    assert store._conn is not None
    store._conn.execute(
        """
        INSERT INTO firmware_device_registry
            (device_id, public_key_b64, posture, capability_hash,
             provisioned_at_ms, approved, anchor_epoch_id)
        VALUES (?, ?, 'sealed_flash', ?, 1, 1, ?)
        """,
        (
            device_id,
            "AA==",
            "sha256:" + "aa" * 32,
            "sha256:" + "bb" * 32,
        ),
    )
    store._conn.execute(
        """
        INSERT INTO firmware_confirmation_outbox
            (device_id, anchor_epoch_id, status, created_at_ms)
        VALUES (?, ?, 'confirmed', 1)
        """,
        (device_id, "sha256:" + "bb" * 32),
    )
    store._conn.execute(
        """
        INSERT INTO firmware_device_anchors
            (anchor_epoch_id, device_id, key_epoch_id, public_key_b64,
             posture, capability_hash, state, created_at_ms,
             state_changed_at_ms)
        VALUES (?, ?, ?, ?, 'sealed_flash', ?, 'active', 1, 1)
        """,
        (
            "sha256:" + "bb" * 32,
            device_id,
            "sha256:" + "dd" * 32,
            "AA==",
            "sha256:" + "aa" * 32,
        ),
    )
    store._conn.commit()


async def test_provision_seq_is_independent_durable_and_survives_revocation(
    tmp_path,
) -> None:
    path = tmp_path / "state.db"
    store = StateStore(db_path=str(path))
    await store.open()
    await _insert_registry_row(store, "ori-fw-01")
    assert (
        await store.allocate_firmware_provision_seq(
            "ori-fw-01",
            expected_anchor_epoch_id="sha256:" + "bb" * 32,
            allow_revoked=False,
        )
        == 1
    )
    assert await store.allocate_firmware_command_seq("ori-fw-01") == 1
    assert store._conn is not None
    store._conn.execute(
        "UPDATE firmware_device_registry SET revoked = 1 WHERE device_id = ?",
        ("ori-fw-01",),
    )
    store._conn.commit()
    assert (
        await store.allocate_firmware_provision_seq(
            "ori-fw-01",
            expected_anchor_epoch_id="sha256:" + "bb" * 32,
            allow_revoked=True,
        )
        == 2
    )
    await store.close()

    reopened = StateStore(db_path=str(path))
    await reopened.open()
    try:
        assert (
            await reopened.allocate_firmware_provision_seq(
                "ori-fw-01",
                expected_anchor_epoch_id="sha256:" + "bb" * 32,
                allow_revoked=True,
            )
            == 3
        )
        row = await reopened.get_firmware_device("ori-fw-01")
        assert row is not None
        assert row["last_provision_seq"] == 3
    finally:
        await reopened.close()


async def test_provisioning_audit_is_append_only(tmp_path) -> None:
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        audit_id = await store.append_firmware_mqtt_provisioning_audit(
            device_id="ori-fw-01",
            event_kind="request_signed",
            operation_kind="create_csr",
            provision_seq=1,
            request_id="",
            anchor_epoch_id="sha256:" + "aa" * 32,
            actor="operator-17",
            reason="initial-enrollment",
            request_sha256="sha256:" + "bb" * 32,
            verdict="",
            certificate_sha256="",
            broker_uri="",
            payload_sha256="sha256:" + "cc" * 32,
            occurred_at_ms=1,
        )
        rows = await store.list_firmware_mqtt_provisioning_audit("ori-fw-01")
        assert [row["id"] for row in rows] == [audit_id]
        assert store._conn is not None
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute(
                "UPDATE firmware_mqtt_provisioning_audit SET actor = 'mallory' "
                "WHERE id = ?",
                (audit_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute(
                "DELETE FROM firmware_mqtt_provisioning_audit WHERE id = ?",
                (audit_id,),
            )
        store._conn.rollback()
    finally:
        await store.close()


async def test_provision_seq_allocation_refuses_stale_epoch_atomically(
    tmp_path,
) -> None:
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        await _insert_registry_row(store, "ori-fw-01")
        with pytest.raises(PermissionError, match="authority changed"):
            await store.allocate_firmware_provision_seq(
                "ori-fw-01",
                expected_anchor_epoch_id="sha256:" + "cc" * 32,
                allow_revoked=False,
            )
        row = await store.get_firmware_device("ori-fw-01")
        assert row is not None
        assert row["last_provision_seq"] == 0
    finally:
        await store.close()


class _IssuerStore:
    def __init__(self, *, revoked: bool = False, confirmed: bool = True) -> None:
        self.row = {
            "device_id": "ori-fw-01",
            "anchor_epoch_id": "sha256:" + "aa" * 32,
            "public_key_b64": "AA==",
            "approved": not revoked,
            "revoked": revoked,
        }
        self.confirmed = confirmed
        self.seq = 0
        self.audits: list[dict] = []
        self.fail_audit = False

    async def get_firmware_device(self, device_id: str) -> dict | None:
        return self.row if device_id == self.row["device_id"] else None

    async def get_firmware_confirmation_status(
        self, device_id: str, anchor_epoch_id: str
    ) -> str:
        return "confirmed" if self.confirmed else "confirmation_pending"

    async def firmware_activation_history_is_provable(self, device_id: str) -> bool:
        return True

    async def firmware_anchor_activation_intervals(
        self, device_id: str, anchor_epoch_id: str
    ) -> list[dict]:
        return [{"activated_seq": 1}]

    async def allocate_firmware_provision_seq(
        self,
        device_id: str,
        *,
        expected_anchor_epoch_id: str,
        allow_revoked: bool,
    ) -> int:
        if expected_anchor_epoch_id != self.row["anchor_epoch_id"]:
            raise PermissionError("epoch changed")
        if self.row["revoked"] and not allow_revoked:
            raise PermissionError("revoked")
        if not self.row["revoked"] and not self.confirmed:
            raise PermissionError("unconfirmed")
        self.seq += 1
        return self.seq

    async def append_firmware_mqtt_provisioning_audit(self, **fields) -> int:
        if self.fail_audit:
            raise OSError("audit unavailable")
        self.audits.append(fields)
        return len(self.audits)


async def test_service_gates_epoch_allocates_and_audits_before_return() -> None:
    store = _IssuerStore()
    service = FirmwareMqttProvisioningService(
        store=store, provisioner_key_bytes=PA_SEED
    )
    issued = await service.create_csr(
        device_id="ori-fw-01", actor="operator-17", reason="initial-enrollment"
    )
    assert issued.provision_seq == 1
    assert issued.audit_id == 1
    assert store.audits[0]["request_sha256"].startswith("sha256:")
    assert store.audits[0]["payload_sha256"].startswith("sha256:")
    assert b'"provision_seq":1' in issued.message

    store.confirmed = False
    with pytest.raises(FirmwareMqttProvisioningError, match="not cross-store"):
        await service.create_csr(
            device_id="ori-fw-01",
            actor="operator-17",
            reason="initial-enrollment",
        )
    assert store.seq == 1


async def test_revoked_identity_only_allows_withdrawal_and_status() -> None:
    store = _IssuerStore(revoked=True)
    service = FirmwareMqttProvisioningService(
        store=store, provisioner_key_bytes=PA_SEED
    )
    with pytest.raises(FirmwareMqttProvisioningError, match="revoked"):
        await service.create_csr(
            device_id="ori-fw-01",
            actor="operator-17",
            reason="initial-enrollment",
        )
    revoked = await service.revoke(
        device_id="ori-fw-01",
        actor="operator-17",
        reason="certificate-compromise",
    )
    status = await service.status(
        device_id="ori-fw-01",
        actor="operator-17",
        request_id="inventory-01",
    )
    assert revoked.provision_seq == 1
    assert status.provision_seq is None
    assert store.audits[-1]["reason"] == ""


async def test_audit_failure_spends_sequence_but_returns_no_request() -> None:
    store = _IssuerStore()
    store.fail_audit = True
    service = FirmwareMqttProvisioningService(
        store=store, provisioner_key_bytes=PA_SEED
    )
    with pytest.raises(OSError, match="audit unavailable"):
        await service.create_csr(
            device_id="ori-fw-01",
            actor="operator-17",
            reason="initial-enrollment",
        )
    assert store.seq == 1


async def test_service_binds_and_audits_verified_device_response() -> None:
    store = _IssuerStore()
    store.row = {
        "device_id": "ori-fw-7c9f2b3a",
        "anchor_epoch_id": (
            "sha256:a620b4b540b39b50fb2c1179c4ce656cdcae16ace5d573fa42b6a1a652e00d18"
        ),
        "public_key_b64": base64.b64encode(DEVICE_PUBLIC_KEY).decode(),
        "approved": True,
        "revoked": False,
    }
    store.seq = 40
    service = FirmwareMqttProvisioningService(
        store=store, provisioner_key_bytes=PA_SEED
    )
    issued = await service.create_csr(
        device_id="ori-fw-7c9f2b3a",
        actor="operator-17",
        reason="initial-mqtt-enrollment",
    )
    value = await service.verify_response(issued, _wire_message(CASES["csr_response"]))
    assert value["kind"] == "csr"
    assert [row["event_kind"] for row in store.audits] == [
        "request_signed",
        "response_verified",
    ]
