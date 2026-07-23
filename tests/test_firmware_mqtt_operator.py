# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Authenticated operator-boundary tests for firmware MQTT provisioning."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from ori.firmware_mqtt_operator import (
    FirmwareMqttOperatorController,
    FirmwareMqttOperatorError,
    FirmwareMqttOperatorServer,
    _peer_uid,
)
from ori.runtime import OriRuntime
from ori.security.firmware_mqtt_certificate import FirmwareMqttCertificateAuthority
from ori.security.firmware_mqtt_provisioning import FirmwareMqttProvisioningService
from ori.security.firmware_mqtt_workflow import FirmwareMqttProvisioningWorkflow
from ori.state.store import StateStore

DEVICE_ID = "ori-fw-7c9f2b3a"
ANCHOR_EPOCH = "sha256:" + "aa" * 32
CAPABILITY_HASH = "sha256:" + "bb" * 32
KEY_EPOCH = "sha256:" + "cc" * 32
PA_SEED = b"\x22" * 32
NOW = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
CONTRACT = "ori.runtime.firmware-mqtt-operator"


def _ca_material(common_name: str) -> tuple[bytes, bytes]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _device_csr() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DEVICE_ID)]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


def _signed_device_message(
    device_key: ed25519.Ed25519PrivateKey,
    *,
    outer_field: str,
    value: dict,
) -> bytes:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    signature = base64.b64encode(device_key.sign(canonical)).decode("ascii")
    return (
        b'{"'
        + outer_field.encode()
        + b'":'
        + canonical
        + b',"signature":"ed25519:'
        + signature.encode()
        + b'"}'
    )


async def _approved_store(
    tmp_path, device_key: ed25519.Ed25519PrivateKey
) -> StateStore:
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    assert store._conn is not None
    public_key_b64 = base64.b64encode(
        device_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    store._conn.execute(
        """
        INSERT INTO firmware_device_registry
            (device_id, public_key_b64, posture, capability_hash,
             provisioned_at_ms, approved, anchor_epoch_id, key_epoch_id)
        VALUES (?, ?, 'sealed_flash', ?, 1, 1, ?, ?)
        """,
        (
            DEVICE_ID,
            public_key_b64,
            CAPABILITY_HASH,
            ANCHOR_EPOCH,
            KEY_EPOCH,
        ),
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
            ANCHOR_EPOCH,
            DEVICE_ID,
            KEY_EPOCH,
            public_key_b64,
            CAPABILITY_HASH,
        ),
    )
    store._conn.execute(
        """
        INSERT INTO firmware_confirmation_outbox
            (device_id, anchor_epoch_id, status, created_at_ms)
        VALUES (?, ?, 'confirmed', 1)
        """,
        (DEVICE_ID, ANCHOR_EPOCH),
    )
    store._conn.commit()
    return store


def _workflow(store: StateStore) -> FirmwareMqttProvisioningWorkflow:
    client_ca, client_ca_key = _ca_material("Ori MQTT Client CA")
    broker_ca, _ = _ca_material("Ori MQTT Broker CA")
    return FirmwareMqttProvisioningWorkflow(
        service=FirmwareMqttProvisioningService(
            store=store,
            provisioner_key_bytes=PA_SEED,
        ),
        certificate_authority=FirmwareMqttCertificateAuthority(
            ca_certificate_pem=client_ca,
            ca_private_key_pem=client_ca_key,
            serial_number_factory=lambda: 17,
        ),
        broker_ca_certificate_pem=broker_ca,
    )


def _controller(
    store: StateStore,
    workflow: FirmwareMqttProvisioningWorkflow,
) -> FirmwareMqttOperatorController:
    return FirmwareMqttOperatorController(
        workflow=workflow,
        store=store,
        broker_uri="mqtts://broker.example:8883",
        time_server="time.example",
    )


def _request(operation: str, **fields) -> dict:
    return {
        "contract": CONTRACT,
        "schema_version": 1,
        "operation": operation,
        **fields,
    }


async def test_operator_flow_survives_restart_and_retains_public_only_material(
    tmp_path,
) -> None:
    device_key = ed25519.Ed25519PrivateKey.generate()
    store = await _approved_store(tmp_path, device_key)
    workflow = _workflow(store)
    controller = _controller(store, workflow)
    try:
        create = await controller.handle(
            _request(
                "create_csr",
                device_id=DEVICE_ID,
                reason="initial-mqtt-enrollment",
            ),
            actor="uid-501",
        )
        assert create["operation"] == "create_csr"
        assert b"PRIVATE KEY" not in base64.b64decode(create["message_b64"])

        csr_response = _signed_device_message(
            device_key,
            outer_field="response",
            value={
                "anchor_epoch_id": ANCHOR_EPOCH,
                "csr_pem_b64": base64.b64encode(_device_csr()).decode("ascii"),
                "device_id": DEVICE_ID,
                "kind": "csr",
                "provision_seq": create["provision_seq"],
                "v": 1,
            },
        )
        # Reopen the database and rebuild the workflow to represent a process
        # restart. Correlation lives in durable runtime state, not in the CLI
        # or controller memory.
        await store.close()
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        workflow = _workflow(store)
        controller = _controller(store, workflow)
        install = await controller.handle(
            _request(
                "prepare_install",
                correlation_id=create["correlation_id"],
                response_b64=base64.b64encode(csr_response).decode("ascii"),
                reason="initial-mqtt-enrollment",
            ),
            actor="uid-501",
        )
        assert install["operation"] == "install"
        assert install["certificate"]["sha256"].startswith("sha256:")
        assert "certificate_pem" not in install["certificate"]
        assert b"PRIVATE KEY" not in base64.b64decode(install["message_b64"])
        parent = await store.get_firmware_mqtt_operator_request(
            create["correlation_id"]
        )
        assert parent is not None
        assert parent["response_verdict"] == "accepted"
        assert parent["completed_at_ms"] is not None

        result_message = _signed_device_message(
            device_key,
            outer_field="result",
            value={
                "anchor_epoch_id": ANCHOR_EPOCH,
                "device_id": DEVICE_ID,
                "kind": "install",
                "provision_seq": install["provision_seq"],
                "v": 1,
                "verdict": "storage_failure",
            },
        )
        result = await controller.handle(
            _request(
                "verify_install_result",
                correlation_id=install["correlation_id"],
                response_b64=base64.b64encode(result_message).decode("ascii"),
            ),
            actor="uid-501",
        )
        assert result["verdict"] == "storage_failure"
        assert result["successful"] is False

        with pytest.raises(FirmwareMqttOperatorError, match="already completed") as exc:
            await controller.handle(
                _request(
                    "verify_install_result",
                    correlation_id=install["correlation_id"],
                    response_b64=base64.b64encode(result_message).decode("ascii"),
                ),
                actor="uid-501",
            )
        assert exc.value.code == "stale_correlation"
    finally:
        await store.close()


async def test_operator_contract_rejects_extra_fields(tmp_path) -> None:
    device_key = ed25519.Ed25519PrivateKey.generate()
    store = await _approved_store(tmp_path, device_key)
    try:
        controller = _controller(store, _workflow(store))
        with pytest.raises(FirmwareMqttOperatorError) as exc:
            await controller.handle(
                _request(
                    "create_csr",
                    device_id=DEVICE_ID,
                    reason="enroll",
                    actor="client-supplied-actor",
                ),
                actor="uid-501",
            )
        assert exc.value.code == "invalid_request"

        with pytest.raises(FirmwareMqttOperatorError) as anchor_exc:
            await controller.handle(
                _request(
                    "create_csr",
                    device_id="ori-fw-unknown",
                    reason="enroll",
                ),
                actor="uid-501",
            )
        assert anchor_exc.value.code == "anchor_unknown"
    finally:
        await store.close()


class _CapturingController:
    def __init__(self) -> None:
        self.actor = ""

    async def handle(self, request: dict, *, actor: str) -> dict:
        self.actor = actor
        return {"operation": request["operation"]}


async def test_operator_socket_derives_actor_from_authorized_peer() -> None:
    controller = _CapturingController()
    socket_path = f"/tmp/ori-op-{os.getpid()}-{id(controller)}.sock"
    server = FirmwareMqttOperatorServer(
        socket_path=socket_path,
        mode=0o600,
        allowed_uids={501},
        controller=controller,  # type: ignore[arg-type]
        peer_uid_provider=lambda _: 501,
    )
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(socket_path)
        writer.write(json.dumps(_request("create_csr")).encode("utf-8") + b"\n")
        await writer.drain()
        response = json.loads(await reader.readline())
        writer.close()
        await writer.wait_closed()
        assert response["ok"] is True
        assert controller.actor == "uid-501"
        assert stat_mode(socket_path) == 0o600
    finally:
        await server.close()


async def test_operator_socket_rejects_unauthorized_peer() -> None:
    controller = _CapturingController()
    socket_path = f"/tmp/ori-op-{os.getpid()}-{id(controller)}.sock"
    server = FirmwareMqttOperatorServer(
        socket_path=socket_path,
        mode=0o600,
        allowed_uids={501},
        controller=controller,  # type: ignore[arg-type]
        peer_uid_provider=lambda _: 502,
    )
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(socket_path)
        writer.write(b"{}\n")
        await writer.drain()
        response = json.loads(await reader.readline())
        writer.close()
        await writer.wait_closed()
        assert response["ok"] is False
        assert response["error"]["code"] == "authentication_failed"
        assert controller.actor == ""
    finally:
        await server.close()


def stat_mode(path: str) -> int:
    return os.stat(path).st_mode & 0o777


def test_peer_uid_reads_local_socket_credentials() -> None:
    left, right = socket.socketpair()
    try:
        assert _peer_uid(left) == os.geteuid()
    finally:
        left.close()
        right.close()


async def test_runtime_starts_operator_with_runtime_owned_material(
    tmp_path,
    monkeypatch,
) -> None:
    client_ca, client_key = _ca_material("Ori MQTT Client CA")
    broker_ca, _ = _ca_material("Ori MQTT Broker CA")
    client_ca_path = tmp_path / "client-ca.crt"
    client_key_path = tmp_path / "client-ca.key"
    broker_ca_path = tmp_path / "broker-ca.crt"
    client_ca_path.write_bytes(client_ca)
    client_key_path.write_bytes(client_key)
    client_key_path.chmod(0o600)
    broker_ca_path.write_bytes(broker_ca)
    monkeypatch.setenv("ORI_TEST_PA_SEED", base64.b64encode(PA_SEED).decode("ascii"))

    runtime = OriRuntime(config_path="unused.yaml")
    runtime._state_store = StateStore(db_path=":memory:")
    await runtime._state_store.open()
    socket_path = f"/tmp/ori-op-{os.getpid()}-{id(runtime)}.sock"
    config = SimpleNamespace(
        firmware_mqtt_provisioning={
            "enabled": True,
            "socket_path": socket_path,
            "socket_mode": 0o600,
            "allowed_uids": [os.geteuid()],
            "provisioner_key_env": "ORI_TEST_PA_SEED",
            "client_ca_certfile": str(client_ca_path),
            "client_ca_keyfile": str(client_key_path),
            "client_ca_key_password_env": "",
            "broker_ca_certfile": str(broker_ca_path),
            "broker_uri": "mqtts://broker.example:8883",
            "time_server": "time.example",
            "certificate_validity_days": 90,
        },
        gateway=SimpleNamespace(firmware_commands={}),
    )
    try:
        await runtime._start_firmware_mqtt_operator_if_enabled(config)  # type: ignore[arg-type]
        assert runtime._firmware_mqtt_operator_server is not None
        assert runtime._firmware_mqtt_operator_socket_path == socket_path
        assert stat_mode(socket_path) == 0o600
    finally:
        if runtime._firmware_mqtt_operator_server is not None:
            await runtime._firmware_mqtt_operator_server.close()
        await runtime._state_store.close()


async def test_runtime_refuses_a_different_command_provisioning_root(
    monkeypatch,
) -> None:
    monkeypatch.setenv("ORI_TEST_MQTT_PA", base64.b64encode(PA_SEED).decode("ascii"))
    monkeypatch.setenv(
        "ORI_TEST_COMMAND_PA",
        base64.b64encode(b"\x33" * 32).decode("ascii"),
    )
    runtime = OriRuntime(config_path="unused.yaml")
    runtime._state_store = StateStore(db_path=":memory:")
    await runtime._state_store.open()
    config = SimpleNamespace(
        firmware_mqtt_provisioning={
            "enabled": True,
            "provisioner_key_env": "ORI_TEST_MQTT_PA",
        },
        gateway=SimpleNamespace(
            firmware_commands={
                "enabled": True,
                "provisioner_key_env": "ORI_TEST_COMMAND_PA",
            }
        ),
    )
    try:
        with pytest.raises(RuntimeError, match="keys differ"):
            await runtime._start_firmware_mqtt_operator_if_enabled(config)  # type: ignore[arg-type]
    finally:
        await runtime._state_store.close()
