# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Certificate and orchestration tests for firmware MQTT provisioning."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ori.security.firmware.mqtt_certificate import (
    FirmwareMqttCertificateAuthority,
    FirmwareMqttCertificateError,
)
from ori.security.firmware.mqtt_provisioning import (
    FirmwareMqttProvisioningService,
    FirmwareMqttResponseValidationError,
)
from ori.security.firmware.mqtt_workflow import FirmwareMqttProvisioningWorkflow
from ori.state.store import StateStore

DEVICE_ID = "ori-fw-7c9f2b3a"
ANCHOR_EPOCH = "sha256:" + "aa" * 32
CAPABILITY_HASH = "sha256:" + "bb" * 32
KEY_EPOCH = "sha256:" + "cc" * 32
PA_SEED = b"\x22" * 32
NOW = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)


def _ca_material(
    *,
    common_name: str,
    is_ca: bool = True,
    key: ec.EllipticCurvePrivateKey | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes]:
    private_key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=None,
                decipher_only=None,
            ),
            True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return (
        private_key,
        certificate.public_bytes(serialization.Encoding.PEM),
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _device_csr(
    *,
    common_name: str = DEVICE_ID,
    key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None = None,
) -> tuple[object, bytes]:
    private_key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, csr.public_bytes(serialization.Encoding.PEM)


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
        ensure_ascii=False,
    ).encode()
    signature = base64.b64encode(device_key.sign(canonical)).decode("ascii")
    return (
        b'{"'
        + outer_field.encode("ascii")
        + b'":'
        + canonical
        + b',"signature":"ed25519:'
        + signature.encode("ascii")
        + b'"}'
    )


async def _open_approved_store(
    tmp_path,
    *,
    device_public_key: bytes,
) -> StateStore:
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    assert store._conn is not None
    public_key_b64 = base64.b64encode(device_public_key).decode("ascii")
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


def _workflow(
    store: StateStore,
    *,
    client_ca_certificate_pem: bytes,
    client_ca_private_key_pem: bytes,
    broker_ca_certificate_pem: bytes,
) -> FirmwareMqttProvisioningWorkflow:
    service = FirmwareMqttProvisioningService(
        store=store,
        provisioner_key_bytes=PA_SEED,
    )
    authority = FirmwareMqttCertificateAuthority(
        ca_certificate_pem=client_ca_certificate_pem,
        ca_private_key_pem=client_ca_private_key_pem,
        validity_days=90,
        serial_number_factory=lambda: 17,
    )
    return FirmwareMqttProvisioningWorkflow(
        service=service,
        certificate_authority=authority,
        broker_ca_certificate_pem=broker_ca_certificate_pem,
    )


async def test_workflow_issues_minimal_client_certificate_and_install_request(
    tmp_path,
) -> None:
    device_layer1_key = ed25519.Ed25519PrivateKey.generate()
    store = await _open_approved_store(
        tmp_path,
        device_public_key=device_layer1_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ),
    )
    client_ca_key, client_ca_pem, client_ca_key_pem = _ca_material(
        common_name="Ori MQTT Client CA"
    )
    _, broker_ca_pem, _ = _ca_material(common_name="Ori MQTT Broker CA")
    workflow = _workflow(
        store,
        client_ca_certificate_pem=client_ca_pem,
        client_ca_private_key_pem=client_ca_key_pem,
        broker_ca_certificate_pem=broker_ca_pem,
    )
    try:
        issued_csr = await workflow.create_csr_request(
            device_id=DEVICE_ID,
            actor="operator-17",
            reason="initial-mqtt-enrollment",
        )
        transport_key, csr_pem = _device_csr()
        csr_message = _signed_device_message(
            device_layer1_key,
            outer_field="response",
            value={
                "anchor_epoch_id": ANCHOR_EPOCH,
                "csr_pem_b64": base64.b64encode(csr_pem).decode("ascii"),
                "device_id": DEVICE_ID,
                "kind": "csr",
                "provision_seq": issued_csr.provision_seq,
                "v": 1,
            },
        )
        enrollment = await workflow.prepare_install(
            issued_csr_request=issued_csr,
            csr_response_message=csr_message,
            actor="operator-17",
            reason="initial-mqtt-enrollment",
            broker_uri="mqtts://broker.example:8883",
            time_server="time.example",
            now=NOW,
        )

        certificate = x509.load_pem_x509_certificate(
            enrollment.certificate.certificate_pem
        )
        client_ca_key.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
        assert (
            certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            == DEVICE_ID
        )
        assert (
            certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value.ca
            is False
        )
        assert certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
        assert certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) == transport_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert enrollment.install_request.provision_seq == 2
        assert enrollment.certificate.certificate_sha256 == (
            "sha256:"
            + hashlib.sha256(enrollment.certificate.certificate_pem).hexdigest()
        )
        assert (
            enrollment.install_request.certificate_sha256
            == enrollment.certificate.certificate_sha256
        )
        assert b"PRIVATE KEY" not in enrollment.install_request.message
        assert b"PRIVATE KEY" not in enrollment.certificate.certificate_pem
        install_result = _signed_device_message(
            device_layer1_key,
            outer_field="result",
            value={
                "anchor_epoch_id": ANCHOR_EPOCH,
                "device_id": DEVICE_ID,
                "kind": "install",
                "provision_seq": enrollment.install_request.provision_seq,
                "v": 1,
                "verdict": "accepted",
            },
        )
        assert (await workflow.verify_install_result(enrollment, install_result))[
            "verdict"
        ] == "accepted"

        audits = await store.list_firmware_mqtt_provisioning_audit(DEVICE_ID)
        assert [
            (row["event_kind"], row["operation_kind"], row["verdict"]) for row in audits
        ] == [
            ("request_signed", "create_csr", ""),
            ("response_verified", "create_csr", "accepted"),
            ("request_signed", "install", ""),
            ("response_verified", "install", "accepted"),
        ]
        assert audits[-1]["certificate_sha256"] == (
            enrollment.certificate.certificate_sha256
        )
        row = await store.get_firmware_device(DEVICE_ID)
        assert row is not None
        assert row["last_provision_seq"] == 2
    finally:
        await store.close()


async def test_valid_layer1_wrapper_with_non_p256_csr_is_audited_and_refused(
    tmp_path,
) -> None:
    device_layer1_key = ed25519.Ed25519PrivateKey.generate()
    store = await _open_approved_store(
        tmp_path,
        device_public_key=device_layer1_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ),
    )
    _, client_ca_pem, client_ca_key_pem = _ca_material(common_name="Ori MQTT Client CA")
    _, broker_ca_pem, _ = _ca_material(common_name="Ori MQTT Broker CA")
    workflow = _workflow(
        store,
        client_ca_certificate_pem=client_ca_pem,
        client_ca_private_key_pem=client_ca_key_pem,
        broker_ca_certificate_pem=broker_ca_pem,
    )
    try:
        issued_csr = await workflow.create_csr_request(
            device_id=DEVICE_ID,
            actor="operator-17",
            reason="initial-mqtt-enrollment",
        )
        _, rsa_csr_pem = _device_csr(
            key=rsa.generate_private_key(public_exponent=65537, key_size=2048)
        )
        csr_message = _signed_device_message(
            device_layer1_key,
            outer_field="response",
            value={
                "anchor_epoch_id": ANCHOR_EPOCH,
                "csr_pem_b64": base64.b64encode(rsa_csr_pem).decode("ascii"),
                "device_id": DEVICE_ID,
                "kind": "csr",
                "provision_seq": issued_csr.provision_seq,
                "v": 1,
            },
        )
        with pytest.raises(
            FirmwareMqttResponseValidationError,
            match="invalid P-256 CSR material",
        ) as exc_info:
            await workflow.prepare_install(
                issued_csr_request=issued_csr,
                csr_response_message=csr_message,
                actor="operator-17",
                reason="initial-mqtt-enrollment",
                broker_uri="mqtts://broker.example:8883",
                time_server="time.example",
                now=NOW,
            )
        assert exc_info.value.verdict == "invalid_material"

        audits = await store.list_firmware_mqtt_provisioning_audit(DEVICE_ID)
        assert [
            (row["event_kind"], row["operation_kind"], row["verdict"]) for row in audits
        ] == [
            ("request_signed", "create_csr", ""),
            ("response_verified", "create_csr", "invalid_material"),
        ]
        row = await store.get_firmware_device(DEVICE_ID)
        assert row is not None
        assert row["last_provision_seq"] == 1
    finally:
        await store.close()


def test_authority_refuses_mismatched_key_and_non_ca_certificate() -> None:
    _, ca_pem, _ = _ca_material(common_name="Ori MQTT Client CA")
    _, _, other_key_pem = _ca_material(common_name="Other CA")
    with pytest.raises(FirmwareMqttCertificateError, match="does not match"):
        FirmwareMqttCertificateAuthority(
            ca_certificate_pem=ca_pem,
            ca_private_key_pem=other_key_pem,
        )

    _, leaf_pem, leaf_key_pem = _ca_material(
        common_name="Not A CA",
        is_ca=False,
    )
    with pytest.raises(FirmwareMqttCertificateError, match="not a CA"):
        FirmwareMqttCertificateAuthority(
            ca_certificate_pem=leaf_pem,
            ca_private_key_pem=leaf_key_pem,
        )


def test_authority_refuses_wrong_csr_identity_without_issuing() -> None:
    _, ca_pem, ca_key_pem = _ca_material(common_name="Ori MQTT Client CA")
    authority = FirmwareMqttCertificateAuthority(
        ca_certificate_pem=ca_pem,
        ca_private_key_pem=ca_key_pem,
    )
    _, csr_pem = _device_csr(common_name="ori-fw-someone-else")
    with pytest.raises(FirmwareMqttCertificateError, match="equal device_id"):
        authority.validate_device_csr(csr_pem, device_id=DEVICE_ID)
    with pytest.raises(FirmwareMqttCertificateError, match="fleet identifier"):
        authority.validate_device_csr(csr_pem, device_id="../other-device")


def test_workflow_refuses_non_ca_or_private_broker_trust_material() -> None:
    _, client_ca_pem, client_ca_key_pem = _ca_material(common_name="Ori MQTT Client CA")
    authority = FirmwareMqttCertificateAuthority(
        ca_certificate_pem=client_ca_pem,
        ca_private_key_pem=client_ca_key_pem,
    )
    _, leaf_pem, leaf_key_pem = _ca_material(
        common_name="Broker Leaf",
        is_ca=False,
    )
    service = FirmwareMqttProvisioningService(
        store=None,
        provisioner_key_bytes=PA_SEED,
    )
    with pytest.raises(FirmwareMqttCertificateError, match="not a CA"):
        FirmwareMqttProvisioningWorkflow(
            service=service,
            certificate_authority=authority,
            broker_ca_certificate_pem=leaf_pem,
        )
    with pytest.raises(FirmwareMqttCertificateError, match="required"):
        FirmwareMqttProvisioningWorkflow(
            service=service,
            certificate_authority=authority,
            broker_ca_certificate_pem=client_ca_pem + leaf_key_pem,
        )


def test_issued_certificate_never_copies_csr_ca_request() -> None:
    _, ca_pem, ca_key_pem = _ca_material(common_name="Ori MQTT Client CA")
    authority = FirmwareMqttCertificateAuthority(
        ca_certificate_pem=ca_pem,
        ca_private_key_pem=ca_key_pem,
        serial_number_factory=lambda: 21,
    )
    transport_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DEVICE_ID)]))
        .add_extension(x509.BasicConstraints(ca=True, path_length=3), True)
        .sign(transport_key, hashes.SHA256())
    )
    issued = authority.issue_client_certificate(
        csr,
        device_id=DEVICE_ID,
        now=NOW,
    )
    certificate = x509.load_pem_x509_certificate(issued.certificate_pem)
    assert certificate.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value == x509.BasicConstraints(ca=False, path_length=None)
