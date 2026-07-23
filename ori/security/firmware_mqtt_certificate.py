# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Constrained client-certificate issuance for firmware MQTT identities."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

__all__ = [
    "FirmwareMqttCertificateAuthority",
    "FirmwareMqttCertificateError",
    "IssuedFirmwareMqttCertificate",
]

_PrivateKey = (
    rsa.RSAPrivateKey
    | ec.EllipticCurvePrivateKey
    | ed25519.Ed25519PrivateKey
    | ed448.Ed448PrivateKey
)
_CaPublicKey = (
    rsa.RSAPublicKey
    | ec.EllipticCurvePublicKey
    | ed25519.Ed25519PublicKey
    | ed448.Ed448PublicKey
)
_DEVICE_ID = re.compile(r"^[A-Za-z0-9._-]{1,48}$")


class FirmwareMqttCertificateError(ValueError):
    """CSR or certificate-authority material cannot satisfy the contract."""


@dataclass(frozen=True)
class IssuedFirmwareMqttCertificate:
    """Public certificate output; device private-key material is never present."""

    certificate_pem: bytes
    certificate_sha256: str
    serial_number: int
    not_valid_before: datetime
    not_valid_after: datetime


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _certificate_bounds(certificate: x509.Certificate) -> tuple[datetime, datetime]:
    return (
        _utc(certificate.not_valid_before_utc),
        _utc(certificate.not_valid_after_utc),
    )


def _device_id(value: str) -> str:
    if not isinstance(value, str) or _DEVICE_ID.fullmatch(value) is None:
        raise FirmwareMqttCertificateError(
            "device_id is not a valid firmware fleet identifier"
        )
    return value


def _public_key_der(key: object) -> bytes:
    public_bytes = getattr(key, "public_bytes", None)
    if not callable(public_bytes):
        raise FirmwareMqttCertificateError("certificate key has no public encoding")
    return cast(
        bytes,
        public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


class FirmwareMqttCertificateAuthority:
    """Issues minimal P-256 client-auth certificates from verified CSRs."""

    def __init__(
        self,
        *,
        ca_certificate_pem: bytes,
        ca_private_key_pem: bytes,
        ca_private_key_password: bytes | None = None,
        validity_days: int = 90,
        serial_number_factory: Callable[[], int] = x509.random_serial_number,
    ) -> None:
        if (
            isinstance(validity_days, bool)
            or not isinstance(validity_days, int)
            or not 1 <= validity_days <= 397
        ):
            raise FirmwareMqttCertificateError("validity_days must be within 1..397")
        if not isinstance(ca_certificate_pem, bytes) or not ca_certificate_pem:
            raise FirmwareMqttCertificateError("CA certificate PEM is required")
        if not isinstance(ca_private_key_pem, bytes) or not ca_private_key_pem:
            raise FirmwareMqttCertificateError("CA private key PEM is required")
        try:
            certificate = x509.load_pem_x509_certificate(ca_certificate_pem)
        except ValueError as exc:
            raise FirmwareMqttCertificateError("CA certificate PEM is invalid") from exc
        try:
            private_key = serialization.load_pem_private_key(
                ca_private_key_pem,
                password=ca_private_key_password,
            )
        except (TypeError, ValueError) as exc:
            raise FirmwareMqttCertificateError("CA private key PEM is invalid") from exc
        if not isinstance(
            private_key,
            (
                rsa.RSAPrivateKey,
                ec.EllipticCurvePrivateKey,
                ed25519.Ed25519PrivateKey,
                ed448.Ed448PrivateKey,
            ),
        ):
            raise FirmwareMqttCertificateError(
                "CA private key algorithm is unsupported"
            )
        if _public_key_der(private_key.public_key()) != _public_key_der(
            certificate.public_key()
        ):
            raise FirmwareMqttCertificateError(
                "CA private key does not match the CA certificate"
            )
        try:
            basic_constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound as exc:
            raise FirmwareMqttCertificateError(
                "CA certificate must declare BasicConstraints"
            ) from exc
        if not basic_constraints.ca:
            raise FirmwareMqttCertificateError("CA certificate is not a CA")
        try:
            key_usage = certificate.extensions.get_extension_for_class(
                x509.KeyUsage
            ).value
        except x509.ExtensionNotFound:
            key_usage = None
        if key_usage is not None and not key_usage.key_cert_sign:
            raise FirmwareMqttCertificateError(
                "CA certificate does not permit certificate signing"
            )
        self._certificate = certificate
        self._private_key: _PrivateKey = private_key
        self._validity_days = validity_days
        self._serial_number_factory = serial_number_factory

    def validate_device_csr(
        self,
        csr_pem: bytes,
        *,
        device_id: str,
    ) -> x509.CertificateSigningRequest:
        """Verify one firmware CSR without copying requested extensions."""

        if not isinstance(csr_pem, bytes) or not csr_pem:
            raise FirmwareMqttCertificateError("device CSR PEM is required")
        expected_device_id = _device_id(device_id)
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
        except ValueError as exc:
            raise FirmwareMqttCertificateError("device CSR PEM is invalid") from exc
        if not csr.is_signature_valid:
            raise FirmwareMqttCertificateError("device CSR signature is invalid")
        public_key = csr.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise FirmwareMqttCertificateError(
                "device CSR must prove a P-256 transport key"
            )
        common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(common_names) != 1 or common_names[0].value != expected_device_id:
            raise FirmwareMqttCertificateError(
                "device CSR common name must equal device_id"
            )
        return csr

    def issue_client_certificate(
        self,
        csr: x509.CertificateSigningRequest,
        *,
        device_id: str,
        now: datetime | None = None,
    ) -> IssuedFirmwareMqttCertificate:
        """Issue a leaf certificate containing only runtime-owned constraints."""

        if not isinstance(csr, x509.CertificateSigningRequest):
            raise FirmwareMqttCertificateError("a validated device CSR is required")
        expected_device_id = _device_id(device_id)
        # Revalidate at the issuance boundary so a caller cannot bypass the
        # transport-key algorithm or subject binding by constructing a CSR object.
        validated = self.validate_device_csr(
            csr.public_bytes(serialization.Encoding.PEM),
            device_id=expected_device_id,
        )
        current = _utc(now or datetime.now(UTC))
        ca_not_before, ca_not_after = _certificate_bounds(self._certificate)
        if current < ca_not_before or current >= ca_not_after:
            raise FirmwareMqttCertificateError(
                "CA certificate is not valid at issuance time"
            )
        not_valid_before = max(current - timedelta(minutes=5), ca_not_before)
        not_valid_after = min(
            current + timedelta(days=self._validity_days),
            ca_not_after,
        )
        if not_valid_after <= current:
            raise FirmwareMqttCertificateError(
                "CA validity cannot cover a client certificate"
            )
        serial_number = self._serial_number_factory()
        if (
            isinstance(serial_number, bool)
            or not isinstance(serial_number, int)
            or not 1 <= serial_number < 2**159
        ):
            raise FirmwareMqttCertificateError(
                "serial number factory returned an invalid X.509 serial"
            )
        certificate_builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, expected_device_id)])
            )
            .issuer_name(self._certificate.subject)
            .public_key(validated.public_key())
            .serial_number(serial_number)
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(validated.public_key()),
                False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    cast(_CaPublicKey, self._certificate.public_key())
                ),
                False,
            )
        )
        if isinstance(
            self._private_key,
            (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey),
        ):
            certificate = certificate_builder.sign(
                private_key=self._private_key,
                algorithm=None,
            )
        else:
            certificate = certificate_builder.sign(
                private_key=self._private_key,
                algorithm=hashes.SHA256(),
            )
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        return IssuedFirmwareMqttCertificate(
            certificate_pem=certificate_pem,
            certificate_sha256=(
                "sha256:" + hashlib.sha256(certificate_pem).hexdigest()
            ),
            serial_number=serial_number,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
        )
