# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Transport-neutral firmware MQTT certificate-provisioning workflow."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography import x509

from ori.security.firmware.mqtt_certificate import (
    FirmwareMqttCertificateAuthority,
    FirmwareMqttCertificateError,
    IssuedFirmwareMqttCertificate,
)
from ori.security.firmware.mqtt_provisioning import (
    FirmwareMqttProvisioningService,
    FirmwareMqttResponseValidationError,
    SignedProvisioningRequest,
)

__all__ = [
    "FirmwareMqttCertificateEnrollment",
    "FirmwareMqttProvisioningWorkflow",
]


@dataclass(frozen=True)
class FirmwareMqttCertificateEnrollment:
    """Public artifacts prepared for delivery; no private key is present."""

    csr_response: dict[str, Any]
    certificate: IssuedFirmwareMqttCertificate
    install_request: SignedProvisioningRequest


class FirmwareMqttProvisioningWorkflow:
    """Coordinates issuance without choosing MQTT, serial, USB, or a CLI."""

    def __init__(
        self,
        *,
        service: FirmwareMqttProvisioningService,
        certificate_authority: FirmwareMqttCertificateAuthority,
        broker_ca_certificate_pem: bytes,
    ) -> None:
        if (
            not isinstance(broker_ca_certificate_pem, bytes)
            or not broker_ca_certificate_pem
            or b"PRIVATE KEY" in broker_ca_certificate_pem.upper()
        ):
            raise FirmwareMqttCertificateError("broker CA certificate PEM is required")
        try:
            broker_ca = x509.load_pem_x509_certificate(broker_ca_certificate_pem)
        except ValueError as exc:
            raise FirmwareMqttCertificateError(
                "broker CA certificate PEM is invalid"
            ) from exc
        try:
            broker_constraints = broker_ca.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound as exc:
            raise FirmwareMqttCertificateError(
                "broker CA certificate must declare BasicConstraints"
            ) from exc
        if not broker_constraints.ca:
            raise FirmwareMqttCertificateError("broker CA certificate is not a CA")
        self._service = service
        self._certificate_authority = certificate_authority
        self._broker_ca_certificate_pem = broker_ca_certificate_pem

    async def create_csr_request(
        self,
        *,
        device_id: str,
        actor: str,
        reason: str,
    ) -> SignedProvisioningRequest:
        return await self._service.create_csr(
            device_id=device_id,
            actor=actor,
            reason=reason,
        )

    async def prepare_install(
        self,
        *,
        issued_csr_request: SignedProvisioningRequest,
        csr_response_message: bytes,
        actor: str,
        reason: str,
        broker_uri: str,
        time_server: str,
        now: datetime | None = None,
    ) -> FirmwareMqttCertificateEnrollment:
        """Verify CSR provenance and proof before issuing an install request."""

        if issued_csr_request.kind != "create_csr":
            raise FirmwareMqttCertificateError(
                "prepare_install requires an issued create_csr request"
            )
        validated_csr: x509.CertificateSigningRequest | None = None

        def validate_csr_response(value: dict[str, Any]) -> None:
            nonlocal validated_csr
            try:
                csr_pem = base64.b64decode(
                    str(value["csr_pem_b64"]).encode("ascii"),
                    validate=True,
                )
                validated_csr = self._certificate_authority.validate_device_csr(
                    csr_pem,
                    device_id=issued_csr_request.device_id,
                )
            except (KeyError, UnicodeEncodeError, ValueError) as exc:
                raise FirmwareMqttResponseValidationError(
                    "invalid_material",
                    "signed CSR response contains invalid P-256 CSR material",
                ) from exc

        csr_response = await self._service.verify_response(
            issued_csr_request,
            csr_response_message,
            semantic_validator=validate_csr_response,
        )
        if validated_csr is None:
            raise RuntimeError("CSR validator completed without a validated CSR")
        certificate = self._certificate_authority.issue_client_certificate(
            validated_csr,
            device_id=issued_csr_request.device_id,
            now=now,
        )
        install_request = await self._service.install(
            device_id=issued_csr_request.device_id,
            actor=actor,
            reason=reason,
            broker_ca_pem_b64=base64.b64encode(self._broker_ca_certificate_pem).decode(
                "ascii"
            ),
            broker_uri=broker_uri,
            client_cert_pem_b64=base64.b64encode(certificate.certificate_pem).decode(
                "ascii"
            ),
            time_server=time_server,
        )
        return FirmwareMqttCertificateEnrollment(
            csr_response=csr_response,
            certificate=certificate,
            install_request=install_request,
        )

    async def verify_install_result(
        self,
        enrollment: FirmwareMqttCertificateEnrollment,
        result_message: bytes,
    ) -> dict[str, Any]:
        """Verify and audit a diagnostic result.

        A verified response is authentic, not necessarily successful. Callers
        must inspect the returned ``verdict`` and grant no transport authority
        unless it is exactly ``accepted``.
        """
        return await self._service.verify_response(
            enrollment.install_request,
            result_message,
        )

    async def verify_response(
        self,
        issued_request: SignedProvisioningRequest,
        response_message: bytes,
    ) -> dict[str, Any]:
        """Verify a persisted install, revoke, or status response.

        Operator transports reconstruct public issued-request metadata after a
        runtime restart. They must still delegate signature, anchor, request,
        and audit validation to the provisioning service.
        """
        if issued_request.kind not in {"install", "revoke", "status"}:
            raise FirmwareMqttCertificateError(
                "verify_response requires an install, revoke, or status request"
            )
        return await self._service.verify_response(
            issued_request,
            response_message,
        )

    async def revoke_request(
        self,
        *,
        device_id: str,
        actor: str,
        reason: str,
    ) -> SignedProvisioningRequest:
        return await self._service.revoke(
            device_id=device_id,
            actor=actor,
            reason=reason,
        )

    async def status_request(
        self,
        *,
        device_id: str,
        actor: str,
        request_id: str,
    ) -> SignedProvisioningRequest:
        return await self._service.status(
            device_id=device_id,
            actor=actor,
            request_id=request_id,
        )
