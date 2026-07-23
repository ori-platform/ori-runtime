# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Signed firmware MQTT transport-identity provisioning primitives.

Implements the fixed-byte issuer and response-verifier grammar from
``ori-specs/firmware-mqtt-provisioning/v1.md``. Transport and certificate
issuance remain outside this module: callers receive public signed messages,
and the provisioning-authority private seed never crosses this boundary.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ori.utils.time_utils import now_ms

__all__ = [
    "FirmwareMqttProvisioningError",
    "FirmwareMqttResponseValidationError",
    "FirmwareMqttProvisioningService",
    "FirmwareMqttProvisioningSigner",
    "SignedProvisioningRequest",
    "build_create_csr_request",
    "build_install_request",
    "build_revoke_request",
    "build_status_request",
    "validate_broker_uri",
    "validate_time_server",
    "verify_device_message",
]

_FLEET_ID = re.compile(r"^[A-Za-z0-9._-]+$")
_ANCHOR_EPOCH = re.compile(r"^sha256:[0-9a-f]{64}$")
_CERTIFICATE_SHA256 = _ANCHOR_EPOCH
_BROKER_URI = re.compile(
    r"^mqtts://(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?::[0-9]{1,5})?$"
)
_DNS_HOST = re.compile(
    r"^(?=.{1,255}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_SEQ_MAX = 2**53 - 1
_PEM_MAX = 4095
_SIGNATURE_PREFIX = "ed25519:"
_VERDICTS = frozenset(
    {
        "accepted",
        "malformed",
        "wrong_device",
        "bad_signature",
        "anchor_not_approved",
        "anchor_epoch_mismatch",
        "replayed",
        "audit_required",
        "unsupported_operation",
        "invalid_material",
        "no_pending_key",
        "key_certificate_mismatch",
        "storage_failure",
    }
)
_MUTATION_KINDS = frozenset({"create_csr", "install", "revoke"})


class FirmwareMqttProvisioningError(ValueError):
    """A provisioning message cannot satisfy the v1 contract."""

    def __init__(self, message: str, *, code: str = "provisioning_refused") -> None:
        super().__init__(message)
        self.code = code


class FirmwareMqttResponseValidationError(FirmwareMqttProvisioningError):
    """A signed response failed a normative semantic check."""

    def __init__(self, verdict: str, message: str) -> None:
        if verdict == "accepted" or verdict not in _VERDICTS:
            raise ValueError(f"invalid rejection verdict: {verdict!r}")
        super().__init__(message)
        self.verdict = verdict


@dataclass(frozen=True)
class SignedProvisioningRequest:
    """Public output of one durably audited issuer operation."""

    message: bytes
    request: bytes
    device_id: str
    anchor_epoch_id: str
    kind: str
    provision_seq: int | None
    request_id: str
    actor: str
    reason: str
    request_sha256: str
    certificate_sha256: str
    broker_uri: str
    audit_id: int


def _fleet_id(value: str, field: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not (1 <= len(value) <= maximum)
        or _FLEET_ID.fullmatch(value) is None
    ):
        raise FirmwareMqttProvisioningError(f"{field} is not a valid fleet identifier")
    return value


def _epoch(value: str, field: str = "anchor_epoch_id") -> str:
    if not isinstance(value, str) or _ANCHOR_EPOCH.fullmatch(value) is None:
        raise FirmwareMqttProvisioningError(
            f"{field} must be sha256: + 64 lowercase hex"
        )
    return value


def _sequence(value: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= _SEQ_MAX
    ):
        raise FirmwareMqttProvisioningError("provision_seq is out of range")
    return value


def _reason(value: str) -> str:
    if not isinstance(value, str):
        raise FirmwareMqttProvisioningError("reason must be UTF-8 text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise FirmwareMqttProvisioningError("reason must be UTF-8 text") from exc
    if (
        not encoded
        or len(encoded) > 128
        or '"' in value
        or "\\" in value
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise FirmwareMqttProvisioningError("reason violates the audit grammar")
    return value


def _canonical_pem_b64(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise FirmwareMqttProvisioningError(f"{field} must be canonical base64")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise FirmwareMqttProvisioningError(
            f"{field} must be canonical base64"
        ) from exc
    if (
        not 1 <= len(decoded) <= _PEM_MAX
        or base64.b64encode(decoded).decode("ascii") != value
        or b"PRIVATE KEY" in decoded.upper()
    ):
        raise FirmwareMqttProvisioningError(f"{field} is invalid public PEM material")
    try:
        decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FirmwareMqttProvisioningError(
            f"{field} must decode to UTF-8 PEM"
        ) from exc
    return value


def validate_broker_uri(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > 255
        or _BROKER_URI.fullmatch(value) is None
    ):
        raise FirmwareMqttProvisioningError(
            "broker_uri is not an eligible MQTT TLS URI"
        )
    return value


def validate_time_server(value: str) -> str:
    if not isinstance(value, str) or _DNS_HOST.fullmatch(value) is None:
        raise FirmwareMqttProvisioningError("time_server must be a DNS host")
    return value


def build_create_csr_request(
    *,
    actor: str,
    anchor_epoch_id: str,
    device_id: str,
    provision_seq: int,
    reason: str,
) -> bytes:
    return (
        '{"actor":"%s","anchor_epoch_id":"%s","device_id":"%s",'
        '"kind":"create_csr","provision_seq":%d,"reason":"%s","v":1}'
        % (
            _fleet_id(actor, "actor", maximum=64),
            _epoch(anchor_epoch_id),
            _fleet_id(device_id, "device_id", maximum=48),
            _sequence(provision_seq),
            _reason(reason),
        )
    ).encode()


def build_install_request(
    *,
    actor: str,
    anchor_epoch_id: str,
    broker_ca_pem_b64: str,
    broker_uri: str,
    client_cert_pem_b64: str,
    device_id: str,
    provision_seq: int,
    reason: str,
    time_server: str,
) -> bytes:
    broker_uri = validate_broker_uri(broker_uri)
    time_server = validate_time_server(time_server)
    return (
        '{"actor":"%s","anchor_epoch_id":"%s","broker_ca_pem_b64":"%s",'
        '"broker_uri":"%s","client_cert_pem_b64":"%s","device_id":"%s",'
        '"kind":"install","provision_seq":%d,"reason":"%s",'
        '"time_server":"%s","v":1}'
        % (
            _fleet_id(actor, "actor", maximum=64),
            _epoch(anchor_epoch_id),
            _canonical_pem_b64(broker_ca_pem_b64, "broker_ca_pem_b64"),
            broker_uri,
            _canonical_pem_b64(client_cert_pem_b64, "client_cert_pem_b64"),
            _fleet_id(device_id, "device_id", maximum=48),
            _sequence(provision_seq),
            _reason(reason),
            time_server,
        )
    ).encode()


def build_revoke_request(
    *,
    actor: str,
    anchor_epoch_id: str,
    device_id: str,
    provision_seq: int,
    reason: str,
) -> bytes:
    return (
        '{"actor":"%s","anchor_epoch_id":"%s","device_id":"%s",'
        '"kind":"revoke","provision_seq":%d,"reason":"%s","v":1}'
        % (
            _fleet_id(actor, "actor", maximum=64),
            _epoch(anchor_epoch_id),
            _fleet_id(device_id, "device_id", maximum=48),
            _sequence(provision_seq),
            _reason(reason),
        )
    ).encode()


def build_status_request(
    *,
    actor: str,
    anchor_epoch_id: str,
    device_id: str,
    request_id: str,
) -> bytes:
    return (
        '{"actor":"%s","anchor_epoch_id":"%s","device_id":"%s",'
        '"kind":"status","request_id":"%s","v":1}'
        % (
            _fleet_id(actor, "actor", maximum=64),
            _epoch(anchor_epoch_id),
            _fleet_id(device_id, "device_id", maximum=48),
            _fleet_id(request_id, "request_id", maximum=64),
        )
    ).encode()


class FirmwareMqttProvisioningSigner:
    """Provisioning-authority signer for pre-built canonical requests."""

    def __init__(self, private_key_bytes: bytes) -> None:
        if not isinstance(private_key_bytes, bytes) or len(private_key_bytes) != 32:
            raise FirmwareMqttProvisioningError(
                "provisioning-authority key must be 32 raw Ed25519 seed bytes"
            )
        self._key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)

    def sign_request(self, request: bytes) -> bytes:
        if not isinstance(request, bytes) or not request:
            raise FirmwareMqttProvisioningError(
                "request must be non-empty canonical bytes"
            )
        value = _strict_object(request)
        if request != _canonical_request_object(value):
            raise FirmwareMqttProvisioningError("request is not canonical")
        signature = base64.b64encode(self._key.sign(request)).decode("ascii")
        return (
            b'{"request":'
            + request
            + b',"signature":"ed25519:'
            + signature.encode("ascii")
            + b'"}'
        )


class FirmwareMqttProvisioningService:
    """Store-backed request issuer; the PA seed remains inside the runtime."""

    def __init__(self, *, store: Any, provisioner_key_bytes: bytes) -> None:
        self._store = store
        self._signer = FirmwareMqttProvisioningSigner(provisioner_key_bytes)

    async def create_csr(
        self, *, device_id: str, actor: str, reason: str
    ) -> SignedProvisioningRequest:
        _fleet_id(device_id, "device_id", maximum=48)
        _fleet_id(actor, "actor", maximum=64)
        _reason(reason)
        row = await self._eligible_anchor(device_id, allow_revoked=False)
        provision_seq = await self._allocate_sequence(row, allow_revoked=False)
        request = build_create_csr_request(
            actor=actor,
            anchor_epoch_id=row["anchor_epoch_id"],
            device_id=device_id,
            provision_seq=provision_seq,
            reason=reason,
        )
        return await self._sign_and_audit(
            request=request,
            row=row,
            actor=actor,
            reason=reason,
            kind="create_csr",
            provision_seq=provision_seq,
        )

    async def install(
        self,
        *,
        device_id: str,
        actor: str,
        reason: str,
        broker_ca_pem_b64: str,
        broker_uri: str,
        client_cert_pem_b64: str,
        time_server: str,
    ) -> SignedProvisioningRequest:
        _fleet_id(device_id, "device_id", maximum=48)
        _fleet_id(actor, "actor", maximum=64)
        _reason(reason)
        _canonical_pem_b64(broker_ca_pem_b64, "broker_ca_pem_b64")
        client_cert = _canonical_pem_b64(client_cert_pem_b64, "client_cert_pem_b64")
        broker_uri = validate_broker_uri(broker_uri)
        time_server = validate_time_server(time_server)
        row = await self._eligible_anchor(device_id, allow_revoked=False)
        provision_seq = await self._allocate_sequence(row, allow_revoked=False)
        request = build_install_request(
            actor=actor,
            anchor_epoch_id=row["anchor_epoch_id"],
            broker_ca_pem_b64=broker_ca_pem_b64,
            broker_uri=broker_uri,
            client_cert_pem_b64=client_cert,
            device_id=device_id,
            provision_seq=provision_seq,
            reason=reason,
            time_server=time_server,
        )
        certificate_sha256 = (
            "sha256:" + hashlib.sha256(base64.b64decode(client_cert)).hexdigest()
        )
        return await self._sign_and_audit(
            request=request,
            row=row,
            actor=actor,
            reason=reason,
            kind="install",
            provision_seq=provision_seq,
            certificate_sha256=certificate_sha256,
            broker_uri=broker_uri,
        )

    async def revoke(
        self, *, device_id: str, actor: str, reason: str
    ) -> SignedProvisioningRequest:
        _fleet_id(device_id, "device_id", maximum=48)
        _fleet_id(actor, "actor", maximum=64)
        _reason(reason)
        row = await self._eligible_anchor(device_id, allow_revoked=True)
        provision_seq = await self._allocate_sequence(row, allow_revoked=True)
        request = build_revoke_request(
            actor=actor,
            anchor_epoch_id=row["anchor_epoch_id"],
            device_id=device_id,
            provision_seq=provision_seq,
            reason=reason,
        )
        return await self._sign_and_audit(
            request=request,
            row=row,
            actor=actor,
            reason=reason,
            kind="revoke",
            provision_seq=provision_seq,
        )

    async def status(
        self, *, device_id: str, actor: str, request_id: str
    ) -> SignedProvisioningRequest:
        _fleet_id(device_id, "device_id", maximum=48)
        _fleet_id(actor, "actor", maximum=64)
        _fleet_id(request_id, "request_id", maximum=64)
        row = await self._eligible_anchor(device_id, allow_revoked=True)
        request = build_status_request(
            actor=actor,
            anchor_epoch_id=row["anchor_epoch_id"],
            device_id=device_id,
            request_id=request_id,
        )
        return await self._sign_and_audit(
            request=request,
            row=row,
            actor=actor,
            reason="",
            kind="status",
            provision_seq=None,
            request_id=request_id,
        )

    async def verify_response(
        self,
        issued: SignedProvisioningRequest,
        message: bytes,
        *,
        semantic_validator: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Verify one response against its exact issued request and audit it."""
        allow_revoked = issued.kind in {"revoke", "status"}
        row = await self._eligible_anchor(issued.device_id, allow_revoked=allow_revoked)
        if row["anchor_epoch_id"] != issued.anchor_epoch_id:
            raise FirmwareMqttProvisioningError(
                "response anchor is no longer the eligible request anchor",
                code="anchor_changed",
            )
        try:
            public_key = base64.b64decode(
                str(row["public_key_b64"]).encode("ascii"), validate=True
            )
        except (UnicodeEncodeError, ValueError) as exc:
            raise FirmwareMqttProvisioningError(
                "eligible device public key is invalid",
                code="invalid_device_key",
            ) from exc
        try:
            value = verify_device_message(message, device_public_key_bytes=public_key)
        except FirmwareMqttProvisioningError as exc:
            detail = str(exc)
            code = "bad_signature" if "signature" in detail else "malformed_response"
            raise FirmwareMqttProvisioningError(detail, code=code) from exc
        if value.get("device_id") != issued.device_id:
            raise FirmwareMqttProvisioningError(
                "response device_id mismatch",
                code="device_response_mismatch",
            )
        if issued.kind == "status":
            if (
                value.get("kind") != "status"
                or value.get("request_id") != issued.request_id
            ):
                raise FirmwareMqttProvisioningError(
                    "status response mismatch",
                    code="device_response_mismatch",
                )
        elif issued.kind == "create_csr":
            if (
                value.get("kind") != "csr"
                or value.get("provision_seq") != issued.provision_seq
            ):
                raise FirmwareMqttProvisioningError(
                    "CSR response mismatch",
                    code="device_response_mismatch",
                )
            if value.get("anchor_epoch_id") != issued.anchor_epoch_id:
                raise FirmwareMqttProvisioningError(
                    "CSR anchor mismatch",
                    code="anchor_epoch_mismatch",
                )
        else:
            if (
                value.get("kind") != issued.kind
                or value.get("provision_seq") != issued.provision_seq
                or value.get("anchor_epoch_id") != issued.anchor_epoch_id
            ):
                raise FirmwareMqttProvisioningError(
                    "mutation result mismatch",
                    code="device_response_mismatch",
                )
        if semantic_validator is not None:
            try:
                semantic_validator(value)
            except FirmwareMqttResponseValidationError as exc:
                await self._audit_response(
                    issued=issued,
                    message=message,
                    verdict=exc.verdict,
                )
                raise
        await self._audit_response(
            issued=issued,
            message=message,
            verdict=str(value.get("verdict", "accepted")),
        )
        return value

    async def _audit_response(
        self,
        *,
        issued: SignedProvisioningRequest,
        message: bytes,
        verdict: str,
    ) -> None:
        await self._store.append_firmware_mqtt_provisioning_audit(
            device_id=issued.device_id,
            event_kind="response_verified",
            operation_kind=issued.kind,
            provision_seq=issued.provision_seq,
            request_id=issued.request_id,
            anchor_epoch_id=issued.anchor_epoch_id,
            actor=issued.actor,
            reason=issued.reason,
            request_sha256=issued.request_sha256,
            verdict=verdict,
            certificate_sha256=issued.certificate_sha256,
            broker_uri=issued.broker_uri,
            payload_sha256="sha256:" + hashlib.sha256(message).hexdigest(),
            occurred_at_ms=now_ms(),
        )

    async def _eligible_anchor(
        self, device_id: str, *, allow_revoked: bool
    ) -> dict[str, Any]:
        row = await self._store.get_firmware_device(device_id)
        if row is None:
            raise FirmwareMqttProvisioningError(
                f"unknown firmware device: {device_id!r}",
                code="anchor_unknown",
            )
        epoch = str(row.get("anchor_epoch_id", "") or "")
        _epoch(epoch)
        if row.get("revoked"):
            if not allow_revoked:
                raise FirmwareMqttProvisioningError(
                    f"device {device_id!r} is revoked",
                    code="device_revoked",
                )
            if not await self._store.firmware_activation_history_is_provable(device_id):
                raise FirmwareMqttProvisioningError(
                    f"device {device_id!r} has no provable retained active anchor",
                    code="anchor_history_unprovable",
                )
            intervals = await self._store.firmware_anchor_activation_intervals(
                device_id, epoch
            )
            if not intervals:
                raise FirmwareMqttProvisioningError(
                    f"device {device_id!r} anchor was never active",
                    code="anchor_history_unprovable",
                )
            return cast(dict[str, Any], row)
        if not row.get("approved"):
            raise FirmwareMqttProvisioningError(
                f"device {device_id!r} is not approved",
                code="anchor_not_approved",
            )
        status = await self._store.get_firmware_confirmation_status(device_id, epoch)
        if status != "confirmed":
            raise FirmwareMqttProvisioningError(
                f"device {device_id!r} epoch is not cross-store confirmed",
                code="anchor_not_confirmed",
            )
        return cast(dict[str, Any], row)

    async def _allocate_sequence(
        self, row: dict[str, Any], *, allow_revoked: bool
    ) -> int:
        try:
            return cast(
                int,
                await self._store.allocate_firmware_provision_seq(
                    row["device_id"],
                    expected_anchor_epoch_id=row["anchor_epoch_id"],
                    allow_revoked=allow_revoked,
                ),
            )
        except PermissionError as exc:
            raise FirmwareMqttProvisioningError(
                "firmware provisioning authority changed before signing",
                code="anchor_changed",
            ) from exc
        except OverflowError as exc:
            raise FirmwareMqttProvisioningError(
                "firmware provisioning sequence is exhausted",
                code="sequence_exhausted",
            ) from exc

    async def _sign_and_audit(
        self,
        *,
        request: bytes,
        row: dict[str, Any],
        actor: str,
        reason: str,
        kind: str,
        provision_seq: int | None,
        request_id: str = "",
        certificate_sha256: str = "",
        broker_uri: str = "",
    ) -> SignedProvisioningRequest:
        message = self._signer.sign_request(request)
        digest = request_sha256(request)
        audit_id = await self._store.append_firmware_mqtt_provisioning_audit(
            device_id=row["device_id"],
            event_kind="request_signed",
            operation_kind=kind,
            provision_seq=provision_seq,
            request_id=request_id,
            anchor_epoch_id=row["anchor_epoch_id"],
            actor=actor,
            reason=reason,
            request_sha256=digest,
            verdict="",
            certificate_sha256=certificate_sha256,
            broker_uri=broker_uri,
            payload_sha256="sha256:" + hashlib.sha256(message).hexdigest(),
            occurred_at_ms=now_ms(),
        )
        return SignedProvisioningRequest(
            message=message,
            request=request,
            device_id=row["device_id"],
            anchor_epoch_id=row["anchor_epoch_id"],
            kind=kind,
            provision_seq=provision_seq,
            request_id=request_id,
            actor=actor,
            reason=reason,
            request_sha256=digest,
            certificate_sha256=certificate_sha256,
            broker_uri=broker_uri,
            audit_id=audit_id,
        )


def _strict_object(raw: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise FirmwareMqttProvisioningError("duplicate JSON field")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FirmwareMqttProvisioningError("malformed device message") from exc
    if not isinstance(value, dict):
        raise FirmwareMqttProvisioningError("device message must be an object")
    return value


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not value.startswith(_SIGNATURE_PREFIX):
        raise FirmwareMqttProvisioningError("signature encoding is invalid")
    encoded = value[len(_SIGNATURE_PREFIX) :]
    try:
        signature = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise FirmwareMqttProvisioningError("signature encoding is invalid") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded:
        raise FirmwareMqttProvisioningError("signature encoding is invalid")
    return signature


def _canonical_request_object(value: dict[str, Any]) -> bytes:
    if value.get("v") != 1 or isinstance(value.get("v"), bool):
        raise FirmwareMqttProvisioningError("request version is invalid")
    kind = value.get("kind")
    common = {"actor", "anchor_epoch_id", "device_id", "kind", "v"}
    if kind == "create_csr":
        if set(value) != common | {"provision_seq", "reason"}:
            raise FirmwareMqttProvisioningError("create_csr fields are invalid")
        return build_create_csr_request(
            actor=value["actor"],
            anchor_epoch_id=value["anchor_epoch_id"],
            device_id=value["device_id"],
            provision_seq=value["provision_seq"],
            reason=value["reason"],
        )
    if kind == "install":
        if set(value) != common | {
            "broker_ca_pem_b64",
            "broker_uri",
            "client_cert_pem_b64",
            "provision_seq",
            "reason",
            "time_server",
        }:
            raise FirmwareMqttProvisioningError("install fields are invalid")
        return build_install_request(
            actor=value["actor"],
            anchor_epoch_id=value["anchor_epoch_id"],
            broker_ca_pem_b64=value["broker_ca_pem_b64"],
            broker_uri=value["broker_uri"],
            client_cert_pem_b64=value["client_cert_pem_b64"],
            device_id=value["device_id"],
            provision_seq=value["provision_seq"],
            reason=value["reason"],
            time_server=value["time_server"],
        )
    if kind == "revoke":
        if set(value) != common | {"provision_seq", "reason"}:
            raise FirmwareMqttProvisioningError("revoke fields are invalid")
        return build_revoke_request(
            actor=value["actor"],
            anchor_epoch_id=value["anchor_epoch_id"],
            device_id=value["device_id"],
            provision_seq=value["provision_seq"],
            reason=value["reason"],
        )
    if kind == "status":
        if set(value) != common | {"request_id"}:
            raise FirmwareMqttProvisioningError("status fields are invalid")
        return build_status_request(
            actor=value["actor"],
            anchor_epoch_id=value["anchor_epoch_id"],
            device_id=value["device_id"],
            request_id=value["request_id"],
        )
    raise FirmwareMqttProvisioningError("unsupported provisioning operation")


def _canonical_response_object(outer_field: str, value: dict[str, Any]) -> bytes:
    if value.get("v") != 1 or isinstance(value.get("v"), bool):
        raise FirmwareMqttProvisioningError("response version is invalid")
    kind = value.get("kind")
    if outer_field == "response" and kind == "csr":
        if set(value) != {
            "anchor_epoch_id",
            "csr_pem_b64",
            "device_id",
            "kind",
            "provision_seq",
            "v",
        }:
            raise FirmwareMqttProvisioningError("CSR response fields are invalid")
        return (
            '{"anchor_epoch_id":"%s","csr_pem_b64":"%s","device_id":"%s",'
            '"kind":"csr","provision_seq":%d,"v":1}'
            % (
                _epoch(value["anchor_epoch_id"]),
                _canonical_pem_b64(value["csr_pem_b64"], "csr_pem_b64"),
                _fleet_id(value["device_id"], "device_id", maximum=48),
                _sequence(value["provision_seq"]),
            )
        ).encode()
    if outer_field == "response" and kind == "status":
        expected = {
            "active_anchor_epoch_id",
            "active_certificate_sha256",
            "candidate_anchor_epoch_id",
            "candidate_certificate_sha256",
            "device_id",
            "kind",
            "pending_csr",
            "request_id",
            "revoked",
            "v",
        }
        if set(value) != expected:
            raise FirmwareMqttProvisioningError("status response fields are invalid")
        for field in ("active_anchor_epoch_id", "candidate_anchor_epoch_id"):
            if value[field] is not None:
                _epoch(value[field], field)
        for field in (
            "active_certificate_sha256",
            "candidate_certificate_sha256",
        ):
            if value[field] is not None and (
                not isinstance(value[field], str)
                or _CERTIFICATE_SHA256.fullmatch(value[field]) is None
            ):
                raise FirmwareMqttProvisioningError(f"{field} must be null or sha256")
        if type(value["pending_csr"]) is not bool or type(value["revoked"]) is not bool:
            raise FirmwareMqttProvisioningError("status booleans are invalid")
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    if outer_field == "result" and kind in _MUTATION_KINDS:
        if set(value) != {
            "anchor_epoch_id",
            "device_id",
            "kind",
            "provision_seq",
            "v",
            "verdict",
        }:
            raise FirmwareMqttProvisioningError("mutation result fields are invalid")
        if value["verdict"] not in _VERDICTS:
            raise FirmwareMqttProvisioningError("mutation verdict is invalid")
        return (
            '{"anchor_epoch_id":"%s","device_id":"%s","kind":"%s",'
            '"provision_seq":%d,"v":1,"verdict":"%s"}'
            % (
                _epoch(value["anchor_epoch_id"]),
                _fleet_id(value["device_id"], "device_id", maximum=48),
                kind,
                _sequence(value["provision_seq"]),
                value["verdict"],
            )
        ).encode()
    raise FirmwareMqttProvisioningError("unsupported device response kind")


def verify_device_message(
    message: bytes,
    *,
    device_public_key_bytes: bytes,
) -> dict[str, Any]:
    """Verify exact device response bytes and return the signed object."""

    if not isinstance(message, bytes):
        raise FirmwareMqttProvisioningError("device message must be bytes")
    outer = _strict_object(message)
    if set(outer) not in ({"response", "signature"}, {"result", "signature"}):
        raise FirmwareMqttProvisioningError("device message fields are invalid")
    outer_field = "response" if "response" in outer else "result"
    value = outer[outer_field]
    if not isinstance(value, dict):
        raise FirmwareMqttProvisioningError("signed device object is invalid")
    canonical = _canonical_response_object(outer_field, value)
    expected = (
        b'{"'
        + outer_field.encode()
        + b'":'
        + canonical
        + b',"signature":"'
        + str(outer["signature"]).encode()
        + b'"}'
    )
    if message != expected:
        raise FirmwareMqttProvisioningError("device message is not canonical")
    if (
        not isinstance(device_public_key_bytes, bytes)
        or len(device_public_key_bytes) != 32
    ):
        raise FirmwareMqttProvisioningError("device public key must be 32 raw bytes")
    try:
        Ed25519PublicKey.from_public_bytes(device_public_key_bytes).verify(
            _decode_signature(outer["signature"]), canonical
        )
    except InvalidSignature as exc:
        raise FirmwareMqttProvisioningError("device signature is invalid") from exc
    return value


def request_sha256(request: bytes) -> str:
    """Digest recorded by the append-only provisioning audit."""

    return "sha256:" + hashlib.sha256(request).hexdigest()
