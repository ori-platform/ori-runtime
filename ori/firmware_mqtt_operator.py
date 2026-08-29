# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Authenticated local operator boundary for firmware MQTT provisioning."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import socket
import stat
import struct
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ori.security.firmware.mqtt_certificate import FirmwareMqttCertificateError
from ori.security.firmware.mqtt_provisioning import (
    FirmwareMqttProvisioningError,
    FirmwareMqttResponseValidationError,
    SignedProvisioningRequest,
    validate_broker_uri,
    validate_time_server,
)
from ori.security.firmware.mqtt_workflow import FirmwareMqttProvisioningWorkflow
from ori.utils.time_utils import now_ms

_CONTRACT = "ori.runtime.firmware-mqtt-operator"
_SCHEMA_VERSION = 1
_MAX_REQUEST_BYTES = 32 * 1024
_REQUEST_TIMEOUT_SECONDS = 10.0
_CORRELATION_LENGTH = 32
_OPERATIONS = frozenset(
    {
        "create_csr",
        "prepare_install",
        "verify_install_result",
        "revoke",
        "verify_revoke_result",
        "status",
        "verify_status_response",
    }
)
logger = logging.getLogger(__name__)


class FirmwareMqttOperatorError(ValueError):
    """A typed, operator-safe refusal."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class FirmwareMqttOperatorController:
    """Translate authenticated operator intent into runtime-owned workflow calls."""

    def __init__(
        self,
        *,
        workflow: FirmwareMqttProvisioningWorkflow,
        store: Any,
        broker_uri: str,
        time_server: str,
    ) -> None:
        self._workflow = workflow
        self._store = store
        self._broker_uri = validate_broker_uri(broker_uri)
        self._time_server = validate_time_server(time_server)
        self._operation_lock = asyncio.Lock()

    async def handle(self, request: dict[str, Any], *, actor: str) -> dict[str, Any]:
        """Execute one strict v1 request for an already-authenticated actor."""
        operation = request.get("operation")
        if request.get("contract") != _CONTRACT:
            raise FirmwareMqttOperatorError(
                "contract_mismatch",
                f"contract must be {_CONTRACT}",
            )
        if request.get("schema_version") != _SCHEMA_VERSION:
            raise FirmwareMqttOperatorError(
                "version_mismatch",
                f"schema_version must be {_SCHEMA_VERSION}",
            )
        if operation not in _OPERATIONS:
            raise FirmwareMqttOperatorError(
                "unsupported_operation",
                "operation is not supported",
            )

        handlers = {
            "create_csr": self._create_csr,
            "prepare_install": self._prepare_install,
            "verify_install_result": self._verify_install_result,
            "revoke": self._revoke,
            "verify_revoke_result": self._verify_revoke_result,
            "status": self._status,
            "verify_status_response": self._verify_status_response,
        }
        try:
            # Operator volume is deliberately low. Serializing the state
            # transitions ensures two concurrent submissions cannot both pass
            # the pre-workflow single-use correlation check and sign competing
            # install requests before one consumes the parent.
            async with self._operation_lock:
                result = await handlers[str(operation)](request, actor)
        except FirmwareMqttOperatorError:
            raise
        except FirmwareMqttResponseValidationError as exc:
            raise FirmwareMqttOperatorError(
                "device_response_refused",
                f"device response was refused with verdict {exc.verdict}",
            ) from exc
        except FirmwareMqttCertificateError as exc:
            raise FirmwareMqttOperatorError(
                "invalid_certificate_material",
                str(exc),
            ) from exc
        except FirmwareMqttProvisioningError as exc:
            raise FirmwareMqttOperatorError(
                exc.code,
                str(exc),
            ) from exc
        return result

    async def _create_csr(self, request: dict[str, Any], actor: str) -> dict[str, Any]:
        self._require_fields(request, {"device_id", "reason"})
        issued = await self._workflow.create_csr_request(
            device_id=self._text(request, "device_id"),
            actor=actor,
            reason=self._text(request, "reason"),
        )
        correlation_id = await self._persist(issued)
        return self._public_request(issued, correlation_id)

    async def _prepare_install(
        self, request: dict[str, Any], actor: str
    ) -> dict[str, Any]:
        self._require_fields(request, {"correlation_id", "response_b64", "reason"})
        parent_id = self._correlation(request)
        row, issued = await self._load_issued(parent_id, expected_kind="create_csr")
        response = self._response_bytes(request)
        try:
            enrollment = await self._workflow.prepare_install(
                issued_csr_request=issued,
                csr_response_message=response,
                actor=actor,
                reason=self._text(request, "reason"),
                broker_uri=self._broker_uri,
                time_server=self._time_server,
            )
        except FirmwareMqttResponseValidationError as exc:
            await self._complete(
                row,
                verdict=exc.verdict,
                response=response,
            )
            raise

        install_id = await self._persist(
            enrollment.install_request,
            parent_correlation_id=parent_id,
            certificate_serial=str(enrollment.certificate.serial_number),
            not_valid_before=enrollment.certificate.not_valid_before.isoformat(),
            not_valid_after=enrollment.certificate.not_valid_after.isoformat(),
            completed_parent_correlation_id=parent_id,
            parent_response_verdict="accepted",
            parent_response=response,
        )
        result = self._public_request(enrollment.install_request, install_id)
        result["certificate"] = {
            "sha256": enrollment.certificate.certificate_sha256,
            "serial_number": str(enrollment.certificate.serial_number),
            "not_valid_before": enrollment.certificate.not_valid_before.isoformat(),
            "not_valid_after": enrollment.certificate.not_valid_after.isoformat(),
        }
        return result

    async def _verify_install_result(
        self, request: dict[str, Any], actor: str
    ) -> dict[str, Any]:
        del actor
        return await self._verify_response(request, expected_kind="install")

    async def _revoke(self, request: dict[str, Any], actor: str) -> dict[str, Any]:
        self._require_fields(request, {"device_id", "reason"})
        issued = await self._workflow.revoke_request(
            device_id=self._text(request, "device_id"),
            actor=actor,
            reason=self._text(request, "reason"),
        )
        correlation_id = await self._persist(issued)
        return self._public_request(issued, correlation_id)

    async def _verify_revoke_result(
        self, request: dict[str, Any], actor: str
    ) -> dict[str, Any]:
        del actor
        return await self._verify_response(request, expected_kind="revoke")

    async def _status(self, request: dict[str, Any], actor: str) -> dict[str, Any]:
        self._require_fields(request, {"device_id", "request_id"})
        issued = await self._workflow.status_request(
            device_id=self._text(request, "device_id"),
            actor=actor,
            request_id=self._text(request, "request_id"),
        )
        correlation_id = await self._persist(issued)
        return self._public_request(issued, correlation_id)

    async def _verify_status_response(
        self, request: dict[str, Any], actor: str
    ) -> dict[str, Any]:
        del actor
        return await self._verify_response(request, expected_kind="status")

    async def _verify_response(
        self,
        request: dict[str, Any],
        *,
        expected_kind: str,
    ) -> dict[str, Any]:
        self._require_fields(request, {"correlation_id", "response_b64"})
        row, issued = await self._load_issued(
            self._correlation(request),
            expected_kind=expected_kind,
        )
        response = self._response_bytes(request)
        value = await self._workflow.verify_response(issued, response)
        verdict = str(value.get("verdict", "accepted"))
        await self._complete(row, verdict=verdict, response=response)
        return {
            "correlation_id": str(row["correlation_id"]),
            "device_id": issued.device_id,
            "operation": issued.kind,
            "verdict": verdict,
            "response": value,
            "successful": verdict == "accepted",
        }

    async def _persist(
        self,
        issued: SignedProvisioningRequest,
        *,
        parent_correlation_id: str = "",
        certificate_serial: str = "",
        not_valid_before: str = "",
        not_valid_after: str = "",
        completed_parent_correlation_id: str = "",
        parent_response_verdict: str = "",
        parent_response: bytes = b"",
    ) -> str:
        correlation_id = uuid.uuid4().hex
        await self._store.save_firmware_mqtt_operator_request(
            correlation_id=correlation_id,
            parent_correlation_id=parent_correlation_id,
            operation_kind=issued.kind,
            message=issued.message,
            request=issued.request,
            device_id=issued.device_id,
            anchor_epoch_id=issued.anchor_epoch_id,
            provision_seq=issued.provision_seq,
            request_id=issued.request_id,
            actor=issued.actor,
            reason=issued.reason,
            request_sha256=issued.request_sha256,
            certificate_sha256=issued.certificate_sha256,
            broker_uri=issued.broker_uri,
            audit_id=issued.audit_id,
            certificate_serial=certificate_serial,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            created_at_ms=now_ms(),
            completed_parent_correlation_id=completed_parent_correlation_id,
            parent_response_verdict=parent_response_verdict,
            parent_response_payload_sha256=(
                "sha256:" + hashlib.sha256(parent_response).hexdigest()
                if completed_parent_correlation_id
                else ""
            ),
            parent_completed_at_ms=(now_ms() if completed_parent_correlation_id else 0),
        )
        return correlation_id

    async def _load_issued(
        self,
        correlation_id: str,
        *,
        expected_kind: str,
    ) -> tuple[dict[str, Any], SignedProvisioningRequest]:
        row = await self._store.get_firmware_mqtt_operator_request(correlation_id)
        if row is None:
            raise FirmwareMqttOperatorError(
                "stale_correlation",
                "correlation is unknown",
            )
        if row.get("completed_at_ms") is not None:
            raise FirmwareMqttOperatorError(
                "stale_correlation",
                "correlation is already completed",
            )
        if row.get("operation_kind") != expected_kind:
            raise FirmwareMqttOperatorError(
                "correlation_mismatch",
                f"correlation does not reference {expected_kind}",
            )
        issued = SignedProvisioningRequest(
            message=bytes(row["message"]),
            request=bytes(row["request"]),
            device_id=str(row["device_id"]),
            anchor_epoch_id=str(row["anchor_epoch_id"]),
            kind=str(row["operation_kind"]),
            provision_seq=(
                int(row["provision_seq"])
                if row.get("provision_seq") is not None
                else None
            ),
            request_id=str(row["request_id"]),
            actor=str(row["actor"]),
            reason=str(row["reason"]),
            request_sha256=str(row["request_sha256"]),
            certificate_sha256=str(row["certificate_sha256"]),
            broker_uri=str(row["broker_uri"]),
            audit_id=int(row["audit_id"]),
        )
        return row, issued

    async def _complete(
        self,
        row: dict[str, Any],
        *,
        verdict: str,
        response: bytes,
    ) -> None:
        await self._store.complete_firmware_mqtt_operator_request(
            correlation_id=str(row["correlation_id"]),
            verdict=verdict,
            payload_sha256="sha256:" + hashlib.sha256(response).hexdigest(),
            completed_at_ms=now_ms(),
        )

    def _public_request(
        self,
        issued: SignedProvisioningRequest,
        correlation_id: str,
    ) -> dict[str, Any]:
        return {
            "correlation_id": correlation_id,
            "operation": issued.kind,
            "device_id": issued.device_id,
            "anchor_epoch_id": issued.anchor_epoch_id,
            "provision_seq": issued.provision_seq,
            "request_id": issued.request_id,
            "request_sha256": issued.request_sha256,
            "message_b64": base64.b64encode(issued.message).decode("ascii"),
        }

    def _require_fields(
        self,
        request: dict[str, Any],
        operation_fields: set[str],
    ) -> None:
        expected = {"contract", "schema_version", "operation"} | operation_fields
        if set(request) != expected:
            raise FirmwareMqttOperatorError(
                "invalid_request",
                "request fields do not match the operation contract",
            )

    def _text(self, request: dict[str, Any], field: str) -> str:
        value = request.get(field)
        if not isinstance(value, str) or not value:
            raise FirmwareMqttOperatorError(
                "invalid_request",
                f"{field} must be non-empty text",
            )
        return value

    def _correlation(self, request: dict[str, Any]) -> str:
        value = self._text(request, "correlation_id")
        if len(value) != _CORRELATION_LENGTH:
            raise FirmwareMqttOperatorError(
                "invalid_request",
                "correlation_id is invalid",
            )
        try:
            int(value, 16)
        except ValueError as exc:
            raise FirmwareMqttOperatorError(
                "invalid_request",
                "correlation_id is invalid",
            ) from exc
        return value

    def _response_bytes(self, request: dict[str, Any]) -> bytes:
        value = self._text(request, "response_b64")
        try:
            response = base64.b64decode(value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError) as exc:
            raise FirmwareMqttOperatorError(
                "invalid_request",
                "response_b64 must be canonical base64",
            ) from exc
        if (
            not response
            or len(response) > 16 * 1024
            or base64.b64encode(response).decode("ascii") != value
        ):
            raise FirmwareMqttOperatorError(
                "invalid_request",
                "response_b64 must be canonical base64",
            )
        return response


class FirmwareMqttOperatorServer:
    """Serve the v1 operator contract over a peer-authenticated Unix socket."""

    def __init__(
        self,
        *,
        socket_path: str,
        mode: int,
        allowed_uids: set[int],
        controller: FirmwareMqttOperatorController,
        peer_uid_provider: Callable[[Any], int] | None = None,
    ) -> None:
        if (
            not socket_path
            or "\x00" in socket_path
            or not Path(socket_path).is_absolute()
        ):
            raise ValueError("operator socket path must be an absolute path")
        if (
            isinstance(mode, bool)
            or not isinstance(mode, int)
            or mode < 0
            or mode > 0o777
            or mode & 0o007
            or mode & 0o220 == 0
        ):
            raise ValueError("operator socket mode is unsafe")
        normalized_uids = set(allowed_uids) or {os.geteuid()}
        if any(
            isinstance(uid, bool) or not isinstance(uid, int) or uid < 0
            for uid in normalized_uids
        ):
            raise ValueError("operator allowed_uids contains an invalid uid")
        self._socket_path = socket_path
        self._mode = mode
        self._allowed_uids = normalized_uids
        self._controller = controller
        self._peer_uid_provider = peer_uid_provider or _peer_uid
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> str:
        if os.name == "nt":
            raise RuntimeError("firmware MQTT operator socket requires AF_UNIX")
        await asyncio.to_thread(self._prepare_path)
        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=self._socket_path,
            limit=_MAX_REQUEST_BYTES + 1,
        )
        await asyncio.to_thread(os.chmod, self._socket_path, self._mode)
        return self._socket_path

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        await asyncio.to_thread(self._cleanup_path)

    def _prepare_path(self) -> None:
        path = Path(self._socket_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            current = path.lstat()
            if not stat.S_ISSOCK(current.st_mode):
                raise RuntimeError(
                    f"operator socket path {self._socket_path!r} is not a socket"
                )
            path.unlink()

    def _cleanup_path(self) -> None:
        path = Path(self._socket_path)
        try:
            current = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISSOCK(current.st_mode):
            path.unlink()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            peer_uid = self._peer_uid_provider(writer.get_extra_info("socket"))
            if peer_uid not in self._allowed_uids:
                raise FirmwareMqttOperatorError(
                    "authentication_failed",
                    "peer uid is not authorized",
                )
            try:
                raw = await asyncio.wait_for(
                    reader.readline(),
                    timeout=_REQUEST_TIMEOUT_SECONDS,
                )
            except TimeoutError as exc:
                raise FirmwareMqttOperatorError(
                    "request_timeout",
                    "request was not completed in time",
                ) from exc
            except ValueError as exc:
                raise FirmwareMqttOperatorError(
                    "request_too_large",
                    "request exceeded maximum size",
                ) from exc
            if len(raw) > _MAX_REQUEST_BYTES:
                raise FirmwareMqttOperatorError(
                    "request_too_large",
                    "request exceeded maximum size",
                )
            request = _strict_request(raw)
            result = await self._controller.handle(
                request,
                actor=f"uid-{peer_uid}",
            )
            response = {
                "contract": _CONTRACT,
                "schema_version": _SCHEMA_VERSION,
                "ok": True,
                "result": result,
            }
        except FirmwareMqttOperatorError as exc:
            response = _error_response(exc.code, exc.detail)
        except Exception:
            logger.exception("[firmware-mqtt-operator] request failed")
            response = _error_response(
                "internal_error",
                "runtime could not complete the operation",
            )
        try:
            writer.write(
                json.dumps(
                    response,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()


def _strict_request(raw: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise FirmwareMqttOperatorError(
                    "invalid_request",
                    "duplicate JSON field",
                )
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FirmwareMqttOperatorError(
            "invalid_request",
            "request must be one JSON object",
        ) from exc
    if not isinstance(value, dict):
        raise FirmwareMqttOperatorError(
            "invalid_request",
            "request must be one JSON object",
        )
    return value


def _error_response(code: str, detail: str) -> dict[str, Any]:
    return {
        "contract": _CONTRACT,
        "schema_version": _SCHEMA_VERSION,
        "ok": False,
        "error": {"code": code, "detail": detail},
    }


def _peer_uid(peer_socket: Any) -> int:
    if peer_socket is None:
        raise FirmwareMqttOperatorError(
            "authentication_failed",
            "peer credentials are unavailable",
        )
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if sys.platform.startswith("linux") and so_peercred is not None:
        raw = peer_socket.getsockopt(socket.SOL_SOCKET, so_peercred, 12)
        _, uid, _ = struct.unpack("=3i", raw)
        return int(uid)
    if sys.platform == "darwin" and hasattr(socket, "LOCAL_PEERCRED"):
        # Darwin's xucred begins with cr_version (u32), then cr_uid (uid_t).
        raw = peer_socket.getsockopt(0, socket.LOCAL_PEERCRED, 8)
        _, uid = struct.unpack("=II", raw)
        return int(uid)
    raise FirmwareMqttOperatorError(
        "authentication_failed",
        "peer credential verification is unsupported on this platform",
    )
