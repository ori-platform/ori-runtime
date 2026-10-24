# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The services startup opens: exports, the health and operator sockets, and the
firmware MQTT operator."""

import asyncio
import hmac
import logging
import os
import sys
from typing import Any

from ori.config import Config
from ori.firmware_mqtt_operator import (
    FirmwareMqttOperatorController,
    FirmwareMqttOperatorServer,
)
from ori.gateway.envelope_auth import (
    build_gateway_message_auth as _build_gateway_message_auth,
)
from ori.gateway.export import GatewayExportResponder, MqttGatewayExportServer
from ori.gateway.firmware_commands import load_raw_ed25519_seed_from_env
from ori.network.event_bus import EventBus
from ori.operator_socket import (
    CommissionRequest,
    OperatorSocketServer,
    PeerCredentials,
    ReconcileRequest,
    installed_operator_uid,
    runtime_directory,
)
from ori.runtime._constants import HEALTH_SOCKET_DEFAULT_PATH
from ori.runtime._gateway_wiring import (
    build_gateway_message_encryptor,
    read_private_key_file,
    read_public_pem_file,
)
from ori.runtime._health import HealthSnapshot
from ori.runtime_health_socket import RuntimeHealthSocketServer
from ori.security.approvers.wiring import prepare_registry_service
from ori.security.evidence.first_party import RegistrationUnreadableError
from ori.security.evidence.registration import status_after_recording
from ori.security.firmware.mqtt_certificate import FirmwareMqttCertificateAuthority
from ori.security.firmware.mqtt_provisioning import FirmwareMqttProvisioningService
from ori.security.firmware.mqtt_workflow import FirmwareMqttProvisioningWorkflow
from ori.security.gateway_messages import GatewayEnvelopeState
from ori.telemetry.http_export import HttpTelemetryExporter
from ori.utils.path_utils import shown
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.runtime")


class OperatorServices(HealthSnapshot):
    """Starting the export, health, operator and firmware-operator services."""

    def _start_gateway_export_responder_if_enabled(
        self, config: Config, envelope_state: GatewayEnvelopeState | None = None
    ) -> asyncio.Task[None] | None:
        if not bool(config.gateway.enabled):
            return None
        if self._state_store is None:
            logger.warning(
                "[gateway-export] state store unavailable; skipping MQTT export responder"
            )
            return None
        try:
            responder = GatewayExportResponder(
                device_id=config.device.id,
                state_store=self._state_store,
                health_snapshot_provider=self._build_health_snapshot,
                message_auth=_build_gateway_message_auth(config, envelope_state),
                message_encryptor=build_gateway_message_encryptor(config),
            )
            server = MqttGatewayExportServer(
                broker_url=config.gateway.broker_url,
                responder=responder,
                tls_config=getattr(config.gateway, "tls", {}),
            )
        except Exception:
            logger.exception("[gateway-export] invalid responder configuration")
            return None
        self._gateway_export_server = server
        return asyncio.create_task(
            server.serve_until(self._shutdown_event),
            name="gateway-export-responder",
        )

    def _start_telemetry_export_if_enabled(
        self,
        config: Config,
        event_bus: EventBus,
    ) -> asyncio.Task[None] | None:
        export_cfg = config.telemetry_export
        if not export_cfg.enabled:
            return None
        exporter = HttpTelemetryExporter(
            device_id=config.device.id,
            config=export_cfg,
        )
        self._telemetry_exporter = exporter
        event_bus.subscribe("*", exporter.handle_event)
        return asyncio.create_task(
            exporter.serve_until(self._shutdown_event),
            name="telemetry-export",
        )

    async def _start_health_socket_if_enabled(self, config: Config) -> None:
        cfg = config.health_socket if isinstance(config.health_socket, dict) else {}
        if not bool(cfg.get("enabled", True)):
            return

        socket_path = str(cfg.get("path", HEALTH_SOCKET_DEFAULT_PATH)).strip()
        mode = int(cfg.get("mode", 0o660))
        if not socket_path:
            logger.warning("[runtime] health socket path is empty; skipping startup")
            return

        server = RuntimeHealthSocketServer(
            socket_path=socket_path,
            mode=mode,
            snapshot_provider=self._build_health_snapshot,
        )
        try:
            bound_path = await server.start()
        except Exception:
            # Said at CRITICAL rather than as a traceback and a shrug. This
            # runtime keeps serving every other surface, and the conditions the
            # snapshot is the only reporter of — a sensor that stopped
            # measuring, a trust anchor that verifies nothing, a signed field
            # an unsigned source supplied — now have nowhere to be read. From a
            # fleet's side that device is indistinguishable from one that is
            # not answering at all, so the log line is the only thing that
            # distinguishes them.
            logger.critical(
                "[runtime] health socket did not start; this runtime is "
                "running with no health surface and can report nothing about "
                "its own posture. Every other surface is unaffected.",
                exc_info=True,
            )
            return

        self._health_socket_server = server
        self._health_socket_path = bound_path
        logger.info("[runtime] health socket ready at %s", shown(bound_path))

    async def _start_operator_socket(self, deployment_profile: str) -> None:
        """Bind the operator socket in the runtime directory systemd created.

        Only the service unit provides one. A development runtime run in the
        foreground has none and says so; a staging or production runtime
        without one has lost its only reconciliation and commissioning-reference
        surface, which is CRITICAL.
        """
        directory = runtime_directory()
        if directory is None:
            logger.log(
                logging.WARNING
                if deployment_profile == "development"
                else logging.CRITICAL,
                "[runtime] no runtime directory was provided (RUNTIME_DIRECTORY is "
                "unset; only the service unit provides one), so the operator socket "
                "is not bound and an uncertain Tier C dispatch cannot be reconciled "
                "by this process",
            )
            return
        server = OperatorSocketServer(
            directory=directory,
            reconcile=self._reconcile_from_operator,
            commission=self._commission_from_operator,
            operator_uid=installed_operator_uid(sys.prefix),
            registry=await prepare_registry_service(self._state_store, self._config),
        )
        try:
            bound = await server.start()
        except Exception as exc:
            logger.critical(
                "[runtime] the operator socket at %s was not bound (%s: %s); no "
                "socket is left behind, and an uncertain Tier C dispatch cannot be "
                "reconciled until a start binds it",
                shown(str(server.path)),
                type(exc).__name__,
                exc,
            )
            return
        self._operator_socket_server = server
        logger.info("[runtime] operator socket ready at %s", shown(str(bound)))

    async def _reconcile_from_operator(
        self, request: ReconcileRequest, peer: PeerCredentials, account: str | None
    ) -> dict[str, Any]:
        if self._dispatcher is None:
            return {"ok": False, "error": "runtime_store_unavailable"}
        return await self._dispatcher.reconcile_tier_c(
            self._state_store,
            proposal_id=request.proposal_id,
            device_id=request.device_id,
            runtime_device_id=self._device_id,
            zone_id=request.zone_id,
            outcome=request.outcome,
            reason=request.reason,
            note=request.note,
            principal_uid=peer.uid,
            principal_account=account,
            principal_login_uid=peer.login_uid,
        )

    async def _commission_from_operator(
        self, request: CommissionRequest, peer: PeerCredentials, account: str | None
    ) -> dict[str, Any]:
        """Record the reference against this runtime's own device and epoch.

        The status is the one the runtime reports once the next reconciliation
        reads the record, stated from the registration it reports now.
        """
        attestor = self._evidence_attestor
        anchor = (
            attestor.anchor if attestor is not None and attestor.available else None
        )
        if attestor is None or anchor is None:
            return {"ok": False, "error": "evidence_epoch_unavailable"}
        try:
            registration = await attestor.read_registration_health(now_ms())
        except RegistrationUnreadableError as exc:
            logger.warning(
                "[runtime] commissioning refused: registration state unreadable (%s)",
                exc,
            )
            return {"ok": False, "error": "runtime_store_unavailable"}
        if registration is None:
            return {"ok": False, "error": "evidence_epoch_unavailable"}
        # Decided before the record, so nothing can fail after it is durable.
        status = status_after_recording(registration)
        store = self._state_store
        if store is None:
            return {"ok": False, "error": "runtime_store_unavailable"}
        answer = await store.record_evidence_commissioning_reference(
            device_id=anchor.device_id,
            anchor_epoch_id=anchor.anchor_epoch_id,
            commissioning_reference=request.reference,
            force=request.force,
            recorded_at_ms=now_ms(),
        )
        if not answer.get("ok"):
            return answer
        return {
            "ok": True,
            "device_id": anchor.device_id,
            "anchor_epoch_id": anchor.anchor_epoch_id,
            "commissioning_reference": request.reference,
            "replaced": answer["replaced"],
            "registration_status": status.value,
        }

    async def _start_firmware_mqtt_operator_if_enabled(
        self,
        config: Config,
    ) -> None:
        cfg = (
            config.firmware_mqtt_provisioning
            if isinstance(config.firmware_mqtt_provisioning, dict)
            else {}
        )
        if not bool(cfg.get("enabled", False)):
            return
        if self._state_store is None:
            raise RuntimeError(
                "firmware MQTT operator service requires the runtime state store"
            )

        provisioner_key = load_raw_ed25519_seed_from_env(
            str(cfg["provisioner_key_env"]),
            label="firmware MQTT provisioner key",
        )
        command_cfg = (
            config.gateway.firmware_commands
            if isinstance(getattr(config.gateway, "firmware_commands", {}), dict)
            else {}
        )
        if bool(command_cfg.get("enabled", False)):
            command_provisioner_key = load_raw_ed25519_seed_from_env(
                str(command_cfg.get("provisioner_key_env", "")),
                label="firmware command provisioner key",
            )
            if not hmac.compare_digest(provisioner_key, command_provisioner_key):
                raise RuntimeError(
                    "firmware MQTT and command provisioning-authority keys differ"
                )
        (
            ca_certificate_pem,
            ca_private_key_pem,
            broker_ca_certificate_pem,
        ) = await asyncio.gather(
            asyncio.to_thread(read_public_pem_file, str(cfg["client_ca_certfile"])),
            asyncio.to_thread(
                read_private_key_file,
                str(cfg["client_ca_keyfile"]),
            ),
            asyncio.to_thread(read_public_pem_file, str(cfg["broker_ca_certfile"])),
        )
        password_env = str(cfg.get("client_ca_key_password_env", "")).strip()
        ca_password: bytes | None = None
        if password_env:
            password = os.environ.get(password_env)
            if password is None or not password:
                raise RuntimeError(
                    "firmware MQTT client CA key password environment variable is unset"
                )
            ca_password = password.encode("utf-8")

        service = FirmwareMqttProvisioningService(
            store=self._state_store,
            provisioner_key_bytes=provisioner_key,
        )
        certificate_authority = FirmwareMqttCertificateAuthority(
            ca_certificate_pem=ca_certificate_pem,
            ca_private_key_pem=ca_private_key_pem,
            ca_private_key_password=ca_password,
            validity_days=int(cfg["certificate_validity_days"]),
        )
        workflow = FirmwareMqttProvisioningWorkflow(
            service=service,
            certificate_authority=certificate_authority,
            broker_ca_certificate_pem=broker_ca_certificate_pem,
        )
        controller = FirmwareMqttOperatorController(
            workflow=workflow,
            store=self._state_store,
            broker_uri=str(cfg["broker_uri"]),
            time_server=str(cfg["time_server"]),
        )
        server = FirmwareMqttOperatorServer(
            socket_path=str(cfg["socket_path"]),
            mode=int(cfg["socket_mode"]),
            allowed_uids={int(uid) for uid in cfg.get("allowed_uids", [])},
            controller=controller,
        )
        try:
            bound_path = await server.start()
        except Exception:
            await server.close()
            raise
        self._firmware_mqtt_operator_server = server
        self._firmware_mqtt_operator_socket_path = bound_path
        logger.info(
            "[runtime] firmware MQTT operator service ready at %s", shown(bound_path)
        )
