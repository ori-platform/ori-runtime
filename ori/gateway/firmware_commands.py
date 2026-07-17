# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""MQTT egress for signed firmware approvals and commands.

The cryptographic grammar lives in :mod:`ori.security.firmware_commands`.
This module owns only the transport binding from
``ori-specs/firmware-commands/v1.md``:

* retained provisioning approvals on ``ori/fw/<device_id>/provision``;
* non-retained commands on ``ori/fw/<device_id>/cmd``.

Commands are never retained. Provisioning approvals are retained so a rebooted
device can reload the current runtime command key for its accepted manifest
epoch.
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
from typing import Any, Callable, cast

from ori.gateway.mqtt_security import apply_tls_context, parse_gateway_broker_url
from ori.security.firmware_commands import (
    FirmwareCommandError,
    FirmwareCommandSigner,
    build_provisioning_approval_bytes,
)

mqtt: Any
try:
    import paho.mqtt.client as mqtt

    _PAHO_AVAILABLE = True
except ImportError:  # pragma: no cover - paho is installed in production images
    mqtt = None
    _PAHO_AVAILABLE = False

_FLEET_ID = re.compile(r"^[A-Za-z0-9._-]{1,48}$")


class FirmwareCommandPublishError(RuntimeError):
    """The command/approval could not be handed to the broker."""


class MqttFirmwareCommandPublisher:
    """Publishes signed firmware command-channel messages."""

    def __init__(
        self,
        *,
        broker_url: str,
        runtime_device_id: str,
        qos: int = 1,
        tls_config: dict[str, Any] | None = None,
        client_factory: Callable[..., Any] | None = None,
        publish_timeout_s: float = 10.0,
    ) -> None:
        if not _PAHO_AVAILABLE or mqtt is None:
            raise RuntimeError("paho-mqtt is not installed")
        if int(qos) != 1:
            raise ValueError("firmware command MQTT binding requires QoS 1")
        if publish_timeout_s <= 0:
            raise ValueError("publish_timeout_s must be positive")
        self._broker = parse_gateway_broker_url(broker_url, tls_config=tls_config)
        self._runtime_device_id = str(runtime_device_id)
        self._qos = int(qos)
        self._client_factory = client_factory or _default_client_factory
        self._publish_timeout_s = float(publish_timeout_s)
        self._client: Any = None

    async def connect(self) -> None:
        client = self._client_factory(client_id=f"ori-fw-cmd-{self._runtime_device_id}")
        if self._broker.username:
            client.username_pw_set(self._broker.username, self._broker.password)
        apply_tls_context(client, self._broker)
        await asyncio.to_thread(
            client.connect,
            self._broker.host,
            int(self._broker.port),
            60,
        )
        await asyncio.to_thread(client.loop_start)
        self._client = client

    async def close(self) -> None:
        client = self._client
        self._client = None
        if client is None:
            return
        try:
            await asyncio.to_thread(client.loop_stop)
        finally:
            await asyncio.to_thread(client.disconnect)

    async def publish_provisioning_approval(
        self, device_id: str, message: bytes
    ) -> None:
        await self._publish(
            _topic(device_id, "provision"),
            message,
            retain=True,
        )

    async def publish_command(self, device_id: str, message: bytes) -> None:
        await self._publish(
            _topic(device_id, "cmd"),
            message,
            retain=False,
        )

    async def _publish(self, topic: str, message: bytes, *, retain: bool) -> None:
        client = self._client
        if client is None:
            raise FirmwareCommandPublishError(
                "firmware command publisher is not connected"
            )
        if not isinstance(message, bytes) or not message:
            raise FirmwareCommandPublishError("firmware command payload must be bytes")
        info = await asyncio.to_thread(
            client.publish,
            topic,
            payload=message,
            qos=self._qos,
            retain=retain,
        )
        rc = int(getattr(info, "rc", 0))
        if rc != 0:
            raise FirmwareCommandPublishError(f"MQTT publish failed rc={rc}")
        wait_for_publish = getattr(info, "wait_for_publish", None)
        if callable(wait_for_publish):
            ok = await asyncio.to_thread(wait_for_publish, self._publish_timeout_s)
            if ok is False:
                raise FirmwareCommandPublishError("MQTT publish timed out")


class FirmwareCommandService:
    """Store-backed approval and command egress for firmware devices."""

    def __init__(
        self,
        *,
        store: Any,
        publisher: MqttFirmwareCommandPublisher,
        runtime_command_key_bytes: bytes,
        provisioner_key_bytes: bytes,
    ) -> None:
        self._store = store
        self._publisher = publisher
        self._signer = FirmwareCommandSigner(store, runtime_command_key_bytes)
        self._runtime_public_key_b64 = base64.b64encode(
            self._signer.public_key_bytes()
        ).decode("ascii")
        if (
            not isinstance(provisioner_key_bytes, bytes)
            or len(provisioner_key_bytes) != 32
        ):
            raise FirmwareCommandError(
                "provisioner key must be 32 raw Ed25519 seed bytes"
            )
        self._provisioner_key_bytes = provisioner_key_bytes

    async def publish_provisioning_approval(self, device_id: str) -> bytes:
        row = await self._require_approved_device(device_id)
        message = build_provisioning_approval_bytes(
            capability_hash=row["capability_hash"],
            device_id=row["device_id"],
            posture=row["posture"],
            public_key_b64=row["public_key_b64"],
            runtime_public_key_b64=self._runtime_public_key_b64,
            provisioner_private_key_bytes=self._provisioner_key_bytes,
        )
        await self._publisher.publish_provisioning_approval(row["device_id"], message)
        return message

    async def publish_command(
        self,
        *,
        device_id: str,
        action: str,
        channel: str,
    ) -> bytes:
        message = await self._signer.sign_command(
            device_id=device_id,
            action=action,
            channel=channel,
        )
        await self._publisher.publish_command(device_id, message)
        return message

    async def _require_approved_device(self, device_id: str) -> dict[str, Any]:
        row = await self._store.get_firmware_device(device_id)
        if row is None:
            raise FirmwareCommandError(f"unknown firmware device: {device_id!r}")
        if row.get("revoked"):
            raise FirmwareCommandError(f"device {device_id!r} is revoked")
        if not row.get("approved"):
            raise FirmwareCommandError(f"device {device_id!r} is not approved")
        return cast(dict[str, Any], row)


def load_raw_ed25519_seed_from_env(env_name: str, *, label: str) -> bytes:
    clean_name = str(env_name or "").strip()
    if not clean_name:
        raise FirmwareCommandError(f"{label} env var name is required")
    raw_value = os.environ.get(clean_name, "")
    if not raw_value:
        raise FirmwareCommandError(f"{label} env var {clean_name!r} is empty")
    try:
        seed = base64.b64decode(raw_value.encode("ascii"), validate=True)
    except Exception as exc:
        raise FirmwareCommandError(
            f"{label} env var {clean_name!r} must be base64"
        ) from exc
    if len(seed) != 32 or base64.b64encode(seed).decode("ascii") != raw_value:
        raise FirmwareCommandError(
            f"{label} env var {clean_name!r} must encode exactly 32 bytes"
        )
    return seed


def _topic(device_id: str, leaf: str) -> str:
    if not isinstance(device_id, str) or not _FLEET_ID.match(device_id):
        raise FirmwareCommandPublishError(
            f"device_id is not a valid MQTT fleet identifier: {device_id!r}"
        )
    return f"ori/fw/{device_id}/{leaf}"


def _default_client_factory(**kwargs: Any) -> Any:
    assert mqtt is not None
    return mqtt.Client(**kwargs)
