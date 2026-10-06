# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""MQTT egress for signed firmware approvals and commands.

The cryptographic grammar lives in :mod:`ori.security.firmware.commands`.
This module owns only the transport binding from
``ori-specs/firmware-commands/v1.md``:

* retained provisioning approvals on ``ori/fw/<device_id>/provision``;
* non-retained commands on ``ori/fw/<device_id>/cmd``;
* non-retained runtime liveness on ``ori/fw/<device_id>/runtime``.

Commands are never retained. Provisioning approvals are retained so a rebooted
device can reload the current runtime command key for its accepted manifest
epoch.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import math
import os
import re
import time
from typing import Any, Callable, cast

from ori.gateway.mqtt_security import apply_tls_context, parse_gateway_broker_url
from ori.security.firmware.commands import (
    FirmwareCommandError,
    FirmwareCommandSigner,
    build_provisioning_approval_bytes,
)
from ori.security.firmware.liveness import (
    FirmwareLivenessSigner,
    FirmwareLivenessSupervisor,
    SupervisedDevice,
)
from ori.security.published_test_keys import is_published_seed

logger = logging.getLogger(__name__)

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
        if (
            isinstance(publish_timeout_s, bool)
            or not isinstance(publish_timeout_s, (int, float))
            or not math.isfinite(publish_timeout_s)
            or publish_timeout_s <= 0
        ):
            raise ValueError("publish_timeout_s must be a finite positive number")
        self._broker = parse_gateway_broker_url(broker_url, tls_config=tls_config)
        self._runtime_device_id = str(runtime_device_id)
        self._qos = int(qos)
        self._client_factory = client_factory or _default_client_factory
        self._publish_timeout_s = float(publish_timeout_s)
        self._client: Any = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        async with self._lock:
            await self._connect_locked()

    async def _connect_locked(self) -> None:
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
        # Publishing waits for the session: a publish before the broker's
        # acknowledgement would be refused as disconnected.
        deadline = time.monotonic() + self._publish_timeout_s
        while not client.is_connected() and time.monotonic() < deadline:
            await asyncio.sleep(0.02)

    async def close(self) -> None:
        async with self._lock:
            client = self._client
            self._client = None
        if client is not None:
            await _stop_client(client)

    def _retire(self, client: Any) -> None:
        """Stop a client from sending anything more, without awaiting.

        A client that failed a publication holds a QoS 1 message it would
        send on reconnect, after whatever authority signed it may have been
        withdrawn. Nothing here awaits, so cancellation cannot skip it:
        ``disconnect`` ends reconnects and resends at once, and the network
        loop is stopped off the event loop.
        """
        if self._client is client:
            self._client = None
        try:
            client.disconnect()
        except Exception:
            logger.debug("[firmware-commands] disconnect of a retired client failed")
        stopped = asyncio.get_running_loop().run_in_executor(None, client.loop_stop)
        stopped.add_done_callback(_consume)

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

    async def publish_runtime_liveness(self, device_id: str, message: bytes) -> None:
        """Publish one signed liveness message.

        ``retain=False`` is not a default here, it is the contract. A
        retained liveness message is the broker asserting, on behalf of a
        runtime that may since have died, that an authority is watching —
        so a device reconnecting after this runtime dies would suppress
        its own backstop for a full expiry window. No ACL can forbid it;
        this call site is where it is prevented.
        """
        await self._publish(
            _topic(device_id, "runtime"),
            message,
            retain=False,
        )

    async def _publish(self, topic: str, message: bytes, *, retain: bool) -> None:
        if not isinstance(message, bytes) or not message:
            raise FirmwareCommandPublishError("firmware command payload must be bytes")
        # A publication that fails is never delivered later by this process:
        # nothing is handed to a disconnected client, which would queue it,
        # and a client that took a message and failed it is discarded. A
        # disconnected client is replaced at once rather than left to its
        # own reconnect backoff.
        async with self._lock:
            stale = self._client
            if stale is not None and not stale.is_connected():
                self._retire(stale)
            if self._client is None:
                try:
                    await self._connect_locked()
                except Exception as exc:
                    raise FirmwareCommandPublishError(
                        "firmware command publisher is not connected"
                    ) from exc
            client = self._client
        if client is None or not client.is_connected():
            raise FirmwareCommandPublishError(
                "firmware command publisher is not connected; nothing was queued"
            )
        try:
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
            # wait_for_publish returns None whether or not the broker
            # acknowledged; only is_published says which.
            await asyncio.to_thread(info.wait_for_publish, self._publish_timeout_s)
            if not info.is_published():
                raise FirmwareCommandPublishError("MQTT publish timed out")
        except BaseException as exc:
            # Cancellation included: an outer timeout must not leave the
            # message queued in a live client.
            self._retire(client)
            if isinstance(exc, (FirmwareCommandPublishError, asyncio.CancelledError)):
                raise
            if not isinstance(exc, Exception):
                raise
            raise FirmwareCommandPublishError(f"MQTT publish failed: {exc}") from exc


class FirmwareCommandService:
    """Store-backed approval and command egress for firmware devices."""

    def __init__(
        self,
        *,
        store: Any,
        publisher: MqttFirmwareCommandPublisher,
        runtime_command_key_bytes: bytes,
        provisioner_key_bytes: bytes,
        liveness_supervisor: FirmwareLivenessSupervisor,
    ) -> None:
        self._store = store
        self._publisher = publisher
        self._signer = FirmwareCommandSigner(store, runtime_command_key_bytes)
        # Required, and never defaulted. Supervision is established on the
        # telemetry side; a service holding its own instance would read a
        # map nothing writes to and refuse every device forever, which
        # looks exactly like a fleet that is simply quiet. Callers that
        # only need command egress must still pass one explicitly, so the
        # choice is visible at the call site instead of inferred here.
        #
        # The SAME key the device pins for commands: no new key material,
        # no second trust root.
        self._liveness = FirmwareLivenessSigner(
            store,
            runtime_command_key_bytes,
            supervisor=liveness_supervisor,
        )
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
        # The checks above span several reads. The approval is retained, so
        # it is published only if the anchor it names still holds, in one.
        if not await self._store.firmware_command_authority_holds(
            device_id, verified_against=row
        ):
            raise FirmwareCommandError(
                f"device {device_id!r} authority changed before the approval "
                "was published; nothing was published"
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

    @property
    def liveness_supervisor(self) -> FirmwareLivenessSupervisor:
        """Hand this to the telemetry subscriber so accepted telemetry
        establishes supervision."""
        return self._liveness.supervisor

    def supervised_devices(self) -> tuple[SupervisedDevice, ...]:
        """Snapshot for a publish loop. Every value signing needs is here,
        so a scheduler never queries the registry to decide who to publish
        for — that would turn an event-driven map into a fleet poll."""
        return self._liveness.supervisor.supervised_devices()

    async def publish_runtime_liveness(
        self,
        *,
        device_id: str,
        boot_id: int,
        capability_hash: str,
    ) -> bytes:
        """Sign and publish one liveness message for a supervised device.

        This is the application-facing API, and the publisher's raw
        ``publish_runtime_liveness`` is transport glue beneath it. Going
        through here is what makes the supervision refusal load-bearing:
        the signer declines when this runtime is no longer receiving from
        the device, and nothing is published. Calling the transport
        directly bypasses that, so application code must not.
        """
        message = await self._liveness.sign_liveness(
            device_id=device_id,
            boot_id=boot_id,
            capability_hash=capability_hash,
        )
        await self._publisher.publish_runtime_liveness(device_id, message)
        return message

    async def _require_approved_device(self, device_id: str) -> dict[str, Any]:
        row = await self._store.get_firmware_device(device_id)
        if row is None:
            raise FirmwareCommandError(f"unknown firmware device: {device_id!r}")
        if row.get("revoked"):
            raise FirmwareCommandError(f"device {device_id!r} is revoked")
        if not row.get("approved"):
            raise FirmwareCommandError(f"device {device_id!r} is not approved")

        # The local `approved` flag is only intent. Authority becomes
        # effective when the evidence store has confirmed the identical
        # anchor_epoch_id (ori-specs/device-provisioning/v1.md). A command
        # or approval MUST NOT reach firmware until then, so this gate --
        # not `approved` -- decides whether the grant may be published. A
        # store without the confirmation surface (older schema) is treated
        # as unconfirmed rather than silently bypassing the gate.
        epoch = str(row.get("anchor_epoch_id", "") or "")
        status = None
        if epoch and hasattr(self._store, "get_firmware_confirmation_status"):
            status = await self._store.get_firmware_confirmation_status(
                device_id, epoch
            )
        if status != "confirmed":
            raise FirmwareCommandError(
                f"device {device_id!r} epoch is not cross-store confirmed "
                f"(status={status or 'unknown'!r}); the evidence store has not "
                "confirmed the same anchor_epoch_id, so the approval must not "
                "reach firmware yet"
            )
        return cast(dict[str, Any], row)


def _refuse_published_seed(seed: bytes, env_name: str, label: str) -> None:
    """A signing seed this repository publishes signs for anyone who has it.

    A seed whose key cannot be derived is refused rather than allowed through:
    the length and canonical encoding are already checked above, so reaching
    that state means the check could not be made, and a security refusal that
    cannot be made must not pass.
    """
    try:
        published = is_published_seed(seed)
    except Exception as exc:
        raise FirmwareCommandError(
            f"{label} env var {env_name!r} could not be checked against the "
            "published-key set, so it is refused rather than trusted"
        ) from exc
    if published:
        raise FirmwareCommandError(
            f"{label} env var {env_name!r} holds a seed this repository "
            "publishes as test material, so anyone with a clone signs the same "
            "firmware approvals or commands this device would accept. Generate "
            "a signing key that has never left the producer."
        )


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
    _refuse_published_seed(seed, clean_name, label)
    return seed


def _topic(device_id: str, leaf: str) -> str:
    if not isinstance(device_id, str) or not _FLEET_ID.match(device_id):
        raise FirmwareCommandPublishError(
            f"device_id is not a valid MQTT fleet identifier: {device_id!r}"
        )
    return f"ori/fw/{device_id}/{leaf}"


def _consume(future: Any) -> None:
    if not future.cancelled() and future.exception() is not None:
        logger.debug("[firmware-commands] stopping a retired client failed")


async def _stop_client(client: Any) -> None:
    try:
        await asyncio.to_thread(client.loop_stop)
    finally:
        await asyncio.to_thread(client.disconnect)


def _default_client_factory(**kwargs: Any) -> Any:
    assert mqtt is not None
    callback_api_version = getattr(mqtt, "CallbackAPIVersion", None)
    if callback_api_version is not None:
        kwargs.setdefault("callback_api_version", callback_api_version.VERSION2)
    return mqtt.Client(**kwargs)
