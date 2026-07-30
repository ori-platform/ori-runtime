# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""MQTT subscriber for device-signed firmware telemetry.

Firmware nodes publish signed Layer 1 telemetry and fault events on
``ori/fw/<device_id>/telemetry``. This subscriber is transport glue only:
verification remains in :mod:`ori.security.firmware_ingest`; accepted
readings are converted to normal runtime events, while signed faults are
recorded as evidence and never enter reasoning or action dispatch.
"""

from __future__ import annotations

import asyncio
import json
import logging
from concurrent.futures import Future as ConcurrentFuture
from typing import Any, Callable

from ori.gateway.mqtt_security import apply_tls_context, parse_gateway_broker_url
from ori.network.deduplicator import EventDeduplicator
from ori.network.event_bus import EventBus
from ori.network.events import OriEvent, compute_fingerprint
from ori.security.firmware_ingest import FirmwareTelemetryGate
from ori.security.firmware_liveness import FirmwareLivenessSupervisor
from ori.state.store import StateStore

try:
    import paho.mqtt.client as mqtt

    _PAHO_AVAILABLE = True
except ImportError:  # pragma: no cover - paho is installed in production images
    mqtt = None
    _PAHO_AVAILABLE = False

logger = logging.getLogger(__name__)

FIRMWARE_TELEMETRY_TOPIC = "ori/fw/+/telemetry"


class MqttFirmwareTelemetrySubscriber:
    """Persistent MQTT subscriber for signed firmware telemetry."""

    def __init__(
        self,
        *,
        broker_url: str,
        telemetry_gate: FirmwareTelemetryGate,
        event_bus: EventBus,
        state_store: StateStore,
        runtime_device_id: str,
        topic: str = FIRMWARE_TELEMETRY_TOPIC,
        qos: int = 1,
        tls_config: dict[str, Any] | None = None,
        deduplicator: EventDeduplicator | None = None,
        client_factory: Callable[..., Any] | None = None,
        liveness_supervisor: FirmwareLivenessSupervisor,
    ) -> None:
        if not _PAHO_AVAILABLE or mqtt is None:
            raise RuntimeError("paho-mqtt is not installed")
        clean_topic = str(topic or "").strip()
        if not clean_topic:
            raise ValueError("firmware telemetry topic must not be empty")
        if "#" in clean_topic:
            raise ValueError("firmware telemetry topic must not use # wildcard")
        if int(qos) not in {0, 1, 2}:
            raise ValueError("firmware telemetry qos must be 0, 1, or 2")
        self._broker = parse_gateway_broker_url(broker_url, tls_config=tls_config)
        self._telemetry_gate = telemetry_gate
        self._event_bus = event_bus
        self._state_store = state_store
        self._runtime_device_id = str(runtime_device_id)
        self._topic = clean_topic
        self._qos = int(qos)
        self._deduplicator = deduplicator
        # Required and concretely typed. This subscriber is the ONLY thing
        # that establishes supervision; accepting ``None`` here made the
        # whole liveness feature silently inert, and ``Any`` let a wrongly
        # typed object through to fail at the first accepted reading
        # rather than at construction.
        if not isinstance(liveness_supervisor, FirmwareLivenessSupervisor):
            raise TypeError(
                "liveness_supervisor must be the FirmwareLivenessSupervisor "
                "shared with the firmware command service"
            )
        self._liveness_supervisor = liveness_supervisor
        self._client_factory = client_factory or _default_client_factory
        self._client: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        self._loop = asyncio.get_running_loop()
        client = self._client_factory(client_id=f"ori-fw-{self._runtime_device_id}")
        self._client = client
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        try:
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
            logger.info(
                "[firmware-telemetry] subscribed to %s via %s:%s",
                self._topic,
                self._broker.host,
                self._broker.port,
            )
            await shutdown_event.wait()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "[firmware-telemetry] MQTT subscriber stopped unexpectedly"
            )
        finally:
            await self.close()

    async def close(self) -> None:
        client = self._client
        self._client = None
        if client is None:
            return
        try:
            await asyncio.to_thread(client.loop_stop)
        except Exception:
            logger.warning("[firmware-telemetry] failed to stop MQTT loop")
        try:
            await asyncio.to_thread(client.disconnect)
        except Exception:
            logger.warning("[firmware-telemetry] failed to disconnect MQTT client")

    def _on_connect(
        self, client: Any, _userdata: Any, _flags: Any, rc: Any, *_: Any
    ) -> None:
        if int(getattr(rc, "value", rc)) != 0:
            logger.warning("[firmware-telemetry] MQTT connect failed rc=%s", rc)
            return
        client.subscribe(self._topic, qos=self._qos)

    def _on_message(self, _client: Any, _userdata: Any, message: Any) -> None:
        loop = self._loop
        if loop is None:
            logger.warning(
                "[firmware-telemetry] message received before event loop ready"
            )
            return

        payload_bytes: bytes = getattr(message, "payload", b"") or b""
        try:
            payload = json.loads(payload_bytes)
        except Exception:
            logger.debug("[firmware-telemetry] ignoring non-JSON payload")
            return
        if not isinstance(payload, dict):
            logger.debug("[firmware-telemetry] ignoring non-object payload")
            return

        if isinstance(payload.get("envelope"), dict):
            future = asyncio.run_coroutine_threadsafe(
                self._ingest_telemetry(payload), loop
            )
            future.add_done_callback(_log_background_failure)
            return
        if isinstance(payload.get("fault"), dict):
            future = asyncio.run_coroutine_threadsafe(self._ingest_fault(payload), loop)
            future.add_done_callback(_log_background_failure)
            return
        logger.debug("[firmware-telemetry] ignoring payload without envelope or fault")

    async def _ingest_telemetry(self, payload: dict[str, Any]) -> None:
        verification, readings = await self._telemetry_gate.ingest(payload)
        if not verification.accepted:
            return
        # Supervision is established by ACCEPTED, AUTHENTICATED telemetry
        # and nothing else. Doing this before verification would let an
        # unauthenticated publisher keep a device's backstop suppressed by
        # asserting supervision that no runtime is providing.
        self._liveness_supervisor.note_telemetry(
            device_id=verification.device_id,
            boot_id=verification.boot_id,
            capability_hash=verification.capability_hash,
        )
        for reading in readings:
            event = OriEvent.from_reading(reading, self._runtime_device_id)
            event.event_type = f"sensor.{reading.sensor_type}"
            event.source = reading.metadata.get("source", "firmware")
            event.fingerprint = compute_fingerprint(reading, event.device_id)
            await self._state_store.append_history(event)
            if (
                self._deduplicator is not None
                and self._deduplicator.process(event) is None
            ):
                logger.debug(
                    "[firmware-telemetry] deduplicator suppressed duplicate event %s",
                    event.event_id,
                )
                continue
            await self._event_bus.publish(event)

    async def _ingest_fault(self, payload: dict[str, Any]) -> None:
        await self._telemetry_gate.ingest_fault(payload)


def _log_background_failure(future: ConcurrentFuture[None]) -> None:
    try:
        future.result()
    except Exception:
        logger.exception("[firmware-telemetry] failed to process MQTT payload")


def _default_client_factory(*, client_id: str) -> Any:
    if mqtt is None:
        raise RuntimeError("paho-mqtt is not installed")
    kwargs: dict[str, Any] = {"client_id": client_id}
    if hasattr(mqtt, "CallbackAPIVersion"):
        kwargs["callback_api_version"] = mqtt.CallbackAPIVersion.VERSION2
    try:
        return mqtt.Client(**kwargs)
    except TypeError:
        kwargs.pop("callback_api_version", None)
        return mqtt.Client(**kwargs)
