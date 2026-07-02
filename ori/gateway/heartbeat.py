# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""MQTT subscriber for the gateway LAN health heartbeat.

The gateway publishes a JSON heartbeat to ``ori/gateway/health`` every 30 s
(default).  This module maintains a persistent MQTT subscription and calls
``CapabilityPostureTracker.record_gateway_heartbeat`` directly on the asyncio
event loop via ``loop.call_soon_threadsafe`` whenever a heartbeat arrives.

The gateway is a separate process on a separate machine; the heartbeat is an
infrastructure liveness signal, not sensor data.  Routing it through the
sensor ``EventBus`` would conflate two semantically different event streams and
expose it to wildcard skill subscribers.  The direct call is the correct
interface — the heartbeat module is in the gateway package and knows exactly
what it is updating.

When ``gateway.auth.enabled: true`` the heartbeat payload must carry a valid
HMAC ``auth`` envelope (see ``GatewayMessageAuthenticator.verify_broadcast``).
Unsigned, stale, or replayed heartbeats are discarded with a WARNING.  When
auth is disabled the subscriber accepts unsigned heartbeats, which is the
correct default for LAN deployments that rely on broker ACLs rather than
payload-level HMAC (see DECISIONS.md 2026-06-06 and 2026-06-10).

Authentication note
-------------------
The gateway heartbeat payload carries **no** ``device_id`` and uses a
LAN-broadcast topic (``ori/gateway/health``) that is not device-scoped.
The per-device ``GatewayMessageAuthenticator.verify()`` therefore does not
apply.  ``verify_broadcast`` omits device binding but retains full HMAC,
timestamp-skew, and replay-TTL protection.  Gateway-side signing of heartbeat
payloads is required before enabling auth — see DECISIONS.md 2026-06-10.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable

from ori.gateway.mqtt_security import apply_tls_context, parse_gateway_broker_url
from ori.reasoning.capability_posture import CapabilityPostureTracker
from ori.security.gateway_messages import (
    GatewayMessageAuthenticator,
    GatewayMessageAuthError,
)
from ori.utils.time_utils import now_ms

try:
    import paho.mqtt.client as mqtt

    _PAHO_AVAILABLE = True
except ImportError:  # pragma: no cover — paho is always installed in production
    mqtt = None  # type: ignore[assignment]
    _PAHO_AVAILABLE = False

logger = logging.getLogger(__name__)

# Matches contracts.GatewayHealthTopic in ori-gateway.
GATEWAY_HEALTH_TOPIC = "ori/gateway/health"

_VALID_STATUSES = frozenset({"starting", "healthy", "degraded"})

# MQTT message type used in HMAC envelope signing/verification.
_HEARTBEAT_MESSAGE_TYPE = "gateway.heartbeat"


class MqttGatewayHeartbeatSubscriber:
    """Persistent MQTT subscriber that feeds gateway heartbeats into the posture tracker.

    Follows the same paho threading model as
    :class:`~ori.gateway.export.MqttGatewayExportServer`: paho runs its
    network I/O in a background thread started by ``loop_start``; the
    ``_on_message`` callback marshals the call back to the asyncio event loop
    via ``loop.call_soon_threadsafe`` so it executes on the correct thread
    without blocking paho's network thread.
    """

    def __init__(
        self,
        *,
        broker_url: str,
        posture_tracker: CapabilityPostureTracker,
        device_id: str,
        tls_config: dict[str, Any] | None = None,
        authenticator: GatewayMessageAuthenticator | None = None,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        if not _PAHO_AVAILABLE or mqtt is None:
            raise RuntimeError("paho-mqtt is not installed")
        self._broker = parse_gateway_broker_url(broker_url, tls_config=tls_config)
        self._posture_tracker = posture_tracker
        self._device_id = str(device_id)
        self._authenticator = authenticator
        self._client_factory = client_factory or _default_client_factory
        self._client: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        """Connect to the broker, subscribe, and serve until *shutdown_event* fires.

        Mirrors :meth:`~ori.gateway.export.MqttGatewayExportServer.serve_until`
        so the runtime can manage both servers with the same lifecycle pattern.
        """
        self._loop = asyncio.get_running_loop()
        client = self._client_factory(client_id=f"ori-hb-{self._device_id}")
        self._client = client
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        try:
            username = self._broker.username
            password = self._broker.password
            if username:
                client.username_pw_set(username, password)
            apply_tls_context(client, self._broker)
            await asyncio.to_thread(
                client.connect,
                self._broker.host,
                int(self._broker.port),
                60,
            )
            await asyncio.to_thread(client.loop_start)
            logger.info(
                "[gateway-heartbeat] subscribed to %s via %s:%s (auth=%s)",
                GATEWAY_HEALTH_TOPIC,
                self._broker.host,
                self._broker.port,
                "enabled" if self._authenticator is not None else "disabled",
            )
            await shutdown_event.wait()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("[gateway-heartbeat] MQTT subscriber stopped unexpectedly")
        finally:
            await self.close()

    async def close(self) -> None:
        """Stop the paho network loop and disconnect cleanly."""
        client = self._client
        self._client = None
        if client is None:
            return
        try:
            await asyncio.to_thread(client.loop_stop)
        except Exception:
            logger.warning("[gateway-heartbeat] failed to stop MQTT loop")
        try:
            await asyncio.to_thread(client.disconnect)
        except Exception:
            logger.warning("[gateway-heartbeat] failed to disconnect MQTT client")

    # ── paho callbacks ────────────────────────────────────────────────────────

    def _on_connect(
        self, client: Any, _userdata: Any, _flags: Any, rc: Any, *_: Any
    ) -> None:
        """Subscribe to the heartbeat topic on successful broker connect."""
        if int(getattr(rc, "value", rc)) != 0:
            logger.warning("[gateway-heartbeat] MQTT connect failed rc=%s", rc)
            return
        client.subscribe(GATEWAY_HEALTH_TOPIC)

    def _on_message(self, _client: Any, _userdata: Any, message: Any) -> None:
        """Parse a heartbeat payload and update gateway posture directly."""
        loop = self._loop
        if loop is None:
            logger.warning(
                "[gateway-heartbeat] message received before event loop ready"
            )
            return

        payload_bytes: bytes = getattr(message, "payload", b"") or b""
        try:
            payload = json.loads(payload_bytes)
        except Exception:
            logger.debug("[gateway-heartbeat] ignoring non-JSON payload")
            return
        if not isinstance(payload, dict):
            logger.debug("[gateway-heartbeat] ignoring non-object payload")
            return

        if self._authenticator is not None:
            try:
                payload = self._authenticator.verify_broadcast(
                    payload, message_type=_HEARTBEAT_MESSAGE_TYPE
                )
            except GatewayMessageAuthError as exc:
                logger.warning("[gateway-heartbeat] rejected heartbeat: %s", exc)
                return

        # Extract timestamp; fall back to local clock so posture is never
        # blocked by a malformed field.
        raw_ts = payload.get("timestamp_ms")
        try:
            timestamp_ms = int(raw_ts) if raw_ts is not None else now_ms()
        except (TypeError, ValueError):
            timestamp_ms = now_ms()

        status = str(payload.get("status", "") or "")
        if status and status not in _VALID_STATUSES:
            logger.debug(
                "[gateway-heartbeat] unrecognised status %r; heartbeat still recorded",
                status,
            )

        logger.debug(
            "[gateway-heartbeat] received status=%r ts=%d", status, timestamp_ms
        )

        # call_soon_threadsafe is required: _on_message fires on paho's network
        # thread; record_gateway_heartbeat must run on the asyncio event loop.
        loop.call_soon_threadsafe(
            self._posture_tracker.record_gateway_heartbeat, timestamp_ms
        )


# ── paho client factory ───────────────────────────────────────────────────────


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
