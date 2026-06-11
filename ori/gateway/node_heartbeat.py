# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Runtime node heartbeat publisher for site-level gateway liveness.

This module publishes a small runtime-owned liveness payload to the gateway over
MQTT. It is intentionally separate from the sensor EventBus: node liveness is
infrastructure state, not a skill event, and wildcard skill subscribers should
not receive it.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from ori.gateway.mqtt_security import apply_tls_context, parse_gateway_broker_url
from ori.security.gateway_messages import GatewayMessageAuthenticator
from ori.utils.time_utils import now_ms

try:
    import paho.mqtt.client as mqtt

    _PAHO_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by monkeypatch in tests
    mqtt = None  # type: ignore[assignment]
    _PAHO_AVAILABLE = False

logger = logging.getLogger(__name__)

RUNTIME_HEARTBEAT_TOPIC_TEMPLATE = "ori/{device_id}/runtime/heartbeat"
RUNTIME_HEARTBEAT_MESSAGE_TYPE = "runtime.heartbeat"
DEFAULT_RUNTIME_HEARTBEAT_INTERVAL_S = 30.0
MIN_RUNTIME_HEARTBEAT_INTERVAL_S = 1.0


class MqttRuntimeNodeHeartbeatPublisher:
    """Publish runtime node liveness to the gateway at a bounded interval."""

    def __init__(
        self,
        *,
        broker_url: str,
        device_id: str,
        health_snapshot_provider: Callable[
            [], dict[str, Any] | Awaitable[dict[str, Any]]
        ],
        interval_seconds: float = DEFAULT_RUNTIME_HEARTBEAT_INTERVAL_S,
        tls_config: dict[str, Any] | None = None,
        authenticator: GatewayMessageAuthenticator | None = None,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        if not _PAHO_AVAILABLE or mqtt is None:
            raise RuntimeError("paho-mqtt is not installed")
        self._broker = parse_gateway_broker_url(broker_url, tls_config=tls_config)
        self._device_id = str(device_id)
        self._health_snapshot_provider = health_snapshot_provider
        self._interval_seconds = max(
            MIN_RUNTIME_HEARTBEAT_INTERVAL_S, float(interval_seconds)
        )
        self._authenticator = authenticator
        self._client_factory = client_factory or _default_client_factory
        self._client: Any = None

    @property
    def topic(self) -> str:
        return RUNTIME_HEARTBEAT_TOPIC_TEMPLATE.format(device_id=self._device_id)

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        """Connect to MQTT and publish node heartbeat until shutdown."""
        client = self._client_factory(client_id=f"ori-node-hb-{self._device_id}")
        self._client = client
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
                "[runtime-heartbeat] publishing %s via %s:%s every %.1fs (auth=%s)",
                self.topic,
                self._broker.host,
                self._broker.port,
                self._interval_seconds,
                "enabled" if self._authenticator is not None else "disabled",
            )
            await self._publish_once(client)
            while not shutdown_event.is_set():
                try:
                    await asyncio.wait_for(
                        shutdown_event.wait(), timeout=self._interval_seconds
                    )
                    break
                except asyncio.TimeoutError:
                    await self._publish_once(client)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("[runtime-heartbeat] publisher stopped unexpectedly")
        finally:
            await self.close()

    async def close(self) -> None:
        """Stop the paho loop and disconnect cleanly."""
        client = self._client
        self._client = None
        if client is None:
            return
        try:
            await asyncio.to_thread(client.loop_stop)
        except Exception:
            logger.warning("[runtime-heartbeat] failed to stop MQTT loop")
        try:
            await asyncio.to_thread(client.disconnect)
        except Exception:
            logger.warning("[runtime-heartbeat] failed to disconnect MQTT client")

    async def _publish_once(self, client: Any) -> None:
        payload = await self._payload()
        if self._authenticator is not None:
            payload = self._authenticator.sign(
                payload, message_type=RUNTIME_HEARTBEAT_MESSAGE_TYPE
            )
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        await asyncio.to_thread(client.publish, self.topic, body, qos=0, retain=False)

    async def _payload(self) -> dict[str, Any]:
        snapshot = self._health_snapshot_provider()
        if isinstance(snapshot, Awaitable):
            snapshot = await snapshot
        if not isinstance(snapshot, dict):
            snapshot = {}

        current_ms = now_ms()
        raw_status = str(snapshot.get("status", "healthy") or "healthy").strip()
        status = raw_status if raw_status in {"healthy", "degraded"} else "healthy"
        if snapshot.get("critical"):
            status = "degraded"

        active_triggers = snapshot.get("active_triggers", [])
        if not isinstance(active_triggers, list):
            active_triggers = []

        return {
            "device_id": self._device_id,
            "status": status,
            "last_seen_ms": current_ms,
            "gateway_seen_ms": 0,
            "active_triggers": [str(item) for item in active_triggers],
        }


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
