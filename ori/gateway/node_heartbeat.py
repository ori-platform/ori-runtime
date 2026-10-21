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
import math
import re
from collections.abc import Awaitable, Callable
from typing import Any

from ori.gateway.mqtt_retry import (
    MqttSession,
    SessionEnd,
    serve_with_reconnect,
    start_mqtt_client,
    wait_for_session,
)
from ori.gateway.mqtt_security import parse_gateway_broker_url
from ori.gateway.payload_bounds import (
    ACTIVE_TRIGGERS_MAX,
    RUNTIME_HEARTBEAT,
    fits,
    fitting_count,
)
from ori.security.gateway_messages import GatewayMessageAuthenticator
from ori.security.signing_clock import SigningClockUnavailableError
from ori.utils.time_utils import now_ms

try:
    import paho.mqtt.client as mqtt

    _PAHO_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by monkeypatch in tests
    mqtt = None  # type: ignore[assignment]
    _PAHO_AVAILABLE = False

logger = logging.getLogger(__name__)

# ── degradation_reasons (gateway-api/v1) ─────────────────────────────
#
# The closed v1 vocabulary lives at the wire boundary because that is where
# the contract is enforced. A gateway refuses an unrecognised token, so
# emitting one would make a conforming receiver reject the entire heartbeat —
# the same failure the ratified rollout order (specs, then gateway, then
# runtime) exists to prevent. Adding a token here before gateways accept it
# would recreate exactly that.
DEGRADATION_REASON_FIRMWARE_LIVENESS = "firmware_liveness_degraded"

DEGRADATION_REASONS: frozenset[str] = frozenset(
    {
        DEGRADATION_REASON_FIRMWARE_LIVENESS,
    }
)

DEGRADATION_REASONS_MAX = 16


def _wire_degradation_reasons(raw: Any) -> list[str]:
    """Validates snapshot reasons at the wire boundary.

    Refuses rather than coerces. An earlier version ran ``str()`` over
    whatever the snapshot held, deduplicated and published it — which would
    happily emit a token no gateway can accept, and manufacture a plausible
    string from an object that was never a reason at all.

    Anything unusable is dropped with a warning and the field is omitted, so
    a malformed snapshot degrades to "no named reason" rather than to a
    heartbeat a conforming receiver must reject in full.
    """
    if not isinstance(raw, list) or not raw:
        return []

    accepted: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            logger.warning(
                "[runtime-heartbeat] dropping non-string degradation reason %r", item
            )
            continue
        if item not in DEGRADATION_REASONS:
            # Never emitted: a receiver is contractually required to refuse
            # an unratified token, and refusing it here costs one reason
            # while emitting it costs the whole heartbeat.
            logger.warning(
                "[runtime-heartbeat] dropping unratified degradation reason %r", item
            )
            continue
        accepted.add(item)

    tokens = sorted(accepted)
    if len(tokens) > DEGRADATION_REASONS_MAX:
        logger.error(
            "[runtime-heartbeat] %d degradation reasons exceeds the contract "
            "maximum of %d; omitting the field",
            len(tokens),
            DEGRADATION_REASONS_MAX,
        )
        return []
    return tokens


RUNTIME_HEARTBEAT_TOPIC_TEMPLATE = "ori/{device_id}/runtime/heartbeat"
RUNTIME_HEARTBEAT_MESSAGE_TYPE = "runtime.heartbeat"
DEFAULT_RUNTIME_HEARTBEAT_INTERVAL_S = 30.0
MIN_RUNTIME_HEARTBEAT_INTERVAL_S = 1.0
MAX_RUNTIME_HEARTBEAT_INTERVAL_S = 86_400.0


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
        interval = float(interval_seconds)
        # Any number runtime-config/v2 admits, kept to an interval that ever
        # fires again: infinity and NaN are the default, and nothing exceeds
        # a day.
        if not math.isfinite(interval):
            interval = DEFAULT_RUNTIME_HEARTBEAT_INTERVAL_S
        self._interval_seconds = min(
            max(MIN_RUNTIME_HEARTBEAT_INTERVAL_S, interval),
            MAX_RUNTIME_HEARTBEAT_INTERVAL_S,
        )
        self._authenticator = authenticator
        self._client_factory = client_factory or _default_client_factory
        self._client: Any = None

    @property
    def topic(self) -> str:
        return RUNTIME_HEARTBEAT_TOPIC_TEMPLATE.format(device_id=self._device_id)

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        """Connect to MQTT and publish node heartbeat until shutdown."""
        await serve_with_reconnect(
            shutdown_event,
            connect=self._connect,
            close=self.close,
            log=logger,
            service="runtime-heartbeat",
            run=self._publish_until_ended,
        )

    async def _connect(self, session: MqttSession) -> Any:
        client = self._client_factory(client_id=f"ori-node-hb-{self._device_id}")
        self._client = client
        session.bind(client)
        await start_mqtt_client(client, self._broker)
        logger.info(
            "[runtime-heartbeat] publishing %s via %s:%s every %.1fs (auth=%s)",
            self.topic,
            self._broker.host,
            self._broker.port,
            self._interval_seconds,
            "enabled" if self._authenticator is not None else "disabled",
        )
        return client

    async def _publish_until_ended(
        self, client: Any, shutdown: asyncio.Event, lost: asyncio.Event
    ) -> SessionEnd:
        await self._tick(client)
        while True:
            outcome = await wait_for_session(
                shutdown, lost, timeout=self._interval_seconds
            )
            if outcome != "timeout":
                return outcome
            await self._tick(client)

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

    async def _tick(self, client: Any) -> None:
        """Publish once; a failure is logged and the next tick still runs."""
        try:
            await self._publish_once(client)
        except Exception:
            logger.exception("[runtime-heartbeat] no heartbeat was sent this tick")

    async def _publish_once(self, client: Any) -> None:
        payload = await self._payload()
        try:
            body = self._fitted(payload)
        except SigningClockUnavailableError:
            # A fallback would be refused the same way: nothing is signed
            # until the signing clock has claimed again, and it says so.
            return
        except Exception as exc:
            # A mapped heartbeat that cannot be signed or encoded is replaced,
            # not dropped: silence would read as offline rather than degraded.
            body = self._encode(self._fallback(int(payload["last_seen_ms"])))
            logger.warning(
                "[runtime-heartbeat] heartbeat could not be encoded (%s); "
                "publishing degraded",
                type(exc).__name__,
            )
        info = await asyncio.to_thread(
            client.publish, self.topic, body, qos=0, retain=False
        )
        # paho answers a publish it could not queue, such as one on a
        # disconnected client, with a nonzero rc rather than an exception.
        rc = getattr(info, "rc", 0)
        if rc != 0:
            raise RuntimeError(f"the broker client refused the publish (rc={rc})")

    def _fitted(self, payload: dict[str, Any]) -> bytes:
        """*payload* encoded with only the `active_triggers` its maximum holds.

        Names are kept in the order the runtime holds them and no other member
        is given up for them, so a consumer reads their number as a lower bound
        (gateway-api/v2 Payload Size).
        """
        body = self._encode(payload)
        if fits(RUNTIME_HEARTBEAT, body):
            return body
        triggers = payload["active_triggers"]

        def with_first(count: int) -> bytes:
            return self._encode({**payload, "active_triggers": triggers[:count]})

        return with_first(
            fitting_count(
                len(triggers), lambda n: fits(RUNTIME_HEARTBEAT, with_first(n))
            )
        )

    def _encode(self, payload: dict[str, Any]) -> bytes:
        if self._authenticator is not None:
            payload = self._authenticator.sign(
                payload, message_type=RUNTIME_HEARTBEAT_MESSAGE_TYPE
            )
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )

    async def _payload(self) -> dict[str, Any]:
        current_ms = now_ms()
        try:
            snapshot = self._health_snapshot_provider()
            if isinstance(snapshot, Awaitable):
                snapshot = await snapshot
            fault = _snapshot_status_fault(snapshot)
            if fault is None and isinstance(snapshot, dict):
                return self._mapped(snapshot, current_ms)
        except Exception as exc:
            fault = f"unreadable ({type(exc).__name__})"
        # A verdict the runtime cannot read may be hiding a critical one, so
        # it never publishes healthy, and nothing else is taken from it.
        logger.warning(
            "[runtime-heartbeat] health snapshot is malformed (%s); "
            "mapping it to degraded",
            fault,
        )
        return self._fallback(current_ms)

    def _fallback(self, current_ms: int) -> dict[str, Any]:
        return {
            "device_id": self._device_id,
            "status": "degraded",
            "last_seen_ms": current_ms,
            "gateway_seen_ms": 0,
            "active_triggers": [],
        }

    def _mapped(self, snapshot: dict[str, Any], current_ms: int) -> dict[str, Any]:
        # gateway-api/v2 holds `critical` back until a gateway claims its
        # heartbeat rules, and until then a runtime emits only what v1
        # accepts, so a local critical is published as degraded.
        status = "degraded" if "status" in snapshot else "healthy"

        active_triggers = snapshot.get("active_triggers", [])
        if not isinstance(active_triggers, list) or not all(
            isinstance(item, str) for item in active_triggers
        ):
            raise TypeError("active_triggers is not a list of strings")

        payload: dict[str, Any] = {
            "device_id": self._device_id,
            "status": status,
            "last_seen_ms": current_ms,
            "gateway_seen_ms": 0,
            "active_triggers": list(active_triggers[:ACTIVE_TRIGGERS_MAX]),
        }

        # degradation_reasons names which subsystem is degraded, so a site
        # view can tell why a node reports degraded rather than only that it
        # does. Deliberately separate from active_triggers: a trigger is a
        # physical or automation trigger and a degraded subsystem is neither,
        # and overloading that field would inflate its count.
        #
        # Omitted entirely when empty. An empty array is malformed under
        # gateway-api/v1 — absent and present-empty are different states, and
        # a receiver is required to refuse the latter.
        tokens = _wire_degradation_reasons(snapshot.get("degradation_reasons"))
        if tokens:
            # The contract's implication rule runs the other way too: reasons
            # are only meaningful alongside a degraded status. Anything that
            # named a reason has already contributed critical/degraded to the
            # snapshot, so this is a guard against a future caller that
            # forgets, not an expected branch — the composition tests prove
            # it is unreachable in normal operation.
            if status == "degraded":
                payload["degradation_reasons"] = tokens
            else:
                logger.warning(
                    "[runtime-heartbeat] dropping degradation_reasons %s on a %s "
                    "heartbeat: reasons require a degraded status",
                    tokens,
                    status,
                )

        # Evidence-chain truncation signal: the heartbeat carries the chain
        # head so the site can spot a truncated/reset local chain in near
        # real time. The persisted chain remains the evidence object.
        evidence = snapshot.get("evidence")
        if isinstance(evidence, dict) and _wire_bool(
            evidence.get("enabled", False), "evidence.enabled"
        ):
            payload["evidence"] = {
                "chain_head_hash": _wire_text(
                    evidence.get("chain_head_hash"), _CHAIN_HEAD_HASH, "chain_head_hash"
                ),
                "attestation_gap_count": _gap_count(
                    evidence.get("attestation_gap_count")
                ),
                "available": _wire_bool(
                    evidence.get("available", False), "evidence.available"
                ),
                # Emission vocabulary ('' while signing is unavailable) so
                # the site can confirm a mixed-fleet vocabulary rollout
                # without waiting for the first Tier C/D action.
                "action_event_type": _wire_text(
                    evidence.get("action_event_type"),
                    _ACTION_EVENT_TYPE,
                    "action_event_type",
                ),
            }
        return payload


# The shapes gateway-api/v2 admits; a gateway refuses the whole heartbeat
# otherwise, so a value outside them maps to the degraded heartbeat instead.
_CHAIN_HEAD_HASH = re.compile(r"(?:[0-9a-f]{64})?")
_ACTION_EVENT_TYPE = re.compile(r"[A-Z_]{0,64}")


def _wire_text(value: Any, shape: re.Pattern[str], name: str) -> str:
    """A string in *shape*; absent or None is the empty string, nothing else is."""
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise TypeError(f"{name} is not a string")
    text = value
    if shape.fullmatch(text) is None:
        raise ValueError(f"{name} is outside the shape gateway-api/v2 admits")
    return text


def _wire_bool(value: Any, name: str) -> bool:
    """A boolean, as is: a string such as "false" is refused, never read as true."""
    if not isinstance(value, bool):
        raise TypeError(f"{name} is not a boolean")
    return value


def _gap_count(value: Any) -> int:
    """The gap count the contract admits: an integer from 0 to 2^53-1.

    Absent or None is 0. A bool, a float or a string is refused before any
    conversion, so nothing is rounded or parsed into a count.
    """
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("attestation_gap_count is not an integer")
    count = value
    if not 0 <= count <= 2**53 - 1:
        raise ValueError(f"attestation_gap_count {count} is outside 0..2^53-1")
    return count


def _snapshot_status_fault(snapshot: Any) -> str | None:
    """Why *snapshot*'s status cannot be mapped to a heartbeat, or None.

    `status` is absent when healthy, and `critical` is always a boolean equal
    to `status == "critical"`; anything else is malformed.
    """
    if not isinstance(snapshot, dict):
        return "not an object"
    status = snapshot.get("status")
    if "status" in snapshot and status not in ("degraded", "critical"):
        return f"status {status!r}"
    critical = snapshot.get("critical")
    if not isinstance(critical, bool):
        return f"critical {critical!r}"
    if critical != (status == "critical"):
        return f"critical {critical!r} with status {status!r}"
    return None


def _default_client_factory(*, client_id: str) -> Any:
    if mqtt is None:
        raise RuntimeError("paho-mqtt is not installed")
    kwargs: dict[str, Any] = {"client_id": client_id}
    callback_api_version = getattr(mqtt, "CallbackAPIVersion", None)
    if callback_api_version is not None:
        kwargs["callback_api_version"] = callback_api_version.VERSION2
    try:
        return mqtt.Client(**kwargs)
    except TypeError:
        kwargs.pop("callback_api_version", None)
        return mqtt.Client(**kwargs)
