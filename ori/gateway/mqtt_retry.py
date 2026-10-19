# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Reconnect lifecycle shared by runtime-gateway MQTT clients."""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from ori.gateway.mqtt_security import GatewayBrokerConfig, apply_tls_context
from ori.utils.mqtt_suback import subscription_refusal

logger = logging.getLogger(__name__)

RECONNECT_MIN_S = 5.0
RECONNECT_MAX_S = 300.0

SessionEnd = Literal["shutdown", "lost", "timeout"]


class MqttSession:
    """One broker session: up only once connected and, where it subscribes,
    granted its subscription; callbacks from a retired client reach nothing."""

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        *,
        log: logging.Logger = logger,
        service: str = "gateway-mqtt",
    ) -> None:
        self._loop = loop
        self._log = log
        self._service = service
        self.lost = asyncio.Event()
        self.connected = False
        self.ever_connected = False
        self._active = True

    def bind(
        self,
        client: Any,
        *,
        subscribe: tuple[str, int] | None = None,
        on_subscribed: Callable[[], None] | None = None,
        on_message: Callable[..., Any] | None = None,
    ) -> None:
        """Bind *client*'s callbacks to this session.

        With *subscribe*, sending SUBSCRIBE is not being subscribed: the
        session is up, and *on_subscribed* runs, only once SUBACK grants a QoS
        of 0 to 2. A refusal ends the session like a dropped connection.
        """

        # The message id of this session's SUBSCRIBE; a SUBACK for any other
        # is not its answer. None when a stand-in client returns no id.
        pending_mid: list[Any] = [None]

        def connected(c: Any, _userdata: Any, _flags: Any, rc: Any, *_: Any) -> None:
            if not self._active:
                return
            if reason_code_value(rc) != 0:
                self._log.warning("[%s] MQTT connect failed rc=%s", self._service, rc)
                self._end()
                return
            if subscribe is None:
                self._up(on_subscribed)
                return
            topic, qos = subscribe
            result = c.subscribe(topic, qos=qos)
            sent = result[0] if isinstance(result, tuple) else result
            pending_mid[0] = result[1] if isinstance(result, tuple) else None
            if sent is not None and reason_code_value(sent) != 0:
                self._log.warning(
                    "[%s] could not send subscribe for %s rc=%s",
                    self._service,
                    topic,
                    sent,
                )
                self._end()

        def subscribed(
            _c: Any, _userdata: Any, mid: Any, reason_codes: Any, *_: Any
        ) -> None:
            if not self._active or subscribe is None:
                return
            if pending_mid[0] is not None and mid != pending_mid[0]:
                return
            refused = subscription_refusal(reason_codes)
            if refused is not None:
                self._log.warning(
                    "[%s] broker refused subscription to %s (%s)",
                    self._service,
                    subscribe[0],
                    refused,
                )
                self._end()
                return
            self._log.info("[%s] subscribed to %s", self._service, subscribe[0])
            self._up(on_subscribed)

        def disconnected(_c: Any, *_args: Any) -> None:
            if self._active:
                self._end()

        client.on_connect = connected
        client.on_subscribe = subscribed
        client.on_disconnect = disconnected
        if on_message is not None:

            def received(c: Any, userdata: Any, message: Any) -> None:
                if self._active:
                    on_message(c, userdata, message)

            client.on_message = received

    def retire(self) -> None:
        self._active = False

    def _up(self, on_subscribed: Callable[[], None] | None) -> None:
        if self.connected:
            return
        self.connected = True
        self.ever_connected = True
        if on_subscribed is not None:
            on_subscribed()

    def _end(self) -> None:
        self.connected = False
        if not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self.lost.set)


def reason_code_value(code: Any) -> int:
    """Numeric value of a paho reason code, whichever callback API produced it."""
    try:
        return int(getattr(code, "value", code))
    except (TypeError, ValueError):
        return -1


def ensure_mqtt_success(result: Any, operation: str) -> None:
    """Paho returns an error code; test doubles may return None on success."""
    if result is not None and int(result) != 0:
        raise ConnectionError(f"MQTT {operation} refused with code {result}")


async def wait_for_session(
    shutdown: asyncio.Event,
    lost: asyncio.Event,
    *,
    timeout: float | None = None,
) -> SessionEnd:
    """Wait without leaving an orphan task on cancellation or timeout."""
    if shutdown.is_set():
        return "shutdown"
    if lost.is_set():
        return "lost"
    stopping = asyncio.create_task(shutdown.wait())
    dropping = asyncio.create_task(lost.wait())
    try:
        done, _ = await asyncio.wait(
            {stopping, dropping}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
        )
        if stopping in done:
            return "shutdown"
        if dropping in done:
            return "lost"
        return "timeout"
    finally:
        stopping.cancel()
        dropping.cancel()
        await asyncio.gather(stopping, dropping, return_exceptions=True)


async def start_mqtt_client(client: Any, broker: GatewayBrokerConfig) -> None:
    """Apply credentials and TLS, connect, and start the network thread."""
    if broker.username:
        client.username_pw_set(broker.username, broker.password)
    apply_tls_context(client, broker)
    ensure_mqtt_success(
        await asyncio.to_thread(client.connect, broker.host, int(broker.port), 60),
        "connect",
    )
    ensure_mqtt_success(await asyncio.to_thread(client.loop_start), "loop_start")


async def serve_with_reconnect(
    shutdown: asyncio.Event,
    *,
    connect: Callable[[MqttSession], Awaitable[Any]],
    close: Callable[[], Awaitable[None]],
    log: logging.Logger,
    service: str,
    run: Callable[[Any, asyncio.Event, asyncio.Event], Awaitable[SessionEnd]]
    | None = None,
) -> None:
    """Hold one MQTT session at a time until *shutdown*, reconnecting on loss.

    Each attempt gets a fresh session, which *connect* binds to a fresh client
    and returns. *run* serves it until shutdown or loss; without one the
    session is only held open. A session ends retired and closed however it
    ends, so a retired client's callbacks never reach the next one. Backoff
    doubles to ``RECONNECT_MAX_S`` with jitter and restarts at
    ``RECONNECT_MIN_S`` after a session that came up: connected and, where it
    subscribes, granted its subscription.
    """
    loop = asyncio.get_running_loop()
    delay = RECONNECT_MIN_S
    while True:
        session = MqttSession(loop, log=log, service=service)
        try:
            client = await connect(session)
            if run is None:
                outcome = await wait_for_session(shutdown, session.lost)
            else:
                outcome = await run(client, shutdown, session.lost)
            if outcome == "lost":
                log.warning("[%s] MQTT session lost; reconnecting", service)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("[%s] MQTT session failed; reconnecting", service)
        finally:
            session.retire()
            await close()
        if session.ever_connected:
            delay = RECONNECT_MIN_S
        if not await wait_before_retry(shutdown, delay):
            return
        delay = min(delay * 2, RECONNECT_MAX_S)


def retry_delay(base_delay_s: float) -> float:
    return min(RECONNECT_MAX_S, base_delay_s * random.uniform(0.8, 1.2))


async def wait_before_retry(shutdown: asyncio.Event, base_delay_s: float) -> bool:
    """Return False when shutdown interrupts bounded, jittered backoff."""
    delay = retry_delay(base_delay_s)
    try:
        await asyncio.wait_for(shutdown.wait(), timeout=delay)
        return False
    except asyncio.TimeoutError:
        return True
