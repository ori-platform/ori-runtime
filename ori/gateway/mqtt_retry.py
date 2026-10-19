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

RECONNECT_MIN_S = 5.0
RECONNECT_MAX_S = 300.0

SessionEnd = Literal["shutdown", "lost", "timeout"]


class MqttSession:
    """Keep callbacks from a retired paho client out of the next session."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self.lost = asyncio.Event()
        self.connected = False
        self.ever_connected = False
        self._active = True

    def bind(
        self,
        client: Any,
        *,
        on_connect: Callable[..., Any] | None = None,
        on_message: Callable[..., Any] | None = None,
    ) -> None:
        def connected(c: Any, userdata: Any, flags: Any, rc: Any, *extra: Any) -> None:
            if not self._active:
                return
            self.connected = int(getattr(rc, "value", rc)) == 0
            self.ever_connected |= self.connected
            if not self.connected:
                self._signal_lost()
            if on_connect is not None:
                on_connect(c, userdata, flags, rc, *extra)

        def disconnected(_c: Any, *_args: Any) -> None:
            if self._active:
                self.connected = False
                self._signal_lost()

        client.on_connect = connected
        client.on_disconnect = disconnected
        if on_message is not None:

            def received(c: Any, userdata: Any, message: Any) -> None:
                if self._active:
                    on_message(c, userdata, message)

            client.on_message = received

    def retire(self) -> None:
        self._active = False

    def _signal_lost(self) -> None:
        if not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self.lost.set)


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
    ``RECONNECT_MIN_S`` after a session that connected.
    """
    loop = asyncio.get_running_loop()
    delay = RECONNECT_MIN_S
    while True:
        session = MqttSession(loop)
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
