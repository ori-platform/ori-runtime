# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Reconnect lifecycle shared by runtime-gateway MQTT clients."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Callable
from typing import Any, Literal

RECONNECT_MIN_S = 5.0
RECONNECT_MAX_S = 300.0


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
            if not self._active or c is not client:
                return
            self.connected = int(getattr(rc, "value", rc)) == 0
            self.ever_connected |= self.connected
            if not self.connected:
                self._signal_lost()
            if on_connect is not None:
                on_connect(c, userdata, flags, rc, *extra)

        def disconnected(c: Any, *_args: Any) -> None:
            if self._active and c is client:
                self.connected = False
                self._signal_lost()

        client.on_connect = connected
        client.on_disconnect = disconnected
        if on_message is not None:

            def received(c: Any, userdata: Any, message: Any) -> None:
                if self._active and c is client:
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
) -> Literal["shutdown", "lost", "timeout"]:
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
