# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Publish runtime-posture/v1's signed record on `ori/{device_id}/runtime/posture`.

The record is published retained at QoS 1: a minute after start, whenever a
member other than `posture_seq`, `issued_at_ms` and `signature` would change,
and at least every 60 seconds, within 2 records in any 10 seconds and 5 in any
minute. The runtime keeps no record of earlier publications, so it waits the
minute v1 requires of a runtime that cannot establish them, and the windows
then hold across restarts. Without the posture key, the boot generation or the
signing clock it publishes nothing.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from ori.gateway.mqtt_retry import (
    MqttSession,
    SessionEnd,
    serve_with_reconnect,
    start_mqtt_client,
    wait_for_session,
)
from ori.gateway.mqtt_security import parse_gateway_broker_url
from ori.gateway.payload_bounds import RUNTIME_POSTURE
from ori.security.posture import PostureMembers, PostureRecordError
from ori.security.signing_clock import SigningClockUnavailableError
from ori.utils.coalesced_log import CoalescedWarning

logger = logging.getLogger(__name__)

#: runtime-posture/v1 Publication.
START_WAIT_S = 60.0
REFRESH_S = 60.0
WINDOWS: tuple[tuple[float, int], ...] = ((10.0, 2), (60.0, 5))
#: How often the publisher looks for a change to publish.
POLL_S = 1.0


@dataclass(frozen=True)
class PostureContent:
    """The members a change of which is a new record to publish."""

    device_id: str
    release: str | None
    deployment_profile: str
    commissioned_binding: str | None
    alert_classes: tuple[str, ...]


class PostureSigner(Protocol):
    def posture_public_key(self) -> bytes | None:
        """The posture key's raw 32 bytes, or None while it is not loaded."""

    async def posture_boot_generation(self) -> int | None:
        """The boot generation, claimed durably; None while unavailable."""

    def sign_posture_record(self, members: PostureMembers) -> bytes | None:
        """The signed record, or None while the key is not loaded."""


class PostureSchedule:
    """When a record may be published, on a monotonic clock.

    Due at the first chance after the start wait, after a change, and once the
    refresh interval has passed; allowed only while both sliding windows have
    room. Only a publication counts in the windows.
    """

    def __init__(self, started: float) -> None:
        self._ready_at = started + START_WAIT_S
        self._published: deque[float] = deque()
        self._last: tuple[float, PostureContent | None] | None = None

    def due(self, now: float, content: PostureContent) -> bool:
        if now < self._ready_at:
            return False
        if self._last is None:
            return True
        at, published = self._last
        return published != content or now - at >= REFRESH_S

    def allowed(self, now: float) -> bool:
        return all(
            sum(1 for at in self._published if now - at < span) < limit
            for span, limit in WINDOWS
        )

    def published(self, now: float, content: PostureContent) -> None:
        self._published.append(now)
        while self._published and now - self._published[0] >= WINDOWS[-1][0]:
            self._published.popleft()
        self._last = (now, content)


class RuntimePosturePublisher:
    """Sign and publish the runtime's posture record to the gateway broker."""

    def __init__(
        self,
        *,
        broker_url: str,
        device_id: str,
        content: Callable[[], PostureContent | None],
        signer: PostureSigner,
        issue_time: Callable[[], int],
        client_factory: Callable[..., Any],
        tls_config: dict[str, Any] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._broker = parse_gateway_broker_url(broker_url, tls_config=tls_config)
        self._device_id = str(device_id)
        self._content = content
        self._signer = signer
        self._issue_time = issue_time
        self._client_factory = client_factory
        self._monotonic = monotonic
        self._schedule = PostureSchedule(monotonic())
        self._boot_generation: int | None = None
        self._posture_seq = 0
        self._client: Any = None
        self._skipped = CoalescedWarning(logger)

    @property
    def topic(self) -> str:
        return RUNTIME_POSTURE.format(device_id=self._device_id)

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        """Connect and publish until shutdown."""
        await serve_with_reconnect(
            shutdown_event,
            connect=self._connect,
            close=self.close,
            log=logger,
            service="runtime-posture",
            run=self._publish_until_ended,
        )

    async def _connect(self, session: MqttSession) -> Any:
        client = self._client_factory(client_id=f"ori-posture-{self._device_id}")
        self._client = client
        session.bind(client)
        await start_mqtt_client(client, self._broker)
        return client

    async def close(self) -> None:
        client = self._client
        self._client = None
        if client is None:
            return
        for step in (client.loop_stop, client.disconnect):
            try:
                await asyncio.to_thread(step)
            except Exception:
                logger.warning("[runtime-posture] failed to close the MQTT client")

    async def _publish_until_ended(
        self, client: Any, shutdown: asyncio.Event, lost: asyncio.Event
    ) -> SessionEnd:
        while True:
            try:
                await self.publish_if_due(client)
            except Exception:
                logger.exception("[runtime-posture] no record was published")
            outcome = await wait_for_session(shutdown, lost, timeout=POLL_S)
            if outcome != "timeout":
                return outcome

    async def publish_if_due(self, client: Any) -> bytes | None:
        """Publish one record when one is due and allowed; the bytes, or None."""
        now = self._monotonic()
        content = self._content()
        if content is None or not self._schedule.due(now, content):
            return None
        if not self._schedule.allowed(now):
            return None
        record = await self._signed(content)
        if record is None:
            return None
        info = await asyncio.to_thread(
            client.publish, self.topic, record, qos=1, retain=True
        )
        # Counted however paho answers: a refusal (rc != 0) can leave the
        # message queued, to be sent on reconnect.
        self._schedule.published(now, content)
        rc = getattr(info, "rc", 0)
        if rc != 0:
            raise RuntimeError(f"the broker client refused the publish (rc={rc})")
        return record

    async def _signed(self, content: PostureContent) -> bytes | None:
        if self._signer.posture_public_key() is None:
            self._skip("the posture key is not loaded")
            return None
        generation = await self._signer.posture_boot_generation()
        if generation is None:
            self._skip("the boot generation cannot be claimed")
            return None
        try:
            issued_at_ms = self._issue_time()
        except SigningClockUnavailableError:
            self._skip("the signing clock is unavailable")
            return None
        seq = 1 if generation != self._boot_generation else self._posture_seq + 1
        members = PostureMembers(
            device_id=content.device_id,
            release=content.release,
            deployment_profile=content.deployment_profile,
            commissioned_binding=content.commissioned_binding,
            alert_classes=content.alert_classes,
            boot_generation=generation,
            posture_seq=seq,
            issued_at_ms=issued_at_ms,
        )
        try:
            record = self._signer.sign_posture_record(members)
        except PostureRecordError as exc:
            self._skip(f"a member v1 cannot carry: {exc}")
            return None
        if record is None:
            self._skip("the posture key is not loaded")
            return None
        # Counted once signed, kept even if the publish is then refused: paho
        # can still send that record, so its pair is never reissued.
        self._boot_generation, self._posture_seq = generation, seq
        return record

    def _skip(self, reason: str) -> None:
        self._skipped.warn(reason, "[runtime-posture] no record published: %s", reason)
        return None


def installed_alert_classes(
    loaded_skills: list[Any],
    class_for: Callable[[str, str], str | None],
) -> tuple[str, ...]:
    """The classes whose bound first-party skill and trigger have a handler."""
    classes = {
        cls
        for skill in loaded_skills
        if getattr(skill, "first_party", False) is True
        for trigger in getattr(skill, "triggers", None) or ()
        if (cls := class_for(str(skill.name), _trigger_name(trigger))) is not None
    }
    return tuple(sorted(classes, key=lambda name: name.encode("ascii")))


def _trigger_name(trigger: Any) -> str:
    if isinstance(trigger, dict):
        return str(trigger.get("name", ""))
    return str(getattr(trigger, "name", ""))
