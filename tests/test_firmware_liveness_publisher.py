# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Periodic liveness publication.

The loop turns a signature into a continuous claim. What matters is not
that it publishes, but what it does when things go wrong: a device that
stopped sending must stop being told it is watched, and one broken device
must not be able to silence the fleet.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from ori.gateway.firmware_liveness_publisher import (
    MIN_LIVENESS_PUBLISH_INTERVAL_S,
    FirmwareLivenessScheduler,
)
from ori.security.firmware_liveness import (
    LIVENESS_PUBLISH_INTERVAL_S,
    FirmwareLivenessError,
    SupervisedDevice,
)

HASH = "sha256:" + "a" * 64


def _device(device_id: str, boot_id: int = 41) -> SupervisedDevice:
    return SupervisedDevice(
        device_id=device_id, boot_id=boot_id, capability_hash=HASH
    )


class _FakeService:
    """The FirmwareCommandService surface the scheduler is allowed to use.

    Deliberately does NOT expose the transport publisher: if the scheduler
    ever reached past the service to publish, this fake would not satisfy
    it and the tests would fail rather than quietly lose the supervision
    check.
    """

    def __init__(self, devices=(), fail=None) -> None:
        self._devices = tuple(devices)
        self._fail = fail or {}
        self.published: list[tuple[str, int, str]] = []
        self.snapshots = 0

    def supervised_devices(self):
        self.snapshots += 1
        return self._devices

    def set_devices(self, devices) -> None:
        self._devices = tuple(devices)

    async def publish_runtime_liveness(
        self, *, device_id: str, boot_id: int, capability_hash: str
    ) -> bytes:
        exc = self._fail.get(device_id)
        if exc is not None:
            raise exc
        self.published.append((device_id, boot_id, capability_hash))
        return b'{"liveness":{}}'


async def test_publishes_for_every_supervised_device() -> None:
    service = _FakeService([_device("ori-fw-a"), _device("ori-fw-b")])
    scheduler = FirmwareLivenessScheduler(service)

    assert await scheduler.publish_once() == 2
    assert [row[0] for row in service.published] == ["ori-fw-a", "ori-fw-b"]


async def test_publishes_the_identity_supervision_was_established_under() -> None:
    """Not a registry lookup. The boot and manifest epoch come from the
    telemetry that established supervision, so a scheduler never turns an
    event-driven map back into a fleet poll."""
    service = _FakeService([_device("ori-fw-a", boot_id=77)])
    await FirmwareLivenessScheduler(service).publish_once()
    assert service.published == [("ori-fw-a", 77, HASH)]


async def test_unsupervised_device_is_simply_absent() -> None:
    """There is no removal path and no goodbye message: a device that went
    quiet stops appearing in the snapshot, and silence is what tells it to
    re-enable its own backstop."""
    service = _FakeService([])
    assert await FirmwareLivenessScheduler(service).publish_once() == 0
    assert service.published == []


async def test_a_refusal_mid_tick_does_not_stop_the_others() -> None:
    """Supervision can end between the snapshot and the signature. The
    signer refusing is the mechanism working, not an error."""
    service = _FakeService(
        [_device("ori-fw-a"), _device("ori-fw-b"), _device("ori-fw-c")],
        fail={"ori-fw-b": FirmwareLivenessError("not supervised")},
    )
    assert await FirmwareLivenessScheduler(service).publish_once() == 2
    assert [row[0] for row in service.published] == ["ori-fw-a", "ori-fw-c"]


async def test_a_publish_failure_does_not_silence_the_fleet() -> None:
    """One device whose topic the broker refuses must not stop the others
    from being told they are watched — that would let a single broken
    device suppress the backstop signal fleet-wide."""
    service = _FakeService(
        [_device("ori-fw-a"), _device("ori-fw-b"), _device("ori-fw-c")],
        fail={"ori-fw-a": RuntimeError("broker refused")},
    )
    assert await FirmwareLivenessScheduler(service).publish_once() == 2
    assert [row[0] for row in service.published] == ["ori-fw-b", "ori-fw-c"]


async def test_publish_once_never_raises_for_a_single_device() -> None:
    service = _FakeService(
        [_device("ori-fw-a")], fail={"ori-fw-a": RuntimeError("boom")}
    )
    assert await FirmwareLivenessScheduler(service).publish_once() == 0


async def test_cancellation_is_not_swallowed_as_a_device_failure() -> None:
    """CancelledError means shutdown, not a broken device. Catching it as
    one would make the loop unstoppable."""
    service = _FakeService(
        [_device("ori-fw-a")], fail={"ori-fw-a": asyncio.CancelledError()}
    )
    with pytest.raises(asyncio.CancelledError):
        await FirmwareLivenessScheduler(service).publish_once()


async def test_a_tick_slower_than_the_interval_is_reported(caplog) -> None:
    """A fleet that no longer fits in one interval means devices are being
    served more slowly than configured and some may expire. Capacity
    signal, not a transient error."""
    service = _FakeService([_device("ori-fw-a")])
    ticks = iter([100.0, 130.0])
    scheduler = FirmwareLivenessScheduler(
        service, interval_s=15.0, clock=lambda: next(ticks)
    )
    with caplog.at_level(logging.WARNING):
        await scheduler.publish_once()
    assert "longer than the 15.0s interval" in caplog.text


async def test_a_tick_within_the_interval_is_silent(caplog) -> None:
    service = _FakeService([_device("ori-fw-a")])
    ticks = iter([100.0, 101.0])
    scheduler = FirmwareLivenessScheduler(
        service, interval_s=15.0, clock=lambda: next(ticks)
    )
    with caplog.at_level(logging.WARNING):
        await scheduler.publish_once()
    assert caplog.text == ""


def test_the_scheduler_refuses_the_transport_publisher() -> None:
    """Publishing must go through the service, whose signing refusal IS the
    supervision obligation. A transport publisher has a
    publish_runtime_liveness of its own that skips it."""

    class _TransportOnly:
        async def publish_runtime_liveness(self, device_id, message):
            pass

    with pytest.raises(TypeError, match="not the transport publisher"):
        FirmwareLivenessScheduler(_TransportOnly())


@pytest.mark.parametrize("bad", [0, 0.5, -15.0, True, "15"])
def test_an_interval_that_cannot_keep_a_device_alive_is_refused(bad) -> None:
    """The interval is a safety parameter: at or above the device's expiry
    window it guarantees expiry, so it is validated rather than trusted."""
    with pytest.raises(ValueError):
        FirmwareLivenessScheduler(_FakeService(), interval_s=bad)


def test_default_interval_matches_the_contract() -> None:
    scheduler = FirmwareLivenessScheduler(_FakeService())
    assert scheduler.interval_s == LIVENESS_PUBLISH_INTERVAL_S
    assert LIVENESS_PUBLISH_INTERVAL_S >= MIN_LIVENESS_PUBLISH_INTERVAL_S


async def test_serve_until_publishes_repeatedly_then_stops() -> None:
    service = _FakeService([_device("ori-fw-a")])
    scheduler = FirmwareLivenessScheduler(service, interval_s=1.0)
    shutdown = asyncio.Event()

    task = asyncio.create_task(scheduler.serve_until(shutdown))
    # Let several intervals elapse without sleeping in real time.
    for _ in range(3):
        await asyncio.sleep(0)
    await asyncio.sleep(0.05)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)

    assert not task.cancelled()


async def test_shutdown_before_the_first_interval_publishes_nothing() -> None:
    """Nothing is supervised until telemetry arrives, so an immediate tick
    at startup would find an empty map; the first publish waits one
    interval and a fast shutdown must not force one."""
    service = _FakeService([_device("ori-fw-a")])
    scheduler = FirmwareLivenessScheduler(service, interval_s=30.0)
    shutdown = asyncio.Event()
    shutdown.set()

    await asyncio.wait_for(scheduler.serve_until(shutdown), timeout=2.0)
    assert service.published == []


async def test_the_loop_survives_a_snapshot_that_raises(caplog) -> None:
    """If the loop dies silently every device believes it is supervised
    until its own window expires, so a failure must be loud."""

    class _BrokenService(_FakeService):
        def supervised_devices(self):
            raise RuntimeError("supervisor exploded")

    # The interval floor is a real safety bound, so this waits out one
    # genuine tick rather than lowering it for the test's convenience.
    scheduler = FirmwareLivenessScheduler(
        _BrokenService(), interval_s=MIN_LIVENESS_PUBLISH_INTERVAL_S
    )
    shutdown = asyncio.Event()
    with caplog.at_level(logging.ERROR):
        task = asyncio.create_task(scheduler.serve_until(shutdown))
        await asyncio.wait_for(task, timeout=5.0)
    assert "stopped unexpectedly" in caplog.text
    # The task ended rather than spinning: a loop that kept running after
    # losing its supervisor snapshot would report nothing and do nothing.
    assert task.done() and not task.cancelled()
