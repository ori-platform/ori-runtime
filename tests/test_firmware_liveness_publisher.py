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
import time

import pytest

from ori.gateway.firmware_liveness_publisher import (
    MAX_LIVENESS_PUBLISH_INTERVAL_S,
    MIN_LIVENESS_PUBLISH_INTERVAL_S,
    FirmwareLivenessScheduler,
)
from ori.security.firmware_liveness import (
    LIVENESS_EXPIRY_WINDOW_S,
    LIVENESS_PUBLISH_INTERVAL_S,
    FirmwareLivenessError,
    SupervisedDevice,
)

HASH = "sha256:" + "a" * 64


def _device(device_id: str, boot_id: int = 41) -> SupervisedDevice:
    return SupervisedDevice(device_id=device_id, boot_id=boot_id, capability_hash=HASH)


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
def test_an_interval_below_the_floor_is_refused(bad) -> None:
    """The floor only stops a misconfiguration becoming a publish storm."""
    with pytest.raises(ValueError):
        FirmwareLivenessScheduler(_FakeService(), interval_s=bad)


@pytest.mark.parametrize("bad", [20.1, 30.0, 60.0, 3600.0])
def test_an_interval_that_cannot_keep_a_device_alive_is_refused(bad) -> None:
    """The safety-relevant bound, and the one an earlier revision missed.

    The contract requires the device's expiry window to be at least 3x the
    publication interval, so isolated message loss cannot mark a healthy
    runtime unreachable. Above the ceiling a single dropped message expires
    a device — 30s and 60s were accepted before, and 60s means a device
    expires exactly as its replacement message is due.
    """
    with pytest.raises(ValueError, match="at most"):
        FirmwareLivenessScheduler(_FakeService(), interval_s=bad)


@pytest.mark.parametrize("bad", [float("inf"), float("nan"), float("-inf")])
def test_a_non_finite_interval_is_refused(bad) -> None:
    """NaN is the dangerous one: every deadline comparison against it is
    false, so the loop would run without ever publishing while reporting
    itself healthy."""
    with pytest.raises(ValueError, match="finite"):
        FirmwareLivenessScheduler(_FakeService(), interval_s=bad)


def test_the_ceiling_is_derived_from_the_contract_not_chosen() -> None:
    """If the expiry window is ever ratified to a different value, the
    ceiling must move with it rather than stay a magic number."""
    assert MAX_LIVENESS_PUBLISH_INTERVAL_S == LIVENESS_EXPIRY_WINDOW_S / 3.0
    assert LIVENESS_PUBLISH_INTERVAL_S <= MAX_LIVENESS_PUBLISH_INTERVAL_S


@pytest.mark.parametrize("bad", [0, -1.0, float("nan"), float("inf"), True, "5"])
def test_an_invalid_per_device_timeout_is_refused(bad) -> None:
    with pytest.raises(ValueError):
        FirmwareLivenessScheduler(_FakeService(), per_device_timeout_s=bad)


@pytest.mark.parametrize("bad", [0, -1, True, 1.5])
def test_an_invalid_concurrency_bound_is_refused(bad) -> None:
    with pytest.raises(ValueError):
        FirmwareLivenessScheduler(_FakeService(), max_concurrent=bad)


def test_the_worst_case_device_latency_stays_under_the_expiry_window() -> None:
    """The bound the scheduler exists to provide: one interval waiting for
    its tick, plus the longest a single publication may take. A bounded-
    but-slow tick must still not be able to expire a device."""
    scheduler = FirmwareLivenessScheduler(_FakeService())
    assert (
        scheduler.max_device_publish_latency_s
        == scheduler.interval_s + scheduler.per_device_timeout_s
    )
    assert scheduler.max_device_publish_latency_s < LIVENESS_EXPIRY_WINDOW_S


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
    scheduler = FirmwareLivenessScheduler(
        service, interval_s=MAX_LIVENESS_PUBLISH_INTERVAL_S
    )
    shutdown = asyncio.Event()
    shutdown.set()

    await asyncio.wait_for(scheduler.serve_until(shutdown), timeout=2.0)
    assert service.published == []


class _BrokenService(_FakeService):
    def supervised_devices(self):
        raise RuntimeError("supervisor exploded")


async def test_a_failing_tick_does_not_end_the_loop(caplog) -> None:
    """An earlier revision logged once and returned forever. Every
    supervised device then expired while the runtime carried on looking
    healthy, and the test of the day asserted that as correct.

    The loop must keep trying: a transient store or supervisor failure
    that resolves itself should resume publishing without an operator.
    """
    scheduler = FirmwareLivenessScheduler(
        _BrokenService(), interval_s=MIN_LIVENESS_PUBLISH_INTERVAL_S
    )
    shutdown = asyncio.Event()
    with caplog.at_level(logging.ERROR):
        task = asyncio.create_task(scheduler.serve_until(shutdown))
        await asyncio.sleep(MIN_LIVENESS_PUBLISH_INTERVAL_S * 2.5)
        assert not task.done(), "a failing tick must not end the loop"
        assert scheduler.health()["consecutive_tick_failures"] >= 2
        shutdown.set()
        await asyncio.wait_for(task, timeout=2.0)

    assert "tick failed" in caplog.text
    assert "devices will expire if this persists" in caplog.text


async def test_a_failing_tick_is_reported_as_degraded_health() -> None:
    """The runtime otherwise looks healthy, so this is the only signal an
    operator gets that the fleet's authority is lapsing."""
    clock_value = [1000.0]
    scheduler = FirmwareLivenessScheduler(
        _BrokenService(),
        interval_s=MIN_LIVENESS_PUBLISH_INTERVAL_S,
        clock=lambda: clock_value[0],
    )
    # Never ran: not yet degraded, because it has not yet failed.
    assert scheduler.health()["degraded"] is False

    shutdown = asyncio.Event()
    task = asyncio.create_task(scheduler.serve_until(shutdown))
    await asyncio.sleep(0)
    assert scheduler.health()["running"] is True
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)

    # Stopped is degraded: a loop that is not running publishes nothing.
    health = scheduler.health()
    assert health["running"] is False
    assert health["degraded"] is True


async def test_a_loop_that_has_not_ticked_within_the_expiry_window_is_degraded() -> (
    None
):
    """Running is not the same as working. A loop whose last successful
    tick is older than the device expiry window has already let devices
    lapse, so elapsed time is what decides, not the absence of an error.
    """
    now = [1000.0]
    service = _FakeService([_device("ori-fw-a")])
    scheduler = FirmwareLivenessScheduler(service, clock=lambda: now[0])

    await scheduler.publish_once()
    scheduler._last_successful_tick_at = now[0]
    scheduler._running = True

    now[0] += LIVENESS_EXPIRY_WINDOW_S - 1
    assert scheduler.health()["degraded"] is False

    now[0] += 2
    health = scheduler.health()
    assert health["degraded"] is True
    assert health["last_successful_tick_age_s"] > LIVENESS_EXPIRY_WINDOW_S


async def test_a_recovering_tick_clears_the_failure_count() -> None:
    """A transient failure must not leave the scheduler permanently
    degraded once publishing resumes."""

    class _FlakyService(_FakeService):
        def __init__(self) -> None:
            super().__init__([_device("ori-fw-a")])
            self.explode = True

        def supervised_devices(self):
            if self.explode:
                raise RuntimeError("transient")
            return super().supervised_devices()

    service = _FlakyService()
    scheduler = FirmwareLivenessScheduler(
        service, interval_s=MIN_LIVENESS_PUBLISH_INTERVAL_S
    )
    shutdown = asyncio.Event()
    task = asyncio.create_task(scheduler.serve_until(shutdown))
    await asyncio.sleep(MIN_LIVENESS_PUBLISH_INTERVAL_S * 1.5)
    assert scheduler.health()["consecutive_tick_failures"] >= 1

    service.explode = False
    await asyncio.sleep(MIN_LIVENESS_PUBLISH_INTERVAL_S * 1.5)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)

    assert scheduler.health()["consecutive_tick_failures"] == 0
    assert service.published, "publishing must resume after recovery"


# --- Cadence and concurrency: the timing property the loop exists for ----


async def test_a_slow_device_does_not_delay_the_devices_behind_it() -> None:
    """Serial publication made the tick as long as the sum of its parts, so
    a few stalled publications pushed later devices past the expiry window.
    Concurrency is here for that bound, not for throughput.
    """
    started: list[str] = []
    release = asyncio.Event()

    class _StallingService(_FakeService):
        async def publish_runtime_liveness(
            self, *, device_id: str, boot_id: int, capability_hash: str
        ) -> bytes:
            started.append(device_id)
            if device_id == "ori-fw-slow":
                await release.wait()
            self.published.append((device_id, boot_id, capability_hash))
            return b"{}"

    service = _StallingService(
        [_device("ori-fw-slow"), _device("ori-fw-b"), _device("ori-fw-c")]
    )
    scheduler = FirmwareLivenessScheduler(service)
    tick = asyncio.create_task(scheduler.publish_once())
    await asyncio.sleep(0.05)

    # The fast devices are already published while the slow one is stalled.
    assert {"ori-fw-b", "ori-fw-c"}.issubset({row[0] for row in service.published})
    release.set()
    assert await asyncio.wait_for(tick, timeout=2.0) == 3


async def test_concurrency_is_bounded() -> None:
    """Unbounded fan-out would hand the broker the whole fleet at once."""
    in_flight = 0
    peak = 0
    release = asyncio.Event()

    class _CountingService(_FakeService):
        async def publish_runtime_liveness(self, **kwargs) -> bytes:
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            try:
                await release.wait()
            finally:
                in_flight -= 1
            return b"{}"

    service = _CountingService([_device(f"ori-fw-{i}") for i in range(20)])
    scheduler = FirmwareLivenessScheduler(service, max_concurrent=4)
    tick = asyncio.create_task(scheduler.publish_once())
    await asyncio.sleep(0.05)
    assert peak == 4, f"expected at most 4 in flight, saw {peak}"
    release.set()
    await asyncio.wait_for(tick, timeout=2.0)


async def test_a_stalled_publication_is_abandoned_not_waited_on() -> None:
    """Without a per-device timeout, one device that never completes holds
    a concurrency slot forever and its own liveness never resumes."""

    class _HangingService(_FakeService):
        async def publish_runtime_liveness(self, **kwargs) -> bytes:
            await asyncio.Event().wait()

    service = _HangingService([_device("ori-fw-a")])
    scheduler = FirmwareLivenessScheduler(service, per_device_timeout_s=0.05)
    assert await asyncio.wait_for(scheduler.publish_once(), timeout=2.0) == 0


async def test_cadence_holds_when_ticks_are_slow() -> None:
    """The defect this replaces: sleeping a full interval AFTER each tick
    made the real cadence `tick duration + interval`, so every slow tick
    pushed the next further out and devices drifted toward expiry.

    Drives the real loop in real time rather than re-deriving the deadline
    arithmetic in the test, which would only prove the test can add.
    """
    interval = MIN_LIVENESS_PUBLISH_INTERVAL_S  # 1.0s
    tick_cost = 0.6
    fired: list[float] = []

    class _SlowService(_FakeService):
        async def publish_runtime_liveness(self, **kwargs) -> bytes:
            await asyncio.sleep(tick_cost)
            return b"{}"

        def supervised_devices(self):
            fired.append(time.monotonic())
            return (_device("ori-fw-a"),)

    scheduler = FirmwareLivenessScheduler(_SlowService(), interval_s=interval)
    shutdown = asyncio.Event()
    task = asyncio.create_task(scheduler.serve_until(shutdown))
    await asyncio.sleep(interval * 3 + tick_cost + 0.3)
    shutdown.set()
    await asyncio.wait_for(task, timeout=3.0)

    assert len(fired) >= 3, f"expected at least 3 ticks, got {len(fired)}"
    gaps = [b - a for a, b in zip(fired, fired[1:])]
    # Deadline scheduling: ~1.0s apart. Sleeping after the tick would put
    # them ~1.6s apart, which is what this must be able to tell apart.
    for gap in gaps:
        assert gap < interval + (tick_cost / 2), (
            f"cadence drifted to {gap:.2f}s; deadlines are not being honoured"
        )


async def test_missed_deadlines_do_not_fire_a_catch_up_burst() -> None:
    """Only the newest message matters to a device, so replaying missed
    ticks would spend sequence numbers for nothing.

    The first tick deliberately overruns several intervals. What follows
    must be a single tick at the next future deadline, not one tick per
    deadline the overrun stepped over.
    """
    interval = MIN_LIVENESS_PUBLISH_INTERVAL_S
    tick_starts: list[float] = []
    overran = asyncio.Event()

    class _OverrunningService(_FakeService):
        def supervised_devices(self):
            tick_starts.append(time.monotonic())
            return (_device("ori-fw-a"),)

        async def publish_runtime_liveness(self, **kwargs) -> bytes:
            if not overran.is_set():
                overran.set()
                # Blow through three deadlines inside one tick.
                await asyncio.sleep(interval * 3.4)
            return b"{}"

    scheduler = FirmwareLivenessScheduler(
        _OverrunningService(),
        interval_s=interval,
        per_device_timeout_s=interval * 5,
    )
    shutdown = asyncio.Event()
    task = asyncio.create_task(scheduler.serve_until(shutdown))
    # One interval to the first tick, 3.4 for the overrun, then a little
    # over one more interval — room for exactly one further tick.
    await asyncio.sleep(interval * 5.7)
    shutdown.set()
    await asyncio.wait_for(task, timeout=3.0)

    assert len(tick_starts) == 2, (
        f"expected the overrun to be followed by one tick, got {len(tick_starts)}"
    )
    # The follow-up lands on a deadline in the future, not immediately.
    assert tick_starts[1] - tick_starts[0] >= interval * 3.4
