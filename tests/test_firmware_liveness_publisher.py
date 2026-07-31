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


class _VirtualClock:
    """Elapsed time the test controls exactly.

    The loop's own waits are what advance it, so tick timing is decided by
    the scheduler's deadline arithmetic rather than by how loaded the
    machine is. Real-time timing tests pass alone and fail in a full suite,
    which is the flakiness that teaches people to re-run rather than read.
    """

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class _VirtualScheduler(FirmwareLivenessScheduler):
    """Real scheduler, virtual waits.

    Overrides only the wait seam, so the deadline arithmetic under test is
    the production code path.
    """

    def __init__(self, *args, vclock: _VirtualClock, max_waits: int = 50, **kwargs):
        super().__init__(*args, clock=vclock, **kwargs)
        self._vclock = vclock
        self._max_waits = max_waits
        self.waits: list[float] = []

    async def _wait_or_shutdown(self, shutdown_event, delay: float) -> bool:
        if len(self.waits) >= self._max_waits:
            # Model an orderly shutdown rather than an unexplained exit, so
            # tests that end the loop do not read as the task dying.
            shutdown_event.set()
        if shutdown_event.is_set():
            return True
        self.waits.append(delay)
        self._vclock.now += delay
        await asyncio.sleep(0)
        return False


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

    assert (await scheduler.publish_once()).sent == 2
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
    assert (await FirmwareLivenessScheduler(service).publish_once()).sent == 0
    assert service.published == []


async def test_a_refusal_mid_tick_does_not_stop_the_others() -> None:
    """Supervision can end between the snapshot and the signature. The
    signer refusing is the mechanism working, not an error."""
    service = _FakeService(
        [_device("ori-fw-a"), _device("ori-fw-b"), _device("ori-fw-c")],
        fail={"ori-fw-b": FirmwareLivenessError("not supervised")},
    )
    assert (await FirmwareLivenessScheduler(service).publish_once()).sent == 2
    assert [row[0] for row in service.published] == ["ori-fw-a", "ori-fw-c"]


async def test_a_publish_failure_does_not_silence_the_fleet() -> None:
    """One device whose topic the broker refuses must not stop the others
    from being told they are watched — that would let a single broken
    device suppress the backstop signal fleet-wide."""
    service = _FakeService(
        [_device("ori-fw-a"), _device("ori-fw-b"), _device("ori-fw-c")],
        fail={"ori-fw-a": RuntimeError("broker refused")},
    )
    assert (await FirmwareLivenessScheduler(service).publish_once()).sent == 2
    assert [row[0] for row in service.published] == ["ori-fw-b", "ori-fw-c"]


async def test_publish_once_never_raises_for_a_single_device() -> None:
    service = _FakeService(
        [_device("ori-fw-a")], fail={"ori-fw-a": RuntimeError("boom")}
    )
    assert (await FirmwareLivenessScheduler(service).publish_once()).sent == 0


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


def test_the_latency_bound_accounts_for_semaphore_batching() -> None:
    """An earlier revision claimed a constant `interval + timeout`. That is
    false the moment the fleet exceeds `max_concurrent`: devices in later
    batches wait for the batches ahead of them, each of which can take the
    full timeout before giving up.
    """
    scheduler = FirmwareLivenessScheduler(
        _FakeService(), interval_s=15.0, per_device_timeout_s=15.0, max_concurrent=16
    )
    # Within one batch the old claim happens to hold.
    assert scheduler.max_device_publish_latency_s(1) == 30.0
    assert scheduler.max_device_publish_latency_s(16) == 30.0
    # Beyond it, the bound grows per batch — the case the old claim missed.
    assert scheduler.max_device_publish_latency_s(17) == 45.0
    assert scheduler.max_device_publish_latency_s(64) == 75.0
    # 64 stalled devices exceed the 60s expiry window, exactly as reported.
    assert scheduler.max_device_publish_latency_s(64) > LIVENESS_EXPIRY_WINDOW_S


def test_capacity_is_the_fleet_size_the_bound_actually_holds_for() -> None:
    """The scheduler stays correct past this, but stops being bounded — a
    capacity condition an operator must be told, not discover from
    expiring devices."""
    scheduler = FirmwareLivenessScheduler(
        _FakeService(), interval_s=15.0, per_device_timeout_s=15.0, max_concurrent=16
    )
    # 60s expiry - 15s interval = 45s budget = 3 batches of 16.
    assert scheduler.supported_device_capacity == 48
    assert scheduler.max_device_publish_latency_s(48) <= LIVENESS_EXPIRY_WINDOW_S
    assert scheduler.max_device_publish_latency_s(49) > LIVENESS_EXPIRY_WINDOW_S


def test_defaults_are_bounded_for_a_single_batch() -> None:
    scheduler = FirmwareLivenessScheduler(_FakeService())
    assert scheduler.max_device_publish_latency_s(1) < LIVENESS_EXPIRY_WINDOW_S
    assert scheduler.supported_device_capacity >= scheduler._max_concurrent


@pytest.mark.parametrize("timeout", [45.0, 60.0, 600.0])
def test_a_timeout_that_cannot_fit_the_expiry_window_is_refused(timeout) -> None:
    """Positivity was never the safety property. With a 15s interval a 45s
    timeout means one slow publication expires the device it was for."""
    with pytest.raises(ValueError, match="expiry window"):
        FirmwareLivenessScheduler(_FakeService(), per_device_timeout_s=timeout)


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
    vclock = _VirtualClock()
    scheduler = _VirtualScheduler(_BrokenService(), vclock=vclock, max_waits=3)
    with caplog.at_level(logging.ERROR):
        await asyncio.wait_for(scheduler.serve_until(asyncio.Event()), timeout=5.0)
        assert scheduler.health()["consecutive_tick_failures"] == 3, (
            "every failing tick must be counted, and the loop must reach them all"
        )

    assert "tick failed" in caplog.text
    assert "devices will expire if this persists" in caplog.text


async def test_a_scheduler_that_has_never_run_is_not_degraded() -> None:
    """Otherwise every runtime reports degraded for the window between
    building the stack and starting the loop, and an alarm that is always
    on is an alarm nobody reads."""
    scheduler = FirmwareLivenessScheduler(_BrokenService())
    health = scheduler.health()
    assert health["started"] is False
    assert health["degraded"] is False


async def test_an_orderly_shutdown_is_not_degraded() -> None:
    """The runtime stops its own tasks on the way down; reporting that as
    a fault would make shutdown look like failure every time."""
    vclock = _VirtualClock()
    scheduler = _VirtualScheduler(_FakeService([]), vclock=vclock, max_waits=1)
    await asyncio.wait_for(scheduler.serve_until(asyncio.Event()), timeout=5.0)
    health = scheduler.health()
    assert health["running"] is False
    assert health["degraded"] is False


async def test_a_loop_that_ends_without_shutdown_is_degraded() -> None:
    """The P1 this exists for: the task ends, the runtime carries on, and
    every supervised device expires with nothing reporting it. Ending
    without the shutdown event is exactly that case."""
    vclock = _VirtualClock()

    class _SelfEndingScheduler(_VirtualScheduler):
        async def _wait_or_shutdown(self, shutdown_event, delay: float) -> bool:
            # Ends the loop WITHOUT shutdown being requested.
            return True

    scheduler = _SelfEndingScheduler(_FakeService([]), vclock=vclock)
    await asyncio.wait_for(scheduler.serve_until(asyncio.Event()), timeout=5.0)

    health = scheduler.health()
    assert health["running"] is False
    assert health["started"] is True
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
    vclock = _VirtualClock()

    class _RecoveringScheduler(_VirtualScheduler):
        async def _wait_or_shutdown(self, shutdown_event, delay):
            # Stop exploding after the first failed tick.
            if self.waits:
                service.explode = False
            return await super()._wait_or_shutdown(shutdown_event, delay)

    scheduler = _RecoveringScheduler(service, vclock=vclock, max_waits=3)
    await asyncio.wait_for(scheduler.serve_until(asyncio.Event()), timeout=5.0)

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
    assert (await asyncio.wait_for(tick, timeout=2.0)).sent == 3


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
    assert (await asyncio.wait_for(scheduler.publish_once(), timeout=2.0)).sent == 0


async def test_cadence_holds_when_ticks_are_slow() -> None:
    """The defect this replaces: sleeping a full interval AFTER each tick
    made the real cadence `tick duration + interval`, so every slow tick
    pushed the next further out and devices drifted toward expiry.

    Exercises the production deadline arithmetic on a virtual clock, so the
    assertion is exact rather than a tolerance around wall-clock noise.
    """
    vclock = _VirtualClock()
    fired: list[float] = []

    class _SlowService(_FakeService):
        def supervised_devices(self):
            fired.append(vclock.now)
            # The tick itself costs most of an interval.
            vclock.now += 4.0
            return ()

    scheduler = _VirtualScheduler(
        _SlowService(), interval_s=5.0, vclock=vclock, max_waits=4
    )
    await asyncio.wait_for(scheduler.serve_until(asyncio.Event()), timeout=5.0)

    # Ticks land on interval boundaries. Sleeping after the tick would put
    # them 9s apart (5 + 4), which is what this distinguishes.
    assert fired == [5.0, 10.0, 15.0, 20.0]


async def test_missed_deadlines_do_not_fire_a_catch_up_burst() -> None:
    """Only the newest message matters to a device, so replaying missed
    ticks would spend sequence numbers for nothing. A tick that overruns
    several deadlines is followed by one tick at the next future slot."""
    vclock = _VirtualClock()
    fired: list[float] = []

    class _OverrunOnceService(_FakeService):
        def __init__(self) -> None:
            super().__init__(())
            self.overran = False

        def supervised_devices(self):
            fired.append(vclock.now)
            if not self.overran:
                self.overran = True
                # Blow through three further deadlines inside one tick.
                vclock.now += 17.0
            return ()

    scheduler = _VirtualScheduler(
        _OverrunOnceService(), interval_s=5.0, vclock=vclock, max_waits=3
    )
    await asyncio.wait_for(scheduler.serve_until(asyncio.Event()), timeout=5.0)

    # First tick at 5s, overruns to 22s. Deadlines at 10/15/20 are skipped
    # rather than replayed, so the next tick is at 25s, not four in a row.
    assert fired == [5.0, 25.0, 30.0]


# --- Delivering nothing is not a healthy tick ----------------------------


class _AllFailingService(_FakeService):
    async def publish_runtime_liveness(self, **kwargs) -> bytes:
        raise RuntimeError("broker rejected")


async def test_a_tick_that_reaches_no_device_is_a_failed_tick() -> None:
    """The defect this closes: every publication failing produced the same
    'zero sent' as an empty fleet, so the loop recorded a healthy tick,
    cleared the failure count, and advanced the last-success time while the
    entire fleet expired. A broker outage looked exactly like health.
    """
    service = _AllFailingService([_device("ori-fw-a"), _device("ori-fw-b")])
    vclock = _VirtualClock()
    scheduler = _VirtualScheduler(service, vclock=vclock, max_waits=2)
    await asyncio.wait_for(scheduler.serve_until(asyncio.Event()), timeout=5.0)
    health = scheduler.health()

    assert health["consecutive_tick_failures"] == 2
    assert health["last_successful_tick_age_s"] is None
    assert health["degraded"] is True
    assert "delivered 0 of 2" in health["last_error"]


async def test_an_empty_fleet_is_not_a_failed_tick() -> None:
    """Nothing supervised is nothing owed. Treating it as failure would
    make every runtime degraded before its first device is provisioned."""
    vclock = _VirtualClock()
    scheduler = _VirtualScheduler(_FakeService([]), vclock=vclock, max_waits=3)
    await asyncio.wait_for(scheduler.serve_until(asyncio.Event()), timeout=5.0)
    health = scheduler.health()

    assert health["consecutive_tick_failures"] == 0
    assert health["degraded"] is False


async def test_a_tick_of_pure_refusals_is_not_a_failure() -> None:
    """A refused device is one this runtime is no longer supervising, so it
    is meant to lapse. Counting that as a delivery failure would report the
    supervision rule working as an outage."""
    service = _FakeService(
        [_device("ori-fw-a")],
        fail={"ori-fw-a": FirmwareLivenessError("not supervised")},
    )
    scheduler = FirmwareLivenessScheduler(service)
    result = await scheduler.publish_once()
    assert result.refused == 1 and result.failed == 0
    assert result.delivered_nothing is False


async def test_a_partial_failure_still_records_a_successful_tick() -> None:
    """Some devices were reached, so the loop is working; the failure is
    visible per device rather than as a tick-level outage."""
    service = _FakeService(
        [_device("ori-fw-a"), _device("ori-fw-b")],
        fail={"ori-fw-a": RuntimeError("broker refused")},
    )
    result = await FirmwareLivenessScheduler(service).publish_once()
    assert result.sent == 1 and result.failed == 1
    assert result.delivered_nothing is False


async def test_one_device_failing_forever_is_visible() -> None:
    """The counters stay clean because every other device is fine, so
    without per-device tracking this device sits unsupervised, backstop
    re-enabled, and nothing reports it."""
    now = [1000.0]
    service = _FakeService(
        [_device("ori-fw-a"), _device("ori-fw-b")],
        fail={"ori-fw-a": RuntimeError("broker refused")},
    )
    scheduler = FirmwareLivenessScheduler(service, clock=lambda: now[0])

    await scheduler.publish_once()
    assert scheduler.health()["expiring_device_ids"] == []

    now[0] += LIVENESS_EXPIRY_WINDOW_S + 1
    await scheduler.publish_once()
    health = scheduler.health()
    assert health["expiring_device_ids"] == ["ori-fw-a"]
    assert health["degraded"] is True


async def test_a_device_that_stops_being_supervised_is_not_reported_expiring() -> None:
    """It is supposed to lapse. Reporting it would make correct behaviour
    look like a fault and train operators to ignore the signal."""
    now = [1000.0]
    service = _FakeService([_device("ori-fw-a")])
    scheduler = FirmwareLivenessScheduler(service, clock=lambda: now[0])
    await scheduler.publish_once()

    service.set_devices([])
    now[0] += LIVENESS_EXPIRY_WINDOW_S + 1
    await scheduler.publish_once()

    health = scheduler.health()
    assert health["expiring_device_ids"] == []
    assert health["degraded"] is False


def test_a_fleet_beyond_capacity_is_reported() -> None:
    """Past capacity the scheduler is still correct but no longer bounded,
    which the operator has to learn from health rather than from devices
    dropping out."""
    scheduler = FirmwareLivenessScheduler(
        _FakeService(), interval_s=15.0, per_device_timeout_s=15.0, max_concurrent=16
    )
    scheduler._started = True
    scheduler._running = True
    scheduler._last_device_success = {f"d{i}": 0.0 for i in range(49)}
    scheduler._clock = lambda: 0.0

    health = scheduler.health()
    assert health["supervised_devices"] == 49
    assert health["supported_device_capacity"] == 48
    assert health["over_capacity"] is True
    assert health["degraded"] is True


async def test_the_startup_log_line_formats(caplog) -> None:
    """A regression test for a real crash, not a style check.

    The startup line interpolates the scheduler's own configuration. When
    `max_device_publish_latency_s` became a method taking a device count,
    the call site kept passing the bound method to a `%.1f`, which raises
    while formatting and kills the loop on its first statement. Focused
    runs missed it because nothing formatted INFO records.
    """
    vclock = _VirtualClock()
    scheduler = _VirtualScheduler(_FakeService([]), vclock=vclock, max_waits=1)
    with caplog.at_level(logging.INFO):
        await asyncio.wait_for(scheduler.serve_until(asyncio.Event()), timeout=5.0)

    line = next(r for r in caplog.records if "publishing every" in r.getMessage())
    # getMessage() is what raised; asserting on the rendered text is what
    # makes this test able to fail.
    assert "%" not in line.getMessage()
    assert f"{scheduler.supported_device_capacity} device(s)" in line.getMessage()
