# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Periodic publication of signed runtime liveness to firmware devices.

Signing proves a key holder claims to be watching; this loop is what makes
the claim *continuous*. A device marks the runtime unreachable once its
expiry window passes without accepted liveness, so the timing here is a
safety property rather than a scheduling convenience: publish too slowly
and a healthy runtime looks dead to the fleet.

The loop owns no MQTT client and no signing key. It drives
:meth:`FirmwareCommandService.publish_runtime_liveness`, which refuses an
unsupervised device before spending a sequence number. Reaching past that
into the transport publisher would turn the supervision obligation into a
comment, so this module deliberately holds only the service.

What the design has to guarantee, and how:

**A per-device upper latency bound.** Ticks are scheduled against
deadlines, not by sleeping an interval after the previous tick finished —
otherwise the real cadence is ``tick duration + interval`` and drifts
further every slow tick. Devices within a tick are published concurrently
under a bounded semaphore, and each publication has its own timeout, so
one stalled broker call cannot delay the devices behind it. The resulting
bound is one interval plus one per-device timeout.

**A device that stops sending stops being told it is watched.** The
supervisor decides that, not this loop: each tick republishes for whoever
is supervised *now*, so a device that went quiet simply stops appearing.
There is no removal path to forget and no goodbye message — a claim of
absence could not be trusted from an absent party.

**Nothing fails silently.** A loop that died would leave every device
believing it is supervised until its own window expires, with the runtime
otherwise healthy. Tick failures are therefore survivable and retried, and
the scheduler reports a degraded state that the runtime health snapshot
surfaces.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from dataclasses import dataclass
from typing import Any

from ori.security.firmware.liveness import (
    LIVENESS_EXPIRY_WINDOW_S,
    LIVENESS_PUBLISH_INTERVAL_S,
    MAX_LIVENESS_PUBLISH_INTERVAL_S,
    FirmwareLivenessError,
)

logger = logging.getLogger(__name__)

__all__ = [
    "FirmwareLivenessScheduler",
    "TickResult",
    "MAX_LIVENESS_PUBLISH_INTERVAL_S",
    "MIN_LIVENESS_PUBLISH_INTERVAL_S",
]

# A floor only to stop a misconfiguration turning the fleet into a publish
# storm; the ceiling is the safety-relevant bound and is derived from the
# contract rather than chosen here.
MIN_LIVENESS_PUBLISH_INTERVAL_S = 1.0

# How many devices may be in flight at once. Concurrency exists to stop one
# slow broker call delaying the devices behind it, not to maximise
# throughput, so this stays small enough to bound broker pressure.
DEFAULT_MAX_CONCURRENT_PUBLISHES = 16


@dataclass(frozen=True)
class TickResult:
    """What one publication round actually achieved.

    ``sent`` alone cannot distinguish "nothing to do" from "nothing got
    through", and those are opposite health states.
    """

    attempted: int
    sent: int
    refused: int
    failed: int

    @property
    def delivered_nothing(self) -> bool:
        """A tick that owed publications and delivered none.

        Refusals do not count as owed: a refused device is one this runtime
        is no longer supervising, and it is supposed to lapse. What matters
        is having devices to reach and reaching none of them.
        """
        return self.failed > 0 and self.sent == 0


def _within_expiry_window(elapsed_s: float) -> bool:
    """Whether a device is still reachable after ``elapsed_s``.

    The contract says a device treats the runtime as reachable while the
    elapsed time since its last accepted liveness is UNDER the expiry
    window. Equality is therefore already expired, not the last moment of
    reachability. The rule lives here because it was written four times
    and got the boundary wrong in three of them.
    """
    return elapsed_s < LIVENESS_EXPIRY_WINDOW_S


def _validate_interval(interval_s: Any) -> float:
    """The interval is a safety parameter, so it is checked rather than
    trusted. Above the ceiling a single dropped message expires a device;
    NaN would make every deadline comparison false and silently stop the
    loop publishing at all.
    """
    if isinstance(interval_s, bool) or not isinstance(interval_s, (int, float)):
        raise ValueError(f"liveness interval must be a number: {interval_s!r}")
    if not math.isfinite(interval_s):
        raise ValueError(f"liveness interval must be finite: {interval_s!r}")
    if interval_s < MIN_LIVENESS_PUBLISH_INTERVAL_S:
        raise ValueError(
            f"liveness interval must be at least "
            f"{MIN_LIVENESS_PUBLISH_INTERVAL_S}s: {interval_s!r}"
        )
    if interval_s > MAX_LIVENESS_PUBLISH_INTERVAL_S:
        raise ValueError(
            f"liveness interval must be at most {MAX_LIVENESS_PUBLISH_INTERVAL_S}s "
            f"so the device's {LIVENESS_EXPIRY_WINDOW_S}s expiry window stays at "
            f"least 3x the interval: {interval_s!r}"
        )
    return float(interval_s)


class FirmwareLivenessScheduler:
    """Republish liveness for every currently supervised device."""

    def __init__(
        self,
        service: Any,
        *,
        interval_s: float = LIVENESS_PUBLISH_INTERVAL_S,
        per_device_timeout_s: float | None = None,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT_PUBLISHES,
        clock: Any = time.monotonic,
    ) -> None:
        if not hasattr(service, "supervised_devices") or not hasattr(
            service, "publish_runtime_liveness"
        ):
            raise TypeError(
                "liveness scheduler requires the FirmwareCommandService API, "
                "not the transport publisher: publishing must go through the "
                "supervision check"
            )
        self._interval_s = _validate_interval(interval_s)
        # Defaults to one interval: a publication that has not completed by
        # the time the next tick is due has already lost its slot, and
        # holding the semaphore longer only delays other devices.
        timeout = (
            self._interval_s if per_device_timeout_s is None else per_device_timeout_s
        )
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError(
                f"per-device publish timeout must be positive and finite: "
                f"{per_device_timeout_s!r}"
            )
        self._per_device_timeout_s = float(timeout)
        # Positivity is not the safety property. A timeout that leaves no
        # room inside the expiry window means even a single device, in a
        # single batch, can exceed the window this scheduler exists to keep
        # it inside — the class would be claiming a bound it cannot hold at
        # any fleet size.
        if not _within_expiry_window(self._interval_s + self._per_device_timeout_s):
            raise ValueError(
                f"interval {self._interval_s}s plus per-device timeout "
                f"{self._per_device_timeout_s}s must stay under the device's "
                f"{LIVENESS_EXPIRY_WINDOW_S}s expiry window; one slow publication "
                f"would otherwise expire the device it was for"
            )
        if isinstance(max_concurrent, bool) or not isinstance(max_concurrent, int):
            raise ValueError(f"max_concurrent must be an int: {max_concurrent!r}")
        if max_concurrent < 1:
            raise ValueError(f"max_concurrent must be at least 1: {max_concurrent!r}")
        self._max_concurrent = max_concurrent
        self._service = service
        self._clock = clock

        self._started = False
        self._running = False
        self._stopped_cleanly = False
        self._consecutive_tick_failures = 0
        self._last_successful_tick_at: float | None = None
        self._last_tick_error: str = ""
        # device_id -> monotonic time of its last successful publication.
        self._last_device_success: dict[str, float] = {}

    @property
    def interval_s(self) -> float:
        return self._interval_s

    @property
    def per_device_timeout_s(self) -> float:
        return self._per_device_timeout_s

    def max_device_publish_latency_s(self, device_count: int) -> float:
        """Worst-case wait between publications for one device, at a given
        fleet size.

        Stated as a function of ``device_count`` because a constant is a
        false claim: publication is bounded by a semaphore, so devices past
        the first ``max_concurrent`` wait for the batches ahead of them,
        and each of those batches can take the full per-device timeout
        before it gives up. With 64 devices at the defaults the last batch
        starts around 45s in — already at the expiry window before its own
        timeout begins.
        """
        if device_count <= 0:
            return self._interval_s
        batches = math.ceil(device_count / self._max_concurrent)
        return self._interval_s + batches * self._per_device_timeout_s

    @property
    def supported_device_capacity(self) -> int:
        """How many supervised devices this configuration can carry while
        still guaranteeing every one of them stays inside the expiry
        window, even if every publication times out.

        Beyond this the scheduler is still correct but no longer bounded,
        which is a capacity condition an operator has to be told about
        rather than something to discover from expiring devices.
        """
        budget = LIVENESS_EXPIRY_WINDOW_S - self._interval_s
        batches = math.floor(budget / self._per_device_timeout_s)
        # floor() admits the batch whose worst case lands exactly on the
        # window, which is already expired. Step back to the last batch
        # count that is strictly inside, using the same arithmetic the
        # bound itself reports so the two can never disagree.
        while batches > 0 and not _within_expiry_window(
            self._interval_s + batches * self._per_device_timeout_s
        ):
            batches -= 1
        return max(0, batches) * self._max_concurrent

    # -- health ----------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """State the runtime health snapshot surfaces.

        ``degraded`` is the load-bearing field. A scheduler that has
        stopped, or that has not completed a tick within the device expiry
        window, is one whose devices are expiring while the rest of the
        runtime looks healthy — the failure this reporting exists to make
        impossible to miss.
        """
        now = self._clock()
        last = self._last_successful_tick_at
        age = None if last is None else max(0.0, now - last)
        stale = age is not None and not _within_expiry_window(age)
        # A scheduler that has never been started owes nothing yet, so it is
        # not degraded — otherwise every runtime would report degraded for
        # the window between building the stack and starting the loop. Once
        # started, though, not running IS the P1 failure: the task ended
        # while the runtime carried on.
        # An orderly shutdown is not a fault. What must never pass as
        # healthy is a loop that ended any other way — that is the task
        # dying while the runtime carries on.
        stopped_after_starting = (
            self._started and not self._running and not self._stopped_cleanly
        )

        # Devices still supervised whose last successful publication is
        # older than the expiry window. Without this a single device
        # failing forever is invisible: the fleet-wide counters stay clean
        # because every other device is fine, and that one device sits
        # unsupervised with its backstop re-enabled.
        expiring = sorted(
            device_id
            for device_id, at in self._last_device_success.items()
            if not _within_expiry_window(now - at)
        )

        supervised_count = len(self._last_device_success)
        capacity = self.supported_device_capacity
        over_capacity = supervised_count > capacity

        return {
            "running": self._running,
            "started": self._started,
            "interval_s": self._interval_s,
            "per_device_timeout_s": self._per_device_timeout_s,
            "max_concurrent": self._max_concurrent,
            "supervised_devices": supervised_count,
            "supported_device_capacity": capacity,
            "over_capacity": over_capacity,
            "worst_case_device_latency_s": self.max_device_publish_latency_s(
                supervised_count
            ),
            "consecutive_tick_failures": self._consecutive_tick_failures,
            "last_successful_tick_age_s": age,
            "expiring_device_ids": expiring,
            "last_error": self._last_tick_error,
            "degraded": bool(
                stopped_after_starting
                or stale
                or self._consecutive_tick_failures
                or expiring
                or over_capacity
            ),
        }

    # -- publishing ------------------------------------------------------

    async def _publish_one(self, device: Any) -> str:
        """Returns the outcome, not merely success.

        A refusal and a delivery failure look identical to a counter and
        are opposites in meaning: a refusal is the supervision rule working
        and the device SHOULD lapse, while a delivery failure is this
        runtime failing to say something it still owes.
        """
        try:
            await asyncio.wait_for(
                self._service.publish_runtime_liveness(
                    device_id=device.device_id,
                    boot_id=device.boot_id,
                    capability_hash=device.capability_hash,
                ),
                timeout=self._per_device_timeout_s,
            )
        except FirmwareLivenessError:
            # Supervision ended between the snapshot and the signature, or
            # the counter is exhausted. Refusing is the mechanism working:
            # this runtime must not claim to watch a device it is no longer
            # receiving from.
            logger.debug(
                "[firmware-liveness] declined to publish for %s",
                device.device_id,
                exc_info=True,
            )
            return "refused"
        except asyncio.CancelledError:
            # Redundant today — CancelledError derives from BaseException,
            # so the clause below never sees it. Kept explicit because that
            # is the only thing making the containment below safe: widened
            # to BaseException, this would swallow its own shutdown.
            raise
        except TimeoutError:
            # Abandoned rather than waited on. The slot is already lost and
            # holding the semaphore only delays other devices.
            logger.warning(
                "[firmware-liveness] publish for %s exceeded %.1fs and was abandoned",
                device.device_id,
                self._per_device_timeout_s,
            )
            return "failed"
        except Exception:
            # Contained on purpose. A broker refusing one device's topic
            # must not stop the others from being told they are watched.
            logger.warning(
                "[firmware-liveness] publish failed for %s",
                device.device_id,
                exc_info=True,
            )
            return "failed"
        return "sent"

    async def publish_once(self) -> TickResult:
        """Publish for every supervised device and report what happened.

        Returns the outcome rather than a bare count. A tick that reached
        no device is not a successful tick, and a count cannot express the
        difference: every publication failing produces the same "zero sent"
        as an empty fleet, which would let the loop record a healthy tick
        while the whole fleet expired.

        Raises only if the supervisor snapshot itself fails; per-device
        failures are contained. The snapshot is taken once, so a device
        expiring mid-tick is handled by the signer's own refusal rather
        than by re-reading a moving map.
        """
        devices = tuple(self._service.supervised_devices())
        if not devices:
            self._last_device_success.clear()
            return TickResult(attempted=0, sent=0, refused=0, failed=0)

        started = self._clock()
        semaphore = asyncio.Semaphore(self._max_concurrent)

        async def _guarded(device: Any) -> str:
            async with semaphore:
                return await self._publish_one(device)

        outcomes = await asyncio.gather(*(_guarded(d) for d in devices))
        result = TickResult(
            attempted=len(devices),
            sent=sum(1 for o in outcomes if o == "sent"),
            refused=sum(1 for o in outcomes if o == "refused"),
            failed=sum(1 for o in outcomes if o == "failed"),
        )

        # Per-device success times, so a single device failing forever is
        # visible instead of being averaged away by a mostly-healthy fleet.
        now = self._clock()
        supervised_ids = set()
        for device, outcome in zip(devices, outcomes):
            supervised_ids.add(device.device_id)
            if outcome == "sent":
                self._last_device_success[device.device_id] = now
            elif outcome == "refused":
                # No longer supervised, so it is meant to lapse. Keeping it
                # would report a correctly-expiring device as a failure.
                self._last_device_success.pop(device.device_id, None)
                supervised_ids.discard(device.device_id)
            elif device.device_id not in self._last_device_success:
                # Never delivered to. Count from now so it becomes visible
                # after one expiry window rather than immediately.
                self._last_device_success[device.device_id] = now
        for known in tuple(self._last_device_success):
            if known not in supervised_ids:
                self._last_device_success.pop(known, None)

        elapsed = now - started
        if elapsed > self._interval_s:
            # Deadline scheduling absorbs this without drifting, but it
            # still means the fleet no longer fits in one interval and
            # devices are closer to expiry than configured.
            logger.warning(
                "[firmware-liveness] tick took %.1fs for %d device(s), "
                "longer than the %.1fs interval; devices may expire",
                elapsed,
                len(devices),
                self._interval_s,
            )
        if result.failed:
            logger.warning(
                "[firmware-liveness] %d of %d publication(s) failed this tick",
                result.failed,
                result.attempted,
            )
        return result

    # -- loop ------------------------------------------------------------

    async def _wait_or_shutdown(
        self, shutdown_event: asyncio.Event, delay: float
    ) -> bool:
        """Wait until the next deadline, or until shutdown. True if
        shutdown won.

        A named seam rather than an inline ``wait_for`` so the loop's
        deadline arithmetic can be driven on a virtual clock. Timing tests
        that sleep in real time are the flaky kind: they pass alone and
        fail under load, which trains everyone to re-run them.
        """
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=delay)
            return True
        except TimeoutError:
            # The deadline arrived before shutdown did, which is the normal
            # path: this wait IS the interval timer, so a timeout means
            # "publish now" rather than an error.
            return False

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        """Publish on interval deadlines until shutdown.

        No publish happens at startup: nothing is supervised until accepted
        telemetry arrives, so an immediate tick would find an empty map.

        A failing tick does not end the loop. Ending it would leave every
        device expiring while the runtime looked healthy, and the interval
        ceiling means there is no backoff longer than one interval that
        would not itself expire devices — so the retry cadence stays the
        publication cadence and the failure is reported instead.
        """
        logger.info(
            "[firmware-liveness] publishing every %.1fs to supervised devices "
            "(per-device timeout %.1fs, up to %d concurrent, bounded for up to "
            "%d device(s))",
            self._interval_s,
            self._per_device_timeout_s,
            self._max_concurrent,
            self.supported_device_capacity,
        )
        self._started = True
        self._running = True
        self._stopped_cleanly = False
        next_deadline = self._clock() + self._interval_s
        try:
            while not shutdown_event.is_set():
                delay = max(0.0, next_deadline - self._clock())
                if await self._wait_or_shutdown(shutdown_event, delay):
                    break

                try:
                    result = await self.publish_once()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self._consecutive_tick_failures += 1
                    self._last_tick_error = f"{type(exc).__name__}: {exc}"
                    logger.exception(
                        "[firmware-liveness] tick failed (%d consecutive); "
                        "devices will expire if this persists",
                        self._consecutive_tick_failures,
                    )
                else:
                    # Completing is not succeeding. A tick where every
                    # publication was rejected or timed out reaches no
                    # device, so recording it as a success would keep
                    # health green while the whole fleet expires — which is
                    # exactly what a broker outage looks like.
                    if result.delivered_nothing:
                        self._consecutive_tick_failures += 1
                        self._last_tick_error = (
                            f"delivered 0 of {result.attempted} publication(s)"
                        )
                        logger.error(
                            "[firmware-liveness] tick reached none of %d device(s) "
                            "(%d consecutive); they will expire if this persists",
                            result.attempted,
                            self._consecutive_tick_failures,
                        )
                    else:
                        self._consecutive_tick_failures = 0
                        self._last_tick_error = ""
                        self._last_successful_tick_at = self._clock()

                # Advance to the next deadline strictly in the future,
                # skipping whole intervals. Catching up by firing a burst
                # of missed ticks would spend sequence numbers to no
                # benefit: only the newest message matters to a device.
                now = self._clock()
                while next_deadline <= now:
                    next_deadline += self._interval_s
        finally:
            # Recorded even on cancellation, so health never reports a
            # running loop that has stopped. Cancellation counts as an
            # orderly stop: it is how the runtime tears its tasks down.
            self._running = False
            self._stopped_cleanly = shutdown_event.is_set()
