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
from typing import Any

from ori.security.firmware_liveness import (
    LIVENESS_EXPIRY_WINDOW_S,
    LIVENESS_PUBLISH_INTERVAL_S,
    MAX_LIVENESS_PUBLISH_INTERVAL_S,
    FirmwareLivenessError,
)

logger = logging.getLogger(__name__)

__all__ = [
    "FirmwareLivenessScheduler",
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
        if isinstance(max_concurrent, bool) or not isinstance(max_concurrent, int):
            raise ValueError(f"max_concurrent must be an int: {max_concurrent!r}")
        if max_concurrent < 1:
            raise ValueError(f"max_concurrent must be at least 1: {max_concurrent!r}")
        self._max_concurrent = max_concurrent
        self._service = service
        self._clock = clock

        self._started = False
        self._running = False
        self._consecutive_tick_failures = 0
        self._last_successful_tick_at: float | None = None
        self._last_tick_error: str = ""

    @property
    def interval_s(self) -> float:
        return self._interval_s

    @property
    def per_device_timeout_s(self) -> float:
        return self._per_device_timeout_s

    @property
    def max_device_publish_latency_s(self) -> float:
        """The bound this scheduler is built to provide.

        Worst case a supervised device waits between publications: one full
        interval before its tick is due, plus the longest a single
        publication may take before it is abandoned. Kept below the
        device's expiry window so a bounded-but-slow tick still cannot
        expire a device.
        """
        return self._interval_s + self._per_device_timeout_s

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
        stale = age is not None and age > LIVENESS_EXPIRY_WINDOW_S
        # A scheduler that has never been started owes nothing yet, so it is
        # not degraded — otherwise every runtime would report degraded for
        # the window between building the stack and starting the loop. Once
        # started, though, not running IS the P1 failure: the task ended
        # while the runtime carried on.
        stopped_after_starting = self._started and not self._running
        return {
            "running": self._running,
            "started": self._started,
            "interval_s": self._interval_s,
            "per_device_timeout_s": self._per_device_timeout_s,
            "max_device_publish_latency_s": self.max_device_publish_latency_s,
            "consecutive_tick_failures": self._consecutive_tick_failures,
            "last_successful_tick_age_s": age,
            "last_error": self._last_tick_error,
            "degraded": stopped_after_starting or stale,
        }

    # -- publishing ------------------------------------------------------

    async def _publish_one(self, device: Any) -> bool:
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
            return False
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
            return False
        except Exception:
            # Contained on purpose. A broker refusing one device's topic
            # must not stop the others from being told they are watched.
            logger.warning(
                "[firmware-liveness] publish failed for %s",
                device.device_id,
                exc_info=True,
            )
            return False
        return True

    async def publish_once(self) -> int:
        """Publish for every supervised device. Returns the number sent.

        Raises only if the supervisor snapshot itself fails; per-device
        failures are contained. The snapshot is taken once, so a device
        expiring mid-tick is handled by the signer's own refusal rather
        than by re-reading a moving map.
        """
        devices = tuple(self._service.supervised_devices())
        if not devices:
            return 0

        started = self._clock()
        semaphore = asyncio.Semaphore(self._max_concurrent)

        async def _guarded(device: Any) -> bool:
            async with semaphore:
                return await self._publish_one(device)

        results = await asyncio.gather(*(_guarded(d) for d in devices))
        sent = sum(1 for ok in results if ok)

        elapsed = self._clock() - started
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
        return sent

    # -- loop ------------------------------------------------------------

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
            "(per-device timeout %.1fs, worst-case device latency %.1fs)",
            self._interval_s,
            self._per_device_timeout_s,
            self.max_device_publish_latency_s,
        )
        self._started = True
        self._running = True
        next_deadline = self._clock() + self._interval_s
        try:
            while not shutdown_event.is_set():
                delay = max(0.0, next_deadline - self._clock())
                try:
                    await asyncio.wait_for(shutdown_event.wait(), timeout=delay)
                    break
                except TimeoutError:
                    pass

                try:
                    await self.publish_once()
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
            # running loop that has stopped.
            self._running = False
