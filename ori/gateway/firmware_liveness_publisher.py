# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Periodic publication of signed runtime liveness to firmware devices.

Signing proves a key holder claims to be watching; this loop is what makes
the claim *continuous*. A device treats silence as the end of supervision
and re-enables its Local Interlock, so the interval is a safety parameter:
publish too slowly and a healthy runtime looks dead to the fleet.

The loop owns no MQTT client and no signing key. It drives
:meth:`FirmwareCommandService.publish_runtime_liveness`, which refuses an
unsupervised device before spending a sequence number. Reaching past that
into the transport publisher would turn the supervision obligation into a
comment, so this module deliberately holds only the service.

Two properties matter more than the timer.

**A device that stops sending must stop being told it is watched.** The
supervisor decides that, not this loop: each tick republishes for whoever
is supervised *now*, so a device that went quiet simply stops appearing.
There is no removal path to forget, and no goodbye message — a claim of
absence could not be trusted from an absent party.

**One device must not be able to silence the fleet.** A publish failure,
an expiry mid-tick, or an exhausted counter is contained to that device.
Anything else would let a single broken device suppress the backstop
suppression signal for every other device, which is the failure this
whole mechanism exists to prevent.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from ori.security.firmware_liveness import (
    LIVENESS_PUBLISH_INTERVAL_S,
    FirmwareLivenessError,
)

logger = logging.getLogger(__name__)

__all__ = ["FirmwareLivenessScheduler"]

# A publish interval at or above the device's expiry window guarantees the
# device expires; well below it, a lost message is survivable because the
# next one arrives in time. The supervision window is the runtime-side
# bound and is deliberately shorter than the device's, so a device learns
# of lost supervision through silence rather than racing this runtime to
# the same deadline.
MIN_LIVENESS_PUBLISH_INTERVAL_S = 1.0


class FirmwareLivenessScheduler:
    """Republish liveness for every currently supervised device."""

    def __init__(
        self,
        service: Any,
        *,
        interval_s: float = LIVENESS_PUBLISH_INTERVAL_S,
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
        if not isinstance(interval_s, (int, float)) or isinstance(interval_s, bool):
            raise ValueError(f"liveness interval must be a number: {interval_s!r}")
        if interval_s < MIN_LIVENESS_PUBLISH_INTERVAL_S:
            raise ValueError(
                f"liveness interval must be at least "
                f"{MIN_LIVENESS_PUBLISH_INTERVAL_S}s: {interval_s!r}"
            )
        self._service = service
        self._interval_s = float(interval_s)
        self._clock = clock

    @property
    def interval_s(self) -> float:
        return self._interval_s

    async def publish_once(self) -> int:
        """Publish for every supervised device. Returns the number sent.

        Never raises for a single device. The snapshot is taken once so a
        device expiring mid-tick is handled by the signer's own refusal
        rather than by re-reading a moving map.
        """
        devices = self._service.supervised_devices()
        started = self._clock()
        sent = 0
        for device in devices:
            try:
                await self._service.publish_runtime_liveness(
                    device_id=device.device_id,
                    boot_id=device.boot_id,
                    capability_hash=device.capability_hash,
                )
            except FirmwareLivenessError:
                # Supervision ended between the snapshot and the signature,
                # or the counter is exhausted. Refusing is the mechanism
                # working: this runtime must not claim to watch a device it
                # is no longer receiving from.
                logger.debug(
                    "[firmware-liveness] declined to publish for %s",
                    device.device_id,
                    exc_info=True,
                )
            except asyncio.CancelledError:
                # Redundant today — CancelledError derives from
                # BaseException, so the clause below never sees it. Kept
                # explicit because that is the only thing making the
                # containment below safe: widened to BaseException, this
                # loop would swallow its own shutdown.
                raise
            except Exception:
                # Contained on purpose. A broker refusing one device's topic
                # must not stop the others from being told they are watched.
                logger.warning(
                    "[firmware-liveness] publish failed for %s",
                    device.device_id,
                    exc_info=True,
                )
            else:
                sent += 1

        elapsed = self._clock() - started
        if elapsed > self._interval_s:
            # The fleet no longer fits in one interval, so devices are being
            # served more slowly than configured and some may expire. This
            # is a capacity signal, not a transient error.
            logger.warning(
                "[firmware-liveness] tick took %.1fs for %d device(s), "
                "longer than the %.1fs interval; devices may expire",
                elapsed,
                len(devices),
                self._interval_s,
            )
        return sent

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        """Publish every interval until shutdown.

        No publish happens at startup: nothing is supervised until accepted
        telemetry arrives, so an immediate tick would find an empty map.
        """
        logger.info(
            "[firmware-liveness] publishing every %.1fs to supervised devices",
            self._interval_s,
        )
        try:
            while not shutdown_event.is_set():
                try:
                    await asyncio.wait_for(
                        shutdown_event.wait(), timeout=self._interval_s
                    )
                    break
                except asyncio.TimeoutError:
                    await self.publish_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            # The loop dying silently would leave every device believing it
            # is supervised until its own window expires, so say so loudly.
            logger.exception("[firmware-liveness] publish loop stopped unexpectedly")
