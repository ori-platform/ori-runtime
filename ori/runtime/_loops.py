# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The watchdogs, heartbeat, compaction, posture and status-signal loops."""

import asyncio
import logging
import os

from ori.hardware.led_indicator import LEDIndicator
from ori.network.deduplicator import EventDeduplicator
from ori.reasoning.capability_posture import CapabilityPostureTracker
from ori.reasoning.elevator import IntelligenceElevator
from ori.reasoning.local_llm import LocalLLM
from ori.runtime._capabilities import is_local_slm_available
from ori.runtime._constants import (
    EXTERNAL_WATCHDOG_GPIO,
    EXTERNAL_WATCHDOG_PING_S,
    WATCHDOG_DEVICE,
    WATCHDOG_PING_INTERVAL,
    WATCHDOG_TIMEOUT,
)
from ori.runtime._core import RuntimeCore
from ori.runtime._device_io import sync_network_state_from_posture

logger = logging.getLogger("ori.runtime")


class BackgroundLoops(RuntimeCore):
    """The runtime's periodic loops: watchdogs, heartbeat, compaction, posture, status."""

    async def _watchdog_loop(self) -> None:
        """Ping /dev/watchdog every WATCHDOG_PING_INTERVAL seconds."""
        if not os.path.exists(WATCHDOG_DEVICE):
            logger.warning(
                "Watchdog: %s not found. "
                "Run: echo bcm2835_wdt | sudo tee -a /etc/modules",
                WATCHDOG_DEVICE,
            )
            return
        try:
            with open(WATCHDOG_DEVICE, "wb", buffering=0) as wd:
                logger.info(
                    "Watchdog: active on %s — timeout %ds",
                    WATCHDOG_DEVICE,
                    WATCHDOG_TIMEOUT,
                )
                try:
                    while not self._shutdown_event.is_set():
                        wd.write(b"1")
                        wd.flush()
                        try:
                            # Immediate wake on shutdown instead of sleeping blindly
                            await asyncio.wait_for(
                                self._shutdown_event.wait(),
                                timeout=WATCHDOG_PING_INTERVAL,
                            )
                        except asyncio.TimeoutError:
                            pass  # the ping interval elapsed: ping again
                finally:
                    # Clean shutdown — magic V tells the kernel this was intentional
                    # Runs even if the task is cancelled (CancelledError)
                    wd.write(b"V")
                    wd.flush()
                    logger.info("Watchdog: closed cleanly (magic V written)")
        except PermissionError:
            logger.warning(
                "Watchdog: cannot open %s — permission denied. "
                "Run Ori with sudo or add user to watchdog group.",
                WATCHDOG_DEVICE,
            )
        except Exception:
            logger.exception("Watchdog loop failed — reboot may follow")

    async def _external_watchdog_loop(
        self,
        gpio_pin: int = EXTERNAL_WATCHDOG_GPIO,
        ping_interval_s: float = EXTERNAL_WATCHDOG_PING_S,
    ) -> None:
        """Pulse a GPIO pin for optional external watchdog hardware."""
        try:
            import importlib

            gpiozero = importlib.import_module("gpiozero")
        except ImportError:
            # Optional hardware feature; silently skip on non-Pi systems.
            return

        pin = None
        try:
            pin = gpiozero.DigitalOutputDevice(gpio_pin)
            logger.info("External GPIO watchdog active on BCM%d", gpio_pin)
            while not self._shutdown_event.is_set():
                pin.on()
                await asyncio.sleep(0.1)
                pin.off()
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=ping_interval_s,
                    )
                except asyncio.TimeoutError:
                    pass  # the ping interval elapsed: toggle the pin again
        except Exception:
            logger.exception("[runtime] external watchdog loop failed")
        finally:
            if pin is not None:
                try:
                    pin.off()
                except Exception:
                    pass  # best effort on the way out; the loop has already ended
                if hasattr(pin, "close"):
                    try:
                        pin.close()
                    except Exception:
                        pass  # best effort on the way out, as for off() above

    async def _heartbeat_loop(self, device_id: str) -> None:
        """Log a heartbeat every 5 minutes to confirm the runtime is alive.

        The heartbeat reports:
        - managed runtime background tasks (pollers/watchdog/compaction/etc.)
        - pending reasoning tasks
        - pending approval-wait tasks
        - total active asyncio tasks
        """
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=300.0,
                )
                break  # shutdown was signalled during the wait — exit cleanly
            except asyncio.TimeoutError:
                pass  # 5 minutes elapsed normally — log heartbeat
            active = [t for t in asyncio.all_tasks() if not t.done()]
            managed = [t for t in self._background_tasks if not t.done()]
            reasoning_pending = 0
            approval_pending = 0
            for task in active:
                name = task.get_name()
                if name.startswith("reason:"):
                    reasoning_pending += 1
                elif name.startswith("approval:"):
                    approval_pending += 1
            logger.info(
                "[heartbeat] device=%s managed_tasks=%d reasoning_pending=%d "
                "approval_pending=%d active_tasks=%d",
                device_id,
                len(managed),
                reasoning_pending,
                approval_pending,
                len(active),
            )
        logger.debug("[heartbeat] loop exited cleanly")

    async def _compaction_loop(
        self,
        deduplicator: EventDeduplicator | None = None,
        max_backward_skew_ms: int = 3600000,
    ) -> None:
        """Run the SQLite Compaction Pyramid every 5 minutes."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=300.0,
                )
                break  # shutdown was signalled
            except asyncio.TimeoutError:
                pass  # five minutes elapsed: log the heartbeat
            if self._state_store is not None:
                try:
                    await self._state_store.compact_history(
                        max_backward_skew_ms=max_backward_skew_ms
                    )
                    logger.debug("[compaction] history compaction complete")
                except Exception:
                    logger.exception(
                        "[compaction] history compaction failed — will retry"
                    )
            if deduplicator is not None:
                try:
                    deduplicator.cleanup()
                    logger.debug("[compaction] deduplicator cleanup complete")
                except Exception:
                    logger.exception(
                        "[compaction] deduplicator cleanup failed — will retry"
                    )

    async def _capability_posture_loop(
        self,
        *,
        tracker: CapabilityPostureTracker,
        elevator: IntelligenceElevator,
        sms_enabled: bool,
        whatsapp_enabled: bool,
        local_llm: LocalLLM | None,
        relay_connected: bool,
        update_interval_s: float,
    ) -> None:
        """Periodically refresh capability posture and feed it into the elevator."""
        interval = max(update_interval_s, 1.0)
        while not self._shutdown_event.is_set():
            try:
                posture = await tracker.refresh(
                    sms_available=sms_enabled,
                    whatsapp_available=whatsapp_enabled,
                    local_slm_loaded=is_local_slm_available(local_llm),
                    relay_connected=relay_connected,
                )
                elevator.update_capability_posture(posture)
                if self._dispatcher is not None:
                    self._dispatcher.update_capability_posture(posture)
                if self._alert_sender is not None:
                    self._alert_sender.update_capability_posture(posture)
                if self._status_indicator is not None:
                    sync_network_state_from_posture(self._status_indicator, posture)
            except Exception:
                logger.exception("[runtime] capability posture refresh failed")

            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass  # the interval elapsed: refresh the posture again

    async def _status_signaling_loop(
        self,
        *,
        indicator: LEDIndicator,
        tick_ms: int,
    ) -> None:
        interval = max(int(tick_ms), 50) / 1000.0
        while not self._shutdown_event.is_set():
            try:
                indicator.tick()
            except Exception:
                logger.exception("[runtime] status signaling tick failed")
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass  # the interval elapsed: signal status again
        await indicator.close()
