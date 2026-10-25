# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The stop protocol: a stop requested during startup, and ``stop()``."""

import asyncio
import logging

from ori.hardware.led_indicator import RuntimeHealthState
from ori.runtime._constants import TIER_D_DRAIN_TIMEOUT
from ori.runtime._evidence import EvidenceLoops
from ori.runtime._measurement import MeasurementSupervision
from ori.runtime._skills import SkillReload
from ori.sensor_connection import close_adapters

logger = logging.getLogger("ori.runtime")


class Shutdown(MeasurementSupervision, EvidenceLoops, SkillReload):
    """Stopping the runtime, including a stop that arrives while it is still starting."""

    def _request_stop(self) -> None:
        """Handle SIGTERM or SIGINT, deciding what the signal means right now.

        After startup has finished, a signal stops the runtime, which is the
        whole of its meaning. During startup it cannot: `stop()` closes the
        state store, the adapters and every server, and startup is still
        constructing and using them. Running the two concurrently is how a
        resource is closed under a step that is mid-way through using it, and
        the failure surfaces deep inside whichever step lost the race.

        So during startup the request is recorded and startup unwinds at its
        next checkpoint, which serialises the two rather than making `stop()`
        defensive against every order they could interleave in.

        A second signal is taken as an instruction rather than a repetition.
        Startup can block in an adapter connect that never answers, which is
        exactly when an operator sends the first signal and exactly when no
        checkpoint is coming. An operator who has asked twice is left with a
        way out, at the cost of the untidy teardown the first signal avoids.
        """
        if self._startup_complete or self._stop_requested_during_startup:
            if not self._startup_complete:
                logger.warning(
                    "[runtime] second stop signal during startup; tearing down "
                    "now without waiting for a checkpoint"
                )
            asyncio.create_task(self.stop())
            return
        self._stop_requested_during_startup = True
        logger.info(
            "[runtime] stop requested during startup; unwinding at the next "
            "checkpoint. Signal again to tear down immediately."
        )

    async def _stop_if_requested_during_startup(self) -> bool:
        """A startup checkpoint: stop here if a signal asked us to.

        Returns True when the caller should abandon the rest of startup.
        """
        if not self._stop_requested_during_startup:
            return False
        logger.info("[runtime] startup interrupted by a stop request")
        await self.stop()
        return True

    async def stop(self) -> None:
        """Graceful shutdown. Called by SIGTERM/SIGINT signal handlers."""
        if self._shutdown_event.is_set():
            return
        logger.info("[runtime] shutdown initiated")
        # Retain a shutdown checkpoint and hand the courier what it can take
        # while the routes are still up: setting the shutdown event is what
        # tears them down, so this has to come first or the flush finds a
        # closed route and the checkpoint waits for the next start.
        await self._issue_shutdown_checkpoint()
        self._shutdown_event.set()
        if self._status_indicator is not None:
            self._status_indicator.set_runtime_state(RuntimeHealthState.DEGRADED)

        # 1. Drain in-flight Tier D tasks before cancelling anything else.
        tier_d_tasks: list[asyncio.Task] = []
        if self._dispatcher is not None and hasattr(
            self._dispatcher, "get_inflight_tier_d_tasks"
        ):
            tier_d_tasks.extend(self._dispatcher.get_inflight_tier_d_tasks())

        # Backward-compatible fallback: if any legacy Tier D task tags exist,
        # still honour them during shutdown drain.
        for task in asyncio.all_tasks():
            if task.done():
                continue
            if getattr(task, "_is_tier_d", False) and task not in tier_d_tasks:
                tier_d_tasks.append(task)

        if tier_d_tasks:
            logger.warning(
                "[shutdown] waiting up to %.1fs for %d Tier D task(s)",
                TIER_D_DRAIN_TIMEOUT,
                len(tier_d_tasks),
            )
            await asyncio.wait(tier_d_tasks, timeout=TIER_D_DRAIN_TIMEOUT)

        # 2. Cancel tracked background tasks only — never cancel the task
        #    running start() itself, which returns naturally once the shutdown
        #    event is set. This stops the sensor loops, so no act starts after
        #    its records have been closed below.
        tasks = [t for t in self._background_tasks if not t.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # 2a. An open proposal has no live process to admit its reply once this
        #     one stops: closed now, with its one non-actuating safe default,
        #     so nothing is lost silently and nothing is approved later.
        if self._dispatcher is not None and self._state_store is not None:
            try:
                closed = await asyncio.wait_for(
                    self._dispatcher.close_open_proposals(
                        self._state_store, reason="graceful_shutdown"
                    ),
                    timeout=TIER_D_DRAIN_TIMEOUT,
                )
                if closed:
                    logger.warning(
                        "[shutdown] closed %d open Tier C proposal(s); none is approved",
                        closed,
                    )
            except Exception:
                logger.exception("[shutdown] open Tier C proposals could not be closed")

        # 2a. Stop the skill hook thread. A hook that does not finish within
        #     the bound is abandoned and counted lost, never waited for.
        if self._elevator is not None:
            lost_hooks = await self._elevator.close_hooks()
            if lost_hooks:
                logger.warning("[shutdown] %d skill hook call(s) lost", lost_hooks)

        # 2b. Write the records of acts. They are kept off each act's path, so
        #     they settle afterwards, and must land while the store and the
        #     evidence attestor are still open. What the store has not taken by
        #     the deadline is reported lost; an act that has not settled — an
        #     approval still open — is reported apart.
        dispatcher = self._dispatcher
        if dispatcher is not None and hasattr(dispatcher, "pending_record_count"):
            pending_records = dispatcher.pending_record_count()
            if pending_records:
                logger.warning(
                    "[shutdown] waiting up to %.1fs for %d action record(s)",
                    TIER_D_DRAIN_TIMEOUT,
                    pending_records,
                )
            await dispatcher.drain_records(timeout=TIER_D_DRAIN_TIMEOUT)
            await dispatcher.abandon_records()

        # 2b. Stop gateway export responder.
        if self._gateway_export_server is not None:
            try:
                await self._gateway_export_server.close()
            except Exception:
                logger.exception("[shutdown] error closing gateway export responder")
            self._gateway_export_server = None

        # 2c. Stop runtime node heartbeat publisher.
        if self._runtime_node_heartbeat_publisher is not None:
            try:
                await self._runtime_node_heartbeat_publisher.close()
            except Exception:
                logger.exception("[shutdown] error closing runtime node heartbeat")
            self._runtime_node_heartbeat_publisher = None

        # 2d. Stop firmware command egress.
        if self._firmware_command_publisher is not None:
            try:
                await self._firmware_command_publisher.close()
            except Exception:
                logger.exception("[shutdown] error closing firmware command publisher")
            self._firmware_command_publisher = None
            self._firmware_command_service = None
        self._firmware_liveness_scheduler = None
        self._firmware_profile_library = None
        self._firmware_alarm_tracker = None

        # 2e. Stop local health socket service.
        if self._health_socket_server is not None:
            try:
                await self._health_socket_server.close()
            except Exception:
                logger.exception("[shutdown] error closing health socket")
            self._health_socket_server = None
            self._health_socket_path = ""

        # 2e'. Stop the operator socket; an append already begun completes.
        if self._operator_socket_server is not None:
            try:
                await self._operator_socket_server.close()
            except Exception:
                logger.exception("[shutdown] error closing the operator socket")
            self._operator_socket_server = None

        # 2f. Stop the authenticated firmware MQTT operator service.
        if self._firmware_mqtt_operator_server is not None:
            try:
                await self._firmware_mqtt_operator_server.close()
            except Exception:
                logger.exception(
                    "[shutdown] error closing firmware MQTT operator socket"
                )
            self._firmware_mqtt_operator_server = None
            self._firmware_mqtt_operator_socket_path = ""

        # 2g. Stop the evidence executor; the shutdown checkpoint is already
        #     retained (1b).
        if self._evidence_attestor is not None:
            self._evidence_attestor.set_sealed_listener(None)
            try:
                self._evidence_attestor.close()
            except Exception:
                logger.exception("[shutdown] error closing evidence attestor")
            self._evidence_attestor = None

        # 2h. Once every signer is stopped: the signing clock, then the store.
        if self._gateway_envelope_state is not None:
            await asyncio.to_thread(self._gateway_envelope_state.close)

        # 3. Close HAL adapters, at once: the stop waits for the slowest only
        await close_adapters(self._adapters)

        # 4. Close StateStore, after the measurement writer has settled what
        #    it can: a write still in flight past its grace is unknown, one
        #    never started is lost, and both are counted.
        await self._close_measurement_writer()
        if self._state_store is not None:
            await self._state_store.close()

        self._unregister_skill_handlers()
        self._loaded_skills = []

        logger.info("[runtime] shutdown complete")
