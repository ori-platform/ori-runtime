# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Measurement supervision: refused windows, degradation, recovery and escalation."""

import logging

from ori.runtime._alerts import AlertDelivery
from ori.runtime._measurement_policy import (
    MEASUREMENT_CLOSE_GRACE_S,
    MEASUREMENT_NOTIFY_MAX_ATTEMPTS,
    MEASUREMENT_REFUSALS_BEFORE_DEGRADED,
    MEASUREMENT_WINDOWS_TO_RECOVER,
    measurement_notice_stage_due,
)
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.runtime")


class MeasurementSupervision(AlertDelivery):
    """Tracking refused measurements, degrading and recovering a sensor, and escalating a loss."""

    async def _restore_measurement_state(self) -> None:
        """Rebuild every measurement-degradation fact from the state store.

        Restored rather than cleared. The notice fires on the transition into
        degradation, so an in-memory set emptied by every start would make a
        crash-looping runtime re-send the same warning after each restart, and
        a schedule reset by every start would postpone every escalation
        forever on the same device.

        One seam, called at startup and driven directly by the tests that
        prove a restart behaves, so the durable join cannot drift from what
        startup actually does.
        """
        restored = (
            await self._state_store.get_measurement_degradation()
            if self._state_store is not None
            else {}
        )
        schedule = (
            await self._state_store.get_measurement_notice_schedule()
            if self._state_store is not None
            else {}
        )
        self._measurement_degraded = set(restored)
        # The reason is not persisted; say so rather than report none.
        self._measurement_refusal_reason = {
            sensor_id: "degraded before this start; no window refused since"
            for sensor_id in restored
        }
        self._measurement_degraded_since = {
            sensor_id: since for sensor_id, (since, _) in schedule.items()
        }
        self._measurement_notice_stage = {
            sensor_id: stage for sensor_id, (_, stage) in schedule.items()
        }
        # A degradation whose notice never got out is still owed one. Losing
        # that distinction would make the crash that prevented the alert the
        # reason it is never sent.
        self._measurement_unnotified = {
            sensor_id for sensor_id, notified in restored.items() if not notified
        }
        self._measurement_notify_attempts = {}

    async def _escalate_persistent_measurement_loss(self) -> None:
        """Re-notify, and escalate, while a measurement loss persists.

        The first notice fires on the transition and is not repeated, so a
        device that cannot establish a trustworthy measurement said so once
        and then waited indefinitely for a person. This is what keeps saying
        it.

        It restores nothing. A channel that is not being measured is not being
        protected, and telling somebody about it does not change that; the
        notice exists so an operator can act, not so the device can claim to
        have handled it.
        """
        now = now_ms()
        for sensor_id in sorted(self._measurement_degraded):
            since = self._measurement_degraded_since.get(sensor_id)
            if since is None:
                # Degraded with no recorded start. Anchor it here rather than
                # treating it as owed every stage at once.
                self._measurement_degraded_since[sensor_id] = now
                continue
            due = measurement_notice_stage_due(now - since)
            if due <= self._measurement_notice_stage.get(sensor_id, 0):
                continue
            await self._send_measurement_escalation(
                sensor_id=sensor_id,
                stage=due,
                elapsed_ms=now - since,
                first_notice_delivered=sensor_id not in self._measurement_unnotified,
            )

    def _measurement_escalation_recipient(self, stage: int) -> str:
        """Who a given stage is addressed to.

        Stages 0 and 1 are the primary contact; from stage 2 the escalation
        goes to the secondary contact, and to the primary again only where no
        secondary is configured. A device with one contact is not left silent
        because it has nobody to escalate to.
        """
        if stage >= 2 and self._secondary_contact:
            return self._secondary_contact
        return self._operator_contact

    async def _send_measurement_escalation(
        self,
        *,
        sensor_id: str,
        stage: int,
        elapsed_ms: int,
        first_notice_delivered: bool,
    ) -> None:
        """Send one scheduled stage, and record it only if it got out.

        The escalation runs whether or not the notice on the transition ever
        reached anybody. An undelivered first notice is the case where an
        operator knows least, so blocking the schedule on it would silence the
        device precisely when its contact is unreachable — and the initial
        notice's own retries are bounded, so the block would be permanent.
        What changes is the wording: a stage that cannot assume the first
        notice arrived states the fault rather than recalling one.
        """
        recipient = self._measurement_escalation_recipient(stage)
        if self._alert_sender is None or not recipient:
            logger.warning(
                "[sensor] measurement escalation for %s not sent: "
                "no alert sender or no recipient for stage %d",
                sensor_id,
                stage,
            )
            return
        hours = elapsed_ms // (60 * 60 * 1000)
        opening = (
            f"Sensor {sensor_id} has still not produced a valid measurement "
            f"after {hours} hours."
            if first_notice_delivered
            else (
                f"Sensor {sensor_id} has not produced a valid measurement for "
                f"{hours} hours. An earlier notice about it could not be "
                "delivered."
            )
        )
        message = (
            f"{opening} Readings are not being published for it, and any "
            "protection depending on them is not running. Nothing has been "
            "restored. Check the sensor wiring and signal."
        )
        # Structural rather than policy-gated, for the same reason as the
        # notice on the transition, and addressed to the escalation contact.
        delivered = await self._send_or_queue_safety_alert(
            message=message,
            trigger_name=f"measurement_degraded_persists:{sensor_id}",
            alert_sender=self._alert_sender,
            recipient=recipient,
        )
        if not delivered:
            # Left un-recorded so this stage is retried on the next pass, and
            # superseded without ceremony when the next stage falls due. A
            # reminder that could not be sent never cancels the escalation
            # after it.
            return
        # Advanced in memory whether or not the write below lands, so a store
        # that is failing does not turn every pass of the loop into another
        # message. A restart then repeats at most this one stage.
        self._measurement_notice_stage[sensor_id] = stage
        recorded = True
        if self._state_store is not None:
            try:
                # One write, not two, and an upsert rather than an update.
                # Recording only the stage would leave the disk saying a later
                # stage was sent while still saying nobody was notified, so
                # the next start would send the notice for the transition all
                # over again. And the row may not exist at all: the write that
                # records the degradation is allowed to fail transiently, so
                # an escalation can be the first one to land. It carries the
                # in-memory start so a reconstructed row dates the loss to
                # when it happened rather than to when the disk caught up.
                await self._state_store.record_measurement_notice_delivered(
                    sensor_id,
                    stage,
                    degraded_since=self._measurement_degraded_since.get(
                        sensor_id, now_ms()
                    ),
                )
            except Exception:
                recorded = False
                logger.exception(
                    "[sensor] could not persist notice stage %d for %s; "
                    "a restart may repeat this reminder",
                    stage,
                    sensor_id,
                )
        if recorded:
            # Cleared only once the disk agrees. Clearing it on a failed write
            # would leave memory saying the operator has been told and disk
            # saying they have not, and the restart would resolve that
            # disagreement by messaging them again.
            self._measurement_unnotified.discard(sensor_id)
            self._measurement_notify_attempts.pop(sensor_id, None)
        logger.warning(
            "[sensor] measurement loss for %s persists after %d hours; "
            "stage %d notice sent",
            sensor_id,
            hours,
            stage,
        )

    async def _note_measurement_accepted(self, sensor_id: str) -> None:
        """A window that was a measurement. Counts toward clearing degradation."""
        if sensor_id not in self._measurement_degraded:
            self._measurement_refusals.pop(sensor_id, None)
            self._measurement_refusal_reason.pop(sensor_id, None)
            return
        streak = self._measurement_valid_streak.get(sensor_id, 0) + 1
        self._measurement_valid_streak[sensor_id] = streak
        if streak < MEASUREMENT_WINDOWS_TO_RECOVER:
            self._reconcile_measurement(sensor_id, clear=False)
            return
        if sensor_id in self._measurement_disk_recovered:
            if sensor_id in self._measurement_reconciling:
                # A restore is in flight and will put the degraded row back;
                # its landing queues the clear this completed run is owed.
                return
            # The disk already says recovered, and now memory agrees.
            self._measurement_disk_recovered.discard(sensor_id)
            self._finish_measurement_recovery(sensor_id, streak)
            return
        # Queued, never awaited: recovery is bookkeeping, and the reading that
        # completed it is evaluated now. The sensor stays degraded in memory
        # until the clear lands, so memory is never healthier than disk.
        self._reconcile_measurement(sensor_id, clear=True, streak=streak)

    def _reconcile_measurement(
        self, sensor_id: str, *, clear: bool, streak: int = 0
    ) -> None:
        """Queue the disk write a sensor's measurement state is owed, once.

        *clear* records a completed recovery. Otherwise this restores the
        degraded row for a sensor whose disk says recovered while it is still
        degraded, and does nothing for one whose disk already agrees. A write
        the store refuses is counted lost by the writer; the next window for
        the sensor queues it again.
        """
        if not clear and sensor_id not in self._measurement_disk_recovered:
            return
        if sensor_id in self._measurement_reconciling:
            return
        store = self._state_store
        if store is None:
            if clear:
                self._finish_measurement_recovery(sensor_id, streak)
            return
        self._measurement_reconciling.add(sensor_id)

        async def write_clear() -> None:
            await store.clear_measurement_degraded(sensor_id)
            self._measurement_reconciling.discard(sensor_id)
            self._measurement_cleared_on_disk(sensor_id, streak)

        async def write_restore() -> None:
            await store.set_measurement_degraded(
                sensor_id, notified=sensor_id not in self._measurement_unnotified
            )
            self._measurement_reconciling.discard(sensor_id)
            self._measurement_disk_recovered.discard(sensor_id)
            completed = self._measurement_valid_streak.get(sensor_id, 0)
            if (
                sensor_id in self._measurement_degraded
                and completed >= MEASUREMENT_WINDOWS_TO_RECOVER
            ):
                # The run completed while the row was being restored.
                self._reconcile_measurement(sensor_id, clear=True, streak=completed)

        def lost() -> None:
            self._measurement_reconciling.discard(sensor_id)

        self._measurement_writer.submit(
            write_clear if clear else write_restore,
            label=(
                f"measurement {'recovery' if clear else 'restore'} sensor={sensor_id}"
            ),
            report=True,
            on_lost=lost,
        )

    def _measurement_cleared_on_disk(self, sensor_id: str, streak: int) -> None:
        """The disk says recovered; clear memory unless the run was broken."""
        if sensor_id not in self._measurement_degraded:
            return
        if (
            self._measurement_valid_streak.get(sensor_id, 0)
            < MEASUREMENT_WINDOWS_TO_RECOVER
        ):
            # A refused window arrived while the clear was written: the sensor
            # is still degraded, and the disk is owed its row back.
            self._measurement_disk_recovered.add(sensor_id)
            self._reconcile_measurement(sensor_id, clear=False)
            return
        self._finish_measurement_recovery(sensor_id, streak)

    async def _close_measurement_writer(
        self, grace_s: float = MEASUREMENT_CLOSE_GRACE_S
    ) -> None:
        writer = self._measurement_writer
        await writer.drain(grace_s)
        await writer.close(grace_s=grace_s)
        if writer.lost or writer.unknown or self._measurement_disk_recovered:
            logger.warning(
                "[shutdown] measurement state: %d writes lost, %d unknown, "
                "%d sensors recovered on disk while still degraded",
                writer.lost,
                writer.unknown,
                len(self._measurement_disk_recovered),
            )

    def _finish_measurement_recovery(self, sensor_id: str, streak: int) -> None:
        self._measurement_degraded.discard(sensor_id)
        self._measurement_unnotified.discard(sensor_id)
        self._measurement_notify_attempts.pop(sensor_id, None)
        self._measurement_refusals.pop(sensor_id, None)
        self._measurement_refusal_reason.pop(sensor_id, None)
        self._measurement_valid_streak.pop(sensor_id, None)
        self._measurement_degraded_since.pop(sensor_id, None)
        self._measurement_notice_stage.pop(sensor_id, None)
        logger.info(
            "[sensor] %s measurement recovered after %d consecutive valid windows",
            sensor_id,
            streak,
        )

    async def _note_measurement_refusal(self, *, sensor_id: str, detail: str) -> None:
        """A window that was not a measurement.

        No reading was published, so nothing downstream saw a value. What the
        operator must not be left with is silence: a sensor that has quietly
        stopped measuring looks identical to one measuring zero.
        """
        # Any refusal breaks a recovery run. Alternating windows are not a
        # measurement path coming back.
        self._measurement_valid_streak.pop(sensor_id, None)
        self._reconcile_measurement(sensor_id, clear=False)
        self._measurement_refusal_reason[sensor_id] = detail
        refusals = self._measurement_refusals.get(sensor_id, 0) + 1
        self._measurement_refusals[sensor_id] = refusals
        if refusals < MEASUREMENT_REFUSALS_BEFORE_DEGRADED:
            return
        if sensor_id in self._measurement_degraded:
            if sensor_id not in self._measurement_unnotified:
                # Already reported. The alert fires on the transition, not per
                # window, so a persistent fault does not become a message flood.
                return
            # Degraded, but the operator was never actually reached — no sender,
            # no contact, or send and durable queueing both failed. Retry on
            # this refusal rather than treating the failure as delivery.
            attempts = self._measurement_notify_attempts.get(sensor_id, 0)
            if attempts >= MEASUREMENT_NOTIFY_MAX_ATTEMPTS:
                return
            self._measurement_notify_attempts[sensor_id] = attempts + 1
            await self._deliver_measurement_warning(
                sensor_id=sensor_id, refusals=refusals
            )
            return
        self._measurement_degraded.add(sensor_id)
        self._measurement_unnotified.add(sensor_id)
        self._measurement_degraded_since.setdefault(sensor_id, now_ms())
        self._measurement_notice_stage[sensor_id] = 0
        # Recorded before the alert is attempted, and without letting a store
        # failure escape the poll loop: this runs inside an `except` clause, so
        # an exception here would not be caught by the handler below it and
        # would end polling for this sensor entirely.
        await self._persist_measurement_state(sensor_id, notified=False)
        logger.warning(
            "[sensor] %s measurement degraded after %d consecutive refused windows: %s",
            sensor_id,
            refusals,
            detail,
        )
        self._measurement_notify_attempts[sensor_id] = 1
        await self._deliver_measurement_warning(sensor_id=sensor_id, refusals=refusals)

    async def _deliver_measurement_warning(
        self, *, sensor_id: str, refusals: int
    ) -> None:
        """Try to reach the operator, and record it only if that succeeded."""
        if not await self._emit_measurement_degraded_warning(
            sensor_id=sensor_id, refusals=refusals
        ):
            return
        # Delivered or durably queued. Only now is the operator owed nothing
        # further, so only now may a restart stay quiet.
        self._measurement_unnotified.discard(sensor_id)
        self._measurement_notify_attempts.pop(sensor_id, None)
        await self._persist_measurement_state(sensor_id, notified=True)

    async def _persist_measurement_state(
        self, sensor_id: str, *, notified: bool
    ) -> None:
        """Record degradation durably. A store failure must not stop polling."""
        if self._state_store is None:
            return
        try:
            await self._state_store.set_measurement_degraded(
                sensor_id, notified=notified
            )
        except Exception:
            logger.exception(
                "[sensor] could not persist measurement degradation for %s; "
                "the alert still fires, but a restart may repeat it",
                sensor_id,
            )

    async def _emit_measurement_degraded_warning(
        self, *, sensor_id: str, refusals: int
    ) -> bool:
        """Send or queue the Tier A notice that a sensor stopped measuring.

        Returns whether the operator is owed nothing further — delivered, or
        durably queued for delivery. A False answer leaves the notification
        pending so a later poll or a restart tries again.
        """
        if self._alert_sender is None:
            logger.warning(
                "[runtime] measurement degraded warning not sent: no alert sender"
            )
            return False
        if not self._operator_contact:
            logger.warning(
                "[runtime] measurement degraded warning not sent: "
                "operator_contact is not configured"
            )
            return False
        message = (
            f"Sensor {sensor_id} has stopped producing valid measurements after "
            f"{refusals} consecutive refused windows. Readings are not being "
            "published for it, and any protection depending on them is not "
            "running. Check the sensor wiring and signal."
        )
        # Structural rather than policy-gated. A notice that a protection is
        # absent must not be suppressed by an entitlement cap: suppressing it
        # leaves an operator believing a measurement is being taken that is
        # not, which is the fact this notice exists to carry.
        return bool(
            await self._send_or_queue_safety_alert(
                message=message,
                trigger_name=f"measurement_degraded:{sensor_id}",
                alert_sender=self._alert_sender,
            )
        )
