# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Sensor polling, read failures and staleness."""

import asyncio
import logging
from typing import Any

from ori.actions.alert_failover import AlertFailoverSender
from ori.hal.base import (
    AdapterReadError,
    BaseAdapter,
    MeasurementRefusedError,
    refuse_quality_above_one,
    refuse_unusable_reading,
    silence_bound_ms,
)
from ori.network.deduplicator import EventDeduplicator
from ori.network.event_bus import EventBus
from ori.network.events import OriEvent
from ori.runtime._constants import (
    READ_FAILURE_LOG_INTERVAL_S,
    STALE_SENSOR_MIN_CHECK_INTERVAL_S,
)
from ori.runtime._device_io import sync_power_state_from_reading
from ori.runtime._measurement import MeasurementSupervision
from ori.sensor_connection import SendNotice, announce_late_connection, connected_late
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.runtime")


class SensorPolling(MeasurementSupervision):
    """Polling each sensor, and noticing one that fails or goes quiet."""

    # ── Background tasks ──────────────────────────────────────────────────────

    async def _poll_sensor(
        self,
        adapter: BaseAdapter,
        sensor_cfg: Any,
        event_bus: EventBus,
        device_id: str,
        deduplicator: EventDeduplicator | None = None,
        device_timezone: str = "",
        device_country_code: str = "",
        device_location: str = "",
        device_site_type: str = "",
    ) -> None:
        """Read *adapter* at the configured poll interval and publish to *event_bus*."""
        if self._state_store is None:
            logger.error(
                "[runtime] state_store unavailable for sensor poll task sensor_id=%s; stopping poll loop",
                sensor_cfg.id,
            )
            return
        while not self._shutdown_event.is_set():
            try:
                reading = await adapter.read(sensor_cfg.id)
                # Outside the reading's quality domain, this is a refused window
                # rather than an input the safety profile can judge.
                refuse_quality_above_one(reading)
                # The safety registry consumes every reading synchronously,
                # before deduplication, history, the EventBus, or any skill:
                # a duplicate is irrelevant to skills and still matters to
                # credible-reading freshness and a latched trip.
                if self._safety_registry is not None:
                    for decision in await self._safety_registry.observe_reading(
                        reading.sensor_id,
                        reading.value,
                        reading.unit,
                        reading.quality,
                    ):
                        if decision.tripped:
                            logger.critical(
                                "[safety] TRIP zone=%s profile=%s driver_accepted=%s",
                                decision.pair[0],
                                decision.pair[1],
                                decision.driver_accepted,
                            )
                # After the registry, which judges the value itself, and before
                # anything counts the sensor as seen: a reading that cannot be
                # stored or compared would otherwise mark the sensor live and
                # then fail on every poll before any skill evaluated it.
                refuse_unusable_reading(reading)
                self._sensor_last_seen_ms[sensor_cfg.id] = now_ms()
                if connected_late(
                    str(sensor_cfg.id),
                    unconnected=self._unconnected_sensors,
                    connected=self._connected_sensor_ids,
                ):
                    # A task, so delivery never delays this reading's evaluation.
                    notice = announce_late_connection(
                        str(sensor_cfg.id),
                        announced=self._retrying_sensors_announced,
                        send=self._safety_notice_sender(),
                    )
                    self._background_tasks.append(
                        asyncio.create_task(
                            notice, name=f"sensor-connected-notice:{sensor_cfg.id}"
                        )
                    )
                if (
                    self._read_failure_logged_at.pop(str(sensor_cfg.id), None)
                    is not None
                ):
                    logger.info("[sensor] %s read recovered", sensor_cfg.id)
                await self._note_measurement_accepted(str(sensor_cfg.id))
                if sensor_cfg.id in self._stale_sensor_active:
                    self._stale_sensor_active.discard(sensor_cfg.id)
                    logger.info(
                        "[runtime] sensor recovered from stale state sensor_id=%s",
                        sensor_cfg.id,
                    )
                if sensor_cfg.id in self._faulted_sensors:
                    self._faulted_sensors.discard(sensor_cfg.id)
                    if self._status_indicator is not None and not self._faulted_sensors:
                        self._status_indicator.set_hardware_fault(False)
                # Adapters publish protocol provenance through
                # reading.metadata["source"]; the poll path names no default.
                event = OriEvent.published_reading(reading, device_id)
                if not isinstance(event.context, dict):
                    event.context = {}
                event.context["device_timezone"] = device_timezone
                event.context["location"] = str(device_location or "")
                event.context["site_type"] = str(device_site_type or "")
                event.context["device_country_code"] = (
                    str(device_country_code or "").strip().upper()
                )
                calibration = getattr(sensor_cfg, "calibration", None)
                if isinstance(calibration, dict) and calibration:
                    event.context["sensor_calibration"] = dict(calibration)
                # Queued, never awaited: a busy store must not delay or drop the
                # reading's evaluation. Its row lands after, or is counted lost.
                self._state_store.admit_history(event)
                # A suppressed duplicate still waits out the poll interval: a
                # cached adapter answers without yielding, so skipping the
                # sleep would re-read at CPU speed and starve the event loop.
                if (
                    event.reading is not None
                    and deduplicator is not None
                    and deduplicator.process(event) is None
                ):
                    logger.debug(
                        "Deduplicator suppressed duplicate event for sensor %s "
                        "(fingerprint %s...)",
                        event.sensor_id,
                        event.fingerprint[:8],
                    )
                else:
                    await event_bus.publish(event)
                    if self._status_indicator is not None:
                        sync_power_state_from_reading(self._status_indicator, reading)
            except AdapterReadError as exc:
                self._log_read_failure(str(sensor_cfg.id), exc)
                if isinstance(exc, MeasurementRefusedError):
                    await self._note_measurement_refusal(
                        sensor_id=str(sensor_cfg.id),
                        detail=str(exc),
                    )
                if self._status_indicator is not None and "circuit breaker OPEN" in str(
                    exc
                ):
                    self._faulted_sensors.add(sensor_cfg.id)
                    self._status_indicator.set_hardware_fault(True)
            except Exception:
                logger.exception("[sensor] unexpected error polling %s", sensor_cfg.id)
            await asyncio.sleep(sensor_cfg.poll_interval_ms / 1000)

    def _log_read_failure(self, sensor_id: str, exc: AdapterReadError) -> None:
        """Log a failed read at WARNING once per interval per sensor, otherwise DEBUG."""
        now = asyncio.get_running_loop().time()
        last = self._read_failure_logged_at.get(sensor_id)
        if last is None or now - last >= READ_FAILURE_LOG_INTERVAL_S:
            self._read_failure_logged_at[sensor_id] = now
            logger.warning("[sensor] %s read failed: %s", sensor_id, exc)
        else:
            logger.debug("[sensor] %s read failed: %s", sensor_id, exc)

    async def _sensor_staleness_loop(
        self,
        *,
        alert_sender: AlertFailoverSender,
        check_interval_s: float,
    ) -> None:
        """Emit Tier A warnings when sensors go silent past 2x poll interval."""
        interval = max(STALE_SENSOR_MIN_CHECK_INTERVAL_S, float(check_interval_s))
        while not self._shutdown_event.is_set():
            now = now_ms()
            for sensor_id, poll_ms in self._sensor_poll_interval_ms.items():
                last_seen = self._sensor_last_seen_ms.get(sensor_id)
                if last_seen is None:
                    continue
                stale_after_ms = silence_bound_ms(int(poll_ms))
                stale_duration_ms = now - int(last_seen)
                is_stale = stale_duration_ms > stale_after_ms
                if is_stale and sensor_id not in self._stale_sensor_active:
                    self._stale_sensor_active.add(sensor_id)
                    logger.warning(
                        "[runtime] stale sensor warning sensor_id=%s stale_for_ms=%d threshold_ms=%d",
                        sensor_id,
                        stale_duration_ms,
                        stale_after_ms,
                    )
                    await self._emit_stale_sensor_warning(
                        alert_sender=alert_sender,
                        sensor_id=sensor_id,
                        stale_duration_ms=stale_duration_ms,
                        stale_after_ms=stale_after_ms,
                    )

            await self._escalate_persistent_measurement_loss()

            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass  # the interval elapsed: check staleness again

    def _safety_notice_sender(self) -> SendNotice | None:
        sender = self._alert_sender
        if sender is None:
            return None
        return lambda message, trigger: self._send_or_queue_safety_alert(
            message=message, trigger_name=trigger, alert_sender=sender
        )

    async def _emit_stale_sensor_warning(
        self,
        *,
        alert_sender: AlertFailoverSender,
        sensor_id: str,
        stale_duration_ms: int,
        stale_after_ms: int,
    ) -> None:
        """Send or queue a stale-sensor Tier A notification."""
        if not self._operator_contact:
            logger.warning(
                "[runtime] stale sensor warning not sent: operator_contact is not configured"
            )
            return
        minutes = max(stale_duration_ms // 60_000, 1)
        threshold_seconds = max(stale_after_ms // 1000, 1)
        message = (
            f"Sensor {sensor_id} has not reported for about {minutes} minute(s). "
            f"This exceeded the stale threshold of {threshold_seconds}s."
        )
        alert_ts = now_ms()
        await self._send_or_queue_alert(
            channel=self._primary_alert_channel,
            message=message,
            recipient=self._operator_contact,
            action_tier="A",
            trigger_name="sensor_stale_warning",
            original_ts=alert_ts,
            received_at_ms=alert_ts,
            alert_sender=alert_sender,
        )
