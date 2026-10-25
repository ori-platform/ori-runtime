# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Alert delivery: send or queue, alert policy, the setup notice, and the outbox."""

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, cast

from ori.actions.alert_delivery import (
    AlertIntent,
    AlertSendReceipt,
    OutboundAlert,
    build_outbound_alert,
)
from ori.actions.alert_failover import AlertFailoverSender
from ori.config import Config
from ori.policy.alert_classes import alert_class_for_trigger
from ori.reasoning.action_taken import SUPPRESSED
from ori.runtime._alert_text import (
    alert_policy_count_key,
    build_alert_id,
    coerce_alert_send_receipt,
    count_active_triggers,
    format_alert_timestamp,
    preference_disabled_key,
    resolve_setup_notification_channels,
    setup_success_message,
)
from ori.runtime._core import RuntimeCore
from ori.utils.bool_utils import is_truthy
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.runtime")


class AlertDelivery(RuntimeCore):
    """Sending or queueing alerts under alert policy, and draining the durable outbox."""

    def _configure_alert_outbox(self, alert_outbox_cfg: dict[str, Any]) -> None:
        cfg = alert_outbox_cfg if isinstance(alert_outbox_cfg, dict) else {}
        self._alert_outbox_retry_interval_s = (
            float(cfg.get("retry_interval_minutes", 0.5)) * 60.0
        )
        self._alert_outbox_batch_size = int(cfg.get("batch_size", 50))
        self._alert_outbox_max_non_tier_d_attempts = int(
            cfg.get("max_non_tier_d_attempts", 10)
        )
        self._alert_outbox_tier_d_critical_threshold = int(
            cfg.get("tier_d_critical_warning_threshold", 3)
        )

    async def _send_or_queue_alert(
        self,
        *,
        channel: str,
        message: str,
        recipient: str,
        action_tier: str,
        trigger_name: str,
        original_ts: int,
        received_at_ms: int,
        alert_sender: AlertFailoverSender,
        allow_failover: bool = True,
        outbound_alert: OutboundAlert | None = None,
        skill_name: str = "",
        skill_is_first_party: bool = False,
    ) -> bool | str:
        """Durably record an alert, then attempt provider acceptance.

        ``original_ts`` is the event's own account of when it happened and is
        kept raw; ``received_at_ms`` is the runtime's clock when it saw the
        event, and it is what the provider template's "detected at" slot shows.

        Returns True if the provider accepted it or a durable retry obligation
        exists, False if neither holds, or `SUPPRESSED` when a customer
        preference withheld the notice. Suppression is deliberate non-action,
        not a failed attempt. Provider acceptance is not handset delivery.
        """
        if not self._policy_permits_alert_class(
            skill_name,
            trigger_name,
            action_tier=action_tier,
            first_party=skill_is_first_party,
        ):
            logger.info(
                "[runtime] %s alert suppressed by customer preference "
                "skill=%s trigger=%s class=%s",
                channel,
                skill_name,
                trigger_name,
                alert_class_for_trigger(
                    skill_name, trigger_name, first_party=skill_is_first_party
                ),
            )
            await self._record_preference_disabled_alert(
                channel=channel,
                alert_class=alert_class_for_trigger(
                    skill_name, trigger_name, first_party=skill_is_first_party
                ),
                trigger_name=trigger_name,
                action_tier=action_tier,
                original_ts=original_ts,
            )
            return SUPPRESSED

        if not recipient:
            # Checked after the preference, because a notice the customer
            # switched off was not going to be sent to anyone. Reporting it as
            # a missing recipient would record a configuration fault the
            # deployment does not have.
            logger.warning(
                "[runtime] %s alert skipped: operator_contact not configured", channel
            )
            return False

        if not await self._policy_permits_external_alert(
            channel=channel,
            action_tier=action_tier,
        ):
            logger.info(
                "[runtime] %s alert suppressed by DevicePolicy monthly cap tier=%s trigger=%s",
                channel,
                action_tier,
                trigger_name,
            )
            return False

        if received_at_ms <= 0:
            logger.warning(
                "[runtime] alert trigger=%s arrived with no receipt; using now",
                trigger_name,
            )
            received_at_ms = now_ms()
        alert = outbound_alert or build_outbound_alert(
            intent=AlertIntent.TIER_A_ALERT,
            sms_body=message,
            template_variables=(
                trigger_name or "configured risk",
                self._device_location or self._device_id or "site",
                format_alert_timestamp(received_at_ms, self._device_timezone),
            ),
        )
        alert_id = build_alert_id(
            channel=channel,
            recipient=recipient,
            alert=alert,
            action_tier=action_tier,
            trigger_name=trigger_name,
            original_ts=original_ts,
        )

        inserted = False
        if self._state_store is not None:
            inserted = await self._state_store.enqueue_alert(
                alert_id=alert_id,
                channel=channel,
                recipient=recipient,
                message=alert.sms_body,
                intent=alert.intent.value,
                template_variables=alert.template_variables,
                action_tier=action_tier,
                trigger_name=trigger_name,
                original_ts=original_ts,
            )
            if not inserted:
                logger.debug(
                    "[runtime] alert already recorded id=%s channel=%s",
                    alert_id,
                    channel,
                )
                return True

        # Stamped only once a send is actually attempted. These timestamps are
        # published in the health snapshot, and a customer preference or a cap
        # that stopped the alert would otherwise report activity that never
        # happened.
        alert_ts = now_ms()
        self._last_alert_timestamps_by_channel[channel] = alert_ts
        if trigger_name:
            self._last_alert_timestamps_by_trigger[trigger_name] = alert_ts

        try:
            if allow_failover:
                receipt = coerce_alert_send_receipt(
                    await alert_sender.send(
                        alert=alert,
                        to_number=recipient,
                        preferred_channel=channel,
                    ),
                    fallback_channel=channel,
                )
            else:
                exact_sender = getattr(alert_sender, "send_exact", None)
                if callable(exact_sender):
                    # `callable()` narrows to a callable returning `object`,
                    # which is not awaitable. The cast names the contract a
                    # duck-typed sender must satisfy; the guard is unchanged,
                    # so a non-callable attribute still falls through to
                    # `send()` rather than being invoked.
                    send_exact = cast(Callable[..., Awaitable[object]], exact_sender)
                    receipt = coerce_alert_send_receipt(
                        await send_exact(
                            alert=alert,
                            to_number=recipient,
                            channel=channel,
                        ),
                        fallback_channel=channel,
                    )
                else:
                    receipt = coerce_alert_send_receipt(
                        await alert_sender.send(
                            alert=alert,
                            to_number=recipient,
                            preferred_channel=channel,
                        ),
                        fallback_channel=channel,
                    )
        except Exception:
            logger.exception(
                "[runtime] unexpected %s send failure; falling back to outbox queue",
                channel,
            )
            receipt = AlertSendReceipt.refused(channel=channel, error="sender_raised")

        if receipt.accepted:
            if self._state_store is not None:
                accepted_at_ms = receipt.accepted_at_ms or now_ms()
                await self._state_store.mark_alert_accepted(
                    alert_id,
                    accepted_channel=receipt.channel,
                    provider_message_id=receipt.provider_message_id,
                    provider_status=receipt.provider_status or "accepted",
                    accepted_at_ms=accepted_at_ms,
                    delivered_at_ms=receipt.delivered_at_ms,
                )
            await self._record_policy_counted_alert(
                receipt.channel, action_tier=action_tier
            )
            logger.info(
                "[runtime] provider accepted alert id=%s channel=%s status=%s sid=%s",
                alert_id,
                receipt.channel,
                receipt.provider_status,
                receipt.provider_message_id,
            )
            return True

        if inserted:
            await self._record_policy_counted_alert(channel, action_tier=action_tier)
            logger.info(
                "[runtime] queued refused %s alert id=%s tier=%s trigger=%s original_ts=%d",
                channel,
                alert_id,
                action_tier,
                trigger_name,
                original_ts,
            )
            return True

        logger.error(
            "[runtime] alert provider refused submission and StateStore is unavailable; dropping alert"
        )
        return False

    async def _send_or_queue_safety_alert(
        self,
        *,
        message: str,
        trigger_name: str,
        alert_sender: AlertFailoverSender,
        recipient: str = "",
    ) -> bool:
        """Mandatory notices: acceptance or durable queue, structurally outside
        DevicePolicy — no external-alert gate is consulted and no
        policy-counted counter moves.

        Two callers, admitted by one rule: a notice that a protection is
        absent or failed must not be suppressed by an entitlement cap, because
        suppressing it leaves an operator believing something is being watched
        that is not. The safety registry's sink is one. A configured sensor
        that never connected is the other, and it qualifies for the same
        reason — the runtime cannot measure what it was told to measure. A
        persistent measurement loss is the third, and its escalation is why
        `recipient` exists: from the second stage the notice is addressed to
        the secondary contact, and it must stay on this route to get there.
        An entitlement cap that silenced the escalation would leave exactly
        the operator who has not acted still not knowing.
        Never reachable from skills or ordinary action execution."""
        recipient = recipient or self._operator_contact
        if not recipient:
            logger.warning(
                "[safety] notice not sent: operator_contact is not configured"
            )
            return False
        channel = self._primary_alert_channel
        alert_ts = now_ms()
        alert = build_outbound_alert(
            intent=AlertIntent.TIER_A_ALERT,
            sms_body=message,
            template_variables=(
                trigger_name or "configured risk",
                self._device_location or self._device_id or "site",
                format_alert_timestamp(alert_ts, self._device_timezone),
            ),
        )
        alert_id = build_alert_id(
            channel=channel,
            recipient=recipient,
            alert=alert,
            action_tier="A",
            trigger_name=trigger_name,
            original_ts=alert_ts,
        )
        inserted = False
        if self._state_store is not None:
            inserted = await self._state_store.enqueue_alert(
                alert_id=alert_id,
                channel=channel,
                recipient=recipient,
                message=alert.sms_body,
                intent=alert.intent.value,
                template_variables=alert.template_variables,
                action_tier="A",
                trigger_name=trigger_name,
                original_ts=alert_ts,
            )
            if not inserted:
                return True

        self._last_alert_timestamps_by_channel[channel] = alert_ts
        self._last_alert_timestamps_by_trigger[trigger_name] = alert_ts
        try:
            receipt = coerce_alert_send_receipt(
                await alert_sender.send(
                    alert=alert,
                    to_number=recipient,
                    preferred_channel=channel,
                ),
                fallback_channel=channel,
            )
        except Exception:
            logger.exception(
                "[safety] %s notice send failed; falling back to outbox", channel
            )
            receipt = AlertSendReceipt.refused(channel=channel, error="sender_raised")
        if receipt.accepted:
            if self._state_store is not None:
                await self._state_store.mark_alert_accepted(
                    alert_id,
                    accepted_channel=receipt.channel,
                    provider_message_id=receipt.provider_message_id,
                    provider_status=receipt.provider_status or "accepted",
                    accepted_at_ms=receipt.accepted_at_ms or now_ms(),
                    delivered_at_ms=receipt.delivered_at_ms,
                )
            return True
        if inserted:
            return True
        logger.error("[safety] notice submission failed and StateStore is unavailable")
        return False

    def _policy_permits_alert_class(
        self,
        skill_name: str,
        trigger_name: str,
        *,
        action_tier: str = "A",
        first_party: bool = False,
    ) -> bool:
        """Whether a customer preference leaves this trigger's notice on.

        Reached only from `_send_or_queue_alert`. Mandatory notices travel
        `_send_or_queue_safety_alert`, which does not call this and must not.
        No policy means no preference, so the notice stands.
        """
        if str(action_tier).upper() == "D":
            return True
        alert_class = alert_class_for_trigger(
            skill_name, trigger_name, first_party=first_party
        )
        if alert_class is None:
            return True
        if self._dispatcher is None:
            return True
        return self._dispatcher.permits_alert_class(
            alert_class, action_tier=action_tier
        )

    async def _record_preference_disabled_alert(
        self,
        *,
        channel: str,
        alert_class: str | None,
        trigger_name: str,
        action_tier: str,
        original_ts: int,
    ) -> None:
        """Record that a notice was withheld by preference, and send nothing.

        Bounded to one row per channel, class and month, like the cap counter
        beside it. Keying by event timestamp instead would add a row per
        suppression, and a class with no cooldown suppressing at the poll rate
        would grow the state store without limit for a record nothing reads
        back yet.
        """
        if self._state_store is None:
            return
        key = preference_disabled_key(channel, alert_class, original_ts)
        try:
            raw = await self._state_store.get_skill_state(
                "__runtime_alert_preferences__", key
            )
            try:
                previous = json.loads(raw) if raw else {}
            except ValueError:
                previous = {}
            count = int(previous.get("count", 0) or 0) + 1
            await self._state_store.set_skill_state(
                "__runtime_alert_preferences__",
                key,
                json.dumps(
                    {
                        "outcome": "disabled",
                        "reason": "customer_preference",
                        "channel": channel,
                        "alert_class": alert_class,
                        "action_tier": action_tier,
                        "count": count,
                        "last_trigger_name": trigger_name,
                        "last_suppressed_ms": now_ms(),
                    },
                    sort_keys=True,
                ),
            )
        except Exception:
            logger.exception(
                "[runtime] failed to record a preference-disabled alert outcome"
            )

    async def _policy_permits_external_alert(
        self,
        *,
        channel: str,
        action_tier: str,
    ) -> bool:
        if str(action_tier).upper() == "D":
            return True
        if self._dispatcher is None or self._state_store is None:
            return True
        count = await self._current_policy_counted_alerts(channel)
        return self._dispatcher.permits_external_alert(
            channel=channel,
            action_tier=action_tier,
            current_month_count=count,
        )

    async def _current_policy_counted_alerts(self, channel: str) -> int:
        if self._state_store is None:
            return 0
        raw = await self._state_store.get_skill_state(
            "__runtime_alert_policy__",
            alert_policy_count_key(channel, now_ms()),
        )
        try:
            return max(0, int(raw or "0"))
        except (TypeError, ValueError):
            return 0

    async def _record_policy_counted_alert(
        self,
        channel: str,
        *,
        action_tier: str,
    ) -> None:
        if str(action_tier).upper() == "D":
            return
        if self._state_store is None:
            return
        try:
            key = alert_policy_count_key(channel, now_ms())
            current = await self._current_policy_counted_alerts(channel)
            await self._state_store.set_skill_state(
                "__runtime_alert_policy__",
                key,
                str(current + 1),
            )
        except Exception:
            logger.warning(
                "[runtime] failed to persist %s alert policy count; accepted or queued alert remains valid",
                channel,
                exc_info=True,
            )

    async def _send_setup_success_notifications(
        self,
        config: Config,
        alert_sender: AlertFailoverSender,
    ) -> None:
        setup_cfg = (
            config.actions.setup_notifications
            if isinstance(config.actions.setup_notifications, dict)
            else {}
        )
        if not is_truthy(setup_cfg.get("enabled", False)):
            return

        if not self._operator_contact:
            logger.warning(
                "[runtime] setup notification skipped: operator_contact not configured"
            )
            return

        channels = resolve_setup_notification_channels(
            setup_cfg.get("channels", ["primary"]),
            config.actions.primary_alert_channel,
        )
        if not channels:
            logger.warning("[runtime] setup notification skipped: no valid channels")
            return

        channel_enabled = {
            "sms": is_truthy(config.actions.sms.get("enabled", False)),
            "whatsapp": is_truthy(config.actions.whatsapp.get("enabled", False)),
        }
        connected_sensor_count = len(self._connected_sensor_ids)
        active_trigger_count = count_active_triggers(
            configured_sensors=config.sensors,
            connected_sensor_ids=self._connected_sensor_ids,
            loaded_skills=self._loaded_skills,
        )
        message = setup_success_message(
            config=config,
            connected_sensor_count=connected_sensor_count,
            active_trigger_count=active_trigger_count,
        )
        original_ts = self._runtime_started_at_ms or now_ms()
        startup_alert = build_outbound_alert(
            intent=AlertIntent.STARTUP,
            sms_body=message,
            template_variables=(
                config.device.location or "site",
                connected_sensor_count,
                active_trigger_count,
            ),
        )
        for channel in channels:
            if not channel_enabled.get(channel, False):
                logger.info(
                    "[runtime] setup notification skipped for disabled channel=%s",
                    channel,
                )
                continue
            try:
                await self._send_or_queue_alert(
                    channel=channel,
                    message=message,
                    recipient=self._operator_contact,
                    action_tier="A",
                    trigger_name="runtime_setup_complete",
                    original_ts=original_ts,
                    received_at_ms=original_ts,
                    alert_sender=alert_sender,
                    allow_failover=False,
                    outbound_alert=startup_alert,
                )
            except Exception:
                logger.exception(
                    "[runtime] setup notification failed unexpectedly on channel=%s",
                    channel,
                )

    async def _alert_delivery_loop(
        self,
        alert_sender: AlertFailoverSender,
    ) -> None:
        """Retry refused alerts and reconcile accepted provider receipts."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self._alert_outbox_retry_interval_s,
                )
                break
            except asyncio.TimeoutError:
                pass  # the retry interval elapsed: drain the outbox again

            if self._state_store is None:
                continue

            await self._reconcile_alert_delivery_receipts(alert_sender)

            try:
                pending = await self._state_store.get_retryable_alerts(
                    self._alert_outbox_batch_size
                )
            except Exception:
                logger.exception("[runtime] alert outbox fetch failed")
                continue

            for alert in pending:
                try:
                    channel = str(alert["channel"])
                    message = str(alert["message"])
                    recipient = str(alert["recipient"])
                    action_tier = str(alert["action_tier"]).upper()
                    trigger_name = str(alert.get("trigger_name", "") or "")
                    attempt_count = int(alert.get("attempt_count", 0))
                    alert_id = str(alert["alert_id"])
                    intent = AlertIntent(str(alert.get("intent", "tier_a_alert")))
                    template_variables = tuple(alert.get("template_variables") or ())
                    if not template_variables:
                        # A row queued before template variables were stored:
                        # the "detected at" slot takes the queue receipt, never
                        # the event's producer time.
                        queued_at = int(alert.get("queued_at_ms", 0) or 0)
                        template_variables = (
                            trigger_name or "configured risk",
                            self._device_location or self._device_id or "site",
                            format_alert_timestamp(
                                queued_at if queued_at > 0 else now_ms(),
                                self._device_timezone,
                            ),
                        )
                    outbound_alert = OutboundAlert(
                        intent=intent,
                        sms_body=message,
                        template_variables=template_variables,
                    )
                except Exception:
                    logger.exception("[runtime] malformed outbox row: %r", alert)
                    continue

                receipt = AlertSendReceipt.refused(
                    channel=channel, error="submission_not_attempted"
                )
                try:
                    preferred_channel = channel
                    if channel not in {"sms", "whatsapp"}:
                        logger.error(
                            "[runtime] alert outbox has unknown channel=%r id=%s",
                            channel,
                            alert_id,
                        )
                        preferred_channel = "sms"
                    elif attempt_count >= 1:
                        # On retries, switch first attempt preference to the other
                        # channel so a persistent single-channel outage does not
                        # stall notification delivery.
                        preferred_channel = "whatsapp" if channel == "sms" else "sms"

                    receipt = coerce_alert_send_receipt(
                        await alert_sender.send(
                            alert=outbound_alert,
                            to_number=recipient,
                            preferred_channel=preferred_channel,
                        ),
                        fallback_channel=preferred_channel,
                    )
                except Exception:
                    logger.exception(
                        "[runtime] alert outbox send failed for id=%s channel=%s",
                        alert_id,
                        channel,
                    )

                if receipt.accepted:
                    accepted_ts = receipt.accepted_at_ms or now_ms()
                    self._last_alert_timestamps_by_channel[receipt.channel] = (
                        accepted_ts
                    )
                    if trigger_name:
                        self._last_alert_timestamps_by_trigger[trigger_name] = (
                            accepted_ts
                        )
                    await self._state_store.mark_alert_accepted(
                        alert_id,
                        accepted_channel=receipt.channel,
                        provider_message_id=receipt.provider_message_id,
                        provider_status=receipt.provider_status or "accepted",
                        accepted_at_ms=accepted_ts,
                        delivered_at_ms=receipt.delivered_at_ms,
                    )
                    logger.info(
                        "[runtime] provider accepted queued alert id=%s channel=%s "
                        "status=%s sid=%s after %d attempt(s)",
                        alert_id,
                        receipt.channel,
                        receipt.provider_status,
                        receipt.provider_message_id,
                        attempt_count + 1,
                    )
                    continue

                await self._state_store.mark_alert_attempt_failed(alert_id)
                failed_ts = now_ms()
                self._last_alert_timestamps_by_channel[channel] = failed_ts
                if trigger_name:
                    self._last_alert_timestamps_by_trigger[trigger_name] = failed_ts
                attempts_after = attempt_count + 1
                logger.warning(
                    "[runtime] retry failed for queued alert id=%s channel=%s tier=%s attempt=%d",
                    alert_id,
                    channel,
                    action_tier,
                    attempts_after,
                )

                if action_tier == "D":
                    if attempts_after >= self._alert_outbox_tier_d_critical_threshold:
                        logger.critical(
                            "[runtime] Tier D notification delivery still failing id=%s "
                            "channel=%s attempts=%d (will keep retrying)",
                            alert_id,
                            channel,
                            attempts_after,
                        )
                    continue

                if attempts_after >= self._alert_outbox_max_non_tier_d_attempts:
                    await self._state_store.mark_alert_abandoned(alert_id)
                    logger.warning(
                        "[runtime] abandoning queued alert id=%s channel=%s after %d attempts",
                        alert_id,
                        channel,
                        attempts_after,
                    )

    async def _reconcile_alert_delivery_receipts(
        self,
        alert_sender: AlertFailoverSender,
    ) -> None:
        """Advance accepted messages only from later provider observations."""

        if self._state_store is None:
            return
        try:
            awaiting = await self._state_store.get_alerts_awaiting_delivery_receipt(
                self._alert_outbox_batch_size
            )
        except Exception:
            logger.exception("[runtime] alert delivery receipt fetch failed")
            return

        for alert in awaiting:
            alert_id = str(alert.get("alert_id", "") or "")
            channel = str(alert.get("accepted_channel", "") or "")
            provider_message_id = str(alert.get("provider_message_id", "") or "")
            if not alert_id or not channel or not provider_message_id:
                continue
            receipt = await alert_sender.get_delivery_receipt(
                channel=channel,
                provider_message_id=provider_message_id,
            )
            if receipt is None:
                continue
            await self._state_store.record_alert_delivery_status(
                alert_id,
                provider_status=receipt.provider_status,
                observed_at_ms=receipt.observed_at_ms,
                delivered_at_ms=receipt.delivered_at_ms,
                terminal_failure=receipt.terminal_failure,
            )
            if receipt.delivered_at_ms is not None:
                logger.info(
                    "[runtime] provider confirmed handset delivery id=%s channel=%s "
                    "status=%s sid=%s",
                    alert_id,
                    channel,
                    receipt.provider_status,
                    provider_message_id,
                )
            elif receipt.terminal_failure:
                action_tier = str(alert.get("action_tier", "A") or "A").upper()
                attempts_after = int(alert.get("attempt_count", 0) or 0) + 1
                logger.warning(
                    "[runtime] provider reported terminal delivery failure id=%s "
                    "channel=%s status=%s sid=%s attempt=%d",
                    alert_id,
                    channel,
                    receipt.provider_status,
                    provider_message_id,
                    attempts_after,
                )
                if action_tier == "D":
                    if attempts_after >= self._alert_outbox_tier_d_critical_threshold:
                        logger.critical(
                            "[runtime] Tier D notification reached terminal provider "
                            "failure id=%s channel=%s attempts=%d (will keep retrying)",
                            alert_id,
                            channel,
                            attempts_after,
                        )
                elif attempts_after >= self._alert_outbox_max_non_tier_d_attempts:
                    await self._state_store.mark_alert_abandoned(alert_id)
                    logger.warning(
                        "[runtime] abandoning alert id=%s channel=%s after %d "
                        "terminal provider failures",
                        alert_id,
                        channel,
                        attempts_after,
                    )
